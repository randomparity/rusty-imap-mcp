//! Wire-level LOGIN-rejection handling through the production binary (#566).
//! Companion to the rimap-imap-layer test
//! (`rimap-imap/tests/login_handshake_rejection.rs::login_no_surfaces_login_rejected`);
//! this one drives the same refusal through the whole production wiring —
//! config parse → account registry → `Connection` → TLS handshake → LOGIN
//! `NO` → `ImapError::Auth` → audit.
//!
//! # Why this is a boot-failure assertion, not a `tools/call` assertion
//!
//! Like the TLS pin-mismatch case (`e2e_wire_tls_pin_mismatch.rs`), a rejected
//! LOGIN surfaces at **boot**, not on a tool call: `build_registry` (main.rs)
//! eagerly issues `list_folders("*")` for every account *during boot*, which
//! drives connect → greeting → CAPABILITY → LOGIN before the MCP serve loop
//! starts, and propagates any error with `?`. So bad credentials make the
//! server **fail closed at boot** and exit non-zero — it never reaches
//! `initialize`, so no tool can be called. This is the security-correct
//! behavior (an account whose credentials are refused never comes up) and is a
//! *stronger* property than a per-call error.
//!
//! Unlike the pin-mismatch case, here the TLS handshake *succeeds* (the config
//! pins the fake's real leaf), so the audit record carries
//! `fingerprint_match: true` — the refusal is credential-level, not TLS-level.
//! The `auth` failure record is written synchronously by
//! `Connection::connect_inner` before the boot error propagates, so it survives
//! the aborted boot.
//!
//! Because the fake is in-process (no container), this test runs on every PR.

#![expect(clippy::expect_used, reason = "integration tests")]
#![expect(clippy::panic, reason = "test diagnostics")]

#[path = "support/wire/mod.rs"]
mod wire;

#[path = "support/canary.rs"]
mod canary;

use rimap_fake_imap::fake_imap::{FakeImapServer, Step};
use serde_json::Value;
use tempfile::TempDir;

use wire::Harness;

/// Env var the keyring falls back to for the account password. A password must
/// be present so credential resolution succeeds and the flow reaches LOGIN —
/// the server then refuses it with a tagged `NO`.
const PASSWORD_ENV_VAR: &str = "RUSTY_IMAP_MCP_PASSWORD";

/// Scripted dialog that answers the greeting and pre-login CAPABILITY, then
/// refuses LOGIN with `NO [AUTHENTICATIONFAILED]`. The boot `list_folders`
/// never reaches a folder command — the refusal aborts the connect flow.
fn login_rejected_script() -> Vec<Step> {
    vec![
        Step::Send(b"* OK fake ready\r\n".to_vec()),
        Step::Expect { verb: "CAPABILITY" },
        Step::Send(b"* CAPABILITY IMAP4rev1\r\n".to_vec()),
        Step::Reply {
            text: "OK CAPABILITY completed",
        },
        Step::Expect { verb: "LOGIN" },
        Step::Reply {
            text: "NO [AUTHENTICATIONFAILED] invalid credentials",
        },
    ]
}

/// Single-account, readonly-posture config pointing the binary at the fake with
/// its *correct* pin, so the TLS handshake succeeds and the flow reaches LOGIN.
/// Mirrors `e2e_wire_fetch_skipped.rs::fake_config`.
fn fake_config(port: u16, fingerprint_hex: &str, tempdir: &TempDir) -> String {
    let base = tempdir.path();
    format!(
        r#"
[audit]
path = "{audit}"
allowed_base_dir = "{base}"

[attachments]
download_dir = "{base}"

[defaults.credentials]
fallback = "keyring-then-env"

[[accounts]]
name = "readonly"

[accounts.imap]
host = "127.0.0.1"
port = {port}
username = "rimap-test"
encryption = "tls"
tls_fingerprint_sha256 = "{fingerprint_hex}"

[accounts.security]
posture = "readonly"
"#,
        audit = base.join("audit.jsonl").display(),
        base = base.display(),
    )
}

/// Parse an audit JSONL file into records. Tolerates a missing file
/// (returns empty) so callers can render it in a diagnostic.
fn read_audit_lines(path: &std::path::Path) -> Vec<Value> {
    let s = std::fs::read_to_string(path).unwrap_or_default();
    s.lines()
        .enumerate()
        .map(|(idx, l)| {
            serde_json::from_str(l)
                .unwrap_or_else(|e| panic!("audit line {} not JSON: {e}\nline: {l}", idx + 1))
        })
        .collect()
}

#[tokio::test]
async fn login_rejected_fails_boot_closed_and_records_err_auth_over_wire() {
    let server = FakeImapServer::start(login_rejected_script()).await;

    let password = canary::fresh_canary();
    let tempdir = TempDir::new().expect("tempdir");
    let config_path = tempdir.path().join("config.toml");
    let config = fake_config(server.port(), &server.pin().to_hex(), &tempdir);
    std::fs::write(&config_path, config).expect("write config");

    // Spawn the binary but do NOT `initialize`: boot fails before the serve
    // loop, so there is no JSON-RPC session to drive. `shutdown_and_wait`
    // drops stdin and reaps the child, returning its boot exit status.
    let harness = Harness::spawn_with_config(
        &config_path,
        tempdir,
        &[(PASSWORD_ENV_VAR, password.as_str())],
    )
    .await;
    let (status, tempdir) = harness.shutdown_and_wait().await;

    let audit_path = tempdir.path().join("audit.jsonl");
    let stderr_path = tempdir.path().join("rusty-imap-mcp.stderr.log");
    let stderr = std::fs::read_to_string(&stderr_path).unwrap_or_default();

    assert!(
        !status.success(),
        "a rejected LOGIN must fail the boot closed (non-zero exit); got {status:?}\n\
         --- captured stderr ---\n{stderr}",
    );

    // Exactly one `auth` failure record carrying the typed ERR_AUTH code. The
    // TLS handshake matched the pin, so the failure is credential-level, not
    // TLS-level — `fingerprint_match` is true.
    let lines = read_audit_lines(&audit_path);
    let rejected = lines
        .iter()
        .find(|v| v["kind"] == "auth" && v["error_code"] == "ERR_AUTH")
        .unwrap_or_else(|| {
            panic!(
                "expected an ERR_AUTH auth record; audit lines: {lines:#?}\n\
                 --- captured stderr ---\n{stderr}"
            )
        });
    assert_eq!(
        rejected["fingerprint_match"],
        Value::Bool(true),
        "a credential rejection over a matching pin must record fingerprint_match=true: {rejected}",
    );
    assert_eq!(
        rejected["tls_fingerprint_sha256"].as_str(),
        Some(server.pin().to_hex().as_str()),
        "audit must capture the fake's real observed leaf: {rejected}",
    );

    // The rejected LOGIN still reaches the wire, so the positive control holds:
    // the canary appears in the recorded LOGIN frame and nowhere else, and in no
    // artifact file.
    let recorded = server.recorded();
    canary::assert_login_frame_only(&password, &recorded);
    canary::assert_absent(&password, &[tempdir.path()], &[]);
}
