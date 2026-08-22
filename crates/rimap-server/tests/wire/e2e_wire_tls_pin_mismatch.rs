//! Wire-level TLS pin-mismatch rejection through the production binary
//! (#564). Companion to the rimap-imap-layer live-handshake test
//! (`rimap-imap/tests/tls_pin_mismatch_live.rs`); this one drives the same
//! rejection through the whole production wiring — config parse → account
//! registry → `Connection` → rustls pin verify → `ImapError::Tls` → audit.
//!
//! # Why this is a boot-failure assertion, not a `tools/call` assertion
//!
//! The originating issue proposed calling a tool over JSON-RPC and asserting
//! an `ERR_TLS` tool-result envelope. That is not how a pin mismatch actually
//! surfaces: `build_registry` (main.rs) eagerly issues `LIST "" *` for every
//! account *during boot*, before the MCP serve loop starts, and propagates any
//! error with `?`. So a wrong pin makes the server **fail closed at boot** and
//! exit non-zero — it never reaches `initialize`, so no tool can be called.
//! That is the security-correct behavior (a MITM'd account never comes up),
//! and it is a *stronger* property than a per-call error. This test asserts
//! it directly: the binary exits non-zero, and the synchronously-written
//! `auth` audit record carries `ERR_TLS`, `fingerprint_match: false`, and the
//! fake's real observed leaf fingerprint. The auth record is written by
//! `Connection::connect_inner` (a synchronous, fsynced audit write) *before*
//! the boot error propagates, so it survives the aborted boot even though the
//! cancellation drainer is spawned only after `build_registry` returns.
//!
//! Because the fake is in-process (no container), this test runs on every PR.

#![expect(clippy::expect_used, reason = "integration tests")]
#![expect(clippy::panic, reason = "test diagnostics")]

#[path = "../support/wire/mod.rs"]
mod wire;

#[path = "../support/canary.rs"]
mod canary;

use rimap_core::TlsFingerprint;
use rimap_fake_imap::fake_imap::{FakeImapServer, Step};
use serde_json::Value;
use tempfile::TempDir;

use wire::Harness;

/// Env var the keyring falls back to for the account password. Credential
/// resolution is never reached on a pin mismatch (the TLS handshake fails
/// first), but the value must be present so config validation passes.
const PASSWORD_ENV_VAR: &str = "RUSTY_IMAP_MCP_PASSWORD";

/// A valid 64-char SHA-256 hex that cannot match any freshly generated leaf.
/// Distinct from `fake.pin()`, so it drives the mismatch path rather than
/// being rejected as malformed config.
fn wrong_pin() -> TlsFingerprint {
    TlsFingerprint::from_cert_der(b"deliberately-wrong")
}

/// Single-account, readonly-posture config pointing the binary at the fake
/// with a deliberately wrong `tls_fingerprint_sha256`. Mirrors
/// `e2e_wire_fetch_skipped.rs::fake_config`.
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
async fn pin_mismatch_fails_boot_closed_and_records_err_tls_over_wire() {
    // The fake serves a real rustls leaf; a mismatched pin fails the
    // handshake before the greeting is ever sent, so this trivial script is
    // never driven.
    let server = FakeImapServer::start(vec![Step::Send(b"* OK fake ready\r\n".to_vec())]).await;

    let wrong = wrong_pin();
    assert_ne!(
        wrong,
        server.pin(),
        "wrong pin must differ from the fake's real leaf fingerprint",
    );

    let password = canary::fresh_canary();
    let tempdir = TempDir::new().expect("tempdir");
    let config_path = tempdir.path().join("config.toml");
    let config = fake_config(server.port(), &wrong.to_hex(), &tempdir);
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
        "pin mismatch must fail the boot closed (non-zero exit); got {status:?}\n\
         --- captured stderr ---\n{stderr}",
    );

    // The MITM defense's evidence: exactly one `auth` failure record carrying
    // the typed ERR_TLS code, the mismatch flag, and the *live* observed leaf.
    let lines = read_audit_lines(&audit_path);
    let mismatch = lines
        .iter()
        .find(|v| v["kind"] == "auth" && v["error_code"] == "ERR_TLS")
        .unwrap_or_else(|| {
            panic!(
                "expected an ERR_TLS auth record; audit lines: {lines:#?}\n\
                 --- captured stderr ---\n{stderr}"
            )
        });
    assert_eq!(
        mismatch["fingerprint_match"],
        Value::Bool(false),
        "pin mismatch must record fingerprint_match=false: {mismatch}",
    );
    assert_eq!(
        mismatch["tls_fingerprint_sha256"].as_str(),
        Some(server.pin().to_hex().as_str()),
        "audit must capture the fake's real observed leaf, not a placeholder: {mismatch}",
    );

    // Hygiene-only: the TLS pin fails before LOGIN, so no positive control — the
    // recorded dialog is empty of the canary and the credential must not appear
    // in any boot-path artifact (stderr/audit/config).
    let recorded = server.recorded();
    canary::assert_absent(&password, &[tempdir.path()], &recorded);
}
