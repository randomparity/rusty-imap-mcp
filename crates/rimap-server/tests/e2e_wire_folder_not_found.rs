//! Full-wire assertion of the folder-not-found error-code mapping (#569),
//! driven against the in-process scriptable fake (`rimap_fake_imap`) so the
//! suite runs on **every PR** with no container runtime.
//!
//! ## The pinned decision (#569)
//!
//! A tagged `NO` on `SELECT` / `EXAMINE` means the mailbox does not exist or
//! cannot be accessed (RFC 3501 §6.3.1 / §6.3.2) — a client / input error,
//! categorically different from a malformed-server protocol fault. The
//! deliberate mapping (recorded on issue #569) is **REMAP**: this now reaches
//! the agent as `ERR_NOT_FOUND` (MCP `RESOURCE_NOT_FOUND`), replacing the prior
//! `ERR_IMAP_PROTOCOL`, so the agent gets the actionable "check the folder
//! name" affordance and can tell it apart from a genuine protocol fault.
//!
//! ## Non-vacuity
//!
//! The load-bearing assertion is `error_code == "ERR_NOT_FOUND"`. Under the
//! pre-#569 behavior the same tagged `NO` surfaced as `ERR_IMAP_PROTOCOL`, so
//! reverting `ops::folders::map_select_err` (or the `ImapError::FolderNotFound`
//! `code()` arm) flips this string and fails the test. The scope is narrow: a
//! sibling unit test (`ops::folders::map_select_err_routes_bad_to_protocol`)
//! pins that a `BAD` on the same path still maps to `ERR_IMAP_PROTOCOL`.

#![expect(clippy::expect_used, reason = "integration tests")]
#![expect(clippy::panic, reason = "test diagnostics")]

#[path = "support/wire/mod.rs"]
mod wire;

#[path = "support/canary.rs"]
mod canary;

use rimap_fake_imap::fake_imap::{FakeImapServer, Step, login_preamble};
use serde_json::{Value, json};
use tempfile::TempDir;

use wire::{Harness, assert_valid};

/// Env var the keyring falls back to for the account password. The fake accepts
/// any password, so the value only needs to be present so credential resolution
/// succeeds and the flow reaches the tool call.
const PASSWORD_ENV_VAR: &str = "RUSTY_IMAP_MCP_PASSWORD";

/// A syntactically valid mailbox name that does not exist on the fake — passes
/// the MCP-boundary folder validation so the request reaches the IMAP EXAMINE,
/// which the fake then refuses with a tagged `NO`.
const BOGUS_FOLDER: &str = "DoesNotExist";

/// Prints the fake's recorded client-command dialog to stderr **iff** the test
/// is unwinding, so a miscalibrated script surfaces as a legible divergence
/// rather than a bare 2s harness timeout. Mirrors
/// `e2e_wire_fetch_skipped::DumpOnPanic`.
struct DumpOnPanic<'a>(&'a FakeImapServer);

impl Drop for DumpOnPanic<'_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            #[expect(clippy::print_stderr, reason = "test diagnostic on failure")]
            {
                eprintln!("fake recorded dialog:\n{:#?}", self.0.recorded());
            }
        }
    }
}

/// Login preamble, the boot `LIST "" *` (answered with a single `INBOX` so the
/// binary boots), then the `search` read-only EXAMINE of the bogus folder,
/// refused with a tagged `NO`. `search` calls `select(_, true)` → EXAMINE and
/// aborts on the refusal before any `UID SEARCH`, so no further steps follow.
fn folder_not_found_script() -> Vec<Step> {
    let mut steps = login_preamble("IMAP4rev1");
    steps.extend([
        Step::Expect { verb: "LIST" },
        Step::Send(b"* LIST (\\HasNoChildren) \"/\" \"INBOX\"\r\n".to_vec()),
        Step::Reply {
            text: "OK LIST completed",
        },
        // search: read-only EXAMINE of the nonexistent folder → tagged NO.
        Step::Expect { verb: "EXAMINE" },
        Step::Reply {
            text: "NO Mailbox doesn't exist",
        },
    ]);
    steps
}

/// Single-account, readonly-posture config pointing the binary at the fake.
/// Mirrors `e2e_wire_fetch_skipped::fake_config`.
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

/// Parse an audit JSONL file into records, panicking with the offending line on
/// any non-JSON entry. Mirrors `e2e_wire_login_rejected::read_audit_lines`.
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
async fn search_nonexistent_folder_maps_to_err_not_found_over_wire() {
    let server = FakeImapServer::start(folder_not_found_script()).await;
    let _dump = DumpOnPanic(&server);

    let password = canary::fresh_canary();
    let tempdir = TempDir::new().expect("tempdir");
    let config_path = tempdir.path().join("config.toml");
    let config = fake_config(server.port(), &server.pin().to_hex(), &tempdir);
    std::fs::write(&config_path, config).expect("write config");

    let mut harness = Harness::spawn_with_config(
        &config_path,
        tempdir,
        &[(PASSWORD_ENV_VAR, password.as_str())],
    )
    .await;

    harness.initialize_handshake().await;
    harness.send_initialized().await;

    let resp = harness
        .request(
            "tools/call",
            json!({ "name": "use_account", "arguments": { "account": "readonly" } }),
        )
        .await;
    assert!(resp["error"].is_null(), "use_account failed: {resp}");

    let resp = harness
        .request(
            "tools/call",
            json!({
                "name": "readonly.search",
                "arguments": { "folder": BOGUS_FOLDER, "subject": "anything" },
            }),
        )
        .await;

    // A nonexistent folder is a tool-execution error (the request was validly
    // routed and the tool ran), not a JSON-RPC error envelope.
    assert!(
        resp["error"].is_null(),
        "folder-not-found must surface as a tool result, not a JSON-RPC error; got {resp}",
    );
    assert_valid(&resp["result"], "CallToolResult");
    assert_eq!(
        resp["result"]["isError"],
        json!(true),
        "folder-not-found must surface as isError=true; got {resp}",
    );
    assert_eq!(
        resp["result"]["structuredContent"]["error_code"],
        json!("ERR_NOT_FOUND"),
        "tagged NO on EXAMINE must map to ERR_NOT_FOUND, not ERR_IMAP_PROTOCOL (#569); got {resp}",
    );
    assert!(
        resp["result"]["content"][0]["text"]
            .as_str()
            .is_some_and(|t| !t.is_empty()),
        "folder-not-found must carry a non-empty message; got {resp}",
    );

    // The audit trail must record the same code. Shut the harness down first so
    // the audit writer flushes its buffered records to disk, then read them.
    let (status, tempdir) = harness.shutdown_and_wait().await;
    assert!(status.success(), "clean shutdown expected; got {status:?}");

    let audit_path = tempdir.path().join("audit.jsonl");
    let lines = read_audit_lines(&audit_path);
    assert!(
        lines
            .iter()
            .any(|v| v["kind"] == "tool_end" && v["error_code"] == "ERR_NOT_FOUND"),
        "expected a tool_end audit record with error_code ERR_NOT_FOUND; audit lines: {lines:#?}",
    );

    let recorded = server.recorded();
    canary::assert_login_frame_only(&password, &recorded);
    canary::assert_absent(&password, &[tempdir.path()], &[]);
}
