//! Full-wire assertion of `search` `meta.fetch_skipped` on a scripted
//! short-page FETCH (#561, follow-up to #535 / PR #560).
//!
//! Unlike the Dovecot-backed `e2e_wire*` suite, this test needs an
//! *inconsistent* server: one that lists three UIDs in its `UID SEARCH`
//! answer but returns a usable message for only two of them in the `UID
//! FETCH` answer. A conformant server never does this, so the test drives
//! the production binary against the in-process scriptable fake
//! (`rimap_fake_imap`), which binds a real `127.0.0.1:0` IMAPS socket and
//! can emit a `UID FETCH` reply that omits the line for one requested UID.
//!
//! Because the fake is in-process (no container), this test runs on every
//! PR — it does NOT gate on a container runtime.
//!
//! Flow: start the fake with a scripted short-page dialog (it lists three UIDs
//! in `UID SEARCH` but returns FETCH lines for only two — the exact IMAP
//! sequence is in `short_page_script`); point the binary at
//! `127.0.0.1:<fake.port()>` with `fake.pin()` as the pinned fingerprint; issue
//! a `search` over the JSON-RPC wire; assert `meta.fetch_skipped == 1`,
//! `meta.returned == 2`, and `meta.total_matched == 3`.

#![expect(clippy::expect_used, reason = "integration tests")]
#![expect(clippy::panic, reason = "test diagnostics")]

#[path = "support/wire/mod.rs"]
mod wire;

use rimap_fake_imap::fake_imap::{FakeImapServer, Step, login_preamble};
use serde_json::{Value, json};
use tempfile::TempDir;

use wire::schema::validator_for_tool_response;
use wire::{Harness, assert_valid};

/// Env var the keyring falls back to for the account password. The fake
/// accepts any password (its `login_preamble` always replies `OK LOGIN
/// completed`), so the value is irrelevant — it only needs to be present so
/// credential resolution succeeds.
const PASSWORD_ENV_VAR: &str = "RUSTY_IMAP_MCP_PASSWORD";

/// Prints the fake's recorded client-command dialog to stderr **iff** the
/// test is unwinding. This fires on the harness's 2s timeout panic (which
/// is how a miscalibrated script or a capability-gated command the fake
/// cannot answer surfaces), the fake's own in-task `assert!` (surfaced as a
/// dropped connection), and a wrong-`meta` assertion alike — so a
/// mid-sequence divergence is legible instead of a bare timeout.
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

/// Build the scripted dialog for one `search` tool call against the fake:
/// login preamble, then the read-only search path's
/// EXAMINE → `UID SEARCH` → EXAMINE → `UID FETCH` sequence. The `UID SEARCH`
/// lists UIDs 1, 2, 3; the `UID FETCH` returns fully-parseable envelope
/// lines for UIDs 1 and 3 only, omitting UID 2 — the page shortfall.
///
/// This one linear script assumes the binary drives the whole dialog on a
/// **single reused connection**: the fake's accept-loop replays the entire
/// script per accepted connection and serves connections sequentially, so a
/// second concurrent connection would not be served until the first `serve()`
/// returns. The assumption holds because the server caches one session per
/// account (`with_session` reuses it across the boot `LIST` and the
/// search/fetch ops) and both EXAMINE commands are re-issued because
/// `select()` is unconditional. If a future change opens a second concurrent
/// connection or elides the second select, this script diverges — the `DumpOnPanic`
/// guard prints `recorded()` so the diverging client command is legible rather
/// than surfacing only as the harness's 2s timeout.
fn short_page_script() -> Vec<Step> {
    let mut steps = login_preamble("IMAP4rev1");
    steps.extend([
        // Boot: the server lists folders for the account at startup to build
        // its reveal-on-select tool catalog (`LIST "" *`), before initialize
        // completes. Answer it so the binary boots.
        Step::Expect { verb: "LIST" },
        Step::Send(b"* LIST (\\HasNoChildren) \"/\" \"INBOX\"\r\n".to_vec()),
        Step::Reply {
            text: "OK LIST completed",
        },
        // search: read-only EXAMINE (ops::search calls select(_, true)).
        Step::Expect { verb: "EXAMINE" },
        Step::Send(b"* 3 EXISTS\r\n* OK [UIDVALIDITY 1] .\r\n".to_vec()),
        Step::Reply {
            text: "OK [READ-ONLY] EXAMINE completed",
        },
        // UID SEARCH lists three UIDs.
        Step::Expect { verb: "UID SEARCH" },
        Step::Send(b"* SEARCH 1 2 3\r\n".to_vec()),
        Step::Reply {
            text: "OK SEARCH completed",
        },
        // fetch: a second read-only EXAMINE (Connection::fetch re-selects).
        Step::Expect { verb: "EXAMINE" },
        Step::Send(b"* 3 EXISTS\r\n* OK [UIDVALIDITY 1] .\r\n".to_vec()),
        Step::Reply {
            text: "OK [READ-ONLY] EXAMINE completed",
        },
        // UID FETCH: fully-parseable envelope lines for UIDs 1 and 3, NONE
        // for UID 2. The FetchSpec the search page requests is
        // {envelope, flags, size}, so each line carries UID + FLAGS +
        // RFC822.SIZE + a well-formed RFC 3501 ENVELOPE.
        Step::Expect { verb: "UID FETCH" },
        Step::Send(fetch_line(1, "hello one", "<msg1@example.com>")),
        Step::Send(fetch_line(3, "hello three", "<msg3@example.com>")),
        Step::Reply {
            text: "OK FETCH completed",
        },
    ]);
    steps
}

/// One untagged `UID FETCH` response line carrying a well-formed ENVELOPE.
/// The ENVELOPE tuple is
/// `(date subject from sender reply-to to cc bcc in-reply-to message-id)`
/// with cc/bcc/in-reply-to as `NIL` and single-address from/sender/reply-to/to.
fn fetch_line(uid: u32, subject: &str, message_id: &str) -> Vec<u8> {
    format!(
        "* {uid} FETCH (UID {uid} FLAGS (\\Seen) RFC822.SIZE 42 ENVELOPE \
         (\"Thu, 09 Jul 2026 12:00:00 +0000\" \"{subject}\" \
         ((\"A\" NIL \"a\" \"example.com\")) ((\"A\" NIL \"a\" \"example.com\")) \
         ((\"A\" NIL \"a\" \"example.com\")) ((\"B\" NIL \"b\" \"example.com\")) \
         NIL NIL NIL \"{message_id}\"))\r\n"
    )
    .into_bytes()
}

/// Single-account, readonly-posture config pointing the binary at the fake.
/// `[defaults.credentials] fallback = "keyring-then-env"` + the injected
/// `RUSTY_IMAP_MCP_PASSWORD` resolves the password.
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

/// Invoke `tools/call`, assert no error, validate the response against the
/// per-tool response schema fixture, and return `structuredContent`. Local
/// equivalent of `e2e_wire.rs::call_tool` (that fn is private to its binary).
async fn call_tool(harness: &mut Harness, name: &str, bare: &'static str, args: Value) -> Value {
    let resp = harness
        .request("tools/call", json!({ "name": name, "arguments": args }))
        .await;
    assert!(resp["error"].is_null(), "tool {name} failed: {resp}");
    assert_valid(&resp["result"], "CallToolResult");
    let body = &resp["result"]["structuredContent"];
    let validator = validator_for_tool_response(bare);
    if !validator.is_valid(body) {
        let errors: Vec<String> = validator.iter_errors(body).map(|e| e.to_string()).collect();
        panic!(
            "tool {name} response failed schema:\n  {}\n\nresponse: {body}",
            errors.join("\n  ")
        );
    }
    body.clone()
}

#[tokio::test]
async fn search_reports_fetch_skipped_on_short_page_over_wire() {
    let server = FakeImapServer::start(short_page_script()).await;
    let _dump = DumpOnPanic(&server);

    let tempdir = TempDir::new().expect("tempdir");
    let config_path = tempdir.path().join("config.toml");
    let config = fake_config(server.port(), &server.pin().to_hex(), &tempdir);
    std::fs::write(&config_path, config).expect("write config");

    let mut harness = Harness::spawn_with_config(
        &config_path,
        tempdir,
        &[(PASSWORD_ENV_VAR, "fake-password")],
    )
    .await;

    harness.initialize_handshake().await;
    harness.send_initialized().await;

    call_tool(
        &mut harness,
        "use_account",
        "use_account",
        json!({ "account": "readonly" }),
    )
    .await;

    // Omit `limit`/`offset` so page_requested == total_matched == 3
    // (default limit = MAX_LIMIT = 100, offset = 0).
    let body = call_tool(
        &mut harness,
        "readonly.search",
        "search",
        json!({ "folder": "INBOX", "subject": "hello" }),
    )
    .await;

    let meta = &body["meta"];
    assert_eq!(
        meta["total_matched"].as_u64(),
        Some(3),
        "server listed 3 UIDs: {body}",
    );
    assert_eq!(
        meta["returned"].as_u64(),
        Some(2),
        "only UIDs 1 and 3 returned usable messages: {body}",
    );
    assert_eq!(
        meta["fetch_skipped"].as_u64(),
        Some(1),
        "exactly one UID (2) was listed but not returned: {body}",
    );
}
