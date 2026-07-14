//! Golden transcript of a "day in the life" cleanup session driven against the
//! in-process fake (`rimap_fake_imap`) — PR-blocking, no container. Snapshots the
//! full JSON-RPC transcript an agent sees: initialize instructions, `tools/list`,
//! then `search` → `move_message` → `delete_message` → `expunge`. See spec
//! `docs/superpowers/specs/2026-07-13-issue-524-golden-agent-transcripts-design.md`
//! and ADR-0009.
//!
//! Updating this snapshot: see AGENTS.md "Updating golden agent transcripts".
//! Destructive-posture flow; the IMAP dialog is hand-scripted on ONE reused
//! connection. A miscalibrated step surfaces via the `DumpOnPanic` guard.

#![expect(clippy::expect_used, reason = "integration tests")]

#[path = "support/wire/mod.rs"]
mod wire;

#[path = "support/canary.rs"]
mod canary;

use rimap_fake_imap::fake_imap::{FakeImapServer, Step, login_preamble};
use serde_json::{Value, json};
use tempfile::TempDir;

use wire::transcript::Recorder;
use wire::{Harness, PINNED_PROTOCOL_VERSION, assert_valid};

const PASSWORD_ENV_VAR: &str = "RUSTY_IMAP_MCP_PASSWORD";

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

fn select_body(exists: u32, uid_validity: u32) -> Vec<u8> {
    format!("* {exists} EXISTS\r\n* OK [UIDVALIDITY {uid_validity}] .\r\n").into_bytes()
}

fn page_line(uid: u32, subject: &str, message_id: &str) -> Vec<u8> {
    format!(
        "* {uid} FETCH (UID {uid} FLAGS (\\Seen) RFC822.SIZE 42 ENVELOPE \
         (\"Thu, 09 Jul 2026 12:00:00 +0000\" \"{subject}\" \
         ((\"A\" NIL \"a\" \"example.com\")) ((\"A\" NIL \"a\" \"example.com\")) \
         ((\"A\" NIL \"a\" \"example.com\")) ((\"B\" NIL \"b\" \"example.com\")) \
         NIL NIL NIL \"{message_id}\"))\r\n"
    )
    .into_bytes()
}

/// The full cleanup IMAP dialog on one reused connection.
fn cleanup_script() -> Vec<Step> {
    let mut steps = login_preamble("IMAP4rev1 MOVE UIDPLUS");
    steps.extend([
        // Boot discovery LIST.
        Step::Expect { verb: "LIST" },
        Step::Send(b"* LIST (\\HasNoChildren) \"/\" \"INBOX\"\r\n".to_vec()),
        Step::Reply {
            text: "OK LIST completed",
        },
    ]);
    // search(subject): EXAMINE + UID SEARCH + EXAMINE + UID FETCH page.
    steps.extend([
        Step::Expect { verb: "EXAMINE" },
        Step::Send(select_body(2, 1)),
        Step::Reply {
            text: "OK [READ-ONLY] EXAMINE completed",
        },
        Step::Expect { verb: "UID SEARCH" },
        Step::Send(b"* SEARCH 1 2\r\n".to_vec()),
        Step::Reply {
            text: "OK SEARCH completed",
        },
        Step::Expect { verb: "EXAMINE" },
        Step::Send(select_body(2, 1)),
        Step::Reply {
            text: "OK [READ-ONLY] EXAMINE completed",
        },
        Step::Expect { verb: "UID FETCH" },
        Step::Send(page_line(1, "old thread one", "<old-0001@example.com>")),
        Step::Send(page_line(2, "old thread two", "<old-0002@example.com>")),
        Step::Reply {
            text: "OK FETCH completed",
        },
    ]);
    // move_message(uid 1 -> Trash): SELECT (read-write) + UID MOVE.
    steps.extend([
        Step::Expect { verb: "SELECT" },
        Step::Send(select_body(2, 1)),
        Step::Reply {
            text: "OK [READ-WRITE] SELECT completed",
        },
        Step::Expect { verb: "UID MOVE" },
        Step::Send(b"* OK [COPYUID 5 1 10] Moved\r\n* 1 EXPUNGE\r\n".to_vec()),
        Step::Reply {
            text: "OK MOVE completed",
        },
    ]);
    // delete_message(uid 2): SELECT (read-write) + UID STORE +FLAGS (\Deleted)
    // (delete always flags first) + UID MOVE to Trash.
    steps.extend([
        Step::Expect { verb: "SELECT" },
        Step::Send(select_body(1, 1)),
        Step::Reply {
            text: "OK [READ-WRITE] SELECT completed",
        },
        Step::Expect { verb: "UID STORE" },
        Step::Send(b"* 1 FETCH (UID 2 FLAGS (\\Deleted))\r\n".to_vec()),
        Step::Reply {
            text: "OK STORE completed",
        },
        Step::Expect { verb: "UID MOVE" },
        Step::Send(b"* OK [COPYUID 5 2 11] Moved\r\n* 1 EXPUNGE\r\n".to_vec()),
        Step::Reply {
            text: "OK MOVE completed",
        },
    ]);
    // expunge(Archive): EXAMINE + UID SEARCH DELETED + SELECT (read-write) +
    // EXPUNGE. The SEARCH reports one `\Deleted` UID and the EXPUNGE reply carries
    // one `* <seq> EXPUNGE` so the destructive golden demonstrates a real erase
    // (`expunged_count: 1`), not a vacuous no-op.
    steps.extend([
        Step::Expect { verb: "EXAMINE" },
        Step::Send(select_body(1, 1)),
        Step::Reply {
            text: "OK [READ-ONLY] EXAMINE completed",
        },
        Step::Expect { verb: "UID SEARCH" },
        Step::Send(b"* SEARCH 3\r\n".to_vec()),
        Step::Reply {
            text: "OK SEARCH completed",
        },
        Step::Expect { verb: "SELECT" },
        Step::Send(select_body(1, 1)),
        Step::Reply {
            text: "OK [READ-WRITE] SELECT completed",
        },
        Step::Expect { verb: "EXPUNGE" },
        Step::Send(b"* 1 EXPUNGE\r\n".to_vec()),
        Step::Reply {
            text: "OK EXPUNGE completed",
        },
    ]);
    steps
}

/// Single-account, destructive config with `Archive` allowlisted for expunge.
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
name = "agent"

[accounts.imap]
host = "127.0.0.1"
port = {port}
username = "rimap-test"
encryption = "tls"
tls_fingerprint_sha256 = "{fingerprint_hex}"

[accounts.security]
posture = "destructive"
# `INBOX` is always protected (the validator force-adds it), so expunge targets
# a non-protected working folder allowlisted here.
expunge_folders = ["Archive"]

# `destructive` posture enables the SMTP send tools; deny them so the fixture
# needs no `[smtp]` section (the cleanup flow never sends).
[accounts.security.tools]
send_email = "deny"
forward = "deny"
"#,
        audit = base.join("audit.jsonl").display(),
        base = base.display(),
    )
}

async fn spawn_unhandshaken(server: &FakeImapServer, tempdir: TempDir, password: &str) -> Harness {
    let config_path = tempdir.path().join("config.toml");
    let config = fake_config(server.port(), &server.pin().to_hex(), &tempdir);
    std::fs::write(&config_path, config).expect("write config");
    Harness::spawn_with_config(&config_path, tempdir, &[(PASSWORD_ENV_VAR, password)]).await
}

/// Mandatory non-vacuity checks (spec Testing §Non-vacuity), factored out to keep
/// `cleanup_transcript` within the 100-line limit. Beyond the shared checks (no
/// errored call, non-empty instructions/catalog/search), the destructive flow
/// asserts each mutation actually did work — `move_message` moved something,
/// `delete_message` reached trash, `expunge` erased at least one message — so a
/// hollowed-out mutation response cannot be silently re-blessed via `insta`.
fn assert_non_vacuity(
    init: &Value,
    tools: &Value,
    search: &Value,
    mv: &Value,
    del: &Value,
    expunge: &Value,
) {
    for (name, r) in [
        ("search", search),
        ("move_message", mv),
        ("delete_message", del),
        ("expunge", expunge),
    ] {
        assert_ne!(
            r["result"]["isError"],
            json!(true),
            "{name} unexpectedly errored (miscalibrated dialog): {r}",
        );
    }
    let instructions = init["result"]["instructions"]
        .as_str()
        .or_else(|| init["result"]["serverInfo"]["instructions"].as_str())
        .unwrap_or("");
    assert!(
        instructions.len() > 32,
        "initialize instructions empty/short: {init}",
    );
    assert!(
        tools["result"]["tools"]
            .as_array()
            .is_some_and(|t| !t.is_empty()),
        "tools/list advertised empty catalog: {tools}",
    );
    assert_valid(&search["result"], "CallToolResult");
    assert!(
        search["result"]["structuredContent"]["untrusted"]["messages"]
            .as_array()
            .is_some_and(|m| !m.is_empty()),
        "search returned no messages (empty SEARCH would still snapshot full): {search}",
    );
    assert!(
        mv["result"]["structuredContent"]["meta"]["moves"]
            .as_array()
            .is_some_and(|m| !m.is_empty()),
        "move_message reported no moves: {mv}",
    );
    assert_eq!(
        del["result"]["structuredContent"]["meta"]["moved_to_trash"],
        json!(true),
        "delete_message did not move to trash: {del}",
    );
    assert!(
        expunge["result"]["structuredContent"]["meta"]["expunged_count"]
            .as_u64()
            .is_some_and(|n| n > 0),
        "expunge erased nothing (vacuous destructive golden): {expunge}",
    );
}

#[tokio::test]
async fn cleanup_transcript() {
    let server = FakeImapServer::start(cleanup_script()).await;
    let _dump = DumpOnPanic(&server);
    let password = canary::fresh_canary();
    let tempdir = TempDir::new().expect("tempdir");

    let mut rec = Recorder::new();
    let mut harness = spawn_unhandshaken(&server, tempdir, &password).await;

    let init = rec
        .call(
            &mut harness,
            "initialize",
            json!({
                "protocolVersion": PINNED_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": { "name": "rusty-imap-mcp-transcript", "version": "0" },
            }),
        )
        .await;
    harness.send_initialized().await;

    // Recorded into the transcript but not asserted on individually (a failed
    // use_account would cascade into the search call the flow depends on).
    rec.call(
        &mut harness,
        "tools/call",
        json!({ "name": "use_account", "arguments": { "account": "agent" } }),
    )
    .await;
    let tools = rec.call(&mut harness, "tools/list", json!({})).await;
    let search = rec
        .call(
            &mut harness,
            "tools/call",
            json!({ "name": "agent.search", "arguments": { "folder": "INBOX", "subject": "old" } }),
        )
        .await;
    let mv = rec
        .call(
            &mut harness,
            "tools/call",
            json!({
                "name": "agent.move_message",
                "arguments": { "folder": "INBOX", "uid": 1, "destination": "Trash" }
            }),
        )
        .await;
    let del = rec
        .call(
            &mut harness,
            "tools/call",
            json!({ "name": "agent.delete_message", "arguments": { "folder": "INBOX", "uid": 2 } }),
        )
        .await;
    let expunge = rec
        .call(
            &mut harness,
            "tools/call",
            json!({ "name": "agent.expunge", "arguments": { "folder": "Archive" } }),
        )
        .await;

    assert_non_vacuity(&init, &tools, &search, &mv, &del, &expunge);

    let recorded = server.recorded();
    let (status, tempdir) = harness.shutdown_and_wait().await;
    assert!(status.success(), "clean shutdown expected; got {status:?}");
    canary::assert_login_frame_only(&password, &recorded);
    canary::assert_absent(&password, &[tempdir.path()], &[]);

    insta::assert_snapshot!("cleanup", rec.render());
}
