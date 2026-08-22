//! Golden transcript of a "day in the life" triage session driven against the
//! in-process fake (`rimap_fake_imap`) — PR-blocking, no container. Snapshots the
//! full JSON-RPC transcript an agent sees: initialize instructions, `tools/list`,
//! then `list_folders` → `search`(unread) → `fetch_message`(clean) →
//! `fetch_message`(hostile) → `mark_read` → `create_draft`. See spec
//! `docs/superpowers/specs/2026-07-13-issue-524-golden-agent-transcripts-design.md`
//! and ADR-0009.
//!
//! Updating this snapshot: see AGENTS.md "Updating golden agent transcripts".
//! The IMAP dialog is hand-scripted on ONE reused connection (the server caches a
//! session per account); a miscalibrated step surfaces via the `DumpOnPanic`
//! guard, which prints the fake's recorded client commands.

#![expect(clippy::expect_used, reason = "integration tests")]

#[path = "../support/wire/mod.rs"]
mod wire;

#[path = "../support/canary.rs"]
mod canary;

use rimap_fake_imap::fake_imap::{FakeImapServer, Step, login_preamble};
use serde_json::{Value, json};
use tempfile::TempDir;

use wire::transcript::Recorder;
use wire::{Harness, PINNED_PROTOCOL_VERSION, assert_valid};

const PASSWORD_ENV_VAR: &str = "RUSTY_IMAP_MCP_PASSWORD";

/// Frozen, transcript-owned fixtures (decoupled from the injection corpus).
const CLEAN_EML: &[u8] = include_bytes!("../fixtures/transcript/clean.eml");
const HOSTILE_EML: &[u8] = include_bytes!("../fixtures/transcript/hostile.eml");

/// Prints the fake's recorded client-command dialog to stderr iff the test is
/// unwinding, so a miscalibrated script surfaces as a legible divergence.
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

/// One untagged EXAMINE/SELECT reply body: EXISTS + a present UIDVALIDITY (the
/// fetch path fail-closes without it).
fn select_body(exists: u32, uid_validity: u32) -> Vec<u8> {
    format!("* {exists} EXISTS\r\n* OK [UIDVALIDITY {uid_validity}] .\r\n").into_bytes()
}

/// One `UID FETCH` page line carrying a well-formed RFC 3501 ENVELOPE (copied
/// from the known-parseable shape in `e2e_wire_fetch_skipped.rs`).
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

/// A `UID FETCH ... BODY[]` reply carrying the raw message bytes as a literal.
fn body_line(seq: u32, uid: u32, body: &[u8]) -> Vec<u8> {
    let mut v = format!("* {seq} FETCH (UID {uid} BODY[] {{{}}}\r\n", body.len()).into_bytes();
    v.extend_from_slice(body);
    v.extend_from_slice(b")\r\n");
    v
}

/// The full triage IMAP dialog on one reused connection.
fn triage_script() -> Vec<Step> {
    let mut steps = login_preamble("IMAP4rev1 MOVE UIDPLUS");
    steps.extend([
        // Boot discovery LIST (main.rs, per-account, before initialize returns).
        Step::Expect { verb: "LIST" },
        Step::Send(b"* LIST (\\HasNoChildren) \"/\" \"INBOX\"\r\n".to_vec()),
        Step::Reply {
            text: "OK LIST completed",
        },
        // list_folders tool: LIST + STATUS per selectable folder.
        Step::Expect { verb: "LIST" },
        Step::Send(b"* LIST (\\HasNoChildren) \"/\" \"INBOX\"\r\n".to_vec()),
        Step::Reply {
            text: "OK LIST completed",
        },
        Step::Expect { verb: "STATUS" },
        Step::Send(
            b"* STATUS \"INBOX\" (MESSAGES 2 RECENT 0 UIDNEXT 3 UIDVALIDITY 1 UNSEEN 2)\r\n"
                .to_vec(),
        ),
        Step::Reply {
            text: "OK STATUS completed",
        },
    ]);
    // search(seen=false): EXAMINE + UID SEARCH + EXAMINE + UID FETCH page.
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
        Step::Send(page_line(1, "Lunch tomorrow", "<clean-0001@example.com>")),
        Step::Send(page_line(
            2,
            "Action required",
            "<hostile-0001@example.com>",
        )),
        Step::Reply {
            text: "OK FETCH completed",
        },
    ]);
    // fetch_message(clean, uid 1): EXAMINE + size + EXAMINE + body.
    steps.extend(fetch_steps(1, CLEAN_EML));
    // fetch_message(hostile, uid 2): EXAMINE + size + EXAMINE + body.
    steps.extend(fetch_steps(2, HOSTILE_EML));
    // mark_read(uid 1): SELECT (read-write) + UID STORE.
    steps.extend([
        Step::Expect { verb: "SELECT" },
        Step::Send(select_body(2, 1)),
        Step::Reply {
            text: "OK [READ-WRITE] SELECT completed",
        },
        Step::Expect { verb: "UID STORE" },
        Step::Send(b"* 1 FETCH (UID 1 FLAGS (\\Seen))\r\n".to_vec()),
        Step::Reply {
            text: "OK STORE completed",
        },
    ]);
    // create_draft: APPEND with a synchronizing literal. The fake sends the
    // continuation, then `ExpectLiteral` drains the message literal the client
    // writes (LEN octets + CRLF) so the connection closes with a clean FIN.
    // Skipping the drain leaves the literal unread, and closing a socket with
    // unread bytes RSTs — which raced ahead of the tagged OK and surfaced as
    // ERR_CONNECTION_LOST in CI even though it passed locally.
    steps.extend([
        Step::Expect { verb: "APPEND" },
        Step::Send(b"+ OK\r\n".to_vec()),
        Step::ExpectLiteral,
        Step::Reply {
            text: "OK [APPENDUID 3 10] APPEND completed",
        },
    ]);
    steps
}

/// One `fetch_message` sub-dialog: size preflight (EXAMINE + UID FETCH
/// RFC822.SIZE) then body (EXAMINE + UID FETCH BODY[]).
fn fetch_steps(uid: u32, body: &[u8]) -> Vec<Step> {
    vec![
        Step::Expect { verb: "EXAMINE" },
        Step::Send(select_body(2, 1)),
        Step::Reply {
            text: "OK [READ-ONLY] EXAMINE completed",
        },
        Step::Expect { verb: "UID FETCH" },
        Step::Send(
            format!("* {uid} FETCH (UID {uid} RFC822.SIZE {})\r\n", body.len()).into_bytes(),
        ),
        Step::Reply {
            text: "OK FETCH completed",
        },
        Step::Expect { verb: "EXAMINE" },
        Step::Send(select_body(2, 1)),
        Step::Reply {
            text: "OK [READ-ONLY] EXAMINE completed",
        },
        Step::Expect { verb: "UID FETCH" },
        Step::Send(body_line(uid, uid, body)),
        Step::Reply {
            text: "OK FETCH completed",
        },
    ]
}

/// Single-account, draft-safe config pointing the binary at the fake.
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
posture = "draft-safe"
"#,
        audit = base.join("audit.jsonl").display(),
        base = base.display(),
    )
}

/// Spawn the binary against `server` WITHOUT the MCP handshake, so the `Recorder`
/// can capture the `initialize` exchange itself.
async fn spawn_unhandshaken(server: &FakeImapServer, tempdir: TempDir, password: &str) -> Harness {
    let config_path = tempdir.path().join("config.toml");
    let config = fake_config(server.port(), &server.pin().to_hex(), &tempdir);
    std::fs::write(&config_path, config).expect("write config");
    Harness::spawn_with_config(&config_path, tempdir, &[(PASSWORD_ENV_VAR, password)]).await
}

/// The flow's mandatory non-vacuity checks (spec Testing §Non-vacuity), factored
/// out so `triage_transcript` stays within the 100-line limit. Asserts: no
/// happy-path call errored, `initialize` carries non-empty instructions,
/// `tools/list` is non-empty, `search` returned matching messages, and the
/// hostile fetch carries a non-empty `security_warnings`.
fn assert_non_vacuity(
    init: &Value,
    tools: &Value,
    search: &Value,
    hostile: &Value,
    calls: &[(&str, &Value)],
) {
    for (name, r) in calls {
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
        hostile["result"]["structuredContent"]["security_warnings"]
            .as_array()
            .is_some_and(|w| !w.is_empty()),
        "hostile fetch has no security_warnings: {hostile}",
    );
}

#[tokio::test]
async fn triage_transcript() {
    let server = FakeImapServer::start(triage_script()).await;
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

    let use_acct = rec
        .call(
            &mut harness,
            "tools/call",
            json!({ "name": "use_account", "arguments": { "account": "agent" } }),
        )
        .await;
    let tools = rec.call(&mut harness, "tools/list", json!({})).await;
    let folders = rec
        .call(
            &mut harness,
            "tools/call",
            json!({ "name": "agent.list_folders", "arguments": {} }),
        )
        .await;
    let search = rec
        .call(
            &mut harness,
            "tools/call",
            json!({ "name": "agent.search", "arguments": { "folder": "INBOX", "seen": false } }),
        )
        .await;
    let clean = rec
        .call(
            &mut harness,
            "tools/call",
            json!({ "name": "agent.fetch_message", "arguments": { "folder": "INBOX", "uid": 1 } }),
        )
        .await;
    let hostile = rec
        .call(
            &mut harness,
            "tools/call",
            // No `include_html`: that sub-capability needs `full` posture. The
            // `html_hidden_content_detected` warning still fires during text
            // sanitization, which is what the non-vacuity assertion checks.
            json!({
                "name": "agent.fetch_message",
                "arguments": { "folder": "INBOX", "uid": 2 }
            }),
        )
        .await;
    let mark = rec
        .call(
            &mut harness,
            "tools/call",
            json!({ "name": "agent.mark_read", "arguments": { "folder": "INBOX", "uid": 1 } }),
        )
        .await;
    let draft = rec
        .call(
            &mut harness,
            "tools/call",
            json!({
                "name": "agent.create_draft",
                "arguments": {
                    "to": [{ "address": "alice@example.com" }],
                    "subject": "Re: Lunch tomorrow",
                    "body_text": "Yes \u{2014} see you at noon."
                }
            }),
        )
        .await;

    assert_non_vacuity(
        &init,
        &tools,
        &search,
        &hostile,
        &[
            ("use_account", &use_acct),
            ("list_folders", &folders),
            ("search", &search),
            ("fetch_clean", &clean),
            ("fetch_hostile", &hostile),
            ("mark_read", &mark),
            ("create_draft", &draft),
        ],
    );

    let recorded = server.recorded();
    let (status, tempdir) = harness.shutdown_and_wait().await;
    assert!(status.success(), "clean shutdown expected; got {status:?}");
    canary::assert_login_frame_only(&password, &recorded);
    canary::assert_absent(&password, &[tempdir.path()], &[]);

    insta::assert_snapshot!("triage", rec.render());
}
