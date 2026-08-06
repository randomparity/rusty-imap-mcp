//! `process_end` is the terminal record of its process (#645).
//!
//! A connect that the shutdown cuts writes its `auth` record from
//! `AuthEmitGuard::drop` (#623/#644). rmcp spawns every request handler as a
//! detached `tokio::spawn`, so before this fix nothing owned those futures at
//! shutdown: `run_server` wrote `process_end` and only then dropped the
//! runtime, which is what dropped the handler — appending an `auth` record with
//! a higher `seq` after the `process_end` of the same `process_id`, or losing
//! it to process exit, or tearing the JSONL tail mid-line.
//!
//! The scenario drives the production binary against the in-process scriptable
//! fake (`rimap_fake_imap`), so it runs on every PR and gates on no container.
//!
//! Flow: the fake serves two connections. The first completes the boot login
//! and folder `LIST`, then disconnects, leaving the server's cached session
//! dead. A `list_folders` tool call finds that dead session and — `LIST` being
//! read-only, so retryable — reconnects. The second connection answers the
//! greeting and `CAPABILITY` but parks on `LOGIN`, which leaves the connect
//! genuinely in flight with its `AuthEmitGuard` live. Closing stdin then cuts
//! it, and the audit log must show the resulting `auth` record BEFORE
//! `process_end`, with nothing after it.
//!
//! Two deliberate departures from `support/wire/harness.rs`:
//!
//! * **The child is driven directly.** With a request still outstanding at EOF,
//!   rmcp spends its own fixed ~5s response-drain budget before `service.
//!   waiting()` returns, which is the harness's whole `SHUTDOWN_TIMEOUT`. That
//!   budget is rmcp's and precedes the drain under test, so this suite carries
//!   its own exit budget rather than widening a constant every other wire suite
//!   shares.
//! * **The audit log is parsed strictly.** Not
//!   `tests/support/chaos/audit.rs::read_records`: every line must parse and the
//!   file must end on a record boundary. A lenient parser reads a torn tail as
//!   an absent record, which is exactly the failure mode this test exists to
//!   catch.

#![expect(clippy::expect_used, reason = "integration tests")]
#![expect(clippy::panic, reason = "test diagnostics")]

#[path = "support/canary.rs"]
mod canary;

use std::process::Stdio;
use std::time::{Duration, Instant};

use assert_cmd::cargo::cargo_bin;
use rimap_fake_imap::fake_imap::{FakeImapServer, Step, login_preamble};
use rmcp::model::ProtocolVersion;
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

/// How long the second connection parks on `LOGIN`. Long enough to outlive the
/// whole test; the fake's accept-loop task is aborted on drop.
const PARK: Duration = Duration::from_secs(120);

/// Budget for observing the reconnect's `LOGIN` frame in the fake's recorded
/// dialog. Generous because it covers a cold binary start and a TLS handshake.
const RECONNECT_BUDGET: Duration = Duration::from_secs(10);

/// Budget for the child to exit after stdin closes. Covers rmcp's own ~5s
/// response drain, then the dispatch drain, then `process_end` — with enough
/// headroom that a contended host cannot turn a pass into a flake. It is a
/// backstop, not an assertion: this suite claims nothing about how *fast* the
/// exit is, only about what the audit log says afterwards.
const EXIT_BUDGET: Duration = Duration::from_secs(60);

/// Budget for the `initialize` round trip against a cold binary.
const INITIALIZE_BUDGET: Duration = Duration::from_secs(30);

/// Connection 1: a complete boot login and folder `LIST`, then a disconnect.
/// The disconnect is what makes the tool call reconnect rather than reuse the
/// cached session.
fn boot_then_disconnect() -> Vec<Step> {
    let mut steps = login_preamble("IMAP4rev1");
    steps.extend([
        Step::Expect { verb: "LIST" },
        Step::Send(b"* LIST (\\HasNoChildren) \"/\" \"INBOX\"\r\n".to_vec()),
        Step::Reply {
            text: "OK LIST completed",
        },
        Step::Disconnect,
    ]);
    steps
}

/// Connection 2: answer the greeting and pre-login `CAPABILITY`, read the
/// `LOGIN` command line, then park without replying. The client is left
/// awaiting a tagged `LOGIN` response, which is the only state in which the
/// connect is genuinely in flight. Reading the `LOGIN` line (rather than
/// parking earlier) is also this suite's synchronisation point: it appears in
/// `FakeImapServer::recorded`, so the test knows when to close stdin instead of
/// guessing with a sleep.
fn park_on_login() -> Vec<Step> {
    vec![
        Step::Send(b"* OK fake ready\r\n".to_vec()),
        Step::Expect { verb: "CAPABILITY" },
        Step::Send(b"* CAPABILITY IMAP4rev1\r\n".to_vec()),
        Step::Reply {
            text: "OK CAPABILITY completed",
        },
        Step::Expect { verb: "LOGIN" },
        Step::Stall(PARK),
    ]
}

/// Single-account, readonly-posture config pointing the binary at the fake.
///
/// Every timeout is set far above this suite's own budgets so nothing but the
/// shutdown can end the parked connect: a fired connect / command / tool-call
/// ceiling would write its own `auth` record on the normal path, and the test
/// would then assert nothing about shutdown ordering.
fn fake_config(port: u16, fingerprint_hex: &str, base: &std::path::Path) -> String {
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
connect_timeout_seconds = 120
command_timeout_seconds = 120

[accounts.limits]
# The loader rejects a ceiling below `2 x (2 x command + connect)`, so this is
# the floor implied by the per-stage timeouts above, not a free choice.
tool_call_timeout_seconds = 720

[accounts.security]
posture = "readonly"
"#,
        audit = base.join("audit.jsonl").display(),
        base = base.display(),
    )
}

/// Number of recorded frames whose command token is `LOGIN`.
fn login_frames(recorded: &[String]) -> usize {
    let mut n = 0;
    for frame in recorded {
        let mut tokens = frame.split_whitespace();
        let _tag = tokens.next();
        if tokens
            .next()
            .is_some_and(|c| c.eq_ignore_ascii_case("LOGIN"))
        {
            n += 1;
        }
    }
    n
}

/// Poll the fake's recorded dialog until it has read `want` `LOGIN` command
/// lines, or the budget expires.
async fn await_login_frames(server: &FakeImapServer, want: usize, stderr: &std::path::Path) {
    let deadline = Instant::now() + RECONNECT_BUDGET;
    loop {
        let recorded = server.recorded();
        if login_frames(&recorded) >= want {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "fake never read {want} LOGIN frame(s) within {RECONNECT_BUDGET:?}; \
             recorded dialog: {recorded:#?}\nserver stderr:\n{}",
            std::fs::read_to_string(stderr).unwrap_or_default(),
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// Strictly parse the audit JSONL. Unlike the chaos suite's `parse_lines`, an
/// unparseable line is a failure rather than a skip.
fn parse_strict(raw: &str) -> Vec<Value> {
    let mut out = Vec::new();
    for (i, line) in raw.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<Value>(line) {
            Ok(v) => out.push(v),
            Err(e) => panic!("audit line {} is not valid JSON ({e}): {line:?}", i + 1),
        }
    }
    out
}

/// The whole assertion: the file is intact, `process_end` closes it, and the
/// connect the shutdown cut is recorded inside the same process, before that
/// `process_end`.
fn assert_cut_auth_precedes_terminal_process_end(raw: &str) {
    assert!(
        raw.ends_with('\n'),
        "audit log must end on a record boundary, not a torn line: {:?}",
        raw.rsplit('\n').next(),
    );
    let records = parse_strict(raw);

    let end_at = records
        .iter()
        .position(|r| r["kind"] == "process_end")
        .unwrap_or_else(|| panic!("no process_end record: {records:#?}"));
    assert_eq!(
        end_at,
        records.len() - 1,
        "process_end must be the terminal record; trailing records: {:#?}",
        &records[end_at + 1..],
    );

    let process_end = &records[end_at];
    let cut = records[..end_at]
        .iter()
        .find(|r| r["kind"] == "auth" && r["error_code"] == "ERR_CANCELLED")
        .unwrap_or_else(|| {
            panic!("the shutdown-cut connect wrote no auth record before process_end: {records:#?}")
        });
    assert_eq!(
        cut["process_id"], process_end["process_id"],
        "the cut connect's auth record belongs to this process",
    );
    // Unwrapped, not compared as `Option`: `None < Some(_)`, so a record that
    // lost its `seq` would satisfy the comparison instead of failing it.
    let cut_seq = cut["seq"].as_u64().expect("cut auth record carries a seq");
    let end_seq = process_end["seq"]
        .as_u64()
        .expect("process_end carries a seq");
    assert!(
        cut_seq < end_seq,
        "cut auth seq {cut_seq} must precede process_end seq {end_seq}",
    );
}

/// What one run of the parked-dispatch scenario leaves behind. The `TempDir` is
/// carried so the audit log and the canary sweep outlive the driver.
struct ScenarioRun {
    tempdir: TempDir,
    /// The audit JSONL, verbatim — parsed by the caller, which decides how
    /// strict to be.
    raw: String,
    /// The fake's recorded IMAP dialog at the moment stdin closed.
    recorded: Vec<String>,
    /// The child's stderr. Carried because the audit log alone cannot separate
    /// a residue caused by a regression from one caused by a slow host: the
    /// `outstanding registrations outlived the shutdown drain` warning lands
    /// here, and a failing assertion that prints only the JSONL costs a second
    /// run to diagnose.
    stderr: String,
    password: String,
}

/// Drive the whole scenario: boot the fake, park a `list_folders` reconnect on
/// `LOGIN`, close stdin, and wait for the binary to exit.
async fn run_parked_dispatch_scenario() -> ScenarioRun {
    let server =
        FakeImapServer::start_sequence(vec![boot_then_disconnect(), park_on_login()]).await;

    let password = canary::fresh_canary();
    let tempdir = TempDir::new().expect("tempdir");
    let base = tempdir.path();
    let config_path = base.join("config.toml");
    std::fs::write(
        &config_path,
        fake_config(server.port(), &server.pin().to_hex(), base),
    )
    .expect("write config");

    let stderr_path = base.join("rusty-imap-mcp.stderr.log");
    let stderr_file = std::fs::File::create(&stderr_path).expect("create stderr log");
    let mut child = Command::new(cargo_bin("rusty-imap-mcp"))
        .env("RUSTY_IMAP_MCP_PASSWORD", &password)
        .arg("--config")
        .arg(&config_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::from(stderr_file))
        .kill_on_drop(true)
        .spawn()
        .expect("spawn rusty-imap-mcp binary");
    let mut stdin = child.stdin.take().expect("stdin");
    let mut stdout = BufReader::new(child.stdout.take().expect("stdout"));

    let read_stderr = || std::fs::read_to_string(&stderr_path).unwrap_or_default();

    send(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": ProtocolVersion::LATEST.as_str(),
                "capabilities": {},
                "clientInfo": { "name": "shutdown-ordering-test", "version": "0" },
            },
        }),
    )
    .await;

    let mut line = String::new();
    let read = tokio::time::timeout(INITIALIZE_BUDGET, stdout.read_line(&mut line)).await;
    match read {
        Ok(Ok(n)) if n > 0 => {}
        other => panic!(
            "no initialize response ({other:?}); stderr:\n{}",
            read_stderr()
        ),
    }

    send(
        &mut stdin,
        &json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
    )
    .await;

    // Sent without awaiting a response — it never gets one, because the
    // reconnect it triggers parks forever.
    send(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": { "name": "readonly.list_folders", "arguments": {} },
        }),
    )
    .await;

    // Connection 2's LOGIN means the reconnect is in flight and its
    // `AuthEmitGuard` is live. Only now is closing stdin a shutdown *cut*.
    await_login_frames(&server, 2, &stderr_path).await;
    let recorded = server.recorded();

    drop(stdin);
    let status = tokio::time::timeout(EXIT_BUDGET, child.wait())
        .await
        .unwrap_or_else(|_| panic!("child did not exit within {EXIT_BUDGET:?}"))
        .expect("wait for child");
    assert!(
        status.success(),
        "server exited {status}; stderr:\n{}",
        read_stderr(),
    );

    let raw = std::fs::read_to_string(base.join("audit.jsonl")).expect("read audit log");
    let stderr = read_stderr();
    ScenarioRun {
        tempdir,
        raw,
        recorded,
        stderr,
        password,
    }
}

/// The `process_end` record, as parsed JSON. Strict, like everything else in
/// this suite: an unparseable line is a failure, not a skip.
fn process_end_record(raw: &str) -> Value {
    parse_strict(raw)
        .into_iter()
        .find(|r| r["kind"] == "process_end")
        .unwrap_or_else(|| panic!("no process_end record in:\n{raw}"))
}

/// The `undrained_dispatches == 0` assertion is the only end-to-end check on the
/// shipped `DISPATCH_DRAIN_BUDGET`: every wire suite runs at that constant, but
/// this is the one that parks a dispatch, cuts it, and then reads back what the
/// drain reported — so the zero is precisely the claim that two seconds covers
/// this scenario's cut path. The non-zero half of the pair is not reachable from
/// the wire and lives in `mcp::server`'s `dispatch_drain_tests`, at a budget of
/// its own.
///
/// Two mechanisms could make the drain report a residue here, and only one is
/// ruled out. A budget the runtime cannot drive to time *overruns*: by the time
/// `shutdown`'s timeout is finally polled the fsync has landed and `inflight` is
/// zero, so it returns zero and this passes. What is **not** ruled out is a
/// driven timer that genuinely expires — workers available, `audit.path` on a
/// filesystem where the cut path's synchronous fsync exceeds two seconds. That
/// is a real, accepted flake risk on a slow host, taken deliberately: widening
/// the budget would make this assertion unfailable and delete the shipped
/// constant's only end-to-end coverage in the same stroke. The assertion
/// therefore prints the child's stderr, where the
/// `outstanding registrations outlived the shutdown drain` warning
/// distinguishes a slow disk from a regression on the first run rather than
/// the second.
#[tokio::test]
async fn shutdown_cut_auth_record_precedes_process_end() {
    let run = run_parked_dispatch_scenario().await;
    assert_cut_auth_precedes_terminal_process_end(&run.raw);

    // The whole point of the drain is that this run has no residue, and the
    // record says so rather than leaving a reader to infer it from absence.
    assert_eq!(
        process_end_record(&run.raw)["undrained_dispatches"],
        0,
        "a run whose dispatch was cut in time must state a zero residue.\n\
         audit log:\n{}\nserver stderr:\n{}",
        run.raw,
        run.stderr,
    );

    canary::assert_login_frame_only(&run.password, &run.recorded);
    canary::assert_absent(&run.password, &[run.tempdir.path()], &[]);
}

/// Write one newline-delimited JSON-RPC frame to the child's stdin.
async fn send(stdin: &mut tokio::process::ChildStdin, envelope: &Value) {
    let line = format!("{envelope}\n");
    stdin
        .write_all(line.as_bytes())
        .await
        .expect("write to server stdin");
    stdin.flush().await.expect("flush server stdin");
}
