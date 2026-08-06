//! Compile-time enforcement of the audit envelope (#110).
//!
//! `execute_tool_for_test` composes the full dispatch pipeline
//! (posture → `pre_dispatch` → audit envelope → handler). This test
//! invokes it against the `list_accounts` infrastructure tool — no
//! IMAP connection is required — and asserts that both the
//! `tool_start` and `tool_end` envelope records landed in the audit
//! log. If a future refactor lets a caller bypass
//! `run_with_audit_envelope`, these records are absent and the test
//! fails.

#![expect(clippy::expect_used, reason = "tests")]

use std::collections::BTreeMap;

use rimap_audit::{AuditOptions, AuditWriter, Seq};
use rimap_core::tool::ToolName;
use rimap_server::boot::registry::AccountRegistry;
use rimap_server::mcp::server::ImapMcpServer;
use serde_json::json;
use tempfile::TempDir;

struct TestFixture {
    server: ImapMcpServer,
    audit_path: std::path::PathBuf,
    _audit_dir: TempDir,
}

fn build_test_server() -> TestFixture {
    let audit_dir = TempDir::new().expect("audit tempdir");
    let audit_path = audit_dir.path().join("audit.jsonl");
    let audit = AuditWriter::open(&AuditOptions::new(audit_path.clone())).expect("audit open");

    let registry = AccountRegistry::new(BTreeMap::new());
    let (cancellation_sender, _cancellation_rx) = rimap_audit::cancellation_channel();
    let server = ImapMcpServer::new(registry, audit, cancellation_sender);

    TestFixture {
        server,
        audit_path,
        _audit_dir: audit_dir,
    }
}

fn read_audit_records(path: &std::path::Path) -> Vec<serde_json::Value> {
    let contents = std::fs::read_to_string(path).expect("read audit log");
    contents
        .lines()
        .map(|line| serde_json::from_str(line).expect("parse record"))
        .collect()
}

/// A never-completing tool body that signals `entered` on its first poll.
///
/// This is the barrier for "the envelope is ready to be cancelled".
/// `run_with_audit_envelope` awaits `emit_tool_start`, constructs the
/// `AuditEnvelopeGuard`, and only *then* polls the body — so observing the
/// first poll proves the `tool_start` write finished and the guard is
/// armed. Nothing else polls this future, so the signal cannot arrive
/// early, which makes it an exact ordering barrier rather than a timing
/// window.
///
/// Kept in sync with the copy in `src/mcp/audit_envelope.rs`, which this
/// integration-test binary cannot reach.
fn body_signalling_first_poll(
    entered: tokio::sync::oneshot::Sender<()>,
) -> impl std::future::Future<Output = Result<serde_json::Value, rimap_core::RimapError>> {
    let mut entered = Some(entered);
    std::future::poll_fn(move |_cx| {
        if let Some(entered) = entered.take() {
            // A dropped receiver means the test already gave up; the
            // assertions report that, so the send result is not actionable.
            let _ = entered.send(());
        }
        // Never resolve: the abort must land while the body is suspended.
        std::task::Poll::Pending
    })
}

#[tokio::test]
async fn execute_tool_for_test_emits_audit_envelope() {
    let fixture = build_test_server();

    // `list_accounts` is an infrastructure tool and needs no IMAP
    // connection. If the envelope were bypassed, the tool_start /
    // tool_end records below would be missing.
    let _result = fixture
        .server
        .execute_tool_for_test(None, ToolName::ListAccounts, json!({}))
        .await
        .expect("execute_tool_for_test should succeed");

    // Drop the server to flush the audit writer.
    drop(fixture.server);

    let records = read_audit_records(&fixture.audit_path);

    assert!(
        records
            .iter()
            .any(|r| r["kind"] == "tool_start" && r["tool"] == "list_accounts"),
        "tool_start record missing; dispatch must not bypass the envelope. records={records:#?}",
    );
    assert!(
        records
            .iter()
            .any(|r| r["kind"] == "tool_end" && r["tool"] == "list_accounts"),
        "tool_end record missing. records={records:#?}",
    );

    let start = records
        .iter()
        .find(|r| r["kind"] == "tool_start" && r["tool"] == "list_accounts")
        .expect("tool_start record");
    let end = records
        .iter()
        .find(|r| r["kind"] == "tool_end" && r["tool"] == "list_accounts")
        .expect("tool_end record");

    assert_eq!(
        start["seq"], end["start_seq"],
        "tool_end.start_seq must correlate back to tool_start.seq; otherwise the envelope's pairing guarantee is broken",
    );
}

#[tokio::test]
async fn use_account_rejected_spoof_is_not_in_audit_log() {
    let fixture = build_test_server();

    // Spoofed account name containing RLO (U+202E) and ZWSP (U+200B).
    // After rejection, the audit log must contain neither the raw
    // account string nor the JSON-escaped form of the spoof codepoints —
    // only the `<redacted:N>` placeholder.
    let _ = fixture
        .server
        .execute_tool_for_test(
            None,
            ToolName::UseAccount,
            serde_json::json!({ "account": "work\u{202e}\u{200b}cnyS" }),
        )
        .await;

    drop(fixture.server);

    let raw = std::fs::read_to_string(&fixture.audit_path).expect("read audit log");

    // serde_json may or may not escape non-ASCII as \uXXXX depending on
    // configuration. Check both the literal UTF-8 bytes AND the JSON-escape
    // forms so a regression is caught regardless of serializer behavior.
    assert!(
        !raw.contains('\u{202e}'),
        "RTL-override literal codepoint leaked into audit log: {raw}",
    );
    assert!(
        !raw.contains('\u{200b}'),
        "zero-width-space literal codepoint leaked into audit log: {raw}",
    );
    assert!(
        !raw.contains("\\u202e"),
        "RTL-override escape form leaked into audit log: {raw}",
    );
    assert!(
        !raw.contains("\\u200b"),
        "zero-width-space escape form leaked into audit log: {raw}",
    );
    assert!(
        !raw.contains("\"work"),
        "raw account string prefix leaked into audit log: {raw}",
    );

    // Walk the structured records. The `tool_start` for `use_account`
    // must carry the redacted placeholder in `arguments_redacted.account`,
    // proving the `RedactString` policy is active.
    let start = raw
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .find(|r| r["kind"] == "tool_start" && r["tool"] == "use_account")
        .expect("tool_start record for use_account");
    let account_field = start
        .pointer("/arguments_redacted/account")
        .expect("tool_start must expose arguments_redacted.account")
        .as_str()
        .expect("arguments_redacted.account must be a string");
    assert!(
        account_field.starts_with("<redacted:"),
        "account field must be redacted placeholder, got: {account_field:?}",
    );
}

/// Drop the outer dispatch future while a tool body is still awaiting.
/// The `AuditEnvelopeGuard::Drop` path must fire, enqueue a synthetic
/// cancellation `tool_end`, and the drainer must persist it to disk.
///
/// Regression test for the closure form of `run_with_audit_envelope`:
/// the guard lives inside the closure's future, so if a future refactor
/// disarms the guard above the `body(ticket).await`, cancellation would
/// silently lose its `tool_end` — the unit test at `audit_envelope.rs`
/// only exercises the guard in isolation, not the closure wiring.
#[tokio::test]
async fn drop_during_body_enqueues_cancellation_tool_end() {
    use rimap_audit::spawn_drainer;
    use std::sync::Arc;

    let audit_dir = tempfile::TempDir::new().expect("audit tempdir");
    let audit_path = audit_dir.path().join("audit.jsonl");
    let mut options = rimap_audit::AuditOptions::new(audit_path.clone());
    // Deliberately not `Seq::FIRST`: the assertions below join `tool_end`
    // to `tool_start` on `seq`, and with the default start every record
    // in this test would be seq 1 — so a guard that hardcoded
    // `Seq::FIRST` instead of carrying the real seq would still pass.
    options.initial_seq = Seq(41);
    let audit = rimap_audit::AuditWriter::open(&options).expect("audit open");

    let registry =
        rimap_server::boot::registry::AccountRegistry::new(std::collections::BTreeMap::new());
    let (cancellation_sender, cancellation_rx) = rimap_audit::cancellation_channel();
    let drainer = spawn_drainer(cancellation_rx, audit.clone());
    let server = Arc::new(rimap_server::mcp::server::ImapMcpServer::new(
        registry,
        audit,
        cancellation_sender,
    ));

    // Use a never-resolving body so the abort reliably lands mid-body.
    // Real infrastructure tools (ListAccounts) complete synchronously —
    // no yield point exists between guard creation and `guard.disarm()`,
    // so aborting at a yield point always lands outside the guarded
    // window. A body that never resolves guarantees the abort fires while
    // the body is suspended, which is exactly the state where
    // `AuditEnvelopeGuard::drop` must enqueue the cancellation `tool_end`.
    //
    // The invariant: every `tool_start` must be paired with a `tool_end`.
    // Aborting mid-body exercises the cancellation path: the guard's
    // `Drop` fires and enqueues the `tool_end` via the drainer channel.
    // A bad refactor that disarms the guard ABOVE `body(ticket).await`
    // breaks this: the `Drop` is a no-op, no `tool_end` is enqueued,
    // and counts diverge.
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let server_clone = Arc::clone(&server);
    let task = tokio::spawn(async move {
        server_clone
            .run_envelope_with_body_for_test(
                ToolName::ListAccounts,
                body_signalling_first_poll(entered_tx),
            )
            .await
    });

    // Wait for the body's first poll rather than for a clock. This orders
    // the abort strictly after `tool_start` is written and the guard is
    // armed, so no amount of host load can make the abort land early
    // (#684 — the previous 50ms sleep was a race window, not a barrier).
    //
    // A dropped sender (e.g. `emit_tool_start` returned `Err`) already fails
    // this fast. The outer timeout only covers the envelope *hanging* before
    // the body: it is a bound on failure reporting, never on the barrier
    // itself, so unlike the old sleep it cannot expire during a healthy run.
    tokio::time::timeout(std::time::Duration::from_secs(30), entered_rx)
        .await
        .expect("tool body was never polled within 30s")
        .expect("envelope dropped the body without ever polling it");
    task.abort();
    let _ = task.await; // wait for the abort to settle

    // No sleep needed before the drain: dropping `server` closes the last
    // cancellation sender, and `drainer.await` below then observes channel
    // close only after every queued record has been written.
    drop(server);
    // Await the drainer after dropping server (which drops the last sender)
    // so it exits cleanly after flushing remaining records.
    drainer.await.expect("drainer task should not panic");

    let records = read_audit_records(&audit_path);

    // Pin exact counts, not just equality: `starts == ends` alone would also
    // hold for a double-emitted `tool_end`, and equality plus a `>= 1` floor
    // still says nothing about *which* `tool_end` was written.
    let starts: Vec<_> = records
        .iter()
        .filter(|r| r["kind"] == "tool_start")
        .collect();
    let ends: Vec<_> = records.iter().filter(|r| r["kind"] == "tool_end").collect();
    assert_eq!(
        starts.len(),
        1,
        "expected exactly one tool_start; records={records:#?}",
    );
    assert_eq!(
        ends.len(),
        1,
        "expected exactly one tool_end; records={records:#?}",
    );

    // The `tool_end` must be the guard's synthetic cancellation record, and
    // it must be joined to the `tool_start` this dispatch actually wrote.
    // Without these a `tool_end` from any other path would satisfy the counts.
    let (start, end) = (starts[0], ends[0]);
    assert_eq!(
        end["status"], "cancelled",
        "tool_end must record the cancellation, not a normal completion; end={end:#?}",
    );
    assert_eq!(
        end["error_code"], "ERR_CANCELLED",
        "cancellation tool_end must carry ERR_CANCELLED; end={end:#?}",
    );
    assert_eq!(
        end["start_seq"], start["seq"],
        "tool_end.start_seq must reference this dispatch's tool_start.seq; \
         start={start:#?} end={end:#?}",
    );
    assert_eq!(
        start["tool"], "list_accounts",
        "the envelope under test is the list_accounts dispatch; start={start:#?}",
    );
    assert_eq!(
        end["tool"], "list_accounts",
        "tool_end duplicates the tool name so the line stands alone; end={end:#?}",
    );
}
