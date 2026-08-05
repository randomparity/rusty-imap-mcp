//! Pin that the shutdown drain's residue reaches the durable audit trail, as
//! `process_end.undrained_dispatches`.
//!
//! Before this, `DispatchDrain::shutdown`'s `#[must_use]` count went to a
//! `tracing::warn!` in `serve_mcp` and nowhere else. Stderr is the one channel
//! an MCP client routinely discards, so a reader holding only the audit file
//! could not distinguish a run that drained cleanly from one that left
//! dispatches running past `process_end` — precisely the state that makes the
//! terminal-record rule unreliable for that run. Issue: #680.
//!
//! The *non-zero* case needs a dispatch parked past the drain budget, which
//! costs a fake IMAP server; it lives with the rest of that machinery in
//! `e2e_wire_shutdown_audit_ordering.rs`. What is here is the pair that needs no
//! fake: a clean run states its zero, and a line written before the field
//! existed still parses.
//!
//! Assertions read the raw JSONL rather than going through `reader`, which is
//! lenient by design and would happily default a missing field back to zero —
//! the same reasoning as `audit_records_lost.rs`.

#![expect(clippy::expect_used, reason = "integration tests")]
#![expect(clippy::panic, reason = "test diagnostics")]

#[path = "support/mod.rs"]
mod support;

/// The one `process_end` line in `path`, as raw text.
///
/// A near-copy of the same helper in `audit_records_lost.rs`. Each integration
/// test is its own crate, so the two cannot share a private fn; hoisting it into
/// `support/` would compile it into every suite that includes the module and
/// need a dead-code suppression in each. Nine lines duplicated is the cheaper
/// side of that trade.
fn process_end_line(path: &std::path::Path) -> String {
    let contents = std::fs::read_to_string(path).expect("read audit log");
    let mut lines = contents
        .lines()
        .filter(|line| line.contains(r#""kind":"process_end""#));
    let line = lines.next().expect("a process_end line must be on disk");
    assert!(lines.next().is_none(), "expected exactly one process_end");
    line.to_string()
}

/// A run with nothing in flight at shutdown must *state* its zero rather than
/// omit it. Absence is what a pre-#680 writer produces, so a reader cannot tell
/// the two apart unless the field is always present.
#[tokio::test]
async fn a_clean_shutdown_records_zero_undrained_end_to_end() {
    // `Harness::spawn` is the zero-account config: enough to boot the binary,
    // answer `list_accounts`, and shut down with no IMAP connection at all.
    let mut harness = support::wire::harness::Harness::spawn().await;
    let _ = harness.initialize_handshake().await;
    harness.send_initialized().await;
    let response = harness
        .request(
            "tools/call",
            serde_json::json!({ "name": "list_accounts", "arguments": {} }),
        )
        .await;
    assert!(response.get("error").is_none(), "list_accounts: {response}");

    let audit_path = harness.audit_path();
    let (status, _tempdir) = harness.shutdown_and_wait().await;
    assert!(status.success(), "server exited {status}");

    let line = process_end_line(&audit_path);
    let parsed: serde_json::Value = serde_json::from_str(&line).expect("process_end is JSON");
    assert_eq!(
        parsed["undrained_dispatches"], 0,
        "a clean shutdown must state a zero residue explicitly: {line}",
    );
}

#[test]
fn an_old_process_end_without_the_field_still_parses() {
    // The on-disk shape predating #680 must keep deserializing:
    // `undrained_dispatches` is `#[serde(default)]`. Pins the compatibility
    // promise `fuzz/corpus/audit_jsonl/process_end.jsonl` also depends on.
    let old = r#"{"seq":2,"ts":"2026-05-05T12:00:00.000Z","process_id":"01HM0000000000000000000000","kind":"process_end","reason":"eof","total_tool_calls":3,"records_lost":1}"#;

    let record: rimap_audit::record::AuditRecord =
        serde_json::from_str(old).expect("pre-#680 line parses");
    let rimap_audit::record::Payload::ProcessEnd(end) = record.payload else {
        panic!("expected a process_end payload");
    };
    assert_eq!(end.total_tool_calls, 3);
    assert_eq!(end.records_lost, 1);
    assert_eq!(end.undrained_dispatches, 0);
}
