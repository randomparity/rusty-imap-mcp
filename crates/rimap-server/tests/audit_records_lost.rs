//! Pin that a record the writer failed to persist and told no caller about
//! reaches the durable audit trail, as `process_end.records_lost`.
//!
//! Before this, `AuditWriter::suppressed_failures` was readable in-process
//! only: an operator reading the JSONL saw a complete-looking record stream
//! with a silent hole in it. Issue: #647.
//!
//! Assertions read the raw JSONL rather than going through `reader`, which is
//! lenient by design (see `crates/rimap-audit/tests/partial_line.rs`) and
//! would happily default a missing field back to zero.

#![expect(clippy::unwrap_used, reason = "tests")]
#![expect(clippy::expect_used, reason = "tests")]
#![expect(clippy::panic, reason = "test diagnostics")]

#[path = "support/mod.rs"]
mod support;

use rimap_audit::record::{ProcessEnd, ProcessEndReason};
use rimap_audit::{AuditOptions, AuditWriter, Seq, ToolStartInputs};
use rimap_core::tool::ToolName;
use tempfile::tempdir;

fn open_writer(path: std::path::PathBuf, fail_open: bool) -> AuditWriter {
    AuditWriter::open(&AuditOptions {
        path,
        rotate_bytes: 10 * 1024 * 1024,
        rotate_keep: 5,
        retention_seconds: None,
        fail_open,
        initial_seq: Seq::FIRST,
    })
    .unwrap()
}

fn tool_start_inputs() -> ToolStartInputs {
    let mut inputs = ToolStartInputs::new(
        ToolName::Search,
        serde_json::Value::Object(serde_json::Map::new()),
        "0".repeat(64),
    );
    inputs.account = Some("test".to_string());
    inputs.posture_effective = Some(rimap_core::Posture::Readonly);
    inputs
}

/// The one `process_end` line in `path`, as raw text.
fn process_end_line(path: &std::path::Path) -> String {
    let contents = std::fs::read_to_string(path).unwrap();
    let mut lines = contents
        .lines()
        .filter(|line| line.contains(r#""kind":"process_end""#));
    let line = lines.next().expect("a process_end line must be on disk");
    assert!(lines.next().is_none(), "expected exactly one process_end");
    line.to_string()
}

/// Mirrors `rimap-server`'s `emit_process_end`: the counters are read off the
/// writer at shutdown and stamped into the record.
fn emit_process_end(writer: &AuditWriter) {
    let end = ProcessEnd::new(
        ProcessEndReason::Eof,
        writer.total_tool_calls(),
        writer.suppressed_failures(),
    );
    writer.log_process_end(end).unwrap();
}

#[test]
fn suppressed_write_failure_reaches_process_end() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let writer = open_writer(path.clone(), true);

    // fail_open = true: the write failure is swallowed, counted, and the
    // caller is told nothing.
    writer.force_next_write_failure();
    writer.log_tool_start(tool_start_inputs()).unwrap();
    assert_eq!(writer.suppressed_failures(), 1);

    emit_process_end(&writer);

    let line = process_end_line(&path);
    assert!(
        line.contains(r#""records_lost":1"#),
        "process_end must carry the lost-record count; got: {line}",
    );
}

#[test]
fn clean_run_records_zero_lost() {
    // The field is always present, so "no records lost" is stated rather than
    // inferred from absence — a reader cannot otherwise distinguish a clean
    // run from a writer that predates the field.
    let dir = tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let writer = open_writer(path.clone(), true);

    writer.log_tool_start(tool_start_inputs()).unwrap();
    emit_process_end(&writer);

    let line = process_end_line(&path);
    assert!(
        line.contains(r#""records_lost":0"#),
        "process_end must state a zero count explicitly; got: {line}",
    );
}

#[test]
fn old_process_end_without_records_lost_still_parses() {
    // The on-disk shape predating #647 must keep deserializing: `records_lost`
    // is `#[serde(default)]`. Pins the compatibility promise that
    // `fuzz/corpus/audit_jsonl/process_end.jsonl` also depends on.
    let old = r#"{"seq":2,"ts":"2026-05-05T12:00:00.000Z","process_id":"01HM0000000000000000000000","kind":"process_end","reason":"eof","total_tool_calls":3}"#;

    let record: rimap_audit::record::AuditRecord = serde_json::from_str(old).unwrap();
    let rimap_audit::record::Payload::ProcessEnd(end) = record.payload else {
        panic!("expected a process_end payload");
    };
    assert_eq!(end.total_tool_calls, 3);
    assert_eq!(end.records_lost, 0);
}

/// Zero-account config with `fail_open = true`, so an armed write failure is
/// swallowed and counted rather than propagated to the caller.
fn write_fail_open_config(tempdir: &tempfile::TempDir) -> std::path::PathBuf {
    let config_path = tempdir.path().join("config.toml");
    let config = format!(
        r#"
accounts = []

[audit]
path = "{audit}"
allowed_base_dir = "{base}"
fail_open = true
"#,
        audit = tempdir.path().join("audit.jsonl").display(),
        base = tempdir.path().display(),
    );
    std::fs::write(&config_path, config).expect("write config");
    config_path
}

/// End-to-end through the production binary: the count reaches the file via
/// `main.rs::emit_process_end`, not via a test that re-implements it.
///
/// `RIMAP_TEST_FORCE_NEXT_AUDIT_WRITE_FAILURE` arms the real `AuditWriter` at
/// boot; the next write is `tool_start` for the `list_accounts` call below.
/// With `fail_open = true` the server answers normally and the loss shows up
/// only in `process_end`, which is the hole this test exists to close.
#[tokio::test]
async fn process_end_reports_records_lost_end_to_end() {
    let tempdir = tempfile::TempDir::new().expect("tempdir");
    let config_path = write_fail_open_config(&tempdir);

    let mut harness = support::wire::harness::Harness::spawn_with_config(
        &config_path,
        tempdir,
        &[("RIMAP_TEST_FORCE_NEXT_AUDIT_WRITE_FAILURE", "1")],
    )
    .await;

    let _ = harness.initialize_handshake().await;
    harness.send_initialized().await;
    let response = harness
        .request(
            "tools/call",
            serde_json::json!({ "name": "list_accounts", "arguments": {} }),
        )
        .await;
    assert!(
        response.get("error").is_none(),
        "fail_open=true must keep the call succeeding: {response}",
    );

    let audit_path = harness.audit_path();
    let (status, _tempdir) = harness.shutdown_and_wait().await;
    assert!(status.success(), "server exited {status}");

    let line = process_end_line(&audit_path);
    let parsed: serde_json::Value = serde_json::from_str(&line).expect("process_end is JSON");
    assert_eq!(
        parsed["records_lost"], 1,
        "the suppressed tool_start write must be reported in process_end: {line}",
    );
}
