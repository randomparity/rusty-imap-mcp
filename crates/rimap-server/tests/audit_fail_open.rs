//! Pin the `fail_open = true` propagation path: when an audit write fails and
//! the writer was configured with `fail_open = true`, calls that would normally
//! return an error instead return Ok, and the writer's `suppressed_failures`
//! counter increments.
//!
//! Issue: #72.

#![expect(clippy::unwrap_used, reason = "tests")]

use rimap_audit::{AuditOptions, AuditWriter, Seq, ToolStartInputs};
use rimap_core::tool::ToolName;
use tempfile::tempdir;

fn tool_start_inputs() -> ToolStartInputs {
    ToolStartInputs::new(
        ToolName::Search,
        Some("test".to_string()),
        Some(rimap_core::Posture::Readonly),
        serde_json::Value::Object(serde_json::Map::new()),
        "0".repeat(64),
    )
}

#[test]
fn fail_open_suppresses_write_failure_and_increments_counter() {
    let dir = tempdir().unwrap();
    let mut options = AuditOptions::new(dir.path().join("audit.jsonl"), Seq::FIRST);
    options.rotate_bytes = 10 * 1024 * 1024;
    options.rotate_keep = 5;
    options.fail_open = true;
    let writer = AuditWriter::open(&options).unwrap();

    // Inject one write failure. The next log_tool_start should encounter
    // AuditError::Write, which fail_open=true converts to Ok while
    // incrementing suppressed_failures.
    writer.force_next_write_failure();

    let result = writer.log_tool_start(tool_start_inputs());

    assert!(
        result.is_ok(),
        "fail_open=true should suppress the write failure, got: {result:?}",
    );
    assert_eq!(
        writer.suppressed_failures(),
        1,
        "suppressed_failures counter should have incremented once",
    );
}

#[test]
fn fail_open_false_propagates_write_failure() {
    // Symmetric control: fail_open=false propagates the write failure as
    // AuditError::Write. Not strictly required by #72 but pins the
    // complementary contract so a regression in either direction trips a
    // test.
    let dir = tempdir().unwrap();
    let mut options = AuditOptions::new(dir.path().join("audit.jsonl"), Seq::FIRST);
    options.rotate_bytes = 10 * 1024 * 1024;
    options.rotate_keep = 5;
    let writer = AuditWriter::open(&options).unwrap();

    writer.force_next_write_failure();

    let result = writer.log_tool_start(tool_start_inputs());

    assert!(
        result.is_err(),
        "fail_open=false should propagate the failure, got: {result:?}",
    );
    assert_eq!(
        writer.suppressed_failures(),
        0,
        "suppressed_failures counter should not have incremented",
    );
}
