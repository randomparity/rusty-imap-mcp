//! Integration tests for the `fail_open` escape hatch on `AuditWriter`.

#![cfg(unix)]
#![expect(clippy::unwrap_used, reason = "tests")]

use std::os::unix::fs::PermissionsExt;

use rimap_audit::record::{AuditRecord, Payload, ProcessEnd, ProcessEndReason};
use rimap_audit::{AuditOptions, AuditWriter};
use rimap_audit::{ProcessId, Seq, Timestamp};
use tempfile::TempDir;

fn make_record(seq: u64) -> AuditRecord {
    AuditRecord {
        seq: Seq(seq),
        ts: Timestamp::now(),
        process_id: ProcessId::new_now(),
        payload: Payload::ProcessEnd(ProcessEnd {
            reason: ProcessEndReason::Eof,
            total_tool_calls: seq,
        }),
    }
}

fn lock_parent_readonly(parent: &std::path::Path) {
    let mut perms = std::fs::metadata(parent).unwrap().permissions();
    perms.set_mode(0o500); // r-x------
    std::fs::set_permissions(parent, perms).unwrap();
}

fn unlock_parent(parent: &std::path::Path) {
    let mut perms = std::fs::metadata(parent).unwrap().permissions();
    perms.set_mode(0o700);
    std::fs::set_permissions(parent, perms).unwrap();
}

#[test]
fn fail_open_false_propagates_rotation_failure() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("audit.jsonl");
    let writer = AuditWriter::open(&AuditOptions {
        path: path.clone(),
        rotate_bytes: 10,
        rotate_keep: 5,
        retention_seconds: None,
        fail_open: false,
        initial_seq: Seq::FIRST,
    })
    .unwrap();

    lock_parent_readonly(dir.path());

    let r1 = writer.write_record(&make_record(1));
    let r2 = writer.write_record(&make_record(2));

    unlock_parent(dir.path());

    assert!(
        r1.is_err() || r2.is_err(),
        "expected at least one write to fail with fail_open=false"
    );
    assert_eq!(writer.suppressed_failures(), 0);
}

#[test]
fn fail_open_true_suppresses_rotation_failure_and_counts_it() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("audit.jsonl");
    let writer = AuditWriter::open(&AuditOptions {
        path: path.clone(),
        rotate_bytes: 10,
        rotate_keep: 5,
        retention_seconds: None,
        fail_open: true,
        initial_seq: Seq::FIRST,
    })
    .unwrap();

    lock_parent_readonly(dir.path());

    let r1 = writer.write_record(&make_record(1));
    let r2 = writer.write_record(&make_record(2));

    unlock_parent(dir.path());

    assert!(r1.is_ok());
    assert!(r2.is_ok());
    assert!(
        writer.suppressed_failures() >= 1,
        "expected suppressed_failures >= 1, got {}",
        writer.suppressed_failures()
    );
}
