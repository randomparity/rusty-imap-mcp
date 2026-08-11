//! Integration test for rotation-under-lock. Crosses the rotation boundary
//! multiple times and asserts no record loss, plus that the lock remains
//! held after each rotation.

#![expect(clippy::unwrap_used, reason = "tests")]
#![expect(clippy::panic, reason = "tests")]

use std::collections::BTreeSet;

use rimap_audit::{
    AuditError, AuditOptions, AuditRecord, AuditWriter, Payload, ProcessEnd, ProcessEndReason,
    ProcessId, Seq, Timestamp,
};
use tempfile::TempDir;

fn record(seq: u64) -> AuditRecord {
    AuditRecord::new(
        Seq(seq),
        Timestamp::now(),
        ProcessId::new_now(),
        Payload::ProcessEnd(ProcessEnd::new(ProcessEndReason::Eof, seq, 0, 0, 0)),
    )
}

const N: u64 = 25;

#[test]
fn writes_survive_multiple_rotations() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("audit.jsonl");
    let mut options = AuditOptions::new(path.clone(), Seq::FIRST);
    options.rotate_bytes = 300;
    options.rotate_keep = 50;
    let writer = AuditWriter::open(&options).unwrap();
    for seq in 1..=N {
        writer.write_record(&record(seq)).unwrap();
    }
    drop(writer);

    // Gather every `audit.jsonl*` file in the directory.
    let mut all = String::new();
    for entry in std::fs::read_dir(dir.path()).unwrap() {
        let entry = entry.unwrap();
        let p = entry.path();
        if p.file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("audit.jsonl")
        {
            all.push_str(&std::fs::read_to_string(&p).unwrap());
        }
    }

    let seen: BTreeSet<u64> = all
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter_map(|v| v.get("seq").and_then(serde_json::Value::as_u64))
        .collect();
    assert_eq!(seen, (1..=N).collect::<BTreeSet<_>>());
}

#[test]
fn lock_persists_across_rotations() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("audit.jsonl");
    let mut options = AuditOptions::new(path.clone(), Seq::FIRST);
    options.rotate_bytes = 300;
    options.rotate_keep = 5;
    let writer = AuditWriter::open(&options).unwrap();
    for seq in 1_u64..=10 {
        writer.write_record(&record(seq)).unwrap();
    }

    let err = AuditWriter::open(&AuditOptions::new(path.clone(), Seq::FIRST)).unwrap_err();
    match err {
        AuditError::Locked { .. } => {}
        other => panic!("expected Locked, got {other:?}"),
    }
}
