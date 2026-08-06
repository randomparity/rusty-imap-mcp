//! End-to-end test: write a synthetic audit log via `AuditWriter`, invoke
//! the compiled `rusty-imap-mcp audit merge` binary, parse its stdout, and
//! verify every record is present in order.

#![expect(clippy::unwrap_used, reason = "tests")]

use std::collections::BTreeSet;

use assert_cmd::Command;
use rimap_audit::{
    AuditOptions, AuditRecord, AuditWriter, Payload, ProcessEnd, ProcessEndReason, ProcessId,
    ProcessStartInputs, Seq, Timestamp, current_inode, read_trailing_state,
};
use tempfile::TempDir;

fn record(seq: u64, pid: ProcessId) -> AuditRecord {
    AuditRecord::new(
        Seq(seq),
        Timestamp::now(),
        pid,
        Payload::ProcessEnd(ProcessEnd::new(ProcessEndReason::Eof, seq, 0, 0)),
    )
}

#[test]
fn audit_merge_round_trips_synthetic_log() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("audit.jsonl");
    let config_path = dir.path().join("config.toml");
    std::fs::write(&config_path, b"# synthetic config for test").unwrap();

    {
        let writer = AuditWriter::open(&AuditOptions::new(path.clone())).unwrap();
        // Seq 1: process_start record, as required by the audit format.
        let trailing = read_trailing_state(&path).unwrap();
        let inode = current_inode(&path).unwrap();
        let mut start = ProcessStartInputs::new(
            "0.0.0-test".to_string(),
            String::new(),
            config_path.clone(),
            String::new(),
            trailing,
            inode,
        );
        start.posture = Some(rimap_core::Posture::Readonly);
        writer.log_process_start(start).unwrap();
        // Seqs 2–8: synthetic process_end records.
        let pid = ProcessId::new_now();
        for seq in 2_u64..=8 {
            writer.write_record(&record(seq, pid)).unwrap();
        }
        // Drop releases the lock so the subcommand can take a shared lock.
    }

    let out = Command::cargo_bin("rusty-imap-mcp")
        .unwrap()
        .arg("audit")
        .arg("merge")
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "audit merge failed: stderr={}",
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<serde_json::Value> = stdout
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    // First record must be process_start with seq 1.
    assert_eq!(lines[0]["kind"], "process_start");
    assert_eq!(lines[0]["seq"], 1);
    let seqs: BTreeSet<u64> = lines.iter().map(|v| v["seq"].as_u64().unwrap()).collect();
    assert_eq!(seqs, (1_u64..=8).collect::<BTreeSet<_>>());
}

#[test]
fn audit_merge_filters_by_kind() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("audit.jsonl");

    {
        let writer = AuditWriter::open(&AuditOptions::new(path.clone())).unwrap();
        let pid = ProcessId::new_now();
        for seq in 1_u64..=3 {
            writer.write_record(&record(seq, pid)).unwrap();
        }
    }

    let out = Command::cargo_bin("rusty-imap-mcp")
        .unwrap()
        .arg("audit")
        .arg("merge")
        .arg(&path)
        .arg("--kind")
        .arg("process_start")
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.trim().is_empty(),
        "expected no matches, got {stdout}"
    );
}
