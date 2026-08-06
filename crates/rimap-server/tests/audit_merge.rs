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
        let writer = AuditWriter::open(&AuditOptions::new(path.clone(), Seq::FIRST)).unwrap();
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
        let writer = AuditWriter::open(&AuditOptions::new(path.clone(), Seq::FIRST)).unwrap();
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

/// Run `audit merge` over `lines` written verbatim, one per line.
fn merge_raw_lines(dir: &TempDir, lines: &[&str]) -> std::process::Output {
    let path = dir.path().join("audit.jsonl");
    std::fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();
    Command::cargo_bin("rusty-imap-mcp")
        .unwrap()
        .arg("audit")
        .arg("merge")
        .arg(&path)
        .output()
        .unwrap()
}

const PID: &str = "01JXAAAAAAAAAAAAAAAAAAAAAA";

fn known_line(seq: u64) -> String {
    format!(
        r#"{{"seq":{seq},"ts":"2026-04-07T14:22:0{seq}.000Z","process_id":"{PID}","kind":"process_end","reason":"eof","total_tool_calls":0}}"#
    )
}

/// The #717 scenario at the operator's shell: a file holding a record kind a
/// later version invented. The merge must succeed, carry the records this
/// binary understood on stdout, and say on stderr that it read past one — the
/// count is the only trace, since the unknown record is absent from stdout.
#[test]
fn audit_merge_skips_unknown_kinds_and_reports_the_count_on_stderr() {
    let dir = TempDir::new().unwrap();
    let future = format!(
        r#"{{"seq":2,"ts":"2026-04-07T14:22:02.000Z","process_id":"{PID}","kind":"policy","rule":"deny-all"}}"#
    );
    let out = merge_raw_lines(&dir, &[&known_line(1), &future, &known_line(3)]);

    assert!(
        out.status.success(),
        "an unknown kind must not fail the merge: stderr={}",
        String::from_utf8_lossy(&out.stderr),
    );

    let stdout = String::from_utf8(out.stdout).unwrap();
    let seqs: Vec<u64> = stdout
        .lines()
        .map(|l| {
            serde_json::from_str::<serde_json::Value>(l).unwrap()["seq"]
                .as_u64()
                .unwrap()
        })
        .collect();
    assert_eq!(seqs, vec![1, 3], "the records either side must survive");

    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("skipped 1 record(s) of an unrecognized kind"),
        "the skip must be operator-visible on stderr, got: {stderr}",
    );
}

/// The other half, and the one that must not regress: a line malformed for a
/// reason *other* than an unrecognized kind still fails the merge. Here the
/// `kind` is one this binary knows and the payload will not deserialize, so
/// tolerating it would mean hiding real corruption.
#[test]
fn audit_merge_still_fails_on_a_line_malformed_for_another_reason() {
    let dir = TempDir::new().unwrap();
    let corrupt = format!(
        r#"{{"seq":1,"ts":"2026-04-07T14:22:01.000Z","process_id":"{PID}","kind":"auth"}}"#
    );
    let out = merge_raw_lines(&dir, &[&corrupt, &known_line(2)]);

    assert!(
        !out.status.success(),
        "a corrupt known-kind line must still fail the merge",
    );
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("line 1"),
        "the failure must name the offending line, got: {stderr}",
    );
}
