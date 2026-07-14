//! Meta-test for the canary sweep (issue #528, AC2). Proves the sweep detects a
//! deliberately-seeded leak and stays clean on a leak-free tree. Host-runnable,
//! no container, PR-blocking.
// Only `unwrap_used` is expected: this file uses `.unwrap()` but no `.expect()`
// and no literal `panic!` (assert!/assert_eq!/#[should_panic] do NOT trigger
// clippy::panic). Declaring expect_used/panic here would be unfulfilled → error.
#![expect(clippy::unwrap_used, reason = "test")]

use std::path::Path;

use tempfile::TempDir;

#[path = "support/canary.rs"]
mod canary;

#[test]
fn scan_flags_a_seeded_file_leak() {
    let canary = canary::fresh_canary();
    let dir = TempDir::new().unwrap();
    let leaky = dir.path().join("audit.jsonl");
    std::fs::write(&leaky, format!("{{\"pw\":\"{canary}\"}}\n")).unwrap();

    let report = canary::scan(&canary, &[dir.path()], &[]);
    assert_eq!(report.errors.len(), 0, "no read errors expected");
    assert!(
        report.hits.iter().any(|h| h.source.contains("audit.jsonl")),
        "seeded leak must be reported, got {:?}",
        report.hits.iter().map(|h| &h.source).collect::<Vec<_>>(),
    );
}

#[test]
fn scan_flags_an_extra_string_leak() {
    let canary = canary::fresh_canary();
    let frame = format!("a1 LOGIN rimap-test {canary}\r\n");
    let report = canary::scan(&canary, &[], &[frame]);
    assert_eq!(report.hits.len(), 1, "extra-string leak must be reported");
}

#[test]
fn scan_is_clean_on_a_leak_free_tree() {
    let canary = canary::fresh_canary();
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("audit.jsonl"), b"{\"ok\":true}\n").unwrap();
    std::fs::write(dir.path().join("server.stderr.log"), b"info: ready\n").unwrap();
    std::fs::create_dir(dir.path().join("downloads")).unwrap();
    std::fs::write(
        dir.path().join("downloads/msg.eml"),
        b"Subject: hi\r\n\r\nbody",
    )
    .unwrap();

    let report = canary::scan(&canary, &[dir.path()], &[]);
    assert_eq!(report.hits.len(), 0, "no leak expected");
    assert_eq!(report.errors.len(), 0, "no read errors expected");
}

#[cfg(unix)]
#[test]
fn scan_reports_unreadable_artifact() {
    use std::os::unix::fs::PermissionsExt;

    let canary = canary::fresh_canary();
    let dir = TempDir::new().unwrap();
    let secret = dir.path().join("locked.log");
    std::fs::write(&secret, b"whatever").unwrap();
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o000)).unwrap();

    // Root can read a 0o000 file, so only assert the error path when the OS
    // actually denies the read (non-root). Keeps the test non-flaky under both.
    if std::fs::read(&secret).is_ok() {
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o644)).unwrap();
        return;
    }
    let report = canary::scan(&canary, &[dir.path()], &[]);
    assert!(
        report.errors.iter().any(|e| e.contains("locked.log")),
        "unreadable file must surface in errors, not be silently skipped: {:?}",
        report.errors,
    );
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o644)).unwrap();
}

#[test]
#[should_panic(expected = "canary sweep failed")]
fn assert_absent_panics_on_a_leak() {
    let canary = canary::fresh_canary();
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("stderr.log"), canary.as_bytes()).unwrap();
    canary::assert_absent(&canary, &[dir.path()], &[]);
}

#[test]
fn login_frame_only_accepts_canary_in_login() {
    let canary = canary::fresh_canary();
    let recorded = vec![
        "a1 CAPABILITY\r\n".to_string(),
        format!("a2 LOGIN rimap-test {canary}\r\n"),
        "a3 SELECT INBOX\r\n".to_string(),
    ];
    canary::assert_login_frame_only(&canary, &recorded);
}

#[test]
#[should_panic(expected = "non-LOGIN")]
fn login_frame_only_rejects_canary_outside_login() {
    let canary = canary::fresh_canary();
    let recorded = vec![
        format!("a2 LOGIN rimap-test {canary}\r\n"),
        format!("a3 APPEND INBOX {{10}}\r\n{canary}\r\n"),
    ];
    canary::assert_login_frame_only(&canary, &recorded);
}

#[test]
#[should_panic(expected = "positive control failed")]
fn login_frame_only_rejects_missing_login() {
    let canary = canary::fresh_canary();
    let recorded = vec!["a1 CAPABILITY\r\n".to_string()];
    canary::assert_login_frame_only(&canary, &recorded);
}

#[test]
#[should_panic(expected = "non-LOGIN")]
fn login_frame_predicate_matches_command_position_only() {
    let canary = canary::fresh_canary();
    // Command is SEARCH, not LOGIN, even though the arg contains "LOGIN".
    let recorded = vec![
        format!("a2 LOGIN rimap-test {canary}\r\n"),
        format!("a3 SEARCH SUBJECT \"LOGIN {canary}\"\r\n"),
    ];
    canary::assert_login_frame_only(&canary, &recorded);
}

#[test]
fn dovecot_sentinel_is_colon_free() {
    let p: &Path = Path::new(".");
    let _ = p;
    assert!(
        !canary::DOVECOT_CANARY_PASSWORD.contains(':'),
        "sentinel must be a valid passwd-file password",
    );
}
