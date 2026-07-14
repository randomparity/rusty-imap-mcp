//! AC1 enforcement (issue #528): every `e2e_wire*.rs` suite references the canary
//! sweep, and per file its `assert_absent` count is >= its `#[tokio::test]`
//! count so no single test can spawn a harness without sweeping. Source-text
//! check; host-runnable, no container.
// Only `unwrap_used` is expected — this file uses `.unwrap()` and `assert!`
// (which is not clippy::panic). A `panic` expectation here would be unfulfilled.
#![expect(clippy::unwrap_used, reason = "test")]

use std::path::PathBuf;

fn tests_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests")
}

fn wire_suite_sources() -> Vec<(String, String)> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(tests_dir()).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let is_rs = path
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("rs"));
        if name.starts_with("e2e_wire") && is_rs {
            let text = std::fs::read_to_string(&path).unwrap();
            out.push((name, text));
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

#[test]
fn every_wire_suite_references_the_sweep() {
    let suites = wire_suite_sources();
    assert!(!suites.is_empty(), "expected e2e_wire*.rs suites to exist");
    let mut missing = Vec::new();
    for (name, text) in &suites {
        let refs_sweep = text.contains("canary::assert_absent")
            || text.contains("canary::assert_login_frame_only");
        if !refs_sweep {
            missing.push(name.clone());
        }
    }
    assert!(
        missing.is_empty(),
        "these e2e_wire*.rs suites do not reference the canary sweep: {missing:?}",
    );
}

#[test]
fn each_test_sweeps_once() {
    // Per-test coverage floor: every `#[tokio::test]` in a wire suite drives a
    // harness and must sweep once. Require `assert_absent` count >= the number of
    // `#[tokio::test]` fns. The `#[tokio::test]` denominator is per-test — unlike
    // a raw spawn count it does NOT collapse when several tests spawn through a
    // shared helper (cancellation=2 tests/1 spawn, uidvalidity=3/1, chaos=5/1),
    // and unlike a `shutdown_and_wait` count it is not inflated by comments.
    // `assert_absent` is called exactly once per swept test in every backend, so
    // this is an exact 1:1 (fake suites also call `assert_login_frame_only`,
    // which is intentionally NOT counted to keep the ratio exact).
    let mut offenders = Vec::new();
    for (name, text) in wire_suite_sources() {
        let tests = text.matches("#[tokio::test").count();
        let sweeps = text.matches("assert_absent").count();
        if sweeps < tests {
            offenders.push(format!(
                "{name}: {sweeps} assert_absent < {tests} #[tokio::test]"
            ));
        }
    }
    assert!(
        offenders.is_empty(),
        "a harness-driving test lacks a canary sweep in:\n{}",
        offenders.join("\n"),
    );
}
