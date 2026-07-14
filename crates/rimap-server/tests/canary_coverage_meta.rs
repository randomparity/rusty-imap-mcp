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
fn each_test_body_sweeps() {
    // Per-test-BODY enforcement of the AC1 promise: no harness-driving test
    // spawns without sweeping. Partition each file on the `#[tokio::test]`
    // attribute and assert every test region calls a sweep. A whole-file count
    // (`assert_absent` >= `#[tokio::test]`) would pass if one test swept twice
    // while another skipped it — an aggregate that can rot green as suites are
    // copied. Partitioning closes that: each region must carry its own sweep.
    // The `#[tokio::test]` boundary is per-test and does not collapse under
    // shared spawn helpers. `split("#[tokio::test")` yields the module preamble
    // as element 0 (skipped), then one region per test up to the next attribute.
    let mut offenders = Vec::new();
    for (name, text) in wire_suite_sources() {
        for region in text.split("#[tokio::test").skip(1) {
            let sweeps = region.contains("canary::assert_absent")
                || region.contains("canary::assert_login_frame_only");
            if !sweeps {
                let sig = region
                    .lines()
                    .find(|l| l.contains("async fn"))
                    .map_or("<unknown fn>", str::trim);
                offenders.push(format!("{name}: {sig}"));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "these harness-driving tests do not call a canary sweep:\n{}",
        offenders.join("\n"),
    );
}
