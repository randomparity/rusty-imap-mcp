//! AC1 enforcement (issue #528): every `e2e_wire*.rs` suite references the canary
//! sweep, and every `#[tokio::test]` region within one calls a sweep of its own,
//! so no single test can spawn a harness without sweeping. Source-text check;
//! host-runnable, no container.
//!
//! # Why the glob stops at `crates/rimap-server/tests/e2e_wire*.rs`
//!
//! A scope choice from #528 — and, for the one escape found outside it, these
//! sweeps would not have helped anyway. That escape was issue #750:
//! `crates/rimap-imap/tests/adversarial_imap.rs` printed the fake's recorded
//! dialog, plaintext `LOGIN` frame and all, on its *passing* path.
//!
//! Neither sweep reads the channel it escaped through. `canary::assert_absent`
//! walks files under the roots it is handed plus explicit `extra` strings;
//! `canary::assert_login_frame_only` walks the fake's `recorded()` vector. The
//! #750 dump went to the test process's **stderr** via `eprintln!`, which
//! `--success-output final` (PR #746) then retained in the CI log. A canary
//! planted in that very test would have sailed through both.
//!
//! So do not read this glob as a promise that files outside it are unreachable
//! — `crates/rimap-imap/tests/` is not canary-free (it holds the source of
//! truth for `canary::DOVECOT_CANARY_PASSWORD`, and its `integration/` targets
//! spawn containers), and `FakeImapServer::connection_with` takes an arbitrary
//! resolver, so a fake-backed suite there *could* plant one. Widening would be
//! cross-crate — `tests_dir()` is this crate's `CARGO_MANIFEST_DIR` — and would
//! still miss a stderr dump.
//!
//! What catches a dump of that shape is a `DumpOnPanic` guard: gate the print
//! on `std::thread::panicking()` so it renders only when the test is already
//! failing. The fake-backed suites under this glob use one, and
//! `adversarial_imap.rs` now does too. Any new dialog dump needs that guard,
//! inside this glob or outside it — these sweeps will not catch it for you.
// Only `unwrap_used` is expected — this file uses `.unwrap()` and `assert!`
// (which is not clippy::panic). A `panic` expectation here would be unfulfilled.
#![expect(clippy::unwrap_used, reason = "test")]

use std::path::PathBuf;

fn tests_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests")
}

fn wire_suite_sources() -> Vec<(String, String)> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(tests_dir().join("wire")).unwrap() {
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
