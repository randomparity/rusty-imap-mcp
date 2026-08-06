//! End-to-end check of the runner over a tiny synthesized corpus.
#![expect(clippy::unwrap_used, reason = "tests")]

use std::process::Command;

#[test]
fn runner_greens_on_benign_corpus_and_writes_report() {
    let tmp = tempfile::tempdir().unwrap();
    // Minimal fuzz seed that both engines agree on.
    let seed_dir = tmp.path().join("fuzz/corpus/content_html");
    std::fs::create_dir_all(&seed_dir).unwrap();
    std::fs::write(seed_dir.join("hello"), b"<p>hello world</p>").unwrap();

    let report = tmp.path().join("report.json");
    let status = Command::new(env!("CARGO_BIN_EXE_html-oracle"))
        .arg("--repo-root")
        .arg(tmp.path())
        .arg("--report")
        .arg(&report)
        .status()
        .unwrap();
    assert!(status.success(), "benign corpus must exit 0");

    let text = std::fs::read_to_string(&report).unwrap();
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(json["totals"]["hard"], 0);
    assert!(json["totals"]["compared_nonempty"].as_u64().unwrap() >= 1);
}

/// Minimal repo tree with one in-repo seed so the global run is never inert.
fn seeded_repo() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    let seed = tmp.path().join("fuzz/corpus/content_html");
    std::fs::create_dir_all(&seed).unwrap();
    std::fs::write(seed.join("hello"), b"<p>hello world</p>").unwrap();
    tmp
}

#[test]
fn reports_corpus_prefixed_counts() {
    let tmp = seeded_repo();
    let corpus = tmp.path().join("corpus");
    std::fs::create_dir_all(&corpus).unwrap();
    std::fs::write(
        corpus.join("c1.eml"),
        "Content-Type: text/html; charset=utf-8\r\n\r\n<p>alpha beta</p>\r\n",
    )
    .unwrap();
    std::fs::write(corpus.join("c1.meta.toml"), "probes = []\n").unwrap();

    let report = tmp.path().join("report.json");
    let status = Command::new(env!("CARGO_BIN_EXE_html-oracle"))
        .args(["--repo-root"])
        .arg(tmp.path())
        .args(["--corpus-root"])
        .arg(&corpus)
        .args(["--report"])
        .arg(&report)
        .status()
        .unwrap();
    assert!(status.success());

    let json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&report).unwrap()).unwrap();
    assert_eq!(json["corpus"]["total"], 1);
    assert_eq!(json["corpus"]["compared_nonempty"], 1);
    assert_eq!(json["corpus"]["skipped"], 0);
}

#[test]
fn corpus_min_compared_above_actual_fails() {
    let tmp = seeded_repo();
    let corpus = tmp.path().join("corpus");
    std::fs::create_dir_all(&corpus).unwrap();
    std::fs::write(
        corpus.join("c1.eml"),
        "Content-Type: text/html; charset=utf-8\r\n\r\n<p>alpha</p>\r\n",
    )
    .unwrap();
    std::fs::write(corpus.join("c1.meta.toml"), "probes = []\n").unwrap();

    let report = tmp.path().join("report.json");
    let status = Command::new(env!("CARGO_BIN_EXE_html-oracle"))
        .args(["--repo-root"])
        .arg(tmp.path())
        .args(["--corpus-root"])
        .arg(&corpus)
        .args(["--corpus-min-compared", "99"])
        .args(["--report"])
        .arg(&report)
        .status()
        .unwrap();
    assert!(!status.success(), "floor breach must fail the run");
}

#[test]
fn empty_corpus_plumbing_proof_greens() {
    // Mirrors the nightly's step-2 empty-but-valid corpus, floor flag absent.
    let tmp = seeded_repo();
    let corpus = tmp.path().join("corpus"); // empty tree
    std::fs::create_dir_all(&corpus).unwrap();

    let report = tmp.path().join("report.json");
    let status = Command::new(env!("CARGO_BIN_EXE_html-oracle"))
        .args(["--repo-root"])
        .arg(tmp.path())
        .args(["--corpus-root"])
        .arg(&corpus)
        .args(["--report"])
        .arg(&report)
        .status()
        .unwrap();
    assert!(status.success(), "empty corpus + no floor must green");
    let json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&report).unwrap()).unwrap();
    assert_eq!(json["corpus"]["total"], 0);
}

/// A run that loads nothing at all must fail, not green.
///
/// `corpus::load` treats a missing input directory as "not an error", so a
/// refactor that moves or renames `fuzz/corpus/content_html` and
/// `tests/injection-corpus` would leave the oracle comparing zero inputs and
/// exiting 0. That was survivable while the oracle ran only in the nightly
/// behind a `--corpus-min-compared` floor; the PR gate added in #699 carries no
/// floor, so the inert check is the only thing standing between this crate and
/// exactly the vacuously-green check the gate exists to abolish.
#[test]
fn empty_repo_root_fails_rather_than_greening() {
    let tmp = tempfile::tempdir().unwrap(); // deliberately *not* seeded
    // `--report` into the tempdir, like every test above: the default path is
    // `html-oracle/report.json` in the source tree, which would clobber a real
    // report and, in CI, leave an all-zeros one for the failure-upload step.
    let out = Command::new(env!("CARGO_BIN_EXE_html-oracle"))
        .args(["--repo-root"])
        .arg(tmp.path())
        .args(["--report"])
        .arg(tmp.path().join("report.json"))
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "a run with zero comparable inputs must fail, not green"
    );
    // Pin *why* it failed — `!success()` alone would also pass for a report
    // write error or an allowlist parse error, neither of which is this test.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("oracle inert"),
        "expected the inert diagnostic, got: {stderr}"
    );
}
