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
