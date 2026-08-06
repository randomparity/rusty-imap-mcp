//! Integration test for the reader's partial-trailing-line tolerance. The
//! scenario models a crash between `BufWriter::flush` attempts: a well-formed
//! prefix followed by a truncated last record.

#![expect(clippy::unwrap_used, reason = "tests")]

use std::io::Write;

use rimap_audit::{Filter, stream_records};
use tempfile::TempDir;

#[test]
fn partial_trailing_line_is_skipped() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("audit.jsonl");

    let good_a = r#"{"seq":1,"ts":"2026-04-07T14:22:01.000Z","process_id":"01JXAAAAAAAAAAAAAAAAAAAAAA","kind":"process_end","reason":"eof","total_tool_calls":0}"#;
    let good_b = r#"{"seq":2,"ts":"2026-04-07T14:22:02.000Z","process_id":"01JXAAAAAAAAAAAAAAAAAAAAAA","kind":"process_end","reason":"eof","total_tool_calls":1}"#;
    let bad = r#"{"seq":3,"ts":"2026-04-07T14:22:03.000Z","process"#;

    let mut f = std::fs::File::create(&path).unwrap();
    writeln!(f, "{good_a}").unwrap();
    writeln!(f, "{good_b}").unwrap();
    // Truncated: no trailing newline.
    write!(f, "{bad}").unwrap();
    drop(f);

    let mut seen = Vec::new();
    let summary = stream_records(&path, &Filter::default(), |rec| {
        seen.push(rec.seq.get());
        Ok(())
    })
    .unwrap();
    assert_eq!(summary.matched, 2);
    assert_eq!(seen, vec![1, 2]);
    assert_eq!(
        summary.skipped_unknown_kind, 0,
        "a torn write is not a record of an unrecognized kind",
    );
}
