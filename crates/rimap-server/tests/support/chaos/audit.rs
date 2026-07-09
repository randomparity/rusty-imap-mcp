//! Audit-log drain + Seq-bracket assertion helpers for the chaos suite (#522).
//!
//! Every audit line is a flat JSON record with a top-level `seq` and a `kind`
//! discriminator (`auth`, `tool_start`, `tool_end`, `process_start`,
//! `process_end`); `tool_end` carries `start_seq` back to its `tool_start` and an
//! `error_code`. These helpers scope assertions (e.g. "exactly one `auth`
//! Failure") to a single tool-call's Seq window.
//!
//! Note: the server connects EAGERLY at boot (special-use folder discovery,
//! fatal-on-failure), so the first-ever `auth` record is the boot connect, not a
//! tool call. Per-call assertions therefore bracket by the failing call's
//! `tool_start`/`tool_end` Seq window rather than assuming "first auth record".

use std::path::Path;

use serde_json::Value;

/// Parse each non-empty JSONL line into a `Value`, skipping unparseable lines.
pub fn parse_lines(s: &str) -> Vec<Value> {
    let mut out = Vec::new();
    for line in s.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<Value>(line) {
            out.push(v);
        }
    }
    out
}

/// Read + parse an audit JSONL file. Missing/unreadable file → empty vec.
pub fn read_records(path: &Path) -> Vec<Value> {
    let s = std::fs::read_to_string(path).unwrap_or_default();
    parse_lines(&s)
}

fn seq(v: &Value) -> Option<u64> {
    v["seq"].as_u64()
}

/// `(start_seq, end_seq)` of the last `tool_start`/matching `tool_end` pair
/// (matched by `tool_end.start_seq == tool_start.seq`, identified by the highest
/// `tool_end` seq).
pub fn last_tool_call(records: &[Value]) -> Option<(u64, u64)> {
    let mut best: Option<(u64, u64)> = None;
    for r in records {
        if r["kind"] == "tool_end" {
            let end = seq(r)?;
            let start = r["start_seq"].as_u64()?;
            if best.is_none_or(|(_, e)| end > e) {
                best = Some((start, end));
            }
        }
    }
    best
}

/// `error_code` of the `tool_end` whose `start_seq == start_seq`.
pub fn tool_end_error_code(records: &[Value], start_seq: u64) -> Option<String> {
    for r in records {
        if r["kind"] == "tool_end" && r["start_seq"].as_u64() == Some(start_seq) {
            return r["error_code"].as_str().map(str::to_owned);
        }
    }
    None
}

/// `(start_seq, end_seq)` of the last `tool_end` whose `error_code` is one of
/// `codes`. Lets a scenario locate its failing call's window when other
/// (successful) calls also appear in the log.
pub fn last_tool_call_matching_error(records: &[Value], codes: &[&str]) -> Option<(u64, u64)> {
    let mut best: Option<(u64, u64)> = None;
    for r in records {
        if r["kind"] != "tool_end" {
            continue;
        }
        let matches = r["error_code"].as_str().is_some_and(|c| codes.contains(&c));
        if !matches {
            continue;
        }
        let (Some(end), Some(start)) = (seq(r), r["start_seq"].as_u64()) else {
            continue;
        };
        if best.is_none_or(|(_, e)| end > e) {
            best = Some((start, end));
        }
    }
    best
}

/// Count `auth` records with `result == "failure"` whose seq lies strictly
/// between `start_seq` and `end_seq` (the failing call's window).
pub fn count_auth_failures_between(records: &[Value], start_seq: u64, end_seq: u64) -> usize {
    let mut n = 0;
    for r in records {
        let Some(s) = seq(r) else { continue };
        if r["kind"] == "auth" && r["result"] == "failure" && s > start_seq && s < end_seq {
            n += 1;
        }
    }
    n
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::expect_used,
        clippy::needless_pass_by_value,
        reason = "unit tests"
    )]

    use super::*;
    use serde_json::json;

    fn line(v: Value) -> String {
        v.to_string()
    }

    #[test]
    fn counts_one_auth_failure_in_the_failing_call_window() {
        let jsonl = [
            line(json!({"seq":0,"kind":"process_start"})),
            line(json!({"seq":1,"kind":"tool_start"})),
            line(json!({"seq":2,"kind":"auth","result":"failure","error_code":"ERR_CONNECTION_LOST"})),
            line(json!({"seq":3,"kind":"tool_end","start_seq":1,"error_code":"ERR_CONNECTION_LOST"})),
        ]
        .join("\n");
        let recs = parse_lines(&jsonl);
        let (s0, s1) = last_tool_call(&recs).expect("a tool call");
        assert_eq!((s0, s1), (1, 3));
        assert_eq!(
            tool_end_error_code(&recs, s0).as_deref(),
            Some("ERR_CONNECTION_LOST")
        );
        assert_eq!(count_auth_failures_between(&recs, s0, s1), 1);
    }

    #[test]
    fn ignores_auth_records_outside_the_window() {
        let jsonl = [
            line(json!({"seq":0,"kind":"tool_start"})),
            line(json!({"seq":1,"kind":"auth","result":"failure","error_code":"ERR_TLS"})),
            line(json!({"seq":2,"kind":"tool_end","start_seq":0,"error_code":"ERR_TLS"})),
            line(json!({"seq":3,"kind":"tool_start"})),
            line(json!({"seq":4,"kind":"tool_end","start_seq":3,"error_code":null})),
        ]
        .join("\n");
        let recs = parse_lines(&jsonl);
        let (s0, s1) = last_tool_call(&recs).expect("a tool call");
        assert_eq!((s0, s1), (3, 4));
        assert_eq!(count_auth_failures_between(&recs, s0, s1), 0);
    }

    #[test]
    fn last_tool_call_matching_error_picks_the_matching_window() {
        let jsonl = [
            line(json!({"seq":0,"kind":"tool_start"})),
            line(json!({"seq":1,"kind":"tool_end","start_seq":0,"error_code":null})),
            line(json!({"seq":2,"kind":"tool_start"})),
            line(json!({"seq":3,"kind":"tool_end","start_seq":2,"error_code":"ERR_TIMEOUT"})),
            line(json!({"seq":4,"kind":"tool_start"})),
            line(json!({"seq":5,"kind":"tool_end","start_seq":4,"error_code":null})),
        ]
        .join("\n");
        let recs = parse_lines(&jsonl);
        assert_eq!(
            last_tool_call_matching_error(&recs, &["ERR_TIMEOUT", "ERR_CONNECTION_LOST"]),
            Some((2, 3))
        );
        assert_eq!(last_tool_call_matching_error(&recs, &["ERR_TLS"]), None);
    }

    #[test]
    fn read_records_round_trips_from_a_file() {
        let jsonl = [
            line(json!({"seq":0,"kind":"tool_start"})),
            line(json!({"seq":1,"kind":"tool_end","start_seq":0,"error_code":null})),
        ]
        .join("\n");
        let f = tempfile::NamedTempFile::new().expect("tempfile");
        std::fs::write(f.path(), &jsonl).expect("write jsonl");
        assert_eq!(read_records(f.path()), parse_lines(&jsonl));
    }
}
