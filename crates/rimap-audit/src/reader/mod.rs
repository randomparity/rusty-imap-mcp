//! Shared-lock JSONL reader for `audit merge` and external tools.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use fs4::{FileExt, TryLockError};
use time::OffsetDateTime;

pub mod backup_exclude;

use crate::AuditError;
use crate::record::{AuditRecord, Payload};

/// Filter predicate for `audit merge`. Empty fields mean "no constraint".
///
/// `#[non_exhaustive]`: every new `audit merge` filter dimension is a field
/// here, so a downstream struct literal would make each one a breaking
/// change. `Default` is the all-`None` "match everything" predicate, which is
/// the correct starting point for building one; assign the fields to
/// constrain. No constructor: nothing about this type is required.
///
/// A struct expression is rejected outside this crate:
///
/// ```compile_fail,E0639
/// let _ = rimap_audit::Filter {
///     since: None,
///     until: None,
///     tool: None,
///     kind: None,
///     process: None,
///     account: None,
/// };
/// ```
///
/// And so is functional-update syntax — `..Default::default()` is still a
/// struct expression (E0639), which is the premise that is easy to get wrong:
///
/// ```compile_fail,E0639
/// let _ = rimap_audit::Filter {
///     kind: Some("tool_end".to_owned()),
///     ..Default::default()
/// };
/// ```
///
/// The supported form is [`Filter::default`] plus field assignment:
///
/// ```
/// let mut filter = rimap_audit::Filter::default();
/// filter.kind = Some("tool_end".to_owned());
/// ```
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct Filter {
    /// Inclusive lower bound on `ts`.
    pub since: Option<OffsetDateTime>,
    /// Inclusive upper bound on `ts`.
    pub until: Option<OffsetDateTime>,
    /// If set, only `tool_start` / `tool_end` records whose `tool` field
    /// exactly matches are returned. All other payload kinds
    /// (`process_start`, `process_end`, `auth`, `config`) are excluded.
    pub tool: Option<String>,
    /// Required `kind` field (exact match).
    pub kind: Option<String>,
    /// Required `process_id` (canonical ULID string).
    pub process: Option<String>,
    /// If set, only records whose `account` field matches are returned.
    /// Records without an account field (`process_start`, `process_end`,
    /// `config`) pass through when this filter is set.
    pub account: Option<String>,
}

impl Filter {
    /// Whether `record` passes this filter.
    #[must_use]
    pub fn matches(&self, record: &AuditRecord) -> bool {
        if let Some(since) = self.since
            && record.ts.offset() < since
        {
            return false;
        }
        if let Some(until) = self.until
            && record.ts.offset() > until
        {
            return false;
        }
        if let Some(ref want) = self.process
            && record.process_id.to_string() != *want
        {
            return false;
        }
        if let Some(ref want) = self.kind
            && kind_of(&record.payload) != want
        {
            return false;
        }
        if let Some(ref want) = self.tool {
            let got = match &record.payload {
                Payload::ToolStart(t) => Some(t.tool.as_str()),
                Payload::ToolEnd(t) => Some(t.tool.as_str()),
                Payload::ProcessStart(_)
                | Payload::ProcessEnd(_)
                | Payload::Auth(_)
                | Payload::Config(_) => None,
            };
            match got {
                Some(name) if name == want => {}
                Some(_) | None => return false,
            }
        }
        if let Some(ref want) = self.account {
            let got = match &record.payload {
                Payload::Auth(a) => a.account.as_deref(),
                Payload::ToolStart(t) => t.account.as_deref(),
                Payload::ToolEnd(t) => t.account.as_deref(),
                Payload::ProcessStart(_) | Payload::ProcessEnd(_) | Payload::Config(_) => None,
            };
            // Records that lack an account field pass through.
            if let Some(name) = got
                && name != want
            {
                return false;
            }
        }
        true
    }
}

fn kind_of(payload: &Payload) -> &'static str {
    match payload {
        Payload::ProcessStart(_) => "process_start",
        Payload::ProcessEnd(_) => "process_end",
        Payload::Auth(_) => "auth",
        Payload::ToolStart(_) => "tool_start",
        Payload::ToolEnd(_) => "tool_end",
        Payload::Config(_) => "config",
    }
}

/// Parse a single JSONL line into an [`AuditRecord`].
///
/// Thin wrapper around `serde_json::from_slice` that maps any decode
/// failure to [`AuditError::Parse`]. Callers that have file path / line
/// context (like `stream_records`) rewrap the error as
/// [`AuditError::Read`] before propagating. Empty input is treated as
/// malformed and returns `Err`; callers that want the trailing-empty-line
/// tolerance enforced by `stream_records` should use that function instead.
///
/// # Errors
/// [`AuditError::Parse`] when the bytes do not deserialize to a valid
/// [`AuditRecord`].
pub fn parse_line(raw: &[u8]) -> Result<AuditRecord, AuditError> {
    serde_json::from_slice::<AuditRecord>(raw).map_err(AuditError::Parse)
}

/// Open the audit file with a shared lock.
///
/// # Errors
/// - [`AuditError::Open`] on I/O failure.
/// - [`AuditError::Locked`] when the file is held exclusively by another
///   process (e.g. a running server).
pub fn open_shared(path: &Path) -> Result<File, AuditError> {
    let file = crate::fs::reader_open_options()
        .open(path)
        .map_err(|source| AuditError::Open {
            path: path.to_path_buf(),
            source,
        })?;
    match FileExt::try_lock_shared(&file) {
        Ok(()) => Ok(file),
        Err(TryLockError::WouldBlock) => Err(AuditError::Locked {
            path: path.to_path_buf(),
        }),
        Err(TryLockError::Error(source)) => Err(AuditError::Open {
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// Stream records from `path` through `filter` into `on_record`. A partial
/// trailing line emits a single `tracing::warn!` and is skipped. Any other
/// parse failure aborts with [`AuditError::Read`] containing the offending
/// line number.
///
/// Memory is bounded by the length of the longest single line — the file is
/// not fully loaded into memory before processing.
///
/// # Errors
/// I/O error from reading the file, or a JSON parse failure on a
/// non-trailing line.
pub fn stream_records<F>(
    path: &Path,
    filter: &Filter,
    mut on_record: F,
) -> Result<usize, AuditError>
where
    F: FnMut(&AuditRecord) -> Result<(), AuditError>,
{
    let file = open_shared(path)?;
    let reader = BufReader::new(file);
    let mut count = 0_usize;
    let mut prev: Option<(usize, String)> = None; // (line_no, content)
    let mut line_no = 0_usize;

    for raw in reader.lines() {
        let line = raw.map_err(|source| AuditError::Read {
            path: path.to_path_buf(),
            line: None,
            source,
        })?;
        line_no += 1;

        if let Some((prev_no, prev_line)) = prev.take() {
            parse_filter_and_dispatch(
                path,
                prev_no,
                &prev_line,
                filter,
                &mut on_record,
                &mut count,
                false,
            )?;
        }
        prev = Some((line_no, line));
    }

    // The final buffered line is the "trailing" one — malformed trailing is tolerated.
    if let Some((prev_no, prev_line)) = prev {
        parse_filter_and_dispatch(
            path,
            prev_no,
            &prev_line,
            filter,
            &mut on_record,
            &mut count,
            true,
        )?;
    }

    Ok(count)
}

fn parse_filter_and_dispatch<F>(
    path: &Path,
    line_no: usize,
    line: &str,
    filter: &Filter,
    on_record: &mut F,
    count: &mut usize,
    is_trailing: bool,
) -> Result<(), AuditError>
where
    F: FnMut(&AuditRecord) -> Result<(), AuditError>,
{
    if line.is_empty() {
        return Ok(());
    }
    match parse_line(line.as_bytes()) {
        Ok(rec) => {
            if filter.matches(&rec) {
                on_record(&rec)?;
                *count += 1;
            }
            Ok(())
        }
        Err(AuditError::Parse(source)) if is_trailing => {
            tracing::warn!(
                path = %path.display(),
                line = line_no,
                error = %source,
                "skipping malformed trailing line in audit file",
            );
            Ok(())
        }
        Err(AuditError::Parse(source)) => Err(AuditError::Read {
            path: path.to_path_buf(),
            line: Some(line_no),
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, source),
        }),
        Err(other) => Err(other),
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use std::io::Write;

    use tempfile::TempDir;
    use time::macros::datetime;

    use crate::reader::{Filter, stream_records};
    use crate::record::ids::{ProcessId, Timestamp};
    use crate::record::{AuditRecord, Payload, ProcessEnd, ProcessEndReason};

    fn sample(seq: u64, pid: ProcessId) -> AuditRecord {
        AuditRecord {
            seq: crate::record::ids::Seq(seq),
            ts: Timestamp::from_offset(datetime!(2026-04-07 14:22:01.000 UTC)),
            process_id: pid,
            payload: Payload::ProcessEnd(ProcessEnd {
                reason: ProcessEndReason::Eof,
                total_tool_calls: seq,
                records_lost: 0,
                undrained_dispatches: 0,
            }),
        }
    }

    fn write_lines(dir: &TempDir, name: &str, lines: &[String]) -> std::path::PathBuf {
        let path = dir.path().join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        for line in lines {
            f.write_all(line.as_bytes()).unwrap();
            f.write_all(b"\n").unwrap();
        }
        path
    }

    #[test]
    fn streams_all_records_with_empty_filter() {
        let dir = TempDir::new().unwrap();
        let pid = ProcessId::new_now();
        let lines: Vec<String> = (1_u64..=3)
            .map(|s| serde_json::to_string(&sample(s, pid)).unwrap())
            .collect();
        let path = write_lines(&dir, "a.jsonl", &lines);

        let mut seen = Vec::new();
        let count = stream_records(&path, &Filter::default(), |rec| {
            seen.push(rec.seq.get());
            Ok(())
        })
        .unwrap();
        assert_eq!(count, 3);
        assert_eq!(seen, vec![1, 2, 3]);
    }

    #[test]
    fn malformed_trailing_line_is_skipped_with_warning() {
        let dir = TempDir::new().unwrap();
        let pid = ProcessId::new_now();
        let mut lines: Vec<String> = (1_u64..=2)
            .map(|s| serde_json::to_string(&sample(s, pid)).unwrap())
            .collect();
        lines.push("{\"seq\":3,\"kind\":\"xxx".to_string());
        let path = write_lines(&dir, "a.jsonl", &lines);

        let mut count = 0;
        stream_records(&path, &Filter::default(), |_rec| {
            count += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn malformed_non_trailing_line_is_an_error() {
        let dir = TempDir::new().unwrap();
        let pid = ProcessId::new_now();
        let good = serde_json::to_string(&sample(1, pid)).unwrap();
        let good2 = serde_json::to_string(&sample(2, pid)).unwrap();
        let lines = vec!["not json".to_string(), good, good2];
        let path = write_lines(&dir, "a.jsonl", &lines);

        let err = stream_records(&path, &Filter::default(), |_| Ok(())).unwrap_err();
        assert!(format!("{err}").contains("line "));
    }

    #[test]
    fn filter_by_kind_matches_exact_string() {
        let dir = TempDir::new().unwrap();
        let pid = ProcessId::new_now();
        let lines: Vec<String> = (1_u64..=3)
            .map(|s| serde_json::to_string(&sample(s, pid)).unwrap())
            .collect();
        let path = write_lines(&dir, "a.jsonl", &lines);

        let filter = Filter {
            kind: Some("process_end".to_string()),
            ..Filter::default()
        };
        let count = stream_records(&path, &filter, |_| Ok(())).unwrap();
        assert_eq!(count, 3);

        let filter = Filter {
            kind: Some("process_start".to_string()),
            ..Filter::default()
        };
        let count = stream_records(&path, &filter, |_| Ok(())).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn filter_by_process_id_matches() {
        let dir = TempDir::new().unwrap();
        let pid_a = ProcessId::new_now();
        let pid_b = ProcessId::new_now();
        let lines = vec![
            serde_json::to_string(&sample(1, pid_a)).unwrap(),
            serde_json::to_string(&sample(2, pid_b)).unwrap(),
            serde_json::to_string(&sample(3, pid_a)).unwrap(),
        ];
        let path = write_lines(&dir, "a.jsonl", &lines);

        let filter = Filter {
            process: Some(pid_a.to_string()),
            ..Filter::default()
        };
        let count = stream_records(&path, &filter, |_| Ok(())).unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn empty_file_streams_zero_records() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("a.jsonl");
        std::fs::File::create(&path).unwrap();
        let count = stream_records(&path, &Filter::default(), |_| Ok(())).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn tool_filter_excludes_non_tool_records() {
        use crate::record::ToolStart;

        let dir = TempDir::new().unwrap();
        let pid = ProcessId::new_now();
        let tool_rec = AuditRecord {
            seq: crate::record::ids::Seq(1),
            ts: Timestamp::from_offset(datetime!(2026-04-07 14:22:01.000 UTC)),
            process_id: pid,
            payload: Payload::ToolStart(ToolStart {
                account: None,
                tool: rimap_core::tool::ToolName::FetchMessage,
                posture_effective: crate::record::PostureEffective::Account(
                    rimap_core::Posture::DraftSafe,
                ),
                arguments_redacted: serde_json::json!({}),
                arguments_hash_sha256: "0".repeat(64),
            }),
        };
        let proc_rec = sample(2, pid);
        let lines = vec![
            serde_json::to_string(&tool_rec).unwrap(),
            serde_json::to_string(&proc_rec).unwrap(),
        ];
        let path = write_lines(&dir, "a.jsonl", &lines);

        let filter = Filter {
            tool: Some("fetch_message".to_string()),
            ..Filter::default()
        };
        let mut seen_kinds = Vec::new();
        let count = stream_records(&path, &filter, |rec| {
            seen_kinds.push(match &rec.payload {
                Payload::ToolStart(_) => "tool_start",
                Payload::ToolEnd(_) => "tool_end",
                Payload::ProcessStart(_) => "process_start",
                Payload::ProcessEnd(_) => "process_end",
                Payload::Auth(_) => "auth",
                Payload::Config(_) => "config",
            });
            Ok(())
        })
        .unwrap();
        assert_eq!(count, 1);
        assert_eq!(seen_kinds, vec!["tool_start"]);
    }

    #[test]
    fn filter_by_since_and_until_restricts_range() {
        let dir = TempDir::new().unwrap();
        let pid = ProcessId::new_now();
        let lines = vec![serde_json::to_string(&sample(1, pid)).unwrap()];
        let path = write_lines(&dir, "a.jsonl", &lines);

        let filter = Filter {
            since: Some(datetime!(2027-01-01 00:00:00.000 UTC)),
            ..Filter::default()
        };
        let count = stream_records(&path, &filter, |_| Ok(())).unwrap();
        assert_eq!(count, 0);

        let filter = Filter {
            until: Some(datetime!(2020-01-01 00:00:00.000 UTC)),
            ..Filter::default()
        };
        let count = stream_records(&path, &filter, |_| Ok(())).unwrap();
        assert_eq!(count, 0);

        let filter = Filter {
            since: Some(datetime!(2026-01-01 00:00:00.000 UTC)),
            until: Some(datetime!(2026-12-31 23:59:59.999 UTC)),
            ..Filter::default()
        };
        let count = stream_records(&path, &filter, |_| Ok(())).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    #[expect(clippy::expect_used, reason = "tests")]
    fn parse_line_round_trips_a_valid_record() {
        let pid = ProcessId::new_now();
        let rec = sample(7, pid);
        let bytes = serde_json::to_vec(&rec).unwrap();

        let parsed = super::parse_line(&bytes).expect("valid record must parse");
        assert_eq!(parsed.seq.get(), 7);
    }

    #[test]
    #[expect(clippy::expect_used, reason = "tests use expect for assertions")]
    #[expect(clippy::panic, reason = "tests assert variant shapes via panic")]
    fn parse_line_returns_parse_variant_on_malformed_json() {
        let err = super::parse_line(b"{not json").expect_err("malformed JSON must error");
        match err {
            crate::AuditError::Parse(source) => {
                assert_eq!(source.classify(), serde_json::error::Category::Syntax);
            }
            other => panic!("unexpected error kind: {other:?}"),
        }
    }

    #[test]
    #[expect(clippy::expect_used, reason = "tests use expect for assertions")]
    fn parse_line_display_is_human_readable_without_empty_backticks() {
        // Regression test for issue #255: the previous implementation reused
        // `AuditError::Read` with an empty `PathBuf`, rendering the message
        // as ``failed to read audit file `` `` ... ``. The `Parse` variant
        // must produce a clean, path-less message.
        let err = super::parse_line(b"{not json").expect_err("malformed JSON must error");
        let display = err.to_string();
        assert!(
            display.starts_with("failed to parse audit record:"),
            "Display must lead with the parse-failure framing; got: {display}",
        );
        assert!(
            !display.contains("``"),
            "Display must not contain empty backticks; got: {display}",
        );
        assert!(
            !display.contains("audit file"),
            "path-less parse failure must not claim a file path; got: {display}",
        );
    }

    #[test]
    fn parse_line_returns_err_on_empty_input() {
        assert!(
            super::parse_line(b"").is_err(),
            "empty input is malformed; doc comment promises Err",
        );
    }

    #[test]
    fn parse_line_does_not_panic_on_garbage_bytes() {
        let mut bytes = Vec::with_capacity(1024);
        for i in 0_u16..1024 {
            bytes.push((i & 0xff) as u8);
        }
        let _ = super::parse_line(&bytes);
    }

    #[test]
    fn since_bound_is_inclusive_at_record_timestamp() {
        // Pin the doc-comment "Inclusive lower bound on `ts`" so a `<` -> `<=`
        // mutation in `Filter::matches` is observable. With `<=`, the record
        // whose `ts` exactly matches `since` would be filtered out.
        let dir = TempDir::new().unwrap();
        let pid = ProcessId::new_now();
        let exact_ts = datetime!(2026-04-07 14:22:01.000 UTC);
        let rec = AuditRecord {
            seq: crate::record::ids::Seq(1),
            ts: Timestamp::from_offset(exact_ts),
            process_id: pid,
            payload: Payload::ProcessEnd(ProcessEnd {
                reason: ProcessEndReason::Eof,
                total_tool_calls: 0,
                records_lost: 0,
                undrained_dispatches: 0,
            }),
        };
        let path = write_lines(&dir, "a.jsonl", &[serde_json::to_string(&rec).unwrap()]);

        let filter = Filter {
            since: Some(exact_ts),
            ..Filter::default()
        };
        let count = stream_records(&path, &filter, |_| Ok(())).unwrap();
        assert_eq!(count, 1, "since bound is inclusive at the record timestamp");
    }

    #[test]
    fn until_bound_is_inclusive_at_record_timestamp() {
        // Pin the doc-comment "Inclusive upper bound on `ts`" so a `>` -> `>=`
        // mutation in `Filter::matches` is observable. With `>=`, the record
        // whose `ts` exactly matches `until` would be filtered out.
        let dir = TempDir::new().unwrap();
        let pid = ProcessId::new_now();
        let exact_ts = datetime!(2026-04-07 14:22:01.000 UTC);
        let rec = AuditRecord {
            seq: crate::record::ids::Seq(1),
            ts: Timestamp::from_offset(exact_ts),
            process_id: pid,
            payload: Payload::ProcessEnd(ProcessEnd {
                reason: ProcessEndReason::Eof,
                total_tool_calls: 0,
                records_lost: 0,
                undrained_dispatches: 0,
            }),
        };
        let path = write_lines(&dir, "a.jsonl", &[serde_json::to_string(&rec).unwrap()]);

        let filter = Filter {
            until: Some(exact_ts),
            ..Filter::default()
        };
        let count = stream_records(&path, &filter, |_| Ok(())).unwrap();
        assert_eq!(count, 1, "until bound is inclusive at the record timestamp");
    }

    #[test]
    fn tool_filter_excludes_record_whose_tool_does_not_match() {
        use crate::record::ToolStart;

        let dir = TempDir::new().unwrap();
        let pid = ProcessId::new_now();
        let tool_rec = AuditRecord {
            seq: crate::record::ids::Seq(1),
            ts: Timestamp::from_offset(datetime!(2026-04-07 14:22:01.000 UTC)),
            process_id: pid,
            payload: Payload::ToolStart(ToolStart {
                account: None,
                tool: rimap_core::tool::ToolName::FetchMessage,
                posture_effective: crate::record::PostureEffective::Account(
                    rimap_core::Posture::DraftSafe,
                ),
                arguments_redacted: serde_json::json!({}),
                arguments_hash_sha256: "0".repeat(64),
            }),
        };
        let path = write_lines(
            &dir,
            "a.jsonl",
            &[serde_json::to_string(&tool_rec).unwrap()],
        );

        // Filter for a *different* tool. The matching guard `name == want` must
        // reject this record; mutating it to `true` would let it through.
        let filter = Filter {
            tool: Some("search".to_string()),
            ..Filter::default()
        };
        let count = stream_records(&path, &filter, |_| Ok(())).unwrap();
        assert_eq!(
            count, 0,
            "tool filter must exclude non-matching tool records"
        );
    }

    #[test]
    fn account_filter_excludes_record_with_different_account() {
        use crate::record::{AuthEvent, AuthResult};

        let dir = TempDir::new().unwrap();
        let pid = ProcessId::new_now();
        let auth_rec = AuditRecord {
            seq: crate::record::ids::Seq(1),
            ts: Timestamp::from_offset(datetime!(2026-04-07 14:22:01.000 UTC)),
            process_id: pid,
            payload: Payload::Auth(AuthEvent {
                account: Some("bob".to_string()),
                result: AuthResult::Success,
                host: "h".to_string(),
                port: 993,
                username: "u".to_string(),
                tls_fingerprint_sha256: None,
                fingerprint_match: None,
                error_code: None,
                credential_source: None,
            }),
        };
        let path = write_lines(
            &dir,
            "a.jsonl",
            &[serde_json::to_string(&auth_rec).unwrap()],
        );

        // Filter for a *different* account. The `name != want` predicate must
        // reject this record; mutating to `==` would invert it (only matching
        // records would be filtered out).
        let filter = Filter {
            account: Some("alice".to_string()),
            ..Filter::default()
        };
        let count = stream_records(&path, &filter, |_| Ok(())).unwrap();
        assert_eq!(
            count, 0,
            "account filter must exclude records whose account differs",
        );
    }

    #[test]
    fn malformed_non_trailing_line_error_carries_one_based_line_number() {
        // Pin `line_no += 1` against `*= 1` mutation in `stream_records`. With
        // `*= 1`, line_no stays at 0 throughout; the error would format as
        // `(line 0)`. The original `+= 1` produces 1-based line numbers, so a
        // malformed line in slot 2 must report "line 2".
        let dir = TempDir::new().unwrap();
        let pid = ProcessId::new_now();
        let good = serde_json::to_string(&sample(1, pid)).unwrap();
        let good2 = serde_json::to_string(&sample(2, pid)).unwrap();
        let lines = vec![good, "not json".to_string(), good2];
        let path = write_lines(&dir, "a.jsonl", &lines);

        let err = stream_records(&path, &Filter::default(), |_| Ok(())).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("line 2"),
            "expected `line 2` in error, got: {msg}"
        );
    }
}
