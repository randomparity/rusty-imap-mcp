//! `audit merge` subcommand handler.
//!
//! Streams JSONL from an audit file on stdout, filtered by the CLI flags.
//! Stdout writes go through `std::io::stdout().lock()` directly to dodge the
//! workspace `print_stdout` lint (same pattern as `dry_run`).
//!
//! The audit log is the source of truth; this command re-serializes every
//! record via `serde_json::to_string` so the output is canonical and easily
//! piped into `jq`.

use std::io::Write;
use std::path::Path;

use anyhow::Context;
use rimap_audit::{Filter, stream_records};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Filter inputs for [`run`], expressed as string slices straight from
/// the CLI parser. Parsed into `rimap_audit::Filter` inside [`run`] so
/// error contexts can point back at the originating flag.
#[derive(Debug, Default, Clone, Copy)]
pub struct RunArgs<'a> {
    /// `--since` RFC 3339 timestamp.
    pub since: Option<&'a str>,
    /// `--until` RFC 3339 timestamp.
    pub until: Option<&'a str>,
    /// `--tool` name filter.
    pub tool: Option<&'a str>,
    /// `--kind` record-kind filter.
    pub kind: Option<&'a str>,
    /// `--process` id filter.
    pub process: Option<&'a str>,
    /// `--account` name filter.
    pub account: Option<&'a str>,
}

/// Parse CLI [`RunArgs`] into a [`Filter`]. Pure: no I/O, no logging;
/// surfaces parse failures for `--since` / `--until` with a context that
/// identifies which flag and which literal value failed so the CLI user
/// sees an actionable message.
///
/// # Errors
/// - Returns an `anyhow::Error` with context when `--since` or `--until`
///   is not an RFC 3339 timestamp. All string fields pass through
///   unchanged.
pub fn parse_filter(args: &RunArgs<'_>) -> anyhow::Result<Filter> {
    let since = args
        .since
        .map(|s| OffsetDateTime::parse(s, &Rfc3339))
        .transpose()
        .with_context(|| format!("parsing --since `{}`", args.since.unwrap_or("")))?;
    let until = args
        .until
        .map(|s| OffsetDateTime::parse(s, &Rfc3339))
        .transpose()
        .with_context(|| format!("parsing --until `{}`", args.until.unwrap_or("")))?;
    let mut filter = Filter::default();
    filter.since = since;
    filter.until = until;
    filter.tool = args.tool.map(str::to_string);
    filter.kind = args.kind.map(str::to_string);
    filter.process = args.process.map(str::to_string);
    filter.account = args.account.map(str::to_string);
    Ok(filter)
}

/// Run the `audit merge` subcommand.
///
/// Records whose `kind` this binary does not recognize are skipped by the
/// reader rather than aborting the merge (#717). A skip is not silent: the
/// count goes to stderr on the way out, so an operator piping stdout to `jq`
/// still learns the merged stream is missing records a newer version wrote.
/// The note is written directly rather than through `tracing` so it survives
/// whatever log filter the invocation is running under.
///
/// # Errors
/// - Any `AuditError` from opening / locking / reading the file.
/// - Parse errors on `--since` / `--until` arguments.
/// - Stdout I/O errors.
pub fn run(path: &Path, args: RunArgs<'_>) -> anyhow::Result<()> {
    let filter = parse_filter(&args)?;

    let mut stdout = std::io::stdout().lock();
    let summary = stream_records(path, &filter, |record| {
        let line = serde_json::to_string(record).map_err(rimap_audit::AuditError::Serialize)?;
        writeln!(stdout, "{line}").map_err(|source| rimap_audit::AuditError::Write {
            path: path.to_path_buf(),
            source,
        })?;
        Ok(())
    })
    .context("streaming audit records")?;

    report_skipped(&mut std::io::stderr().lock(), path, &summary)
}

/// Write the unknown-kind note for `summary` to `out`, if there is one.
///
/// Split out from [`run`] so the message is testable without a subprocess;
/// `run` passes the real stderr.
///
/// # Errors
/// I/O error writing to `out`.
fn report_skipped(
    out: &mut impl Write,
    path: &Path,
    summary: &rimap_audit::StreamSummary,
) -> anyhow::Result<()> {
    if summary.skipped_unknown_kind == 0 {
        return Ok(());
    }
    writeln!(
        out,
        "warning: skipped {} record(s) of an unrecognized kind in {}; \
         they were written by a newer version than this binary, and are \
         not in the output above",
        summary.skipped_unknown_kind,
        path.display(),
    )
    .context("writing the skipped-record warning to stderr")
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use std::path::{Path, PathBuf};

    use super::{RunArgs, parse_filter, report_skipped};

    /// Stream `lines` from a throwaway file and hand back the summary.
    ///
    /// `StreamSummary` is `#[non_exhaustive]` with no constructor, so this
    /// crate cannot mint one — which is the intended shape: the only summary
    /// worth asserting on is one a real pass produced.
    fn summary_of(dir: &tempfile::TempDir, lines: &[&str]) -> rimap_audit::StreamSummary {
        let path = dir.path().join("audit.jsonl");
        std::fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();
        rimap_audit::stream_records(&path, &rimap_audit::Filter::default(), |_| Ok(())).unwrap()
    }

    const GOOD_LINE: &str = r#"{"seq":1,"ts":"2026-04-07T14:22:01.000Z","process_id":"01JXAAAAAAAAAAAAAAAAAAAAAA","kind":"process_end","reason":"eof","total_tool_calls":0}"#;
    const FUTURE_LINE: &str = r#"{"seq":2,"ts":"2026-04-07T14:22:02.000Z","process_id":"01JXAAAAAAAAAAAAAAAAAAAAAA","kind":"policy","rule":"deny-all"}"#;

    #[test]
    fn skipped_records_are_reported_with_their_count_and_path() {
        let dir = tempfile::TempDir::new().unwrap();
        let summary = summary_of(&dir, &[GOOD_LINE, FUTURE_LINE, GOOD_LINE]);
        assert_eq!(summary.skipped_unknown_kind, 1, "fixture must skip one");

        let mut out = Vec::new();
        report_skipped(&mut out, Path::new("/tmp/audit.jsonl"), &summary).unwrap();
        let text = String::from_utf8(out).unwrap();

        assert!(
            text.contains('1'),
            "the count must be in the message: {text}"
        );
        assert!(
            text.contains("/tmp/audit.jsonl"),
            "the message must name the file: {text}",
        );
        assert!(
            text.contains("unrecognized kind"),
            "the message must say why: {text}",
        );
    }

    #[test]
    fn a_clean_merge_says_nothing() {
        let dir = tempfile::TempDir::new().unwrap();
        let summary = summary_of(&dir, &[GOOD_LINE, GOOD_LINE]);
        assert_eq!(summary.skipped_unknown_kind, 0);

        let mut out = Vec::new();
        report_skipped(&mut out, &PathBuf::from("/tmp/audit.jsonl"), &summary).unwrap();
        assert!(
            out.is_empty(),
            "a merge that skipped nothing must not print a warning",
        );
    }

    #[test]
    fn all_none_default_parses_to_empty_filter() {
        let args = RunArgs::default();
        let filter = parse_filter(&args).unwrap();
        assert!(filter.since.is_none());
        assert!(filter.until.is_none());
        assert!(filter.tool.is_none());
        assert!(filter.kind.is_none());
        assert!(filter.process.is_none());
        assert!(filter.account.is_none());
    }

    #[test]
    fn bad_since_produces_contextual_error() {
        let args = RunArgs {
            since: Some("not-a-timestamp"),
            ..RunArgs::default()
        };
        let err = parse_filter(&args).unwrap_err();
        let full = format!("{err:#}");
        assert!(
            full.contains("--since"),
            "error should name the flag that failed: {full}"
        );
        assert!(
            full.contains("not-a-timestamp"),
            "error should echo the bad literal: {full}"
        );
    }

    #[test]
    fn bad_until_produces_contextual_error() {
        let args = RunArgs {
            until: Some("2025-13-40T99:99:99Z"),
            ..RunArgs::default()
        };
        let err = parse_filter(&args).unwrap_err();
        let full = format!("{err:#}");
        assert!(
            full.contains("--until"),
            "error should name the flag that failed: {full}"
        );
        assert!(
            full.contains("2025-13-40T99:99:99Z"),
            "error should echo the bad literal: {full}"
        );
    }

    #[test]
    fn valid_rfc3339_since_round_trips() {
        let args = RunArgs {
            since: Some("2026-01-02T03:04:05Z"),
            ..RunArgs::default()
        };
        let filter = parse_filter(&args).unwrap();
        let since = filter.since.unwrap();
        assert_eq!(since.year(), 2026);
        assert_eq!(u8::from(since.month()), 1);
        assert_eq!(since.day(), 2);
        assert_eq!(since.hour(), 3);
        assert_eq!(since.minute(), 4);
        assert_eq!(since.second(), 5);
    }

    #[test]
    fn valid_rfc3339_until_round_trips() {
        let args = RunArgs {
            until: Some("2026-12-31T23:59:59+00:00"),
            ..RunArgs::default()
        };
        let filter = parse_filter(&args).unwrap();
        let until = filter.until.unwrap();
        assert_eq!(until.year(), 2026);
        assert_eq!(u8::from(until.month()), 12);
        assert_eq!(until.day(), 31);
    }

    #[test]
    fn string_fields_pass_through_unchanged() {
        let args = RunArgs {
            tool: Some("fetch_message"),
            kind: Some("tool_end"),
            process: Some("01HXYZ"),
            account: Some("work"),
            ..RunArgs::default()
        };
        let filter = parse_filter(&args).unwrap();
        assert_eq!(filter.tool.as_deref(), Some("fetch_message"));
        assert_eq!(filter.kind.as_deref(), Some("tool_end"));
        assert_eq!(filter.process.as_deref(), Some("01HXYZ"));
        assert_eq!(filter.account.as_deref(), Some("work"));
    }

    #[test]
    fn bad_since_does_not_mask_valid_until() {
        // Parse fails early on --since; the error must still point at
        // --since rather than --until even when --until is also set.
        let args = RunArgs {
            since: Some("garbage"),
            until: Some("2026-06-15T12:00:00Z"),
            ..RunArgs::default()
        };
        let err = parse_filter(&args).unwrap_err();
        let full = format!("{err:#}");
        assert!(full.contains("--since"), "error = {full}");
        assert!(!full.contains("--until"), "error = {full}");
    }
}
