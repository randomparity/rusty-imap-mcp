//! Bulk regression runner for external malicious-email datasets.
//!
//! This binary walks a directory tree of `.eml` files, parses each
//! sample with [`rimap_content::parse_message`], aggregates warnings
//! and failures, and optionally writes a JSON report.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write as _};
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use rimap_content::{Content, ContentError, WarningCode, parse_message};
use serde::Serialize;
use thiserror::Error;

const MAX_RECORDED_FAILURES: usize = 50;

/// Typed errors emitted by the runner CLI. Flattened `String` details
/// let each variant keep its fs-path context without forcing a full
/// source-chain hierarchy for a throwaway binary.
#[derive(Debug, Error)]
enum RunnerError {
    #[error("{0}")]
    UsageMessage(String),
    #[error("{0}")]
    Argument(String),
    #[error("no .eml files found under {0}")]
    NoEmlFilesFound(PathBuf),
    #[error("{operation} {path}: {source}")]
    Filesystem {
        operation: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    #[error("serialize JSON report {path}: {source}")]
    JsonSerialize {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("write {what}: {source}")]
    Io {
        what: &'static str,
        source: io::Error,
    },
}

type RunnerResult<T> = Result<T, RunnerError>;

#[derive(Debug)]
struct Args {
    dataset_root: PathBuf,
    limit: Option<usize>,
    json_out: Option<PathBuf>,
}

#[derive(Debug, Serialize)]
struct RunSummary {
    dataset_root: String,
    discovered_files: usize,
    processed_files: usize,
    ok_count: usize,
    panic_count: usize,
    read_failure_count: usize,
    parse_error_count: usize,
    limit: Option<usize>,
    warning_counts: BTreeMap<String, usize>,
    parse_error_counts: BTreeMap<String, usize>,
    recorded_failures: Vec<FailureRecord>,
}

#[derive(Debug, Serialize)]
struct FailureRecord {
    path: String,
    kind: String,
    detail: String,
}

#[derive(Debug)]
enum SampleOutcome {
    Ok(Box<Content>),
    ParseError(ContentError),
    Panic(String),
}

fn main() -> ExitCode {
    match run() {
        Ok(exit_code) => exit_code,
        Err(RunnerError::UsageMessage(msg)) => {
            let _ = writeln!(io::stderr().lock(), "{msg}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            let _ = writeln!(io::stderr().lock(), "{err}");
            ExitCode::from(2)
        }
    }
}

fn run() -> RunnerResult<ExitCode> {
    let args = parse_args()?;
    let files = collect_eml_files(&args.dataset_root)?;
    if files.is_empty() {
        return Err(RunnerError::NoEmlFilesFound(args.dataset_root));
    }

    let summary = run_dataset(&args.dataset_root, &files, args.limit, parse_message);
    print_summary(&summary).map_err(|err| RunnerError::Io {
        what: "stdout",
        source: err,
    })?;
    if let Some(json_out) = &args.json_out {
        write_json_report(json_out, &summary)?;
    }

    if is_success(&summary) {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(1))
    }
}

fn parse_args() -> RunnerResult<Args> {
    let mut dataset_root: Option<PathBuf> = None;
    let mut limit: Option<usize> = None;
    let mut json_out: Option<PathBuf> = None;

    let mut args = std::env::args_os();
    let _program = args.next();

    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--help" | "-h") => {
                return Err(RunnerError::UsageMessage(usage()));
            }
            Some("--limit") => {
                let Some(value) = args.next() else {
                    return Err(RunnerError::Argument("--limit requires a value".into()));
                };
                let parsed = value
                    .to_str()
                    .ok_or_else(|| RunnerError::Argument("--limit must be valid UTF-8".into()))?
                    .parse::<usize>()
                    .map_err(|_| {
                        RunnerError::Argument("--limit must be a non-negative integer".into())
                    })?;
                limit = Some(parsed);
            }
            Some("--json-out") => {
                let Some(value) = args.next() else {
                    return Err(RunnerError::Argument("--json-out requires a path".into()));
                };
                json_out = Some(PathBuf::from(value));
            }
            Some(flag) if flag.starts_with('-') => {
                return Err(RunnerError::Argument(format!(
                    "unknown flag: {flag}\n\n{}",
                    usage()
                )));
            }
            _ => {
                if dataset_root.is_some() {
                    let arg = arg.to_string_lossy();
                    return Err(RunnerError::Argument(format!(
                        "unexpected extra positional argument: {arg}"
                    )));
                }
                dataset_root = Some(PathBuf::from(arg));
            }
        }
    }

    let Some(dataset_root) = dataset_root else {
        return Err(RunnerError::Argument(usage()));
    };

    Ok(Args {
        dataset_root,
        limit,
        json_out,
    })
}

// cargo-mutants: known-equivalent — usage() output is consumed only as stderr text in
// RunnerError::UsageMessage / RunnerError::Argument; no test or production caller asserts on its
// content. Mutating it to "" or "xyzzy" leaves all exit codes and JSON schema unchanged.
fn usage() -> String {
    "usage: epvme_runner <dataset-root> [--limit N] [--json-out PATH]".to_string()
}

fn collect_eml_files(root: &Path) -> RunnerResult<Vec<PathBuf>> {
    if !root.exists() {
        return Err(RunnerError::Argument(format!(
            "dataset root does not exist: {}",
            root.display()
        )));
    }
    if !root.is_dir() {
        return Err(RunnerError::Argument(format!(
            "dataset root is not a directory: {}",
            root.display()
        )));
    }

    let mut files = Vec::new();
    walk_eml_files(root, &mut files)?;
    files.sort();
    Ok(files)
}

fn walk_eml_files(root: &Path, files: &mut Vec<PathBuf>) -> RunnerResult<()> {
    let entries = fs::read_dir(root).map_err(|err| RunnerError::Filesystem {
        operation: "read directory",
        path: root.to_path_buf(),
        source: err,
    })?;
    for entry in entries {
        let entry = entry.map_err(|err| RunnerError::Filesystem {
            operation: "read directory entry",
            path: root.to_path_buf(),
            source: err,
        })?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|err| RunnerError::Filesystem {
            operation: "read file type",
            path: path.clone(),
            source: err,
        })?;
        if file_type.is_dir() {
            walk_eml_files(&path, files)?;
            continue;
        }
        if file_type.is_file() && is_eml_path(&path) {
            files.push(path);
        }
    }
    Ok(())
}

fn is_eml_path(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("eml"))
}

fn run_dataset<P>(
    dataset_root: &Path,
    files: &[PathBuf],
    limit: Option<usize>,
    parser: P,
) -> RunSummary
where
    P: Fn(&[u8]) -> Result<Content, ContentError>,
{
    let mut summary = RunSummary {
        dataset_root: dataset_root.display().to_string(),
        discovered_files: files.len(),
        processed_files: 0,
        ok_count: 0,
        panic_count: 0,
        read_failure_count: 0,
        parse_error_count: 0,
        limit,
        warning_counts: BTreeMap::new(),
        parse_error_counts: BTreeMap::new(),
        recorded_failures: Vec::new(),
    };

    let take_count = limit.unwrap_or(files.len());
    for path in files.iter().take(take_count) {
        summary.processed_files += 1;
        let raw = match fs::read(path) {
            Ok(raw) => raw,
            Err(err) => {
                summary.read_failure_count += 1;
                record_failure(
                    &mut summary,
                    path,
                    "read_error",
                    format!("read {}: {err}", path.display()),
                );
                continue;
            }
        };

        match parse_one(&raw, &parser) {
            SampleOutcome::Ok(content) => {
                summary.ok_count += 1;
                for warning in content.security_warnings {
                    let label = rimap_content::test_support::warning_code_label(warning.code)
                        .unwrap_or_else(|| unknown_warning_code_label(warning.code))
                        .to_string();
                    *summary.warning_counts.entry(label).or_insert(0) += 1;
                }
            }
            SampleOutcome::ParseError(err) => {
                summary.parse_error_count += 1;
                let label = rimap_content::test_support::error_kind_label(&err)
                    .unwrap_or("Unknown")
                    .to_string();
                *summary.parse_error_counts.entry(label.clone()).or_insert(0) += 1;
                record_failure(&mut summary, path, label, err.to_string());
            }
            SampleOutcome::Panic(message) => {
                summary.panic_count += 1;
                record_failure(&mut summary, path, "panic", message);
            }
        }
    }

    summary
}

fn parse_one<P>(raw: &[u8], parser: P) -> SampleOutcome
where
    P: Fn(&[u8]) -> Result<Content, ContentError>,
{
    match panic::catch_unwind(AssertUnwindSafe(|| parser(raw))) {
        Ok(Ok(content)) => SampleOutcome::Ok(Box::new(content)),
        Ok(Err(err)) => SampleOutcome::ParseError(err),
        Err(payload) => SampleOutcome::Panic(panic_message(payload)),
    }
}

fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
    let payload = match payload.downcast::<String>() {
        Ok(message) => return *message,
        Err(payload) => payload,
    };

    let payload = match payload.downcast::<&'static str>() {
        Ok(message) => return (*message).to_string(),
        Err(payload) => payload,
    };

    let _payload = payload;
    "panic payload was not a string".to_string()
}

fn unknown_warning_code_label(code: WarningCode) -> &'static str {
    match code.severity() {
        rimap_content::WarningSeverity::Informational => "unknown_informational_warning",
        rimap_content::WarningSeverity::Adversarial => "unknown_adversarial_warning",
        _ => "unknown_warning",
    }
}

fn record_failure(summary: &mut RunSummary, path: &Path, kind: impl Into<String>, detail: String) {
    if summary.recorded_failures.len() >= MAX_RECORDED_FAILURES {
        return;
    }
    summary.recorded_failures.push(FailureRecord {
        path: path.display().to_string(),
        kind: kind.into(),
        detail,
    });
}

fn print_summary(summary: &RunSummary) -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "EPVME dataset root: {}", summary.dataset_root)?;
    writeln!(
        stdout,
        "Discovered .eml files: {}",
        summary.discovered_files
    )?;
    writeln!(stdout, "Processed files: {}", summary.processed_files)?;
    if let Some(limit) = summary.limit {
        writeln!(stdout, "Limit: {limit}")?;
    }
    writeln!(stdout, "Parsed successfully: {}", summary.ok_count)?;
    writeln!(stdout, "Parse errors: {}", summary.parse_error_count)?;
    writeln!(stdout, "Read failures: {}", summary.read_failure_count)?;
    writeln!(stdout, "Panics: {}", summary.panic_count)?;

    // cargo-mutants: known-equivalent — guard inversion would print the section header
    // "Parse error kinds:" with zero rows; stdout phrasing is human-facing only and no
    // test or production caller asserts on print_summary output. JSON schema
    // (RunSummary fields) and the success verdict are unaffected.
    if !summary.parse_error_counts.is_empty() {
        writeln!(stdout, "Parse error kinds:")?;
        for (kind, count) in &summary.parse_error_counts {
            writeln!(stdout, "  {kind}: {count}")?;
        }
    }

    // cargo-mutants: known-equivalent — guard inversion would print the section header
    // "Warning counts:" with zero rows; stdout phrasing is human-facing only and no
    // test or production caller asserts on print_summary output. JSON schema
    // (RunSummary fields) and the success verdict are unaffected.
    if !summary.warning_counts.is_empty() {
        writeln!(stdout, "Warning counts:")?;
        for (warning, count) in &summary.warning_counts {
            writeln!(stdout, "  {warning}: {count}")?;
        }
    }

    // cargo-mutants: known-equivalent — guard inversion would print the section header
    // "Recorded failures (showing up to 50):" with zero rows; stdout phrasing is
    // human-facing only and no test or production caller asserts on print_summary
    // output. JSON schema (RunSummary fields) and the success verdict are unaffected.
    if !summary.recorded_failures.is_empty() {
        writeln!(
            stdout,
            "Recorded failures (showing up to {MAX_RECORDED_FAILURES}):"
        )?;
        for failure in &summary.recorded_failures {
            writeln!(
                stdout,
                "  {} [{}] {}",
                failure.path, failure.kind, failure.detail
            )?;
        }
    }

    Ok(())
}

fn write_json_report(path: &Path, summary: &RunSummary) -> RunnerResult<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|err| RunnerError::Filesystem {
            operation: "create JSON report directory",
            path: parent.to_path_buf(),
            source: err,
        })?;
    }

    let json = serde_json::to_vec_pretty(summary).map_err(|err| RunnerError::JsonSerialize {
        path: path.to_path_buf(),
        source: err,
    })?;
    fs::write(path, json).map_err(|err| RunnerError::Filesystem {
        operation: "write JSON report",
        path: path.to_path_buf(),
        source: err,
    })
}

fn is_success(summary: &RunSummary) -> bool {
    summary.parse_error_count == 0 && summary.read_failure_count == 0 && summary.panic_count == 0
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test helpers construct temporary datasets"
)]
mod tests {
    use super::*;

    use tempfile::TempDir;

    fn write_sample(root: &Path, relative: &str, body: &[u8]) -> PathBuf {
        let path = root.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&path, body).unwrap();
        path
    }

    fn simple_email(body: &str) -> Vec<u8> {
        format!(
            "From: sender@example.com\r\nTo: user@example.com\r\nSubject: Test\r\n\r\n{body}\r\n"
        )
        .into_bytes()
    }

    #[test]
    fn collect_eml_files_walks_nested_tree() {
        let tempdir = TempDir::new().unwrap();
        let root = tempdir.path();
        write_sample(root, "1/one.eml", &simple_email("hello"));
        write_sample(root, "2/two.EML", &simple_email("world"));
        write_sample(root, "2/skip.txt", b"nope");

        let files = collect_eml_files(root).unwrap();

        assert_eq!(files.len(), 2);
        assert!(files.iter().all(|path| is_eml_path(path)));
    }

    #[test]
    fn run_dataset_reports_parse_errors_by_kind() {
        let tempdir = TempDir::new().unwrap();
        let root = tempdir.path();
        let good = write_sample(root, "1/good.eml", &simple_email("hello"));
        let bad = write_sample(root, "1/bad.eml", &simple_email("trigger-malformed"));
        let files = vec![bad.clone(), good];

        let summary = run_dataset(root, &files, None, |raw| {
            if raw
                .windows("trigger-malformed".len())
                .any(|window| window == b"trigger-malformed")
            {
                return Err(ContentError::Malformed {
                    reason: "synthetic malformed fixture".to_string(),
                });
            }
            parse_message(raw)
        });

        assert_eq!(summary.processed_files, 2);
        assert_eq!(summary.ok_count, 1);
        assert_eq!(summary.parse_error_count, 1);
        assert_eq!(summary.parse_error_counts.get("Malformed"), Some(&1));
        assert_eq!(summary.recorded_failures.len(), 1);
        assert_eq!(summary.recorded_failures[0].path, bad.display().to_string());
        assert!(!is_success(&summary));
    }

    #[test]
    fn run_dataset_catches_panics_and_continues() {
        let tempdir = TempDir::new().unwrap();
        let root = tempdir.path();
        let panic_path = write_sample(root, "1/panic.eml", &simple_email("panic"));
        let ok_path = write_sample(root, "1/ok.eml", &simple_email("ok"));
        let files = vec![panic_path.clone(), ok_path];

        let summary = run_dataset(root, &files, None, |raw| {
            assert!(!raw.windows(5).any(|window| window == b"panic"), "boom");
            parse_message(raw)
        });

        assert_eq!(summary.processed_files, 2);
        assert_eq!(summary.ok_count, 1);
        assert_eq!(summary.panic_count, 1);
        assert_eq!(
            summary.recorded_failures[0].path,
            panic_path.display().to_string()
        );
        assert_eq!(summary.recorded_failures[0].kind, "panic");
        // Kills panic_message return-value mutants (327:5): detail must be the
        // actual panic message, not "" or "xyzzy".
        assert_eq!(summary.recorded_failures[0].detail, "boom");
    }

    #[test]
    fn panic_message_captures_string_payload() {
        let payload: Box<dyn std::any::Any + Send> = Box::new("static str message".to_string());
        assert_eq!(panic_message(payload), "static str message");
    }

    #[test]
    fn panic_message_captures_static_str_payload() {
        let payload: Box<dyn std::any::Any + Send> = Box::new("static literal");
        assert_eq!(panic_message(payload), "static literal");
    }

    #[test]
    fn panic_message_fallback_for_unknown_payload() {
        let payload: Box<dyn std::any::Any + Send> = Box::new(42u64);
        assert_eq!(panic_message(payload), "panic payload was not a string");
    }

    #[test]
    fn unknown_warning_code_label_informational() {
        // ParseBodyTruncated has Informational severity (see rimap-core/src/warning.rs).
        // Kills mutants 342:5 (return "" or "xyzzy") and 343:9 (delete Informational arm).
        assert_eq!(
            unknown_warning_code_label(WarningCode::ParseBodyTruncated),
            "unknown_informational_warning",
        );
    }

    #[test]
    fn unknown_warning_code_label_adversarial() {
        // UnicodeZeroWidthStripped has Adversarial severity (see rimap-core/src/warning.rs).
        // Kills mutants 342:5 (return "" or "xyzzy") and 344:9 (delete Adversarial arm).
        assert_eq!(
            unknown_warning_code_label(WarningCode::UnicodeZeroWidthStripped),
            "unknown_adversarial_warning",
        );
    }

    #[test]
    fn run_dataset_honors_limit() {
        let tempdir = TempDir::new().unwrap();
        let root = tempdir.path();
        let first = write_sample(root, "1/a.eml", &simple_email("one"));
        let second = write_sample(root, "1/b.eml", &simple_email("two"));
        let files = vec![first, second];

        let summary = run_dataset(root, &files, Some(1), parse_message);

        assert_eq!(summary.discovered_files, 2);
        assert_eq!(summary.processed_files, 1);
        assert_eq!(summary.ok_count, 1);
    }

    #[test]
    fn run_dataset_aggregates_warning_counts() {
        let tempdir = TempDir::new().unwrap();
        let root = tempdir.path();
        let sample = write_sample(root, "1/zero-width.eml", &simple_email("te\u{200B}st"));
        let files = vec![sample];

        let summary = run_dataset(root, &files, None, parse_message);

        assert_eq!(summary.ok_count, 1);
        assert_eq!(
            summary.warning_counts.get("unicode_zero_width_stripped"),
            Some(&1)
        );
        assert!(is_success(&summary));
    }

    #[test]
    fn run_dataset_records_read_failures() {
        // Kills the read_failure_count += 1 mutants in run_dataset (line 276:44):
        // both += -> -= (would underflow usize) and += -> *= (would keep 0).
        let tempdir = TempDir::new().unwrap();
        let root = tempdir.path();
        let missing = root.join("does-not-exist.eml");
        let files = vec![missing.clone()];

        let summary = run_dataset(root, &files, None, parse_message);

        assert_eq!(summary.processed_files, 1);
        assert_eq!(summary.read_failure_count, 1);
        assert_eq!(summary.ok_count, 0);
        assert_eq!(summary.recorded_failures.len(), 1);
        assert_eq!(summary.recorded_failures[0].kind, "read_error");
        assert_eq!(
            summary.recorded_failures[0].path,
            missing.display().to_string()
        );
        assert!(!is_success(&summary));
    }
}
