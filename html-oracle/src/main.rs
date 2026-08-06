//! Differential HTML→text sanitizer oracle runner. See
//! `docs/superpowers/specs/2026-07-10-issue-529-differential-html-oracle-design.md`.

mod allowlist;
mod corpus;
mod diff;
mod norm;
mod reference;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde::Serialize;

use crate::diff::Verdict;

#[derive(Debug, Default, Serialize)]
struct Totals {
    total: usize,
    hard: usize,
    soft: usize,
    matched: usize,
    skipped: usize,
    ref_error: usize,
    compared_nonempty: usize,
    stale_allowlist_entries: usize,
}

#[derive(Debug, Serialize)]
struct InputReport {
    id: String,
    verdict: &'static str,
    reference_only: Vec<String>,
    production_only: Vec<String>,
    warnings: Vec<String>,
}

/// Per-input classification, returned by [`process_one`] so the `corpus/`-prefix
/// counts and canary check derive from one source of truth. Orthogonal to the
/// Match/Soft/Hard verdict, which stays in the global totals + report vecs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// `sanitize_html` errored before the binary guard was reached.
    SanitizeSkip,
    /// Skipped by `is_mostly_binary` (the guard fired).
    BinarySkip,
    /// The `lol_html` reference extractor errored.
    RefError,
    /// Reached the diff with an empty reference (no live comparison).
    ComparedEmpty,
    /// Reached the diff with a non-empty reference (a live comparison).
    ComparedNonempty,
}

/// A `corpus/`-prefixed input's `probes` families paired with its outcome.
struct CorpusRecord {
    probes: Vec<String>,
    kind: Kind,
}

/// `corpus/`-prefix counts, reported separately from the global totals so the
/// in-repo baseline cannot mask an all-skipped corpus. Coverage denominator is
/// `total − skipped − ref_error`.
#[derive(Debug, Default, Serialize)]
struct CorpusReport {
    total: usize,
    skipped: usize,
    ref_error: usize,
    compared_nonempty: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    min_compared: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    floor_breach: Option<String>,
    canary_failures: Vec<String>,
}

/// Comparison-layer hardening families whose healthy state is a *live comparison*.
const TEXT_TOKEN_FAMILIES: &[&str] = &["stray-tag-boundary", "entity-href"];
/// Family whose healthy state is *inverted*: skipped by `is_mostly_binary`.
const BINARY_FAMILY: &str = "binary-part";

#[derive(Debug, Serialize)]
struct Report {
    totals: Totals,
    #[serde(skip_serializing_if = "Option::is_none")]
    corpus: Option<CorpusReport>,
    hard_inputs: Vec<InputReport>,
    soft_inputs: Vec<InputReport>,
    stale_allowlist_inputs: Vec<String>,
}

struct Args {
    repo_root: PathBuf,
    report: PathBuf,
    epvme_dir: Option<PathBuf>,
    corpus_root: Option<PathBuf>,
    corpus_min_compared: Option<usize>,
    limit: Option<usize>,
}

enum ParsedArgs {
    Run(Box<Args>),
    Help,
    Error(String),
}

const USAGE: &str = "\
html-oracle — differential HTML→text sanitizer oracle

USAGE:
    html-oracle [OPTIONS]

OPTIONS:
    --repo-root <DIR>            Main-repo checkout: in-repo fuzz + injection seeds
    --corpus-root <DIR>          External corpus checkout (rusty-imap-mcp-corpus);
                                 loaded under `corpus/…` ids. Env: CORPUS_ROOT
    --epvme-dir <DIR>            Local EPVME dataset tree. Env: EPVME_DIR
    --corpus-min-compared <N>    Fail if fewer than N corpus/ inputs compare nonempty
    --limit <N>                  Cap source .eml files per external tree
    --report <FILE>              JSON report path (default: html-oracle/report.json)
    -h, --help                   Print this help
";

fn parse_args() -> ParsedArgs {
    parse_args_from(
        std::env::args().skip(1),
        std::env::var_os("EPVME_DIR").map(PathBuf::from),
        std::env::var_os("CORPUS_ROOT").map(PathBuf::from),
    )
}

fn parse_args_from<I: Iterator<Item = String>>(
    iter: I,
    epvme_env: Option<PathBuf>,
    corpus_env: Option<PathBuf>,
) -> ParsedArgs {
    let mut repo_root: Option<PathBuf> = None;
    let mut report: Option<PathBuf> = None;
    let mut epvme_dir = epvme_env;
    let mut corpus_root = corpus_env;
    let mut corpus_min_compared: Option<usize> = None;
    let mut limit: Option<usize> = None;
    let mut it = iter;
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--help" | "-h" => return ParsedArgs::Help,
            "--repo-root" => repo_root = it.next().map(PathBuf::from),
            "--report" => report = it.next().map(PathBuf::from),
            "--epvme-dir" => epvme_dir = it.next().map(PathBuf::from),
            "--corpus-root" => corpus_root = it.next().map(PathBuf::from),
            "--corpus-min-compared" => match it.next() {
                Some(v) => match v.parse() {
                    Ok(n) => corpus_min_compared = Some(n),
                    Err(_) => {
                        return ParsedArgs::Error(format!(
                            "--corpus-min-compared expects a non-negative integer, got {v:?}"
                        ));
                    }
                },
                None => {
                    return ParsedArgs::Error("--corpus-min-compared requires a value".to_string());
                }
            },
            "--limit" => limit = it.next().and_then(|v| v.parse().ok()),
            _ => {}
        }
    }
    let repo_root = repo_root.unwrap_or_else(|| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."))
    });
    let report =
        report.unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("report.json"));
    ParsedArgs::Run(Box::new(Args {
        repo_root,
        report,
        epvme_dir,
        corpus_root,
        corpus_min_compared,
        limit,
    }))
}

/// True when a decoded body is mostly Unicode replacement characters (`U+FFFD`),
/// the signature of a wrongly decoded or binary part rather than real HTML text.
/// Legitimate non-Latin text decodes to real codepoints, not `U+FFFD`, so a low
/// threshold does not exclude international content.
fn is_mostly_binary(text: &str) -> bool {
    let total = text.chars().filter(|c| !c.is_whitespace()).count();
    if total == 0 {
        return false;
    }
    let replacement = text.chars().filter(|c| *c == '\u{FFFD}').count();
    replacement * 10 > total
}

/// Accumulated per-input classification results.
#[derive(Default)]
struct Outcome {
    totals: Totals,
    hard_inputs: Vec<InputReport>,
    soft_inputs: Vec<InputReport>,
    seen_ids: BTreeSet<String>,
    corpus_records: Vec<CorpusRecord>,
}

/// Assemble the allowlist: the base `allowlist.toml` plus each loaded external
/// source's companion file (`epvme-allowlist.toml`, `corpus-allowlist.toml`).
/// See [`append_allowlist`] for why a source's file is merged only when loaded.
fn assemble_allowlist(with_epvme: bool, with_corpus: bool) -> Result<allowlist::Allowlist, String> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut text = std::fs::read_to_string(manifest.join("allowlist.toml")).unwrap_or_default();
    append_allowlist(&mut text, &manifest, with_epvme, "epvme-allowlist.toml");
    append_allowlist(&mut text, &manifest, with_corpus, "corpus-allowlist.toml");
    allowlist::load(&text).map_err(|e| e.to_string())
}

/// Concatenate a per-source allowlist file onto `text` when `enabled`. Merging
/// a source's file only when that source is loaded keeps its entries from
/// showing as stale in a run that does not load it. Concatenated `[[allow]]`
/// blocks parse as one array.
fn append_allowlist(text: &mut String, manifest: &Path, enabled: bool, file: &str) {
    if enabled && let Ok(extra) = std::fs::read_to_string(manifest.join(file)) {
        text.push('\n');
        text.push_str(&extra);
    }
}

/// Assemble the corpus: the in-repo sources, plus the external EPVME tree when
/// `--epvme-dir` is set.
fn assemble_inputs(args: &Args) -> Result<Vec<corpus::CorpusInput>, String> {
    let mut inputs = corpus::load(&args.repo_root).map_err(|e| e.to_string())?;
    if let Some(epvme_dir) = &args.epvme_dir {
        let mut extra =
            corpus::load_eml_tree(epvme_dir, "epvme", args.limit).map_err(|e| e.to_string())?;
        eprintln!(
            "html-oracle: EPVME corpus {} html part(s) from {}",
            extra.len(),
            epvme_dir.display()
        );
        inputs.append(&mut extra);
    }
    if let Some(corpus_root) = &args.corpus_root {
        let mut extra =
            corpus::load_corpus_tree(corpus_root, args.limit).map_err(|e| e.to_string())?;
        eprintln!(
            "html-oracle: corpus {} html part(s) from {}",
            extra.len(),
            corpus_root.display()
        );
        inputs.append(&mut extra);
    }
    Ok(inputs)
}

fn run_inputs(inputs: &[corpus::CorpusInput], allow: &allowlist::Allowlist) -> Outcome {
    let mut out = Outcome::default();
    for input in inputs {
        out.totals.total += 1;
        out.seen_ids.insert(input.id.clone());
        let kind = process_one(input, allow, &mut out);
        if input.id.split('/').next() == Some(corpus::CORPUS_ID_PREFIX) {
            out.corpus_records.push(CorpusRecord {
                probes: input.probes.clone(),
                kind,
            });
        }
    }
    out
}

fn process_one(
    input: &corpus::CorpusInput,
    allow: &allowlist::Allowlist,
    out: &mut Outcome,
) -> Kind {
    let Ok(prod) = rimap_content::test_support::sanitize_html(&input.raw, input.charset.as_deref())
    else {
        out.totals.skipped += 1;
        return Kind::SanitizeSkip;
    };
    let decoded = rimap_content::decode(&input.raw, input.charset.as_deref());
    if is_mostly_binary(&decoded) {
        // A part that decodes to mostly replacement characters is not HTML text;
        // two tokenizers shred byte-soup differently, so comparing it yields
        // noise, not sanitizer signal. Skip it.
        out.totals.skipped += 1;
        return Kind::BinarySkip;
    }
    let refx = match reference::extract_reference(&decoded) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("html-oracle: reference error on {}: {e}", input.id);
            out.totals.ref_error += 1;
            return Kind::RefError;
        }
    };
    let nonempty = !refx.text_tokens.is_empty() || !refx.href_ids.is_empty();
    if nonempty {
        out.totals.compared_nonempty += 1;
    }
    let divergence = diff::classify(&prod, &refx, &allow.tokens_for(&input.id));
    record_verdict(input, &prod, divergence, out);
    if nonempty {
        Kind::ComparedNonempty
    } else {
        Kind::ComparedEmpty
    }
}

fn corpus_report(records: &[CorpusRecord]) -> CorpusReport {
    let mut report = CorpusReport {
        total: records.len(),
        ..CorpusReport::default()
    };
    for rec in records {
        match rec.kind {
            Kind::SanitizeSkip | Kind::BinarySkip => report.skipped += 1,
            Kind::RefError => report.ref_error += 1,
            Kind::ComparedNonempty => report.compared_nonempty += 1,
            Kind::ComparedEmpty => {}
        }
    }
    report
}

/// Fail when the corpus comparison count is below the `--corpus-min-compared`
/// floor. A missing floor (`None`) means no check — the empty-corpus plumbing
/// proof and the wave's first nightly run without a baseline.
fn check_floor(compared_nonempty: usize, min: Option<usize>) -> Option<String> {
    let min = min?;
    if compared_nonempty < min {
        Some(format!(
            "corpus comparison floor breached: {compared_nonempty} < --corpus-min-compared {min}"
        ))
    } else {
        None
    }
}

/// Count the records tagged with `family`, and how many of them are `healthy`,
/// in a single pass: `(tagged_total, healthy)`.
fn tally_family(records: &[CorpusRecord], family: &str, healthy: Kind) -> (usize, usize) {
    records
        .iter()
        .filter(|r| r.probes.iter().any(|p| p == family))
        .fold((0, 0), |(tagged, ok), r| {
            (tagged + 1, ok + usize::from(r.kind == healthy))
        })
}

/// Assert direction-aware canary health over the `corpus/` records. Only
/// *present* families are checked (an empty corpus asserts nothing, keeping the
/// plumbing proof green); absent-family detection is deferred to the wave-1
/// baseline (#551). Text-token families must produce ≥1 live comparison;
/// `binary-part` is inverted — healthy only when skipped by `is_mostly_binary`.
fn check_canaries(records: &[CorpusRecord]) -> Vec<String> {
    let mut fails = Vec::new();
    for family in TEXT_TOKEN_FAMILIES {
        let (tagged, live) = tally_family(records, family, Kind::ComparedNonempty);
        if tagged > 0 && live == 0 {
            fails.push(format!(
                "canary family '{family}' has tagged inputs but produced 0 live comparisons — \
                 comparison-layer hardening regressed (its guard inputs went inert)"
            ));
        }
    }
    // Healthy when the is_mostly_binary guard fired at least once (≥1 BinarySkip)
    // — symmetric with the text families' ≥1-live rule, so a multipart canary
    // whose clean part also compares is not a false FAIL. Zero BinarySkip means
    // the guard did NOT fire on any tagged input: either it regressed (inputs
    // reached the comparison stage) or they errored earlier in sanitize. The
    // message names all three hypotheses so triage is not biased toward a false
    // security-regression conclusion.
    let (bin_tagged, via_guard) = tally_family(records, BINARY_FAMILY, Kind::BinarySkip);
    if bin_tagged > 0 && via_guard == 0 {
        fails.push(format!(
            "binary-part canary unhealthy (0/{bin_tagged} tagged inputs skipped via \
             is_mostly_binary): the is_mostly_binary guard regressed, this canary no longer \
             decodes to >10% U+FFFD, or it was skipped/errored by a different stage"
        ));
    }
    fails
}

fn record_verdict(
    input: &corpus::CorpusInput,
    prod: &rimap_content::test_support::HtmlResult,
    divergence: diff::Divergence,
    out: &mut Outcome,
) {
    let warnings: Vec<String> = prod
        .warnings
        .iter()
        .map(|w| format!("{:?}", w.code))
        .collect();
    let production_only: Vec<String> = divergence.production_only.into_iter().collect();
    let (verdict, reference_only) = match divergence.verdict {
        Verdict::Match => {
            out.totals.matched += 1;
            return;
        }
        Verdict::Soft { reference_only } => {
            out.totals.soft += 1;
            ("soft", reference_only)
        }
        Verdict::Hard { reference_only } => {
            out.totals.hard += 1;
            ("hard", reference_only)
        }
    };
    let report = InputReport {
        id: input.id.clone(),
        verdict,
        reference_only: reference_only.into_iter().collect(),
        production_only,
        warnings,
    };
    if verdict == "hard" {
        out.hard_inputs.push(report);
    } else {
        out.soft_inputs.push(report);
    }
}

fn print_summary(report: &Report) {
    eprintln!(
        "html-oracle: {} inputs, {} hard, {} soft, {} match, {} skipped, {} ref_error, {} compared",
        report.totals.total,
        report.totals.hard,
        report.totals.soft,
        report.totals.matched,
        report.totals.skipped,
        report.totals.ref_error,
        report.totals.compared_nonempty,
    );
    if report.totals.stale_allowlist_entries > 0 {
        eprintln!(
            "html-oracle: WARNING {} stale allowlist entries",
            report.totals.stale_allowlist_entries
        );
    }
    if let Some(corpus) = &report.corpus {
        eprintln!(
            "html-oracle: corpus/ {} inputs, {} skipped, {} ref_error, {} compared",
            corpus.total, corpus.skipped, corpus.ref_error, corpus.compared_nonempty,
        );
    }
}

fn exit_code(report: &Report, inert: bool) -> ExitCode {
    let mut failed = false;
    if report.totals.hard > 0 {
        eprintln!(
            "html-oracle: FAIL — {} silent-drop (HARD) divergence(s)",
            report.totals.hard
        );
        failed = true;
    }
    if inert {
        eprintln!("html-oracle: FAIL — oracle inert (compared_nonempty == 0)");
        failed = true;
    }
    if let Some(corpus) = &report.corpus {
        if let Some(breach) = &corpus.floor_breach {
            eprintln!("html-oracle: FAIL — {breach}");
            failed = true;
        }
        for canary in &corpus.canary_failures {
            eprintln!("html-oracle: FAIL — {canary}");
            failed = true;
        }
    }
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn main() -> ExitCode {
    let args = match parse_args() {
        ParsedArgs::Run(a) => *a,
        ParsedArgs::Help => {
            eprint!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        ParsedArgs::Error(msg) => {
            eprintln!("html-oracle: {msg}");
            return ExitCode::FAILURE;
        }
    };
    let allow = match assemble_allowlist(args.epvme_dir.is_some(), args.corpus_root.is_some()) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("html-oracle: invalid allowlist: {e}");
            return ExitCode::FAILURE;
        }
    };
    let inputs = match assemble_inputs(&args) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("html-oracle: corpus load failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    let mut outcome = run_inputs(&inputs, &allow);
    let stale: Vec<String> = allow
        .input_ids()
        .filter(|id| !outcome.seen_ids.contains(*id))
        .cloned()
        .collect();
    outcome.totals.stale_allowlist_entries = stale.len();
    // No `total > 0` guard: loading zero inputs is itself an inert run. Both
    // corpus loaders treat a missing directory as "not an error", so a refactor
    // that moves `fuzz/corpus/content_html` or `tests/injection-corpus` would
    // otherwise green with nothing compared (#699).
    let inert = outcome.totals.compared_nonempty == 0;

    let corpus = args.corpus_root.is_some().then(|| {
        let mut corpus = corpus_report(&outcome.corpus_records);
        corpus.min_compared = args.corpus_min_compared;
        corpus.floor_breach = check_floor(corpus.compared_nonempty, args.corpus_min_compared);
        corpus.canary_failures = check_canaries(&outcome.corpus_records);
        corpus
    });

    let report = Report {
        totals: outcome.totals,
        corpus,
        hard_inputs: outcome.hard_inputs,
        soft_inputs: outcome.soft_inputs,
        stale_allowlist_inputs: stale,
    };
    let json = serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".into());
    if let Err(e) = std::fs::write(&args.report, json) {
        eprintln!("html-oracle: failed to write report: {e}");
        return ExitCode::FAILURE;
    }
    print_summary(&report);
    exit_code(&report, inert)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_args(argv: &[&str]) -> Args {
        match parse_args_from(argv.iter().map(|s| s.to_string()), None, None) {
            ParsedArgs::Run(a) => *a,
            ParsedArgs::Help => panic!("expected Run, got Help"),
            ParsedArgs::Error(e) => panic!("expected Run, got Error: {e}"),
        }
    }

    #[test]
    fn parses_corpus_root_and_min_compared() {
        let a = run_args(&["--corpus-root", "/c", "--corpus-min-compared", "42"]);
        assert_eq!(a.corpus_root.as_deref(), Some(Path::new("/c")));
        assert_eq!(a.corpus_min_compared, Some(42));
    }

    #[test]
    fn corpus_root_defaults_from_env() {
        let p = PathBuf::from("/from-env");
        let parsed = parse_args_from(std::iter::empty(), None, Some(p.clone()));
        let ParsedArgs::Run(a) = parsed else {
            panic!("expected Run")
        };
        assert_eq!(a.corpus_root, Some(p));
    }

    #[test]
    fn explicit_corpus_root_overrides_env() {
        let parsed = parse_args_from(
            ["--corpus-root", "/cli"].iter().map(|s| s.to_string()),
            None,
            Some(PathBuf::from("/env")),
        );
        let ParsedArgs::Run(a) = parsed else {
            panic!("expected Run")
        };
        assert_eq!(a.corpus_root.as_deref(), Some(Path::new("/cli")));
    }

    #[test]
    fn help_flag_yields_help_and_names_both_roots() {
        for flag in ["--help", "-h"] {
            let parsed = parse_args_from([flag].iter().map(|s| s.to_string()), None, None);
            assert!(matches!(parsed, ParsedArgs::Help), "{flag}");
        }
        assert!(USAGE.contains("--repo-root"));
        assert!(USAGE.contains("--corpus-root"));
        assert!(USAGE.contains("--corpus-min-compared"));
    }

    #[test]
    fn unparsable_min_compared_is_an_error_not_a_silent_disable() {
        let parsed = parse_args_from(
            ["--corpus-min-compared", "notanumber"]
                .iter()
                .map(|s| s.to_string()),
            None,
            None,
        );
        assert!(matches!(parsed, ParsedArgs::Error(_)));
    }

    fn rec(probes: &[&str], kind: Kind) -> CorpusRecord {
        CorpusRecord {
            probes: probes.iter().map(|s| s.to_string()).collect(),
            kind,
        }
    }

    #[test]
    fn floor_fails_only_below_min() {
        assert!(check_floor(5, Some(10)).is_some());
        assert!(check_floor(10, Some(10)).is_none());
        assert!(check_floor(0, None).is_none());
    }

    #[test]
    fn canaries_empty_corpus_is_silent() {
        assert!(check_canaries(&[]).is_empty());
    }

    #[test]
    fn text_family_needs_a_live_comparison() {
        assert!(check_canaries(&[rec(&["stray-tag-boundary"], Kind::ComparedNonempty)]).is_empty());
        let fails = check_canaries(&[rec(&["entity-href"], Kind::ComparedEmpty)]);
        assert_eq!(fails.len(), 1);
        assert!(fails[0].contains("entity-href"));
    }

    #[test]
    fn binary_part_canary_is_inverted() {
        assert!(check_canaries(&[rec(&["binary-part"], Kind::BinarySkip)]).is_empty());
        let fails = check_canaries(&[rec(&["binary-part"], Kind::ComparedNonempty)]);
        assert_eq!(fails.len(), 1);
        assert!(fails[0].contains("is_mostly_binary"));
        assert!(fails[0].contains("no longer decodes"));
    }

    #[test]
    fn binary_part_canary_flags_non_guard_skip_without_misattribution() {
        let fails = check_canaries(&[rec(&["binary-part"], Kind::SanitizeSkip)]);
        assert_eq!(fails.len(), 1);
        assert!(fails[0].contains("different stage"));
    }

    #[test]
    fn binary_part_canary_tolerates_multipart_dilution() {
        // A canary eml with one binary part (guard fires) and one clean part
        // (compares) must stay healthy: the guard fired at least once.
        let fails = check_canaries(&[
            rec(&["binary-part"], Kind::BinarySkip),
            rec(&["binary-part"], Kind::ComparedNonempty),
        ]);
        assert!(fails.is_empty(), "{fails:?}");
    }

    #[test]
    fn corpus_report_tallies_kinds() {
        let records = [
            rec(&[], Kind::ComparedNonempty),
            rec(&[], Kind::BinarySkip),
            rec(&[], Kind::SanitizeSkip),
            rec(&[], Kind::RefError),
            rec(&[], Kind::ComparedEmpty),
        ];
        let report = corpus_report(&records);
        assert_eq!(report.total, 5);
        assert_eq!(report.skipped, 2);
        assert_eq!(report.ref_error, 1);
        assert_eq!(report.compared_nonempty, 1);
    }

    #[test]
    fn is_mostly_binary_flags_replacement_soup_only() {
        assert!(is_mostly_binary("\u{FFFD}\u{FFFD}\u{FFFD}abc"));
        // Legitimate international text has no replacement chars.
        assert!(!is_mostly_binary("Καλημέρα κόσμε"));
        assert!(!is_mostly_binary("hello world"));
        // A lone stray replacement char in real text is not enough to skip.
        assert!(!is_mostly_binary(
            "a normal sentence with one \u{FFFD} glitch"
        ));
        // Empty / whitespace-only is not binary.
        assert!(!is_mostly_binary("   "));
    }
}
