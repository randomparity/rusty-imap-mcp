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

#[derive(Debug, Serialize)]
struct Report {
    totals: Totals,
    hard_inputs: Vec<InputReport>,
    soft_inputs: Vec<InputReport>,
    stale_allowlist_inputs: Vec<String>,
}

struct Args {
    repo_root: PathBuf,
    report: PathBuf,
    epvme_dir: Option<PathBuf>,
    limit: Option<usize>,
}

fn parse_args() -> Args {
    let mut repo_root: Option<PathBuf> = None;
    let mut report: Option<PathBuf> = None;
    let mut epvme_dir: Option<PathBuf> = std::env::var_os("EPVME_DIR").map(PathBuf::from);
    let mut limit: Option<usize> = None;
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--repo-root" => repo_root = it.next().map(PathBuf::from),
            "--report" => report = it.next().map(PathBuf::from),
            "--epvme-dir" => epvme_dir = it.next().map(PathBuf::from),
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
    Args {
        repo_root,
        report,
        epvme_dir,
        limit,
    }
}

/// True when a decoded body is mostly Unicode replacement characters (`U+FFFD`),
/// the signature of a mis-decoded / binary part rather than real HTML text.
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

fn main() -> ExitCode {
    let args = parse_args();

    let allowlist_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("allowlist.toml");
    let allow_text = std::fs::read_to_string(&allowlist_path).unwrap_or_default();
    let allow = match allowlist::load(&allow_text) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("html-oracle: invalid allowlist: {e}");
            return ExitCode::FAILURE;
        }
    };

    let mut inputs = match corpus::load(&args.repo_root) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("html-oracle: corpus load failed: {e}");
            return ExitCode::FAILURE;
        }
    };
    if let Some(epvme_dir) = &args.epvme_dir {
        match corpus::load_eml_tree(epvme_dir, "epvme", args.limit) {
            Ok(mut extra) => {
                eprintln!(
                    "html-oracle: EPVME corpus {} html part(s) from {}",
                    extra.len(),
                    epvme_dir.display()
                );
                inputs.append(&mut extra);
            }
            Err(e) => {
                eprintln!("html-oracle: EPVME load failed: {e}");
                return ExitCode::FAILURE;
            }
        }
    }

    let mut seen_ids: BTreeSet<String> = BTreeSet::new();
    let mut totals = Totals::default();
    let mut hard_inputs = Vec::new();
    let mut soft_inputs = Vec::new();

    for input in &inputs {
        totals.total += 1;
        seen_ids.insert(input.id.clone());

        let prod = match rimap_content::test_support::sanitize_html(
            &input.raw,
            input.charset.as_deref(),
        ) {
            Ok(r) => r,
            Err(_) => {
                totals.skipped += 1;
                continue;
            }
        };
        let decoded = rimap_content::decode(&input.raw, input.charset.as_deref());
        if is_mostly_binary(&decoded) {
            // A part that decodes to mostly replacement characters is not HTML
            // text; two tokenizers shred byte-soup differently, so comparing it
            // yields noise, not sanitizer signal. Skip it.
            totals.skipped += 1;
            continue;
        }
        let refx = match reference::extract_reference(&decoded) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("html-oracle: reference error on {}: {e}", input.id);
                totals.ref_error += 1;
                continue;
            }
        };

        if !refx.text_tokens.is_empty() || !refx.href_ids.is_empty() {
            totals.compared_nonempty += 1;
        }

        let allow_tokens = allow.tokens_for(&input.id);
        let divergence = diff::classify(&prod, &refx, &allow_tokens);
        let warnings: Vec<String> = prod
            .warnings
            .iter()
            .map(|w| format!("{:?}", w.code))
            .collect();
        let production_only: Vec<String> = divergence.production_only.into_iter().collect();

        match divergence.verdict {
            Verdict::Match => totals.matched += 1,
            Verdict::Soft { reference_only } => {
                totals.soft += 1;
                soft_inputs.push(InputReport {
                    id: input.id.clone(),
                    verdict: "soft",
                    reference_only: reference_only.into_iter().collect(),
                    production_only,
                    warnings,
                });
            }
            Verdict::Hard { reference_only } => {
                totals.hard += 1;
                hard_inputs.push(InputReport {
                    id: input.id.clone(),
                    verdict: "hard",
                    reference_only: reference_only.into_iter().collect(),
                    production_only,
                    warnings,
                });
            }
        }
    }

    let stale: Vec<String> = allow
        .input_ids()
        .filter(|id| !seen_ids.contains(*id))
        .cloned()
        .collect();
    totals.stale_allowlist_entries = stale.len();

    let inert = totals.total > 0 && totals.compared_nonempty == 0;

    let report = Report {
        totals,
        hard_inputs,
        soft_inputs,
        stale_allowlist_inputs: stale,
    };
    let json = serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".into());
    if let Err(e) = std::fs::write(&args.report, json) {
        eprintln!("html-oracle: failed to write report: {e}");
        return ExitCode::FAILURE;
    }

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

    if report.totals.hard > 0 {
        eprintln!(
            "html-oracle: FAIL — {} silent-drop (HARD) divergence(s)",
            report.totals.hard
        );
        ExitCode::FAILURE
    } else if inert {
        eprintln!("html-oracle: FAIL — oracle inert (compared_nonempty == 0)");
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
