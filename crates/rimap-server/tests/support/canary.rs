//! Secret-leak canary sweep shared by the wire e2e suites (issue #528, ADR-0010).
//! Each suite injects a canary password and, at teardown, asserts it appears in
//! no artifact the run produced. See
//! `docs/superpowers/specs/2026-07-14-issue-528-secret-leak-canary-design.md`.
// NOTE: declare ONLY lints this file actually triggers — an unfulfilled
// `#[expect]` is itself an error under `-D warnings`. This module uses `panic!`
// (in `assert_absent`) but no `.expect()` and no `.unwrap()`, so only
// `clippy::panic` is expected.
#![expect(clippy::panic, reason = "test assertions render diagnostics")]

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Fixed high-entropy sentinel that IS the Dovecot fixture password. MUST match,
/// byte for byte:
///   crates/rimap-imap/tests/integration/dovecot/users   (source of truth)
///   crates/rimap-imap/tests/integration/support/container.rs
/// Contains no ':' — the passwd-file field separator.
pub const DOVECOT_CANARY_PASSWORD: &str = "RIMAP-CANARY-DVC-9f83b1a7c0d6e4f2";

/// Mint a unique, high-entropy, per-run canary password for fake-backed / env-fed
/// suites (the fake accepts any LOGIN). The `RIMAP-CANARY-` prefix makes any leak
/// instantly attributable in an artifact dump. Same entropy recipe as the Dovecot
/// harness's `uuid_like` (`SystemTime` nanos + pid + process-local counter).
pub fn fresh_canary() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("RIMAP-CANARY-{nanos:x}-{pid:x}-{n:x}")
}

/// One place the canary appeared.
pub struct CanaryHit {
    /// A file path, or `extra[N]` for an in-memory string.
    pub source: String,
    /// Context window around the match, canary masked as `<CANARY>`.
    pub excerpt: String,
}

/// Outcome of a scan: hits found + artifacts that could not be read. A detector
/// that "could not look" must never be reported as clean, so both are surfaced.
pub struct ScanReport {
    pub hits: Vec<CanaryHit>,
    pub errors: Vec<String>,
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn excerpt_at(bytes: &[u8], at: usize, needle_len: usize, canary: &str) -> String {
    let start = at.saturating_sub(24);
    let end = (at + needle_len + 24).min(bytes.len());
    String::from_utf8_lossy(&bytes[start..end]).replace(canary, "<CANARY>")
}

/// Recursively scan regular files under each root (as bytes), plus each `extra`
/// string, for `canary`. Does not follow symlinks. Surfaces read/traversal
/// errors rather than swallowing them. Never panics.
pub fn scan(canary: &str, roots: &[&Path], extra: &[String]) -> ScanReport {
    let needle = canary.as_bytes();
    let mut report = ScanReport {
        hits: Vec::new(),
        errors: Vec::new(),
    };
    for root in roots {
        scan_path(root, needle, canary, &mut report);
    }
    for (i, s) in extra.iter().enumerate() {
        if let Some(at) = find_bytes(s.as_bytes(), needle) {
            report.hits.push(CanaryHit {
                source: format!("extra[{i}]"),
                excerpt: excerpt_at(s.as_bytes(), at, needle.len(), canary),
            });
        }
    }
    report
}

fn scan_path(path: &Path, needle: &[u8], canary: &str, report: &mut ScanReport) {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) => {
            report.errors.push(format!("{}: {e}", path.display()));
            return;
        }
    };
    let file_type = meta.file_type();
    if file_type.is_symlink() {
        return;
    }
    if file_type.is_dir() {
        let entries = match std::fs::read_dir(path) {
            Ok(rd) => rd,
            Err(e) => {
                report.errors.push(format!("{}: {e}", path.display()));
                return;
            }
        };
        for entry in entries {
            match entry {
                Ok(e) => scan_path(&e.path(), needle, canary, report),
                Err(e) => report.errors.push(format!("{}: {e}", path.display())),
            }
        }
        return;
    }
    if !file_type.is_file() {
        return;
    }
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            report.errors.push(format!("{}: {e}", path.display()));
            return;
        }
    };
    if let Some(at) = find_bytes(&bytes, needle) {
        report.hits.push(CanaryHit {
            source: path.display().to_string(),
            excerpt: excerpt_at(&bytes, at, needle.len(), canary),
        });
    }
}

/// Assert the canary is absent from every file artifact AND that every artifact
/// was readable; panic listing all hits and read errors otherwise. Thin wrapper
/// over `scan`. An unreadable root/file is a hard failure, not a silent skip.
pub fn assert_absent(canary: &str, roots: &[&Path], extra: &[String]) {
    let report = scan(canary, roots, extra);
    if report.hits.is_empty() && report.errors.is_empty() {
        return;
    }
    let mut lines = Vec::new();
    for h in &report.hits {
        lines.push(format!("  LEAK in {}: {}", h.source, h.excerpt));
    }
    for e in &report.errors {
        lines.push(format!("  UNREADABLE {e}"));
    }
    panic!(
        "canary sweep failed ({} leak(s), {} unreadable):\n{}",
        report.hits.len(),
        report.errors.len(),
        lines.join("\n"),
    );
}

/// Reference every public item so no e2e binary sees a partially-used module as
/// dead code. Mirrors the `force_use_for_dead_code_link` pattern in
/// `support/wire/harness.rs`. `assert_login_frame_only` is added in a follow-up
/// task.
#[expect(
    dead_code,
    reason = "type-link to suppress per-binary dead-code across e2e_wire binaries"
)]
fn force_use_for_dead_code_link() {
    let _ = DOVECOT_CANARY_PASSWORD;
    let _ = fresh_canary;
    let _ = scan;
    let _ = assert_absent;
    let hit = CanaryHit {
        source: String::new(),
        excerpt: String::new(),
    };
    let _ = (&hit.source, &hit.excerpt);
    let rep = ScanReport {
        hits: Vec::new(),
        errors: Vec::new(),
    };
    let _ = (&rep.hits, &rep.errors);
}
