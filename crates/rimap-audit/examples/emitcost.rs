//! Wall-clock cost of one synchronous `AuthEventSink::emit_auth` against a real
//! `AuditWriter` — the measurement behind
//! [ADR-0014](../../../docs/ADR/0014-synchronous-auth-audit-emission.md).
//!
//! ```text
//! cargo run -p rimap-audit --release --example emitcost -- <dir> [n]
//! ```
//!
//! `<dir>` is created if missing; `n` defaults to 2000 samples after a 50-emit
//! warmup. Build `--release`: ADR-0014's numbers are release numbers, and a
//! debug build measures the wrong thing. Point it at storage of the class you
//! care about — the finding the ADR rests on is that an fsync per record is
//! cheap on local storage, which is a claim about a filesystem, not about this
//! code.
//!
//! **Give it an empty scratch directory, never a configured `audit.path`.**
//! This writes `WARMUP + n` real-shaped `auth` records for a fabricated
//! account, and it opens at [`Seq::FIRST`] every time, which on a file that
//! already holds records restarts the sequence and puts duplicate `seq` values
//! into an append-only, tamper-evident log. It therefore refuses to start when
//! `<dir>/audit.jsonl` already exists — a refusal, rather than a
//! read-and-continue, because continuing a real log means writing fabricated
//! `auth` records into it, which is the outcome the check exists to prevent.
//!
//! Rotation is off and `fail_open` is false, so every sample is a steady-state
//! append: no rotation outlier, and a write failure fails the run rather than
//! being logged and counted as a fast success.
//!
//! ## Why this is a committed example and not a snippet in the ADR
//!
//! An example compiles as its own crate, so `#[non_exhaustive]` on
//! `AuditOptions` (#715) and `AuthEvent` (#716) is in force here exactly as it
//! is in a reader's scratch crate — and `just lint`'s `--all-targets` clippy
//! builds it, so it cannot rot unnoticed the way the ADR-embedded version did
//! (#743). See ADR-0018.

use std::io::Write as _;
use std::path::PathBuf;
use std::time::Instant;

use rimap_audit::{AuditOptions, AuditWriter, Seq};
use rimap_core::auth_event::{AuthEvent, AuthResult};
use rimap_core::auth_sink::AuthEventSink;

/// Emits discarded before sampling starts, to page in the file and warm the
/// allocator so the first real sample is not measuring cold-start cost.
const WARMUP: usize = 50;

/// Sample count when the caller does not pass one.
const DEFAULT_SAMPLES: usize = 2000;

/// A representative successful `auth` record: every optional field that the
/// production path populates is populated, so the serialized line is the length
/// the writer actually sees rather than a minimal one.
fn event() -> AuthEvent {
    let mut ev = AuthEvent::new(
        AuthResult::Success,
        "imap.example.test".to_string(),
        993,
        "alice@example.test".to_string(),
        Some("ab".repeat(32)),
        Some(true),
        None, // error_code
        None, // credential_source
    );
    ev.account = Some("alice".to_string());
    ev
}

/// `numerator/denominator` percentile of an already-sorted slice, by nearest
/// rank. `sorted` is non-empty at every call site.
fn percentile(sorted: &[f64], numerator: usize, denominator: usize) -> f64 {
    let idx = sorted.len().saturating_sub(1) * numerator / denominator;
    sorted.get(idx).copied().unwrap_or(f64::NAN)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let Some(dir) = args.next() else {
        return Err("usage: emitcost <dir> [n]".into());
    };
    let samples_wanted = match args.next() {
        Some(raw) => raw
            .parse::<usize>()
            .map_err(|e| format!("sample count {raw:?}: {e} — pass a positive integer"))?,
        None => DEFAULT_SAMPLES,
    };
    if samples_wanted == 0 {
        return Err("sample count must be at least 1".into());
    }

    let path = PathBuf::from(dir).join("audit.jsonl");
    if path.exists() {
        return Err(format!(
            "{} already exists — emitcost writes fabricated auth records and \
             restarts the seq chain at Seq::FIRST. Point it at an empty \
             directory.",
            path.display()
        )
        .into());
    }
    let writer = AuditWriter::open(&AuditOptions::new(path, Seq::FIRST))?;

    for _ in 0..WARMUP {
        AuthEventSink::emit_auth(&writer, event())?;
    }

    let mut samples = Vec::with_capacity(samples_wanted);
    for _ in 0..samples_wanted {
        let ev = event();
        let start = Instant::now();
        AuthEventSink::emit_auth(&writer, ev)?;
        samples.push(start.elapsed().as_secs_f64() * 1000.0);
    }
    samples.sort_by(f64::total_cmp);

    #[expect(
        clippy::cast_precision_loss,
        reason = "sample count is bounded by what fits in a Vec of f64; the \
                  mean is reported to 3 decimal places"
    )]
    let mean = samples.iter().sum::<f64>() / samples.len() as f64;

    // stdout via a locked handle, dodging the workspace `print_stdout` lint the
    // same way `rimap-server`'s audit-merge CLI does.
    let mut out = std::io::stdout().lock();
    writeln!(out, "n {samples_wanted}  mean {mean:.3}")?;
    writeln!(
        out,
        "p50 {:.3}  p95 {:.3}  p99 {:.3}  max {:.3}",
        percentile(&samples, 50, 100),
        percentile(&samples, 95, 100),
        percentile(&samples, 99, 100),
        percentile(&samples, 100, 100),
    )?;
    out.flush()?;
    Ok(())
}
