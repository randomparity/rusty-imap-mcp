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
//! account, and it opens at [`Seq::FIRST`] every time. Against a file that
//! already holds records that restarts the sequence, putting duplicate `seq`
//! values into an append-only, tamper-evident log; against a real audit
//! directory whose active file happens to be absent it is quieter and worse,
//! because `rimap-server` resumes from `last_seq` on the next boot and the
//! fabricated block becomes chain history with nothing anomalous to find.
//!
//! It therefore refuses to start unless the directory is empty or absent, and
//! refuses rather than continuing an existing chain — continuing means writing
//! fabricated `auth` records into a real log, which is the outcome being
//! prevented. See [`require_empty_or_absent`] for what that check does and
//! does not defend.
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

/// Refuses any `dir` that exists and holds anything at all. An absent `dir` is
/// fine — `AuditWriter::open` creates it.
///
/// Emptiness rather than "no `audit.jsonl`", because the quieter hazard is a
/// real audit directory whose active file is currently absent — a fresh
/// install, or one whose active file has been rotated away. There, a
/// filename-only check passes, `Seq::FIRST` collides with nothing, and
/// `rimap-server`'s boot path resumes from `last_seq` and adopts the
/// fabricated block as chain history with no anomaly to notice later. An
/// empty directory cannot be that.
///
/// This is a guard against an operator's slip, not against a local attacker:
/// `AuditWriter::open` is public API, so anyone with a shell can write these
/// records without this binary. It is also not atomic — the directory can
/// gain an entry between this check and the open — which does not matter for
/// what it defends. The writer's own `O_NOFOLLOW` and exclusive `flock` are
/// what stop a symlinked path or a racing live server.
fn require_empty_or_absent(dir: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    match std::fs::read_dir(dir) {
        Ok(mut entries) => {
            if entries.next().is_some() {
                return Err(format!(
                    "{} is not empty — emitcost writes fabricated auth records and \
                     opens at Seq::FIRST, so it must never share a directory with a \
                     real audit log. Point it at an empty or absent directory.",
                    dir.display()
                )
                .into());
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("reading {}: {e}", dir.display()).into()),
    }
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

    let dir = PathBuf::from(dir);
    require_empty_or_absent(&dir)?;
    let writer = AuditWriter::open(&AuditOptions::new(dir.join("audit.jsonl"), Seq::FIRST))?;

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
