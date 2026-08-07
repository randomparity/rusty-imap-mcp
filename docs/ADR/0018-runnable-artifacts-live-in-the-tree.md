# ADR-0018: Runnable artifacts live in the tree; ADR immutability binds the decision, not the artifact

**Status:** Accepted · 2026-08-06 · issue [#743](https://github.com/randomparity/rusty-imap-mcp/issues/743)

## Context

[ADR-0014](0014-synchronous-auth-audit-emission.md) rests on a measurement, and
reproduced the `emitcost` harness that produced it inline, under a heading that
told the reader to "drop it into a scratch crate depending on `rimap-audit` and
`rimap-core` by path, build `--release`, and pass a directory".

That instruction is what made the snippet rot. A scratch crate is *outside*
`rimap-audit` and `rimap-core`, so `#[non_exhaustive]` is in force in it. Both
of the harness's struct literals acquired the attribute after the ADR was
accepted — `rimap_audit::AuditOptions` by
[#715](https://github.com/randomparity/rusty-imap-mcp/issues/715),
`rimap_core::auth_event::AuthEvent` by
[#716](https://github.com/randomparity/rusty-imap-mcp/issues/716) — and each is
now E0639 at the reader's first `cargo build`.

Nothing caught it, and nothing in the workspace would have. `just test-doc` is
`cargo test --workspace --doc`, which compiles fenced Rust in *rustdoc comments*
and reaches no markdown file. The repo already leans on that mechanism to keep
`#[non_exhaustive]` honest — the `compile_fail` doctest for
`rimap_config::model::ImapConfig` (#665) and the `compile_fail,E0639` one for
`rimap_audit::record::ProcessEnd` (#706) exist precisely because a doctest
compiles as its own crate — but the ADR body was never inside it.

The repair was not made in #715 because `docs/ADR/README.md` says each ADR is
immutable once accepted, and ADR-0014 is Accepted. So the question this ADR
answers is not "how do we fix two literals" — it is what immutability is *for*,
and which repairs it forbids.

Immutability exists so a decision cannot be quietly rewritten after the fact:
the record of what was chosen, on what grounds, against which alternatives, has
to stay stable or it stops being evidence. A rotted measurement harness is not
any of that. It is a tool the decision cites, and keeping a copy that does not
compile is not fidelity to the record — the record is in git either way — it is
a defect that a reader hits by doing what the document tells them to do.

## Decision

**Runnable artifacts are committed to the tree, not embedded in ADR bodies.**
An ADR that cites a harness, script, or reproducer the reader is told to execute
links to a committed location that the workspace's existing build gates already
compile. Illustrative fragments — a signature, a single expression quoted to
make a sentence concrete — are not runnable artifacts and stay inline.

**Immutability binds the whole accepted document**, not a list of section
names — an ADR's sections vary, and ADR-0014's own measurement table lives
under a heading (`What the change costs`) that no such list would have caught.
Revising a decision still requires a superseding ADR with both `Status` fields
and the `Supersedes` / `Superseded-by` links updated.

**Exactly two edits to an accepted ADR are permitted, and no others:**

1. Replacing an embedded runnable artifact with a pointer to its committed
   location. This may rewrite the prose that says how to obtain and run the
   artifact, because that prose describes an arrangement that no longer holds;
   it may not touch the surrounding argument, and it may not change any claim
   the decision rests on.
2. Appending a dated entry to an `## Errata` section at the end of the file.

Every exercise of (1) is recorded by an entry under (2), naming what was
replaced, why, and that the pre-edit text is in git history. An errata entry
states facts about the record; it does not restate, extend, or soften the
decision. Anything that would is a superseding ADR.

**`emitcost` is committed at `crates/rimap-audit/examples/emitcost.rs`**, and
ADR-0014's harness section links to it.

### The gate, and what it does not cover

An example target compiles as its own crate against `rimap-audit` as a
dependency — the same position as the reader's scratch crate, so
`#[non_exhaustive]` is in force on both offending types. It is built by
`just lint` — `cargo clippy --workspace --all-targets --all-features --locked
-- -D warnings`, which `just ci` runs — and by `just test-msrv`'s
`--all-targets` check. In CI it is built three more times: the `clippy` job
runs the same command, and the `check` and `test (MSRV)` jobs both pass
`--all-targets`. (`just check` also builds it, but is not one of `just ci`'s
prerequisites.) No new recipe, no new CI job: the next `#[non_exhaustive]`,
renamed field, or changed constructor signature that touches this harness
reddens the required lint check on the PR that introduces it.

An example rather than a doctest because a doctest cannot be handed a directory
and run; the harness's whole purpose is to be executed against real storage, and
`cargo run -p rimap-audit --release --example emitcost -- <dir>` is a thing an
operator can do that "drop it into a scratch crate" was not.

What this does **not** cover: fenced Rust in markdown, anywhere in this repo.
Nothing compiles it, this change adds nothing that does, and the remaining
`rust` fences in [ADR-0013](0013-per-field-defaults-merge.md) and ADR-0014 are
untouched. Both are fragments — one `let` binding, one bare `.await` expression
— that never compiled standalone and were never claimed to. The rule above is
what keeps a *runnable* artifact out of that ungated position; it is enforced by
review, not by a check.

## Alternatives considered

- **Supersede ADR-0014.** Rejected. Its decision — every `auth` record written
  synchronously on the producing thread — is unchanged and in force. A
  `Superseded-by` marker on it would tell a reader to stop relying on a rule
  that is still the rule, to fix a code block. Superseding is the instrument for
  a decision that changed; nothing about this one did.

- **Append-only errata alone, leaving the broken snippet in place.** Rejected.
  It satisfies the letter of immutability and fails the reader: the erratum
  would sit fifty lines below the snippet, and the reader who followed the
  instruction has already copied the code and hit E0639 before reaching it. A
  document that fails when followed is a defect; an appendix noting the defect
  does not repair it.

- **Fix the two literals in place, no rule change.** Rejected. That is the
  drive-by edit #715 correctly declined. Doing it now without amending the rule
  makes immutability advisory-by-precedent, which is worse than either keeping
  it strict or bounding it explicitly — the next editor gets to decide what
  counts as a small enough fix.

- **A `docs/measurements/` directory holding the harness as a loose `.rs`
  file.** Rejected. A `.rs` file that is not a cargo target is compiled by
  nothing, which is the defect being fixed, restated one directory over. The
  file scope this issue names includes that option; it does not survive the
  requirement that the fix add a gate.

- **A gate that compiles every fenced `rust` block under `docs/`.** Rejected as
  out of proportion, and worth saying why rather than leaving it implied. The
  fences that would be in scope are overwhelmingly fragments: two in the ADR
  directory after this change, and many more under
  `docs/superpowers/specs/` and `docs/superpowers/plans/` that are historical
  planning records and were never claimed to be runnable. Every one of them
  would need either a tagged fence — an edit to two accepted ADRs that the
  amendment above deliberately does not permit — or an allowlist, which grows
  silently and stops meaning anything. The rule that runnable artifacts are
  committed targets is the same protection without the annotation debt.

## Consequences

- `docs/ADR/README.md`'s immutability paragraph now points here for what
  immutability covers. Both permitted edits are exercised on ADR-0014 in the
  same change that accepts this ADR: its harness section became a link, and it
  gained an `## Errata` section recording that.

- `emitcost` is a target in the `rimap-audit` package and ships in its published
  contents. It has no dependencies beyond `rimap-audit`'s own and
  `rimap-core`, which is already a normal dependency, so nothing is added to the
  dependency graph.

- The harness is now maintained code subject to the workspace lint set. What it
  measures is unchanged from the version in ADR-0014 — same 50-emit warmup,
  same 2000-sample default, rotation off, `fail_open` false, same percentiles —
  but it reports errors rather than panicking and writes through a locked
  stdout handle, because the workspace denies `unwrap_used` and `print_stdout`
  and warns `expect_used`, which the `-D warnings` lint arms make fatal. That
  is a real cost of committing it, and it is the right one: the snippet was
  exempt from those lints only because nothing compiled it.

- It also gained a refusal the snippet did not have: it will not start unless
  its directory is empty or absent. A scratch snippet that opens at
  `Seq::FIRST` and appends fabricated `auth` records is harmless; a committed,
  published example a reader may point at a configured `audit.path` is not.
  Two outcomes, and the second is the one that shaped the check: against a file
  that already holds records it restarts the `seq` chain, which is at least
  loud; against a real audit directory whose active file is absent — a fresh
  install, or one whose active file was rotated away — a filename-only guard
  would pass, `Seq::FIRST` would collide with nothing, and `rimap-server`'s
  boot path would resume from `last_seq` and adopt the fabricated block as
  chain history with no anomaly left to find. Emptiness is the property that
  excludes both.

  What it does not do: it is a guard against an operator's slip, not a security
  control. `AuditWriter::open` is public API, so a local attacker gains nothing
  from this binary that twenty lines of their own would not give them, and the
  check is not atomic against a directory that gains an entry immediately after
  it. The writer's own `O_NOFOLLOW` and exclusive `flock` are what defend the
  symlink and racing-server cases, and they predate this change.

  This is the standing cost of the decision above. Committing an artifact means
  owning the ways it can be misused; the version in the ADR body was exempt only
  because nobody could run it.

- An ADR author who wants to show a reader how to reproduce something now has
  more work to do: commit the artifact first, then link it. This is intended.
  The alternative is what produced #743.

- The two permitted edits are checked by review. Nothing mechanically prevents a
  wider edit to an accepted ADR; git history is what makes one visible.
