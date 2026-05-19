# cargo-mutants runbook

cargo-mutants 27.0.0 hits a macOS-specific temp-tree bug
([sourcefrog/cargo-mutants#611](https://github.com/sourcefrog/cargo-mutants/issues/611),
project tracker [#235](https://github.com/randomparity/rusty-imap-mcp/issues/235))
that strands worker copies missing source files mid-run. The
project-default workaround is `--in-place`, which sidesteps the
temp-copy path entirely. See "The bug, in detail" below for the
mechanism.

## Blessed invocations

| Situation | Command |
|---|---|
| Quarterly workspace survey (per `fuzzing-coverage.md`) | `just mutants --workspace --timeout 60 -- --test-threads 1` |
| Single-package survey | `just mutants --package <crate>` |
| Single-mutant inspection (regex on mutant name) | `just mutants --package <crate> -F '<regex>'` |

The `just mutants` recipe is a thin wrapper around `cargo mutants
--in-place`. Pass any extra flags after the recipe name; they are
forwarded verbatim.

## Linux fast path (bypass `--in-place`)

The `--in-place` flag exists to dodge a macOS-specific cargo-mutants
bug ([#611](https://github.com/sourcefrog/cargo-mutants/issues/611)).
On Linux, the temp-tree path the bug affects is not exercised — you
can drop `--in-place` and run cargo-mutants directly with `--jobs N`
for proportional wall-clock speedup. The 2026-05-18 issue #289
baselines used:

```bash
cargo mutants --package rimap-server --no-shuffle --jobs 8 --timeout 60
cargo mutants --package rimap-imap  --no-shuffle --jobs 8 --timeout 60
```

The `rimap-server` baseline (529 mutants) finished in 22 minutes at
`--jobs 8` on a 48-thread Xeon w7-2495X, against the documented
~3.5h `--jobs 1` wall time for the macOS workaround path.

Trade-offs:

- **No `just mutants` wrapper.** Drop down to plain `cargo mutants`
  since the recipe forces `--in-place`. A future justfile change
  could pick the right invocation per `uname -s`, but is not done
  today.
- **Tune `--jobs` to physical cores.** Each worker spawns a full
  `cargo` invocation; rule of thumb `--jobs ≤ physical_cores / 2`,
  more aggressive if the box has tens of GiB of RAM headroom per
  worker.
- **No source-tree contention.** Workers operate on `target/mutants/`
  temp trees, so concurrent IDE / rust-analyzer work is fine.
- **Ctrl-C is safe.** The source tree is never mutated.

On macOS, do not use this path until cargo-mutants 27.0.1+ ships
containing [PR #613](https://github.com/sourcefrog/cargo-mutants/pull/613).

## What `--in-place` costs you

- **Locked to `--jobs 1`.** cargo-mutants refuses parallel jobs in
  `--in-place` mode because they would race on the same files. A
  workspace survey at `--jobs 1` runs in roughly 3.5 hours on the
  reference dev host (compare ~50 minutes if the temp-copy path were
  usable with `--jobs 4`).
- **Mutates the live tree.** A `Ctrl-C` mid-run can leave a mutated
  source file in place. Recover with `git restore <file>` (or
  `git restore .` if you do not know which file).
- **Cannot edit the same files concurrently.** Do not run `just
  mutants` against a crate you are actively editing; either finish
  your edit and commit, or stash first.
- **Conflicts with rust-analyzer / IDE rebuilds.** Either disable the
  language server for the run or expect noisy diagnostics while the
  tree is briefly mutated.

## Why not just downgrade to 25.x?

cargo-mutants 25.x predates the reflink path and so does not hit the
macOS `dirhelper` race at all. It would also unlock `--jobs N` on
macOS, recovering most of the wall-clock cost above. We chose
`--in-place` for four reasons:

- The development host has a documented RAM ceiling that high
  `--jobs` settings push past, freezing the box.
  `--in-place` forces `--jobs 1`, which neutralises that hazard for
  free.
- 25.x is roughly 18 months of missed mutant operators and bug fixes;
  the survey would catch a strictly smaller (and different) set of
  mutants than 26+.
- We do not pin cargo-mutants in this repo (it is `cargo install`-ed
  by `just setup`). Pinning to `=25.x` adds a maintenance step on
  every contributor box and a re-test when we eventually unpin.
- Cleanup when upstream lands a fix is one line (drop `--in-place`
  from the recipe). A version pin would mean an unpin + a fresh
  version-bump retest.

If wall-clock time on macOS becomes the binding constraint before
[#611](https://github.com/sourcefrog/cargo-mutants/issues/611) is
fixed (i.e. a tagged release containing
[PR #613](https://github.com/sourcefrog/cargo-mutants/pull/613)),
revisit this. Linux contributors can use the "Linux fast path"
section above today without changes.

## The bug, in detail

Symptom (verbatim from
[#235](https://github.com/randomparity/rusty-imap-mcp/issues/235)):

```
ERROR Worker thread failed: ".../cargo-mutants-rusty-imap-mcp-XXXXXX.tmp/crates/rimap-content/src/parse/sniff.rs" is not a file
Error: ".../crates/rimap-content/src/parse/sniff.rs" is not a file
```

`crates/rimap-content/src/parse/sniff.rs` is a regular UTF-8 source
file declared by `mod sniff;` in `parse/mod.rs` with no `#[path]`,
no symlinks, and no sibling subdirectories. The bug is in
cargo-mutants' temp-tree handling on macOS: a worker's per-mutant
scratch tree is missing `sniff.rs` (and other files — multiple vanish
silently) even though the source has them. Per the upstream
investigation in
[#611](https://github.com/sourcefrog/cargo-mutants/issues/611), the
macOS `dirhelper` background process unlinks the reflink copies that
[#557](https://github.com/sourcefrog/cargo-mutants/pull/557) (landed
in 26.0.0) introduced. Linux/btrfs, which also supports reflinks,
does not reproduce — so this is macOS-specific, not generic to
reflinks.

Diagnostic capture procedure (run from a clean tree; produces a log
plus a `diff` of source vs. leaked tempdir):

```bash
set -euo pipefail
mkdir -p /tmp/issue-235
cargo mutants --package rimap-content --jobs 1 --leak-dirs \
  2>&1 | tee /tmp/issue-235/repro-temp-copy.log

LEAKED=$(rg -o 'cargo-mutants-[A-Za-z0-9-]+\.tmp' \
  /tmp/issue-235/repro-temp-copy.log | head -1)
[ -n "$LEAKED" ] || { echo "no leaked tempdir found in log" >&2; exit 1; }
ls -la "/tmp/$LEAKED/crates/rimap-content/src/parse/"
diff <(ls crates/rimap-content/src/parse/) \
     <(ls "/tmp/$LEAKED/crates/rimap-content/src/parse/")

# Tempdirs are workspace-sized; delete once you have what you need.
# trash "/tmp/$LEAKED"   # if you have trash-cli
# rm -r "/tmp/$LEAKED"   # otherwise
```

The diff identifies which files the worker is missing. Attach to any
upstream report.

## Troubleshooting

- **`Worker thread failed: ... is not a file` on a clean run.** You
  forgot `--in-place` (or used bare `cargo mutants` instead of `just
  mutants`). Re-run via the recipe.
- **Mutated file left after Ctrl-C.** `git status` will show the
  mutated file as modified. `git restore <file>` to recover.
- **`error: cannot run --in-place with --jobs N` for N > 1.** Drop
  the `--jobs` flag; in-place mode is single-threaded by design.
- **Run takes too long.** Scope to a single package
  (`--package <crate>`) or a single regex (`-F '<regex>'`). The
  workspace survey is intentionally a quarterly cadence, not a
  per-PR check.

## When the upstream fix lands

Cleanup checklist (do all in one PR, close
[#235](https://github.com/randomparity/rusty-imap-mcp/issues/235)):

1. Bump cargo-mutants in any pinned tooling and confirm the bare
   `cargo mutants --package rimap-content` command runs to completion.
2. Drop `--in-place` from the `mutants` recipe in `justfile` (or
   delete the recipe and document the bare command if no other
   wrapping is needed).
3. Remove the `#611` workaround comment block from
   `.cargo/mutants.toml` (and the cross-link to this runbook in that
   comment). Decide whether the remaining `minimum_test_timeout` /
   `timeout_multiplier` entries are still load-bearing; delete the
   file if not.
4. Strike the "Known issue" subsection from
   `docs/security/fuzzing-coverage.md`, restore the bare
   `cargo mutants` survey command.
5. Delete this runbook (the "Why not downgrade to 25.x?" subsection
   and the diagnostic capture procedure go with it).
6. Remove the runbook row from `docs/INDEX.md`.
7. Comment on
   [#235](https://github.com/randomparity/rusty-imap-mcp/issues/235)
   with the upstream fix release tag, then close.
