# ADR-0033: The Dependabot realign also writes the compiler-probe fixture lockfiles

**Status:** Accepted · 2026-11-12 · issue [#923](https://github.com/randomparity/rusty-imap-mcp/issues/923)

- **Supersedes:** the write-back set of
  [ADR-0016](0016-dependabot-fuzz-lock-auto-realign.md). ADR-0016 says the
  workflow "writes back only the two realigned lockfiles", meaning the fuzz
  lockfiles. This record widens that set to include the two compiler-probe
  fixture lockfiles. Every other decision in ADR-0016 is unchanged and is
  **not** superseded: the trigger, the actor and author gate, the overlay, the
  symlink defences, and the no-head-file-is-executed invariant. ADR-0017's push
  credential is also unchanged.

**Relates to:** [ADR-0027](0027-locked-downstream-compiler-probes.md), whose
fixture-lock parity gate this record pays for on Dependabot PRs.

## Context

ADR-0027 put the two `e0639-probe` fixture lockfiles under a parity gate
against the workspace `Cargo.lock`. The gate runs in the required `cargo-deny`
job. ADR-0027 records that "dependency and release-version updates must realign
both fixture locks". It wired that realign into `scripts/post-release-bump.sh`
for version bumps, but not into the ADR-0016 workflow for dependency bumps.

The result was the failure ADR-0016 exists to remove, reintroduced for a second
pair of lockfiles. Every Dependabot PR that moved a crate in the fixture graph
stayed red on `cargo-deny` until someone pushed
`just realign-compiler-probe-locks` by hand. #918 was the first to hit it. Its
tokio bump left `crates/rimap-audit/tests/fixtures/e0639-probe/Cargo.lock`
naming a tokio that the root lock no longer carried.

## Decision

`.github/workflows/dependabot-fuzz-lock.yml` runs
`just realign-compiler-probe-locks` after the fuzz realign and parity
re-check. It saves the fixture lockfiles beside the fuzz ones and allows them
in the apply step's guard. It stages them in the same automated commit.

The fixture realign preserves ADR-0016's invariant on its own terms.
`scripts/check-compiler-probe-locks.sh --fix` copies each fixture's
`Cargo.toml` and `src/` into a scratch directory, seeds that directory's lock
from the workspace `Cargo.lock`, and runs `cargo metadata` there. Its only
other subprocesses are `git rev-parse` and `git ls-files`. It compiles nothing.

The fixture `Cargo.toml` and `Cargo.lock` come from the PR head under the
overlay's existing `*/Cargo.toml` and `*/Cargo.lock` pathspecs, and are read as
data. The scope gate's blob-mode check and `core.symlinks=false` cover them as
they cover every other manifest. The script, the fixture `src/`, and the probe
test sources the script reads to discover fixtures all stay at the base
branch's version.

The write-back set is bounded twice. The save step lists fixture lockfiles with
`:(glob)crates/*/tests/fixtures/*/Cargo.lock`, where `*` stops at `/`. The apply
step refuses to push if any changed path falls outside
`(.*/)?fuzz/Cargo.lock` or `crates/<crate>/tests/fixtures/<fixture>/Cargo.lock`.

## Consequences

- Dependabot cargo PRs that move the fixture graph go green without a manual
  commit, the same as for the fuzz graph.
- The automated commit can now touch up to four lockfiles. Its message names
  both sets.
- Adding a compiler-probe fixture outside `crates/<crate>/tests/fixtures/<name>/`
  would make the save step miss it, and the `cargo-deny` gate would go red on
  the next Dependabot bump. Both fixtures live at that depth today, but
  `check-compiler-probe-locks.sh` does not require it.
- `html-oracle/Cargo.lock` remains a manual realign (`just realign-oracle-lock`,
  #699). Its repair runs `cargo check`, which compiles, so it cannot join this
  workflow under ADR-0016's invariant.

## Considered & rejected

- **A second workflow for the fixture locks.** Rejected. It would race the
  fuzz realign on the same PR branch with two pushes, and duplicate every
  control ADR-0016 records.
- **Realigning the fixture locks by hand on each Dependabot PR.** Rejected for
  the reason ADR-0016 rejected it for the fuzz locks: red CI becomes the normal
  state of the dependency queue.
- **Dropping the fixture locks from the required gate.** Rejected. It removes
  the reviewed-graph guarantee ADR-0027 exists to provide.
