# Local Test Runtime Trim — Narrow Hook Compile Scope and Add `just test-fast`

**Date:** 2026-05-20
**Status:** Design approved; implementation pending
**Scope:** Developer tooling only. No runtime code changes, no CI workflow
changes, no test code refactor.
**Builds on:** [`2026-05-15-pre-push-hook-trim-design.md`](2026-05-15-pre-push-hook-trim-design.md)

## Problem

Local commit/push hooks and the inner-loop test command have grown to the
point where:

1. `git push` regularly drops the ref transfer on cold target/, because
   pre-push hooks exceed github.com's ~30 s SSH idle window. The prior
   `pre-push-hook-trim` spec replaced `just test` at pre-push with
   `cargo check --workspace --all-targets --locked`, which fixed the warm
   case but explicitly flagged cold target/ as still-unsolved.
2. `just test` takes 90–120 s warm on a 48-core / 250 GB workstation
   (and proportionally worse on weaker laptops). Developers either skip
   it before pushing (and find out from CI) or wait minutes per change.

Empirical timings, measured 2026-05-20 on the maintainer's workstation
(Fedora 43, 48 cores, 250 GB, warm `~/.cargo/registry`):

| stage | warm (s) | cold (s) | warm-repeat (s) |
|---|---|---|---|
| pre-commit `cargo clippy --workspace --all-targets --locked -- -D warnings` | 2.5 | 23.2 | 2.5 |
| pre-commit (fmt-check + shellcheck + shfmt + actionlint + zizmor + typos + branch + macros) | <1 total | <1 | <1 |
| pre-push `cargo check --workspace --all-targets --locked` (no preceding clippy) | 4.0 | 21.7 | 1.1 |
| pre-push `cargo deny check advisories bans` (advisory-db on disk) | 0.5 | 0.5 | 0.5 |
| `just test` (`cargo nextest run --workspace --locked`) | 118.8 | n/a | 91.9 |
| `just test-msrv` (MSRV check + nextest, MSRV target partially warm) | n/a | 140.6 | n/a |

Cold-cache numbers on a 4–8-core developer laptop are typically 3–10×
these — easily 60–180 s for cold `cargo check --workspace --all-targets`.
That is the regime in which the SSH idle window blows.

Per-test-binary breakdown of `just test`:

| binary | sum-of-test-times (s) | test count | type |
|---|---|---|---|
| `rimap-imap::dovecot` | 332.5 | 43 | container |
| `rimap-server::e2e_wire` | 34.1 | 5 | container |
| `rimap-content::proptest_html_lookalike` | 33.4 | 3 | proptest |
| `rimap-server::e2e_wire_cancellation` | 32.2 | 5 | container |
| `rimap-server::e2e` | 17.2 | 1 | container |
| everything else combined (~1350 tests) | ~13 | ~1350 | unit |

≈ 97 % of `just test` wall clock is the five heavy binaries above. The
other ~1350 unit tests run in single-digit seconds combined. nextest
already caps container-backed binaries to 4 parallel threads via
`.config/nextest.toml`, so further parallelism inside `just test` is not
the lever.

## Root cause

Two distinct sources of avoidable cost.

### 1. `--all-targets` in the hooks compiles test binaries the hooks never run

Both pre-commit clippy and pre-push check use `--workspace --all-targets`.
`--all-targets` expands to `--lib --bins --tests --examples --benches`.
Neither hook executes tests; the test/example/bench artifacts exist
only to ensure they compile.

Measured impact of dropping `--all-targets` (same workstation,
`cargo clean` between cold runs):

| invocation | cold (s) | warm-repeat (s) |
|---|---|---|
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | 23.2 | 2.5 |
| `cargo clippy --workspace --lib --bins --locked -- -D warnings` | 19.7 | 1.4 |
| `cargo check --workspace --all-targets --locked` | 21.7 | 1.1 (post-clippy) |
| `cargo check --workspace --lib --bins --locked` | 19.4 | 2.1 (post-clippy with different flags) |

The cold savings are smaller than naive volume math would suggest
(~15 % here, not ~50 %), because dep-graph compilation dominates and
parallelizes across this machine's 48 cores. On a 4–8-core laptop the
relative savings should be larger — test binaries are the part that
*stops* parallelizing first once core count runs out — but we can't
measure that here directly. The warm-repeat win is real and consistent
(~40–50 % faster).

The bigger argument is correctness of intent: spending compile budget
on test/example/bench artifacts at *commit* and *push* time is the
wrong place to pay it. CI runs `cargo nextest run --workspace` on every
push and PR, which is a strict superset of "test code compiles." The
only thing the hook adds today is local feedback ~5 minutes earlier than
the CI run, paid every commit/push.

### 2. `just test` is dominated by container + proptest binaries that don't belong in the inner loop

The five heavy binaries (dovecot, e2e, e2e_wire, e2e_wire_cancellation,
proptest_html_lookalike) provide high-value coverage — Dovecot wire
behavior, MCP e2e, HTML adversarial properties — but each test takes
10–25 s of wall clock and the suite is dominated by them. They're the
right thing to run on CI and before a push that touches their surface;
they're the wrong thing to run after every two-line edit.

The other ~1350 tests are pure unit tests with no external dependencies.
They finish in <10 s on this hardware and would still finish in <30 s on
a weak laptop. There is no fast-tier `just` target today, so developers
either run `just test` (slow, often skipped) or no test at all.

## Desired behavior

After this change:

1. **Pre-commit cold target/:** ≈ 20 s on this hardware (down from 23 s,
   modest absolute gain), warm-repeat ≈ 1.4 s (down from 2.5 s).
   Estimated proportionally larger savings on lower-core-count laptops.
   Lint coverage for `--lib --bins` is unchanged; lint coverage for
   `--tests --examples --benches` moves entirely to CI.
2. **Pre-push cold target/:** ≈ 20 s on this hardware (down from 22 s),
   warm (post-pre-commit) ≈ 2 s. SSH idle window comfortably honored in
   the warm case; cold-laptop case marginally improved, with the
   documented `GIT_SSH_COMMAND` keepalive remaining as the escape hatch
   when needed.
3. **Inner-loop tests:** `just test-fast` measured at 4.2 s warm here
   (target: ≤ 10 s warm, ≤ 30 s on a weak laptop) versus 91.9 s for
   `just test`. Runs the ~1380 unit tests; skips the five heavy
   binaries.
4. **Pre-push and CI test coverage:** Unchanged. `just test`, `just
   test-msrv`, `just ci`, and the CI workflow all keep running the full
   sweep. Nothing previously enforced loses coverage; we only add a
   faster inner-loop alternative.

Approach A's standalone value is modest on this hardware — the headline
win is Approach B's inner-loop test command. A is still worth shipping
in the same change because it's a single-line edit, scales better on
weaker hardware, and tightens the alignment between hook intent ("did
this commit break the build?") and hook scope.

## Approach

Two complementary, independent changes. Either could ship alone; both
together is the goal.

### A. Drop `--all-targets` from pre-commit clippy and pre-push check

Single-file edit to `.pre-commit-config.yaml`:

```yaml
# Pre-commit: was
- id: cargo-clippy
  entry: cargo clippy --workspace --all-targets --locked -- -D warnings
# Pre-commit: becomes
- id: cargo-clippy
  entry: cargo clippy --workspace --lib --bins --locked -- -D warnings

# Pre-push: was
- id: cargo-check
  entry: cargo check --workspace --all-targets --locked
# Pre-push: becomes
- id: cargo-check
  entry: cargo check --workspace --lib --bins --locked
```

`--lib --bins` is explicit rather than relying on cargo's default-target
behavior so the hook command reads the same as the documented intent.

#### Why `--lib --bins` and not `--lib` only

The workspace has one binary target (`rusty-imap-mcp` in `rimap-server`)
that contains the production main and clap CLI surface. A library-only
check could miss CLI compile errors in `main.rs` — exactly the kind of
mistake that should be caught at commit/push, not CI. The bin is small;
including it is cheap.

#### Why not also drop `--locked`

`--locked` fails if `Cargo.lock` would be modified by the build. That's
the lockfile-drift catch the prior spec called "exactly the right time."
Kept verbatim.

#### Why not narrow further with `-p <crate>` based on changed files

Per-crate clippy invocations measured at 2.6–9.0 s warm each (sum: 43.1 s
across the 8 crates) versus 2.5 s warm for the whole-workspace clippy.
Per-crate invocations re-load and re-fingerprint dependencies from cargo's
cache per invocation; workspace-level clippy amortizes that work once.
Trying to scope clippy to "only the crates with changed files" would
*slow down* warm cases and add scripting brittleness. Not worth it.

#### Why not move clippy from pre-commit to pre-push

Pre-commit is the right stage for lints: the developer is still in the
local context that produced the warning, and the rebuild is incremental
from inner-loop iteration. Moving clippy to pre-push compresses the
"commit → push" interval (which the prior spec specifically widened) and
costs cold compile latency exactly when the SSH window is at risk.

### B. Add `just test-fast` for the inner loop

Add a new `just` target backed by a nextest filter expression:

```just
# Fast unit-test loop. Skips container-backed integration suites and the
# slowest property-test binary. Use this between `cargo check` cycles
# during inner-loop iteration. Before pushing, run `just test` (or
# `just ci`) for the full sweep.
test-fast:
    cargo nextest run --workspace --locked --no-tests=pass \
        -E 'not (binary(dovecot) | binary(e2e) | binary(e2e_wire) | binary(e2e_wire_cancellation) | binary(proptest_html_lookalike))'
```

The filter excludes exactly the five binaries identified in the
measurements. All other binaries (including `rimap-imap::proton`, which
is fast despite being container-tagged, and the other proptest binaries
`properties`, `mcp_wire_proptest`, `proptest_charset`, all sub-second)
stay in `test-fast`.

#### Why a nextest `-E` filter and not a nextest profile

Profiles are the right tool when test behavior changes (retries, threads,
timeouts). Here we want one switch — "skip the heavy five." A filter
expression keeps the heavy/fast split visible at the call site in the
justfile, doesn't require touching `.config/nextest.toml`, and behaves
identically regardless of which profile is active.

#### Why these five binaries and not "all container-backed" or "all proptest"

Empirical, not categorical: these five each contribute ≥ 17 s of
sum-of-test-times. `rimap-imap::proton` is container-tagged in the
nextest config but the 20 tests in it run as a unit-test sweep of
container support code (port reservation, project naming) — 0.69 s
total. Excluding it would drop coverage with no speed benefit.
`rimap-content::properties` and `rimap-server::mcp_wire_proptest` are
proptest-shaped but cheap. The empirical rule is "binaries that cost
more than a couple of seconds skip the fast tier"; that happens to
correlate with `dovecot` + `e2e*` + `proptest_html_lookalike`.

#### Why not also tune `PROPTEST_CASES` for `test-fast`

`proptest_html_lookalike` could in principle be made faster by setting
`PROPTEST_CASES=64` (versus the default 256) for the fast tier. We're
choosing the simpler split — skip the binary entirely — because
property tests at reduced case counts give a misleading "I ran the
properties" signal. Either run them fully or don't; halfway is worse
than either extreme.

### Documentation update

Update `AGENTS.md` to describe the three test commands:

- `just test-fast` — inner-loop unit tests, ≤ 10 s warm. Run frequently.
- `just test` — full nextest workspace including container and
  proptest binaries. Run before pushing. Already documented; gets one
  line clarifying that it's the "before push" sweep.
- `just ci` — full local CI equivalent (test + test-msrv + deny +
  mcp-conformance-node + typos). Run before sharing a PR or making a
  large push. Already documented.

The "Golden rule: if `just ci` passes locally, CI will pass" line in
the existing development-commands section stays.

## File layout

- **Modified:** `.pre-commit-config.yaml` — two hook `entry:` lines.
- **Modified:** `justfile` — add `test-fast` target.
- **Modified:** `AGENTS.md` — add `just test-fast` to the commands list
  in the development-commands section and clarify when to use each.
- **No new files.** No new dependencies. No cargo or nextest config
  changes. No CI workflow changes.

## Testing

Configuration change only; the hooks and `just` target are themselves
the tests. Manual verification:

1. **Pre-commit narrowed-clippy still catches lint regressions in lib/bin.**
   Add a deliberate clippy warning to a non-test `.rs` file under
   `crates/rimap-server/src/`, attempt `git commit`, observe the hook
   fails with `-D warnings`.
2. **Pre-commit no longer compiles test binaries.** With a warm target/,
   delete `target/debug/deps/*-test-*` artifacts, run the hook, observe
   no test binaries are rebuilt (verify with `find target/debug/deps
   -newer .pre-commit-config.yaml -name '*-*'` post-hook).
3. **Pre-push narrowed-check still catches lockfile drift.** Hand-edit
   `Cargo.lock` to a stale state, attempt push, observe `cargo check
   --locked` fails the hook.
4. **Pre-push cold-cache timing.** `cargo clean && time git push`
   (against a no-op branch or with `--dry-run` if available); expect
   ≤ 15 s on this hardware. The prior spec's clean-push smoke test
   (push without `GIT_SSH_COMMAND` keepalive, observe ref transfer
   succeeds) continues to apply.
5. **`just test-fast` test selection.** Run `just test-fast --list` (or
   the nextest equivalent), verify none of the five excluded binaries
   appear in the selected set.
6. **`just test-fast` warm timing.** `just test-fast` after a warm
   `just test`; expect ≤ 10 s wall clock on this hardware.
7. **`just test` is unchanged.** Run `just test`, observe all 1438
   tests still selected and pass.
8. **CI is unchanged.** `just ci` continues to invoke the full sweep.
   No `.github/workflows/` files modified.

No automated regression suite for this change. The prior spec's note
("`prek run --all-files` exercises the hook in CI's mcp-conformance /
lint paths but doesn't simulate the network timing") continues to apply.

## Risks and mitigations

- **Test-target compile error slips past pre-commit.** Previously caught
  by pre-commit clippy via `--all-targets`. Now caught only at CI (and
  at `just test` if the developer runs it before push). Acceptable: CI
  is a strict gate; the median test-target compile error is "I renamed
  a public fn and forgot to update its test", which the developer will
  hit the moment they run `just test` or `just test-fast` against the
  changed crate. The other risk profile — a test in crate A breaks
  because of an unrelated edit to crate B — is rare in this codebase
  and CI catches it before merge.
- **Developer runs only `just test-fast` and pushes without `just test`.**
  Then a regression in dovecot/e2e/proptest_html_lookalike slips past
  local validation; CI catches it. Same net outcome as today's
  "developer skips `just test` entirely because it's slow." A faster
  inner loop makes it more likely the developer runs *something*
  rather than nothing.
- **`--lib --bins` is too narrow and misses a real category of error.**
  The workspace has no `[[example]]` targets and no `[[bench]]` targets
  worth gating on. If those are added later, the spec author should
  revisit whether they belong in the hook scope.
- **Cold target/ on a weak laptop still blows the SSH idle window.**
  The fix narrows compile scope by ~50 %, not by 100 %. A truly cold
  laptop push may still exceed 30 s. Mitigations unchanged: documented
  `GIT_SSH_COMMAND='ssh -o ServerAliveInterval=15 -o ServerAliveCountMax=20'
  git push ...` escape hatch from the `project-push-ssh-keepalive`
  memory, or a permanent `~/.ssh/config` keepalive. Out of scope here.
- **Container-backed test regression detected only at push time, not at
  commit.** Same as today; `just test` was never wired into the hooks
  after `2026-05-15-pre-push-hook-trim`. No change.
- **nextest filter expression syntax changes.** Pinned to current
  cargo-nextest CLI behavior. If the `-E 'binary(...)'` syntax changes,
  the `just test-fast` target needs an update. This is the same risk
  surface as any nextest invocation in the repo.

## Out of scope

- **`sccache` / `mold` / linker tuning.** Orthogonal; would shave cold
  compile time across all stages, but does not address the "we compile
  test binaries we never run" waste and does not address `just test`
  test-execution time. Candidate for a future spec if cold-laptop pain
  remains after this lands.
- **CI workflow changes.** `.github/workflows/ci.yml` continues to run
  the full sweep (`cargo nextest run --workspace --locked`,
  `cargo clippy --workspace --all-targets --all-features --locked`,
  msrv, mcp-conformance, e2e wire). The CI side is the safety net for
  this spec's narrower local gates.
- **Test code refactor / tiering via `#[cfg]` flags.** The fast tier is
  achieved via a runtime nextest filter, not by gating tests at compile
  time. No test code touched.
- **`PROPTEST_CASES` tuning.** Mentioned above; rejected for honesty
  reasons.
- **Reducing the per-test cost of the container-backed binaries
  themselves.** That's a separate concern (Dovecot fixture startup,
  per-test session setup). Out of scope; covered partially by prior
  specs (`2026-05-11-dovecot-port-race-design.md`,
  `2026-05-13-dovecot-24-multiarch-fixture-design.md`).
- **The `include_bytes!` rebuild quirk in
  `crates/rimap-server/src/mcp/fuzz_oracle.rs:75`** that causes
  `rimap-server` to re-check on every clippy invocation. ~1–2 s tax;
  not worth bundling into this spec. Flag for follow-up.
- **`just test-msrv` reduction.** The MSRV nextest run duplicates the
  stable run (~90–140 s on top of `just test`). Removing or trimming it
  would speed `just ci` substantially but is a coverage decision, not a
  speed decision; out of scope here.
