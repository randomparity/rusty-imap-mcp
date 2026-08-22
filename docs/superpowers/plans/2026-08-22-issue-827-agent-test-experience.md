# Plan: agent-facing unit-test output contract (#827)

Goal: make test results machine-ingestible (JUnit artifact), quiet the default
terminal stream, and give agents standing runtime/escape-hatch guidance.

Architecture: config-only nextest profile changes plus justfile passthrough;
AGENTS.md carries the guidance. No Rust source changes.

Tech stack: cargo-nextest ≥ 0.9.95 (already floored as `NEXTEST_MIN` in the
justfile), just with `set positional-arguments` (long-established setting; host
has 1.57.0), xmllint as a documented convenience for ingestion examples (any
XML parser works; `grep -c '<failure'` is the zero-dependency fallback).

Spec: `docs/superpowers/specs/2026-08-22-issue-827-agent-test-experience-design.md`

## Global Constraints

- No new dependencies. Surface limited to `.config/nextest.toml`, `justfile`,
  `AGENTS.md`. No `test-timing` recipe (rejected in spec — jq cannot read the
  XML report; the run-tail slow listing already carries durations).
- One junit table lives under `[profile.default]`; `[profile.ci]` inherits it
  (`--profile ci` writes `target/nextest/ci/junit.xml`). No explicit
  `[profile.ci.junit]` table.
- Every nextest profile key used must be valid on nextest ≥ 0.9.95;
  `final-status-level` takes ONE cumulative enum value (`"slow"` includes
  retry + fail) — never a comma-combined form. Slow-warning suppression under
  `status-level = "fail"` holds only on nextest ≥ 0.9.133; older versions
  render a corrupt mid-run line (upstream #3236) — document accordingly.
- Multiple `-E` filtersets are ORed; substring positional filters intersect
  with the filterset union. Never document `-E` passthrough as scoping.
- `failure-output = "final"` groups failure bodies only at run end;
  `immediate-final` would print them twice.
- junit.xml is written once at the end of a run: a missing file means the run
  did not complete; a stale file (older than the run being diagnosed) is void;
  a non-zero nextest exit (`max-fail`/fail-fast) means only recorded tests ran;
  a zero-test report means the filter matched nothing — never a health signal;
  never run two same-profile suites concurrently in one workspace. The report
  never outranks the run's own summary line (`N tests run`).
- Commits: conventional, imperative, ≤72 chars, explicit paths only.
- Branch: `feat/agent-test-experience-827`; BASE_BRANCH `main`.

## Task 1 — Nextest profile changes

Files: `.config/nextest.toml` (modify).

Interfaces: later tasks read `target/nextest/<profile>/junit.xml` (default |
ci). Nothing else consumes the profile keys.

1. In `[profile.default]` (the table that already holds `leak-timeout` /
   `slow-timeout`), add:

   ```toml
   status-level = "fail"
   failure-output = "final"
   final-status-level = "slow"
   ```

2. After the existing `[profile.ci]` table, add:

   ```toml
   [profile.default.junit]
   path = "junit.xml"
   ```

   (`junit.xml` resolves relative to `target/nextest/<profile>/`; ci inherits
   the table.)

3. Confirm-it-parses and inheritance proof:
   `cargo nextest run -p rimap-config --locked --no-tests=pass` exits 0 AND
   writes `target/nextest/default/junit.xml`; rerun with `--profile ci` and
   assert `target/nextest/ci/junit.xml` exists (proves ci inherits the junit
   table). A bad key would be a bare config-parse error on EVERY run — this
   step is the tripwire. Record whether these zero-test runs produce an empty
   report or no report at all: the AGENTS.md ingestion bullet must match the
   observed behavior.

4. Confirm-it-fails: temporarily invert one assertion in the test module of
   `crates/rimap-config/src/loader.rs` (`mod tests`, line 179), then
   `cargo nextest run -p rimap-config -E 'test(loader)'` must exit non-zero
   AND update `target/nextest/default/junit.xml` containing a `<failure>`
   element whose body embeds the assertion's captured output:

   ```sh
   grep -c '<failure' target/nextest/default/junit.xml   # expect >= 1
   ```

   Revert the assertion immediately (`git checkout -- crates/rimap-config`).
   Then re-run step 3's default-profile command so the artifact on disk is
   green again.

5. Acceptance: both profile junit paths exist and parse; their `<testcase>`
   counts equal nextest's "N tests run" figure for the same runs (passed +
   failed + flaky, excluding skipped — skipped tests do not appear in the
   report); no diff remains under `crates/`.

## Task 2 — Justfile: argument passthrough

Files: `justfile` (modify).

Interfaces: produces Task 1's artifact-writing runs with passthrough; consumed
by AGENTS.md docs (Task 3) which document these exact invocations.

1. Below the existing `set shell := ["bash", "-uc"]` line, add:

   ```just
   set positional-arguments
   ```

2. Change `test` to accept passthrough args (keep the `prune-containers`
   dependency and all existing flags verbatim):

   ```just
   test *args: prune-containers
       cargo nextest run --workspace --locked --no-tests=pass --profile ci "$@"
   ```

3. Change `test-fast`'s signature to `test-fast *args:` and its `exec` line to
   append `"$@"` AFTER the `-E` exclusion filter (order matters: the exclusion
   filterset stays; appended positional substring filters intersect with it):

   ```just
       exec cargo nextest run --workspace --locked --no-tests=pass \
           -E "not (${containers} | binary(proptest_html_lookalike))" "$@"
   ```

4. Verification:
   - `just -n test-fast -- --no-capture` prints the exec line with
     `--no-capture` appended after the `-E` argument.
   - `just -n test ci-extra` shows `"$@"` position receiving `ci-extra`.
   - `just test-fast -- nonexistent_substring_zz` runs ~zero tests and exits 0
     (`--no-tests=pass` semantics) — proves substring intersection without a
     long run.

5. Acceptance: no existing recipe line changed except the two signatures/exec
   lines named above; `just --list` exits 0 (justfile parses).

## Task 3 — AGENTS.md guidance block

Files: `AGENTS.md` (modify).

Interfaces: documents Task 1's artifact paths and Task 2's recipe signatures;
nothing consumes it programmatically.

1. Insert a new `### Running tests as an agent` subsection immediately after
   the fenced command block in *Development commands* (before the *Container
   runtime* subsection). Open it with one cross-reference line to the existing
   *Testing expectations* section (the noise-triage note points there rather
   than duplicating it), then six numbered points:
   1. Recipe map with warm-machine ranges: filtered single test = seconds;
      `just test-fast` ≈ 1–3 min; `just test` = minutes (container-backed
      tests individually up to ~60 s warm / ~180 s cold first pull); `just ci`
      = tens of minutes.
   2. Background rule: run `just test` / `just ci` in the background and poll
      to completion; never bind them to a foreground timeout. Only the
      filtered inner loop belongs in a bounded foreground call.
   3. Inner loop: `cargo nextest run -p <crate> -E 'test(substring)'` (or
      `just test-fast -- substring`) — never a workspace sweep to iterate one
      failure. Warning: extra `-E` expressions OR into the filterset union and
      widen past `test-fast`'s container exclusion; use substring filters.
   4. JUnit ingestion: `target/nextest/ci/junit.xml` for `--profile ci` runs,
      `target/nextest/default/junit.xml` otherwise; failing test names AND
      their captured output are embedded.
      `xmllint --xpath '//testcase[failure]/@name' <report>` extracts failed
      test names; xmllint is a convenience, not a gate — any XML parser works,
      and `grep -c '<failure' <report>` is the zero-dependency fallback.
      A missing or empty file after a run means the run did not complete
      cleanly — treat the run as void, shrink scope or raise budget, re-run;
      never parse a partial file. Existence alone is not proof of freshness:
      ingest only files whose mtime is newer than the start of the run being
      diagnosed (a compile error before test start leaves the previous run's
      report in place), pair the file with nextest's exit code — non-zero
      (`max-fail`/fail-fast abort) means only the recorded tests ran; ingest
      their failure records without concluding overall health — confirm it
      parses as XML first (a malformed or truncated file gets the void
      treatment), and treat a report recording zero tests as "the filter
      matched nothing", never a health signal. The report never outranks the
      run's own summary line (`N tests run`). Never run two same-profile
      suites concurrently in one workspace: the JUnit path collides and
      last-writer-wins corrupts attribution. Match the zero-report wording to
      what Task 1 step 3 actually observed.
   5. Verbose escape hatches: `--no-capture` (live output; hang diagnosis) and
      `--status-level=all` via recipe passthrough; `RUST_BACKTRACE=1` is an
      environment variable — prefix form `RUST_BACKTRACE=1 just test-fast`,
      never a passthrough argument. `--no-capture` caveat: it runs the
      selection serially and produces a JUnit report without embedded failure
      output — for watching a run, never for ingesting it.
   6. Noise triage: proptest shrink transcripts and insta snapshot diffs appear
      only on genuine failures; volume signals a red, not brokenness. Slow
      tests (>60 s) are listed with durations in every run's tail.

2. Verification: `typos AGENTS.md` exits 0; every command and path in the new
   section was executed or exercised by Tasks 1–2 (doc drift is the named
   hazard — do not write an untested invocation). The xmllint one-liner and
   the grep fallback are each run against Task 1's failing-test artifact.

3. Acceptance: section present under *Development commands*; every documented
   command matches actual recipe/config behavior verified above.

## Task 4 — Guardrail sweep

Files: none (verification only).

1. `typos` (repo-wide) exits 0.
2. `just fmt-check && just lint` exit 0 (Rust untouched; proves it).
3. Background-run `just test-fast` (~1–3 min warm): exits 0; captured stdout
   has zero per-test PASS lines (`grep -c '^ *PASS'` == 0); tail lists
   failures/slow entries only; fresh `target/nextest/default/junit.xml` exists
   (mtime after run start).
4. Commit any straggler with explicit paths; branch is ready for review.
