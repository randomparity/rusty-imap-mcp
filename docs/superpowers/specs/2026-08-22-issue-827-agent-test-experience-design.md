# Agent-facing unit-test output contract (#827)

Date: 2026-08-22
Issue: [#827 — Improve Agent Experience for Unit Test](https://github.com/randomparity/rusty-imap-mcp/issues/827)
Scope token: `q827-665ceb80`

## Problem

An agent running the test suite ingests results through the terminal stream.
Today that stream is hostile to ingestion: thousands of PASS lines precede any
failure, failure bodies interleave across parallel tests mid-stream, terminal
capture truncates long runs, and there is no standing guidance for expected
runtime — so every session re-derives timeouts and re-runs killed jobs with
larger budgets.

## Goal

Make test results machine-ingestible and the terminal stream quiet by default,
with documented escape hatches and runtime expectations, so an agent needs at
most one run plus file reads to go from "suite ran" to "here is what failed
and why".

## Non-goals

- **No `-verbose` boolean flag** (rejected in brainstorm): nextest already has
  the verbs (`--no-capture`, `--status-level=all`, `RUST_BACKTRACE`);
  passthrough beats a wrapper.
- **No committed per-test timing tables**: rot immediately, host-dependent;
  fresh timing comes free from `final-status-level = slow` and JUnit `time`
  attributes.
- **No per-test timeout metadata attributes**: `slow-timeout` already is that
  mechanism.
- **No `retry-failed` helper yet**: revisit after real use demonstrates the
  friction; the JUnit artifact makes it a ~20-line addition later if needed.
- **No CI workflow edits**: the JUnit sink is additive; uploading it as a
  workflow artifact is separate scope.
- **html-oracle crate**: workspace-excluded; out of reach of these profiles.

## Design

### 1. Nextest profile changes (`.config/nextest.toml`)

Single-profile quiet defaults (user decision, 2026-08-22 session — no
agent-specific profile):

```toml
[profile.default]
# existing leak-timeout / slow-timeout keys stay
status-level = "fail"                    # live lines: failures only
failure-output = "final"                 # failure bodies grouped at run end
final-status-level = "slow"              # cumulative: includes retry + fail

[profile.default.junit]
path = "junit.xml"                       # -> target/nextest/default/junit.xml

[profile.ci.junit]
path = "junit.xml"                       # -> target/nextest/ci/junit.xml
```

- `[profile.ci]` inherits the default-profile status settings; `just test`,
  `test-msrv`, and `test-injection` (`--profile ci`) therefore get the same
  quiet behavior and write `target/nextest/ci/junit.xml`; `just test-fast`
  (default profile) writes `target/nextest/default/junit.xml`. Both files sit
  under `target/` — never tracked.
- JUnit defaults do the right thing: `store-failure-output = true` embeds each
  failing test's captured stdout/stderr; success output stays unstored.
- Human cost, accepted: the live progress heartbeat and mid-run slow warnings
  disappear; failures still print live at status-level `fail`, per-test
  durations above 60 s land in the run tail via the existing `slow-timeout`
  machinery, and the final summary is unchanged in completeness. The trade
  was explicitly approved by the operator.
- Requires nextest ≥ 0.9.95 (already floored as `NEXTEST_MIN` in the
  justfile); all keys used predate that release.
- Note: with `status-level = "fail"`, the mid-run 60-second slow-period warn
  lines are suppressed; slow attribution arrives in the final summary instead.

### 2. Justfile: argument passthrough + timing recipe

- `test` and `test-fast` gain `*args` forwarded to `cargo nextest run`
  verbatim: flags like `--no-capture` or `--status-level=all`, and
  **positional substring filters** for scoping (`just test-fast -- my_test`
  intersects the substring union with test-fast's container-exclusion
  filterset, keeping the inner loop fast). Warning for AGENTS.md: additional
  `-E` expressions are ORed into the filterset union and therefore *widen*
  past the exclusion filter rather than narrowing — never advertise `-E`
  passthrough as scoping.
- New `test-timing PROFILE="default"` recipe (inner-loop profile is the
  primary audience): `xmllint --xpath` over
  `target/nextest/<PROFILE>/junit.xml` printing the file's modification time
  plus every `<testcase>`'s `time`/`name` attributes, sorted by duration.
  Read-only convenience over data §1 already produces; errors loudly when the
  file is absent ("run the suite first") and — mirroring
  `scripts/mcp-probe-tools.sh`'s convention — with "xmllint is required" when
  xmllint is missing. (jq is a JSON processor and cannot read the XML report.)

### 3. AGENTS.md guidance block

A compact "Running tests as an agent" section under *Development commands*:

1. **Recipe map with warm-machine runtime ranges**: single filtered test =
   seconds; `test-fast` ≈ 1–3 min; `test` = minutes with individual
   container-backed tests up to ~60 s warm (~180 s cold first pull); `ci` =
   tens of minutes.
2. **The background rule**: run `just test` / `just ci` in the background and
   poll to completion; never bind them to a foreground timeout. Only the
   filtered inner loop belongs in a bounded foreground call.
3. **Inner loop**: `cargo nextest run -p <crate> -E 'test(substring)'` — never
   a workspace sweep to iterate one failure.
4. **JUnit ingestion**: where the file lands per profile; an `xmllint`
   example extracting failed test names; failure bodies live in the same
   file. A missing `target/nextest/<profile>/junit.xml` after a run means the
   run did not complete cleanly — treat it as void, shrink scope or raise the
   budget, and re-run; never parse a partial file. Existence alone is not
   proof of freshness: ingest only files whose mtime is newer than the start
   of the run being diagnosed (a compile error before test start leaves the
   previous run's report in place), pair the file with nextest's exit code —
   non-zero (`max-fail`/fail-fast abort) means only recorded tests ran;
   ingest their failure records without concluding overall health — and
   confirm it parses as XML first (a malformed or truncated file gets the
   void treatment). Never run two same-profile suites concurrently in one
   workspace: the JUnit path collides and last-writer-wins corrupts
   attribution.
5. **Verbose escape hatches**: `--no-capture` (live output, hang diagnosis)
   and `--status-level=all` via recipe passthrough; `RUST_BACKTRACE=1` is an
   environment variable — set it as a prefix (`RUST_BACKTRACE=1 just
   test-fast`), not as a passthrough argument.
6. **Noise triage note**: proptest shrink transcripts and insta diffs appear
   only on genuine failures; volume signals a red, not brokenness.

## Considered & rejected

- **Agent-specific nextest profile.** judgment: two profiles for one knob;
  single-profile simplicity explicitly approved by the operator.
- **`-verbose` wrapper flag.** judgment: duplicates nextest's own CLI verbs
  behind new surface; passthrough composes better.
- **Committed per-test timing table.** verified: JUnit XML carries per-test
  `time` attributes and `final-status-level = slow` lists slow tests with
  durations every run (nextest docs, nexte.st/docs/reporting + /machine-readable/junit),
  so a static table rots for no informational gain.
- **Per-test timeout attributes.** verified: `.config/nextest.toml` already
  sets `slow-timeout = { period = "60s", terminate-after = 3 }` workspace-wide.
- **`retry-failed` helper now.** judgment: build after demonstrated friction;
  the JUnit artifact keeps it cheap.

## Security

Not security-relevant: no untrusted-input handling, no entry-point or
permission change, no dependency additions; the JUnit path is a fixed relative
path under `target/`. Failure output embedded in `junit.xml` can contain test
fixture content — it lands in an untracked build directory with default
permissions, same exposure as nextest's own captured output today.

## Testing strategy

Config + docs + shell tooling; no Rust feature code, so the TDD loop applies
as explicit verification commands:

- After the profile change: run a scoped nextest command, assert
  `target/nextest/*/junit.xml` exists, parses as XML, and its `<testcase>`
  count matches nextest's summary line.
- Force exactly one deliberate failure (temporary broken assertion, reverted
  in the same step) to prove `<failure>` with captured output appears in the
  JUnit file — the confirm-it-fails step for this change.
- `just -n test-fast -- --no-capture` shows the flag reaching `cargo nextest
  run`; `just test-timing` prints slowest cases from the file produced above.
- Guardrails for touched files: `typos`, `just fmt-check`/`lint` unaffected
  but run as part of the branch sweep; AGENTS.md prose reviewed against actual
  recipe behavior (doc drift is the named hazard).
