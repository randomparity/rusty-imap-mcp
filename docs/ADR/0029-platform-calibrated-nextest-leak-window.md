# ADR-0029: Platform-calibrated nextest leak window

## Status

Accepted

## Context

The workspace makes nextest's inherited-stdout/stderr leak marker fatal after five seconds. A
full local macOS arm64 `just ci` run reported a pure string test as leaky at 5.014 seconds even
though the test starts no subprocess, passed alone in 0.008 seconds, and passed in the next full
run. Nextest 0.9.132 reports only that pipe EOF was not observed before the configured timer; it
does not attribute the open descriptor to a process. The existing five-second calibration did not
cover this local macOS contention regime.

## Decision

Retain the fatal five-second default and add a macOS host-platform override with a fatal
30-second leak window. This is a provisional operational margin, not a measured upper-tail bound:
the next macOS false positive at 30 seconds reopens calibration and must arrive with nextest run
recording plus a process snapshot. Test the policy records structurally; on macOS, run 32
dependency-free, no-descendant fixture tests for ten stress iterations at 18-way concurrency to
exercise concurrent process exit and pipe draining while a live sampler—with a known-child
positive control—proves those test processes have no descendants; exercise a deliberate inherited-pipe descendant that must produce
`LEAK-FAIL`; and load the copied policy with cargo-nextest 0.9.95 in the required macOS check job.
Gate the platform-neutral checks in local CI and the required Ubuntu `publish checks` job.

## Consequences

Linux retains the calibrated five-second signal. macOS scheduling and pipe-notification artifacts
have six times the only observed boundary before failing; that margin is intentionally provisional
because one censored event cannot establish a distribution. A genuine macOS descendant that keeps
a captured handle open longer than 30 seconds still fails, so the safety property remains intact.
MacOS leak failures take up to 25 seconds longer to surface.

## Considered & rejected

- **Make macOS leaks advisory.** judgment: this violates issue #846's requirement that genuine
  leaks remain fatal.
- **Disable capture or run macOS tests serially.** verified: nextest's official leaky-test
  documentation defines capture as the detection mechanism, while `--no-capture` serializes the
  suite; both choices remove more test-runner value than calibration requires.
- **Change the pure test.** verified: the issue's isolated CI-profile run completed in 0.008
  seconds and the source contains only string assertions, so no test-owned child can be reaped.
- **Raise the default on every platform.** judgment: the verified false-positive environment is
  macOS, while the existing Linux/CI calibration remains valid; widening all targets adds latency
  without evidence.
- **Keep five seconds unchanged.** verified: issue #846 records a fatal report at 5.014 seconds
  during a full macOS arm64 run, so the bound is not reliable for its stated environment.
- **Describe 30 seconds as a calibrated upper bound.** verified: a 100-iteration focused run of
  the reported test on macOS arm64 with cargo-nextest 0.9.132 produced 100 passes but did not
  recreate full-suite contention; one prior 5.014-second event cannot establish the tail.
- **Use focused repetition as the regression.** verified: the same 100-iteration run executes one
  process at a time and therefore omits the concurrent process-exit/pipe-drain pressure present in
  the failing full-suite run.
