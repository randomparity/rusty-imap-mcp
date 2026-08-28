# Nextest Leak Calibration Design (#846)

## Scope

Issue #846 requires the workspace-wide fatal nextest leak policy to distinguish a real
inherited-handle leak from the observed macOS arm64 contention artifact. Genuine leaks must
remain fatal. Public APIs, dependencies, production behavior, and unrelated test structure are
out of scope.

This design implements [ADR-0029](../../../ADR/0029-platform-calibrated-nextest-leak-window.md).

## Evidence and diagnosis

The failed test, `escape_wire_name_escapes_supplementary_codepoint`, performs one pure string
assertion and starts no subprocess. It passed alone under the CI profile in 0.008 seconds; the
full run reported `LEAK-FAIL` after 5.014 seconds; a subsequent full run passed. That rules out a
handle retained by the test body and makes the failure contention-dependent.

Cargo-nextest 0.9.132 detects leaks only by waiting for captured stdout/stderr to reach EOF after
the test process exits. Its executor races pipe draining against a timeout and reports a leak
when EOF has not been observed before the timer; it does not identify which process holds the
descriptor. Therefore the report proves only that nextest did not observe pipe closure within
five seconds, not that the named test spawned a surviving descendant.

The five-second value was calibrated on an 18-CPU host and CI samples, but not on a full local
macOS arm64 `just ci` run under the contention that produced #846. The observed 5.014-second
boundary is evidence that five seconds does not reliably cover that environment.

## Design

Keep the existing five-second fatal policy as the cross-platform default. Add a host-platform
override for macOS that keeps `result = "fail"` but uses a 30-second period. Thirty seconds is a
provisional operational margin: it is six times the only observed boundary and remains below the
existing 60-second slow-test reporting period, but one censored event does not establish an upper
tail. A genuine inherited stdout/stderr handle that survives 30 seconds still fails; the change
does not make any leak advisory or exempt any test. A future macOS false positive at 30 seconds
reopens calibration and must preserve the nextest run recording and a contemporaneous process
snapshot rather than increasing the window from another un-attributed marker.

Use nextest's existing host-platform override rather than a wrapper, retry, or production-code
change. The selector is exactly `platform = { host = 'cfg(target_os = "macos")' }`; nextest's
string selector is target-scoped and is forbidden because it would also relax cross-compiled
macOS tests on a non-macOS host. The override belongs in `.config/nextest.toml` beside the default
policy and applies to arm64 and x86_64 macOS hosts. Linux hosts retain five seconds.

## Verification

Add a shell regression harness that copies the nextest configuration to a temporary Cargo
workspace and asserts the two normative policy records structurally:

- default: five seconds and fatal;
- macOS host override: thirty seconds and fatal.

The harness must reject a missing host selector, a target-only macOS selector, a non-fatal result,
or a changed duration. It
also compiles a tiny dependency-free fixture with 32 no-descendant tests and one test that spawns
a longer-lived child with inherited stdout/stderr. On macOS the clean tests run for ten stress
iterations at 18-way concurrency, constructing 320 concurrent process-exit/pipe-drain observations;
each clean test stays alive for 50 ms so a sampler can record its process identity and verify it has
no descendants. A positive-control test keeps a known child alive while its parent remains
observable; the same sampler must record that exact relationship before the clean phase can count
as evidence. All clean tests must pass under the repository policy, and the diagnostic must contain
at least one observed clean-test process so an inert sampler fails. The child test must produce
`LEAK-FAIL` and a nonzero nextest exit under a short fixture-local fatal window. This live process
snapshot distinguishes the no-descendant proxy from the deliberate inherited-descriptor case. It
is a bounded proxy for the observed contention, not a claim that the original full-workspace
schedule is deterministic.

Run the copied configuration with cargo-nextest 0.9.95 in the required `check (macOS)` job. The
floor binary must load the configuration and complete the concurrent clean fixture run on macOS,
proving that the host-platform override syntax and selection remain compatible at the documented
floor. The Ubuntu `publish checks` job runs the structural check only, proving the default and
override records remain exact without adding a nextest prerequisite. The local harness accepts an explicit
`NEXTEST_BIN`; its default remains `cargo-nextest`, invoked directly as
`$NEXTEST_BIN nextest run ...`.

Wire the harness into `just ci` through a dedicated recipe and the individually required
`publish checks` CI job runs the structural checker only. The required
`check (macOS)` job installs exactly cargo-nextest 0.9.95 for the floor proof. Run the harness, the
affected pure test under the CI profile, and `just ci`.

## Error handling and rollback

The regression script exits nonzero with a message naming the missing or incorrect policy. It
uses only POSIX shell tools already used by repository scripts. Rollback is a single commit revert;
the previous five-second fatal default remains explicit in history.

## Global constraints

- Rust MSRV remains exactly 1.88.0; development Rust remains exactly 1.94.0.
- Cargo-nextest's supported floor remains exactly 0.9.95.
- Supported release targets remain `x86_64-unknown-linux-gnu`,
  `aarch64-unknown-linux-gnu`, `aarch64-apple-darwin`,
  `powerpc64le-unknown-linux-gnu`, and `s390x-unknown-linux-gnu`.
- Add no dependency and change no public or persisted contract.
- Genuine leaks remain fatal on every platform.
