# ADR-0010: Fixed sentinel for Dovecot, per-run canary elsewhere, swept in teardown

**Status:** Accepted · 2026-07-14 · issue [#528](https://github.com/randomparity/rusty-imap-mcp/issues/528)

## Context

Credential redaction is unit-tested, but no e2e test reads back the artifacts a
run produces (child stderr/tracing, audit JSONL, exported `.eml`, the fake's
recorded IMAP dialog) and asserts the harness password never appears in them.
#528 asks for a canary sweep: make each harness password a unique high-entropy
canary and assert it appears in no artifact.

The obstacle is that two backends resolve the password differently:

- The **in-process fake** (`crates/rimap-fake-imap`, ADR-0008) accepts any
  LOGIN, so a per-run random password authenticates fine.
- **Dovecot** validates LOGIN against a static passwd-file
  (`crates/rimap-imap/tests/integration/dovecot/users`,
  `rimap-test:{PLAIN}testpass`). A per-run random password would fail LOGIN, so
  the run would never reach the post-LOGIN surface (FETCH bodies, audit
  tool records, tracing spans) — exactly where a leak would occur. The sweep
  would then run against an un-authenticated session and prove nothing.

Making the Dovecot password per-run-unique requires the server to accept it,
which means regenerating the passwd-file per run. The suite runs many Dovecot
containers concurrently (unique compose-project names), so mutating the single
tracked `users` file per run is a race; the only safe per-run mechanism is
teaching the container entrypoint to generate the passwd-file from an env var
and plumbing that env through both crates' Dovecot harnesses.

## Decision

- **Dovecot-backed suites use a fixed high-entropy sentinel**
  (`DOVECOT_CANARY_PASSWORD`), replacing the short, collision-prone `testpass`
  literal. It is colon-free (a valid passwd-file password) and defined once,
  with the `users` file as the source of truth and cross-reference comments at
  the two other sync points (`container.rs`, the support constant).
- **Fake-backed and env-fed suites use a fresh per-run canary**
  (`fresh_canary()`), because uniqueness there is free.
- **The sweep is a pure `scan()` + a thin `assert_absent()` wrapper**, called
  explicitly at the end of each wire suite (after `shutdown_and_wait`), not from
  a `Drop` guard.
- **The sweep is one recursive byte-walk of the harness `TempDir` root** (which
  roots audit, stderr, config, and downloads) plus the fake's `recorded()`
  frames as in-memory extras.

## Consequences

- Every credential-under-test is a greppable, high-entropy canary; uniqueness is
  preserved everywhere it is free. Dovecot trades per-run uniqueness for a fixed
  sentinel the sweep still detects unambiguously.
- No container/entrypoint changes and no second-crate harness plumbing for
  per-run Dovecot passwords — the smaller, more reviewable change the issue's
  "Effort: S" sizing implies. The rename touches only literal occurrences.
- The `scan`/`assert_absent` split makes the sweep self-testable: the negative
  meta-test (`canary_sweep_meta.rs`) seeds a leak and asserts `scan` returns a
  hit, satisfying acceptance criterion 2 as a committed, always-run test.
- The explicit teardown call avoids the double-panic-on-unwind and `Drop`-order
  hazards a guard would introduce, at the cost of one added line per suite that
  review must confirm is present.
- The Dovecot sentinel is a fixed constant checked into the repo. It is a test
  fixture password for a throwaway local container, never a real secret, so its
  presence in source is not itself a leak.

## Considered & rejected

- **Per-run parameterized Dovecot password** (entrypoint reads
  `RIMAP_DOVECOT_PASSWORD` and generates the passwd-file; compose + both crates'
  harnesses plumb a fresh canary per run). Fully satisfies "every harness a
  unique canary," but adds an entrypoint contract, compose env plumbing, and
  changes to *both* the `rimap-imap` and `rimap-server` Dovecot harnesses — a
  materially larger, cross-crate change for marginal added assurance: the
  server-side redaction code path does not branch on the password *value*, so a
  fixed sentinel exercises the same code a per-run value would. Rejected as
  disproportionate for this issue; the sentinel is trivially swappable if a
  future need for per-run Dovecot uniqueness appears.
- **A `Drop`-guard that sweeps automatically at scope exit.** Cleaner call sites,
  but asserting inside `Drop` during unwind risks a double-panic abort (masking
  the original failure), and `Drop` ordering against the `TempDir` guard is
  fragile. Rejected in favor of an explicit, predictable teardown call.
- **Keep `testpass`, just add the sweep.** The literal is short and low-entropy;
  swept against large audit/stderr/`.eml` artifacts it risks coincidental
  substring hits (false positives). Rejected: the `RIMAP-CANARY-` prefix + high-
  entropy tail is what makes any hit a guaranteed true leak.
- **Wire the sweep into the in-process suites too** (`e2e.rs`,
  `server_capabilities.rs`, `e2e_smtp*.rs`). They produce no harness-owned
  artifact files (tracing goes to cargo's captured stdout), so there is nothing
  for the file-walk to read; their redaction is already unit-tested. Deferred to
  a follow-up issue if capture-and-sweep of their tracing is wanted, not adopted
  here.
