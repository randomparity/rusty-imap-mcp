# Secret-leak canary threaded through every e2e harness (#528)

**Status:** Draft
**Issue:** [#528](https://github.com/randomparity/rusty-imap-mcp/issues/528)
**Theme:** C (oracles, invariants, meta-testing) · Priority P3 · Effort S
**Related:** [#527](https://github.com/randomparity/rusty-imap-mcp/issues/527)
(post-run audit-log invariant sweep — sibling force-multiplier, not yet built),
[#561 / ADR-0008](../../ADR/0008-shared-fake-imap-test-support-crate.md)
(`crates/rimap-fake-imap` shared fake with `recorded()`).
**ADR:** [0010](../../ADR/0010-secret-leak-canary-sweep.md)

## 1. Problem

Credential redaction is tested at the unit level
(`crates/rimap-audit/tests/redact_properties.rs`, credential-sanitization
units), but nothing guarantees end-to-end that the *actual password a harness
feeds the server* never appears in an observable artifact. A regression that
logged the password to `tracing`, wrote it into an audit record, or serialized
it into an exported `.eml` would pass every existing test.

The gap is an **invariant sweep**: every e2e run already produces the artifacts
where such a leak would surface (child stderr, audit JSONL, downloaded message
files, the fake's recorded IMAP dialog). No test reads them back and asserts the
credential is absent.

## 2. Goal & non-goals

**Goal.** Give every wire-driven e2e suite a post-run sweep that fails the test
if the harness's password appears in any artifact that run produced.

**In scope:**

- A shared, reusable canary helper in `rimap-server`'s test-support tree.
- A per-run, high-entropy, greppable canary password for suites whose backend
  accepts any LOGIN (the fake) or never validates it (env-fed).
- A fixed high-entropy sentinel password for Dovecot-backed suites (Dovecot
  authenticates against a static passwd-file; see §4.2 and ADR-0010).
- Wiring the sweep into the teardown of every wire-driven e2e suite.
- A committed negative meta-test proving the sweep detects a deliberate leak
  (acceptance criterion 2).

**Out of scope (documented boundaries, not silent gaps):**

- **In-process e2e suites** (`e2e.rs`, `server_capabilities.rs`, `e2e_smtp.rs`,
  `e2e_smtp_real.rs`) call server internals directly rather than spawning the
  binary, so they produce **no external artifact files** to sweep (their
  `tracing` output goes to cargo's captured test stdout, not a harness-owned
  file). They receive the sentinel rename (§4.2) so they stay green and so their
  credential is still a searchable canary, but the file-artifact sweep is not
  wired into them. Their redaction is already covered by the unit tests above.
  If capture-and-sweep of their tracing is wanted later, that is a follow-up
  issue, not this one.
- Changing production redaction behavior. This work only *observes*; it adds no
  new redaction code path. Any leak it finds is a bug fixed separately.
- New runtime or dev dependencies. The helper is pure `std`.

## 3. Acceptance criteria (from the issue)

1. Canary sweep active in all (wire-driven) e2e suites.
2. A test that logs the credential on purpose is caught by the sweep.

Restated as falsifiable checks:

- **AC1:** every `e2e_wire*` integration-test binary that spawns a harness calls
  the sweep after the harness run, passing the exact password string it
  injected. Verified by inspection + the fact that removing a sweep call leaves
  a suite that no longer references `canary::assert_absent`.
- **AC2:** `crates/rimap-server/tests/canary_sweep_meta.rs` seeds the canary into
  a scratch artifact and asserts `canary::scan(...)` returns a non-empty hit
  list; and asserts a clean tree returns an empty list. Host-runnable, no
  container, PR-blocking.

## 4. Design

### 4.1 The canary helper (`support/canary.rs`)

A new support module, pulled into each wire e2e binary via the existing
`#[path = "support/canary.rs"] mod canary;` convention. Because every wire
binary *calls* the sweep, no per-binary dead-code suppression is needed for the
sweep entry points (contrast the `force_use_for_dead_code_link` pattern used for
partially-used helpers).

Public surface:

```rust
/// Fixed high-entropy sentinel that IS the Dovecot fixture password.
/// MUST match, byte for byte:
///   crates/rimap-imap/tests/integration/dovecot/users   (source of truth)
///   crates/rimap-imap/tests/integration/support/container.rs
/// Contains no ':' — that is the passwd-file field separator.
pub const DOVECOT_CANARY_PASSWORD: &str = "RIMAP-CANARY-DVC-9f83b1a7c0d6e4f2";

/// Mint a unique, high-entropy, per-run canary password. For fake-backed or
/// env-fed suites, where the backend accepts any LOGIN. The `RIMAP-CANARY-`
/// prefix makes any leak instantly attributable in an artifact dump.
pub fn fresh_canary() -> String;

/// One place the canary appeared.
pub struct CanaryHit {
    /// Artifact identity: a file path, or `recorded frame N`.
    pub source: String,
    /// Context window around the match, with the canary masked as `<CANARY>`.
    pub excerpt: String,
}

/// Pure detection: recursively read every file under each root as *bytes*,
/// plus each in-memory `extra` string, and return every occurrence of the
/// canary. No panics — this is what makes the sweep self-testable.
pub fn scan(canary: &str, roots: &[&Path], extra: &[String]) -> Vec<CanaryHit>;

/// Assert the canary is absent from every artifact; panic listing all hits
/// otherwise. Thin wrapper over `scan`.
pub fn assert_absent(canary: &str, roots: &[&Path], extra: &[String]);
```

Design points:

- **Byte search, not UTF-8.** Artifacts may be non-UTF-8 (`.eml` attachments,
  binary bodies). `scan` reads files as `Vec<u8>` and searches for the canary's
  bytes, so a leak in binary content is still caught. The `excerpt` is rendered
  with `String::from_utf8_lossy` over a bounded window.
- **`fresh_canary` entropy source.** Reuse the established
  `uuid_like`-style mint (`SystemTime` nanos ⊕ `process::id()` ⊕ a process-local
  `AtomicU64`) already used by the Dovecot harness for unique compose-project
  names. This gives per-run uniqueness with zero new dependencies; a
  cryptographic RNG is unnecessary because the requirement is
  non-collision + attributability, not unpredictability.
- **One recursive walk covers most artifacts.** Every wire harness roots its
  `audit.jsonl` (and rotated siblings), stderr log, `config.toml`, and
  `downloads/` under one `TempDir`. Passing that single root to `scan` sweeps
  audit + stderr + exported `.eml` + any other file the run wrote. The fake's
  `recorded()` client frames are passed as `extra`.
- **Symlink safety.** The walk does **not** follow symlinks (a symlink out of
  the tempdir could pull unrelated host files into the scan and either false-
  positive or hang); it scans regular files only.

### 4.2 Canary values and the Dovecot constraint

The password a harness feeds the server is only a *meaningful* leak probe if the
run actually authenticates and exercises the post-LOGIN surface (FETCH bodies,
audit `tool_start`/`tool_end`, tracing spans). Two backends, two strategies:

- **Fake-backed / env-fed suites** (`e2e_wire_fetch_skipped`,
  `_folder_not_found`, `_transcript_cleanup`, `_transcript_triage`,
  `_uidvalidity`, `_tls_pin_mismatch`, `_login_rejected`): the fake accepts any
  LOGIN, so each run injects a **fresh per-run canary** from `fresh_canary()`,
  replacing the current hardcoded `"fake-password"` literal. `_login_rejected`
  deliberately sends a rejected password — that rejected string is still the
  credential-under-test, so the suite sweeps for exactly the (fresh) value it
  injected.

- **Dovecot-backed suites**: Dovecot validates LOGIN against the static
  passwd-file `crates/rimap-imap/tests/integration/dovecot/users`
  (`rimap-test:{PLAIN}testpass`). A per-run random password would fail LOGIN and
  never reach the post-LOGIN surface. Mutating the tracked `users` file per run
  is unsafe under the suite's parallel container execution (many concurrent
  Dovecot projects). Per ADR-0010, Dovecot suites therefore use a **fixed
  high-entropy sentinel** — the current short, collision-prone `testpass` is
  renamed to `DOVECOT_CANARY_PASSWORD`. Uniqueness-per-run is preserved
  everywhere it is free (all fake/env suites); Dovecot trades per-run uniqueness
  for a fixed sentinel that the sweep still detects unambiguously.

**Rename footprint** (every occurrence of the fixture password literal, so
nothing breaks and every credential-under-test is a greppable canary):

- `crates/rimap-imap/tests/integration/dovecot/users` — source of truth.
- `crates/rimap-imap/tests/integration/support/container.rs:160`.
- Every `const DOVECOT_PASSWORD: &str = "testpass";` in `rimap-server` wire and
  in-process suites → replaced by `canary::DOVECOT_CANARY_PASSWORD` (de-dups ~10
  copies to one).
- `StaticCreds("testpass")` in the in-process Dovecot suites (`e2e.rs`,
  `server_capabilities.rs`, `e2e_smtp.rs`, `e2e_smtp_real.rs`).
- The SMTP-side `SmtpClient::new(&cfg, "testpass")` in `e2e_smtp_real.rs`
  (Mailpit does not validate it; renamed for canary hygiene so an SMTP-path leak
  is also detectable).

The three cross-crate sync points (`users` file, `container.rs`,
`DOVECOT_CANARY_PASSWORD`) carry cross-reference comments. This is *fewer* sync
points than today, where every suite re-declares the literal.

### 4.3 Which artifacts, mapped to the issue's list

| Issue artifact | How it is swept |
|---|---|
| Audit logs | `audit.jsonl` + rotated siblings under the tempdir root — recursive walk. |
| stderr / tracing | The harness stderr log file under the tempdir root — recursive walk. |
| Exported `.eml` | Files under `downloads/` under the tempdir root — recursive walk. |
| Panic messages | The child's panics are written to its stderr log (swept above); the harness's own panic diagnostics embed `captured_stderr()`, also from that file. So panic output ⊆ the stderr sweep. |
| Wire frames (both directions) | The password's only on-wire appearance is the **client→server IMAP LOGIN**. For fake suites that is captured by `recorded()` (passed as `extra`). Server→client fake bytes are test-scripted and never carry the secret; MCP stdio frames never carry the IMAP password. For **Dovecot** suites the IMAP wire is TLS-encrypted and not interceptable at the harness — a plaintext leak there would instead surface in stderr/audit, which are swept. |

### 4.4 Teardown wiring

Rust integration-test binaries have no shared teardown hook, so "teardown" is an
explicit call at the end of each test, mirroring the issue's "one helper, called
from the same teardown as C1." The call is placed **after
`shutdown_and_wait`** returns the `TempDir` (child has exited and flushed all
stderr/audit), so the sweep reads final on-disk state:

```rust
let (_status, tempdir) = harness.shutdown_and_wait().await;
canary::assert_absent(&password, &[tempdir.path()], &recorded_frames);
```

For suites that reap the child without `shutdown_and_wait` (e.g.
`_tls_pin_mismatch`, which fails boot closed), the sweep reads the tempdir root
after the child has exited via a `Harness::artifact_root()` accessor.

An explicit call (rather than a `Drop` guard) is chosen deliberately: asserting
inside `Drop` during unwind risks a double-panic abort, and `Drop` ordering
against the `TempDir` guard is fragile. The explicit call is predictable and
matches how these tests already end.

### 4.5 Negative meta-test (AC2)

`crates/rimap-server/tests/canary_sweep_meta.rs`, host-runnable and PR-blocking:

- **`scan_flags_a_seeded_file_leak`**: write a file containing the canary into a
  scratch tempdir; assert `scan` returns ≥1 hit whose `source` is that file.
- **`scan_flags_an_extra_string_leak`**: pass a `recorded`-style string
  containing the canary as `extra`; assert a hit.
- **`scan_is_clean_on_a_leak_free_tree`**: a tempdir with audit/stderr/eml-shaped
  files that do *not* contain the canary; assert `scan` returns empty.
- **`assert_absent_panics_on_a_leak`**: `#[should_panic]`, proving the asserting
  wrapper bites.

This satisfies "a test that logs the credential on purpose is caught" as a
committed, always-run test rather than a throwaway scratch branch.

## 5. Risks & mitigations

- **A suite that authenticates but a sweep is forgotten.** Mitigation: the plan
  enumerates every wire suite; review checks each references
  `canary::assert_absent`. No structural enforcement is possible across
  independent test binaries.
- **False positives from coincidental substrings.** Mitigated by the
  `RIMAP-CANARY-` prefix and high-entropy tail; the canary is never legitimately
  written anywhere.
- **The sweep surfaces a *real* pre-existing leak.** That is a success, not a
  blocker — but it would redden the suite. Mitigation: run the full sweep during
  build and, if a real leak is found, fix the redaction bug (or, if it is out of
  this issue's scope, file it and narrow the sweep with a documented, reviewed
  exception). Do not weaken the canary to hide it.
- **Rename breaks a Dovecot login.** Mitigation: the sentinel is colon-free
  (valid passwd-file password) and every literal occurrence is updated in the
  same change; `just test` against Dovecot verifies login still succeeds.
- **MSRV / deps.** Pure `std`; no new deps; no MSRV risk.

## 6. Guardrails

`just fmt-check`, `just lint` (clippy `-D warnings`), `just test` (full nextest,
incl. the new meta-test + a Dovecot run to confirm login), `just deny`,
`just ci` before pushing. Container suites silent-skip without a runtime; the
meta-test and the fake-backed sweeps run without a container.
