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
if the harness's password appears *verbatim* in any artifact that run
produced — except the one place it legitimately must (the IMAP LOGIN frame),
which the sweep instead uses as a positive control that authentication actually
happened (§4.3, §4.4).

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
- **Detecting encoded or transformed leaks.** The sweep is a raw-byte substring
  search for the canary's *verbatim* form. A leak that is base64-encoded (e.g. a
  SASL/`AUTHENTICATE` blob), percent-encoded, compressed, or otherwise
  transformed before being written evades it. This is an accepted boundary, not
  an implied guarantee — the credential travels through the codebase in its
  literal form on every path this project exercises (env var → `SecretString` →
  plaintext `LOGIN`), so the verbatim scan covers the realistic leak surface.
  The canary's charset (ASCII letters, digits, `-`) contains nothing JSON string
  escaping would distort, so a verbatim leak into audit JSONL is still caught.

## 3. Acceptance criteria (from the issue)

1. Canary sweep active in all (wire-driven) e2e suites.
2. A test that logs the credential on purpose is caught by the sweep.

Restated as falsifiable checks:

- **AC1:** every `e2e_wire*` integration-test binary that spawns a harness
  references the `canary` sweep after the harness run. Made **falsifiable and
  PR-blocking** by an enumeration meta-test (§4.6): it globs the `e2e_wire*.rs`
  sources and asserts each references the sweep, matching a checked-in allowlist
  — a new wire suite or a dropped sweep call reddens CI rather than depending on
  a reviewer noticing. The enumeration is a source-text check; it enforces
  *presence*, not that the swept value equals the injected one. Value-identity is
  instead guaranteed by convention (§4.4): each suite binds its canary **once**
  to a local (`let password = fresh_canary();` or the `DOVECOT_CANARY_PASSWORD`
  constant) and uses that same binding for both the spawn env and the sweep call,
  so a mismatch is not expressible. For fake suites the LOGIN-frame positive
  control is an independent backstop — sweeping a value other than the injected
  one fails the positive control, because `recorded()` holds the real credential.
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

/// Outcome of a scan: places the canary appeared, AND artifacts that could not
/// be read. Both are surfaced — a detector that "could not look" must never be
/// reported as clean.
pub struct ScanReport {
    pub hits: Vec<CanaryHit>,
    /// Paths whose traversal or read failed (permissions, transient I/O, a path
    /// that raced with harness cleanup), each with the error rendered.
    pub errors: Vec<String>,
}

/// Pure detection: recursively read every file under each root as *bytes*,
/// plus each in-memory `extra` string. Returns every canary occurrence AND
/// every unreadable artifact. Does not panic — that self-testability is why the
/// meta-test can inspect both vectors directly.
pub fn scan(canary: &str, roots: &[&Path], extra: &[String]) -> ScanReport;

/// Assert the canary is absent from every file artifact AND that every artifact
/// was actually readable; panic listing all hits and all read errors otherwise.
/// Thin wrapper over `scan`. An unreadable root/file is a hard failure, not a
/// silent skip, so "clean" always means "looked and found nothing".
pub fn assert_absent(canary: &str, roots: &[&Path], extra: &[String]);

/// Positive + negative control over the fake's recorded client dialog.
/// The credential legitimately appears exactly once, in the plaintext
/// `LOGIN` line (`recorded()` captures the raw client frame post-TLS). So a
/// blanket `assert_absent` over `recorded()` would always fire. Instead:
///   - **positive control**: assert at least one recorded frame is a `LOGIN`
///     line containing the canary — proof the run authenticated and the
///     credential reached the wire, closing the vacuous-pass gap (§4.2);
///   - **negative control**: assert no *non-`LOGIN`* recorded frame contains
///     the canary — a copy of the credential anywhere else in the dialog is a
///     leak.
/// Panics on either violation. For suites that deliberately never reach LOGIN
/// (`_tls_pin_mismatch`), do not call this — use
/// `assert_absent(canary, &[artifact_root], &recorded)`, which still sweeps the
/// tempdir files and treats `recorded` as an ordinary (canary-free) extra
/// because no LOGIN was sent.
pub fn assert_login_frame_only(canary: &str, recorded: &[String]);
```

**LOGIN-frame predicate.** A recorded frame is a `LOGIN` frame iff, after
trimming the leading tag (first whitespace-delimited token), the next token
upper-cased equals `LOGIN`. This matches the IMAP *command position*, so a
`SEARCH`/`APPEND`/`SELECT` frame whose argument merely contains the substring
`LOGIN` is correctly classified as non-`LOGIN` (and a canary leak inside it is
caught by the negative control). The predicate is a small pure function with its
own meta-test case (§4.5).

**Same-frame / inline-password dependency.** `assert_login_frame_only` assumes
the canary and the `LOGIN` keyword land in the *same* recorded frame. That holds
here because (a) `recorded()` captures one client command per `read_line`, and
(b) async-imap emits LOGIN inline as `<tag> LOGIN <user> <password>\r\n`
(`quote!`-wrapped args on one line), not as an IMAP literal continuation. The
canary charset (§4.1, ASCII letters/digits/`-`) contains no CR, LF, quote, or
`{` that would force `quote!` into a literal-continuation form, so the password
stays inline. If a future canary charset or auth mechanism (SASL/`AUTHENTICATE`)
broke this, the positive control would fail loudly (LOGIN frame lacks the
canary) rather than silently pass — a safe failure direction.

**Byte search, verbatim only.** `scan` matches the canary's literal bytes;
encoded/transformed representations are out of scope (§2 non-goals). The
"never appears" guarantee is therefore "never appears **verbatim**."

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
  `recorded()` client frames are **not** swept with `assert_absent` (they
  legitimately contain the LOGIN password); they go through
  `assert_login_frame_only` instead (§4.3).
- **Symlink safety.** The walk does **not** follow symlinks (a symlink out of
  the tempdir could pull unrelated host files into the scan and either false-
  positive or hang); it scans regular files only.

### 4.2 Canary values and the Dovecot constraint

The password a harness feeds the server is only a *meaningful* leak probe if the
run actually authenticates and exercises the post-LOGIN surface (FETCH bodies,
audit `tool_start`/`tool_end`, tracing spans). An absence-only assertion would
otherwise **pass vacuously** on a run that fails to boot, fails LOGIN, or injects
an empty/wrong password — green while testing nothing. Every authenticating suite
therefore carries a **positive control** that authentication occurred, so that
"clean" can never mean "never ran":

- **Fake-backed suites**: `assert_login_frame_only` requires the canary to appear
  in a recorded `LOGIN` frame (§4.3) — direct proof the credential reached the
  wire.
- **Dovecot-backed suites**: the fake's wire is not visible, but each Dovecot
  suite's test body already asserts **successful tool responses**, which are
  unreachable without a successful LOGIN. Those existing assertions are the
  positive control; the canary sweep adds only the absence check.

Two backends, two canary strategies:

- **Fake-backed / env-fed suites** (`e2e_wire_fetch_skipped`,
  `_folder_not_found`, `_transcript_cleanup`, `_transcript_triage`,
  `_uidvalidity`, `_tls_pin_mismatch`, `_login_rejected`): the fake accepts any
  LOGIN, so each run injects a **fresh per-run canary** from `fresh_canary()`,
  replacing the current hardcoded `"fake-password"` literal. Each suite sweeps
  for exactly the (fresh) value it injected. Two boundary cases:
  - `_login_rejected` deliberately sends a password the fake rejects, but the
    `LOGIN` frame still reaches the wire and is recorded, so
    `assert_login_frame_only` applies (the rejected string is the
    credential-under-test; its positive control is "reached the wire").
  - `_tls_pin_mismatch` fails the TLS pin **before** any `LOGIN` is sent, so
    `recorded()` is empty. It has no positive control by design; it uses plain
    `assert_absent(canary, &[artifact_root], &recorded)` — still sweeping the
    tempdir files (the failed-boot path may write stderr/config) with the empty
    dialog as a canary-free extra — and its purpose is documented as
    hygiene-only.

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
| Wire frames (both directions) | The password's only *legitimate* on-wire appearance is the **client→server IMAP `LOGIN`**, captured verbatim by the fake's `recorded()`. Blanket-sweeping `recorded()` would therefore always fire, so it is checked with `assert_login_frame_only` (§4.1): the canary must appear in a `LOGIN` frame (positive control that auth happened) and in **no other** recorded frame (negative control — a copy elsewhere in the dialog is a leak). Server→client fake bytes are test-scripted and never carry the secret; MCP stdio frames never carry the IMAP password. For **Dovecot** suites the IMAP wire is TLS-encrypted and not interceptable at the harness — a plaintext leak there would instead surface in stderr/audit, which are swept, and the positive control is the suite's existing successful-tool-call assertions (§4.2). |

### 4.4 Teardown wiring

Rust integration-test binaries have no shared teardown hook, so "teardown" is an
explicit call at the end of each test, mirroring the issue's "one helper, called
from the same teardown as C1." The sweep must read **final on-disk state**, so it
runs only after the child has been **reaped (exit status collected) and its
stdio pipes closed** — that barrier is what guarantees all buffered stderr/audit
has flushed. `shutdown_and_wait` provides exactly that barrier and returns the
`TempDir`:

```rust
// Fake-backed, authenticating suite:
let recorded = server.recorded();                       // capture before drop
let (_status, tempdir) = harness.shutdown_and_wait().await;
canary::assert_login_frame_only(&password, &recorded);  // wire: positive+negative
canary::assert_absent(&password, &[tempdir.path()], &[]); // files: absence only

// Dovecot-backed suite (no recorded() wire visibility):
let (_status, tempdir) = harness.shutdown_and_wait().await;
canary::assert_absent(&canary::DOVECOT_CANARY_PASSWORD, &[tempdir.path()], &[]);
```

For suites that reap the child **without** `shutdown_and_wait` (e.g.
`_tls_pin_mismatch`, which fails boot closed), the sweep reads the tempdir root
via a `Harness::artifact_root()` accessor — but **only after** the same barrier:
the child's exit status has been collected and its stdio closed. `artifact_root`
must not be read while the child may still be writing, or a late-written leak is
missed (a silent false negative). The plan specifies collecting the exit status
first for those suites.

An explicit call (rather than a `Drop` guard) is chosen deliberately: asserting
inside `Drop` during unwind risks a double-panic abort, and `Drop` ordering
against the `TempDir` guard is fragile. The explicit call is predictable and
matches how these tests already end.

### 4.6 AC1 enforcement: sweep-presence meta-test

`crates/rimap-server/tests/canary_coverage_meta.rs`, host-runnable and
PR-blocking, makes "sweep active in all wire suites" falsifiable rather than
inspection-dependent:

- Glob `${CARGO_MANIFEST_DIR}/tests/e2e_wire*.rs`.
- Assert every matched file's text references the `canary` sweep (contains
  `canary::assert_absent` or `canary::assert_login_frame_only`).
- Assert the matched set equals a checked-in allowlist constant, so **adding** a
  new `e2e_wire*` suite fails the test until the author both wires the sweep and
  extends the allowlist — closing the "new suite silently skips the sweep" gap.

This is structural enforcement without a shared teardown hook: a dropped sweep
call or an un-swept new suite reddens CI.

### 4.5 Negative meta-test (AC2)

`crates/rimap-server/tests/canary_sweep_meta.rs`, host-runnable and PR-blocking:

- **`scan_flags_a_seeded_file_leak`**: write a file containing the canary into a
  scratch tempdir; assert `scan` returns `hits` with ≥1 whose `source` is that
  file, and empty `errors`.
- **`scan_flags_an_extra_string_leak`**: pass a `recorded`-style string
  containing the canary as `extra`; assert a hit.
- **`scan_is_clean_on_a_leak_free_tree`**: a tempdir with audit/stderr/eml-shaped
  files that do *not* contain the canary; assert `scan` returns empty `hits` and
  empty `errors`.
- **`scan_reports_unreadable_artifact`**: seed a file the walk cannot read (e.g.
  `chmod 000` on a supported host, or a broken path) and assert it appears in
  `errors` — never silently treated as clean. `assert_absent` over that root
  panics (a companion `#[should_panic]` case).
- **`assert_absent_panics_on_a_leak`**: `#[should_panic]`, proving the asserting
  wrapper bites.
- **`login_frame_only_accepts_canary_in_login`**: recorded frames where the
  canary appears only in a `LOGIN` line → passes (positive + negative control
  both hold).
- **`login_frame_only_rejects_canary_outside_login`**: `#[should_panic]`, canary
  in a non-`LOGIN` recorded frame → fires (negative control bites).
- **`login_frame_only_rejects_missing_login`**: `#[should_panic]`, recorded
  frames with no canary-bearing `LOGIN` line → fires (positive control bites,
  catching a vacuous non-authenticating run).
- **`login_frame_predicate_matches_command_position_only`**: a
  `SEARCH SUBJECT "LOGIN"` frame carrying the canary is classified **non**-`LOGIN`
  (command position is `SEARCH`), so the negative control flags it → pins the
  predicate against substring misclassification (finding from spec review).

This satisfies "a test that logs the credential on purpose is caught" as a
committed, always-run test rather than a throwaway scratch branch, and proves
both controls of `assert_login_frame_only`.

## 5. Risks & mitigations

- **A suite that authenticates but a sweep is forgotten, or a new wire suite
  skips the sweep.** Mitigation: the `canary_coverage_meta.rs` enumeration test
  (§4.6) fails PR CI when any `e2e_wire*.rs` source lacks a sweep reference or is
  missing from the allowlist. Structural, not inspection-dependent.
- **Vacuous green: a run passes without authenticating.** An absence-only check
  reports success on a run that never reached the post-LOGIN surface. Mitigation:
  every authenticating suite carries a positive control (§4.2) — the
  `assert_login_frame_only` LOGIN-frame requirement for fake suites, the existing
  successful-tool-call assertions for Dovecot suites. Deliberately
  non-authenticating suites (`_tls_pin_mismatch`) are documented as hygiene-only.
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
