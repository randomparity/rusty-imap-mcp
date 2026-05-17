# MCP Protocol Fuzzing & Negative-Path Coverage — Design

**Status:** Draft 2026-05-13
**Issue:** #266 (Phase 4 of 4)
**Depends on:** #263 (Phase 1 wire harness, closed), #265 (Phase 3 Dovecot fixture, closed)
**Scope:** Property-based and targeted negative-path tests for the MCP
JSON-RPC wire: malformed envelopes, protocol-state errors, oversized
payloads, concurrent requests, cancellation mid-call, audit fail-closed
boundary. Builds on the wire-driving `Harness` shipped in Phase 1.

## 1. Motivation

Phases 1–3 cover happy-path conformance against three different
validators (vendored MCP spec schema in #263, official Node SDK in
#264, Dovecot behavioral conformance in #265). They do not cover what
happens when a misbehaving or malicious client sends garbage. The
server must respond with well-formed JSON-RPC error envelopes (per
spec) — or cleanly close the connection — rather than crash, hang, or
leak partial state. The most security-relevant tests live here, and
this phase locks in the negative-path contract before any new tool or
config surface is added.

## 2. Goals & Non-Goals

### Goals

- Cover the negative-path categories the issue enumerates: malformed
  input, method-level errors, protocol-state errors, concurrency,
  cancellation, property-based envelope fuzzing, audit fail-closed.
- Every test asserts a concrete contract — no test that only checks
  "didn't crash."
- Deterministic concurrency (no clock-based races); deterministic
  proptest reproducibility (`proptest-regressions/` committed).
- ≥1000 cases per property in CI; overnight runs scale via
  `PROPTEST_CASES`.
- Zero new production crate dependencies. Reuse the Phase 1 harness
  and the existing workspace `proptest`.

### Non-Goals

- IMAP-server-side fuzzing — covered by `rimap-content` ammonia
  property tests and the mail-parser adversarial corpus.
- Coverage-guided fuzzing infrastructure — `.clusterfuzzlite/`
  already exists.
- Tool-output schema fuzzing — Phase 4 targets the wire/envelope
  layer; output schemas are validated in Phase 1 and Phase 3.
- New tools, new config surface, new production code paths. Phase 4
  is testing only. The audit-failure tests reuse the existing
  `AuditWriter::force_next_write_failure()` hook (§6.4) rather than
  introducing any new sink, feature flag, or filesystem trickery.

## 3. Architecture

Five new test binaries across two crates, all reusing the existing
`support/wire/` module from Phase 1 where they cross the wire. The
harness is extended in place — no new struct, no forked spawn
path. Four binaries live under `rimap-server/tests/`; the audit-
layer Drop test lives under `rimap-audit/tests/` (see §4.4.2 for
the rationale).

| File | Purpose | Spawn config |
| --- | --- | --- |
| `crates/rimap-server/tests/mcp_wire_negative.rs` | Malformed JSON, protocol-state errors, version negotiation failures, concurrent in-flight requests. | Zero-account (`Harness::spawn`). |
| `crates/rimap-server/tests/mcp_wire_proptest.rs` | `proptest`-driven envelope and `tools/call` argument fuzzing. ≥1000 cases per property by default. | Zero-account, harness reused across cases with restart-on-close discipline (§3.2). |
| `crates/rimap-server/tests/mcp_audit_failure.rs` | Audit fail-closed boundary tests. | Zero-account, audit path on a write-failing target. |
| `crates/rimap-server/tests/e2e_wire_cancellation.rs` | Wire-layer cancellation: server accepts `notifications/cancelled` and stays responsive. Race-free assertions only (no `tool_end {status: cancelled}` here — see audit-layer test). | Phase 3 Dovecot fixture (`support/dovecot/harness.rs`). |
| `crates/rimap-audit/tests/drop_emits_cancelled.rs` (new) | Audit-layer Drop discipline (#99): construct a `run_with_audit_envelope` future, poll once, drop it, assert exactly one `tool_end {status: cancelled}` record was written. Deterministic, no Dovecot, no race. | In-process unit test, no spawned binary. |

### 3.1 Harness extensions

`crates/rimap-server/tests/support/wire/harness.rs` gains these methods.
The existing `request` / `notify` / `shutdown_and_wait` surface is
unchanged so Phases 1 and 3 continue to validate envelopes by default.

```rust
async fn send_raw(&mut self, bytes: &[u8]);
async fn send_line(&mut self, line: &str);                     // appends \n
async fn recv_line_within(&mut self, dur: Duration) -> Option<String>;
async fn send_request_no_wait(&mut self, method: &str, params: Value) -> u64;
async fn recv_until_id(&mut self, id: u64) -> Value;
async fn assert_clean_shutdown_or_response(&mut self, request_dur: Duration);
```

The notification-skip loop currently inlined in `request` is refactored
into a private `read_one_envelope` helper so `request` and
`recv_until_id` share parsing and the stderr-on-failure diagnostics.
`recv_until_id` buffers out-of-order responses in a small `VecDeque`
keyed by id — when a later call asks for a buffered id, it is returned
without touching stdout.

### 3.2 Determinism primitives

- **Concurrency** — `send_request_no_wait` + `recv_until_id` is a
  single-task design; no `tokio::spawn`, no shared `Mutex` over
  stdout. The harness drains stdout linearly; out-of-order responses
  are buffered. Deterministic under nextest load.
- **Cancellation timing** — the Dovecot-backed test polls the audit
  log for `tool_start` (100 ms cap, 10 ms granularity) before issuing
  `notifications/cancelled`. No `sleep()`-and-hope ordering.
- **Proptest seeds** — `proptest-regressions/` is committed (same
  pattern `rimap-content` already uses). Each shrink reproduces from
  the committed seed.
- **Proptest session isolation** — properties share a harness across
  cases for speed (re-spawning the binary per case would push 1000
  cases per property past the CI budget). Two disciplines keep
  cases from poisoning each other:
  - **Restart-on-close**: after every case, the harness checks
    whether the connection is still alive (child process running,
    stdout not at EOF). If not, the case records "connection closed
    cleanly" as its result and the next case spawns a fresh
    harness. No case ever runs against a poisoned session.
  - **State-mutating-method exclusion** (property 1 only): the
    strategy explicitly avoids generating `method` values that
    mutate MCP session state. Pinned exclusion set:
    `{"initialize", "notifications/initialized"}`. A pinned
    assertion in the test cross-references this set against
    `rmcp`'s known stateful methods so a future MCP spec addition
    that introduces a new stateful method trips the assertion
    rather than silently coupling cases. Properties 2 and 3 are
    stateless by construction (`method` is fixed to
    `tools/call <X>`) so they need no exclusion.
  - **Shrinking caveat**: a shrunk regression assumes a freshly
    initialized session. If a committed seed in
    `proptest-regressions/` fails to reproduce against a fresh
    harness, that is evidence of state-coupling — investigate as a
    bug, do not delete the seed.

## 4. Test inventory & contracts

Every test asserts a concrete contract. Probe-based contracts ("either
envelope-X or clean close") record the probed behavior inline so
future readers can tell why the assertion is shaped that way.

### 4.1 `mcp_wire_negative.rs` (≈8–10 tests, zero-account)

| Test | Input | Contract |
| --- | --- | --- |
| `unparsable_json_errors_or_closes` | `not json\n` | Envelope `code: -32700` OR child exits 0 within `SHUTDOWN_TIMEOUT`. |
| `valid_json_invalid_envelope_returns_minus_32600` | `{"foo":"bar"}` | `-32600` invalid request, `jsonrpc == "2.0"`. |
| `missing_method_field` | envelope without `method` | `-32600`. |
| `wrong_type_method_field` | `"method": 42` | `-32600`. |
| `oversized_params_payload` | `params.note` = 1 MiB string | Valid envelope (success or error) or clean close; never hang past `REQUEST_TIMEOUT`. |
| `initialize_after_already_initialized` | Two `initialize` calls | Second returns an error envelope; exact code recorded inline. |
| `tools_list_before_initialize` | `tools/list` without prior `initialize` | Error envelope; code recorded. |
| `initialize_unsupported_protocol_version` | `protocolVersion: "1999-01-01"` | Echo of supported version OR error envelope (spec allows either). |
| `concurrent_tools_list_two_inflight` | Two `tools/list` via `send_request_no_wait`, both awaited via `recv_until_id` | Both responses received within `REQUEST_TIMEOUT`, ids match, no corruption. |
| `bidi_override_in_tool_argument` | `tools/call use_account` with bidi-override in `account_id` | Accepted or rejected with valid error envelope; no panic in audit writer. |

### 4.2 `mcp_wire_proptest.rs` (3 properties, zero-account)

```rust
#![proptest_config(ProptestConfig::with_cases(1000))]
```

`PROPTEST_CASES` overrides the case count. Overnight runs use 100 000.
Each property block starts with one `Harness` and replays N
envelopes through it. The restart-on-close discipline from §3.2
spawns a fresh harness whenever a case closes the connection, so a
case that legitimately ends the session never poisons the next
case. Re-spawning unconditionally per case would push the suite
past minutes without adding coverage, since properties 2 and 3 are
stateless by construction and property 1 excludes the pinned
state-mutating method set.

1. **`prop_envelope_never_panics`** — strategy generates arbitrary
   JSON values with optional `jsonrpc`, `id`, `method`, `params`
   fields of randomized types. The `method` strategy excludes the
   pinned state-mutating set `{"initialize", "notifications/initialized"}`
   (see §3.2 Proptest session isolation) so cases stay independent
   of session state. The test asserts at compile time / startup
   that the exclusion set matches the methods rmcp documents as
   stateful; a future spec addition that introduces a new stateful
   method trips this assertion before silently coupling cases.
   Assert per case: the input either produces a well-formed
   JSON-RPC envelope validating against
   `JSONRPCResponse`/`JSONRPCError`, or the server cleanly closes
   the connection (restart-on-close discipline handles the latter).
   No panic, no hang past `REQUEST_TIMEOUT`, no malformed line.
2. **`prop_tools_call_unknown_tool`** — arbitrary string tool names
   plus arbitrary JSON `arguments`. Assert: every response validates
   as `JSONRPCErrorResponse`; `code` is one of a documented small
   set.
3. **`prop_tools_call_use_account_argument_shape`** — `use_account`
   called with arbitrary argument shapes. Assert: server returns a
   valid error envelope (no account configured ⇒ rejection); never
   a result envelope. (`list_accounts` is also advertised in the
   zero-account config but takes no arguments, so it is not a
   useful fuzz target for argument-shape properties; envelope-level
   coverage for it lives in property 1.)

### 4.3 `mcp_audit_failure.rs` (2–3 tests, zero-account)

| Test | Setup | Contract |
| --- | --- | --- |
| `audit_write_failure_fails_closed_for_tools_call` | Arm the in-process `AuditWriter` via `force_next_write_failure()` (see §6.4), then send `tools/call use_account` over the wire. | `tools/call use_account` returns an error envelope; server does NOT silently succeed. Exercises the real writer's lock / append / error-mapping path. |
| `audit_write_failure_does_not_block_initialize` | Same setup, but the failure is armed before `initialize`. | `initialize` either succeeds or fails with a clear error; exact behavior asserted from probe. |

### 4.4 Cancellation — split across two layers

The contract has two parts and they belong in two places. The wire
layer's job is to accept the cancel envelope without crashing or
breaking the session; the audit layer's job is to emit
`tool_end {status: cancelled}` on Drop. Testing both ends in a
single Dovecot-backed wire test forces a race (was the call still
in flight when the cancel arrived?). The Codex adversarial review
flagged this; the fix is to split.

#### 4.4.1 `e2e_wire_cancellation.rs` (2 tests, Dovecot-backed)

Race-free assertions only — these tests do *not* try to prove that
the in-flight call was cancelled mid-execution.

| Test | Flow | Contract |
| --- | --- | --- |
| `cancel_during_inflight_tools_call_keeps_session_alive` | `use_account` → start `tools/call search` → immediately send `notifications/cancelled` with the request id (no audit-log polling) → drain stdout. | Server emits exactly one response envelope for the cancelled request id (either result or error, race-dependent), then accepts a subsequent `tools/list` without restart. No panic, no malformed envelope, no orphaned stdout bytes. |
| `cancel_unknown_request_id_is_noop` | Send `notifications/cancelled` for an id that was never used. | No response, no panic, server still responsive to subsequent `tools/list`. |

#### 4.4.2 `crates/rimap-audit/tests/drop_emits_cancelled.rs` (new, 1–2 tests)

In-process tests that drive the Drop discipline directly. No
spawned binary, no Dovecot, no timing dependency.

| Test | Flow | Contract |
| --- | --- | --- |
| `drop_after_tool_start_emits_cancelled_end` | Construct an `AuditWriter` writing to a tempdir. Wrap a never-completing future in `run_with_audit_envelope`. Poll once (drives the `tool_start` write). Drop. Read the audit log. | Exactly one `tool_start` followed by exactly one `tool_end` with `status: cancelled`. Issues #71, #99. |
| `drop_before_tool_start_emits_nothing` | Construct the future but never poll it. Drop. | Audit log is empty. (Documents that the Drop guard only fires once `tool_start` has been written, which is the contract that #71 fixed.) |

If `run_with_audit_envelope` is private to `rimap-server`, a
crate-internal `#[cfg(test)]` accessor is added to expose it for
the new test — flagged in §7 risk register.

## 5. Error handling

Every assertion failure includes captured child stderr via the
existing `Harness::captured_stderr` helper. Test diagnostics quote the
captured stream so a CI failure surfaces the binary's
`tracing::error!` output, not just the test panic line.

For probe-based contracts, the probed behavior is documented inline:

```rust
// Probed 2026-05-13 (rmcp 1.5): server responds with -32700.
// If this changes, the parse-error path either tightened (stricter
// envelope rejection) or the framing changed — investigate before
// updating the assertion.
```

Bugs found during probing — server panics on malformed input, hangs,
leaks partial state, emits malformed envelopes — are filed as
separate issues per the issue's acceptance criteria and fixed before
Phase 4 merges. Each such bug gets a regression test that lands with
the fix.

## 6. CI, dependencies, decomposition

### 6.1 CI integration

- Default `cargo test -p rimap-server` runs the 1000-case proptest
  properties under a per-property budget that keeps the suite under
  the existing `rimap-server` test wall-clock. No CI matrix changes.
- Overnight runs: GitHub Actions cron workflow at
  `.github/workflows/mcp-fuzz-nightly.yml` sets
  `PROPTEST_CASES=100000` and runs
  `cargo test -p rimap-server --test mcp_wire_proptest -- --nocapture`
  (singular `--test`, selects the integration-test binary by name;
  the plural `--tests` form would have turned `mcp_wire_proptest`
  into a substring filter on test function names and silently run
  zero properties). A subsequent step parses the test output and
  fails the workflow if the runner reports zero tests executed —
  this is the guard that catches any future drift in the selector
  syntax. Pinned to a SHA per the repo's existing convention;
  `zizmor` passes before merge.
- Nextest classification: proptest tests use
  `slow-timeout` overrides so a stuck case fails fast instead of
  hitting the full CI timeout.
- Dovecot-backed cancellation tests reuse the existing
  `dovecot` gating mechanism from `e2e_wire.rs`.

### 6.2 Dependencies

No new crate. The fuzzing layer reuses `proptest` 1.6 (already a
workspace dep), `jsonschema`, `tempfile`, `tokio`, `serde_json`,
`assert_cmd`. `rmcp` 1.5 unchanged; the existing version-drift
detector in
`wire_protocol_version_negotiation_matches_vendored_schema` will
catch any bump that invalidates a fuzz assertion.

### 6.3 Decomposition

Phase 4 lands as a single PR but the work decomposes into sequenced
commits so probing-phase fallout does not block earlier commits:

1. **Harness extensions** (`support/wire/harness.rs`). Exercised
   transitively by the first test in `mcp_wire_negative.rs` that
   uses each new method — no separate unit-test module is added to
   `harness.rs` (the file currently has none and the integration
   tests are the natural call site).
2. **`mcp_wire_negative.rs`** — all probed contracts. Bugs found
   during probing are fixed on sibling branches before this commit
   lands.
3. **`mcp_wire_proptest.rs`** — three properties at 1000 cases.
   `proptest-regressions/` directory committed.
4. **`mcp_audit_failure.rs`** — fail-closed boundary tests via
   `AuditWriter::force_next_write_failure()` (§6.4).
5. **`drop_emits_cancelled.rs` in `rimap-audit/tests/`** —
   audit-layer Drop discipline (#99). In-process, deterministic, no
   wire. Lands before the wire-layer cancel test so the source-of-
   truth contract is pinned first.
6. **`e2e_wire_cancellation.rs`** — Dovecot-backed wire-layer
   cancel acceptance test. Race-free assertions only (§4.4.1).
   Lands last; depends on Phase 3 harness.
7. **Nightly CI workflow** — same PR, reviewed separately.

### 6.4 Audit failure injection

`rimap-audit::AuditWriter` already exposes a real test-injection
hook used by `crates/rimap-server/tests/audit_fail_open.rs`:

```rust
writer.force_next_write_failure();
```

This forces the *real* `AuditWriter`'s next `log_*` call to take
the write-failure path through the real lock / append / error-
mapping logic — it is not a swappable sink. Phase 4's audit tests
reuse this hook rather than relying on filesystem permissions
(`chmod 0o500` is unreliable as root on some CI runners) or a
sentinel sink (which would bypass the very path the tests need to
exercise, and add a permanent non-production branch). The Codex
adversarial review flagged the sentinel-sink approach for exactly
this reason.

The audit-failure tests in `mcp_audit_failure.rs` drive the wire
from the outside but use `force_next_write_failure()` on the
in-process `AuditWriter` via the binary's existing test-support
surface. If the surface needs a small extension (e.g., to call
`force_next_write_failure()` from outside the process), that
extension lives behind the existing `test-support` feature flag on
`rimap-server` rather than `rimap-audit`, since the hook itself is
already public on `AuditWriter`.

## 7. Risk register

| Risk | Mitigation |
| --- | --- |
| Probing reveals a panic in the server on malformed input. | File issue, fix on sibling branch, regression test lands in Phase 4. Expected outcome, not blocker. |
| Proptest finds a minimal-shrunk case hard to reproduce. | `proptest-regressions/` committed; each property's regressions reviewed in the PR. |
| Concurrent-request test flaky under nextest. | Determinism comes from `send_request_no_wait` + `recv_until_id` (no clock races). If the binary serializes responses, the test still passes — just less interesting. |
| `run_with_audit_envelope` is private to `rimap-server`, so the audit-layer Drop test in `rimap-audit/tests/drop_emits_cancelled.rs` can't reach it. | Add a crate-internal `#[cfg(test)]` accessor on `rimap-server`, or move the test under `rimap-server/tests/` if the future is wholly server-internal. Decided during implementation; flagged here so the choice is visible. |
| Wire-layer cancel test asserts race-dependent outcomes. | Tests only race-free invariants (server stays responsive, response envelope is well-formed). Cancellation-status assertion lives in the audit-layer Drop test, not here. |
| Proptest at 100 000 cases overruns the nightly job's runner budget. | `slow-timeout` per property; nightly runs publish duration as part of the failure summary so we can split a single property into smaller ones if needed. |

## 8. Acceptance criteria mapping

Each acceptance criterion from issue #266 maps to a concrete artifact:

- [ ] Every category exercised by an explicit per-binary
      invocation (no glob): `cargo test -p rimap-server --test mcp_wire_negative`,
      `--test mcp_wire_proptest`, `--test mcp_audit_failure`,
      `--test e2e_wire_cancellation`, and
      `cargo test -p rimap-audit --test drop_emits_cancelled`.
      Covered by §4.1–§4.4.
- [ ] Property tests run for ≥1000 cases per property in CI, gated by
      env flag — `ProptestConfig::with_cases(1000)` + `PROPTEST_CASES`
      override, §4.2 and §6.1.
- [ ] Every negative case has an explicit assertion about correct
      behavior — every row in §4.1–§4.4 has a contract column; "didn't
      crash" alone is never an assertion (§5).
- [ ] No new flakiness — determinism primitives in §3.2.
- [ ] Bugs found during implementation filed as separate issues and
      fixed before merge — §6.3 step 2 and §5.
- [ ] Design doc in `docs/superpowers/specs/` — this file.

## 9. Out of scope (explicit)

- Coverage-guided fuzzing (`.clusterfuzzlite/` already exists).
- IMAP-server-side fuzzing.
- Tool-output schema fuzzing.
- New tools, new config surface.
- Schema drift detection — already covered by
  `wire_protocol_version_negotiation_matches_vendored_schema` from
  Phase 1.
