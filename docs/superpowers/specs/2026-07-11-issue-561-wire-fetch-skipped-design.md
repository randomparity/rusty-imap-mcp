# Full-wire e2e assertion for `search` `meta.fetch_skipped` — design

**Status:** Draft 2026-07-11 · issue [#561](https://github.com/randomparity/rusty-imap-mcp/issues/561)
**ADR:** [ADR-0008](../../ADR/0008-shared-fake-imap-test-support-crate.md)
**Follow-up to:** #535 (PR #560), spec
`docs/superpowers/specs/2026-07-11-issue-535-fetch-inband-truncation-design.md`
**Scope:** Close the coverage gap #535 flagged (its "AC interpretation" note):
add a host-runnable JSON-RPC-wire test that drives the production binary against
a scripted short-page IMAP server and asserts `SearchMeta.fetch_skipped > 0` on
the `search` tool response. Enabling that requires promoting the scriptable
adversarial fake to a shared test-support crate reachable by `rimap-server`.
Test-only + test-support packaging change; **no production code changes.**

## Problem

#535 (PR #560) added `SearchMeta.fetch_skipped` — the `search` page shortfall
(`page_requested − returned`), a SEARCH↔FETCH consistency signal. It verified the
field at the unit level (`build_search_meta` shortfall/zero tests) and the
contract level (schema-presence test) but **deferred** a full JSON-RPC-wire
assertion. The reason recorded in the #535 spec was that the `e2e_wire*` harness
drives the binary against **Dovecot**, which is conformant and cannot emit a
short page, and "there is no adversarial-fake seam behind the server binary."

That last claim was wrong. The scriptable `FakeImapServer`
(`crates/rimap-imap/tests/support/fake_imap.rs`) **binds a real
`127.0.0.1:0` IMAPS socket**, exposes `.port()` and `.pin()`, and
`Step::Send(Vec<u8>)` can emit a `UID FETCH` reply that omits the line for a
requested UID. The server binary already connects to a configurable IMAPS
host/port with a pinned fingerprint (that is how the Dovecot e2e wire tests
work). So the fault can be produced and asserted over the wire — the only real
blocker is **packaging**: the fake lives in `rimap-imap/tests/support/` and is
not reachable from `rimap-server`'s tests.

### What this closes (and does not)

This adds *coverage*, not behavior. It asserts the already-shipped
`fetch_skipped` signal survives the full production path — real binary, real
IMAPS socket, JSON-RPC wire, real reassembly layer — end to end, on the one
input a conformant server cannot produce (a short page). It does **not** change
`fetch_skipped`'s semantics, the posture matrix, `rimap-imap`, or any shipped
code. The signal's limits are unchanged and remain recorded in ADR-0007 / the
#535 spec (it is a SEARCH↔FETCH consistency check, not an anti-omission
guarantee).

## Acceptance criteria (from the issue)

- [ ] `fake_imap` is reachable from `rimap-server` tests without a relative
      cross-crate `#[path]` hack; existing `rimap-imap` fake-based tests still pass.
- [ ] A host-runnable (no-container) `e2e_wire` test asserts
      `meta.fetch_skipped > 0` on a scripted truncated `search` response over the
      JSON-RPC wire.
- [ ] `just ci` stays green.

## Decision

Two parts, both settled in ADR-0008 and below.

1. **Promote the fake to `crates/rimap-fake-imap`** — a `publish = false`
   workspace crate holding the `fake_imap` + `certs` modules verbatim, taken as a
   `dev-dependency` by both `rimap-imap` and `rimap-server`. The
   crate-vs-`#[path]`-hack and dev-dependency-cycle rationale is ADR-0008.
2. **Add `crates/rimap-server/tests/e2e_wire_fetch_skipped.rs`** — a
   host-runnable wire test that starts the fake with a scripted short-page FETCH,
   points the binary at it, and asserts `fetch_skipped > 0` over the wire.

## Design

### 1. `crates/rimap-fake-imap` (new, `publish = false`)

```
crates/rimap-fake-imap/
├── Cargo.toml
└── src/
    ├── lib.rs        # pub mod fake_imap; pub mod certs;
    ├── fake_imap.rs  # moved verbatim from rimap-imap/tests/support/
    └── certs.rs      # moved verbatim (incl. its #[cfg(test)] unit test)
```

- `Cargo.toml`: `publish = false`, `[lints] workspace = true`, and the deps the
  two files already use — normal deps on `rimap-core`, `rimap-imap`,
  `secrecy`, `tokio`, `tokio-rustls`, `rustls`, and `rcgen`. Internal path deps
  carry `version = "0.1.1-dev"` (matching the workspace convention that satisfies
  cargo-deny's wildcard ban for versioned path deps).
- `lib.rs` re-declares the two modules. The old `support/mod.rs`
  `#![allow(dead_code)]` is **not** carried over: `pub` items in a library crate
  are not dead-code-warned, so each consumer using a subset compiles clean.
- The `#![expect(clippy::unwrap_used, reason = "tests")]` module-inner
  attributes on both files are retained — the crate is test-support, so `unwrap`
  is acceptable, and the `expect` remains fulfilled under workspace lints.
- Import path inside `fake_imap.rs` changes from
  `use crate::support::certs::{…}` to `use crate::certs::{…}` (same crate, new
  module layout).
- Added to `[workspace] members`.

### 2. `rimap-imap` — repoint existing fake-based tests

- `rimap-imap/Cargo.toml`: add `rimap-fake-imap = { path = "../rimap-fake-imap" }`
  to `[dev-dependencies]` (path-only; `publish = false` crate has no published
  version to reference, and `deny.toml` sets `allow-wildcard-paths = true`).
- Delete `crates/rimap-imap/tests/support/fake_imap.rs` and
  `crates/rimap-imap/tests/support/certs.rs`.
- `crates/rimap-imap/tests/support/mod.rs` keeps only `pub mod tracing_capture;`
  (drop the `certs` / `fake_imap` decls). The module-level `#![allow(dead_code)]`
  stays — `tracing_capture` is still a per-binary include and keeps its
  per-binary dead-code behavior.
- Update imports in `adversarial_imap.rs` and `expunge_folder_wide_gap.rs`:
  `use support::fake_imap::{…}` → `use rimap_fake_imap::fake_imap::{…}` (and
  drop `mod support;` where `tracing_capture` is not also used —
  `expunge_folder_wide_gap.rs` uses only the fake, so its `mod support;` is
  removed; `adversarial_imap.rs` keeps `mod support;` for `tracing_capture`).
- No production `rimap-imap` code changes; `ops::fetch` is untouched.

### 3. `rimap-server` — the new wire test

- `rimap-server/Cargo.toml`: add
  `rimap-fake-imap = { path = "../rimap-fake-imap" }` to `[dev-dependencies]`.
- New test `crates/rimap-server/tests/e2e_wire_fetch_skipped.rs`:
  1. Start `FakeImapServer` with a script:
     `login_preamble("IMAP4rev1")` + read-only `EXAMINE` (the search path opens
     read-only) + `UID SEARCH` replying `* SEARCH 1 2 3` + a `UID FETCH` reply
     that returns **complete** items for UIDs 1 and 3 but **omits the line for
     UID 2**.
  2. Build a **single-account, `readonly`-posture** TOML pointing the binary at
     `127.0.0.1:<fake.port()>`, `encryption = "tls"`,
     `tls_fingerprint_sha256 = <fake.pin().to_hex()>`,
     `[defaults.credentials] fallback = "keyring-then-env"` — modeled on the
     one-account blocks in `tests/support/wire/config.rs`. Written to a tempdir.
  3. Spawn the binary via `Harness::spawn_with_config`, injecting
     `RUSTY_IMAP_MCP_PASSWORD` (the fake accepts any password — `login_preamble`
     always replies `OK LOGIN completed`).
  4. `initialize` → `notifications/initialized` → `use_account("readonly")` →
     `readonly.search` with `{ folder: "INBOX", <a key that maps to UID SEARCH> }`.
  5. Assert all three of `structuredContent.meta.fetch_skipped == 1`,
     `meta.returned == 2`, and `meta.total_matched == 3` (server listed 3 UIDs,
     returned 2 usable messages, exactly one — UID 2 — dropped). These three
     equalities are the **hard merge gate**, not aspirations; see
     "Merge gate is exact" below.
- Gating: **no container runtime** — the fake binds a loopback socket in-process,
  so this test always runs on PR CI (unlike the Dovecot-gated `e2e_wire*` suite).
  It must not import the Dovecot harness.

### Merge gate is exact (`returned == 2`, `total_matched == 3`, `fetch_skipped == 1`)

The test asserts the precise omitted-line semantics, not a weaker "something was
dropped" bound. `total_matched` derives from the SEARCH result length
(`ops/search.rs`, before any FETCH), so `== 3` is robust by construction.
`returned = messages.len()` after reassembly, so `== 2` requires the FETCH reply
lines for UIDs 1 and 3 to be **fully parseable** into `SearchResultEntry`.

**The item set is richer than any existing fake scenario hand-scripts.** The
search page fetches `FetchSpec { envelope: true, flags: true, size: true, .. }`
(`fetch_and_format_page`, `search.rs`), so each surviving reply line must carry
`UID`, a well-formed `ENVELOPE` (RFC 3501 §7.4.2 parenthesized form:
date, subject, from/sender/reply-to/to/cc/bcc address lists, in-reply-to,
message-id), `FLAGS`, and `RFC822.SIZE`. Existing fake scenarios only ever
hand-script a `FLAGS`-only line (`* 3 FETCH (UID 5 FLAGS (\Seen))`), which is
strictly simpler; **there is no precedent for a hand-scripted `ENVELOPE`** in the
fake. Shaping two faithful `ENVELOPE`-bearing lines is therefore an **explicit
up-front task**, not an assumed one — a malformed parenthesization or a missing
required item drops the entry and yields `returned == 1`. The exact bytes are
calibrated during TDD (dump the client `UID FETCH` to confirm the requested
items, then shape the reply against the RFC 3501 `ENVELOPE` grammar).

**`page_requested == 3` is not accidental.** `fetch_skipped = page_requested −
returned`, and `page_requested == 3` only if the binary fetches all three listed
UIDs in one page. `limit` defaults to `MAX_LIMIT = 100` (`search.rs`) when the
`search` arguments omit it, and `paginate_uids` takes `min(limit, matches)`, so
with 3 matches and the default limit, `page_requested == 3`. The test therefore
**must not pass `limit < 3`** in the `search` arguments (omitting `limit` is the
safe default). A sub-3 limit would make `page_requested == 2`, `fetch_skipped ==
0`, and the test would fail as a config mismatch, not a logic bug. The same rule
applies to `offset`, the other page-shaping knob (`paginate_uids(uids, offset,
limit, …)`): the args **must omit `offset`** (or set it to `0`), since a non-zero
offset drops a leading UID from the page and breaks the exact `returned == 2` /
`fetch_skipped == 1` gate identically.

There is **no weaker fallback**. If TDD cannot produce two fully-parseable lines
(so `returned` lands at 1, not 2), that is a **blocker to escalate**, not a
license to relax the assertion to `fetch_skipped >= 1`. A green test must mean
"the server listed 3, returned exactly 2, and the one gap surfaced as
`fetch_skipped == 1`" — one defined outcome, fully falsifiable.

### Fake-script sequence: expected, confirmed by calibration

The scripted sequence — `login_preamble("IMAP4rev1")` → `EXAMINE` →
`UID SEARCH` (`* SEARCH 1 2 3`) → `UID FETCH` (lines for 1 and 3, none for 2) — is
the **expected** dialog derived from the read-only search path
(`ops/search.rs`: read-only `EXAMINE`, then `uid_search`, then the page FETCH).
It is **not yet demonstrated against the fake** as a single sequence: existing
scenarios cover `EXAMINE`+`UID FETCH` (no intervening SEARCH) and read-write
`SELECT`+`UID SEARCH` separately, never the read-only three-command chain this
test needs. So the exact dialog is a **TDD discovery task**, confirmed the way the
existing scenarios were: run the test, dump `server.recorded()`, and match the
reply to the actual client commands.

Two concrete calibration risks the implementer must resolve, not assume:

- **Capability-gated commands.** `Step::Expect { verb }` is strictly linear and
  reads a client line only at `Expect` steps; any unanticipated command the
  binary emits under a minimal `IMAP4rev1`-only capability set (a folder-probing
  `LIST`/`STATUS`, `NAMESPACE`/`ID`/`ENABLE`, or a capability re-probe) lands on
  the wrong `Expect` and trips the fake's in-task `assert!`. That panic runs on
  the fake's spawned (never-awaited) accept task, so it surfaces to the test only
  as a dropped connection or a 2s `REQUEST_TIMEOUT`, not as the fake's message.
  If calibration shows the search path issues such commands, extend
  `login_preamble`'s capability atoms and/or add matching `Expect`/`Reply` steps.
- **Diagnosability on *every* failure path, not just assertion failure.** The
  two calibration risks above surface *before* any `assert_eq!` on `meta` runs:
  `Harness::request` **panics** (not returns `Err`) on a 2s timeout or a dropped
  connection. A `recorded()` dump guarded only around the final assertion would
  never fire on exactly those two most-likely failures. The test **must**
  therefore print `server.recorded()` via a **drop guard** that dumps when
  `std::thread::panicking()` is true — so it fires on the harness timeout-panic,
  the fake's in-task `assert!` panic (surfaced as a dropped connection), and a
  wrong-`meta` `assert_eq!` alike. `Harness::request` already appends the child's
  captured stderr (the binary's `tracing` for connection/command errors) to its
  panic message; the drop guard adds the client-command order the harness cannot
  see. Both together make a mid-sequence divergence legible instead of a bare 2s
  timeout. (`eprintln!` in the guard is under `#[expect(clippy::print_stderr, …)]`,
  as `adversarial_imap.rs` does.)

### Connection budget vs `MAX_ACCEPTS`

The fake serves at most `MAX_ACCEPTS = 4` connections, replaying the full script
per accept. The read-only search path is expected to use **one** connection (a
transparent read-only reconnect on `ConnectionLost` would add at most one more —
still ≤ 2, comfortably under 4). If calibration reveals the pooled binary opens
more (e.g. a reconnect storm from a miscalibrated FETCH reply that drops the
stream mid-literal), the accept loop returns after the 4th accept and subsequent
requests hang to the 2s `REQUEST_TIMEOUT` rather than failing usefully — that
timeout signature (distinct from a clean `fetch_skipped` mismatch) is the tell
that the budget, not the arithmetic, is the problem. Raising `MAX_ACCEPTS` is the
remedy if a legitimate pooled sequence needs it; do not paper over a reconnect
storm by raising it.

## Testing

- **New wire test** (headline AC): `e2e_wire_fetch_skipped.rs` as above —
  the first assertion of `fetch_skipped` over the real binary + real socket +
  JSON-RPC wire.
- **Existing `rimap-imap` fake tests** (`adversarial_imap.rs`,
  `expunge_folder_wide_gap.rs`) must still pass unchanged in behavior after the
  import repoint — this proves the crate move is behavior-preserving (AC 1).
- **`certs` unit test** moves with the file and runs under
  `cargo test -p rimap-fake-imap`.
- **`just ci` green** (AC 3), including the schema-regen gate (no schema change
  here — no `*Meta`/`*Untrusted` struct changes — so the gate must show an empty
  diff).

## Residual risk

- **Fake ≠ Dovecot.** The fake is a scripted byte replayer, not a conformant
  server; it proves the binary *surfaces* `fetch_skipped` when a short page
  arrives, not that any particular real server produces one. That is the correct
  scope — a conformant server by definition never short-pages, so the signal can
  only be exercised against an adversarial fake.
- **Script drift.** If the `search` path's IMAP command sequence changes (e.g.
  `EXAMINE` → `SELECT`, or the fetch item set changes), the hand-scripted fake
  must be updated. This is inherent to any wire-level fake test and is why the
  calibration-via-`recorded()` workflow is documented above. The existing
  `rimap-imap` fake scenarios carry the same maintenance property.

## Out of scope / non-goals

- Any change to `fetch_skipped` semantics, `rimap-imap`, `ops::fetch`, the
  posture matrix, or any shipped code. Coverage only.
- Moving `tracing_capture` into the shared crate (not needed cross-crate).
- A conformant-server reproduction of a short page (impossible by definition).
- Asserting the *cause* of the shortfall (omitted vs malformed vs substituted);
  the tool surfaces one count and the test asserts that count, matching ADR-0007.

## Guardrails

`just ci` (rustfmt, clippy `--all-targets --all-features --locked -D warnings`,
check-macOS, test stable, test MSRV 1.88.0, cargo-deny, zizmor) plus the
schema-regen diff gate (expected empty). Branch:
`feat/wire-fetch-skipped-561`, base `main`.
