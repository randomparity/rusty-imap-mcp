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
  5. Assert `structuredContent.meta.fetch_skipped >= 1`,
     `meta.returned == 2`, and `meta.total_matched == 3` (server listed 3 UIDs,
     returned 2 usable messages).
- Gating: **no container runtime** — the fake binds a loopback socket in-process,
  so this test always runs on PR CI (unlike the Dovecot-gated `e2e_wire*` suite).
  It must not import the Dovecot harness.

### Fake-script exactness (calibration during TDD)

The byte-exact `UID FETCH` reply for UIDs 1 and 3 must carry enough for
`format_search_result` to build a `SearchResultEntry` (UID plus the envelope/flag
items the search fetch requests) so those two survive reassembly and only UID 2
is the shortfall. The precise item set is discovered during TDD the same way the
existing scenarios were: run the test, dump `server.recorded()` to read the exact
client `UID FETCH` command, and shape the reply to match. This spec does not pin
the byte-exact reply because the search fetch spec is the authority; the test's
assertions (`returned == 2`, `fetch_skipped >= 1`) are what is contractually
required. If shaping a fully-parseable line for 1 and 3 proves fiddly, the
fallback still satisfies the AC: the assertion `fetch_skipped >= 1` holds as long
as fewer than 3 usable messages come back, and `returned == 2` is the precise
form we aim for.

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
