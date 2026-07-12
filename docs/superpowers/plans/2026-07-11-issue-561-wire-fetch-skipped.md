# Implementation plan — full-wire `search` `meta.fetch_skipped` e2e (#561)

**Spec:** `docs/superpowers/specs/2026-07-11-issue-561-wire-fetch-skipped-design.md`
**ADR:** `docs/ADR/0008-shared-fake-imap-test-support-crate.md`
**Issue:** [#561](https://github.com/randomparity/rusty-imap-mcp/issues/561)
**Branch:** `feat/wire-fetch-skipped-561` (base `main`)
**Nature:** test-only + test-support packaging. **No production code changes.**

## Guardrails (run for every task's verification)

- Fast inner loop: `just check`, `just test-fast`.
- Per-crate test: `cargo nextest run -p <crate>` (or `cargo test -p <crate>` if
  a test isn't nextest-visible).
- Full gate before push: `just ci` (rustfmt, clippy
  `--all-targets --all-features --locked -D warnings`, check-macOS, test stable,
  test MSRV 1.88.0, cargo-deny, zizmor). Schema-regen gate must show an **empty**
  diff (no `*Meta`/`*Untrusted` change here).
- Commit convention: conventional-commit prefix, imperative ≤72-char subject,
  `Co-Authored-By` trailer. Stage explicit paths; never `git add -A`. `.rs`
  commits trigger a full clippy recompile in prek — use a generous commit
  timeout.

Tasks are ordered; each is independently committable and leaves the tree green.

---

## Task 1 — Create `crates/rimap-fake-imap` and move the fake into it

**Where it fits:** Foundation for AC 1 (the fake reachable cross-crate). Per
ADR-0008, a `publish = false` workspace crate holding the fake + its cert helper.

**Steps:**

1. Create `crates/rimap-fake-imap/Cargo.toml`:
   ```toml
   [package]
   name = "rimap-fake-imap"
   version.workspace = true
   edition.workspace = true
   rust-version.workspace = true
   license.workspace = true
   repository.workspace = true
   authors.workspace = true
   publish = false
   description = "In-process scriptable adversarial IMAP fake for rusty-imap-mcp tests"

   [lints]
   workspace = true

   [dependencies]
   rimap-core = { path = "../rimap-core", version = "0.1.1-dev" }
   rimap-imap = { path = "../rimap-imap", version = "0.1.1-dev" }
   secrecy = { workspace = true }
   tokio = { workspace = true }
   tokio-rustls = { workspace = true }
   rustls = { workspace = true }
   rcgen = { workspace = true }
   ```
   (`rcgen`, `tokio-rustls`, `rustls` are already workspace deps used by the fake
   today; no new external dependency enters the graph.)
2. `git mv crates/rimap-imap/tests/support/fake_imap.rs
   crates/rimap-fake-imap/src/fake_imap.rs` and
   `git mv crates/rimap-imap/tests/support/certs.rs
   crates/rimap-fake-imap/src/certs.rs` (preserve history).
3. Create `crates/rimap-fake-imap/src/lib.rs`:
   ```rust
   //! In-process scriptable adversarial IMAP fake shared by rimap-imap and
   //! rimap-server integration tests. See ADR-0008.
   pub mod certs;
   pub mod fake_imap;
   ```
   Do **not** add `#![deny(missing_docs)]` (test-support crate) and do **not**
   carry over the old `support/mod.rs` `#![allow(dead_code)]` — `pub` items in a
   lib are never dead-code-warned.
4. In `fake_imap.rs`, change `use crate::support::certs::{self, SelfSigned};` to
   `use crate::certs::{self, SelfSigned};`. Keep the module-inner
   `#![expect(clippy::unwrap_used, reason = "tests")]` (still fulfilled under
   workspace lints). Keep `certs.rs`'s `#![expect(...)]` and its `#[cfg(test)] mod
   tests`.
5. Add `"crates/rimap-fake-imap"` to `[workspace] members` in the root
   `Cargo.toml` (place it after `crates/rimap-server` or alphabetically near the
   other crates; ordering is cosmetic).

**Acceptance criteria (reviewer-checkable):**

- `cargo build -p rimap-fake-imap` compiles clean.
- `cargo test -p rimap-fake-imap` runs and passes the moved `certs` unit test
  (`pin_matches_leaf_der_and_is_fresh_each_call`).
- `cargo clippy -p rimap-fake-imap --all-targets -- -D warnings` clean (no
  `#[allow]`, no unfulfilled `#[expect]`).
- The two source files are byte-identical to the originals except the one
  `use crate::certs` line.

**Note — dev-dep cycle:** at this point `rimap-imap`'s tests won't compile
(the deleted `support::fake_imap`); that is repaired in Task 2. Verify Task 1 in
isolation with `-p rimap-fake-imap`, which does not build `rimap-imap`'s tests.

**Rollback:** delete the crate dir + the workspace-members line; `git mv` the two
files back.

---

## Task 2 — Repoint `rimap-imap` fake-based tests to the new crate

**Where it fits:** AC 1 — existing fake-based tests still pass through the new
path. Proves the move is behavior-preserving.

**Steps:**

1. `crates/rimap-imap/Cargo.toml` `[dev-dependencies]`: add
   `rimap-fake-imap = { path = "../rimap-fake-imap" }` (path-only — `publish =
   false` crate has no published version; `deny.toml` sets
   `allow-wildcard-paths = true`). Leave `rcgen`, `tokio-rustls`, `rustls` in
   `rimap-imap`'s dev-deps only if other `rimap-imap` tests still use them
   directly; if the fake was their sole consumer, remove the now-unused ones (run
   `just check` / clippy to confirm none are orphaned or newly-unused —
   `unused_crate_dependencies` is not on by default, so verify by grepping the
   remaining `tests/` for `rcgen`/`tokio_rustls`/`rustls` direct use, and drop
   any that no longer appear to keep the manifest honest).
2. `crates/rimap-imap/tests/support/mod.rs`: remove `pub mod certs;` and
   `pub mod fake_imap;`, leaving only `pub mod tracing_capture;`. Keep the
   file-level `#![allow(dead_code)]` and its explanatory comment (tracing_capture
   is still a per-binary include).
3. `crates/rimap-imap/tests/adversarial_imap.rs`: keep `mod support;` (still uses
   `support::tracing_capture::WarnCapture`); change
   `use support::fake_imap::{FakeImapServer, PanicResolver, Step, login_preamble};`
   to `use rimap_fake_imap::fake_imap::{FakeImapServer, PanicResolver, Step,
   login_preamble};`.
4. `crates/rimap-imap/tests/expunge_folder_wide_gap.rs`: it uses **only** the
   fake (no `tracing_capture`), so remove its `mod support;` line and change
   `use support::fake_imap::{FakeImapServer, Step, login_preamble};` to
   `use rimap_fake_imap::fake_imap::{FakeImapServer, Step, login_preamble};`.
5. Confirm no other `rimap-imap` test references `support::fake_imap` /
   `support::certs` (`rg "support::(fake_imap|certs)" crates/rimap-imap/tests`).

**Acceptance criteria:**

- `cargo nextest run -p rimap-imap` passes, including
  `adversarial_imap::*` and `expunge_folder_wide_gap::*`, with **no behavior
  change** (same assertions, same pass).
- `cargo clippy -p rimap-imap --all-targets --all-features -- -D warnings` clean.
- `rg "support::(fake_imap|certs)" crates/rimap-imap` returns nothing.

**Rollback:** revert the Cargo.toml + test import edits; restore
`support/mod.rs`.

---

## Task 3 — Add the wire test in `rimap-server` (TDD)

**Where it fits:** the headline AC — a host-runnable JSON-RPC-wire assertion of
`meta.fetch_skipped` on a scripted short page.

**Prereq:** `crates/rimap-server/Cargo.toml` `[dev-dependencies]`: add
`rimap-fake-imap = { path = "../rimap-fake-imap" }` (path-only).

**TDD sequence (calibrate, don't guess):**

1. **Red / calibrate.** Write `crates/rimap-server/tests/e2e_wire_fetch_skipped.rs`
   with the harness plumbing and an *intentionally minimal* fake script
   (`login_preamble("IMAP4rev1")` only). Run it; it will fail/timeout. Use the
   `recorded()` drop-guard (below) to read the exact client command sequence the
   binary emits for a `search` call, then extend the script step-by-step
   (EXAMINE → UID SEARCH → UID FETCH) until the dialog matches. This is how the
   exact bytes — including whether `login_preamble`'s capability atoms need
   extending and the precise `UID FETCH` item order — are discovered. See spec
   §"Fake-script sequence: expected, confirmed by calibration".
2. **Green.** Shape the `UID SEARCH` reply as `* SEARCH 1 2 3` and the `UID
   FETCH` reply to return **fully-parseable** lines for UIDs 1 and 3
   (each carrying `UID`, a well-formed RFC 3501 `ENVELOPE`, `FLAGS`, and
   `RFC822.SIZE` — the `FetchSpec { envelope, flags, size }` the page fetch
   requests) and **no line for UID 2**. Assert the exact gate.

**Test shape (concrete):**

- Config: a **single `readonly`-posture account** TOML pointing at
  `127.0.0.1:<fake.port()>`, `encryption = "tls"`,
  `tls_fingerprint_sha256 = <fake.pin().to_hex()>`,
  `[defaults.credentials] fallback = "keyring-then-env"`, plus `[audit]` and
  `[attachments]` sections under a tempdir. Model on the single-account block in
  `crates/rimap-server/tests/support/wire/config.rs::build_dovecot_full_config`
  (inline the TOML in the test or add a `build_fake_config` helper).
- Pull the wire harness in the same way the other `e2e_wire*` tests do
  (`#[path = "support/wire/mod.rs"] mod wire;` or via `support::wire`); spawn with
  `Harness::spawn_with_config(&config_path, tempdir, &[("RUSTY_IMAP_MCP_PASSWORD",
  "fake-password")])`. The fake accepts any password (`login_preamble` always
  replies `OK LOGIN completed`).
- Flow: `initialize_handshake()` → `send_initialized()` →
  `use_account("readonly")` → `readonly.search` with `{ "folder": "INBOX", "<a
  key that maps to UID SEARCH, e.g. subject>": "…" }`. **Omit `limit` and
  `offset`** (spec §"page_requested == 3 is not accidental" — default
  `limit = MAX_LIMIT = 100`, `offset = 0`, so `page_requested == 3`).
- Extract `body = resp["result"]["structuredContent"]` and assert, via a helper
  that also validates the envelope against the MCP schema (`assert_valid` /
  `assert_envelope_valid`, as the other wire tests do):
  - `body["meta"]["total_matched"] == 3`
  - `body["meta"]["returned"] == 2`
  - `body["meta"]["fetch_skipped"] == 1`
- **Diagnosability drop guard (required).** Add a guard bound before the search
  call that, on `Drop`, prints `server.recorded()` **iff**
  `std::thread::panicking()` — so it fires on the harness timeout-panic, the
  fake's in-task `assert!` (surfaced as a dropped connection / 2s timeout), and a
  wrong-`meta` `assert_eq!` alike. `eprintln!` under
  `#[expect(clippy::print_stderr, reason = "test diagnostic")]`. Sketch:
  ```rust
  struct DumpOnPanic<'a>(&'a FakeImapServer);
  impl Drop for DumpOnPanic<'_> {
      fn drop(&mut self) {
          if std::thread::panicking() {
              #[expect(clippy::print_stderr, reason = "test diagnostic")]
              { eprintln!("fake recorded dialog: {:#?}", self.0.recorded()); }
          }
      }
  }
  ```
- Gating: **no container runtime**. The fake binds a loopback socket in-process,
  so the test runs on every PR. Do **not** import the Dovecot harness or gate on
  `RIMAP_REQUIRE_DOCKER`.
- Connection budget: expect **one** fake connection (spec §"Connection budget vs
  MAX_ACCEPTS"; `MAX_ACCEPTS = 4` gives headroom). If calibration reveals a
  reconnect storm exhausting the budget (manifests as the 2s timeout, distinct
  from a clean `meta` mismatch), fix the script — do not paper over it by raising
  `MAX_ACCEPTS`.

**Acceptance criteria:**

- `cargo nextest run -p rimap-server -E 'binary(e2e_wire_fetch_skipped)'`
  passes with the three exact equalities, **with no container runtime present**
  (the whole point — it must not silent-skip).
- The test fails loudly (not hangs opaquely) if the script is miscalibrated: on
  any panic the drop guard prints the recorded dialog.
- If two fully-parseable `ENVELOPE` lines prove infeasible so `returned` lands at
  1 (not 2), **stop and escalate** — do not relax the assertion to
  `fetch_skipped >= 1` (spec §"no weaker fallback").
- `cargo clippy -p rimap-server --all-targets --all-features -- -D warnings`
  clean.

**Rollback:** delete the test file + the `rimap-server` dev-dep line.

---

## Task 4 — Full guardrail sweep + schema-regen gate

**Where it fits:** AC 3 — `just ci` stays green.

**Steps:**

1. `just regen-tool-schemas` → confirm an **empty** diff under
   `crates/rimap-server/tests/fixtures/rimap-tool-schemas/` (no `*Meta`/
   `*Untrusted` struct changed, so nothing should regenerate).
2. `just ci` green end to end. Watch specifically:
   - `cargo-deny`: the new `publish = false` crate must not trip advisories /
     bans / sources / license (it adds no external dep; run `just deny`).
   - MSRV (`just test-msrv`, 1.88.0): the crate + tests must build on MSRV.
   - clippy `--all-features`: the fake crate compiles under the full workspace
     lint set with no bare `#[allow]`.
3. Verify the fuzz subcrate's `Cargo.lock` parity is untouched (this change does
   not alter the parser stack, so no realignment needed — confirm `git status`
   shows no `crates/rimap-server/fuzz/Cargo.lock` churn).

**Acceptance criteria:**

- `just ci` exits 0.
- `git status` clean after `just regen-tool-schemas` (empty schema diff).

**Rollback:** n/a (verification only).

---

## Definition of done

- AC 1: `rg "support::(fake_imap|certs)"` empty; `rimap-imap` fake tests green
  through `rimap_fake_imap::fake_imap`.
- AC 2: `e2e_wire_fetch_skipped` asserts `fetch_skipped == 1` (with
  `returned == 2`, `total_matched == 3`) over the JSON-RPC wire, container-free.
- AC 3: `just ci` green; schema diff empty.
- Spec/ADR committed; PR links #561 and notes it closes the #535 AC-interpretation
  follow-up.
