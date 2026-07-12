# Implementation plan — full-wire `search` `meta.fetch_skipped` e2e (#561)

**Spec:** `docs/superpowers/specs/2026-07-11-issue-561-wire-fetch-skipped-design.md`
**ADR:** `docs/ADR/0008-shared-fake-imap-test-support-crate.md`
**Issue:** [#561](https://github.com/randomparity/rusty-imap-mcp/issues/561)
**Branch:** `feat/wire-fetch-skipped-561` (base `main`)
**Nature:** test-only + test-support packaging. **No production code changes.**

## Guardrails (run for every task's verification)

- Fast inner loop: `just check`, `just test-fast`. Both are `--workspace
  --all-targets`, so they only pass on a green *whole* workspace — see the
  green-tree note below.
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

**Green-tree invariant.** Each of the three tasks below is a single commit that
leaves `cargo check --workspace --all-targets` green. The crate creation and the
`rimap-imap` import repoint are deliberately **one atomic task/commit** (Task 1):
moving the fake out without repointing the importers would leave `rimap-imap`'s
tests referencing deleted modules, so `just check`/`just test-fast` (both
`--workspace`) would fail on that intermediate. Do not split Task 1 across
commits.

---

## Task 1 — Create `crates/rimap-fake-imap` AND repoint `rimap-imap` tests (one atomic commit)

**Where it fits:** AC 1 — the fake reachable cross-crate *and* the existing
`rimap-imap` fake tests still green. Per ADR-0008, a `publish = false` workspace
crate holding the fake + its cert helper. Crate move and importer repoint land
together so the workspace never has a red intermediate.

### 1a. Create the crate

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
   `Cargo.toml`.

### 1b. Repoint `rimap-imap` tests (same commit)

6. `crates/rimap-imap/Cargo.toml` `[dev-dependencies]`: add
   `rimap-fake-imap = { path = "../rimap-fake-imap" }` (path-only — `publish =
   false` crate has no published version; `deny.toml` sets
   `allow-wildcard-paths = true`). Then check whether `rcgen`, `tokio-rustls`,
   `rustls` are still used directly by any remaining `rimap-imap` test
   (`rg -w "rcgen|tokio_rustls|rustls" crates/rimap-imap/tests`); drop from
   `rimap-imap`'s dev-deps only those that no longer appear (keep the manifest
   honest). `rustls`/`tokio-rustls` are also normal deps of `rimap-imap`, so
   only the `[dev-dependencies]` duplicates are in question.
7. `crates/rimap-imap/tests/support/mod.rs`: remove `pub mod certs;` and
   `pub mod fake_imap;`, leaving only `pub mod tracing_capture;`. Keep the
   file-level `#![allow(dead_code)]` and its comment (tracing_capture is still a
   per-binary include).
8. `crates/rimap-imap/tests/adversarial_imap.rs`: keep `mod support;` (still uses
   `support::tracing_capture::WarnCapture`); change
   `use support::fake_imap::{FakeImapServer, PanicResolver, Step, login_preamble};`
   to `use rimap_fake_imap::fake_imap::{FakeImapServer, PanicResolver, Step,
   login_preamble};`.
9. `crates/rimap-imap/tests/expunge_folder_wide_gap.rs`: uses **only** the fake,
   so remove its `mod support;` line and change
   `use support::fake_imap::{FakeImapServer, Step, login_preamble};` to
   `use rimap_fake_imap::fake_imap::{FakeImapServer, Step, login_preamble};`.
10. Confirm no other `rimap-imap` test references the moved modules
    (`rg "support::(fake_imap|certs)" crates/rimap-imap` → empty).

**Acceptance criteria (reviewer-checkable):**

- `cargo check --workspace --all-targets` green (no red intermediate).
- `cargo test -p rimap-fake-imap` passes the moved `certs` unit test
  (`pin_matches_leaf_der_and_is_fresh_each_call`).
- `cargo nextest run -p rimap-imap` passes `adversarial_imap::*` and
  `expunge_folder_wide_gap::*` unchanged in behavior.
- `cargo clippy -p rimap-fake-imap -p rimap-imap --all-targets --all-features --
  -D warnings` clean (no `#[allow]`, no unfulfilled `#[expect]`).
- The two moved files are byte-identical to the originals except the one
  `use crate::certs` line.
- `rg "support::(fake_imap|certs)" crates/rimap-imap` empty.

**Rollback:** `git revert` (or reset) the single commit — this undoes the move,
the import edit, the manifest edits, and the workspace-members line together. A
bare `git mv` back is **insufficient**: it would restore the files carrying the
edited `use crate::certs` path, which is wrong for the old location.

---

## Task 2 — Add the wire test in `rimap-server` (TDD)

**Where it fits:** the headline AC — a host-runnable JSON-RPC-wire assertion of
`meta.fetch_skipped` on a scripted short page.

**Prereq:** `crates/rimap-server/Cargo.toml` `[dev-dependencies]`: add
`rimap-fake-imap = { path = "../rimap-fake-imap" }` (path-only).

**TDD sequence (calibrate, don't guess):**

1. **Red / calibrate.** Write `crates/rimap-server/tests/e2e_wire_fetch_skipped.rs`
   with the harness plumbing and an *intentionally minimal* fake script
   (`login_preamble("IMAP4rev1")` only). Run it; it will fail/timeout. The
   primary calibration guide is the **expected** sequence the spec derives from
   `ops/search.rs`: EXAMINE → UID SEARCH → UID FETCH; extend the script one step
   at a time toward it. `recorded()` (via the drop guard below) shows the client
   commands the fake has **already matched** up to the current script length — it
   does **not** show the *next*, unmatched command, because `serve()` returns
   without reading past the last scripted `Step`. To capture that next command
   verbatim during Red calibration, temporarily append a catch-all
   `Step::Expect { verb: "ZZZ" }`: the `Expect` arm **records the client line
   before** asserting the verb, so the real command lands in `recorded()` and the
   drop guard prints it even though the bogus verb assertion then fails. Use this
   to discover whether `login_preamble`'s capability atoms need extending and the
   precise `UID FETCH` command (spec §"Fake-script sequence").
2. **Green.** Shape the `UID SEARCH` reply as `* SEARCH 1 2 3` and the `UID
   FETCH` reply to return **fully-parseable** lines for UIDs 1 and 3 and **no
   line for UID 2**, then assert the exact gate.

**Concrete FETCH reply template (starting point for the two surviving UIDs).**
The page fetch requests `FetchSpec { envelope: true, flags: true, size: true }`,
so each surviving line must carry `UID`, `FLAGS`, `RFC822.SIZE`, and a well-formed
RFC 3501 §7.4.2 `ENVELOPE`. Item order within the parens is irrelevant to the
parser. A minimal valid `ENVELOPE` uses explicit `NIL`s for the optional address
lists and a single-address `from`/`sender`/`reply-to`/`to`:
```text
* 1 FETCH (UID 1 FLAGS (\Seen) RFC822.SIZE 42 ENVELOPE ("Wed, 09 Jul 2026 12:00:00 +0000" "hello one" (("A" NIL "a" "example.com")) (("A" NIL "a" "example.com")) (("A" NIL "a" "example.com")) (("B" NIL "b" "example.com")) NIL NIL NIL "<msg1@example.com>"))\r\n
* 3 FETCH (UID 3 FLAGS (\Seen) RFC822.SIZE 42 ENVELOPE ("Wed, 09 Jul 2026 12:00:00 +0000" "hello three" (("A" NIL "a" "example.com")) (("A" NIL "a" "example.com")) (("A" NIL "a" "example.com")) (("B" NIL "b" "example.com")) NIL NIL NIL "<msg3@example.com>"))\r\n
```
(The `ENVELOPE` tuple is: date, subject, from, sender, reply-to, to, cc, bcc,
in-reply-to, message-id — here cc/bcc/in-reply-to are `NIL`.) The sequence
numbers (`* 1`, `* 3`) can be any distinct values; the load-bearing part is the
`UID` item. **No line for UID 2** — that omission is the shortfall. Send each
line via `Step::Send(b"…".to_vec())`, then `Step::Reply { text: "OK FETCH
completed" }`. Calibrate against the actual client command; if the parser rejects
a line (dropping it to `returned == 1`), fix the `ENVELOPE` form rather than
weakening the assertion (spec §"no weaker fallback").

**Test shape (concrete):**

- Config: a **single `readonly`-posture account** TOML pointing at
  `127.0.0.1:<fake.port()>`, `encryption = "tls"`,
  `tls_fingerprint_sha256 = <fake.pin().to_hex()>`,
  `[defaults.credentials] fallback = "keyring-then-env"`, plus `[audit]` and
  `[attachments]` sections under a tempdir. Model on the single-account block in
  `crates/rimap-server/tests/support/wire/config.rs::build_dovecot_full_config`
  (inline the TOML in the test or add a `build_fake_config` helper).
- Pull the wire harness the way the other `e2e_wire*` tests do
  (`#[path = "support/wire/mod.rs"] mod wire;` or via `support::wire`); spawn with
  `Harness::spawn_with_config(&config_path, tempdir, &[("RUSTY_IMAP_MCP_PASSWORD",
  "fake-password")])`. The fake accepts any password (`login_preamble` always
  replies `OK LOGIN completed`).
- Flow: `initialize_handshake()` → `send_initialized()` →
  `use_account("readonly")` → `readonly.search` with `{ "folder": "INBOX",
  "subject": "…" }`. **Omit `limit` and `offset`** (spec §"page_requested == 3 is
  not accidental" — default `limit = MAX_LIMIT = 100`, `offset = 0`, so
  `page_requested == 3`).
- Extract `body = resp["result"]["structuredContent"]`, validate the envelope
  against the MCP schema (`assert_valid` / `assert_envelope_valid`, as the other
  wire tests do), and assert:
  - `body["meta"]["total_matched"] == 3`
  - `body["meta"]["returned"] == 2`
  - `body["meta"]["fetch_skipped"] == 1`
- **Diagnosability drop guard (required).** Bind a guard before the search call
  that, on `Drop`, prints `server.recorded()` **iff** `std::thread::panicking()`
  — so it fires on the harness timeout-panic, the fake's in-task `assert!`
  (surfaced as a dropped connection / 2s timeout), and a wrong-`meta` `assert_eq!`
  alike (`Harness::request` *panics* on timeout, so an assertion-only guard would
  miss the two most-likely failures). Sketch:
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
  so the test runs on every PR under `just test`/CI. Do **not** import the
  Dovecot harness or gate on `RIMAP_REQUIRE_DOCKER`.
- Connection budget: expect **one** fake connection (`MAX_ACCEPTS = 4` headroom;
  a read-only reconnect adds ≤ 1). A reconnect storm exhausting the budget
  manifests as the 2s timeout (distinct from a clean `meta` mismatch) — fix the
  script, don't raise `MAX_ACCEPTS` to mask it.

**Test-runner note.** nextest's `binary(NAME)` predicate is a **glob/exact**
matcher (a bare name matches the whole binary name; `~` is the contains prefix),
**not** substring — confirmed by `justfile:233` listing `binary(e2e_wire)` and
`binary(e2e_wire_cancellation)` as *separate* terms, and by the other
`e2e_wire_*` binaries (destructive, fault_injection, …) not being listed at all
(they self-silent-skip without a container). So `binary(e2e_wire)` does **not**
match `e2e_wire_fetch_skipped`, and this test is **not** excluded from
`just test-fast`. That is the intended outcome: unlike the Dovecot-gated
`e2e_wire`, this test is container-free and fast (one binary spawn + loopback
TLS, like `mcp_wire_conformance`, which also runs in test-fast), so it runs in
`just test-fast`, full `just test`, and CI. **No justfile edit is needed.** Verify
directly with `cargo nextest run -p rimap-server -E
'binary(e2e_wire_fetch_skipped)'`.

**Acceptance criteria:**

- `cargo nextest run -p rimap-server -E 'binary(e2e_wire_fetch_skipped)'`
  passes with the three exact equalities, **with no container runtime present**
  (it must not silent-skip).
- The test fails loudly (drop guard prints the recorded dialog) if miscalibrated.
- If two fully-parseable `ENVELOPE` lines prove infeasible so `returned` lands at
  1, **stop and escalate** — do not relax to `fetch_skipped >= 1` (spec §"no
  weaker fallback").
- `cargo clippy -p rimap-server --all-targets --all-features -- -D warnings`
  clean.

**Rollback:** delete the test file + the `rimap-server` dev-dep line.

---

## Task 3 — Full guardrail sweep + schema-regen gate

**Where it fits:** AC 3 — `just ci` stays green.

**Steps:**

1. `just regen-tool-schemas` → confirm an **empty** diff under
   `crates/rimap-server/tests/fixtures/rimap-tool-schemas/` (no `*Meta`/
   `*Untrusted` struct changed, so nothing should regenerate).
2. `just ci` green end to end. Watch specifically:
   - `cargo-deny` (`just deny`): the new `publish = false` crate must not trip
     advisories / bans / sources / license (it adds no external dep).
   - MSRV (`just test-msrv`, 1.88.0): the crate + tests must build on MSRV.
   - clippy `--all-features`: the fake crate compiles under the full workspace
     lint set with no bare `#[allow]`.
3. Verify no `crates/rimap-server/fuzz/Cargo.lock` churn (`git status`) — this
   change does not alter the parser stack, so no fuzz-lockfile realignment.

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
