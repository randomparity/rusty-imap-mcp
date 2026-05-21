# Issue #300 Structural Refactor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Split six oversized modules into focused peers so the workspace's "small focused module" pattern is restored without changing any behavior.

**Architecture:** Pure code moves only. For each oversized file, identify the orchestrator function (or group of related functions) and move it into a new sibling file inside the existing directory module, leaving `mod.rs` as a wiring + re-export hub. Tests follow the code they exercise. Each commit must compile and pass `just test-fast` independently — bisectability across the merged PR is part of the deliverable.

**Tech Stack:** Rust 1.94.0 (dev), 1.88.0 (MSRV), edition 2024, `cargo` / `just` / `prek`.

**Source of truth:** `docs/superpowers/specs/2026-05-20-issue-300-structural-refactor-design.md`.

**Commit order:** spec (already landed) → Item 1 (connection.rs) → Item 3a (writer) → Item 3b (parse) → Item 3c (validate) → Item 3d (html) → Item 2 (wire_validator).

---

## Conventions used in every task

- **Validation recipe** (the spec's "Content-equivalence smell-check") —
  each task's content-check step inlines this so it works in a fresh
  shell:
  ```bash
  strip() { rg -v '^\s*(//|//!|use |mod |pub use |#\[|\}|\{)' "$@" \
              | rg -v '^\s*$' | sort -u; }
  ```
  Always capture the pre-refactor SHA in step N.1 (`PRE_SHA=$(git rev-parse HEAD)`)
  and pass it into the diff command literally. Do not rely on `HEAD~0`
  because intermediate commits in the same task break it. A small diff
  is expected (impl-block boundaries leak through); a *large* diff means
  a function body changed and needs investigation.

- **Per-task quality gate:**
  ```bash
  just fmt-check && just lint && just test-fast
  ```
  These three must pass before the commit. **On failure:** fix the
  error in place (compiler errors are usually missing `use` statements
  the cut-and-paste lost). To start the task over from scratch:
  ```bash
  git restore --staged crates/<crate>/src/
  git checkout -- crates/<crate>/src/
  # delete any untracked new files manually
  ```

- **Commit message template:**
  ```
  refactor(<crate>): <what was split>

  Moves <list of items> from <old-path> to <new-paths> per #300 item N.
  No behavior change. Content-equivalence check (recipe in
  docs/superpowers/specs/2026-05-20-issue-300-structural-refactor-design.md):
  <one-line summary, e.g. "clean diff modulo impl-boundary noise">.

  Refs #300

  Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
  ```

---

## Task 1: Split `crates/rimap-imap/src/connection.rs`

**Files:**
- Delete: `crates/rimap-imap/src/connection.rs`
- Create: `crates/rimap-imap/src/connection/mod.rs`
- Create: `crates/rimap-imap/src/connection/handshake.rs`
- Create: `crates/rimap-imap/src/connection/login.rs`
- Create: `crates/rimap-imap/src/connection/dispatch.rs`
- Create: `crates/rimap-imap/src/connection/test_support.rs`
- (No change to `crates/rimap-imap/src/lib.rs` — it already says `pub mod connection;`.)

**Item placement** (from spec § Item 1):

| Item (connection.rs line) | Destination |
|---|---|
| `pub use rimap_core::ImapEncryption;` (43) | `mod.rs` |
| `pub struct ConnectionConfig` (53) | `mod.rs` |
| `pub(crate) type ImapSession = ...` (83) | `mod.rs` |
| `pub struct Connection` (87) | `mod.rs` |
| `impl Debug for Connection` (118) | `mod.rs` |
| `pub(crate) fn enrich_tls_handshake_error` (134) | `mod.rs` |
| `Connection::new`, `host`, `username` (159-191) | `mod.rs` |
| `Connection::session` (192-201) | `mod.rs` |
| `Connection::has_move_capability` / `has_uidplus_capability` / `has_list_status_capability` (203-223) | `mod.rs` |
| `Connection::invalidate` (226) | `mod.rs` |
| `Connection::connect_inner` (236) | `mod.rs` |
| `Connection::connect_with_bundle` (300) | `handshake.rs` |
| `Connection::imap_login` (388) | `login.rs` |
| `Connection::emit_auth` (541) | `login.rs` |
| `Connection::with_session` (572) | `dispatch.rs` |
| All command wrappers (602-987): `list_folders`, `list_folders_with_status`, `status`, `select`, `search`, `fetch`, `fetch_body`, `store_flags`, `move_messages`, `append_message`, `delete_message`, `expunge`, `create_folder`, `rename_folder`, `delete_folder` | `dispatch.rs` |
| Free fn `capability_advertised` (989) | `handshake.rs` |
| Free fn `drain_for_logindisabled` (1008) | `handshake.rs` |
| Free fn `starttls_negotiate` (1017) | `handshake.rs` |
| Free fn `drain_for_starttls` (1088) | `handshake.rs` |
| `pub(crate) tls_handshake` (1094) | `handshake.rs` |
| `pub(crate) starttls_upgrade` (1110) | `handshake.rs` |
| Free fn `map_tls_handshake_error` (1122) | `handshake.rs` |
| Free fn `error_code_for` (1131) | `mod.rs` |

**Test placement** (from spec § Item 1, "Tests"):

| Test (line) | Destination |
|---|---|
| `error_code_for_covers_every_variant` (1149) | `mod.rs::tests` |
| `map_tls_handshake_error_wraps_io_error` (1226) | `handshake.rs::tests` |
| `enrich_tls_handshake_mismatch_rewrites_to_typed_tls_error` (1244) | `mod.rs::tests` |
| `enrich_tls_handshake_matching_pin_passes_through_unchanged` (1269) | `mod.rs::tests` |
| `enrich_tls_handshake_no_pin_passes_through_unchanged` (1287) | `mod.rs::tests` |
| `enrich_tls_handshake_non_handshake_error_passes_through` (1302) | `mod.rs::tests` |
| `emit_auth_completes_despite_caller_cancellation` (1325) and its inline AuthSink/CredentialResolver stubs (1348-1367) | `login.rs::tests` (stubs hoisted to `test_support`) |
| `mock_server` fixture (~1472-1493) | `test_support.rs` |
| `connection_for` helper, `bundle_with_observed` helper, `fp_zeros` helper, `AuthSink`/`CredentialResolver` stubs (1144-1569 grab-bag) | `test_support.rs` |
| `connect_with_starttls_*` (1587-1629), `negotiate_*` (1630-1755), `negotiate_returns_bare_tcpstream_...` (1756), `mock_server_round_trips_a_line` (1793) | `handshake.rs::tests` |
| `debug_format_includes_connection_fields` (1820) | `mod.rs::tests` |

- [ ] **Step 1.1: Capture the pre-refactor SHA**

  ```bash
  cd /home/dave/src/rusty-imap-mcp/.claude/worktrees/issue-300-structural-refactor
  PRE_SHA=$(git rev-parse HEAD)
  echo "Task 1 PRE_SHA = $PRE_SHA"   # write this down for step 1.9
  ```

- [ ] **Step 1.2: Move `connection.rs` to `connection/mod.rs`**

  ```bash
  mkdir -p crates/rimap-imap/src/connection
  git mv crates/rimap-imap/src/connection.rs crates/rimap-imap/src/connection/mod.rs
  ```

  Running `cargo check -p rimap-imap` now should still pass (file path changed but Rust treats `connection.rs` and `connection/mod.rs` equivalently).

- [ ] **Step 1.3: Create `connection/handshake.rs` with the handshake-related items**

  Cut these from `connection/mod.rs` and paste into `connection/handshake.rs`:
  - The free functions `capability_advertised`, `drain_for_logindisabled`, `starttls_negotiate`, `drain_for_starttls`, `map_tls_handshake_error` (mod.rs lines 989-1142 minus `error_code_for`).
  - The two `pub(crate)` async functions `tls_handshake` and `starttls_upgrade`.
  - The `Connection::connect_with_bundle` method (lines 300-388).

  `Connection` is defined in `mod.rs` (the parent of `handshake.rs`).
  In `handshake.rs`, write a fresh `impl Connection { ... }` block
  containing the method — same-crate impl blocks may live in sibling
  files. The top of `handshake.rs` needs:

  ```rust
  use super::{Connection, ConnectionConfig, ImapSession};
  use crate::error::ImapError;
  // ... plus whatever else the cut code referenced
  // (the compiler tells you what's missing; add use lines until it stops complaining)
  ```

  Then:

  ```rust
  impl Connection {
      pub(super) async fn connect_with_bundle(
          &self,
          // ... existing signature
      ) -> Result<ImapSession, ImapError> {
          // ... existing body
      }
  }
  ```

  Visibility note: the method's visibility on the original was
  whatever `connection.rs` had (probably `async fn` with no modifier,
  i.e. private to the file). Inside the new `handshake.rs` it needs
  to be `pub(super)` so `mod.rs`'s `Connection::session()` (which
  calls `connect_inner` which calls `connect_with_bundle`) can reach
  it. Apply the same pattern to `imap_login` / `emit_auth` (Task 1.4)
  and `with_session` + command wrappers (Task 1.5).

  Add to top of `connection/mod.rs`: `mod handshake;`.

- [ ] **Step 1.4: Create `connection/login.rs` with `imap_login` and `emit_auth`**

  Same pattern as 1.3: write a fresh `impl Connection { ... }` block inside `login.rs` containing the two methods. Cut from `mod.rs`. Add `mod login;` to `mod.rs`.

- [ ] **Step 1.5: Create `connection/dispatch.rs` with `with_session` and the 15 command wrappers**

  Same pattern. The methods are: `with_session`, `list_folders`, `list_folders_with_status`, `status`, `select`, `search`, `fetch`, `fetch_body`, `store_flags`, `move_messages`, `append_message`, `delete_message`, `expunge`, `create_folder`, `rename_folder`, `delete_folder`. Add `mod dispatch;` to `mod.rs`.

- [ ] **Step 1.6: Create `connection/test_support.rs` with shared test fixtures**

  ```rust
  //! Shared test scaffolding for connection's submodules.
  //!
  //! `#[cfg(test)] only — compiled out of release builds. Re-exported
  //! to siblings via `pub(super)`.

  #![cfg(test)]
  #![allow(dead_code)]

  // ... move here: AuthSink stub, CredentialResolver stub, mock_server
  // fixture, connection_for(), bundle_with_observed(), fp_zeros() helpers
  ```

  Add to `mod.rs`: `#[cfg(test)] mod test_support;`.

- [ ] **Step 1.7: Place the tests in their destination files per the table above**

  Each destination file gets its own `#[cfg(test)] mod tests { ... }` block. Tests that need the shared fixtures `use super::test_support::*` (or specific items).

- [ ] **Step 1.8: Quality gate**

  ```bash
  cd /home/dave/src/rusty-imap-mcp/.claude/worktrees/issue-300-structural-refactor
  cargo check -p rimap-imap --all-targets --all-features --locked
  just fmt-check
  just lint
  just test-fast
  ```
  Expected: all four pass. If `cargo check` complains about missing imports, add the relevant `use` statements (compiler errors are explicit).

- [ ] **Step 1.9: Content-equivalence smell-check**

  Use `PRE_SHA` from step 1.1 (paste the literal SHA if you've lost
  the variable):

  ```bash
  strip() { rg -v '^\s*(//|//!|use |mod |pub use |#\[|\}|\{)' "$@" \
              | rg -v '^\s*$' | sort -u; }
  diff <(git show $PRE_SHA:crates/rimap-imap/src/connection.rs | strip /dev/stdin) \
       <(strip crates/rimap-imap/src/connection/{mod,handshake,login,dispatch,test_support}.rs)
  ```
  Expected: short diff (impl-block boundary noise + a few `pub(super)`
  visibility tweaks). A long diff means a function body changed — go
  back and find it.

- [ ] **Step 1.10: Commit**

  ```bash
  git add crates/rimap-imap/src/connection*
  git commit -m "$(cat <<'EOF'
  refactor(rimap-imap): split connection.rs into handshake/login/dispatch

  Splits the 1863-LOC connection.rs into a connection/ directory
  module: mod.rs (Connection lifecycle), handshake.rs (TCP/TLS/
  STARTTLS), login.rs (imap_login + emit_auth), dispatch.rs
  (with_session + command wrappers), test_support.rs (shared test
  fixtures). No behavior change.

  Refs #300 (item 1)

  Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
  EOF
  )"
  ```

---

## Task 2: Extract `writer/core.rs` from `crates/rimap-audit/src/writer/mod.rs`

**Files:**
- Modify: `crates/rimap-audit/src/writer/mod.rs` (shrink to wiring + re-exports)
- Create: `crates/rimap-audit/src/writer/core.rs`

**Item placement:**

`mod.rs` keeps: the `//!` crate-level doc, the `mod emit;`/`mod log;`/`mod provenance;`/`mod rotation;`/`mod self_check;` declarations, the new `mod core;`, the `pub use log::{...}` re-export, and any `pub use core::*;` (or named re-export) needed to keep the existing public surface intact.

`core.rs` receives: `AuditOptions` struct, `AuditWriter` struct, `pub(crate) Inner` struct, the `impl AuditWriter` block (lines 97-244), the platform-gated `set_file_mode_0600` / `set_parent_mode_0700` functions and their cfg-stubs, and the `#[cfg(test)] mod tests` block (line 278+).

- [ ] **Step 2.1: Capture pre-refactor SHA**

  ```bash
  PRE_SHA=$(git rev-parse HEAD)
  echo "Task 2 PRE_SHA = $PRE_SHA"
  ```

- [ ] **Step 2.2: Create `writer/core.rs`**

  Cut from `mod.rs` (line range ≈ 14-end, minus the `mod`/`pub use` declarations near the top): `use` statements, the struct definitions, the `impl AuditWriter` block, the platform helpers, and the test module.

  At the top of `core.rs`, add only the `use` lines that `core.rs` actually needs (the compiler will tell you).

- [ ] **Step 2.3: Trim `mod.rs` to wiring**

  After cutting, `mod.rs` should contain only:
  - the crate-level `//!` doc.
  - `mod emit; mod log; mod provenance; mod rotation; mod self_check; mod core;`
  - `pub use log::{ProcessStartInputs, ToolEndInputs, ToolStartInputs};`
  - `pub use core::{AuditOptions, AuditWriter};` (named so the public surface is unchanged).
  - Any other `pub use` the existing call sites rely on. Verify by `cargo check -p rimap-audit --all-targets`.

- [ ] **Step 2.4: Restore any intra-dir `super::*` references**

  If any sibling (`emit.rs`, `log.rs`, etc.) referenced items now in `core.rs` via `super::*`, the `pub use core::*` (or specific names) in `mod.rs` re-exports them automatically. Run `cargo check -p rimap-audit --all-targets` to confirm — fix any missing names by adding them to the `pub use` in `mod.rs`.

- [ ] **Step 2.5: Quality gate**

  ```bash
  cargo check -p rimap-audit --all-targets --all-features --locked
  just fmt-check
  just lint
  just test-fast
  ```

- [ ] **Step 2.6: Size check**

  ```bash
  wc -l crates/rimap-audit/src/writer/mod.rs
  ```
  Expected: well under the pre-refactor 1003 LOC, ideally <200. If
  still >300, an extraction was missed. If 200-300, document in the
  commit body which items legitimately stayed (long crate-level docs,
  wide re-export surface, a struct definition the whole sub-module
  consumes) and move on.

- [ ] **Step 2.7: Content-equivalence smell-check**

  ```bash
  strip() { rg -v '^\s*(//|//!|use |mod |pub use |#\[|\}|\{)' "$@" \
              | rg -v '^\s*$' | sort -u; }
  diff <(git show $PRE_SHA:crates/rimap-audit/src/writer/mod.rs | strip /dev/stdin) \
       <(strip crates/rimap-audit/src/writer/{mod,core}.rs)
  ```

- [ ] **Step 2.8: Commit**

  ```
  refactor(rimap-audit): extract writer/core.rs from writer/mod.rs

  Moves AuditOptions, AuditWriter, Inner, impl AuditWriter,
  set_file_mode_0600, set_parent_mode_0700, and the tests module
  from writer/mod.rs to a new writer/core.rs sibling. mod.rs keeps
  the child-module declarations and re-exports the public surface.
  No behavior change.

  Refs #300 (item 3, hub 1/4)
  ```

---

## Task 3: Extract `parse/pipeline.rs` from `crates/rimap-content/src/parse/mod.rs`

**Files:**
- Modify: `crates/rimap-content/src/parse/mod.rs`
- Create: `crates/rimap-content/src/parse/pipeline.rs`

**Item placement:**

`mod.rs` keeps the crate-level `//!` doc, `mod attachments; ... mod sniff; mod pipeline;`, `pub use pipeline::*;` (or named re-exports), and any other `pub use` the existing crate surface needs.

`pipeline.rs` receives: the six `pub const MAX_*` constants (lines 30-49), the `MAX_HEADER_COUNT` constant (52), the `parse_message` function (line 64+), and the `#[cfg(test)] mod tests` block (line 113+).

- [ ] **Step 3.1: Capture pre-refactor SHA.**

  ```bash
  PRE_SHA=$(git rev-parse HEAD)
  echo "Task 3 PRE_SHA = $PRE_SHA"
  ```

- [ ] **Step 3.2: Create `parse/pipeline.rs`** with the constants, `parse_message`, and the tests module. Move the `use` lines that `parse_message` and its tests need.

- [ ] **Step 3.3: Trim `parse/mod.rs`** to crate-level docs + `mod` declarations + `pub use pipeline::*` (or named).

- [ ] **Step 3.4: Restore intra-dir paths.** Siblings like `attachments.rs` may say `use super::MAX_*` or `use super::parse_message`. The `pub use pipeline::*` re-export keeps the `super::*` path resolvable. Run `cargo check -p rimap-content --all-targets` to confirm.

- [ ] **Step 3.5: Quality gate.**

  ```bash
  cargo check -p rimap-content --all-targets --all-features --locked
  just fmt-check && just lint && just test-fast
  ```

- [ ] **Step 3.6: Size check.** `wc -l crates/rimap-content/src/parse/mod.rs` — expect well under 998 LOC, ideally <200. If 200-300, document the legitimate items that stayed in the commit body.

- [ ] **Step 3.7: Content-equivalence smell-check.**

  ```bash
  strip() { rg -v '^\s*(//|//!|use |mod |pub use |#\[|\}|\{)' "$@" \
              | rg -v '^\s*$' | sort -u; }
  diff <(git show $PRE_SHA:crates/rimap-content/src/parse/mod.rs | strip /dev/stdin) \
       <(strip crates/rimap-content/src/parse/{mod,pipeline}.rs)
  ```

- [ ] **Step 3.8: Commit.**

  ```
  refactor(rimap-content): extract parse/pipeline.rs from parse/mod.rs

  Moves parse_message + the six MAX_* size-limit constants from
  parse/mod.rs to a new parse/pipeline.rs sibling. mod.rs keeps the
  child-module declarations and re-exports the public surface via
  `pub use pipeline::*`. No behavior change.

  Refs #300 (item 3, hub 2/4)
  ```

---

## Task 4: Extract `validate/compose.rs` from `crates/rimap-config/src/validate/mod.rs`

**Files:**
- Modify: `crates/rimap-config/src/validate/mod.rs`
- Create: `crates/rimap-config/src/validate/compose.rs`

**Item placement:**

`mod.rs` keeps the `//!` doc, `mod identity; mod limits; mod paths; mod rules; mod compose;`, the two `pub struct`s `ValidatedAccountConfig` (line 37) and `ValidatedMultiConfig` (line 58) (or moves them too — see note), and `pub use compose::*` (or named).

`compose.rs` receives: the four composition functions `validate_multi` (71), `validate_multi_allowing_empty` (88), `validate_multi_inner` (98), `validate_legacy_as_multi` (142), the private helper `validate_account` (178), and the `mod tests` (214). The `ValidateAccountInputs` struct used by `validate_account` moves with it.

**Note on struct placement:** if any sibling references `super::ValidatedAccountConfig`, leave the struct in `mod.rs` (it's a return type for `compose.rs` items anyway — circular but normal since both files are siblings). The `compose.rs` body uses `super::{ValidatedAccountConfig, ValidatedMultiConfig}`. Decide by running `rg "super::Validated" crates/rimap-config/src/validate/` — if siblings reference them, keep in `mod.rs`; otherwise move to `compose.rs`.

- [ ] **Step 4.1: Capture pre-refactor SHA.**

  ```bash
  PRE_SHA=$(git rev-parse HEAD)
  echo "Task 4 PRE_SHA = $PRE_SHA"
  ```

- [ ] **Step 4.2: Inspect sibling deps.**

  ```bash
  rg "super::Validated|super::validate_multi|super::validate_account" crates/rimap-config/src/validate/
  ```
  Decide struct placement based on output.

- [ ] **Step 4.3: Create `validate/compose.rs`** per the placement decision from 4.2.

- [ ] **Step 4.4: Trim `validate/mod.rs`** to wiring + (optionally) the two `Validated*Config` structs.

- [ ] **Step 4.5: Restore intra-dir paths.** `pub use compose::*` in `mod.rs`. `cargo check -p rimap-config --all-targets`.

- [ ] **Step 4.6: Quality gate.**

  ```bash
  cargo check -p rimap-config --all-targets --all-features --locked
  just fmt-check && just lint && just test-fast
  ```

- [ ] **Step 4.7: Size check.** `wc -l crates/rimap-config/src/validate/mod.rs` — expect well under 970 LOC, ideally <200. If 200-300 because the `Validated*Config` structs stayed, document that in the commit body.

- [ ] **Step 4.8: Content-equivalence smell-check.**

  ```bash
  strip() { rg -v '^\s*(//|//!|use |mod |pub use |#\[|\}|\{)' "$@" \
              | rg -v '^\s*$' | sort -u; }
  diff <(git show $PRE_SHA:crates/rimap-config/src/validate/mod.rs | strip /dev/stdin) \
       <(strip crates/rimap-config/src/validate/{mod,compose}.rs)
  ```

- [ ] **Step 4.9: Commit.**

  ```
  refactor(rimap-config): extract validate/compose.rs from validate/mod.rs

  Moves validate_multi, validate_multi_allowing_empty,
  validate_multi_inner, validate_legacy_as_multi, validate_account,
  and the tests module from validate/mod.rs to a new
  validate/compose.rs sibling. No behavior change.

  Refs #300 (item 3, hub 3/4)
  ```

---

## Task 5: Extract `html/pipeline.rs` from `crates/rimap-content/src/html/mod.rs`

**Files:**
- Modify: `crates/rimap-content/src/html/mod.rs`
- Create: `crates/rimap-content/src/html/pipeline.rs`

**Item placement:**

`mod.rs` keeps the `//!` doc, `mod extract; mod hidden; mod mismatch; mod sanitize; mod style_parse; mod pipeline;`, and `pub use pipeline::*` (or named).

`pipeline.rs` receives: `pub struct HtmlResult` (line 38), `HiddenMethod` and its `impl` (98+), the `pub fn sanitize` (131), the `mod tests` (197).

- [ ] **Step 5.1: Capture pre-refactor SHA.**

  ```bash
  PRE_SHA=$(git rev-parse HEAD)
  echo "Task 5 PRE_SHA = $PRE_SHA"
  ```

- [ ] **Step 5.2: Inspect sibling deps.**

  ```bash
  rg "super::HtmlResult|super::sanitize|super::HiddenMethod" crates/rimap-content/src/html/
  ```

- [ ] **Step 5.3: Create `html/pipeline.rs`** with the above items.

- [ ] **Step 5.4: Trim `html/mod.rs`** to wiring + re-exports.

- [ ] **Step 5.5: Restore intra-dir paths.** `pub use pipeline::*` in `mod.rs`. `cargo check -p rimap-content --all-targets`.

- [ ] **Step 5.6: Quality gate.**

  ```bash
  cargo check -p rimap-content --all-targets --all-features --locked
  just fmt-check && just lint && just test-fast
  ```

- [ ] **Step 5.7: Size check.** `wc -l crates/rimap-content/src/html/mod.rs` — expect well under 914 LOC, ideally <200. If 200-300, document the legitimate items that stayed in the commit body.

- [ ] **Step 5.8: Content-equivalence smell-check.**

  ```bash
  strip() { rg -v '^\s*(//|//!|use |mod |pub use |#\[|\}|\{)' "$@" \
              | rg -v '^\s*$' | sort -u; }
  diff <(git show $PRE_SHA:crates/rimap-content/src/html/mod.rs | strip /dev/stdin) \
       <(strip crates/rimap-content/src/html/{mod,pipeline}.rs)
  ```

- [ ] **Step 5.9: Commit.**

  ```
  refactor(rimap-content): extract html/pipeline.rs from html/mod.rs

  Moves HtmlResult, HiddenMethod + impl, sanitize, and the tests
  module from html/mod.rs to a new html/pipeline.rs sibling. No
  behavior change.

  Refs #300 (item 3, hub 4/4)
  ```

---

## Task 6: Split `crates/rimap-server/src/mcp/wire_validator.rs`

**Files:**
- Delete: `crates/rimap-server/src/mcp/wire_validator.rs`
- Create: `crates/rimap-server/src/mcp/wire_validator/mod.rs`
- Create: `crates/rimap-server/src/mcp/wire_validator/envelope.rs`
- Create: `crates/rimap-server/src/mcp/wire_validator/supervisor.rs`
- Create: `crates/rimap-server/src/mcp/wire_validator/inbound.rs`
- Create: `crates/rimap-server/src/mcp/wire_validator/outbound.rs`

**Item placement** (from spec § Item 2):

| Item (wire_validator.rs line) | Destination |
|---|---|
| `pub(crate) enum ValidationOutcome` (28) | `mod.rs` |
| `pub(crate) struct ErrorEnvelope` (39) | `mod.rs` |
| `pub struct ValidatedStdio` (50) | `mod.rs` |
| `pub struct ValidatorSupervisor` (71) | `mod.rs` |
| `pub fn stdio_with_validation` (732) | `mod.rs` |
| `pub(crate) fn is_forwardable_id` (87) | `envelope.rs` |
| `pub(crate) fn is_valid_params` (108) | `envelope.rs` |
| `pub(crate) fn is_well_formed_error` (116) | `envelope.rs` |
| `pub(crate) fn extract_id` (144) | `envelope.rs` |
| `pub(crate) fn parse_error` (151) | `envelope.rs` |
| `pub(crate) fn invalid_request` (159) | `envelope.rs` |
| `struct OneLevelDupCheck` (171) and impls | `envelope.rs` |
| `struct DupCheckOneLevel` (246) and impls | `envelope.rs` |
| `struct TopAndErrorDupCheck` (261) and impls | `envelope.rs` |
| `fn has_duplicate_keys_in_rmcp_strict_positions` (372) | `envelope.rs` |
| `pub(crate) fn validate` (379) | `envelope.rs` |
| `pub(crate) fn synthesize_error_line` (451) | `envelope.rs` |
| `pub(crate) async fn validate_inbound` (498) | `inbound.rs` |
| `pub(crate) async fn passthrough_outbound` (587) | `outbound.rs` |
| `impl ValidatorSupervisor` (607-730) | `supervisor.rs` |
| `#[cfg(test)] mod tests` (764+) — partition by what each test exercises | each file gets the tests for items it owns |

**Re-export contract:** `fuzz_oracle.rs` imports `super::wire_validator::{ValidationOutcome, synthesize_error_line, validate}`. `mod.rs` must re-export `synthesize_error_line` and `validate` from `envelope.rs` at the same `pub(crate)` visibility so the consumer path is unchanged:

```rust
// in wire_validator/mod.rs
mod envelope;
mod supervisor;
mod inbound;
mod outbound;

pub(crate) use envelope::{
    extract_id, invalid_request, is_forwardable_id, is_valid_params,
    is_well_formed_error, parse_error, synthesize_error_line, validate,
};
pub(crate) use inbound::validate_inbound;
pub(crate) use outbound::passthrough_outbound;
```

- [ ] **Step 6.1: Capture pre-refactor SHA.**

  ```bash
  PRE_SHA=$(git rev-parse HEAD)
  echo "Task 6 PRE_SHA = $PRE_SHA"
  ```

- [ ] **Step 6.2: Move file into directory.**

  ```bash
  mkdir -p crates/rimap-server/src/mcp/wire_validator
  git mv crates/rimap-server/src/mcp/wire_validator.rs \
         crates/rimap-server/src/mcp/wire_validator/mod.rs
  ```
  `cargo check -p rimap-server` should still pass.

- [ ] **Step 6.3: Create `envelope.rs`** with the per-table items. Add the `use` statements it needs. Add `mod envelope;` and the `pub(crate) use envelope::{...}` re-export to `mod.rs`.

- [ ] **Step 6.4: Create `inbound.rs`** with `validate_inbound`. Add `mod inbound;` and `pub(crate) use inbound::validate_inbound;` to `mod.rs`.

- [ ] **Step 6.5: Create `outbound.rs`** with `passthrough_outbound`. Add `mod outbound;` and `pub(crate) use outbound::passthrough_outbound;` to `mod.rs`.

- [ ] **Step 6.6: Create `supervisor.rs`** with the `impl ValidatorSupervisor` block.

  Because `ValidatorSupervisor` lives in `mod.rs`, the `impl` block in `supervisor.rs` just writes `impl super::ValidatorSupervisor { ... }` — same crate, same module tree, no visibility widening.

- [ ] **Step 6.7: Partition the `mod tests` block.** Each test goes to the file whose function it exercises. Tests that exercise multiple things (e.g. integration-style) stay with the highest-level item or in `mod.rs::tests`.

- [ ] **Step 6.8: Verify `fuzz_oracle.rs` still compiles.**

  ```bash
  cargo check -p rimap-server --features fuzzing
  ```
  The import `super::wire_validator::{ValidationOutcome, synthesize_error_line, validate}` should resolve unchanged.

- [ ] **Step 6.9: Quality gate.**

  ```bash
  cargo check -p rimap-server --all-targets --all-features --locked
  just fmt-check && just lint && just test-fast
  ```

- [ ] **Step 6.10: Content-equivalence smell-check.**

  ```bash
  strip() { rg -v '^\s*(//|//!|use |mod |pub use |#\[|\}|\{)' "$@" \
              | rg -v '^\s*$' | sort -u; }
  diff <(git show $PRE_SHA:crates/rimap-server/src/mcp/wire_validator.rs | strip /dev/stdin) \
       <(strip crates/rimap-server/src/mcp/wire_validator/{mod,envelope,supervisor,inbound,outbound}.rs)
  ```

- [ ] **Step 6.11: Commit.**

  ```
  refactor(rimap-server): split wire_validator.rs into envelope/supervisor/inbound/outbound

  Splits the 1564-LOC wire_validator.rs into a wire_validator/
  directory module: mod.rs (ValidatedStdio + stdio_with_validation
  factory + ValidatorSupervisor type), envelope.rs (frame validation
  + dup-key visitors + synthesize_error_line), supervisor.rs (impl
  ValidatorSupervisor watch/drain/shutdown), inbound.rs
  (validate_inbound), outbound.rs (passthrough_outbound). pub(crate)
  re-exports preserve fuzz_oracle's import paths unchanged. No
  behavior change.

  Refs #300 (item 2)

  Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
  ```

---

## Task 7: Final integration check

- [ ] **Step 7.1: Run the full local-CI equivalent.**

  ```bash
  just ci
  ```
  All seven status checks must pass: rustfmt, clippy, check, test (stable), test (MSRV), cargo-deny, zizmor.

- [ ] **Step 7.2: Verify bisectability (non-destructive).**

  ```bash
  git log --oneline worktree-issue-300-structural-refactor ^main
  ```
  Should show 7 commits (spec + 6 refactors). Spot-check by running
  `cargo check` against a middle commit in a temporary worktree —
  this never touches the main working tree, never stashes, and can't
  lose work:

  ```bash
  MID=$(git rev-parse HEAD~3)
  git worktree add /tmp/bisect-300 "$MID"
  (cd /tmp/bisect-300 && cargo check -p rimap-imap --all-targets --locked)
  git worktree remove /tmp/bisect-300
  ```

  Skip the spot-check entirely if every per-task quality gate passed
  green — the gates already prove bisectability per commit.

- [ ] **Step 7.3: Hand off to /simplify and PR cycle.** No further commits in this plan — the workflow continues with /simplify and the push/PR/merge cycle.

---

## Self-Review checklist (post-write)

- [x] Every spec section maps to a task (Item 1 → Task 1; Item 3 → Tasks 2-5; Item 2 → Task 6; final-CI/bisect → Task 7).
- [x] No "TBD", "TODO", or "similar to" placeholders.
- [x] Validation recipe is consistent across tasks (same `strip` function, same `OLD` capture pattern).
- [x] Each task has its own quality gate + content-equivalence + size check (where applicable) + commit step.
- [x] Per-commit bisectability requirement met: each task ends with a fully-green build.
