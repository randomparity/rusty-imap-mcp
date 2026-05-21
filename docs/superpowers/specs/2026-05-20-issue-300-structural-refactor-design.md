# Structural Refactor: Split Monolithic Modules (#300)

**Date:** 2026-05-20
**Issue:** [#300](https://github.com/randomparity/rusty-imap-mcp/issues/300)
**Discovered by:** desloppify holistic review (commits 9b18515, e35a388, 125c02b on `desloppify/code-health`).
**Status:** Design approved; implementation pending.

## Problem

Six files concentrate enough orchestration to soften the workspace's
"small focused module" pattern. None of them are correctness bugs —
the reviewer scored the affected dimensions 88–91 and noted the code
is "correct but cognitively heavy". The cost is review-time and
LLM-context-window friction, not runtime.

Workspace LOC snapshot (worktree base, 2026-05-20):

| File | LOC |
|------|-----|
| `crates/rimap-imap/src/connection.rs` | 1863 |
| `crates/rimap-server/src/mcp/wire_validator.rs` | 1564 |
| `crates/rimap-audit/src/writer/mod.rs` | 1003 |
| `crates/rimap-content/src/parse/mod.rs` | 998 |
| `crates/rimap-config/src/validate/mod.rs` | 970 |
| `crates/rimap-content/src/html/mod.rs` | 914 |

All sibling submodules referenced in the issue still exist; the
suggested target layouts remain feasible without any cross-crate
plumbing changes.

## Scope

Items 1, 2, and 3 from #300 land in a single PR, one commit per item,
in the order **1 → 3 → 2**.

**Item 4 (rimap-mcp library extraction) is deferred** to a fresh
follow-up issue. The first /challenge review of this spec surfaced
four hard blockers that #300 did not anticipate:

- `audit_envelope.rs` defines methods on `ImapMcpServer` (which stays
  in `rimap-server`), creating a circular workspace dep.
- `tool_catalog.rs` tests import 14+ tool Input types from
  `crate::tools::*` (which stays in `rimap-server`).
- `fuzz_oracle.rs` explicitly documents its design intent to *not*
  widen `ValidationOutcome`'s `pub(crate)` — moving `wire_validator`
  to a sibling crate would force that widening.
- `tool_name.rs` consumes `crate::boot::registry::AccountState`.

#300 itself flagged item 4 as low-confidence and suggested deferring
until "the MCP surface stabilizes (likely post-1.0)". The blockers
above confirm the deferral is the right call. A new issue tracks item
4 with the pre-conditions named explicitly.

Each landed item is a pure code move: no behavior change, no public
API change, no test semantics change. Tests stay with the code they
exercise — when a function moves to a peer file, its tests move with
it. Shared test fixtures get a dedicated `test_support` sub-module
(see Item 1 below).

Each commit must build and pass `just test-fast` independently. The
PR is a refactor; `git bisect` across the merged commits is part of
the deliverable, so no commit may leave the workspace in a broken
intermediate state.

## Decision

### Item 1 — Split `crates/rimap-imap/src/connection.rs`

Target layout (refined from #300 after the /challenge findings):

```
crates/rimap-imap/src/connection/
├── mod.rs            # Connection struct, ConnectionConfig, ImapEncryption re-export,
│                     #   ImapSession alias, Debug impl, enrich_tls_handshake_error,
│                     #   error_code_for. Connection's lifecycle methods:
│                     #     new(), host(), username(), session(), invalidate(),
│                     #     connect_inner(), has_move_capability(),
│                     #     has_uidplus_capability(), has_list_status_capability().
│                     #   Plus `pub use` re-exports of child-module items the
│                     #   crate boundary needs.
├── handshake.rs      # connect_with_bundle, capability_advertised,
│                     #   starttls_negotiate, drain_for_starttls,
│                     #   drain_for_logindisabled, map_tls_handshake_error,
│                     #   tls_handshake, starttls_upgrade
├── login.rs          # imap_login, emit_auth
├── dispatch.rs       # with_session helper + per-command wrappers ONLY:
│                     #   list_folders, list_folders_with_status, status,
│                     #   select, search, fetch, fetch_body, store_flags,
│                     #   move_messages, append_message, delete_message,
│                     #   expunge, create_folder, rename_folder, delete_folder
└── test_support.rs   # #[cfg(test)] only. AuthSink + CredentialResolver stubs,
                      #   mock_server fixture, connection_for() helper,
                      #   bundle_with_observed() helper. pub(super) visibility.
```

**Naming refinement vs. #300:** the issue suggests `connection/auth.rs`,
but `crates/rimap-imap/src/auth.rs` already exists as the
`AuthContext` / `AuthEvent` builder module. Rename the new file to
`connection/login.rs` — it carries the IMAP LOGIN/CAPABILITY auth-flow
code, which matches the function name (`imap_login`).

**Placement refinement vs. #300:** `session()`, `invalidate()`, and
`connect_inner()` are core lifecycle on `Connection` (called from
`with_session` *and* directly by `session()` → `connect_inner()` →
`connect_with_bundle`). They stay in `mod.rs` alongside the other
`Connection` accessors. `dispatch.rs` is `with_session` + command
wrappers only.

**Tests:** the in-file test module at `connection.rs:1143+` covers
`error_code_for` and `enrich_tls_handshake_error` (stay in `mod.rs`),
`emit_auth` (moves to `login.rs`), `map_tls_handshake_error` and the
STARTTLS negotiation path (move to `handshake.rs`). Shared test
fixtures (`AuthSink` stub, `CredentialResolver` stub, `mock_server`,
`connection_for`, `bundle_with_observed`) consolidate into
`test_support.rs` with `pub(super)` visibility so any sibling test
module can re-import them.

### Item 3 — Extract orchestration bodies from four `mod.rs` hubs

| File | LOC | Existing siblings | New peer |
|------|-----|--------------------|----------|
| `crates/rimap-audit/src/writer/mod.rs` | 1003 | `emit`, `log`, `provenance`, `rotation`, `self_check` | `writer/core.rs` (AuditWriter impl + AuditOptions + failure injection hooks) |
| `crates/rimap-content/src/parse/mod.rs` | 998 | `attachments`, `bodies`, `filename`, `headers`, `meta`, `mime_scrub`, `safe_parser`, `sniff` | `parse/pipeline.rs` (parse_message + the 6 limit constants) |
| `crates/rimap-config/src/validate/mod.rs` | 970 | `identity`, `limits`, `paths`, `rules` | `validate/compose.rs` (multi-account composition pipeline) |
| `crates/rimap-content/src/html/mod.rs` | 914 | `extract`, `hidden`, `mismatch`, `sanitize`, `style_parse` | `html/pipeline.rs` (`sanitize` orchestrator + HtmlResult) |

Each `mod.rs` keeps its child-module declarations, `pub use`
re-exports, and crate-level doc comment. The orchestrator body, its
private helpers, and its tests move to the new peer file. Public
import paths are preserved by re-exporting the peer's items from
`mod.rs`.

**Intra-directory re-exports:** existing siblings inside the same
directory (e.g. `parse/attachments.rs`, `html/sanitize.rs`) today
import the orchestrator's helpers and constants via `super::*`. For
each extracted peer, `mod.rs` must `pub use <peer>::*` (or list the
specific items) so every `super::*` use site continues to resolve.
After each extraction, run `cargo check -p <crate>` to surface any
missed names before commit.

**Size target:** each refactored `mod.rs` lands under **200 LOC**.
That is the natural ceiling for "wiring + crate-level docs +
re-exports + at most one or two enum/struct definitions that the
whole sub-module surface needs". If `mod.rs` exceeds 200 LOC after
the move, a sibling extraction was missed.

### Item 2 — Split `crates/rimap-server/src/mcp/wire_validator.rs`

Target layout (refined from #300):

```
crates/rimap-server/src/mcp/wire_validator/
├── mod.rs            # ValidatedStdio struct, stdio_with_validation factory,
│                     #   ValidatorSupervisor struct definition, ErrorEnvelope,
│                     #   ValidationOutcome, pub(crate) re-exports of submodule
│                     #   items needed by callers (preinit, fuzz_oracle).
├── envelope.rs       # is_forwardable_id, is_valid_params, is_well_formed_error,
│                     #   extract_id, parse_error, invalid_request,
│                     #   has_duplicate_keys_in_rmcp_strict_positions, validate,
│                     #   synthesize_error_line, OneLevelDupCheck /
│                     #   DupCheckOneLevel / TopAndErrorDupCheck visitors
├── supervisor.rs     # impl ValidatorSupervisor (watch_for_error, drain,
│                     #   shutdown_after_failure, take_or_await, flatten)
├── inbound.rs        # validate_inbound + frame-parser plumbing
└── outbound.rs       # passthrough_outbound + write/flush glue
```

**Refinement vs. #300:** the issue lists three child files
(`supervisor`, `inbound`, `outbound`). The duplicate-key visitor types
and the `validate()` / `synthesize_error_line` envelope helpers are
~370 LOC that are neither supervisor nor I/O — they belong with the
schema validation logic. Split them into a fourth child, `envelope.rs`,
so `inbound.rs` can stay focused on the async I/O loop.

`fuzz_oracle.rs` currently imports `super::wire_validator::{ValidationOutcome,
synthesize_error_line, validate}`. After the split it imports
`super::wire_validator::{ValidationOutcome, synthesize_error_line,
validate}` unchanged — `mod.rs` re-exports these three from their
submodules so the consumer's path is preserved.

`main.rs::run()` carries a comment about lifecycle ordering forcing it
to stay monolithic. The split touches only what lives behind the
`pub fn stdio_with_validation()` factory; `run()` continues to call
the same factory. A separate cleanup pass on `run()` is out of scope.

### Item 4 — Deferred to follow-up issue

Out of scope for this PR. The /challenge review showed item 4 cannot
land as drawn in #300; the new issue will document the four blockers
and the pre-conditions (MCP wire shape stable / post-1.0) that must
be met before any rimap-mcp extraction is worth attempting.

## Follow-up flags (not load-bearing on this refactor)

The async-locking concerns called out by #300 span files in three
locations, only one of which this refactor touches:

- `wire_validator::passthrough_outbound` and
  `wire_validator::validate_inbound` (Item 2 makes them individually
  reviewable by isolating them in their own files).
- `connection::session` (Item 1 territory, lives in `rimap-imap`).
- `main::emit_pre_init_error_envelope` (lives in
  `rimap-server/src/main.rs`, untouched by this PR).

Addressing the locking semantics is follow-up work. The refactor
only makes them easier to reason about by splitting them off the
hot-path file.

## Out of scope

- Behavior change of any kind. If a test would have passed before
  the refactor and fails after, the refactor is wrong, not the test.
- Documentation rewrites beyond moving in-file `//!` headers to the
  new file owners.
- `main.rs::run()` cleanup.
- The async-locking fixes referenced in #300.
- Item 4 (rimap-mcp extraction) — separate issue.
- Renaming or restructuring public types, functions, or trait impls.

## Validation

After each item lands as a commit:

1. `just fmt-check` — formatting clean.
2. `just lint` — clippy clean at `-D warnings`.
3. `just test-fast` — unit tests green.
4. **Content-equivalence smell-check (heuristic):** for each split
   commit, diff a stripped form of the pre- and post-refactor files.
   The recipe filters items that *legitimately* differ between
   mono-file and multi-file layouts (comments, `use` / `mod`
   declarations, attributes) so the remainder is signal:

   ```bash
   strip() { rg -v '^\s*(//|//!|use |mod |pub use |#\[|\}|\{)' "$@" \
                | rg -v '^\s*$' | sort -u; }
   OLD=$(git rev-parse HEAD~1)
   diff <(git show $OLD:crates/rimap-imap/src/connection.rs | strip /dev/stdin) \
        <(strip crates/rimap-imap/src/connection/{mod,handshake,login,dispatch,test_support}.rs)
   ```

   This is heuristic, not proof: multi-line attribute splits and
   `impl` boundary noise still leak through, so a small diff is
   expected and gets eyeballed. A *large* diff means a function
   body was edited, not moved — re-investigate before commit. The
   `HEAD~1` anchor keeps the comparison per-commit; running the
   recipe between item 1 and item 3 commits, for example, compares
   item 3's pre/post only. Copy the actual recipe and its output
   summary into the commit body as the audit trail.

After all items land:

5. `just ci` — full local-CI equivalent green.

## References

- GitHub issue #300 (source of truth for items 1–3 target layouts;
  item 4 deferred to a new issue).
- `crates/rimap-audit/src/writer/` and `crates/rimap-content/src/parse/`
  for the workspace's established `mod.rs` + focused-siblings pattern.
- `crates/rimap-server/src/tools/mod.rs` (16 lines) and
  `crates/rimap-server/src/boot/mod.rs` (6 lines) as examples of pure
  wiring `mod.rs` hubs.
- /challenge review (this session, 2026-05-20) — round 1 surfaced
  the item 4 blockers and the item 1 placement of `session()` /
  `invalidate()`; round 2 surfaced the validation-recipe ambiguity,
  the intra-dir re-export requirement, and the async-locking
  bucket-misclassification.
