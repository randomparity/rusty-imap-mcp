# Accept stringified integers in batch `uid`/`uids` params

Issue: #461 (epic #446, FABLE_RELEASE_AUDIT finding H-6, High). Builds on the
lenient-int coercion shipped for #292.

## Problem

`crate::UidSelector` (in `crates/rimap-core/src/uid_selector.rs`) backs the
`target` shape (`{"uid": N}` or `{"uids": [...]}`) on seven batch mutation
tools: `mark_read`, `mark_unread`, `flag`, `unflag`, `add_label`,
`remove_label`, `move_message`. It deserialized `uid` as a plain
`Option<NonZeroU32>` and each `uids` element as a plain `NonZeroU32`, with no
lenient path and a derived schema that published bare `integer` branches.

Every *other* numeric tool param — including the sibling `expected_uidvalidity`
on these same input structs — already routes through
`rimap-server::tools::lenient_int`, which accepts both the integer and the
digit-string wire forms and publishes `oneOf {integer|string}` schemas. Hosts
that stringify integer args (Claude Code, anthropics/claude-code#24599) can call
single-message reads but get a pre-dispatch schema rejection on every batch
mutation, with no hint the cause is string-vs-int.

## Decision: relocate `lenient_int` into `rimap-core`, reuse it in `UidSelector`

The lenient decode + schema helpers lived in `rimap-server::tools::lenient_int`,
but `UidSelector` lives in `rimap-core`, which `rimap-server` depends on — so the
helper could not be referenced from core without a dependency cycle. Options were
(a) duplicate the decode into core, or (b) relocate it to core.

**Chosen: (b) relocate.** Single source of truth, no duplication, no
deprecation shim. The module moves to `crates/rimap-core/src/lenient_int.rs`
(`pub mod`), and `rimap-server` re-exports it at its existing
`crate::tools::lenient_int` path via `pub(crate) use rimap_core::lenient_int;`.
The ~40 `deserialize_with`/`schema_with` string-path references across the
server crate's tool inputs therefore resolve unchanged — the relocation touches
no consumer source. `serde_json` moves from a dev-dependency to a normal
dependency of `rimap-core` (the schema builder uses `serde_json::json!`); it is
already a workspace dependency, so no new external crate is introduced.

## Shape

- `UidSelectorWire.uid`: `deserialize_with = "crate::lenient_int::deserialize_opt_nonzero_u32"`.
- `BoundedUids::deserialize`: decode `Vec<LenientNonZeroU32>` (a private newtype
  delegating to `crate::lenient_int::deserialize_nonzero_u32`), then apply the
  existing non-empty / max-100 bounds.
- Schema: `#[schemars(schema_with = ...)]` on the `Single::uid` field
  (`schema_nonzero_u32`) and on the `Batch::uids` field (`schema_bounded_uids`,
  an array of `schema_nonzero_u32` items with `minItems: 1`, `maxItems: 100`).
  The published input schema for each affected tool now shows `uid` and each
  `uids` element as `oneOf {integer|string}`, matching `expected_uidvalidity`.

The manual `UidSelector` `Deserialize` (which enforces "exactly one of uid or
uids") is unchanged apart from the wire field attributes; all existing
ambiguity/empty/bounds/zero errors are preserved.

## Tests

- `uid_selector.rs` unit tests: stringified single `uid`, stringified and
  mixed int/string `uids` batches, string-form zero and non-digit rejection,
  flatten-into-parent with stringified forms, and a schema-shape assertion that
  both `uid` and `uids` elements publish the digit-string branch.
- `lenient_int_dispatch.rs` integration tests: `FlagInput` accepts the
  stringified forms via `serde_json::from_value` (the MCP dispatch path),
  covering the acceptance criterion `mark_read {"folder":"INBOX","uid":"42"}`.

## Out of scope

The single-target read/destructive tools (`fetch_message`, `delete_message`,
etc.) already use `lenient_int` directly and are unaffected. The `rimap-tool-schemas`
fixtures are response/output schemas and do not capture the input-schema change,
so `regen-tool-schemas` produces no fixture diff.
