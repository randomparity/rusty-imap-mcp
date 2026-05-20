# Lenient Integer Coercion for Tool Inputs (#292)

**Date:** 2026-05-18
**Issue:** [#292](https://github.com/randomparity/rusty-imap-mcp/issues/292)
**Discovered by:** Live use — Claude Code sent `{"limit":"100"}` to `search`; the host's AJV validator rejected with `params/limit must be integer,null`.
**Status:** Design approved; implementation pending.

## Problem

Claude Code (and likely other MCP hosts that pre-validate tool arguments
against the cached `inputSchema`) serializes integer-typed parameters as
JSON strings non-deterministically — the same model in the same session
may emit `100` on one call and `"100"` on the next. Because every host
that validates client-side rejects the call before it reaches our
process, server-side coercion alone cannot fix this; the published
schema itself has to accept both shapes.

See [anthropics/claude-code#24599](https://github.com/anthropics/claude-code/issues/24599)
for the upstream client bug and
[modelcontextprotocol/typescript-sdk#1361](https://github.com/modelcontextprotocol/typescript-sdk/issues/1361)
for the pending SDK-level fix.

## Root cause

`schemars` 1.2 emits `{"type": ["integer","null"], "format":"uint", "minimum":0}`
for every `Option<usize>` / `Option<u32>` input field. AJV (used inside
the host) correctly rejects `"100"` against that schema. There is no
hook in our pipeline that runs before validation.

## Decision

Adopt the approach FastMCP, github/github-mcp-server, and the MCP
sequential-thinking reference server have already shipped: declare the
input schema as a union of integer-form and string-form, then coerce the
string to its numeric type during deserialization. Apply only to integer
input fields. Booleans and strings remain strict.

## Design

### One helper module: `crates/rimap-server/src/tools/lenient_int.rs`

The module exports one deserializer / schema pair per integer type used
in tool inputs. The pattern matches the existing
`offset_date_time_tuple_schema` in `fetch_message.rs:174` so reviewers
already know the shape.

```rust
// Module structure (illustrative — Task 2 writes the real code):
pub fn deserialize_opt_usize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<usize>, D::Error>;
pub fn deserialize_opt_u32<'de, D>(d: D) -> Result<Option<u32>, D::Error>;
pub fn deserialize_nonzero_u32<'de, D>(d: D) -> Result<NonZeroU32, D::Error>;
pub fn deserialize_opt_nonzero_u32<'de, D>(d: D) -> Result<Option<NonZeroU32>, D::Error>;
pub fn deserialize_usize<'de, D>(d: D) -> Result<usize, D::Error>;
pub fn deserialize_u32<'de, D>(d: D) -> Result<u32, D::Error>;

pub fn schema_opt_usize(g: &mut schemars::SchemaGenerator) -> schemars::Schema;
pub fn schema_opt_u32(g: &mut schemars::SchemaGenerator) -> schemars::Schema;
pub fn schema_nonzero_u32(g: &mut schemars::SchemaGenerator) -> schemars::Schema;
pub fn schema_opt_nonzero_u32(g: &mut schemars::SchemaGenerator) -> schemars::Schema;
// etc.
```

Application sites use a doubled attribute:

```rust
#[serde(default, deserialize_with = "lenient_int::deserialize_opt_usize")]
#[schemars(schema_with = "lenient_int::schema_opt_usize")]
pub limit: Option<usize>,
```

The field type stays `Option<usize>` — handler code is unchanged.

### Schema shape

For `Option<usize>` (unsigned, nullable):

```json
{
  "oneOf": [
    { "type": "integer", "minimum": 0 },
    { "type": "string", "pattern": "^[0-9]+$" },
    { "type": "null" }
  ]
}
```

For `NonZeroU32` (unsigned, non-null, non-zero):

```json
{
  "oneOf": [
    { "type": "integer", "minimum": 1 },
    { "type": "string", "pattern": "^[1-9][0-9]*$" }
  ]
}
```

`oneOf` is preferred over `type: ["integer","string","null"]` with
top-level `minimum`/`pattern` because every keyword in each branch is
type-scoped — no chance of a permissive validator skipping the
constraint that applies to the other branch.

### Deserialization

Internal helper:

```rust
enum IntOrStr<T> { Int(T), Str(String) }
```

with a custom `Deserialize` impl that accepts either a JSON integer or a
JSON string and dispatches:

- integer → return as-is
- string → require non-empty, match the pattern, parse via `T::from_str`,
  propagate parse errors with `D::Error::invalid_value`

Per-type wrappers convert `IntOrStr<T>` to the final type, including the
zero-rejection branch for `NonZeroU32`.

### Scope (initial PR)

In-scope integer input fields (audit performed 2026-05-18):

`CreateDraftInput` and `SendEmailInput` are type aliases for `ComposeInput`
(`create_draft.rs:11`, `send_email.rs:11`), so the single annotation on
`ComposeInput::in_reply_to_uid` widens the published schema for both the
`create_draft` and `send_email` tools.

| File | Field | Type |
|---|---|---|
| `tools/retrieval/search.rs` | `limit`, `offset` | `Option<usize>` |
| `tools/retrieval/fetch_message.rs` | `max_body_bytes` | `Option<usize>` |
| `tools/retrieval/fetch_message.rs` | `uid` | `NonZeroU32` |
| `tools/retrieval/download_attachment.rs` | `uid` | `NonZeroU32` |
| `tools/retrieval/list_attachments.rs` | `uid` | `NonZeroU32` |
| `tools/mailbox/delete_message.rs` | `uid` | `NonZeroU32` |
| `tools/mailbox/flags.rs` | `expected_uidvalidity` | `Option<u32>` |
| `tools/mailbox/labels.rs` | `expected_uidvalidity` (×2), `uid` | `Option<u32>`, `NonZeroU32` |
| `tools/mailbox/move_message.rs` | `expected_source_uidvalidity` | `Option<u32>` |
| `tools/compose/message_builder.rs` | `in_reply_to_uid` | `Option<NonZeroU32>` |

The audit step in the plan re-runs the search so any field added after
this design doc is captured.

### Out of scope (deferred to follow-up issues)

1. **Booleans.** `z.coerce.boolean("false") === true` is a footgun
   ([modelcontextprotocol/servers#3533 review thread](https://github.com/modelcontextprotocol/servers/pull/3533)).
   Boolean coercion requires the `preprocess`-style explicit mapping,
   and we have not seen booleans rejected in the wild. Defer.

2. **String fields.** FastMCP
   [#1873](https://github.com/modelcontextprotocol/python-sdk/issues/1873)
   documents data loss when string-typed inputs (UUIDs, phone numbers)
   were coerced. Strings stay strict — annotation is authoritative.

3. **`UidSelector` / `BoundedUids` (batch UIDs).** Used by `flag`,
   `mark_read`, `mark_unread`, `unflag`, `add_label`, `remove_label`,
   `move_message`. These live in `rimap-core` and use a manual
   `Deserialize` impl. Making the array elements coerce requires
   modifying `rimap-core`. File as a follow-up issue once the
   `lenient_int` helper has settled.

4. **Output schemas (`*Meta`, `*Untrusted`).** The server controls its
   own output types; coercion never applies to outputs.

### Why one helper module instead of a newtype

A `LenientInt<T>` newtype would force every field to be
`Option<LenientInt<usize>>` and every handler to use `.0` accessors. That
ripples through ~10 call sites with no benefit over a `deserialize_with`
attribute pair. The existing `offset_date_time_tuple_schema` precedent
keeps the field type natural and confines the per-type code to one
module.

## Testing strategy

1. **Unit tests in `lenient_int.rs`** for each helper: accept int form,
   accept string form, reject non-numeric string, reject overflow,
   reject zero for `NonZeroU32`, accept null for `Option<*>`.
2. **Schema dump test** (`tests/dump_tool_catalog.rs` already verifies
   `inputSchema.type == "object"` at the root). Add an assertion that
   each affected field's schema contains a `oneOf` with an integer and
   string branch.
3. **End-to-end dispatch test** for `search` with `{"limit":"100"}`
   that exercises the full `parse_args` → handler path.

## Migration / compatibility

- Wire-level: schema becomes strictly broader (accepts strictly more
  values). No existing integer-form caller breaks.
- Internal: handler code is unchanged.
- Test fixtures and snapshots: the `dump-tool-catalog` output changes
  for the affected fields. Update those snapshots in the same PR.

## Future work

- File a follow-up issue for `BoundedUids` / `UidSelector` coercion if
  batch-UID tools start failing in the wild.
- When MCP TS SDK #1361 ships and Claude Code adopts it, we can
  reconsider whether our schema-side widening is still necessary.
  Likely "yes" — other clients (other models, future hosts) will hit
  the same class of bug.
