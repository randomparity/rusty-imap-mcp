# Expand searchable email fields in the `search` tool

- **Date**: 2026-05-18
- **Status**: Approved (brainstorm)
- **Scope**: `crates/rimap-imap` (`StructuredQuery`, `ops/search`), `crates/rimap-server` (`tools/retrieval/search.rs`)

## Motivation

The MCP `search` tool exposes a narrow subset of RFC 3501 SEARCH keys: `from`,
`to`, `subject`, `since`, `before`, `seen`, `has_attachment`. An agent attempting
to filter by `CC:` has no structured option and must escalate to
`advanced_query`, which is gated behind the `SearchAdvanced` posture and is
unavailable in the two lower postures. Several other common
keys (`BCC`, `BODY`, `TEXT`, generic `HEADER`, size bounds, sent-date bounds,
flag predicates) have the same problem.

This change adds the common RFC 3501 SEARCH keys to the structured path so
agents can express ordinary filters without crossing the posture line. The
new keys ride the existing `Search` posture, which is allowed in all four
postures.

The CC and BCC headers are also added to the per-message response so an
agent that filters by `cc: "alice"` can see who else was CC'd without a
follow-up `fetch_message` call.

## Goals

- Add `cc`, `bcc`, `body`, `text`, `headers`, `larger`, `smaller`,
  `sent_since`, `sent_before`, `answered`, `flagged`, `draft` to
  `SearchInput` and `StructuredQuery`.
- Add `cc` and `bcc` to `SearchResultEntry`, populated from the envelope
  already fetched by the search handler.
- Preserve existing posture semantics (structured search stays under
  `Search`; raw passthrough stays under `SearchAdvanced`).
- Preserve existing security boundaries (CR/LF/NUL injection blocked,
  header names validated as RFC 5322 field-name tokens).

## Non-goals

- `DELETED`/`UNDELETED` — rarely useful on modern servers that expunge.
- `OR`/`NOT`/`KEYWORD` combinators — composition belongs in
  `advanced_query`.
- `OLDER`/`YOUNGER` (RFC 5032 `WITHIN` extension) — capability-gated;
  defer until requested.
- Fuzz/mutation baseline additions for the new keys — they mirror existing
  paths already covered by the issue-289 baselines.

## Design

### Architecture

Two thin extensions, no new modules.

**`rimap-imap`**

- `crates/rimap-imap/src/types.rs`: extend `StructuredQuery` with the new
  fields; add a public `HeaderSearch { name: String, value: String }`
  struct.
- `crates/rimap-imap/src/ops/search.rs`: extend `structured_to_key` to
  emit the new keys; add a `validate_header_name` helper enforcing RFC
  5322 field-name syntax.

**`rimap-server`**

- `crates/rimap-server/src/tools/retrieval/search.rs`: extend `SearchInput`
  and `SearchResultEntry`; thread the new inputs through `build_query`;
  populate `cc`/`bcc` in `format_search_result` from the envelope already
  fetched.

Posture matrix (`crates/rimap-core/src/posture_matrix.rs:16-17`) is
unchanged. All new fields are quoted/validated, so structured search
keeps its universal-posture status.

### Input fields

Each new field is `Option<...>` and is AND-combined into the existing
structured query. Empty/`None` is ignored, matching the existing pattern.

| Field         | Type                       | IMAP key emitted             | Notes                                                            |
|---------------|----------------------------|------------------------------|------------------------------------------------------------------|
| `cc`          | `Option<String>`           | `CC "<v>"`                   | Quoted via existing `quote()`; CR/LF/NUL rejected                |
| `bcc`         | `Option<String>`           | `BCC "<v>"`                  | Same                                                             |
| `body`        | `Option<String>`           | `BODY "<v>"`                 | Substring in body parts                                          |
| `text`        | `Option<String>`           | `TEXT "<v>"`                 | Substring in headers OR body                                     |
| `headers`     | `Option<Vec<HeaderSearch>>`| `HEADER <name> "<v>"` per entry | `name` validated; `value` quoted                              |
| `larger`      | `Option<u64>`              | `LARGER <n>`                 | Numeric token, no quoting                                        |
| `smaller`     | `Option<u64>`              | `SMALLER <n>`                | Numeric token, no quoting                                        |
| `sent_since`  | `Option<String>` (ISO date)| `SENTSINCE DD-Mon-YYYY`      | Uses message `Date:` header (not INTERNALDATE)                   |
| `sent_before` | `Option<String>` (ISO date)| `SENTBEFORE DD-Mon-YYYY`     | Same                                                             |
| `answered`    | `Option<bool>`             | `ANSWERED` / `UNANSWERED`    | Mirrors existing `seen`                                          |
| `flagged`     | `Option<bool>`             | `FLAGGED` / `UNFLAGGED`      | Same                                                             |
| `draft`       | `Option<bool>`             | `DRAFT` / `UNDRAFT`          | Same                                                             |

`HeaderSearch`:

```rust
pub struct HeaderSearch {
    pub name: String,
    pub value: String,
}
```

The `SearchInput` docstring will call out that `sent_*` filters use the
message's `Date:` header while `since`/`before` use the server's
INTERNALDATE — these are different and an agent must pick the right one.

### Output fields

`SearchResultEntry` gains:

```rust
#[serde(default, skip_serializing_if = "Vec::is_empty")]
pub cc: Vec<String>,
#[serde(default, skip_serializing_if = "Vec::is_empty")]
pub bcc: Vec<String>,
```

Populated by `format_search_result` from `env.cc` and `env.bcc`
(the envelope is already fetched). Same `sanitize_for_output` pipeline as
`from`/`to`. No extra IMAP traffic.

### Validation and security

1. **Header name** (new): byte-level check in `structured_to_key` before
   emitting `HEADER`. Every byte must be in `33..=126` and not `b':'`.
   Empty names rejected. Failure returns `ImapError::InvalidInput { field:
   "header name", reason: ... }`, surfaced as
   `RimapError::invalid_input` by the existing call path.
2. **Header value**: routed through the existing `quote()` which already
   rejects CR/LF/NUL. No new code path.
3. **`larger`/`smaller`**: `u64`, formatted with `{}`. Numeric token; no
   quoting needed.
4. **`sent_since`/`sent_before`**: parsed by the existing
   `parse_iso_date`; formatted by `format_imap_date`. Same error type and
   error path as `since`/`before`.
5. **Raw branch unchanged**: `advanced_query` path is not touched.

### MCP schema and tool catalog

`SearchInput` and `SearchResultEntry` derive `JsonSchema`. The tool
descriptor regenerates automatically. The `dump_tool_catalog` snapshot
under `crates/rimap-server/tests/dump_tool_catalog.rs` must be regenerated
and committed — this is what agents see and the reviewable surface of the
change.

## Testing

### `rimap-imap` (where `structured_to_key` lives)

Add unit tests alongside the existing ones in `ops/search.rs`:

- One test per new field rendering to the expected key.
- `headers: [{name: "List-Id", value: "rust-users"}]` → `HEADER List-Id
  "rust-users"`.
- Multiple headers AND together in input order: `headers: [a, b]` → two
  `HEADER ...` clauses in order.
- One combined test mixing several new fields with existing fields to
  lock in field ordering.
- `validate_header_name` accepts canonical names (`Message-ID`, `X-Foo`)
  and rejects: empty, contains `:`, contains space, contains CR/LF/NUL,
  contains a high-bit byte.

### `rimap-server` (handler + formatter)

Add unit tests alongside the existing ones in
`tools/retrieval/search.rs`:

- `format_search_result` populates `cc`/`bcc` from an envelope containing
  CC and BCC addresses.
- `format_search_result` returns empty `cc`/`bcc` when the envelope omits
  them (verifies the skip-serialize-on-empty behavior).
- `build_query` wires each new `SearchInput` field into the corresponding
  `StructuredQuery` field — table-driven if it stays clean.

### Snapshot regeneration

Regenerate the `dump_tool_catalog` snapshot for the `search` tool's input
and output schema. The regen is the verification that `JsonSchema`
picked up every new field.

### E2E

One additive case in `crates/rimap-server/tests/e2e_wire.rs` exercising
`cc: "..."` against the mock IMAP server, asserting the IMAP command
body contains `CC "..."`.

### Out of scope

- Fuzz/mutation baseline expansion for the new keys (per issue #289
  notes, full local cargo-mutants runs are unsafe on this host;
  baselines refresh on the regular schedule).

## Risks

- **Schema growth**: the `search` MCP descriptor roughly doubles in
  field count. The contract is purely additive — every new field is
  `Option`/`Vec` — so older agents continue to work unchanged. No
  version bump required.
- **`sent_*` vs `since`/`before` confusion**: the two pairs of date
  filters use different message attributes (Date: header vs
  INTERNALDATE). The `SearchInput` docstrings will distinguish them
  explicitly.
- **Server compatibility**: every emitted key is RFC 3501 core. No
  capability negotiation needed; the change should work against every
  server already tested.

## File-level summary

- `crates/rimap-imap/src/types.rs` — extend `StructuredQuery`; add
  `HeaderSearch`.
- `crates/rimap-imap/src/ops/search.rs` — extend `structured_to_key`;
  add `validate_header_name`; add unit tests.
- `crates/rimap-server/src/tools/retrieval/search.rs` — extend
  `SearchInput` and `SearchResultEntry`; thread fields through
  `build_query`; populate `cc`/`bcc` in `format_search_result`; add
  unit tests.
- `crates/rimap-server/tests/dump_tool_catalog.rs` snapshot — regen.
- `crates/rimap-server/tests/e2e_wire.rs` — one additive case.
