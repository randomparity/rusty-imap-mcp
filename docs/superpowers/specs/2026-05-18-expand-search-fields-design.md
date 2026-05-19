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
agents can express ordinary filters without unnecessary escalation. The
envelope/flag keys (`cc`, `larger`, `smaller`, `sent_since`, `sent_before`,
`answered`, `flagged`, `draft`) ride the existing `Search` posture and are
allowed in all four postures. The content-oracle keys (`body`, `text`,
generic `headers`, `bcc`) promote the dispatch to `SearchAdvanced` and are
denied under `Readonly` and `DraftSafe`, matching the existing
`advanced_query` boundary.

CC is also added to the per-message response so an agent that filters by
`cc: "alice"` can see who else was CC'd without a follow-up
`fetch_message` call. BCC is intentionally not added to the response — see
*Privacy* below.

## Goals

- Add `cc`, `bcc`, `body`, `text`, `headers`, `larger`, `smaller`,
  `sent_since`, `sent_before`, `answered`, `flagged`, `draft` to
  `SearchInput` and `StructuredQuery`.
- Add `cc` (but not `bcc`) to `SearchResultEntry`, populated from the
  envelope already fetched by the search handler.
- Gate the content-oracle inputs (`body`, `text`, `headers`, `bcc`) to
  the `SearchAdvanced` posture by extending the existing
  `refine_tool_name` predicate. Other new fields stay under `Search`.
- Preserve existing security boundaries (CR/LF/NUL injection blocked,
  header names validated as RFC 5322 field-name tokens, empty/whitespace
  string filters rejected at the MCP boundary).

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
  and `SearchResultEntry` (adding `cc` only on the output); thread the new
  inputs through `build_query`; populate `cc` in `format_search_result`
  from the envelope already fetched. Reject empty/whitespace-only string
  filters before constructing the `StructuredQuery`.
- `crates/rimap-server/src/mcp/tool_name.rs`: extend the
  `refine_tool_name` predicate so that any of `body`, `text`, a
  non-empty `headers`, or `bcc` promotes `Search` to `SearchAdvanced`
  (in addition to the existing `advanced_query` trigger).

### Posture split

The posture matrix in `crates/rimap-core/src/posture_matrix.rs:14-22`
keeps its current shape:

- `Search` — `[true, true, true, true]` (allowed in every posture).
- `SearchAdvanced` — `[false, false, true, true]` (denied under
  `Readonly` and `DraftSafe`).

`DispatchGuard::pre_dispatch` (`crates/rimap-authz/src/guard.rs:40-44`)
already enforces this; no change there. The new fields split across the
two postures as follows.

**Stays under low-posture `Search`** — envelope/flag predicates that map
to IMAP-indexed metadata, no content scan:

- `cc`, `larger`, `smaller`, `sent_since`, `sent_before`, `answered`,
  `flagged`, `draft`.

**Promotes to `SearchAdvanced`** — content-oracle predicates that scan
header values or body bytes the server may otherwise refuse to index for
low-trust clients, matching the existing treatment of `advanced_query`:

- `body`, `text`, `headers` (any non-empty array), `bcc`.

The promotion happens in `refine_tool_name`
(`crates/rimap-server/src/mcp/tool_name.rs:31-76`) by extending the
existing predicate. The current line
`ToolName::Search if args.get("advanced_query").is_some() => ToolName::SearchAdvanced`
becomes a multi-condition check: presence of `advanced_query` OR `body`
OR `text` OR a non-empty `headers` array OR `bcc`. The dispatch seam then
runs the existing `SearchAdvanced` posture check; no new gating layer is
added.

`headers: Some([])` (an explicitly empty array) does NOT promote — a
present-but-empty array carries no filter intent and is normalized to
`None` by `build_query`.

### Privacy

BCC is exposed as an input filter (gated to `SearchAdvanced`) but is
intentionally not exposed in `SearchResultEntry` in any posture. No
existing MCP tool returns BCC: `fetch_message`
(`crates/rimap-server/src/tools/retrieval/fetch_message.rs:53-84`) and
`ContentMeta` (`crates/rimap-content/src/output.rs:38-66`) both surface
only `to` and `cc`. Adding `bcc` to search output would create a new
disclosure surface for blind-recipient metadata that is particularly
sensitive on `Sent` and `Drafts` folders. Future BCC-on-output work is
out of scope for this change and would require its own posture / capability
decision.

### Input fields

Each new field is `Option<...>` and is AND-combined into the existing
structured query. `None` is ignored. Empty or whitespace-only string
filters are rejected at the MCP boundary — see *Validation and security*.

| Field         | Type                       | IMAP key emitted             | Posture            | Notes                                                            |
|---------------|----------------------------|------------------------------|--------------------|------------------------------------------------------------------|
| `cc`          | `Option<String>`           | `CC "<v>"`                   | `Search`           | Quoted via existing `quote()`; CR/LF/NUL rejected                |
| `bcc`         | `Option<String>`           | `BCC "<v>"`                  | `SearchAdvanced`   | Same; promotes dispatch (content-oracle)                         |
| `body`        | `Option<String>`           | `BODY "<v>"`                 | `SearchAdvanced`   | Substring in body parts; promotes dispatch                       |
| `text`        | `Option<String>`           | `TEXT "<v>"`                 | `SearchAdvanced`   | Substring in headers OR body; promotes dispatch                  |
| `headers`     | `Option<Vec<HeaderSearch>>`| `HEADER <name> "<v>"` per entry | `SearchAdvanced` (when non-empty) | `name` validated; `value` quoted; empty array does not promote |
| `larger`      | `Option<u64>`              | `LARGER <n>`                 | `Search`           | Numeric token, no quoting                                        |
| `smaller`     | `Option<u64>`              | `SMALLER <n>`                | `Search`           | Numeric token, no quoting                                        |
| `sent_since`  | `Option<String>` (ISO date)| `SENTSINCE DD-Mon-YYYY`      | `Search`           | Uses message `Date:` header (not INTERNALDATE)                   |
| `sent_before` | `Option<String>` (ISO date)| `SENTBEFORE DD-Mon-YYYY`     | `Search`           | Same                                                             |
| `answered`    | `Option<bool>`             | `ANSWERED` / `UNANSWERED`    | `Search`           | Mirrors existing `seen`                                          |
| `flagged`     | `Option<bool>`             | `FLAGGED` / `UNFLAGGED`      | `Search`           | Same                                                             |
| `draft`       | `Option<bool>`             | `DRAFT` / `UNDRAFT`          | `Search`           | Same                                                             |

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

`SearchResultEntry` gains a single field:

```rust
#[serde(default, skip_serializing_if = "Vec::is_empty")]
pub cc: Vec<String>,
```

Populated by `format_search_result` from `env.cc` (the envelope is
already fetched). Same `sanitize_for_output` pipeline as `from`/`to`. No
extra IMAP traffic.

`bcc` is intentionally omitted from the output struct — see *Privacy*
above. `format_search_result` does not read `env.bcc`.

### Validation and security

1. **Empty-string rejection** (new): in `build_query`
   (`crates/rimap-server/src/tools/retrieval/search.rs`), every new
   string filter is checked before constructing `StructuredQuery`. The
   rule is `s.trim().is_empty()` → reject with
   `RimapError::invalid_input("<field-name> must not be empty or whitespace-only")`.
   This covers `cc`, `bcc`, `body`, `text`, and every
   `headers[i].name` / `headers[i].value`. Without this gate the
   existing `quote()` (`crates/rimap-imap/src/ops/search.rs:67-84`)
   only rejects CR/LF/NUL, so `""` would pass through and the IMAP
   server would happily execute broad scans like `BODY ""` or
   `HEADER X-Foo ""`.

   `headers: Some(vec![])` (a present-but-empty array) is normalized to
   `None` rather than rejected — an empty array carries no filter
   intent.
2. **Header name** (new): byte-level check in `structured_to_key` before
   emitting `HEADER`. Every byte must be in `33..=126` and not `b':'`.
   Empty names rejected. Failure returns `ImapError::InvalidInput { field:
   "header name", reason: ... }`, surfaced as
   `RimapError::invalid_input` by the existing call path. This runs in
   addition to the MCP-boundary empty-string check above.
3. **Header value**: routed through the existing `quote()` which already
   rejects CR/LF/NUL. No new code path.
4. **`larger`/`smaller`**: `u64`, formatted with `{}`. Numeric token; no
   quoting needed.
5. **`sent_since`/`sent_before`**: parsed by the existing
   `parse_iso_date`; formatted by `format_imap_date`. Same error type and
   error path as `since`/`before`.
6. **Posture enforcement**: content-oracle inputs (`body`, `text`,
   non-empty `headers`, `bcc`) promote the dispatched tool to
   `SearchAdvanced` via `refine_tool_name`, so
   `DispatchGuard::pre_dispatch` rejects them with
   `Authz { code: PostureDenied }` under `Readonly` and `DraftSafe`.
   See *Posture split*.
7. **Raw branch unchanged**: `advanced_query` path is not touched.

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

- `format_search_result` populates `cc` from an envelope containing CC
  addresses.
- `format_search_result` returns empty `cc` when the envelope omits it
  (verifies the skip-serialize-on-empty behavior).
- `format_search_result` does NOT read `env.bcc` — assert that an
  envelope with BCC addresses produces a `SearchResultEntry` whose
  serialized JSON contains no `bcc` key.
- `build_query` wires each new `SearchInput` field into the corresponding
  `StructuredQuery` field — table-driven if it stays clean.

### Posture refinement (`mcp/tool_name.rs`)

Extend `refine_tool_name_promotes_sub_capabilities` (or add a sibling
test) at `crates/rimap-server/src/mcp/tool_name.rs:175`:

- One assertion per promotion trigger: `body`, `text`, `headers: [{...}]`
  (non-empty), `bcc` — each promotes `ToolName::Search` to
  `ToolName::SearchAdvanced`.
- One assertion that low-posture fields (`cc`, `larger`, `sent_since`,
  `answered`) do NOT promote — base `Search` is returned.
- One assertion that `headers: []` (an explicit empty array) does NOT
  promote.

### Posture denial (E2E)

Extend the existing posture-denied wire-test scaffolding in
`crates/rimap-server/tests/e2e_wire.rs`:

- Calling `search` with `body: Some("hello")` under `Readonly` posture
  returns `Authz { code: PostureDenied }` — exercises the
  `refine_tool_name` + `DispatchGuard::pre_dispatch` path end-to-end.

### Empty-string rejection (unit)

In `crates/rimap-server/src/tools/retrieval/search.rs`:

- One rejection assertion per field — `cc`, `bcc`, `body`, `text`,
  `headers[].name`, `headers[].value` — for both `""` and `"   "` —
  asserting `RimapError::Authz { code: InvalidInput, ... }`.
- One assertion that `headers: Some(vec![])` produces a
  `StructuredQuery` that emits no `HEADER` clause (i.e. is treated as
  `None`) and is accepted.

### Snapshot regeneration

Regenerate the `dump_tool_catalog` snapshot for the `search` tool's input
and output schema. The regen is the verification that `JsonSchema`
picked up every new input field and that `bcc` is absent from the
`SearchResultEntry` schema.

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
- `crates/rimap-server/src/mcp/tool_name.rs` — extend the
  `refine_tool_name` predicate so `body`, `text`, non-empty `headers`,
  or `bcc` promote `Search` to `SearchAdvanced`; add unit tests.
- `crates/rimap-server/src/tools/retrieval/search.rs` — extend
  `SearchInput` and `SearchResultEntry` (output: `cc` only); thread
  fields through `build_query`; reject empty/whitespace-only string
  filters; populate `cc` in `format_search_result`; add unit tests.
- `crates/rimap-server/tests/dump_tool_catalog.rs` snapshot — regen.
- `crates/rimap-server/tests/e2e_wire.rs` — add one additive case for
  `cc` wire-format and one posture-denied case for `body` under
  `Readonly`.
