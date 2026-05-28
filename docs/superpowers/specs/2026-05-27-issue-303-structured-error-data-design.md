# Structured `ErrorData.data` for RateLimited / CircuitOpen / AttachmentTooLarge (#303)

## Context

Phase 1 of the MCP tool-catalog-richness work
(`2026-05-20-mcp-tool-catalog-richness-design.md`) gave three error variants
structured `ErrorData.data`: `NoAccount`, `UnknownAccount`,
`UidValidityChanged`. Three more were deferred to Phase 2 (this issue) because
their typed fields are flattened into a message string before reaching
`to_mcp_error`:

- `AuthzError::RateLimited { retry_after_ms }` — flattened by
  `From<AuthzError> for RimapError` into `RimapError::Authz { code, message }`
  (`crates/rimap-authz/src/error.rs:108`).
- `AuthzError::CircuitOpen { retry_after_ms }` — same path.
- `ContentError::LimitExceeded { kind, limit }` — classified into
  `RimapError::Authz { code: AttachmentTooLarge, message }` at
  `crates/rimap-server/src/mcp/content.rs:38`, stringified via `err.to_string()`.

Today `to_mcp_error` (`crates/rimap-server/src/mcp/error.rs:98-100`) emits
`data: None` for all three codes. Clients must parse prose to recover retry
timing or size limits.

### Correction to the issue text

Issue #303 describes `ContentError::LimitExceeded { limit_bytes, actual_bytes }`.
The actual variant (`crates/rimap-content/src/error.rs:24`) is
`{ kind: &'static str, limit: usize }`. There are five construction sites and
only two are byte-denominated:

| kind | limit constant | byte-denominated? |
|------|----------------|-------------------|
| `message_bytes` | `MAX_MESSAGE_BYTES` | yes |
| `html_body` | `MAX_HTML_BYTES` | yes |
| `header_count` | `MAX_HEADER_COUNT` | no (count) |
| `mime_parts` | `MAX_MIME_PARTS` | no (count) |
| `mime_depth` | `MAX_MIME_DEPTH` | no (depth) |

No construction site captures an "actual" value today. A `limit_bytes` /
`actual_bytes` shape would be wrong for three of the five kinds. The design
below exposes the fields that already exist (`kind`, `limit`) rather than
inventing a byte-only shape or capturing a new `actual` value nothing currently
measures (no client has asked for it — see "Rejected alternatives").

## Goal

Publish the typed recovery information as structured `ErrorData.data` so MCP
clients can implement programmatic retry and size-aware fallbacks without
parsing prose. Match the Phase 1 wire shape: a JSON object with an
`error_code` string plus the typed fields.

## Approach

Follow the `UidValidityChanged` precedent exactly (issue option **b**):
dedicated `RimapError` variants carrying typed fields, routed through a
dedicated `From` arm, built into structured `data` by a short-circuit in
`to_mcp_error`.

Rationale for **b** over the alternatives:

- **(a) extend `RimapError::Authz` with `data: Option<Value>`** — touches ~52
  `RimapError::Authz` construct/match sites across the workspace and erases the
  type information at the boundary (every site would hand-build JSON). The
  precedent already rejected this for `UidValidityChanged`.
- **(c) build `ErrorData` directly from `AuthzError` before `?`-flattening** —
  splits error→wire mapping across two functions (`dispatch` and
  `to_mcp_error`), so the wire contract is no longer in one place. Loses the
  single-source-of-truth `to_mcp_error` gives us.
- **(b)** keeps every error→wire decision in `to_mcp_error`, mirrors the
  existing three short-circuit arms, and preserves the typed fields end to end.

### Delta 1 — `rimap-core`: two new `RimapError` variants

```rust
RimapError::RateLimited { retry_after_ms: u64 }
RimapError::CircuitOpen { retry_after_ms: u64 }
```

- `#[error(...)]` Display strings copy today's `AuthzError` wording so the
  human-readable message is unchanged.
- `code()` maps them to `ErrorCode::RateLimited` / `ErrorCode::CircuitOpen`.
- No `#[source]` — unlike `UidValidityChanged`, the `AuthzError` source carries
  no extra chain depth worth preserving (it is a leaf describing the same
  condition). Sibling `Authz`-origin errors today carry no source either, so
  this keeps reporter depth consistent for the authz family.

### Delta 2 — `rimap-authz`: route the two variants in `From<AuthzError>`

`From<AuthzError> for RimapError` gains a match (mirroring the
`From<ImapError>` `if let`) that sends `RateLimited` / `CircuitOpen` to the new
dedicated variants and everything else through the existing `Authz` arm. The
`code()` accessor on `AuthzError` is unchanged.

The pinning test `from_impl_preserves_code_and_message` currently asserts
`RateLimited` flattens to `Authz`. It is rewritten to assert the new routing
(typed variant, preserved `retry_after_ms`, unchanged Display) — this is the
intended contract change, not a regression.

**Second `RateLimited` producer.** The infrastructure-tool limiter
(`AccountRegistry::check_infrastructure_rate` →
`infra_rate_limited`, `crates/rimap-server/src/boot/registry.rs`) does **not**
go through `AuthzError`; it built `RimapError::Authz { code: RateLimited }`
directly and stringified the retry hint. For the same wire-code-consistency
reason as the dual `AttachmentTooLarge` producers (Delta 3), it is rerouted to
return `RimapError::RateLimited { retry_after_ms }` so every `-32003` carries
the typed hint regardless of which limiter tripped.

### Delta 3 — typed fields for `AttachmentTooLarge` (both producers)

`ErrorCode::AttachmentTooLarge` has **two** producers and both must carry
structured `data`, or the wire code is inconsistent (a client keying on
`-32005` would see `data` present sometimes, absent other times):

1. `ContentError::LimitExceeded { kind, limit }` — content-pipeline caps
   (message bytes, MIME depth/parts, header count, HTML body), classified at
   `crates/rimap-server/src/mcp/content.rs:38`.
2. `ImapError::SizeLimit { limit }` — the IMAP fetch-body cap
   (`max_fetch_body_bytes`), at `crates/rimap-imap/src/error.rs:46` →
   `code()` `AttachmentTooLarge` (`error.rs:206`), today flattened through the
   generic `From<ImapError>` → `RimapError::Imap` arm.

Add one dedicated variant that both producers feed:

```rust
RimapError::AttachmentTooLarge { kind: String, limit: u64 }
```

`kind` is `String` (not `&'static str`) because `RimapError` lives in
`rimap-core`, below both `rimap-content` and `rimap-imap`, and must not borrow
their constants. `code()` → `ErrorCode::AttachmentTooLarge`.

- `classify_content_error` (`rimap-server`) constructs it from the
  `LimitExceeded { kind, limit }` fields (`limit as u64`).
- `From<ImapError>` (`rimap-imap`) gains an arm that routes
  `SizeLimit { limit }` into it with a stable `kind: "fetch_body_bytes"`,
  mirroring the existing `UidValidityChanged` `if let` arm. Everything else
  still flows through the generic `Imap` arm.

No change to `ContentError` or `ImapError` themselves and no change to their
construction sites — the typed fields already exist.

**Source chain — deliberate carve-out.** `AttachmentTooLarge` carries **no
`#[source]`**, unlike `UidValidityChanged`. Rerouting `SizeLimit` out of the
generic `Imap` arm drops the one-level source link that arm preserves today, so
this is an explicit decision, not an oversight:

- `ImapError::SizeLimit` is a *leaf* error
  (`#[error("body size exceeded limit of {limit} bytes")]`, no `#[source]` of
  its own). Its entire payload is `limit`, which `AttachmentTooLarge` now
  surfaces as a typed field, and its message is reproduced in the variant's
  Display (below). No diagnostic information is lost from the chain.
- The other producer, `ContentError::LimitExceeded`, is **not** IMAP-origin and
  is classified from a `&ContentError` borrow (`ContentError` is not `Clone`),
  so it cannot supply a source at all. A source-less variant keeps both
  producers symmetric.
- This makes the three *new structured* variants
  (`RateLimited` / `CircuitOpen` / `AttachmentTooLarge`) uniform: all are
  source-less leaves whose recovery data lives in typed fields. The
  "every IMAP-origin variant carries a source" rule on `UidValidityChanged`'s
  docstring is amended to except `AttachmentTooLarge`, with this reason.

**Display / message change.** The variant gets one unified `#[error(...)]`
Display, reusing the existing content wording (lower churn):
`"content limit exceeded: {kind} (limit={limit})"`. Following the Phase 1
precedent (`NoAccount` / `UidValidityChanged` Display strings carry **no**
`ERR_` prefix, since `to_mcp_error` sets `message = err.to_string()`), this
**changes the human-readable `message`** for both producers:

- Content path today: `"ERR_ATTACHMENT_TOO_LARGE: content limit exceeded: …"`
  (via `RimapError::Authz`'s `"{code}: {message}"` Display) → becomes
  `"content limit exceeded: {kind} (limit={limit})"` (prefix dropped).
- IMAP fetch path today: `"ERR_ATTACHMENT_TOO_LARGE: body size exceeded limit
  of N bytes"` (via `RimapError::Imap`) → becomes the unified
  `"content limit exceeded: fetch_body_bytes (limit=N)"`.

This is acceptable: the MCP `message` is explanatory prose, not a stable
contract — only `code` and the new `data` are contractual (see Wire-contract /
semver impact). The shape tests assert the unified wording, not the old
per-producer strings.

### Delta 4 — `rimap-server`: structured `data` in `to_mcp_error`

Three new short-circuit arms, mirroring the existing three:

```jsonc
// RateLimited  → code -32003
{ "error_code": "ERR_RATE_LIMITED",  "retry_after_ms": <u64> }
// CircuitOpen  → code -32004
{ "error_code": "ERR_CIRCUIT_OPEN",  "retry_after_ms": <u64> }
// AttachmentTooLarge → code -32005
{ "error_code": "ERR_ATTACHMENT_TOO_LARGE", "kind": "<str>", "limit": <u64> }
```

The custom MCP codes (`RATE_LIMITED` -32003, `CIRCUIT_OPEN` -32004,
`ATTACHMENT_TOO_LARGE` -32005) already exist; only the `data` payload is new.
The existing `code()`-based arms stay as defensive fallbacks (same pattern the
Phase 1 arms use) so an accidental `Authz { code: RateLimited, .. }` still
maps to the right code with `data: None`.

## Wire-contract / semver impact

- `data` moves from `null` to a populated object on three error paths.
  Additive for clients that ignore `data`; the wire `code` is unchanged.
  Not a breaking change.
- **`message` text changes** on the `RateLimited` / `CircuitOpen` /
  `AttachmentTooLarge` paths: the dedicated variants' Display carries no
  `ERR_…:` prefix (matching the Phase 1 structured variants), and
  `AttachmentTooLarge` unifies the two producers' wording (see Delta 3). MCP
  `message` is explanatory prose, not a stable contract — only `code` and the
  typed `data` fields are contractual — so this is acceptable. The
  `RateLimited` / `CircuitOpen` Display strings are copied verbatim from the
  current `AuthzError` wording, so those two paths lose only the `ERR_…:`
  prefix that the old `Authz`-routed form added.
- The `CircuitOpen` `retry_after_ms == 0` half-open semantics
  (`crates/rimap-authz/src/error.rs:33-42`) carry through verbatim — `0` is a
  valid value, not "retry now". The variant docstring is copied so the meaning
  travels with the typed field.

## Test plan

The `data` contract for each path is guarded by a **named pair** of tests — a
routing test (does the typed `From` impl preserve the fields into the dedicated
variant?) and a shape test (does `to_mcp_error` serialize the right payload?).
Neither alone is sufficient: the `to_mcp_error` tests construct `RimapError`
directly and so never exercise the `From` routing where the historical
field-loss occurs.

- `rimap-core`: `code()` accessor + Display for the three new variants;
  round-trip of `retry_after_ms` / `kind` / `limit`.
- **Routing — `rimap-authz`:** rewrite `from_impl_preserves_code_and_message`
  to assert `RateLimited` / `CircuitOpen` route into the dedicated `RimapError`
  variants with preserved `retry_after_ms` and unchanged Display.
- **Routing — `rimap-imap`:** assert `From<ImapError>` sends
  `SizeLimit { limit }` into `RimapError::AttachmentTooLarge { kind:
  "fetch_body_bytes", limit }` (new test alongside the existing
  `UidValidityChanged` routing test).
- **Routing — `rimap-server`:** extend
  `limit_exceeded_classifies_as_attachment_too_large` so
  `classify_content_error` produces `RimapError::AttachmentTooLarge { kind,
  limit }` with the `kind`/`limit` preserved (not just the right `code()`).
- **Shape — `rimap-server` `error.rs`:** three `*_carries_structured_data`
  unit tests asserting the exact `data` payload shape and values for the
  rate-limit, circuit-open, and attachment-too-large paths (mirror the Phase 1
  trio). These are the on-wire contract.
- The rate-limit / circuit-open / attachment `data` contract is therefore
  pinned by the routing-test + shape-test pair above; no single deleted test
  leaves a path silently emitting `data: null`. A full `e2e_wire.rs` round trip
  is added only if a deterministic trigger is cheap — it is not the contract of
  record.

## Rejected alternatives

- **Adding `actual` to `ContentError::LimitExceeded`** — would require capturing
  a measured value at all five sites (three of which are counts/depths, not
  bytes) and a `ContentError` signature change rippling through fuzz/test
  fixtures. No client has requested actual-vs-limit deltas; the limit alone lets
  a client choose a smaller request. Deferred unless a concrete need appears
  (YAGNI; matches the issue's own "revisit if a real client surfaces a need").
- **Single `RimapError::Authz { data }` field** — see Approach (a) above.
