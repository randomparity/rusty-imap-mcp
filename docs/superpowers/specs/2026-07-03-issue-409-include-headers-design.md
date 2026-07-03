# fetch_message `include_headers` — posture placement and design

Issue: #409 (epic #400, FABLE_AUDIT finding F12, Medium). Verified on `main` @ `9921f87c`.

## Problem

`fetch_message` returns a fixed parsed header set (subject, from, to, cc,
reply_to, date, message_id) plus body and attachments. No other header is
readable at any posture — including `readonly`, whose purpose is safe
inspection. The only raw-header access is `export_messages` (deny-by-default
everywhere). `search` can *filter* on a header behind `SearchAdvanced` but
never returns header values. This blocks unsubscribe, mailing-list triage,
delivery/spam debugging, and custom-app-header workflows.

## Decision: posture placement

**`include_headers` is available wherever `fetch_message` is — no
sub-capability gate.** It is NOT modeled like `fetch_message.include_html`.

Rationale (threat model):

- **Weaker capability than what higher postures already grant.**
  `SearchAdvanced` (full+) lets an agent *filter the whole mailbox* on
  arbitrary header criteria. Reading named header values off a single
  message the agent has *already* fetched is strictly less powerful: it
  is bounded to one message the caller already named and already reads
  the body of.
- **Headers are metadata-adjacent and less sensitive than the body**,
  which `fetch_message` returns at every posture. An agent that can read
  the plain-text body can already read the most sensitive message
  content; exposing `Received`/`List-*`/`X-*` header lines adds routing
  and provenance metadata, not new message content.
- **`readonly`'s stated purpose is safe inspection.** Gating header reads
  above `readonly` would deny the posture the exact metadata-inspection
  workflows (unsubscribe discovery, list triage, spam debugging) that
  motivate a read-only posture in the first place.
- **The value is attacker-controlled and treated as such.** All values
  are returned under `untrusted`, routed through the same Unicode
  sanitization pipeline as every other header (control-char stripping,
  RFC 2047 decode, bidi-domain audit), and the per-value byte cap
  (`MAX_HEADER_BYTES` = 8 KiB) applies. Any codepoint-class finding
  surfaces as a `security_warnings` entry, identical to `subject`/`from`.

`include_html` is gated because HTML is a materially larger and more
dangerous rendering surface (active content, remote-fetch vectors); named
header *values* carry none of that.

## Design

Single parse, shared scrubbing. Header extraction runs on the **same
scrubbed + parsed `mail_parser::Message`** as the body/meta extraction, so
a header removed by `scrub_header_smuggling` (CRLF-smuggled header) can
never reappear in `include_headers` output. Extracting from the raw bytes
in a second pass would resurrect scrubbed headers, so it is not done.

- `rimap-content`: `parse_message` is refactored to delegate to an
  internal `parse_message_inner(raw, wanted)`; a new public
  `parse_message_with_headers(raw, wanted) -> (Content, Vec<SelectedHeader>)`
  threads the request-scoped allowlist through the one parse. Existing
  `parse_message(raw)` callers are unchanged (empty allowlist).
- Extraction is case-insensitive (RFC 5322), keyed by the caller's
  requested name; repeated header lines collect into a value array;
  requested names with no matching header are omitted (absent key, not an
  error). Each value is sanitized via the existing `sanitize_header_value`
  (handles `Text`/`TextList`/`Address`, drops non-textual/empty).
- `rimap-server` `fetch_message`: new optional `include_headers: [String]`
  input. Validation caps the request at 16 names and rejects
  empty/structurally-invalid RFC 5322 field names (`InvalidInput`);
  names are deduplicated case-insensitively. The response gains an
  optional `headers` object under `untrusted` (name → values), present
  only when `include_headers` is supplied (possibly empty when none of
  the requested headers exist).

## Limits

| Limit | Value | Enforced by |
|-------|-------|-------------|
| Requested header names per call | ≤ 16 | server input validation |
| Per-value bytes (post-sanitize) | 8 KiB (`MAX_HEADER_BYTES`) | `unicode::sanitize` |
| Total headers on the message | 256 (`MAX_HEADER_COUNT`) | existing parse limit |

## Out of scope

Returning *all* headers (unbounded response), header *mutation*, and any
change to `export_messages` (still the only raw-message oracle).
