# search `body_preview_bytes` — batch preview for inbox summarization

Issue: #410 (epic #400, FABLE_AUDIT finding F13, Medium). Verified on `main` @ `fb2d7dc9`.

## Problem

"Summarize my unread mail" today costs 1 `search` + K `fetch_message` calls —
K MCP round trips, K parses, K body payloads. `search` returns envelope
entries but no body content, so there is no way to get a gist of many
messages in one call. This is the N+1 the issue targets; the cost that hurts
is **MCP round trips and token count**, not server-side IMAP fetches.

## Decision: option (b), `body_preview_bytes` on `search`

The issue offers (a) a `fetch_messages` batch tool, (b) a `body_preview_bytes`
option on `search`, and (c) `thread` support. It recommends **either a or b**
and notes: *"prefer extending `search` (b/c) over new tool surface where
equivalent."*

**Chosen: (b).** Rationale:

- **Directly kills the N+1 for the headline use case in ONE call.** With
  previews inline, "summarize my unread mail" is a single `search` — beating
  the acceptance target of ≤2 calls for 50 messages.
- **No new tool surface.** Option (a) adds a `fetch_messages` tool, which adds
  `tools/list` catalog weight — the exact cost #411 is trying to reduce. (b)
  extends an existing tool, matching the issue's stated preference.
- **Reuses the proven body pipeline** (`fetch_body` + `parse_message_async`),
  so previews get the same Unicode sanitization as `fetch_message` bodies.

Option (c) (threading) is independent and out of scope here; it can land
separately without conflicting with this change.

## Shape

- `search` input gains `body_preview_bytes: Option<usize>`. When set and
  non-zero, each returned result carries `body_preview` under `untrusted`:
  the first N bytes of the message's sanitized plain-text body.
- N is clamped to `MAX_BODY_PREVIEW_BYTES` (1024). `None`/`0` ⇒ no previews
  and byte-for-byte unchanged output (back-compat).
- Previews are provided for up to the first `MAX_PREVIEW_MESSAGES` (50)
  results of the page; entries beyond that omit `body_preview`. This keeps
  `limit`/`offset`/`next_offset` pagination semantics unchanged (the flag
  never silently resizes a page) while bounding server work. To preview more,
  request `limit ≤ 50` or page with `next_offset`.

## Byte budget and cost

- **Per message:** the body is fetched with the existing `fetch_body`
  (capped at the configured `max_fetch_body_bytes`, default 1 MiB), parsed,
  and the sanitized `body_text` is truncated to N bytes on a grapheme
  boundary. Peak heap stays ≈ one body: fetch → parse → keep the ≤1 KiB
  preview → drop the body before the next UID.
- **Per response:** ≤ 50 previews × ≤ 1 KiB ≈ 51 KiB of preview text — well
  within the MCP stdio envelope.
- **Failure isolation:** a per-UID fetch/parse error (including an oversize
  body rejected by the `max_fetch_body_bytes` preflight, exactly as
  `fetch_message` would reject it) yields `body_preview = null` for that
  entry and never fails the whole `search`.
- **Known cost:** previews are fetched sequentially over the single IMAP
  session (one `SELECT`+`SIZE`+`FETCH` per UID). A batch body-fetch primitive
  (select once, fetch many) would cut round trips; it is deliberately left as
  a follow-up so this change stays scoped to `search` + the existing fetch
  primitive.

## Posture

`body_preview` is available wherever `search` is (`readonly`+) — **no new
gate**, and specifically NOT behind the `full`/`destructive` content-search
gate. Reasoning:

- **Returning content ≠ filtering on content.** The `full`-gated `body`/
  `text`/`headers` filters are a *content oracle*: they let an agent ask
  "which messages contain X" across the whole mailbox. `body_preview` does
  not filter on content — it returns a truncated body of messages already
  matched by envelope criteria. It grants no ability to probe for content.
- **`fetch_message` already returns full body text at `readonly`.** A preview
  is a strictly weaker, truncated, batched form of a capability the default
  posture already has. It exposes no message an agent couldn't already read
  one-by-one via `fetch_message`.
- Because the preview is real body content (unlike the envelope snippets
  `search` returns today), sanitization warnings from preview parsing are
  aggregated into the response's top-level `security_warnings`. Per-message
  attribution still requires `fetch_message`.

## Acceptance mapping

- Spec choosing among a/b/c with byte-budget + posture analysis — this doc.
- Limits tested: preview-byte clamp, per-message truncation flag via
  `body_preview` length, per-UID failure isolation, preview-count cap.
- Summarize-inbox ≤ 2 calls for 50 messages: a single `search` with
  `body_preview_bytes` and `limit = 50` returns 50 previews (1 call).
- Schema/description/docs/conformance updated.
