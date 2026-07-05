# Issue #500 — surface `body_html` for `multipart/alternative` messages

## Problem

`fetch_message` with `include_html=true` returns no `body_html` field for a
`multipart/alternative` message. The server surfaces `content.untrusted.body_html`
verbatim, so the defect is in `rimap-content`'s body extractor
(`crates/rimap-content/src/parse/bodies.rs::extract_bodies`).

`extract_bodies` walks only `message.text_body`. For `multipart/alternative`,
mail-parser places the `text/plain` part in `text_body` and the `text/html`
part in `html_body`. The HTML part is therefore never visited, and
`state.body_html` stays `None`. HTML-only messages work because mail-parser
lists the single HTML part in *both* `text_body` and `html_body`, so the loop
processes it.

**Round-trip impact:** the server writes `multipart/alternative` drafts via
`create_draft.include_html`; fetching such a draft back with `include_html=true`
loses the HTML.

Confirmed by the existing unit test
`parse_multipart_alternative_picks_text_plain_first`, which deliberately does
not assert `body_html`.

## Desired behavior

When a message has a primary `text/html` part that is not the primary text body
(the `multipart/alternative` case), surface that part's sanitized HTML as
`body_html`, while keeping `text/plain` as the primary `body_text`. The HTML
part's extracted plain text becomes an `alternate_parts` entry.

## Design

After the `text_body` walk in `extract_bodies`, if the primary HTML part
(`message.html_body.first()`) exists and was **not** already surfaced
(`state.body_html.is_none()`), and the body budget is not exhausted, run that
part through the identical `sanitize_html_part` → `html::sanitize` path the
in-loop primary-HTML branch already uses. This guarantees:

- The newly-surfaced HTML flows through the **same** ammonia allowlist /
  HTML→text / hidden-content / anchor-mismatch / lookalike pipeline. No raw
  untrusted HTML is ever surfaced.
- `text/plain` remains primary (`sanitize_html_part` appends to `alternates`
  because `primary_text` is already `Some`).
- The HTML part's `anchor_hrefs` flow into `lookalike::audit`, so homograph /
  mixed-script anchors in the alternative are detected exactly as for HTML-only
  messages.

The budget/truncation guard (`state.body_truncated`,
`total_bytes >= MAX_TOTAL_BODY_BYTES`) is respected so the alternative HTML
cannot bust the aggregate body cap that the in-loop walk enforces.

### Threat model

`rimap-content` treats all email content as untrusted. This change *increases*
the set of message shapes for which HTML is surfaced, so the security invariant
is: the alternative HTML must receive identical sanitization to the primary
HTML. It does, because it reuses `sanitize_html_part` unchanged. No new
sanitization code is introduced.

## Testing

- Unit (`parse/bodies.rs` + `parse/pipeline.rs`): a `multipart/alternative`
  message populates `body_html` (sanitized: `<script>` stripped) while
  `body_text` stays the plain part; the HTML text lands in `alternate_parts`.
- Corpus (`tests/injection-corpus/multipart-alternative-html-homograph/`): a
  `multipart/alternative` whose HTML alternative carries a homograph anchor
  (`pаypal.com`, Cyrillic а). Expected `LookalikeMixedScript` warning — which
  only fires if the alternative's anchor hrefs flow through the sanitization +
  lookalike pipeline. Pre-fix this warning does not fire; post-fix it does.
- No `<Tool>Meta` / `<Tool>Untrusted` struct changes, so no schema regen.

## Scope

`crates/rimap-content/src/parse/bodies.rs` (+ its unit tests),
`crates/rimap-content/src/parse/pipeline.rs` tests, one new corpus fixture.
No server or schema changes.
