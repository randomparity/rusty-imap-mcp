# Plan — Issue #531: grow injection corpus (five missing attack classes)

**Issue:** #531 · **Theme C** (oracles, invariants, meta-testing) · Priority P3
**Extends:** `docs/superpowers/specs/2026-04-30-test-strategy-improvements-design.md` §8.1
**Branch:** `feat/injection-corpus-classes-531`

## Goal

Add five `tests/injection-corpus/` fixtures covering email-borne agent attack
classes with no current coverage, each green through the auto-discovering corpus
runner (`crates/rimap-content/tests/injection_corpus.rs`). Establish a corpus
`README.md` index documenting every fixture's attack class (the "corpus only
grows" standing convention).

## Empirical findings (from probing real `parse_message` output)

Assertions below are grounded in observed pipeline behavior, not assumed. The
pipeline's defenses are **structural** — keyed on how `mail-parser` sorts parts
into `text_body` (surfaced as body) vs. attachments (surfaced in `meta` only).

| Class | Observed behavior | Security property asserted |
|-------|-------------------|----------------------------|
| `text/calendar` invite | Quarantined as attachment (with or without `Content-Disposition`); `DESCRIPTION` never enters `body_text` | Injection text absent from `body_text`; `attachment_count=1` |
| EAI raw-UTF-8 headers (RFC 6532) | Reach Unicode sanitization even without RFC 2047 encoding | `unicode_zero_width_stripped` + `unicode_bidi_override_stripped` emitted |
| `multipart/signed` unsigned sibling | Payload surfaces in `untrusted.alternate_parts`, signature in `meta.attachments`; no trust elevation | Payload present in `alternate_parts` (untrusted, not `meta`); benign signed part is primary `body_text` |
| `message/partial` fragment | Quarantined as attachment; `body_text` empty; no reassembly | Fragment payload absent from `body_text`; `attachment_count=1` |
| RFC 2231 filename (`filename*0*` + pct-encoding) | mail-parser decodes to `../../etc/passwd`; sanitizer rewrites | `parse_attachment_filename_rewritten` emitted |

## Design decisions

1. **Fixtures** (one dir each, `input.eml` CRLF-terminated + `expected.json`):
   - `calendar-invite-injection`
   - `eai-raw-utf8-headers`
   - `pgp-signed-unsigned-sibling`
   - `message-partial-fragment`
   - `attachment-filename-rfc2231`

2. **Harness addition** — the corpus runner currently asserts only against
   `body_text`, `body_html`, warnings, and `meta`. It cannot assert anything
   about `untrusted.alternate_parts`, which issue #500 made load-bearing. The
   signed fixture's real security property is that the unsigned sibling's
   payload is *surfaced under `untrusted` but segregated into `alternate_parts`*
   — not dropped, not promoted to `meta`. Asserting only its absence from
   `body_text` would be a misleading half-truth. Add one field
   `alternate_parts_must_contain: Vec<String>` (symmetric with the existing
   `body_html_must_contain`), unit-tested, used by the signed fixture.

3. **README** — create `tests/injection-corpus/README.md`: purpose, the CRLF
   authoring requirement, the "corpus only grows" convention, and a one-line
   attack-class entry for every fixture (existing + new).

4. **Snapshots** — register the five new fixtures in
   `crates/rimap-content/tests/snapshots.rs` and commit generated `.snap` files,
   so any future sanitizer change surfaces as a reviewable diff (matches the
   repo's snapshot posture).

## TDD tasks

1. Add `alternate_parts_must_contain` to the runner `Expected` struct + an
   `assert_alternate_parts_substrings` check; add a focused unit test proving it
   fails when the substring is absent and passes when present. (Red → green.)
2. Author the five `input.eml` files (CRLF) + `expected.json`. Run
   `just test-injection` — expect green.
3. Register five snapshot tests; `cargo insta test --accept`; review the `.snap`
   diffs for correctness (no payload leakage into `body_text`/`body_html`).
4. Write `tests/injection-corpus/README.md`.
5. `just ci` green.

## Guardrails

`just fmt-check`, `just lint`, `just test`, `just test-msrv`, `just deny`,
`just hooks` — all via `just ci`. CI gates the corpus through
`cargo nextest run --workspace`.

## Out of scope

- No production sanitizer changes: all five classes are already defended
  structurally. If a fixture had revealed a *gap*, that would be a separate
  issue per the AGENTS.md deferral rule — none did.
- No backfill of snapshots for the 26 pre-existing fixtures.
