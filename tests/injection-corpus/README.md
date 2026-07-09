# Adversarial injection corpus

Each subdirectory is one adversarial email fixture: an `input.eml` plus an
`expected.json` declaring the required and forbidden outputs of
`rimap_content::parse_message`. The corpus is the standing regression suite for
the content pipeline's prompt-injection and malformed-input defenses.

**The corpus only grows.** Every crash or divergence promoted from fuzzing, the
EPVME oracle, or a security review becomes a fixture here. Removing a fixture
requires an explicit rationale — a defense that no longer holds is a regression,
not cleanup.

## How it runs

- `crates/rimap-content/tests/injection_corpus.rs` **auto-discovers** every
  subdirectory containing an `expected.json` and asserts the declared
  properties. Adding a fixture directory is enough to have it exercised — run
  `just test-injection`.
- `crates/rimap-content/tests/snapshots.rs` holds an opt-in `insta` snapshot of
  a fixture's full `parse_message` output, so any sanitizer change surfaces as a
  reviewable diff. Register new fixtures there and commit the generated `.snap`.

## Authoring rules

- **`input.eml` must use CRLF (`\r\n`) line terminators.** The corpus is
  excluded from the pre-commit end-of-line fixer precisely so these bytes
  survive; header parsing depends on them. `expected.json` uses LF.
- Non-ASCII / control / bidi codepoints in `input.eml` are intentional — the
  corpus is excluded from the typo and whitespace hooks.

## `expected.json` fields

| Field | Meaning |
|-------|---------|
| `description` | What the fixture proves (required). |
| `expect` | `"ok"` (default) or `"error"`. |
| `must_contain` / `must_not_contain` | Substrings required / forbidden in `untrusted.body_text`. |
| `body_html_must_contain` / `body_html_must_not_contain` | Same, against `untrusted.body_html`. |
| `alternate_parts_must_contain` | Substring required in at least one `untrusted.alternate_parts` entry. |
| `warning_codes` / `forbidden_warning_codes` | Security-warning codes required / forbidden. |
| `meta` | Expected `attachment_count`, `mailing_list_present`, `body_truncated`. |
| `error_kind` | Required `ContentError` kind when `expect` is `"error"`. |

## Fixtures

### Parsing & MIME structure

| Fixture | Attack class |
|---------|--------------|
| `attachment-path-traversal` | Attachment filename with `../` traversal → rewritten, `parse_attachment_filename_rewritten`. |
| `attachment-filename-rfc2231` | RFC 2231 continuation + percent-encoded `../../etc/passwd` → decoded, rewritten. |
| `calendar-invite-injection` | `text/calendar` VEVENT `DESCRIPTION` injection quarantined as an attachment, absent from `body_text`. |
| `message-partial-fragment` | `message/partial` fragment quarantined as an attachment, never reassembled into `body_text`. |
| `mime-type-spoofing` | MZ-exe bytes declared `image/png` → `parse_mime_type_mismatch`. |
| `multipart-bomb` | MIME nesting past `MAX_MIME_DEPTH` → `ContentError::LimitExceeded`. |
| `nested-rfc822` | `message/rfc822` attachment not recursively parsed into `body_text`. |
| `oversized-body` | Body past `MAX_BODY_BYTES` → truncated, `parse_body_truncated`. |
| `pgp-signed-unsigned-sibling` | `multipart/signed` unsigned sibling payload surfaced under `untrusted` (`alternate_parts`), no trust elevation. |
| `rfc2047-crlf-smuggling` | RFC 2047 encoded-word with raw CRLF smuggling a `Bcc` → scrubbed, `parse_header_smuggling_blocked`. |

### Unicode & headers

| Fixture | Attack class |
|---------|--------------|
| `eai-raw-utf8-headers` | RFC 6532 raw-UTF-8 (EAI) headers with zero-width + bidi codepoints → stripped, both warnings fire. |
| `trojan-source-bidi` | Bidi override (RLO/PDF) in subject and body → stripped, `unicode_bidi_override_stripped`. |
| `zero-width-poisoning` | Zero-width codepoints in subject and body → stripped, `unicode_zero_width_stripped`. |

### HTML sanitization

| Fixture | Attack class |
|---------|--------------|
| `html-anchor-unparsable-href` | Unparsable anchor host while text claims `paypal.com` → `html_anchor_unparsable_href`. |
| `html-display-none` | `display:none` hidden `<div>` → excluded from `body_text`, hidden-content detected. |
| `html-offscreen-evasion` | Off-screen `left:-999px` / `translateX(-9999px)` → hidden-content detected. |
| `html-only-hidden-instructions` | HTML-only message with hidden `display:none` instructions → excluded and warned. |
| `html-remote-image-tracker` | 1×1 remote tracking pixel → `html_remote_image_stripped`. |
| `html-script-payload` | Inline `<script>` exfiltration payload → dropped, `html_script_stripped`. |
| `html-text-href-mismatch` | Anchor visible text vs `href` domain mismatch → `html_link_text_href_mismatch`. |
| `html-tokenizer-divergence` | Dual-engine (scraper/ammonia) probe; mixed-case `<SCRIPT>` stripped, no payload survives. |
| `html-white-on-white` | White-on-white hidden `<div>` → excluded, `html_hidden_content_detected`. |
| `multipart-alternative-html-homograph` | HTML alternative with homograph anchor + `<script>` → surfaced, sanitized, mixed-script fires. |

### Look-alike & homograph

| Fixture | Attack class |
|---------|--------------|
| `lookalike-filename-rlo-bidi` | Attachment filename with U+202E RLO disguising an `.exe` → `lookalike_filename_extension_spoof`. |
| `lookalike-homograph-paypal` | Cyrillic `а` homograph of `paypal.com` in `From`/`href` → mixed-script + idn-punycode. |
| `lookalike-idn-positive` | Legitimate IDN (`münchen.de`) → informational `lookalike_idn_punycode`, no false alarm. |
| `lookalike-idn-punycode` | Punycode A-label in `From` + matching body URL → per-site `lookalike_idn_punycode`. |
| `lookalike-reply-to-mismatch` | Cyrillic homograph of `paypal.com` in `Reply-To` → `lookalike_mixed_script`. |

### Baseline & negative (must stay clean)

| Fixture | Attack class |
|---------|--------------|
| `mailing-list` | Legitimate `List-*` headers → populate `meta.mailing_list`, zero warnings. |
| `multilingual-negative` | Legitimate multilingual mail (ja/ar/he/de) → zero warnings. |
| `prompt-injection-plaintext` | Plaintext injection body → passes through as untrusted content, zero warnings (content, not a pipeline attack). |
