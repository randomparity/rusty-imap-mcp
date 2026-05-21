//! Message parsing via `mail-parser`.
//!
//! This module owns all interaction with `mail-parser`; no other
//! module in `rimap-content` imports `mail-parser` types directly.
//! It applies hard limits declared as compile-time constants and
//! routes every extracted string through [`crate::unicode::sanitize`]
//! so downstream consumers see only Unicode-clean text.

use crate::error::ContentError;
use crate::lookalike;
use crate::output::{Content, SecurityWarning, Untrusted};

mod attachments;
mod bodies;
mod filename;
mod headers;
mod meta;
pub(crate) mod mime_scrub;
pub(crate) mod safe_parser;
mod sniff;

use crate::parse::bodies::extract_bodies;
use crate::parse::headers::{collect_header_domains, enforce_header_count};
use crate::parse::meta::extract_meta;
use crate::parse::mime_scrub::scrub_header_smuggling;

/// Maximum raw message size accepted. Messages larger than this are
/// rejected with [`ContentError::LimitExceeded`] with `kind = "message_bytes"`
/// before any parsing work is performed.
pub const MAX_MESSAGE_BYTES: usize = 25 * 1024 * 1024;

/// Maximum per-text-part size after sanitization.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Maximum total sanitized body bytes across `body_text` +
/// `alternate_parts`. Enforced in addition to the per-part
/// [`MAX_BODY_BYTES`] cap to prevent a multipart message from
/// producing a `Content` too large for the MCP stdio transport.
pub const MAX_TOTAL_BODY_BYTES: usize = 4 * 1024 * 1024;

/// Maximum per-header-value size after sanitization.
pub const MAX_HEADER_BYTES: usize = 8 * 1024;

/// Maximum MIME nesting depth. Exceeding this is a terminal error.
pub const MAX_MIME_DEPTH: usize = 8;

/// Maximum number of MIME parts (across all depths). Exceeding this
/// is a terminal error.
pub const MAX_MIME_PARTS: usize = 100;

/// Maximum number of headers. Exceeding this is a terminal error.
pub const MAX_HEADER_COUNT: usize = 256;

/// Parse a raw RFC 5322 message into a [`Content`] structure.
///
/// # Errors
///
/// - [`ContentError::LimitExceeded`] with `kind = "message_bytes"` when
///   `raw.len() > MAX_MESSAGE_BYTES`, and with other `kind` values when
///   MIME depth, part count, or header count exceed their hard limits.
/// - [`ContentError::Malformed`] if `mail-parser` rejects the byte stream.
/// - [`ContentError::ParserPanic`] when the underlying `mail-parser`
///   panics and is caught by the safe-parser wrapper.
pub fn parse_message(raw: &[u8]) -> Result<Content, ContentError> {
    if raw.len() > MAX_MESSAGE_BYTES {
        return Err(ContentError::LimitExceeded {
            kind: "message_bytes",
            limit: MAX_MESSAGE_BYTES,
        });
    }
    let original_size_bytes = raw.len() as u64;
    let mut warnings: Vec<SecurityWarning> = Vec::new();
    let scrubbed = scrub_header_smuggling(raw, &mut warnings);

    let message = safe_parser::safe_parse(&scrubbed)
        .map_err(|_| ContentError::ParserPanic)?
        .ok_or_else(|| ContentError::Malformed {
            reason: "mail-parser rejected byte stream".to_string(),
        })?;

    enforce_header_count(&message, &mut warnings)?;

    let mut meta = extract_meta(&message, original_size_bytes, &mut warnings);
    let bodies = extract_bodies(&message, &mut warnings)?;
    meta.body_truncated = bodies.body_truncated;
    let html_anchor_hrefs = bodies.anchor_hrefs;

    let mut content = Content {
        meta,
        untrusted: Untrusted {
            body_text: bodies.primary_text,
            body_html: bodies.body_html,
            alternate_parts: bodies.alternates,
        },
        security_warnings: warnings,
    };

    let header_domains = collect_header_domains(&message);
    let lookalike_warnings = lookalike::audit(&lookalike::LookalikeInput {
        meta: &content.meta,
        body_text: &content.untrusted.body_text,
        anchor_hrefs: &html_anchor_hrefs,
        header_domains,
    });
    content.security_warnings.extend(lookalike_warnings);

    Ok(content)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests may unwrap on constructed values")]
#[expect(clippy::panic, reason = "test failure paths")]
mod tests {
    use super::*;
    use crate::output::WarningCode;
    use crate::parse::filename::{contains_bidi_override, last_extension, sanitize_filename};
    use crate::parse::mime_scrub::{detect_smuggling_spans, find_header_end, split_header_lines};
    use crate::parse::sniff::{content_types_compatible, sniff_content_types};

    #[test]
    fn find_header_end_crlf() {
        let raw = b"From: a\r\nTo: b\r\n\r\nbody";
        let (end, sep) = find_header_end(raw).unwrap();
        assert_eq!(sep, 2);
        assert_eq!(&raw[..end], b"From: a\r\nTo: b\r\n");
        assert_eq!(&raw[end + sep..], b"body");
    }

    #[test]
    fn find_header_end_lf_only() {
        let raw = b"From: a\nTo: b\n\nbody";
        let (end, sep) = find_header_end(raw).unwrap();
        assert_eq!(sep, 1);
        assert_eq!(&raw[end + sep..], b"body");
    }

    #[test]
    fn find_header_end_none_when_no_blank() {
        let raw = b"From: a\r\nTo: b\r\n";
        assert!(find_header_end(raw).is_none());
    }

    #[test]
    fn split_header_lines_folds_continuations() {
        let raw = b"Subject: line one\r\n continuation\r\nFrom: a\r\n";
        let lines = split_header_lines(raw);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], b"Subject: line one\r\n continuation\r\n");
        assert_eq!(lines[1], b"From: a\r\n");
    }

    #[test]
    fn encoded_word_with_clean_content_is_not_smuggling() {
        let logical: Vec<&[u8]> = vec![b"Subject: =?utf-8?B?aGVsbG8=?=\r\n"];
        let mask = detect_smuggling_spans(&logical);
        assert_eq!(mask, vec![false]);
    }

    #[test]
    fn encoded_word_with_crlf_is_smuggling() {
        // Raw CR+LF injected inside an encoded-word, producing multiple
        // logical header lines where the `?=` terminator lands in a
        // later header than the opening `=?`.
        let logical: Vec<&[u8]> = vec![
            b"Subject: =?utf-8?B?aGVsbG8\r\n",
            b"Bcc: victim@example\r\n",
            b"?=\r\n",
        ];
        let mask = detect_smuggling_spans(&logical);
        assert_eq!(mask, vec![true, true, true]);
    }

    #[test]
    fn scrub_drops_smuggled_header_and_emits_warning() {
        let raw = b"From: a\r\nSubject: =?utf-8?B?x\r\nBcc: y@e\r\n?=\r\nTo: b\r\n\r\nbody";
        let mut warnings = Vec::new();
        let out = scrub_header_smuggling(raw, &mut warnings);
        let out_str = std::str::from_utf8(&out).unwrap();
        assert!(out_str.contains("From: a"));
        assert!(out_str.contains("To: b"));
        assert!(!out_str.contains("Bcc:"));
        assert!(!out_str.contains("Subject:"));
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].code, WarningCode::ParseHeaderSmugglingBlocked);
        assert!(
            warnings[0]
                .detail
                .as_deref()
                .unwrap_or("")
                .contains("names=[Subject"),
            "detail should include names=[Subject..., got: {:?}",
            warnings[0].detail
        );
    }

    #[test]
    fn scrub_clean_message_no_warnings() {
        let raw = b"From: a@example\r\nSubject: hello\r\n\r\nbody";
        let mut warnings = Vec::new();
        let out = scrub_header_smuggling(raw, &mut warnings);
        assert_eq!(out, raw);
        assert!(warnings.is_empty());
    }

    #[test]
    fn encoded_word_that_stays_in_one_line_is_legal() {
        let raw = b"From: a\r\nSubject: =?utf-8?B?aGVsbG8=?=\r\nTo: b\r\n\r\nbody";
        let mut warnings = Vec::new();
        let out = scrub_header_smuggling(raw, &mut warnings);
        let out_str = std::str::from_utf8(&out).unwrap();
        assert!(out_str.contains("Subject: =?utf-8?B?aGVsbG8=?="));
        assert!(out_str.contains("From: a"));
        assert!(out_str.contains("To: b"));
        assert!(warnings.is_empty());
    }

    #[test]
    fn dangling_encoded_word_is_dropped() {
        // =? with no matching ?= anywhere in headers.
        let raw = b"From: a\r\nSubject: =?utf-8?B?dangling\r\nTo: b\r\n\r\nbody";
        let mut warnings = Vec::new();
        let out = scrub_header_smuggling(raw, &mut warnings);
        let out_str = std::str::from_utf8(&out).unwrap();
        assert!(out_str.contains("From: a"));
        assert!(out_str.contains("To: b"));
        assert!(!out_str.contains("Subject:"));
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].code, WarningCode::ParseHeaderSmugglingBlocked);
    }

    #[test]
    fn dangling_encoded_word_at_last_header_is_dropped() {
        // Originating `=?` is the last logical header — the `Missing`
        // branch must still mark it even though there are no later
        // headers to search for `?=`.
        let raw = b"From: a\r\nSubject: =?utf-8?B?dangling\r\n\r\nbody";
        let mut warnings = Vec::new();
        let out = scrub_header_smuggling(raw, &mut warnings);
        let out_str = std::str::from_utf8(&out).unwrap();
        assert!(out_str.contains("From: a"));
        assert!(!out_str.contains("Subject:"));
        assert!(out_str.contains("body"));
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].code, WarningCode::ParseHeaderSmugglingBlocked);
    }

    #[test]
    fn legal_then_smuggled_encoded_word_in_same_header_drops_span() {
        // First `=?...?=` is a legal SameHeader match; the second `=?`
        // on the same header opens a smuggling span into later headers.
        // The detector's `scan_from` cursor must advance past the legal
        // token and still catch the second opener. The originating
        // header is dropped together with the span through `?=`.
        let raw = b"From: a\r\nSubject: =?utf-8?B?aGVsbG8=?= =?utf-8?B?x\r\nBcc: y@e\r\n?=\r\nTo: b\r\n\r\nbody";
        let mut warnings = Vec::new();
        let out = scrub_header_smuggling(raw, &mut warnings);
        let out_str = std::str::from_utf8(&out).unwrap();
        assert!(out_str.contains("From: a"));
        assert!(out_str.contains("To: b"));
        assert!(!out_str.contains("Subject:"));
        assert!(!out_str.contains("Bcc:"));
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].code, WarningCode::ParseHeaderSmugglingBlocked);
    }

    #[test]
    fn multiple_legal_encoded_words_in_one_header_are_not_flagged() {
        // Two legal SameHeader encoded-words in a single header line.
        // The `scan_from` cursor must advance past the first `?=` so the
        // second opener is detected and resolved correctly.
        let logical: Vec<&[u8]> = vec![b"Subject: =?utf-8?B?aA==?= =?utf-8?B?Yg==?=\r\n"];
        let mask = detect_smuggling_spans(&logical);
        assert_eq!(mask, vec![false]);
    }

    #[test]
    fn parse_extracts_from_to_subject() {
        let raw = b"From: Alice <alice@example.com>\r\n\
                    To: Bob <bob@example.com>\r\n\
                    Subject: Test message\r\n\
                    Date: Tue, 8 Apr 2026 12:00:00 +0000\r\n\
                    \r\n\
                    body text";
        let content = parse_message(raw).unwrap();
        assert_eq!(
            content.meta.from.as_deref(),
            Some("Alice <alice@example.com>")
        );
        assert_eq!(content.meta.to, vec!["Bob <bob@example.com>".to_string()]);
        assert_eq!(content.meta.subject.as_deref(), Some("Test message"));
        assert!(content.meta.date.is_some());
        assert!(content.security_warnings.is_empty());
    }

    #[test]
    fn parse_sanitizes_subject_zero_width() {
        let raw = "From: a@example\r\nSubject: he\u{200B}llo\r\n\r\nbody".as_bytes();
        let content = parse_message(raw).unwrap();
        assert_eq!(content.meta.subject.as_deref(), Some("hello"));
        assert!(
            content
                .security_warnings
                .iter()
                .any(|w| w.code == WarningCode::UnicodeZeroWidthStripped)
        );
    }

    #[test]
    fn parse_missing_headers_yields_none() {
        let raw = b"\r\nbody only";
        let content = parse_message(raw).unwrap();
        assert!(content.meta.from.is_none());
        assert!(content.meta.subject.is_none());
        assert_eq!(content.meta.original_size_bytes, raw.len() as u64);
    }

    #[test]
    fn parse_idn_u_label_address_emits_only_idn_informational() {
        // Raw UTF-8 U-label IDN (Russian "example.rf"). Sprint 4b's
        // lookalike pass classifies any IDN through `idna::domain_to_ascii`,
        // so a legitimate single-script Cyrillic domain produces an
        // informational `LookalikeIdnPunycode` warning but MUST NOT
        // produce a `LookalikeMixedScript` warning — pure Cyrillic is
        // single-script.
        let raw = "From: Тест <user@\u{043F}\u{0440}\u{0438}\u{043C}\u{0435}\u{0440}.\u{0440}\u{0444}>\r\n\
                   Subject: IDN baseline\r\n\
                   \r\n\
                   body"
            .as_bytes();
        let content = parse_message(raw).unwrap();
        assert!(content.meta.from.is_some());
        let from = content.meta.from.as_deref().unwrap();
        assert!(from.contains("\u{043F}\u{0440}\u{0438}\u{043C}\u{0435}\u{0440}.\u{0440}\u{0444}"));
        assert!(
            !content
                .security_warnings
                .iter()
                .any(|w| w.code == WarningCode::LookalikeMixedScript),
            "single-script Cyrillic IDN must not flag mixed-script, got {:?}",
            content.security_warnings
        );
        assert!(
            content
                .security_warnings
                .iter()
                .any(|w| w.code == WarningCode::LookalikeIdnPunycode),
            "expected informational LookalikeIdnPunycode, got {:?}",
            content.security_warnings
        );
    }

    #[test]
    fn parse_idn_a_label_address_emits_only_idn_informational() {
        // Punycode A-label form of the same Cyrillic domain. Pure ASCII
        // input, so NFKC and the codepoint filter pass it through; the
        // lookalike pass decodes the `xn--` labels and emits the same
        // informational `LookalikeIdnPunycode` warning, with no
        // mixed-script signal.
        let raw = b"From: Test <user@xn--e1afmkfd.xn--p1ai>\r\n\
                    Subject: IDN A-label baseline\r\n\
                    \r\n\
                    body";
        let content = parse_message(raw).unwrap();
        let from = content.meta.from.as_deref().unwrap();
        assert!(from.contains("xn--e1afmkfd.xn--p1ai"));
        assert!(
            !content
                .security_warnings
                .iter()
                .any(|w| w.code == WarningCode::LookalikeMixedScript),
            "punycode A-label of Cyrillic IDN must not flag mixed-script, got {:?}",
            content.security_warnings
        );
        assert!(
            content
                .security_warnings
                .iter()
                .any(|w| w.code == WarningCode::LookalikeIdnPunycode),
            "expected informational LookalikeIdnPunycode, got {:?}",
            content.security_warnings
        );
    }

    #[test]
    fn parse_extracts_text_plain_body() {
        let raw = b"From: a@example\r\n\
                    Content-Type: text/plain; charset=utf-8\r\n\
                    \r\n\
                    hello world";
        let content = parse_message(raw).unwrap();
        assert_eq!(content.untrusted.body_text, "hello world");
        assert!(content.untrusted.alternate_parts.is_empty());
        assert!(!content.meta.body_truncated);
    }

    #[test]
    fn parse_multipart_alternative_picks_text_plain_first() {
        let raw = b"From: a@example\r\n\
                    Content-Type: multipart/alternative; boundary=\"BOUND\"\r\n\
                    \r\n\
                    --BOUND\r\n\
                    Content-Type: text/plain; charset=utf-8\r\n\
                    \r\n\
                    plain version\r\n\
                    --BOUND\r\n\
                    Content-Type: text/html; charset=utf-8\r\n\
                    \r\n\
                    <p>html version</p>\r\n\
                    --BOUND--\r\n";
        let content = parse_message(raw).unwrap();
        assert_eq!(content.untrusted.body_text, "plain version");
        assert!(!content.untrusted.body_text.contains("<p>"));
    }

    #[test]
    fn content_html_only_populates_body_html_and_body_text() {
        let raw = b"From: a@example\r\n\
                    Content-Type: text/html; charset=utf-8\r\n\
                    \r\n\
                    <html><body><p>visible text</p></body></html>\r\n";
        let content = parse_message(raw).unwrap();
        assert_eq!(content.untrusted.body_text, "visible text");
        assert!(content.untrusted.body_html.is_some());
        let body_html = content.untrusted.body_html.as_deref().unwrap();
        assert!(body_html.contains("<p>"));
        assert!(body_html.contains("visible text"));
    }

    #[test]
    fn content_html_only_with_hidden_content_emits_warning() {
        let raw = b"From: a@example\r\n\
                    Content-Type: text/html; charset=utf-8\r\n\
                    \r\n\
                    <html><body><p>ok</p>\
                    <div style=\"display:none\">hidden</div></body></html>\r\n";
        let content = parse_message(raw).unwrap();
        assert!(
            content
                .security_warnings
                .iter()
                .any(|w| matches!(w.code, WarningCode::HtmlHiddenContentDetected)),
            "expected HtmlHiddenContentDetected warning, got {:?}",
            content.security_warnings
        );
        assert!(!content.untrusted.body_text.contains("hidden"));
    }

    #[test]
    fn parse_oversized_body_emits_truncation_warning() {
        let mut raw = Vec::from(
            &b"From: a@example\r\n\
               Content-Type: text/plain; charset=utf-8\r\n\
               \r\n"[..],
        );
        raw.extend(std::iter::repeat_n(b'x', MAX_BODY_BYTES + 1024));
        let content = parse_message(&raw).unwrap();
        assert!(content.meta.body_truncated);
        assert!(
            content
                .security_warnings
                .iter()
                .any(|w| w.code == WarningCode::ParseBodyTruncated)
        );
        assert!(content.untrusted.body_text.len() <= MAX_BODY_BYTES);
    }

    #[test]
    fn parse_enforces_aggregate_body_cap() {
        let mut raw = String::from(
            "From: a@example\r\n\
             Content-Type: multipart/mixed; boundary=\"BOUND\"\r\n\
             \r\n",
        );
        let part = "a".repeat(512 * 1024);
        for _ in 0..10 {
            raw.push_str("--BOUND\r\nContent-Type: text/plain\r\n\r\n");
            raw.push_str(&part);
            raw.push_str("\r\n");
        }
        raw.push_str("--BOUND--\r\n");
        let content = parse_message(raw.as_bytes()).unwrap();
        let total = content.untrusted.body_text.len()
            + content
                .untrusted
                .alternate_parts
                .iter()
                .map(String::len)
                .sum::<usize>();
        assert!(
            total <= MAX_TOTAL_BODY_BYTES,
            "total={total} cap={MAX_TOTAL_BODY_BYTES}"
        );
        assert!(content.meta.body_truncated);
        assert!(
            content
                .security_warnings
                .iter()
                .any(|w| w.location.as_deref() == Some("body:aggregate"))
        );
    }

    #[test]
    fn parse_extracts_attachment_metadata() {
        let raw = b"From: a@example\r\n\
                    Content-Type: multipart/mixed; boundary=\"BOUND\"\r\n\
                    \r\n\
                    --BOUND\r\n\
                    Content-Type: text/plain\r\n\
                    \r\n\
                    hello\r\n\
                    --BOUND\r\n\
                    Content-Type: image/png\r\n\
                    Content-Disposition: attachment; filename=\"pic.png\"\r\n\
                    Content-Transfer-Encoding: base64\r\n\
                    \r\n\
                    iVBORw0KGgo=\r\n\
                    --BOUND--\r\n";
        let content = parse_message(raw).unwrap();
        assert_eq!(content.meta.attachments.len(), 1);
        let att = &content.meta.attachments[0];
        assert_eq!(att.filename.as_deref(), Some("pic.png"));
        assert_eq!(att.content_type, "image/png");
        assert!(
            !content
                .security_warnings
                .iter()
                .any(|w| w.code == WarningCode::ParseMimeTypeMismatch)
        );
    }

    #[test]
    fn parse_detects_mime_type_spoofing() {
        let raw = b"From: a@example\r\n\
                    Content-Type: multipart/mixed; boundary=\"BOUND\"\r\n\
                    \r\n\
                    --BOUND\r\n\
                    Content-Type: text/plain\r\n\
                    \r\n\
                    hello\r\n\
                    --BOUND\r\n\
                    Content-Type: image/png\r\n\
                    Content-Disposition: attachment; filename=\"fake.png\"\r\n\
                    Content-Transfer-Encoding: base64\r\n\
                    \r\n\
                    TVqQAAMAAAA=\r\n\
                    --BOUND--\r\n";
        let content = parse_message(raw).unwrap();
        assert!(
            content
                .security_warnings
                .iter()
                .any(|w| w.code == WarningCode::ParseMimeTypeMismatch)
        );
    }

    #[test]
    fn sniff_detects_elf() {
        assert_eq!(
            sniff_content_types(b"\x7fELFblah"),
            vec!["application/x-elf"]
        );
    }

    #[test]
    fn sniff_detects_macho_64bit_le() {
        assert_eq!(
            sniff_content_types(b"\xcf\xfa\xed\xfeblah"),
            vec!["application/x-mach-binary"]
        );
    }

    #[test]
    fn sniff_detects_macho_fat_binary() {
        assert_eq!(
            sniff_content_types(b"\xca\xfe\xba\xbeblah"),
            vec!["application/x-mach-binary"]
        );
    }

    #[test]
    fn sniff_detects_7z() {
        assert_eq!(
            sniff_content_types(b"7z\xbc\xaf\x27\x1cblah"),
            vec!["application/x-7z-compressed"]
        );
    }

    #[test]
    fn sniff_detects_ole2() {
        assert_eq!(
            sniff_content_types(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1blah"),
            vec!["application/x-ole-storage"]
        );
    }

    #[test]
    fn sniff_empty_for_unknown() {
        assert!(sniff_content_types(b"random text").is_empty());
    }

    #[test]
    fn content_types_octet_stream_no_longer_wildcard() {
        // application/octet-stream is no longer compatible with a specific
        // sniffed type — the caller handles the "sniff empty" case separately.
        assert!(!content_types_compatible(
            "application/octet-stream",
            "application/x-msdownload"
        ));
    }

    #[test]
    fn content_types_openxml_still_compatible_with_zip() {
        assert!(content_types_compatible(
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "application/zip",
        ));
    }

    #[test]
    fn content_types_exact_match() {
        assert!(content_types_compatible("image/png", "image/png"));
        assert!(content_types_compatible("IMAGE/PNG", "image/png"));
    }

    #[test]
    fn parse_extracts_mailing_list_headers() {
        let raw = b"From: announce@example\r\n\
                    List-ID: <dev.example.com>\r\n\
                    List-Unsubscribe: <mailto:unsub@example>\r\n\
                    List-Post: <mailto:dev@example>\r\n\
                    \r\n\
                    body";
        let content = parse_message(raw).unwrap();
        let ml = content.meta.mailing_list.unwrap();
        assert!(
            ml.list_id
                .as_deref()
                .unwrap_or("")
                .contains("dev.example.com")
        );
        assert!(
            ml.list_unsubscribe
                .as_deref()
                .unwrap_or("")
                .contains("unsub@example")
        );
        assert!(
            ml.list_post
                .as_deref()
                .unwrap_or("")
                .contains("dev@example")
        );
    }

    #[test]
    fn parse_no_mailing_list_when_headers_absent() {
        let raw = b"From: a@example\r\n\r\nbody";
        let content = parse_message(raw).unwrap();
        assert!(content.meta.mailing_list.is_none());
    }

    #[test]
    fn parse_rejects_oversize_message() {
        let mut raw = Vec::from(&b"From: a@example\r\n\r\n"[..]);
        raw.resize(MAX_MESSAGE_BYTES + 1, b'x');
        let err = parse_message(&raw).unwrap_err();
        let ContentError::LimitExceeded { kind, limit } = err else {
            panic!("expected LimitExceeded message_bytes, got {err:?}");
        };
        assert_eq!(kind, "message_bytes");
        assert_eq!(limit, MAX_MESSAGE_BYTES);
    }

    #[test]
    fn parse_accepts_message_at_max_message_bytes() {
        // Kills `> with >=` on `raw.len() > MAX_MESSAGE_BYTES`. With `>`,
        // a 25 MiB raw is below-or-equal and proceeds to parse (may
        // produce non-fatal warnings or a body LimitExceeded later); the
        // `>=` mutant errors immediately with `kind = "message_bytes"`.
        let mut raw = Vec::from(&b"From: a@example\r\nContent-Type: text/plain\r\n\r\n"[..]);
        raw.resize(MAX_MESSAGE_BYTES, b'x');
        let result = parse_message(&raw);
        match result {
            Ok(_) => (),
            Err(ContentError::LimitExceeded { kind, .. }) => {
                assert_ne!(
                    kind, "message_bytes",
                    "must not error with kind=message_bytes at exactly MAX_MESSAGE_BYTES",
                );
            }
            Err(other) => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn parse_keeps_long_subject_within_max_header_bytes() {
        // Kills `* with +` on `MAX_HEADER_BYTES = 8 * 1024`. The mutant
        // flips the constant to 8 + 1024 = 1032, well below 8 KiB. A
        // Subject of 5000 ASCII bytes round-trips intact under the
        // 8 KiB cap but gets sliced to ~1032 bytes under the mutant.
        let long = "a".repeat(5000);
        let raw = format!("From: a@example\r\nSubject: {long}\r\n\r\nbody");
        let content = parse_message(raw.as_bytes()).unwrap();
        let subject = content.meta.subject.unwrap();
        assert!(
            subject.len() >= 5000,
            "subject must round-trip ~5000 bytes under MAX_HEADER_BYTES=8192, got {} bytes",
            subject.len(),
        );
    }

    #[test]
    fn parse_rejects_mime_depth_bomb() {
        // Build 12 properly nested multipart containers. Each level's
        // boundary opens a child whose own Content-Type declares the
        // next level's boundary.
        use std::fmt::Write as _;
        let depth = 12;
        let mut raw = String::from("From: a@example\r\n");
        raw.push_str("Content-Type: multipart/mixed; boundary=\"B0\"\r\n\r\n");
        for i in 0..depth - 1 {
            write!(raw, "--B{i}\r\n").unwrap();
            write!(
                raw,
                "Content-Type: multipart/mixed; boundary=\"B{}\"\r\n\r\n",
                i + 1
            )
            .unwrap();
        }
        write!(raw, "--B{}\r\n", depth - 1).unwrap();
        raw.push_str("Content-Type: text/plain\r\n\r\ninner\r\n");
        for i in (0..depth).rev() {
            write!(raw, "--B{i}--\r\n").unwrap();
        }
        let err = parse_message(raw.as_bytes()).unwrap_err();
        let ContentError::LimitExceeded { kind, .. } = err else {
            panic!("expected LimitExceeded, got {err:?}");
        };
        assert!(
            kind == "mime_depth" || kind == "mime_parts",
            "expected mime_depth or mime_parts, got {kind}"
        );
    }

    #[test]
    fn sanitize_filename_strips_path_separators() {
        let (out, rewritten) = sanitize_filename("../../etc/passwd", 0);
        assert!(!out.contains('/'));
        assert!(!out.contains(".."));
        assert!(rewritten);
    }

    #[test]
    fn sanitize_filename_strips_backslash_traversal() {
        let (out, rewritten) = sanitize_filename("..\\..\\Windows\\System32\\evil.dll", 0);
        assert!(!out.contains('\\'));
        assert!(!out.contains(".."));
        assert!(rewritten);
    }

    #[test]
    fn sanitize_filename_prefixes_reserved_windows_names() {
        let (out, rewritten) = sanitize_filename("CON.txt", 0);
        assert_eq!(out, "_CON.txt");
        assert!(rewritten);
    }

    #[test]
    fn sanitize_filename_trims_trailing_dots_and_spaces() {
        let (out, rewritten) = sanitize_filename("report.pdf. . ", 0);
        assert_eq!(out, "report.pdf");
        assert!(rewritten);
    }

    #[test]
    fn sanitize_filename_empty_fallback() {
        let (out, rewritten) = sanitize_filename("...", 7);
        assert_eq!(out, "attachment_7");
        assert!(rewritten);
    }

    #[test]
    fn sanitize_filename_clean_passes_through() {
        let (out, rewritten) = sanitize_filename("invoice-2026-04.pdf", 0);
        assert_eq!(out, "invoice-2026-04.pdf");
        assert!(!rewritten);
    }

    #[test]
    fn lookalike_homograph_anchor_fires_via_parse_message() {
        // HTML body with an anchor whose href domain mixes Latin with a
        // Cyrillic 'а' (U+0430). `parse_message` must invoke
        // `lookalike::audit` and surface a `LookalikeMixedScript`
        // warning located at `html:anchor_href`.
        let raw = "From: a@example\r\n\
                   Content-Type: text/html; charset=utf-8\r\n\
                   \r\n\
                   <html><body><a href=\"https://p\u{0430}ypal.com/login\">click</a></body></html>\r\n"
            .as_bytes();
        let content = parse_message(raw).unwrap();
        assert!(
            content.security_warnings.iter().any(|w| {
                w.code == WarningCode::LookalikeMixedScript
                    && w.location.as_deref() == Some("html:anchor_href")
            }),
            "expected LookalikeMixedScript at html:anchor_href, got {:?}",
            content.security_warnings
        );
    }

    #[test]
    fn contains_bidi_override_detects_rlo() {
        assert!(contains_bidi_override("invoice\u{202E}gpj.exe"));
        assert!(!contains_bidi_override("invoice.pdf"));
    }

    #[test]
    fn last_extension_returns_after_final_dot() {
        assert_eq!(last_extension("file.tar.gz"), Some("gz"));
        assert_eq!(last_extension("noext"), None);
        assert_eq!(last_extension(".hidden"), Some("hidden"));
    }

    #[test]
    fn attachment_with_rlo_bidi_extension_emits_lookalike_warning() {
        // Filename "resume_CV<RLO>gpj.exe" — visually renders as
        // "resume_CVexe.jpg" after right-to-left override is applied.
        let raw = "From: a@example\r\n\
                   Content-Type: multipart/mixed; boundary=\"BOUND\"\r\n\
                   \r\n\
                   --BOUND\r\n\
                   Content-Type: text/plain\r\n\
                   \r\n\
                   hello\r\n\
                   --BOUND\r\n\
                   Content-Type: application/octet-stream\r\n\
                   Content-Disposition: attachment; filename=\"resume_CV\u{202E}gpj.exe\"\r\n\
                   Content-Transfer-Encoding: base64\r\n\
                   \r\n\
                   AAAA\r\n\
                   --BOUND--\r\n"
            .as_bytes();
        let content = parse_message(raw).unwrap();
        assert!(
            content.security_warnings.iter().any(|w| {
                w.code == WarningCode::LookalikeFilenameExtensionSpoof
                    && w.location.as_deref() == Some("attachment[0]:filename")
            }),
            "expected LookalikeFilenameExtensionSpoof at attachment[0]:filename, got {:?}",
            content.security_warnings
        );
    }

    #[test]
    fn from_header_with_bidi_domain_emits_homograph_warning() {
        // RLO codepoint embedded in the From: header domain. Detection
        // must fire BEFORE the unicode sanitize pass strips the bidi
        // char, so it lives in `audit_addr_domain_bidi` at the raw-Addr
        // boundary.
        let raw = "From: Bob <bob@exa\u{202E}mple.com>\r\n\
                   Subject: hi\r\n\
                   \r\n\
                   body"
            .as_bytes();
        let content = parse_message(raw).unwrap();
        assert!(
            content.security_warnings.iter().any(|w| {
                w.code == WarningCode::LookalikeHomographDomain
                    && w.location.as_deref() == Some("header:from")
                    && w.detail
                        .as_deref()
                        .unwrap_or("")
                        .contains("reason=bidi_pre_strip")
            }),
            "expected LookalikeHomographDomain bidi_pre_strip at header:from, got {:?}",
            content.security_warnings
        );
    }

    #[test]
    fn nested_rfc822_attachment_reports_nonzero_size() {
        let raw = b"From: a@example\r\n\
                    Content-Type: multipart/mixed; boundary=\"BOUND\"\r\n\
                    \r\n\
                    --BOUND\r\n\
                    Content-Type: text/plain\r\n\
                    \r\n\
                    outer\r\n\
                    --BOUND\r\n\
                    Content-Type: message/rfc822\r\n\
                    Content-Disposition: attachment\r\n\
                    \r\n\
                    From: inner@example\r\n\
                    Subject: nested\r\n\
                    \r\n\
                    inner body\r\n\
                    --BOUND--\r\n";
        let content = parse_message(raw).unwrap();
        assert_eq!(content.meta.attachments.len(), 1);
        assert!(content.meta.attachments[0].size_bytes > 0);
    }

    #[test]
    fn double_extension_pdf_exe_fires_spoof_warning() {
        let eml = b"From: test@example.com\r\n\
            Subject: invoice\r\n\
            MIME-Version: 1.0\r\n\
            Content-Type: multipart/mixed; boundary=\"bound\"\r\n\
            \r\n\
            --bound\r\n\
            Content-Type: text/plain\r\n\
            \r\n\
            See attached.\r\n\
            --bound\r\n\
            Content-Type: application/octet-stream\r\n\
            Content-Disposition: attachment; filename=\"invoice.pdf.exe\"\r\n\
            Content-Transfer-Encoding: base64\r\n\
            \r\n\
            AAAA\r\n\
            --bound--\r\n";
        let content = parse_message(eml).unwrap();
        assert!(
            content.security_warnings.iter().any(|w| {
                w.code == WarningCode::LookalikeFilenameExtensionSpoof
                    && w.detail
                        .as_deref()
                        .is_some_and(|d| d.contains("double_extension"))
            }),
            "expected LookalikeFilenameExtensionSpoof with double_extension, \
             got {:?}",
            content.security_warnings
        );
    }

    #[test]
    fn reply_to_extracted_into_meta() {
        let eml = b"From: sender@example.com\r\n\
            Reply-To: reply@different.com\r\n\
            To: recipient@example.com\r\n\
            Subject: test\r\n\
            \r\n\
            body\r\n";
        let content = parse_message(eml).unwrap();
        assert_eq!(
            content.meta.reply_to.as_deref(),
            Some("reply@different.com")
        );
    }

    #[test]
    fn reply_to_bidi_override_emits_warning() {
        let eml = "From: sender@example.com\r\n\
             Reply-To: attacker@evil\u{202E}.com\r\n\
             To: recipient@example.com\r\n\
             Subject: test\r\n\
             \r\n\
             body\r\n";
        let content = parse_message(eml.as_bytes()).unwrap();
        assert!(
            content.security_warnings.iter().any(|w| {
                w.code == WarningCode::LookalikeHomographDomain
                    && w.location.as_deref() == Some("header:reply_to")
            }),
            "expected LookalikeHomographDomain on reply_to, got {:?}",
            content.security_warnings
        );
    }

    #[test]
    fn single_extension_does_not_fire_double_extension() {
        let eml = b"From: test@example.com\r\n\
            Subject: file\r\n\
            MIME-Version: 1.0\r\n\
            Content-Type: multipart/mixed; boundary=\"bound\"\r\n\
            \r\n\
            --bound\r\n\
            Content-Type: text/plain\r\n\
            \r\n\
            See attached.\r\n\
            --bound\r\n\
            Content-Type: application/pdf\r\n\
            Content-Disposition: attachment; filename=\"invoice.pdf\"\r\n\
            Content-Transfer-Encoding: base64\r\n\
            \r\n\
            AAAA\r\n\
            --bound--\r\n";
        let content = parse_message(eml).unwrap();
        assert!(
            !content.security_warnings.iter().any(|w| {
                w.code == WarningCode::LookalikeFilenameExtensionSpoof
                    && w.detail
                        .as_deref()
                        .is_some_and(|d| d.contains("double_extension"))
            }),
            "single extension should not fire double_extension spoof"
        );
    }
}
