//! Seed fixtures used by the wire-driven e2e tests. Constants and
//! builders live here so the seed bytes and the assertion-side bytes
//! reference the same source — no "what was seeded" / "what to check"
//! duplication.
//!
//! `e2e_wire.rs` uses every public item below. `e2e.rs` pulls this
//! module in through `support/dovecot/mod.rs` but never references the
//! items — see [`force_use_for_dead_code_link`] for the per-binary dead-code suppression.

/// Filename declared in the attachment's `Content-Disposition`.
pub const ATTACHMENT_FILENAME: &str = "attached.bin";

/// Known byte payload of the attachment. 32 deterministic bytes —
/// large enough that an off-by-one in part extraction is visible, small
/// enough to print in test panic messages.
pub const ATTACHMENT_BYTES: &[u8] = &[
    0x52, 0x49, 0x4d, 0x41, 0x50, 0x2d, 0x50, 0x33, 0x2d, 0x41, 0x54, 0x54, 0x41, 0x43, 0x48, 0x45,
    0x44, 0x2d, 0x42, 0x59, 0x54, 0x45, 0x53, 0x2d, 0x32, 0x30, 0x32, 0x36, 0x2d, 0x30, 0x35, 0x12,
];

/// MIME boundary for the multipart container. Fixed so the message
/// bytes are deterministic across runs.
const BOUNDARY: &str = "rimap-p3-boundary-c0ffee";

/// Plain-text body content. Asserted by `fetch_message` in the wire flow.
pub const PLAIN_BODY: &str = "Hello from the Phase 3 wire-driven e2e smoke test.";

/// Returns the raw bytes of a `multipart/mixed` MIME message suitable
/// for `Connection::append_message`. Contains one `text/plain` part
/// with `PLAIN_BODY` and one `application/octet-stream` attachment
/// part with filename `ATTACHMENT_FILENAME` and payload `ATTACHMENT_BYTES`.
///
/// The filename is duplicated in both the `Content-Type` `name`
/// parameter and `Content-Disposition` `filename` parameter. IMAP
/// BODYSTRUCTURE only exposes the Content-Type params dict, so the
/// `list_attachments` tool reads the filename from there (see
/// `crates/rimap-server/src/tools/retrieval/list_attachments.rs::extract_filename`);
/// repeating the value in Content-Disposition matches what real-world
/// clients send and keeps the fixture forwards-compatible with a
/// future server-side parser that walks the disposition field.
///
/// The Content-Transfer-Encoding for the attachment is `base64`. The
/// returned bytes are CRLF-terminated as required by RFC 5322.
#[expect(clippy::expect_used, reason = "test fixture; base64 output is ASCII")]
pub fn multipart_with_attachment() -> Vec<u8> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    let attachment_b64 = STANDARD.encode(ATTACHMENT_BYTES);
    let mut wrapped = String::new();
    // 76-char lines per RFC 2045.
    for chunk in attachment_b64.as_bytes().chunks(76) {
        let chunk_str = std::str::from_utf8(chunk).expect("base64 output is always valid ASCII");
        wrapped.push_str(chunk_str);
        wrapped.push_str("\r\n");
    }

    let body = format!(
        "From: sender@example.com\r\n\
         To: rimap-test@localhost\r\n\
         Subject: e2e-wire-test-smoke\r\n\
         Date: Sat, 12 May 2026 10:00:00 +0000\r\n\
         Message-ID: <e2e-wire-smoke-001@example.com>\r\n\
         MIME-Version: 1.0\r\n\
         Content-Type: multipart/mixed; boundary=\"{BOUNDARY}\"\r\n\
         \r\n\
         --{BOUNDARY}\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Transfer-Encoding: 7bit\r\n\
         \r\n\
         {PLAIN_BODY}\r\n\
         --{BOUNDARY}\r\n\
         Content-Type: application/octet-stream; name=\"{ATTACHMENT_FILENAME}\"\r\n\
         Content-Disposition: attachment; filename=\"{ATTACHMENT_FILENAME}\"\r\n\
         Content-Transfer-Encoding: base64\r\n\
         \r\n\
         {wrapped}\
         --{BOUNDARY}--\r\n",
    );

    body.into_bytes()
}

/// Subject of the HTML fixture. Distinct from the plain fixture's
/// subject so the full-posture `advanced_query` round-trip can target it
/// with a raw IMAP `SUBJECT` key.
pub const HTML_SUBJECT: &str = "e2e-wire-html-body";

/// Distinctive token embedded in the `text/html` body of
/// [`html_body_message`]. Wrapped in safe markup that the content
/// sanitizer preserves, so `fetch_message` with `include_html = true`
/// returns a `body_html` still containing it.
pub const HTML_MARKER: &str = "e2e-wire-html-marker";

/// Returns the raw bytes of a `text/html` MIME message whose body carries
/// [`HTML_MARKER`] inside safe markup. Suitable for
/// `Connection::append_message`.
///
/// Exercises the full-posture `fetch_message.include_html` capability
/// end-to-end: the HTML part is what makes `body_html` non-empty once the
/// server-side sanitizer runs (`fetch_message` derives a plain `body_text`
/// from the same HTML). The subject is [`HTML_SUBJECT`] so the companion
/// `search.advanced_query` round-trip can locate it with a raw IMAP
/// `SUBJECT` key.
///
/// This is an HTML-only message rather than `multipart/alternative`: the
/// content parser only surfaces `body_html` for the message's primary
/// displayable body, and in a `multipart/alternative` the `text/plain`
/// part wins that slot, leaving the HTML alternative unsurfaced (see
/// `rimap-content` `parse_multipart_alternative_picks_text_plain_first`).
/// Bytes are CRLF-terminated as required by RFC 5322.
pub fn html_body_message() -> Vec<u8> {
    let body = format!(
        "From: sender@example.com\r\n\
         To: rimap-test@localhost\r\n\
         Subject: {HTML_SUBJECT}\r\n\
         Date: Sat, 12 May 2026 11:00:00 +0000\r\n\
         Message-ID: <e2e-wire-html-body-001@example.com>\r\n\
         MIME-Version: 1.0\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Transfer-Encoding: 7bit\r\n\
         \r\n\
         <html><body><p>Rich body for the e2e round-trip: \
         <strong>{HTML_MARKER}</strong></p></body></html>\r\n",
    );

    body.into_bytes()
}

/// Per-binary dead-code suppression. `e2e.rs` compiles this module
/// through `support/dovecot/mod.rs` but never calls any item here; if
/// we relied on `#![expect(dead_code)]` instead, that expectation
/// would be unfulfilled in `e2e_wire.rs` (which does use them) and
/// `clippy::allow_attributes = "deny"` forbids `#[allow]`. Referencing
/// each public item inside a never-called function marks them as used
/// in every compilation unit. The function name omits the leading `_`
/// so the function itself is flagged dead and the `#[expect]` is
/// fulfilled.
#[expect(
    dead_code,
    reason = "type-link to suppress per-binary dead-code in e2e.rs"
)]
fn force_use_for_dead_code_link() {
    let _: &str = ATTACHMENT_FILENAME;
    let _: &[u8] = ATTACHMENT_BYTES;
    let _: &str = PLAIN_BODY;
    let _: &str = HTML_SUBJECT;
    let _: &str = HTML_MARKER;
    let _ = multipart_with_attachment;
    let _ = html_body_message;
}
