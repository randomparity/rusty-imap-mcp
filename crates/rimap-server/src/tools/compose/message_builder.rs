//! Shared RFC 5322 message construction for `create_draft` and `send_email`.
//!
//! Extracted from `create_draft` to avoid duplication. Both tool handlers
//! call `build_message_headers` and `apply_threading_headers`; only the
//! delivery step differs (IMAP APPEND vs SMTP send).

use mail_builder::MessageBuilder;
use mail_builder::headers::address::Address;
use mail_builder::headers::content_type::ContentType;
use mail_builder::headers::message_id::MessageId;
use mail_builder::mime::MimePart;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::boot::registry::AccountState;

/// An email address with optional display name.
#[derive(Debug, Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct AddressInput {
    /// Display name (optional).
    pub name: Option<String>,
    /// Email address.
    pub address: String,
}

pub(crate) const MAX_RECIPIENTS: usize = 100;
pub(crate) const MAX_SUBJECT_LEN: usize = 1000;
pub(crate) const MAX_BODY_BYTES: usize = 1_048_576;
pub(crate) const MAX_REFERENCES: usize = 50;

/// Maximum number of attachments on a single composed message.
pub(crate) const MAX_ATTACHMENTS: usize = 20;

/// Per-file read cap for a sandbox-sourced attachment. A sandbox file larger
/// than this is rejected without being fully read (see
/// [`crate::tools::retrieval::sandbox::read_sandboxed_file`]).
pub(crate) const MAX_ATTACHMENT_BYTES: usize = 10 * 1_048_576;

/// Total composed-message budget: `body_text` plus the sum of attachment sizes
/// (raw bytes, before base64 inflation). Keeps a single message within common
/// MTA limits and bounds server memory.
pub(crate) const MAX_TOTAL_MESSAGE_BYTES: usize = 25 * 1_048_576;

/// Upper bound on the size of the original message a `forward` will
/// re-send. The fetched message is base64-wrapped as a `message/rfc822`
/// part (≈ +33% on the wire), so this raw cap keeps the outgoing message
/// within common MTA limits while bounding server memory.
pub(crate) const MAX_FORWARD_ORIGINAL_BYTES: usize = 25 * 1_048_576;

/// A single attachment sourced from the download sandbox.
///
/// `path` must resolve inside the shared download-sandbox root; the bytes are
/// read via the sandbox containment primitive. The trust boundary is the shared
/// root: an agent can attach any file the server itself downloaded/exported or
/// the operator placed there, never an arbitrary host path.
#[derive(Debug, Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct AttachmentInput {
    /// Path to a file within the download-sandbox root.
    pub path: String,
    /// Override attachment name. Defaults to the file's basename. Reduced to a
    /// basename regardless, so caller path separators are never emitted.
    pub filename: Option<String>,
    /// MIME content type. Defaults to a magic-byte sniff, then
    /// `application/octet-stream`.
    pub content_type: Option<String>,
}

/// Common input fields shared by `create_draft` and `send_email`.
#[derive(Debug, Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct ComposeInput {
    /// Recipient addresses.
    pub to: Vec<AddressInput>,
    /// CC addresses.
    pub cc: Option<Vec<AddressInput>>,
    /// BCC addresses.
    pub bcc: Option<Vec<AddressInput>>,
    /// Email subject.
    pub subject: String,
    /// Plain text body. Always sent, and used as the `text/plain` alternative
    /// when `body_html` is present.
    pub body_text: String,
    /// Optional sanitized HTML body. When present, the message is
    /// `multipart/alternative` (text first, sanitized HTML second). Requires
    /// `full` posture for `create_draft` (`create_draft.include_html`).
    pub body_html: Option<String>,
    /// Attachments sourced from the download sandbox.
    pub attachments: Option<Vec<AttachmentInput>>,
    /// UID of message to reply to (for threading headers).
    #[serde(
        default,
        deserialize_with = "crate::tools::lenient_int::deserialize_opt_nonzero_u32"
    )]
    #[schemars(schema_with = "crate::tools::lenient_int::schema_opt_nonzero_u32")]
    pub in_reply_to_uid: Option<core::num::NonZeroU32>,
    /// Folder containing the message to reply to (default INBOX).
    pub in_reply_to_folder: Option<String>,
}

/// Validate all user-supplied fields in a compose input.
pub(crate) fn validate_compose_input(input: &ComposeInput) -> Result<(), rimap_core::RimapError> {
    if input.to.is_empty() {
        return Err(rimap_core::RimapError::invalid_input(
            "at least one To recipient is required",
        ));
    }

    let total_recipients = input.to.len()
        + input.cc.as_ref().map_or(0, Vec::len)
        + input.bcc.as_ref().map_or(0, Vec::len);
    if total_recipients > MAX_RECIPIENTS {
        return Err(rimap_core::RimapError::invalid_input(format!(
            "too many recipients ({total_recipients}); max is {MAX_RECIPIENTS}"
        )));
    }

    if input.subject.len() > MAX_SUBJECT_LEN {
        return Err(rimap_core::RimapError::invalid_input(format!(
            "subject too long ({} bytes); max is {MAX_SUBJECT_LEN}",
            input.subject.len()
        )));
    }

    if input.body_text.len() > MAX_BODY_BYTES {
        return Err(rimap_core::RimapError::invalid_input(format!(
            "body_text too large ({} bytes); max is {MAX_BODY_BYTES}",
            input.body_text.len()
        )));
    }

    if let Some(html) = input.body_html.as_deref().filter(|h| !h.is_empty())
        && html.len() > MAX_BODY_BYTES
    {
        return Err(rimap_core::RimapError::invalid_input(format!(
            "body_html too large ({} bytes); max is {MAX_BODY_BYTES}",
            html.len()
        )));
    }

    if let Some(attachments) = &input.attachments {
        validate_attachments(attachments)?;
    }

    validate_addresses("To", &input.to)?;
    if let Some(cc) = &input.cc {
        validate_addresses("CC", cc)?;
    }
    if let Some(bcc) = &input.bcc {
        validate_addresses("BCC", bcc)?;
    }
    if input
        .subject
        .bytes()
        .any(|b| b == b'\r' || b == b'\n' || b == b'\0')
    {
        return Err(rimap_core::RimapError::invalid_input(
            "subject contains forbidden characters",
        ));
    }
    if let Some(folder) = &input.in_reply_to_folder {
        crate::tools::validation::validate_folder_input("in_reply_to_folder", folder)?;
    }
    Ok(())
}

/// Validate a forward's recipient set: at least one `To`, the shared
/// `MAX_RECIPIENTS` cap across To/Cc/Bcc, and per-address header-injection
/// guards. Mirrors the recipient checks in [`validate_compose_input`] for
/// the `forward` tool, which carries no subject/body of its own.
pub(crate) fn validate_recipient_set(
    to: &[AddressInput],
    cc: Option<&[AddressInput]>,
    bcc: Option<&[AddressInput]>,
) -> Result<(), rimap_core::RimapError> {
    if to.is_empty() {
        return Err(rimap_core::RimapError::invalid_input(
            "at least one To recipient is required",
        ));
    }
    let total = to.len() + cc.map_or(0, <[_]>::len) + bcc.map_or(0, <[_]>::len);
    if total > MAX_RECIPIENTS {
        return Err(rimap_core::RimapError::invalid_input(format!(
            "too many recipients ({total}); max is {MAX_RECIPIENTS}"
        )));
    }
    validate_addresses("To", to)?;
    if let Some(cc) = cc {
        validate_addresses("CC", cc)?;
    }
    if let Some(bcc) = bcc {
        validate_addresses("BCC", bcc)?;
    }
    Ok(())
}

/// Prefix a fetched (untrusted) subject with `Fwd: ` for a forward.
///
/// The subject comes from `rimap_content::extract_subject`, which RFC
/// 2047-decodes it. A decoded encoded-word can contain bare CR/LF that
/// `mail_builder` does NOT neutralize in a `Subject` value, so every
/// control character is stripped here before the value reaches the
/// builder — otherwise it would enable header injection into the outgoing
/// message. The result is capped at `MAX_SUBJECT_LEN` on a char boundary.
#[must_use]
pub(crate) fn forwarded_subject(original: Option<&str>) -> String {
    let cleaned: String = original
        .unwrap_or("")
        .chars()
        .filter(|c| !c.is_control())
        .collect();
    let cleaned = cleaned.trim();
    let subject = if cleaned.is_empty() {
        "Fwd:".to_string()
    } else {
        format!("Fwd: {cleaned}")
    };
    if subject.len() <= MAX_SUBJECT_LEN {
        return subject;
    }
    let mut end = MAX_SUBJECT_LEN;
    while !subject.is_char_boundary(end) {
        end -= 1;
    }
    subject[..end].to_string()
}

/// Build the raw RFC 5322 bytes for a `forward`: a `message/rfc822`
/// wrapper carrying `original_raw` verbatim, with `comment_body` as the
/// text/plain body and threading headers echoing the source message.
///
/// Security-relevant construction choices:
/// - `Bcc` is intentionally NOT set on the builder, so the header never
///   appears in the sent DATA (Bcc recipients ride only in the SMTP
///   envelope). Passing `bcc` here would disclose them to every recipient.
/// - The wrapper is added via [`MessageBuilder::attachment`] with a
///   non-`text/*` content type, so `mail_builder` base64-encodes it. This
///   neutralizes bare-LF headers, boundary-lookalikes, and 8bit content in
///   attacker-crafted original bytes. Never switch this to a raw/7bit/8bit
///   part.
/// - `subject` must already be sanitized via [`forwarded_subject`]; the
///   threading `message_id` is already stripped of `< > CR LF NUL` by
///   `extract_threading_headers`.
pub(crate) fn build_forward_message(
    from_addr: &str,
    to: &[AddressInput],
    cc: Option<&[AddressInput]>,
    subject: &str,
    comment_body: &str,
    original_raw: &[u8],
    threading: &rimap_content::ThreadingHeaders,
) -> Result<Vec<u8>, rimap_core::RimapError> {
    let msg_id = generate_message_id(from_addr);
    let mut builder = MessageBuilder::new()
        .from(from_addr)
        .to(addresses_to_builder(to))
        .subject(subject)
        .text_body(comment_body)
        .message_id(msg_id);

    if let Some(cc) = cc.filter(|v| !v.is_empty()) {
        builder = builder.cc(addresses_to_builder(cc));
    }

    if let Some(orig_id) = threading.message_id.as_ref().filter(|s| !s.is_empty()) {
        builder = builder.in_reply_to(orig_id.clone());
        let mut refs = threading.references.clone();
        refs.push(orig_id.clone());
        let refs = cap_references(refs);
        builder = builder.references(MessageId::new_list(refs.into_iter()));
    }

    // Non-`text/*` content type → mail_builder base64-encodes the part.
    builder = builder.attachment("message/rfc822", "forwarded.eml", original_raw.to_vec());

    builder
        .write_to_vec()
        .map_err(|e| rimap_core::RimapError::InternalSourced {
            message: "failed to build forward message".into(),
            source: Box::new(e),
        })
}

/// Validate attachment metadata: count cap plus per-entry `path`,
/// `filename`, and `content_type` guards. Byte-size and sandbox containment
/// are enforced at read time (see [`build_message`]).
pub(crate) fn validate_attachments(
    attachments: &[AttachmentInput],
) -> Result<(), rimap_core::RimapError> {
    if attachments.len() > MAX_ATTACHMENTS {
        return Err(rimap_core::RimapError::invalid_input(format!(
            "too many attachments ({}); max is {MAX_ATTACHMENTS}",
            attachments.len()
        )));
    }
    for att in attachments {
        if att.path.is_empty() {
            return Err(rimap_core::RimapError::invalid_input(
                "attachment path must not be empty",
            ));
        }
        if let Some(name) = &att.filename {
            validate_header_text("attachment filename", name)?;
        }
        if let Some(ct) = &att.content_type {
            validate_content_type(ct)?;
        }
    }
    Ok(())
}

/// Validate a caller-supplied MIME `content_type` as a bare `type/subtype`
/// token per RFC 2045.
///
/// `mail_builder` writes the content-type string **verbatim** into the part's
/// `Content-Type` header with no escaping, so this guard is load-bearing: it
/// rejects not only the CR/LF/NUL header-injection bytes but also `;`,
/// whitespace, quotes, and any parameter syntax that would let a caller inject
/// MIME parameters or a second header token. Exactly one `/` separates a
/// non-empty type from a non-empty subtype; every character must be an RFC 2045
/// token char.
pub(crate) fn validate_content_type(value: &str) -> Result<(), rimap_core::RimapError> {
    fn is_token_char(b: u8) -> bool {
        // RFC 2045 token: any US-ASCII char except SPACE, CTLs, and tspecials.
        b.is_ascii_graphic() && !b"()<>@,;:\\\"/[]?=".contains(&b)
    }
    let reject = || {
        rimap_core::RimapError::invalid_input("attachment content_type is not a valid MIME type")
    };
    let (ty, sub) = value.split_once('/').ok_or_else(reject)?;
    if ty.is_empty() || sub.is_empty() {
        return Err(reject());
    }
    if !ty.bytes().all(is_token_char) || !sub.bytes().all(is_token_char) {
        return Err(reject());
    }
    Ok(())
}

/// Whether a `body_html` value counts as "present" for both the posture-gate
/// seam (`refine_tool_name`) and the MIME builder. A single predicate keeps the
/// authz decision and the emitted structure in agreement: whitespace-only HTML
/// neither elevates the capability nor produces a `text/html` part.
#[must_use]
pub(crate) fn body_html_is_present(value: &str) -> bool {
    !value.trim().is_empty()
}

/// Reject strings that could inject RFC 5322 headers.
pub(crate) fn validate_header_text(field: &str, value: &str) -> Result<(), rimap_core::RimapError> {
    if value
        .bytes()
        .any(|b| b == b'\r' || b == b'\n' || b == b'\0' || b == b'<' || b == b'>')
    {
        return Err(rimap_core::RimapError::invalid_input(format!(
            "{field} contains forbidden characters"
        )));
    }
    Ok(())
}

fn validate_addresses(field: &str, addrs: &[AddressInput]) -> Result<(), rimap_core::RimapError> {
    for addr in addrs {
        validate_header_text(&format!("{field} address"), &addr.address)?;
        if let Some(name) = &addr.name {
            validate_header_text(&format!("{field} name"), name)?;
        }
    }
    Ok(())
}

/// Generate a Message-ID using the From address domain.
pub(crate) fn generate_message_id(from_addr: &str) -> String {
    let domain = from_addr.rsplit('@').next().unwrap_or("local");
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!("{}.{}@{domain}", std::process::id(), nanos)
}

/// Set From, To, CC, BCC, Subject, body, and Message-ID on a builder.
/// `include_bcc` controls whether the `Bcc` header is written into the
/// message DATA. `create_draft` passes `true` so a saved draft retains the
/// full recipient set for later sending; `send_email` passes `false` so the
/// transmitted (and Sent-copy) bytes never carry a `Bcc` header — blind
/// recipients are delivered via the SMTP envelope `RCPT TO` only and are
/// never disclosed to other recipients (#432).
pub(crate) fn build_message_headers<'a>(
    from_addr: &'a str,
    input: &'a ComposeInput,
    include_bcc: bool,
) -> MessageBuilder<'a> {
    let msg_id = generate_message_id(from_addr);
    let builder = MessageBuilder::new()
        .from(from_addr)
        .to(addresses_to_builder(&input.to))
        .subject(input.subject.as_str())
        .text_body(input.body_text.as_str())
        .message_id(msg_id);

    let builder = if let Some(cc) = input.cc.as_ref().filter(|v| !v.is_empty()) {
        builder.cc(addresses_to_builder(cc))
    } else {
        builder
    };

    match input.bcc.as_ref().filter(|v| !v.is_empty()) {
        Some(bcc) if include_bcc => builder.bcc(addresses_to_builder(bcc)),
        Some(_) | None => builder,
    }
}

fn addresses_to_builder(addrs: &[AddressInput]) -> Address<'_> {
    if addrs.len() == 1 {
        return single_address(&addrs[0]);
    }
    let list: Vec<Address<'_>> = addrs.iter().map(single_address).collect();
    Address::new_list(list)
}

fn single_address(addr: &AddressInput) -> Address<'_> {
    match &addr.name {
        Some(name) => Address::new_address(Some(name.as_str()), addr.address.as_str()),
        None => Address::new_address(None::<&str>, addr.address.as_str()),
    }
}

/// Truncate a References chain to at most `MAX_REFERENCES` entries.
pub(crate) fn cap_references(mut refs: Vec<String>) -> Vec<String> {
    if refs.len() <= MAX_REFERENCES {
        return refs;
    }
    let root = refs.remove(0);
    let keep_recent = MAX_REFERENCES - 1;
    let start = refs.len().saturating_sub(keep_recent);
    let mut result = Vec::with_capacity(MAX_REFERENCES);
    result.push(root);
    result.extend(refs.into_iter().skip(start));
    result
}

/// Fetch referenced message and set In-Reply-To / References headers.
pub(crate) async fn apply_threading_headers<'a>(
    account: &AccountState,
    builder: MessageBuilder<'a>,
    reply_uid: core::num::NonZeroU32,
    in_reply_to_folder: Option<&str>,
) -> Result<MessageBuilder<'a>, rimap_core::RimapError> {
    let folder = in_reply_to_folder.unwrap_or("INBOX");
    let uid = rimap_imap::types::Uid::from(reply_uid);

    let raw = account.imap.fetch_body(folder, uid, None).await?;
    let headers = rimap_content::extract_threading_headers(&raw);

    let Some(msg_id) = headers.message_id else {
        return Ok(builder);
    };

    let builder = builder.in_reply_to(msg_id.clone());

    let mut ref_ids = headers.references;
    ref_ids.push(msg_id);
    let ref_ids = cap_references(ref_ids);

    Ok(builder.references(MessageId::new_list(ref_ids.into_iter())))
}

/// Basename + byte count of one attachment placed on a composed message.
/// Surfaced in the tool response and recorded in the audit `result_summary`
/// so an incident responder can see which sandbox file left the boundary,
/// even though the raw `path` is redacted in the request args.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct AttachmentSummary {
    /// Basename of the attached file (never a full sandbox path).
    pub filename: String,
    /// Raw byte length of the attachment before base64 inflation.
    pub bytes: u64,
}

/// A fully-built outbound message plus the observations a handler surfaces.
pub(crate) struct BuiltMessage {
    /// Raw RFC 5322 bytes ready for APPEND or SMTP send.
    pub raw: Vec<u8>,
    /// Warnings from sanitizing an HTML body (empty when no HTML body).
    pub security_warnings: Vec<rimap_content::SecurityWarning>,
    /// One entry per attachment, in caller order.
    pub attachments: Vec<AttachmentSummary>,
}

/// Resolve an attachment's outbound filename: the explicit override or the
/// source path's basename, reduced to a basename either way so a caller can
/// never emit path separators into the MIME `filename` parameter.
fn attachment_filename(att: &AttachmentInput) -> String {
    let raw = att.filename.as_deref().unwrap_or(att.path.as_str());
    std::path::Path::new(raw)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("attachment")
        .to_string()
}

/// Resolve an attachment's content type: the (already-validated) caller
/// override, else a magic-byte sniff, else `application/octet-stream`.
fn attachment_content_type(att: &AttachmentInput, bytes: &[u8]) -> String {
    att.content_type.clone().unwrap_or_else(|| {
        crate::tools::retrieval::sandbox::sniff_mime(bytes)
            .unwrap_or_else(|| "application/octet-stream".to_string())
    })
}

/// One attachment read from the sandbox, resolved and ready to attach.
#[derive(Debug)]
struct AttachmentRead {
    filename: String,
    content_type: String,
    bytes: Vec<u8>,
}

/// Read every attachment from the sandbox under an *incremental* byte budget.
///
/// The running total seeds with `body_text` plus the raw `body_html` length (an
/// upper bound on the sanitized HTML). Each read is capped at
/// `min(MAX_ATTACHMENT_BYTES, remaining_total)`, so peak resident bytes never
/// exceed `MAX_TOTAL_MESSAGE_BYTES` no matter how many large files the shared
/// sandbox holds — an over-budget set is rejected on the read that crosses the
/// budget, never silently truncated.
async fn read_attachments(
    download_dir: &std::sync::Arc<std::path::Path>,
    input: &ComposeInput,
) -> Result<Vec<AttachmentRead>, rimap_core::RimapError> {
    let Some(inputs) = &input.attachments else {
        return Ok(Vec::new());
    };
    let mut total: usize = input.body_text.len();
    if let Some(html) = input
        .body_html
        .as_deref()
        .filter(|h| body_html_is_present(h))
    {
        total = total.saturating_add(html.len());
    }
    let mut out = Vec::with_capacity(inputs.len());
    for att in inputs {
        let remaining = MAX_TOTAL_MESSAGE_BYTES.saturating_sub(total);
        let cap = remaining.min(MAX_ATTACHMENT_BYTES);
        let bytes = crate::tools::retrieval::sandbox::read_sandboxed_file_async(
            std::sync::Arc::clone(download_dir),
            att.path.clone(),
            cap,
        )
        .await?;
        total = total.saturating_add(bytes.len());
        out.push(AttachmentRead {
            filename: attachment_filename(att),
            content_type: attachment_content_type(att, &bytes),
            bytes,
        });
    }
    Ok(out)
}

/// Layer the optional sanitized HTML alternative and the already-read
/// attachments onto `builder`, then serialize.
///
/// HTML and attachments are added to the same builder [`build_message_headers`]
/// returned, so the `include_bcc` handling (#432) is untouched. Attachment
/// bytes are added as `BodyPart::Binary`, which `mail_builder` base64-encodes
/// for any non-`text/*` content type; a `text/*` attachment uses a safe CTE
/// (bare-LF normalized to CRLF, QP for 8-bit). Framing is further protected by
/// `mail_builder`'s unguessable random boundary.
fn assemble_message(
    mut builder: MessageBuilder<'_>,
    input: &ComposeInput,
    reads: Vec<AttachmentRead>,
) -> Result<BuiltMessage, rimap_core::RimapError> {
    let mut security_warnings = Vec::new();
    if let Some(html) = input
        .body_html
        .as_deref()
        .filter(|h| body_html_is_present(h))
    {
        let sanitized = rimap_content::sanitize_outbound_html(html)
            .map_err(|e| rimap_core::RimapError::invalid_input(format!("body_html: {e}")))?;
        security_warnings = sanitized.warnings;
        builder = builder.html_body(sanitized.body_html);
    }

    let mut attachments = Vec::with_capacity(reads.len());
    for read in reads {
        attachments.push(AttachmentSummary {
            filename: read.filename.clone(),
            bytes: read.bytes.len() as u64,
        });
        // Set the filename in BOTH the Content-Type `name` parameter and the
        // Content-Disposition `filename` parameter. `mail_builder`'s
        // `.attachment()` helper writes only the disposition, but many clients
        // (and this server's own `list_attachments`, which reads the Content-Type
        // `name`) key off the `name` param — so a disposition-only filename
        // round-trips as an unnamed part. Emitting both matches standard mailer
        // behavior. The bytes are `BodyPart::Binary`, so a non-`text/*` type is
        // base64-encoded.
        let content_type =
            ContentType::new(read.content_type).attribute("name", read.filename.clone());
        let part = MimePart::new(content_type, read.bytes).attachment(read.filename);
        builder.attachments.get_or_insert_with(Vec::new).push(part);
    }

    let raw = builder
        .write_to_vec()
        .map_err(|e| rimap_core::RimapError::InternalSourced {
            message: "failed to build message".into(),
            source: Box::new(e),
        })?;
    Ok(BuiltMessage {
        raw,
        security_warnings,
        attachments,
    })
}

/// Build raw RFC 5322 bytes from compose input: headers + text body, optional
/// threading, an optional sanitized HTML alternative, and sandbox-sourced
/// attachments read under an incremental byte budget.
pub(crate) async fn build_message(
    account: &AccountState,
    from_addr: &str,
    input: &ComposeInput,
    include_bcc: bool,
) -> Result<BuiltMessage, rimap_core::RimapError> {
    let mut builder = build_message_headers(from_addr, input, include_bcc);

    if let Some(reply_uid) = input.in_reply_to_uid {
        builder = Box::pin(apply_threading_headers(
            account,
            builder,
            reply_uid,
            input.in_reply_to_folder.as_deref(),
        ))
        .await?;
    }

    let reads = read_attachments(&account.download_dir, input).await?;
    assemble_message(builder, input, reads)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, clippy::panic, reason = "tests")]
mod tests {
    use mail_builder::MessageBuilder;
    use mail_builder::headers::address::Address;
    use mail_builder::headers::message_id::MessageId;

    use super::{
        AddressInput, ComposeInput, addresses_to_builder, cap_references, validate_compose_input,
    };

    /// Build a minimal draft, parse it, verify headers round-trip.
    #[test]
    fn round_trip_simple_draft() {
        let input = ComposeInput {
            to: vec![AddressInput {
                name: Some("Bob".into()),
                address: "bob@example.com".into(),
            }],
            cc: Some(vec![AddressInput {
                name: None,
                address: "cc@example.com".into(),
            }]),
            bcc: None,
            subject: "Test subject".into(),
            body_text: "Hello, world!".into(),
            body_html: None,
            attachments: None,
            in_reply_to_uid: None,
            in_reply_to_folder: None,
        };

        let builder = super::build_message_headers("alice@example.com", &input, true);
        let raw = builder.write_to_vec().unwrap();
        let parsed = mail_parser::MessageParser::new().parse(&raw).unwrap();

        let from = parsed.from().unwrap().first().unwrap();
        assert_eq!(from.address().unwrap(), "alice@example.com");

        let to = parsed.to().unwrap().first().unwrap();
        assert_eq!(to.name().unwrap(), "Bob");
        assert_eq!(to.address().unwrap(), "bob@example.com");

        let cc = parsed.cc().unwrap().first().unwrap();
        assert_eq!(cc.address().unwrap(), "cc@example.com");

        assert_eq!(parsed.subject().unwrap(), "Test subject");
        assert_eq!(parsed.body_text(0).unwrap().as_ref(), "Hello, world!");
        assert!(parsed.message_id().is_some());
    }

    /// Build an "original" message, then a reply, verify threading.
    #[test]
    fn threading_headers_round_trip() {
        let original = MessageBuilder::new()
            .from("sender@example.com")
            .to("me@example.com")
            .message_id("original-id-123@example.com")
            .references(MessageId::new_list(["root-id@example.com"].into_iter()))
            .subject("Original")
            .text_body("original body")
            .write_to_vec()
            .unwrap();

        let parsed_original = mail_parser::MessageParser::new().parse(&original).unwrap();

        let orig_msg_id = parsed_original.message_id().unwrap();
        assert_eq!(orig_msg_id, "original-id-123@example.com");

        let mut ref_ids: Vec<String> = Vec::new();
        match parsed_original.references() {
            mail_parser::HeaderValue::Text(t) => {
                ref_ids.push(t.to_string());
            }
            mail_parser::HeaderValue::TextList(list) => {
                for r in list {
                    ref_ids.push(r.to_string());
                }
            }
            _ => {}
        }
        ref_ids.push(orig_msg_id.to_string());

        let reply = MessageBuilder::new()
            .from("me@example.com")
            .to("sender@example.com")
            .subject("Re: Original")
            .text_body("reply body")
            .in_reply_to(orig_msg_id.to_string())
            .references(MessageId::new_list(ref_ids.into_iter()))
            .write_to_vec()
            .unwrap();

        let parsed_reply = mail_parser::MessageParser::new().parse(&reply).unwrap();

        let in_reply_to = parsed_reply.in_reply_to();
        assert_eq!(
            in_reply_to.as_text().unwrap(),
            "original-id-123@example.com"
        );

        match parsed_reply.references() {
            mail_parser::HeaderValue::TextList(list) => {
                let refs: Vec<&str> = list.iter().map(AsRef::as_ref).collect();
                assert_eq!(
                    refs,
                    vec!["root-id@example.com", "original-id-123@example.com",]
                );
            }
            other => {
                panic!("expected TextList for References, got {other:?}")
            }
        }
    }

    /// Multiple To addresses produce a single To header with all
    /// addresses.
    #[test]
    fn multiple_to_addresses() {
        let addrs = vec![
            AddressInput {
                name: Some("A".into()),
                address: "a@example.com".into(),
            },
            AddressInput {
                name: None,
                address: "b@example.com".into(),
            },
        ];
        let addr = addresses_to_builder(&addrs);
        let builder = MessageBuilder::new()
            .from("from@example.com")
            .to(addr)
            .subject("multi")
            .text_body("body");
        let raw = builder.write_to_vec().unwrap();
        let parsed = mail_parser::MessageParser::new().parse(&raw).unwrap();

        let to_addrs = parsed.to().unwrap();
        let list = to_addrs.as_list().unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].address().unwrap(), "a@example.com");
        assert_eq!(list[1].address().unwrap(), "b@example.com");
    }

    /// Single address does not wrap in a list.
    #[test]
    fn single_address_no_list_wrap() {
        let addrs = vec![AddressInput {
            name: None,
            address: "solo@example.com".into(),
        }];
        let addr = addresses_to_builder(&addrs);
        if let Address::Address(email) = &addr {
            assert_eq!(email.email, "solo@example.com");
        } else {
            panic!("expected Address::Address for single input");
        }
    }

    fn make_input(to: Vec<AddressInput>) -> ComposeInput {
        ComposeInput {
            to,
            cc: None,
            bcc: None,
            subject: "Test".into(),
            body_text: "body".into(),
            body_html: None,
            attachments: None,
            in_reply_to_uid: None,
            in_reply_to_folder: None,
        }
    }

    #[test]
    fn crlf_in_address_rejected() {
        let input = make_input(vec![AddressInput {
            name: None,
            address: "a@b>\r\nBcc: spy@evil".into(),
        }]);
        let err = validate_compose_input(&input).unwrap_err();
        assert_eq!(err.code(), rimap_core::error::ErrorCode::InvalidInput,);
    }

    #[test]
    fn crlf_in_name_rejected() {
        let input = make_input(vec![AddressInput {
            name: Some("Evil\r\nBcc: spy@evil".into()),
            address: "ok@example.com".into(),
        }]);
        let err = validate_compose_input(&input).unwrap_err();
        assert_eq!(err.code(), rimap_core::error::ErrorCode::InvalidInput,);
    }

    #[test]
    fn angle_brackets_in_address_rejected() {
        let input = make_input(vec![AddressInput {
            name: None,
            address: "<injected>@example.com".into(),
        }]);
        let err = validate_compose_input(&input).unwrap_err();
        assert_eq!(err.code(), rimap_core::error::ErrorCode::InvalidInput,);
    }

    #[test]
    fn empty_to_rejected() {
        let input = make_input(vec![]);
        let err = validate_compose_input(&input).unwrap_err();
        assert_eq!(err.code(), rimap_core::error::ErrorCode::InvalidInput,);
        assert!(
            err.to_string().contains("at least one To"),
            "unexpected message: {err}",
        );
    }

    #[test]
    fn subject_crlf_rejected() {
        let mut input = make_input(vec![AddressInput {
            name: None,
            address: "ok@example.com".into(),
        }]);
        input.subject = "Hello\r\nBcc: spy@evil".into();
        let err = validate_compose_input(&input).unwrap_err();
        assert_eq!(err.code(), rimap_core::error::ErrorCode::InvalidInput,);
    }

    #[test]
    fn cc_address_validated() {
        let mut input = make_input(vec![AddressInput {
            name: None,
            address: "ok@example.com".into(),
        }]);
        input.cc = Some(vec![AddressInput {
            name: None,
            address: "bad\n@example.com".into(),
        }]);
        let err = validate_compose_input(&input).unwrap_err();
        assert_eq!(err.code(), rimap_core::error::ErrorCode::InvalidInput,);
    }

    #[test]
    fn message_id_uses_from_domain() {
        let input = make_input(vec![AddressInput {
            name: None,
            address: "bob@example.com".into(),
        }]);
        let builder = super::build_message_headers("alice@secret-host.internal", &input, true);
        let raw = builder.write_to_vec().unwrap();
        let parsed = mail_parser::MessageParser::new().parse(&raw).unwrap();
        let mid = parsed.message_id().unwrap();
        assert!(
            mid.ends_with("@secret-host.internal"),
            "Message-ID should use from domain: {mid}",
        );
    }

    #[test]
    fn valid_input_passes() {
        let input = make_input(vec![AddressInput {
            name: Some("Bob".into()),
            address: "bob@example.com".into(),
        }]);
        validate_compose_input(&input).unwrap();
    }

    #[test]
    fn references_chain_capped_at_50() {
        let refs: Vec<String> = (0..200).map(|i| format!("msg-{i}@example.com")).collect();
        let capped = cap_references(refs);
        assert_eq!(capped.len(), 50);
        assert_eq!(capped[0], "msg-0@example.com");
        assert_eq!(capped[49], "msg-199@example.com");
    }

    #[test]
    fn references_chain_under_cap_unchanged() {
        let refs: Vec<String> = (0..10).map(|i| format!("msg-{i}@example.com")).collect();
        let capped = cap_references(refs);
        assert_eq!(capped.len(), 10);
    }

    #[test]
    fn too_many_recipients_rejected() {
        let addrs: Vec<AddressInput> = (0..101)
            .map(|i| AddressInput {
                name: None,
                address: format!("user{i}@example.com"),
            })
            .collect();
        let input = make_input(addrs);
        let err = validate_compose_input(&input).unwrap_err();
        assert_eq!(err.code(), rimap_core::error::ErrorCode::InvalidInput);
    }

    #[test]
    fn too_many_recipients_across_fields_rejected() {
        let to: Vec<AddressInput> = (0..50)
            .map(|i| AddressInput {
                name: None,
                address: format!("to{i}@example.com"),
            })
            .collect();
        let cc: Vec<AddressInput> = (0..30)
            .map(|i| AddressInput {
                name: None,
                address: format!("cc{i}@example.com"),
            })
            .collect();
        let bcc: Vec<AddressInput> = (0..21)
            .map(|i| AddressInput {
                name: None,
                address: format!("bcc{i}@example.com"),
            })
            .collect();
        let mut input = make_input(to);
        input.cc = Some(cc);
        input.bcc = Some(bcc);
        let err = validate_compose_input(&input).unwrap_err();
        assert_eq!(err.code(), rimap_core::error::ErrorCode::InvalidInput);
    }

    #[test]
    fn exactly_max_recipients_accepted() {
        let addrs: Vec<AddressInput> = (0..100)
            .map(|i| AddressInput {
                name: None,
                address: format!("user{i}@example.com"),
            })
            .collect();
        let input = make_input(addrs);
        validate_compose_input(&input).unwrap();
    }

    #[test]
    fn subject_too_long_rejected() {
        let mut input = make_input(vec![AddressInput {
            name: None,
            address: "ok@example.com".into(),
        }]);
        input.subject = "x".repeat(1001);
        let err = validate_compose_input(&input).unwrap_err();
        assert_eq!(err.code(), rimap_core::error::ErrorCode::InvalidInput);
    }

    #[test]
    fn subject_at_max_accepted() {
        let mut input = make_input(vec![AddressInput {
            name: None,
            address: "ok@example.com".into(),
        }]);
        input.subject = "x".repeat(1000);
        validate_compose_input(&input).unwrap();
    }

    #[test]
    fn body_too_large_rejected() {
        let mut input = make_input(vec![AddressInput {
            name: None,
            address: "ok@example.com".into(),
        }]);
        input.body_text = "x".repeat(1_048_577);
        let err = validate_compose_input(&input).unwrap_err();
        assert_eq!(err.code(), rimap_core::error::ErrorCode::InvalidInput);
    }

    #[test]
    fn body_at_max_accepted() {
        let mut input = make_input(vec![AddressInput {
            name: None,
            address: "ok@example.com".into(),
        }]);
        input.body_text = "x".repeat(1_048_576);
        validate_compose_input(&input).unwrap();
    }

    #[test]
    fn in_reply_to_folder_with_crlf_rejected() {
        let mut input = make_input(vec![AddressInput {
            name: None,
            address: "ok@example.com".into(),
        }]);
        input.in_reply_to_uid = Some(core::num::NonZeroU32::new(1).unwrap());
        input.in_reply_to_folder = Some("bad\r\nfolder".into());
        let err = validate_compose_input(&input).unwrap_err();
        assert_eq!(err.code(), rimap_core::error::ErrorCode::InvalidInput);
    }

    #[test]
    fn in_reply_to_folder_with_null_rejected() {
        let mut input = make_input(vec![AddressInput {
            name: None,
            address: "ok@example.com".into(),
        }]);
        input.in_reply_to_uid = Some(core::num::NonZeroU32::new(1).unwrap());
        input.in_reply_to_folder = Some("bad\0folder".into());
        let err = validate_compose_input(&input).unwrap_err();
        assert_eq!(err.code(), rimap_core::error::ErrorCode::InvalidInput);
    }

    #[test]
    fn in_reply_to_folder_valid_accepted() {
        let mut input = make_input(vec![AddressInput {
            name: None,
            address: "ok@example.com".into(),
        }]);
        input.in_reply_to_uid = Some(core::num::NonZeroU32::new(1).unwrap());
        input.in_reply_to_folder = Some("INBOX".into());
        validate_compose_input(&input).unwrap();
    }

    #[test]
    fn empty_cc_does_not_panic() {
        let input = ComposeInput {
            to: vec![AddressInput {
                name: None,
                address: "bob@example.com".into(),
            }],
            cc: Some(vec![]),
            bcc: Some(vec![]),
            subject: "Test".into(),
            body_text: "body".into(),
            body_html: None,
            attachments: None,
            in_reply_to_uid: None,
            in_reply_to_folder: None,
        };
        validate_compose_input(&input).unwrap();
        let builder = super::build_message_headers("alice@example.com", &input, true);
        let raw = builder.write_to_vec().unwrap();
        let parsed = mail_parser::MessageParser::new().parse(&raw).unwrap();
        assert!(parsed.cc().is_none());
        assert!(parsed.bcc().is_none());
    }

    // --- Bcc exclusion from sent DATA (#432) ---

    fn bcc_input() -> ComposeInput {
        ComposeInput {
            to: vec![AddressInput {
                name: None,
                address: "to@example.com".into(),
            }],
            cc: None,
            bcc: Some(vec![AddressInput {
                name: None,
                address: "blind@secret.example".into(),
            }]),
            subject: "Hi".into(),
            body_text: "body".into(),
            body_html: None,
            attachments: None,
            in_reply_to_uid: None,
            in_reply_to_folder: None,
        }
    }

    #[test]
    fn send_email_path_excludes_bcc_from_data() {
        // include_bcc = false (the send_email path): the Bcc header must not
        // appear in the message bytes and no blind address may leak into the
        // DATA. Blind recipients are delivered via the SMTP envelope instead.
        let raw = super::build_message_headers("from@example.com", &bcc_input(), false)
            .write_to_vec()
            .unwrap();
        let parsed = mail_parser::MessageParser::new().parse(&raw).unwrap();
        assert!(
            parsed.bcc().is_none(),
            "Bcc header must not be in the sent DATA",
        );
        let text = String::from_utf8_lossy(&raw);
        assert!(
            !text.contains("Bcc:"),
            "no Bcc header line may appear in DATA"
        );
        assert!(
            !text.contains("blind@secret.example"),
            "blind recipient leaked into the sent DATA",
        );
    }

    #[test]
    fn draft_path_retains_bcc_in_data() {
        // include_bcc = true (the create_draft path): a saved draft keeps the
        // Bcc so the full recipient set survives until the user sends it.
        let raw = super::build_message_headers("from@example.com", &bcc_input(), true)
            .write_to_vec()
            .unwrap();
        let parsed = mail_parser::MessageParser::new().parse(&raw).unwrap();
        let bcc = parsed.bcc().unwrap();
        assert_eq!(
            bcc.first().unwrap().address().unwrap(),
            "blind@secret.example",
        );
    }

    #[test]
    fn empty_bcc_never_emitted_regardless_of_flag() {
        for include_bcc in [true, false] {
            let mut input = bcc_input();
            input.bcc = Some(vec![]);
            let raw = super::build_message_headers("from@example.com", &input, include_bcc)
                .write_to_vec()
                .unwrap();
            let parsed = mail_parser::MessageParser::new().parse(&raw).unwrap();
            assert!(
                parsed.bcc().is_none(),
                "empty bcc must not emit a header (include_bcc={include_bcc})",
            );
        }
    }

    // --- forward (#408) ---

    use super::{
        MAX_RECIPIENTS, MAX_SUBJECT_LEN, build_forward_message, forwarded_subject,
        validate_recipient_set,
    };

    fn to_one(a: &str) -> Vec<AddressInput> {
        vec![AddressInput {
            name: None,
            address: a.to_string(),
        }]
    }

    #[test]
    fn forwarded_subject_prefixes_and_strips_controls() {
        assert_eq!(forwarded_subject(Some("Hello")), "Fwd: Hello");
        assert_eq!(forwarded_subject(None), "Fwd:");
        assert_eq!(forwarded_subject(Some("   ")), "Fwd:");
        // A decoded encoded-word can carry bare CR/LF; they must be stripped
        // before the value reaches the builder, or they inject headers.
        let cleaned = forwarded_subject(Some("hi\r\nBcc: evil@example.com"));
        assert!(!cleaned.contains('\r') && !cleaned.contains('\n'));
        assert_eq!(cleaned, "Fwd: hiBcc: evil@example.com");
    }

    #[test]
    fn forwarded_subject_capped_at_max_len() {
        let subject = forwarded_subject(Some(&"x".repeat(MAX_SUBJECT_LEN * 2)));
        assert!(subject.len() <= MAX_SUBJECT_LEN);
    }

    #[test]
    fn build_forward_wraps_original_as_base64_message_rfc822() {
        let original = MessageBuilder::new()
            .from("orig@example.com")
            .to("me@example.com")
            .message_id("orig-123@example.com")
            .subject("Original")
            .text_body("original body")
            .write_to_vec()
            .unwrap();

        let threading = rimap_content::extract_threading_headers(&original);
        let subject = forwarded_subject(rimap_content::extract_subject(&original).as_deref());
        let raw = build_forward_message(
            "me@example.com",
            &to_one("dest@example.com"),
            None,
            &subject,
            "see below",
            &original,
            &threading,
        )
        .unwrap();

        let parsed = mail_parser::MessageParser::new().parse(&raw).unwrap();
        assert_eq!(parsed.subject().unwrap(), "Fwd: Original");
        assert_eq!(
            parsed.to().unwrap().first().unwrap().address().unwrap(),
            "dest@example.com",
        );
        // Threading preserved from the fetched bytes.
        assert_eq!(
            parsed.in_reply_to().as_text().unwrap(),
            "orig-123@example.com",
        );

        let text = String::from_utf8_lossy(&raw);
        assert!(text.contains("message/rfc822"), "wrapper part missing");
        // The wrapper must be base64 — never a raw/8bit part. If it were raw,
        // the original's `Subject:`/`From:` lines would appear verbatim in
        // the output and could break the outer framing.
        assert!(
            text.to_ascii_lowercase().contains("base64"),
            "message/rfc822 wrapper must be base64-encoded",
        );
        assert!(
            !text.contains("original body"),
            "original body leaked unencoded into the wrapper",
        );
    }

    #[test]
    fn build_forward_excludes_bcc_from_data() {
        // build_forward_message never receives bcc; the header must not
        // appear in the sent DATA (bcc rides the SMTP envelope only).
        let original = MessageBuilder::new()
            .from("orig@example.com")
            .subject("O")
            .text_body("b")
            .write_to_vec()
            .unwrap();
        let threading = rimap_content::extract_threading_headers(&original);
        let raw = build_forward_message(
            "me@example.com",
            &to_one("dest@example.com"),
            None,
            "Fwd: O",
            "",
            &original,
            &threading,
        )
        .unwrap();
        let parsed = mail_parser::MessageParser::new().parse(&raw).unwrap();
        assert!(
            parsed.bcc().is_none(),
            "Bcc must not be in the message DATA"
        );
    }

    #[test]
    fn build_forward_neutralizes_smuggled_subject_header_injection() {
        // A malicious original carries a Q-encoded Subject that decodes to a
        // value containing CRLF + a fake Bcc header. Extracting + sanitizing
        // it must strip the CRLF so the outbound message has no injected
        // header. The original's own `Subject:` line is base64-wrapped, so it
        // never appears as a second plaintext Subject header.
        let original = b"From: attacker@evil.example\r\n\
              Subject: =?utf-8?Q?PWNED=0D=0ABcc:=20evil@example.com?=\r\n\
              Message-ID: <o@evil.example>\r\n\
              \r\n\
              body\r\n"
            .to_vec();

        let decoded = rimap_content::extract_subject(&original);
        // The decoded subject really does contain the smuggled CRLF...
        assert!(decoded.as_deref().unwrap().contains('\n'));
        // ...but forwarded_subject strips it.
        let subject = forwarded_subject(decoded.as_deref());
        assert!(!subject.contains('\r') && !subject.contains('\n'));

        let threading = rimap_content::extract_threading_headers(&original);
        let raw = build_forward_message(
            "me@example.com",
            &to_one("dest@example.com"),
            None,
            &subject,
            "",
            &original,
            &threading,
        )
        .unwrap();

        let parsed = mail_parser::MessageParser::new().parse(&raw).unwrap();
        assert!(
            parsed.bcc().is_none(),
            "smuggled Bcc must not become a real header",
        );
        let text = String::from_utf8_lossy(&raw);
        assert_eq!(
            text.matches("Subject:").count(),
            1,
            "exactly one (outer) Subject header; original's is base64-wrapped",
        );
    }

    #[test]
    fn build_forward_base64_neutralizes_boundary_lookalike() {
        // An original whose bytes embed a boundary-lookalike and a bare-LF
        // header must be base64-wrapped so those bytes cannot break the outer
        // MIME frame — none of the attacker's tokens appear as plaintext.
        let original = b"From: a@b\nSubject: x\n\r\n--=_lookalike_boundary\r\n\
              Content-Type: text/x-smuggled\r\n\r\npayload\r\n"
            .to_vec();
        let threading = rimap_content::extract_threading_headers(&original);
        let raw = build_forward_message(
            "me@example.com",
            &to_one("dest@example.com"),
            None,
            "Fwd: x",
            "",
            &original,
            &threading,
        )
        .unwrap();
        let text = String::from_utf8_lossy(&raw);
        assert!(
            !text.contains("text/x-smuggled") && !text.contains("--=_lookalike_boundary"),
            "attacker tokens leaked unencoded; wrapper is not base64",
        );
        // The result still parses as a single well-formed message.
        let parsed = mail_parser::MessageParser::new().parse(&raw).unwrap();
        assert_eq!(parsed.subject().unwrap(), "Fwd: x");
    }

    #[test]
    fn validate_recipient_set_enforces_cap_and_injection() {
        assert!(validate_recipient_set(&to_one("a@example.com"), None, None).is_ok());
        // empty To
        assert!(validate_recipient_set(&[], None, None).is_err());
        // injection in address
        assert!(validate_recipient_set(&to_one("a@b>\r\nBcc: x@evil"), None, None).is_err(),);
        // over the recipient cap
        let many: Vec<AddressInput> = (0..=MAX_RECIPIENTS)
            .map(|i| AddressInput {
                name: None,
                address: format!("u{i}@example.com"),
            })
            .collect();
        assert!(validate_recipient_set(&many, None, None).is_err());
    }

    // --- attachments + HTML (#408) ---

    use super::{
        AttachmentInput, AttachmentRead, MAX_ATTACHMENTS, assemble_message,
        attachment_content_type, attachment_filename, body_html_is_present, build_message_headers,
        validate_attachments, validate_content_type,
    };

    fn att(path: &str) -> AttachmentInput {
        AttachmentInput {
            path: path.to_string(),
            filename: None,
            content_type: None,
        }
    }

    #[test]
    fn validate_attachments_over_count_cap_rejected() {
        let many: Vec<AttachmentInput> = (0..=MAX_ATTACHMENTS)
            .map(|i| att(&format!("/d/f{i}")))
            .collect();
        let err = validate_attachments(&many).unwrap_err();
        assert_eq!(err.code(), rimap_core::error::ErrorCode::InvalidInput);
    }

    #[test]
    fn validate_attachments_at_count_cap_ok() {
        let ok: Vec<AttachmentInput> = (0..MAX_ATTACHMENTS)
            .map(|i| att(&format!("/d/f{i}")))
            .collect();
        assert!(validate_attachments(&ok).is_ok());
    }

    #[test]
    fn validate_attachments_empty_path_rejected() {
        assert!(validate_attachments(&[att("")]).is_err());
    }

    #[test]
    fn validate_attachments_filename_injection_rejected() {
        let mut a = att("/d/f");
        a.filename = Some("evil\r\nBcc: x@evil".into());
        assert!(validate_attachments(std::slice::from_ref(&a)).is_err());
    }

    #[test]
    fn validate_attachments_content_type_injection_rejected() {
        let mut a = att("/d/f");
        a.content_type = Some("text/plain\r\nX-Injected: 1".into());
        assert!(validate_attachments(std::slice::from_ref(&a)).is_err());
    }

    #[test]
    fn validate_content_type_accepts_plain_token() {
        assert!(validate_content_type("application/pdf").is_ok());
        assert!(validate_content_type("text/plain").is_ok());
        assert!(validate_content_type("image/svg+xml").is_ok());
    }

    #[test]
    fn validate_content_type_rejects_parameters_and_whitespace() {
        // mail_builder writes the content-type verbatim, so a parameter or
        // whitespace must be rejected here — this guard is load-bearing.
        assert!(validate_content_type("text/plain; name=\"x\"").is_err());
        assert!(validate_content_type("text/ plain").is_err());
        assert!(validate_content_type("application/octet-stream ").is_err());
        assert!(validate_content_type("text").is_err());
        assert!(validate_content_type("/plain").is_err());
        assert!(validate_content_type("text/").is_err());
        assert!(validate_content_type("a/b/c").is_err());
    }

    #[test]
    fn body_html_present_predicate() {
        assert!(body_html_is_present("<p>x</p>"));
        assert!(!body_html_is_present(""));
        assert!(!body_html_is_present("   \t\n"));
    }

    #[test]
    fn attachment_filename_reduces_to_basename() {
        // No override → basename of the path; a filename override is also
        // reduced to a basename so no path separator ever reaches the header.
        assert_eq!(
            attachment_filename(&att("/srv/dl/report.pdf")),
            "report.pdf"
        );
        let mut a = att("/srv/dl/report.pdf");
        a.filename = Some("../../etc/passwd".into());
        assert_eq!(attachment_filename(&a), "passwd");
    }

    #[test]
    fn attachment_content_type_sniffs_then_falls_back() {
        // Declared type wins; else sniff; else octet-stream.
        let mut a = att("/d/f");
        a.content_type = Some("application/pdf".into());
        assert_eq!(attachment_content_type(&a, b"anything"), "application/pdf");

        let png = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        assert_eq!(attachment_content_type(&att("/d/f"), &png), "image/png");

        assert_eq!(
            attachment_content_type(&att("/d/f"), b"not a known magic"),
            "application/octet-stream",
        );
    }

    fn html_input(body_text: &str, body_html: Option<&str>) -> ComposeInput {
        ComposeInput {
            to: to_one("dest@example.com"),
            cc: None,
            bcc: None,
            subject: "s".into(),
            body_text: body_text.into(),
            body_html: body_html.map(str::to_string),
            attachments: None,
            in_reply_to_uid: None,
            in_reply_to_folder: None,
        }
    }

    #[test]
    fn assemble_html_produces_multipart_alternative_and_strips_script() {
        let input = html_input("plain fallback", Some("<p>hi</p><script>alert(1)</script>"));
        let builder = build_message_headers("me@example.com", &input, false);
        let built = assemble_message(builder, &input, Vec::new()).unwrap();
        let text = String::from_utf8_lossy(&built.raw);
        assert!(
            text.contains("multipart/alternative"),
            "expected alternative"
        );
        assert!(
            text.contains("text/plain"),
            "text/plain alternative missing"
        );
        assert!(text.contains("text/html"), "text/html part missing");
        // Hostile agent HTML must not survive into the emitted bytes.
        assert!(!text.contains("<script"), "script leaked into sent bytes");
        assert!(!text.contains("alert(1)"), "script body leaked");
        // The sanitizer stripped a script → a warning must be surfaced.
        assert!(!built.security_warnings.is_empty());
    }

    #[test]
    fn assemble_empty_html_emits_plain_text_only() {
        let input = html_input("just text", Some("   "));
        let builder = build_message_headers("me@example.com", &input, false);
        let built = assemble_message(builder, &input, Vec::new()).unwrap();
        let text = String::from_utf8_lossy(&built.raw);
        assert!(!text.contains("multipart/alternative"));
        assert!(built.security_warnings.is_empty());
    }

    fn read_of(content_type: &str, filename: &str, bytes: &[u8]) -> AttachmentRead {
        AttachmentRead {
            filename: filename.to_string(),
            content_type: content_type.to_string(),
            bytes: bytes.to_vec(),
        }
    }

    #[test]
    fn assemble_attachment_produces_multipart_mixed() {
        use mail_parser::MimeHeaders as _;
        let input = html_input("body", None);
        let builder = build_message_headers("me@example.com", &input, false);
        let reads = vec![read_of("application/pdf", "report.pdf", b"%PDF-1.4 data")];
        let built = assemble_message(builder, &input, reads).unwrap();
        let text = String::from_utf8_lossy(&built.raw);
        assert!(text.contains("multipart/mixed"));
        assert!(text.contains("report.pdf"));
        assert_eq!(built.attachments.len(), 1);
        assert_eq!(built.attachments[0].filename, "report.pdf");
        // Non-text part is base64; raw payload must not appear verbatim.
        assert!(
            !text.contains("%PDF-1.4 data"),
            "attachment not base64-encoded"
        );
        // The filename must round-trip through a parser: it is set in both the
        // Content-Type `name` and the Content-Disposition `filename`, so a
        // reader keying off either recovers it (regression guard for the null
        // filename the e2e attachment round-trip surfaced).
        let parsed = mail_parser::MessageParser::new().parse(&built.raw).unwrap();
        let names: Vec<&str> = parsed
            .attachments()
            .filter_map(|a| a.attachment_name())
            .collect();
        assert!(
            names.contains(&"report.pdf"),
            "attachment_name did not round-trip; got {names:?}",
        );
    }

    #[test]
    fn assemble_html_and_attachment_nests_alternative_in_mixed() {
        let input = html_input("body", Some("<p>rich</p>"));
        let builder = build_message_headers("me@example.com", &input, false);
        let reads = vec![read_of("application/pdf", "a.pdf", b"data")];
        let built = assemble_message(builder, &input, reads).unwrap();
        let text = String::from_utf8_lossy(&built.raw);
        assert!(text.contains("multipart/mixed"));
        assert!(text.contains("multipart/alternative"));
        assert!(text.contains("text/plain"));
        assert!(text.contains("text/html"));
    }

    #[tokio::test]
    async fn read_attachments_enforces_incremental_total_budget() {
        // 20 files of 2 MiB each = 40 MiB > MAX_TOTAL_MESSAGE_BYTES (25 MiB):
        // the read that crosses the budget must fail, so the whole message is
        // rejected rather than materializing 40 MiB.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        let two_mib = vec![0u8; 2 * 1_048_576];
        let mut attachments = Vec::new();
        for i in 0..20 {
            let p = root.join(format!("f{i}.bin"));
            std::fs::write(&p, &two_mib).unwrap();
            attachments.push(super::AttachmentInput {
                path: p.to_str().unwrap().to_string(),
                filename: None,
                content_type: None,
            });
        }
        let mut input = html_input("body", None);
        input.attachments = Some(attachments);
        let root_arc: std::sync::Arc<std::path::Path> = std::sync::Arc::from(root);
        let err = super::read_attachments(&root_arc, &input)
            .await
            .unwrap_err();
        assert_eq!(err.code(), rimap_core::error::ErrorCode::InvalidInput);
    }

    #[tokio::test]
    async fn read_attachments_small_set_ok() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        let p = root.join("doc.pdf");
        std::fs::write(&p, b"%PDF-1.4").unwrap();
        let mut input = html_input("body", None);
        input.attachments = Some(vec![super::AttachmentInput {
            path: p.to_str().unwrap().to_string(),
            filename: None,
            content_type: None,
        }]);
        let root_arc: std::sync::Arc<std::path::Path> = std::sync::Arc::from(root);
        let reads = super::read_attachments(&root_arc, &input).await.unwrap();
        assert_eq!(reads.len(), 1);
        assert_eq!(reads[0].bytes, b"%PDF-1.4");
    }
}
