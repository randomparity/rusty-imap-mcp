//! `forward` tool handler: re-send an existing message as a
//! `message/rfc822` wrapper via SMTP, then best-effort APPEND a copy to
//! the Sent folder.
//!
//! The payload is a message the server fetches from the resolved account's
//! own IMAP server, so `forward` does not widen the outbound trust domain
//! (no caller-supplied message bytes). Same-account only: it re-sends the
//! resolved account's mail, never another account's.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::boot::registry::AccountState;
use crate::mcp::response::ToolResponse;
use crate::tools::compose::message_builder::{
    self, AddressInput, MAX_BODY_BYTES, MAX_FORWARD_ORIGINAL_BYTES,
};
use crate::tools::compose::send_email::SentCopyInfo;

#[derive(Debug, Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct ForwardInput {
    /// Folder containing the message to forward.
    pub folder: String,
    /// UID of the message to forward.
    #[serde(deserialize_with = "crate::tools::lenient_int::deserialize_nonzero_u32")]
    #[schemars(schema_with = "crate::tools::lenient_int::schema_nonzero_u32")]
    pub uid: core::num::NonZeroU32,
    /// Recipient addresses.
    pub to: Vec<AddressInput>,
    /// CC addresses.
    pub cc: Option<Vec<AddressInput>>,
    /// BCC addresses (delivered via the SMTP envelope only; never written
    /// into the message headers).
    pub bcc: Option<Vec<AddressInput>>,
    /// Optional note placed above the forwarded message as the body.
    pub comment: Option<String>,
}

/// Trusted metadata for a `forward` response.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct ForwardMeta {
    /// Whether the message was delivered via SMTP.
    pub sent: bool,
    /// RFC 2822 `Message-ID` assigned to the outgoing forward.
    pub message_id: Option<String>,
    /// Human-readable SMTP delivery status.
    pub smtp_status: String,
    /// Folder the forwarded message was fetched from.
    pub source_folder: String,
    /// UID of the forwarded source message.
    pub source_uid: u32,
    /// Result of the best-effort copy to the Sent folder.
    pub sent_copy: SentCopyInfo,
}

/// `forward` handler.
///
/// # Errors
///
/// Returns `RimapError::Authz { code: InvalidInput, ... }` for malformed
/// recipients, an invalid folder, an oversized comment, or a source
/// message larger than `MAX_FORWARD_ORIGINAL_BYTES`. Returns
/// `RimapError::Config` if no SMTP is configured. Returns
/// `RimapError::Imap { ... }` if the source message cannot be fetched, and
/// `RimapError::Smtp { ... }` on SMTP failure. The copy-to-Sent APPEND is
/// best-effort and surfaces via `sent_copy.failed`, not as an error.
pub async fn handle(
    account: &AccountState,
    input: ForwardInput,
) -> Result<ToolResponse<ForwardMeta>, rimap_core::RimapError> {
    crate::tools::validation::validate_folder_input("folder", &input.folder)?;
    message_builder::validate_recipient_set(&input.to, input.cc.as_deref(), input.bcc.as_deref())?;
    let comment_body = validate_comment(input.comment.as_deref())?;

    let smtp = account.smtp.as_ref().ok_or_else(|| {
        rimap_core::RimapError::Config("forward requires SMTP configuration".into())
    })?;

    let from_addr = account.imap.username();
    let uid = rimap_imap::types::Uid::from(input.uid);
    let original = account.imap.fetch_body(&input.folder, uid, None).await?;

    // Bound the wrapped payload. The fetch is already capped by
    // `max_fetch_body_bytes`, but that limit can be looser than the
    // forward cap, so re-check here before building/sending.
    if original.len() > MAX_FORWARD_ORIGINAL_BYTES {
        return Err(rimap_core::RimapError::invalid_input(format!(
            "source message too large to forward ({} bytes); max is {MAX_FORWARD_ORIGINAL_BYTES}",
            original.len(),
        )));
    }

    let subject =
        message_builder::forwarded_subject(rimap_content::extract_subject(&original).as_deref());
    // Extract threading from the bytes already fetched — no second fetch
    // (a re-fetch of the same UID could see a different message after an
    // interleaved EXPUNGE/UIDVALIDITY change).
    let threading = rimap_content::extract_threading_headers(&original);

    let raw_msg = message_builder::build_forward_message(
        from_addr,
        &input.to,
        input.cc.as_deref(),
        &subject,
        &comment_body,
        &original,
        &threading,
    )?;

    let envelope = build_envelope(from_addr, &input);
    let smtp_response = smtp.send_raw(&envelope, &raw_msg).await?;
    tracing::info!(smtp_response, "forward: SMTP send succeeded");

    let generated_msg_id = rimap_content::extract_message_id(&raw_msg);
    let sent_copy = append_sent_copy(account, &raw_msg).await;

    Ok(ToolResponse::meta_only(ForwardMeta {
        sent: true,
        message_id: generated_msg_id,
        smtp_status: "delivered".to_string(),
        source_folder: input.folder,
        source_uid: input.uid.get(),
        sent_copy,
    }))
}

/// Validate and normalize the optional forward comment. The comment is the
/// message body (not a header), so newlines are permitted; `mail_builder`
/// encodes the body and cannot be tricked into emitting a header from it.
/// A NUL byte is rejected and the size is capped at `MAX_BODY_BYTES`.
fn validate_comment(comment: Option<&str>) -> Result<String, rimap_core::RimapError> {
    let Some(comment) = comment else {
        return Ok(String::new());
    };
    if comment.len() > MAX_BODY_BYTES {
        return Err(rimap_core::RimapError::invalid_input(format!(
            "comment too large ({} bytes); max is {MAX_BODY_BYTES}",
            comment.len(),
        )));
    }
    if comment.bytes().any(|b| b == b'\0') {
        return Err(rimap_core::RimapError::invalid_input(
            "comment contains a NUL byte",
        ));
    }
    Ok(comment.to_string())
}

/// Build the SMTP envelope for a forward, unioning To/Cc/Bcc into the
/// RCPT TO set. Bcc rides here only; it is never written into the message
/// headers (see `build_forward_message`).
fn build_envelope(from_addr: &str, input: &ForwardInput) -> rimap_smtp::SendEnvelope {
    let mut recipients: Vec<String> = Vec::new();
    recipients.extend(input.to.iter().map(|a| a.address.clone()));
    if let Some(cc) = &input.cc {
        recipients.extend(cc.iter().map(|a| a.address.clone()));
    }
    if let Some(bcc) = &input.bcc {
        recipients.extend(bcc.iter().map(|a| a.address.clone()));
    }
    rimap_smtp::SendEnvelope {
        from: from_addr.to_string(),
        to: recipients,
    }
}

/// Best-effort APPEND of the sent forward to the resolved Sent folder.
/// SMTP has already delivered by this point, so any IMAP failure surfaces
/// through the returned `SentCopyInfo`, never as a handler error.
async fn append_sent_copy(account: &AccountState, raw_msg: &[u8]) -> SentCopyInfo {
    let sent_folder: &str = account.special_use.sent().unwrap_or("Sent");
    if let Err(e) = rimap_authz::folder_name::FolderName::new(sent_folder) {
        tracing::warn!(
            tool = "forward",
            error_code = "invalid_sent_folder",
            "resolved Sent folder failed validation",
        );
        tracing::debug!(sent_folder, error = %e, "sent-folder validation detail");
        return SentCopyInfo::failed(sent_folder, rimap_core::ErrorCode::InvalidInput);
    }
    match account
        .imap
        .append_message(sent_folder, raw_msg, &[rimap_imap::types::Flag::Seen], &[])
        .await
    {
        Ok(result) => {
            SentCopyInfo::succeeded(sent_folder, result.uid.map(rimap_imap::types::Uid::get))
        }
        Err(e) => {
            let code = e.code();
            tracing::warn!(tool = "forward", error_code = %code, "failed to append to Sent folder");
            tracing::debug!(error = %e, "sent-folder append detail");
            SentCopyInfo::failed(sent_folder, code)
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    fn addr(a: &str) -> AddressInput {
        AddressInput {
            name: None,
            address: a.to_string(),
        }
    }

    fn input(to: Vec<AddressInput>) -> ForwardInput {
        ForwardInput {
            folder: "INBOX".into(),
            uid: core::num::NonZeroU32::new(1).unwrap(),
            to,
            cc: None,
            bcc: None,
            comment: None,
        }
    }

    #[test]
    fn comment_none_is_empty_body() {
        assert_eq!(validate_comment(None).unwrap(), "");
    }

    #[test]
    fn comment_allows_newlines() {
        // The comment is a body, not a header; multi-line text is valid.
        let c = validate_comment(Some("line one\r\nline two")).unwrap();
        assert_eq!(c, "line one\r\nline two");
    }

    #[test]
    fn comment_rejects_nul() {
        let err = validate_comment(Some("evil\0")).unwrap_err();
        assert_eq!(err.code(), rimap_core::error::ErrorCode::InvalidInput);
    }

    #[test]
    fn comment_over_cap_rejected() {
        let big = "x".repeat(MAX_BODY_BYTES + 1);
        let err = validate_comment(Some(&big)).unwrap_err();
        assert_eq!(err.code(), rimap_core::error::ErrorCode::InvalidInput);
    }

    #[test]
    fn envelope_unions_to_cc_bcc() {
        let mut inp = input(vec![addr("a@example.com")]);
        inp.cc = Some(vec![addr("b@example.com")]);
        inp.bcc = Some(vec![addr("c@example.com")]);
        let env = build_envelope("from@example.com", &inp);
        assert_eq!(env.from, "from@example.com");
        assert_eq!(
            env.to,
            vec!["a@example.com", "b@example.com", "c@example.com"],
        );
    }

    #[test]
    fn empty_to_rejected() {
        let inp = input(vec![]);
        let err =
            message_builder::validate_recipient_set(&inp.to, inp.cc.as_deref(), inp.bcc.as_deref())
                .unwrap_err();
        assert_eq!(err.code(), rimap_core::error::ErrorCode::InvalidInput);
    }

    #[test]
    fn crlf_recipient_rejected() {
        let inp = input(vec![addr("a@b>\r\nBcc: spy@evil")]);
        let err =
            message_builder::validate_recipient_set(&inp.to, inp.cc.as_deref(), inp.bcc.as_deref())
                .unwrap_err();
        assert_eq!(err.code(), rimap_core::error::ErrorCode::InvalidInput);
    }
}
