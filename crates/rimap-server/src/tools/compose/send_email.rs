//! `send_email` tool handler: compose and send via SMTP, then APPEND
//! a copy to the Sent folder.

use serde::Serialize;

use crate::boot::registry::AccountState;
use crate::mcp::response::ToolResponse;
use crate::tools::compose::message_builder::{self, AttachmentSummary, ComposeInput};

/// Input for `send_email` — identical fields to `create_draft`.
pub type SendEmailInput = ComposeInput;

/// Copy-to-Sent result included in a `send_email` response.
#[derive(Debug, Serialize, schemars::JsonSchema)]
#[non_exhaustive]
pub struct SentCopyInfo {
    /// Folder the copy was appended to.
    pub folder: String,
    /// UID assigned by the server, if returned.
    pub uid: Option<u32>,
    /// `true` if the APPEND failed (best-effort; send itself succeeded).
    pub failed: bool,
    /// Error code classifying why the APPEND failed. Present only when
    /// `failed` is `true`. Clients use this to decide whether to retry
    /// (e.g. `Timeout`, `ConnectionLost`) or surface an operator action
    /// (e.g. `InvalidInput`, `ImapProtocol`, `AttachmentTooLarge`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<rimap_core::ErrorCode>,
}

impl SentCopyInfo {
    /// A successful copy-to-Sent, carrying the server-assigned UID if any.
    #[must_use]
    pub(crate) fn succeeded(folder: &str, uid: Option<u32>) -> Self {
        Self {
            folder: folder.to_string(),
            uid,
            failed: false,
            failure_code: None,
        }
    }

    /// A failed (or skipped) copy-to-Sent classified by `code`.
    #[must_use]
    pub(crate) fn failed(folder: &str, code: rimap_core::ErrorCode) -> Self {
        Self {
            folder: folder.to_string(),
            uid: None,
            failed: true,
            failure_code: Some(code),
        }
    }
}

/// Trusted metadata for a `send_email` response.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct SendEmailMeta {
    /// Whether the message was delivered via SMTP.
    pub sent: bool,
    /// RFC 2822 `Message-ID` assigned to the outgoing message.
    pub message_id: Option<String>,
    /// Human-readable SMTP delivery status.
    pub smtp_status: String,
    /// Result of the best-effort copy to the Sent folder.
    pub sent_copy: SentCopyInfo,
    /// Attachments placed on the sent message (basename + byte count), in order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<AttachmentSummary>,
}

/// `send_email` handler.
///
/// # Errors
///
/// Returns `RimapError::Authz { code: InvalidInput, ... }` for malformed
/// recipient addresses or compose-input violations. Returns
/// `RimapError::Config` if no SMTP is configured for the account.
/// Returns `RimapError::Smtp { ... }` on SMTP failure. Returns
/// `RimapError::Internal` if the lettre envelope cannot be built from an
/// already-validated compose input (should not happen in practice). The
/// copy-to-Sent APPEND is best-effort; an IMAP failure there surfaces via
/// `sent_copy.failed` in the response, not as an error.
pub async fn handle(
    account: &AccountState,
    input: SendEmailInput,
) -> Result<ToolResponse<SendEmailMeta>, rimap_core::RimapError> {
    message_builder::validate_compose_input(&input)?;

    let smtp = account.smtp.as_ref().ok_or_else(|| {
        rimap_core::RimapError::Config("send_email requires SMTP configuration".into())
    })?;

    let from_addr = account.imap.username();
    // Exclude the Bcc header from the message DATA (include_bcc = false):
    // blind recipients are delivered via the SMTP envelope only, never
    // disclosed in the transmitted bytes. The same Bcc-free bytes are used
    // for the best-effort Sent copy below, so the Sent folder does not
    // record Bcc either (#432).
    let built = message_builder::build_message(account, from_addr, &input, false).await?;
    let raw_msg = built.raw;

    // Build SMTP envelope from the compose addresses (unions To/Cc/Bcc into
    // the RCPT TO set, so blind recipients are still delivered).
    let envelope = build_envelope(from_addr, &input);

    // Send via SMTP using raw bytes
    let smtp_response = smtp.send_raw(&envelope, &raw_msg).await?;
    tracing::info!(smtp_response, "send_email: SMTP send succeeded");

    // Extract Message-ID for the response
    let generated_msg_id = rimap_content::extract_message_id(&raw_msg);

    // Best-effort: APPEND copy to Sent folder. SMTP has already delivered
    // by this point — any failure (including a malformed resolved folder
    // name) must route through `sent_copy.failed` so the response does
    // not misleadingly report delivery failure. Each error is logged at
    // the failure site. The error code is forwarded to the helper so
    // clients can distinguish transient from permanent failures; the
    // helper stays pure and directly testable without an AccountState
    // fixture.
    let sent_folder: &str = account.special_use.sent().unwrap_or("Sent");
    let append_outcome: Option<Result<Option<u32>, rimap_core::ErrorCode>> =
        if let Err(e) = rimap_authz::folder_name::FolderName::new(sent_folder) {
            // Stable warn fields go in the structured record; the full
            // Display goes to DEBUG so it is available when tracing is
            // configured verbose but not piped into the default stderr
            // subscriber operator dashboards read.
            tracing::warn!(
                tool = "send_email",
                error_code = "invalid_sent_folder",
                "resolved Sent folder failed validation",
            );
            tracing::debug!(sent_folder, error = %e, "sent-folder validation detail");
            None
        } else {
            match account
                .imap
                .append_message(sent_folder, &raw_msg, &[rimap_imap::types::Flag::Seen], &[])
                .await
            {
                Ok(result) => Some(Ok(result.uid.map(rimap_imap::types::Uid::get))),
                Err(e) => {
                    let code = e.code();
                    tracing::warn!(
                        tool = "send_email",
                        error_code = %code,
                        "failed to append to Sent folder",
                    );
                    tracing::debug!(error = %e, "sent-folder append detail");
                    Some(Err(code))
                }
            }
        };

    Ok(ToolResponse::meta_only(SendEmailMeta {
        sent: true,
        message_id: generated_msg_id,
        smtp_status: "delivered".to_string(),
        sent_copy: build_sent_copy_info(sent_folder, append_outcome),
        attachments: built.attachments,
    })
    .with_warnings(built.security_warnings))
}

/// Translate a best-effort APPEND-to-Sent outcome into a [`SentCopyInfo`].
///
/// `append_outcome` encodes three cases the handler can produce:
/// - `None` — the resolved Sent folder name failed structural validation,
///   so APPEND was never attempted.
/// - `Some(Ok(uid))` — APPEND succeeded; `uid` is the server-assigned UID
///   if the server returned one in the `APPENDUID` response code.
/// - `Some(Err(_))` — APPEND was attempted and failed; the error has been
///   logged elsewhere and is intentionally discarded here so SMTP's
///   already-successful delivery is reported accurately.
///
/// In every failure case (`None` or `Some(Err)`), `failed = true` and
/// `uid = None`. Pure: enables direct unit testing without an
/// `AccountState` fixture.
fn build_sent_copy_info(
    sent_folder: &str,
    append_outcome: Option<Result<Option<u32>, rimap_core::ErrorCode>>,
) -> SentCopyInfo {
    let (uid, failed, failure_code) = match append_outcome {
        Some(Ok(uid)) => (uid, false, None),
        Some(Err(code)) => (None, true, Some(code)),
        None => (None, true, Some(rimap_core::ErrorCode::InvalidInput)),
    };
    SentCopyInfo {
        folder: sent_folder.to_string(),
        uid,
        failed,
        failure_code,
    }
}

/// Build a rimap-smtp `SendEnvelope` from the compose input addresses.
/// Address validation is delegated to rimap-smtp's parser at send time;
/// this helper only gathers the addresses into a single To / Cc / Bcc
/// recipient list and keeps the handler off the `lettre` type surface.
fn build_envelope(from_addr: &str, input: &ComposeInput) -> rimap_smtp::SendEnvelope {
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

#[cfg(test)]
mod tests {
    use super::build_envelope;
    use crate::tools::compose::message_builder::{AddressInput, ComposeInput};

    fn addr(address: &str) -> AddressInput {
        AddressInput {
            name: None,
            address: address.to_string(),
        }
    }

    fn compose(to: Vec<AddressInput>) -> ComposeInput {
        ComposeInput {
            to,
            cc: None,
            bcc: None,
            subject: "s".into(),
            body_text: "b".into(),
            body_html: None,
            attachments: None,
            in_reply_to_uid: None,
            in_reply_to_folder: None,
        }
    }

    #[test]
    fn build_envelope_single_recipient() {
        let env = build_envelope("from@example.com", &compose(vec![addr("a@example.com")]));
        assert_eq!(env.from, "from@example.com");
        assert_eq!(env.to, vec!["a@example.com"]);
    }

    #[test]
    fn build_envelope_unions_to_cc_bcc() {
        let mut input = compose(vec![addr("a@example.com")]);
        input.cc = Some(vec![addr("b@example.com")]);
        input.bcc = Some(vec![addr("c@example.com")]);
        let env = build_envelope("from@example.com", &input);
        assert_eq!(
            env.to,
            vec!["a@example.com", "b@example.com", "c@example.com"],
        );
    }

    #[test]
    fn build_envelope_keeps_raw_strings_for_smtp_layer() {
        // The SMTP layer owns address validation — build_envelope itself
        // is infallible and preserves the user-supplied string so the
        // rejection text from rimap-smtp matches what the caller typed.
        let env = build_envelope("not-an-email", &compose(vec![addr("also-bad")]));
        assert_eq!(env.from, "not-an-email");
        assert_eq!(env.to, vec!["also-bad"]);
    }

    use super::build_sent_copy_info;

    #[test]
    fn sent_copy_marks_failed_when_folder_validation_skipped_append() {
        // The handler signals "Sent folder name was invalid; APPEND was
        // never attempted" by passing `None`. SMTP delivery already
        // succeeded by this point, so the Meta still reports `sent: true`
        // upstream — only the sent_copy carries the failure.
        let info = build_sent_copy_info("Sent", None);
        assert_eq!(info.folder, "Sent");
        assert!(info.failed);
        assert_eq!(info.uid, None);
        assert_eq!(info.failure_code, Some(rimap_core::ErrorCode::InvalidInput));
    }

    #[test]
    fn sent_copy_carries_uid_on_successful_append() {
        let info = build_sent_copy_info("Sent", Some(Ok(Some(42))));
        assert_eq!(info.folder, "Sent");
        assert!(!info.failed);
        assert_eq!(info.uid, Some(42));
    }

    #[test]
    fn sent_copy_succeeds_without_uid_when_server_omits_appenduid() {
        // Some IMAP servers omit the APPENDUID response code; the handler
        // forwards `Ok(None)` and the resulting copy is marked successful
        // but UID-less.
        let info = build_sent_copy_info("Sent", Some(Ok(None)));
        assert_eq!(info.folder, "Sent");
        assert!(!info.failed);
        assert_eq!(info.uid, None);
    }

    #[test]
    fn sent_copy_marks_failed_when_append_errored() {
        let info = build_sent_copy_info("Sent", Some(Err(rimap_core::ErrorCode::ImapProtocol)));
        assert_eq!(info.folder, "Sent");
        assert!(info.failed);
        assert_eq!(info.uid, None);
        assert_eq!(info.failure_code, Some(rimap_core::ErrorCode::ImapProtocol));
    }

    #[test]
    fn sent_copy_preserves_resolved_folder_string() {
        // Confirms the response surfaces the *resolved* Sent folder name
        // (e.g. account.special_use.sent() result), not a hard-coded
        // "Sent" literal — important when the server uses non-default
        // SPECIAL-USE mappings like "[Gmail]/Sent Mail".
        let info = build_sent_copy_info("[Gmail]/Sent Mail", Some(Ok(Some(7))));
        assert_eq!(info.folder, "[Gmail]/Sent Mail");
    }

    #[test]
    fn sent_copy_carries_failure_code_when_append_errored() {
        let info = build_sent_copy_info("Sent", Some(Err(rimap_core::ErrorCode::Timeout)));
        assert!(info.failed);
        assert_eq!(info.uid, None);
        assert_eq!(info.failure_code, Some(rimap_core::ErrorCode::Timeout));
    }

    #[test]
    fn sent_copy_omits_failure_code_on_success() {
        let info = build_sent_copy_info("Sent", Some(Ok(Some(42))));
        assert!(!info.failed);
        assert_eq!(info.failure_code, None);
    }
}
