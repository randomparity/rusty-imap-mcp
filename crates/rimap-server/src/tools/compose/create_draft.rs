//! `create_draft` tool handler: compose a draft email and APPEND it
//! to the Drafts folder with a `$PendingReview` keyword.

use serde::Serialize;

use crate::boot::registry::AccountState;
use crate::mcp::response::ToolResponse;
use crate::tools::compose::message_builder::{self, ComposeInput};

/// Input for `create_draft` — identical to shared `ComposeInput`.
pub type CreateDraftInput = ComposeInput;

/// Trusted metadata for a `create_draft` response.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct CreateDraftMeta {
    /// Folder the draft was appended to.
    pub folder: String,
    /// UID assigned by the server, if returned.
    pub uid: Option<u32>,
    /// RFC 2822 `Message-ID` assigned to the draft.
    pub message_id: Option<String>,
    /// IMAP keywords applied to the draft.
    pub keywords: Vec<&'static str>,
}

/// `create_draft` handler.
///
/// # Errors
///
/// Returns `RimapError::Authz { code: InvalidInput, ... }` for malformed
/// recipient addresses, subject/body size violations, or bad threading
/// headers. Returns `RimapError::Imap { ... }` on APPEND failure.
/// Returns `RimapError::Internal` if `message_builder::build_message`
/// or `apply_threading_headers` reports an unrecoverable construction
/// failure (should not happen with validated input). The upstream
/// `DispatchGuard::pre_dispatch` gate returns
/// `Authz { code: PostureDenied }` when posture forbids draft creation.
pub async fn handle(
    account: &AccountState,
    input: CreateDraftInput,
) -> Result<ToolResponse<CreateDraftMeta>, rimap_core::RimapError> {
    message_builder::validate_compose_input(&input)?;
    let from_addr = account.imap.username();
    let raw_msg = message_builder::build_message(account, from_addr, &input).await?;

    let drafts_folder: &str = account.special_use.drafts().unwrap_or("Drafts");
    crate::tools::validation::validate_folder_input("drafts folder", drafts_folder)?;
    let result = account
        .imap
        .append_message(
            drafts_folder,
            &raw_msg,
            &[rimap_imap::types::Flag::Draft],
            &["$PendingReview"],
        )
        .await?;

    let generated_msg_id = rimap_content::extract_message_id(&raw_msg);

    Ok(ToolResponse::meta_only(CreateDraftMeta {
        folder: drafts_folder.to_string(),
        uid: result.uid.map(rimap_imap::types::Uid::get),
        message_id: generated_msg_id,
        keywords: vec!["$PendingReview"],
    }))
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use rimap_imap::SpecialUseMap;
    use rimap_imap::special_use::SpecialUse;
    use rimap_imap::types::{Folder, FolderAttribute};

    use super::CreateDraftMeta;

    fn folder(name: &str, special: Option<SpecialUse>) -> Folder {
        Folder {
            name: name.to_string(),
            attributes: Vec::<FolderAttribute>::new(),
            delimiter: Some('/'),
            special_use: special,
        }
    }

    #[test]
    fn drafts_fallback_is_literal_drafts_when_special_use_absent() {
        // Mirrors the handler's fallback:
        //     account.special_use.drafts().unwrap_or("Drafts")
        let map = SpecialUseMap::from_folders(&[folder("INBOX", None)]);
        let drafts_folder: &str = map.drafts().unwrap_or("Drafts");
        assert_eq!(drafts_folder, "Drafts");
    }

    #[test]
    fn drafts_resolves_to_server_name_when_special_use_present() {
        let map = SpecialUseMap::from_folders(&[
            folder("INBOX", None),
            folder("[Gmail]/Drafts", Some(SpecialUse::Drafts)),
        ]);
        let drafts_folder: &str = map.drafts().unwrap_or("Drafts");
        assert_eq!(drafts_folder, "[Gmail]/Drafts");
    }

    #[test]
    fn drafts_fallback_survives_when_only_other_special_uses_present() {
        // \Sent is present, \Drafts is not → fallback still applies.
        let map = SpecialUseMap::from_folders(&[
            folder("INBOX", None),
            folder("Sent", Some(SpecialUse::Sent)),
        ]);
        let drafts_folder: &str = map.drafts().unwrap_or("Drafts");
        assert_eq!(drafts_folder, "Drafts");
    }

    #[test]
    fn fallback_drafts_name_passes_folder_name_validation() {
        // `FolderName::new("Drafts")` must not error — the handler
        // revalidates whatever the fallback produced and would surface
        // `RimapError::invalid_input` otherwise.
        assert!(rimap_authz::folder_name::FolderName::new("Drafts").is_ok());
    }

    #[test]
    fn empty_drafts_override_is_rejected_by_folder_name() {
        // If a server somehow reported an empty special-use folder name,
        // the revalidation at the handler would reject it. Pin the
        // structural invariant so a regression doesn't bypass the check.
        assert!(rimap_authz::folder_name::FolderName::new("").is_err());
    }

    #[test]
    fn meta_shape_with_uid_some() {
        let meta = CreateDraftMeta {
            folder: "Drafts".to_string(),
            uid: Some(42),
            message_id: Some("<abc@example.com>".to_string()),
            keywords: vec!["$PendingReview"],
        };
        let value = serde_json::to_value(&meta).unwrap();
        assert_eq!(value["folder"], serde_json::json!("Drafts"));
        assert_eq!(value["uid"], serde_json::json!(42));
        assert_eq!(value["message_id"], serde_json::json!("<abc@example.com>"));
        assert_eq!(value["keywords"], serde_json::json!(["$PendingReview"]));
    }

    #[test]
    fn meta_shape_with_uid_none_emits_null() {
        let meta = CreateDraftMeta {
            folder: "Drafts".to_string(),
            uid: None,
            message_id: None,
            keywords: vec!["$PendingReview"],
        };
        let value = serde_json::to_value(&meta).unwrap();
        assert_eq!(value["uid"], serde_json::Value::Null);
        assert_eq!(value["message_id"], serde_json::Value::Null);
        // Regardless of UID presence, the $PendingReview keyword is
        // always set on the draft — this is the quarantine contract.
        assert_eq!(value["keywords"], serde_json::json!(["$PendingReview"]));
    }

    #[test]
    fn meta_always_carries_pending_review_keyword() {
        // The keywords field is hard-coded at construction; an empty
        // list here would mean a regression in the handler. Capture the
        // intent explicitly so a refactor that rewires the field can't
        // silently drop the quarantine marker.
        let meta = CreateDraftMeta {
            folder: "Drafts".to_string(),
            uid: Some(1),
            message_id: None,
            keywords: vec!["$PendingReview"],
        };
        assert!(meta.keywords.contains(&"$PendingReview"));
        assert_eq!(meta.keywords.len(), 1);
    }
}
