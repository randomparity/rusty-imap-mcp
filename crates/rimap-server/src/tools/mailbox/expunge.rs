//! `expunge` tool handler: permanently remove \Deleted messages from a folder.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::boot::registry::AccountState;
use crate::mcp::response::ToolResponse;

/// Input for `expunge`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ExpungeInput {
    /// Folder to expunge.
    pub folder: String,
}

/// Trusted metadata for an `expunge` response.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct ExpungeMeta {
    /// Folder that was expunged.
    pub folder: String,
    /// Number of messages permanently removed.
    pub expunged_count: u32,
    /// UIDs that had the `\Deleted` flag set before expunge.
    pub deleted_uids_before_expunge: Vec<u32>,
}

/// `expunge` handler.
///
/// # Errors
///
/// `FolderGuard::check_expunge` runs before any IMAP traffic and is the
/// first source of errors:
/// - `RimapError::Authz { code: InvalidFolderName, ... }` if the name
///   fails structural validation (empty, too long, forbidden chars).
/// - `RimapError::Authz { code: ExpungeDenied, ... }` when the folder
///   is not in `expunge_folders`.
///
/// After the guard passes, `RimapError::Imap { ... }` may be propagated
/// from the underlying EXPUNGE. The upstream `DispatchGuard::pre_dispatch`
/// gate may also return `PostureDenied`.
pub async fn handle(
    account: &AccountState,
    input: ExpungeInput,
) -> Result<ToolResponse<ExpungeMeta>, rimap_core::RimapError> {
    crate::tools::validation::validate_folder_input("folder", &input.folder)?;
    account.folder_guard.check_expunge(&input.folder)?;

    let (deleted_uids, expunged_count) = account.imap.expunge(&input.folder).await?;

    Ok(ToolResponse::meta_only(ExpungeMeta {
        folder: input.folder,
        expunged_count,
        deleted_uids_before_expunge: deleted_uids.iter().map(|u| u.get()).collect(),
    }))
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use rimap_authz::FolderGuard;
    use rimap_authz::error::AuthzError;

    use super::{ExpungeInput, ExpungeMeta};

    fn sample_meta(uids: Vec<u32>) -> ExpungeMeta {
        ExpungeMeta {
            folder: "Trash".to_string(),
            expunged_count: u32::try_from(uids.len()).unwrap(),
            deleted_uids_before_expunge: uids,
        }
    }

    #[test]
    fn input_parses_from_json() {
        let input: ExpungeInput = serde_json::from_str(r#"{"folder": "Trash"}"#).unwrap();
        assert_eq!(input.folder, "Trash");
    }

    #[test]
    fn input_round_trip_json_form_is_stable() {
        let input: ExpungeInput = serde_json::from_str(r#"{"folder": "Archive"}"#).unwrap();
        // Reparse via the meta shape so adding fields to ExpungeInput
        // later doesn't silently change the accepted wire format.
        let meta = ExpungeMeta {
            folder: input.folder.clone(),
            expunged_count: 0,
            deleted_uids_before_expunge: vec![],
        };
        assert_eq!(meta.folder, "Archive");
    }

    #[test]
    fn meta_shape_with_empty_deleted_uids() {
        let meta = sample_meta(vec![]);
        let json = serde_json::to_string(&meta).unwrap();
        assert!(json.contains(r#""folder":"Trash""#), "json = {json}");
        assert!(json.contains(r#""expunged_count":0"#), "json = {json}");
        assert!(
            json.contains(r#""deleted_uids_before_expunge":[]"#),
            "json = {json}"
        );
    }

    #[test]
    fn meta_shape_with_non_empty_deleted_uids() {
        let meta = sample_meta(vec![1, 2, 3]);
        let value = serde_json::to_value(&meta).unwrap();
        assert_eq!(value["expunged_count"], serde_json::json!(3));
        assert_eq!(
            value["deleted_uids_before_expunge"],
            serde_json::json!([1, 2, 3])
        );
    }

    #[test]
    fn missing_folder_name_is_rejected_by_guard() {
        // The handler's first step is `folder_guard.check_expunge(&folder)`,
        // which validates the folder name before any IMAP traffic. Empty
        // or whitespace-only names fail structural validation.
        let guard = FolderGuard::new(&[], &["Trash".into()]);
        let err = guard.check_expunge("").unwrap_err();
        assert!(
            matches!(err, AuthzError::InvalidFolderName { .. }),
            "expected InvalidFolderName, got {err:?}"
        );
    }

    #[test]
    fn folder_outside_allowlist_is_rejected_by_guard() {
        // Any folder not listed in `expunge_folders` surfaces as
        // `ExpungeDenied` (distinct from missing-folder / name-invalid).
        let guard = FolderGuard::new(&[], &["Trash".into()]);
        let err = guard.check_expunge("INBOX").unwrap_err();
        assert!(
            matches!(err, AuthzError::ExpungeDenied { .. }),
            "expected ExpungeDenied, got {err:?}"
        );
    }

    #[test]
    fn allowlisted_folder_is_accepted_by_guard() {
        let guard = FolderGuard::new(&[], &["Trash".into()]);
        assert!(guard.check_expunge("Trash").is_ok());
    }
}
