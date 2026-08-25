//! `delete_message` tool handler: flag as \Deleted and move to Trash.
//!
//! The destination folder is resolved via the account's RFC 6154
//! `\Trash` SPECIAL-USE mailbox, falling back to the literal `"Trash"`
//! when the server does not advertise SPECIAL-USE or has no `\Trash`
//! mailbox. This mirrors `create_draft`'s `\Drafts` resolution — servers
//! such as Gmail (`[Gmail]/Trash`) do not use the literal name `Trash`,
//! and moving a message into a folder the provider doesn't recognize as
//! trash silently defeats the deletion (no auto-purge, still searchable).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::boot::registry::AccountState;
use crate::mcp::response::ToolResponse;

// Scalar-uid rationale: this tool intentionally has no batch shape, see
// the `Scalar vs batch uid shapes` section of `crate::tools` module docs (#405).
#[derive(Debug, Deserialize, JsonSchema)]
pub struct DeleteMessageInput {
    /// Source folder containing the message.
    pub folder: String,
    /// UID of the message to delete.
    #[serde(deserialize_with = "crate::tools::lenient_int::deserialize_nonzero_u32")]
    #[schemars(schema_with = "crate::tools::lenient_int::schema_nonzero_u32")]
    pub uid: core::num::NonZeroU32,
    /// When set, the handler verifies the folder's UIDVALIDITY matches this
    /// value before deleting the message. A mismatch returns
    /// `ERR_UID_VALIDITY_CHANGED`. Omit to skip the guard.
    #[serde(
        default,
        deserialize_with = "crate::tools::lenient_int::deserialize_opt_u32",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(schema_with = "crate::tools::lenient_int::schema_opt_u32")]
    pub expected_uidvalidity: Option<u32>,
}

/// Literal fallback used when the account has no `\Trash` SPECIAL-USE
/// mailbox on record.
const TRASH_FOLDER_FALLBACK: &str = "Trash";

/// Trusted metadata for a `delete_message` response.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct DeleteMessageMeta {
    /// Always `true` when the handler returns `Ok`.
    pub deleted: bool,
    /// Source folder the message was deleted from.
    pub folder: String,
    /// UID of the deleted message.
    pub uid: u32,
    /// Whether the message was moved to the trash folder.
    pub moved_to_trash: bool,
    /// Trash folder the message was moved to — the account's resolved
    /// `\Trash` SPECIAL-USE mailbox name, or the literal `"Trash"` fallback.
    pub destination: String,
    /// UIDVALIDITY observed at the SELECT used for this operation. `None`
    /// when the server's SELECT response omitted the response code. (#70)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid_validity: Option<u32>,
}

/// `delete_message` handler.
///
/// # Errors
///
/// Returns `RimapError::Imap { ... }` for IMAP-layer failures (server
/// rejects the MOVE/COPY/STORE or the source folder is missing).
/// Returns `RimapError::UidValidityChanged` if `expected_uidvalidity` is
/// set and does not match the folder's observed UIDVALIDITY. The
/// upstream `DispatchGuard::pre_dispatch` gate may return
/// `PostureDenied`.
pub async fn handle(
    account: &AccountState,
    input: DeleteMessageInput,
) -> Result<ToolResponse<DeleteMessageMeta>, rimap_core::RimapError> {
    crate::tools::validation::validate_folder_input("folder", &input.folder)?;

    let trash_folder: &str = account.special_use.trash().unwrap_or(TRASH_FOLDER_FALLBACK);
    crate::tools::validation::validate_folder_input("trash folder", trash_folder)?;

    let uid = rimap_imap::types::Uid::from(input.uid);

    let outcome = account
        .imap
        .delete_message(&input.folder, uid, trash_folder, input.expected_uidvalidity)
        .await?;
    let result = outcome.result;
    let uid_validity = outcome.uidvalidity;

    let warnings =
        super::fallback_security_warnings(result.used_fallback, result.folder_wide_expunge);

    Ok(ToolResponse::meta_only(DeleteMessageMeta {
        deleted: true,
        folder: input.folder,
        uid: input.uid.get(),
        moved_to_trash: result.moved_to_trash,
        destination: trash_folder.to_string(),
        uid_validity,
    })
    .with_warnings(warnings))
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use rimap_imap::SpecialUseMap;
    use rimap_imap::special_use::SpecialUse;
    use rimap_imap::types::Folder;

    use super::{DeleteMessageInput, DeleteMessageMeta, TRASH_FOLDER_FALLBACK};

    fn folder(name: &str, special: Option<SpecialUse>) -> Folder {
        let mut folder = Folder::new(name.to_string());
        folder.delimiter = Some('/');
        folder.special_use = special;
        folder
    }

    fn sample_meta(uid: u32, moved: bool) -> DeleteMessageMeta {
        DeleteMessageMeta {
            deleted: true,
            folder: "INBOX".to_string(),
            uid,
            moved_to_trash: moved,
            destination: TRASH_FOLDER_FALLBACK.to_string(),
            uid_validity: None,
        }
    }

    #[test]
    fn trash_fallback_is_literal_trash_when_special_use_absent() {
        // Mirrors the handler's fallback:
        //     account.special_use.trash().unwrap_or(TRASH_FOLDER_FALLBACK)
        let map = SpecialUseMap::from_folders(&[folder("INBOX", None)]);
        let trash_folder: &str = map.trash().unwrap_or(TRASH_FOLDER_FALLBACK);
        assert_eq!(trash_folder, "Trash");
    }

    #[test]
    fn trash_resolves_to_server_name_when_special_use_present() {
        let map = SpecialUseMap::from_folders(&[
            folder("INBOX", None),
            folder("[Gmail]/Trash", Some(SpecialUse::Trash)),
        ]);
        let trash_folder: &str = map.trash().unwrap_or(TRASH_FOLDER_FALLBACK);
        assert_eq!(trash_folder, "[Gmail]/Trash");
    }

    #[test]
    fn trash_fallback_survives_when_only_other_special_uses_present() {
        // \Sent is present, \Trash is not → fallback still applies.
        let map = SpecialUseMap::from_folders(&[
            folder("INBOX", None),
            folder("Sent", Some(SpecialUse::Sent)),
        ]);
        let trash_folder: &str = map.trash().unwrap_or(TRASH_FOLDER_FALLBACK);
        assert_eq!(trash_folder, "Trash");
    }

    #[test]
    fn fallback_trash_name_passes_folder_name_validation() {
        // `FolderName::new("Trash")` must not error — the handler
        // revalidates whatever the fallback produced and would surface
        // `RimapError::invalid_input` otherwise.
        assert!(rimap_core::folder_name::FolderName::new("Trash").is_ok());
    }

    #[test]
    fn zero_uid_is_rejected_at_deserialize() {
        // The NonZeroU32 field rejects 0 before the handler is called.
        let err = serde_json::from_str::<DeleteMessageInput>(r#"{"folder": "INBOX", "uid": 0}"#)
            .unwrap_err();
        assert!(
            err.to_string().contains("zero") || err.to_string().contains("non-zero"),
            "deserialize error should call out the zero constraint: {err}"
        );
    }

    #[test]
    fn nonzero_uid_parses_through_to_typed_uid() {
        let input = DeleteMessageInput {
            folder: "INBOX".into(),
            uid: core::num::NonZeroU32::new(42).unwrap(),
            expected_uidvalidity: None,
        };
        let uid = rimap_imap::types::Uid::from(input.uid);
        assert_eq!(uid.get(), 42);
    }

    #[test]
    fn input_parses_expected_uidvalidity_when_present() {
        let input: DeleteMessageInput =
            serde_json::from_str(r#"{"folder": "INBOX", "uid": 1, "expected_uidvalidity": 42}"#)
                .unwrap();
        assert_eq!(input.expected_uidvalidity, Some(42));
    }

    #[test]
    fn input_defaults_expected_uidvalidity_to_none() {
        let input: DeleteMessageInput =
            serde_json::from_str(r#"{"folder": "INBOX", "uid": 1}"#).unwrap();
        assert_eq!(input.expected_uidvalidity, None);
    }

    #[test]
    fn meta_json_contains_all_expected_keys() {
        let meta = sample_meta(7, true);
        let value = serde_json::to_value(&meta).unwrap();
        let obj = value.as_object().unwrap();
        assert_eq!(obj.get("deleted"), Some(&serde_json::json!(true)));
        assert_eq!(obj.get("folder"), Some(&serde_json::json!("INBOX")));
        assert_eq!(obj.get("uid"), Some(&serde_json::json!(7)));
        assert_eq!(obj.get("moved_to_trash"), Some(&serde_json::json!(true)));
        assert_eq!(obj.get("destination"), Some(&serde_json::json!("Trash")));
    }

    #[test]
    fn meta_preserves_moved_to_trash_false() {
        let meta = sample_meta(9, false);
        let json = serde_json::to_string(&meta).unwrap();
        assert!(json.contains(r#""moved_to_trash":false"#), "json = {json}");
    }

    #[test]
    fn destination_reports_resolved_folder_not_fallback_when_special_use_present() {
        // Downstream clients and audit trails read the `destination`
        // string back to learn where the message actually landed. Pin
        // that it carries the resolved SPECIAL-USE name, not the
        // hard-coded fallback, when the server advertises one.
        let meta = DeleteMessageMeta {
            deleted: true,
            folder: "INBOX".to_string(),
            uid: 1,
            moved_to_trash: true,
            destination: "[Gmail]/Trash".to_string(),
            uid_validity: None,
        };
        let json = serde_json::to_string(&meta).unwrap();
        assert!(
            json.contains(r#""destination":"[Gmail]/Trash""#),
            "json = {json}"
        );
    }

    #[test]
    fn meta_serializes_uid_validity_when_some() {
        let mut meta = sample_meta(1, true);
        meta.uid_validity = Some(42);
        let json = serde_json::to_string(&meta).unwrap();
        assert!(json.contains(r#""uid_validity":42"#), "json = {json}");
    }

    #[test]
    fn meta_omits_uid_validity_when_none() {
        let meta = sample_meta(1, true);
        let json = serde_json::to_string(&meta).unwrap();
        assert!(!json.contains("uid_validity"), "json = {json}");
    }

    #[test]
    fn input_round_trips_through_json() {
        let input: DeleteMessageInput =
            serde_json::from_str(r#"{"folder": "Archive", "uid": 123}"#).unwrap();
        assert_eq!(input.folder, "Archive");
        assert_eq!(input.uid.get(), 123);
    }
}
