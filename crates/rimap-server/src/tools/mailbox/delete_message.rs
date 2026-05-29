//! `delete_message` tool handler: flag as \Deleted and move to Trash.
//!
//! The destination folder name is hard-coded to `"Trash"` by design:
//! IMAP servers almost universally use this exact spelling (RFC 6154
//! `\Trash` SPECIAL-USE mailbox maps to `Trash` at every mainstream
//! provider). If a deployment needs a different folder, the right seam
//! is a per-account `trash_folder` config override — not a per-call
//! argument — so that the gesture of "delete" is consistent.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::boot::registry::AccountState;
use crate::mcp::response::ToolResponse;

/// Input for `delete_message`.
///
/// # Shape
///
/// This tool intentionally takes a single scalar `uid` (non-zero) rather than a
/// batch. The asymmetry with batch-capable tools (`flag`, `add_label`,
/// `move_message`) is deliberate: batch shapes (`uid` XOR `uids`) are
/// reserved for commutative, idempotent mutations where per-UID ordering
/// does not matter and results fan out uniformly. Read-side and
/// destructive single-target tools keep a scalar `uid` so the response
/// schema and error semantics stay unambiguous.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct DeleteMessageInput {
    /// Source folder containing the message.
    pub folder: String,
    /// UID of the message to delete.
    #[serde(deserialize_with = "crate::tools::lenient_int::deserialize_nonzero_u32")]
    #[schemars(schema_with = "crate::tools::lenient_int::schema_nonzero_u32")]
    pub uid: core::num::NonZeroU32,
}

/// Target folder for `delete_message`. Hard-coded per the module-level
/// doc; a config override is the right seam if a deployment needs to
/// diverge from this.
const TRASH_FOLDER: &str = "Trash";

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
    /// Trash folder the message was moved to.
    pub destination: &'static str,
}

/// `delete_message` handler.
///
/// # Errors
///
/// Returns `RimapError::Imap { ... }` for IMAP-layer failures (server
/// rejects the MOVE/COPY/STORE or the source folder is missing). The
/// upstream `DispatchGuard::pre_dispatch` gate may return
/// `PostureDenied`.
pub async fn handle(
    account: &AccountState,
    input: DeleteMessageInput,
) -> Result<ToolResponse<DeleteMessageMeta>, rimap_core::RimapError> {
    crate::tools::validation::validate_folder_input("folder", &input.folder)?;

    let uid = rimap_imap::types::Uid::from(input.uid);

    let result = account
        .imap
        .delete_message(&input.folder, uid, TRASH_FOLDER)
        .await?;

    let warnings =
        super::fallback_security_warnings(result.used_fallback, result.folder_wide_expunge);

    Ok(ToolResponse::meta_only(DeleteMessageMeta {
        deleted: true,
        folder: input.folder,
        uid: input.uid.get(),
        moved_to_trash: result.moved_to_trash,
        destination: TRASH_FOLDER,
    })
    .with_warnings(warnings))
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::{DeleteMessageInput, DeleteMessageMeta, TRASH_FOLDER};

    fn sample_meta(uid: u32, moved: bool) -> DeleteMessageMeta {
        DeleteMessageMeta {
            deleted: true,
            folder: "INBOX".to_string(),
            uid,
            moved_to_trash: moved,
            destination: TRASH_FOLDER,
        }
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
        };
        let uid = rimap_imap::types::Uid::from(input.uid);
        assert_eq!(uid.get(), 42);
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
    fn trash_constant_round_trips_through_meta() {
        // The TRASH_FOLDER literal is load-bearing: downstream clients
        // and audit trails read the `destination` string back. Pin the
        // exact spelling so a silent rename can't drift past review.
        assert_eq!(TRASH_FOLDER, "Trash");
        let meta = sample_meta(1, true);
        assert_eq!(meta.destination, TRASH_FOLDER);
        let json = serde_json::to_string(&meta).unwrap();
        assert!(json.contains(r#""destination":"Trash""#), "json = {json}");
    }

    #[test]
    fn input_round_trips_through_json() {
        let input: DeleteMessageInput =
            serde_json::from_str(r#"{"folder": "Archive", "uid": 123}"#).unwrap();
        assert_eq!(input.folder, "Archive");
        assert_eq!(input.uid.get(), 123);
    }
}
