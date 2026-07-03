//! `move_message` tool handler.

use rimap_core::UidSelector;
use rimap_imap::types::Uid;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::boot::registry::AccountState;
use crate::mcp::response::ToolResponse;

/// Input for `move_message`. Accepts either a single `uid` or a batch
/// `uids` (exactly one of the two; batch max 100).
// Design note (not published — see #405): the asymmetry with
// single-target tools (`fetch_message`, `list_attachments`,
// `download_attachment`, `delete_message`) is deliberate: batch shapes
// are reserved for commutative, idempotent mutations where per-UID
// ordering does not matter and results fan out uniformly. Read-side and
// destructive single-target tools keep a scalar `uid` so the response
// schema and error semantics stay unambiguous.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct MoveMessageInput {
    /// Source folder.
    pub folder: String,
    /// Destination folder.
    pub destination: String,
    /// UID target: `{"uid": N}` or `{"uids": [...]}`.
    #[serde(flatten)]
    pub target: UidSelector,
    /// When set, the handler verifies the source folder's UIDVALIDITY matches
    /// this value before performing the move. A mismatch returns
    /// `ERR_UID_VALIDITY_CHANGED`. Omit to skip the guard.
    #[serde(
        default,
        deserialize_with = "crate::tools::lenient_int::deserialize_opt_u32",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(schema_with = "crate::tools::lenient_int::schema_opt_u32")]
    pub expected_source_uidvalidity: Option<u32>,
}

/// Per-UID move result entry.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct MoveEntry {
    /// Source UID that was moved.
    pub old_uid: u32,
    /// Destination UID assigned by the server, if returned.
    pub new_uid: Option<u32>,
}

/// Trusted metadata for a `move_message` response.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct MoveMessageMeta {
    /// Source folder.
    pub folder: String,
    /// Destination folder.
    pub destination: String,
    /// Per-UID move results.
    pub moves: Vec<MoveEntry>,
    /// Source-folder UIDVALIDITY observed at the guard STATUS probe, or at
    /// the source SELECT if no guard was requested. `None` when the server
    /// omitted the response code or no guard/probe occurred. (#70)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_uid_validity: Option<u32>,
    /// Destination-folder UIDVALIDITY observed after the COPY+DELETE fallback
    /// path. `None` on the UID MOVE happy path (destination UIDVALIDITY not
    /// observable without an extra STATUS) or when the server omitted the
    /// response code. (#70)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_uid_validity: Option<u32>,
}

/// Execute the `move_message` tool.
///
/// In addition to the posture-matrix gate in `DispatchGuard::pre_dispatch`,
/// this handler runs [`rimap_authz::folder_name::FolderName`] structural
/// validation on both source and destination. The protected-folder list
/// is intentionally not consulted here: it gates folder-mutation
/// operations (delete, rename, create), not message moves between
/// existing folders. Per-folder ACLs on the IMAP server still apply
/// when the COPY+EXPUNGE fallback runs.
///
/// # Errors
///
/// Returns `RimapError::Authz { code: InvalidInput, ... }` for malformed
/// `uid`/`uids` (zero, both/neither set, batch over 100) or malformed
/// folder names. Returns `RimapError::Imap { ... }` for IMAP-layer
/// failures.
pub async fn handle(
    account: &AccountState,
    input: MoveMessageInput,
) -> Result<ToolResponse<MoveMessageMeta>, rimap_core::RimapError> {
    crate::tools::validation::validate_folder_input("folder", &input.folder)?;
    crate::tools::validation::validate_folder_input("destination", &input.destination)?;
    let uids: Vec<Uid> = input
        .target
        .into_uids()
        .into_iter()
        .map(Uid::from)
        .collect();
    let outcome = account
        .imap
        .move_messages(
            &input.folder,
            &input.destination,
            &uids,
            input.expected_source_uidvalidity,
        )
        .await?;

    let moves: Vec<MoveEntry> = outcome
        .results
        .iter()
        .map(|r| MoveEntry {
            old_uid: r.old_uid.get(),
            new_uid: r.new_uid.map(Uid::get),
        })
        .collect();

    let warnings =
        super::fallback_security_warnings(outcome.used_fallback, outcome.folder_wide_expunge);

    Ok(ToolResponse::meta_only(MoveMessageMeta {
        folder: input.folder,
        destination: input.destination,
        moves,
        source_uid_validity: outcome.source_uid_validity,
        destination_uid_validity: outcome.destination_uid_validity,
    })
    .with_warnings(warnings))
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    fn base_meta(src: Option<u32>, dst: Option<u32>) -> MoveMessageMeta {
        MoveMessageMeta {
            folder: "INBOX".to_string(),
            destination: "Archive".to_string(),
            moves: vec![],
            source_uid_validity: src,
            destination_uid_validity: dst,
        }
    }

    #[test]
    fn move_meta_serializes_source_uid_validity_when_some() {
        let meta = base_meta(Some(10), None);
        let json = serde_json::to_string(&meta).unwrap();
        assert!(
            json.contains(r#""source_uid_validity":10"#),
            "json = {json}"
        );
        assert!(!json.contains("destination_uid_validity"), "json = {json}");
    }

    #[test]
    fn move_meta_serializes_destination_uid_validity_when_some() {
        let meta = base_meta(None, Some(20));
        let json = serde_json::to_string(&meta).unwrap();
        assert!(!json.contains("source_uid_validity"), "json = {json}");
        assert!(
            json.contains(r#""destination_uid_validity":20"#),
            "json = {json}"
        );
    }

    #[test]
    fn move_meta_omits_both_uid_validity_fields_when_none() {
        let meta = base_meta(None, None);
        let json = serde_json::to_string(&meta).unwrap();
        assert!(!json.contains("source_uid_validity"), "json = {json}");
        assert!(!json.contains("destination_uid_validity"), "json = {json}");
    }

    #[test]
    fn move_meta_serializes_both_uid_validity_fields_when_some() {
        let meta = base_meta(Some(11), Some(22));
        let json = serde_json::to_string(&meta).unwrap();
        assert!(
            json.contains(r#""source_uid_validity":11"#),
            "json = {json}"
        );
        assert!(
            json.contains(r#""destination_uid_validity":22"#),
            "json = {json}"
        );
    }

    #[test]
    fn move_input_parses_expected_source_uidvalidity_when_present() {
        let input: MoveMessageInput = serde_json::from_str(
            r#"{"folder": "INBOX", "destination": "Archive", "uid": 1,
               "expected_source_uidvalidity": 55}"#,
        )
        .unwrap();
        assert_eq!(input.expected_source_uidvalidity, Some(55));
    }

    #[test]
    fn move_input_defaults_expected_source_uidvalidity_to_none() {
        let input: MoveMessageInput =
            serde_json::from_str(r#"{"folder": "INBOX", "destination": "Archive", "uid": 1}"#)
                .unwrap();
        assert_eq!(input.expected_source_uidvalidity, None);
    }
}
