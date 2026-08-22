//! Flag mutation tool handlers: `mark_read`, `mark_unread`, `flag`,
//! `unflag`.
//!
//! # Errors (applies to all four handlers)
//!
//! The `uid`/`uids` shape is validated at deserialize time via
//! [`rimap_core::UidSelector`] — ambiguous or empty payloads fail with a
//! JSON-Schema error before the handler runs. Returns
//! `RimapError::Imap { ... }` for IMAP-layer failures. The upstream
//! `DispatchGuard::pre_dispatch` gate may return `PostureDenied`.

use rimap_core::UidSelector;
use rimap_imap::types::{Flag, FlagAction, Uid};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::boot::registry::AccountState;
use crate::mcp::response::ToolResponse;

/// Input for flag mutation tools. Accepts either a single `uid` or a
/// batch `uids` (exactly one of the two; batch max 100).
// Scalar-vs-batch uid shape rationale: deliberate asymmetry, see the
// `Scalar vs batch uid shapes` section of `crate::tools` module docs (#405).
#[derive(Debug, Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct FlagInput {
    /// Target folder.
    pub folder: String,
    /// UID target: `{"uid": N}` or `{"uids": [...]}`.
    #[serde(flatten)]
    pub target: UidSelector,
    /// When set, the handler verifies the folder's UIDVALIDITY matches this
    /// value before applying flags. A mismatch returns
    /// `ERR_UID_VALIDITY_CHANGED`. Omit to skip the guard.
    #[serde(
        default,
        deserialize_with = "crate::tools::lenient_int::deserialize_opt_u32",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(schema_with = "crate::tools::lenient_int::schema_opt_u32")]
    pub expected_uidvalidity: Option<u32>,
}

/// Trusted metadata for a flag mutation response.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct FlagsMeta {
    /// Folder the flags were updated in.
    pub folder: String,
    /// UIDs that were updated.
    pub uids_updated: Vec<u32>,
    /// UIDVALIDITY observed at the SELECT used for this operation. `None`
    /// when the server's SELECT response omitted the response code. (#70)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid_validity: Option<u32>,
}

pub async fn handle_mark_read(
    account: &AccountState,
    input: FlagInput,
) -> Result<ToolResponse<FlagsMeta>, rimap_core::RimapError> {
    Box::pin(handle_flag_op(
        account,
        input,
        &[Flag::Seen],
        FlagAction::Add,
    ))
    .await
}

pub async fn handle_mark_unread(
    account: &AccountState,
    input: FlagInput,
) -> Result<ToolResponse<FlagsMeta>, rimap_core::RimapError> {
    Box::pin(handle_flag_op(
        account,
        input,
        &[Flag::Seen],
        FlagAction::Remove,
    ))
    .await
}

pub async fn handle_flag(
    account: &AccountState,
    input: FlagInput,
) -> Result<ToolResponse<FlagsMeta>, rimap_core::RimapError> {
    Box::pin(handle_flag_op(
        account,
        input,
        &[Flag::Flagged],
        FlagAction::Add,
    ))
    .await
}

pub async fn handle_unflag(
    account: &AccountState,
    input: FlagInput,
) -> Result<ToolResponse<FlagsMeta>, rimap_core::RimapError> {
    Box::pin(handle_flag_op(
        account,
        input,
        &[Flag::Flagged],
        FlagAction::Remove,
    ))
    .await
}

async fn handle_flag_op(
    account: &AccountState,
    input: FlagInput,
    flags: &[Flag],
    action: FlagAction,
) -> Result<ToolResponse<FlagsMeta>, rimap_core::RimapError> {
    crate::tools::validation::validate_folder_input("folder", &input.folder)?;

    let uids: Vec<Uid> = input
        .target
        .into_uids()
        .into_iter()
        .map(Uid::from)
        .collect();
    let (updated, uid_validity) = account
        .imap
        .store_flags(
            &input.folder,
            &uids,
            flags,
            action,
            input.expected_uidvalidity,
        )
        .await?;

    let updated_ids: Vec<u32> = updated.iter().map(|u| u.get()).collect();

    Ok(ToolResponse::meta_only(FlagsMeta {
        folder: input.folder,
        uids_updated: updated_ids,
        uid_validity,
    }))
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn flags_meta_serializes_uid_validity_when_some() {
        let meta = FlagsMeta {
            folder: "INBOX".to_string(),
            uids_updated: vec![1, 2],
            uid_validity: Some(42),
        };
        let json = serde_json::to_string(&meta).unwrap();
        assert!(json.contains(r#""uid_validity":42"#), "json = {json}");
    }

    #[test]
    fn flags_meta_omits_uid_validity_when_none() {
        let meta = FlagsMeta {
            folder: "INBOX".to_string(),
            uids_updated: vec![1, 2],
            uid_validity: None,
        };
        let json = serde_json::to_string(&meta).unwrap();
        assert!(!json.contains("uid_validity"), "json = {json}");
    }

    #[test]
    fn flag_input_parses_single_shape() {
        let input: FlagInput = serde_json::from_str(r#"{"folder": "INBOX", "uid": 42}"#).unwrap();
        assert_eq!(input.folder, "INBOX");
        let uids: Vec<u32> = input.target.into_uids().iter().map(|u| u.get()).collect();
        assert_eq!(uids, vec![42]);
    }

    #[test]
    fn flag_input_parses_batch_shape() {
        let input: FlagInput =
            serde_json::from_str(r#"{"folder": "INBOX", "uids": [1, 2, 3]}"#).unwrap();
        let got: Vec<u32> = input.target.into_uids().iter().map(|u| u.get()).collect();
        assert_eq!(got, vec![1, 2, 3]);
    }

    #[test]
    fn flag_input_rejects_both_uid_shapes() {
        let err =
            serde_json::from_str::<FlagInput>(r#"{"folder": "INBOX", "uid": 1, "uids": [2]}"#)
                .unwrap_err();
        assert!(err.to_string().contains("exactly one"), "got: {err}");
    }

    #[test]
    fn flag_input_rejects_neither_uid_shape() {
        let err = serde_json::from_str::<FlagInput>(r#"{"folder": "INBOX"}"#).unwrap_err();
        assert!(err.to_string().contains("exactly one"), "got: {err}");
    }

    #[test]
    fn flag_input_rejects_empty_batch() {
        let err =
            serde_json::from_str::<FlagInput>(r#"{"folder": "INBOX", "uids": []}"#).unwrap_err();
        assert!(err.to_string().contains("empty"), "got: {err}");
    }

    #[test]
    fn flag_input_rejects_oversized_batch() {
        let uids: Vec<u32> = (1..=101).collect();
        let json =
            serde_json::to_string(&serde_json::json!({"folder": "INBOX", "uids": uids})).unwrap();
        let err = serde_json::from_str::<FlagInput>(&json).unwrap_err();
        assert!(err.to_string().contains("exceeds maximum"), "got: {err}");
    }

    #[test]
    fn flag_input_rejects_zero_uid() {
        let err =
            serde_json::from_str::<FlagInput>(r#"{"folder": "INBOX", "uid": 0}"#).unwrap_err();
        assert!(
            err.to_string().contains("nonzero") || err.to_string().contains("non-zero"),
            "got: {err}"
        );
    }

    #[test]
    fn flag_input_parses_expected_uidvalidity_when_present() {
        let input: FlagInput =
            serde_json::from_str(r#"{"folder": "INBOX", "uid": 1, "expected_uidvalidity": 42}"#)
                .unwrap();
        assert_eq!(input.expected_uidvalidity, Some(42));
    }

    #[test]
    fn flag_input_defaults_expected_uidvalidity_to_none() {
        let input: FlagInput = serde_json::from_str(r#"{"folder": "INBOX", "uid": 1}"#).unwrap();
        assert_eq!(input.expected_uidvalidity, None);
    }
}
