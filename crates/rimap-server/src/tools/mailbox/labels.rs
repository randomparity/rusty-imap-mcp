//! Label (custom keyword) tool handlers: `add_label`, `remove_label`,
//! `list_labels`.
//!
//! All handlers echo `uid_validity` from the SELECT/EXAMINE issued per
//! operation. Callers can use this to detect UID namespace rotation between
//! acquisition and mutation. (#70)

use rimap_core::UidSelector;
use rimap_imap::types::{FetchSpec, Flag, FlagAction, Uid};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::boot::registry::AccountState;
use crate::mcp::response::ToolResponse;

/// IMAP atom specials (RFC 3501 §9) plus backslash. Any of these
/// inside a keyword would break the STORE command or collide with
/// the system-flag namespace.
const ATOM_SPECIALS: &[char] = &['(', ')', '{', ' ', '%', '*', '"', '[', ']', '\\'];

/// System flag names that must not be used as custom keywords.
const SYSTEM_FLAGS: &[&str] = &["seen", "answered", "flagged", "deleted", "draft", "recent"];

/// Maximum label length in bytes.
const MAX_LABEL_BYTES: usize = 256;

/// Validate a custom keyword label for IMAP STORE safety.
pub(crate) fn validate_label(label: &str) -> Result<(), rimap_core::RimapError> {
    if label.is_empty() {
        return Err(invalid_input("label must not be empty"));
    }
    if !label.is_ascii() {
        return Err(invalid_input("label must be ASCII (RFC 3501 atom syntax)"));
    }
    if label.len() > MAX_LABEL_BYTES {
        return Err(invalid_input(&format!(
            "label exceeds maximum of {MAX_LABEL_BYTES} bytes"
        )));
    }
    if label.as_bytes().contains(&0) {
        return Err(invalid_input("label must not contain null bytes"));
    }
    if label.starts_with('\\') {
        return Err(invalid_input(
            "label must not start with '\\' (system flag namespace)",
        ));
    }
    if label.chars().any(|c| ATOM_SPECIALS.contains(&c)) {
        return Err(invalid_input("label contains IMAP atom special characters"));
    }
    if label.chars().any(|c| c.is_ascii_control()) {
        return Err(invalid_input(
            "label must not contain ASCII control characters",
        ));
    }
    if SYSTEM_FLAGS.contains(&label.to_ascii_lowercase().as_str()) {
        return Err(invalid_input(&format!(
            "'{label}' is a reserved system flag name"
        )));
    }
    Ok(())
}

fn invalid_input(message: &str) -> rimap_core::RimapError {
    rimap_core::RimapError::invalid_input(message)
}

/// Input for `add_label` and `remove_label` tools.
///
/// # Shape
///
/// This tool accepts either a single `uid` or a batch `uids` (XOR; max
/// 100). The asymmetry with single-target tools (`fetch_message`,
/// `list_attachments`, `download_attachment`, `delete_message`) is
/// deliberate: batch shapes are reserved for commutative, idempotent
/// mutations where per-UID ordering does not matter and results fan out
/// uniformly. Read-side and destructive single-target tools keep a
/// scalar `uid` so the response schema and error semantics stay
/// unambiguous.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct LabelInput {
    /// Target folder.
    pub folder: String,
    /// UID target: `{"uid": N}` or `{"uids": [...]}`.
    #[serde(flatten)]
    pub target: UidSelector,
    /// Custom keyword label to add or remove.
    pub label: String,
    /// When set, the handler verifies the folder's UIDVALIDITY matches this
    /// value before applying the label. A mismatch returns
    /// `ERR_UID_VALIDITY_CHANGED`. Omit to skip the guard.
    #[serde(
        default,
        deserialize_with = "crate::tools::lenient_int::deserialize_opt_u32",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(schema_with = "crate::tools::lenient_int::schema_opt_u32")]
    pub expected_uidvalidity: Option<u32>,
}

/// Input for `list_labels` tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListLabelsInput {
    /// Target folder.
    pub folder: String,
    /// Message UID.
    #[serde(deserialize_with = "crate::tools::lenient_int::deserialize_nonzero_u32")]
    #[schemars(schema_with = "crate::tools::lenient_int::schema_nonzero_u32")]
    pub uid: core::num::NonZeroU32,
    /// When set, the handler verifies the folder's UIDVALIDITY matches this
    /// value before fetching labels. A mismatch returns
    /// `ERR_UID_VALIDITY_CHANGED`. Omit to skip the guard.
    #[serde(
        default,
        deserialize_with = "crate::tools::lenient_int::deserialize_opt_u32",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(schema_with = "crate::tools::lenient_int::schema_opt_u32")]
    pub expected_uidvalidity: Option<u32>,
}

/// Trusted metadata for `add_label` and `remove_label` responses.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct LabelsMeta {
    /// Folder the label was applied to.
    pub folder: String,
    /// Label that was added or removed.
    pub label: String,
    /// UIDs that were updated.
    pub uids_updated: Vec<u32>,
    /// UIDVALIDITY observed at the SELECT used for this operation. `None`
    /// when the server's SELECT response omitted the response code. (#70)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid_validity: Option<u32>,
}

/// Trusted metadata for a `list_labels` response.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct ListLabelsMeta {
    /// Folder the labels were fetched from.
    pub folder: String,
    /// UID of the message.
    pub uid: u32,
    /// Custom keyword labels on the message.
    pub labels: Vec<String>,
    /// UIDVALIDITY observed at the EXAMINE used for this operation. `None`
    /// when the server's EXAMINE response omitted the response code. (#70)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid_validity: Option<u32>,
}

/// `add_label` handler — STORE +FLAGS with a custom keyword.
///
/// # Errors
///
/// Returns `RimapError::Authz { code: InvalidInput, ... }` for invalid
/// labels (empty, control chars, atom-specials, system-flag collisions,
/// zero UID, batch over 100). Returns `RimapError::Imap { ... }` for
/// IMAP-layer failures.
pub async fn handle_add_label(
    account: &AccountState,
    input: LabelInput,
) -> Result<ToolResponse<LabelsMeta>, rimap_core::RimapError> {
    handle_label_op(account, input, FlagAction::Add).await
}

/// `remove_label` handler — STORE -FLAGS with a custom keyword.
///
/// # Errors
///
/// Same shape as [`handle_add_label`]: `Authz { InvalidInput }` for shape
/// errors and `Imap { ... }` for IMAP-layer failures.
pub async fn handle_remove_label(
    account: &AccountState,
    input: LabelInput,
) -> Result<ToolResponse<LabelsMeta>, rimap_core::RimapError> {
    handle_label_op(account, input, FlagAction::Remove).await
}

/// Shared body for `add_label` / `remove_label`: validate the label,
/// resolve UIDs, issue a STORE ±FLAGS, return the per-UID result summary.
async fn handle_label_op(
    account: &AccountState,
    input: LabelInput,
    action: FlagAction,
) -> Result<ToolResponse<LabelsMeta>, rimap_core::RimapError> {
    crate::tools::validation::validate_folder_input("folder", &input.folder)?;
    validate_label(&input.label)?;
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
            &[Flag::Keyword(input.label.clone())],
            action,
            input.expected_uidvalidity,
        )
        .await?;

    let updated_ids: Vec<u32> = updated.iter().map(|u| u.get()).collect();
    Ok(ToolResponse::meta_only(LabelsMeta {
        folder: input.folder,
        label: input.label,
        uids_updated: updated_ids,
        uid_validity,
    }))
}

/// `list_labels` handler — FETCH FLAGS and return keyword entries.
///
/// # Errors
///
/// Returns `RimapError::Authz { code: NotFound }` if the message UID is
/// missing in the folder, and `Imap { ... }` for IMAP-layer failures.
pub async fn handle_list_labels(
    account: &AccountState,
    input: ListLabelsInput,
) -> Result<ToolResponse<ListLabelsMeta>, rimap_core::RimapError> {
    crate::tools::validation::validate_folder_input("folder", &input.folder)?;

    let uid = rimap_imap::types::Uid::from(input.uid);

    let spec = FetchSpec {
        flags: true,
        ..FetchSpec::default()
    };
    let (msg, uid_validity) = crate::tools::fetch_by_uid::fetch_single_by_uid(
        account,
        &input.folder,
        uid,
        spec,
        input.expected_uidvalidity,
    )
    .await?;

    let labels: Vec<String> = msg
        .flags
        .as_ref()
        .map(|flags| {
            flags
                .iter()
                .filter_map(|f| match f {
                    Flag::Keyword(kw) => Some(kw.clone()),
                    Flag::Seen
                    | Flag::Answered
                    | Flag::Flagged
                    | Flag::Deleted
                    | Flag::Draft
                    | Flag::Recent => None,
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(ToolResponse::meta_only(ListLabelsMeta {
        folder: input.folder,
        uid: input.uid.get(),
        labels,
        uid_validity,
    }))
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn labels_meta_serializes_uid_validity_when_some() {
        let meta = LabelsMeta {
            folder: "INBOX".to_string(),
            label: "MyLabel".to_string(),
            uids_updated: vec![1],
            uid_validity: Some(99),
        };
        let json = serde_json::to_string(&meta).unwrap();
        assert!(json.contains(r#""uid_validity":99"#), "json = {json}");
    }

    #[test]
    fn labels_meta_omits_uid_validity_when_none() {
        let meta = LabelsMeta {
            folder: "INBOX".to_string(),
            label: "MyLabel".to_string(),
            uids_updated: vec![1],
            uid_validity: None,
        };
        let json = serde_json::to_string(&meta).unwrap();
        assert!(!json.contains("uid_validity"), "json = {json}");
    }

    #[test]
    fn list_labels_meta_serializes_uid_validity_when_some() {
        let meta = ListLabelsMeta {
            folder: "INBOX".to_string(),
            uid: 7,
            labels: vec!["tag".to_string()],
            uid_validity: Some(77),
        };
        let json = serde_json::to_string(&meta).unwrap();
        assert!(json.contains(r#""uid_validity":77"#), "json = {json}");
    }

    #[test]
    fn list_labels_meta_omits_uid_validity_when_none() {
        let meta = ListLabelsMeta {
            folder: "INBOX".to_string(),
            uid: 7,
            labels: vec![],
            uid_validity: None,
        };
        let json = serde_json::to_string(&meta).unwrap();
        assert!(!json.contains("uid_validity"), "json = {json}");
    }

    #[test]
    fn rejects_empty_label() {
        let err = validate_label("").unwrap_err();
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn rejects_overlength_label() {
        let long = "a".repeat(257);
        let err = validate_label(&long).unwrap_err();
        assert!(err.to_string().contains("exceeds maximum"));
    }

    #[test]
    fn accepts_max_length_label() {
        let exact = "a".repeat(256);
        validate_label(&exact).unwrap();
    }

    #[test]
    fn rejects_null_bytes() {
        let err = validate_label("foo\0bar").unwrap_err();
        assert!(err.to_string().contains("null"));
    }

    #[test]
    fn rejects_backslash_prefix() {
        let err = validate_label("\\Seen").unwrap_err();
        assert!(err.to_string().contains("system flag namespace"));
    }

    #[test]
    fn rejects_system_flags_case_insensitive() {
        for name in &[
            "Seen", "SEEN", "seen", "Answered", "Flagged", "Deleted", "Draft", "Recent", "DRAFT",
            "rEcEnT",
        ] {
            let err = validate_label(name).unwrap_err();
            assert!(
                err.to_string().contains("reserved system flag"),
                "expected rejection for '{name}', got: {err}"
            );
        }
    }

    #[test]
    fn rejects_atom_specials() {
        for ch in ATOM_SPECIALS {
            let label = format!("foo{ch}bar");
            let result = validate_label(&label);
            assert!(result.is_err(), "expected rejection for char '{ch}'");
        }
    }

    #[test]
    fn rejects_control_characters() {
        let err = validate_label("foo\x01bar").unwrap_err();
        assert!(err.to_string().contains("control"));

        let err = validate_label("foo\x7Fbar").unwrap_err();
        assert!(err.to_string().contains("control"));

        let err = validate_label("\t").unwrap_err();
        assert!(err.to_string().contains("control"));
    }

    #[test]
    fn accepts_valid_labels() {
        validate_label("Urgent").unwrap();
        validate_label("$PendingReview").unwrap();
        validate_label("project/alpha").unwrap();
        validate_label("my-label").unwrap();
        validate_label("Label_123").unwrap();
    }

    #[test]
    fn non_ascii_label_rejected() {
        assert!(validate_label("résumé").is_err());
        assert!(validate_label("Urgеnt").is_err()); // Cyrillic 'е'
        assert!(validate_label("\u{202E}evil").is_err()); // RTL override
        assert!(validate_label("foo\u{200B}bar").is_err()); // zero-width space
    }

    #[test]
    fn left_bracket_rejected() {
        assert!(validate_label("foo[bar").is_err());
    }

    #[test]
    fn accepts_dollar_prefix_keywords() {
        validate_label("$Junk").unwrap();
        validate_label("$NotJunk").unwrap();
        validate_label("$MDNSent").unwrap();
    }

    #[test]
    fn label_input_parses_expected_uidvalidity_when_present() {
        let input: LabelInput = serde_json::from_str(
            r#"{"folder": "INBOX", "uid": 1, "label": "Urgent", "expected_uidvalidity": 99}"#,
        )
        .unwrap();
        assert_eq!(input.expected_uidvalidity, Some(99));
    }

    #[test]
    fn label_input_defaults_expected_uidvalidity_to_none() {
        let input: LabelInput =
            serde_json::from_str(r#"{"folder": "INBOX", "uid": 1, "label": "Urgent"}"#).unwrap();
        assert_eq!(input.expected_uidvalidity, None);
    }

    #[test]
    fn list_labels_input_parses_expected_uidvalidity_when_present() {
        let input: ListLabelsInput =
            serde_json::from_str(r#"{"folder": "INBOX", "uid": 5, "expected_uidvalidity": 77}"#)
                .unwrap();
        assert_eq!(input.expected_uidvalidity, Some(77));
    }

    #[test]
    fn list_labels_input_defaults_expected_uidvalidity_to_none() {
        let input: ListLabelsInput =
            serde_json::from_str(r#"{"folder": "INBOX", "uid": 5}"#).unwrap();
        assert_eq!(input.expected_uidvalidity, None);
    }
}
