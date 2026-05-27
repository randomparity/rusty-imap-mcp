//! `export_messages` tool handler: bulk raw export of multiple UIDs to a
//! single `git am`-able mbox file in the download sandbox.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::boot::registry::AccountState;
use crate::mcp::response::ToolResponse;

/// Hard ceiling on the aggregate export size, regardless of the
/// caller-supplied `max_total_bytes`.
pub const MAX_EXPORT_TOTAL_BYTES: u64 = 100 * 1024 * 1024;

/// Input for the `export_messages` tool.
#[derive(Debug, Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct ExportMessagesInput {
    /// IMAP folder containing the messages.
    pub folder: String,
    /// UIDs to export, in mbox (patch) order. Non-empty, max 100, de-duped.
    pub uids: Vec<core::num::NonZeroU32>,
    /// UIDVALIDITY observed when the UID list was discovered (e.g. from
    /// `search`). Required: pins mailbox identity across search→export.
    #[serde(deserialize_with = "crate::tools::lenient_int::deserialize_nonzero_u32")]
    #[schemars(schema_with = "crate::tools::lenient_int::schema_nonzero_u32")]
    pub expected_uidvalidity: core::num::NonZeroU32,
    /// Optional destination directory. Must be within the download root.
    pub dest_dir: Option<String>,
    /// Optional advisory basename prefix (sanitized).
    pub filename: Option<String>,
    /// Aggregate byte cap; clamped to `MAX_EXPORT_TOTAL_BYTES`.
    #[serde(
        default,
        deserialize_with = "crate::tools::lenient_int::deserialize_opt_u64"
    )]
    #[schemars(schema_with = "crate::tools::lenient_int::schema_opt_u64")]
    pub max_total_bytes: Option<u64>,
    /// When true, write the successes to a `.partial.mbox` artifact instead
    /// of failing the whole call. Default false (all-or-nothing).
    pub allow_partial: Option<bool>,
}

/// One successfully exported message.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct ExportedUid {
    pub uid: u32,
    pub size_bytes: usize,
}

/// Reason a requested UID was not exported. Both are determined at the size
/// preflight, before any body fetch — a UID that reaches the body fetch is
/// known-present and in-bounds, and any error there is fatal (never per-UID),
/// so there is no `FetchError` variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExportFailReason {
    NotFound,
    Oversize,
}

/// One requested UID that failed.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct FailedUid {
    pub uid: u32,
    pub reason: ExportFailReason,
}

/// Trusted metadata for an `export_messages` response.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct ExportMessagesMeta {
    /// Folder the messages were exported from.
    pub folder: String,
    /// True iff every requested UID was exported.
    pub complete: bool,
    /// `git am`-ready mbox path. Present only on a complete export;
    /// omitted from the response otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Path of a `.partial.mbox` artifact. Present only on a partial
    /// export; omitted otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partial_path: Option<String>,
    /// SHA-256 of the written mbox, hex-encoded.
    pub sha256: String,
    /// Number of messages written to the artifact.
    pub message_count: usize,
    /// Total bytes written.
    pub total_bytes: u64,
    /// UIDVALIDITY the export was pinned to.
    pub uid_validity: u32,
    /// Exported UIDs, in mbox order, with sizes.
    pub succeeded: Vec<ExportedUid>,
    /// Requested UIDs that failed, with reasons.
    pub failed: Vec<FailedUid>,
}

/// Execute the `export_messages` tool.
///
/// # Errors
///
/// Returns `RimapError::Internal` — not yet implemented (filled in Task 7).
#[expect(
    clippy::unused_async,
    reason = "inert handler; dispatch awaits this future and the real \
              implementation (Task 7) performs IMAP I/O"
)]
pub async fn handle(
    _account: &AccountState,
    _input: ExportMessagesInput,
) -> Result<ToolResponse<ExportMessagesMeta, ()>, rimap_core::RimapError> {
    Err(rimap_core::RimapError::Internal(
        "export_messages not yet implemented".into(),
    ))
}
