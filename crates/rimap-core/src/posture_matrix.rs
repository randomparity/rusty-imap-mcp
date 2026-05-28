//! Compile-time posture matrix: which tools are allowed at each base posture.
//!
//! Kept in `rimap-core` so that both `rimap-config` (validation) and
//! `rimap-authz` (runtime authorization) can query it without introducing
//! a circular dependency.

use crate::posture::Posture;
use crate::tool::ToolName;

/// Compile-time truth table. `true` = allowed by base posture.
///
/// Layout: outer by [`ToolName`] (23 tools),
/// inner `[readonly, draft_safe, full, destructive]`.
pub const POSTURE_MATRIX: [(ToolName, [bool; 4]); 23] = [
    (ToolName::ListFolders, [true, true, true, true]),
    (ToolName::Search, [true, true, true, true]),
    (ToolName::SearchAdvanced, [false, false, true, true]),
    (ToolName::FetchMessage, [true, true, true, true]),
    (ToolName::FetchMessageHtml, [false, false, true, true]),
    (ToolName::ListAttachments, [true, true, true, true]),
    (ToolName::DownloadAttachment, [true, true, true, true]),
    // export_messages: default-DENY at every posture. Reachable only via
    // an explicit [security.tools].export_messages = "allow" override.
    (ToolName::ExportMessages, [false, false, false, false]),
    (ToolName::MarkRead, [false, true, true, true]),
    (ToolName::MarkUnread, [false, true, true, true]),
    (ToolName::Flag, [false, true, true, true]),
    (ToolName::Unflag, [false, true, true, true]),
    (ToolName::AddLabel, [false, true, true, true]),
    (ToolName::RemoveLabel, [false, true, true, true]),
    (ToolName::ListLabels, [true, true, true, true]),
    (ToolName::MoveMessage, [false, true, true, true]),
    (ToolName::CreateDraft, [false, true, true, true]),
    // v2 tools:
    (ToolName::SendEmail, [false, false, true, true]),
    (ToolName::DeleteMessage, [false, false, true, true]),
    (ToolName::CreateFolder, [false, false, true, true]),
    (ToolName::RenameFolder, [false, false, true, true]),
    (ToolName::Expunge, [false, false, false, true]),
    (ToolName::DeleteFolder, [false, false, false, true]),
];

fn posture_index(p: Posture) -> usize {
    match p {
        Posture::Readonly => 0,
        Posture::DraftSafe => 1,
        Posture::Full => 2,
        Posture::Destructive => 3,
    }
}

/// Query whether a tool is allowed at a given base posture, ignoring
/// per-tool overrides.
///
/// Used by `rimap-config` validation and `rimap-authz` to share a single
/// authoritative posture matrix without a circular crate dependency.
#[must_use]
pub fn base_allows(posture: Posture, tool: ToolName) -> bool {
    let idx = posture_index(posture);
    for (t, row) in POSTURE_MATRIX {
        if t == tool {
            return row[idx];
        }
    }
    // Unreachable: POSTURE_MATRIX must cover all ToolName variants.
    // A compile-time exhaustiveness check lives in rimap-authz's test module.
    false
}
