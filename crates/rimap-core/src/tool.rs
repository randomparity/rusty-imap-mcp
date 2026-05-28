//! Tool identity. Models the v1 tool surface at *capability* granularity so
//! the posture matrix can gate sub-features (`search.advanced_query`,
//! `fetch_message.include_html`) independently of the parent tool.

use core::fmt;
use core::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use strum::{EnumIter, IntoEnumIterator};
use thiserror::Error;

/// Identifier for a dispatchable capability. This is a superset of the MCP
/// tool names because some MCP tools expose multiple gated capabilities
/// (e.g. `search` and `search_advanced`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, EnumIter)]
pub enum ToolName {
    /// `list_folders`
    ListFolders,
    /// `search` with the structured query form only.
    Search,
    /// `search` with `advanced_query` escape hatch. Requires `full` posture.
    SearchAdvanced,
    /// `fetch_message` returning text parts only.
    FetchMessage,
    /// `fetch_message` with `include_html = true`. Requires `full` posture.
    FetchMessageHtml,
    /// `list_attachments`
    ListAttachments,
    /// `download_attachment`
    DownloadAttachment,
    /// `export_messages` — bulk raw export of multiple UIDs to a
    /// `git am`-able mbox in the download sandbox. Default-denied in the
    /// base posture matrix; enabled only via `[security.tools]`.
    ExportMessages,
    /// `mark_read`
    MarkRead,
    /// `mark_unread`
    MarkUnread,
    /// `flag`
    Flag,
    /// `unflag`
    Unflag,
    /// `add_label`
    AddLabel,
    /// `remove_label`
    RemoveLabel,
    /// `list_labels`
    ListLabels,
    /// `move_message`
    MoveMessage,
    /// `create_draft` (appends to Drafts with `$PendingReview`).
    CreateDraft,
    /// `send_email`
    SendEmail,
    /// `delete_message`
    DeleteMessage,
    /// `expunge`
    Expunge,
    /// `create_folder`
    CreateFolder,
    /// `rename_folder`
    RenameFolder,
    /// `delete_folder`
    DeleteFolder,
    /// `use_account` — switch the active account context.
    /// Bypasses posture/rate-limit checks.
    UseAccount,
    /// `list_accounts` — enumerate configured accounts.
    /// Bypasses posture/rate-limit checks.
    ListAccounts,
}

impl ToolName {
    /// Canonical snake-case name used in config overrides and audit log
    /// entries. Sub-capabilities reuse the parent tool name joined with a
    /// descriptive suffix.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ListFolders => "list_folders",
            Self::Search => "search",
            Self::SearchAdvanced => "search.advanced_query",
            Self::FetchMessage => "fetch_message",
            Self::FetchMessageHtml => "fetch_message.include_html",
            Self::ListAttachments => "list_attachments",
            Self::DownloadAttachment => "download_attachment",
            Self::ExportMessages => "export_messages",
            Self::MarkRead => "mark_read",
            Self::MarkUnread => "mark_unread",
            Self::Flag => "flag",
            Self::Unflag => "unflag",
            Self::AddLabel => "add_label",
            Self::RemoveLabel => "remove_label",
            Self::ListLabels => "list_labels",
            Self::MoveMessage => "move_message",
            Self::CreateDraft => "create_draft",
            Self::SendEmail => "send_email",
            Self::DeleteMessage => "delete_message",
            Self::Expunge => "expunge",
            Self::CreateFolder => "create_folder",
            Self::RenameFolder => "rename_folder",
            Self::DeleteFolder => "delete_folder",
            Self::UseAccount => "use_account",
            Self::ListAccounts => "list_accounts",
        }
    }

    /// Every tool variant, in declaration order. Used for exhaustive matrix tests
    /// and for building the advertised-tools set in `list_tools`. Built from
    /// `EnumIter` so adding a new variant cannot silently desynchronize this
    /// list (compile-time parity).
    #[must_use]
    pub fn all() -> Vec<Self> {
        Self::iter().collect()
    }

    /// Whether this tool is an infrastructure tool that bypasses the
    /// posture matrix (not gated by posture, rate limits, or circuit
    /// breakers). Infrastructure tools are always available regardless
    /// of security posture.
    #[must_use]
    pub fn is_infrastructure(self) -> bool {
        // Explicit list of infrastructure variants; remaining variants are all
        // posture-gated. New variants default to non-infrastructure, which is
        // the safer behavior (they will be subject to the posture matrix).
        match self {
            Self::UseAccount | Self::ListAccounts => true,
            Self::ListFolders
            | Self::Search
            | Self::SearchAdvanced
            | Self::FetchMessage
            | Self::FetchMessageHtml
            | Self::ListAttachments
            | Self::DownloadAttachment
            | Self::ExportMessages
            | Self::MarkRead
            | Self::MarkUnread
            | Self::Flag
            | Self::Unflag
            | Self::AddLabel
            | Self::RemoveLabel
            | Self::ListLabels
            | Self::MoveMessage
            | Self::CreateDraft
            | Self::SendEmail
            | Self::DeleteMessage
            | Self::Expunge
            | Self::CreateFolder
            | Self::RenameFolder
            | Self::DeleteFolder => false,
        }
    }

    /// Whether this tool consumes a token from the per-minute *draft* rate
    /// bucket. Only `create_draft` appends to a Drafts folder, so it is the
    /// only variant gated by that bucket. Exhaustive match so a new variant
    /// forces an explicit decision at compile time.
    #[must_use]
    pub fn is_draft_quota_gated(self) -> bool {
        match self {
            Self::CreateDraft => true,
            Self::ListFolders
            | Self::Search
            | Self::SearchAdvanced
            | Self::FetchMessage
            | Self::FetchMessageHtml
            | Self::ListAttachments
            | Self::DownloadAttachment
            | Self::ExportMessages
            | Self::MarkRead
            | Self::MarkUnread
            | Self::Flag
            | Self::Unflag
            | Self::AddLabel
            | Self::RemoveLabel
            | Self::ListLabels
            | Self::MoveMessage
            | Self::SendEmail
            | Self::DeleteMessage
            | Self::Expunge
            | Self::CreateFolder
            | Self::RenameFolder
            | Self::DeleteFolder
            | Self::UseAccount
            | Self::ListAccounts => false,
        }
    }

    /// Whether this tool consumes a token from the per-minute *send* rate
    /// bucket. Only `send_email` dispatches through SMTP, so it is the only
    /// variant gated by that bucket. Exhaustive match so a new variant
    /// forces an explicit decision at compile time.
    #[must_use]
    pub fn is_send_quota_gated(self) -> bool {
        match self {
            Self::SendEmail => true,
            Self::ListFolders
            | Self::Search
            | Self::SearchAdvanced
            | Self::FetchMessage
            | Self::FetchMessageHtml
            | Self::ListAttachments
            | Self::DownloadAttachment
            | Self::ExportMessages
            | Self::MarkRead
            | Self::MarkUnread
            | Self::Flag
            | Self::Unflag
            | Self::AddLabel
            | Self::RemoveLabel
            | Self::ListLabels
            | Self::MoveMessage
            | Self::CreateDraft
            | Self::DeleteMessage
            | Self::Expunge
            | Self::CreateFolder
            | Self::RenameFolder
            | Self::DeleteFolder
            | Self::UseAccount
            | Self::ListAccounts => false,
        }
    }
}

/// MCP tool annotation hints. Mirrored to `rmcp::model::ToolAnnotations`
/// in the server crate; defined here so `ToolName` owns the
/// classification.
// Four orthogonal annotation axes map directly to the MCP spec fields;
// state-machine enums would add indirection without adding safety here.
#[expect(
    clippy::struct_excessive_bools,
    reason = "four MCP spec fields, each a distinct axis"
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolAnnotationHints {
    /// `read_only_hint`: tool does not modify mailbox or session state.
    pub read_only: bool,
    /// `destructive_hint`: tool performs irreversible operations on the
    /// server.
    pub destructive: bool,
    /// `idempotent_hint`: calling twice has the same effect as calling
    /// once.
    pub idempotent: bool,
    /// `open_world_hint`: tool interacts with an external system
    /// (IMAP/SMTP server). `false` for tools that operate purely on
    /// local registry state.
    pub open_world: bool,
}

impl ToolName {
    /// MCP tool annotation hints for this tool. Hand-authored per
    /// variant; see the spec at
    /// `docs/superpowers/specs/2026-05-20-mcp-tool-catalog-richness-design.md`
    /// (Delta 3) for the classification rules.
    #[must_use]
    pub fn annotation_hints(self) -> ToolAnnotationHints {
        let (read_only, destructive, idempotent, open_world) = match self {
            // Read-only, external (IMAP).
            Self::ListFolders
            | Self::Search
            | Self::SearchAdvanced
            | Self::FetchMessage
            | Self::FetchMessageHtml
            | Self::ListAttachments
            | Self::ListLabels => (true, false, false, true),

            // Read-only, local registry (no IMAP/SMTP).
            Self::ListAccounts => (true, false, false, false),

            // Mutates session state, local registry.
            //
            // `idempotent: true` interpreted in MCP's sense: calling
            // `use_account("A")` twice has the same net effect as
            // calling it once. Calls with *different* arguments are a
            // different operation and don't bear on this hint. The
            // spec's Delta 3 table does not enumerate `use_account`
            // explicitly; this interpretation matches MCP's standard
            // single-argument-shape definition of idempotence.
            Self::UseAccount => (false, false, true, false),

            // Idempotent flag mutations on IMAP, plus download_attachment
            // (writes to the local sandbox; same UID+part_id writes
            // identical bytes, so calling twice = once observably).
            Self::MarkRead
            | Self::MarkUnread
            | Self::Flag
            | Self::Unflag
            | Self::AddLabel
            | Self::RemoveLabel
            | Self::DownloadAttachment => (false, false, true, true),

            // Non-idempotent, non-destructive mutations. `CreateFolder`
            // also falls here: same name fails the second call per IMAP
            // semantics. `ExportMessages` writes a new sandbox file per
            // call (write_attachment de-dups, never overwrites) and reads
            // from IMAP, so it is non-idempotent + open-world like the
            // rest of this group.
            Self::MoveMessage
            | Self::CreateDraft
            | Self::RenameFolder
            | Self::CreateFolder
            | Self::ExportMessages => (false, false, false, true),

            // Destructive, irreversible.
            Self::SendEmail | Self::DeleteMessage | Self::Expunge | Self::DeleteFolder => {
                (false, true, false, true)
            }
        };
        ToolAnnotationHints {
            read_only,
            destructive,
            idempotent,
            open_world,
        }
    }
}

impl fmt::Display for ToolName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error returned by [`ToolName::from_str`] when a name is not recognized.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseToolNameError {
    /// The name is not a known tool.
    #[error("unknown tool name `{0}`")]
    Unknown(String),
}

impl FromStr for ToolName {
    type Err = ParseToolNameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        for tool in Self::all() {
            if tool.as_str() == s {
                return Ok(tool);
            }
        }
        Err(ParseToolNameError::Unknown(s.to_string()))
    }
}

impl Serialize for ToolName {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ToolName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <&str>::deserialize(deserializer)?;
        Self::from_str(s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use crate::tool::{ParseToolNameError, ToolName};
    use core::str::FromStr;
    use strum::IntoEnumIterator;

    #[test]
    fn all_has_exactly_twenty_five_variants() {
        assert_eq!(ToolName::all().len(), 25);
        assert_eq!(ToolName::iter().count(), 25);
    }

    #[test]
    fn round_trip_all_tool_names() {
        for tool in ToolName::all() {
            let parsed = ToolName::from_str(tool.as_str()).unwrap();
            assert_eq!(parsed, tool);
        }
    }

    #[test]
    fn all_names_are_unique() {
        let mut seen = std::collections::BTreeSet::new();
        for tool in ToolName::all() {
            assert!(
                seen.insert(tool.as_str()),
                "duplicate name: {}",
                tool.as_str()
            );
        }
    }

    #[test]
    fn unknown_name_returns_unknown_error() {
        let err = ToolName::from_str("nuke_inbox").unwrap_err();
        assert_eq!(err, ParseToolNameError::Unknown("nuke_inbox".to_string()));
    }

    #[test]
    fn v2_tool_names_parse_as_real_variants() {
        assert_eq!(
            ToolName::from_str("send_email").unwrap(),
            ToolName::SendEmail
        );
        assert_eq!(
            ToolName::from_str("delete_message").unwrap(),
            ToolName::DeleteMessage
        );
        assert_eq!(ToolName::from_str("expunge").unwrap(), ToolName::Expunge);
        assert_eq!(
            ToolName::from_str("create_folder").unwrap(),
            ToolName::CreateFolder
        );
        assert_eq!(
            ToolName::from_str("rename_folder").unwrap(),
            ToolName::RenameFolder
        );
        assert_eq!(
            ToolName::from_str("delete_folder").unwrap(),
            ToolName::DeleteFolder
        );
    }

    #[test]
    fn display_uses_canonical_name() {
        assert_eq!(ToolName::Search.to_string(), "search");
        assert_eq!(
            ToolName::SearchAdvanced.to_string(),
            "search.advanced_query"
        );
    }
}

#[cfg(test)]
mod annotation_tests {
    use super::ToolName;

    #[test]
    fn list_folders_is_read_only_open_world() {
        let h = ToolName::ListFolders.annotation_hints();
        assert!(h.read_only);
        assert!(!h.destructive);
        assert!(h.open_world);
    }

    #[test]
    fn use_account_is_not_read_only() {
        // use_account mutates the session-scoped active-account state via
        // AccountRegistry::set_active. See spec rationale (Delta 3).
        let h = ToolName::UseAccount.annotation_hints();
        assert!(
            !h.read_only,
            "use_account must not advertise read_only_hint"
        );
        assert!(!h.open_world, "use_account is local-registry only");
        assert!(
            h.idempotent,
            "use_account is idempotent: calling set_active twice = once",
        );
    }

    #[test]
    fn delete_message_is_destructive() {
        let h = ToolName::DeleteMessage.annotation_hints();
        assert!(h.destructive);
        assert!(!h.read_only);
    }

    #[test]
    fn move_message_is_not_destructive() {
        // Per spec: move is reversible.
        let h = ToolName::MoveMessage.annotation_hints();
        assert!(!h.destructive);
    }

    #[test]
    fn mark_read_is_idempotent() {
        let h = ToolName::MarkRead.annotation_hints();
        assert!(h.idempotent);
    }

    #[test]
    fn create_folder_is_not_idempotent() {
        // Same name fails the second call per IMAP semantics; treat as
        // non-idempotent.
        let h = ToolName::CreateFolder.annotation_hints();
        assert!(!h.idempotent);
    }

    #[test]
    fn list_accounts_is_not_open_world() {
        let h = ToolName::ListAccounts.annotation_hints();
        assert!(!h.open_world);
        assert!(h.read_only);
    }

    #[test]
    fn search_is_read_only_open_world() {
        let h = ToolName::Search.annotation_hints();
        assert!(h.read_only);
        assert!(h.open_world);
    }

    #[test]
    fn download_attachment_is_not_read_only() {
        // download_attachment writes a file into the sandbox directory
        // (`state.download_dir`) and emits a `path` field in its meta
        // payload — that is environmental modification per the MCP
        // `read_only_hint` definition. Calling twice with the same
        // UID+part_id writes identical bytes, so it is idempotent.
        let h = ToolName::DownloadAttachment.annotation_hints();
        assert!(
            !h.read_only,
            "download_attachment writes to the sandbox and must not advertise read_only_hint",
        );
        assert!(h.idempotent, "same UID+part_id yields identical bytes");
        assert!(!h.destructive, "no irreversible server-side mutation");
        assert!(h.open_world, "fetches from the IMAP server");
    }

    #[test]
    fn export_messages_is_non_idempotent_open_world_write() {
        // Pins ExportMessages to (read_only, destructive, idempotent,
        // open_world) = (false, false, false, true). Without this, a future
        // edit could silently fold the variant into a different
        // annotation_hints match arm (e.g. the idempotent
        // download_attachment group) and change the advertised hints.
        let h = ToolName::ExportMessages.annotation_hints();
        assert!(
            !h.read_only,
            "export_messages writes a sandbox file; must not advertise read_only_hint",
        );
        assert!(!h.destructive, "no irreversible server-side mutation");
        assert!(
            !h.idempotent,
            "writes a new artifact per call; not idempotent"
        );
        assert!(h.open_world, "reads from the IMAP server");
    }
}
