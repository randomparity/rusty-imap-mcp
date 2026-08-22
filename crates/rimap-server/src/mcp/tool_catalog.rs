//! MCP tool catalog: descriptions, input schemas, and the memoized
//! [`TOOL_DEFS`] map.
//!
//! Centralises the mapping from [`ToolName`] to MCP `Tool` advertisement
//! metadata. Sub-capabilities that share a wire name with a parent
//! (`SearchAdvanced`, `FetchMessageHtml`) intentionally return `None`
//! from [`tool_def_parts`] — they are surfaced via the parent tool.
//!
//! Also hosts the argument-serialization helpers ([`ser`], [`parse_args`])
//! used by the dispatch pipeline.
//!
//! Also hosts the `tools/list` pagination primitives (page size, cursor
//! decoding, window arithmetic), split out of `mcp::server`.

use rmcp::model::ErrorData;
use std::collections::HashMap;
use std::sync::Arc;

use rimap_core::tool::ToolName;
use rmcp::model::{Tool, ToolAnnotations};

use crate::mcp::response::{ToolResponse, envelope_schema};

/// Type alias for tool definition tuples — `(title, description, input
/// schema, output schema)`. The wire name comes from `ToolName::as_str()`
/// so there is a single source of truth for tool names.
type ToolDef = (
    &'static str,                               // title (Title Case, human-readable)
    &'static str,                               // description
    serde_json::Map<String, serde_json::Value>, // input schema
    serde_json::Map<String, serde_json::Value>, // output (envelope) schema
);

/// Serialize a typed response to `serde_json::Value`.
///
/// Used in dispatch code paths to unify concrete handler return types
/// into a single `Value` before the audit envelope processes them.
pub(super) fn ser<T: serde::Serialize>(
    resp: T,
) -> Result<serde_json::Value, rimap_core::RimapError> {
    serde_json::to_value(&resp).map_err(|e| rimap_core::RimapError::InternalSourced {
        message: "response serialization failed".into(),
        source: Box::new(e),
    })
}

/// Deserialize tool arguments into a typed input struct.
pub(super) fn parse_args<T: serde::de::DeserializeOwned>(
    args: &serde_json::Map<String, serde_json::Value>,
) -> Result<T, rimap_core::RimapError> {
    serde_json::from_value(serde_json::Value::Object(args.clone()))
        .map_err(|e| rimap_core::RimapError::invalid_input(format!("invalid arguments: {e}")))
}

/// JSON Schema for a tool that takes no arguments. The MCP spec models
/// `inputSchema` as an object schema (`"type": "object"`) — a bare `{}` is
/// technically a permissive JSON Schema but spec-strict clients (e.g.
/// `bobshell`'s Zod validator) reject any tool whose `inputSchema.type`
/// is not the string `"object"`.
fn no_args_schema() -> serde_json::Map<String, serde_json::Value> {
    let mut map = serde_json::Map::new();
    map.insert(
        "type".to_string(),
        serde_json::Value::String("object".into()),
    );
    map.insert(
        "properties".to_string(),
        serde_json::Value::Object(serde_json::Map::new()),
    );
    map
}

/// Translate the language-agnostic `ToolAnnotationHints` into rmcp's
/// `ToolAnnotations` shape and mirror the catalog title.
///
/// Uses `ToolAnnotations::from_raw` because the struct is
/// `#[non_exhaustive]` and cannot be built via a struct literal from
/// outside the rmcp crate.
fn build_annotations(title: &'static str, name: ToolName) -> ToolAnnotations {
    let hints = name.annotation_hints();
    ToolAnnotations::from_raw(
        Some(title.to_string()),
        Some(hints.read_only),
        Some(hints.destructive),
        Some(hints.idempotent),
        Some(hints.open_world),
    )
}

/// Return the title, description, input schema, and output-envelope
/// schema for the given `ToolName`, or `None` for sub-capabilities that
/// share an MCP tool name with a parent (e.g. `SearchAdvanced`,
/// `FetchMessageHtml`) — those are advertised under the parent entry and
/// have no standalone definition.
///
/// A single match keeps the input and output schemas for each tool on the
/// same arm, so there is no cross-function invariant to keep in sync. The
/// output-envelope schemas are byte-identical to what
/// `crates/rimap-server/src/cli/dump_tool_schemas.rs::tool_envelope` dumps
/// for the fixture set.
#[expect(
    clippy::too_many_lines,
    reason = "single match over every ToolName variant; the alternative is two parallel matches with a cross-function invariant"
)]
fn tool_def_parts(name: ToolName) -> Option<ToolDef> {
    use crate::tools::admin::accounts::{ListAccountsMeta, UseAccountInput, UseAccountMeta};
    use crate::tools::admin::list_folders::ListFoldersMeta;
    use crate::tools::compose::create_draft::{CreateDraftInput, CreateDraftMeta};
    use crate::tools::compose::forward::{ForwardInput, ForwardMeta};
    use crate::tools::compose::send_email::{SendEmailInput, SendEmailMeta};
    use crate::tools::mailbox::delete_message::{DeleteMessageInput, DeleteMessageMeta};
    use crate::tools::mailbox::expunge::{ExpungeInput, ExpungeMeta};
    use crate::tools::mailbox::flags::{FlagInput, FlagsMeta};
    use crate::tools::mailbox::folder_management::{
        CreateFolderInput, CreateFolderMeta, DeleteFolderInput, DeleteFolderMeta,
        RenameFolderInput, RenameFolderMeta,
    };
    use crate::tools::mailbox::labels::{LabelInput, LabelsMeta, ListLabelsInput, ListLabelsMeta};
    use crate::tools::mailbox::move_message::{MoveMessageInput, MoveMessageMeta};
    use crate::tools::retrieval::download_attachment::{
        DownloadAttachmentInput, DownloadAttachmentMeta, DownloadAttachmentUntrusted,
    };
    use crate::tools::retrieval::export_messages::{ExportMessagesInput, ExportMessagesMeta};
    use crate::tools::retrieval::fetch_message::{
        FetchMessageInput, FetchMessageMeta, FetchMessageUntrusted,
    };
    use crate::tools::retrieval::list_attachments::{
        ListAttachmentsInput, ListAttachmentsMeta, ListAttachmentsUntrusted,
    };
    use crate::tools::retrieval::search::{SearchInput, SearchMeta, SearchUntrusted};
    let parts = match name {
        ToolName::ListFolders => (
            "List IMAP Folders",
            "List every IMAP folder on the account. Use it to discover \
             folder names before searching, moving, or fetching; most \
             other tools take a `folder` argument.",
            no_args_schema(),
            envelope_schema::<ToolResponse<ListFoldersMeta, ()>>(),
        ),
        ToolName::Search => (
            "Search Messages",
            "Find message UIDs in a folder by structured criteria (sender, \
             subject, date, flags, size). The UID-discovery step feeding \
             fetch_message, mark_read, move_message and other per-message \
             tools; it also returns the folder's uid_validity, which \
             mark_read/mark_unread, flag/unflag, \
             add_label/remove_label/list_labels, move_message, \
             delete_message, and export_messages accept as an optional \
             guard against UID reuse. Ordered oldest-first by UID (set \
             newest_first to reverse); paginate with offset/limit and \
             next_offset. Set thread_of_uid to retrieve a whole \
             conversation instead of a filtered search.",
            envelope_schema::<SearchInput>(),
            envelope_schema::<ToolResponse<SearchMeta, SearchUntrusted>>(),
        ),
        ToolName::FetchMessage => (
            "Fetch Message",
            "Fetch one message's envelope metadata and sanitized text body \
             by folder and uid (get the uid from search). Attachments are \
             not inlined; list them with list_attachments and retrieve \
             with download_attachment.",
            envelope_schema::<FetchMessageInput>(),
            envelope_schema::<ToolResponse<FetchMessageMeta, FetchMessageUntrusted>>(),
        ),
        ToolName::ListAttachments => (
            "List Message Attachments",
            "List a message's attachments with filename, MIME type, size, \
             and the part_id. Provides the part_id that download_attachment \
             requires; get the message uid from search first.",
            envelope_schema::<ListAttachmentsInput>(),
            envelope_schema::<ToolResponse<ListAttachmentsMeta, ListAttachmentsUntrusted>>(),
        ),
        ToolName::DownloadAttachment => (
            "Download Attachment",
            "Download one attachment (by folder, uid, and the part_id from \
             list_attachments) into the server's download sandbox and \
             return its path. File bytes are not returned inline.",
            envelope_schema::<DownloadAttachmentInput>(),
            envelope_schema::<ToolResponse<DownloadAttachmentMeta, DownloadAttachmentUntrusted>>(),
        ),
        ToolName::ExportMessages => (
            "Export Messages",
            "Export multiple messages by UID as a single git am-able mbox \
             file in the download sandbox. Discover UIDs with `search` and \
             pass its uid_validity. Disabled unless enabled in [security.tools].",
            envelope_schema::<ExportMessagesInput>(),
            envelope_schema::<ToolResponse<ExportMessagesMeta, ()>>(),
        ),
        ToolName::MarkRead => (
            "Mark Messages Read",
            "Mark messages read (Seen) in a folder. Accepts a single `uid` \
             or up to 100 `uids` from search. Reversible with mark_unread.",
            envelope_schema::<FlagInput>(),
            envelope_schema::<ToolResponse<FlagsMeta, ()>>(),
        ),
        ToolName::MarkUnread => (
            "Mark Messages Unread",
            "Mark messages unread (clear Seen) in a folder. Accepts a \
             single `uid` or up to 100 `uids`. Inverse of mark_read.",
            envelope_schema::<FlagInput>(),
            envelope_schema::<ToolResponse<FlagsMeta, ()>>(),
        ),
        ToolName::Flag => (
            "Flag Messages",
            "Add the flagged (starred) status to messages in a folder. \
             Accepts a single `uid` or up to 100 `uids` from search. \
             Remove it with unflag.",
            envelope_schema::<FlagInput>(),
            envelope_schema::<ToolResponse<FlagsMeta, ()>>(),
        ),
        ToolName::Unflag => (
            "Unflag Messages",
            "Remove the flagged (starred) status from messages. Accepts a \
             single `uid` or up to 100 `uids`. Inverse of flag.",
            envelope_schema::<FlagInput>(),
            envelope_schema::<ToolResponse<FlagsMeta, ()>>(),
        ),
        ToolName::MoveMessage => (
            "Move Messages",
            "Move messages from one folder to another (destination by \
             name; see list_folders). Accepts a single `uid` or up to 100 \
             `uids` from search. Moved messages receive new UIDs in the \
             destination folder.",
            envelope_schema::<MoveMessageInput>(),
            envelope_schema::<ToolResponse<MoveMessageMeta, ()>>(),
        ),
        ToolName::CreateDraft => (
            "Create Draft Email",
            "Save a new email as a draft flagged $PendingReview for a human \
             to review and send from their own mail client. This ends the \
             workflow: the draft cannot be sent through this server, so do \
             not follow up with send_email (that would send a duplicate \
             and bypass the human-review gate). Optional attachments are \
             read from the server's download sandbox by path (only files the \
             server downloaded/exported or the operator placed there; max 20 \
             files, 10 MiB each, 25 MiB total). Optional body_html is \
             sanitized (scripts, event handlers, remote content, and \
             javascript: URLs are stripped) and always sent alongside the \
             required plain-text body_text as a text/plain alternative; \
             supplying body_html requires the full posture \
             (create_draft.include_html).",
            envelope_schema::<CreateDraftInput>(),
            envelope_schema::<ToolResponse<CreateDraftMeta, ()>>(),
        ),
        ToolName::SendEmail => (
            "Send Email",
            "Send a new email immediately via SMTP from the account. This \
             is an autonomous send; when a human should review first, use \
             create_draft instead. Requires the full or destructive \
             posture; a lower posture is denied with ERR_POSTURE_DENIED \
             (see the rimap://docs/postures resource). Optional attachments \
             are read from the server's download sandbox by path (only files \
             the server downloaded/exported or the operator placed there; max \
             20 files, 10 MiB each, 25 MiB total). Optional body_html is \
             sanitized and always sent alongside the required plain-text \
             body_text as a text/plain alternative.",
            envelope_schema::<SendEmailInput>(),
            envelope_schema::<ToolResponse<SendEmailMeta, ()>>(),
        ),
        ToolName::Forward => (
            "Forward Message",
            "Forward an existing message (by folder + uid) to new \
             recipients as a message/rfc822 attachment, with an optional \
             comment. Re-sends the account's own stored mail via SMTP; the \
             original is attached verbatim. Same posture gate as send_email.",
            envelope_schema::<ForwardInput>(),
            envelope_schema::<ToolResponse<ForwardMeta, ()>>(),
        ),
        ToolName::DeleteMessage => (
            "Delete Message",
            "Delete a single message (by folder and uid) by moving it to \
             Trash, which is recoverable. This does not erase it; permanent \
             removal is the separate, irreversible expunge step. Pass \
             expected_uidvalidity to guard against a changed folder.",
            envelope_schema::<DeleteMessageInput>(),
            envelope_schema::<ToolResponse<DeleteMessageMeta, ()>>(),
        ),
        ToolName::Expunge => (
            "Expunge Folder",
            "Permanently and irreversibly erase every message already \
             flagged for deletion in a folder; the second step after \
             delete_message. Only allowed for folders the operator has \
             allowlisted in the server's [security].expunge_folders (empty \
             = deny-all by default) and at the destructive posture. A \
             denial returns ERR_EXPUNGE_DENIED (folder not allowlisted) or \
             ERR_POSTURE_DENIED (posture too low); neither is overridable \
             through MCP, so the operator must change the server config. \
             See the rimap://docs/postures resource.",
            envelope_schema::<ExpungeInput>(),
            envelope_schema::<ToolResponse<ExpungeMeta, ()>>(),
        ),
        ToolName::CreateFolder => (
            "Create IMAP Folder",
            "Create a new IMAP folder by name. A name colliding with a \
             protected folder (INBOX, Sent, Drafts, Trash by default, set \
             by the server's [security].protected_folders) is refused with \
             ERR_PROTECTED_FOLDER. Requires the full or destructive \
             posture, else ERR_POSTURE_DENIED. Both are server-side policy \
             the agent cannot override; see the rimap://docs/postures \
             resource.",
            envelope_schema::<CreateFolderInput>(),
            envelope_schema::<ToolResponse<CreateFolderMeta, ()>>(),
        ),
        ToolName::RenameFolder => (
            "Rename IMAP Folder",
            "Rename an IMAP folder. Renaming a protected folder or reusing \
             a protected name (INBOX, Sent, Drafts, Trash by default, from \
             the server's [security].protected_folders) is refused with \
             ERR_PROTECTED_FOLDER. Requires the full or destructive \
             posture, else ERR_POSTURE_DENIED. These are server-side \
             policy, not overridable through MCP; see the \
             rimap://docs/postures resource.",
            envelope_schema::<RenameFolderInput>(),
            envelope_schema::<ToolResponse<RenameFolderMeta, ()>>(),
        ),
        ToolName::DeleteFolder => (
            "Delete IMAP Folder",
            "Delete an IMAP folder and everything inside it; this is \
             irreversible. A protected folder (INBOX, Sent, Drafts, Trash \
             by default, from the server's [security].protected_folders) is \
             refused with ERR_PROTECTED_FOLDER, and a folder not \
             allowlisted in [security].expunge_folders is refused with \
             ERR_EXPUNGE_DENIED. Requires the destructive posture, else \
             ERR_POSTURE_DENIED. All are server-side policy the agent \
             cannot override; see the rimap://docs/postures resource.",
            envelope_schema::<DeleteFolderInput>(),
            envelope_schema::<ToolResponse<DeleteFolderMeta, ()>>(),
        ),
        ToolName::AddLabel => (
            "Add Label to Messages",
            "Add an IMAP keyword label to messages in a folder. Accepts a \
             single `uid` or up to 100 `uids` from search. Remove it with \
             remove_label; inspect current labels with list_labels.",
            envelope_schema::<LabelInput>(),
            envelope_schema::<ToolResponse<LabelsMeta, ()>>(),
        ),
        ToolName::RemoveLabel => (
            "Remove Label from Messages",
            "Remove an IMAP keyword label from messages. Accepts a single \
             `uid` or up to 100 `uids`. Inverse of add_label.",
            envelope_schema::<LabelInput>(),
            envelope_schema::<ToolResponse<LabelsMeta, ()>>(),
        ),
        ToolName::ListLabels => (
            "List Labels on Message",
            "List the IMAP keyword labels set on a single message (by \
             folder and uid from search).",
            envelope_schema::<ListLabelsInput>(),
            envelope_schema::<ToolResponse<ListLabelsMeta, ()>>(),
        ),
        ToolName::UseAccount => (
            "Select Active Account",
            "Select the active account so tools/list advertises its tools. \
             Optional: every account stays callable by its \
             <account>.<tool> name regardless of which is active. Discover \
             account names with list_accounts.",
            envelope_schema::<UseAccountInput>(),
            envelope_schema::<ToolResponse<UseAccountMeta, ()>>(),
        ),
        ToolName::ListAccounts => (
            "List Email Accounts",
            "List the configured email accounts (name and whether SMTP is \
             set up). In multi-account setups, start here to learn the \
             <account> prefix for namespaced tool calls; read the \
             rimap://accounts/<name> resource for an account's posture and \
             available tools.",
            no_args_schema(),
            envelope_schema::<ToolResponse<ListAccountsMeta, ()>>(),
        ),
        // Sub-capabilities that share an MCP tool name with a parent
        // (e.g. `SearchAdvanced` shares `search`; `FetchMessageHtml`
        // shares `fetch_message`) are advertised under the parent entry,
        // so they have no standalone definition.
        ToolName::SearchAdvanced | ToolName::FetchMessageHtml | ToolName::CreateDraftHtml => {
            return None;
        }
    };
    Some(parts)
}

/// Build the complete map of tool definitions. Called once by `TOOL_DEFS`.
fn build_tool_defs() -> HashMap<ToolName, Tool> {
    let mut map = HashMap::new();
    for tn in ToolName::all() {
        let Some((title, description, input_schema, output_schema)) = tool_def_parts(tn) else {
            continue;
        };
        map.insert(
            tn,
            Tool::new(tn.as_str(), description, Arc::new(input_schema))
                .with_title(title)
                .with_annotations(build_annotations(title, tn))
                .with_raw_output_schema(Arc::new(output_schema)),
        );
    }
    map
}

/// Memoized MCP tool definitions. Built once at first access; each
/// `list_tools` call reuses the same `Arc<JsonObject>` for schemas.
///
/// `pub` so the gated `mcp::TOOL_DEFS` re-export can expose it to the
/// binary's test-support `dump-tool-catalog` subcommand (#264); the
/// `tool_catalog` module itself is `pub(crate)`, so this is not a stable
/// library API. In-crate callers reach it via `crate::mcp::tool_catalog`.
pub static TOOL_DEFS: std::sync::LazyLock<HashMap<ToolName, Tool>> =
    std::sync::LazyLock::new(build_tool_defs);

#[cfg(test)]
mod tests {
    use rimap_core::tool::ToolName;

    use super::TOOL_DEFS;

    #[test]
    fn tool_definition_covers_all_mcp_tools() {
        // Sub-capabilities are surfaced via their parent tool's schema, not
        // as standalone MCP tools, so they do not appear in `TOOL_DEFS`.
        const SUB_CAPABILITIES: &[ToolName] = &[
            ToolName::SearchAdvanced,
            ToolName::FetchMessageHtml,
            ToolName::CreateDraftHtml,
        ];
        let expected = ToolName::all().len() - SUB_CAPABILITIES.len();
        let defs: Vec<_> = ToolName::all()
            .into_iter()
            .filter_map(|tn| TOOL_DEFS.get(&tn))
            .collect();
        assert_eq!(defs.len(), expected);
    }

    #[test]
    fn sub_capabilities_return_none() {
        assert!(TOOL_DEFS.get(&ToolName::SearchAdvanced).is_none());
        assert!(TOOL_DEFS.get(&ToolName::FetchMessageHtml).is_none());
        assert!(TOOL_DEFS.get(&ToolName::CreateDraftHtml).is_none());
    }

    #[test]
    fn tool_names_are_snake_case() {
        for def in ToolName::all()
            .into_iter()
            .filter_map(|tn| TOOL_DEFS.get(&tn))
        {
            assert!(
                def.name.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "tool name {} is not snake_case",
                def.name,
            );
        }
    }

    #[test]
    fn tool_definitions_have_non_empty_schemas() {
        for def in ToolName::all()
            .into_iter()
            .filter_map(|tn| TOOL_DEFS.get(&tn))
        {
            let schema = &def.input_schema;
            assert!(
                !schema.is_empty(),
                "tool {} has empty input schema",
                def.name,
            );
        }
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "panicking on serialization failure is the right test behavior"
    )]
    fn no_tool_schema_leaks_rustdoc_or_internal_identifiers() {
        // Regression net for #405: published tool schemas are generated
        // from rustdoc via schemars, so unresolvable doc-link syntax,
        // internal-only identifiers, and design essays for reviewers can
        // leak straight to agents if a doc comment isn't written with
        // the schema in mind. Scans the full serialized Tool (title,
        // description, input/output schema) for every tool.
        const BANNED_SUBSTRINGS: &[&str] = &[
            "# Shape",
            "Content-oracle",
            "MAX_BATCH_UIDS",
            "MAX_EXPORT_TOTAL_BYTES",
            "build_query",
            "escape_wire_name",
            "must `Serialize`",
        ];
        for def in ToolName::all()
            .into_iter()
            .filter_map(|tn| TOOL_DEFS.get(&tn))
        {
            let serialized = serde_json::to_string(def).expect("tool def serializes");
            assert!(
                !serialized.contains("[`"),
                "tool {} schema contains unresolvable rustdoc doc-link syntax \
                 ([`...`]); inline the referenced value or drop the link",
                def.name,
            );
            for banned in BANNED_SUBSTRINGS {
                assert!(
                    !serialized.contains(banned),
                    "tool {} schema leaks internal identifier or maintainer \
                     jargon {banned:?}",
                    def.name,
                );
            }
        }
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test lookups")]
    fn descriptions_carry_workflow_guidance() {
        // Regression net for #404: the description is the primary signal an
        // agent uses to plan a call sequence. Pin the load-bearing pieces
        // so a future edit can't silently drop them.
        fn desc(tn: ToolName) -> String {
            TOOL_DEFS
                .get(&tn)
                .and_then(|d| d.description.as_deref())
                .expect("tool has a description")
                .to_string()
        }

        // create_draft must document the $PendingReview dead-end (F18):
        // the draft cannot be sent via MCP and send_email is not a
        // follow-up.
        let draft = desc(ToolName::CreateDraft);
        assert!(
            draft.contains("$PendingReview"),
            "create_draft must name the $PendingReview lifecycle; got {draft:?}",
        );
        assert!(
            draft.contains("send_email"),
            "create_draft must warn against following up with send_email; got {draft:?}",
        );

        // Batch tools must state the single-uid-or-up-to-100-uids contract.
        for tn in [
            ToolName::MarkRead,
            ToolName::Flag,
            ToolName::AddLabel,
            ToolName::MoveMessage,
        ] {
            let d = desc(tn);
            assert!(
                d.contains("100"),
                "batch tool {} must state the 100-uid limit; got {d:?}",
                tn.as_str(),
            );
        }

        // The two-step delete model must be discoverable from both ends.
        assert!(
            desc(ToolName::DeleteMessage).contains("expunge"),
            "delete_message must point at the separate expunge step",
        );
        assert!(
            desc(ToolName::Expunge).contains("delete_message"),
            "expunge must reference delete_message as the first step",
        );

        // download_attachment depends on list_attachments for the part_id.
        assert!(
            desc(ToolName::DownloadAttachment).contains("list_attachments"),
            "download_attachment must reference list_attachments for part_id",
        );
    }

    #[test]
    #[expect(clippy::expect_used, reason = "test lookups")]
    fn descriptions_carry_denial_remediation() {
        // Regression net for #417: denial errors are scrubbed at runtime
        // (ProtectedFolder/ExpungeDenied -> "operation denied for this
        // folder"), so the folder-policy tools must carry the remediation
        // statically. Each references the governing config key, the stable
        // error_code an agent will see in structuredContent (#402), and the
        // rimap://docs/postures resource, and states the policy is not
        // overridable through MCP.
        fn desc(tn: ToolName) -> String {
            TOOL_DEFS
                .get(&tn)
                .and_then(|d| d.description.as_deref())
                .expect("tool has a description")
                .to_string()
        }

        // Posture denials name the stable code + point at the doc resource.
        for tn in [
            ToolName::SendEmail,
            ToolName::Expunge,
            ToolName::CreateFolder,
            ToolName::RenameFolder,
            ToolName::DeleteFolder,
        ] {
            let d = desc(tn);
            assert!(
                d.contains("ERR_POSTURE_DENIED"),
                "{} must name ERR_POSTURE_DENIED; got {d:?}",
                tn.as_str(),
            );
            assert!(
                d.contains("rimap://docs/postures"),
                "{} must point at rimap://docs/postures; got {d:?}",
                tn.as_str(),
            );
        }

        // protected_folders policy: create/rename/delete_folder name the
        // config key and the ERR_PROTECTED_FOLDER code.
        for tn in [
            ToolName::CreateFolder,
            ToolName::RenameFolder,
            ToolName::DeleteFolder,
        ] {
            let d = desc(tn);
            assert!(
                d.contains("[security].protected_folders") && d.contains("ERR_PROTECTED_FOLDER"),
                "{} must name [security].protected_folders + ERR_PROTECTED_FOLDER; got {d:?}",
                tn.as_str(),
            );
        }

        // expunge_folders allowlist: expunge and delete_folder name the
        // config key and the ERR_EXPUNGE_DENIED code.
        for tn in [ToolName::Expunge, ToolName::DeleteFolder] {
            let d = desc(tn);
            assert!(
                d.contains("[security].expunge_folders") && d.contains("ERR_EXPUNGE_DENIED"),
                "{} must name [security].expunge_folders + ERR_EXPUNGE_DENIED; got {d:?}",
                tn.as_str(),
            );
        }

        // The denial is a server-side decision the agent cannot self-serve.
        assert!(
            desc(ToolName::Expunge).contains("operator must change the server config"),
            "expunge must state the operator (not the agent) resolves an expunge denial",
        );
    }

    #[test]
    fn every_tool_input_schema_declares_object_type() {
        // Spec-strict MCP clients (e.g. bobshell's Zod validator) reject
        // any tool whose inputSchema.type is not the string "object". A
        // bare `{}` is a valid JSON Schema but the wrong shape for MCP.
        for def in ToolName::all()
            .into_iter()
            .filter_map(|tn| TOOL_DEFS.get(&tn))
        {
            let type_field = def.input_schema.get("type");
            assert_eq!(
                type_field.and_then(serde_json::Value::as_str),
                Some("object"),
                "tool {} input_schema.type must be the string \"object\"; got {type_field:?}",
                def.name,
            );
        }
    }

    #[test]
    fn every_tool_has_a_description() {
        for def in ToolName::all()
            .into_iter()
            .filter_map(|tn| TOOL_DEFS.get(&tn))
        {
            assert!(
                def.description.is_some(),
                "tool {} missing description",
                def.name,
            );
        }
    }

    #[test]
    fn every_tool_has_a_non_empty_title() {
        for def in ToolName::all()
            .into_iter()
            .filter_map(|tn| TOOL_DEFS.get(&tn))
        {
            let title = def.title.as_deref();
            assert!(
                title.is_some_and(|t| !t.is_empty()),
                "tool {} missing non-empty title; got {title:?}",
                def.name,
            );
        }
    }

    #[test]
    fn every_tool_has_annotations() {
        for def in ToolName::all()
            .into_iter()
            .filter_map(|tn| TOOL_DEFS.get(&tn))
        {
            assert!(
                def.annotations.is_some(),
                "tool {} must publish annotations",
                def.name,
            );
        }
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "panicking on missing entry or annotation is the right test behavior"
    )]
    fn use_account_advertises_not_read_only() {
        let def = TOOL_DEFS
            .get(&ToolName::UseAccount)
            .expect("use_account in TOOL_DEFS");
        let ann = def.annotations.as_ref().expect("annotations present");
        assert_eq!(
            ann.read_only_hint,
            Some(false),
            "use_account mutates session state; read_only_hint must be false",
        );
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "panicking on missing entry or annotation is the right test behavior"
    )]
    fn delete_message_advertises_destructive() {
        let def = TOOL_DEFS
            .get(&ToolName::DeleteMessage)
            .expect("delete_message in TOOL_DEFS");
        let ann = def.annotations.as_ref().expect("annotations present");
        assert_eq!(ann.destructive_hint, Some(true));
    }

    #[test]
    fn every_advertised_tool_has_output_schema() {
        for def in ToolName::all()
            .into_iter()
            .filter_map(|tn| TOOL_DEFS.get(&tn))
        {
            assert!(
                def.output_schema.is_some(),
                "tool {} must publish an outputSchema",
                def.name,
            );
        }
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "panicking on missing entry is the right test behavior"
    )]
    fn search_output_schema_declares_object_type() {
        let def = TOOL_DEFS
            .get(&ToolName::Search)
            .expect("search in TOOL_DEFS");
        let schema = def.output_schema.as_ref().expect("output schema present");
        assert_eq!(
            schema.get("type").and_then(serde_json::Value::as_str),
            Some("object"),
        );
    }

    #[test]
    #[expect(
        clippy::panic,
        reason = "test fixture I/O failures should panic with a clear message"
    )]
    fn every_tool_output_schema_matches_fixture() {
        // Catches drift between this file's `tool_def_parts(name)` match
        // and `cli/dump_tool_schemas.rs::build_schemas` if their parallel
        // `ToolName → (MetaType, UntrustedType)` tables disagree. The wire
        // test `wire_published_output_schema_matches_fixture` only
        // exercises 2 tools in the zero-account harness; this unit test
        // covers all 24 without docker.
        use std::path::Path;
        for def in ToolName::all()
            .into_iter()
            .filter_map(|tn| TOOL_DEFS.get(&tn))
        {
            let fixture_path = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/rimap-tool-schemas")
                .join(format!("{}.schema.json", def.name));
            let fixture_raw = std::fs::read_to_string(&fixture_path)
                .unwrap_or_else(|e| panic!("read fixture {fixture_path:?}: {e}"));
            let fixture_value: serde_json::Value = serde_json::from_str(&fixture_raw)
                .unwrap_or_else(|e| panic!("parse fixture {fixture_path:?}: {e}"));
            let published = def
                .output_schema
                .as_ref()
                .unwrap_or_else(|| panic!("tool {} has no output_schema", def.name));
            let published_value = serde_json::Value::Object(published.as_ref().clone());
            assert_eq!(
                published_value, fixture_value,
                "tool {} output_schema diverges from fixture {fixture_path:?}.\n\
                 Run `just regen-tool-schemas` AND audit `tool_catalog::tool_def_parts` \
                 vs `dump_tool_schemas::build_schemas` for type-pair drift.",
                def.name,
            );
        }
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "panicking on missing title or empty word is the right test behavior"
    )]
    fn every_tool_title_is_title_case() {
        // Short function words that may be lowercase in title case
        // (articles, prepositions, coordinating conjunctions) when not
        // in the first position.
        const LOWERCASE_EXCEPTIONS: &[&str] = &[
            "a", "an", "the", "and", "but", "or", "nor", "for", "so", "yet", "at", "by", "in",
            "of", "on", "to", "up", "via", "from", "into", "with",
        ];
        for def in ToolName::all()
            .into_iter()
            .filter_map(|tn| TOOL_DEFS.get(&tn))
        {
            let title = def.title.as_deref().expect("title present");
            for (i, word) in title.split_whitespace().enumerate() {
                let first = word.chars().next().expect("non-empty word");
                let is_exception =
                    LOWERCASE_EXCEPTIONS.contains(&word.to_ascii_lowercase().as_str());
                // First word must always be uppercase; subsequent words may
                // be lowercase only if they are a recognized function word.
                if i == 0 || !is_exception {
                    assert!(
                        first.is_ascii_uppercase(),
                        "tool {} title {title:?}: word {word:?} must start uppercase",
                        def.name,
                    );
                }
            }
        }
    }
}
/// Number of tools per `tools/list` page. Chosen comfortably above a
/// single-account full-posture catalog (infrastructure + one account's
/// advertised tools) so single- and few-account deployments always fit in
/// one page and see no pagination behavior change; larger multi-account
/// catalogs page. The `single_account_catalog_fits_one_page` test pins the
/// single-account invariant so a future tool addition that breaks it fails
/// loudly instead of silently paginating single-account deployments.
pub(super) const TOOLS_PER_PAGE: usize = 25;
/// Decode an opaque `tools/list` cursor (a decimal catalog offset) into a
/// start index. An unparsable cursor is a client error, mapped to
/// `-32602 Invalid params` per the MCP pagination contract.
pub(super) fn decode_tool_cursor(cursor: &str) -> Result<usize, ErrorData> {
    cursor.parse::<usize>().map_err(|_| {
        ErrorData::invalid_params(format!("invalid tools/list cursor: {cursor:?}"), None)
    })
}

/// Compute the page window over a catalog of `len` tools starting at
/// `start`. Returns the clamped start (so slicing is always in bounds even
/// for a stale/oversized cursor), the exclusive end, and the next page's
/// start offset (`None` on the last page).
pub(super) fn tool_page_window(len: usize, start: usize) -> (usize, usize, Option<usize>) {
    let start = start.min(len);
    let end = start.saturating_add(TOOLS_PER_PAGE).min(len);
    let next = (end < len).then_some(end);
    (start, end, next)
}
#[cfg(test)]
#[expect(clippy::expect_used, reason = "tests")]
mod pagination_tests {
    use std::collections::BTreeMap;

    use rimap_authz::matrix::EffectiveMatrix;
    use rimap_core::posture::Posture;
    use rimap_core::tool::ToolName;

    use super::{TOOLS_PER_PAGE, decode_tool_cursor, tool_page_window};
    use crate::mcp::tool_catalog::TOOL_DEFS;

    #[test]
    fn empty_catalog_yields_one_empty_page() {
        assert_eq!(tool_page_window(0, 0), (0, 0, None));
    }

    #[test]
    fn short_catalog_fits_one_page_without_next_cursor() {
        let (start, end, next) = tool_page_window(TOOLS_PER_PAGE - 1, 0);
        assert_eq!((start, end), (0, TOOLS_PER_PAGE - 1));
        assert_eq!(next, None);
    }

    #[test]
    fn exactly_one_page_has_no_next_cursor() {
        let (_start, end, next) = tool_page_window(TOOLS_PER_PAGE, 0);
        assert_eq!(end, TOOLS_PER_PAGE);
        assert_eq!(next, None, "a full-but-final page must not advertise more");
    }

    #[test]
    fn overflowing_catalog_pages_without_gap_or_overlap() {
        // Walk a 2.5-page catalog end to end via next_cursor and assert the
        // visited indices are exactly 0..len — no tool dropped or duplicated
        // (the advertised set is preserved across pages).
        let len = TOOLS_PER_PAGE * 2 + 10;
        let mut visited: Vec<usize> = Vec::new();
        let mut start = 0;
        loop {
            let (s, e, next) = tool_page_window(len, start);
            visited.extend(s..e);
            match next {
                Some(n) => start = n,
                None => break,
            }
        }
        assert_eq!(visited, (0..len).collect::<Vec<_>>());
    }

    #[test]
    fn stale_cursor_past_end_yields_empty_final_page() {
        let (start, end, next) = tool_page_window(5, 1000);
        assert_eq!((start, end), (5, 5));
        assert_eq!(next, None);
    }

    #[test]
    fn decode_cursor_accepts_offset_and_rejects_garbage() {
        assert_eq!(decode_tool_cursor("25").expect("valid offset"), 25);
        assert!(decode_tool_cursor("abc").is_err());
        assert!(decode_tool_cursor("").is_err());
        assert!(decode_tool_cursor("-1").is_err());
    }

    #[test]
    fn single_account_catalog_fits_one_page() {
        // Invariant behind TOOLS_PER_PAGE: a single-account, most-permissive
        // (full) catalog — infrastructure tools plus one account's advertised
        // tools that have a TOOL_DEFS entry — must fit in one page so
        // single-account deployments never paginate (AC: no single-account
        // behavior change). If a future tool addition breaks this, bump
        // TOOLS_PER_PAGE.
        let matrix = EffectiveMatrix::build(Posture::Full, &BTreeMap::new());
        let per_account = matrix
            .advertised()
            .iter()
            .filter(|tn| TOOL_DEFS.get(tn).is_some())
            .count();
        let infra = [ToolName::UseAccount, ToolName::ListAccounts]
            .iter()
            .filter(|tn| TOOL_DEFS.get(tn).is_some())
            .count();
        let single_len = infra + per_account;
        let (_s, _e, next) = tool_page_window(single_len, 0);
        assert_eq!(
            next, None,
            "single-account catalog of {single_len} tools must fit one page \
             (TOOLS_PER_PAGE={TOOLS_PER_PAGE}); bump the page size",
        );
    }
}
