//! MCP tool catalog: descriptions, input schemas, and the memoized
//! [`TOOL_DEFS`] map.
//!
//! Centralises the mapping from [`ToolName`] to MCP `Tool` advertisement
//! metadata. Sub-capabilities that share a wire name with a parent
//! (`SearchAdvanced`, `FetchMessageHtml`) intentionally return `None`
//! from [`tool_spec`] — they are surfaced via the parent tool.
//!
//! Also hosts the argument-serialization helpers ([`ser`], [`parse_args`])
//! used by the dispatch pipeline.

use std::collections::HashMap;
use std::sync::Arc;

use rimap_core::tool::ToolName;
use rmcp::model::{Tool, ToolAnnotations};

use crate::mcp::response::{ToolResponse, envelope_schema};

/// Type alias for tool spec tuples — `(title, description, schema)`. The wire
/// name comes from `ToolName::as_str()` so there is a single source of
/// truth for tool names.
type ToolSpec = (
    &'static str,                               // title (Title Case, human-readable)
    &'static str,                               // description
    serde_json::Map<String, serde_json::Value>, // input schema
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

/// Per-tool output-envelope JSON Schema, byte-identical to what
/// `crates/rimap-server/src/cli/dump_tool_schemas.rs::tool_envelope`
/// dumps for the fixture set. Returns `None` for sub-capability
/// variants that share an MCP wire name with their parent.
fn output_schema(name: ToolName) -> Option<serde_json::Map<String, serde_json::Value>> {
    use crate::tools::{
        admin::{
            accounts::{ListAccountsMeta, UseAccountMeta},
            list_folders::ListFoldersMeta,
        },
        compose::{create_draft::CreateDraftMeta, send_email::SendEmailMeta},
        mailbox::{
            delete_message::DeleteMessageMeta,
            expunge::ExpungeMeta,
            flags::FlagsMeta,
            folder_management::{CreateFolderMeta, DeleteFolderMeta, RenameFolderMeta},
            labels::{LabelsMeta, ListLabelsMeta},
            move_message::MoveMessageMeta,
        },
        retrieval::{
            download_attachment::{DownloadAttachmentMeta, DownloadAttachmentUntrusted},
            export_messages::ExportMessagesMeta,
            fetch_message::{FetchMessageMeta, FetchMessageUntrusted},
            list_attachments::{ListAttachmentsMeta, ListAttachmentsUntrusted},
            search::{SearchMeta, SearchUntrusted},
        },
    };

    let schema = match name {
        ToolName::ListAccounts => envelope_schema::<ToolResponse<ListAccountsMeta, ()>>(),
        ToolName::UseAccount => envelope_schema::<ToolResponse<UseAccountMeta, ()>>(),
        ToolName::ListFolders => envelope_schema::<ToolResponse<ListFoldersMeta, ()>>(),
        ToolName::Search => envelope_schema::<ToolResponse<SearchMeta, SearchUntrusted>>(),
        ToolName::FetchMessage => {
            envelope_schema::<ToolResponse<FetchMessageMeta, FetchMessageUntrusted>>()
        }
        ToolName::ListAttachments => {
            envelope_schema::<ToolResponse<ListAttachmentsMeta, ListAttachmentsUntrusted>>()
        }
        ToolName::DownloadAttachment => {
            envelope_schema::<ToolResponse<DownloadAttachmentMeta, DownloadAttachmentUntrusted>>()
        }
        ToolName::ExportMessages => envelope_schema::<ToolResponse<ExportMessagesMeta, ()>>(),
        ToolName::MarkRead | ToolName::MarkUnread | ToolName::Flag | ToolName::Unflag => {
            envelope_schema::<ToolResponse<FlagsMeta, ()>>()
        }
        ToolName::AddLabel | ToolName::RemoveLabel => {
            envelope_schema::<ToolResponse<LabelsMeta, ()>>()
        }
        ToolName::ListLabels => envelope_schema::<ToolResponse<ListLabelsMeta, ()>>(),
        ToolName::MoveMessage => envelope_schema::<ToolResponse<MoveMessageMeta, ()>>(),
        ToolName::CreateDraft => envelope_schema::<ToolResponse<CreateDraftMeta, ()>>(),
        ToolName::SendEmail => envelope_schema::<ToolResponse<SendEmailMeta, ()>>(),
        ToolName::DeleteMessage => envelope_schema::<ToolResponse<DeleteMessageMeta, ()>>(),
        ToolName::Expunge => envelope_schema::<ToolResponse<ExpungeMeta, ()>>(),
        ToolName::CreateFolder => envelope_schema::<ToolResponse<CreateFolderMeta, ()>>(),
        ToolName::RenameFolder => envelope_schema::<ToolResponse<RenameFolderMeta, ()>>(),
        ToolName::DeleteFolder => envelope_schema::<ToolResponse<DeleteFolderMeta, ()>>(),
        ToolName::SearchAdvanced | ToolName::FetchMessageHtml => return None,
    };
    Some(schema)
}

/// Return (title, description, schema) for the given `ToolName`, or `None`
/// for sub-capabilities that share an MCP tool name with a parent
/// (e.g. `SearchAdvanced`, `FetchMessageHtml`).
#[expect(
    clippy::too_many_lines,
    reason = "single match over 25 ToolName variants; splitting would create two parallel matches"
)]
fn tool_spec(name: ToolName) -> Option<ToolSpec> {
    use crate::tools::admin::accounts::UseAccountInput;
    use crate::tools::compose::create_draft::CreateDraftInput;
    use crate::tools::compose::send_email::SendEmailInput;
    use crate::tools::mailbox::delete_message::DeleteMessageInput;
    use crate::tools::mailbox::expunge::ExpungeInput;
    use crate::tools::mailbox::flags::FlagInput;
    use crate::tools::mailbox::folder_management::{
        CreateFolderInput, DeleteFolderInput, RenameFolderInput,
    };
    use crate::tools::mailbox::labels::{LabelInput, ListLabelsInput};
    use crate::tools::mailbox::move_message::MoveMessageInput;
    use crate::tools::retrieval::download_attachment::DownloadAttachmentInput;
    use crate::tools::retrieval::export_messages::ExportMessagesInput;
    use crate::tools::retrieval::fetch_message::FetchMessageInput;
    use crate::tools::retrieval::list_attachments::ListAttachmentsInput;
    use crate::tools::retrieval::search::SearchInput;
    let tuple = match name {
        ToolName::ListFolders => (
            "List IMAP Folders",
            "List all IMAP folders",
            no_args_schema(),
        ),
        ToolName::Search => (
            "Search Messages",
            "Search messages with structured query",
            envelope_schema::<SearchInput>(),
        ),
        ToolName::FetchMessage => (
            "Fetch Message",
            "Fetch message metadata and text body",
            envelope_schema::<FetchMessageInput>(),
        ),
        ToolName::ListAttachments => (
            "List Message Attachments",
            "List attachments on a message",
            envelope_schema::<ListAttachmentsInput>(),
        ),
        ToolName::DownloadAttachment => (
            "Download Attachment",
            "Download an attachment to the sandbox directory",
            envelope_schema::<DownloadAttachmentInput>(),
        ),
        ToolName::ExportMessages => (
            "Export Messages",
            "Export multiple messages by UID as a single git am-able mbox \
             file in the download sandbox. Discover UIDs with `search` and \
             pass its uid_validity. Disabled unless enabled in [security.tools].",
            envelope_schema::<ExportMessagesInput>(),
        ),
        ToolName::MarkRead => (
            "Mark Messages Read",
            "Mark messages as read",
            envelope_schema::<FlagInput>(),
        ),
        ToolName::MarkUnread => (
            "Mark Messages Unread",
            "Mark messages as unread",
            envelope_schema::<FlagInput>(),
        ),
        ToolName::Flag => (
            "Flag Messages",
            "Add the flagged flag to messages",
            envelope_schema::<FlagInput>(),
        ),
        ToolName::Unflag => (
            "Unflag Messages",
            "Remove the flagged flag from messages",
            envelope_schema::<FlagInput>(),
        ),
        ToolName::MoveMessage => (
            "Move Messages",
            "Move messages to another folder",
            envelope_schema::<MoveMessageInput>(),
        ),
        ToolName::CreateDraft => (
            "Create Draft Email",
            "Create a draft email with $PendingReview flag",
            envelope_schema::<CreateDraftInput>(),
        ),
        ToolName::SendEmail => (
            "Send Email",
            "Send an email via SMTP",
            envelope_schema::<SendEmailInput>(),
        ),
        ToolName::DeleteMessage => (
            "Delete Message",
            "Delete a message (move to Trash)",
            envelope_schema::<DeleteMessageInput>(),
        ),
        ToolName::Expunge => (
            "Expunge Folder",
            "Permanently remove deleted messages from a folder",
            envelope_schema::<ExpungeInput>(),
        ),
        ToolName::CreateFolder => (
            "Create IMAP Folder",
            "Create a new IMAP folder",
            envelope_schema::<CreateFolderInput>(),
        ),
        ToolName::RenameFolder => (
            "Rename IMAP Folder",
            "Rename an IMAP folder",
            envelope_schema::<RenameFolderInput>(),
        ),
        ToolName::DeleteFolder => (
            "Delete IMAP Folder",
            "Delete an IMAP folder and all its contents",
            envelope_schema::<DeleteFolderInput>(),
        ),
        ToolName::AddLabel => (
            "Add Label to Messages",
            "Add a keyword label to messages",
            envelope_schema::<LabelInput>(),
        ),
        ToolName::RemoveLabel => (
            "Remove Label from Messages",
            "Remove a keyword label from messages",
            envelope_schema::<LabelInput>(),
        ),
        ToolName::ListLabels => (
            "List Labels on Message",
            "List keyword labels on a message",
            envelope_schema::<ListLabelsInput>(),
        ),
        ToolName::UseAccount => (
            "Select Active Account",
            "Set the active account for subsequent tool calls",
            envelope_schema::<UseAccountInput>(),
        ),
        ToolName::ListAccounts => (
            "List Email Accounts",
            "List all configured email accounts",
            no_args_schema(),
        ),
        // Sub-capabilities that share an MCP tool name with a parent
        // (e.g. `SearchAdvanced` shares `search`; `FetchMessageHtml`
        // shares `fetch_message`) are advertised under the parent entry,
        // so they have no standalone spec.
        ToolName::SearchAdvanced | ToolName::FetchMessageHtml => return None,
    };
    Some(tuple)
}

/// Build the complete map of tool definitions. Called once by `TOOL_DEFS`.
///
/// `expect` is load-bearing: every `tool_spec`-positive `ToolName` is also
/// `output_schema`-positive. Both functions return `None` for the same two
/// sub-capability variants (`SearchAdvanced`, `FetchMessageHtml`), so the
/// `continue` guard above means we never reach the `expect` for those.
#[expect(
    clippy::expect_used,
    reason = "output_schema returns None exactly for the same variants tool_spec returns None for; \
              the continue guard above means we never reach expect for those variants"
)]
fn build_tool_defs() -> HashMap<ToolName, Tool> {
    let mut map = HashMap::new();
    for tn in ToolName::all() {
        let Some((title, description, schema)) = tool_spec(tn) else {
            continue;
        };
        let out_schema = output_schema(tn).expect("every catalog tool has an output schema");
        map.insert(
            tn,
            Tool::new(tn.as_str(), description, Arc::new(schema))
                .with_title(title)
                .with_annotations(build_annotations(title, tn))
                .with_raw_output_schema(Arc::new(out_schema)),
        );
    }
    map
}

/// Memoized MCP tool definitions. Built once at first access; each
/// `list_tools` call reuses the same `Arc<JsonObject>` for schemas.
///
/// `pub` so the binary's test-support `dump-tool-catalog` subcommand
/// (#264) can iterate the catalog from outside the library crate. The
/// parent `mcp` module is `#[doc(hidden)]` so this does not become a
/// stable library API.
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
        const SUB_CAPABILITIES: &[ToolName] =
            &[ToolName::SearchAdvanced, ToolName::FetchMessageHtml];
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
        // Catches drift between this file's `output_schema(name)` match
        // and `cli/dump_tool_schemas.rs::build_schemas` if their parallel
        // `ToolName → (MetaType, UntrustedType)` tables disagree. The wire
        // test `wire_published_output_schema_matches_fixture` only
        // exercises 2 tools in the zero-account harness; this unit test
        // covers all 23 without docker.
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
                 Run `just regen-tool-schemas` AND audit `tool_catalog::output_schema` \
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
