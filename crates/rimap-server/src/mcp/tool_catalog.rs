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

/// Type alias for tool spec tuples — `(title, description, schema)`. The wire
/// name comes from `ToolName::as_str()` so there is a single source of
/// truth for tool names.
type ToolSpec = (
    &'static str, // title (Title Case, human-readable)
    &'static str, // description
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

/// Convert a `schemars::JsonSchema` type into a JSON object map
/// suitable for an MCP tool's `inputSchema`.
fn schema_map<T: schemars::JsonSchema>() -> serde_json::Map<String, serde_json::Value> {
    let schema = schemars::schema_for!(T);
    match serde_json::to_value(schema) {
        Ok(serde_json::Value::Object(mut map)) => {
            // Strip Rust struct name to avoid leaking implementation
            // details in the MCP list_tools response.
            map.remove("title");
            map
        }
        Ok(
            serde_json::Value::Null
            | serde_json::Value::Bool(_)
            | serde_json::Value::Number(_)
            | serde_json::Value::String(_)
            | serde_json::Value::Array(_),
        )
        | Err(_) => serde_json::Map::new(),
    }
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

/// Return (title, description, schema) for the given `ToolName`, or `None`
/// for sub-capabilities that share an MCP tool name with a parent
/// (e.g. `SearchAdvanced`, `FetchMessageHtml`).
#[expect(
    clippy::too_many_lines,
    reason = "single match over 24 ToolName variants; splitting would create two parallel matches"
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
            schema_map::<SearchInput>(),
        ),
        ToolName::FetchMessage => (
            "Fetch Message",
            "Fetch message metadata and text body",
            schema_map::<FetchMessageInput>(),
        ),
        ToolName::ListAttachments => (
            "List Message Attachments",
            "List attachments on a message",
            schema_map::<ListAttachmentsInput>(),
        ),
        ToolName::DownloadAttachment => (
            "Download Attachment",
            "Download an attachment to the sandbox directory",
            schema_map::<DownloadAttachmentInput>(),
        ),
        ToolName::MarkRead => (
            "Mark Messages Read",
            "Mark messages as read",
            schema_map::<FlagInput>(),
        ),
        ToolName::MarkUnread => (
            "Mark Messages Unread",
            "Mark messages as unread",
            schema_map::<FlagInput>(),
        ),
        ToolName::Flag => (
            "Flag Messages",
            "Add the flagged flag to messages",
            schema_map::<FlagInput>(),
        ),
        ToolName::Unflag => (
            "Unflag Messages",
            "Remove the flagged flag from messages",
            schema_map::<FlagInput>(),
        ),
        ToolName::MoveMessage => (
            "Move Messages",
            "Move messages to another folder",
            schema_map::<MoveMessageInput>(),
        ),
        ToolName::CreateDraft => (
            "Create Draft Email",
            "Create a draft email with $PendingReview flag",
            schema_map::<CreateDraftInput>(),
        ),
        ToolName::SendEmail => (
            "Send Email",
            "Send an email via SMTP",
            schema_map::<SendEmailInput>(),
        ),
        ToolName::DeleteMessage => (
            "Delete Message",
            "Delete a message (move to Trash)",
            schema_map::<DeleteMessageInput>(),
        ),
        ToolName::Expunge => (
            "Expunge Folder",
            "Permanently remove deleted messages from a folder",
            schema_map::<ExpungeInput>(),
        ),
        ToolName::CreateFolder => (
            "Create IMAP Folder",
            "Create a new IMAP folder",
            schema_map::<CreateFolderInput>(),
        ),
        ToolName::RenameFolder => (
            "Rename IMAP Folder",
            "Rename an IMAP folder",
            schema_map::<RenameFolderInput>(),
        ),
        ToolName::DeleteFolder => (
            "Delete IMAP Folder",
            "Delete an IMAP folder and all its contents",
            schema_map::<DeleteFolderInput>(),
        ),
        ToolName::AddLabel => (
            "Add Label to Messages",
            "Add a keyword label to messages",
            schema_map::<LabelInput>(),
        ),
        ToolName::RemoveLabel => (
            "Remove Label from Messages",
            "Remove a keyword label from messages",
            schema_map::<LabelInput>(),
        ),
        ToolName::ListLabels => (
            "List Labels on Message",
            "List keyword labels on a message",
            schema_map::<ListLabelsInput>(),
        ),
        ToolName::UseAccount => (
            "Select Active Account",
            "Set the active account for subsequent tool calls",
            schema_map::<UseAccountInput>(),
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

/// Memoized MCP tool definitions. Built once at first access; each
/// `list_tools` call reuses the same `Arc<JsonObject>` for schemas.
///
/// `pub` so the binary's test-support `dump-tool-catalog` subcommand
/// (#264) can iterate the catalog from outside the library crate. The
/// parent `mcp` module is `#[doc(hidden)]` so this does not become a
/// stable library API.
pub static TOOL_DEFS: std::sync::LazyLock<HashMap<ToolName, Tool>> =
    std::sync::LazyLock::new(|| {
        let mut map = HashMap::new();
        for tn in ToolName::all() {
            let Some((title, description, schema)) = tool_spec(tn) else {
                continue;
            };
            map.insert(
                tn,
                Tool::new(tn.as_str(), description, Arc::new(schema))
                    .with_title(title)
                    .with_annotations(build_annotations(title, tn)),
            );
        }
        map
    });

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
    #[expect(
        clippy::expect_used,
        reason = "panicking on missing title or empty word is the right test behavior"
    )]
    fn every_tool_title_is_title_case() {
        // Short function words that may be lowercase in title case
        // (articles, prepositions, coordinating conjunctions) when not
        // in the first position.
        const LOWERCASE_EXCEPTIONS: &[&str] = &[
            "a", "an", "the", "and", "but", "or", "nor", "for", "so",
            "yet", "at", "by", "in", "of", "on", "to", "up", "via",
            "from", "into", "with",
        ];
        for def in ToolName::all()
            .into_iter()
            .filter_map(|tn| TOOL_DEFS.get(&tn))
        {
            let title = def.title.as_deref().expect("title present");
            for (i, word) in title.split_whitespace().enumerate() {
                let first = word.chars().next().expect("non-empty word");
                let is_exception = LOWERCASE_EXCEPTIONS.contains(&word.to_ascii_lowercase().as_str());
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
