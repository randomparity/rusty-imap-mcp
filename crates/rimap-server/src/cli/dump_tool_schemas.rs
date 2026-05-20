//! `dump-tool-schemas` test-support CLI subcommand. Emits one JSON
//! Schema per in-scope tool, deriving the per-tool envelope from
//! `schemars::schema_for!(ToolResponse<M, U>)`. The resulting fixtures
//! are byte-identical to what `output_schema()` (Task D4) will publish
//! at runtime, so the Phase 3 wire-conformance harness (issue #265)
//! validates every response against the same schema that ships on the
//! wire.

use std::collections::BTreeMap;
use std::io::Write;

use serde_json::Value;

/// Emit `{ "<tool>": <schema>, ... }` as pretty-printed JSON to the
/// given writer. Iteration order is deterministic (`BTreeMap`).
///
/// # Errors
///
/// Returns the I/O error if the writer fails or the serializer cannot
/// encode an entry. Schemars produces valid JSON for every derive-using
/// struct in scope; failure indicates a bug, not user input.
pub fn dump_tool_schemas<W: Write>(writer: &mut W) -> std::io::Result<()> {
    let schemas = build_schemas();
    serde_json::to_writer_pretty(&mut *writer, &schemas)?;
    writer.write_all(b"\n")?;
    writer.flush()
}

fn build_schemas() -> BTreeMap<&'static str, Value> {
    use rimap_server::tools::{
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
            fetch_message::{FetchMessageMeta, FetchMessageUntrusted},
            list_attachments::{ListAttachmentsMeta, ListAttachmentsUntrusted},
            search::{SearchMeta, SearchUntrusted},
        },
    };

    let mut out = BTreeMap::<&'static str, Value>::new();

    // meta-only tools (no untrusted payload on the wire): U = ()
    out.insert("list_folders", tool_envelope::<ListFoldersMeta, ()>());
    out.insert("list_accounts", tool_envelope::<ListAccountsMeta, ()>());
    out.insert("use_account", tool_envelope::<UseAccountMeta, ()>());
    out.insert("list_labels", tool_envelope::<ListLabelsMeta, ()>());
    out.insert("mark_read", tool_envelope::<FlagsMeta, ()>());
    out.insert("mark_unread", tool_envelope::<FlagsMeta, ()>());
    out.insert("flag", tool_envelope::<FlagsMeta, ()>());
    out.insert("unflag", tool_envelope::<FlagsMeta, ()>());
    out.insert("add_label", tool_envelope::<LabelsMeta, ()>());
    out.insert("remove_label", tool_envelope::<LabelsMeta, ()>());
    out.insert("move_message", tool_envelope::<MoveMessageMeta, ()>());
    out.insert("create_draft", tool_envelope::<CreateDraftMeta, ()>());
    out.insert("send_email", tool_envelope::<SendEmailMeta, ()>());
    out.insert("delete_message", tool_envelope::<DeleteMessageMeta, ()>());
    out.insert("expunge", tool_envelope::<ExpungeMeta, ()>());
    out.insert("create_folder", tool_envelope::<CreateFolderMeta, ()>());
    out.insert("rename_folder", tool_envelope::<RenameFolderMeta, ()>());
    out.insert("delete_folder", tool_envelope::<DeleteFolderMeta, ()>());

    // meta + untrusted tools
    out.insert(
        "search",
        tool_envelope::<SearchMeta, SearchUntrusted>(),
    );
    out.insert(
        "fetch_message",
        tool_envelope::<FetchMessageMeta, FetchMessageUntrusted>(),
    );
    out.insert(
        "list_attachments",
        tool_envelope::<ListAttachmentsMeta, ListAttachmentsUntrusted>(),
    );
    out.insert(
        "download_attachment",
        tool_envelope::<DownloadAttachmentMeta, DownloadAttachmentUntrusted>(),
    );

    out
}

/// Produce the JSON Schema for a tool's full response envelope by
/// deriving it from `ToolResponse<M, U>`. Delegates to
/// `rimap_server::mcp::response::envelope_schema`, the single source
/// of truth shared with `tool_catalog::output_schema`, so fixtures and
/// the published `outputSchema` are byte-identical.
fn tool_envelope<M, U>() -> Value
where
    M: schemars::JsonSchema + serde::Serialize,
    U: schemars::JsonSchema + serde::Serialize,
{
    use rimap_server::mcp::response::{envelope_schema, ToolResponse};
    Value::Object(envelope_schema::<ToolResponse<M, U>>())
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
#[expect(clippy::expect_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn dump_emits_one_key_per_in_scope_tool() {
        let mut buf = Vec::new();
        dump_tool_schemas(&mut buf).unwrap();
        let parsed: serde_json::Map<String, Value> = serde_json::from_slice(&buf).unwrap();

        for name in [
            "list_folders",
            "list_accounts",
            "use_account",
            "list_labels",
            "mark_read",
            "mark_unread",
            "flag",
            "unflag",
            "add_label",
            "remove_label",
            "move_message",
            "create_draft",
            "send_email",
            "delete_message",
            "expunge",
            "create_folder",
            "rename_folder",
            "delete_folder",
            "search",
            "fetch_message",
            "list_attachments",
            "download_attachment",
        ] {
            assert!(parsed.contains_key(name), "missing schema for {name}");
            let entry = &parsed[name];
            assert_eq!(entry["type"], "object");
            assert!(
                entry["properties"]["meta"].is_object(),
                "{name}.meta must be a JSON Schema object"
            );
        }

        assert_eq!(
            parsed.len(),
            22,
            "expected exactly 22 tool schemas, found {}",
            parsed.len()
        );
    }

    #[test]
    fn meta_and_untrusted_tools_include_untrusted_key() {
        let mut buf = Vec::new();
        dump_tool_schemas(&mut buf).unwrap();
        let parsed: serde_json::Map<String, Value> = serde_json::from_slice(&buf).unwrap();
        for name in [
            "search",
            "fetch_message",
            "list_attachments",
            "download_attachment",
        ] {
            assert!(
                parsed[name]["properties"]["untrusted"].is_object(),
                "{name} must declare an untrusted schema"
            );
        }
    }

    #[test]
    fn dump_covers_every_catalog_tool() {
        use rimap_core::tool::ToolName;
        let mut buf = Vec::new();
        dump_tool_schemas(&mut buf).unwrap();
        let parsed: serde_json::Map<String, Value> = serde_json::from_slice(&buf).unwrap();

        for tn in ToolName::all() {
            // Sub-capabilities share a wire name with their parent; they are
            // not separately dumped.
            if matches!(tn, ToolName::SearchAdvanced | ToolName::FetchMessageHtml) {
                continue;
            }
            assert!(
                parsed.contains_key(tn.as_str()),
                "dump_tool_schemas must emit a schema for {}",
                tn.as_str(),
            );
        }
    }

    #[test]
    fn search_schema_hoists_defs_to_envelope_root() {
        let mut buf = Vec::new();
        dump_tool_schemas(&mut buf).unwrap();
        let parsed: serde_json::Map<String, Value> = serde_json::from_slice(&buf).unwrap();

        let search = &parsed["search"];
        assert!(
            search.get("$defs").is_some(),
            "search schema must hoist nested $defs to envelope root: {search}"
        );
        let defs = search["$defs"].as_object().expect("$defs is an object");
        assert!(
            defs.contains_key("SearchResultEntry"),
            "envelope $defs must include SearchResultEntry: {defs:?}"
        );

        // No nested $defs anywhere under properties.
        let props = search["properties"].as_object().expect("properties");
        for (name, sub) in props {
            assert!(
                sub.get("$defs").is_none(),
                "tool subschema {name} must not carry its own $defs after hoist: {sub}"
            );
        }
    }
}
