//! `dump-tool-doc` test-support CLI subcommand. Emits, one line-delimited
//! JSON object per advertised tool, the data the `docs/tools.md`
//! generator needs (#413): the published `title`, `description`, and
//! input/output schemas from [`TOOL_DEFS`], plus the minimum base posture
//! derived from `rimap-core`'s posture matrix (which is not present in the
//! tool definition itself). Rendered to Markdown by
//! `scripts/gen-tools-doc.py`; wired up via `just gen-tools-doc`.
//!
//! Kept separate from `dump-tool-catalog` (consumed by the Node
//! conformance harness, which validates each line as an SDK `Tool`): this
//! output is a doc-oriented superset and is not a wire contract.

use std::io::Write;

use crate::mcp::TOOL_DEFS;
use rimap_core::posture::Posture;
use rimap_core::tool::ToolName;

/// The least-capable base posture that allows `tool`, or `None` when no
/// posture allows it. `export_messages` is deny-all at every posture and
/// is reachable only through an explicit `[security.tools]` override, so
/// it has no minimum posture.
fn min_posture(tool: ToolName) -> Option<Posture> {
    [
        Posture::Readonly,
        Posture::DraftSafe,
        Posture::Full,
        Posture::Destructive,
    ]
    .into_iter()
    .find(|&p| rimap_core::base_allows(p, tool))
}

/// Emit the per-tool documentation records as line-delimited JSON to
/// `writer`. Iteration order follows `ToolName::all()` so the output —
/// and the generated `docs/tools.md` — is stable across runs.
///
/// # Errors
///
/// Returns the underlying I/O error if the writer fails or the serializer
/// cannot encode an entry. The catalog is built from `Tool::new`, which
/// always produces a JSON-serializable object.
pub fn dump_tool_doc<W: Write>(writer: &mut W) -> std::io::Result<()> {
    for tn in ToolName::all() {
        let Some(def) = TOOL_DEFS.get(&tn) else {
            continue;
        };
        let entry = serde_json::json!({
            "name": def.name,
            "title": def.title,
            "description": def.description,
            "min_posture": min_posture(tn).map(Posture::as_str),
            "input_schema": &*def.input_schema,
            "output_schema": def.output_schema.as_deref(),
        });
        serde_json::to_writer(&mut *writer, &entry)?;
        writer.write_all(b"\n")?;
    }
    writer.flush()
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "tests")]
mod tests {
    use rimap_core::tool::ToolName;

    use super::{dump_tool_doc, min_posture};

    #[test]
    fn min_posture_reflects_the_matrix() {
        use rimap_core::posture::Posture;
        // A representative tool at each rung, plus the deny-all export tool.
        assert_eq!(min_posture(ToolName::ListFolders), Some(Posture::Readonly));
        assert_eq!(min_posture(ToolName::MarkRead), Some(Posture::DraftSafe));
        assert_eq!(min_posture(ToolName::SendEmail), Some(Posture::Full));
        assert_eq!(min_posture(ToolName::Expunge), Some(Posture::Destructive));
        assert_eq!(
            min_posture(ToolName::ExportMessages),
            None,
            "export_messages is deny-all; override-only",
        );
    }

    #[test]
    fn dump_emits_one_json_line_per_advertised_tool() {
        let mut buf: Vec<u8> = Vec::new();
        dump_tool_doc(&mut buf).expect("dump succeeds");
        let text = String::from_utf8(buf).expect("utf8");
        let lines: Vec<&str> = text.lines().collect();

        // Advertised tools = all ToolName variants minus the
        // sub-capabilities that share a parent's wire entry.
        let expected = ToolName::all()
            .into_iter()
            .filter(|tn| {
                !matches!(
                    tn,
                    ToolName::SearchAdvanced
                        | ToolName::FetchMessageHtml
                        | ToolName::CreateDraftHtml
                )
            })
            .count();
        assert_eq!(lines.len(), expected, "one record per advertised tool");

        // Each line is a JSON object carrying the doc fields.
        for line in lines {
            let v: serde_json::Value = serde_json::from_str(line).expect("valid JSON line");
            assert!(v["name"].is_string(), "record has a name: {line}");
            assert!(
                v["input_schema"].is_object(),
                "record has input_schema: {line}"
            );
            assert!(
                v["output_schema"].is_object(),
                "record has output_schema: {line}"
            );
            // min_posture is a string for every tool except the deny-all
            // export tool, where it is null.
            let mp = &v["min_posture"];
            assert!(
                mp.is_string() || mp.is_null(),
                "min_posture is a string or null: {line}",
            );
        }
    }
}
