//! `dump-tool-catalog` test-support CLI subcommand. Emits the static
//! MCP tool catalog as line-delimited JSON to stdout. Used by the
//! Phase 2 Node conformance harness (issue #264) to validate every
//! tool's `inputSchema` through the SDK's Zod Tool definition
//! without standing up a configured account or live IMAP server.

use std::io::Write;

use crate::mcp::TOOL_DEFS;
use rimap_core::tool::ToolName;

/// Print each entry of the static `TOOL_DEFS` map as one line of
/// JSON to the given writer. Iteration order follows `ToolName::all()`
/// so the output is stable across runs.
///
/// # Errors
///
/// Returns the underlying I/O error if the writer fails or the
/// serializer cannot encode an entry. The static catalog is built
/// from `Tool::new`, which always produces a JSON-serializable
/// object, so the serializer should not fail in practice.
pub fn dump_tool_catalog<W: Write>(writer: &mut W) -> std::io::Result<()> {
    for tn in ToolName::all() {
        let Some(def) = TOOL_DEFS.get(&tn) else {
            continue;
        };
        serde_json::to_writer(&mut *writer, def)?;
        writer.write_all(b"\n")?;
    }
    writer.flush()
}
