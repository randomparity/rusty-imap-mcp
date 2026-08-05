//! Pins the cross-links from `rimap-audit` into `docs/audit-log.md` to the
//! headings that define their anchors. If the doc is reorganized and a
//! heading is renamed without a coordinated update to the code that points
//! at it, these tests fail.

#![expect(clippy::expect_used, reason = "tests")]
#![expect(clippy::panic, reason = "tests")]

use std::path::PathBuf;

/// Contents of `docs/audit-log.md`.
///
/// `CARGO_MANIFEST_DIR` points at `crates/rimap-audit/`; walk up two levels to
/// reach the workspace root.
fn audit_log_md() -> String {
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root must exist two levels above crate dir")
        .to_path_buf();
    let docs_path = workspace_root.join("docs").join("audit-log.md");

    std::fs::read_to_string(&docs_path).unwrap_or_else(|err| {
        panic!("failed to read {}: {err}", docs_path.display());
    })
}

#[test]
fn audit_log_md_defines_running_multiple_mcp_clients_heading() {
    assert!(
        audit_log_md().contains("\n## Running multiple MCP clients\n"),
        "docs/audit-log.md must define the `## Running multiple MCP clients` \
         heading referenced by AuditError::Locked. Did the heading get renamed?",
    );
}

#[test]
fn audit_log_md_defines_compatibility_contract_heading() {
    // Referenced by `rimap_audit::record`'s module docs and by the failure
    // message of `non_exhaustive_record.rs`, both of which send a reader here
    // to find out what "additive" means for a record on disk (#706). That
    // section is the normative statement; the code only points at it.
    assert!(
        audit_log_md().contains("\n## Compatibility contract\n"),
        "docs/audit-log.md must define the `## Compatibility contract` heading \
         referenced by rimap_audit::record's module docs. Did it get renamed?",
    );
}
