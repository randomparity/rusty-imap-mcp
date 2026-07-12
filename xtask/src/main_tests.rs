use std::fs;

use tempfile::tempdir;

use crate::generate_man;

#[test]
fn generates_top_and_production_subcommand_pages() {
    let dir = tempdir().unwrap();
    generate_man(dir.path()).unwrap();

    let top = dir.path().join("rusty-imap-mcp.1");
    let top_body = fs::read_to_string(&top).unwrap();
    assert!(!top_body.is_empty(), "top page empty");
    // roff escapes hyphens (Security\-first), so assert on a hyphen-free slice
    // of the `about` string.
    assert!(
        top_body.contains("MCP server for IMAP email access"),
        "top page missing the CLI 'about' text",
    );

    // Always-present production subcommands (feature-independent — the negative
    // 'no dump-tool page' guarantee lives in the release manpages-job guard, not
    // here, because a --workspace test run may unify rimap-server with
    // test-support ON. See spec finding F1.)
    for page in [
        "rusty-imap-mcp-login.1",
        "rusty-imap-mcp-audit.1",
        "rusty-imap-mcp-migrate-keyring.1",
    ] {
        assert!(dir.path().join(page).is_file(), "missing page {page}");
    }
}
