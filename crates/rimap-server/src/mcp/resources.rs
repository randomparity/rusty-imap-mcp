//! Static `rimap://docs/...` MCP resources.
//!
//! The embedded copies under `crates/rimap-server/docs/` ship in the
//! published crate; the repo-root originals are what humans edit. The
//! drift tests here fail `just ci` the moment the two diverge.

use rmcp::model::Resource;

/// URI of the static `rimap://docs/postures` resource.
pub(crate) const POSTURES_DOC_URI: &str = "rimap://docs/postures";

/// URI of the static `rimap://docs/workflows` resource.
pub(crate) const WORKFLOWS_DOC_URI: &str = "rimap://docs/workflows";

/// Content of the `rimap://docs/postures` resource. Literally
/// `docs/postures.md` — the human-facing doc IS the agent-facing doc, so
/// there is nothing to drift.
pub(crate) const POSTURES_DOC: &str = include_str!("../../docs/postures.md");

/// Content of the `rimap://docs/workflows` resource: search → fetch →
/// act, UIDVALIDITY pinning, attachment retrieval, draft lifecycle,
/// `export_messages` opt-in, and a numeric-limits table. The limits
/// table is pinned against the Rust constants it describes by
/// `workflows_doc_limits_match_source_constants` below.
pub(crate) const WORKFLOWS_DOC: &str = include_str!("../../docs/mcp-workflows.md");

/// The static, non-account doc resources always advertised by
/// `list_resources` — present even with zero accounts configured, since
/// they describe the server's semantics rather than any account's state.
pub(crate) fn static_doc_resources() -> Vec<Resource> {
    vec![
        Resource::new(POSTURES_DOC_URI, "postures")
            .with_description(
                "Security posture matrix: the four levels, per-tool gating, \
                 sub-capabilities, and the [security.tools] override mechanism.",
            )
            .with_mime_type("text/markdown"),
        Resource::new(WORKFLOWS_DOC_URI, "workflows")
            .with_description(
                "Agent workflows: search\u{2192}fetch\u{2192}act, UIDVALIDITY \
                 pinning, attachment retrieval, the draft lifecycle, the \
                 export_messages opt-in, and numeric limits.",
            )
            .with_mime_type("text/markdown"),
    ]
}

/// Content for a static doc resource URI, or `None` if `uri` does not
/// name one (the caller then falls through to the per-account lookup).
pub(crate) fn static_doc_content(uri: &str) -> Option<&'static str> {
    match uri {
        POSTURES_DOC_URI => Some(POSTURES_DOC),
        WORKFLOWS_DOC_URI => Some(WORKFLOWS_DOC),
        _ => None,
    }
}

#[cfg(test)]
mod embedded_doc_drift_tests {
    #![expect(clippy::panic, reason = "tests")]
    //! The embedded copies under `docs/` are what ships in the published
    //! crate (the repo-root originals cannot be packaged — cargo refuses
    //! paths outside the package root), but the repo-root files are the
    //! ones humans edit and the generated `docs/tools.md` links. This
    //! guard fails `just ci` the moment the two diverge, so an edit to
    //! the root doc that skips the crate copy cannot ship stale
    //! agent-facing content.

    use super::{POSTURES_DOC, WORKFLOWS_DOC};

    #[test]
    fn embedded_docs_match_repo_root_canonical_copies() {
        for (embedded, canonical) in [
            (POSTURES_DOC, "docs/postures.md"),
            (WORKFLOWS_DOC, "docs/mcp-workflows.md"),
        ] {
            let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join(canonical);
            let source = std::fs::read_to_string(&root)
                .unwrap_or_else(|e| panic!("cannot read {}: {e}", root.display()));
            assert_eq!(
                embedded, source,
                "{canonical} drifted from the crate-local copy at \
                 crates/rimap-server/docs/ — update both or the published \
                 crate ships stale content"
            );
        }
    }
}

#[cfg(test)]
mod static_doc_resource_tests {
    #![expect(clippy::panic, reason = "tests")]

    use super::{
        POSTURES_DOC, POSTURES_DOC_URI, WORKFLOWS_DOC, WORKFLOWS_DOC_URI, static_doc_content,
        static_doc_resources,
    };

    #[test]
    fn static_doc_resources_advertises_both_uris_as_markdown() {
        let resources = static_doc_resources();
        assert_eq!(
            resources.len(),
            2,
            "expected exactly two static doc resources"
        );
        for r in &resources {
            assert_eq!(
                r.mime_type.as_deref(),
                Some("text/markdown"),
                "resource {:?} must advertise text/markdown",
                r.uri,
            );
        }
        let uris: Vec<&str> = resources.iter().map(|r| r.uri.as_str()).collect();
        assert!(uris.contains(&POSTURES_DOC_URI));
        assert!(uris.contains(&WORKFLOWS_DOC_URI));
    }

    #[test]
    fn static_doc_content_resolves_known_uris_and_rejects_unknown() {
        assert_eq!(static_doc_content(POSTURES_DOC_URI), Some(POSTURES_DOC));
        assert_eq!(static_doc_content(WORKFLOWS_DOC_URI), Some(WORKFLOWS_DOC));
        assert_eq!(static_doc_content("rimap://accounts/default"), None);
        assert_eq!(static_doc_content("rimap://docs/nonexistent"), None);
    }

    #[test]
    fn postures_doc_mentions_all_four_postures() {
        for posture in ["readonly", "draft-safe", "full", "destructive"] {
            assert!(
                POSTURES_DOC.contains(posture),
                "postures doc must mention posture {posture:?}",
            );
        }
    }

    /// Extract the leading integer from the last `|`-delimited cell of
    /// the markdown table row whose text contains `row_label`. Panics
    /// (test failure) if no matching row exists or the cell has no
    /// leading digits — either is a doc/test drift bug worth surfacing
    /// loudly rather than silently skipping the check.
    fn workflow_limit_value(row_label: &str) -> u64 {
        let line = WORKFLOWS_DOC
            .lines()
            .find(|l| l.starts_with('|') && l.contains(row_label))
            .unwrap_or_else(|| panic!("workflows doc missing limits row for {row_label:?}"));
        let cell = line
            .rsplit('|')
            .nth(1)
            .unwrap_or_else(|| panic!("malformed table row: {line:?}"))
            .trim();
        let digits: String = cell.chars().take_while(char::is_ascii_digit).collect();
        digits.parse().unwrap_or_else(|e| {
            panic!("row {row_label:?} cell {cell:?} not a leading integer: {e}")
        })
    }

    /// Pins every numeric limit quoted in the `rimap://docs/workflows`
    /// resource against the Rust constant that actually enforces it. A
    /// constant change that isn't reflected in the doc fails this test
    /// instead of silently drifting into stale agent-facing guidance.
    #[test]
    fn workflows_doc_limits_match_source_constants() {
        assert_eq!(
            workflow_limit_value("Batch mutation UIDs"),
            rimap_core::uid_selector::MAX_BATCH_UIDS as u64,
        );
        assert_eq!(
            workflow_limit_value("`search` results per call"),
            crate::tools::retrieval::search::MAX_LIMIT as u64,
        );
        assert_eq!(
            workflow_limit_value("Fetched message body size"),
            rimap_content::parse::MAX_BODY_BYTES as u64,
        );
        assert_eq!(
            workflow_limit_value("`export_messages` UID count"),
            crate::tools::retrieval::export_messages::MAX_EXPORT_UIDS as u64,
        );
        assert_eq!(
            workflow_limit_value("`export_messages` total size"),
            crate::tools::retrieval::export_messages::MAX_EXPORT_TOTAL_BYTES,
        );
        assert_eq!(
            workflow_limit_value("recipients"),
            crate::tools::compose::message_builder::MAX_RECIPIENTS as u64,
        );
    }
}
