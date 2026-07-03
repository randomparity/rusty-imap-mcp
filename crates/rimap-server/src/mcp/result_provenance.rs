//! Derive the durable [`ResultSummary`] from a tool's successful result for
//! the `tool_end` audit record (#316).
//!
//! Only the write-producing tools (`export_messages`, `download_attachment`)
//! contribute artifact provenance — the path, sha256, byte count, and (for
//! export) the succeeded/failed UID partition — so the *actual* on-disk scope
//! is reconstructable post-incident, not just the requested scope in the
//! redacted args. Every other tool records the default summary, preserving its
//! prior `tool_end` shape.

use rimap_audit::record::ResultSummary;
use rimap_core::tool::ToolName;

/// Build the [`ResultSummary`] recorded in `tool_end` from a successful tool
/// result `value` (the serialized `ToolResponse`, with a top-level `meta`).
///
/// The match is exhaustive on purpose: a new tool that writes a durable
/// artifact is a compile error here until its provenance is wired (or it is
/// explicitly added to the no-provenance arm), so provenance can never be
/// silently dropped for a future tool.
pub(super) fn result_provenance(tool: ToolName, value: &serde_json::Value) -> ResultSummary {
    match tool {
        ToolName::ExportMessages => export_provenance(value),
        ToolName::DownloadAttachment => download_provenance(value),
        ToolName::ListFolders
        | ToolName::Search
        | ToolName::SearchAdvanced
        | ToolName::FetchMessage
        | ToolName::FetchMessageHtml
        | ToolName::ListAttachments
        | ToolName::MarkRead
        | ToolName::MarkUnread
        | ToolName::Flag
        | ToolName::Unflag
        | ToolName::AddLabel
        | ToolName::RemoveLabel
        | ToolName::ListLabels
        | ToolName::MoveMessage
        | ToolName::CreateDraft
        | ToolName::SendEmail
        | ToolName::Forward
        | ToolName::DeleteMessage
        | ToolName::Expunge
        | ToolName::CreateFolder
        | ToolName::RenameFolder
        | ToolName::DeleteFolder
        | ToolName::UseAccount
        | ToolName::ListAccounts => ResultSummary::default(),
    }
}

/// `export_messages`: a complete export reports `path`, a partial reports
/// `partial_path`, and a zero-success partial reports neither but still
/// records the failed UID partition.
///
/// The field names below are the contract with `ExportMessagesMeta`; the
/// `tests` module serializes a real `ExportMessagesMeta` so a rename here (or
/// there) fails an assertion. Keep them in sync.
fn export_provenance(value: &serde_json::Value) -> ResultSummary {
    let Some(meta) = value.get("meta") else {
        return ResultSummary::default();
    };
    ResultSummary {
        artifact_path: string_field(meta, "path").or_else(|| string_field(meta, "partial_path")),
        artifact_sha256: string_field(meta, "sha256"),
        artifact_bytes: meta.get("total_bytes").and_then(serde_json::Value::as_u64),
        uids_exported: uid_list(meta, "succeeded"),
        uids_failed: uid_list(meta, "failed"),
        ..ResultSummary::default()
    }
}

/// `download_attachment`: always writes exactly one artifact on success.
///
/// Field names are the contract with `DownloadAttachmentMeta`, pinned by the
/// `tests` module (which serializes a real `DownloadAttachmentMeta`).
fn download_provenance(value: &serde_json::Value) -> ResultSummary {
    let Some(meta) = value.get("meta") else {
        return ResultSummary::default();
    };
    ResultSummary {
        artifact_path: string_field(meta, "path"),
        artifact_sha256: string_field(meta, "sha256"),
        artifact_bytes: meta.get("size_bytes").and_then(serde_json::Value::as_u64),
        ..ResultSummary::default()
    }
}

fn string_field(meta: &serde_json::Value, key: &str) -> Option<String> {
    meta.get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
}

/// Extract each object's `uid` (as `u32`) from the `key` array of `meta`.
fn uid_list(meta: &serde_json::Value, key: &str) -> Vec<u32> {
    let Some(arr) = meta.get(key).and_then(serde_json::Value::as_array) else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(arr.len());
    for entry in arr {
        if let Some(uid) = entry.get("uid").and_then(serde_json::Value::as_u64)
            && let Ok(uid) = u32::try_from(uid)
        {
            out.push(uid);
        }
    }
    out
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "tests")]
mod tests {
    use super::result_provenance;
    use crate::mcp::response::ToolResponse;
    use crate::tools::retrieval::download_attachment::DownloadAttachmentMeta;
    use crate::tools::retrieval::export_messages::{
        ExportFailReason, ExportMessagesMeta, ExportedUid, FailedUid,
    };
    use rimap_core::tool::ToolName;

    /// Serialize a real meta through the response envelope, exactly as dispatch
    /// does, so a meta field rename breaks this test at compile time.
    fn value_of<M: serde::Serialize>(meta: M) -> serde_json::Value {
        serde_json::to_value(ToolResponse::<M, ()>::meta_only(meta)).expect("serialize meta")
    }

    #[test]
    fn export_complete_records_path_sha_bytes_and_partition() {
        let meta = ExportMessagesMeta {
            folder: "INBOX".to_string(),
            complete: true,
            path: Some("/srv/dl/messages-abc.mbox".to_string()),
            partial_path: None,
            sha256: "ab".repeat(32),
            message_count: 2,
            total_bytes: 4096,
            uid_validity: 42,
            succeeded: vec![
                ExportedUid {
                    uid: 7,
                    size_bytes: 100,
                },
                ExportedUid {
                    uid: 9,
                    size_bytes: 200,
                },
            ],
            failed: vec![],
        };
        let summary = result_provenance(ToolName::ExportMessages, &value_of(meta));
        assert_eq!(
            summary.artifact_path.as_deref(),
            Some("/srv/dl/messages-abc.mbox")
        );
        assert_eq!(summary.artifact_sha256, Some("ab".repeat(32)));
        assert_eq!(summary.artifact_bytes, Some(4096));
        assert_eq!(summary.uids_exported, vec![7, 9]);
        assert!(summary.uids_failed.is_empty());
    }

    #[test]
    fn export_partial_uses_partial_path_and_records_failed_partition() {
        let meta = ExportMessagesMeta {
            folder: "INBOX".to_string(),
            complete: false,
            path: None,
            partial_path: Some("/srv/dl/messages-abc.partial.mbox".to_string()),
            sha256: "cd".repeat(32),
            message_count: 1,
            total_bytes: 50,
            uid_validity: 42,
            succeeded: vec![ExportedUid {
                uid: 7,
                size_bytes: 50,
            }],
            failed: vec![FailedUid {
                uid: 8,
                reason: ExportFailReason::NotFound,
            }],
        };
        let summary = result_provenance(ToolName::ExportMessages, &value_of(meta));
        assert_eq!(
            summary.artifact_path.as_deref(),
            Some("/srv/dl/messages-abc.partial.mbox")
        );
        assert_eq!(summary.uids_exported, vec![7]);
        assert_eq!(summary.uids_failed, vec![8]);
    }

    #[test]
    fn export_zero_success_records_failed_partition_without_path() {
        let meta = ExportMessagesMeta {
            folder: "INBOX".to_string(),
            complete: false,
            path: None,
            partial_path: None,
            sha256: "ef".repeat(32),
            message_count: 0,
            total_bytes: 0,
            uid_validity: 42,
            succeeded: vec![],
            failed: vec![
                FailedUid {
                    uid: 10,
                    reason: ExportFailReason::NotFound,
                },
                FailedUid {
                    uid: 20,
                    reason: ExportFailReason::Oversize,
                },
            ],
        };
        let summary = result_provenance(ToolName::ExportMessages, &value_of(meta));
        assert!(summary.artifact_path.is_none());
        assert!(summary.uids_exported.is_empty());
        assert_eq!(summary.uids_failed, vec![10, 20]);
    }

    #[test]
    fn download_records_path_sha_and_size() {
        let meta = DownloadAttachmentMeta {
            folder: "INBOX".to_string(),
            uid: 5,
            part_id: "2".to_string(),
            path: "/srv/dl/doc.pdf".to_string(),
            size_bytes: 1234,
            sha256: "11".repeat(32),
            mime_declared: "application/pdf".to_string(),
            mime_sniffed: Some("application/pdf".to_string()),
        };
        let summary = result_provenance(ToolName::DownloadAttachment, &value_of(meta));
        assert_eq!(summary.artifact_path.as_deref(), Some("/srv/dl/doc.pdf"));
        assert_eq!(summary.artifact_sha256, Some("11".repeat(32)));
        assert_eq!(summary.artifact_bytes, Some(1234));
        assert!(summary.uids_exported.is_empty());
    }

    #[test]
    fn non_artifact_tool_records_default_summary() {
        // A search result carries no artifact provenance.
        let value = serde_json::json!({ "meta": { "results": [] } });
        let summary = result_provenance(ToolName::Search, &value);
        assert_eq!(summary, rimap_audit::record::ResultSummary::default());
    }
}
