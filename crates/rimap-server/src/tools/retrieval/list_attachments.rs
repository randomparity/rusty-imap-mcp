//! `list_attachments` tool handler.

use rimap_imap::types::{BodyStructure, FetchSpec, Uid};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::boot::registry::AccountState;
use crate::mcp::response::ToolResponse;
use crate::tools::retrieval::part_walker::walk_body_structure;

// Scalar-uid rationale: this tool intentionally has no batch shape, see
// the `Scalar vs batch uid shapes` section of `crate::tools` module docs (#405).
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListAttachmentsInput {
    /// IMAP folder containing the message.
    pub folder: String,
    /// UID of the message.
    #[serde(deserialize_with = "crate::tools::lenient_int::deserialize_nonzero_u32")]
    #[schemars(schema_with = "crate::tools::lenient_int::schema_nonzero_u32")]
    pub uid: core::num::NonZeroU32,
}

/// Metadata for a single attachment discovered in the MIME tree.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct AttachmentInfo {
    /// IMAP part identifier (e.g. `"2"`, `"1.2"`).
    pub part_id: String,
    /// Full MIME type (e.g. `"application/pdf"`).
    pub mime_type: String,
    /// Size of the part in bytes as reported by `BODYSTRUCTURE`.
    pub size_bytes: u32,
    /// Filename from the MIME content-type `name` (or `filename`)
    /// parameter, RFC 2231 / RFC 2047 decoded and sanitized.
    pub filename: Option<String>,
}

/// Trusted metadata for a `list_attachments` response.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct ListAttachmentsMeta {
    /// IMAP folder the message was fetched from.
    pub folder: String,
    /// UID of the inspected message.
    pub uid: u32,
    /// Number of attachment parts found.
    pub attachment_count: usize,
}

/// Untrusted payload for a `list_attachments` response.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct ListAttachmentsUntrusted {
    /// Attachment parts found in the MIME tree.
    pub attachments: Vec<AttachmentInfo>,
}

/// Execute the `list_attachments` tool.
///
/// Fetches `BODYSTRUCTURE` for the given message and walks the MIME
/// tree to find non-text attachment parts.
///
/// # Errors
///
/// - `RimapError::Authz { code: NotFound, ... }` if the UID is absent
///   from `folder`.
/// - `RimapError::Internal` if the server accepted the FETCH but did
///   not return a `BODYSTRUCTURE`.
/// - Propagates `RimapError::Imap { ... }` from SELECT / UID FETCH.
pub async fn handle(
    account: &AccountState,
    input: ListAttachmentsInput,
) -> Result<ToolResponse<ListAttachmentsMeta, ListAttachmentsUntrusted>, rimap_core::RimapError> {
    crate::tools::validation::validate_folder_input("folder", &input.folder)?;

    let uid = Uid::from(input.uid);

    let mut spec = FetchSpec::default();
    spec.bodystructure = true;
    let (msg, _uid_validity) =
        crate::tools::fetch_by_uid::fetch_single_by_uid(account, &input.folder, uid, spec, None)
            .await?;

    let bodystructure = msg.bodystructure.ok_or_else(|| {
        rimap_core::RimapError::Internal("server did not return BODYSTRUCTURE".into())
    })?;

    let mut attachments = Vec::new();
    let mut warnings = Vec::new();
    collect_attachments(&bodystructure, &mut attachments, &mut warnings);

    Ok(ToolResponse::meta_only(ListAttachmentsMeta {
        folder: input.folder,
        uid: input.uid.get(),
        attachment_count: attachments.len(),
    })
    .with_untrusted(ListAttachmentsUntrusted { attachments })
    .with_warnings(warnings))
}

/// Walk the `BodyStructure` tree and collect non-inline-text parts.
fn collect_attachments(
    bs: &BodyStructure,
    out: &mut Vec<AttachmentInfo>,
    warnings: &mut Vec<rimap_content::SecurityWarning>,
) {
    walk_body_structure(bs, |part_id: &str, node: &BodyStructure| {
        if let BodyStructure::Single {
            mime_type,
            mime_subtype,
            params,
            disposition_params,
            size,
            ..
        } = node
        {
            if is_inline_text(mime_type, mime_subtype) {
                return;
            }
            let filename = rimap_content::attachment_filename_from_params(
                params,
                disposition_params,
                out.len(),
                warnings,
            );
            let full_type = format!(
                "{}/{}",
                mime_type.to_lowercase(),
                mime_subtype.to_lowercase()
            );
            out.push(AttachmentInfo {
                part_id: part_id.to_string(),
                mime_type: full_type,
                size_bytes: *size,
                filename,
            });
        }
    });
}

/// Returns `true` for `text/plain` and `text/html`, which are
/// typically inline body parts rather than attachments.
fn is_inline_text(mime_type: &str, mime_subtype: &str) -> bool {
    mime_type.eq_ignore_ascii_case("text")
        && (mime_subtype.eq_ignore_ascii_case("plain") || mime_subtype.eq_ignore_ascii_case("html"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn single(mime_type: &str, sub: &str, size: u32) -> BodyStructure {
        BodyStructure::Single {
            mime_type: mime_type.to_string(),
            mime_subtype: sub.to_string(),
            params: Vec::new(),
            disposition_params: Vec::new(),
            encoding: "7bit".to_string(),
            size,
        }
    }

    fn single_with_name(mime_type: &str, sub: &str, size: u32, name: &str) -> BodyStructure {
        BodyStructure::Single {
            mime_type: mime_type.to_string(),
            mime_subtype: sub.to_string(),
            params: vec![("name".to_string(), name.to_string())],
            disposition_params: Vec::new(),
            encoding: "base64".to_string(),
            size,
        }
    }

    #[test]
    fn single_text_plain_is_not_attachment() {
        let bs = single("text", "plain", 100);
        let mut out = Vec::new();
        collect_attachments(&bs, &mut out, &mut Vec::new());
        assert!(out.is_empty());
    }

    #[test]
    fn single_text_html_is_not_attachment() {
        let bs = single("text", "html", 200);
        let mut out = Vec::new();
        collect_attachments(&bs, &mut out, &mut Vec::new());
        assert!(out.is_empty());
    }

    #[test]
    fn single_image_is_attachment() {
        let bs = single_with_name("image", "png", 5000, "photo.png");
        let mut out = Vec::new();
        collect_attachments(&bs, &mut out, &mut Vec::new());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].part_id, "1");
        assert_eq!(out[0].mime_type, "image/png");
        assert_eq!(out[0].size_bytes, 5000);
        assert_eq!(out[0].filename.as_deref(), Some("photo.png"));
    }

    #[test]
    fn multipart_mixed_extracts_attachments() {
        let bs = BodyStructure::Multipart {
            subtype: "mixed".to_string(),
            parts: vec![
                single("text", "plain", 100),
                single_with_name("application", "pdf", 20000, "report.pdf"),
                single_with_name("image", "jpeg", 8000, "cat.jpg"),
            ],
        };
        let mut out = Vec::new();
        collect_attachments(&bs, &mut out, &mut Vec::new());
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].part_id, "2");
        assert_eq!(out[0].mime_type, "application/pdf");
        assert_eq!(out[1].part_id, "3");
        assert_eq!(out[1].mime_type, "image/jpeg");
    }

    #[test]
    fn nested_multipart_numbering() {
        let inner = BodyStructure::Multipart {
            subtype: "mixed".to_string(),
            parts: vec![
                single("text", "plain", 50),
                single_with_name("image", "gif", 1000, "anim.gif"),
            ],
        };
        let bs = BodyStructure::Multipart {
            subtype: "mixed".to_string(),
            parts: vec![
                inner,
                single_with_name("application", "zip", 50000, "archive.zip"),
            ],
        };
        let mut out = Vec::new();
        collect_attachments(&bs, &mut out, &mut Vec::new());
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].part_id, "1.2");
        assert_eq!(out[0].filename.as_deref(), Some("anim.gif"));
        assert_eq!(out[1].part_id, "2");
        assert_eq!(out[1].filename.as_deref(), Some("archive.zip"));
    }

    #[test]
    fn is_inline_text_case_insensitive() {
        assert!(is_inline_text("TEXT", "PLAIN"));
        assert!(is_inline_text("Text", "Html"));
        assert!(!is_inline_text("text", "csv"));
        assert!(!is_inline_text("image", "plain"));
    }

    fn single_with_params(params: &[(&str, &str)]) -> BodyStructure {
        BodyStructure::Single {
            mime_type: "application".to_string(),
            mime_subtype: "pdf".to_string(),
            params: params
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
            disposition_params: Vec::new(),
            encoding: "base64".to_string(),
            size: 10,
        }
    }

    #[test]
    fn rfc2231_name_from_bodystructure_is_decoded() {
        // Dovecot reports RFC 2231 sections verbatim in BODYSTRUCTURE.
        let bs = single_with_params(&[
            ("name*0*", "UTF-8''%C3%9Cbersicht%20der"),
            ("name*1*", "%20Fassung.pdf"),
        ]);
        let mut out = Vec::new();
        collect_attachments(&bs, &mut out, &mut Vec::new());
        assert_eq!(
            out[0].filename.as_deref(),
            Some("Übersicht der Fassung.pdf")
        );
    }

    #[test]
    fn filename_warnings_are_tagged_with_the_attachment_index() {
        let bs = BodyStructure::Multipart {
            subtype: "mixed".to_string(),
            parts: vec![
                single_with_name("image", "png", 10, "ok.png"),
                single_with_params(&[("name", "=?utf-8?Q?invoice=E2=80=AEfdp.exe?=")]),
            ],
        };
        let mut out = Vec::new();
        let mut warnings = Vec::new();
        collect_attachments(&bs, &mut out, &mut warnings);
        assert!(
            out[1]
                .filename
                .as_deref()
                .is_some_and(|name| !name.contains('\u{202e}')),
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.location.as_deref() == Some("attachment[1]:filename")),
            "{warnings:?}",
        );
    }

    #[test]
    fn deeply_nested_mime_respects_depth_limit() {
        let mut bs = single("application", "pdf", 100);
        for _ in 0..70 {
            bs = BodyStructure::Multipart {
                subtype: "mixed".to_string(),
                parts: vec![bs],
            };
        }
        let mut out = Vec::new();
        collect_attachments(&bs, &mut out, &mut Vec::new());
        assert!(out.is_empty());
    }
}
