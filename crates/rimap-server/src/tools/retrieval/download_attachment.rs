//! `download_attachment` tool handler.

use std::sync::Arc;

use rimap_imap::types::{BodyStructure, FetchSpec, Uid};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::boot::registry::AccountState;
use crate::mcp::response::ToolResponse;
use crate::tools::retrieval::part_walker::walk_body_structure;
use crate::tools::retrieval::sandbox;

/// Input for the `download_attachment` tool.
///
/// # Shape
///
/// This tool intentionally takes a single scalar `uid` (non-zero) rather than a
/// batch. The asymmetry with batch-capable tools (`flag`, `add_label`,
/// `move_message`) is deliberate: batch shapes (`uid` XOR `uids`) are
/// reserved for commutative, idempotent mutations where per-UID ordering
/// does not matter and results fan out uniformly. Read-side and
/// destructive single-target tools keep a scalar `uid` so the response
/// schema and error semantics stay unambiguous.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct DownloadAttachmentInput {
    /// IMAP folder containing the message.
    pub folder: String,
    /// UID of the message.
    #[serde(deserialize_with = "crate::tools::lenient_int::deserialize_nonzero_u32")]
    #[schemars(schema_with = "crate::tools::lenient_int::schema_nonzero_u32")]
    pub uid: core::num::NonZeroU32,
    /// MIME part ID of the attachment (e.g. "2", "1.2").
    pub part_id: String,
    /// Optional destination directory. Must be within the
    /// configured download root.
    pub dest_dir: Option<String>,
}

/// Trusted metadata for a `download_attachment` response.
#[derive(Debug, Serialize)]
#[cfg_attr(feature = "test-support", derive(schemars::JsonSchema))]
pub struct DownloadAttachmentMeta {
    /// IMAP folder the message was fetched from.
    pub folder: String,
    /// UID of the parent message.
    pub uid: u32,
    /// IMAP part ID that was extracted.
    pub part_id: String,
    /// Absolute path of the written attachment inside the sandbox.
    pub path: String,
    /// Attachment body size in bytes (post-transfer-decoding).
    pub size_bytes: usize,
    /// SHA-256 of the decoded bytes, hex-encoded.
    pub sha256: String,
    /// `Content-Type` declared by the MIME part (`type/subtype`).
    pub mime_declared: String,
    /// Magic-byte-sniffed MIME type, if any signature matched.
    pub mime_sniffed: Option<String>,
}

/// Untrusted payload for a `download_attachment` response.
#[derive(Debug, Serialize)]
#[cfg_attr(feature = "test-support", derive(schemars::JsonSchema))]
pub struct DownloadAttachmentUntrusted {
    /// Original filename from `Content-Disposition` / `Content-Type`
    /// name parameter (sanitized).
    pub filename_original: Option<String>,
}

/// Execute the `download_attachment` tool.
///
/// Fetches the full message, walks its MIME tree via
/// `rimap_content::walk_attachment_parts` (behind the shared parse
/// semaphore), extracts the part matching `part_id`, and writes it
/// to the sandbox directory.
///
/// # Errors
///
/// - `RimapError::Authz { code: InvalidInput, ... }` if the resolved
///   `dest_dir` cannot be canonicalized or escapes the configured
///   download sandbox.
/// - `RimapError::Authz { code: NotFound, ... }` if the `part_id` is
///   not present in the message.
/// - Propagates `RimapError::Imap { ... }` from SELECT / UID FETCH.
/// - `RimapError::Authz { code: InvalidInput, ... }` for malformed MIME
///   bodies and `RimapError::Authz { code: AttachmentTooLarge, ... }`
///   when a content-pipeline cap (MIME depth/parts, header count, body
///   size) is exceeded during parse.
/// - `RimapError::Internal` for unrecoverable filesystem or hashing
///   failures while writing the attachment bytes.
pub async fn handle(
    account: &AccountState,
    input: DownloadAttachmentInput,
) -> Result<ToolResponse<DownloadAttachmentMeta, DownloadAttachmentUntrusted>, rimap_core::RimapError>
{
    crate::tools::validation::validate_folder_input("folder", &input.folder)?;

    let uid = Uid::from(input.uid);

    if input.part_id.is_empty() {
        return Err(rimap_core::RimapError::invalid_input(
            "part_id must not be empty",
        ));
    }

    let dest =
        sandbox::resolve_dest_dir_async(input.dest_dir, Arc::clone(&account.download_dir)).await?;

    let raw = account.imap.fetch_body(&input.folder, uid).await?;

    let parts = crate::mcp::content::walk_attachment_parts_async(raw).await?;

    let part = parts
        .into_iter()
        .find(|p| p.part_id == input.part_id)
        .ok_or_else(|| rimap_core::RimapError::Authz {
            code: rimap_core::error::ErrorCode::NotFound,
            message: format!("part_id {} not found in message", input.part_id),
        })?;

    let original_filename = part.filename;
    let declared_type = part.content_type;
    let part_body = part.body;

    let safe_filename = original_filename.as_deref().unwrap_or("attachment");

    let size = part_body.len();
    let sha256 = sandbox::sha256_hex(&part_body);
    let mime_sniffed = sandbox::sniff_mime(&part_body);
    let path = sandbox::write_attachment_async(dest, safe_filename.to_string(), part_body).await?;

    let path_str = path.to_string_lossy().to_string();

    let mut security_warnings = Vec::new();

    // Cross-validate: fetch BODYSTRUCTURE and compare its declared
    // MIME type against what mail_parser reports. Best-effort — if
    // the fetch or lookup fails we skip validation silently.
    let spec = FetchSpec {
        bodystructure: true,
        ..FetchSpec::default()
    };
    if let Ok((msgs, _uid_validity)) = account.imap.fetch(&input.folder, &[uid], spec, None).await
        && let Some(bs) = msgs.into_iter().next().and_then(|m| m.bodystructure)
        && let Some(bs_type) = lookup_bodystructure_type(&bs, &input.part_id)
    {
        security_warnings.extend(cross_validate_mime_type(&bs_type, &declared_type));
    }

    // Compare declared MIME type against magic-byte detection.
    security_warnings.extend(check_sniff_mismatch(
        &declared_type,
        mime_sniffed.as_deref(),
    ));

    Ok(ToolResponse::meta_only(DownloadAttachmentMeta {
        folder: input.folder,
        uid: input.uid.get(),
        part_id: input.part_id,
        path: path_str,
        size_bytes: size,
        sha256,
        mime_declared: declared_type,
        mime_sniffed,
    })
    .with_untrusted(DownloadAttachmentUntrusted {
        filename_original: original_filename,
    })
    .with_warnings(security_warnings))
}

/// Compare BODYSTRUCTURE-declared MIME type against `mail_parser`'s type.
///
/// Returns a security warning if they disagree (case-insensitive).
fn cross_validate_mime_type(
    bodystructure_type: &str,
    parser_type: &str,
) -> Vec<rimap_content::SecurityWarning> {
    if bodystructure_type.eq_ignore_ascii_case(parser_type) {
        return Vec::new();
    }
    vec![rimap_content::SecurityWarning::new(
        rimap_content::WarningCode::ParseBodystructureTypeMismatch,
        Some(format!(
            "bodystructure={bodystructure_type},parser={parser_type}"
        )),
        Some("download_attachment:bodystructure_vs_parser".into()),
    )]
}

/// Compare declared MIME type against magic-byte-sniffed type.
///
/// Returns a security warning when they disagree. Returns nothing
/// when sniffing produced no result (unknown magic bytes).
fn check_sniff_mismatch(
    declared: &str,
    sniffed: Option<&str>,
) -> Vec<rimap_content::SecurityWarning> {
    let Some(sniffed) = sniffed else {
        return Vec::new();
    };
    if declared.eq_ignore_ascii_case(sniffed) {
        return Vec::new();
    }
    vec![rimap_content::SecurityWarning::new(
        rimap_content::WarningCode::ParseMimeTypeMismatch,
        Some(format!("declared={declared},sniffed={sniffed}")),
        Some("download_attachment:sniff".into()),
    )]
}

/// Look up a part's declared MIME type from a `BodyStructure` tree by
/// IMAP-style part ID (e.g. "2", "1.2").
fn lookup_bodystructure_type(bs: &BodyStructure, target_part_id: &str) -> Option<String> {
    let mut found = None;
    walk_body_structure(bs, |part_id: &str, node: &BodyStructure| {
        if found.is_some() || part_id != target_part_id {
            return;
        }
        if let BodyStructure::Single {
            mime_type,
            mime_subtype,
            ..
        } = node
        {
            found = Some(format!(
                "{}/{}",
                mime_type.to_lowercase(),
                mime_subtype.to_lowercase()
            ));
        }
    });
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- cross_validate_mime_type ------------------------------------------

    #[test]
    fn cross_validate_catches_type_mismatch() {
        let warnings = cross_validate_mime_type("image/png", "text/html");
        assert_eq!(warnings.len(), 1);
        assert_eq!(
            warnings[0].code,
            rimap_content::WarningCode::ParseBodystructureTypeMismatch
        );
        assert_eq!(
            warnings[0].detail.as_deref(),
            Some("bodystructure=image/png,parser=text/html")
        );
    }

    #[test]
    fn cross_validate_passes_on_match() {
        let warnings = cross_validate_mime_type("image/png", "image/png");
        assert!(warnings.is_empty());
    }

    #[test]
    fn cross_validate_case_insensitive() {
        let warnings = cross_validate_mime_type("IMAGE/PNG", "image/png");
        assert!(warnings.is_empty());
    }

    // -- lookup_bodystructure_type ----------------------------------------

    fn single(mt: &str, sub: &str) -> BodyStructure {
        BodyStructure::Single {
            mime_type: mt.to_string(),
            mime_subtype: sub.to_string(),
            params: Vec::new(),
            encoding: "7bit".to_string(),
            size: 100,
        }
    }

    #[test]
    fn lookup_single_part_message() {
        let bs = single("image", "png");
        let result = lookup_bodystructure_type(&bs, "1");
        assert_eq!(result.as_deref(), Some("image/png"));
    }

    #[test]
    fn lookup_multipart_by_id() {
        let bs = BodyStructure::Multipart {
            subtype: "mixed".to_string(),
            parts: vec![single("text", "plain"), single("application", "pdf")],
        };
        assert_eq!(
            lookup_bodystructure_type(&bs, "2").as_deref(),
            Some("application/pdf")
        );
        assert_eq!(
            lookup_bodystructure_type(&bs, "1").as_deref(),
            Some("text/plain")
        );
    }

    #[test]
    fn lookup_nested_multipart() {
        let inner = BodyStructure::Multipart {
            subtype: "mixed".to_string(),
            parts: vec![single("text", "plain"), single("image", "gif")],
        };
        let bs = BodyStructure::Multipart {
            subtype: "mixed".to_string(),
            parts: vec![inner, single("application", "zip")],
        };
        assert_eq!(
            lookup_bodystructure_type(&bs, "1.2").as_deref(),
            Some("image/gif")
        );
        assert_eq!(
            lookup_bodystructure_type(&bs, "2").as_deref(),
            Some("application/zip")
        );
    }

    #[test]
    fn lookup_missing_part_id_returns_none() {
        let bs = single("text", "plain");
        assert!(lookup_bodystructure_type(&bs, "99").is_none());
    }

    #[test]
    fn lookup_respects_depth_limit() {
        let mut bs = single("application", "pdf");
        for _ in 0..70 {
            bs = BodyStructure::Multipart {
                subtype: "mixed".to_string(),
                parts: vec![bs],
            };
        }
        // The deeply nested part should be unreachable.
        assert!(lookup_bodystructure_type(&bs, "1").is_none());
    }

    // -- check_sniff_mismatch -----------------------------------------------

    #[test]
    fn sniff_mismatch_produces_warning() {
        let warnings = check_sniff_mismatch("text/plain", Some("image/png"));
        assert_eq!(warnings.len(), 1);
        assert_eq!(
            warnings[0].code,
            rimap_content::WarningCode::ParseMimeTypeMismatch
        );
        assert_eq!(
            warnings[0].detail.as_deref(),
            Some("declared=text/plain,sniffed=image/png")
        );
    }

    #[test]
    fn sniff_match_produces_no_warning() {
        let warnings = check_sniff_mismatch("image/png", Some("image/png"));
        assert!(warnings.is_empty());
    }

    #[test]
    fn sniff_none_produces_no_warning() {
        let warnings = check_sniff_mismatch("text/plain", None);
        assert!(warnings.is_empty());
    }

    #[test]
    fn sniff_mismatch_case_insensitive() {
        let warnings = check_sniff_mismatch("IMAGE/PNG", Some("image/png"));
        assert!(warnings.is_empty());
    }
}
