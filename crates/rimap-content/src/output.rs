//! Output types for the rimap-content pipeline.
//!
//! [`Content`] is the single top-level return type produced by
//! [`crate::parse_message`]. Every field is `#[non_exhaustive]` so that
//! Sprint 4b can add HTML- and look-alike-specific variants without
//! breaking downstream callers.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Top-level parsed message payload.
///
/// Consumers read `meta` for trusted structural information (headers,
/// attachment metadata, mailing-list markers), `untrusted` for
/// sanitized text that may still contain attacker-controlled content,
/// and `security_warnings` for the list of pipeline warnings emitted
/// during parsing.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Content {
    /// Trusted structural metadata extracted from the message.
    pub meta: ContentMeta,
    /// Sanitized text parts. All strings here have passed the unicode
    /// pipeline; any codepoint-class warnings are recorded in
    /// `security_warnings`.
    pub untrusted: Untrusted,
    /// Ordered list of warnings emitted during parsing. Order is
    /// deterministic within a single `parse_message` call but callers
    /// should not rely on cross-version ordering.
    pub security_warnings: Vec<SecurityWarning>,
}

/// Trusted structural metadata extracted from message headers and
/// MIME structure. Every string field has been routed through the
/// unicode pipeline.
#[non_exhaustive]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContentMeta {
    /// Parsed `From:` header, sanitized. `None` if absent.
    pub from: Option<String>,
    /// Parsed `To:` header recipients, sanitized.
    pub to: Vec<String>,
    /// Parsed `Cc:` header recipients, sanitized.
    pub cc: Vec<String>,
    /// Parsed `Reply-To:` header, sanitized. `None` if absent.
    pub reply_to: Option<String>,
    /// Parsed `Subject:` header, sanitized. `None` if absent.
    pub subject: Option<String>,
    /// Parsed `Date:` header as a UTC-normalized `OffsetDateTime`.
    pub date: Option<OffsetDateTime>,
    /// Parsed `Message-ID:` header value (without angle brackets), sanitized.
    pub message_id: Option<String>,
    /// Parsed `In-Reply-To:` header value (without angle brackets), sanitized.
    pub in_reply_to: Option<String>,
    /// Parsed `References:` header values (without angle brackets), sanitized.
    pub references: Vec<String>,
    /// Mailing-list markers if `List-*` headers were present.
    pub mailing_list: Option<MailingListInfo>,
    /// Attachment metadata for every non-inline part.
    pub attachments: Vec<AttachmentMeta>,
    /// Original message size in bytes before any truncation or sanitization.
    pub original_size_bytes: u64,
    /// `true` if the body was truncated because it exceeded
    /// [`crate::parse::MAX_BODY_BYTES`].
    pub body_truncated: bool,
}

/// A single requested header and its sanitized value(s).
///
/// Produced by [`crate::parse_message_with_headers`] for names in the
/// caller's allowlist that are present on the message. Repeated header
/// lines (e.g. multiple `Received:`) collect into `values` in message
/// order. Requested names absent from the message produce no
/// `SelectedHeader`. Every value has passed the Unicode sanitization
/// pipeline, so any codepoint-class finding is recorded in the parent
/// [`Content::security_warnings`].
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectedHeader {
    /// The requested header name, echoed back in the caller's spelling.
    pub name: String,
    /// Sanitized value(s), one per matching header line, in message order.
    pub values: Vec<String>,
}

/// Mailing-list markers extracted from `List-*` headers.
#[non_exhaustive]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MailingListInfo {
    /// Value of `List-ID:` if present.
    pub list_id: Option<String>,
    /// Value of `List-Unsubscribe:` if present.
    pub list_unsubscribe: Option<String>,
    /// Value of `List-Post:` if present.
    pub list_post: Option<String>,
}

/// Metadata for a single attachment part. Body bytes are not retained.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AttachmentMeta {
    /// Decoded filename if available (from `Content-Disposition` or
    /// `Content-Type` name parameter), sanitized.
    pub filename: Option<String>,
    /// Declared content type (e.g. `"image/png"`), sanitized.
    pub content_type: String,
    /// Size of the attachment body in bytes (post-transfer-decoding).
    pub size_bytes: u64,
    /// Value of `Content-ID:` if present (without angle brackets), sanitized.
    pub content_id: Option<String>,
    /// `true` if the disposition was `inline`.
    pub is_inline: bool,
}

/// Sanitized text payload from the message body.
#[non_exhaustive]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Untrusted {
    /// The primary `text/plain` body part, post-unicode-sanitization.
    /// Empty if no text/plain part was found.
    pub body_text: String,
    /// Sanitized HTML view of the message body, when the message
    /// carries a `text/html` part. `None` when no HTML body exists.
    ///
    /// Produced by the `html` module via an allowlist-based ammonia
    /// pipeline with remote content (images, scripts, stylesheets, and
    /// other network-fetching elements) stripped.
    pub body_html: Option<String>,
    /// Other `text/*` parts (e.g. additional alternatives), each
    /// independently sanitized.
    pub alternate_parts: Vec<String>,
}

/// A single warning emitted by the content pipeline.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SecurityWarning {
    /// Classification of the warning.
    pub code: WarningCode,
    /// Optional context string, format varies by `code`. Within a
    /// single server version the format is structured (key=value
    /// pairs), but it may change across versions — do not depend on
    /// its exact shape; use `code` for stable dispatch. `None` when no
    /// additional detail is available.
    pub detail: Option<String>,
    /// Logical location in the message (e.g. `"header:subject"`,
    /// `"body:part[2]"`, `"attachment[0]"`). `None` for crate-wide events.
    pub location: Option<String>,
}

impl SecurityWarning {
    /// Construct a new warning.
    ///
    /// `code` classifies the event. `detail` carries an optional context
    /// string whose format is defined per-variant in the [`WarningCode`]
    /// doc comments — see those docs for the key=value structure each
    /// variant uses. The format is stable within a single crate version
    /// but may change across versions; consumers MUST NOT rely on it for
    /// cross-version compatibility. `location` names the logical site in
    /// the message where the warning was raised.
    #[must_use]
    pub fn new(code: WarningCode, detail: Option<String>, location: Option<String>) -> Self {
        Self {
            code,
            detail,
            location,
        }
    }

    /// Construct a warning with both `detail` and `location` populated.
    ///
    /// This is the common shape for pipeline-emitted warnings: every
    /// call site in the content pipeline supplies both a structured
    /// `detail` string (see [`WarningCode`] docs for the per-variant
    /// key=value format) and a logical `location` naming the site in
    /// the message where the warning was raised.
    #[must_use]
    pub fn at(code: WarningCode, detail: impl Into<String>, location: impl Into<String>) -> Self {
        Self {
            code,
            detail: Some(detail.into()),
            location: Some(location.into()),
        }
    }
}

/// Re-exported so existing `rimap_content::WarningCode` paths keep
/// working. The canonical definition lives in
/// [`rimap_core::warning`] so `rimap-audit` can type its
/// `security_warnings_emitted` field without inverting the crate
/// dependency direction.
pub use rimap_core::warning::{WarningCode, WarningSeverity};
#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests may unwrap on constructed values")]
mod tests {
    use super::*;

    #[test]
    fn content_meta_has_reply_to_field() {
        let meta = ContentMeta {
            reply_to: Some("reply@example.com".to_string()),
            ..ContentMeta::default()
        };
        assert_eq!(meta.reply_to.as_deref(), Some("reply@example.com"));
    }

    #[test]
    fn content_default_meta_is_empty() {
        let meta = ContentMeta::default();
        assert!(meta.from.is_none());
        assert!(meta.to.is_empty());
        assert_eq!(meta.original_size_bytes, 0);
        assert!(!meta.body_truncated);
    }

    #[test]
    fn severity_classifies_known_variants() {
        // Compile-time exhaustiveness is enforced by the non-wildcarded
        // match in severity(). This test pins a few known mappings.
        assert_eq!(
            WarningCode::ParseBodyTruncated.severity(),
            WarningSeverity::Informational
        );
        assert_eq!(
            WarningCode::ParseHeaderSmugglingBlocked.severity(),
            WarningSeverity::Adversarial
        );
        assert_eq!(
            WarningCode::ParseAttachmentFilenameRewritten.severity(),
            WarningSeverity::Adversarial
        );
        assert_eq!(
            WarningCode::ParseAttachmentPolyglot.severity(),
            WarningSeverity::Adversarial
        );
        assert_eq!(
            WarningCode::HtmlHiddenContentDetected.severity(),
            WarningSeverity::Adversarial
        );
        assert_eq!(
            WarningCode::HtmlLinkTextHrefMismatch.severity(),
            WarningSeverity::Adversarial
        );
        assert_eq!(
            WarningCode::HtmlScriptStripped.severity(),
            WarningSeverity::Adversarial
        );
        assert_eq!(
            WarningCode::HtmlStyleStripped.severity(),
            WarningSeverity::Informational
        );
        assert_eq!(
            WarningCode::HtmlRemoteImageStripped.severity(),
            WarningSeverity::Informational
        );
        assert_eq!(
            WarningCode::HtmlAnchorUnparsableHref.severity(),
            WarningSeverity::Informational
        );
        assert_eq!(
            WarningCode::LookalikeMixedScript.severity(),
            WarningSeverity::Adversarial
        );
        assert_eq!(
            WarningCode::LookalikeHomographDomain.severity(),
            WarningSeverity::Adversarial
        );
        assert_eq!(
            WarningCode::LookalikeIdnPunycode.severity(),
            WarningSeverity::Informational
        );
        assert_eq!(
            WarningCode::LookalikeFilenameExtensionSpoof.severity(),
            WarningSeverity::Adversarial
        );
    }

    #[test]
    fn new_warning_variants_serialize_snake_case() {
        let cases = [
            (
                WarningCode::HtmlHiddenContentDetected,
                "html_hidden_content_detected",
            ),
            (
                WarningCode::HtmlLinkTextHrefMismatch,
                "html_link_text_href_mismatch",
            ),
            (WarningCode::HtmlScriptStripped, "html_script_stripped"),
            (WarningCode::HtmlStyleStripped, "html_style_stripped"),
            (
                WarningCode::HtmlRemoteImageStripped,
                "html_remote_image_stripped",
            ),
            (
                WarningCode::HtmlAnchorUnparsableHref,
                "html_anchor_unparsable_href",
            ),
            (WarningCode::LookalikeMixedScript, "lookalike_mixed_script"),
            (
                WarningCode::LookalikeHomographDomain,
                "lookalike_homograph_domain",
            ),
            (WarningCode::LookalikeIdnPunycode, "lookalike_idn_punycode"),
            (
                WarningCode::LookalikeFilenameExtensionSpoof,
                "lookalike_filename_extension_spoof",
            ),
        ];
        for (code, expected) in cases {
            let json = serde_json::to_string(&code).unwrap();
            assert_eq!(json, format!("\"{expected}\""));
        }
    }

    #[test]
    fn security_warning_round_trip() {
        let warning = SecurityWarning {
            code: WarningCode::ParseBodyTruncated,
            detail: Some("original=1048577 truncated=1048576".to_string()),
            location: Some("body:part[0]".to_string()),
        };
        let json = serde_json::to_string(&warning).unwrap();
        let parsed: SecurityWarning = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.code, warning.code);
        assert_eq!(parsed.detail, warning.detail);
        assert_eq!(parsed.location, warning.location);
    }
}
