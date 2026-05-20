//! Test/diagnostic label helpers. Gated on the `test-support` feature so the
//! mappings are not part of the regular public API surface.
//!
//! Callers decide how to treat unknown variants (both enums are
//! `#[non_exhaustive]`): the helpers return `None` for anything not in
//! the known set. The runner surfaces `None` as a severity-keyed label;
//! the corpus test harness panics on `None` (a new variant = a harness
//! gap that must fail loudly).

/// Re-export of [`crate::html::process`] under the alias `sanitize_html`
/// for fuzz harnesses and out-of-tree integration tests. Production code
/// must continue to reach `process` through the [`crate::parse::parse_message`]
/// pipeline.
pub use crate::html::process as sanitize_html;

/// Re-export of [`crate::parse::mime_scrub::scrub_header_smuggling`]
/// for fuzz harnesses. Production code reaches this function through
/// [`crate::parse::parse_message`].
pub use crate::parse::mime_scrub::scrub_header_smuggling;

/// Re-export of [`crate::parse::mime_scrub::find_header_end`] for fuzz
/// harnesses that need to mirror the scrubber's exact header-boundary
/// detection without redefining the offset arithmetic. Returns
/// `(header_end, sep_len)` where `header_end` excludes the blank-line
/// separator. Production code reaches this through `scrub_header_smuggling`.
pub use crate::parse::mime_scrub::find_header_end;

/// Re-export of [`crate::html::HtmlResult`] so external callers of the
/// re-exported `sanitize_html` alias can name the return type. Production
/// code does not see `HtmlResult` directly — its fields are folded into
/// [`crate::output::Content`] by [`crate::parse::parse_message`].
pub use crate::html::HtmlResult;

use crate::{ContentError, WarningCode};

/// Map a known `WarningCode` variant to its stable audit-label string.
/// Returns `None` for variants added after this function was written.
#[must_use]
pub fn warning_code_label(code: WarningCode) -> Option<&'static str> {
    let label = match code {
        WarningCode::UnicodeZeroWidthStripped => "unicode_zero_width_stripped",
        WarningCode::UnicodeBidiOverrideStripped => "unicode_bidi_override_stripped",
        WarningCode::UnicodeC0C1Stripped => "unicode_c0_c1_stripped",
        WarningCode::ParseHeaderSmugglingBlocked => "parse_header_smuggling_blocked",
        WarningCode::ParseMimeTypeMismatch => "parse_mime_type_mismatch",
        WarningCode::ParseBodystructureTypeMismatch => "parse_bodystructure_type_mismatch",
        WarningCode::ParseAttachmentPolyglot => "parse_attachment_polyglot",
        WarningCode::ParseBodyTruncated => "parse_body_truncated",
        WarningCode::ParseMimeDepthExceeded => "parse_mime_depth_exceeded",
        WarningCode::ParseMimePartCountExceeded => "parse_mime_part_count_exceeded",
        WarningCode::ParseHeaderCountExceeded => "parse_header_count_exceeded",
        WarningCode::ParseAttachmentFilenameRewritten => "parse_attachment_filename_rewritten",
        WarningCode::HtmlHiddenContentDetected => "html_hidden_content_detected",
        WarningCode::HtmlLinkTextHrefMismatch => "html_link_text_href_mismatch",
        WarningCode::HtmlScriptStripped => "html_script_stripped",
        WarningCode::HtmlStyleStripped => "html_style_stripped",
        WarningCode::HtmlRemoteImageStripped => "html_remote_image_stripped",
        WarningCode::HtmlAnchorUnparsableHref => "html_anchor_unparsable_href",
        WarningCode::LookalikeMixedScript => "lookalike_mixed_script",
        WarningCode::LookalikeHomographDomain => "lookalike_homograph_domain",
        WarningCode::LookalikeIdnPunycode => "lookalike_idn_punycode",
        WarningCode::LookalikeFilenameExtensionSpoof => "lookalike_filename_extension_spoof",
        WarningCode::ServerNonAtomicMoveFallback => "server_non_atomic_move_fallback",
        _ => return None,
    };
    Some(label)
}

/// Map a known `ContentError` variant to its kind string. Returns `None`
/// for variants added after this function was written.
#[must_use]
#[expect(
    unreachable_patterns,
    reason = "ContentError is #[non_exhaustive]; _ arm is unreachable within the defining crate \
              but required for forward-compatibility with new variants added externally"
)]
pub fn error_kind_label(err: &ContentError) -> Option<&'static str> {
    let label = match err {
        ContentError::Malformed { .. } => "Malformed",
        ContentError::LimitExceeded { .. } => "LimitExceeded",
        ContentError::ParserPanic => "ParserPanic",
        _ => return None,
    };
    Some(label)
}

#[cfg(test)]
mod tests {
    use super::{error_kind_label, warning_code_label};
    use crate::{ContentError, WarningCode};

    #[test]
    fn all_known_warning_codes_have_stable_labels() {
        let cases = [
            (
                WarningCode::UnicodeZeroWidthStripped,
                "unicode_zero_width_stripped",
            ),
            (
                WarningCode::UnicodeBidiOverrideStripped,
                "unicode_bidi_override_stripped",
            ),
            (WarningCode::UnicodeC0C1Stripped, "unicode_c0_c1_stripped"),
            (
                WarningCode::ParseHeaderSmugglingBlocked,
                "parse_header_smuggling_blocked",
            ),
            (
                WarningCode::ParseMimeTypeMismatch,
                "parse_mime_type_mismatch",
            ),
            (
                WarningCode::ParseBodystructureTypeMismatch,
                "parse_bodystructure_type_mismatch",
            ),
            (
                WarningCode::ParseAttachmentPolyglot,
                "parse_attachment_polyglot",
            ),
            (WarningCode::ParseBodyTruncated, "parse_body_truncated"),
            (
                WarningCode::ParseMimeDepthExceeded,
                "parse_mime_depth_exceeded",
            ),
            (
                WarningCode::ParseMimePartCountExceeded,
                "parse_mime_part_count_exceeded",
            ),
            (
                WarningCode::ParseHeaderCountExceeded,
                "parse_header_count_exceeded",
            ),
            (
                WarningCode::ParseAttachmentFilenameRewritten,
                "parse_attachment_filename_rewritten",
            ),
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
            (
                WarningCode::ServerNonAtomicMoveFallback,
                "server_non_atomic_move_fallback",
            ),
        ];
        for (code, expected) in cases {
            assert_eq!(
                warning_code_label(code),
                Some(expected),
                "label for {code:?} changed",
            );
        }
    }

    #[test]
    fn error_kind_label_stable_for_known_variants() {
        let cases: &[(ContentError, &str)] = &[
            (
                ContentError::Malformed {
                    reason: "x".to_string(),
                },
                "Malformed",
            ),
            (
                ContentError::LimitExceeded {
                    kind: "mime_depth",
                    limit: 8,
                },
                "LimitExceeded",
            ),
            (ContentError::ParserPanic, "ParserPanic"),
        ];
        for (err, expected) in cases {
            assert_eq!(
                error_kind_label(err),
                Some(*expected),
                "label for {err:?} changed",
            );
        }
    }
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "tests")]
mod test_support_reexports {
    use crate::output::SecurityWarning;

    #[test]
    fn fuzz_entries_are_callable_via_test_support() {
        // sanitize_html: minimal HTML body should round-trip without panic.
        let result = super::sanitize_html(b"<p>hi</p>", Some("utf-8"))
            .expect("sanitize_html on minimal HTML must succeed");
        assert!(!result.body_text.is_empty());

        // scrub_header_smuggling: a clean encoded-word produces no warnings.
        let mut warnings: Vec<SecurityWarning> = Vec::new();
        let raw = b"Subject: =?utf-8?B?aGVsbG8=?=\r\n\r\nbody";
        let scrubbed = super::scrub_header_smuggling(raw, &mut warnings);
        assert!(warnings.is_empty(), "clean encoded word should not warn");
        assert!(!scrubbed.is_empty());
    }
}
