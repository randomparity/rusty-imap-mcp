//! HTML processing pipeline for rimap-content.
//!
//! Parses `text/html` bodies via `scraper`, detects hidden-element and
//! anchor/href phishing signals, extracts sanitized plain text, and
//! produces an ammonia-sanitized HTML rendering with remote content
//! stripped. The only consumer of `scraper`, `ammonia`, and `linkify`
//! in the workspace.
//!
//! The single entrypoint visible outside `parse_message` is [`sanitize`],
//! re-exported through [`crate::test_support`] (under the alias `sanitize_html`)
//! for fuzz harnesses; production callers reach it via
//! [`crate::parse::parse_message`].

use std::collections::HashSet;

use scraper::Html;

use crate::error::ContentError;
use crate::output::SecurityWarning;

mod extract;
mod hidden;
mod mismatch;
mod sanitize;
mod style_parse;

use crate::html::extract::{collect_anchor_hrefs, extract_text};
use crate::html::hidden::detect_hidden;
use crate::html::mismatch::detect_mismatches;
use crate::html::sanitize::sanitize_body;

// `pub` only because `test_support` re-exports through `pub mod test_support` (Rust
// E0364 forbids `pub use` of `pub(crate)` items). Module privacy keeps
// this unreachable outside the crate; production callers reach this type
// through [`crate::output::Content`] populated by [`crate::parse::parse_message`].
/// Result of processing a single HTML body part.
#[derive(Debug, Clone)]
pub struct HtmlResult {
    /// Plain text extracted from the HTML, already run through
    /// `unicode::sanitize`.
    pub body_text: String,
    /// Ammonia-sanitized HTML (allowlist minus remote content).
    pub body_html: String,
    /// Anchor hrefs surviving sanitization, in document order.
    /// Consumed by `lookalike::audit`.
    pub anchor_hrefs: Vec<String>,
    /// Warnings produced during parse, detection, and sanitization.
    pub warnings: Vec<SecurityWarning>,
}

/// Maximum raw HTML body size. Matches `MAX_BODY_BYTES` from parse.rs.
pub(crate) const MAX_HTML_BYTES: usize = 1024 * 1024;

/// Maximum anchor-text length scanned by `linkify` during href-mismatch
/// detection.
pub(crate) const MAX_ANCHOR_TEXT_SCAN: usize = 4 * 1024;

/// Cap on individual hidden-content hits before summarization.
pub(crate) const MAX_HIDDEN_HITS: usize = 64;

/// Cap on individual href-mismatch hits before summarization.
pub(crate) const MAX_MISMATCH_HITS: usize = 32;

/// `kind` value used for [`ContentError::LimitExceeded`] when the raw
/// HTML body exceeds [`MAX_HTML_BYTES`].
pub(crate) const HTML_BODY_LIMIT_KIND: &str = "html_body";

/// Stable identifier for an element we've decided is hidden. Used by
/// `extract_text` to skip hidden subtrees.
///
/// `scraper` does not give us a stable `ElementRef` across re-parses,
/// so we identify hidden elements by their position in a pre-order
/// walk of the document tree (a `usize` index). This is sufficient for
/// a single processing pass.
pub(crate) type ElementIndex = usize;

/// Categorization of how an element was hidden from a recipient.
///
/// Each variant corresponds to a distinct CSS pattern that effectively
/// removes content from rendering, used by hidden-content detection in
/// [`crate::html::hidden::detect_hidden`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HiddenMethod {
    /// `display: none` — element omitted from layout entirely.
    DisplayNone,
    /// `visibility: hidden` — element occupies space but is invisible.
    VisibilityHidden,
    /// `opacity: 0` — element is fully transparent.
    OpacityZero,
    /// Absolute or fixed positioning placing the element far off-screen.
    OffScreen,
    /// `font-size: 0` — text collapses to zero rendered size.
    ZeroFont,
    /// `color` and `background-color` strings are byte-identical.
    ColorMatch,
}

impl HiddenMethod {
    /// Stable identifier used in `SecurityWarning::detail` strings.
    pub(crate) fn as_detail(self) -> &'static str {
        match self {
            HiddenMethod::DisplayNone => "display_none",
            HiddenMethod::VisibilityHidden => "visibility_hidden",
            HiddenMethod::OpacityZero => "opacity_0",
            HiddenMethod::OffScreen => "offscreen",
            HiddenMethod::ZeroFont => "zero_font",
            HiddenMethod::ColorMatch => "color_match",
        }
    }
}

// `pub` only because `test_support` re-exports through `pub mod test_support` (Rust
// E0364 forbids `pub use` of `pub(crate)` items). Module privacy (`mod html;`
// in `lib.rs`) keeps this unreachable outside the crate; production callers
// MUST reach it via [`crate::parse::parse_message`] so the unicode +
// lookalike-audit pipeline runs first.
/// Process a raw HTML body into sanitized text + html + warnings.
///
/// # Arguments
///
/// * `raw` - Raw HTML body bytes as received from the MIME part.
/// * `charset` - Optional charset label from the MIME `Content-Type`
///   header (e.g. `Some("iso-8859-1")`). When `None`, `unicode::decode`
///   falls back to `encoding_rs` auto-detection (UTF-8 with BOM sniffing
///   then Windows-1252). Invalid bytes are replaced with U+FFFD.
///
/// # Errors
///
/// Returns [`ContentError::LimitExceeded`] if `raw` exceeds
/// [`MAX_HTML_BYTES`].
pub fn sanitize(raw: &[u8], charset: Option<&str>) -> Result<HtmlResult, ContentError> {
    if raw.len() > MAX_HTML_BYTES {
        return Err(ContentError::LimitExceeded {
            kind: HTML_BODY_LIMIT_KIND,
            limit: MAX_HTML_BYTES,
        });
    }
    let decoded = crate::unicode::decode(raw, charset);
    let document = Html::parse_document(&decoded);
    let (hidden_hits, hidden_overflow) = detect_hidden(&document);
    let mut warnings: Vec<SecurityWarning> = Vec::new();
    for (_idx, method) in &hidden_hits {
        warnings.push(SecurityWarning::at(
            crate::output::WarningCode::HtmlHiddenContentDetected,
            format!("method={}", method.as_detail()),
            "body:html",
        ));
    }
    if hidden_overflow > 0 {
        warnings.push(SecurityWarning::at(
            crate::output::WarningCode::HtmlHiddenContentDetected,
            format!("method=mixed,additional_hits={hidden_overflow}"),
            "body:html",
        ));
    }
    let (mismatches, mismatch_overflow, unparsable_hrefs) = detect_mismatches(&document);
    for hit in &mismatches {
        warnings.push(SecurityWarning::at(
            crate::output::WarningCode::HtmlLinkTextHrefMismatch,
            format!(
                "text_domain={},href_domain={}",
                hit.text_domain, hit.href_domain
            ),
            "html:anchor",
        ));
    }
    if mismatch_overflow > 0 {
        warnings.push(SecurityWarning::at(
            crate::output::WarningCode::HtmlLinkTextHrefMismatch,
            format!("additional_hits={mismatch_overflow}"),
            "html:anchor",
        ));
    }
    for (href, text) in &unparsable_hrefs {
        warnings.push(SecurityWarning::at(
            crate::output::WarningCode::HtmlAnchorUnparsableHref,
            format!("href={href},text={text}"),
            "body_html:anchor",
        ));
    }
    let hidden_indices: HashSet<ElementIndex> = hidden_hits.iter().map(|(idx, _)| *idx).collect();
    let (body_text, mut text_warnings) = extract_text(&document, &hidden_indices);
    warnings.append(&mut text_warnings);
    let body_html = sanitize_body(&document, &decoded, &mut warnings);
    let anchor_hrefs = collect_anchor_hrefs(&body_html);
    Ok(HtmlResult {
        body_text,
        body_html,
        anchor_hrefs,
        warnings,
    })
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "tests may expect on constructed values")]
#[expect(clippy::panic, reason = "test failure paths")]
mod tests {
    use super::*;
    use crate::html::hidden::{SEL_BODY_ALL, compile_selector};
    use crate::html::mismatch::{SEL_ANCHOR, SEL_IMG, extract_registrable_domain};
    use crate::html::sanitize::{AMMONIA_BUILDER, SEL_SCRIPT, SEL_STYLE};
    use crate::html::style_parse::{classify_inline_style, classify_single_declaration};

    #[test]
    fn sanitize_oversize_input_returns_limit_exceeded() {
        let huge = vec![b'<'; MAX_HTML_BYTES + 1];
        let err = sanitize(&huge, None).expect_err("oversize input must error");
        match err {
            ContentError::LimitExceeded { kind, limit } => {
                assert_eq!(kind, HTML_BODY_LIMIT_KIND);
                assert_eq!(limit, MAX_HTML_BYTES);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn sanitize_accepts_input_at_max_html_bytes() {
        // Kills `> with >=` on `raw.len() > MAX_HTML_BYTES`. With `>=`,
        // a 1 MiB body errors immediately with html_body kind; the
        // original passes the check and proceeds (may emit body
        // truncation warnings later, but kind != html_body).
        let body = vec![b'a'; MAX_HTML_BYTES];
        let result = sanitize(&body, None);
        match result {
            Ok(_) => (),
            Err(ContentError::LimitExceeded { kind, .. }) => {
                assert_ne!(
                    kind, HTML_BODY_LIMIT_KIND,
                    "must not error with html_body kind at exactly MAX_HTML_BYTES",
                );
            }
            Err(other) => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn sanitize_emits_mismatch_summary_warning_when_overflow_positive() {
        // Kills `> with <` on `if mismatch_overflow > 0`. With `<`,
        // mismatch_overflow (a usize) can never satisfy `< 0`, so the
        // summary warning is never emitted regardless of overflow.
        // Construct MAX_MISMATCH_HITS + 3 distinct mismatched anchors;
        // expect a warning whose detail mentions the overflow count.
        use std::fmt::Write as _;
        let mut body = String::new();
        for i in 0..(MAX_MISMATCH_HITS + 3) {
            write!(
                body,
                "<a href=\"https://actual.com\">https://evil-{i}.example</a>",
            )
            .expect("write! into String never fails");
        }
        let html = format!("<html><body>{body}</body></html>");
        let result = sanitize(html.as_bytes(), None).expect("sanitize must succeed");
        let summary_count = result
            .warnings
            .iter()
            .filter(|w| {
                w.code == crate::output::WarningCode::HtmlLinkTextHrefMismatch
                    && w.detail
                        .as_deref()
                        .is_some_and(|d| d.contains("additional_hits="))
            })
            .count();
        assert_eq!(
            summary_count, 1,
            "expected exactly one mismatch summary warning, got {summary_count}",
        );
    }

    #[test]
    fn sanitize_scans_anchor_text_up_to_max_anchor_text_scan() {
        // Kills `* with +` on `MAX_ANCHOR_TEXT_SCAN = 4 * 1024`. The
        // mutant flips the constant to 4 + 1024 = 1028, well below 4 KiB.
        // An anchor whose mismatched URL sits at byte offset ~2000
        // (within 4 KiB but past 1 KiB) round-trips a mismatch warning
        // under the original cap and silently drops it under the mutant.
        let padding = "x".repeat(2000);
        let html = format!(
            "<html><body><a href=\"https://actual.com\">{padding} https://evil.example</a></body></html>",
        );
        let result = sanitize(html.as_bytes(), None).expect("sanitize must succeed");
        let mismatch_seen = result.warnings.iter().any(|w| {
            w.code == crate::output::WarningCode::HtmlLinkTextHrefMismatch
                && w.detail
                    .as_deref()
                    .is_some_and(|d| d.contains("text_domain=evil.example"))
        });
        assert!(
            mismatch_seen,
            "expected a mismatch warning for the URL at byte ~2000 within MAX_ANCHOR_TEXT_SCAN=4096",
        );
    }

    #[test]
    fn sanitize_empty_input_returns_empty_result() {
        let result = sanitize(b"", None).expect("empty input is valid");
        assert!(result.body_text.is_empty());
        // ammonia returns an empty string for empty input.
        assert!(result.body_html.is_empty());
        assert!(result.anchor_hrefs.is_empty());
        assert!(result.warnings.is_empty());
    }

    #[test]
    fn sanitize_minimal_html_document_parses_without_panic() {
        let html = b"<!DOCTYPE html><html><head><title>Hi</title></head>\
            <body><p>hello</p></body></html>";
        let result = sanitize(html, Some("utf-8")).expect("valid html parses");
        assert_eq!(result.body_text, "hello");
        assert!(result.body_html.contains("<p>hello</p>"));
        assert!(result.anchor_hrefs.is_empty());
        assert!(result.warnings.is_empty());
    }

    #[test]
    fn sanitize_unclosed_tags_does_not_error() {
        // scraper/html5ever recovers from malformed input rather than
        // erroring; verify the pipeline tolerates it.
        let html = b"<html><body><p>oops<div><span>still here";
        let result = sanitize(html, None).expect("malformed html still parses");
        assert!(result.body_text.contains("oops"));
        assert!(result.body_text.contains("still here"));
        assert!(result.warnings.is_empty());
    }

    #[test]
    fn compile_selector_accepts_valid_const() {
        let _ = compile_selector("a[href]");
    }

    #[test]
    fn constants_are_referenced() {
        let _ = (
            MAX_HTML_BYTES,
            MAX_ANCHOR_TEXT_SCAN,
            MAX_HIDDEN_HITS,
            MAX_MISMATCH_HITS,
        );
    }

    #[test]
    fn classify_display_none() {
        assert_eq!(
            classify_inline_style("display: none"),
            Some(HiddenMethod::DisplayNone)
        );
        assert_eq!(
            classify_inline_style("DISPLAY:NONE;color:red"),
            Some(HiddenMethod::DisplayNone)
        );
    }

    #[test]
    fn classify_visibility_hidden() {
        assert_eq!(
            classify_inline_style("visibility: hidden"),
            Some(HiddenMethod::VisibilityHidden)
        );
    }

    #[test]
    fn classify_opacity_zero() {
        assert_eq!(
            classify_inline_style("opacity: 0"),
            Some(HiddenMethod::OpacityZero)
        );
        assert_eq!(
            classify_inline_style("opacity: 0.0"),
            Some(HiddenMethod::OpacityZero)
        );
    }

    #[test]
    fn classify_font_size_zero() {
        assert_eq!(
            classify_inline_style("font-size: 0"),
            Some(HiddenMethod::ZeroFont)
        );
        assert_eq!(
            classify_inline_style("font-size: 0px"),
            Some(HiddenMethod::ZeroFont)
        );
    }

    #[test]
    fn classify_offscreen_absolute() {
        assert_eq!(
            classify_inline_style("position: absolute; left: -9999px"),
            Some(HiddenMethod::OffScreen)
        );
        assert_eq!(
            classify_inline_style("position: fixed; top: -5000px"),
            Some(HiddenMethod::OffScreen)
        );
    }

    #[test]
    fn classify_color_match() {
        assert_eq!(
            classify_inline_style("color: #ffffff; background-color: #ffffff"),
            Some(HiddenMethod::ColorMatch)
        );
        assert_eq!(
            classify_inline_style("color: white; background-color: white"),
            Some(HiddenMethod::ColorMatch)
        );
    }

    #[test]
    fn classify_visible_styles_return_none() {
        assert_eq!(classify_inline_style("color: red"), None);
        assert_eq!(classify_inline_style("font-weight: bold"), None);
        assert_eq!(
            classify_inline_style("position: absolute; left: 10px"),
            None
        );
        assert_eq!(classify_inline_style("opacity: 0.5"), None);
    }

    /// Negative cases for [`classify_single_declaration`] guards.
    #[test]
    fn classify_single_declaration_visible_values_return_none() {
        assert_eq!(classify_single_declaration("display", "block"), None);
        assert_eq!(classify_single_declaration("display", "inline"), None);
        assert_eq!(classify_single_declaration("visibility", "visible"), None);
        assert_eq!(classify_single_declaration("visibility", "collapse"), None);
        assert_eq!(classify_single_declaration("font-size", "14px"), None);
        assert_eq!(classify_single_declaration("font-size", "1em"), None);
        assert_eq!(classify_single_declaration("opacity", "1"), None);
        assert_eq!(classify_single_declaration("color", "red"), None);
    }

    /// Positive cases for [`classify_single_declaration`].
    #[test]
    fn classify_single_declaration_variant_per_property() {
        assert_eq!(
            classify_single_declaration("display", "none"),
            Some(HiddenMethod::DisplayNone)
        );
        assert_eq!(
            classify_single_declaration("visibility", "hidden"),
            Some(HiddenMethod::VisibilityHidden)
        );
        assert_eq!(
            classify_single_declaration("opacity", "0"),
            Some(HiddenMethod::OpacityZero)
        );
        assert_eq!(
            classify_single_declaration("font-size", "0"),
            Some(HiddenMethod::ZeroFont)
        );
    }

    #[test]
    fn sanitize_detects_display_none_in_body() {
        let input = br#"<html><body>
            <p>visible</p>
            <div style="display: none">HIDDEN SECRET</div>
        </body></html>"#;
        let result = sanitize(input, None).expect("process should succeed");
        let hit = result
            .warnings
            .iter()
            .find(|w| {
                matches!(
                    w.code,
                    crate::output::WarningCode::HtmlHiddenContentDetected
                )
            })
            .expect("expected HtmlHiddenContentDetected warning");
        assert_eq!(hit.detail.as_deref(), Some("method=display_none"));
        assert_eq!(hit.location.as_deref(), Some("body:html"));
    }

    #[test]
    fn sanitize_hidden_hit_cap_summarizes_overflow() {
        use std::fmt::Write as _;
        let mut body = String::from("<html><body>");
        for i in 0..(MAX_HIDDEN_HITS + 5) {
            write!(body, r#"<span style="display: none">hidden {i}</span>"#)
                .expect("write to String never fails");
        }
        body.push_str("</body></html>");
        let result = sanitize(body.as_bytes(), None).expect("process should succeed");
        let hidden_warnings: Vec<_> = result
            .warnings
            .iter()
            .filter(|w| {
                matches!(
                    w.code,
                    crate::output::WarningCode::HtmlHiddenContentDetected
                )
            })
            .collect();
        assert_eq!(hidden_warnings.len(), MAX_HIDDEN_HITS + 1);
        let overflow = hidden_warnings
            .last()
            .expect("at least one warning")
            .detail
            .as_deref()
            .expect("overflow warning has detail");
        assert!(overflow.contains("additional_hits=5"), "got {overflow}");
        assert!(overflow.contains("method=mixed"), "got {overflow}");
    }

    #[test]
    fn mismatch_fires_for_different_domains() {
        let input = br#"<html><body>
            <a href="https://attacker.example/login">Visit bank.example.com now</a>
        </body></html>"#;
        let result = sanitize(input, None).expect("ok");
        let mismatch = result
            .warnings
            .iter()
            .find(|w| matches!(w.code, crate::output::WarningCode::HtmlLinkTextHrefMismatch))
            .expect("expected mismatch warning");
        let detail = mismatch.detail.as_deref().expect("detail present");
        assert!(detail.contains("text_domain=example.com"), "got {detail}");
        assert!(
            detail.contains("href_domain=attacker.example"),
            "got {detail}"
        );
        assert_eq!(mismatch.location.as_deref(), Some("html:anchor"));
    }

    #[test]
    fn mismatch_does_not_fire_for_matching_subdomain() {
        let input = br#"<html><body>
            <a href="https://bank.example.com/auth">Go to login.bank.example.com</a>
        </body></html>"#;
        let result = sanitize(input, None).expect("ok");
        assert!(
            !result
                .warnings
                .iter()
                .any(|w| matches!(w.code, crate::output::WarningCode::HtmlLinkTextHrefMismatch)),
            "should not fire for matching registrable domain: {:?}",
            result.warnings
        );
    }

    #[test]
    fn mismatch_does_not_fire_for_click_here_text() {
        let input = br#"<html><body>
            <a href="https://attacker.example">click here</a>
        </body></html>"#;
        let result = sanitize(input, None).expect("ok");
        assert!(
            !result
                .warnings
                .iter()
                .any(|w| matches!(w.code, crate::output::WarningCode::HtmlLinkTextHrefMismatch)),
            "should not fire when anchor text has no URL token"
        );
    }

    #[test]
    fn extract_registrable_domain_skips_non_web_schemes() {
        assert_eq!(extract_registrable_domain("mailto:foo@example.com"), None);
        assert_eq!(extract_registrable_domain("tel:+15551234567"), None);
        assert_eq!(extract_registrable_domain("javascript:alert(1)"), None);
        assert_eq!(extract_registrable_domain("data:text/html,foo"), None);
        assert_eq!(extract_registrable_domain(""), None);
        assert_eq!(extract_registrable_domain("   "), None);
        assert_eq!(extract_registrable_domain("relative/path"), None);
        assert_eq!(extract_registrable_domain("singlelabel"), None);
    }

    #[test]
    fn extract_registrable_domain_returns_psl_root() {
        assert_eq!(
            extract_registrable_domain("https://www.example.com/path?q=1"),
            Some("example.com".into())
        );
        assert_eq!(
            extract_registrable_domain("http://sub.example.co.uk"),
            Some("example.co.uk".into())
        );
        assert_eq!(
            extract_registrable_domain("https://example.com:8443/"),
            Some("example.com".into())
        );
    }

    #[test]
    fn mismatch_skips_mailto_and_relative_hrefs() {
        let input = br#"<html><body>
            <a href="mailto:foo@example.com">visit example.com</a>
            <a href="/relative/path">relative.example</a>
        </body></html>"#;
        let result = sanitize(input, None).expect("ok");
        assert!(
            !result
                .warnings
                .iter()
                .any(|w| matches!(w.code, crate::output::WarningCode::HtmlLinkTextHrefMismatch))
        );
    }

    #[test]
    fn mismatch_emits_unparsable_href_for_psl_failure() {
        let input = br#"<html><body>
            <a href="https://evilserver/phish">Visit paypal.com now</a>
        </body></html>"#;
        let result = sanitize(input, None).expect("ok");
        assert!(
            result
                .warnings
                .iter()
                .any(|w| matches!(w.code, crate::output::WarningCode::HtmlAnchorUnparsableHref)),
            "expected HtmlAnchorUnparsableHref, got {:?}",
            result.warnings
        );
    }

    #[test]
    fn extract_text_returns_visible_body_text() {
        let input = br#"<html>
            <head><title>should be skipped</title></head>
            <body>
                <p>visible paragraph</p>
                <script>alert(1)</script>
                <style>.x{color:red}</style>
                <div style="display:none">hidden secret</div>
                <p>second paragraph</p>
            </body>
        </html>"#;
        let result = sanitize(input, None).expect("ok");
        assert!(
            result.body_text.contains("visible paragraph"),
            "got {:?}",
            result.body_text
        );
        assert!(
            result.body_text.contains("second paragraph"),
            "got {:?}",
            result.body_text
        );
        assert!(!result.body_text.contains("alert(1)"));
        assert!(!result.body_text.contains("should be skipped"));
        assert!(
            !result.body_text.contains("hidden secret"),
            "hidden leaked: {:?}",
            result.body_text
        );
        assert!(!result.body_text.contains(".x{color:red}"));
    }

    #[test]
    fn extract_text_normalizes_whitespace() {
        let input = b"<html><body><p>hello    world</p>   <p>line\t\ttwo</p></body></html>";
        let result = sanitize(input, None).expect("ok");
        assert!(!result.body_text.contains("    "));
        assert!(!result.body_text.contains("\t\t"));
        assert!(result.body_text.contains("hello world"));
        assert!(result.body_text.contains("line two"));
    }

    #[test]
    fn extract_text_empty_body_returns_empty_string() {
        let input = b"<html><head><title>t</title></head><body></body></html>";
        let result = sanitize(input, None).expect("ok");
        assert!(result.body_text.is_empty(), "got {:?}", result.body_text);
    }

    #[test]
    fn extract_text_index_alignment_skips_only_hidden_elements() {
        let input = br#"<html><body>
            <span>alpha</span>
            <span style="display:none">SECRET</span>
            <span>omega</span>
        </body></html>"#;
        let result = sanitize(input, None).expect("ok");
        assert!(
            result.body_text.contains("alpha"),
            "got {:?}",
            result.body_text
        );
        assert!(
            result.body_text.contains("omega"),
            "got {:?}",
            result.body_text
        );
        assert!(
            !result.body_text.contains("SECRET"),
            "hidden text leaked, alignment broken: {:?}",
            result.body_text
        );
    }

    #[test]
    fn extract_text_index_alignment_handles_nested_hidden() {
        let input = br#"<html><body>
            <p>before</p>
            <div style="display:none"><span>nested hidden</span><em>still hidden</em></div>
            <p>after</p>
        </body></html>"#;
        let result = sanitize(input, None).expect("ok");
        assert!(result.body_text.contains("before"));
        assert!(result.body_text.contains("after"));
        assert!(!result.body_text.contains("nested hidden"));
        assert!(!result.body_text.contains("still hidden"));
    }

    #[test]
    fn sanitize_produces_body_html_with_safe_tags() {
        let input = b"<html><body><p>hello <strong>world</strong></p></body></html>";
        let result = sanitize(input, None).expect("ok");
        assert!(result.body_html.contains("<p>"));
        assert!(result.body_html.contains("<strong>"));
        assert!(result.body_html.contains("hello"));
    }

    #[test]
    fn sanitize_strips_script_and_warns() {
        let input = br"<html><body><p>ok</p><script>evil()</script></body></html>";
        let result = sanitize(input, None).expect("ok");
        assert!(!result.body_html.contains("<script"));
        assert!(!result.body_html.contains("evil()"));
        assert!(
            result
                .warnings
                .iter()
                .any(|w| matches!(w.code, crate::output::WarningCode::HtmlScriptStripped))
        );
    }

    #[test]
    fn sanitize_strips_style_and_warns() {
        let input = br"<html><body><style>.x{color:red}</style><p>ok</p></body></html>";
        let result = sanitize(input, None).expect("ok");
        assert!(!result.body_html.contains("<style"));
        assert!(
            result
                .warnings
                .iter()
                .any(|w| matches!(w.code, crate::output::WarningCode::HtmlStyleStripped))
        );
    }

    #[test]
    fn sanitize_strips_img_src_preserves_alt_and_warns() {
        let input = br#"<html><body>
            <img src="https://tracker.example/px.gif" alt="invoice attached" width="1" height="1">
        </body></html>"#;
        let result = sanitize(input, None).expect("ok");
        assert!(!result.body_html.contains("tracker.example"));
        assert!(!result.body_html.contains("src="));
        assert!(result.body_html.contains("alt=\"invoice attached\""));
        assert!(
            result
                .warnings
                .iter()
                .any(|w| matches!(w.code, crate::output::WarningCode::HtmlRemoteImageStripped))
        );
    }

    #[test]
    fn sanitize_drops_javascript_url_from_anchor() {
        let input = br#"<html><body><a href="javascript:alert(1)">click</a></body></html>"#;
        let result = sanitize(input, None).expect("ok");
        assert!(!result.body_html.contains("javascript:"));
    }

    #[test]
    fn anchor_hrefs_are_collected_from_sanitized_html() {
        let input = br#"<html><body>
            <a href="https://legit.example/login">ok</a>
            <a href="https://other.example/page">other</a>
            <a href="mailto:foo@example.com">email</a>
            <a href="javascript:alert(1)">bad</a>
        </body></html>"#;
        let result = sanitize(input, None).expect("ok");
        assert_eq!(result.anchor_hrefs.len(), 3);
        assert!(
            result
                .anchor_hrefs
                .iter()
                .any(|h| h.contains("legit.example"))
        );
        assert!(
            result
                .anchor_hrefs
                .iter()
                .any(|h| h.contains("other.example"))
        );
        assert!(result.anchor_hrefs.iter().any(|h| h.starts_with("mailto:")));
        assert!(
            !result
                .anchor_hrefs
                .iter()
                .any(|h| h.contains("javascript:"))
        );
    }

    #[test]
    fn cdata_script_content_excluded_from_body_text() {
        let html = br#"<html><body>
            <p>visible</p>
            <![CDATA[<script>alert("cdata-bypass")</script>]]>
        </body></html>"#;
        let result = sanitize(html, None).expect("ok");
        assert!(
            !result.body_text.contains("alert"),
            "CDATA script content should not leak into body_text: {:?}",
            result.body_text
        );
        assert!(
            !result.body_text.contains("cdata-bypass"),
            "CDATA content should not appear in body_text: {:?}",
            result.body_text
        );
        assert!(
            result.body_text.contains("visible"),
            "non-CDATA text should still appear: {:?}",
            result.body_text
        );
    }

    #[test]
    fn unclosed_cdata_script_content_excluded_from_body_text() {
        let html = br#"<html><body>
            <p>visible</p>
            <![CDATA[<script>alert("leaked")
        </body></html>"#;
        let result = sanitize(html, None).expect("ok");
        assert!(
            !result.body_text.contains("alert"),
            "unclosed CDATA script content should not leak: {:?}",
            result.body_text
        );
    }

    #[test]
    fn lazylocks_initialize_without_panic() {
        let _ = &*SEL_ANCHOR;
        let _ = &*SEL_IMG;
        let _ = &*SEL_SCRIPT;
        let _ = &*SEL_STYLE;
        let _ = &*SEL_BODY_ALL;
        let _ = &*AMMONIA_BUILDER;
    }

    #[test]
    fn sanitize_drops_iframe_and_details() {
        let tags = [
            "iframe", "object", "embed", "meta", "base", "link", "form", "input", "button",
            "textarea", "svg", "math", "frame", "frameset", "noframes", "applet", "details",
            "summary",
        ];
        for tag in tags {
            let input = format!("<html><body><{tag}>hidden content</{tag}></body></html>");
            let result = sanitize(input.as_bytes(), None).expect("process should succeed");
            assert!(
                !result.body_html.contains(&format!("<{tag}")),
                "tag <{tag}> should be stripped from body_html, got: {}",
                result.body_html
            );
        }
    }

    #[test]
    fn classify_offscreen_minus_999_fires() {
        assert_eq!(
            classify_inline_style("position: absolute; left: -999px"),
            Some(HiddenMethod::OffScreen)
        );
    }

    #[test]
    fn classify_offscreen_minus_50_does_not_fire() {
        assert_eq!(
            classify_inline_style("position: absolute; left: -50px"),
            None
        );
    }

    #[test]
    fn classify_offscreen_transform_translate() {
        assert_eq!(
            classify_inline_style("position: absolute; transform: translateX(-9999px)"),
            Some(HiddenMethod::OffScreen)
        );
        assert_eq!(
            classify_inline_style("position: fixed; transform: translate(-500px, 0)"),
            Some(HiddenMethod::OffScreen)
        );
    }

    #[test]
    fn classify_offscreen_transform_small_value_no_fire() {
        assert_eq!(
            classify_inline_style("position: absolute; transform: translateX(-50px)"),
            None
        );
    }

    #[test]
    fn body_html_has_no_html_comments() {
        let input = b"<html><body><!-- secret comment --><p>visible</p></body></html>";
        let result = sanitize(input, None).expect("process should succeed");
        assert!(
            !result.body_html.contains("<!--"),
            "HTML comments should be stripped, got: {}",
            result.body_html
        );
        assert!(
            !result.body_html.contains("secret comment"),
            "comment content should be stripped, got: {}",
            result.body_html
        );
    }
}
