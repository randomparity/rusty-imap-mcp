//! Ammonia-based HTML sanitization and remote-content warnings.

use std::collections::HashSet;
use std::sync::LazyLock;

use ammonia::Builder;
use scraper::{Html, Selector};

use crate::html::hidden::compile_selector;
use crate::html::mismatch::{count_img_with_src, count_matching};
use crate::output::SecurityWarning;

/// Selector matching `<script>` elements.
pub(super) static SEL_SCRIPT: LazyLock<Selector> = LazyLock::new(|| compile_selector("script"));
/// Selector matching `<style>` elements.
pub(super) static SEL_STYLE: LazyLock<Selector> = LazyLock::new(|| compile_selector("style"));

/// Shared ammonia builder.
pub(super) static AMMONIA_BUILDER: LazyLock<Builder<'static>> =
    LazyLock::new(build_ammonia_builder);

/// Build the ammonia `Builder` used for html sanitization.
///
/// Restricts URL schemes to `{http, https, mailto, tel}` and locks
/// `<img>` attributes to `{alt, width, height}`, dropping `src`,
/// `srcset`, and other remote-fetching surfaces. Ammonia's defaults
/// already strip `<script>`, `<style>`, and event handler attributes.
///
/// Uses `rm_tag_attributes` + `add_tag_attributes` rather than
/// `tag_attributes` so the defaults for unrelated tags (notably
/// `<a href>`, which the anchor-href collector needs to enumerate
/// post-sanitize) remain in place.
fn build_ammonia_builder() -> Builder<'static> {
    let mut builder = Builder::default();
    let schemes: HashSet<&'static str> = ["http", "https", "mailto", "tel"].into_iter().collect();
    builder.url_schemes(schemes);
    builder.rm_tag_attributes("img", &["src", "srcset"]);
    builder.add_tag_attributes("img", &["alt", "width", "height"]);
    // Pin tag removals against ammonia default drift. details/summary
    // are explicitly removed: collapsed content is invisible to humans
    // but visible to LLMs reading HTML tokens.
    builder.rm_tags(&[
        "script", "style", "iframe", "object", "embed", "meta", "base", "link", "form", "input",
        "button", "textarea", "svg", "math", "frame", "frameset", "noframes", "applet", "details",
        "summary",
    ]);
    builder.strip_comments(true);
    builder
}

/// Count pre-sanitize remote-content elements on the scraper-parsed
/// `document`, run `ammonia::clean` on `decoded`, and emit
/// `HtmlScriptStripped` / `HtmlStyleStripped` / `HtmlRemoteImageStripped`
/// warnings when the pre-sanitize count is non-zero. Returns the
/// sanitized HTML string.
///
/// The counting deliberately runs against the same pre-sanitize `Html`
/// value used by all earlier detection stages (scraper's parse), not
/// against ammonia's own internal parse — the point is to observe what
/// ammonia *will* strip, on the same DOM the detectors saw. ammonia
/// 4.1 and scraper 0.27 now share html5ever 0.39, so the two parses
/// agree on tokenization; any residual divergence between them still
/// surfaces as a warning-count vs. `body_html` mismatch, which the
/// `html-tokenizer-divergence` snapshot fixture exercises.
pub(super) fn sanitize_body(
    document: &Html,
    decoded: &str,
    warnings: &mut Vec<SecurityWarning>,
) -> String {
    let script_count = count_matching(document, &SEL_SCRIPT);
    let style_count = count_matching(document, &SEL_STYLE);
    let remote_img_count = count_img_with_src(document);
    let body_html = AMMONIA_BUILDER.clean(decoded).to_string();
    if script_count > 0 {
        warnings.push(SecurityWarning::at(
            crate::output::WarningCode::HtmlScriptStripped,
            format!("count={script_count}"),
            "body:html",
        ));
    }
    if style_count > 0 {
        warnings.push(SecurityWarning::at(
            crate::output::WarningCode::HtmlStyleStripped,
            format!("count={style_count}"),
            "body:html",
        ));
    }
    if remote_img_count > 0 {
        warnings.push(SecurityWarning::at(
            crate::output::WarningCode::HtmlRemoteImageStripped,
            format!("count={remote_img_count}"),
            "body:html",
        ));
    }
    body_html
}
