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

mod extract;
mod hidden;
mod mismatch;
mod pipeline;
mod sanitize;
mod style_parse;

#[cfg(any(test, feature = "test-support"))]
pub use pipeline::HtmlResult;
pub use pipeline::sanitize;
pub(crate) use pipeline::{
    ElementIndex, HiddenMethod, MAX_ANCHOR_TEXT_SCAN, MAX_HIDDEN_HITS, MAX_HTML_BYTES,
    MAX_MISMATCH_HITS,
};
