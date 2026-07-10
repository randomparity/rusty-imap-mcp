//! Independent reference extractor over `lol_html` (its own WHATWG tokenizer,
//! not html5ever). Mirrors production's non-content suppression, implicit-body
//! scope, text-node boundary separation, and Unicode scrub — so the only
//! remaining divergence axis is the tokenizer.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::rc::Rc;

use lol_html::html_content::TextType;
use lol_html::{HtmlRewriter, Settings, element, end_tag, text};

use crate::norm;

/// Tags whose text content is not user-visible body text. Same set as
/// production's `NON_CONTENT_TAGS` in `rimap-content`.
const NON_CONTENT_TAGS: &[&str] = &["script", "style", "noscript", "template", "head", "title"];

/// Byte cap handed to the Unicode scrubber; matches `MAX_HTML_BYTES` (1 MiB).
const SCRUB_LIMIT: usize = 1024 * 1024;

/// Extracted, normalized view produced by the reference engine.
#[derive(Debug, Default)]
pub struct ReferenceExtract {
    pub text_tokens: BTreeSet<String>,
    pub href_ids: BTreeSet<String>,
}

/// Errors from the reference extraction pass.
#[derive(Debug, thiserror::Error)]
pub enum ReferenceError {
    #[error("lol_html rewrite error: {0}")]
    Rewrite(String),
}

#[derive(Default)]
struct State {
    /// Text accumulated with push_text-equivalent boundary separators.
    buf: String,
    /// Current text-node accumulator (flushed at node end).
    node: String,
    /// Suppression depth: > 0 means inside a non-content subtree.
    suppress: usize,
    hrefs: Vec<String>,
}

impl State {
    /// Mirror of production `push_text`: insert one separating space when the
    /// buffer is non-empty and does not already end in whitespace.
    fn flush_node(&mut self) {
        if self.node.is_empty() {
            return;
        }
        if !self.buf.is_empty() && !self.buf.ends_with(char::is_whitespace) {
            self.buf.push(' ');
        }
        self.buf.push_str(&self.node);
        self.node.clear();
    }
}

pub fn extract_reference(decoded_html: &str) -> Result<ReferenceExtract, ReferenceError> {
    let state = Rc::new(RefCell::new(State::default()));

    let selector = NON_CONTENT_TAGS.join(", ");
    {
        let s_suppress = Rc::clone(&state);
        let s_text = Rc::clone(&state);
        let s_href = Rc::clone(&state);

        let settings = Settings::new()
            .append_element_content_handler(element!(selector, move |el| {
                s_suppress.borrow_mut().suppress += 1;
                let end_state = Rc::clone(&s_suppress);
                // on_end_tag fires for properly closed suppression tags. Raw-text
                // tags left open consume to EOF in both tokenizers, so a
                // never-firing decrement stays consistent between the engines.
                el.on_end_tag(end_tag!(move |_end| {
                    let mut st = end_state.borrow_mut();
                    st.suppress = st.suppress.saturating_sub(1);
                    Ok(())
                }))?;
                Ok(())
            }))
            .append_element_content_handler(text!("*", move |t| {
                let mut st = s_text.borrow_mut();
                if st.suppress == 0 && t.text_type() == TextType::Data {
                    let chunk = t.as_str().to_string();
                    st.node.push_str(&chunk);
                    if t.last_in_text_node() {
                        st.flush_node();
                    }
                }
                Ok(())
            }))
            .append_element_content_handler(element!("a[href]", move |el| {
                if let Some(href) = el.get_attribute("href") {
                    s_href.borrow_mut().hrefs.push(href);
                }
                Ok(())
            }));

        let mut rewriter = HtmlRewriter::new(settings, |_: &[u8]| {});
        rewriter
            .write(decoded_html.as_bytes())
            .map_err(|e| ReferenceError::Rewrite(e.to_string()))?;
        rewriter
            .end()
            .map_err(|e| ReferenceError::Rewrite(e.to_string()))?;
    }

    let mut st = state.borrow_mut();
    st.flush_node();
    // Scrub identically to production `extract_text`: NFKC + codepoint filter.
    let (scrubbed, _warnings) = rimap_content::sanitize(
        st.buf.as_bytes(),
        Some("utf-8"),
        SCRUB_LIMIT,
        "oracle:reference",
    );
    Ok(ReferenceExtract {
        text_tokens: norm::tokenize(&scrubbed),
        href_ids: norm::href_identities(st.hrefs.iter()),
    })
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn bodyless_fragment_is_not_inert() {
        // No <html>/<body>: implicit-body model must still surface text.
        let r = extract_reference("<p>visible</p>").unwrap();
        assert!(
            r.text_tokens.contains("visible"),
            "tokens: {:?}",
            r.text_tokens
        );
    }

    #[test]
    fn element_boundary_separator_parity() {
        // Adjacent elements with no source whitespace must NOT merge.
        let r = extract_reference("<p>a</p><p>b</p>").unwrap();
        assert!(r.text_tokens.contains("a"));
        assert!(r.text_tokens.contains("b"));
        assert!(!r.text_tokens.contains("ab"), "merged: {:?}", r.text_tokens);
    }

    #[test]
    fn non_content_tags_suppressed() {
        let r = extract_reference(
            "<title>skip</title><body><p>keep</p><script>drop()</script>\
             <style>.x{}</style></body>",
        )
        .unwrap();
        assert!(r.text_tokens.contains("keep"));
        assert!(!r.text_tokens.contains("skip"));
        assert!(!r.text_tokens.iter().any(|t| t.contains("drop")));
        assert!(!r.text_tokens.iter().any(|t| t.contains(".x")));
    }

    #[test]
    fn unclosed_title_suppresses_only_its_raw_text_tail() {
        // <title> is escapable-raw-text: both tokenizers consume to EOF, so an
        // unclosed <title> at the end suppresses only what follows it.
        let r = extract_reference("<p>before</p><title>after-eof").unwrap();
        assert!(r.text_tokens.contains("before"));
        assert!(!r.text_tokens.iter().any(|t| t.contains("after")));
    }

    #[test]
    fn safe_scheme_href_ids_only() {
        let r = extract_reference(r#"<a href="https://e.com/p">x</a><a href="javascript:1">y</a>"#)
            .unwrap();
        assert!(r.href_ids.contains("https|e.com"));
        assert!(!r.href_ids.iter().any(|h| h.starts_with("javascript")));
    }
}
