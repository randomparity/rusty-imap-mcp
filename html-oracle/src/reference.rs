//! Independent reference extractor over `lol_html` (its own WHATWG tokenizer,
//! not html5ever). To keep the differential fair, it equalizes every
//! non-tokenizer axis production applies during extraction: non-content
//! suppression, implicit-body scope, text-node boundary separation, HTML
//! character-reference decoding, `<![CDATA[` handling, and the Unicode scrub —
//! so the only remaining divergence axis is the tokenizer itself.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::rc::Rc;

use lol_html::html_content::TextType;
use lol_html::{HtmlRewriter, Settings, comments, element, end_tag, text};

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
    /// Mirrors production `walk_children`'s `after_cdata` flag: set by a
    /// `<![CDATA[` bogus-comment, cleared at the next element boundary. While
    /// set, text siblings are dropped (CDATA-leak defense).
    after_cdata: bool,
    hrefs: Vec<String>,
}

/// Decode HTML character references with the *same* html5ever engine
/// production uses (via `scraper`), guaranteeing byte-identical handling —
/// including the legacy semicolon-less named references (`&copy`, `&amp`,
/// `&nbsp`) and longest-prefix matching that a standalone decoder gets wrong.
///
/// `lol_html` still tokenizes independently (it isolated `raw` as one text
/// node); html5ever is used only to decode references *within* that already-
/// isolated text, so the tokenizer-boundary divergence the oracle exists to
/// catch is unaffected. Parsed as a fragment: a text node contains no `<`, so
/// no new tokenization occurs — only char-ref decoding.
fn decode_entities(raw: &str) -> String {
    scraper::Html::parse_fragment(raw)
        .root_element()
        .text()
        .collect()
}

impl State {
    /// Flush the current text node into the buffer, equalizing the two
    /// non-tokenizer axes production applies during extraction:
    ///
    /// 1. **Entity decoding** — [`decode_entities`] via html5ever, matching
    ///    production. Done at node granularity because a reference is contiguous
    ///    within a single text node (never split across nodes).
    /// 2. **`]]>` drop** — mirror production `push_text`, which drops any text
    ///    node containing `]]>`. Checked post-decode to match html5ever's order
    ///    (an entity-encoded `]]>` decodes first, then is dropped).
    ///
    /// Then apply the push_text boundary separator (one space when the buffer is
    /// non-empty and does not already end in whitespace).
    fn flush_node(&mut self) {
        if self.node.is_empty() {
            return;
        }
        // html5ever character-reference decoding only ever fires on `&`, so a
        // node with no `&` (and text nodes never contain `<`) decodes to itself
        // — skip the per-node fragment parse in that common case.
        let decoded = if self.node.contains('&') {
            decode_entities(&self.node)
        } else {
            std::mem::take(&mut self.node)
        };
        self.node.clear();
        if decoded.contains("]]>") {
            return;
        }
        if !self.buf.is_empty() && !self.buf.ends_with(char::is_whitespace) {
            self.buf.push(' ');
        }
        self.buf.push_str(&decoded);
    }
}

pub fn extract_reference(decoded_html: &str) -> Result<ReferenceExtract, ReferenceError> {
    let state = Rc::new(RefCell::new(State::default()));

    let selector = NON_CONTENT_TAGS.join(", ");
    {
        let s_suppress = Rc::clone(&state);
        let s_reset = Rc::clone(&state);
        let s_text = Rc::clone(&state);
        let s_comment = Rc::clone(&state);
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
            // Any element boundary clears after_cdata, mirroring production
            // `walk_children` resetting the flag when it encounters an element
            // child. Registered before the text handler so it runs first.
            .append_element_content_handler(element!("*", move |_el| {
                s_reset.borrow_mut().after_cdata = false;
                Ok(())
            }))
            .append_element_content_handler(comments!("*", move |c| {
                // html5ever/lol_html parse `<![CDATA[ … ]]>` in HTML content as a
                // bogus comment whose text starts with `[CDATA[`. Production
                // suppresses the following text sibling; set the flag to match.
                if c.text().starts_with("[CDATA[") {
                    s_comment.borrow_mut().after_cdata = true;
                }
                Ok(())
            }))
            .append_element_content_handler(text!("*", move |t| {
                let mut st = s_text.borrow_mut();
                if st.suppress == 0 && !st.after_cdata && t.text_type() == TextType::Data {
                    st.node.push_str(t.as_str());
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

    /// Token-for-token parity with production for the same input is the core
    /// differential-fairness invariant: any divergence here would be a false
    /// HARD in the runner. `prod_tokens` mirrors `diff::classify`'s tokenizing
    /// of `body_text`.
    fn prod_tokens(html: &str) -> std::collections::BTreeSet<String> {
        let prod = rimap_content::test_support::sanitize_html(html.as_bytes(), Some("utf-8"))
            .expect("production sanitize");
        crate::norm::tokenize(&prod.body_text)
    }

    #[test]
    fn html_entities_decoded_to_match_production() {
        // &eacute; -> é, &nbsp; -> U+00A0 (whitespace), &amp; -> & (a decoded
        // ampersand is correct — production produces the same "x&y" token).
        let html = "<p>caf&eacute;&nbsp;x&amp;y</p>";
        let refx = extract_reference(html).unwrap();
        assert!(
            !refx
                .text_tokens
                .iter()
                .any(|t| t.contains("&amp;") || t.contains("&nbsp;")),
            "raw named entity leaked undecoded: {:?}",
            refx.text_tokens
        );
        assert_eq!(
            refx.text_tokens,
            prod_tokens(html),
            "reference must equal production token-for-token"
        );
    }

    #[test]
    fn cdata_sibling_text_matches_production() {
        // Production drops the CDATA content and the trailing "b" sibling
        // (after_cdata); the reference must do the same, not surface "b".
        let html = "<p>a<![CDATA[ hello ]]>b</p>";
        let refx = extract_reference(html).unwrap();
        assert_eq!(
            refx.text_tokens,
            prod_tokens(html),
            "cdata handling diverged: ref={:?}",
            refx.text_tokens
        );
    }

    #[test]
    fn entity_encoded_cdata_terminator_dropped() {
        // `&#93;&#93;&gt;` decodes to `]]>`, which production drops.
        let html = "<p>ok<span>&#93;&#93;&gt; leak</span></p>";
        let refx = extract_reference(html).unwrap();
        assert_eq!(refx.text_tokens, prod_tokens(html));
    }

    #[test]
    fn legacy_semicolonless_entities_match_production() {
        // html5ever decodes legacy semicolon-less named refs and longest-
        // prefix-matches them; the reference must match production exactly.
        for html in [
            "<p>&copy 2020</p>",
            "<p>a&ampb</p>",
            "<p>a&amp b</p>",
            "<p>&notanentity; end</p>",
            "<p>price &lt; 5 &amp; qty &gt; 0</p>",
        ] {
            let refx = extract_reference(html).unwrap();
            assert_eq!(
                refx.text_tokens,
                prod_tokens(html),
                "entity decode diverged from html5ever for {html:?}: ref={:?}",
                refx.text_tokens
            );
        }
    }
}
