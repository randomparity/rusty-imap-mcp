# Differential HTML→text sanitizer oracle — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a nightly differential oracle that compares the production HTML→text
sanitizer against an independent `lol_html` tokenizer and red-flags text the
sanitizer drops with no explaining `SecurityWarning`.

**Architecture:** A standalone crate `html-oracle/` **excluded** from the main
workspace (mirrors `fuzz/`), so its `lol_html` dependency never touches the PR
gates (`clippy --all-features`, `test-msrv` 1.88, `cargo-deny`). A CLI runner
loads the fuzz + injection HTML corpus, runs both engines, and applies a two-tier
equivalence rule (HARD = silent drop → nightly red; SOFT = warning-explained drop
→ green + artifact). A nightly workflow runs it.

**Tech Stack:** Rust (edition 2024, toolchain 1.94.0), `lol_html` 3, `mail-parser`,
`url`, `serde`/`serde_json`, `toml`, `rimap-content` (`test-support` feature).

**Spec:** `docs/superpowers/specs/2026-07-10-issue-529-differential-html-oracle-design.md`

## Global Constraints

- **Excluded crate.** `html-oracle` MUST be in the root `Cargo.toml` `exclude`
  list and have its own `Cargo.lock`. It is NOT a workspace member. Nothing in
  `crates/` may depend on it.
- **No production-code changes.** The oracle only observes. Any sanitizer bug it
  finds is fixed under a separate issue.
- **Production entry point:** `rimap_content::test_support::sanitize_html(raw:
  &[u8], charset: Option<&str>) -> Result<rimap_content::test_support::HtmlResult,
  rimap_content::ContentError>` (feature `test-support`). `HtmlResult` fields:
  `body_text: String`, `anchor_hrefs: Vec<String>`, `body_html: String`,
  `warnings: Vec<rimap_content::SecurityWarning>`. **Do not** call
  `rimap_content::sanitize` for HTML — that is the Unicode scrubber.
- **Shared normalization:** decode via `rimap_content::decode(raw, charset)`;
  scrub reference text via `rimap_content::sanitize(bytes, charset, limit, loc)`
  (the Unicode scrubber) so NFKC + codepoint-strip match production exactly.
- **`DROP_EXPLAINING` warning codes:** `HtmlHiddenContentDetected`,
  `HtmlScriptStripped`, `HtmlStyleStripped`, `HtmlRemoteImageStripped`,
  `HtmlLinkTextHrefMismatch`, `HtmlAnchorUnparsableHref`.
- **`NON_CONTENT_TAGS` (suppressed by both engines):** `script`, `style`,
  `noscript`, `template`, `head`, `title`.
- **Rust style (repo):** no `unwrap()`/`expect()` in non-test code (use `?`,
  `match`, `let-else`); no `println!`/`eprintln!` in non-test *library* code, but
  this is a **binary** whose stderr diagnostics are allowed via `eprintln!`
  (stdout stays clean); 100-char lines; absolute imports; `thiserror` for error
  types. Tests may `#[expect(clippy::unwrap_used)]` the whole `mod tests`.
- **Every `uses:` in the workflow is a full 40-char SHA + version comment.**

---

## File structure

```
html-oracle/
├── Cargo.toml              # excluded crate manifest
├── Cargo.lock              # committed
├── deny.toml               # supply-chain config for the oracle graph
├── allowlist.toml          # known-benign divergences (ships empty)
├── src/
│   ├── main.rs             # CLI runner: load → diff → report → exit code
│   ├── norm.rs             # tokenize() + href_identity()
│   ├── reference.rs        # lol_html reference extractor
│   ├── allowlist.rs        # Allowlist load/lookup
│   ├── diff.rs             # two-tier classify()
│   └── corpus.rs           # corpus loader (fuzz seeds + injection .eml parts)
└── tests/
    └── oracle_logic.rs     # integration tests over hand-built inputs
.github/workflows/nightly-html-oracle.yml
Cargo.toml                  # root: add "html-oracle" to exclude
AGENTS.md                   # one-line "how to run locally" note
```

---

## Task 1: Scaffold the excluded oracle crate

**Files:**
- Create: `html-oracle/Cargo.toml`, `html-oracle/src/main.rs`,
  `html-oracle/deny.toml`
- Modify: root `Cargo.toml` (`exclude` list)

**Interfaces:**
- Produces: a buildable excluded crate. Later tasks add modules to `src/`.

- [ ] **Step 1: Add the crate to the root workspace exclude**

In root `Cargo.toml`, extend the existing `exclude` line:

```toml
exclude = ["fuzz", "html-oracle"]
```

- [ ] **Step 2: Write `html-oracle/Cargo.toml`**

```toml
[package]
name = "rusty-imap-mcp-html-oracle"
version = "0.0.0"
edition = "2024"
rust-version = "1.94.0"
publish = false
description = "Nightly differential HTML→text sanitizer oracle for rusty-imap-mcp."

[[bin]]
name = "html-oracle"
path = "src/main.rs"

[dependencies]
rimap-content = { path = "../crates/rimap-content", features = ["test-support"] }
rimap-core = { path = "../crates/rimap-core" }
lol_html = "3"
mail-parser = "0.11"
url = "2"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
toml = "0.8"

[lints.clippy]
unwrap_used = "warn"
```

> Pin `mail-parser` to the version the workspace uses; check
> `rg 'mail-parser' Cargo.toml` at the repo root and echo that exact version
> here. If it differs from `0.11`, use the workspace value.

- [ ] **Step 3: Write a stub `html-oracle/src/main.rs`**

```rust
//! Differential HTML→text sanitizer oracle. See
//! `docs/superpowers/specs/2026-07-10-issue-529-differential-html-oracle-design.md`.

fn main() -> std::process::ExitCode {
    std::process::ExitCode::SUCCESS
}
```

- [ ] **Step 4: Write `html-oracle/deny.toml`**

Copy the `[licenses]`, `[bans]`, `[advisories]`, `[sources]` skeleton from the
root `deny.toml`, keeping the same `allow` license list (MIT, Apache-2.0,
BSD-2-Clause, BSD-3-Clause, ISC, Unicode-3.0, 0BSD, MIT-0, plus
Apache-2.0 WITH LLVM-exception). Set `[sources] allow-registry =
["https://github.com/rust-lang/crates.io-index"]`. This governs the oracle's own
`lol_html` + transitive graph in the nightly `cargo deny` step.

- [ ] **Step 5: Build the crate and generate its lockfile**

Run: `cargo build --manifest-path html-oracle/Cargo.toml`
Expected: compiles; creates `html-oracle/Cargo.lock`.

- [ ] **Step 6: Verify isolation — the main workspace does NOT see the crate**

Run: `cargo metadata --format-version 1 --no-deps | rg -c 'html-oracle' || echo "ISOLATED"`
Expected: `ISOLATED` (0 matches — the crate is not a workspace member).

Run: `just check`
Expected: the main workspace still compiles, unaffected by the new crate.

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml html-oracle/Cargo.toml html-oracle/Cargo.lock \
  html-oracle/src/main.rs html-oracle/deny.toml
git commit -m "feat(oracle): scaffold excluded html-oracle crate (#529)"
```

---

## Task 2: `norm.rs` — tokenize + href identity

**Files:**
- Create: `html-oracle/src/norm.rs`
- Modify: `html-oracle/src/main.rs` (add `mod norm;`)

**Interfaces:**
- Produces:
  - `pub fn tokenize(scrubbed: &str) -> std::collections::BTreeSet<String>`
    — lowercase, split on Unicode whitespace, drop empties. Input is assumed
    already Unicode-scrubbed (production `body_text`, or reference text after the
    shared scrub).
  - `pub fn href_identity(href: &str) -> Option<String>` — returns
    `"<scheme>|<host-or-domain>"` for `http`/`https`/`mailto` hrefs, lowercased;
    `None` for any other scheme or unparseable input. Path/query/fragment are
    discarded.
  - `pub fn href_identities<I: IntoIterator<Item = S>, S: AsRef<str>>(hrefs: I)
    -> std::collections::BTreeSet<String>` — map + filter over `href_identity`.

- [ ] **Step 1: Write failing tests** in `html-oracle/src/norm.rs`

```rust
#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn tokenize_splits_and_lowercases() {
        let t = tokenize("Hello   WORLD\tfoo");
        assert!(t.contains("hello"));
        assert!(t.contains("world"));
        assert!(t.contains("foo"));
        assert!(!t.iter().any(|s| s.is_empty()));
    }

    #[test]
    fn href_identity_scheme_host_only() {
        assert_eq!(
            href_identity("https://E.com/a%20b?x=1#frag"),
            Some("https|e.com".to_string())
        );
        assert_eq!(
            href_identity("http://e.com/other"),
            Some("http|e.com".to_string())
        );
    }

    #[test]
    fn href_identity_mailto_domain() {
        assert_eq!(
            href_identity("mailto:Foo@Example.com"),
            Some("mailto|example.com".to_string())
        );
    }

    #[test]
    fn href_identity_rejects_unsafe_scheme() {
        assert_eq!(href_identity("javascript:alert(1)"), None);
        assert_eq!(href_identity("data:text/html,x"), None);
        assert_eq!(href_identity("/relative/path"), None);
        assert_eq!(href_identity(""), None);
    }
}
```

- [ ] **Step 2: Run tests, verify they fail**

Run: `cargo test --manifest-path html-oracle/Cargo.toml norm::`
Expected: FAIL (functions not defined).

- [ ] **Step 3: Implement `norm.rs`**

```rust
//! Normalization shared by the production and reference sides so the only
//! divergence the oracle can see is the tokenizer, never encoding or casing.

use std::collections::BTreeSet;

/// Tokenize already-Unicode-scrubbed text: lowercase, split on Unicode
/// whitespace, drop empty tokens.
pub fn tokenize(scrubbed: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for word in scrubbed.split(char::is_whitespace) {
        if word.is_empty() {
            continue;
        }
        out.insert(word.to_lowercase());
    }
    out
}

/// Reduce an anchor href to a `scheme|host` identity for the safe schemes the
/// mismatch defense cares about. Path/query/fragment are dropped so ammonia's
/// URL canonicalization cannot masquerade as a divergence.
pub fn href_identity(href: &str) -> Option<String> {
    let trimmed = href.trim();
    if let Some(rest) = trimmed
        .strip_prefix("mailto:")
        .or_else(|| trimmed.strip_prefix("MAILTO:"))
    {
        let domain = rest.rsplit('@').next()?;
        if domain.is_empty() {
            return None;
        }
        return Some(format!("mailto|{}", domain.to_lowercase()));
    }
    let parsed = url::Url::parse(trimmed).ok()?;
    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let host = parsed.host_str()?;
    Some(format!("{}|{}", scheme, host.to_lowercase()))
}

/// Map + filter a href iterable through [`href_identity`].
pub fn href_identities<I, S>(hrefs: I) -> BTreeSet<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut out = BTreeSet::new();
    for href in hrefs {
        if let Some(id) = href_identity(href.as_ref()) {
            out.insert(id);
        }
    }
    out
}
```

Add `mod norm;` to `src/main.rs`.

- [ ] **Step 4: Run tests, verify pass**

Run: `cargo test --manifest-path html-oracle/Cargo.toml norm::`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add html-oracle/src/norm.rs html-oracle/src/main.rs html-oracle/Cargo.lock
git commit -m "feat(oracle): tokenize + scheme+host href identity (#529)"
```

---

## Task 3: `reference.rs` — independent `lol_html` extractor

**Files:**
- Create: `html-oracle/src/reference.rs`
- Modify: `html-oracle/src/main.rs` (add `mod reference;`)

**Interfaces:**
- Consumes: `norm::tokenize`, `norm::href_identities`.
- Produces:
  - `pub struct ReferenceExtract { pub text_tokens: BTreeSet<String>, pub
    href_ids: BTreeSet<String> }`
  - `#[derive(Debug, thiserror::Error)] pub enum ReferenceError { ... }` (wraps
    `lol_html` errors).
  - `pub fn extract_reference(decoded_html: &str) -> Result<ReferenceExtract,
    ReferenceError>`

Key rules (from spec Component 2): implicit-body model (NO literal-`<body>`
gate); suppress `NON_CONTENT_TAGS`; insert a `push_text`-equivalent space
between text nodes; scrub via `rimap_content::sanitize`; hrefs via
`norm::href_identities`.

- [ ] **Step 1: Write failing tests** in `reference.rs`

```rust
#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn bodyless_fragment_is_not_inert() {
        // No <html>/<body>: implicit-body model must still surface text.
        let r = extract_reference("<p>visible</p>").unwrap();
        assert!(r.text_tokens.contains("visible"), "tokens: {:?}", r.text_tokens);
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
        let r = extract_reference(
            r#"<a href="https://e.com/p">x</a><a href="javascript:1">y</a>"#,
        )
        .unwrap();
        assert!(r.href_ids.contains("https|e.com"));
        assert!(!r.href_ids.iter().any(|h| h.starts_with("javascript")));
    }
}
```

- [ ] **Step 2: Run tests, verify they fail**

Run: `cargo test --manifest-path html-oracle/Cargo.toml reference::`
Expected: FAIL (not defined).

- [ ] **Step 3: Implement `reference.rs`**

```rust
//! Independent reference extractor over `lol_html` (its own WHATWG tokenizer,
//! not html5ever). Mirrors production's non-content suppression, body scope
//! (implicit), text-node boundary separation, and Unicode scrub — so the only
//! remaining divergence axis is the tokenizer.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::rc::Rc;

use lol_html::html_content::TextType;
use lol_html::{HtmlRewriter, Settings, element, text};

use crate::norm;

/// Tags whose text content is not user-visible body text. Same set as
/// production's `NON_CONTENT_TAGS` in `rimap-content`.
const NON_CONTENT_TAGS: &[&str] =
    &["script", "style", "noscript", "template", "head", "title"];

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

        let mut rewriter = HtmlRewriter::new(
            Settings {
                element_content_handlers: vec![
                    element!(selector, move |el| {
                        s_suppress.borrow_mut().suppress += 1;
                        let end_state = Rc::clone(&s_suppress);
                        // on_end_tag fires for properly closed suppression
                        // tags. Raw-text tags left open consume to EOF in both
                        // tokenizers, so a never-firing decrement is consistent.
                        let _ = el.on_end_tag(move |_end| {
                            let mut st = end_state.borrow_mut();
                            st.suppress = st.suppress.saturating_sub(1);
                            Ok(())
                        });
                        Ok(())
                    }),
                    text!("*", move |t| {
                        let mut st = s_text.borrow_mut();
                        if st.suppress == 0 && t.text_type() == TextType::Data {
                            let chunk = t.as_str().to_string();
                            st.node.push_str(&chunk);
                            if t.last_in_text_node() {
                                st.flush_node();
                            }
                        }
                        Ok(())
                    }),
                    element!("a[href]", move |el| {
                        if let Some(href) = el.get_attribute("href") {
                            s_href.borrow_mut().hrefs.push(href);
                        }
                        Ok(())
                    }),
                ],
                ..Settings::new()
            },
            |_: &[u8]| {},
        );

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
```

> Implementer notes:
> - Verify the `rimap_content::sanitize` signature and return type against
>   `crates/rimap-content/src/unicode.rs` (`pub fn sanitize`), and adjust the
>   call if it differs (e.g. returns a `FilterResult`-bearing tuple). The scrub
>   MUST be the same one `extract_text` uses.
> - Verify `lol_html` 3.x handler API names (`Settings::new`, `text!`,
>   `element!`, `TextChunk::last_in_text_node`, `TextChunk::text_type`,
>   `Element::on_end_tag`, `Element::get_attribute`). If a name changed, fix the
>   call — the *behavior* (suppress set, boundary separator, safe-scheme href) is
>   the contract, not the exact method spelling.

- [ ] **Step 4: Run tests, verify pass**

Run: `cargo test --manifest-path html-oracle/Cargo.toml reference::`
Expected: PASS (all five).

- [ ] **Step 5: Commit**

```bash
git add html-oracle/src/reference.rs html-oracle/src/main.rs html-oracle/Cargo.lock
git commit -m "feat(oracle): lol_html reference extractor (#529)"
```

---

## Task 4: `allowlist.rs` — known-benign divergence suppression

**Files:**
- Create: `html-oracle/src/allowlist.rs`
- Modify: `html-oracle/src/main.rs` (add `mod allowlist;`)

**Interfaces:**
- Produces:
  - `pub struct Allowlist { by_input: HashMap<String, BTreeSet<String>> }`
  - `pub fn load(toml_text: &str) -> Result<Allowlist, AllowlistError>` — parses
    entries; a missing `reason` is an error.
  - `impl Allowlist { pub fn tokens_for(&self, input_id: &str) -> &BTreeSet<String>;
    pub fn input_ids(&self) -> impl Iterator<Item = &String>; }`
  - `#[derive(Debug, thiserror::Error)] pub enum AllowlistError`

- [ ] **Step 1: Write failing tests**

```rust
#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn loads_entry_and_looks_up_tokens() {
        let toml = r#"
            [[allow]]
            input = "content_html/x"
            tokens = ["foo", "bar"]
            reason = "benign formatting artifact"
        "#;
        let a = load(toml).unwrap();
        assert!(a.tokens_for("content_html/x").contains("foo"));
        assert!(a.tokens_for("content_html/x").contains("bar"));
        assert!(a.tokens_for("nonexistent").is_empty());
    }

    #[test]
    fn missing_reason_is_error() {
        let toml = r#"
            [[allow]]
            input = "content_html/x"
            tokens = ["foo"]
        "#;
        assert!(load(toml).is_err());
    }

    #[test]
    fn empty_allowlist_loads() {
        let a = load("# no entries yet\n").unwrap();
        assert!(a.tokens_for("anything").is_empty());
        assert_eq!(a.input_ids().count(), 0);
    }
}
```

- [ ] **Step 2: Run tests, verify fail**

Run: `cargo test --manifest-path html-oracle/Cargo.toml allowlist::`
Expected: FAIL.

- [ ] **Step 3: Implement `allowlist.rs`**

```rust
//! Known-benign divergence suppression. Each entry names an input id and the
//! tokens/href-ids to subtract, with a REQUIRED reason (fail closed).

use std::collections::{BTreeSet, HashMap};

use serde::Deserialize;

#[derive(Debug, thiserror::Error)]
pub enum AllowlistError {
    #[error("failed to parse allowlist TOML: {0}")]
    Parse(String),
    #[error("allowlist entry for input {input:?} is missing a `reason`")]
    MissingReason { input: String },
}

#[derive(Debug, Deserialize)]
struct RawFile {
    #[serde(default)]
    allow: Vec<RawEntry>,
}

#[derive(Debug, Deserialize)]
struct RawEntry {
    input: String,
    #[serde(default)]
    tokens: Vec<String>,
    reason: Option<String>,
}

#[derive(Debug, Default)]
pub struct Allowlist {
    by_input: HashMap<String, BTreeSet<String>>,
}

pub fn load(toml_text: &str) -> Result<Allowlist, AllowlistError> {
    let raw: RawFile =
        toml::from_str(toml_text).map_err(|e| AllowlistError::Parse(e.to_string()))?;
    let mut by_input: HashMap<String, BTreeSet<String>> = HashMap::new();
    for entry in raw.allow {
        if entry.reason.as_deref().unwrap_or("").trim().is_empty() {
            return Err(AllowlistError::MissingReason { input: entry.input });
        }
        let set = by_input.entry(entry.input).or_default();
        for token in entry.tokens {
            set.insert(token.to_lowercase());
        }
    }
    Ok(Allowlist { by_input })
}

impl Allowlist {
    /// Tokens/href-ids suppressed for `input_id` (empty set if none).
    pub fn tokens_for(&self, input_id: &str) -> BTreeSet<String> {
        self.by_input.get(input_id).cloned().unwrap_or_default()
    }

    /// All input ids named by the allowlist (for stale-entry detection).
    pub fn input_ids(&self) -> impl Iterator<Item = &String> {
        self.by_input.keys()
    }
}
```

> Note: `tokens_for` returns an owned `BTreeSet` for simple set subtraction in
> `diff.rs`; adjust the interface block if you prefer a borrow.

- [ ] **Step 4: Run tests, verify pass**

Run: `cargo test --manifest-path html-oracle/Cargo.toml allowlist::`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add html-oracle/src/allowlist.rs html-oracle/src/main.rs html-oracle/Cargo.lock
git commit -m "feat(oracle): allowlist loader with required reason (#529)"
```

---

## Task 5: `diff.rs` — two-tier equivalence rule

**Files:**
- Create: `html-oracle/src/diff.rs`
- Modify: `html-oracle/src/main.rs` (add `mod diff;`)

**Interfaces:**
- Consumes: `reference::ReferenceExtract`, `allowlist::Allowlist`, `norm`,
  `rimap_content::test_support::HtmlResult`, `rimap_core::warning::WarningCode`.
- Produces:
  - `pub enum Verdict { Match, Soft { reference_only: BTreeSet<String> }, Hard {
    reference_only: BTreeSet<String> } }`
  - `pub struct Divergence { pub verdict: Verdict, pub production_only:
    BTreeSet<String> }`
  - `pub fn classify(prod: &HtmlResult, refx: &ReferenceExtract, allow_tokens:
    &BTreeSet<String>) -> Divergence`
  - `pub const DROP_EXPLAINING: &[WarningCode]`

- [ ] **Step 1: Write failing tests**

```rust
#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;
    use rimap_content::test_support::sanitize_html;
    use std::collections::BTreeSet;

    fn refx(tokens: &[&str]) -> crate::reference::ReferenceExtract {
        crate::reference::ReferenceExtract {
            text_tokens: tokens.iter().map(|s| s.to_string()).collect(),
            href_ids: BTreeSet::new(),
        }
    }

    #[test]
    fn silent_drop_is_hard() {
        // Production result with a token dropped and NO explaining warning.
        let prod = sanitize_html(b"<p>keep</p>", Some("utf-8")).unwrap();
        let r = refx(&["keep", "ghost"]); // reference sees an extra token
        let d = classify(&prod, &r, &BTreeSet::new());
        assert!(matches!(d.verdict, Verdict::Hard { .. }));
    }

    #[test]
    fn explained_drop_is_soft() {
        // display:none hidden text => HtmlHiddenContentDetected fires.
        let prod = sanitize_html(
            br#"<p>keep</p><div style="display:none">secret</div>"#,
            Some("utf-8"),
        )
        .unwrap();
        let r = refx(&["keep", "secret"]); // reference surfaces the hidden text
        let d = classify(&prod, &r, &BTreeSet::new());
        assert!(matches!(d.verdict, Verdict::Soft { .. }));
    }

    #[test]
    fn allowlisted_token_suppressed() {
        let prod = sanitize_html(b"<p>keep</p>", Some("utf-8")).unwrap();
        let r = refx(&["keep", "ghost"]);
        let mut allow = BTreeSet::new();
        allow.insert("ghost".to_string());
        let d = classify(&prod, &r, &allow);
        assert!(matches!(d.verdict, Verdict::Match));
    }
}
```

- [ ] **Step 2: Run tests, verify fail**

Run: `cargo test --manifest-path html-oracle/Cargo.toml diff::`
Expected: FAIL.

- [ ] **Step 3: Implement `diff.rs`**

```rust
//! Two-tier equivalence rule. reference_only = ref - prod - allowlist. Empty =>
//! Match. Non-empty with an explaining warning => Soft. Non-empty with none =>
//! Hard (silent drop = bug).

use std::collections::BTreeSet;

use rimap_content::test_support::HtmlResult;
use rimap_core::warning::WarningCode;

use crate::norm;
use crate::reference::ReferenceExtract;

/// Warning codes that legitimately explain dropped/removed text.
pub const DROP_EXPLAINING: &[WarningCode] = &[
    WarningCode::HtmlHiddenContentDetected,
    WarningCode::HtmlScriptStripped,
    WarningCode::HtmlStyleStripped,
    WarningCode::HtmlRemoteImageStripped,
    WarningCode::HtmlLinkTextHrefMismatch,
    WarningCode::HtmlAnchorUnparsableHref,
];

#[derive(Debug)]
pub enum Verdict {
    Match,
    Soft { reference_only: BTreeSet<String> },
    Hard { reference_only: BTreeSet<String> },
}

#[derive(Debug)]
pub struct Divergence {
    pub verdict: Verdict,
    pub production_only: BTreeSet<String>,
}

fn has_explaining_warning(prod: &HtmlResult) -> bool {
    for w in &prod.warnings {
        for code in DROP_EXPLAINING {
            if w.code == *code {
                return true;
            }
        }
    }
    false
}

pub fn classify(
    prod: &HtmlResult,
    refx: &ReferenceExtract,
    allow_tokens: &BTreeSet<String>,
) -> Divergence {
    let prod_tokens = norm::tokenize(&prod.body_text);
    let prod_href_ids = norm::href_identities(prod.anchor_hrefs.iter());

    let mut reference_only: BTreeSet<String> = BTreeSet::new();
    for t in &refx.text_tokens {
        if !prod_tokens.contains(t) && !allow_tokens.contains(t) {
            reference_only.insert(t.clone());
        }
    }
    for h in &refx.href_ids {
        if !prod_href_ids.contains(h) && !allow_tokens.contains(h) {
            reference_only.insert(h.clone());
        }
    }

    let mut production_only: BTreeSet<String> = BTreeSet::new();
    for t in &prod_tokens {
        if !refx.text_tokens.contains(t) {
            production_only.insert(t.clone());
        }
    }

    let verdict = if reference_only.is_empty() {
        Verdict::Match
    } else if has_explaining_warning(prod) {
        Verdict::Soft { reference_only }
    } else {
        Verdict::Hard { reference_only }
    };
    Divergence {
        verdict,
        production_only,
    }
}
```

> Verify `WarningCode` variants exist by name against
> `crates/rimap-core/src/warning.rs` and `w.code` is directly comparable
> (`PartialEq`). If `WarningCode` is not `PartialEq`, compare via the serde label
> or add the derive upstream is out of scope — use whatever equality the enum
> already supports (it is used with `==` in `rimap-content` tests, so `PartialEq`
> holds).

- [ ] **Step 4: Run tests, verify pass**

Run: `cargo test --manifest-path html-oracle/Cargo.toml diff::`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add html-oracle/src/diff.rs html-oracle/src/main.rs html-oracle/Cargo.lock
git commit -m "feat(oracle): two-tier equivalence classifier (#529)"
```

---

## Task 6: `corpus.rs` — load fuzz seeds + injection HTML parts

**Files:**
- Create: `html-oracle/src/corpus.rs`
- Modify: `html-oracle/src/main.rs` (add `mod corpus;`)

**Interfaces:**
- Produces:
  - `pub struct CorpusInput { pub id: String, pub raw: Vec<u8>, pub charset:
    Option<String> }`
  - `pub fn load(repo_root: &Path) -> Result<Vec<CorpusInput>, CorpusError>` —
    reads `fuzz/corpus/content_html/*` (charset None) and every
    `tests/injection-corpus/*/input.eml` `text/html` part (with declared charset).
  - `#[derive(Debug, thiserror::Error)] pub enum CorpusError`

- [ ] **Step 1: Write failing tests**

```rust
#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn extracts_html_part_from_eml() {
        let dir = tempfile::tempdir().unwrap();
        let corpus = dir.path().join("tests/injection-corpus/sample");
        std::fs::create_dir_all(&corpus).unwrap();
        let eml = "Content-Type: text/html; charset=utf-8\r\n\r\n<p>hello</p>\r\n";
        let mut f = std::fs::File::create(corpus.join("input.eml")).unwrap();
        f.write_all(eml.as_bytes()).unwrap();
        // no fuzz corpus dir -> that source contributes nothing, not an error.
        let inputs = load(dir.path()).unwrap();
        let sample = inputs
            .iter()
            .find(|i| i.id.starts_with("injection/sample"))
            .expect("html part extracted");
        assert!(String::from_utf8_lossy(&sample.raw).contains("hello"));
    }

    #[test]
    fn charset_is_carried_and_contents_are_predecoded() {
        // mail-parser charset-decodes text parts to UTF-8 BEFORE storage, so
        // `part.contents()` is already UTF-8 and the declared charset is carried
        // verbatim. This is faithful to production: `bodies.rs` passes exactly
        // `cow.as_bytes()` (the decoded UTF-8) + the declared charset to
        // `html::sanitize`, so the oracle feeds both engines the same bytes
        // production's real pipeline does. (Re-decoding UTF-8 bytes under the
        // windows-1252 label is a double-decode — NOT idempotent — but it happens
        // identically on both sides, so it can never be a false divergence.)
        let dir = tempfile::tempdir().unwrap();
        let corpus = dir.path().join("tests/injection-corpus/w1252");
        std::fs::create_dir_all(&corpus).unwrap();
        // 0xE9 is 'é' in Windows-1252; mail-parser decodes it to UTF-8 'é'.
        let mut eml = b"Content-Type: text/html; charset=windows-1252\r\n\r\n".to_vec();
        eml.extend_from_slice(b"<p>caf\xE9</p>");
        std::fs::write(corpus.join("input.eml"), &eml).unwrap();
        let inputs = load(dir.path()).unwrap();
        let sample = inputs.iter().find(|i| i.id.starts_with("injection/w1252")).unwrap();
        assert_eq!(sample.charset.as_deref(), Some("windows-1252"));
        // contents() is already decoded to UTF-8 'é' by mail-parser.
        assert!(
            String::from_utf8_lossy(&sample.raw).contains('é'),
            "raw should be pre-decoded UTF-8: {:?}",
            sample.raw
        );
    }
}
```

- [ ] **Step 2: Run tests, verify fail**

Run: `cargo test --manifest-path html-oracle/Cargo.toml corpus::`
Expected: FAIL. (Add `tempfile = "3"` to `[dev-dependencies]` in the oracle
`Cargo.toml` first.)

- [ ] **Step 3: Implement `corpus.rs`**

```rust
//! Corpus loader: raw HTML fuzz seeds + text/html parts from injection .eml
//! fixtures. Each input carries its raw bytes + declared charset so the runner
//! can decode identically for both engines.

use std::path::{Path, PathBuf};

use mail_parser::{MessageParser, MimeHeaders};

#[derive(Debug, thiserror::Error)]
pub enum CorpusError {
    #[error("failed to read {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
}

#[derive(Debug)]
pub struct CorpusInput {
    pub id: String,
    pub raw: Vec<u8>,
    pub charset: Option<String>,
}

pub fn load(repo_root: &Path) -> Result<Vec<CorpusInput>, CorpusError> {
    let mut inputs = Vec::new();
    load_fuzz_seeds(repo_root, &mut inputs)?;
    load_injection_parts(repo_root, &mut inputs)?;
    Ok(inputs)
}

fn load_fuzz_seeds(repo_root: &Path, out: &mut Vec<CorpusInput>) -> Result<(), CorpusError> {
    let dir = repo_root.join("fuzz/corpus/content_html");
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return Ok(()), // absent corpus is not an error
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let raw = std::fs::read(&path).map_err(|source| CorpusError::Io {
            path: path.clone(),
            source,
        })?;
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned());
        if let Some(name) = name {
            out.push(CorpusInput {
                id: format!("content_html/{name}"),
                raw,
                charset: None,
            });
        }
    }
    Ok(())
}

fn load_injection_parts(repo_root: &Path, out: &mut Vec<CorpusInput>) -> Result<(), CorpusError> {
    let dir = repo_root.join("tests/injection-corpus");
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };
    for entry in entries.flatten() {
        let fixture = entry.path();
        let eml = fixture.join("input.eml");
        if !eml.is_file() {
            continue;
        }
        let bytes = std::fs::read(&eml).map_err(|source| CorpusError::Io {
            path: eml.clone(),
            source,
        })?;
        let Some(msg) = MessageParser::default().parse(&bytes) else {
            continue;
        };
        let dir_name = fixture
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let mut part_no = 0usize;
        for part in msg.html_bodies() {
            let ct = part.content_type();
            let charset = ct
                .and_then(|c| c.attribute("charset"))
                .map(|s| s.to_string());
            let raw = part.contents().to_vec();
            let id = if part_no == 0 {
                format!("injection/{dir_name}")
            } else {
                format!("injection/{dir_name}/part{part_no}")
            };
            out.push(CorpusInput { id, raw, charset });
            part_no += 1;
        }
    }
    Ok(())
}
```

> Implementer notes:
> - `mail-parser`'s `Message::html_bodies()` yields the HTML parts;
>   `part.contents()` returns the decoded body bytes and `part.content_type()`
>   gives charset via `attribute("charset")`. Verify these method names against
>   the pinned `mail-parser` version (`cargo doc -p mail-parser --open` or the
>   version's docs) and adjust — `rimap-content` already uses `mail-parser`, so
>   cross-check `crates/rimap-content/src/parse/` for the idiomatic calls.
> - If a fixture has multiple HTML parts, each gets a distinct `partN` id.
> - **Faithfulness (do not "fix" this):** `part.contents()` is already
>   charset-decoded to UTF-8 by mail-parser, yet the loader still carries the
>   *declared* charset. That mirrors production exactly — `bodies.rs` passes
>   `cow.as_bytes()` (decoded UTF-8) + the declared charset to `html::sanitize`
>   (lines 64-69, 157-158). Feeding the same `(bytes, charset)` to both engines
>   is what makes the differential faithful; do not strip the charset or
>   re-decode, or the oracle would test a code path production never runs.

- [ ] **Step 4: Run tests, verify pass**

Run: `cargo test --manifest-path html-oracle/Cargo.toml corpus::`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add html-oracle/src/corpus.rs html-oracle/src/main.rs html-oracle/Cargo.toml html-oracle/Cargo.lock
git commit -m "feat(oracle): corpus loader for fuzz seeds + injection parts (#529)"
```

---

## Task 7: `main.rs` — runner, report, exit code

**Files:**
- Modify: `html-oracle/src/main.rs`
- Create: `html-oracle/tests/oracle_logic.rs`

**Interfaces:**
- Consumes: all modules above.
- Produces: a runnable binary. `--repo-root <path>` (default: crate parent).
  Writes `html-oracle/report.json`. Exit non-zero iff `hard > 0` OR
  (`compared_nonempty == 0` while inputs were processed).

- [ ] **Step 1: Write a failing integration test** in `tests/oracle_logic.rs`

```rust
//! End-to-end check of the runner over a tiny synthesized corpus.
#![expect(clippy::unwrap_used, reason = "tests")]

use std::process::Command;

#[test]
fn runner_greens_on_benign_corpus_and_writes_report() {
    let tmp = tempfile::tempdir().unwrap();
    // Minimal fuzz seed that both engines agree on.
    let seed_dir = tmp.path().join("fuzz/corpus/content_html");
    std::fs::create_dir_all(&seed_dir).unwrap();
    std::fs::write(seed_dir.join("hello"), b"<p>hello world</p>").unwrap();

    let report = tmp.path().join("report.json");
    let status = Command::new(env!("CARGO_BIN_EXE_html-oracle"))
        .arg("--repo-root")
        .arg(tmp.path())
        .arg("--report")
        .arg(&report)
        .status()
        .unwrap();
    assert!(status.success(), "benign corpus must exit 0");

    let text = std::fs::read_to_string(&report).unwrap();
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(json["totals"]["hard"], 0);
    assert!(json["totals"]["compared_nonempty"].as_u64().unwrap() >= 1);
}
```

Add `tempfile = "3"` and `serde_json = "1"` to `[dev-dependencies]` (serde_json
is already a normal dep; dev use is fine without re-declaring).

- [ ] **Step 2: Run test, verify it fails**

Run: `cargo test --manifest-path html-oracle/Cargo.toml --test oracle_logic`
Expected: FAIL (`--report` arg unimplemented / report not written).

- [ ] **Step 3: Implement `main.rs`**

```rust
//! Differential HTML→text sanitizer oracle runner. See
//! `docs/superpowers/specs/2026-07-10-issue-529-differential-html-oracle-design.md`.

mod allowlist;
mod corpus;
mod diff;
mod norm;
mod reference;

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::ExitCode;

use serde::Serialize;

use crate::diff::Verdict;

#[derive(Debug, Default, Serialize)]
struct Totals {
    total: usize,
    hard: usize,
    soft: usize,
    matched: usize,
    skipped: usize,
    ref_error: usize,
    compared_nonempty: usize,
    stale_allowlist_entries: usize,
}

#[derive(Debug, Serialize)]
struct InputReport {
    id: String,
    verdict: &'static str,
    reference_only: Vec<String>,
    production_only: Vec<String>,
    warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
struct Report {
    totals: Totals,
    hard_inputs: Vec<InputReport>,
    soft_inputs: Vec<InputReport>,
    stale_allowlist_inputs: Vec<String>,
}

struct Args {
    repo_root: PathBuf,
    report: PathBuf,
}

fn parse_args() -> Args {
    let mut repo_root: Option<PathBuf> = None;
    let mut report: Option<PathBuf> = None;
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--repo-root" => repo_root = it.next().map(PathBuf::from),
            "--report" => report = it.next().map(PathBuf::from),
            _ => {}
        }
    }
    let repo_root = repo_root.unwrap_or_else(|| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."))
    });
    let report = report.unwrap_or_else(|| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("report.json")
    });
    Args { repo_root, report }
}

fn main() -> ExitCode {
    let args = parse_args();

    let allowlist_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("allowlist.toml");
    let allow_text = std::fs::read_to_string(&allowlist_path).unwrap_or_default();
    let allow = match allowlist::load(&allow_text) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("html-oracle: invalid allowlist: {e}");
            return ExitCode::FAILURE;
        }
    };

    let inputs = match corpus::load(&args.repo_root) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("html-oracle: corpus load failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    let mut seen_ids: BTreeSet<String> = BTreeSet::new();
    let mut totals = Totals::default();
    let mut hard_inputs = Vec::new();
    let mut soft_inputs = Vec::new();

    for input in &inputs {
        totals.total += 1;
        seen_ids.insert(input.id.clone());

        let prod = match rimap_content::test_support::sanitize_html(
            &input.raw,
            input.charset.as_deref(),
        ) {
            Ok(r) => r,
            Err(_) => {
                totals.skipped += 1;
                continue;
            }
        };
        let decoded = rimap_content::decode(&input.raw, input.charset.as_deref());
        let refx = match reference::extract_reference(&decoded) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("html-oracle: reference error on {}: {e}", input.id);
                totals.ref_error += 1;
                continue;
            }
        };

        if !refx.text_tokens.is_empty() || !refx.href_ids.is_empty() {
            totals.compared_nonempty += 1;
        }

        let allow_tokens = allow.tokens_for(&input.id);
        let d = diff::classify(&prod, &refx, &allow_tokens);
        let warnings: Vec<String> = prod
            .warnings
            .iter()
            .map(|w| format!("{:?}", w.code))
            .collect();

        match d.verdict {
            Verdict::Match => totals.matched += 1,
            Verdict::Soft { reference_only } => {
                totals.soft += 1;
                soft_inputs.push(InputReport {
                    id: input.id.clone(),
                    verdict: "soft",
                    reference_only: reference_only.into_iter().collect(),
                    production_only: d.production_only.into_iter().collect(),
                    warnings,
                });
            }
            Verdict::Hard { reference_only } => {
                totals.hard += 1;
                hard_inputs.push(InputReport {
                    id: input.id.clone(),
                    verdict: "hard",
                    reference_only: reference_only.into_iter().collect(),
                    production_only: d.production_only.into_iter().collect(),
                    warnings,
                });
            }
        }
    }

    let stale: Vec<String> = allow
        .input_ids()
        .filter(|id| !seen_ids.contains(*id))
        .cloned()
        .collect();
    totals.stale_allowlist_entries = stale.len();

    let inert = totals.total > 0 && totals.compared_nonempty == 0;

    let report = Report {
        totals,
        hard_inputs,
        soft_inputs,
        stale_allowlist_inputs: stale,
    };
    let json = serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".into());
    if let Err(e) = std::fs::write(&args.report, json) {
        eprintln!("html-oracle: failed to write report: {e}");
        return ExitCode::FAILURE;
    }

    eprintln!(
        "html-oracle: {} inputs, {} hard, {} soft, {} match, {} skipped, {} ref_error, {} compared",
        report.totals.total,
        report.totals.hard,
        report.totals.soft,
        report.totals.matched,
        report.totals.skipped,
        report.totals.ref_error,
        report.totals.compared_nonempty,
    );
    if report.totals.stale_allowlist_entries > 0 {
        eprintln!(
            "html-oracle: WARNING {} stale allowlist entries",
            report.totals.stale_allowlist_entries
        );
    }

    if report.totals.hard > 0 {
        eprintln!("html-oracle: FAIL — {} silent-drop (HARD) divergence(s)", report.totals.hard);
        ExitCode::FAILURE
    } else if inert {
        eprintln!("html-oracle: FAIL — oracle inert (compared_nonempty == 0)");
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

use std::path::Path;
```

- [ ] **Step 4: Run the integration test, verify pass**

Run: `cargo test --manifest-path html-oracle/Cargo.toml --test oracle_logic`
Expected: PASS.

- [ ] **Step 5: Run the whole crate's tests + clippy**

Run: `cargo test --manifest-path html-oracle/Cargo.toml`
Run: `cargo clippy --manifest-path html-oracle/Cargo.toml --all-targets -- -D warnings`
Expected: PASS / clean.

- [ ] **Step 6: Commit**

```bash
git add html-oracle/src/main.rs html-oracle/tests/oracle_logic.rs \
  html-oracle/Cargo.toml html-oracle/Cargo.lock
git commit -m "feat(oracle): runner, JSON report, and exit-code gate (#529)"
```

---

## Task 8: allowlist file, nightly workflow, docs

**Files:**
- Create: `html-oracle/allowlist.toml`, `.github/workflows/nightly-html-oracle.yml`
- Modify: `AGENTS.md`

**Interfaces:** none (config + CI + docs).

- [ ] **Step 1: Create the empty allowlist**

`html-oracle/allowlist.toml`:

```toml
# Known-benign divergences for the differential HTML oracle (#529).
# Each entry REQUIRES a `reason`. Populate from the first nightly baseline;
# never allowlist a divergence that is a real sanitizer bug — file an issue.
#
# [[allow]]
# input = "content_html/example-seed"
# tokens = ["benignword", "https|host.example"]
# reason = "why this divergence is benign"
```

- [ ] **Step 2: Create the nightly workflow**

`.github/workflows/nightly-html-oracle.yml`:

```yaml
name: nightly-html-oracle

on:
  schedule:
    - cron: '41 5 * * *'
  workflow_dispatch: {}

permissions:
  contents: read

concurrency:
  group: nightly-html-oracle
  cancel-in-progress: false

jobs:
  html-oracle:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0  # v7.0.0

      - name: Install Rust toolchain
        uses: dtolnay/rust-toolchain@e97e2d8cc328f1b50210efc529dca0028893a2d9  # v1 (toolchain: stable) # zizmor: ignore[superfluous-actions]
        with:
          toolchain: stable

      - name: Cache
        uses: Swatinem/rust-cache@c19371144df3bb44fab255c43d04cbc2ab54d1c4  # v2.9.1
        with:
          workspaces: html-oracle

      - name: Install cargo-deny
        uses: taiki-e/install-action@16b05812d776ae1dfaabc8277e421fb6d2506419  # v2.82.7
        with:
          tool: cargo-deny

      - name: Supply-chain audit (oracle graph)
        run: cargo deny --manifest-path html-oracle/Cargo.toml check advisories bans licenses sources

      - name: Run differential oracle
        run: cargo run --manifest-path html-oracle/Cargo.toml -- --repo-root .

      - name: Upload report
        if: always()
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a  # v7.0.1
        with:
          name: html-oracle-report
          path: html-oracle/report.json
          if-no-files-found: warn
```

- [ ] **Step 3: Lint the workflow**

Run: `actionlint .github/workflows/nightly-html-oracle.yml`
Run: `zizmor .github/workflows/nightly-html-oracle.yml`
Expected: clean (SHA-pinned `uses:` with comments; minimal `contents: read`).

- [ ] **Step 4: Add the run note to `AGENTS.md`**

Under a suitable testing subsection, add one line:

```markdown
### Differential HTML oracle (nightly, #529)

`html-oracle/` is an excluded crate that diffs the production HTML→text
sanitizer against an independent `lol_html` tokenizer. Run locally with
`cargo run --manifest-path html-oracle/Cargo.toml -- --repo-root .`; it exits
non-zero only on a HARD (silent-drop) divergence and writes
`html-oracle/report.json`. Excluded from the workspace, so it never touches the
PR gates. Spec: `docs/superpowers/specs/2026-07-10-issue-529-differential-html-oracle-design.md`.
```

- [ ] **Step 5: Commit**

```bash
git add html-oracle/allowlist.toml .github/workflows/nightly-html-oracle.yml AGENTS.md
git commit -m "ci(oracle): nightly html-oracle workflow + allowlist + docs (#529)"
```

---

## Task 9: Baseline run, triage, and guardrails

**Files:** possibly `html-oracle/allowlist.toml` (baseline entries), and a new
GitHub issue if a real sanitizer bug surfaces.

- [ ] **Step 1: Run the oracle over the real corpus**

Run: `cargo run --manifest-path html-oracle/Cargo.toml -- --repo-root .`
Read: `html-oracle/report.json`.

- [ ] **Step 2: Triage divergences**

- **HARD divergences:** for each, inspect the input and the `reference_only`
  tokens. If it is a *real* silent drop (production dropped attacker-controlled
  text with no warning), **do NOT allowlist it** — this is exactly what the
  oracle exists to find. Open a separate GitHub issue citing the input id,
  tokens, and spec, and (temporarily) allowlist it with
  `reason = "tracked in #NNN — real silent-drop bug, see issue"` so the nightly
  is green pending the fix. If it is a benign tokenizer/structural artifact,
  allowlist it with a precise `reason`.
- **SOFT divergences:** leave them (nightly is green); note any that look like
  future injection-corpus fixtures (C5 graduation).

- [ ] **Step 3: Re-run to confirm green**

Run: `cargo run --manifest-path html-oracle/Cargo.toml -- --repo-root .`
Expected: exit 0; `report.json` totals show `hard = 0` and
`compared_nonempty` covering most inputs.

- [ ] **Step 4: Full crate guardrails**

Run: `cargo test --manifest-path html-oracle/Cargo.toml`
Run: `cargo clippy --manifest-path html-oracle/Cargo.toml --all-targets -- -D warnings`
Run: `cargo fmt --manifest-path html-oracle/Cargo.toml -- --check`
Run: `cargo deny --manifest-path html-oracle/Cargo.toml check`
Expected: all clean.

- [ ] **Step 5: Main-workspace guardrails unaffected**

Run: `just check && just lint`
Expected: the main workspace is unaffected by the excluded crate.

- [ ] **Step 6: Commit any baseline allowlist entries**

```bash
git add html-oracle/allowlist.toml
git commit -m "test(oracle): baseline allowlist from first oracle run (#529)"
```

---

## Self-review notes (author)

- **Spec coverage:** Components 1–6 → Tasks 1,3,5,4,6,8 respectively; norm/tokenize
  underpins Components 2–3 (Task 2); the runner + coverage floor is Task 7; the
  falsifiable retro + rollout is Task 9 triage.
- **Type consistency:** `HtmlResult`/`sanitize_html` (test_support),
  `ReferenceExtract{text_tokens,href_ids}`, `Verdict{Match,Soft,Hard}`,
  `Divergence{verdict,production_only}`, `CorpusInput{id,raw,charset}`,
  `Allowlist::tokens_for -> BTreeSet<String>` are used consistently across tasks.
- **Known verify-at-build points** (flagged inline, not placeholders): exact
  `rimap_content::sanitize` signature, `lol_html` 3.x handler method spellings,
  `mail-parser` HTML-part API, and `WarningCode` `PartialEq`. Each has a fallback
  instruction; behavior is the contract, not the method name.
```
