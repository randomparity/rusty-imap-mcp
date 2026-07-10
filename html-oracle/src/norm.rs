//! Normalization shared by the production and reference sides so the only
//! divergence the oracle can see is the tokenizer, never encoding or casing.

use std::collections::BTreeSet;

/// Tokenize already-Unicode-scrubbed text: lowercase, split on Unicode
/// whitespace, drop empty tokens.
pub fn tokenize(scrubbed: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for word in scrubbed.split(char::is_whitespace) {
        // Trim leading/trailing non-alphanumerics so that a word carrying
        // adjacent punctuation (`member,`, `(usdrugs)`) tokenizes the same as
        // the bare word. This removes the dominant differential noise source:
        // the two engines place text-node boundaries around stray tags
        // differently, which a whitespace-only split turns into `member,`
        // vs `member` + `,`. Interior punctuation (`x&y`, `e.g`) is preserved.
        let trimmed = word.trim_matches(|c: char| !c.is_alphanumeric());
        if trimmed.is_empty() {
            continue;
        }
        out.insert(trimmed.to_lowercase());
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
        // Drop any `?subject=…&body=…` header block before the address, then
        // require an actual recipient: a header-only mailto has no identity.
        let addr = rest.split('?').next().unwrap_or(rest);
        if !addr.contains('@') {
            return None;
        }
        let domain = addr.rsplit('@').next()?;
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

#[cfg(test)]
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
    fn href_identity_mailto_strips_headers_and_requires_recipient() {
        // A recipient with ?subject=…&body=… headers keeps only scheme|domain.
        assert_eq!(
            href_identity("mailto:a@b.com?subject=unsubscribe&body=please"),
            Some("mailto|b.com".to_string())
        );
        // A header-only mailto with no recipient has no identity (was junk before).
        assert_eq!(
            href_identity("mailto:?subject=unsubscribe&body=please"),
            None
        );
        assert_eq!(href_identity("mailto:commercecorps.live?subject=x"), None);
    }

    #[test]
    fn tokenize_strips_edge_punctuation() {
        // Trailing/leading punctuation must not create distinct tokens: production
        // often keeps `member,` as one text run while the reference emits `member`
        // + `,` around a stray tag. Both must reduce to {member}.
        let t = tokenize("Member, (USDrugs). x&y");
        assert!(t.contains("member"), "{t:?}");
        assert!(t.contains("usdrugs"), "{t:?}");
        assert!(t.contains("x&y"), "interior punctuation kept: {t:?}");
        assert!(!t.contains(","));
        assert!(!t.contains("member,"));
        assert!(!t.contains("(usdrugs)"));
    }

    #[test]
    fn href_identity_rejects_unsafe_scheme() {
        assert_eq!(href_identity("javascript:alert(1)"), None);
        assert_eq!(href_identity("data:text/html,x"), None);
        assert_eq!(href_identity("/relative/path"), None);
        assert_eq!(href_identity(""), None);
    }
}
