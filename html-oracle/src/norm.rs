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
    fn href_identity_rejects_unsafe_scheme() {
        assert_eq!(href_identity("javascript:alert(1)"), None);
        assert_eq!(href_identity("data:text/html,x"), None);
        assert_eq!(href_identity("/relative/path"), None);
        assert_eq!(href_identity(""), None);
    }
}
