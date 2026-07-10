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
