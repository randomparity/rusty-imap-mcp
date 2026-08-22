//! Account identity type.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Maximum length of an account name.
const MAX_ACCOUNT_NAME_LEN: usize = 64;

/// The name used when no account is explicitly configured.
pub const DEFAULT_ACCOUNT_NAME: &str = "default";

/// Validated account identifier.
/// ASCII alphanumeric + hyphens, 1–64 characters.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AccountId(String);

impl AccountId {
    /// Parse and validate an account name.
    ///
    /// Validation accepts ASCII alphanumerics and hyphens, 1–64 characters.
    /// The stored value is normalized to ASCII lowercase, so `AccountId`
    /// equality is case-insensitive (`Work` and `work` are the same account).
    ///
    /// # Errors
    ///
    /// Returns [`InvalidAccountName`] if the name is empty, longer than
    /// 64 characters, or contains characters other than ASCII
    /// alphanumerics and hyphens.
    pub fn new(name: &str) -> Result<Self, InvalidAccountName> {
        if name.is_empty() {
            return Err(InvalidAccountName {
                name: name.to_string(),
                reason: "must not be empty".to_string(),
            });
        }
        if name.len() > MAX_ACCOUNT_NAME_LEN {
            return Err(InvalidAccountName {
                name: name.to_string(),
                reason: format!("must be at most {MAX_ACCOUNT_NAME_LEN} characters"),
            });
        }
        if let Some(bad) = name
            .chars()
            .find(|c| !c.is_ascii_alphanumeric() && *c != '-')
        {
            return Err(InvalidAccountName {
                name: name.to_string(),
                reason: format!(
                    "contains invalid character '{bad}'; \
                     only ASCII alphanumerics and hyphens allowed"
                ),
            });
        }
        Ok(Self(name.to_ascii_lowercase()))
    }

    /// The built-in default account name.
    #[must_use]
    pub fn default_account() -> Self {
        Self(DEFAULT_ACCOUNT_NAME.to_string())
    }

    /// Borrow the inner string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
    /// The legacy single-account sentinel renders as *no* account.
    ///
    /// A flat pre-multi-account config names its sole account
    /// `"default"`; every surface that presents an **optional** account
    /// identity — `ConnectionConfig::account`, audit-record
    /// attribution, bare-tool-name preservation — must map the
    /// sentinel to absence through this one function so the sites
    /// cannot drift.
    #[must_use]
    pub fn as_optional(&self) -> Option<&AccountId> {
        (self.as_str() != DEFAULT_ACCOUNT_NAME).then_some(self)
    }
}

impl fmt::Display for AccountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Error returned when an account name fails validation.
#[derive(Debug, Clone, thiserror::Error)]
#[error("invalid account name `{name}`: {reason}")]
#[non_exhaustive]
pub struct InvalidAccountName {
    /// The name that was rejected.
    pub name: String,
    /// Why it was rejected.
    pub reason: String,
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "tests")]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn valid_names() {
        // Each tuple is (input, expected stored form after lowercasing).
        for (input, expected) in [
            ("work", "work"),
            ("personal-2", "personal-2"),
            ("default", "default"),
            ("a", "a"),
            ("A-1-b", "a-1-b"),
        ] {
            let id = AccountId::new(input).expect("should be valid");
            assert_eq!(id.as_str(), expected);
        }
    }

    #[test]
    fn max_length_accepted() {
        let name = "a".repeat(MAX_ACCOUNT_NAME_LEN);
        assert!(AccountId::new(&name).is_ok());
    }

    #[test]
    fn rejects_empty() {
        assert!(AccountId::new("").is_err());
    }

    #[test]
    fn rejects_too_long() {
        let name = "a".repeat(MAX_ACCOUNT_NAME_LEN + 1);
        assert!(AccountId::new(&name).is_err());
    }

    #[test]
    fn rejects_spaces() {
        assert!(AccountId::new("my account").is_err());
    }

    #[test]
    fn rejects_underscores() {
        assert!(AccountId::new("my_account").is_err());
    }

    #[test]
    fn rejects_special_chars() {
        for name in ["user@host", "path/part", "a!b", "c.d"] {
            assert!(
                AccountId::new(name).is_err(),
                "expected rejection for {name}"
            );
        }
    }

    #[test]
    fn display_matches_inner() {
        let id = AccountId::new("work").expect("should be valid");
        assert_eq!(format!("{id}"), "work");
    }

    #[test]
    fn default_account_valid() {
        let id = AccountId::default_account();
        assert_eq!(id.as_str(), DEFAULT_ACCOUNT_NAME);
    }

    #[test]
    fn new_lowercases_inner_string() {
        // Regression (#75): casing is presentation, not identity.
        assert_eq!(AccountId::new("Work").unwrap().as_str(), "work");
        assert_eq!(AccountId::new("WORK").unwrap().as_str(), "work");
        assert_eq!(
            AccountId::new("PersonalAccount-2").unwrap().as_str(),
            "personalaccount-2"
        );
    }

    #[test]
    fn case_variants_are_equal() {
        // Regression (#75): AccountId("Work") == AccountId("work") so that
        // the multi-account registry deduplicates them via BTreeMap insert.
        assert_eq!(
            AccountId::new("Work").unwrap(),
            AccountId::new("work").unwrap()
        );
        assert_eq!(
            AccountId::new("WORK").unwrap(),
            AccountId::new("work").unwrap()
        );
    }

    #[test]
    fn display_prints_normalized_lowercase() {
        // Regression (#75): Display follows the inner string, so users see
        // the canonical lowercase form in error messages.
        let id = AccountId::new("Work").unwrap();
        assert_eq!(format!("{id}"), "work");
    }
}
