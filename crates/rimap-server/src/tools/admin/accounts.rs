//! Infrastructure tool handlers for account management.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::boot::registry::AccountRegistry;
use crate::mcp::response::ToolResponse;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct UseAccountInput {
    /// Account name to select as the session default.
    pub account: String,
}

/// Trusted metadata for a `use_account` response.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct UseAccountMeta {
    /// The account that is now active.
    pub account: String,
    /// The previously active account, or `None` if none was set.
    pub previous: Option<String>,
}

/// A single account entry in a `list_accounts` response.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct AccountEntry {
    /// Account name.
    pub name: String,
    /// Whether an SMTP configuration is present for this account.
    pub smtp_configured: bool,
}

/// Trusted metadata for a `list_accounts` response.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct ListAccountsMeta {
    /// All configured accounts.
    pub accounts: Vec<AccountEntry>,
    /// Total number of configured accounts.
    pub count: usize,
}

/// Select `input.account` as the session's active account.
///
/// # Errors
///
/// Returns `RimapError::Authz { code: InvalidInput, ... }` if
/// `input.account` contains bidi-control, zero-width, or Unicode Tag
/// codepoints, or if it is not a valid account-name shape. Returns
/// `RimapError::UnknownAccount { ... }` if the name does not match a
/// configured account.
#[expect(
    clippy::unused_async,
    reason = "handler shape uniform with async-handler siblings"
)]
pub async fn handle_use_account(
    registry: &AccountRegistry,
    input: UseAccountInput,
) -> Result<ToolResponse<UseAccountMeta>, rimap_core::RimapError> {
    // Validate the account-name defense-in-depth: reject display-spoofing
    // codepoints first (so the audit record's error carries a specific
    // diagnostic), then delegate shape validation to AccountId::new, which
    // also enforces the ASCII-only constraint.
    if input
        .account
        .chars()
        .any(rimap_core::is_rejected_display_codepoint)
    {
        return Err(rimap_core::RimapError::invalid_input(
            "account: disallowed bidi/zero-width/tag codepoint in name",
        ));
    }
    rimap_core::account::AccountId::new(&input.account)
        .map_err(|_| rimap_core::RimapError::invalid_input("invalid account name"))?;
    let previous = registry.set_active(&input.account)?;
    Ok(ToolResponse::meta_only(UseAccountMeta {
        account: input.account,
        previous,
    }))
}

/// List all configured accounts.
///
/// # Errors
///
/// Infallible in practice; the `Result` type is preserved for symmetry
/// with other tool handlers so they compose uniformly through the
/// dispatch pipeline.
#[expect(
    clippy::unused_async,
    reason = "handler shape uniform with async-handler siblings"
)]
pub async fn handle_list_accounts(
    registry: &AccountRegistry,
) -> Result<ToolResponse<ListAccountsMeta>, rimap_core::RimapError> {
    let mut accounts: Vec<AccountEntry> = Vec::new();
    for state in registry.accounts().values() {
        accounts.push(AccountEntry {
            name: state.id.as_str().to_string(),
            smtp_configured: state.smtp.is_some(),
        });
    }
    let count = accounts.len();
    Ok(ToolResponse::meta_only(ListAccountsMeta {
        accounts,
        count,
    }))
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests use unwrap_err for assertions")]
#[expect(clippy::expect_used, reason = "tests")]
#[expect(clippy::panic, reason = "tests assert variant shapes via panic")]
mod tests {
    //! Input-shape validation for `handle_use_account` and the empty
    //! case of `handle_list_accounts`. Construction of a full
    //! `AccountState` requires a live IMAP connection, so the
    //! happy-path selection of a configured account is covered by the
    //! Dovecot e2e suite; here we cover the branches an adversarial
    //! or malformed input reaches before any registry lookup.

    use super::*;
    use rimap_core::RimapError;
    use rimap_core::error::ErrorCode;
    use std::collections::BTreeMap;

    fn empty_registry() -> AccountRegistry {
        AccountRegistry::new(BTreeMap::new())
    }

    fn assert_invalid_input(err: &RimapError) {
        match err {
            RimapError::Authz { code, .. } => {
                assert_eq!(*code, ErrorCode::InvalidInput);
            }
            other => panic!("expected Authz{{InvalidInput}}, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn use_account_rejects_empty_name() {
        let reg = empty_registry();
        let err = handle_use_account(
            &reg,
            UseAccountInput {
                account: String::new(),
            },
        )
        .await
        .unwrap_err();
        assert_invalid_input(&err);
    }

    #[tokio::test]
    async fn use_account_rejects_name_with_invalid_chars() {
        let reg = empty_registry();
        let err = handle_use_account(
            &reg,
            UseAccountInput {
                account: "has spaces".to_string(),
            },
        )
        .await
        .unwrap_err();
        assert_invalid_input(&err);
    }

    #[tokio::test]
    async fn use_account_rejects_overlong_name() {
        let reg = empty_registry();
        let err = handle_use_account(
            &reg,
            UseAccountInput {
                account: "a".repeat(65),
            },
        )
        .await
        .unwrap_err();
        assert_invalid_input(&err);
    }

    #[tokio::test]
    async fn use_account_valid_shape_but_unknown_returns_unknown_account() {
        // Name passes shape validation, so we proceed to registry lookup;
        // an empty registry produces `UnknownAccount`, not `InvalidInput`.
        let reg = empty_registry();
        let err = handle_use_account(
            &reg,
            UseAccountInput {
                account: "missing".to_string(),
            },
        )
        .await
        .unwrap_err();
        match err {
            RimapError::UnknownAccount { name, available } => {
                assert_eq!(name, "missing");
                assert!(available.is_empty());
            }
            other => panic!("expected UnknownAccount, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn list_accounts_on_empty_registry_returns_zero_count() {
        let reg = empty_registry();
        let resp = handle_list_accounts(&reg).await.expect("infallible");
        assert_eq!(resp.meta.count, 0);
        assert!(resp.meta.accounts.is_empty());
    }

    #[tokio::test]
    async fn use_account_rejects_bidi_override_in_name() {
        let registry = empty_registry();
        let input = UseAccountInput {
            account: "work\u{202e}cnyS".to_string(),
        };
        let err = handle_use_account(&registry, input)
            .await
            .expect_err("must reject");
        assert_invalid_input(&err);
        // Pin the pre-check as the rejecting layer, not AccountId::new's ASCII
        // gate. If the pre-check is removed, AccountId::new still rejects but
        // with a different message — this assertion catches that regression.
        assert!(
            err.to_string().contains("bidi"),
            "expected bidi-specific rejection, got: {err}",
        );
    }

    #[tokio::test]
    async fn use_account_rejects_zero_width_space_in_name() {
        let registry = empty_registry();
        let input = UseAccountInput {
            account: "work\u{200b}mail".to_string(),
        };
        let err = handle_use_account(&registry, input)
            .await
            .expect_err("must reject");
        assert_invalid_input(&err);
        assert!(
            err.to_string().contains("zero-width"),
            "expected zero-width-specific rejection, got: {err}",
        );
    }
}
