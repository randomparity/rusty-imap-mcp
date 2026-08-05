//! Downstream-construction contract for `rimap_config::validate` (#707).
//!
//! `#[non_exhaustive]` is a no-op inside the crate that defines the type, so
//! an in-crate `#[cfg(test)]` module can never exercise it. An integration
//! test is a separate crate, which makes this file the only place in the
//! workspace where the attribute is actually in force on
//! [`ValidatedAccountConfig`] / [`ValidatedMultiConfig`] — every construction
//! below is compiled under exactly the rules a downstream consumer gets.
//!
//! Three properties are pinned here:
//!
//! 1. The `test-support` fixture constructors are the only downstream way to
//!    mint either type without a config file. `..Default::default()` is not
//!    an alternative: functional-update syntax is still a struct expression,
//!    which `#[non_exhaustive]` rejects across a crate boundary (rustc
//!    E0639). `T::new_for_tests(..)` plus field assignment is the idiom.
//! 2. Each fixture agrees field-for-field with what `validate_multi`
//!    produces for the equivalent minimal config, compared against a real
//!    validation run rather than hard-coded values — so a fixture cannot
//!    drift away from the defaults the validator resolves.
//! 3. Downstream pattern matches need a rest pattern.
//!
//! Sibling of `non_exhaustive_model.rs` (#665), which covers `model.rs`.

#![expect(clippy::expect_used, reason = "integration test")]

use rimap_config::validate::{ValidatedAccountConfig, ValidatedMultiConfig};
use rimap_config::{MultiAccountConfig, validate_multi};
use rimap_core::account::AccountId;
use tempfile::TempDir;

/// A multi-account config that sets only the fields the schema requires, so
/// every remaining field lands on the validator's own resolved default.
///
/// Written as TOML rather than as struct expressions on purpose: the model
/// types are `#[non_exhaustive]` too (#665), and going through the real
/// deserializer is what makes the comparison below a comparison against
/// production behaviour.
fn minimal_toml(dir: &std::path::Path) -> String {
    format!(
        r#"
[[accounts]]
name = "work"

[accounts.imap]
host = "imap.example.com"
port = 993
username = "alice@example.com"

[audit]
path = "{audit}/audit.jsonl"
allowed_base_dir = "{audit}"
"#,
        audit = dir.display(),
    )
}

/// Run [`minimal_toml`] through the real deserializer and validator.
fn validated_minimal() -> (TempDir, ValidatedMultiConfig) {
    let dir = TempDir::new().expect("tempdir");
    let config: MultiAccountConfig =
        toml::from_str(&minimal_toml(dir.path())).expect("deserialize minimal config");
    let validated = validate_multi(config).expect("validate minimal config");
    (dir, validated)
}

fn work_id() -> AccountId {
    AccountId::new("work").expect("`work` is a valid account name")
}

#[test]
fn account_fixture_matches_validated_defaults() {
    let (_dir, validated) = validated_minimal();
    let loaded = validated
        .accounts
        .get(&work_id())
        .expect("minimal config declares one account");

    let built = ValidatedAccountConfig::new_for_tests(loaded.id.clone(), loaded.imap.clone());

    assert_eq!(built.id, loaded.id);
    assert_eq!(built.imap.host, loaded.imap.host);
    assert_eq!(built.imap.port, loaded.imap.port);
    assert!(built.smtp.is_none(), "no `[accounts.smtp]` in the fixture");
    assert!(loaded.smtp.is_none());
    assert_eq!(built.security, loaded.security);
    assert_eq!(built.limits, loaded.limits);
    assert_eq!(built.tool_overrides, loaded.tool_overrides);
    assert_eq!(built.account_written_tools, loaded.account_written_tools);
    assert_eq!(built.tls_fingerprint, loaded.tls_fingerprint);
    assert_eq!(built.fallback_mode, loaded.fallback_mode);
}

#[test]
fn multi_fixture_matches_validated_defaults() {
    let (_dir, validated) = validated_minimal();

    let built =
        ValidatedMultiConfig::new_for_tests(validated.audit.clone(), validated.attachments.clone());

    assert!(
        built.accounts.is_empty(),
        "the fixture starts empty; callers insert what they need"
    );
    assert_eq!(built.audit.path, validated.audit.path);
    assert_eq!(built.audit.fail_open, validated.audit.fail_open);
    assert_eq!(
        built.attachments.download_dir,
        validated.attachments.download_dir
    );
}

#[test]
fn fixtures_stay_field_mutable_downstream() {
    // `#[non_exhaustive]` blocks the struct literal, not field access: a
    // downstream caller reaches every remaining field by assignment after
    // `new_for_tests`, which is why the constructors take only the fields
    // that have no meaningful default.
    let (_dir, validated) = validated_minimal();
    let loaded = validated
        .accounts
        .get(&work_id())
        .expect("minimal config declares one account");

    let mut account = ValidatedAccountConfig::new_for_tests(loaded.id.clone(), loaded.imap.clone());
    account.security.posture = rimap_core::posture::Posture::Full;
    account.tool_overrides.insert(
        rimap_core::tool::ToolName::Search,
        rimap_config::Verdict::Allow,
    );
    assert_eq!(account.security.posture, rimap_core::posture::Posture::Full);
    assert_eq!(account.tool_overrides.len(), 1);

    let mut multi =
        ValidatedMultiConfig::new_for_tests(validated.audit.clone(), validated.attachments.clone());
    multi.accounts.insert(account.id.clone(), account);
    assert_eq!(multi.accounts.len(), 1);
}

#[test]
fn downstream_pattern_match_needs_rest_pattern() {
    let (_dir, validated) = validated_minimal();
    // The `..` is mandatory downstream. Without the attribute this compiles
    // either way, so the rest pattern is the visible cost of the change.
    let ValidatedMultiConfig { accounts, .. } = &validated;
    assert_eq!(accounts.len(), 1);

    let ValidatedAccountConfig { id, .. } = &accounts[&work_id()];
    assert_eq!(id, &work_id());
}
