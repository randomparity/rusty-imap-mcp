//! Downstream-construction contract for `rimap_config::model` (#665).
//!
//! `#[non_exhaustive]` is a no-op inside the crate that defines the type, so
//! an in-crate `#[cfg(test)]` module can never exercise it. An integration
//! test is a separate crate, which makes this file the only place in the
//! workspace where the attribute is actually in force — every construction
//! below is compiled under exactly the rules a downstream consumer gets.
//!
//! Three properties are pinned here:
//!
//! 1. Every model struct that carries a `Default` stays *reachable* through
//!    `T::default()` plus field assignment. Note that `..Default::default()`
//!    is **not** available: functional-update syntax is still a struct
//!    expression, which `#[non_exhaustive]` rejects across a crate boundary
//!    (rustc E0639). `T::default()` + assignment is the downstream idiom.
//! 2. The three constructors added alongside the attribute
//!    ([`ImapConfig::new`], [`SmtpConfig::new`], [`AuditConfig::new`]) produce
//!    exactly what the loader produces for the same required fields. The
//!    comparison is against a real `load_from_path` call rather than against
//!    hard-coded numbers, so a constructor cannot drift away from the serde
//!    defaults it mirrors.
//! 3. Downstream pattern matches need a rest pattern.

#![expect(clippy::expect_used, reason = "integration test")]

use std::path::PathBuf;

use rimap_config::{
    AccountCredentialsOverrides, AccountLimitsOverrides, AccountLookalikeOverrides,
    AccountSecurityOverrides, AttachmentsConfig, AuditConfig, Config, CredentialsConfig,
    DefaultsConfig, FallbackMode, ImapConfig, LimitsConfig, LookalikeConfig, SecurityConfig,
    SmtpConfig, SmtpEncryption, load_from_path,
};
use tempfile::TempDir;

/// A config file that sets only the fields the schema requires, so every
/// remaining field lands on the loader's own default.
const MINIMAL_CONFIG: &str = r#"
[imap]
host = "imap.example.com"
port = 993
username = "alice"

[smtp]
host = "smtp.example.com"
port = 587
encryption = "starttls"
username = "alice"

[audit]
path = "/tmp/rusty-imap-mcp-audit.jsonl"
"#;

/// Parse [`MINIMAL_CONFIG`] through the real loader.
fn loaded_minimal() -> (TempDir, Config) {
    let dir = TempDir::new().expect("create tempdir");
    let path = dir.path().join("config.toml");
    std::fs::write(&path, MINIMAL_CONFIG).expect("write config");
    let config = load_from_path(&path).expect("load minimal config");
    (dir, config)
}

#[test]
fn defaulting_structs_stay_reachable_downstream() {
    // Group A — hand-written `Default`.
    let mut security = SecurityConfig::default();
    security.expunge_folders = vec!["Spam".to_string()];
    assert_eq!(security.expunge_folders, vec!["Spam".to_string()]);
    // The hand-written `Default` is what makes the attribute affordable here:
    // `protected_folders` keeps its curated list rather than emptying.
    assert!(security.protected_folders.contains(&"INBOX".to_string()));

    let mut lookalike = LookalikeConfig::default();
    assert!(lookalike.enabled, "hand-written Default enables detection");
    lookalike.enabled = false;
    assert!(!lookalike.enabled);

    let mut limits = LimitsConfig::default();
    assert_ne!(limits.max_search_results, 0, "hand-written Default is live");
    limits.max_search_results = 42;
    assert_eq!(limits.max_search_results, 42);

    // Group B — derived `Default`.
    assert_eq!(
        CredentialsConfig::default().fallback,
        FallbackMode::KeyringThenEnv
    );

    let mut attachments = AttachmentsConfig::default();
    attachments.download_dir = "/tmp/dl".to_string();
    assert_eq!(attachments.download_dir, "/tmp/dl");

    let mut defaults = DefaultsConfig::default();
    defaults.limits = limits.clone();
    assert_eq!(defaults.limits.max_search_results, 42);

    let mut limit_overrides = AccountLimitsOverrides::default();
    limit_overrides.max_search_results = Some(7);
    assert_eq!(limit_overrides.max_search_results, Some(7));

    let mut security_overrides = AccountSecurityOverrides::default();
    security_overrides.expunge_folders = Some(vec!["Junk".to_string()]);
    assert_eq!(
        security_overrides.expunge_folders,
        Some(vec!["Junk".to_string()])
    );

    let mut lookalike_overrides = AccountLookalikeOverrides::default();
    lookalike_overrides.enabled = Some(true);
    assert_eq!(lookalike_overrides.enabled, Some(true));

    let mut credential_overrides = AccountCredentialsOverrides::default();
    credential_overrides.fallback = Some(FallbackMode::KeyringOnly);
    assert_eq!(
        credential_overrides.fallback,
        Some(FallbackMode::KeyringOnly)
    );
}

#[test]
fn imap_config_new_matches_loader_defaults() {
    let (_dir, loaded) = loaded_minimal();
    let built = ImapConfig::new("imap.example.com".to_string(), 993, "alice".to_string());

    assert_eq!(built.host, loaded.imap.host);
    assert_eq!(built.port, loaded.imap.port);
    assert_eq!(built.username, loaded.imap.username);
    assert_eq!(built.encryption, loaded.imap.encryption);
    assert_eq!(
        built.tls_fingerprint_sha256,
        loaded.imap.tls_fingerprint_sha256
    );
    assert_eq!(
        built.command_timeout_seconds,
        loaded.imap.command_timeout_seconds
    );
    assert_eq!(
        built.connect_timeout_seconds,
        loaded.imap.connect_timeout_seconds
    );
}

#[test]
fn smtp_config_new_matches_loader_defaults() {
    let (_dir, loaded) = loaded_minimal();
    let loaded_smtp = loaded.smtp.expect("minimal config declares [smtp]");
    let built = SmtpConfig::new(
        "smtp.example.com".to_string(),
        587,
        SmtpEncryption::Starttls,
        "alice".to_string(),
    );

    assert_eq!(built.host, loaded_smtp.host);
    assert_eq!(built.port, loaded_smtp.port);
    assert_eq!(built.encryption, loaded_smtp.encryption);
    assert_eq!(built.username, loaded_smtp.username);
    assert_eq!(
        built.command_timeout_seconds,
        loaded_smtp.command_timeout_seconds
    );
}

#[test]
fn audit_config_new_matches_loader_defaults() {
    let (_dir, loaded) = loaded_minimal();
    let built = AuditConfig::new(PathBuf::from("/tmp/rusty-imap-mcp-audit.jsonl"));

    assert_eq!(built.path, loaded.audit.path);
    assert_eq!(built.rotate_bytes, loaded.audit.rotate_bytes);
    assert_eq!(built.rotate_keep, loaded.audit.rotate_keep);
    assert_eq!(built.retention_seconds, loaded.audit.retention_seconds);
    assert_eq!(
        built.provenance_window_seconds,
        loaded.audit.provenance_window_seconds
    );
    assert!(!built.fail_open, "fail_open must default closed");
    assert_eq!(built.fail_open, loaded.audit.fail_open);
    assert_eq!(built.allowed_base_dir, loaded.audit.allowed_base_dir);
}

#[test]
fn constructed_values_stay_field_mutable_downstream() {
    // `#[non_exhaustive]` blocks the struct literal, not field access: a
    // downstream caller reaches every non-required field by assignment after
    // `new`, which is why the constructors take no optional parameters.
    let mut imap = ImapConfig::new("imap.example.com".to_string(), 993, "alice".to_string());
    imap.command_timeout_seconds = 5;
    imap.tls_fingerprint_sha256 = Some("ab:cd".to_string());
    assert_eq!(imap.command_timeout_seconds, 5);

    let mut audit = AuditConfig::new(PathBuf::from("/tmp/a.jsonl"));
    audit.fail_open = true;
    assert!(audit.fail_open);
}

#[test]
fn downstream_pattern_match_needs_rest_pattern() {
    let (_dir, loaded) = loaded_minimal();
    // The `..` is mandatory downstream. Without the attribute this compiles
    // either way, so the rest pattern is the visible cost of the change.
    let ImapConfig { host, port, .. } = &loaded.imap;
    assert_eq!(host, "imap.example.com");
    assert_eq!(*port, 993);
}
