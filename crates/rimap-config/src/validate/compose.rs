//! Multi-account composition pipeline. Owns the `ValidatedAccountConfig`
//! and `ValidatedMultiConfig` output types plus the public entry points
//! (`validate_multi`, `validate_multi_allowing_empty`,
//! `validate_legacy_as_multi`) and the per-account orchestrator
//! `validate_account`. Per-field checks live in the sibling modules
//! (`identity`, `limits`, `paths`, `rules`) and are invoked from
//! `validate_account`.

use std::collections::BTreeMap;

use rimap_core::account::AccountId;
use rimap_core::tls::TlsFingerprint;
use rimap_core::tool::ToolName;

use crate::error::ConfigError;
use crate::model::{
    AttachmentsConfig, AuditConfig, Config, FallbackMode, ImapConfig, LimitsConfig,
    MultiAccountConfig, SecurityConfig, SmtpConfig, Verdict,
};

use super::{identity, limits, paths, rules};

/// Validated per-account config with resolved overrides and fingerprint.
#[derive(Debug, Clone)]
pub struct ValidatedAccountConfig {
    /// Account identity.
    pub id: AccountId,
    /// IMAP connection settings.
    pub imap: ImapConfig,
    /// SMTP connection settings (if configured).
    pub smtp: Option<SmtpConfig>,
    /// Security posture and folder lists.
    pub security: SecurityConfig,
    /// Numeric limits.
    pub limits: LimitsConfig,
    /// Resolved per-tool overrides.
    pub tool_overrides: BTreeMap<ToolName, Verdict>,
    /// Parsed pinned TLS fingerprint.
    pub tls_fingerprint: Option<TlsFingerprint>,
    /// Credential fallback policy (see #78).
    pub fallback_mode: FallbackMode,
}

/// Validated multi-account config — the canonical output of config loading.
#[derive(Debug, Clone)]
pub struct ValidatedMultiConfig {
    /// Per-account validated configs, keyed by account id.
    pub accounts: BTreeMap<AccountId, ValidatedAccountConfig>,
    /// Global audit log settings.
    pub audit: AuditConfig,
    /// Global attachment download settings.
    pub attachments: AttachmentsConfig,
}

/// Validate a multi-account config.
///
/// # Errors
/// Returns `ConfigError` on any validation failure.
pub fn validate_multi(config: MultiAccountConfig) -> Result<ValidatedMultiConfig, ConfigError> {
    if config.accounts.is_empty() {
        return Err(ConfigError::NoAccounts);
    }
    validate_multi_inner(config)
}

/// Variant of [`validate_multi`] that skips the empty-accounts
/// rejection. Used exclusively by the wire-conformance harness so the
/// production server can fail-fast on `accounts = []` while tests
/// still spawn an infrastructure-only binary. Gated behind the
/// `test-support` feature.
///
/// # Errors
/// Same surface as [`validate_multi`], minus `ConfigError::NoAccounts`
/// for empty multi-account configs.
#[cfg(feature = "test-support")]
pub fn validate_multi_allowing_empty(
    config: MultiAccountConfig,
) -> Result<ValidatedMultiConfig, ConfigError> {
    validate_multi_inner(config)
}

/// Shared body of [`validate_multi`] and (under `test-support`)
/// [`validate_multi_allowing_empty`]. Performs per-account validation
/// and global path checks; does not enforce the non-empty accounts
/// invariant — callers must do that when required.
fn validate_multi_inner(config: MultiAccountConfig) -> Result<ValidatedMultiConfig, ConfigError> {
    let mut accounts = BTreeMap::new();
    for raw in config.accounts {
        let id = AccountId::new(&raw.name)?;
        if accounts.contains_key(&id) {
            return Err(ConfigError::DuplicateAccountName { name: raw.name });
        }

        let security = raw
            .security
            .unwrap_or_else(|| config.defaults.security.clone());
        let limits = raw.limits.unwrap_or_else(|| config.defaults.limits.clone());
        let fallback_mode = raw
            .credentials
            .map_or(config.defaults.credentials.fallback, |c| c.fallback);

        let validated = validate_account(ValidateAccountInputs {
            id: id.clone(),
            imap: raw.imap,
            smtp: raw.smtp,
            security,
            limits,
            fallback_mode,
        })?;
        accounts.insert(id, validated);
    }

    paths::validate_audit_config(&config.audit)?;
    paths::validate_paths_multi(&config.audit, &config.attachments)?;
    paths::validate_export_download_root(
        &config.attachments,
        export_messages_enabled(accounts.values()),
    )?;

    Ok(ValidatedMultiConfig {
        accounts,
        audit: config.audit,
        attachments: config.attachments,
    })
}

/// Whether `export_messages` is effectively enabled for any account.
///
/// `export_messages` is base-DENY across every posture (see the posture
/// matrix), so it is enabled only when an account carries an explicit
/// `Allow` override in `[security.tools]`. The download root is a global
/// setting, so a single enabled account is enough to require a private
/// root.
fn export_messages_enabled<'a>(accounts: impl Iterator<Item = &'a ValidatedAccountConfig>) -> bool {
    for account in accounts {
        if account.tool_overrides.get(&ToolName::ExportMessages) == Some(&Verdict::Allow) {
            return true;
        }
    }
    false
}

/// Convert a legacy flat config into a `ValidatedMultiConfig` with a
/// single account named "default". Production paths take this route;
/// per-field invariants are exercised through `validate_account` and
/// its callers (`validate_multi`, `validate_legacy_as_multi`).
///
/// # Errors
/// Returns `ConfigError` on any validation failure.
pub fn validate_legacy_as_multi(config: Config) -> Result<ValidatedMultiConfig, ConfigError> {
    let id = AccountId::default_account();
    let account = validate_account(ValidateAccountInputs {
        id: id.clone(),
        imap: config.imap,
        smtp: config.smtp,
        security: config.security,
        limits: config.limits,
        fallback_mode: FallbackMode::default(),
    })?;
    paths::validate_audit_config(&config.audit)?;
    paths::validate_paths_multi(&config.audit, &config.attachments)?;
    paths::validate_export_download_root(
        &config.attachments,
        export_messages_enabled(std::iter::once(&account)),
    )?;

    let mut accounts = BTreeMap::new();
    accounts.insert(id, account);

    Ok(ValidatedMultiConfig {
        accounts,
        audit: config.audit,
        attachments: config.attachments,
    })
}

/// Inputs to [`validate_account`]. Bundles the six per-account fields
/// a caller would otherwise pass positionally, matching the workspace
/// `*Inputs` convention (see `AuditWriter::log_*` family).
struct ValidateAccountInputs {
    id: AccountId,
    imap: ImapConfig,
    smtp: Option<SmtpConfig>,
    security: SecurityConfig,
    limits: LimitsConfig,
    fallback_mode: FallbackMode,
}

/// Validate a single account's worth of config fields.
fn validate_account(inputs: ValidateAccountInputs) -> Result<ValidatedAccountConfig, ConfigError> {
    let ValidateAccountInputs {
        id,
        imap,
        smtp,
        security,
        limits,
        fallback_mode,
    } = inputs;

    let tls_fingerprint = identity::parse_fingerprint(imap.tls_fingerprint_sha256.as_deref())?;
    identity::validate_imap_username(&imap.username)?;
    if let Some(ref smtp_cfg) = smtp {
        identity::validate_smtp_username(&smtp_cfg.username)?;
    }
    limits::validate_limits(&limits)?;
    rules::validate_folder_safety(&security)?;
    let tool_overrides = rules::resolve_tool_overrides(&security)?;
    rules::validate_smtp_required(&security, &tool_overrides, smtp.as_ref())?;
    rules::validate_smtp_encryption(smtp.as_ref())?;

    Ok(ValidatedAccountConfig {
        id,
        imap,
        smtp,
        security,
        limits,
        tool_overrides,
        tls_fingerprint,
        fallback_mode,
    })
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
#[expect(clippy::panic, reason = "tests")]
mod tests {
    use rimap_core::posture::Posture;
    use rimap_core::tool::{ParseToolNameError, ToolName};
    use tempfile::TempDir;

    use crate::error::ConfigError;
    use crate::model::{
        AttachmentsConfig, AuditConfig, Config, CredentialsConfig, FallbackMode, ImapConfig,
        ImapEncryption, LimitsConfig, SecurityConfig, SmtpEncryption, Verdict,
    };
    use crate::validate::{ValidatedAccountConfig, validate_legacy_as_multi};
    use rimap_core::account::AccountId;

    /// Route a legacy flat `Config` through `validate_legacy_as_multi` and
    /// return the resulting default account. Tests exercise per-field
    /// invariants through this path — the multi pipeline subsumes what the
    /// removed single-account `validate()` used to cover.
    fn validate(config: Config) -> Result<ValidatedAccountConfig, ConfigError> {
        let multi = validate_legacy_as_multi(config)?;
        let id = AccountId::default_account();
        Ok(multi.accounts[&id].clone())
    }

    fn base_config(audit_dir: &std::path::Path) -> Config {
        Config {
            imap: ImapConfig {
                host: "127.0.0.1".into(),
                port: 1143,
                username: "alice@example.test".into(),
                encryption: ImapEncryption::Tls,
                tls_fingerprint_sha256: None,
                command_timeout_seconds: 30,
                connect_timeout_seconds: 10,
            },
            smtp: None,
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig {
                path: audit_dir.join("audit.jsonl"),
                rotate_bytes: 10_485_760,
                rotate_keep: 5,
                retention_seconds: None,
                provenance_window_seconds: 60,
                fail_open: false,
                allowed_base_dir: Some(audit_dir.to_path_buf()),
            },
            attachments: AttachmentsConfig::default(),
        }
    }

    #[test]
    fn minimal_valid_config_passes() {
        let dir = TempDir::new().unwrap();
        let cfg = base_config(dir.path());
        let v = validate(cfg).unwrap();
        assert!(v.tool_overrides.is_empty());
    }

    #[test]
    fn override_resolves_v1_tool_name() {
        let dir = TempDir::new().unwrap();
        let mut cfg = base_config(dir.path());
        cfg.security.tools.insert("mark_read".into(), Verdict::Deny);
        cfg.security.tools.insert("search".into(), Verdict::Allow);
        let v = validate(cfg).unwrap();
        assert_eq!(
            v.tool_overrides.get(&ToolName::MarkRead),
            Some(&Verdict::Deny)
        );
        assert_eq!(
            v.tool_overrides.get(&ToolName::Search),
            Some(&Verdict::Allow)
        );
    }

    #[test]
    fn override_unknown_tool_fails() {
        let dir = TempDir::new().unwrap();
        let mut cfg = base_config(dir.path());
        cfg.security
            .tools
            .insert("nuke_inbox".into(), Verdict::Deny);
        let err = validate(cfg).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::ToolOverride(ParseToolNameError::Unknown(_))
        ));
    }

    #[test]
    fn override_v2_tool_resolves_successfully() {
        let dir = TempDir::new().unwrap();
        let mut cfg = base_config(dir.path());
        cfg.security
            .tools
            .insert("delete_message".into(), Verdict::Allow);
        let v = validate(cfg).unwrap();
        assert_eq!(
            v.tool_overrides.get(&ToolName::DeleteMessage),
            Some(&Verdict::Allow)
        );
    }

    #[test]
    fn fingerprint_32_hex_bytes_with_colons_passes() {
        let dir = TempDir::new().unwrap();
        let mut cfg = base_config(dir.path());
        cfg.imap.tls_fingerprint_sha256 = Some(
            "ab:cd:ef:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d"
                .into(),
        );
        validate(cfg).unwrap();
    }

    #[test]
    fn fingerprint_wrong_length_fails() {
        let dir = TempDir::new().unwrap();
        let mut cfg = base_config(dir.path());
        cfg.imap.tls_fingerprint_sha256 = Some("abcd".into());
        let err = validate(cfg).unwrap_err();
        assert!(matches!(err, ConfigError::TlsFingerprint { .. }));
    }

    #[test]
    fn fingerprint_non_hex_fails() {
        let dir = TempDir::new().unwrap();
        let mut cfg = base_config(dir.path());
        cfg.imap.tls_fingerprint_sha256 = Some("z".repeat(64));
        let err = validate(cfg).unwrap_err();
        assert!(matches!(err, ConfigError::TlsFingerprint { .. }));
    }

    #[test]
    fn validate_returns_parsed_tls_fingerprint() {
        let dir = TempDir::new().unwrap();
        let mut cfg = base_config(dir.path());
        cfg.imap.tls_fingerprint_sha256 = Some(
            "0123456789abcdef0123456789abcdef\
             0123456789abcdef0123456789abcdef"
                .to_string(),
        );
        let validated = validate(cfg).unwrap();
        let Some(fp) = validated.tls_fingerprint else {
            panic!("fingerprint should be set");
        };
        assert_eq!(
            fp.to_hex(),
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn validate_returns_none_when_fingerprint_absent() {
        let dir = TempDir::new().unwrap();
        let cfg = base_config(dir.path());
        let validated = validate(cfg).unwrap();
        assert!(validated.tls_fingerprint.is_none());
    }

    #[test]
    fn validate_uses_default_connect_timeout_when_unset() {
        let dir = TempDir::new().unwrap();
        let cfg = base_config(dir.path());
        let validated = validate(cfg).unwrap();
        assert_eq!(validated.imap.connect_timeout_seconds, 10);
    }

    #[test]
    fn zero_commands_per_second_fails() {
        let dir = TempDir::new().unwrap();
        let mut cfg = base_config(dir.path());
        cfg.limits.commands_per_second = 0;
        let err = validate(cfg).unwrap_err();
        match err {
            ConfigError::InvalidLimit { field, .. } => {
                assert_eq!(field, "limits.commands_per_second");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn zero_drafts_per_minute_fails() {
        let dir = TempDir::new().unwrap();
        let mut cfg = base_config(dir.path());
        cfg.limits.drafts_per_minute = 0;
        assert!(matches!(
            validate(cfg).unwrap_err(),
            ConfigError::InvalidLimit {
                field: "limits.drafts_per_minute",
                ..
            }
        ));
    }

    #[test]
    fn max_search_exceeds_cap_fails() {
        let dir = TempDir::new().unwrap();
        let mut cfg = base_config(dir.path());
        cfg.limits.max_search_results = 5000;
        cfg.limits.max_search_results_cap = 1000;
        assert!(matches!(
            validate(cfg).unwrap_err(),
            ConfigError::InvalidLimit {
                field: "limits.max_search_results",
                ..
            }
        ));
    }

    #[test]
    fn missing_audit_parent_dir_fails() {
        let dir = TempDir::new().unwrap();
        let mut cfg = base_config(dir.path());
        // Construct a guaranteed-nonexistent nested path under the tempdir.
        cfg.audit.path = dir.path().join("nope/nested/audit.jsonl");
        let err = validate(cfg).unwrap_err();
        assert!(matches!(err, ConfigError::PathNotWritable { .. }));
    }

    #[test]
    fn audit_path_inside_allowed_base_passes() {
        let dir = TempDir::new().unwrap();
        let cfg = base_config(dir.path());
        validate(cfg).unwrap();
    }

    #[test]
    fn audit_path_outside_allowed_base_fails() {
        let base = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let mut cfg = base_config(outside.path());
        cfg.audit.allowed_base_dir = Some(base.path().to_path_buf());
        let err = validate(cfg).unwrap_err();
        assert!(matches!(err, ConfigError::AuditPathOutsideBase { .. }));
    }

    #[test]
    fn retention_seconds_zero_is_rejected() {
        let dir = TempDir::new().unwrap();
        let mut cfg = base_config(dir.path());
        cfg.audit.retention_seconds = Some(0);
        let err = validate(cfg).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::InvalidLimit {
                field: "audit.retention_seconds",
                ..
            }
        ));
    }

    #[test]
    fn retention_seconds_nonzero_passes() {
        let dir = TempDir::new().unwrap();
        let mut cfg = base_config(dir.path());
        cfg.audit.retention_seconds = Some(3600);
        validate(cfg).unwrap();
    }

    #[test]
    fn smtp_section_parses_from_toml() {
        let toml_str = r#"
[imap]
host = "imap.example.com"
port = 993
username = "alice@example.com"

[smtp]
host = "smtp.example.com"
port = 587
encryption = "starttls"
username = "alice@example.com"

[audit]
path = "/tmp/audit.jsonl"
"#;
        let cfg: Config = toml::from_str(toml_str).unwrap();
        let smtp = cfg.smtp.as_ref().unwrap();
        assert_eq!(smtp.host, "smtp.example.com");
        assert_eq!(smtp.port, 587);
        assert_eq!(smtp.encryption, SmtpEncryption::Starttls);
    }

    #[test]
    fn config_without_smtp_section_is_valid() {
        let dir = TempDir::new().unwrap();
        let cfg = base_config(dir.path());
        assert!(cfg.smtp.is_none());
        validate(cfg).unwrap();
    }

    #[test]
    fn audit_path_with_traversal_segments_is_canonicalized_before_containment() {
        let base = TempDir::new().unwrap();
        let nested = base.path().join("inner");
        std::fs::create_dir_all(&nested).unwrap();
        let mut cfg = base_config(&nested);
        // Path with "../../" attempting to escape to the base's parent:
        cfg.audit.path = nested.join("..").join("..").join("escape.jsonl");
        cfg.audit.allowed_base_dir = Some(nested);
        let err = validate(cfg).unwrap_err();
        assert!(matches!(err, ConfigError::AuditPathOutsideBase { .. }));
    }

    #[test]
    fn smtp_required_when_send_email_enabled_by_posture() {
        let dir = TempDir::new().unwrap();
        let mut cfg = base_config(dir.path());
        cfg.security.posture = Posture::Full;
        let err = validate(cfg).unwrap_err();
        assert!(matches!(err, ConfigError::SmtpRequired { .. }));
    }

    #[test]
    fn smtp_not_required_when_send_email_explicitly_denied() {
        let dir = TempDir::new().unwrap();
        let mut cfg = base_config(dir.path());
        cfg.security.posture = Posture::Full;
        cfg.security
            .tools
            .insert("send_email".into(), Verdict::Deny);
        validate(cfg).unwrap();
    }

    #[test]
    fn smtp_not_required_for_draft_safe_posture() {
        let dir = TempDir::new().unwrap();
        let cfg = base_config(dir.path());
        validate(cfg).unwrap();
    }

    #[test]
    fn conflicting_folders_fails() {
        let dir = TempDir::new().unwrap();
        let mut cfg = base_config(dir.path());
        cfg.security.protected_folders = vec!["Trash".into()];
        cfg.security.expunge_folders = vec!["Trash".into()];
        let err = validate(cfg).unwrap_err();
        assert!(matches!(err, ConfigError::ConflictingFolders { .. }));
    }

    #[test]
    fn non_overlapping_folders_passes() {
        let dir = TempDir::new().unwrap();
        let mut cfg = base_config(dir.path());
        cfg.security.protected_folders = vec!["INBOX".into(), "Sent".into()];
        cfg.security.expunge_folders = vec!["Trash".into()];
        validate(cfg).unwrap();
    }

    #[test]
    fn conflicting_folders_case_insensitive() {
        let dir = TempDir::new().unwrap();
        let mut cfg = base_config(dir.path());
        cfg.security.protected_folders = vec!["trash".into()];
        cfg.security.expunge_folders = vec!["Trash".into()];
        let err = validate(cfg).unwrap_err();
        assert!(matches!(err, ConfigError::ConflictingFolders { .. }));
    }

    #[test]
    fn zero_sends_per_minute_fails() {
        let dir = TempDir::new().unwrap();
        let mut cfg = base_config(dir.path());
        cfg.limits.sends_per_minute = 0;
        assert!(matches!(
            validate(cfg).unwrap_err(),
            ConfigError::InvalidLimit {
                field: "limits.sends_per_minute",
                ..
            }
        ));
    }

    #[test]
    fn smtp_plaintext_rejected_for_remote_host() {
        use crate::model::SmtpConfig;
        let dir = TempDir::new().unwrap();
        let mut cfg = base_config(dir.path());
        cfg.security.posture = Posture::Full;
        cfg.smtp = Some(SmtpConfig {
            host: "smtp.example.com".into(),
            port: 587,
            encryption: SmtpEncryption::None,
            username: "user".into(),
            command_timeout_seconds: 30,
        });
        let result = validate(cfg);
        assert!(
            matches!(result, Err(ConfigError::SmtpPlaintextDenied { .. })),
            "expected SmtpPlaintextDenied, got {result:?}",
        );
    }

    #[test]
    fn smtp_plaintext_allowed_for_localhost() {
        use crate::model::SmtpConfig;
        let dir = TempDir::new().unwrap();
        let mut cfg = base_config(dir.path());
        cfg.security.posture = Posture::Full;
        cfg.smtp = Some(SmtpConfig {
            host: "127.0.0.1".into(),
            port: 1025,
            encryption: SmtpEncryption::None,
            username: "user".into(),
            command_timeout_seconds: 30,
        });
        let result = validate(cfg);
        assert!(
            result.is_ok(),
            "localhost plaintext should be allowed: {result:?}",
        );
    }

    #[test]
    fn smtp_config_debug_redacts_username() {
        use crate::model::{SmtpConfig, SmtpEncryption};
        let cfg = SmtpConfig {
            host: "smtp.example.com".into(),
            port: 587,
            encryption: SmtpEncryption::Starttls,
            username: "secret_user@example.com".into(),
            command_timeout_seconds: 30,
        };
        let debug = format!("{cfg:?}");
        assert!(
            !debug.contains("secret_user"),
            "Debug output must not contain username: {debug}",
        );
    }

    // -----------------------------------------------------------------------
    // Multi-account validation tests
    // -----------------------------------------------------------------------

    use crate::model::{DefaultsConfig, MultiAccountConfig, RawAccountConfig};
    use crate::validate::validate_multi;
    #[cfg(feature = "test-support")]
    use crate::validate::validate_multi_allowing_empty;

    fn base_multi_config(
        audit_dir: &std::path::Path,
        accounts: Vec<RawAccountConfig>,
    ) -> MultiAccountConfig {
        MultiAccountConfig {
            defaults: DefaultsConfig::default(),
            accounts,
            audit: AuditConfig {
                path: audit_dir.join("audit.jsonl"),
                rotate_bytes: 10_485_760,
                rotate_keep: 5,
                retention_seconds: None,
                provenance_window_seconds: 60,
                fail_open: false,
                allowed_base_dir: Some(audit_dir.to_path_buf()),
            },
            attachments: AttachmentsConfig::default(),
        }
    }

    fn raw_account(name: &str) -> RawAccountConfig {
        RawAccountConfig {
            name: name.to_string(),
            imap: ImapConfig {
                host: "127.0.0.1".into(),
                port: 1143,
                username: format!("{name}@example.test"),
                encryption: ImapEncryption::Tls,
                tls_fingerprint_sha256: None,
                command_timeout_seconds: 30,
                connect_timeout_seconds: 10,
            },
            smtp: None,
            security: None,
            limits: None,
            credentials: None,
        }
    }

    #[test]
    fn multi_two_accounts_parsed() {
        let dir = TempDir::new().unwrap();
        let cfg = base_multi_config(
            dir.path(),
            vec![raw_account("work"), raw_account("personal")],
        );
        let v = validate_multi(cfg).unwrap();
        assert_eq!(v.accounts.len(), 2);
        assert!(v.accounts.contains_key(&AccountId::new("work").unwrap()));
        assert!(
            v.accounts
                .contains_key(&AccountId::new("personal").unwrap())
        );
    }

    #[test]
    fn multi_toml_two_accounts() {
        let dir = TempDir::new().unwrap();
        let toml_str = format!(
            r#"
[[accounts]]
name = "work"

[accounts.imap]
host = "imap.work.com"
port = 993
username = "alice@work.com"

[[accounts]]
name = "personal"

[accounts.imap]
host = "imap.personal.com"
port = 993
username = "alice@personal.com"

[audit]
path = "{}/audit.jsonl"
allowed_base_dir = "{}"
"#,
            dir.path().display(),
            dir.path().display(),
        );
        let cfg: MultiAccountConfig = toml::from_str(&toml_str).unwrap();
        let v = validate_multi(cfg).unwrap();
        assert_eq!(v.accounts.len(), 2);
    }

    #[test]
    fn legacy_wraps_as_default_account() {
        let dir = TempDir::new().unwrap();
        let cfg = base_config(dir.path());
        let v = validate_legacy_as_multi(cfg).unwrap();
        assert_eq!(v.accounts.len(), 1);
        let id = AccountId::default_account();
        assert!(v.accounts.contains_key(&id));
        assert_eq!(v.accounts[&id].id, id);
    }

    #[test]
    fn duplicate_account_name_rejected() {
        let dir = TempDir::new().unwrap();
        let cfg = base_multi_config(dir.path(), vec![raw_account("work"), raw_account("work")]);
        let err = validate_multi(cfg).unwrap_err();
        assert!(
            matches!(err, ConfigError::DuplicateAccountName { ref name } if name == "work"),
            "expected DuplicateAccountName, got {err:?}",
        );
    }

    #[test]
    fn case_variant_account_names_collide() {
        // Regression (#75): AccountId normalizes to lowercase, so a config
        // naming both "Work" and "work" is rejected as a duplicate.
        let dir = TempDir::new().unwrap();
        let cfg = base_multi_config(dir.path(), vec![raw_account("Work"), raw_account("work")]);
        let err = validate_multi(cfg).unwrap_err();
        assert!(
            matches!(err, ConfigError::DuplicateAccountName { .. }),
            "expected DuplicateAccountName, got {err:?}",
        );
    }

    #[test]
    fn empty_accounts_array_rejected_by_production_validator() {
        // Production must fail-fast on `accounts = []` so operators
        // immediately see a broken deployment instead of a healthy
        // zero-data server (Codex adversarial review on PR #270).
        let dir = TempDir::new().unwrap();
        let cfg = base_multi_config(dir.path(), vec![]);
        let err = validate_multi(cfg).unwrap_err();
        assert!(
            matches!(err, ConfigError::NoAccounts),
            "expected ConfigError::NoAccounts, got {err:?}",
        );
    }

    #[cfg(feature = "test-support")]
    #[test]
    fn empty_accounts_array_validates_under_test_support() {
        // Mirror of the previous task's intent, now routed through the
        // test-only relaxed validator. The wire-conformance harness
        // depends on this path to spawn the binary with `accounts = []`
        // (Codex review on PR #270).
        let dir = TempDir::new().unwrap();
        let cfg = base_multi_config(dir.path(), vec![]);
        let validated = validate_multi_allowing_empty(cfg).unwrap();
        assert!(validated.accounts.is_empty());
    }

    #[test]
    fn invalid_account_name_rejected() {
        let dir = TempDir::new().unwrap();
        let cfg = base_multi_config(dir.path(), vec![raw_account("bad name")]);
        let err = validate_multi(cfg).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidAccountName(_)));
    }

    #[test]
    fn multi_fallback_defaults_to_keyring_then_env() {
        let dir = TempDir::new().unwrap();
        let cfg = base_multi_config(dir.path(), vec![raw_account("work")]);
        let v = validate_multi(cfg).unwrap();
        let acct = &v.accounts[&AccountId::new("work").unwrap()];
        assert_eq!(acct.fallback_mode, FallbackMode::KeyringThenEnv);
    }

    #[test]
    fn multi_account_inherits_defaults_fallback() {
        let dir = TempDir::new().unwrap();
        let mut cfg = base_multi_config(dir.path(), vec![raw_account("work")]);
        cfg.defaults.credentials.fallback = FallbackMode::KeyringOnly;
        let v = validate_multi(cfg).unwrap();
        let acct = &v.accounts[&AccountId::new("work").unwrap()];
        assert_eq!(acct.fallback_mode, FallbackMode::KeyringOnly);
    }

    #[test]
    fn multi_account_override_beats_defaults_fallback() {
        let dir = TempDir::new().unwrap();
        let mut acct = raw_account("work");
        acct.credentials = Some(CredentialsConfig {
            fallback: FallbackMode::KeyringOnly,
        });
        let mut cfg = base_multi_config(dir.path(), vec![acct]);
        cfg.defaults.credentials.fallback = FallbackMode::KeyringThenEnv;
        let v = validate_multi(cfg).unwrap();
        let validated = &v.accounts[&AccountId::new("work").unwrap()];
        assert_eq!(validated.fallback_mode, FallbackMode::KeyringOnly);
    }

    #[test]
    fn legacy_fallback_defaults_to_keyring_then_env() {
        let dir = TempDir::new().unwrap();
        let cfg = base_config(dir.path());
        let v = validate_legacy_as_multi(cfg).unwrap();
        let id = AccountId::default_account();
        assert_eq!(v.accounts[&id].fallback_mode, FallbackMode::KeyringThenEnv);
    }

    #[test]
    fn defaults_inherited_when_account_omits() {
        let dir = TempDir::new().unwrap();
        let mut cfg = base_multi_config(dir.path(), vec![raw_account("work")]);
        cfg.defaults.limits.commands_per_second = 42;
        cfg.defaults.security.posture = Posture::Readonly;
        let v = validate_multi(cfg).unwrap();
        let acct = &v.accounts[&AccountId::new("work").unwrap()];
        assert_eq!(acct.limits.commands_per_second, 42);
        assert_eq!(acct.security.posture, Posture::Readonly);
    }

    #[test]
    fn account_overrides_defaults() {
        let dir = TempDir::new().unwrap();
        let mut acct = raw_account("work");
        acct.limits = Some(LimitsConfig {
            commands_per_second: 99,
            ..LimitsConfig::default()
        });
        let mut cfg = base_multi_config(dir.path(), vec![acct]);
        cfg.defaults.limits.commands_per_second = 42;
        let v = validate_multi(cfg).unwrap();
        let validated_acct = &v.accounts[&AccountId::new("work").unwrap()];
        assert_eq!(validated_acct.limits.commands_per_second, 99);
    }

    #[test]
    fn per_account_smtp_required_still_works() {
        let dir = TempDir::new().unwrap();
        let mut acct = raw_account("work");
        acct.security = Some(SecurityConfig {
            posture: Posture::Full,
            ..SecurityConfig::default()
        });
        let cfg = base_multi_config(dir.path(), vec![acct]);
        let err = validate_multi(cfg).unwrap_err();
        assert!(matches!(err, ConfigError::SmtpRequired { .. }));
    }

    #[test]
    fn per_account_conflicting_folders_still_works() {
        let dir = TempDir::new().unwrap();
        let mut acct = raw_account("work");
        acct.security = Some(SecurityConfig {
            protected_folders: vec!["Trash".into()],
            expunge_folders: vec!["Trash".into()],
            ..SecurityConfig::default()
        });
        let cfg = base_multi_config(dir.path(), vec![acct]);
        let err = validate_multi(cfg).unwrap_err();
        assert!(matches!(err, ConfigError::ConflictingFolders { .. }));
    }

    // -----------------------------------------------------------------------
    // Username validation tests (CR/LF/NUL rejection)
    // -----------------------------------------------------------------------

    use crate::validate::identity::{validate_imap_username, validate_smtp_username};

    #[test]
    fn username_with_crlf_rejected() {
        assert!(validate_imap_username("a@b\r\nX-Injected: 1").is_err());
    }

    #[test]
    fn username_with_cr_rejected() {
        assert!(validate_imap_username("a@b\rX").is_err());
    }

    #[test]
    fn username_with_lf_rejected() {
        assert!(validate_imap_username("a@b\nX").is_err());
    }

    #[test]
    fn username_with_null_rejected() {
        assert!(validate_imap_username("a@b\0c").is_err());
    }

    #[test]
    fn normal_username_accepted() {
        assert!(validate_imap_username("user@example.com").is_ok());
    }

    #[test]
    fn empty_username_rejected() {
        assert!(validate_imap_username("").is_err());
    }

    #[test]
    fn smtp_username_crlf_rejected() {
        assert!(validate_smtp_username("a@b\r\nX-Injected: 1").is_err());
    }

    #[test]
    fn smtp_username_normal_accepted() {
        assert!(validate_smtp_username("user@example.com").is_ok());
    }

    #[test]
    fn validate_multi_rejects_crlf_username() {
        let dir = TempDir::new().unwrap();
        let mut acct = raw_account("work");
        acct.imap.username = "a@b\r\nX-Injected: 1".into();
        let cfg = base_multi_config(dir.path(), vec![acct]);
        let err = validate_multi(cfg).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::InvalidLimit {
                field: "imap.username",
                ..
            }
        ));
    }

    // -----------------------------------------------------------------------
    // export_messages private-download-root enforcement (Unix only)
    // -----------------------------------------------------------------------

    #[cfg(unix)]
    fn set_mode(path: &std::path::Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn export_messages_enabled_with_world_writable_root_fails() {
        let audit_dir = TempDir::new().unwrap();
        let download_dir = TempDir::new().unwrap();
        set_mode(download_dir.path(), 0o777);

        let mut cfg = base_config(audit_dir.path());
        cfg.attachments = AttachmentsConfig {
            download_dir: download_dir.path().to_string_lossy().into_owned(),
        };
        cfg.security
            .tools
            .insert("export_messages".into(), Verdict::Allow);

        let err = validate(cfg).unwrap_err();
        let ConfigError::PathNotWritable { reason, .. } = &err else {
            panic!("expected PathNotWritable, got {err:?}");
        };
        assert!(reason.contains("group/world-writable"), "reason: {reason}");
    }

    #[cfg(unix)]
    #[test]
    fn export_messages_enabled_with_private_root_passes() {
        let audit_dir = TempDir::new().unwrap();
        let download_dir = TempDir::new().unwrap();
        set_mode(download_dir.path(), 0o700);

        let mut cfg = base_config(audit_dir.path());
        cfg.attachments = AttachmentsConfig {
            download_dir: download_dir.path().to_string_lossy().into_owned(),
        };
        cfg.security
            .tools
            .insert("export_messages".into(), Verdict::Allow);

        validate(cfg).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn export_messages_disabled_does_not_check_world_writable_root() {
        let audit_dir = TempDir::new().unwrap();
        let download_dir = TempDir::new().unwrap();
        set_mode(download_dir.path(), 0o777);

        let mut cfg = base_config(audit_dir.path());
        cfg.attachments = AttachmentsConfig {
            download_dir: download_dir.path().to_string_lossy().into_owned(),
        };

        validate(cfg).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn multi_account_export_messages_enabled_with_world_writable_root_fails() {
        // Drives the multi-account entry point (`validate_multi` ->
        // `validate_multi_inner`) so the export private-root check stays
        // wired to that path, not just the legacy wrapper.
        let audit_dir = TempDir::new().unwrap();
        let download_dir = TempDir::new().unwrap();
        set_mode(download_dir.path(), 0o777);

        let mut exporter = raw_account("work");
        let mut tools = std::collections::BTreeMap::new();
        tools.insert("export_messages".into(), Verdict::Allow);
        exporter.security = Some(SecurityConfig {
            tools,
            ..SecurityConfig::default()
        });

        let mut cfg = base_multi_config(audit_dir.path(), vec![exporter, raw_account("personal")]);
        cfg.attachments = AttachmentsConfig {
            download_dir: download_dir.path().to_string_lossy().into_owned(),
        };

        let err = validate_multi(cfg).unwrap_err();
        let ConfigError::PathNotWritable { reason, .. } = &err else {
            panic!("expected PathNotWritable, got {err:?}");
        };
        assert!(reason.contains("group/world-writable"), "reason: {reason}");
    }
}
