//! Multi-account composition pipeline. Owns the `ValidatedAccountConfig`
//! and `ValidatedMultiConfig` output types plus the public entry points
//! (`validate_multi`, `validate_multi_allowing_empty`,
//! `validate_legacy_as_multi`) and the per-account orchestrator
//! `validate_account`. Per-field checks live in the sibling modules
//! (`identity`, `limits`, `paths`, `rules`) and are invoked from
//! `validate_account`.

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr as _;

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
///
/// `#[non_exhaustive]`: adding a field here is additive, not a breaking
/// change (#707). Downstream crates cannot write a struct expression for
/// this type — including functional-update syntax, which rustc rejects
/// with E0639 — so a value is obtained from [`validate_multi`] /
/// [`validate_legacy_as_multi`] and adjusted by field assignment.
#[derive(Debug, Clone)]
#[non_exhaustive]
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
    /// The subset of [`Self::tool_overrides`] this account wrote itself, in
    /// its own `[accounts.security.tools]` block. Every other key of
    /// `tool_overrides` was inherited from `[defaults.security.tools]`.
    ///
    /// Kept beside the merged map because
    /// [`AccountSecurityOverrides::merge_onto`](crate::model::AccountSecurityOverrides::merge_onto)
    /// folds both layers into one map and nothing downstream can recover
    /// which layer wrote a given key. That distinction is what the
    /// boot-time tool-matrix log and audit record report (#632) — an
    /// inherited `allow` on an account the operator tightened to
    /// `posture = "readonly"` is the case worth seeing.
    pub account_written_tools: BTreeSet<ToolName>,
    /// Whether the account's own `[accounts.security]` block wrote
    /// `protected_folders`. `false` means the list reached it from
    /// `[defaults.security]` or, when neither layer names it, from the
    /// built-in default.
    ///
    /// A bool rather than a key set: unlike `[security.tools]`, the folder
    /// lists merge whole-list — an account that writes `protected_folders`
    /// replaces the inherited list outright
    /// ([`AccountSecurityOverrides::merge_onto`](crate::model::AccountSecurityOverrides::merge_onto))
    /// — so the layer is a property of the list, not of its entries.
    /// Recorded and printed by the boot folder-policy path (#696).
    pub account_written_protected_folders: bool,
    /// Whether the account's own `[accounts.security]` block wrote
    /// `expunge_folders`. Same semantics as
    /// [`Self::account_written_protected_folders`], and the one that
    /// matters most: a `false` here on a non-empty list is the #624
    /// widening that makes a folder expungeable that was not before.
    pub account_written_expunge_folders: bool,
    /// Parsed pinned TLS fingerprint.
    pub tls_fingerprint: Option<TlsFingerprint>,
    /// Credential fallback policy (see #78).
    pub fallback_mode: FallbackMode,
}

/// Validated multi-account config — the canonical output of config loading.
///
/// `#[non_exhaustive]` for the same reason as [`ValidatedAccountConfig`]
/// (#707): the field set is expected to grow, and no downstream crate
/// should be able to mint a "validated" config that never ran through
/// [`validate_multi`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ValidatedMultiConfig {
    /// Per-account validated configs, keyed by account id.
    pub accounts: BTreeMap<AccountId, ValidatedAccountConfig>,
    /// Global audit log settings.
    pub audit: AuditConfig,
    /// Global attachment download settings.
    pub attachments: AttachmentsConfig,
}

/// Test fixture for [`ValidatedAccountConfig`].
///
/// Gated behind `test-support` on purpose, as is the sibling fixture on
/// [`ValidatedMultiConfig`]. In production these types are obtainable
/// only from the validation entry points, which is what makes
/// "validated" mean something; the gate keeps that true while still
/// letting downstream test code build a fixture without a config file
/// and a filesystem probe. Same rationale and same gate as
/// [`validate_multi_allowing_empty`].
#[cfg(feature = "test-support")]
impl ValidatedAccountConfig {
    /// Build a fixture account from the two fields that have no
    /// meaningful default. Every remaining field starts at its own
    /// default (no SMTP, default posture and limits, no overrides, no
    /// pinned fingerprint); fields are `pub`, so a caller adjusts what
    /// it cares about by assignment.
    #[must_use]
    pub fn new_for_tests(id: AccountId, imap: ImapConfig) -> Self {
        Self {
            id,
            imap,
            smtp: None,
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            tool_overrides: BTreeMap::new(),
            account_written_tools: BTreeSet::new(),
            // The fixture's `security` is `SecurityConfig::default()`, which
            // no account block wrote — so `false` is the accurate answer,
            // not merely the convenient one.
            account_written_protected_folders: false,
            account_written_expunge_folders: false,
            tls_fingerprint: None,
            fallback_mode: FallbackMode::default(),
        }
    }
}

/// Test fixture for [`ValidatedMultiConfig`] — same gate and same
/// rationale as the [`ValidatedAccountConfig`] fixture above.
#[cfg(feature = "test-support")]
impl ValidatedMultiConfig {
    /// Build a fixture multi-account config with no accounts. `audit`
    /// and `attachments` are required because neither has a default that
    /// is safe to invent — an audit path in particular is what the
    /// writer opens. Add accounts by assigning to
    /// [`Self::accounts`].
    #[must_use]
    pub fn new_for_tests(audit: AuditConfig, attachments: AttachmentsConfig) -> Self {
        Self {
            accounts: BTreeMap::new(),
            audit,
            attachments,
        }
    }
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

        // Per-field merge, not wholesale replacement: an account that writes
        // one key of `[accounts.limits]` inherits every other key from
        // `[defaults.limits]` rather than reverting it to the built-in
        // default (#624, ADR-0013). Same for `[accounts.security]` and
        // `[accounts.credentials]`.
        // Captured before the merge consumes `raw.security`: once
        // `merge_onto` has run, the account's own keys are indistinguishable
        // from the inherited ones (#632).
        let account_written_tool_keys: BTreeSet<String> = raw
            .security
            .as_ref()
            .and_then(|overrides| overrides.tools.as_ref())
            .map(|tools| tools.keys().cloned().collect())
            .unwrap_or_default();
        // Same reason, same timing: the folder lists replace whole-list, so
        // after the merge a resolved list cannot say which layer wrote it
        // (#696).
        let account_written_protected_folders = raw
            .security
            .as_ref()
            .is_some_and(|overrides| overrides.protected_folders.is_some());
        let account_written_expunge_folders = raw
            .security
            .as_ref()
            .is_some_and(|overrides| overrides.expunge_folders.is_some());
        let security = raw.security.map_or_else(
            || config.defaults.security.clone(),
            |overrides| overrides.merge_onto(config.defaults.security.clone()),
        );
        let limits = raw.limits.map_or_else(
            || config.defaults.limits.clone(),
            |overrides| overrides.merge_onto(config.defaults.limits.clone()),
        );
        let credentials = raw.credentials.map_or(config.defaults.credentials, |o| {
            o.merge_onto(config.defaults.credentials)
        });
        let fallback_mode = credentials.fallback;

        let validated = validate_account(ValidateAccountInputs {
            id: id.clone(),
            imap: raw.imap,
            smtp: raw.smtp,
            security,
            limits,
            fallback_mode,
            account_written_tool_keys,
            account_written_protected_folders,
            account_written_expunge_folders,
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
    // A flat config has no `[defaults]` layer, so every `[security.tools]`
    // key belongs to the sole account by construction.
    let account_written_tool_keys: BTreeSet<String> =
        config.security.tools.keys().cloned().collect();
    let account = validate_account(ValidateAccountInputs {
        id: id.clone(),
        imap: config.imap,
        smtp: config.smtp,
        security: config.security,
        limits: config.limits,
        fallback_mode: FallbackMode::default(),
        account_written_tool_keys,
        // Likewise for the folder lists: with no `[defaults]` layer there is
        // nothing for the sole account to have inherited them *from*, so
        // reporting them as inherited would send an operator looking for a
        // `[defaults.security]` block that does not exist (#696).
        account_written_protected_folders: true,
        account_written_expunge_folders: true,
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

/// Inputs to [`validate_account`]. Bundles the per-account fields a caller
/// would otherwise pass positionally, matching the workspace `*Inputs`
/// convention (see `AuditWriter::log_*` family).
struct ValidateAccountInputs {
    id: AccountId,
    imap: ImapConfig,
    smtp: Option<SmtpConfig>,
    security: SecurityConfig,
    limits: LimitsConfig,
    fallback_mode: FallbackMode,
    /// Raw `[accounts.security.tools]` keys this account wrote itself, as
    /// observed before the merge with `[defaults.security.tools]`. Resolved
    /// to [`ToolName`] alongside the merged map.
    account_written_tool_keys: BTreeSet<String>,
    /// Whether `[accounts.security] protected_folders` was written by this
    /// account, observed before the merge erased the distinction.
    account_written_protected_folders: bool,
    /// Whether `[accounts.security] expunge_folders` was written by this
    /// account, observed before the merge erased the distinction.
    account_written_expunge_folders: bool,
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
        account_written_tool_keys,
        account_written_protected_folders,
        account_written_expunge_folders,
    } = inputs;

    let tls_fingerprint = identity::parse_fingerprint(imap.tls_fingerprint_sha256.as_deref())?;
    identity::validate_imap_username(&imap.username)?;
    if let Some(ref smtp_cfg) = smtp {
        identity::validate_smtp_username(&smtp_cfg.username)?;
    }
    limits::validate_timeouts(&imap, smtp.as_ref())?;
    limits::validate_limits(&limits)?;
    limits::validate_tool_call_ceiling(&imap, smtp.as_ref(), &limits)?;
    rules::validate_folder_safety(&security)?;
    let tool_overrides = rules::resolve_tool_overrides(&security)?;
    // These keys are a subset of the merged map `resolve_tool_overrides`
    // just accepted, so the parse cannot introduce a new failure; resolving
    // them here rather than matching on `ToolName::as_str` keeps the two
    // maps keyed identically whatever spellings `from_str` accepts.
    let account_written_tools = account_written_tool_keys
        .iter()
        .map(|name| ToolName::from_str(name))
        .collect::<Result<BTreeSet<_>, _>>()?;
    rules::validate_smtp_required(&security, &tool_overrides, smtp.as_ref())?;
    rules::validate_smtp_encryption(smtp.as_ref())?;

    Ok(ValidatedAccountConfig {
        id,
        imap,
        smtp,
        security,
        limits,
        tool_overrides,
        account_written_tools,
        account_written_protected_folders,
        account_written_expunge_folders,
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
        AttachmentsConfig, AuditConfig, Config, FallbackMode, ImapConfig, ImapEncryption,
        LimitsConfig, SecurityConfig, SmtpEncryption, Verdict,
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
                write_deadline_seconds: 15,
                path: audit_dir.join("audit.jsonl"),
                rotate_bytes: 10_485_760,
                rotate_keep: 5,
                retention_seconds: None,
                provenance_window_seconds: 60,
                write_deadline_seconds: 15,
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
    fn flat_config_tool_overrides_are_all_account_written() {
        // A flat config has no `[defaults]` layer to inherit from, so the
        // sole account owns every key it declares (#632).
        let dir = TempDir::new().unwrap();
        let mut cfg = base_config(dir.path());
        cfg.security
            .tools
            .insert("delete_message".into(), Verdict::Allow);
        let v = validate(cfg).unwrap();
        assert_eq!(
            v.account_written_tools.iter().copied().collect::<Vec<_>>(),
            vec![ToolName::DeleteMessage],
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
    fn zero_imap_connect_timeout_fails() {
        let dir = TempDir::new().unwrap();
        let mut cfg = base_config(dir.path());
        cfg.imap.connect_timeout_seconds = 0;
        assert!(matches!(
            validate(cfg).unwrap_err(),
            ConfigError::InvalidLimit {
                field: "imap.connect_timeout_seconds",
                ..
            }
        ));
    }

    #[test]
    fn zero_imap_command_timeout_fails() {
        let dir = TempDir::new().unwrap();
        let mut cfg = base_config(dir.path());
        cfg.imap.command_timeout_seconds = 0;
        assert!(matches!(
            validate(cfg).unwrap_err(),
            ConfigError::InvalidLimit {
                field: "imap.command_timeout_seconds",
                ..
            }
        ));
    }

    #[test]
    fn zero_smtp_command_timeout_fails() {
        use crate::model::SmtpConfig;
        let dir = TempDir::new().unwrap();
        let mut cfg = base_config(dir.path());
        cfg.smtp = Some(SmtpConfig {
            host: "127.0.0.1".into(),
            port: 1025,
            encryption: SmtpEncryption::Starttls,
            username: "user".into(),
            command_timeout_seconds: 0,
        });
        assert!(matches!(
            validate(cfg).unwrap_err(),
            ConfigError::InvalidLimit {
                field: "smtp.command_timeout_seconds",
                ..
            }
        ));
    }

    #[test]
    fn multi_account_zero_connect_timeout_fails() {
        let dir = TempDir::new().unwrap();
        let mut acct = raw_account("work");
        acct.imap.connect_timeout_seconds = 0;
        let cfg = base_multi_config(dir.path(), vec![acct]);
        assert!(matches!(
            validate_multi(cfg).unwrap_err(),
            ConfigError::InvalidLimit {
                field: "imap.connect_timeout_seconds",
                ..
            }
        ));
    }

    #[test]
    fn tool_call_ceiling_below_imap_worst_case_fails() {
        // The ceiling check spans `[imap]` and `[limits]`, so it can only be
        // wired at the per-account composition point — this drives it from
        // there rather than from the unit under `validate::limits` (#594).
        let dir = TempDir::new().unwrap();
        let mut cfg = base_config(dir.path());
        cfg.limits.tool_call_timeout_seconds = 139; // worst case is 140
        assert!(matches!(
            validate(cfg).unwrap_err(),
            ConfigError::InvalidLimit {
                field: "limits.tool_call_timeout_seconds",
                ..
            }
        ));
    }

    #[test]
    fn multi_account_inherited_ceiling_checked_against_account_imap_budgets() {
        // `[defaults.limits]` inheritance must be validated against the
        // *account's* IMAP budgets, not the defaults' — an account that
        // raises `command_timeout_seconds` past what the inherited ceiling
        // covers is rejected.
        let dir = TempDir::new().unwrap();
        let mut acct = raw_account("work");
        acct.imap.command_timeout_seconds = 200; // worst case 2 x (400 + 10) = 820
        let cfg = base_multi_config(dir.path(), vec![acct]);
        assert!(matches!(
            validate_multi(cfg).unwrap_err(),
            ConfigError::InvalidLimit {
                field: "limits.tool_call_timeout_seconds",
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
    fn smtp_required_by_override_on_readonly_posture_names_the_override() {
        // Regression (#327): a readonly posture with an explicit
        // `send_email = "allow"` override requires SMTP, and the diagnostic
        // must blame the override rather than the (non-enabling) posture.
        let dir = TempDir::new().unwrap();
        let mut cfg = base_config(dir.path());
        cfg.security.posture = Posture::Readonly;
        cfg.security
            .tools
            .insert("send_email".into(), Verdict::Allow);
        let err = validate(cfg).unwrap_err();
        assert!(
            matches!(err, ConfigError::SmtpRequiredByOverride { posture } if posture == Posture::Readonly),
            "expected SmtpRequiredByOverride, got {err:?}",
        );
        let msg = err.to_string();
        assert!(msg.contains("override"), "message: {msg}");
        assert!(msg.contains("readonly"), "message: {msg}");
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

    use crate::model::{
        AccountCredentialsOverrides, AccountLimitsOverrides, AccountSecurityOverrides,
        DefaultsConfig, MultiAccountConfig, RawAccountConfig,
    };
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
                write_deadline_seconds: 15,
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
        acct.credentials = Some(AccountCredentialsOverrides {
            fallback: Some(FallbackMode::KeyringOnly),
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
        acct.limits = Some(AccountLimitsOverrides {
            commands_per_second: Some(99),
            ..AccountLimitsOverrides::default()
        });
        let mut cfg = base_multi_config(dir.path(), vec![acct]);
        cfg.defaults.limits.commands_per_second = 42;
        let v = validate_multi(cfg).unwrap();
        let validated_acct = &v.accounts[&AccountId::new("work").unwrap()];
        assert_eq!(validated_acct.limits.commands_per_second, 99);
    }

    // -----------------------------------------------------------------------
    // Per-field `[defaults]` merge (#624)
    //
    // Driven from TOML rather than from constructed structs: the defect is
    // that deserialization erases "key absent" vs "key set to the built-in
    // default", so only a real parse can distinguish the two.
    // -----------------------------------------------------------------------

    /// Build a multi-account TOML document with the given `[defaults]` and
    /// `[[accounts]]` bodies, wiring `[audit]` at `dir`.
    fn multi_toml(dir: &std::path::Path, defaults: &str, account: &str) -> MultiAccountConfig {
        let doc = format!(
            r#"
{defaults}

[[accounts]]
name = "work"

[accounts.imap]
host = "imap.work.test"
port = 993
username = "alice@work.test"

{account}

[audit]
path = "{audit}/audit.jsonl"
allowed_base_dir = "{base}"
"#,
            audit = dir.display(),
            base = dir.display(),
        );
        toml::from_str(&doc).unwrap()
    }

    /// Validate `cfg` and return the "work" account.
    fn work_account(cfg: MultiAccountConfig) -> ValidatedAccountConfig {
        let v = validate_multi(cfg).unwrap();
        v.accounts[&AccountId::new("work").unwrap()].clone()
    }

    #[test]
    fn partial_account_limits_inherits_unset_defaults() {
        // The reproduction from #624: an account setting one limits field for
        // an unrelated reason must not revert the rest to the built-in
        // defaults.
        let dir = TempDir::new().unwrap();
        let cfg = multi_toml(
            dir.path(),
            r"
[defaults.limits]
tool_call_timeout_seconds = 600
commands_per_second = 25
",
            r"
[accounts.limits]
max_search_results = 50
",
        );
        let acct = work_account(cfg);
        assert_eq!(acct.limits.max_search_results, 50, "account's own value");
        assert_eq!(acct.limits.tool_call_timeout_seconds, 600, "inherited");
        assert_eq!(acct.limits.commands_per_second, 25, "inherited");
    }

    #[test]
    fn partial_account_security_inherits_unset_defaults() {
        // The security flavour: tightening one field must not silently drop
        // the deployment-wide protected-folder list.
        let dir = TempDir::new().unwrap();
        let cfg = multi_toml(
            dir.path(),
            r#"
[defaults.security]
posture = "draft-safe"
protected_folders = ["INBOX", "Sent", "Archive"]
"#,
            r#"
[accounts.security]
posture = "readonly"
"#,
        );
        let acct = work_account(cfg);
        assert_eq!(acct.security.posture, Posture::Readonly, "account's own");
        assert_eq!(
            acct.security.protected_folders,
            vec![
                "INBOX".to_string(),
                "Sent".to_string(),
                "Archive".to_string()
            ],
            "inherited",
        );
    }

    #[test]
    fn empty_account_limits_table_inherits_every_default() {
        let dir = TempDir::new().unwrap();
        let cfg = multi_toml(
            dir.path(),
            r"
[defaults.limits]
commands_per_second = 25
drafts_per_minute = 9
",
            "[accounts.limits]",
        );
        let acct = work_account(cfg);
        assert_eq!(acct.limits.commands_per_second, 25);
        assert_eq!(acct.limits.drafts_per_minute, 9);
    }

    #[test]
    fn empty_account_security_table_inherits_every_default() {
        let dir = TempDir::new().unwrap();
        let cfg = multi_toml(
            dir.path(),
            r#"
[defaults.security]
posture = "readonly"
expunge_folders = ["Junk"]
"#,
            "[accounts.security]",
        );
        let acct = work_account(cfg);
        assert_eq!(acct.security.posture, Posture::Readonly);
        assert_eq!(acct.security.expunge_folders, vec!["Junk".to_string()]);
    }

    #[test]
    fn account_limits_override_beats_defaults_for_each_written_key() {
        // The all-keys-written case still overrides — the merge must not
        // resurrect a default the account explicitly restated.
        let dir = TempDir::new().unwrap();
        let cfg = multi_toml(
            dir.path(),
            r"
[defaults.limits]
commands_per_second = 25
drafts_per_minute = 9
",
            r"
[accounts.limits]
commands_per_second = 7
drafts_per_minute = 3
",
        );
        let acct = work_account(cfg);
        assert_eq!(acct.limits.commands_per_second, 7);
        assert_eq!(acct.limits.drafts_per_minute, 3);
    }

    #[test]
    fn account_value_equal_to_the_serde_default_still_overrides_defaults() {
        // The invariant the mirror structs exist for. `commands_per_second`
        // and `drafts_per_minute` are written here at exactly their built-in
        // serde defaults (10 and 5) while `[defaults.limits]` sets 25 and 9.
        // "Written by the operator" and "filled in by serde" are the same
        // bytes in the concrete struct, so a merge that inspected values
        // rather than presence would hand this account 25 and 9 — the
        // operator asked for the stock rate on this account and would
        // silently get the deployment's.
        let dir = TempDir::new().unwrap();
        let cfg = multi_toml(
            dir.path(),
            r"
[defaults.limits]
commands_per_second = 25
drafts_per_minute = 9
",
            r"
[accounts.limits]
commands_per_second = 10
drafts_per_minute = 5
",
        );
        let acct = work_account(cfg);
        assert_eq!(
            acct.limits.commands_per_second,
            LimitsConfig::default().commands_per_second,
            "explicit value equal to the serde default must win over defaults",
        );
        assert_eq!(
            acct.limits.drafts_per_minute,
            LimitsConfig::default().drafts_per_minute,
        );
    }

    #[test]
    fn account_posture_equal_to_the_serde_default_still_overrides_defaults() {
        // Same invariant on the security side: `draft-safe` is
        // `Posture::default()`, so writing it explicitly must beat an
        // inherited `readonly` rather than reading as "unset".
        let dir = TempDir::new().unwrap();
        let cfg = multi_toml(
            dir.path(),
            r#"
[defaults.security]
posture = "readonly"
"#,
            r#"
[accounts.security]
posture = "draft-safe"
"#,
        );
        let acct = work_account(cfg);
        assert_eq!(acct.security.posture, Posture::default());
        assert_eq!(acct.security.posture, Posture::DraftSafe);
    }

    #[test]
    fn account_tool_overrides_merge_per_key_with_defaults() {
        // `docs/multi-account.md` documents per-key inheritance for
        // `[security.tools]`. A default `deny` must survive an account that
        // allows an unrelated tool.
        let dir = TempDir::new().unwrap();
        let cfg = multi_toml(
            dir.path(),
            r#"
[defaults.security.tools]
mark_read = "deny"
"#,
            r#"
[accounts.security.tools]
search = "allow"
"#,
        );
        let acct = work_account(cfg);
        assert_eq!(
            acct.tool_overrides.get(&ToolName::MarkRead),
            Some(&Verdict::Deny),
            "inherited",
        );
        assert_eq!(
            acct.tool_overrides.get(&ToolName::Search),
            Some(&Verdict::Allow),
            "account's own",
        );
    }

    #[test]
    fn account_written_tools_names_only_the_accounts_own_keys() {
        // #632: the merged map cannot say which layer wrote a key, so
        // composition records the account's own key set alongside it.
        let dir = TempDir::new().unwrap();
        let cfg = multi_toml(
            dir.path(),
            r#"
[defaults.security.tools]
delete_message = "allow"
"#,
            r#"
[accounts.security]
posture = "readonly"

[accounts.security.tools]
search = "deny"
"#,
        );
        let acct = work_account(cfg);
        assert_eq!(acct.security.posture, Posture::Readonly);
        assert!(
            acct.account_written_tools.contains(&ToolName::Search),
            "search is written in [accounts.security.tools]",
        );
        assert!(
            !acct
                .account_written_tools
                .contains(&ToolName::DeleteMessage),
            "delete_message is inherited from [defaults.security.tools]",
        );
        // Both still reach the effective override map.
        assert_eq!(
            acct.tool_overrides.get(&ToolName::DeleteMessage),
            Some(&Verdict::Allow),
        );
    }

    #[test]
    fn restating_an_inherited_verdict_counts_as_account_written() {
        // An account that writes the same verdict the default already had
        // still wrote it: the operator made that choice locally.
        let dir = TempDir::new().unwrap();
        let cfg = multi_toml(
            dir.path(),
            r#"
[defaults.security.tools]
mark_read = "deny"
"#,
            r#"
[accounts.security.tools]
mark_read = "deny"
"#,
        );
        let acct = work_account(cfg);
        assert!(acct.account_written_tools.contains(&ToolName::MarkRead));
    }

    #[test]
    fn account_with_no_tools_block_writes_no_tools() {
        let dir = TempDir::new().unwrap();
        let cfg = multi_toml(
            dir.path(),
            r#"
[defaults.security.tools]
mark_read = "deny"
"#,
            r#"
[accounts.security]
posture = "readonly"
"#,
        );
        let acct = work_account(cfg);
        assert!(acct.account_written_tools.is_empty());
        assert_eq!(
            acct.tool_overrides.get(&ToolName::MarkRead),
            Some(&Verdict::Deny),
        );
    }

    #[test]
    fn account_tool_override_replaces_default_verdict_for_same_tool() {
        let dir = TempDir::new().unwrap();
        let cfg = multi_toml(
            dir.path(),
            r#"
[defaults.security.tools]
mark_read = "deny"
"#,
            r#"
[accounts.security.tools]
mark_read = "allow"
"#,
        );
        let acct = work_account(cfg);
        assert_eq!(
            acct.tool_overrides.get(&ToolName::MarkRead),
            Some(&Verdict::Allow),
        );
    }

    #[test]
    fn account_lookalike_partial_inherits_unset_defaults() {
        // The same defect one level down: `[security.lookalike]` is a table
        // inside a table, so it merges per key too.
        let dir = TempDir::new().unwrap();
        let cfg = multi_toml(
            dir.path(),
            r#"
[defaults.security.lookalike]
known_domains = ["work.test"]
warn_on_any_non_ascii_domain = true
"#,
            r"
[accounts.security.lookalike]
enabled = false
",
        );
        let acct = work_account(cfg);
        assert!(!acct.security.lookalike.enabled, "account's own");
        assert_eq!(
            acct.security.lookalike.known_domains,
            vec!["work.test".to_string()],
            "inherited",
        );
        assert!(
            acct.security.lookalike.warn_on_any_non_ascii_domain,
            "inherited",
        );
    }

    #[test]
    fn account_arrays_replace_rather_than_union() {
        // Arrays replace: a union could not be narrowed, and could
        // manufacture the protected/expunge overlap validation rejects.
        let dir = TempDir::new().unwrap();
        let cfg = multi_toml(
            dir.path(),
            r#"
[defaults.security]
protected_folders = ["INBOX", "Sent", "Archive"]
"#,
            r#"
[accounts.security]
protected_folders = ["INBOX"]
"#,
        );
        let acct = work_account(cfg);
        assert_eq!(
            acct.security.protected_folders,
            vec!["INBOX".to_string()],
            "replaced, not unioned",
        );
    }

    #[test]
    fn unknown_key_in_account_limits_is_rejected() {
        // `deny_unknown_fields` must survive the move to a partial struct.
        let dir = TempDir::new().unwrap();
        let doc = format!(
            r#"
[[accounts]]
name = "work"

[accounts.imap]
host = "imap.work.test"
port = 993
username = "alice@work.test"

[accounts.limits]
no_such_key = 7

[audit]
path = "{d}/audit.jsonl"
allowed_base_dir = "{d}"
"#,
            d = dir.path().display(),
        );
        let err = toml::from_str::<MultiAccountConfig>(&doc).unwrap_err();
        assert!(
            err.to_string().contains("no_such_key"),
            "diagnostic should name the offending key: {err}",
        );
    }

    #[test]
    fn unknown_key_in_account_security_is_rejected() {
        let dir = TempDir::new().unwrap();
        let doc = format!(
            r#"
[[accounts]]
name = "work"

[accounts.imap]
host = "imap.work.test"
port = 993
username = "alice@work.test"

[accounts.security]
no_such_key = "readonly"

[audit]
path = "{d}/audit.jsonl"
allowed_base_dir = "{d}"
"#,
            d = dir.path().display(),
        );
        let err = toml::from_str::<MultiAccountConfig>(&doc).unwrap_err();
        assert!(
            err.to_string().contains("no_such_key"),
            "diagnostic should name the offending key: {err}",
        );
    }

    #[test]
    fn merged_limits_are_still_validated_against_account_imap_budgets() {
        // An inherited ceiling too small for the account's own raised
        // command budget must still be rejected — the merge feeds
        // validation, it does not bypass it.
        let dir = TempDir::new().unwrap();
        let cfg = multi_toml(
            dir.path(),
            r"
[defaults.limits]
tool_call_timeout_seconds = 300
",
            r"
[accounts.limits]
max_search_results = 50
",
        );
        let mut cfg = cfg;
        cfg.accounts[0].imap.command_timeout_seconds = 200; // worst case 820
        let err = validate_multi(cfg).unwrap_err();
        let ConfigError::InvalidLimit { field, .. } = &err else {
            panic!("expected InvalidLimit, got {err:?}");
        };
        assert_eq!(*field, "limits.tool_call_timeout_seconds");
    }

    #[test]
    fn empty_account_credentials_table_inherits_defaults_fallback() {
        // Same defect as #624 in the third override block, and the dangerous
        // direction: `CredentialsConfig::fallback` carries `#[serde(default)]`,
        // so an empty `[accounts.credentials]` table used to deserialize to
        // `Some(keyring-then-env)` and silently re-enable the shared env-var
        // fallback that `keyring-only` exists to prevent (#78).
        let dir = TempDir::new().unwrap();
        let cfg = multi_toml(
            dir.path(),
            r#"
[defaults.credentials]
fallback = "keyring-only"
"#,
            "[accounts.credentials]",
        );
        let acct = work_account(cfg);
        assert_eq!(acct.fallback_mode, FallbackMode::KeyringOnly);
    }

    #[test]
    fn account_credentials_override_still_beats_defaults() {
        let dir = TempDir::new().unwrap();
        let cfg = multi_toml(
            dir.path(),
            r#"
[defaults.credentials]
fallback = "keyring-only"
"#,
            r#"
[accounts.credentials]
fallback = "keyring-then-env"
"#,
        );
        let acct = work_account(cfg);
        assert_eq!(acct.fallback_mode, FallbackMode::KeyringThenEnv);
    }

    #[test]
    fn account_security_without_tools_key_inherits_default_tool_verdicts() {
        // The account writes `[accounts.security]` for an unrelated reason.
        // Every `[defaults.security.tools]` verdict must survive — including
        // the denies, which are the ones with safety weight.
        let dir = TempDir::new().unwrap();
        let cfg = multi_toml(
            dir.path(),
            r#"
[defaults.security]
posture = "draft-safe"

[defaults.security.tools]
mark_read = "deny"
search = "allow"
"#,
            r#"
[accounts.security]
posture = "readonly"
"#,
        );
        let acct = work_account(cfg);
        assert_eq!(acct.security.posture, Posture::Readonly);
        assert_eq!(
            acct.tool_overrides.get(&ToolName::MarkRead),
            Some(&Verdict::Deny),
        );
        assert_eq!(
            acct.tool_overrides.get(&ToolName::Search),
            Some(&Verdict::Allow),
        );
    }

    #[test]
    fn account_security_without_lookalike_key_inherits_default_lookalike() {
        let dir = TempDir::new().unwrap();
        let cfg = multi_toml(
            dir.path(),
            r#"
[defaults.security]
posture = "draft-safe"

[defaults.security.lookalike]
enabled = false
known_domains = ["work.test"]
warn_on_any_non_ascii_domain = true
"#,
            r#"
[accounts.security]
posture = "readonly"
"#,
        );
        let acct = work_account(cfg);
        assert!(!acct.security.lookalike.enabled);
        assert_eq!(
            acct.security.lookalike.known_domains,
            vec!["work.test".to_string()],
        );
        assert!(acct.security.lookalike.warn_on_any_non_ascii_domain);
    }

    #[test]
    fn inherited_send_email_allow_still_requires_account_smtp() {
        // Inheriting an `allow` verdict pulls the account into the checks that
        // verdict triggers: `send_email` needs `[accounts.smtp]`, and the
        // account here has none. Failing loud at startup is the point.
        let dir = TempDir::new().unwrap();
        let cfg = multi_toml(
            dir.path(),
            r#"
[defaults.security.tools]
send_email = "allow"
"#,
            r#"
[accounts.security]
posture = "readonly"
"#,
        );
        let err = validate_multi(cfg).unwrap_err();
        let ConfigError::SmtpRequiredByOverride { .. } = &err else {
            panic!("expected SmtpRequiredByOverride, got {err:?}");
        };
    }

    #[test]
    fn unknown_key_in_account_lookalike_is_rejected() {
        let dir = TempDir::new().unwrap();
        let doc = format!(
            r#"
[[accounts]]
name = "work"

[accounts.imap]
host = "imap.work.test"
port = 993
username = "alice@work.test"

[accounts.security.lookalike]
no_such_key = false

[audit]
path = "{d}/audit.jsonl"
allowed_base_dir = "{d}"
"#,
            d = dir.path().display(),
        );
        let err = toml::from_str::<MultiAccountConfig>(&doc).unwrap_err();
        assert!(
            err.to_string().contains("no_such_key"),
            "diagnostic should name the offending key: {err}",
        );
    }

    #[test]
    fn unknown_key_in_account_credentials_is_rejected() {
        let dir = TempDir::new().unwrap();
        let doc = format!(
            r#"
[[accounts]]
name = "work"

[accounts.imap]
host = "imap.work.test"
port = 993
username = "alice@work.test"

[accounts.credentials]
no_such_key = "keyring-only"

[audit]
path = "{d}/audit.jsonl"
allowed_base_dir = "{d}"
"#,
            d = dir.path().display(),
        );
        let err = toml::from_str::<MultiAccountConfig>(&doc).unwrap_err();
        assert!(
            err.to_string().contains("no_such_key"),
            "diagnostic should name the offending key: {err}",
        );
    }

    #[test]
    fn per_account_smtp_required_still_works() {
        let dir = TempDir::new().unwrap();
        let mut acct = raw_account("work");
        acct.security = Some(AccountSecurityOverrides {
            posture: Some(Posture::Full),
            ..AccountSecurityOverrides::default()
        });
        let cfg = base_multi_config(dir.path(), vec![acct]);
        let err = validate_multi(cfg).unwrap_err();
        assert!(matches!(err, ConfigError::SmtpRequired { .. }));
    }

    #[test]
    fn per_account_conflicting_folders_still_works() {
        let dir = TempDir::new().unwrap();
        let mut acct = raw_account("work");
        acct.security = Some(AccountSecurityOverrides {
            protected_folders: Some(vec!["Trash".into()]),
            expunge_folders: Some(vec!["Trash".into()]),
            ..AccountSecurityOverrides::default()
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
        exporter.security = Some(AccountSecurityOverrides {
            tools: Some(tools),
            ..AccountSecurityOverrides::default()
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
