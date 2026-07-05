//! Config file discovery and TOML loading.
//!
//! Path resolution order, per design spec §4:
//!   1. Explicit `--config <path>` argument (handled by caller; passed here as `Some(path)`).
//!   2. `RUSTY_IMAP_MCP_CONFIG` environment variable.
//!   3. Platform default:
//!        - Linux: `$XDG_CONFIG_HOME/rusty-imap-mcp/config.toml`
//!          (falling back to `~/.config/rusty-imap-mcp/config.toml`)
//!        - macOS: `~/Library/Application Support/rusty-imap-mcp/config.toml`

use std::path::{Path, PathBuf};

use directories::ProjectDirs;

use crate::error::ConfigError;
use crate::model::{Config, MultiAccountConfig};
#[cfg(feature = "test-support")]
use crate::validate::validate_multi_allowing_empty;
use crate::validate::{ValidatedMultiConfig, validate_legacy_as_multi, validate_multi};

/// Organization qualifiers for `directories::ProjectDirs`.
const QUALIFIER: &str = "";
const ORGANIZATION: &str = "";
const APPLICATION: &str = "rusty-imap-mcp";

/// Environment variable name for the config path override.
pub const CONFIG_ENV_VAR: &str = "RUSTY_IMAP_MCP_CONFIG";

/// Return the config path based on the explicit override, the environment
/// variable, or the platform default. Returns `None` if no default path can
/// be determined (e.g. headless system with no HOME).
#[must_use]
pub fn resolve_config_path(explicit: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = explicit {
        return Some(p.to_path_buf());
    }
    if let Ok(v) = std::env::var(CONFIG_ENV_VAR)
        && !v.is_empty()
    {
        return Some(PathBuf::from(v));
    }
    ProjectDirs::from(QUALIFIER, ORGANIZATION, APPLICATION)
        .map(|dirs| dirs.config_dir().join("config.toml"))
}

/// Read `path` to a string, classifying an absent file as
/// [`ConfigError::NotFound`] and any other I/O failure as
/// [`ConfigError::Read`].
///
/// Splitting `NotFound` out lets a first-run invocation surface actionable
/// setup guidance instead of a raw "No such file or directory" error, while
/// genuine read failures (permissions, path is a directory) still report the
/// underlying I/O error for diagnosis.
fn read_config_string(path: &Path) -> Result<String, ConfigError> {
    std::fs::read_to_string(path).map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            ConfigError::NotFound {
                path: path.to_path_buf(),
            }
        } else {
            ConfigError::Read {
                path: path.to_path_buf(),
                source,
            }
        }
    })
}

/// Load and deserialize a config file from the given path. Does **not**
/// validate semantic constraints — that's [`crate::validate::validate_multi`]
/// (reached via [`load_and_validate`]).
///
/// # Errors
/// Returns `ConfigError::NotFound` if the file does not exist,
/// `ConfigError::Read` for any other read failure, or `ConfigError::Parse`
/// if the TOML is malformed.
pub fn load_from_path(path: &Path) -> Result<Config, ConfigError> {
    let contents = read_config_string(path)?;
    toml::from_str::<Config>(&contents).map_err(|source| ConfigError::Parse {
        path: path.to_path_buf(),
        source,
    })
}

/// Read and classify `path`, then validate it with `validate_multi_fn` for
/// the multi-account arm and `validate_legacy_as_multi` for the legacy arm.
/// The two public entry points differ only in which multi-account validator
/// they pass.
fn load_and_validate_with(
    path: &Path,
    validate_multi_fn: impl FnOnce(MultiAccountConfig) -> Result<ValidatedMultiConfig, ConfigError>,
) -> Result<ValidatedMultiConfig, ConfigError> {
    match classify_format(path)? {
        DetectedFormat::Multi(config) => validate_multi_fn(config),
        DetectedFormat::Legacy(config) => validate_legacy_as_multi(config),
    }
}

/// Load a config file and validate it, producing a `ValidatedMultiConfig`.
///
/// Detects format by scanning for `[[accounts]]` (multi-account) vs `[imap]`
/// (legacy). Both present is an error. Parses the appropriate struct and
/// runs validation.
///
/// # Errors
/// Returns `ConfigError` on read, parse, or validation failure.
pub fn load_and_validate(path: &Path) -> Result<ValidatedMultiConfig, ConfigError> {
    load_and_validate_with(path, validate_multi)
}

/// Variant of [`load_and_validate`] that, for multi-account format,
/// invokes [`crate::validate::validate_multi_allowing_empty`] so the
/// wire-conformance harness can spawn the binary with `accounts = []`.
/// Gated behind the `test-support` feature.
///
/// # Errors
/// Same surface as [`load_and_validate`], minus `ConfigError::NoAccounts`
/// for empty multi-account configs.
#[cfg(feature = "test-support")]
pub fn load_and_validate_allowing_empty(path: &Path) -> Result<ValidatedMultiConfig, ConfigError> {
    load_and_validate_with(path, validate_multi_allowing_empty)
}

/// Detected on-disk config shape after reading + parsing the file.
///
/// Multi-account vs legacy classification happens here so the two
/// validating entrypoints ([`load_and_validate`] and, under
/// `test-support`, [`load_and_validate_allowing_empty`]) share the
/// same I/O and format-detection path.
enum DetectedFormat {
    Multi(MultiAccountConfig),
    Legacy(Config),
}

/// Read `path`, parse it as TOML, and classify it as multi-account or
/// legacy. Returns [`ConfigError::MixedConfigFormat`] if both shapes
/// appear in the same document.
fn classify_format(path: &Path) -> Result<DetectedFormat, ConfigError> {
    let contents = read_config_string(path)?;

    // Parse once. The top level of any syntactically valid TOML document is
    // a table, so deserialization into `toml::Value` gives us a structured
    // view for format classification. Format-specific deserialization
    // reuses the parsed value instead of re-parsing the raw string.
    let value: toml::Value = toml::from_str(&contents).map_err(|source| ConfigError::Parse {
        path: path.to_path_buf(),
        source,
    })?;

    let (has_accounts, has_flat_imap) = match &value {
        toml::Value::Table(t) => (
            t.get("accounts").and_then(toml::Value::as_array).is_some(),
            t.contains_key("imap"),
        ),
        _ => (false, false),
    };

    if has_accounts && has_flat_imap {
        return Err(ConfigError::MixedConfigFormat);
    }

    if has_accounts {
        let config: MultiAccountConfig = value.try_into().map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })?;
        Ok(DetectedFormat::Multi(config))
    } else {
        let config: Config = value.try_into().map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })?;
        Ok(DetectedFormat::Legacy(config))
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use std::path::PathBuf;

    use rimap_core::posture::Posture;
    use tempfile::TempDir;

    use rimap_core::account::AccountId;

    use crate::error::ConfigError;
    use crate::loader::{CONFIG_ENV_VAR, load_and_validate, load_from_path, resolve_config_path};
    use crate::model::Verdict;

    fn write_config(dir: &TempDir, name: &str, contents: &str) -> PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, contents).unwrap();
        path
    }

    const MINIMAL_CONFIG: &str = r#"
[imap]
host = "127.0.0.1"
port = 1143
username = "alice@example.test"

[audit]
path = "/tmp/rimap-audit.jsonl"
"#;

    #[test]
    fn load_minimal_config_fills_defaults() {
        let dir = TempDir::new().unwrap();
        let path = write_config(&dir, "config.toml", MINIMAL_CONFIG);
        let cfg = load_from_path(&path).unwrap();
        assert_eq!(cfg.imap.host, "127.0.0.1");
        assert_eq!(cfg.imap.port, 1143);
        assert_eq!(cfg.imap.command_timeout_seconds, 30);
        assert_eq!(cfg.imap.connect_timeout_seconds, 10);
        assert_eq!(cfg.security.posture, Posture::DraftSafe);
        assert_eq!(cfg.limits.commands_per_second, 10);
        assert_eq!(cfg.limits.drafts_per_minute, 5);
        assert!(cfg.security.tools.is_empty());
    }

    #[test]
    fn load_with_tool_overrides_preserves_order_independent_map() {
        let toml = format!(
            r#"{MINIMAL_CONFIG}
[security]
posture = "draft-safe"

[security.tools]
mark_read = "deny"
search = "allow"
"#
        );
        let dir = TempDir::new().unwrap();
        let path = write_config(&dir, "config.toml", &toml);
        let cfg = load_from_path(&path).unwrap();
        assert_eq!(cfg.security.tools.get("mark_read"), Some(&Verdict::Deny));
        assert_eq!(cfg.security.tools.get("search"), Some(&Verdict::Allow));
    }

    #[test]
    fn unknown_field_is_rejected() {
        // Prepend the bogus field above any section header so TOML parses it
        // as a top-level key (not a member of `[audit]`).
        let toml = format!("bogus_top_level = 1\n{MINIMAL_CONFIG}");
        let dir = TempDir::new().unwrap();
        let path = write_config(&dir, "config.toml", &toml);
        let err = load_from_path(&path).unwrap_err();
        assert!(matches!(err, crate::error::ConfigError::Parse { .. }));
    }

    #[test]
    fn missing_file_returns_not_found_error() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nope.toml");
        let err = load_from_path(&path).unwrap_err();
        assert!(matches!(err, ConfigError::NotFound { .. }));
    }

    #[test]
    fn unreadable_path_returns_read_error() {
        // Reading a directory as a file fails with a non-`NotFound` I/O error,
        // which must still classify as `Read`, not `NotFound`.
        let dir = TempDir::new().unwrap();
        let err = load_from_path(dir.path()).unwrap_err();
        assert!(
            matches!(err, ConfigError::Read { .. }),
            "expected Read for a present-but-unreadable path, got: {err:?}"
        );
    }

    #[test]
    fn resolve_explicit_path_wins() {
        let p = PathBuf::from("/etc/rimap/custom.toml");
        assert_eq!(resolve_config_path(Some(&p)), Some(p));
    }

    #[test]
    fn resolve_env_var_used_when_no_explicit() {
        // Use a unique tempdir path to avoid clobbering a real user env.
        let dir = TempDir::new().unwrap();
        let env_path = dir.path().join("env.toml");
        // SAFETY: single-threaded test; std::env::set_var is safe here.
        temp_env::with_var(CONFIG_ENV_VAR, Some(env_path.as_os_str()), || {
            assert_eq!(resolve_config_path(None), Some(env_path.clone()));
        });
    }

    #[test]
    fn resolve_default_is_some_on_supported_platforms() {
        temp_env::with_var(CONFIG_ENV_VAR, None::<&str>, || {
            let p = resolve_config_path(None);
            // On supported platforms (Linux, macOS, Windows) directories will
            // return Some. On exotic platforms it may be None; accept both.
            if let Some(path) = p {
                assert!(path.to_string_lossy().contains("rusty-imap-mcp"));
                assert!(path.ends_with("config.toml"));
            }
        });
    }

    // -----------------------------------------------------------------------
    // load_and_validate format detection tests
    // -----------------------------------------------------------------------

    fn legacy_toml(audit_dir: &std::path::Path) -> String {
        format!(
            r#"
[imap]
host = "127.0.0.1"
port = 1143
username = "alice@example.test"

[audit]
path = "{dir}/audit.jsonl"
allowed_base_dir = "{dir}"
"#,
            dir = audit_dir.display(),
        )
    }

    fn multi_toml(audit_dir: &std::path::Path) -> String {
        format!(
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
path = "{dir}/audit.jsonl"
allowed_base_dir = "{dir}"
"#,
            dir = audit_dir.display(),
        )
    }

    #[test]
    fn load_and_validate_legacy_format() {
        let dir = TempDir::new().unwrap();
        let path = write_config(&dir, "config.toml", &legacy_toml(dir.path()));
        let v = load_and_validate(&path).unwrap();
        assert_eq!(v.accounts.len(), 1);
        assert!(v.accounts.contains_key(&AccountId::default_account()));
    }

    #[test]
    fn load_and_validate_multi_format() {
        let dir = TempDir::new().unwrap();
        let path = write_config(&dir, "config.toml", &multi_toml(dir.path()));
        let v = load_and_validate(&path).unwrap();
        assert_eq!(v.accounts.len(), 2);
        assert!(v.accounts.contains_key(&AccountId::new("work").unwrap()));
        assert!(
            v.accounts
                .contains_key(&AccountId::new("personal").unwrap())
        );
    }

    #[test]
    fn load_and_validate_mixed_format_rejected() {
        let dir = TempDir::new().unwrap();
        let mixed = format!(
            r#"
[imap]
host = "127.0.0.1"
port = 1143
username = "alice@example.test"

[[accounts]]
name = "work"

[accounts.imap]
host = "imap.work.com"
port = 993
username = "alice@work.com"

[audit]
path = "{dir}/audit.jsonl"
"#,
            dir = dir.path().display(),
        );
        let path = write_config(&dir, "config.toml", &mixed);
        let err = load_and_validate(&path).unwrap_err();
        assert!(matches!(err, ConfigError::MixedConfigFormat));
    }
}
