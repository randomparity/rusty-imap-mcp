//! Credential resolution.
//!
//! Order of precedence (design spec §4, updated for #77 and #260):
//!   1. OS keychain (service = `rusty-imap-mcp`,
//!      account = `<account-id>/<username>@<host>`), with a back-compat read
//!      on the legacy `<username>@<host>` form that logs a migration hint.
//!   2. Protocol-scoped env var `RUSTY_IMAP_MCP_IMAP_PASSWORD` /
//!      `RUSTY_IMAP_MCP_SMTP_PASSWORD` (only in `KeyringThenEnv`).
//!   3. Legacy shared env var `RUSTY_IMAP_MCP_PASSWORD` (only in
//!      `KeyringThenEnv`).
//!   4. Clear, actionable error naming the keyring keys.

use rimap_core::account::AccountId;
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};

use crate::error::ConfigError;

/// Service name used for all keychain entries.
pub const KEYCHAIN_SERVICE: &str = "rusty-imap-mcp";

/// Environment variable name checked as the legacy shared fallback (consulted
/// after the protocol-scoped variables).
pub const PASSWORD_ENV_VAR: &str = "RUSTY_IMAP_MCP_PASSWORD";

/// Environment variable checked as the IMAP-scoped fallback, before the legacy
/// [`PASSWORD_ENV_VAR`].
pub const IMAP_PASSWORD_ENV_VAR: &str = "RUSTY_IMAP_MCP_IMAP_PASSWORD";

/// Environment variable checked as the SMTP-scoped fallback, before the legacy
/// [`PASSWORD_ENV_VAR`].
pub const SMTP_PASSWORD_ENV_VAR: &str = "RUSTY_IMAP_MCP_SMTP_PASSWORD";

/// Which protocol a credential is being resolved for. Selects the
/// protocol-scoped environment-variable fallback name. Baked into
/// [`KeyringCredentialResolver`] at construction for the IMAP path; passed
/// directly by the SMTP path in `rimap-server`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// IMAP transport — uses [`IMAP_PASSWORD_ENV_VAR`].
    Imap,
    /// SMTP transport — uses [`SMTP_PASSWORD_ENV_VAR`].
    Smtp,
}

impl Protocol {
    /// The protocol-scoped password environment-variable name.
    #[must_use]
    pub fn env_var_name(self) -> &'static str {
        match self {
            Protocol::Imap => IMAP_PASSWORD_ENV_VAR,
            Protocol::Smtp => SMTP_PASSWORD_ENV_VAR,
        }
    }
}

/// Abstract credential store. Production uses [`KeyringStore`]; tests
/// substitute an in-memory map.
pub trait CredentialStore: Send + Sync {
    /// Return the stored password for `account`, or `Ok(None)` if absent.
    /// Any *other* error (permission denied, service unreachable) returns
    /// `Err`.
    ///
    /// # Errors
    /// Returns `ConfigError::Keychain` on I/O or access errors.
    fn get_password(&self, account: &str) -> Result<Option<SecretString>, ConfigError>;

    /// Persist `password` for `account`, overwriting any existing entry.
    ///
    /// # Errors
    /// Returns `ConfigError::Keychain` on I/O or access errors.
    fn set_password(&self, account: &str, password: &str) -> Result<(), ConfigError>;
}

/// Build the keyring account key for `(account_id, username, host)`.
///
/// New format: `<account-id>/<username>@<host>`. Added in #77 to prevent
/// collisions when two accounts share a `<username>@<host>` tuple. Use
/// [`legacy_account_key`] only for the read-fallback path during migration.
#[must_use]
pub fn account_key(account_id: &AccountId, username: &str, host: &str) -> String {
    format!("{}/{username}@{host}", account_id.as_str())
}

/// Legacy keyring key format (`<username>@<host>`) — retained for the
/// back-compat read path in [`resolve_credential`]. New code MUST call
/// [`account_key`].
#[must_use]
pub fn legacy_account_key(username: &str, host: &str) -> String {
    format!("{username}@{host}")
}

/// Return a short (16 hex chars) SHA-256 hash of `"{username}@{host}"` suitable
/// for correlating error/audit log lines without disclosing the username.
///
/// 16 hex chars = 64 bits of prefix — collision probability is negligible at
/// the scale of "accounts a single deployment's error chain correlates".
/// The hash is not a keyring key — `account_key` remains distinct and uses the
/// full unhashed identifiers.
#[must_use]
pub fn hash_account_tag(username: &str, host: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(username.as_bytes());
    hasher.update(b"@");
    hasher.update(host.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(16);
    for byte in &digest[..8] {
        use core::fmt::Write;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

/// Split a `username@host` account key back into `(host, account_tag)` for
/// building error records. If the input has no `@` (malformed), treat the
/// whole string as host and use an empty username for hashing.
pub(crate) fn split_account_for_error(account: &str) -> (String, String) {
    let (username, host) = account.split_once('@').unwrap_or(("", account));
    (host.to_string(), hash_account_tag(username, host))
}

/// Resolve the env-var fallback for one protocol: try the protocol-scoped
/// `proto_var` first, then the legacy [`PASSWORD_ENV_VAR`]. A defined-but-empty
/// value is treated as unset so it never masks a later source. Returns the
/// variable name that actually supplied the value, so callers can log the true
/// source. Callers gate this on [`crate::model::FallbackMode::KeyringThenEnv`].
fn resolve_env_fallback(proto_var: &'static str) -> Option<(&'static str, String)> {
    let non_empty = |name: &'static str| -> Option<(&'static str, String)> {
        match std::env::var(name) {
            Ok(v) if !v.is_empty() => Some((name, v)),
            Ok(_) | Err(_) => None,
        }
    };
    match non_empty(proto_var) {
        Some(hit) => Some(hit),
        None => non_empty(PASSWORD_ENV_VAR),
    }
}

/// Resolve a credential: try the store first (new key, then legacy key), then
/// optionally the env var (depending on `fallback_mode`), then fail.
///
/// Accepts `&dyn CredentialStore` so callers that hold an
/// `Arc<dyn CredentialStore>` can pass `&*arc` without a generic bound.
/// Concrete references (e.g. `&KeyringStore`) coerce to `&dyn CredentialStore`
/// automatically, so existing callers are unaffected.
///
/// Returns `(SecretString, CredentialSource)` — the source lets callers record
/// where the credential came from for audit/observability purposes.
///
/// # Errors
/// - `ConfigError::Keychain` if the store itself errored.
/// - `ConfigError::NoCredential` if no source produced a value.
pub fn resolve_credential(
    store: &dyn CredentialStore,
    account_id: &AccountId,
    username: &str,
    host: &str,
    fallback_mode: crate::model::FallbackMode,
    protocol: Protocol,
) -> Result<(SecretString, rimap_core::CredentialSource), ConfigError> {
    use rimap_core::CredentialSource;

    let new_key = account_key(account_id, username, host);
    let legacy_key = legacy_account_key(username, host);

    // Probe the keyring without surfacing transport errors yet. In
    // `KeyringThenEnv` mode a hard keyring failure (e.g. no D-Bus session
    // in CI/Docker) must not short-circuit the documented env-var fallback;
    // in `KeyringOnly` mode it still propagates because the operator opted
    // out of env. See model.rs `FallbackMode` docs and #265.
    let mut keyring_error: Option<ConfigError> = None;
    match store.get_password(&new_key) {
        Ok(Some(p)) if !p.expose_secret().is_empty() => {
            return Ok((p, CredentialSource::Keyring));
        }
        Ok(_) => {}
        Err(e) => keyring_error = Some(e),
    }

    // Back-compat: before #77 the keyring key was <username>@<host>, with no
    // account-id prefix. If the new key lookup missed and the keyring is
    // otherwise reachable, try the legacy key and warn the operator to run
    // `rusty-imap-mcp migrate-keyring`. Skip when the new-key probe already
    // failed — the keyring transport is broken either way.
    if keyring_error.is_none() {
        match store.get_password(&legacy_key) {
            Ok(Some(p)) if !p.expose_secret().is_empty() => {
                tracing::warn!(
                    account_id = %account_id.as_str(),
                    host = %host,
                    "credential resolved via legacy keyring key format; \
                     run `rusty-imap-mcp migrate-keyring --account {}` to migrate",
                    account_id.as_str(),
                );
                return Ok((p, CredentialSource::LegacyKeyring));
            }
            Ok(_) => {}
            Err(e) => keyring_error = Some(e),
        }
    }

    if fallback_mode == crate::model::FallbackMode::KeyringThenEnv
        && let Some((var_name, value)) = resolve_env_fallback(protocol.env_var_name())
    {
        if let Some(e) = &keyring_error {
            tracing::warn!(
                account_id = %account_id.as_str(),
                host = %host,
                error = %e,
                "keyring lookup failed; using `{var_name}` env-var fallback",
            );
        }
        if var_name == PASSWORD_ENV_VAR {
            tracing::warn!(
                account_id = %account_id.as_str(),
                host = %host,
                "credential resolved via legacy `{PASSWORD_ENV_VAR}`; set \
                 `{}` to scope this credential to one protocol",
                protocol.env_var_name(),
            );
        }
        return Ok((SecretString::from(value), CredentialSource::EnvVar));
    }

    // No env fallback available (env unset/empty, or `KeyringOnly` mode).
    // If the keyring transport itself errored, surface that diagnostic
    // instead of the generic "no credential" message — it tells the
    // operator the difference between a misconfigured keyring and a
    // missing entry.
    if let Some(e) = keyring_error {
        return Err(e);
    }

    Err(ConfigError::NoCredential {
        host: host.to_string(),
        account_tag: hash_account_tag(username, host),
        reason: build_no_credential_reason(
            account_id,
            fallback_mode,
            protocol,
            &new_key,
            &legacy_key,
        ),
    })
}

/// Build the user-facing reason string for [`ConfigError::NoCredential`].
///
/// The string embeds `<account-id>/<username>@<host>` (the keyring
/// lookup key) so operators can correlate the error with the exact
/// keyring entry to create. This is disclosure-consistent with the
/// #81 posture documented in `docs/security-model.md`: v1.0 is
/// stdio-only with a single trusted client, and the username/host
/// are already the inputs the operator typed into their own config.
/// If an HTTP/SSE/WebSocket transport ships, this string must be
/// revisited alongside the account-name disclosure in `UnknownAccount`.
fn build_no_credential_reason(
    account_id: &AccountId,
    fallback_mode: crate::model::FallbackMode,
    protocol: Protocol,
    new_key: &str,
    legacy_key: &str,
) -> String {
    match fallback_mode {
        crate::model::FallbackMode::KeyringOnly => format!(
            "no entry in keychain service `{KEYCHAIN_SERVICE}` under key \
             `{new_key}` or legacy `{legacy_key}`; fallback mode is \
             keyring-only (env var not consulted). Run `rusty-imap-mcp \
             login --account {}`",
            account_id.as_str(),
        ),
        crate::model::FallbackMode::KeyringThenEnv => format!(
            "no entry in keychain service `{KEYCHAIN_SERVICE}` under key \
             `{new_key}` or legacy `{legacy_key}`, and neither `{}` nor \
             `{PASSWORD_ENV_VAR}` is set. Run `rusty-imap-mcp login \
             --account {}` or set `{}`",
            protocol.env_var_name(),
            account_id.as_str(),
            protocol.env_var_name(),
        ),
    }
}

/// Adapter implementing [`rimap_core::CredentialResolver`] over the
/// lower-level [`CredentialStore`] + [`crate::model::FallbackMode`]
/// pair. Bakes the keyring-vs-env-var fallback policy in at
/// construction time so the IMAP transport never sees `FallbackMode`.
///
/// Cheaply cloneable; the `Arc<dyn CredentialStore>` shares a single
/// keyring handle across every per-account resolver in a process.
#[derive(Clone)]
pub struct KeyringCredentialResolver {
    store: std::sync::Arc<dyn CredentialStore>,
    fallback_mode: crate::model::FallbackMode,
    protocol: Protocol,
}

impl std::fmt::Debug for KeyringCredentialResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // CredentialStore is not Debug (production impls wrap a
        // `keyring::Entry` which doesn't implement it either), so the
        // store is shown as an opaque pointer rather than expanded.
        f.debug_struct("KeyringCredentialResolver")
            .field("store", &"<dyn CredentialStore>")
            .field("fallback_mode", &self.fallback_mode)
            .field("protocol", &self.protocol)
            .finish()
    }
}

impl KeyringCredentialResolver {
    /// Build a resolver that walks `store` and falls back to the
    /// configured policy.
    #[must_use]
    pub fn new(
        store: std::sync::Arc<dyn CredentialStore>,
        fallback_mode: crate::model::FallbackMode,
        protocol: Protocol,
    ) -> Self {
        Self {
            store,
            fallback_mode,
            protocol,
        }
    }
}

impl rimap_core::CredentialResolver for KeyringCredentialResolver {
    fn resolve(
        &self,
        account: &AccountId,
        username: &str,
        host: &str,
    ) -> Result<(SecretString, rimap_core::CredentialSource), rimap_core::CredentialResolverError>
    {
        resolve_credential(
            &*self.store,
            account,
            username,
            host,
            self.fallback_mode,
            self.protocol,
        )
        .map_err(|e| {
            let reason = e.to_string();
            rimap_core::CredentialResolverError::with_source(reason, e)
        })
    }
}

/// Keychain-backed [`CredentialStore`] using the `keyring` crate. Not
/// constructed in unit tests (keychain access is unreliable in CI).
#[derive(Debug, Default)]
pub struct KeyringStore;

impl CredentialStore for KeyringStore {
    fn get_password(&self, account: &str) -> Result<Option<SecretString>, ConfigError> {
        let entry = keyring::Entry::new(KEYCHAIN_SERVICE, account).map_err(|e| {
            let (host, account_tag) = split_account_for_error(account);
            ConfigError::Keychain {
                host,
                account_tag,
                source: Box::new(e),
            }
        })?;
        match entry.get_password() {
            Ok(p) => Ok(Some(SecretString::from(p))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => {
                let (host, account_tag) = split_account_for_error(account);
                Err(ConfigError::Keychain {
                    host,
                    account_tag,
                    source: Box::new(e),
                })
            }
        }
    }

    fn set_password(&self, account: &str, password: &str) -> Result<(), ConfigError> {
        let entry = keyring::Entry::new(KEYCHAIN_SERVICE, account).map_err(|e| {
            let (host, account_tag) = split_account_for_error(account);
            ConfigError::Keychain {
                host,
                account_tag,
                source: Box::new(e),
            }
        })?;
        entry.set_password(password).map_err(|e| {
            let (host, account_tag) = split_account_for_error(account);
            ConfigError::Keychain {
                host,
                account_tag,
                source: Box::new(e),
            }
        })
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
#[expect(clippy::panic, reason = "tests")]
mod tests {
    use secrecy::{ExposeSecret, SecretString};

    use rimap_core::account::AccountId;

    use crate::credential::{
        IMAP_PASSWORD_ENV_VAR, PASSWORD_ENV_VAR, Protocol, SMTP_PASSWORD_ENV_VAR, account_key,
        resolve_credential, resolve_env_fallback,
    };
    use crate::error::ConfigError;
    use crate::model::FallbackMode;
    use crate::test_support::MockStore;

    #[test]
    fn protocol_maps_to_scoped_env_var_names() {
        assert_eq!(
            Protocol::Imap.env_var_name(),
            "RUSTY_IMAP_MCP_IMAP_PASSWORD"
        );
        assert_eq!(
            Protocol::Smtp.env_var_name(),
            "RUSTY_IMAP_MCP_SMTP_PASSWORD"
        );
    }

    #[test]
    fn env_fallback_prefers_proto_var_then_legacy() {
        temp_env::with_vars(
            [
                (IMAP_PASSWORD_ENV_VAR, Some("imap_secret")),
                (PASSWORD_ENV_VAR, Some("legacy_secret")),
            ],
            || {
                let (var, val) = resolve_env_fallback(IMAP_PASSWORD_ENV_VAR).unwrap();
                assert_eq!(var, IMAP_PASSWORD_ENV_VAR);
                assert_eq!(val, "imap_secret");
            },
        );
        temp_env::with_vars(
            [
                (IMAP_PASSWORD_ENV_VAR, None::<&str>),
                (PASSWORD_ENV_VAR, Some("legacy_secret")),
            ],
            || {
                let (var, val) = resolve_env_fallback(IMAP_PASSWORD_ENV_VAR).unwrap();
                assert_eq!(var, PASSWORD_ENV_VAR);
                assert_eq!(val, "legacy_secret");
            },
        );
        temp_env::with_vars(
            [
                (IMAP_PASSWORD_ENV_VAR, Some("")),
                (PASSWORD_ENV_VAR, Some("legacy_secret")),
            ],
            || {
                let (var, _val) = resolve_env_fallback(IMAP_PASSWORD_ENV_VAR).unwrap();
                assert_eq!(var, PASSWORD_ENV_VAR);
            },
        );
        temp_env::with_vars(
            [
                (IMAP_PASSWORD_ENV_VAR, None::<&str>),
                (PASSWORD_ENV_VAR, None::<&str>),
            ],
            || assert!(resolve_env_fallback(IMAP_PASSWORD_ENV_VAR).is_none()),
        );
    }

    #[test]
    fn imap_and_smtp_env_vars_resolve_independently() {
        let store = MockStore::default();
        let id = AccountId::default_account();
        temp_env::with_vars(
            [
                (IMAP_PASSWORD_ENV_VAR, Some("imap_pw")),
                (SMTP_PASSWORD_ENV_VAR, Some("smtp_pw")),
                (PASSWORD_ENV_VAR, None::<&str>),
            ],
            || {
                let (imap, _) = resolve_credential(
                    &store,
                    &id,
                    "alice",
                    "host",
                    FallbackMode::KeyringThenEnv,
                    Protocol::Imap,
                )
                .unwrap();
                let (smtp, _) = resolve_credential(
                    &store,
                    &id,
                    "alice",
                    "host",
                    FallbackMode::KeyringThenEnv,
                    Protocol::Smtp,
                )
                .unwrap();
                assert_eq!(imap.expose_secret(), "imap_pw");
                assert_eq!(smtp.expose_secret(), "smtp_pw");
            },
        );
    }

    #[test]
    fn proto_var_does_not_leak_to_other_protocol() {
        let store = MockStore::default();
        let id = AccountId::default_account();
        temp_env::with_vars(
            [
                (IMAP_PASSWORD_ENV_VAR, Some("imap_pw")),
                (SMTP_PASSWORD_ENV_VAR, None::<&str>),
                (PASSWORD_ENV_VAR, None::<&str>),
            ],
            || {
                let err = resolve_credential(
                    &store,
                    &id,
                    "alice",
                    "host",
                    FallbackMode::KeyringThenEnv,
                    Protocol::Smtp,
                )
                .unwrap_err();
                assert!(matches!(err, ConfigError::NoCredential { .. }));
            },
        );
    }

    #[test]
    fn proto_var_wins_over_legacy_var() {
        let store = MockStore::default();
        let id = AccountId::default_account();
        temp_env::with_vars(
            [
                (IMAP_PASSWORD_ENV_VAR, Some("imap_pw")),
                (PASSWORD_ENV_VAR, Some("legacy_pw")),
            ],
            || {
                let (got, src) = resolve_credential(
                    &store,
                    &id,
                    "alice",
                    "host",
                    FallbackMode::KeyringThenEnv,
                    Protocol::Imap,
                )
                .unwrap();
                assert_eq!(got.expose_secret(), "imap_pw");
                assert_eq!(src, rimap_core::CredentialSource::EnvVar);
            },
        );
    }

    #[test]
    fn keyring_error_falls_back_to_proto_var() {
        let store = MockStore::failing();
        let id = AccountId::default_account();
        temp_env::with_vars(
            [
                (SMTP_PASSWORD_ENV_VAR, Some("smtp_pw")),
                (PASSWORD_ENV_VAR, None::<&str>),
            ],
            || {
                let (got, src) = resolve_credential(
                    &store,
                    &id,
                    "alice",
                    "host",
                    FallbackMode::KeyringThenEnv,
                    Protocol::Smtp,
                )
                .unwrap();
                assert_eq!(got.expose_secret(), "smtp_pw");
                assert_eq!(src, rimap_core::CredentialSource::EnvVar);
            },
        );
    }

    #[test]
    fn keyring_only_ignores_proto_var() {
        let store = MockStore::default();
        let id = AccountId::default_account();
        temp_env::with_vars(
            [
                (SMTP_PASSWORD_ENV_VAR, Some("smtp_pw")),
                (PASSWORD_ENV_VAR, Some("legacy_pw")),
            ],
            || {
                let err = resolve_credential(
                    &store,
                    &id,
                    "alice",
                    "host",
                    FallbackMode::KeyringOnly,
                    Protocol::Smtp,
                )
                .unwrap_err();
                assert!(matches!(err, ConfigError::NoCredential { .. }));
            },
        );
    }

    #[test]
    fn hash_account_tag_is_16_hex_and_deterministic() {
        let a = super::hash_account_tag("alice", "mail.example.com");
        let b = super::hash_account_tag("alice", "mail.example.com");
        assert_eq!(a, b);
        assert_eq!(a.len(), 16);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn hash_account_tag_differs_on_different_inputs() {
        let a = super::hash_account_tag("alice", "mail.example.com");
        let b = super::hash_account_tag("bob", "mail.example.com");
        let c = super::hash_account_tag("alice", "other.example.com");
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
    }

    #[test]
    fn account_key_uses_namespaced_format() {
        use rimap_core::account::AccountId;
        let id = AccountId::new("work").unwrap();
        let key = account_key(&id, "alice", "mail.example.test");
        assert_eq!(key, "work/alice@mail.example.test");
    }

    #[test]
    fn legacy_account_key_returns_bare_form() {
        let key = super::legacy_account_key("alice", "mail.example.test");
        assert_eq!(key, "alice@mail.example.test");
    }

    #[test]
    fn resolve_credential_reads_new_key_format_first() {
        use rimap_core::account::AccountId;
        let id = AccountId::new("work").unwrap();
        let store = MockStore::with(&[
            ("work/alice@host", "from_new_key"),
            ("alice@host", "from_legacy_key"),
        ]);
        temp_env::with_var(PASSWORD_ENV_VAR, None::<&str>, || {
            let (got, _src) = resolve_credential(
                &store,
                &id,
                "alice",
                "host",
                FallbackMode::KeyringThenEnv,
                Protocol::Imap,
            )
            .unwrap();
            assert_eq!(got.expose_secret(), "from_new_key");
        });
    }

    #[test]
    fn resolve_credential_falls_back_to_legacy_key() {
        use rimap_core::account::AccountId;
        let id = AccountId::new("work").unwrap();
        let store = MockStore::with(&[("alice@host", "from_legacy_key")]);
        temp_env::with_var(PASSWORD_ENV_VAR, None::<&str>, || {
            let (got, _src) = resolve_credential(
                &store,
                &id,
                "alice",
                "host",
                FallbackMode::KeyringThenEnv,
                Protocol::Imap,
            )
            .unwrap();
            assert_eq!(got.expose_secret(), "from_legacy_key");
        });
    }

    #[test]
    fn keychain_hit_wins_over_env() {
        let default_id = AccountId::default_account();
        let store = MockStore::with(&[("default/alice@host", "from_keychain")]);
        temp_env::with_var(PASSWORD_ENV_VAR, Some("from_env"), || {
            let (got, _src) = resolve_credential(
                &store,
                &default_id,
                "alice",
                "host",
                FallbackMode::KeyringThenEnv,
                Protocol::Imap,
            )
            .unwrap();
            assert_eq!(got.expose_secret(), "from_keychain");
        });
    }

    #[test]
    fn env_used_when_keychain_empty() {
        let store = MockStore::default();
        let default_id = AccountId::default_account();
        temp_env::with_var(PASSWORD_ENV_VAR, Some("from_env"), || {
            let (got, _src) = resolve_credential(
                &store,
                &default_id,
                "alice",
                "host",
                FallbackMode::KeyringThenEnv,
                Protocol::Imap,
            )
            .unwrap();
            assert_eq!(got.expose_secret(), "from_env");
        });
    }

    #[test]
    fn missing_everywhere_returns_no_credential() {
        let store = MockStore::default();
        let default_id = AccountId::default_account();
        temp_env::with_var(PASSWORD_ENV_VAR, None::<&str>, || {
            let err = resolve_credential(
                &store,
                &default_id,
                "alice",
                "host",
                FallbackMode::KeyringThenEnv,
                Protocol::Imap,
            )
            .unwrap_err();
            match err {
                ConfigError::NoCredential {
                    host,
                    account_tag,
                    reason,
                } => {
                    assert_eq!(host, "host");
                    assert_eq!(account_tag.len(), 16);
                    assert!(reason.contains("rusty-imap-mcp login"));
                    assert!(reason.contains("RUSTY_IMAP_MCP_PASSWORD"));
                    // The failure message names the protocol-scoped var so
                    // operators are steered to it, not just the legacy shared var.
                    assert!(reason.contains("RUSTY_IMAP_MCP_IMAP_PASSWORD"));
                }
                other => panic!("wrong variant: {other:?}"),
            }
        });
    }

    #[test]
    fn keychain_error_propagates_in_keyring_only_mode() {
        // `KeyringOnly` is the strict mode: the operator opted out of
        // the env-var fallback, so a hard keyring failure must surface
        // (not silently mask the misconfigured keyring).
        let store = MockStore::failing();
        let default_id = AccountId::default_account();
        temp_env::with_var(PASSWORD_ENV_VAR, Some("unused"), || {
            let err = resolve_credential(
                &store,
                &default_id,
                "alice",
                "host",
                FallbackMode::KeyringOnly,
                Protocol::Imap,
            )
            .unwrap_err();
            assert!(matches!(err, ConfigError::Keychain { .. }));
        });
    }

    #[test]
    fn keychain_error_falls_back_to_env_in_keyring_then_env_mode() {
        // Documented behavior (model.rs `FallbackMode::KeyringThenEnv`):
        // "Suitable for CI/test and single-account deployments." In
        // environments without a working keyring (CI runners, Docker
        // containers, headless servers) the env var must take over —
        // otherwise the documented mode is unusable in its primary
        // use case. Surfaced by the Phase 3 wire e2e tests (#265).
        let store = MockStore::failing();
        let default_id = AccountId::default_account();
        temp_env::with_var(PASSWORD_ENV_VAR, Some("from_env"), || {
            let (got, src) = resolve_credential(
                &store,
                &default_id,
                "alice",
                "host",
                FallbackMode::KeyringThenEnv,
                Protocol::Imap,
            )
            .unwrap();
            assert_eq!(got.expose_secret(), "from_env");
            assert_eq!(src, rimap_core::CredentialSource::EnvVar);
        });
    }

    #[test]
    fn keychain_error_propagates_when_no_env_in_keyring_then_env_mode() {
        // With no env-var set, the keyring error is the most useful
        // diagnostic: it tells the operator the difference between a
        // missing keyring entry and a broken keyring transport.
        let store = MockStore::failing();
        let default_id = AccountId::default_account();
        temp_env::with_var(PASSWORD_ENV_VAR, None::<&str>, || {
            let err = resolve_credential(
                &store,
                &default_id,
                "alice",
                "host",
                FallbackMode::KeyringThenEnv,
                Protocol::Imap,
            )
            .unwrap_err();
            assert!(matches!(err, ConfigError::Keychain { .. }));
        });
    }

    #[test]
    fn empty_keychain_value_falls_through_to_env() {
        let default_id = AccountId::default_account();
        let store = MockStore::with(&[("default/alice@host", "")]);
        temp_env::with_var(PASSWORD_ENV_VAR, Some("from_env"), || {
            assert_eq!(
                resolve_credential(
                    &store,
                    &default_id,
                    "alice",
                    "host",
                    FallbackMode::KeyringThenEnv,
                    Protocol::Imap,
                )
                .unwrap()
                .0
                .expose_secret(),
                "from_env"
            );
        });
    }

    #[test]
    fn resolved_credential_debug_does_not_leak() {
        let p = SecretString::from("hunter2".to_string());
        let formatted = format!("{p:?}");
        assert!(!formatted.contains("hunter2"));
    }

    #[test]
    fn strict_mode_skips_env_var() {
        use rimap_core::account::AccountId;
        let id = AccountId::new("work").unwrap();
        let store = MockStore::default();
        temp_env::with_var(PASSWORD_ENV_VAR, Some("from_env"), || {
            let err = resolve_credential(
                &store,
                &id,
                "alice",
                "host",
                FallbackMode::KeyringOnly,
                Protocol::Imap,
            )
            .unwrap_err();
            assert!(matches!(err, ConfigError::NoCredential { .. }));
        });
    }

    #[test]
    fn permissive_mode_still_uses_env_var() {
        use rimap_core::account::AccountId;
        let id = AccountId::new("work").unwrap();
        let store = MockStore::default();
        temp_env::with_var(PASSWORD_ENV_VAR, Some("from_env"), || {
            let (password, source) = resolve_credential(
                &store,
                &id,
                "alice",
                "host",
                FallbackMode::KeyringThenEnv,
                Protocol::Imap,
            )
            .unwrap();
            assert_eq!(password.expose_secret(), "from_env");
            assert_eq!(source, rimap_core::CredentialSource::EnvVar);
        });
    }

    #[test]
    fn keyring_hit_reports_keyring_source() {
        use rimap_core::account::AccountId;
        let id = AccountId::new("work").unwrap();
        let store = MockStore::with(&[("work/alice@host", "secret")]);
        temp_env::with_var(PASSWORD_ENV_VAR, None::<&str>, || {
            let (_p, source) = resolve_credential(
                &store,
                &id,
                "alice",
                "host",
                FallbackMode::KeyringOnly,
                Protocol::Imap,
            )
            .unwrap();
            assert_eq!(source, rimap_core::CredentialSource::Keyring);
        });
    }

    #[test]
    fn legacy_keyring_hit_reports_legacy_source() {
        use rimap_core::account::AccountId;
        let id = AccountId::new("work").unwrap();
        let store = MockStore::with(&[("alice@host", "secret")]);
        temp_env::with_var(PASSWORD_ENV_VAR, None::<&str>, || {
            let (_p, source) = resolve_credential(
                &store,
                &id,
                "alice",
                "host",
                FallbackMode::KeyringOnly,
                Protocol::Imap,
            )
            .unwrap();
            assert_eq!(source, rimap_core::CredentialSource::LegacyKeyring);
        });
    }
}
