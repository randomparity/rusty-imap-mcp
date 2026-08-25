//! Test fixtures for `rimap-server` unit tests.
//!
//! Provides [`make_test_account_state`], a minimal [`AccountState`]
//! constructor that is socket-free: [`rimap_imap::Connection::new`]
//! does not open a TCP/TLS connection, and the credential resolver +
//! auth-event sink shipped here panic / no-op respectively, so any
//! test that triggers IMAP I/O on the returned state will fail loudly
//! or hang rather than silently make outbound network calls.
//!
//! Use this for tests that read structural [`AccountState`] fields
//! (`id`, `imap.host()`, `imap.username()`, `smtp.is_some()`,
//! `special_use`, `guard.matrix()`). Flows that need real IMAP
//! protocol behavior should use the dovecot harness in
//! `tests/e2e.rs`.

#![cfg(test)]
#![expect(
    clippy::expect_used,
    clippy::unreachable,
    reason = "test fixture: expect() narrows infallible-by-config setup, \
              unreachable!() in the credential resolver surfaces \
              accidental I/O from misconfigured tests"
)]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use rimap_authz::breaker::{BreakerConfig, CircuitBreaker, SystemClock};
use rimap_authz::matrix::EffectiveMatrix;
use rimap_authz::rate_limit::Governor;
use rimap_authz::{DispatchGuard, FolderGuard};
use rimap_core::account::AccountId;
use rimap_core::auth_event::AuthEvent;
use rimap_core::auth_sink::{AuthEventSink, AuthSinkError};
use rimap_core::credential::{CredentialResolver, CredentialResolverError, CredentialSource};
use rimap_core::posture::Posture;
use rimap_imap::{Connection, ConnectionConfig, SpecialUseMap};
use secrecy::SecretString;

use crate::boot::registry::AccountState;

#[derive(Debug)]
struct PanickingCreds;

impl CredentialResolver for PanickingCreds {
    fn resolve(
        &self,
        _account: &AccountId,
        _username: &str,
        _host: &str,
    ) -> Result<(SecretString, CredentialSource), CredentialResolverError> {
        // The test fixture's AccountState is intended for structural
        // reads only. Reaching this resolver means a test triggered an
        // IMAP login flow; surface that loudly so the test is fixed
        // rather than silently making outbound network calls.
        unreachable!("test fixture credential resolver should never be invoked")
    }
}

#[derive(Debug)]
struct DiscardingSink;

impl AuthEventSink for DiscardingSink {
    fn emit_auth(&self, _event: AuthEvent) -> Result<(), AuthSinkError> {
        Ok(())
    }
}

/// Build a minimal [`AccountState`] for unit tests.
///
/// The IMAP connection is configured to point at `127.0.0.1:0` and is
/// **never opened** — `Connection::new` is documented as socket-free.
/// Tests that trigger I/O on the returned state will hit
/// [`PanickingCreds::resolve`] and fail.
pub(crate) fn make_test_account_state(name: &str) -> AccountState {
    make_test_account_state_at(name, 0, Duration::from_secs(1), Duration::from_secs(300))
}

/// [`make_test_account_state`] with an IMAP `port` and a per-tool-call
/// `tool_call_timeout` the caller chooses.
///
/// Pointing `port` at a listener that accepts and then stays silent is
/// how the ceiling tests get a dispatch that parks indefinitely inside
/// the TLS handshake — before any credential resolution, so
/// [`PanickingCreds`] is not reached. Those tests set `imap_timeout` far
/// *above* `tool_call_timeout`, so only the ceiling can be what cuts the
/// call off.
pub(crate) fn make_test_account_state_at(
    name: &str,
    port: u16,
    imap_timeout: Duration,
    tool_call_timeout: Duration,
) -> AccountState {
    make_test_account_state_with_sink(
        name,
        port,
        imap_timeout,
        tool_call_timeout,
        Arc::new(DiscardingSink),
    )
}

/// [`make_test_account_state_at`] with the connection's [`AuthEventSink`]
/// supplied by the caller.
///
/// The default sink discards, which makes the `auth` records the connect flow
/// writes invisible. A test that asserts on those records — the ceiling test
/// for #623 asserts a cut connect still writes one — passes the same
/// `AuditWriter` the server logs through, so both record kinds land in one
/// file in the order they were written.
pub(crate) fn make_test_account_state_with_sink(
    name: &str,
    port: u16,
    imap_timeout: Duration,
    tool_call_timeout: Duration,
    sink: Arc<dyn AuthEventSink>,
) -> AccountState {
    let id = AccountId::new(name).expect("test account name must be valid");
    let mut conn_cfg = ConnectionConfig::new(
        id.clone(),
        "127.0.0.1".into(),
        port,
        rimap_imap::ImapEncryption::Tls,
        format!("{name}@test.invalid"),
        imap_timeout,
        imap_timeout,
        1024,
        1024,
    );
    conn_cfg.account = if name == rimap_core::account::DEFAULT_ACCOUNT_NAME {
        None
    } else {
        Some(name.to_string())
    };
    let creds: Arc<dyn CredentialResolver> = Arc::new(PanickingCreds);
    let imap = Connection::new(conn_cfg, sink, creds);

    let matrix = EffectiveMatrix::build(Posture::DraftSafe, &BTreeMap::new());
    let breaker = CircuitBreaker::new(SystemClock::new(), BreakerConfig::default_spec());
    let governor = Governor::new(10, 10, 10).expect("test governor");
    let guard = DispatchGuard::new(matrix, breaker, governor);

    let folder_guard = FolderGuard::new(&[], &[]);

    AccountState {
        id,
        imap,
        smtp: None,
        guard,
        folder_guard,
        download_dir: Arc::from(std::path::PathBuf::from("/tmp").into_boxed_path()),
        special_use: SpecialUseMap::default(),
        tool_call_timeout,
    }
}

/// Writes `body` as `config.toml` under `dir` and returns the config path.
///
/// Shared tail for every config fixture below so each builder stays a pure
/// body template.
pub(crate) fn write_config_toml(dir: &tempfile::TempDir, body: String) -> std::path::PathBuf {
    let config_path = dir.path().join("config.toml");
    std::fs::write(&config_path, body).expect("write test config.toml");
    config_path
}

/// Single-account config with an audit log and no defaults layer.
///
/// Pass `readonly_posture = true` to include a `[security]` section pinning
/// `posture = "readonly"`; pass `false` for the bare config the dry-run
/// tests use to exercise default (draft-safe) posture.
pub(crate) fn write_single_account_config(
    dir: &tempfile::TempDir,
    readonly_posture: bool,
) -> std::path::PathBuf {
    let security = if readonly_posture {
        "\n[security]\nposture = \"readonly\"\n"
    } else {
        ""
    };
    write_config_toml(
        dir,
        format!(
            r#"
[imap]
host = "127.0.0.1"
port = 1143
username = "alice@example.test"
{security}
[audit]
path = "{}"
allowed_base_dir = "{}"
"#,
            dir.path().join("audit.jsonl").display(),
            dir.path().display()
        ),
    )
}

/// Two-account config whose `[defaults.security.tools]` allows
/// `delete_message` and whose `work` account tightens posture to `readonly`
/// without restating that tool. This is the #632 case: the account holds a
/// destructive tool purely by inheritance.
pub(crate) fn write_inherited_allow_config(dir: &tempfile::TempDir) -> std::path::PathBuf {
    write_config_toml(
        dir,
        format!(
            r#"
[defaults.security]
posture = "full"

[defaults.security.tools]
delete_message = "allow"

[[accounts]]
name = "work"

[accounts.imap]
host = "127.0.0.1"
port = 1143
username = "alice@work.test"

[accounts.security]
posture = "readonly"

[accounts.security.tools]
search = "deny"

[audit]
path = "{audit}"
allowed_base_dir = "{base}"
"#,
            audit = dir.path().join("audit.jsonl").display(),
            base = dir.path().display(),
        ),
    )
}

/// Two-account config whose `[defaults.security]` names both folder lists.
///
/// The `work` account writes a partial `[accounts.security]` block that
/// restates neither list, so post-#624 it inherits both — including an
/// `expunge_folders` making `Trash` expungeable, which is the widening #696
/// exists to surface. With `personal_restates_protected` the `personal`
/// account also writes its own `protected_folders`, so both provenances
/// appear in one record; without it, only its `expunge_folders`.
pub(crate) fn write_inherited_folders_config(
    dir: &tempfile::TempDir,
    personal_restates_protected: bool,
) -> std::path::PathBuf {
    let personal_protected = if personal_restates_protected {
        "protected_folders = [\"Archive\"]\n"
    } else {
        ""
    };
    write_config_toml(
        dir,
        format!(
            r#"
[defaults.security]
posture = "draft-safe"
protected_folders = ["INBOX", "Sent"]
expunge_folders = ["Trash"]

[[accounts]]
name = "work"

[accounts.imap]
host = "127.0.0.1"
port = 1143
username = "alice@work.test"

[accounts.security]
posture = "readonly"

[[accounts]]
name = "personal"

[accounts.imap]
host = "127.0.0.1"
port = 1143
username = "alice@personal.test"

[accounts.security]
{personal_protected}expunge_folders = ["Junk"]

[audit]
path = "{audit}"
allowed_base_dir = "{base}"
"#,
            personal_protected = personal_protected,
            audit = dir.path().join("audit.jsonl").display(),
            base = dir.path().display(),
        ),
    )
}
