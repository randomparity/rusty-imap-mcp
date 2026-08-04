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
    let id = AccountId::new(name).expect("test account name must be valid");
    let conn_cfg = ConnectionConfig {
        account: if name == rimap_core::account::DEFAULT_ACCOUNT_NAME {
            None
        } else {
            Some(name.to_string())
        },
        account_id: id.clone(),
        host: "127.0.0.1".into(),
        port: 0,
        encryption: rimap_imap::ImapEncryption::Tls,
        username: format!("{name}@test.invalid"),
        pinned_fingerprint: None,
        connect_timeout: Duration::from_secs(1),
        command_timeout: Duration::from_secs(1),
        max_fetch_body_bytes: 1024,
        max_append_bytes: 1024,
    };
    let creds: Arc<dyn CredentialResolver> = Arc::new(PanickingCreds);
    let sink: Arc<dyn AuthEventSink> = Arc::new(DiscardingSink);
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
        tool_call_timeout: Duration::from_secs(300),
    }
}
