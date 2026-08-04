//! `Connection`: lazy-connect IMAP session with TLS fingerprint pinning,
//! command timeout enforcement, and `AuthEvent` audit emission.
//!
//! ## Locking discipline
//!
//! - The `tokio::sync::Mutex` around `Option<Session>` IS held across `.await`
//!   points (it has to be — async-imap commands are themselves `.await`).
//! - The injected [`AuthEventSink`] may hold its own internal
//!   `std::sync::Mutex` (the production `rimap-audit::AuditWriter`
//!   does). That lock is NEVER held across an `.await` because every
//!   call to [`AuthEventSink::emit_auth`] goes through
//!   `tokio::task::spawn_blocking`.
//!
//! These two rules are independent and both must hold. See
//! `docs/architecture/audit-locking.md`.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_imap::Session;
use rimap_core::TlsFingerprint;
use rimap_core::auth_sink::AuthEventSink;
use rimap_core::credential::CredentialResolver;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::client::TlsStream;

use crate::auth::{AuthContext, auth_failure, auth_success};
use crate::error::ImapError;
use crate::tls::{TlsConfigBundle, build_tls_config};

mod dispatch;
mod handshake;
mod login;

pub(crate) use handshake::{starttls_upgrade, tls_handshake};

// `ImapEncryption` is owned by `rimap-core` and shared with `rimap-config`,
// so adding a new transport mode is a single-place edit. Re-exported here
// so `rimap_imap::ImapEncryption` continues to resolve.
pub use rimap_core::ImapEncryption;

/// Everything `Connection` needs to open a session. The caller pulls
/// these fields from a validated config entry; `Connection` clones
/// the value once at construction time and never re-reads it.
///
/// Credential-fallback policy is NOT in this struct — that's a config
/// concern baked into the [`CredentialResolver`] handed to
/// [`Connection::new`].
#[derive(Debug, Clone)]
pub struct ConnectionConfig {
    /// Account name this connection belongs to. `None` for the legacy
    /// single-account `"default"` deployment; `Some(name)` in multi-account
    /// configs. Populated into [`AuthEvent`](rimap_core::auth_event::AuthEvent)
    /// audit records.
    pub account: Option<String>,
    /// Account id used for keyring lookups. Always set — the default account
    /// uses `AccountId::default_account()`.
    pub account_id: rimap_core::account::AccountId,
    /// IMAP server host.
    pub host: String,
    /// IMAP server port (typically 993 for IMAPS, 143/1143 for STARTTLS).
    pub port: u16,
    /// Transport encryption mode.
    pub encryption: ImapEncryption,
    /// IMAP username.
    pub username: String,
    /// Optional pinned TLS fingerprint. `None` = use system trust roots.
    pub pinned_fingerprint: Option<TlsFingerprint>,
    /// TCP + TLS handshake + greeting + CAPABILITY deadline.
    pub connect_timeout: Duration,
    /// Per-IMAP-command deadline applied via `tokio::time::timeout`.
    pub command_timeout: Duration,
    /// Hard cap on `FETCH BODY[]` byte count.
    pub max_fetch_body_bytes: u64,
    /// Hard cap on `APPEND` message byte count.
    pub max_append_bytes: u64,
}

/// Active IMAP session type alias. `async-imap` parameterizes over the
/// underlying transport; we always use `TlsStream<TcpStream>`.
pub(crate) type ImapSession = Session<TlsStream<TcpStream>>;

/// Lazy-connect IMAP connection. Cheaply cloneable (`Arc` internally).
#[derive(Clone)]
pub struct Connection {
    pub(super) inner: Arc<ConnectionInner>,
}

// Field order is drop-order-significant. Fields drop in declaration
// order; reorder only with care. Today the order is: config scalars
// first (cheap), then the Arc'd sink and resolver (refcount
// decrements — the real destructors run wherever the last handle is
// dropped), then the live IMAP session (so its teardown cannot observe
// dropped audit/credential sinks), then the capability atomics.
pub(super) struct ConnectionInner {
    pub(super) cfg: ConnectionConfig,
    pub(super) audit: Arc<dyn AuthEventSink>,
    pub(super) credentials: Arc<dyn CredentialResolver>,
    /// `None` = never connected, or last command tore down the connection.
    /// `Some(_)` = live session ready for the next command.
    pub(super) session: Mutex<Option<ImapSession>>,
    /// Server advertised MOVE capability (RFC 6851) after login.
    /// Reset to `false` on `invalidate()`.
    pub(super) has_move: AtomicBool,
    /// Server advertised UIDPLUS capability (RFC 4315) after login.
    /// Reset to `false` on `invalidate()`.
    pub(super) has_uidplus: AtomicBool,
    /// Set by [`Connection::poison`] when a command was cut mid-flight.
    /// Consumed by `dispatch::attempt` under the session lock; see `poison`
    /// for why it is a flag and not a lock.
    pub(super) poisoned: AtomicBool,
}

/// The session lock, held together with the poison flag it has to be ordered
/// against. Dropped undisarmed — which is what a cut command leaves behind —
/// it poisons the connection before releasing the lock (#620).
///
/// The ceiling in `rimap-server` (#594) poisons by *calling*
/// [`Connection::poison`], which works because the ceiling's own code runs on
/// the way out. Nothing runs on the way out of a client cancellation or a
/// runtime shutdown: those drop the whole dispatch future, and a `Drop` impl
/// is the only thing left that can observe it. [`Connection::poison`] being a
/// synchronous atomic store rather than an async invalidate is what makes
/// that expressible at all — a `Drop` impl cannot await.
///
/// ## Why the lock guard is a *field*
///
/// The flag only helps if it is set **before** the session lock is released,
/// because releasing the lock is what wakes the next FIFO waiter, and a peer
/// that queued while the cut command held the lock sits ahead of anything
/// that starts waiting later. Owning the lock guard is what makes that
/// ordering a property of this type: Rust runs a value's own `Drop::drop`
/// before dropping its fields, so `poison` always precedes the release, in
/// every drop path, however `dispatch::attempt` is later rearranged.
///
/// Two weaker placements were measured and rejected:
///
/// * A guard in a frame that *encloses* `attempt` — the audit envelope, or a
///   sibling around the dispatch, as issue #620 originally proposed. Dropping
///   a future drops that frame's locals in reverse declaration order, so the
///   nested `attempt` frame (and its lock guard) is already gone by the time
///   such a guard runs. It sets the flag strictly too late for exactly the
///   peer that needed it.
/// * A separate local declared after the lock guard inside `attempt`. That
///   one does drop first and is correct today, but only because of the order
///   of two `let` statements — nothing a reader or a refactor is forced to
///   preserve.
///
/// ## When it fires
///
/// Two conditions, both necessary. The guard must still be armed —
/// [`Self::disarm`] is called once the command body has finished with the
/// session, so an ordinary return is not a cut. And the slot must hold a
/// session: a cut during the lazy connect, or a `connect_inner` that returned
/// an error, leaves it empty, and there is no half-read response to protect
/// the next command from. Testing the slot in `Drop` is what keeps the flag
/// meaning "a command was cut" rather than also firing on every failed
/// connect; the alternative, an arming window opened after the connect, would
/// have to re-derive the live session afterwards and cost a branch that cannot
/// be reached.
pub(super) struct SessionGuard<'a> {
    conn: &'a Connection,
    armed: bool,
    /// Field order is irrelevant to the ordering guarantee above — `Drop::drop`
    /// precedes *all* field drops — so this sits last purely for readability.
    slot: tokio::sync::MutexGuard<'a, Option<ImapSession>>,
}

impl<'a> SessionGuard<'a> {
    /// Take ownership of an acquired session lock, armed.
    pub(super) fn new(
        conn: &'a Connection,
        slot: tokio::sync::MutexGuard<'a, Option<ImapSession>>,
    ) -> Self {
        Self {
            conn,
            armed: true,
            slot,
        }
    }

    /// The command finished with the session under its own control, so the
    /// drop that follows is an ordinary scope exit and must not poison.
    pub(super) fn disarm(&mut self) {
        self.armed = false;
    }
}

impl std::ops::Deref for SessionGuard<'_> {
    type Target = Option<ImapSession>;

    fn deref(&self) -> &Self::Target {
        &self.slot
    }
}

impl std::ops::DerefMut for SessionGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.slot
    }
}

impl Drop for SessionGuard<'_> {
    fn drop(&mut self) {
        if self.armed && self.slot.is_some() {
            self.conn.poison();
        }
    }
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("host", &self.inner.cfg.host)
            .field("port", &self.inner.cfg.port)
            .field("username", &self.inner.cfg.username)
            .finish_non_exhaustive()
    }
}

/// If `err` is `ImapError::TlsHandshake` and the bundle observed a fingerprint
/// that disagrees with `pinned`, rewrite into `ImapError::Tls { observed,
/// expected }`. Other error variants and matching observations pass through
/// unchanged. Centralizes the rewrite so every TLS-failing code path produces
/// a typed `ImapError::Tls { observed, expected }` when both fingerprints are
/// known, rather than the generic `TlsHandshake` variant.
pub(crate) fn enrich_tls_handshake_error(
    err: ImapError,
    bundle: &TlsConfigBundle,
    pinned: Option<TlsFingerprint>,
) -> ImapError {
    match err {
        ImapError::TlsHandshake(inner) => match (pinned, bundle.last_observed.get().copied()) {
            (Some(expected), Some(observed)) if expected != observed => {
                ImapError::Tls { observed, expected }
            }
            (Some(_) | None, _) => ImapError::TlsHandshake(inner),
        },
        other => other,
    }
}

impl Connection {
    /// Build a connection handle. Does NOT open a socket.
    ///
    /// `audit` and `credentials` are trait objects so the transport
    /// crate stays decoupled from any specific audit-log or credential
    /// store implementation. Production wiring uses the `rimap-audit`
    /// `AuditWriter` (which implements [`AuthEventSink`]) and the
    /// `rimap-config` `KeyringCredentialResolver`.
    #[must_use]
    pub fn new(
        cfg: ConnectionConfig,
        audit: Arc<dyn AuthEventSink>,
        credentials: Arc<dyn CredentialResolver>,
    ) -> Self {
        Self {
            inner: Arc::new(ConnectionInner {
                cfg,
                audit,
                credentials,
                session: Mutex::new(None),
                has_move: AtomicBool::new(false),
                has_uidplus: AtomicBool::new(false),
                poisoned: AtomicBool::new(false),
            }),
        }
    }

    /// Read the configured host (used by ops to log context).
    #[must_use]
    pub fn host(&self) -> &str {
        &self.inner.cfg.host
    }

    /// Read the configured IMAP username. Typically the account's
    /// email address, and suitable for use as the `From:` header.
    #[must_use]
    pub fn username(&self) -> &str {
        &self.inner.cfg.username
    }

    /// Maximum bytes a single `fetch_body` will accept (config cap).
    #[must_use]
    pub fn max_fetch_body_bytes(&self) -> u64 {
        self.inner.cfg.max_fetch_body_bytes
    }

    /// Whether the server advertised the MOVE capability (RFC 6851).
    #[must_use]
    pub fn has_move_capability(&self) -> bool {
        self.inner.has_move.load(Ordering::Relaxed)
    }

    /// Whether the server advertised the UIDPLUS capability (RFC 4315).
    #[must_use]
    pub fn has_uidplus_capability(&self) -> bool {
        self.inner.has_uidplus.load(Ordering::Relaxed)
    }

    /// Mark the cached session unusable without taking the session lock.
    /// The next command to acquire the lock drops the session before
    /// touching it, so the account reconnects.
    ///
    /// For anything that cuts a command mid-flight. A dispatch future
    /// dropped mid-command leaves the cached session holding an unread
    /// server response that the next command would misparse as its own,
    /// and no error `with_session` recognizes as a transport failure, so
    /// it would never self-heal. Two callers reach it:
    ///
    /// * The per-tool-call ceiling in `rimap-server` (#594, ADR-0012),
    ///   which calls this directly because its own code runs when it
    ///   fires.
    /// * [`SessionGuard`], which holds the session lock inside
    ///   `dispatch::attempt`, for the cuts where none of our code runs at
    ///   all — a client cancellation or a runtime shutdown dropping the
    ///   dispatch future (#620).
    ///
    /// This is a flag rather than a call to [`Self::invalidate`] because
    /// `tokio::sync::Mutex` is FIFO-fair: a peer command that queued on
    /// the lock while the cut command held it sits *ahead* of anything
    /// that starts waiting now, and would take the poisoned session
    /// first.
    ///
    /// The flag beats that waiter only if it is set **before** the cut
    /// command's guard is dropped, since dropping the guard is what wakes
    /// the waiter. `with_tool_call_ceiling` holds the cut dispatch alive
    /// across this call for that reason; see its docs. Because the caller
    /// therefore still holds the session lock, this must not try to take
    /// it — hence a plain store rather than an `async fn`.
    ///
    /// `Relaxed` is sufficient: the flag publishes no data of its own — the
    /// session is published through the mutex, whose release/acquire is the
    /// synchronizing edge whenever the poisoner held the guard.
    ///
    /// A ceiling can also fire with no guard held at all: parked on the
    /// lock-acquire timeout, between two IMAP operations in a multi-op tool,
    /// or inside a `spawn_blocking` join. Those poisons are precautionary —
    /// there is no half-read session to protect, and the worst outcome is
    /// that the next command reconnects a healthy one. So the lack of an
    /// ordering edge on that path costs correctness nothing; do not read
    /// the mutex edge as covering every caller.
    pub fn poison(&self) {
        self.inner.poisoned.store(true, Ordering::Relaxed);
    }

    /// Consume the poison flag: if set, clear `slot` so the caller
    /// lazy-reconnects, and report that it did. Called by
    /// `dispatch::attempt` while holding the session lock.
    ///
    /// The swap makes the flag one-shot — a second command must not
    /// discard a session poisoned before the first one already replaced
    /// it. `Relaxed` for the same reason as [`Self::poison`]: where an
    /// ordering edge is needed at all, the mutex carries it.
    pub(super) fn take_poisoned(&self, slot: &mut Option<ImapSession>) -> bool {
        if !self.inner.poisoned.swap(false, Ordering::Relaxed) {
            return false;
        }
        *slot = None;
        self.inner.has_move.store(false, Ordering::Relaxed);
        self.inner.has_uidplus.store(false, Ordering::Relaxed);
        true
    }

    /// Drop any current session. Called by ops on connection-lost errors.
    pub(crate) async fn invalidate(&self) {
        let mut guard = self.inner.session.lock().await;
        *guard = None;
        self.inner.has_move.store(false, Ordering::Relaxed);
        self.inner.has_uidplus.store(false, Ordering::Relaxed);
    }

    /// The full connect/handshake/login/CAPABILITY flow. Emits exactly one
    /// `Auth` audit record on every termination path.
    ///
    /// Callers must not wrap this in a shorter deadline than `connect_timeout`:
    /// the emit happens after `connect_with_bundle` returns, so cancelling the
    /// future mid-connect loses the record. See `dispatch::attempt`, which
    /// deliberately runs it outside the command timeout.
    pub(super) async fn connect_inner(&self) -> Result<ImapSession, ImapError> {
        let cfg = &self.inner.cfg;
        let bundle = build_tls_config(cfg.pinned_fingerprint)?;

        // Run the connect flow. The return type carries `credential_source` for
        // both the success and post-resolve-failure paths.  Pre-resolve failures
        // (TLS, connect, greeting, CAPABILITY) return `None`; post-resolve
        // failures (LoginRejected) and success both return `Some(source)`.
        let raw_outcome = self.connect_with_bundle(&bundle).await;
        let (outcome, credential_source) = match raw_outcome {
            Ok((session, src)) => (Ok(session), Some(src)),
            Err((err, src)) => (
                Err(enrich_tls_handshake_error(
                    err,
                    &bundle,
                    cfg.pinned_fingerprint,
                )),
                src,
            ),
        };

        let observed = bundle.last_observed.get().copied();
        let ctx = AuthContext {
            account: cfg.account.as_deref(),
            host: &cfg.host,
            port: cfg.port,
            username: &cfg.username,
            pinned: cfg.pinned_fingerprint,
            observed,
            credential_source,
        };

        match &outcome {
            Ok(_) => self.emit_auth(auth_success(&ctx)).await?,
            Err(err) => {
                // Deliberate: log but do NOT propagate emit_auth failures on
                // the error branch. The ORIGINAL outcome (ImapError::Auth,
                // ImapError::TlsHandshake, ImapError::Connect, ...) is what the
                // caller and monitoring need to see. Replacing it with
                // ImapError::Audit would mask brute-force signals from
                // whatever observed ERR_AUTH before. Audit-write failures
                // on this path are still visible via tracing; operators
                // running fail_open=false will additionally see the
                // suppressed_failures counter in process_end once #8
                // lands.
                if let Err(audit_err) = self.emit_auth(auth_failure(&ctx, err.code())).await {
                    tracing::error!(
                        original_error = %err,
                        audit_error = %audit_err,
                        "audit write failed during auth-failure emission; \
                         preserving original error for observability",
                    );
                }
            }
        }
        outcome
    }
}

#[cfg(test)]
#[expect(clippy::panic, reason = "tests")]
#[expect(clippy::expect_used, reason = "tests")]
mod tests {
    use rimap_core::TlsFingerprint;

    use crate::error::{AuthFailure, ImapError};

    fn fp_zeros() -> TlsFingerprint {
        TlsFingerprint::from_hex(&"00".repeat(32)).expect("valid 32-byte hex literal")
    }

    #[derive(Debug)]
    struct NoopSink;

    impl rimap_core::auth_sink::AuthEventSink for NoopSink {
        fn emit_auth(
            &self,
            _event: rimap_core::auth_event::AuthEvent,
        ) -> Result<(), rimap_core::auth_sink::AuthSinkError> {
            Ok(())
        }
    }

    #[derive(Debug)]
    struct UnusedResolver;

    impl rimap_core::credential::CredentialResolver for UnusedResolver {
        #[expect(
            clippy::panic_in_result_fn,
            reason = "accessor test builds a Connection but never opens a session"
        )]
        fn resolve(
            &self,
            _account: &rimap_core::account::AccountId,
            _username: &str,
            _host: &str,
        ) -> Result<
            (
                secrecy::SecretString,
                rimap_core::credential::CredentialSource,
            ),
            rimap_core::credential::CredentialResolverError,
        > {
            panic!("credential resolver must not be invoked by an accessor test");
        }
    }

    fn connection_with(host: &str, username: &str, max_fetch_body_bytes: u64) -> super::Connection {
        let cfg = super::ConnectionConfig {
            account: None,
            account_id: rimap_core::account::AccountId::default_account(),
            host: host.to_string(),
            port: 993,
            encryption: super::ImapEncryption::Starttls,
            username: username.to_string(),
            pinned_fingerprint: None,
            connect_timeout: std::time::Duration::from_secs(5),
            command_timeout: std::time::Duration::from_secs(5),
            max_fetch_body_bytes,
            max_append_bytes: 1024,
        };
        super::Connection::new(
            cfg,
            std::sync::Arc::new(NoopSink),
            std::sync::Arc::new(UnusedResolver),
        )
    }

    /// `poison` is a one-shot flag consumed under the session lock. The
    /// one-shot property is load-bearing: a second command must not
    /// discard a session the first command already reconnected after
    /// consuming the same poison (#594).
    ///
    /// This covers the flag's own state machine. That `attempt` actually
    /// consumes it — the call site the ceiling's recovery depends on — is
    /// pinned separately by `tests/poison_reconnect.rs` over the scriptable
    /// fake, because deleting that call site leaves this test green.
    ///
    /// The capability reset is asserted here because a stale `has_move`
    /// would let the next command issue `MOVE` against a server that never
    /// advertised it.
    #[test]
    fn poison_is_consumed_once_and_resets_capabilities() {
        use std::sync::atomic::Ordering;

        let conn = connection_with("mail.example.com", "alice@example.com", 4096);
        let mut slot = None;

        assert!(
            !conn.take_poisoned(&mut slot),
            "an unpoisoned connection must not report a discard",
        );

        conn.inner.has_move.store(true, Ordering::Relaxed);
        conn.inner.has_uidplus.store(true, Ordering::Relaxed);
        conn.poison();

        assert!(
            conn.take_poisoned(&mut slot),
            "poison must be observed by the next holder of the session lock",
        );
        assert!(
            !conn.has_move_capability(),
            "MOVE capability must not survive a poison",
        );
        assert!(
            !conn.has_uidplus_capability(),
            "UIDPLUS capability must not survive a poison",
        );
        assert!(
            !conn.take_poisoned(&mut slot),
            "the flag must be consumed, not latched",
        );
    }

    /// An **armed** `SessionGuard` dropped over an empty slot must not poison.
    /// That is the lazy-connect window: a cut there, or a `connect_inner` that
    /// returned an error, caches nothing, so there is no half-read response to
    /// protect the next command from and the flag must keep meaning "a command
    /// was cut".
    ///
    /// This is the only arm of `Drop` a unit test can decide. Both others turn
    /// on a slot holding a live `ImapSession`, which only a server can
    /// produce — so *poison when armed* and *do not poison once disarmed* are
    /// pinned end-to-end by the paired tests in `tests/cancel_poison.rs`, over
    /// the scriptable fake. Asserting them here against an empty slot would
    /// pass whatever `armed` held, which is no assertion at all.
    ///
    /// That the guard's `Drop` beats the lock release is asserted nowhere,
    /// deliberately: a test of it could only flake, never fail, because the
    /// woken waiter cannot run until the dropping task yields. It is a
    /// language guarantee (`Drop::drop` runs before a value's fields are
    /// dropped) bought by making the lock guard a *field*.
    #[tokio::test]
    async fn session_guard_does_not_poison_before_a_session_is_cached() {
        use std::sync::atomic::Ordering;

        let conn = connection_with("mail.example.com", "alice@example.com", 4096);
        {
            let _guard = super::SessionGuard::new(&conn, conn.inner.session.lock().await);
            // Dropped armed, slot still empty.
        }

        assert!(
            !conn.inner.poisoned.load(Ordering::Relaxed),
            "a cut before a session was cached must not poison: the next \
             command would discard an already-empty slot",
        );
    }

    #[test]
    fn config_accessors_return_the_configured_values() {
        // Pins the `host`/`username`/`max_fetch_body_bytes` getters to the
        // config they read. `username()` in particular feeds the compose
        // `From:` address, so a getter that dropped the value (e.g. returned
        // `""`) would silently forge sender identity.
        let conn = connection_with("mail.example.com", "alice@example.com", 4096);
        assert_eq!(conn.host(), "mail.example.com");
        assert_eq!(conn.username(), "alice@example.com");
        assert_eq!(conn.max_fetch_body_bytes(), 4096);
    }

    #[test]
    fn error_code_for_covers_every_variant() {
        use crate::error::StarttlsFailure;
        let cases: Vec<(ImapError, &str)> = vec![
            (
                ImapError::Tls {
                    observed: fp_zeros(),
                    expected: fp_zeros(),
                },
                "ERR_TLS",
            ),
            (
                ImapError::TlsHandshake(tokio_rustls::rustls::Error::General("x".into())),
                "ERR_TLS",
            ),
            (
                ImapError::Starttls {
                    reason: StarttlsFailure::CapabilityMissing,
                },
                "ERR_TLS",
            ),
            (
                ImapError::Connect(std::io::Error::other("boom")),
                "ERR_CONNECTION_LOST",
            ),
            (ImapError::ConnectionLost, "ERR_CONNECTION_LOST"),
            (ImapError::Timeout { op: "select" }, "ERR_TIMEOUT"),
            (
                ImapError::Auth {
                    reason: AuthFailure::ServerRejected,
                },
                "ERR_AUTH",
            ),
            (
                ImapError::SizeLimit { limit: 0 },
                "ERR_ATTACHMENT_TOO_LARGE",
            ),
            (
                ImapError::Protocol(async_imap::error::Error::Bad("x".into())),
                "ERR_IMAP_PROTOCOL",
            ),
            (
                ImapError::FolderNotFound {
                    name: "Missing".to_string(),
                },
                "ERR_NOT_FOUND",
            ),
            (
                ImapError::InvalidInput {
                    field: "f",
                    reason: "r",
                },
                "ERR_INVALID_INPUT",
            ),
            (
                ImapError::BatchTooLarge {
                    count: 200,
                    limit: 100,
                },
                "ERR_INVALID_INPUT",
            ),
            (
                ImapError::UidValidityChanged {
                    folder: "INBOX".to_string(),
                    expected: 100,
                    actual: 101,
                },
                "ERR_UID_VALIDITY_CHANGED",
            ),
            (
                ImapError::UidValidityUnavailable {
                    folder: "INBOX".to_string(),
                },
                "ERR_UID_VALIDITY_CHANGED",
            ),
            (
                ImapError::Audit {
                    op: "test",
                    message: "test".to_string(),
                    source: Box::new(std::io::Error::other("test")),
                },
                "ERR_INTERNAL",
            ),
        ];
        for (err, expected) in &cases {
            assert_eq!(err.code().as_str(), *expected, "for {err:?}");
        }
    }

    fn bundle_with_observed(observed: TlsFingerprint) -> crate::tls::TlsConfigBundle {
        let b = crate::tls::build_tls_config(None).expect("build_tls_config");
        b.last_observed.get_or_init(|| observed);
        b
    }

    #[test]
    fn enrich_tls_handshake_mismatch_rewrites_to_typed_tls_error() {
        // When the observed fingerprint differs from the configured pin, the
        // raw TlsHandshake error must be rewritten to Tls { observed, expected }
        // so callers can surface the exact fingerprints.
        let expected = TlsFingerprint::from_cert_der(b"expected-pin");
        let observed = TlsFingerprint::from_cert_der(b"observed-cert");
        assert_ne!(expected, observed);
        let bundle = bundle_with_observed(observed);
        let err = ImapError::TlsHandshake(tokio_rustls::rustls::Error::General(
            "handshake failed".into(),
        ));
        let enriched = super::enrich_tls_handshake_error(err, &bundle, Some(expected));
        match enriched {
            ImapError::Tls {
                observed: obs,
                expected: exp,
            } => {
                assert_eq!(obs, observed, "observed fingerprint must be propagated");
                assert_eq!(exp, expected, "expected fingerprint must be propagated");
            }
            other => panic!("expected Tls variant, got {other:?}"),
        }
    }

    #[test]
    fn enrich_tls_handshake_matching_pin_passes_through_unchanged() {
        // When observed == expected (matching pin), the error must pass through as
        // TlsHandshake — a non-mismatch handshake failure should not masquerade as
        // a pin mismatch.
        let fp = TlsFingerprint::from_cert_der(b"same-cert");
        let bundle = bundle_with_observed(fp);
        let err =
            ImapError::TlsHandshake(tokio_rustls::rustls::Error::General("other error".into()));
        let enriched = super::enrich_tls_handshake_error(err, &bundle, Some(fp));
        match enriched {
            ImapError::TlsHandshake(e) => {
                assert!(e.to_string().contains("other error"));
            }
            other => panic!("expected TlsHandshake variant (no rewrite), got {other:?}"),
        }
    }

    #[test]
    fn enrich_tls_handshake_no_pin_passes_through_unchanged() {
        // When no pin is configured, TlsHandshake must pass through regardless
        // of the observed fingerprint.
        let observed = TlsFingerprint::from_cert_der(b"some-cert");
        let bundle = bundle_with_observed(observed);
        let err =
            ImapError::TlsHandshake(tokio_rustls::rustls::Error::General("generic tls".into()));
        let enriched = super::enrich_tls_handshake_error(err, &bundle, None);
        match enriched {
            ImapError::TlsHandshake(_) => {}
            other => panic!("expected TlsHandshake passthrough, got {other:?}"),
        }
    }

    #[test]
    fn enrich_tls_handshake_non_handshake_error_passes_through() {
        // Only TlsHandshake variants are rewritten; other ImapError variants must
        // pass through unmodified.
        let bundle = bundle_with_observed(TlsFingerprint::from_cert_der(b"any"));
        let err = ImapError::Timeout { op: "tcp_connect" };
        let enriched = super::enrich_tls_handshake_error(
            err,
            &bundle,
            Some(TlsFingerprint::from_cert_der(b"pin")),
        );
        match enriched {
            ImapError::Timeout { op: "tcp_connect" } => {}
            other => panic!("expected Timeout passthrough, got {other:?}"),
        }
    }
}
