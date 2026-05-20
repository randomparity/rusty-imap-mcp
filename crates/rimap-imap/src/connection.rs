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
use async_imap::imap_proto::{Capability as ImapCapability, Response, Status};
use async_imap::types::UnsolicitedResponse;
use rimap_core::TlsFingerprint;
use rimap_core::auth_event::AuthEvent;
use rimap_core::auth_sink::AuthEventSink;
use rimap_core::credential::CredentialResolver;
use secrecy::ExposeSecret;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::ServerName;

use crate::auth::{AuthContext, auth_failure, auth_success};
use crate::error::{AuthFailure, ImapError, StarttlsFailure, StarttlsRefusal};
use crate::tls::{TlsConfigBundle, build_tls_config};

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
    /// configs. Populated into [`AuthEvent`] audit records.
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
    inner: Arc<ConnectionInner>,
}

// Field order is drop-order-significant. Fields drop in declaration
// order; reorder only with care. Today the order is: config scalars
// first (cheap), then the Arc'd sink and resolver (refcount
// decrements — the real destructors run wherever the last handle is
// dropped), then the live IMAP session (so its teardown cannot observe
// dropped audit/credential sinks), then the capability atomics.
struct ConnectionInner {
    cfg: ConnectionConfig,
    audit: Arc<dyn AuthEventSink>,
    credentials: Arc<dyn CredentialResolver>,
    /// `None` = never connected, or last command tore down the connection.
    /// `Some(_)` = live session ready for the next command.
    session: Mutex<Option<ImapSession>>,
    /// Server advertised MOVE capability (RFC 6851) after login.
    /// Reset to `false` on `invalidate()`.
    has_move: AtomicBool,
    /// Server advertised UIDPLUS capability (RFC 4315) after login.
    /// Reset to `false` on `invalidate()`.
    has_uidplus: AtomicBool,
    /// Server advertised LIST-STATUS capability (RFC 5819) after login.
    /// Currently informational: async-imap does not yet expose the
    /// extended LIST command, so `list_folders_with_status` always takes
    /// the per-folder STATUS fallback path. Once async-imap surfaces
    /// LIST-STATUS, the fallback can gate on this flag.
    has_list_status: AtomicBool,
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
                has_list_status: AtomicBool::new(false),
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

    /// Acquire the session lock; lazy-connect if needed. The returned guard
    /// holds the tokio mutex; drop it before any other method on `Connection`.
    pub(crate) async fn session(
        &self,
    ) -> Result<tokio::sync::MutexGuard<'_, Option<ImapSession>>, ImapError> {
        let mut guard = self.inner.session.lock().await;
        if guard.is_none() {
            let session = self.connect_inner().await?;
            *guard = Some(session);
        }
        Ok(guard)
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

    /// Whether the server advertises LIST-STATUS (RFC 5819).
    ///
    /// Currently informational — `list_folders_with_status` always uses
    /// the LIST-then-STATUS-per-folder fallback regardless. A future
    /// async-imap release may expose the extended LIST command.
    #[must_use]
    pub fn has_list_status_capability(&self) -> bool {
        self.inner.has_list_status.load(Ordering::Relaxed)
    }

    /// Drop any current session. Called by ops on connection-lost errors.
    pub(crate) async fn invalidate(&self) {
        let mut guard = self.inner.session.lock().await;
        *guard = None;
        self.inner.has_move.store(false, Ordering::Relaxed);
        self.inner.has_uidplus.store(false, Ordering::Relaxed);
        self.inner.has_list_status.store(false, Ordering::Relaxed);
    }

    /// The full connect/handshake/login/CAPABILITY flow. Emits exactly one
    /// `Auth` audit record on every termination path.
    async fn connect_inner(&self) -> Result<ImapSession, ImapError> {
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

    /// Returns `Ok((session, credential_source))` on success, or
    /// `Err((error, Option<credential_source>))` on failure. The
    /// `credential_source` in the `Err` variant is `Some` when the failure
    /// occurred after `resolve_credential` succeeded (e.g. server rejected
    /// the credentials), and `None` for pre-resolve failures (TLS, connect,
    /// greeting, CAPABILITY).
    async fn connect_with_bundle(
        &self,
        bundle: &TlsConfigBundle,
    ) -> Result<
        (ImapSession, rimap_core::CredentialSource),
        (ImapError, Option<rimap_core::CredentialSource>),
    > {
        let cfg = &self.inner.cfg;
        let total_deadline = cfg.connect_timeout;
        let started = std::time::Instant::now();

        // Step 1: TCP connect. Pre-resolve; failures carry `None`.
        let tcp = timeout(
            total_deadline,
            TcpStream::connect((cfg.host.as_str(), cfg.port)),
        )
        .await
        .map_err(|_| (ImapError::Timeout { op: "tcp_connect" }, None))?
        .map_err(|e| (ImapError::Connect(e), None))?;

        // Step 2: TLS establishment. Branches on encryption mode.
        // The `already_greeted` flag tracks whether the plaintext greeting was
        // already consumed during STARTTLS negotiation (true) or must be read
        // from the TLS stream (false).
        let elapsed = started.elapsed();
        let remaining = total_deadline.saturating_sub(elapsed);
        let (tls_stream, already_greeted): (TlsStream<TcpStream>, bool) = match cfg.encryption {
            ImapEncryption::Tls => {
                let s = timeout(remaining, tls_handshake(tcp, bundle, &cfg.host))
                    .await
                    .map_err(|_| {
                        (
                            ImapError::Timeout {
                                op: "tls_handshake",
                            },
                            None,
                        )
                    })?
                    .map_err(|e| (e, None))?;
                (s, false)
            }
            ImapEncryption::Starttls => {
                let s = timeout(remaining, starttls_upgrade(tcp, bundle, &cfg.host))
                    .await
                    .map_err(|_| {
                        (
                            ImapError::Timeout {
                                op: "starttls_upgrade",
                            },
                            None,
                        )
                    })?
                    .map_err(|e| (e, None))?;
                (s, true)
            }
        };

        // Step 3: IMAP greeting + capability check + login. The login step
        // may return a credential source on both success and certain failures.
        // STARTTLS already consumed the plaintext greeting during negotiation;
        // `imap_login` must skip the greeting read in that case.
        let elapsed = started.elapsed();
        let remaining = total_deadline.saturating_sub(elapsed);
        timeout(remaining, self.imap_login(tls_stream, already_greeted))
            .await
            .map_err(|_| (ImapError::Timeout { op: "imap_login" }, None))?
    }

    /// Run the IMAP greeting + CAPABILITY probe + LOGIN sequence.
    ///
    /// `already_greeted` must be `true` for the STARTTLS path: the plaintext
    /// greeting was already consumed during STARTTLS negotiation, so the server
    /// does not send another greeting after the TLS handshake.
    ///
    /// ## async-imap 0.11 API notes
    ///
    /// `capabilities()` is on `Session` (post-login), not on `Client`. To
    /// check LOGINDISABLED pre-login we:
    ///   1. Read the greeting via `Connection::read_response()` (implicit TLS only).
    ///   2. Issue `CAPABILITY` via `Connection::run_command_and_check_ok(cmd, Some(tx))`
    ///      and drain the unsolicited channel for `Other(ResponseData)` items
    ///      containing `Response::Capabilities` data.
    ///   3. Call `client.login(user, pass)`.
    ///
    /// Returns `Ok((session, credential_source))` on success.
    /// Returns `Err((error, Some(source)))` when the failure occurred after
    /// `resolve_credential` succeeded (e.g. server rejected the credentials).
    /// Returns `Err((error, None))` for pre-resolve failures (greeting, CAPABILITY).
    async fn imap_login(
        &self,
        tls_stream: TlsStream<TcpStream>,
        already_greeted: bool,
    ) -> Result<
        (ImapSession, rimap_core::CredentialSource),
        (ImapError, Option<rimap_core::CredentialSource>),
    > {
        let mut client = async_imap::Client::new(tls_stream);

        // Read the server greeting — skipped for STARTTLS, which already
        // consumed the greeting during plaintext negotiation. An absent greeting
        // (EOF) or BYE status means the server immediately rejected us.
        // Pre-resolve; carry `None`.
        if !already_greeted {
            let greeting = client
                .read_response()
                .await
                .map_err(|e| (ImapError::Connect(e), None))?
                .ok_or((
                    ImapError::Auth {
                        reason: AuthFailure::ServerRejected,
                    },
                    None,
                ))?;

            if let Response::Data {
                status: Status::Bye,
                ..
            } = greeting.parsed()
            {
                return Err((
                    ImapError::Auth {
                        reason: AuthFailure::ServerRejected,
                    },
                    None,
                ));
            }
        }

        // Issue CAPABILITY and scan responses for LOGINDISABLED.
        // We create a bounded channel so intermediate untagged responses
        // (including `* CAPABILITY ...`) are routed through it rather than
        // being silently discarded. Pre-resolve; carry `None`.
        let (tx, rx) = async_channel::bounded::<UnsolicitedResponse>(32);
        client
            .run_command_and_check_ok("CAPABILITY", Some(tx))
            .await
            .map_err(|e| (ImapError::Protocol(e), None))?;

        // Drain whatever arrived on the channel (non-blocking; the command
        // has already completed). A `Response::Capabilities` list containing
        // LOGINDISABLED means LOGIN is prohibited. Pre-resolve; carry `None`.
        let logindisabled = drain_for_logindisabled(&rx);
        if logindisabled {
            return Err((
                ImapError::Auth {
                    reason: AuthFailure::CapabilityMissing { needed: "LOGIN" },
                },
                None,
            ));
        }

        // Resolve the password from the injected resolver. A missing
        // credential is an authentication failure, not a network
        // failure — map it to ERR_AUTH so retry logic and operator
        // messages stay accurate. Pre-resolve; carry `None`.
        let cfg = &self.inner.cfg;
        let (password, credential_source) = self
            .inner
            .credentials
            .resolve(&cfg.account_id, &cfg.username, &cfg.host)
            .map_err(|e| {
                (
                    ImapError::Auth {
                        reason: AuthFailure::CredentialUnavailable(e.into_reason()),
                    },
                    None,
                )
            })?;

        // From here on, all errors carry `Some(credential_source)` because
        // resolution succeeded.
        //
        // Attempt LOGIN. On NO response the server rejected the credentials.
        // Expose the secret only at the moment of use; the borrow ends
        // when `client.login` returns.
        let mut session = match client.login(&cfg.username, password.expose_secret()).await {
            Ok(session) => session,
            Err((err, _client)) => {
                return match err {
                    async_imap::error::Error::No(_) => Err((
                        ImapError::Auth {
                            reason: AuthFailure::LoginRejected,
                        },
                        Some(credential_source),
                    )),
                    other => Err((ImapError::Protocol(other), Some(credential_source))),
                };
            }
        };

        // Post-login: probe CAPABILITY for MOVE (RFC 6851),
        // UIDPLUS (RFC 4315), and LIST-STATUS (RFC 5819).
        let (has_move, has_uidplus, has_list_status) = match session.capabilities().await {
            Ok(caps) => (
                caps.has_str("MOVE"),
                caps.has_str("UIDPLUS"),
                caps.has_str("LIST-STATUS"),
            ),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "post-login CAPABILITY probe failed; \
                     assuming no MOVE/UIDPLUS/LIST-STATUS support",
                );
                (false, false, false)
            }
        };
        self.inner.has_move.store(has_move, Ordering::Relaxed);
        self.inner.has_uidplus.store(has_uidplus, Ordering::Relaxed);
        self.inner
            .has_list_status
            .store(has_list_status, Ordering::Relaxed);

        Ok((session, credential_source))
    }

    /// Emit an [`AuthEvent`] through the injected sink. Runs the
    /// (sync) `emit_auth` call inside `spawn_blocking` so any
    /// `std::sync::Mutex` the sink holds (the production
    /// `AuditWriter` impl does) is never held across an `.await`
    /// boundary.
    ///
    /// ## Cancellation behavior
    ///
    /// If the caller future is cancelled at the `.await` below, the
    /// `JoinHandle` is dropped but the `spawn_blocking` task runs to
    /// completion — `tokio` does not kill blocking tasks on handle drop.
    /// The audit record IS written in that case, but the `Result` is
    /// lost: the caller sees neither a success nor an error. This is the
    /// least-bad outcome (audit integrity preserved, caller just gets a
    /// cancellation). Callers that MUST know whether the write succeeded
    /// should not drop this future.
    ///
    /// ## `ImapError` message sanitization
    ///
    /// The [`AuthEventSink`] contract requires implementations to
    /// pre-sanitize the `message` field on [`rimap_core::AuthSinkError`]
    /// (no filesystem paths or operator-configured layout). This
    /// function forwards that `message` verbatim — the full
    /// underlying error is preserved on the `source` chain for
    /// observability.
    async fn emit_auth(&self, event: AuthEvent) -> Result<(), ImapError> {
        let sink = self.inner.audit.clone();
        let join_result = tokio::task::spawn_blocking(move || sink.emit_auth(event)).await;
        match join_result {
            Err(join_err) => Err(ImapError::Audit {
                op: "emit_auth",
                message: "tokio join error during audit write".to_string(),
                source: Box::new(join_err),
            }),
            Ok(Err(sink_err)) => {
                tracing::error!(
                    error = %sink_err,
                    "AuthEventSink::emit_auth failed; converting to ImapError::Audit",
                );
                let message = sink_err.message().to_string();
                Err(ImapError::Audit {
                    op: "emit_auth",
                    message,
                    source: Box::new(sink_err),
                })
            }
            Ok(Ok(())) => Ok(()),
        }
    }

    /// Run an IMAP operation with a command timeout and automatic session
    /// invalidation on connection-level failures.
    ///
    /// The closure receives a mutable reference to the live `Session`.
    /// If it returns `ImapError::ConnectionLost` or `ImapError::Timeout`, the
    /// cached session is dropped so the next call lazy-reconnects.
    async fn with_session<T, F>(&self, op_name: &'static str, body: F) -> Result<T, ImapError>
    where
        F: for<'s> AsyncFnOnce(&'s mut ImapSession) -> Result<T, ImapError>,
    {
        let dur = self.inner.cfg.command_timeout;
        let result = crate::time::with_timeout(op_name, dur, async {
            let mut guard = self.session().await?;
            let session =
                guard
                    .as_mut()
                    .ok_or(ImapError::Protocol(async_imap::error::Error::Bad(
                        "session invariant violated: guard is None after session()".to_string(),
                    )))?;
            body(session).await
        })
        .await;
        if let Err(ImapError::ConnectionLost | ImapError::Timeout { .. }) = &result {
            self.invalidate().await;
        }
        result
    }

    /// `LIST` against `pattern` (e.g. `"*"`, `"INBOX/*"`).
    ///
    /// Drops the cached session on `ConnectionLost` so the next call
    /// lazy-reconnects without auto-retrying the failed command.
    ///
    /// # Errors
    /// Propagates any `ImapError` produced by `time::with_timeout` or the
    /// underlying `ops::folders::list` call.
    pub async fn list_folders(
        &self,
        pattern: &str,
    ) -> Result<Vec<crate::types::Folder>, ImapError> {
        self.with_session("list", async |session| {
            crate::ops::folders::list(session, pattern).await
        })
        .await
    }

    /// List folders and fetch their STATUS in a single operation,
    /// using RFC 5819 LIST-STATUS when the server advertises the
    /// capability. Currently always falls back to LIST-then-STATUS-
    /// per-folder (async-imap does not yet expose the extended LIST).
    ///
    /// Returns `(Folder, Option<FolderStatus>)` pairs. Non-selectable
    /// folders return `None` for the status.
    ///
    /// # Errors
    /// Propagates `ImapError` from the underlying commands.
    pub async fn list_folders_with_status(
        &self,
        pattern: &str,
    ) -> Result<Vec<(crate::types::Folder, Option<crate::types::FolderStatus>)>, ImapError> {
        let has_list_status = self.inner.has_list_status.load(Ordering::Relaxed);
        self.with_session("list_folders_with_status", async move |session| {
            crate::ops::folders::list_with_status(session, pattern, has_list_status).await
        })
        .await
    }

    /// `STATUS` for `folder` selecting the requested items.
    ///
    /// # Errors
    /// Propagates any `ImapError` produced by `time::with_timeout` or the
    /// underlying `ops::folders::status` call.
    pub async fn status(
        &self,
        folder: &str,
        items: crate::types::StatusItems,
    ) -> Result<crate::types::FolderStatus, ImapError> {
        self.with_session("status", async |session| {
            crate::ops::folders::status(session, folder, items).await
        })
        .await
    }

    /// `SELECT` (or `EXAMINE` if `read_only`) the named folder.
    ///
    /// # Errors
    /// Propagates any `ImapError` produced by `time::with_timeout` or the
    /// underlying `ops::folders::select` call.
    pub async fn select(
        &self,
        folder: &str,
        read_only: bool,
    ) -> Result<crate::types::SelectedFolder, ImapError> {
        self.with_session("select", async |session| {
            crate::ops::folders::select(session, folder, read_only).await
        })
        .await
    }

    /// `SEARCH` against `folder`. Returns matching UIDs.
    ///
    /// # Errors
    /// Propagates timeout, connection-lost, or protocol errors from the
    /// underlying `ops::search::search` call.
    pub async fn search(
        &self,
        folder: &str,
        query: crate::types::SearchQuery,
    ) -> Result<Vec<crate::types::Uid>, ImapError> {
        self.with_session("search", async |session| {
            crate::ops::search::search(session, folder, query).await
        })
        .await
    }

    /// `FETCH` for the given UIDs with the requested items. Does NOT include
    /// `BODY[]` — see `fetch_body` (Task 13) for full message retrieval.
    ///
    /// If `expected_uidvalidity` is `Some(v)`, the value is compared against
    /// the UIDVALIDITY returned by the internal EXAMINE (read-only SELECT). A
    /// mismatch returns `ImapError::UidValidityChanged` before the FETCH is
    /// sent. Pass `None` to skip the guard.
    ///
    /// # Errors
    /// Returns `ImapError::UidValidityChanged` on a UIDVALIDITY mismatch.
    /// Propagates timeout, connection-lost, or protocol errors from the
    /// underlying `ops::fetch::fetch` call.
    pub async fn fetch(
        &self,
        folder: &str,
        uids: &[crate::types::Uid],
        spec: crate::types::FetchSpec,
        expected_uidvalidity: Option<u32>,
    ) -> Result<(Vec<crate::types::FetchedMessage>, Option<u32>), ImapError> {
        self.with_session("fetch", async |session| {
            crate::ops::fetch::fetch(session, folder, uids, spec, expected_uidvalidity).await
        })
        .await
    }

    /// Fetch the full `BODY[]` of `uid` from `folder`. Returns raw bytes
    /// (no MIME parsing — Sprint 4's `rimap-content` owns that). Drops
    /// the connection on size-limit overflow OR connection loss so the
    /// half-consumed response state never leaks to the next op.
    ///
    /// # Pre-flight size check
    ///
    /// Before issuing `FETCH BODY.PEEK[]`, this method issues
    /// `UID FETCH <uid> (RFC822.SIZE)` and rejects with
    /// `ImapError::SizeLimit` if the server-reported size exceeds
    /// `max_fetch_body_bytes`. This prevents async-imap from buffering
    /// the full body into memory for oversize messages, at the cost of
    /// one extra IMAP round-trip.
    ///
    /// The post-parse `project_size` check inside `ops::fetch::fetch_body`
    /// remains as defense-in-depth because servers can lie about
    /// `RFC822.SIZE`.
    ///
    /// # Errors
    /// Propagates `ImapError::SizeLimit` if the body exceeds the configured
    /// `max_fetch_body_bytes`, plus the usual timeout / protocol /
    /// connection-lost errors.
    pub async fn fetch_body(
        &self,
        folder: &str,
        uid: crate::types::Uid,
    ) -> Result<Vec<u8>, ImapError> {
        let dur = self.inner.cfg.command_timeout;
        let limit = self.inner.cfg.max_fetch_body_bytes;
        let result = crate::time::with_timeout("fetch_body", dur, async {
            let mut guard = self.session().await?;
            let session =
                guard
                    .as_mut()
                    .ok_or(ImapError::Protocol(async_imap::error::Error::Bad(
                        "session invariant violated: guard is None after session()".to_string(),
                    )))?;
            let server_size = crate::ops::fetch::preflight_fetch_size(session, folder, uid).await?;
            crate::ops::fetch::preflight_size_check(server_size, limit)?;
            crate::ops::fetch::fetch_body(session, folder, uid, limit).await
        })
        .await;
        // Drop the cached session on EITHER ConnectionLost OR SizeLimit.
        // SizeLimit means we aborted mid-stream, so the IMAP response
        // state is half-consumed and the session cannot be reused.
        // The match here lists every ImapError variant explicitly because
        // workspace lints ban `_ =>` wildcards.
        let should_invalidate = match &result {
            Err(ImapError::ConnectionLost | ImapError::SizeLimit { .. }) => true,
            Err(
                ImapError::Tls { .. }
                | ImapError::TlsHandshake(_)
                | ImapError::Starttls { .. }
                | ImapError::Connect(_)
                | ImapError::Timeout { .. }
                | ImapError::Auth { .. }
                | ImapError::Protocol(_)
                | ImapError::InvalidInput { .. }
                | ImapError::BatchTooLarge { .. }
                | ImapError::UidValidityChanged { .. }
                | ImapError::Audit { .. },
            )
            | Ok(_) => false,
        };
        if should_invalidate {
            self.invalidate().await;
        }
        result
    }

    /// `UID STORE` — add or remove flags on messages.
    ///
    /// Batch limit: 100 UIDs. Returns the UIDs the server confirmed.
    ///
    /// If `expected_uidvalidity` is `Some(v)`, the value is compared against
    /// the UIDVALIDITY returned by the internal SELECT. A mismatch returns
    /// `ImapError::UidValidityChanged` before the STORE is sent. Pass `None`
    /// to skip the guard.
    ///
    /// # Errors
    /// Returns `ImapError::BatchTooLarge` if more than 100 UIDs are passed.
    /// Returns `ImapError::UidValidityChanged` on a UIDVALIDITY mismatch.
    /// Returns `ImapError::InvalidInput` if any flag fails `flags_string`
    /// (keyword contains non-atom characters).
    /// Propagates timeout, connection-lost, or protocol errors.
    pub async fn store_flags(
        &self,
        folder: &str,
        uids: &[crate::types::Uid],
        flags: &[crate::types::Flag],
        action: crate::types::FlagAction,
        expected_uidvalidity: Option<u32>,
    ) -> Result<(Vec<crate::types::Uid>, Option<u32>), ImapError> {
        self.with_session("store", async |session| {
            let selected = crate::ops::folders::select(session, folder, false).await?;
            let uid_validity = selected.uid_validity;
            crate::ops::fetch::check_uidvalidity(folder, expected_uidvalidity, uid_validity)?;
            let updated = crate::ops::store::store(session, uids, flags, action).await?;
            Ok((updated, uid_validity))
        })
        .await
    }

    /// Move messages from `source_folder` to `dest_folder`.
    ///
    /// Uses IMAP MOVE extension (RFC 6851) when the server advertised
    /// it; falls back to COPY + STORE \Deleted + EXPUNGE otherwise.
    /// The fallback is not atomic — callers should inspect
    /// `MoveOutcome::used_fallback` and surface a warning.
    ///
    /// If `expected_source_uidvalidity` is `Some(v)`, a STATUS probe is
    /// issued against `source_folder` before the move. A mismatch
    /// returns `ImapError::UidValidityChanged`. Pass `None` to skip the
    /// guard (Task 4 will thread the observed value from SELECT through
    /// tool input).
    ///
    /// Batch limit: 100 UIDs.
    ///
    /// # Errors
    /// Returns `ImapError::BatchTooLarge` if more than 100 UIDs are passed.
    /// Returns `ImapError::UidValidityChanged` on a UIDVALIDITY mismatch.
    /// Propagates timeout, connection-lost, or protocol errors.
    pub async fn move_messages(
        &self,
        source_folder: &str,
        dest_folder: &str,
        uids: &[crate::types::Uid],
        expected_source_uidvalidity: Option<u32>,
    ) -> Result<crate::ops::move_message::MoveOutcome, ImapError> {
        let has_move = self.has_move_capability();
        let has_uidplus = self.has_uidplus_capability();
        self.with_session("move", async |session| {
            crate::ops::folders::select(session, source_folder, false).await?;
            crate::ops::move_message::move_messages(
                session,
                source_folder,
                dest_folder,
                uids,
                expected_source_uidvalidity,
                has_move,
                has_uidplus,
            )
            .await
        })
        .await
    }

    /// `APPEND` a raw RFC 5322 message to `folder` with the given
    /// flags and keywords.
    ///
    /// Does NOT select the folder first -- APPEND targets a named
    /// mailbox directly per RFC 3501 section 6.3.11.
    ///
    /// # Errors
    ///
    /// - `ImapError::SizeLimit` if `message.len()` exceeds the configured
    ///   `max_append_bytes`.
    /// - `ImapError::InvalidInput` if any keyword or `Flag::Keyword` value
    ///   contains non-atom characters.
    /// - Propagates timeout, connection-lost, or protocol errors from
    ///   async-imap.
    pub async fn append_message(
        &self,
        folder: &str,
        message: &[u8],
        flags: &[crate::types::Flag],
        keywords: &[&str],
    ) -> Result<crate::types::AppendResult, ImapError> {
        let limit = self.inner.cfg.max_append_bytes;
        self.with_session("append", async |session| {
            crate::ops::append::append(session, folder, message, flags, keywords, limit).await
        })
        .await
    }

    /// Delete a message by flagging it as `\Deleted` and moving it to Trash.
    ///
    /// If the message is already in the Trash folder, only the flag is applied.
    ///
    /// # Errors
    ///
    /// Returns `ImapError::InvalidInput` if `folder` or `trash_folder` fails
    /// `validate_folder_name`.
    /// Returns `ImapError::ConnectionLost` or `ImapError::Timeout` on transport failure,
    /// or a protocol error if the server rejects the command.
    pub async fn delete_message(
        &self,
        folder: &str,
        uid: crate::types::Uid,
        trash_folder: &str,
    ) -> Result<crate::ops::delete::DeleteResult, ImapError> {
        let has_move = self.has_move_capability();
        let has_uidplus = self.has_uidplus_capability();
        self.with_session("delete_message", async |session| {
            crate::ops::folders::select(session, folder, false).await?;
            crate::ops::delete::delete_message(
                session,
                uid,
                folder,
                trash_folder,
                has_move,
                has_uidplus,
            )
            .await
        })
        .await
    }

    /// Expunge all `\Deleted` messages from `folder`.
    ///
    /// Returns `(deleted_uids, expunged_count)` — the UIDs found by
    /// `UID SEARCH DELETED` before the expunge, and the count from the
    /// EXPUNGE response.
    ///
    /// # Errors
    ///
    /// Returns `ImapError::InvalidInput` if `folder` fails `validate_folder_name`.
    /// Returns `ImapError::ConnectionLost` or `ImapError::Timeout` on transport failure,
    /// or a protocol error if the server rejects the command.
    pub async fn expunge(&self, folder: &str) -> Result<(Vec<crate::types::Uid>, u32), ImapError> {
        self.with_session("expunge", async |session| {
            let deleted_uids = crate::ops::expunge::count_deleted(session, folder).await?;
            crate::ops::folders::select(session, folder, false).await?;
            let count = crate::ops::expunge::expunge(session).await?;
            Ok((deleted_uids, count))
        })
        .await
    }

    /// Create a new IMAP folder.
    ///
    /// # Errors
    ///
    /// Returns `ImapError::InvalidInput` for invalid names, `ImapError::ConnectionLost`
    /// or `ImapError::Timeout` on transport failure, or a protocol error if the
    /// server rejects the command.
    pub async fn create_folder(&self, name: &str) -> Result<(), ImapError> {
        self.with_session("create_folder", async |session| {
            crate::ops::folder_management::create_folder(session, name).await
        })
        .await
    }

    /// Rename an IMAP folder.
    ///
    /// # Errors
    ///
    /// Returns `ImapError::InvalidInput` if either `old_name` or `new_name`
    /// fails `validate_folder_name` (empty, too long, or containing forbidden
    /// characters). Returns `ImapError::ConnectionLost` or
    /// `ImapError::Timeout` on transport failure, or a protocol error if the
    /// server rejects the command.
    pub async fn rename_folder(&self, old_name: &str, new_name: &str) -> Result<(), ImapError> {
        self.with_session("rename_folder", async |session| {
            crate::ops::folder_management::rename_folder(session, old_name, new_name).await
        })
        .await
    }

    /// Delete an IMAP folder and all its contents.
    ///
    /// # Errors
    ///
    /// Returns `ImapError::InvalidInput` if `name` fails
    /// `validate_folder_name`. Returns `ImapError::ConnectionLost` or
    /// `ImapError::Timeout` on transport failure, or a protocol error if
    /// the server rejects the command.
    pub async fn delete_folder(&self, name: &str) -> Result<(), ImapError> {
        self.with_session("delete_folder", async |session| {
            crate::ops::folder_management::delete_folder(session, name).await
        })
        .await
    }
}

/// Walk the unsolicited-response channel and return `true` on the first
/// `Response::Capabilities` item that contains an `ImapCapability::Atom`
/// matching `atom` (case-insensitive). Returns `false` if the channel is
/// drained without a match.
///
/// The channel is non-blocking at this point: `run_command_and_check_ok`
/// has already returned (the tagged Done was received), so all intermediate
/// responses are already queued.
fn capability_advertised(rx: &async_channel::Receiver<UnsolicitedResponse>, atom: &str) -> bool {
    while let Ok(item) = rx.try_recv() {
        if let UnsolicitedResponse::Other(resp) = item
            && let Response::Capabilities(caps) = resp.parsed()
        {
            for cap in caps {
                if let ImapCapability::Atom(name) = cap
                    && name.eq_ignore_ascii_case(atom)
                {
                    return true;
                }
            }
        }
    }
    false
}

/// Drain the unsolicited-response channel and return `true` if any
/// `Response::Capabilities` item contains the `LOGINDISABLED` atom.
fn drain_for_logindisabled(rx: &async_channel::Receiver<UnsolicitedResponse>) -> bool {
    capability_advertised(rx, "LOGINDISABLED")
}

/// Plaintext STARTTLS negotiation: greeting → CAPABILITY → STARTTLS.
/// On success, returns the raw `TcpStream`. The intermediate
/// `async_imap::Client` (and its buffer) is dropped by `into_inner()`,
/// which is the structural defense against CVE-2011-0411-class
/// buffered-plaintext injection.
async fn starttls_negotiate(tcp: TcpStream) -> Result<TcpStream, ImapError> {
    use async_imap::Client as ImapPlainClient;

    let mut client: ImapPlainClient<TcpStream> = ImapPlainClient::new(tcp);

    // Read greeting. Must be OK; BYE → UnexpectedBye.
    let greeting = client
        .read_response()
        .await
        .map_err(|e| ImapError::Connect(std::io::Error::other(format!("read greeting: {e}"))))?
        .ok_or(ImapError::Starttls {
            reason: StarttlsFailure::UnexpectedBye,
        })?;
    match greeting.parsed() {
        Response::Data {
            status: Status::Bye,
            ..
        } => {
            return Err(ImapError::Starttls {
                reason: StarttlsFailure::UnexpectedBye,
            });
        }
        Response::Data {
            status: Status::PreAuth,
            ..
        } => {
            return Err(ImapError::Starttls {
                reason: StarttlsFailure::UnexpectedPreauth,
            });
        }
        _ => {}
    }

    // CAPABILITY + drain for STARTTLS token.
    let (tx, rx) = async_channel::bounded::<UnsolicitedResponse>(32);
    client
        .run_command_and_check_ok("CAPABILITY", Some(tx))
        .await
        .map_err(ImapError::Protocol)?;
    if !drain_for_starttls(&rx) {
        return Err(ImapError::Starttls {
            reason: StarttlsFailure::CapabilityMissing,
        });
    }

    // Issue STARTTLS. Map NO/BAD to ServerRefused; other protocol errors pass through.
    match client.run_command_and_check_ok("STARTTLS", None).await {
        Ok(()) => {}
        Err(async_imap::error::Error::No(_)) => {
            return Err(ImapError::Starttls {
                reason: StarttlsFailure::ServerRefused {
                    tagged_status: StarttlsRefusal::No,
                },
            });
        }
        Err(async_imap::error::Error::Bad(_)) => {
            return Err(ImapError::Starttls {
                reason: StarttlsFailure::ServerRefused {
                    tagged_status: StarttlsRefusal::Bad,
                },
            });
        }
        Err(other) => return Err(ImapError::Protocol(other)),
    }

    // Drop Client (and its ImapStream buffer) by extracting the TcpStream.
    Ok(client.into_inner())
}

/// Drain the unsolicited-response channel and return `true` if any
/// `Response::Capabilities` item contains the `STARTTLS` atom.
fn drain_for_starttls(rx: &async_channel::Receiver<UnsolicitedResponse>) -> bool {
    capability_advertised(rx, "STARTTLS")
}

/// Perform the TLS handshake over an established TCP stream using the
/// provided `TlsConfigBundle`. Pin verification happens inside this call.
pub(crate) async fn tls_handshake(
    tcp: TcpStream,
    bundle: &TlsConfigBundle,
    host: &str,
) -> Result<TlsStream<TcpStream>, ImapError> {
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|_| ImapError::Connect(std::io::Error::other("invalid server name for TLS")))?;
    let connector = TlsConnector::from(bundle.config.clone());
    connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| map_tls_handshake_error(&e))
}

/// Full STARTTLS upgrade: plaintext negotiation + TLS handshake with the
/// same `TlsConfigBundle` the implicit-TLS path uses.
pub(crate) async fn starttls_upgrade(
    tcp: TcpStream,
    bundle: &TlsConfigBundle,
    host: &str,
) -> Result<TlsStream<TcpStream>, ImapError> {
    let tcp = starttls_negotiate(tcp).await?;
    tls_handshake(tcp, bundle, host).await
}

/// Map an `io::ImapError` from the TLS connect call to `ImapError::TlsHandshake`.
/// `connect_inner` will enrich this into `ImapError::Tls { observed, expected }`
/// when the `TlsConfigBundle`'s `last_observed` slot shows a mismatch.
fn map_tls_handshake_error(err: &std::io::Error) -> ImapError {
    ImapError::TlsHandshake(tokio_rustls::rustls::Error::General(err.to_string()))
}

/// Map a connect/login error to its stable short error code for the
/// audit log. Kept for the test harness that pins the complete
/// [`ImapError`] -> [`rimap_core::ErrorCode`] mapping; production
/// callers pass `err.code()` directly through [`ImapError::code`].
#[cfg(test)]
fn error_code_for(err: &ImapError) -> &'static str {
    err.code().as_str()
}

#[cfg(test)]
#[expect(clippy::panic, reason = "tests")]
#[expect(clippy::expect_used, reason = "tests")]
mod tests {
    use super::{error_code_for, map_tls_handshake_error};
    use crate::ImapEncryption;
    use crate::error::{AuthFailure, ImapError};
    use rimap_core::TlsFingerprint;

    fn fp_zeros() -> TlsFingerprint {
        TlsFingerprint::from_hex(&"00".repeat(32)).expect("valid 32-byte hex literal")
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
                ImapError::Audit {
                    op: "test",
                    message: "test".to_string(),
                    source: Box::new(std::io::Error::other("test")),
                },
                "ERR_INTERNAL",
            ),
        ];
        for (err, expected) in &cases {
            assert_eq!(error_code_for(err), *expected, "for {err:?}");
        }
    }

    #[test]
    fn map_tls_handshake_error_wraps_io_error() {
        let io_err = std::io::Error::other("handshake boom");
        let mapped = map_tls_handshake_error(&io_err);
        match mapped {
            ImapError::TlsHandshake(e) => {
                assert!(e.to_string().contains("handshake boom"));
            }
            other => panic!("expected TlsHandshake variant, got {other:?}"),
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

    /// Regression test for the cancellation contract on
    /// [`Connection::emit_auth`]: the sink still observes the event even
    /// when the awaiting future is dropped before `spawn_blocking`
    /// completes. The rustdoc on `emit_auth` documents this; if a future
    /// refactor replaces `spawn_blocking` with a direct await or changes
    /// the join-handle semantics, this test fails.
    #[tokio::test]
    async fn emit_auth_completes_despite_caller_cancellation() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;

        use rimap_core::auth_event::{AuthEvent, AuthResult};
        use rimap_core::auth_sink::{AuthEventSink, AuthSinkError};
        use rimap_core::credential::{
            CredentialResolver, CredentialResolverError, CredentialSource,
        };
        use secrecy::SecretString;

        use super::{Connection, ConnectionConfig};

        /// Blocks for `delay` inside `emit_auth`, then increments
        /// `recorded`. Simulates a slow synchronous sink (the real
        /// `AuditWriter` can block on fsync when the disk is slow).
        struct BlockingSink {
            delay: Duration,
            recorded: Arc<AtomicUsize>,
        }

        impl std::fmt::Debug for BlockingSink {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct("BlockingSink").finish()
            }
        }

        impl AuthEventSink for BlockingSink {
            fn emit_auth(&self, _event: AuthEvent) -> Result<(), AuthSinkError> {
                std::thread::sleep(self.delay);
                self.recorded.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }

        /// Minimal resolver; never invoked in this test because we call
        /// `emit_auth` directly, but `Connection::new` requires one.
        #[derive(Debug)]
        struct DummyResolver;

        impl CredentialResolver for DummyResolver {
            fn resolve(
                &self,
                _: &rimap_core::account::AccountId,
                _: &str,
                _: &str,
            ) -> Result<(SecretString, CredentialSource), CredentialResolverError> {
                Err(CredentialResolverError::new("dummy resolver"))
            }
        }

        let recorded = Arc::new(AtomicUsize::new(0));
        let sink: Arc<dyn AuthEventSink> = Arc::new(BlockingSink {
            delay: Duration::from_millis(80),
            recorded: Arc::clone(&recorded),
        });
        let resolver: Arc<dyn CredentialResolver> = Arc::new(DummyResolver);
        let conn = Connection::new(
            ConnectionConfig {
                account: None,
                account_id: rimap_core::account::AccountId::default_account(),
                host: "127.0.0.1".into(),
                port: 1,
                encryption: ImapEncryption::Tls,
                username: "test".into(),
                pinned_fingerprint: None,
                connect_timeout: Duration::from_secs(1),
                command_timeout: Duration::from_secs(1),
                max_fetch_body_bytes: 1024,
                max_append_bytes: 1024,
            },
            sink,
            resolver,
        );

        let event = AuthEvent {
            account: None,
            result: AuthResult::Success,
            host: "127.0.0.1".into(),
            port: 1,
            username: "test".into(),
            tls_fingerprint_sha256: None,
            fingerprint_match: None,
            error_code: None,
            credential_source: None,
        };

        let handle = tokio::spawn(async move {
            // Dropping this future between `spawn_blocking` dispatch and
            // completion is the cancellation we want to exercise.
            let _ = conn.emit_auth(event).await;
        });

        // Give the future just long enough to enter `spawn_blocking`
        // (far less than the sink's 80ms delay). The abort then drops
        // the JoinHandle mid-blocking-task.
        tokio::time::sleep(Duration::from_millis(10)).await;
        handle.abort();

        // Wait past the sink's total blocking time, then verify the
        // event was recorded even though the caller was cancelled.
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(
            recorded.load(Ordering::SeqCst),
            1,
            "sink must record the event even if the caller future was dropped",
        );
    }
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "tests")]
#[expect(clippy::panic, reason = "tests")]
#[expect(clippy::unwrap_used, reason = "tests")]
mod starttls_unit_tests {
    use std::io::{Error as IoError, ErrorKind};
    use std::net::SocketAddr;

    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::task::JoinHandle;

    /// A one-shot scripted IMAP server. Each step either writes bytes or
    /// reads one CRLF-terminated line and checks its prefix. Returns on
    /// script completion or client disconnect.
    pub(super) struct MockImap {
        addr: SocketAddr,
        join: JoinHandle<Result<Vec<String>, IoError>>,
    }

    /// One script step.
    pub(super) enum Step {
        /// Server sends these bytes verbatim (append to response).
        Send(&'static [u8]),
        /// Server reads one CRLF-terminated line; asserts the line
        /// (after the tag) starts with the given uppercase command.
        ExpectCommand(&'static str),
        /// Hold the connection open indefinitely (until the client closes it
        /// or the test drops the mock). Use this as the final step when you
        /// want the client to stall waiting for a reply that never arrives.
        Stall,
    }

    impl MockImap {
        /// Start a listener bound to 127.0.0.1:0 and spawn a task that
        /// accepts one connection and runs the script.
        pub(super) async fn start(script: Vec<Step>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr = listener.local_addr().expect("local_addr");
            let join = tokio::spawn(async move {
                let (stream, _) = listener.accept().await?;
                run_script(stream, script).await
            });
            Self { addr, join }
        }

        pub(super) fn addr(&self) -> SocketAddr {
            self.addr
        }

        /// Wait for the server task to finish; return the list of lines
        /// it read from the client (in the order it read them).
        pub(super) async fn finish(self) -> Result<Vec<String>, IoError> {
            self.join.await.map_err(IoError::other)?
        }
    }

    async fn run_script(stream: TcpStream, script: Vec<Step>) -> Result<Vec<String>, IoError> {
        let (read, mut write) = stream.into_split();
        let mut reader = BufReader::new(read);
        let mut recorded: Vec<String> = Vec::new();
        for step in script {
            match step {
                Step::Send(bytes) => {
                    write.write_all(bytes).await?;
                    write.flush().await?;
                }
                Step::ExpectCommand(cmd) => {
                    let mut line = String::new();
                    let n = reader.read_line(&mut line).await?;
                    if n == 0 {
                        return Err(IoError::new(ErrorKind::UnexpectedEof, "client closed"));
                    }
                    recorded.push(line.clone());
                    // Line is "<tag> <COMMAND> ...\r\n". Split off tag.
                    let rest = line.split_once(' ').map_or("", |(_, r)| r);
                    if !rest.trim_start().to_ascii_uppercase().starts_with(cmd) {
                        return Err(IoError::other(format!(
                            "expected command `{cmd}` but got `{}`",
                            line.trim()
                        )));
                    }
                }
                Step::Stall => {
                    // Hold the connection open until the peer closes it.
                    // Discard any bytes; we just need the socket to stay alive.
                    let mut discard = String::new();
                    let _ = reader.read_line(&mut discard).await;
                    // Stream is dropped here; return normally.
                    return Ok(recorded);
                }
            }
        }
        Ok(recorded)
    }

    use std::sync::Arc;

    use rimap_core::auth_event::AuthEvent;
    use rimap_core::auth_sink::{AuthEventSink, AuthSinkError};
    use rimap_core::credential::{CredentialResolver, CredentialResolverError, CredentialSource};
    use secrecy::SecretString;

    use super::{Connection, ConnectionConfig, ImapEncryption};
    use super::{ImapError, StarttlsFailure, StarttlsRefusal};

    #[derive(Debug)]
    struct PanicResolver;

    impl CredentialResolver for PanicResolver {
        #[expect(
            clippy::panic_in_result_fn,
            reason = "deliberate: proves resolver is never called"
        )]
        fn resolve(
            &self,
            _account: &rimap_core::account::AccountId,
            _username: &str,
            _host: &str,
        ) -> Result<(SecretString, CredentialSource), CredentialResolverError> {
            panic!("credential resolver must not be invoked before TLS");
        }
    }

    #[derive(Debug)]
    struct NoopAudit;

    impl AuthEventSink for NoopAudit {
        fn emit_auth(&self, _event: AuthEvent) -> Result<(), AuthSinkError> {
            Ok(())
        }
    }

    fn connection_for(addr: std::net::SocketAddr, timeout_ms: u64) -> Connection {
        let cfg = ConnectionConfig {
            account: None,
            account_id: rimap_core::account::AccountId::default_account(),
            host: addr.ip().to_string(),
            port: addr.port(),
            encryption: ImapEncryption::Starttls,
            username: "unused".to_string(),
            pinned_fingerprint: None,
            connect_timeout: std::time::Duration::from_millis(timeout_ms),
            command_timeout: std::time::Duration::from_secs(1),
            max_fetch_body_bytes: 1024,
            max_append_bytes: 1024,
        };
        Connection::new(cfg, Arc::new(NoopAudit), Arc::new(PanicResolver))
    }

    #[tokio::test]
    async fn connect_with_starttls_capability_missing_does_not_resolve_credentials() {
        let mock = MockImap::start(vec![
            Step::Send(b"* OK ready\r\n"),
            Step::ExpectCommand("CAPABILITY"),
            Step::Send(b"* CAPABILITY IMAP4rev1\r\n"),
            Step::Send(b"A0001 OK CAPABILITY completed\r\n"),
        ])
        .await;

        let conn = connection_for(mock.addr(), 5000);
        let err = conn.list_folders("*").await.unwrap_err();
        match err {
            ImapError::Starttls {
                reason: StarttlsFailure::CapabilityMissing,
            } => {}
            other => panic!("expected CapabilityMissing, got {other:?}"),
        }
        let _ = mock.finish().await;
    }

    #[tokio::test]
    async fn connect_with_starttls_stall_times_out_with_starttls_upgrade_op() {
        // Mock greets, reads CAPABILITY, then stalls (never sends a reply).
        // The client waits for the CAPABILITY response. The 100ms
        // connect_timeout fires and must surface the distinctive op tag.
        let mock = MockImap::start(vec![
            Step::Send(b"* OK ready\r\n"),
            Step::ExpectCommand("CAPABILITY"),
            // Stall: hold the connection open; never send the CAPABILITY reply.
            Step::Stall,
        ])
        .await;

        let conn = connection_for(mock.addr(), 100);
        let err = conn.list_folders("*").await.unwrap_err();
        match err {
            ImapError::Timeout { op } => assert_eq!(op, "starttls_upgrade"),
            other => panic!("expected Timeout(starttls_upgrade), got {other:?}"),
        }
        let _ = mock.finish().await;
    }

    #[tokio::test]
    async fn negotiate_capability_missing() {
        let mock = MockImap::start(vec![
            Step::Send(b"* OK IMAP ready\r\n"),
            Step::ExpectCommand("CAPABILITY"),
            // Advertise LOGIN-related caps but NOT STARTTLS.
            Step::Send(b"* CAPABILITY IMAP4rev1 AUTH=PLAIN\r\n"),
            Step::Send(b"A0001 OK CAPABILITY completed\r\n"),
        ])
        .await;

        let tcp = tokio::net::TcpStream::connect(mock.addr()).await.unwrap();
        let err = super::starttls_negotiate(tcp).await.unwrap_err();
        match err {
            ImapError::Starttls {
                reason: StarttlsFailure::CapabilityMissing,
            } => {}
            other => panic!("expected CapabilityMissing, got {other:?}"),
        }

        // Server-side: no STARTTLS command was issued before the client
        // errored out. `recorded` must be exactly one line (CAPABILITY).
        let recorded = mock.finish().await.unwrap();
        assert_eq!(recorded.len(), 1);
        assert!(recorded[0].to_ascii_uppercase().contains("CAPABILITY"));
    }

    #[tokio::test]
    async fn negotiate_unexpected_bye() {
        let mock = MockImap::start(vec![Step::Send(b"* BYE go away\r\n")]).await;

        let tcp = tokio::net::TcpStream::connect(mock.addr()).await.unwrap();
        let err = super::starttls_negotiate(tcp).await.unwrap_err();
        match err {
            ImapError::Starttls {
                reason: StarttlsFailure::UnexpectedBye,
            } => {}
            other => panic!("expected UnexpectedBye, got {other:?}"),
        }
        let _ = mock.finish().await;
    }

    #[tokio::test]
    async fn negotiate_unexpected_preauth() {
        let mock =
            MockImap::start(vec![Step::Send(b"* PREAUTH pre-authenticated session\r\n")]).await;

        let tcp = tokio::net::TcpStream::connect(mock.addr()).await.unwrap();
        let err = super::starttls_negotiate(tcp).await.unwrap_err();
        match err {
            ImapError::Starttls {
                reason: StarttlsFailure::UnexpectedPreauth,
            } => {}
            other => panic!("expected UnexpectedPreauth, got {other:?}"),
        }
        let _ = mock.finish().await;
    }

    #[tokio::test]
    async fn negotiate_server_refused_no() {
        let mock = MockImap::start(vec![
            Step::Send(b"* OK IMAP ready\r\n"),
            Step::ExpectCommand("CAPABILITY"),
            Step::Send(b"* CAPABILITY IMAP4rev1 STARTTLS\r\n"),
            Step::Send(b"A0001 OK CAPABILITY completed\r\n"),
            Step::ExpectCommand("STARTTLS"),
            Step::Send(b"A0002 NO STARTTLS currently unavailable\r\n"),
        ])
        .await;

        let tcp = tokio::net::TcpStream::connect(mock.addr()).await.unwrap();
        let err = super::starttls_negotiate(tcp).await.unwrap_err();
        match err {
            ImapError::Starttls {
                reason: StarttlsFailure::ServerRefused { tagged_status },
            } => assert_eq!(tagged_status, StarttlsRefusal::No),
            other => panic!("expected ServerRefused NO, got {other:?}"),
        }
        let _ = mock.finish().await;
    }

    #[tokio::test]
    async fn negotiate_server_refused_bad() {
        let mock = MockImap::start(vec![
            Step::Send(b"* OK IMAP ready\r\n"),
            Step::ExpectCommand("CAPABILITY"),
            Step::Send(b"* CAPABILITY IMAP4rev1 STARTTLS\r\n"),
            Step::Send(b"A0001 OK CAPABILITY completed\r\n"),
            Step::ExpectCommand("STARTTLS"),
            Step::Send(b"A0002 BAD command unknown\r\n"),
        ])
        .await;

        let tcp = tokio::net::TcpStream::connect(mock.addr()).await.unwrap();
        let err = super::starttls_negotiate(tcp).await.unwrap_err();
        match err {
            ImapError::Starttls {
                reason: StarttlsFailure::ServerRefused { tagged_status },
            } => assert_eq!(tagged_status, StarttlsRefusal::Bad),
            other => panic!("expected ServerRefused BAD, got {other:?}"),
        }
        let _ = mock.finish().await;
    }

    #[tokio::test]
    async fn negotiate_happy_path() {
        let mock = MockImap::start(vec![
            Step::Send(b"* OK IMAP server ready\r\n"),
            Step::ExpectCommand("CAPABILITY"),
            Step::Send(b"* CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED\r\n"),
            Step::Send(b"A0001 OK CAPABILITY completed\r\n"),
            Step::ExpectCommand("STARTTLS"),
            Step::Send(b"A0002 OK Begin TLS negotiation\r\n"),
        ])
        .await;

        let tcp = tokio::net::TcpStream::connect(mock.addr()).await.unwrap();
        let result = super::starttls_negotiate(tcp).await;
        assert!(result.is_ok(), "expected Ok(_), got {result:?}");

        let recorded = mock.finish().await.unwrap();
        assert_eq!(recorded.len(), 2);
        assert!(recorded[0].to_ascii_uppercase().contains("CAPABILITY"));
        assert!(recorded[1].to_ascii_uppercase().contains("STARTTLS"));
    }

    #[tokio::test]
    async fn negotiate_returns_bare_tcpstream_and_drops_client_wrapper() {
        // Regression test for CVE-2011-0411 class: verifies that
        // `starttls_negotiate` returns a raw `TcpStream` (not a
        // `Client<TcpStream>`), which means the plaintext client's
        // internal `ImapStream` buffer was dropped by `into_inner()`.
        // A caller that re-wraps with `Client::new(tls_stream)` after
        // TLS gets a fresh buffer — no buffered plaintext can be
        // replayed against the post-TLS stream.
        //
        // We further simulate a MITM-style injection by having the mock
        // send trailing bytes in the SAME turn as the tagged OK for
        // STARTTLS. If the plaintext parser buffered them, they are
        // lost with `into_inner()`; if not, they remain on the kernel
        // socket but cannot enter any `ImapStream` buffer the caller
        // holds, because none is returned.
        let mock = MockImap::start(vec![
            Step::Send(b"* OK ready\r\n"),
            Step::ExpectCommand("CAPABILITY"),
            Step::Send(b"* CAPABILITY IMAP4rev1 STARTTLS\r\n"),
            Step::Send(b"A0001 OK CAPABILITY completed\r\n"),
            Step::ExpectCommand("STARTTLS"),
            // Tagged OK + trailing injected bytes in the SAME server turn.
            Step::Send(b"A0002 OK Begin TLS negotiation\r\n* INJECTED garbage\r\n"),
        ])
        .await;

        let tcp = tokio::net::TcpStream::connect(mock.addr()).await.unwrap();
        // Explicit type annotation: `returned` must be TcpStream, not
        // Client<TcpStream>. This is checked by the compiler; the
        // annotation documents the CVE-defense guarantee.
        let returned: tokio::net::TcpStream = super::starttls_negotiate(tcp).await.unwrap();
        let _ = returned;

        let _ = mock.finish().await;
    }

    #[tokio::test]
    async fn mock_server_round_trips_a_line() {
        // Smoke test: mock sends a greeting, reads one line, returns.
        let mock = MockImap::start(vec![
            Step::Send(b"* OK hi\r\n"),
            Step::ExpectCommand("NOOP"),
            Step::Send(b"a1 OK NOOP done\r\n"),
        ])
        .await;

        let stream = TcpStream::connect(mock.addr()).await.unwrap();
        let (read, mut write) = stream.into_split();
        let mut reader = BufReader::new(read);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.unwrap();
        assert!(greeting.contains("OK hi"));
        write.write_all(b"a1 NOOP\r\n").await.unwrap();
        let mut resp = String::new();
        reader.read_line(&mut resp).await.unwrap();
        assert!(resp.contains("NOOP done"));

        drop((reader, write));
        let recorded = mock.finish().await.unwrap();
        assert_eq!(recorded.len(), 1);
        assert!(recorded[0].contains("NOOP"));
    }

    #[test]
    fn debug_format_includes_connection_fields() {
        // The manual `Debug` impl for `Connection` writes host, port,
        // and username via `debug_struct(...).finish_non_exhaustive()`.
        // The cargo-mutants `replace <impl Debug>::fmt -> std::fmt::Result
        // with Ok(Default::default())` mutation at connection.rs:127
        // returns Ok(()) without writing — the formatted output collapses
        // to the empty string. Asserting that distinctive field values
        // round-trip through the formatter kills the mutation.
        //
        // `Connection::new` is socket-free, so the IP / port values here
        // are pure config — no listener is bound.
        let cfg = ConnectionConfig {
            account: None,
            account_id: rimap_core::account::AccountId::default_account(),
            host: "imap.fixture.invalid".into(),
            port: 6143,
            encryption: ImapEncryption::Tls,
            username: "u@fixture.invalid".into(),
            pinned_fingerprint: None,
            connect_timeout: std::time::Duration::from_millis(1),
            command_timeout: std::time::Duration::from_millis(1),
            max_fetch_body_bytes: 1024,
            max_append_bytes: 1024,
        };
        let conn = Connection::new(cfg, Arc::new(NoopAudit), Arc::new(PanicResolver));
        let formatted = format!("{conn:?}");
        assert!(
            formatted.contains("Connection"),
            "Debug must include struct name; got {formatted:?}",
        );
        assert!(
            formatted.contains("imap.fixture.invalid"),
            "Debug must include host; got {formatted:?}",
        );
        assert!(
            formatted.contains("6143"),
            "Debug must include port; got {formatted:?}",
        );
        assert!(
            formatted.contains("u@fixture.invalid"),
            "Debug must include username; got {formatted:?}",
        );
    }
}
