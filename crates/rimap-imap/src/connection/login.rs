//! IMAP login flow + audit-event emission for [`Connection`].
//!
//! `imap_login` runs greeting + CAPABILITY + LOGIN over an already-
//! established TLS stream. `emit_auth` ships the resulting
//! [`AuthEvent`] through the injected [`AuthEventSink`] on a blocking
//! thread so the sink's internal `std::sync::Mutex` is never held
//! across an `.await`.

use std::sync::atomic::Ordering;

use async_imap::imap_proto::{Response, Status};
use async_imap::types::UnsolicitedResponse;
use rimap_core::auth_event::AuthEvent;
use secrecy::ExposeSecret;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

use crate::error::{AuthFailure, ImapError};

use super::handshake::drain_for_logindisabled;
use super::{Connection, ImapSession};

impl Connection {
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
    /// The resolved credential's source is published to `progress` the moment
    /// resolution succeeds, rather than returned, so a connect cut after that
    /// point still records which store the credential came from. See
    /// [`super::ConnectProgress`].
    pub(super) async fn imap_login(
        &self,
        tls_stream: TlsStream<TcpStream>,
        already_greeted: bool,
        progress: &super::ConnectProgress,
    ) -> Result<ImapSession, ImapError> {
        let mut client = async_imap::Client::new(tls_stream);

        // Read the server greeting — skipped for STARTTLS, which already
        // consumed the greeting during plaintext negotiation. An absent greeting
        // (EOF) or BYE status means the server immediately rejected us.
        if !already_greeted {
            let greeting = client
                .read_response()
                .await
                .map_err(ImapError::Connect)?
                .ok_or(ImapError::Auth {
                    reason: AuthFailure::ServerRejected,
                })?;

            if let Response::Data {
                status: Status::Bye,
                ..
            } = greeting.parsed()
            {
                return Err(ImapError::Auth {
                    reason: AuthFailure::ServerRejected,
                });
            }
        }

        // Issue CAPABILITY and scan responses for LOGINDISABLED.
        // We create a bounded channel so intermediate untagged responses
        // (including `* CAPABILITY ...`) are routed through it rather than
        // being silently discarded.
        let (tx, rx) = async_channel::bounded::<UnsolicitedResponse>(32);
        client
            .run_command_and_check_ok("CAPABILITY", Some(tx))
            .await
            .map_err(ImapError::Protocol)?;

        // Drain whatever arrived on the channel (non-blocking; the command
        // has already completed). A `Response::Capabilities` list containing
        // LOGINDISABLED means LOGIN is prohibited.
        let logindisabled = drain_for_logindisabled(&rx);
        if logindisabled {
            return Err(ImapError::Auth {
                reason: AuthFailure::CapabilityMissing { needed: "LOGIN" },
            });
        }

        // Resolve the password from the injected resolver. A missing
        // credential is an authentication failure, not a network
        // failure — map it to ERR_AUTH so retry logic and operator
        // messages stay accurate.
        let cfg = &self.inner.cfg;
        let (password, credential_source) = self
            .inner
            .credentials
            .resolve(&cfg.account_id, &cfg.username, &cfg.host)
            .map_err(|e| ImapError::Auth {
                reason: AuthFailure::CredentialUnavailable(e.into_reason()),
            })?;

        // Publish the source before the LOGIN round trip, which is the first
        // await that can be cut with the credential already resolved. Every
        // `auth` record written from here on — this connect's own, or the one
        // `AuthEmitGuard` writes if the future is dropped — names the store the
        // credential came from.
        progress.record_credential_source(credential_source);

        // Attempt LOGIN. On NO response the server rejected the credentials.
        // Expose the secret only at the moment of use; the borrow ends
        // when `client.login` returns.
        let mut session = match client.login(&cfg.username, password.expose_secret()).await {
            Ok(session) => session,
            Err((err, _client)) => {
                return match err {
                    async_imap::error::Error::No(_) => Err(ImapError::Auth {
                        reason: AuthFailure::LoginRejected,
                    }),
                    other => Err(ImapError::Protocol(other)),
                };
            }
        };

        // Post-login: probe CAPABILITY for MOVE (RFC 6851) and
        // UIDPLUS (RFC 4315).
        let (has_move, has_uidplus) = match session.capabilities().await {
            Ok(caps) => (caps.has_str("MOVE"), caps.has_str("UIDPLUS")),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "post-login CAPABILITY probe failed; \
                     assuming no MOVE/UIDPLUS support",
                );
                (false, false)
            }
        };
        self.inner.has_move.store(has_move, Ordering::Relaxed);
        self.inner.has_uidplus.store(has_uidplus, Ordering::Relaxed);

        Ok(session)
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
    pub(super) async fn emit_auth(&self, event: AuthEvent) -> Result<(), ImapError> {
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

    /// Emit an [`AuthEvent`] from a synchronous context — specifically
    /// [`super::AuthEmitGuard`]'s `Drop`, which cannot await and has no caller
    /// left to return a `Result` to.
    ///
    /// ## Why not a plain synchronous `emit_auth`
    ///
    /// `AuditWriter::write_record` fsyncs `auth` records, and its own docs
    /// require async callers to route through `spawn_blocking` (RUST-ASYNC-04).
    /// A `Drop` running inside a dropped future is still on a runtime worker
    /// thread, so calling the sink inline there would stall that worker for a
    /// disk sync — the exact failure the rule exists to prevent. Dispatching to
    /// the blocking pool and detaching the `JoinHandle` costs nothing and
    /// still writes the record: tokio does not cancel a blocking task when its
    /// handle is dropped, which is the same property
    /// [`Connection::emit_auth`]'s cancellation contract already relies on.
    ///
    /// Outside a runtime there is no worker to stall, so the write runs inline
    /// rather than being dropped.
    ///
    /// ## Failure handling
    ///
    /// Best-effort, and logged at `error` level when the sink rejects the
    /// event. There is nowhere to propagate to from a `Drop`, and this mirrors
    /// both `connect_inner`'s existing auth-failure branch (which preserves the
    /// original error and logs the audit failure) and
    /// `rimap_audit::spawn_drainer`, which logs and discards a cancellation
    /// `tool_end` it cannot write. A runtime shutting down can also drop the
    /// spawned blocking task before it runs; that window is the same one
    /// `AuditEnvelopeGuard` accepts for its own records.
    pub(super) fn emit_auth_detached(&self, event: AuthEvent) {
        let sink = self.inner.audit.clone();
        let write = move || {
            if let Err(err) = sink.emit_auth(event) {
                tracing::error!(
                    error = %err,
                    "AuthEventSink::emit_auth failed for a connect that was cut \
                     before it reached its own verdict; the attempt is unrecorded",
                );
            }
        };
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => drop(handle.spawn_blocking(write)),
            Err(_not_in_runtime) => write(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use rimap_core::auth_event::{AuthEvent, AuthResult};
    use rimap_core::auth_sink::{AuthEventSink, AuthSinkError};
    use rimap_core::credential::{CredentialResolver, CredentialResolverError, CredentialSource};
    use secrecy::SecretString;

    use super::super::{Connection, ConnectionConfig, ImapEncryption};

    /// Regression test for the cancellation contract on
    /// [`Connection::emit_auth`]: the sink still observes the event even
    /// when the awaiting future is dropped before `spawn_blocking`
    /// completes. The rustdoc on `emit_auth` documents this; if a future
    /// refactor replaces `spawn_blocking` with a direct await or changes
    /// the join-handle semantics, this test fails.
    #[tokio::test]
    async fn emit_auth_completes_despite_caller_cancellation() {
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
