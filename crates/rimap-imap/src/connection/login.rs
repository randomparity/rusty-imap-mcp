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
    /// Returns `Ok((session, credential_source))` on success.
    /// Returns `Err((error, Some(source)))` when the failure occurred after
    /// `resolve_credential` succeeded (e.g. server rejected the credentials).
    /// Returns `Err((error, None))` for pre-resolve failures (greeting, CAPABILITY).
    pub(super) async fn imap_login(
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
