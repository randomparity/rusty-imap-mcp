//! IMAP login flow + audit-event emission for [`Connection`].
//!
//! `imap_login` runs greeting + CAPABILITY + LOGIN over an already-
//! established TLS stream. `emit_auth` ships the resulting
//! [`AuthEvent`] through the injected [`AuthEventSink`] synchronously,
//! on the calling thread: the sink's internal `std::sync::Mutex` is
//! taken and released without an `.await` in between, so no record can
//! be stranded by a cut or a runtime shutdown (ADR-0014).

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

    /// Emit an [`AuthEvent`] through the injected sink, synchronously, on the
    /// calling thread. The single place any `auth` record is written; both
    /// [`Connection::connect_inner`]'s own emits and
    /// [`Self::emit_auth_blocking`] go through it.
    ///
    /// ## Why this blocks rather than deferring to the blocking pool
    ///
    /// `AuditWriter::write_record` fsyncs `auth` records, and its docs tell
    /// async callers to route through `spawn_blocking` (RUST-ASYNC-04). This
    /// emitter deliberately does not, and ADR-0014 records the decision. The
    /// short form:
    ///
    /// * **`spawn_blocking` loses the record on a shutdown.** Tokio's blocking
    ///   pool refuses new work once the runtime begins shutting down — the
    ///   returned handle never resolves, and even an already-queued closure is
    ///   discarded rather than run. `rimap-server` shuts down with
    ///   `Runtime::shutdown_background`, which waits for nothing, and writes
    ///   `process_end` before it. Deferring guarantees the loss inside that
    ///   window; writing inline removes the window entirely, because there is
    ///   no longer an `.await` between the guard's disarm and the write (#643).
    /// * **`spawn_blocking` cannot be called from a `Drop` at all.**
    ///   [`super::AuthEmitGuard`] has no caller to await for it, and
    ///   `spawn_blocking` panics when the OS refuses a thread — a panic
    ///   escaping a `Drop` that runs during an unwind aborts the process.
    /// * **The cost is not new latency — it is a blocked runtime worker.**
    ///   `connect_inner` already awaited this write to completion before
    ///   returning, so the connect's wall time is unchanged; what moved is the
    ///   thread that spends it, from the blocking pool to a runtime worker.
    ///   Measured at 4.7 ms mean / 6.9 ms p95 / 16.9 ms max per record on
    ///   APFS-on-NVMe (ADR-0014 has the method and the caveats). Once per
    ///   connect, and a connect is lazy and serialized per account by the
    ///   session lock, so the number of workers blocked at once is bounded by
    ///   the number of configured accounts. When the file is due to rotate the
    ///   write also takes a rename, an open, and — with retention configured —
    ///   a `read_dir` and a `remove_file` per pruned file, still under the
    ///   audit mutex.
    ///
    ///   No deadline covers that write, and it is unbounded above. On an
    ///   `audit.path` that stops responding — a hung NFS or SMB mount — it
    ///   never returns: the runtime worker is pinned for the life of the
    ///   process, and `dispatch::attempt` still holds the account's session
    ///   lock, so a peer queued on that account waits forever rather than
    ///   merely spending its `command_timeout`. The runtime is multi-threaded,
    ///   so enough concurrent connects against such a mount wedge the
    ///   scheduler itself, including the stdio MCP wire. The same stall on the
    ///   blocking pool lands against its 512-thread cap instead and cannot
    ///   starve the scheduler — so this makes `audit.path` a local-storage
    ///   requirement rather than a preference. `docs/audit-log.md` says so to
    ///   operators.
    ///
    /// There is no lock-order hazard: the audit mutex is a leaf. It guards only
    /// file I/O, nothing inside its critical section calls back into this
    /// crate, and the advisory file lock is taken once at open rather than per
    /// write, so it cannot block on another process either.
    ///
    /// ## `ImapError` message sanitization
    ///
    /// The [`AuthEventSink`](rimap_core::auth_sink::AuthEventSink) contract
    /// requires implementations to pre-sanitize the `message` field on
    /// [`rimap_core::AuthSinkError`] (no filesystem paths or
    /// operator-configured layout). This function forwards that `message`
    /// verbatim — the full underlying error is preserved on the `source` chain
    /// for observability.
    pub(super) fn emit_auth(&self, event: AuthEvent) -> Result<(), ImapError> {
        self.inner.audit.emit_auth(event).map_err(|sink_err| {
            let message = sink_err.message().to_string();
            ImapError::Audit {
                op: "emit_auth",
                message,
                source: Box::new(sink_err),
            }
        })
    }

    /// Emit an [`AuthEvent`] for a connect that was cut before it reached its
    /// own verdict — the shape [`super::AuthEmitGuard`]'s `Drop` needs, which
    /// cannot await and has no caller left to return a `Result` to.
    ///
    /// Identical to [`Self::emit_auth`] but for the failure handling: logged at
    /// `error` level and counted through `note_auth_write_lost`, because there
    /// is nowhere to propagate to from a `Drop`. This mirrors `connect_inner`'s
    /// auth-failure branch, which likewise preserves the original outcome and
    /// logs the audit failure rather than replacing one with the other.
    ///
    /// Implementations of [`rimap_core::auth_sink::AuthEventSink`] must return
    /// their failures rather than panicking — the production `AuditWriter`
    /// maps even a poisoned mutex to an `AuditError` — because a panic here
    /// would escape a `Drop`.
    pub(super) fn emit_auth_blocking(&self, event: AuthEvent) {
        if let Err(err) = self.emit_auth(event) {
            self.inner.audit.note_auth_write_lost();
            tracing::error!(
                error = %err,
                "AuthEventSink::emit_auth failed for a connect that was cut \
                 before it reached its own verdict; the attempt is unrecorded",
            );
        }
    }
}
