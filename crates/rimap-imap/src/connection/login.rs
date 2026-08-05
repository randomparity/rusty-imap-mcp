//! IMAP login flow + audit-event emission for [`Connection`].
//!
//! `imap_login` runs greeting + CAPABILITY + LOGIN over an already-
//! established TLS stream. `emit_auth` ships the resulting
//! [`AuthEvent`] through the injected [`AuthEventSink`] synchronously,
//! on the calling thread: the sink's internal `std::sync::Mutex` is
//! taken and released without an `.await` in between, so no record can
//! be stranded *on the blocking pool's queue* by a cut or a runtime
//! shutdown (ADR-0014). The guard's record can still lose a race with
//! process exit; see `AuthEmitGuard`.

use std::panic::{AssertUnwindSafe, catch_unwind};

use async_imap::imap_proto::{Response, Status};
use async_imap::types::UnsolicitedResponse;
use rimap_core::auth_event::AuthEvent;
use secrecy::ExposeSecret;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

use crate::error::{AuthFailure, ImapError};

use super::handshake::drain_for_logindisabled;
use super::{Connection, ImapSession, ServerCapabilities, SessionEntry};

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
    ///
    /// Returns the session paired with what its own post-login `CAPABILITY`
    /// probe advertised. This is the only place a [`ServerCapabilities`] value
    /// is produced, and it is produced already attached to the session it
    /// describes — the advertisement has no separate storage to be written to,
    /// so it cannot be left over from, or applied to, a different session
    /// (#652).
    pub(super) async fn imap_login(
        &self,
        tls_stream: TlsStream<TcpStream>,
        already_greeted: bool,
        progress: &super::ConnectProgress,
    ) -> Result<SessionEntry, ImapError> {
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
        // UIDPLUS (RFC 4315), and hand the answer back attached to the session
        // that gave it.
        let capabilities = Self::read_capabilities(&mut session).await;

        Ok(SessionEntry::new(session, capabilities))
    }

    /// Run the post-login `CAPABILITY` probe and classify what came back.
    ///
    /// ## Why an uninformative probe is `Unknown` and not `(false, false)`
    ///
    /// Reporting "the server advertises neither MOVE nor UIDPLUS" from a probe
    /// that established nothing selects the folder-wide RFC 3501 `EXPUNGE` on
    /// the next delete or move — see [`ServerCapabilities`] and #649. So this
    /// returns [`ServerCapabilities::Known`] only when the reply was a
    /// capability listing, and the operations that would otherwise guess refuse
    /// instead.
    ///
    /// ## The two ways the probe tells us nothing
    ///
    /// Both reach the same `Unknown`, and only one of them is an `Err`:
    ///
    /// * **The command failed.** A torn connection or an unparseable response
    ///   comes back as `Err`. Rare, and usually fatal to the session anyway.
    /// * **The command "succeeded" with no listing in it.** This is the common
    ///   one and it was invisible before. `async-imap`'s `parse_capabilities`
    ///   (read against 0.11.3) accumulates `* CAPABILITY` lines until the
    ///   tagged completion and then returns `Ok` **without inspecting the
    ///   tagged status**, so a server answering `BAD` or `NO` — a load-shedding
    ///   proxy, a mid-restart server — yields `Ok(<empty set>)`. That set is
    ///   indistinguishable from a parsed listing by type alone.
    ///
    /// What separates them is `IMAP4rev1`: RFC 3501 §7.2.1 requires the
    /// CAPABILITY response to include it, so a listing that lacks it is not a
    /// listing this client can read. That check is what makes an
    /// `IMAP4rev1`-only server (a genuine "neither extension") land on `Known {
    /// false, false }` while a `BAD` lands on `Unknown`, which is the whole
    /// distinction #649 is about.
    ///
    /// A server advertising only `IMAP4rev2` (RFC 9051) is therefore `Unknown`
    /// too, and its deletes and moves are refused rather than served. That is
    /// the safe side of a gap, not a fix for it: RFC 9051 folds MOVE and
    /// UIDPLUS into the base protocol and stops advertising them, so reading
    /// such a server as "advertises neither" would have selected the
    /// folder-wide `EXPUNGE` against a server that in fact supports `UID
    /// EXPUNGE`. Real `IMAP4rev2` support is #686.
    async fn read_capabilities(session: &mut ImapSession) -> ServerCapabilities {
        let caps = match session.capabilities().await {
            Ok(caps) => caps,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "post-login CAPABILITY probe failed; MOVE/UIDPLUS support \
                     is unknown for this session and operations that would \
                     otherwise fall back to a folder-wide EXPUNGE will refuse",
                );
                return ServerCapabilities::Unknown;
            }
        };

        if !caps.has_str("IMAP4rev1") {
            tracing::warn!(
                advertised = caps.len(),
                "post-login CAPABILITY reply omitted IMAP4rev1, so it is not a \
                 capability listing this client can read (RFC 3501 7.2.1); \
                 MOVE/UIDPLUS support is unknown for this session and \
                 operations that would otherwise fall back to a folder-wide \
                 EXPUNGE will refuse",
            );
            return ServerCapabilities::Unknown;
        }

        ServerCapabilities::Known {
            has_move: caps.has_str("MOVE"),
            has_uidplus: caps.has_str("UIDPLUS"),
        }
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
    /// * **`spawn_blocking` loses the record on a shutdown.** Read against
    ///   tokio 1.53, a deferred closure survives a shutdown only by luck.
    ///   Submitted after `Runtime::shutdown_background` has set the flag,
    ///   `Spawner::spawn_task` shuts the task down and returns
    ///   `SpawnError::ShuttingDown`; the caller still gets a `JoinHandle`,
    ///   which resolves immediately with a *cancelled* `JoinError`, so the
    ///   closure never runs and the old code turned a successful connect into
    ///   `ImapError::Audit`. Already queued, it is a race against process exit
    ///   rather than against the drain: the scheduler's own workers are pool
    ///   tasks, so when the scheduler closes they fall back into the pool's
    ///   `BUSY` loop and run the queue without rechecking the flag — but
    ///   `rimap-server`'s `main` returns straight after `shutdown_background`,
    ///   which waits for nothing, so the process usually exits first. (A third,
    ///   narrower path drops the task outright on the shutdown drain.)
    ///   ADR-0014 has all three with the measurements. Writing inline removes
    ///   the whole question: there is no longer an `.await` between the guard's
    ///   disarm and the write (#643).
    /// * **`spawn_blocking` cannot be called from a `Drop` at all.**
    ///   [`super::AuthEmitGuard`] has no caller to await for it, and
    ///   `spawn_blocking` panics when the OS refuses a thread — a panic
    ///   escaping a `Drop` that runs during an unwind aborts the process.
    /// * **The cost is not new latency — it is a blocked runtime worker.**
    ///   `connect_inner` already awaited this write to completion before
    ///   returning, so the connect's wall time is unchanged; what moved is the
    ///   thread that spends it, from the blocking pool to a runtime worker.
    ///   Measured at 4.7 ms mean / 6.9 ms p95 / 16.9 ms max per record on
    ///   APFS-on-NVMe (ADR-0014 has the harness and the caveats). Once per
    ///   connect, and a connect is lazy and serialized per account by the
    ///   session lock, so the workers blocked at once are bounded by
    ///   `min(accounts, worker_threads)` — note the second term: `Runtime::new`
    ///   sizes workers from `available_parallelism`, which is 1 under a
    ///   one-vCPU quota, and there the bound is reached by a single account.
    ///   The wait is also one fsync *plus* any contention on the audit mutex,
    ///   which `tool_start`/`tool_end` take from the blocking pool. When the
    ///   file is due to rotate the write additionally takes a rename, an open,
    ///   and — with retention configured — a `read_dir` and a `remove_file`
    ///   per pruned file, still under that mutex.
    ///
    ///   No deadline covers that write, and it is unbounded above. On an
    ///   `audit.path` that stops responding — a hung NFS or SMB mount — it
    ///   never returns: the runtime worker is pinned for the life of the
    ///   process, and `dispatch::attempt` still holds the account's session
    ///   lock, so a peer queued on that account waits forever rather than
    ///   merely spending its `command_timeout`. With every worker so pinned the
    ///   time driver stops advancing too, so no `tokio::time` deadline fires —
    ///   `command_timeout` and the ADR-0012 ceiling included — and the stdio
    ///   MCP wire stops being served. The same stall on the blocking pool lands
    ///   against its 512-thread cap instead and cannot starve the scheduler, so
    ///   this makes `audit.path` a local-storage requirement rather than a
    ///   preference — and one nothing currently enforces: `docs/audit-log.md`
    ///   still scopes the warning to the cut path (#667), and detecting a
    ///   non-local `audit.path` at startup is #668.
    ///
    /// There is no lock-order hazard: the audit mutex is a leaf. It guards only
    /// file I/O, nothing inside its critical section calls back into this
    /// crate, and the advisory file lock is taken once at open rather than per
    /// write, so it cannot block on another process either.
    ///
    /// ## Why the sink call is wrapped in `catch_unwind` (#646)
    ///
    /// The [`AuthEventSink`](rimap_core::auth_sink::AuthEventSink) contract
    /// forbids panicking, and the shipped `AuditWriter` honours it — even a
    /// poisoned mutex comes back as a typed `AuditError`. Until #643 that
    /// contract also had a structural backstop it was never credited for:
    /// `spawn_blocking` turned a panicking sink into a `JoinError`, which the
    /// old code surfaced as `ImapError::Audit`. Deleting the hop deleted the
    /// backstop, and left two ways to lose more than one record:
    ///
    /// * From [`Self::emit_auth_blocking`] the unwind escapes
    ///   [`super::AuthEmitGuard`]'s `Drop`. A panic escaping a `Drop` that is
    ///   itself running during an unwind **aborts the process** — no unwinding,
    ///   no `process_end` record, nothing to observe.
    /// * From either caller it poisons the `AuditWriter`'s own mutex, which
    ///   `lock_inner` maps to a permanent `AuditError`: one transient panic
    ///   becomes a process-wide audit outage for the life of the process.
    ///
    /// So the sink call is contained here rather than at the `Drop`. This is
    /// the crate's only call into `AuthEventSink::emit_auth`, so one wrapper
    /// covers both callers — including the completed-connect path, where the
    /// same panic poisons the writer's mutex without ever reaching a `Drop`.
    /// Containing it cannot *un*-poison anything: the mutex is poisoned inside
    /// the sink, before the unwind reaches us. What it buys there is that the
    /// damage stays one lost record and a typed error rather than an unwind
    /// through `connect_inner`.
    /// [`Self::note_auth_write_lost`] is contained for the same reason; a
    /// defaulted trait method can panic just as easily, and it is what this
    /// function's own failure handler calls next, so without its own wrapper
    /// the abort would merely move one frame.
    ///
    /// ### What is contained, and what is not
    ///
    /// Every frame between [`super::AuthEmitGuard`]'s `Drop` and the sink is
    /// covered, and the two that are not wrapped are covered by being
    /// panic-free rather than by luck: `auth_context` reads config fields and
    /// two `OnceLock::get`s, and `auth_failure` is `to_string` plus
    /// `hex::encode` — allocation only, and an allocation failure aborts
    /// whatever wraps it.
    ///
    /// The residual is `tracing::error!`, which all three failure handlers on
    /// this path call after the contained call — this function's panic arm,
    /// [`Self::note_auth_write_lost`]'s, and [`Self::emit_auth_blocking`]'s —
    /// and which is deliberately left bare in each. Under the
    /// subscriber `rimap-server` installs it cannot panic, and wrapping it
    /// would put a second containment mechanism on the same path as this one —
    /// two mechanisms for one job, with the second one's own logging then
    /// unwrappable in turn. Named here so the guarantee is not read as wider
    /// than it is: **a panicking *sink* cannot abort the process; a panicking
    /// *subscriber* is a separate problem with a separate owner.**
    ///
    /// ### `AssertUnwindSafe`
    ///
    /// Required, because `&Connection` is not `UnwindSafe` — it holds `Arc`s
    /// and `AtomicBool`s. Justified by what a caught panic here can have
    /// broken. Nothing of `rimap-imap`'s: the closure captures `&self` and the
    /// event, its body is a single dynamic call, and no field of
    /// `ConnectionInner` is reachable from inside it. The `AuthEvent` was moved
    /// into the sink and is gone on either outcome.
    ///
    /// What a panic *can* leave inconsistent is the sink's own state — and the
    /// sink is shared process-wide, so that damage is not confined to this
    /// call. That is the point rather than a gap in the argument: the
    /// production `AuditWriter` makes it explicit by poisoning its mutex, after
    /// which every user of it — `tool_start`, `tool_end`, `process_end` — gets
    /// a typed `AuditError` rather than a bad value. A sink that corrupts
    /// itself therefore surfaces as lost records, which is exactly what this
    /// function reports, and the alternative to catching is not a healthy sink
    /// but the same damage plus an aborted process.
    ///
    /// On the guard's path the argument is simpler still: the guard is dropped
    /// immediately after, so nothing observes it again at all.
    ///
    /// **This containment depends on unwinding.** No profile in this workspace
    /// sets `panic = "abort"`; under it `catch_unwind` never returns, the
    /// process dies at the panic, and this guarantee is silently gone. Treat
    /// adding it as a decision about the audit trail, not a build-size tweak.
    ///
    /// ## `ImapError` message sanitization
    ///
    /// The [`AuthEventSink`](rimap_core::auth_sink::AuthEventSink) contract
    /// requires implementations to pre-sanitize the `message` field on
    /// [`rimap_core::AuthSinkError`] (no filesystem paths or
    /// operator-configured layout). This function forwards that `message`
    /// verbatim — the full underlying error is preserved on the `source` chain
    /// for observability. A panic payload carries no such guarantee, so it is
    /// dropped unread rather than formatted: it is an arbitrary `Any` a sink
    /// built from its own state, and `ImapError::Audit`'s `message` reaches the
    /// MCP wire.
    ///
    /// Dropping it keeps the payload off the wire, not out of the process.
    /// `catch_unwind` runs *after* the panic hook, and nothing here installs
    /// one, so std's default has already written the payload and its location
    /// to stderr by the time this arm runs — and, for a panic raised while
    /// another unwind is in flight, a full backtrace regardless of
    /// `RUST_BACKTRACE`. stdout, which carries the MCP protocol, is untouched.
    pub(super) fn emit_auth(&self, event: AuthEvent) -> Result<(), ImapError> {
        match catch_unwind(AssertUnwindSafe(|| self.inner.audit.emit_auth(event))) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(sink_err)) => {
                let message = sink_err.message().to_string();
                Err(ImapError::Audit {
                    op: "emit_auth",
                    message,
                    source: Box::new(sink_err),
                })
            }
            Err(_payload) => {
                tracing::error!(
                    "AuthEventSink::emit_auth panicked, violating the trait's \
                     no-panic contract; the record is lost and the sink may be \
                     unusable for the rest of the process",
                );
                Err(ImapError::Audit {
                    op: "emit_auth",
                    message: "auth-event sink panicked".to_string(),
                    source: Box::new(std::io::Error::other("AuthEventSink::emit_auth panicked")),
                })
            }
        }
    }

    /// Count a lost `auth` record through the sink, containing a panic the
    /// same way [`Self::emit_auth`] does and for the same reasons — both of
    /// this function's callers are the failure handler for an emit that
    /// already failed, and one of them is [`super::AuthEmitGuard`]'s `Drop`.
    ///
    /// A panic caught here leaves the loss uncounted, which is strictly worse
    /// than the `error` log it is replaced by but strictly better than the
    /// abort. There is no retry: calling the same broken method again would
    /// panic again.
    pub(super) fn note_auth_write_lost(&self) {
        if catch_unwind(AssertUnwindSafe(|| self.inner.audit.note_auth_write_lost())).is_err() {
            tracing::error!(
                "AuthEventSink::note_auth_write_lost panicked, violating the \
                 trait's no-panic contract; the lost auth record is uncounted",
            );
        }
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
    /// Implementations of [`rimap_core::auth_sink::AuthEventSink`] must still
    /// return their failures rather than panicking — the production
    /// `AuditWriter` maps even a poisoned mutex to an `AuditError`. A panic
    /// here would escape a `Drop`, so neither call this makes goes to the sink
    /// unwrapped: [`Self::emit_auth`] and [`Self::note_auth_write_lost`] each
    /// contain one (#646). That is a backstop for a broken sink, not a licence
    /// for one — a contained panic still costs the record.
    pub(super) fn emit_auth_blocking(&self, event: AuthEvent) {
        if let Err(err) = self.emit_auth(event) {
            self.note_auth_write_lost();
            tracing::error!(
                error = %err,
                "AuthEventSink::emit_auth failed for a connect that was cut \
                 before it reached its own verdict; the attempt is unrecorded",
            );
        }
    }
}
