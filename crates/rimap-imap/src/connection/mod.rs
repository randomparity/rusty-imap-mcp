//! `Connection`: lazy-connect IMAP session with TLS fingerprint pinning,
//! command timeout enforcement, and `AuthEvent` audit emission.
//!
//! ## Locking discipline
//!
//! - The `tokio::sync::Mutex` around `Option<Session>` IS held across `.await`
//!   points (it has to be — async-imap commands are themselves `.await`).
//! - The injected [`AuthEventSink`] may hold its own internal
//!   `std::sync::Mutex` (the production `rimap-audit::AuditWriter`
//!   does). That lock is NEVER held across an `.await`. Every `auth`
//!   record — `connect_inner`'s own, and the one `AuthEmitGuard`'s
//!   `Drop` writes for a cut connect — goes through
//!   `Connection::emit_auth`, which takes and releases the lock inline
//!   on the calling thread. That satisfies the rule and costs a
//!   blocked thread for the duration of one fsync; `emit_auth` and
//!   ADR-0014 argue why that is the right trade (#643).
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
#[non_exhaustive]
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

impl ConnectionConfig {
    /// Construct connection settings from every required value.
    ///
    /// # Arguments
    ///
    /// * `account_id` - Account identifier used for credential lookups.
    /// * `host` - IMAP server host.
    /// * `port` - IMAP server port.
    /// * `encryption` - Transport encryption mode.
    /// * `username` - IMAP username.
    /// * `connect_timeout` - Connection, handshake, greeting, and capability deadline.
    /// * `command_timeout` - Per-command deadline.
    /// * `max_fetch_body_bytes` - Maximum accepted fetched message-body size.
    /// * `max_append_bytes` - Maximum accepted appended message size.
    #[expect(
        clippy::too_many_arguments,
        reason = "all required connection values must remain explicit; invalid defaults would discard operator configuration"
    )]
    #[must_use]
    pub fn new(
        account_id: rimap_core::account::AccountId,
        host: String,
        port: u16,
        encryption: ImapEncryption,
        username: String,
        connect_timeout: Duration,
        command_timeout: Duration,
        max_fetch_body_bytes: u64,
        max_append_bytes: u64,
    ) -> Self {
        Self {
            account_id,
            account: None,
            host,
            port,
            encryption,
            username,
            pinned_fingerprint: None,
            connect_timeout,
            command_timeout,
            max_fetch_body_bytes,
            max_append_bytes,
        }
    }
}

/// Active IMAP session type alias. `async-imap` parameterizes over the
/// underlying transport; we always use `TlsStream<TcpStream>`.
pub(crate) type ImapSession = Session<TlsStream<TcpStream>>;

/// What one session's post-login `CAPABILITY` probe established about the two
/// extensions this crate branches on.
///
/// Produced only by `imap_login`, and only as half of the `SessionEntry` it
/// returns, so a value of this type always arrives attached to the session
/// that answered the probe (#652).
///
/// ## Why this is not a `(bool, bool)` (#649)
///
/// It used to be. A probe that failed, or that came back without a capability
/// listing in it, was recorded as `(false, false)` — the same value a server
/// that affirmatively advertises neither extension produces. Those two states
/// need different answers, because `(false, false)` is *exactly* the condition
/// `crate::ops::expunge::fallback_uses_folder_wide_expunge` selects the RFC
/// 3501 folder-wide `EXPUNGE` on, which removes every `\Deleted` message in the
/// mailbox rather than the requested UIDs. Encoding "we do not know" as "the
/// server does not have it" therefore failed *open*, into the most destructive
/// branch available, on the strength of no evidence at all.
///
/// One tri-state rather than two, because the probe is one event: it either
/// yielded a listing that describes both extensions, or it yielded nothing that
/// describes either. There is no reachable state in which MOVE is known and
/// UIDPLUS is not.
///
/// `Self::require_known` is the only way to get the pair back out, so a
/// caller that wants to branch on a capability has to decide what `Unknown`
/// means to it first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerCapabilities {
    /// The probe returned a capability listing, and this is what it said.
    Known {
        /// Server advertised MOVE (RFC 6851).
        has_move: bool,
        /// Server advertised UIDPLUS (RFC 4315).
        has_uidplus: bool,
    },
    /// The session's probe came back unreadable — it errored, or it "succeeded"
    /// with no listing this client can read. Also what
    /// [`Connection::capabilities`] reports when there is no session at all, a
    /// case that has no advertisement to describe rather than an unreadable
    /// one.
    ///
    /// **Not a synonym for "the server lacks both."** Nothing may be inferred
    /// about the server from this.
    Unknown,
}

impl ServerCapabilities {
    /// The advertised pair, or the typed refusal `op` must return instead of
    /// guessing.
    ///
    /// The single accessor for the pair, and the single place `Unknown` turns
    /// into an outcome. Callers pass their own `op` tag so the error names the
    /// operation that stopped.
    ///
    /// # Errors
    ///
    /// [`ImapError::CapabilitiesUnknown`] when no advertisement is on record.
    pub(crate) fn require_known(self, op: &'static str) -> Result<(bool, bool), ImapError> {
        match self {
            Self::Known {
                has_move,
                has_uidplus,
            } => Ok((has_move, has_uidplus)),
            Self::Unknown => Err(ImapError::CapabilitiesUnknown { op }),
        }
    }
}

/// Lazy-connect IMAP connection. Cheaply cloneable (`Arc` internally).
#[derive(Clone)]
pub struct Connection {
    pub(super) inner: Arc<ConnectionInner>,
}

/// A live IMAP session and what that session's own post-login `CAPABILITY`
/// probe advertised, as one value (#652).
///
/// ## Why they are one value
///
/// The advertisement used to live in an atomic beside the session slot, with
/// its lifetime decoupled from the session it described. Keeping the two in
/// agreement was then everybody's job: [`Connection::take_poisoned`] had to
/// reset the atomic whenever it emptied the slot, `imap_login` had to store
/// into it whenever it produced a session, and every reader had to take its
/// read at a moment when the slot held the session that would serve the
/// command (#634).
///
/// Pairing them deletes all three obligations. There is one write — this
/// struct's construction, in `imap_login`, from the probe that session
/// answered — and emptying the slot drops the advertisement with the session
/// because they are the same value. A connection with no session has nothing
/// to read rather than a value someone had to remember to clear, so the two
/// paths that used to leave an advertisement over an empty slot cannot: a
/// discarded session, and a connect that logged in and then failed on its own
/// audit write, which no reset covered at all.
///
/// Pairing them also removes the hoist, because an op that branches on a
/// capability takes the entry rather than a [`ServerCapabilities`] (#704).
/// There is no signature in the crate a separately-read advertisement fits,
/// so a caller cannot read one outside a command and pass it into one.
///
/// `pub(crate)` rather than `pub(super)` for that reason: `ops::` has to name
/// this type to take it, which couples those two modules the way `ImapSession`
/// already does. It stays crate-private — nothing here is exported.
pub(crate) struct SessionEntry {
    session: ImapSession,
    capabilities: ServerCapabilities,
}

impl SessionEntry {
    /// Pair a freshly logged-in session with the advertisement it answered
    /// with. `imap_login` is the only caller, and it is the only place a
    /// [`ServerCapabilities`] value is produced.
    ///
    /// The one signature in the crate that takes a free-standing
    /// [`ServerCapabilities`], because it is where the pair is formed. Every
    /// later reader takes the entry instead.
    pub(super) fn new(session: ImapSession, capabilities: ServerCapabilities) -> Self {
        Self {
            session,
            capabilities,
        }
    }

    /// The session itself, for the command about to run against it.
    pub(crate) fn session(&mut self) -> &mut ImapSession {
        &mut self.session
    }

    /// What [`Self::session`] advertised at login. Read from the same value,
    /// so it cannot describe a different session.
    pub(crate) fn capabilities(&self) -> ServerCapabilities {
        self.capabilities
    }
}

// Field order is drop-order-significant. Fields drop in declaration
// order; reorder only with care. Today the order is: config scalars
// first (cheap), then the Arc'd sink and resolver (refcount
// decrements — the real destructors run wherever the last handle is
// dropped), then the live IMAP session (so its teardown cannot observe
// dropped audit/credential sinks), then the poison flag.
pub(super) struct ConnectionInner {
    pub(super) cfg: ConnectionConfig,
    pub(super) audit: Arc<dyn AuthEventSink>,
    pub(super) credentials: Arc<dyn CredentialResolver>,
    /// `None` = never connected, or last command tore down the connection.
    /// `Some(_)` = live session, and its advertisement, ready for the next
    /// command. See [`SessionEntry`] for why the advertisement lives here
    /// rather than in an atomic of its own.
    pub(super) session: Mutex<Option<SessionEntry>>,
    /// Set by [`Connection::poison`] when a command was cut mid-flight.
    /// Consumed by `dispatch::attempt` under the session lock; see `poison`
    /// for why it is a flag and not a lock.
    pub(super) poisoned: AtomicBool,
}

/// The session lock, held together with the poison flag it has to be ordered
/// against. Dropped over a cached session without having been disarmed —
/// which is what a cut command leaves behind — it poisons the connection
/// before releasing the lock (#620). See *When it fires* below for the exact
/// condition.
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
    slot: tokio::sync::MutexGuard<'a, Option<SessionEntry>>,
}

impl<'a> SessionGuard<'a> {
    /// Take ownership of an acquired session lock, armed.
    pub(super) fn new(
        conn: &'a Connection,
        slot: tokio::sync::MutexGuard<'a, Option<SessionEntry>>,
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
    type Target = Option<SessionEntry>;

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

/// Facts about an in-flight connect that only become known partway through it.
///
/// `AuthContext` needs a credential source, and `connect_with_bundle` learns it
/// at the moment `imap_login` resolves the credential — well after the TCP
/// connect and the TLS handshake. Returning it up the stack makes it readable
/// only once the connect has *finished*, which is exactly the case a cut
/// connect is not: [`AuthEmitGuard`] has to build its record from whatever is
/// known at the instant the future is dropped.
///
/// A cell written where the fact is learned makes the value readable from both
/// places, and — because [`Connection::auth_context`] is the single reader —
/// makes the cut record and the completed record describe the same attempt by
/// construction. `TlsConfigBundle::last_observed` is the same shape for the
/// same reason, which is why the observed fingerprint is not duplicated here.
#[derive(Debug, Default)]
pub(super) struct ConnectProgress {
    credential_source: std::sync::OnceLock<rimap_core::CredentialSource>,
}

impl ConnectProgress {
    /// Publish the credential source the moment resolution succeeds.
    ///
    /// `OnceLock` rather than `Cell` because `&ConnectProgress` is held across
    /// the connect's awaits: a `Cell` is not `Sync`, which would make the
    /// connect future non-`Send` and unspawnable on the multi-threaded runtime.
    /// There is exactly one writer, so `set` cannot lose; ignoring its result
    /// documents that rather than asserting it.
    pub(super) fn record_credential_source(&self, source: rimap_core::CredentialSource) {
        let _ = self.credential_source.set(source);
    }

    fn credential_source(&self) -> Option<rimap_core::CredentialSource> {
        self.credential_source.get().copied()
    }
}

/// Emits [`Connection::connect_inner`]'s `auth` record when the connect future
/// is dropped before that function reaches its own emit (#623).
///
/// `connect_inner` documents one `auth` record per connect attempt, and the
/// audit log it feeds is append-only and security-relevant: an attempt that was
/// initiated and recorded nothing is a gap an operator cannot tell from an
/// attempt that never happened. Four cuts reach that gap, none of which the
/// connect can see coming — the per-tool-call ceiling (#594, ADR-0012), a
/// client cancellation, a runtime shutdown, and a panic unwinding through the
/// connect. All four drop the frame, and a `Drop` impl is the only thing that
/// still runs.
///
/// So [`rimap_core::ErrorCode::Cancelled`] on an `auth` record reads as *the
/// attempt was cut*, which is wider than the word "cancelled" suggests. It is
/// still the right code: none of the four is a verdict the connect reached,
/// and the alternative is a code per cause that no consumer would branch on.
///
/// Deterministic for the ceiling and for a client cancellation. On a runtime
/// shutdown it is best-effort: `Runtime::shutdown_background` waits for
/// nothing, so the process can exit before the worker dropping this future
/// reaches the write.
///
/// Armed for the whole connect rather than from the first socket write, so a
/// cut parked in `TcpStream::connect` is recorded too. That is deliberate: the
/// attempt is what the log is about, and an operator reading a gap cannot know
/// which side of the connect it fell on.
///
/// ## Why it emits from `Drop` rather than being prevented upstream
///
/// The alternative #623 lists first is to exempt an in-flight connect from the
/// ceiling. That fails on both halves: the ceiling lives in `rimap-server` and
/// the connect in `rimap-imap`, so the exemption would have to cross a crate
/// seam that exists to keep the transport free of server policy — and it would
/// still not cover a client cancellation, where no ceiling is involved and none
/// of our code runs at all. A guard at the connect covers every cut, including
/// ones no caller can enumerate.
///
/// ## What the record says
///
/// [`rimap_core::ErrorCode::Cancelled`], never a verdict the attempt did not
/// reach. The guard cannot know why it was dropped, and a record claiming
/// `ERR_TIMEOUT` or `ERR_AUTH` for an attempt that was simply cut would be
/// worse than the gap it replaces. The `tool_end` record written by the layer
/// that did the cutting carries the reason.
///
/// The rest of the record is whatever was known at the instant of the drop —
/// see [`ConnectProgress`]. Early cuts (a parked TLS handshake) legitimately
/// carry no fingerprint and no credential source, which is the same shape a
/// pre-resolve failure already produces.
///
/// The write is synchronous, on the dropping thread — the same shape
/// `connect_inner`'s own emit uses since #643. `Connection::emit_auth` states
/// why; the short version is that deferring to the blocking pool loses the
/// record during a runtime shutdown, which is one of the cuts this guard
/// exists for.
struct AuthEmitGuard<'a> {
    conn: &'a Connection,
    bundle: &'a TlsConfigBundle,
    progress: &'a ConnectProgress,
    armed: bool,
}

impl<'a> AuthEmitGuard<'a> {
    fn new(
        conn: &'a Connection,
        bundle: &'a TlsConfigBundle,
        progress: &'a ConnectProgress,
    ) -> Self {
        Self {
            conn,
            bundle,
            progress,
            armed: true,
        }
    }

    /// The connect reached its own verdict, so `connect_inner` owns the record
    /// from here.
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for AuthEmitGuard<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let ctx = self.conn.auth_context(self.bundle, self.progress);
        self.conn
            .emit_auth_blocking(auth_failure(&ctx, rimap_core::ErrorCode::Cancelled));
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

    /// What the session currently in the slot advertised about MOVE (RFC 6851)
    /// and UIDPLUS (RFC 4315) at its own login, or
    /// [`ServerCapabilities::Unknown`] when the slot is empty.
    ///
    /// A derived read over the slot rather than a stored value (#652), so the
    /// empty case needs no reset to produce and no window in which a previous
    /// session's advertisement survives it.
    ///
    /// ## What this is for, and what it is not
    ///
    /// **Observation.** The integration tests live outside the crate and assert
    /// on what a completed command left behind; that is this method's only
    /// caller. There is no in-tree production caller and there should not be
    /// one.
    ///
    /// **Not a protocol input.** Code that selects a protocol from a capability
    /// reads it from the `SessionEntry` `with_session` hands its body, where
    /// the advertisement and the session that will serve the command are the
    /// same value (#634, #652). `dispatch::move_messages` and
    /// `dispatch::delete_message` are the only two that branch on a capability
    /// and both do exactly that.
    ///
    /// Reading this and passing the result into a command no longer compiles
    /// (#704). `ops::move_message::move_messages` and
    /// `ops::delete::delete_message` take the `&mut SessionEntry` and read the
    /// advertisement off it themselves, so there is no parameter this value
    /// fits. That closes the stale read the pairing alone did not: the command
    /// lazy-connects, and the connect it triggers can replace the session and
    /// its advertisement between the read here and the branch there. #652
    /// removed the *inconsistent* pair; the hoist is now a type error rather
    /// than a convention.
    ///
    /// ## Do not call this from inside a `with_session` body
    ///
    /// It takes the session lock, which that body already holds, and
    /// `tokio::sync::Mutex` is not reentrant — the call would deadlock the
    /// account for good. Use the entry's own
    /// `SessionEntry::capabilities` there; it is in scope and needs no lock.
    pub async fn capabilities(&self) -> ServerCapabilities {
        self.inner
            .session
            .lock()
            .await
            .as_ref()
            .map_or(ServerCapabilities::Unknown, SessionEntry::capabilities)
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
    /// * `SessionGuard`, which holds the session lock inside
    ///   `dispatch::attempt`, for the cuts where none of our code runs at
    ///   all — a client cancellation or a runtime shutdown dropping the
    ///   dispatch future (#620).
    ///
    /// This is a flag rather than an await on the session lock because
    /// `tokio::sync::Mutex` is FIFO-fair: a peer command that queued on
    /// the lock while the cut command held it sits *ahead* of anything
    /// that starts waiting now, and would take the poisoned session
    /// first. Waiting for the lock in order to clear the slot directly
    /// loses that race twice over — the peer takes the desynced session,
    /// and what the waiter finally clears is the *replacement* the peer
    /// reconnected (#629).
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
    ///
    /// Clearing the slot is the whole discard. It used to be half of one: the
    /// capability advertisement lived in an atomic beside the slot, so this
    /// had to reset that too, and the three paragraphs arguing why the window
    /// between the two stores was unobservable were part of the cost. The
    /// advertisement now travels *in* the slot ([`SessionEntry`]), so it is
    /// dropped here with the session it described and there is no second store
    /// to order against the first (#652).
    pub(super) fn take_poisoned(&self, slot: &mut Option<SessionEntry>) -> bool {
        if !self.inner.poisoned.swap(false, Ordering::Relaxed) {
            return false;
        }
        *slot = None;
        true
    }

    /// Assemble the `auth` record's inputs from the connection's own config
    /// plus whatever the in-flight connect has published so far.
    ///
    /// The single reader of [`ConnectProgress`] and of
    /// `TlsConfigBundle::last_observed`, so a record written by
    /// [`AuthEmitGuard`] on a cut connect and one written by
    /// [`Self::connect_inner`] on a completed connect cannot disagree about
    /// anything but the outcome.
    fn auth_context<'a>(
        &'a self,
        bundle: &TlsConfigBundle,
        progress: &ConnectProgress,
    ) -> AuthContext<'a> {
        let cfg = &self.inner.cfg;
        AuthContext {
            account: cfg.account.as_deref(),
            host: &cfg.host,
            port: cfg.port,
            username: &cfg.username,
            pinned: cfg.pinned_fingerprint,
            observed: bundle.last_observed.get().copied(),
            credential_source: progress.credential_source(),
        }
    }

    /// The full connect/handshake/login/CAPABILITY flow. Emits exactly one
    /// `Auth` audit record on every termination path from the TLS config
    /// onwards, including the paths on which this function never returns at
    /// all.
    ///
    /// Two carve-outs, both narrow and both stated where they arise:
    /// `build_tls_config` failing exits earlier than the attempt itself and
    /// records nothing, and the record [`AuthEmitGuard`] writes for a cut
    /// connect can still lose a race with process exit — see its rustdoc.
    ///
    /// A caller *may* wrap this in a deadline shorter than `connect_timeout` —
    /// the per-tool-call ceiling (#594, ADR-0012) does. Cutting the future
    /// mid-connect used to lose the record, because the emit below only runs
    /// after `connect_with_bundle` returns; [`AuthEmitGuard`] now writes it
    /// instead (#623). `dispatch::attempt` still runs this outside the command
    /// timeout, for the separate reason its own docs give.
    pub(super) async fn connect_inner(&self) -> Result<SessionEntry, ImapError> {
        let cfg = &self.inner.cfg;
        let bundle = build_tls_config(cfg.pinned_fingerprint)?;
        let progress = ConnectProgress::default();

        // Armed for the whole connect. Anything that drops this future before
        // the emit below — the ceiling, a client cancellation, a runtime
        // shutdown — leaves the guard to write the record.
        let mut emit_guard = AuthEmitGuard::new(self, &bundle, &progress);

        let outcome = self
            .connect_with_bundle(&bundle, &progress)
            .await
            .map_err(|err| enrich_tls_handshake_error(err, &bundle, cfg.pinned_fingerprint));

        let ctx = self.auth_context(&bundle, &progress);

        // Nothing awaits between here and the emit below — `emit_auth` writes
        // on this thread (#643) — so the future cannot be dropped in the gap.
        // The handover from guard to `connect_inner` is therefore neither a
        // gap nor a duplicate, whichever order it is written in.
        emit_guard.disarm();

        match &outcome {
            // A rejected audit write fails the whole connect, so a session that
            // logged in successfully is dropped here rather than returned. It
            // takes its advertisement with it because the two are one value
            // ([`SessionEntry`]); while the advertisement lived in an atomic,
            // this path left one behind for a session that never reached the
            // slot and no reset covered it (#652).
            Ok(_) => self.emit_auth(auth_success(&ctx))?,
            Err(err) => {
                // Deliberate: log but do NOT propagate emit_auth failures on
                // the error branch. The ORIGINAL outcome (ImapError::Auth,
                // ImapError::TlsHandshake, ImapError::Connect, ...) is what the
                // caller and monitoring need to see. Replacing it with
                // ImapError::Audit would mask brute-force signals from
                // whatever observed ERR_AUTH before.
                //
                // Swallowed, but not uncounted: `note_auth_write_lost` folds
                // the loss into the sink's own counter, which is what an
                // operator running `fail_open = false` has to go on when the
                // only other trace is a stderr line. (That counter reaches
                // `process_end` when #8 wires it; today it is readable via
                // `AuditWriter::suppressed_failures`.)
                if let Err(audit_err) = self.emit_auth(auth_failure(&ctx, err.code())) {
                    self.note_auth_write_lost();
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

    #[test]
    fn connection_config_new_preserves_required_fields_and_defaults_optionals() {
        let account_id = rimap_core::account::AccountId::default_account();
        let host = "imap.example.test".to_owned();
        let port = 993;
        let encryption = super::ImapEncryption::Tls;
        let username = "alice@example.test".to_owned();
        let connect_timeout = std::time::Duration::from_secs(11);
        let command_timeout = std::time::Duration::from_secs(17);
        let max_fetch_body_bytes = 1_048_576;
        let max_append_bytes = 2_097_152;

        let constructed = super::ConnectionConfig::new(
            account_id.clone(),
            host.clone(),
            port,
            encryption,
            username.clone(),
            connect_timeout,
            command_timeout,
            max_fetch_body_bytes,
            max_append_bytes,
        );
        let legacy = super::ConnectionConfig {
            account: None,
            account_id,
            host,
            port,
            encryption,
            username,
            pinned_fingerprint: None,
            connect_timeout,
            command_timeout,
            max_fetch_body_bytes,
            max_append_bytes,
        };

        assert_eq!(constructed.account, legacy.account);
        assert_eq!(constructed.account_id, legacy.account_id);
        assert_eq!(constructed.host, legacy.host);
        assert_eq!(constructed.port, legacy.port);
        assert_eq!(constructed.encryption, legacy.encryption);
        assert_eq!(constructed.username, legacy.username);
        assert_eq!(constructed.pinned_fingerprint, legacy.pinned_fingerprint);
        assert_eq!(constructed.connect_timeout, legacy.connect_timeout);
        assert_eq!(constructed.command_timeout, legacy.command_timeout);
        assert_eq!(
            constructed.max_fetch_body_bytes,
            legacy.max_fetch_body_bytes
        );
        assert_eq!(constructed.max_append_bytes, legacy.max_append_bytes);
    }

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
            reason = "no test in this module reaches credential resolution: the \
                      accessor tests never open a session, and the connect tests \
                      are cut or refused before login"
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
            panic!("credential resolver must not be invoked by these tests");
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

    /// Collects every [`rimap_core::auth_event::AuthEvent`] the connect flow
    /// emits, so a test can count them. Counting is the point: the guard added
    /// for #623 must produce a record when the connect future is dropped and
    /// must produce *no second* record when it is not.
    #[derive(Debug, Default)]
    struct RecordingSink {
        events: std::sync::Mutex<Vec<rimap_core::auth_event::AuthEvent>>,
    }

    impl RecordingSink {
        fn events(&self) -> Vec<rimap_core::auth_event::AuthEvent> {
            self.events.lock().expect("recording sink mutex").clone()
        }
    }

    impl rimap_core::auth_sink::AuthEventSink for RecordingSink {
        /// Reports a poisoned lock as an [`AuthSinkError`] rather than
        /// unwrapping, because that is what the trait requires of every
        /// implementation and an in-tree example should model the contract it
        /// documents. [`Self::events`] still unwraps: it is the *test's*
        /// accessor, not part of the sink's contract, and a poisoned lock
        /// there should fail the test loudly.
        fn emit_auth(
            &self,
            event: rimap_core::auth_event::AuthEvent,
        ) -> Result<(), rimap_core::auth_sink::AuthSinkError> {
            match self.events.lock() {
                Ok(mut events) => {
                    events.push(event);
                    Ok(())
                }
                Err(poisoned) => Err(rimap_core::auth_sink::AuthSinkError::new(
                    rimap_core::ErrorCode::Internal,
                    "recording sink lock poisoned",
                    Box::new(std::io::Error::other(poisoned.to_string())),
                )),
            }
        }
    }

    /// Rejects every event and counts how many losses the caller reported.
    /// Models the production sink under `fail_open = false` with a full disk.
    #[derive(Debug, Default)]
    struct RejectingSink {
        losses: std::sync::atomic::AtomicUsize,
    }

    impl rimap_core::auth_sink::AuthEventSink for RejectingSink {
        fn emit_auth(
            &self,
            _event: rimap_core::auth_event::AuthEvent,
        ) -> Result<(), rimap_core::auth_sink::AuthSinkError> {
            Err(rimap_core::auth_sink::AuthSinkError::new(
                rimap_core::ErrorCode::Internal,
                "sink rejects everything",
                Box::new(std::io::Error::other("disk full (test)")),
            ))
        }

        fn note_auth_write_lost(&self) {
            self.losses
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Violates the [`rimap_core::auth_sink::AuthEventSink`] no-panic contract
    /// on the write, but keeps its counter honest. Models the realistic shape:
    /// a sink whose write path acquired a lock with `.unwrap()`.
    #[derive(Debug, Default)]
    struct PanickingSink {
        losses: std::sync::atomic::AtomicUsize,
    }

    impl rimap_core::auth_sink::AuthEventSink for PanickingSink {
        #[expect(
            clippy::panic_in_result_fn,
            reason = "the contract violation under test is precisely a panic \
                      from a Result-returning sink"
        )]
        fn emit_auth(
            &self,
            _event: rimap_core::auth_event::AuthEvent,
        ) -> Result<(), rimap_core::auth_sink::AuthSinkError> {
            panic!("sink violates the no-panic contract (test)");
        }

        fn note_auth_write_lost(&self) {
            self.losses
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Violates the contract on *both* trait methods. `note_auth_write_lost` is
    /// a defaulted method an override can panic inside just as easily, and it
    /// is what the emit's own containment calls next — so a sink like this is
    /// the one that proves the abort was removed rather than moved one frame
    /// down the stack.
    #[derive(Debug, Default)]
    struct WhollyPanickingSink {
        /// Bumped *before* the panic, so a test can prove the second
        /// containment was actually exercised rather than merely present.
        notes: std::sync::atomic::AtomicUsize,
    }

    impl rimap_core::auth_sink::AuthEventSink for WhollyPanickingSink {
        #[expect(
            clippy::panic_in_result_fn,
            reason = "the contract violation under test is precisely a panic \
                      from a Result-returning sink"
        )]
        fn emit_auth(
            &self,
            _event: rimap_core::auth_event::AuthEvent,
        ) -> Result<(), rimap_core::auth_sink::AuthSinkError> {
            panic!("sink violates the no-panic contract on emit (test)");
        }

        fn note_auth_write_lost(&self) {
            self.notes
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            panic!("sink violates the no-panic contract on note (test)");
        }
    }

    /// A listener that accepts and then sends nothing, so a client parks on a
    /// `ServerHello` that never arrives. Every connect-cut test below needs
    /// exactly this: a socket that was opened to a server, and a handshake that
    /// will not finish on its own.
    ///
    /// The returned handle owns the accepted streams; abort it to close them.
    async fn silent_listener() -> (u16, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind silent listener");
        let port = listener.local_addr().expect("listener addr").port();
        let accepted = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream); // keep the socket open, send nothing
            }
        });
        (port, accepted)
    }

    /// A connection aimed at `127.0.0.1:port` with the caller's sink. The
    /// resolver is [`UnusedResolver`]: every connect test below is cut or
    /// refused before `imap_login` reaches credential resolution, and a panic
    /// is the loudest way to catch that assumption breaking.
    fn connection_with_sink(
        port: u16,
        sink: std::sync::Arc<dyn rimap_core::auth_sink::AuthEventSink>,
    ) -> super::Connection {
        let cfg = super::ConnectionConfig {
            account: Some("acct".to_string()),
            account_id: rimap_core::account::AccountId::default_account(),
            host: "127.0.0.1".to_string(),
            port,
            encryption: super::ImapEncryption::Tls,
            username: "alice@example.com".to_string(),
            pinned_fingerprint: None,
            connect_timeout: std::time::Duration::from_secs(30),
            command_timeout: std::time::Duration::from_secs(30),
            max_fetch_body_bytes: 4096,
            max_append_bytes: 1024,
        };
        super::Connection::new(cfg, sink, std::sync::Arc::new(UnusedResolver))
    }

    /// Drive a connect until a caller deadline cuts it, which runs
    /// [`AuthEmitGuard`]'s `Drop` on this task. Returns once the guard's write
    /// has been attempted.
    ///
    /// The 150ms budget has to stay well clear of `build_tls_config`, which
    /// runs *before* the guard is armed and builds a ~150-anchor root store on
    /// every connect. That costs single-digit milliseconds today; a cut landing
    /// inside it would record nothing.
    async fn connect_then_cut(conn: &super::Connection) {
        let cut =
            tokio::time::timeout(std::time::Duration::from_millis(150), conn.connect_inner()).await;
        assert!(
            cut.is_err(),
            "the caller deadline must elapse first; a connect that finished on \
             its own would make the assertions that follow vacuous",
        );
    }

    /// A sink that panics must not take the process with it (#646).
    ///
    /// Containment used to be a side effect of `spawn_blocking`: a panicking
    /// sink came back as a `JoinError`. #643 deleted that hop to stop losing
    /// records on shutdown (ADR-0014), which left the no-panic contract
    /// enforced by documentation alone — and three in-tree test sinks were
    /// already violating it. `Connection::emit_auth` now contains the panic
    /// deliberately.
    ///
    /// This is the ordinary-drop half: the panic escapes into a normal unwind,
    /// so an uncontained sink fails this test rather than killing the binary.
    /// The lost record must still be *counted*, which is what distinguishes a
    /// contained panic from one that skipped the failure handler entirely.
    /// [`a_guard_dropped_during_an_unwind_does_not_abort`] covers the shape
    /// that aborts.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_panicking_sink_cannot_abort_the_process_through_the_guard() {
        let (port, accepted) = silent_listener().await;
        let sink = std::sync::Arc::new(PanickingSink::default());
        let conn = connection_with_sink(
            port,
            std::sync::Arc::clone(&sink)
                as std::sync::Arc<dyn rimap_core::auth_sink::AuthEventSink>,
        );

        connect_then_cut(&conn).await;

        assert_eq!(
            sink.losses.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "a contained panic is still a lost record, and must be counted as \
             one rather than silently swallowed",
        );

        accepted.abort();
    }

    /// Containing the emit's panic is not enough on its own: the handler's very
    /// next call is `note_auth_write_lost`, a *defaulted* trait method a bad
    /// sink can panic inside just as easily. Without its own containment the
    /// abort would move one frame rather than disappear.
    ///
    /// The counter is bumped before the panic rather than after, so the
    /// assertion pins both halves at once — that the second containment was
    /// *reached*, and that it held. Surviving alone would go vacuously green if
    /// a later change stopped calling `note_auth_write_lost` from this path.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_sink_that_panics_in_note_auth_write_lost_cannot_abort_either() {
        let (port, accepted) = silent_listener().await;
        let sink = std::sync::Arc::new(WhollyPanickingSink::default());
        let conn = connection_with_sink(
            port,
            std::sync::Arc::clone(&sink)
                as std::sync::Arc<dyn rimap_core::auth_sink::AuthEventSink>,
        );

        connect_then_cut(&conn).await;

        assert_eq!(
            sink.notes.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "the emit's containment must still run the failure handler, so the \
             second panic is reached and contained rather than never raised",
        );

        accepted.abort();
    }

    /// The shape that actually aborts: [`AuthEmitGuard`]'s `Drop` running while
    /// an outer unwind is already in flight. Rust treats a panic escaping a
    /// destructor during cleanup as unrecoverable and calls `abort` — no second
    /// unwind, no `process_end` record, no test failure to read, just SIGABRT
    /// on the whole binary.
    ///
    /// The two tests above drive the guard from a cancelled `timeout`, which is
    /// an ordinary drop; they prove containment but not that *this* case was
    /// closed. `AuthEmitGuard`'s own rustdoc lists a panic unwinding through
    /// the connect among the cuts it exists for, so the case is reachable.
    ///
    /// Constructed directly rather than through a connect: a real unwind has to
    /// pass through the guard's frame, and no network is needed to make the
    /// guard write — it is armed at construction. Removing either `catch_unwind`
    /// turns this from a pass into an aborted test process.
    #[test]
    fn a_guard_dropped_during_an_unwind_does_not_abort() {
        let sink = std::sync::Arc::new(WhollyPanickingSink::default());
        let conn = connection_with_sink(
            0,
            std::sync::Arc::clone(&sink)
                as std::sync::Arc<dyn rimap_core::auth_sink::AuthEventSink>,
        );
        let bundle = crate::tls::build_tls_config(None).expect("build a TLS bundle");
        let progress = super::ConnectProgress::default();

        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = super::AuthEmitGuard::new(&conn, &bundle, &progress);
            panic!("an unwind passing through the connect");
        }));

        assert!(
            caught.is_err(),
            "the outer panic must unwind normally; reaching this line at all \
             means the guard's own panic did not abort the process",
        );
        assert_eq!(
            sink.notes.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "the guard must have been armed and reached the sink — surviving \
             the unwind proves nothing if nothing was emitted",
        );
    }

    /// A record the guard could not write must still be *counted*. The guard
    /// runs in a `Drop`, so swallowing the error is forced — but under the
    /// default `fail_open = false` the writer returns the error rather than
    /// counting it itself, so without this call the loss would leave nothing
    /// behind but a stderr line. That would make the stricter setting yield
    /// less evidence than the laxer one.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_record_the_guard_cannot_write_is_still_counted() {
        let (port, accepted) = silent_listener().await;
        let sink = std::sync::Arc::new(RejectingSink::default());
        let conn = connection_with_sink(
            port,
            std::sync::Arc::clone(&sink)
                as std::sync::Arc<dyn rimap_core::auth_sink::AuthEventSink>,
        );

        connect_then_cut(&conn).await;

        assert_eq!(
            sink.losses.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "a rejected guard write must be reported as a lost record",
        );

        accepted.abort();
    }

    /// A connection aimed at `127.0.0.1:port` whose sink records every event.
    fn recording_connection(port: u16) -> (super::Connection, std::sync::Arc<RecordingSink>) {
        let sink = std::sync::Arc::new(RecordingSink::default());
        let conn = connection_with_sink(
            port,
            std::sync::Arc::clone(&sink)
                as std::sync::Arc<dyn rimap_core::auth_sink::AuthEventSink>,
        );
        (conn, sink)
    }

    /// A caller-imposed deadline shorter than `connect_timeout` — the
    /// per-tool-call ceiling is the one that ships (#594, ADR-0012) — drops
    /// `connect_inner`'s future while the TLS handshake is still parked. A
    /// socket was opened to the server, so the append-only auth log must say
    /// so; before #623 it recorded nothing at all.
    ///
    /// The listener accepts and then writes nothing, so the client blocks on
    /// a `ServerHello` that never arrives. That parks strictly *before*
    /// credential resolution, which is what makes this also the early-drop
    /// case: the guard has to build a record from a half-populated
    /// `AuthContext` (no observed fingerprint, no credential source).
    ///
    /// No settling wait, deliberately: the guard writes on the dropping
    /// thread, so `timeout(..).await` returning means the record is already
    /// in the sink. A test that had to poll for it would also pass with the
    /// count assertion racing a second record it never saw.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_connect_cut_by_a_caller_deadline_still_emits_one_auth_record() {
        use rimap_core::auth_event::AuthResult;

        let (port, accepted) = silent_listener().await;
        let (conn, sink) = recording_connection(port);

        connect_then_cut(&conn).await;

        let events = sink.events();
        assert_eq!(
            events.len(),
            1,
            "a connect cut mid-flight must leave exactly one auth record: {events:?}",
        );
        let event = &events[0];
        assert_eq!(event.result, AuthResult::Failure);
        assert_eq!(
            event.error_code,
            Some(rimap_core::ErrorCode::Cancelled),
            "the connect did not fail on its own terms — it was cut, and the \
             record must not claim a verdict the attempt never reached",
        );
        assert_eq!(event.account.as_deref(), Some("acct"));
        assert_eq!(event.username.0, "alice@example.com");
        assert_eq!(event.port, port);
        assert_eq!(
            event.tls_fingerprint_sha256, None,
            "the handshake never reached certificate verification",
        );
        assert_eq!(
            event.credential_source, None,
            "the cut landed before credential resolution",
        );

        accepted.abort();
    }

    /// The disarm half. A connect that reaches its own verdict emits its one
    /// record on the normal path, and the drop guard must not add a second as
    /// the frame unwinds — a duplicated auth record is as much a defect in an
    /// append-only log as a missing one.
    ///
    /// Nothing is listening on the port, so the TCP connect is refused
    /// immediately and `connect_inner` returns `Err` rather than being cut.
    #[tokio::test]
    async fn a_connect_that_reached_its_own_verdict_emits_exactly_one_record() {
        use rimap_core::auth_event::AuthResult;

        // Bind and immediately drop, so the port is (near-certainly) unused
        // and the connect is refused rather than parked.
        let port = {
            let probe = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind probe listener");
            probe.local_addr().expect("probe addr").port()
        };

        let (conn, sink) = recording_connection(port);
        let outcome = conn.connect_inner().await;
        assert!(
            outcome.is_err(),
            "a refused TCP connect must fail rather than open a session",
        );

        let events = sink.events();
        assert_eq!(
            events.len(),
            1,
            "the normal emit path and the drop guard must not both fire: {events:?}",
        );
        assert_eq!(events[0].result, AuthResult::Failure);
        assert_eq!(
            events[0].error_code,
            Some(rimap_core::ErrorCode::ConnectionLost),
            "the record must carry the connect's own verdict, not the guard's \
             ERR_CANCELLED placeholder",
        );
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
    /// There is no capability assertion here any more, and its absence is the
    /// point. The advertisement used to sit in an atomic beside the slot, so
    /// this function had to reset it and a test had to pin that it did; the
    /// pair now lives *in* the slot ([`super::SessionEntry`]), so clearing the
    /// slot is the whole discard and there is nothing left that could keep
    /// describing a session that is gone (#652). Asserting it here would mean
    /// asserting that `None` has no capabilities — true by construction, and
    /// therefore an assertion that cannot fail. What the pairing buys is pinned
    /// by `tests/capability_slot_ownership.rs`, on the path where no reset ran
    /// at all.
    #[test]
    fn poison_is_consumed_once() {
        let conn = connection_with("mail.example.com", "alice@example.com", 4096);
        let mut slot = None;

        assert!(
            !conn.take_poisoned(&mut slot),
            "an unpoisoned connection must not report a discard",
        );

        conn.poison();

        assert!(
            conn.take_poisoned(&mut slot),
            "poison must be observed by the next holder of the session lock",
        );
        assert!(
            !conn.take_poisoned(&mut slot),
            "the flag must be consumed, not latched",
        );

        // A fired ceiling poisons TWICE (#620): `on_timeout_nonblocking` calls
        // `poison` directly, and dropping the cut dispatch then drops the
        // `SessionGuard`, which poisons again. Both stores land while the cut
        // dispatch still holds the session lock — #594 pins it alive across
        // the callback — so no peer can consume one in between. They must
        // collapse to a single discard, not cost two reconnects.
        conn.poison();
        conn.poison();
        assert!(
            conn.take_poisoned(&mut slot),
            "the first holder of the lock must see the doubly-set flag",
        );
        assert!(
            !conn.take_poisoned(&mut slot),
            "two poisons must collapse to one discard, not two reconnects",
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

    /// A `Connection` that has never logged in holds no advertisement.
    ///
    /// This used to be `(false, false)`, which is bit-identical to "the server
    /// advertises neither MOVE nor UIDPLUS" — so a test that probed an
    /// `IMAP4rev1`-only server and asserted "neither" passed without the login
    /// path running at all. Reporting `Unknown` makes the two states
    /// distinguishable from construction onwards (#649).
    #[tokio::test]
    async fn a_connection_that_never_logged_in_reports_unknown_capabilities() {
        let conn = connection_with("mail.example.com", "alice@example.com", 4096);
        assert_eq!(
            conn.capabilities().await,
            super::ServerCapabilities::Unknown
        );
    }

    /// `Unknown` has no pair to hand out, and the refusal names the caller's
    /// operation so the error tells an operator which command stopped.
    #[test]
    fn require_known_refuses_unknown_and_names_the_operation() {
        use super::ServerCapabilities;

        match ServerCapabilities::Unknown.require_known("move") {
            Err(ImapError::CapabilitiesUnknown { op }) => assert_eq!(op, "move"),
            other => panic!("expected CapabilitiesUnknown, got {other:?}"),
        }

        assert_eq!(
            ServerCapabilities::Known {
                has_move: true,
                has_uidplus: false,
            }
            .require_known("move")
            .ok(),
            Some((true, false)),
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

    /// No `ImapError` maps to [`rimap_core::ErrorCode::Cancelled`], and that
    /// is what makes `kind=auth` + `ERR_CANCELLED` uniquely identify a record
    /// written by [`super::AuthEmitGuard`] rather than by a connect that
    /// reached its own verdict.
    ///
    /// Consumers rely on that: `docs/audit-log.md` tells operators to exclude
    /// the code from failed-login counts, and the chaos harness's
    /// `count_auth_failures_between` does the same. A future variant mapping
    /// to `Cancelled` would collide with the guard's placeholder and be
    /// silently dropped from both. The list is the one
    /// `error_code_for_covers_every_variant` maintains; this asserts the
    /// property over it.
    #[test]
    fn no_imap_error_maps_to_the_guards_cancelled_placeholder() {
        for (err, _expected) in error_code_cases() {
            // Read the real mapping, not the expected-value column: asserting
            // over the table would only pin that the table says no such thing.
            assert_ne!(
                err.code(),
                rimap_core::ErrorCode::Cancelled,
                "{err:?} maps to ERR_CANCELLED, which the cut-connect drop \
                 guard reserves; give it a code of its own or the two become \
                 indistinguishable in the audit log",
            );
        }
    }

    /// Every `ImapError` variant paired with the audit code it must map to.
    /// Shared by the mapping test and by the ERR_CANCELLED-reservation test,
    /// so a new variant is covered by both from one edit.
    fn error_code_cases() -> Vec<(ImapError, &'static str)> {
        use crate::error::StarttlsFailure;
        vec![
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
                ImapError::CapabilitiesUnknown { op: "move" },
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
        ]
    }

    #[test]
    fn error_code_for_covers_every_variant() {
        for (err, expected) in &error_code_cases() {
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
