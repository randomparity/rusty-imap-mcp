//! Trait seam for emitting [`AuthEvent`] records without coupling
//! the IMAP transport to a specific audit-log implementation.
//!
//! `rimap-imap`'s `Connection` holds an `Arc<dyn AuthEventSink>` and
//! calls [`AuthEventSink::emit_auth`] **synchronously, on the calling
//! thread** — including from an async task, and including from a
//! `Drop`. Implementations may perform blocking filesystem I/O (the
//! `rimap-audit::AuditWriter` impl takes the writer's mutex and writes
//! one fsynced JSONL line), and they should assume the thread they
//! block is a runtime worker.
//!
//! That is deliberate and is not the workspace's general rule: every
//! other blocking call from async code here routes through
//! `tokio::task::spawn_blocking`, and this one used to as well. It
//! stopped because a deferred `auth` record is lost when the runtime
//! shuts down, and because `rimap-imap`'s drop guard for a connect that
//! was cut has no async context to defer from at all — a `Drop` cannot
//! await. ADR-0014 in the `rusty-imap-mcp` repository records the
//! decision and what it costs.
//!
//! The `Drop` caller is why implementations must not panic (see
//! [`AuthEventSink::emit_auth`]).
//!
//! Implementations live downstream:
//! - `rimap-audit::AuditWriter` records to the rotated, locked
//!   on-disk log.
//! - Test fixtures can supply an in-memory `Vec<AuthEvent>` collector
//!   via a small adapter.

use std::error::Error as StdError;

use thiserror::Error;

use crate::auth_event::AuthEvent;
use crate::error::ErrorCode;

/// Reason an [`AuthEventSink`] failed to record an event.
///
/// Carries a stable [`ErrorCode`] (so the IMAP layer can classify
/// without inspecting the source) plus the underlying error for
/// observability. Sinks MUST NOT include filesystem paths or other
/// operator-configured strings in `message`; those go in the
/// `source` chain via `tracing` at the implementation site.
///
/// Fields are not `pub` because callers only read them; use
/// [`Self::new`] to construct and [`Self::code`] / [`Self::message`]
/// to read.
#[derive(Debug, Error)]
#[error("auth-event sink failed: {message}")]
pub struct AuthSinkError {
    code: ErrorCode,
    message: String,
    #[source]
    source: Box<dyn StdError + Send + Sync + 'static>,
}

impl AuthSinkError {
    /// Build a sink error. `message` MUST be pre-sanitized (no
    /// filesystem paths or other operator-configured layout) so it
    /// can flow into transport-layer error chains.
    #[must_use]
    pub fn new(
        code: ErrorCode,
        message: impl Into<String>,
        source: Box<dyn StdError + Send + Sync + 'static>,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            source,
        }
    }

    /// Stable classification of the failure.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        self.code
    }

    /// Short, sanitized human label (no filesystem paths, no
    /// operator-specific layout).
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// Sink that durably records [`AuthEvent`] values.
///
/// Implementations are typically wrapped in an `Arc<dyn AuthEventSink>`
/// and shared across many `Connection` instances. The trait is `Send +
/// Sync` because the IMAP transport is `Clone`able and its clones may
/// run on different runtime tasks.
///
/// The single required method is sync, and `rimap-imap` calls it
/// inline on whatever thread produced the event — a runtime worker on
/// the ordinary path, and a `Drop` on the cut-connect path, which
/// cannot await at all. Both callers block until it returns, so an
/// implementation that blocks unboundedly (an audit path on a hung
/// network mount) pins a runtime worker for the life of the process.
pub trait AuthEventSink: Send + Sync + std::fmt::Debug {
    /// Record `event`. Returns the implementation's error on failure.
    ///
    /// **Implementations must not panic.** Report every failure —
    /// including a poisoned lock — as an [`AuthSinkError`]; the
    /// production `AuditWriter` impl does. One caller invokes this
    /// synchronously from a `Drop`, and a panic escaping a `Drop` that
    /// runs during an unwind aborts the process.
    ///
    /// `rimap-imap` no longer takes that on trust: since #646 it calls
    /// this inside `std::panic::catch_unwind` and treats a panic as a
    /// lost record, logged at `error`. Read that as a backstop against
    /// a broken sink, **not** as permission to panic. A contained
    /// panic still costs the `auth` record — a hole in an append-only
    /// security log, on the entry saying a credential was used against
    /// a remote server — and it may leave the sink unusable for the
    /// rest of the process, as it does for `AuditWriter`, whose mutex
    /// a panic poisons. The containment also depends on the binary
    /// unwinding; a profile built with `panic = "abort"` removes it
    /// silently.
    ///
    /// # Errors
    /// Returns [`AuthSinkError`] if the underlying sink rejects the
    /// event (e.g., disk full, lock poisoned, file rotated mid-write).
    fn emit_auth(&self, event: AuthEvent) -> Result<(), AuthSinkError>;

    /// Note that an [`AuthEvent`] was lost — [`Self::emit_auth`] rejected
    /// it on a path with no caller to return the error to.
    ///
    /// Two such paths exist in `rimap-imap`, and both call this. The
    /// `AuthEmitGuard` for a cut connect runs in a `Drop`, which has no
    /// caller at all. `connect_inner`'s auth-failure branch has one, but
    /// deliberately preserves the connect's own error rather than
    /// replacing it with the audit failure. Swallowing is right in both
    /// cases; going *uncounted* is not, so this makes the loss countable
    /// where it cannot be returnable.
    ///
    /// Implementations that keep a failure counter should increment it
    /// here. The production `AuditWriter` folds this into the same
    /// counter it uses for `fail_open` suppressions, so under either
    /// setting a lost record is accounted for exactly once — the
    /// `fail_open = true` branch counts internally and returns `Ok`, so
    /// this is not also called for it.
    ///
    /// The default is a no-op, for sinks with no counter to keep.
    ///
    /// **Overrides must not panic either**, for a sharper version of
    /// [`Self::emit_auth`]'s reason: this is what the caller reaches
    /// for *after* an emit has already failed, so on the `Drop` path a
    /// panic here would land in exactly the same place. `rimap-imap`
    /// contains this call too (#646); a panic caught here leaves the
    /// loss uncounted, and there is no retry, since calling the same
    /// broken method again would only panic again.
    fn note_auth_write_lost(&self) {}
}
