//! Trait seam for emitting [`AuthEvent`] records without coupling
//! the IMAP transport to a specific audit-log implementation.
//!
//! `rimap-imap`'s `Connection` holds an `Arc<dyn AuthEventSink>` and
//! calls [`AuthEventSink::emit_auth`] from within
//! `tokio::task::spawn_blocking` — implementations may perform
//! synchronous filesystem I/O (the `rimap-audit::AuditWriter` impl
//! takes the writer's mutex and writes one JSONL line) and MUST NOT
//! be invoked from an async context without that wrapping.
//!
//! One caller is exempt because it has no async context to defer from:
//! `rimap-imap`'s drop guard for a connect that was cut calls this
//! synchronously, since a `Drop` cannot await. That is what the
//! no-panic requirement on [`AuthEventSink::emit_auth`] exists for.
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
/// The single method is sync; async callers must invoke it inside
/// `tokio::task::spawn_blocking` if the implementation performs
/// blocking I/O (the production `AuditWriter` impl does). One caller
/// deliberately does not — `rimap-imap`'s `AuthEmitGuard` records a
/// connect that was cut, from a `Drop`, which cannot await at all.
/// That caller is why implementations must not panic (below).
pub trait AuthEventSink: Send + Sync + std::fmt::Debug {
    /// Record `event`. Returns the implementation's error on failure.
    ///
    /// **Implementations must not panic.** Report every failure —
    /// including a poisoned lock — as an [`AuthSinkError`]; the
    /// production `AuditWriter` impl does. One caller invokes this
    /// synchronously from a `Drop`, and a panic escaping a `Drop` that
    /// runs during an unwind aborts the process.
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
    fn note_auth_write_lost(&self) {}
}
