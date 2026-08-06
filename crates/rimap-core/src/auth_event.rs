//! Authentication-outcome event shared between the IMAP transport
//! crate (which emits) and the audit writer (which records).
//!
//! Lives in `rimap-core` so `rimap-imap` can build and hand off
//! `AuthEvent` values without taking a dependency on `rimap-audit`.
//! The audit writer keeps the on-disk representation in sync by
//! storing this struct verbatim inside its `auth` payload variant —
//! the field order, names, and serde attributes are the on-disk
//! wire format.

use serde::{Deserialize, Serialize};

use crate::credential::CredentialSource;
use crate::error::ErrorCode;

/// Outcome of an IMAP authentication attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthResult {
    /// Credential resolved and server accepted it.
    Success,
    /// Credential resolved but server rejected it.
    Failure,
}

/// One IMAP authentication attempt, ready for audit recording.
///
/// Constructed by `rimap-imap` (which observes the connect outcome)
/// and consumed by an [`crate::auth_sink::AuthEventSink`]
/// implementation (typically `rimap-audit::AuditWriter`). The on-disk
/// audit-log shape is this struct serialized verbatim — adding /
/// renaming fields is a wire-format change.
///
/// `#[non_exhaustive]` (#716) makes a future field additive at the Rust API
/// level, which it was not when `credential_source` arrived (#78). It is the
/// last of the audit payloads to get the attribute; the other twelve are
/// `rimap_audit::record`'s own (#706), and `rimap_audit`'s three non-record
/// structs are #715.
///
/// The attribute rejects **every** cross-crate struct expression,
/// functional-update syntax included (rustc **E0639**). A struct literal does
/// not compile downstream:
///
/// ```compile_fail,E0639
/// use rimap_core::auth_event::{AuthEvent, AuthResult};
/// let _ = AuthEvent {
///     account: None,
///     result: AuthResult::Success,
///     host: "imap.example.com".to_string(),
///     port: 993,
///     username: "alice@example.com".to_string(),
///     tls_fingerprint_sha256: None,
///     fingerprint_match: None,
///     error_code: None,
///     credential_source: None,
/// };
/// ```
///
/// And neither does functional update. The base here is [`AuthEvent::new`]
/// rather than a `Default` — the type has none — so this fails on the
/// attribute and nothing else:
///
/// ```compile_fail,E0639
/// use rimap_core::auth_event::{AuthEvent, AuthResult};
/// let _ = AuthEvent {
///     port: 143,
///     ..AuthEvent::new(
///         AuthResult::Success,
///         "imap.example.com".to_string(),
///         993,
///         "alice@example.com".to_string(),
///         None,
///         None,
///         None,
///     )
/// };
/// ```
///
/// The supported form is [`AuthEvent::new`] plus field assignment:
///
/// ```
/// use rimap_core::auth_event::{AuthEvent, AuthResult};
/// let mut event = AuthEvent::new(
///     AuthResult::Success,
///     "imap.example.com".to_string(),
///     993,
///     "alice@example.com".to_string(),
///     None,
///     None,
///     None,
/// );
/// event.account = Some("work".to_string());
/// assert_eq!(event.port, 993);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AuthEvent {
    /// Account name this auth attempt belongs to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    /// Outcome.
    pub result: AuthResult,
    /// IMAP host attempted.
    pub host: String,
    /// IMAP port attempted.
    pub port: u16,
    /// IMAP login identity (typically a username or email address).
    ///
    /// **This field MUST NEVER carry a password, OAuth / SASL token, auth
    /// blob, or any other credential material.** The `rimap-imap`
    /// wiring populates this from the config-resolved principal only;
    /// a copy-paste typo that lands a secret here leaks it to disk
    /// via the audit log.
    pub username: String,
    /// Observed TLS certificate fingerprint (SHA-256 hex, lowercase, no colons).
    /// `None` if the connection never reached TLS handshake completion.
    pub tls_fingerprint_sha256: Option<String>,
    /// Whether the observed fingerprint matched `imap.tls_fingerprint_sha256`
    /// from the config. `None` means the config did not pin a fingerprint.
    pub fingerprint_match: Option<bool>,
    /// On failure, the stable error code (`ERR_TLS`, `ERR_AUTH`, …); `None`
    /// on success.
    pub error_code: Option<ErrorCode>,
    /// Which store the credential came from. `None` when the attempt ended
    /// before resolution — a TLS or greeting failure, or a cut that landed
    /// early — and on records from code paths that predate #78. A failure
    /// *after* resolution (a rejected login, a timeout mid-LOGIN, a cut) does
    /// carry the source.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_source: Option<CredentialSource>,
}

impl AuthEvent {
    /// Build an auth event from the fields whose value a caller must state.
    ///
    /// The line between a parameter and a field left to assignment is drawn by
    /// what the record says on disk when the field is `None`, because that is
    /// what a reader of the audit trail acts on:
    ///
    /// - The three `Option` parameters — `tls_fingerprint_sha256`,
    ///   `fingerprint_match`, `error_code` — have no `skip_serializing_if`, so
    ///   a `None` is written out as an explicit `null`. The record makes a
    ///   claim either way: *no fingerprint was observed*, *the config pinned
    ///   nothing to compare against*, *this attempt carried no error code*. A
    ///   caller who never assigned them would publish those claims without
    ///   having established any of them, so they are required.
    /// - `account` and `credential_source` carry `skip_serializing_if`, so a
    ///   `None` leaves no key on the line at all — the record is silent rather
    ///   than affirmative. `credential_source` is additionally ambiguous by
    ///   construction: its absence means *resolution never ran* **or** *this
    ///   record predates #78*, which is why a reader cannot act on it alone.
    ///   Both are reached by assignment.
    ///
    /// Same rule as `rimap_audit`'s `ProcessEnd::new` taking `records_lost`
    /// (#706) and `AuditOptions::new` taking `initial_seq` (#715): a default
    /// that asserts something is a parameter.
    ///
    /// `username` is a login identity and **must never** be passed credential
    /// material; see the field's own documentation.
    #[must_use]
    pub fn new(
        result: AuthResult,
        host: String,
        port: u16,
        username: String,
        tls_fingerprint_sha256: Option<String>,
        fingerprint_match: Option<bool>,
        error_code: Option<ErrorCode>,
    ) -> Self {
        Self {
            account: None,
            result,
            host,
            port,
            username,
            tls_fingerprint_sha256,
            fingerprint_match,
            error_code,
            credential_source: None,
        }
    }
}
