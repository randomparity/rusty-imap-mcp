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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
