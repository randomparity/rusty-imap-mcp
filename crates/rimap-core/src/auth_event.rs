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

/// The IMAP host an authentication attempt targeted.
///
/// A newtype rather than a bare `String` because [`AuthEvent::new`] takes
/// `host` and `username` in adjacent positions separated only by a `u16`
/// (#748). While both were `String`, a transposed call type-checked and
/// compiled, and wrote a login identity into the `host` field of an
/// append-only forensic record that is never rewritten. It is now a type
/// error.
///
/// `#[serde(transparent)]`, so the `auth` line on disk is unchanged — `host`
/// stays the bare string it always was, and the existing byte-exact goldens
/// in `rimap-audit/tests/non_exhaustive_record.rs` are untouched.
///
/// The attribute is doing more than restating serde's newtype-struct default,
/// which would already write these bytes: it is a **compile error** on a
/// struct with more than one field. So a second field added to this wrapper
/// later reddens at the attribute, instead of quietly turning the on-disk
/// `host` into a JSON object in an append-only log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Host(pub String);

/// The IMAP login identity an authentication attempt presented (typically a
/// username or an email address).
///
/// **A value of this type MUST NEVER be constructed from a password, OAuth /
/// SASL token, auth blob, or any other credential material.** The `rimap-imap`
/// wiring builds it from the config-resolved principal only; a value that
/// lands a secret here leaks it to disk via the audit log.
///
/// The wrapper is what makes that rule enforceable at review time rather than
/// only at runtime. It cannot stop `Username(password)` — no type can, since
/// both are strings — but it moves the mistake from *any positional argument
/// at any call site* to *one explicit, greppable `Username(…)` expression*.
/// Its other half is the [`Host`] transposition it makes uncompilable.
///
/// `#[serde(transparent)]` for the same reason as [`Host`]; see there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Username(pub String);

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
/// use rimap_core::auth_event::{AuthEvent, AuthResult, Host, Username};
/// let _ = AuthEvent {
///     account: None,
///     result: AuthResult::Success,
///     host: Host("imap.example.com".to_string()),
///     port: 993,
///     username: Username("alice@example.com".to_string()),
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
/// use rimap_core::auth_event::{AuthEvent, AuthResult, Host, Username};
/// let _ = AuthEvent {
///     port: 143,
///     ..AuthEvent::new(
///         AuthResult::Success,
///         Host("imap.example.com".to_string()),
///         993,
///         Username("alice@example.com".to_string()),
///         None,
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
/// use rimap_core::auth_event::{AuthEvent, AuthResult, Host, Username};
/// let mut event = AuthEvent::new(
///     AuthResult::Success,
///     Host("imap.example.com".to_string()),
///     993,
///     Username("alice@example.com".to_string()),
///     None,
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
    /// IMAP host attempted. Serializes as a bare string; see [`Host`].
    pub host: Host,
    /// IMAP port attempted.
    pub port: u16,
    /// IMAP login identity (typically a username or email address).
    /// Serializes as a bare string.
    ///
    /// **This field MUST NEVER carry a password, OAuth / SASL token, auth
    /// blob, or any other credential material** — see [`Username`], which
    /// carries the rule and the reason it is a newtype.
    pub username: Username,
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
    /// Every field a reader of the audit trail draws a conclusion from is a
    /// parameter, following the rule `rimap_audit`'s `ProcessEnd::new`
    /// (`records_lost`, #706) and `AuditOptions::new` (`initial_seq`, #715)
    /// established: **a default that asserts something is a parameter.** Each
    /// of the four `Option`s here has a load-bearing `None` — *no fingerprint
    /// was observed*, *the config pinned nothing to compare against*, *this
    /// attempt carried no error code*, *the attempt ended before credential
    /// resolution ran*. A caller who never assigned one would publish that
    /// claim without having established it.
    ///
    /// `credential_source` earns its place despite being
    /// `skip_serializing_if`: an omitted key is not a neutral silence, because
    /// `docs/audit-log.md` binds a reader to treat an absent field as
    /// *unknown* rather than as benign, and a forgotten assignment would be
    /// indistinguishable on disk from the genuine pre-resolution failure it
    /// documents. Passing `None` explicitly is at least a checkable claim.
    ///
    /// `account` is the one field left to assignment. It is an operator label
    /// rather than a security fact — `None` is the ordinary shape of a
    /// single-account deployment, not an assertion about what happened — and
    /// it is skipped on the line when absent.
    ///
    /// `host` and `username` are [`Host`] and [`Username`] rather than bare
    /// `String`s (#748). They are separated only by a `u16`, so passed bare a
    /// transposed call type-checked and compiled, and wrote a login identity
    /// into the `host` field of a record that is never rewritten. Transposed
    /// now, it does not compile (rustc **E0308**):
    ///
    /// ```compile_fail,E0308
    /// use rimap_core::auth_event::{AuthEvent, AuthResult, Host, Username};
    /// let host = Host("imap.example.com".to_string());
    /// let username = Username("alice@example.com".to_string());
    /// let _ = AuthEvent::new(
    ///     AuthResult::Success,
    ///     username,
    ///     993,
    ///     host,
    ///     None,
    ///     None,
    ///     None,
    ///     None,
    /// );
    /// ```
    ///
    /// The same two arguments in the order they name compile, which is what
    /// makes the failure above about the transposition and not about anything
    /// else in the call:
    ///
    /// ```
    /// use rimap_core::auth_event::{AuthEvent, AuthResult, Host, Username};
    /// let host = Host("imap.example.com".to_string());
    /// let username = Username("alice@example.com".to_string());
    /// let event = AuthEvent::new(
    ///     AuthResult::Success,
    ///     host,
    ///     993,
    ///     username,
    ///     None,
    ///     None,
    ///     None,
    ///     None,
    /// );
    /// assert_eq!(event.host.0, "imap.example.com");
    /// ```
    ///
    /// What the types cannot check is which *string* each wrapper was built
    /// from; that mapping is pinned by
    /// `rimap-audit/tests/non_exhaustive_record.rs::auth_event_new_maps_each_argument_onto_the_field_it_names`.
    /// `username` must never be built from credential material — see
    /// [`Username`].
    #[must_use]
    #[expect(
        clippy::too_many_arguments,
        reason = "8 of the 9 fields carry a claim a reader acts on, so each is \
                  stated rather than defaulted; a parameter-object type here \
                  would be a second public shape in rimap-core for one caller"
    )]
    pub fn new(
        result: AuthResult,
        host: Host,
        port: u16,
        username: Username,
        tls_fingerprint_sha256: Option<String>,
        fingerprint_match: Option<bool>,
        error_code: Option<ErrorCode>,
        credential_source: Option<CredentialSource>,
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
            credential_source,
        }
    }
}
