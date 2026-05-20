//! Top-level error enum and stable error codes for rusty-imap-mcp.
//!
//! Every error carries a machine-readable [`ErrorCode`] and a human-readable
//! message. Codes are stable across releases; changing a code is a semver-major
//! break. The code list comes from design spec §9.

use core::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

/// Stable machine-readable error codes, per design spec §9.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, schemars::JsonSchema)]
#[schemars(with = "String")]
pub enum ErrorCode {
    /// Input validation failed.
    InvalidInput,
    /// Tool denied by the active posture.
    PostureDenied,
    /// Rate limiter token bucket empty.
    RateLimited,
    /// Circuit breaker open.
    CircuitOpen,
    /// UID / folder / part missing.
    NotFound,
    /// IMAP server misbehaved.
    ImapProtocol,
    /// SMTP server rejected message or command.
    SmtpProtocol,
    /// TLS handshake or cert verification failed.
    Tls,
    /// Authentication rejected.
    Auth,
    /// Mid-call disconnect.
    ConnectionLost,
    /// Command exceeded time limit.
    Timeout,
    /// Attachment exceeded cap.
    AttachmentTooLarge,
    /// Operation blocked because the folder is in `protected_folders`.
    ProtectedFolder,
    /// Expunge or `delete_folder` blocked because folder is not in `expunge_folders`.
    ExpungeDenied,
    /// Startup-time configuration error.
    Config,
    /// Bug, invariant violation, or audit failure.
    Internal,
    /// Multiple accounts configured but none selected.
    NoAccount,
    /// Named account not found in registry.
    UnknownAccount,
    /// Operation cancelled before completion (e.g. client disconnect, runtime
    /// shutdown). Emitted in `tool_end` records synthesized by the cancellation
    /// drop-guard (#99).
    Cancelled,
    /// UIDVALIDITY observed by the server differs from the value the caller
    /// expected (recorded at its prior SELECT). The target UID may now refer
    /// to a different message than the caller intended.
    UidValidityChanged,
}

impl ErrorCode {
    /// Stable on-wire string form (e.g. `"ERR_INVALID_INPUT"`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidInput => "ERR_INVALID_INPUT",
            Self::PostureDenied => "ERR_POSTURE_DENIED",
            Self::RateLimited => "ERR_RATE_LIMITED",
            Self::CircuitOpen => "ERR_CIRCUIT_OPEN",
            Self::NotFound => "ERR_NOT_FOUND",
            Self::ImapProtocol => "ERR_IMAP_PROTOCOL",
            Self::SmtpProtocol => "ERR_SMTP_PROTOCOL",
            Self::Tls => "ERR_TLS",
            Self::Auth => "ERR_AUTH",
            Self::ConnectionLost => "ERR_CONNECTION_LOST",
            Self::Timeout => "ERR_TIMEOUT",
            Self::AttachmentTooLarge => "ERR_ATTACHMENT_TOO_LARGE",
            Self::ProtectedFolder => "ERR_PROTECTED_FOLDER",
            Self::ExpungeDenied => "ERR_EXPUNGE_DENIED",
            Self::Config => "ERR_CONFIG",
            Self::Internal => "ERR_INTERNAL",
            Self::NoAccount => "ERR_NO_ACCOUNT",
            Self::UnknownAccount => "ERR_UNKNOWN_ACCOUNT",
            Self::Cancelled => "ERR_CANCELLED",
            Self::UidValidityChanged => "ERR_UID_VALIDITY_CHANGED",
        }
    }
}

impl core::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error returned by [`ErrorCode::from_str`] for unrecognized codes.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("unknown error code `{0}`")]
pub struct ParseErrorCodeError(pub String);

impl FromStr for ErrorCode {
    type Err = ParseErrorCodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ERR_INVALID_INPUT" => Ok(Self::InvalidInput),
            "ERR_POSTURE_DENIED" => Ok(Self::PostureDenied),
            "ERR_RATE_LIMITED" => Ok(Self::RateLimited),
            "ERR_CIRCUIT_OPEN" => Ok(Self::CircuitOpen),
            "ERR_NOT_FOUND" => Ok(Self::NotFound),
            "ERR_IMAP_PROTOCOL" => Ok(Self::ImapProtocol),
            "ERR_SMTP_PROTOCOL" => Ok(Self::SmtpProtocol),
            "ERR_TLS" => Ok(Self::Tls),
            "ERR_AUTH" => Ok(Self::Auth),
            "ERR_CONNECTION_LOST" => Ok(Self::ConnectionLost),
            "ERR_TIMEOUT" => Ok(Self::Timeout),
            "ERR_ATTACHMENT_TOO_LARGE" => Ok(Self::AttachmentTooLarge),
            "ERR_PROTECTED_FOLDER" => Ok(Self::ProtectedFolder),
            "ERR_EXPUNGE_DENIED" => Ok(Self::ExpungeDenied),
            "ERR_CONFIG" => Ok(Self::Config),
            "ERR_INTERNAL" => Ok(Self::Internal),
            "ERR_NO_ACCOUNT" => Ok(Self::NoAccount),
            "ERR_UNKNOWN_ACCOUNT" => Ok(Self::UnknownAccount),
            "ERR_CANCELLED" => Ok(Self::Cancelled),
            "ERR_UID_VALIDITY_CHANGED" => Ok(Self::UidValidityChanged),
            other => Err(ParseErrorCodeError(other.to_string())),
        }
    }
}

impl Serialize for ErrorCode {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ErrorCode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <&str>::deserialize(deserializer)?;
        Self::from_str(s).map_err(serde::de::Error::custom)
    }
}

/// Top-level tool error returned from dispatch. Library crates produce more
/// specific errors (`AuthzError`, `ConfigError`, `rimap_imap::ImapError`,
/// `AuditError`, …) which map into this via `From` impls.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RimapError {
    /// Authorization, posture, rate limit, or breaker failure.
    #[error("{code}: {message}")]
    Authz {
        /// Stable error code.
        code: ErrorCode,
        /// Human-readable message.
        message: String,
    },
    /// IMAP-layer failure (TLS, auth, network, protocol, timeout, size cap).
    #[error("{code}: {message}")]
    Imap {
        /// Stable error code.
        code: ErrorCode,
        /// Human-readable message.
        message: String,
        /// Underlying source error from `rimap_imap::ImapError`, if any.
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    },
    /// SMTP-layer failure (connection, auth, TLS, rejection, timeout).
    #[error("{code}: {message}")]
    Smtp {
        /// Stable error code.
        code: ErrorCode,
        /// Human-readable message (redacted — no server banners).
        message: String,
        /// Underlying source error, if any.
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    },
    /// Audit log failure. Carries both the stable code (open-time errors
    /// map to `ErrorCode::Config`, runtime errors to `ErrorCode::Internal`)
    /// and the original `AuditError` via the source chain. `message` is
    /// the source's `to_string()` captured at construction time so the
    /// Display form does not double-print the source when reporters walk
    /// the chain.
    #[error("{code}: {message}")]
    Audit {
        /// Stable error code — `Config` for open-time, `Internal` for runtime.
        code: ErrorCode,
        /// Human-readable message captured from the source at construction.
        message: String,
        /// The original audit error.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },
    /// Startup-time configuration error.
    #[error("ERR_CONFIG: {0}")]
    Config(String),
    /// Bug / invariant violation.
    #[error("ERR_INTERNAL: {0}")]
    Internal(String),
    /// Bug / invariant violation with an underlying source error. Use this
    /// instead of [`Self::Internal`] when wrapping a `?`-style upstream
    /// failure so the source chain is preserved for `tracing` and reporters.
    /// `message` should be the short operation context (e.g. `"join task"`,
    /// `"serialize tool catalog"`), not the formatted source.
    #[error("ERR_INTERNAL: {message}")]
    InternalSourced {
        /// Short operation context. Excludes the source string — reporters
        /// walk the `#[source]` chain to render it.
        message: String,
        /// The underlying error.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },
    /// Multiple accounts configured but none selected.
    ///
    /// The `available` list is surfaced in the Display form. This is a
    /// deliberate usability choice for v1 stdio-only deployments — see
    /// `docs/security-model.md` §"Account-name exposure in errors"
    /// (issue #81). Revisit before any non-stdio transport ships.
    #[error(
        "multiple accounts configured; call `use_account` or pass \
         `account` parameter. Available: {}",
        available.join(", ")
    )]
    NoAccount {
        /// Names of the available accounts.
        available: Vec<String>,
    },
    /// Named account not found in registry.
    ///
    /// The `available` list is surfaced in the Display form — see the
    /// `NoAccount` variant and `docs/security-model.md` for the posture
    /// decision (issue #81).
    #[error("account '{name}' not found. Available: {}", available.join(", "))]
    UnknownAccount {
        /// The name that was looked up.
        name: String,
        /// Names of the available accounts.
        available: Vec<String>,
    },
    /// IMAP `UIDVALIDITY` value changed between the caller's recorded
    /// SELECT and the server's current report. Surfaces the typed fields
    /// so MCP clients can implement fresh SELECT + re-fetch without
    /// parsing prose.
    ///
    /// Routed through `From<ImapError> for RimapError`'s dedicated arm
    /// (set up in Task E2) rather than the generic `Imap` variant, so
    /// the typed fields survive translation. See
    /// `docs/superpowers/specs/2026-05-20-mcp-tool-catalog-richness-design.md`
    /// (Delta 5).
    #[error(
        "UIDVALIDITY changed for `{folder}`: expected {expected}, \
         server reports {actual}"
    )]
    UidValidityChanged {
        /// The folder that was selected.
        folder: String,
        /// The UIDVALIDITY value the caller expected.
        expected: u32,
        /// The UIDVALIDITY value the server reported.
        actual: u32,
    },
}

impl RimapError {
    /// Construct an `Authz { code: InvalidInput, ... }` for caller-side
    /// argument validation failures. Use this instead of hand-rolling the
    /// struct form — the `Authz` variant is the canonical envelope for
    /// codes that surface to MCP as `INVALID_PARAMS`.
    #[must_use]
    pub fn invalid_input(message: impl Into<String>) -> Self {
        Self::Authz {
            code: ErrorCode::InvalidInput,
            message: message.into(),
        }
    }

    /// The stable error code carried by this error.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Authz { code, .. }
            | Self::Imap { code, .. }
            | Self::Smtp { code, .. }
            | Self::Audit { code, .. } => *code,
            Self::Config(_) => ErrorCode::Config,
            Self::Internal(_) | Self::InternalSourced { .. } => ErrorCode::Internal,
            Self::NoAccount { .. } => ErrorCode::NoAccount,
            Self::UnknownAccount { .. } => ErrorCode::UnknownAccount,
            Self::UidValidityChanged { .. } => ErrorCode::UidValidityChanged,
        }
    }
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "tests")]
mod tests {
    use crate::error::{ErrorCode, RimapError};

    #[test]
    fn every_error_code_has_stable_string() {
        let cases = [
            (ErrorCode::InvalidInput, "ERR_INVALID_INPUT"),
            (ErrorCode::PostureDenied, "ERR_POSTURE_DENIED"),
            (ErrorCode::RateLimited, "ERR_RATE_LIMITED"),
            (ErrorCode::CircuitOpen, "ERR_CIRCUIT_OPEN"),
            (ErrorCode::NotFound, "ERR_NOT_FOUND"),
            (ErrorCode::ImapProtocol, "ERR_IMAP_PROTOCOL"),
            (ErrorCode::SmtpProtocol, "ERR_SMTP_PROTOCOL"),
            (ErrorCode::Tls, "ERR_TLS"),
            (ErrorCode::Auth, "ERR_AUTH"),
            (ErrorCode::ConnectionLost, "ERR_CONNECTION_LOST"),
            (ErrorCode::Timeout, "ERR_TIMEOUT"),
            (ErrorCode::AttachmentTooLarge, "ERR_ATTACHMENT_TOO_LARGE"),
            (ErrorCode::ProtectedFolder, "ERR_PROTECTED_FOLDER"),
            (ErrorCode::ExpungeDenied, "ERR_EXPUNGE_DENIED"),
            (ErrorCode::Config, "ERR_CONFIG"),
            (ErrorCode::Internal, "ERR_INTERNAL"),
            (ErrorCode::NoAccount, "ERR_NO_ACCOUNT"),
            (ErrorCode::UnknownAccount, "ERR_UNKNOWN_ACCOUNT"),
            (ErrorCode::Cancelled, "ERR_CANCELLED"),
            (ErrorCode::UidValidityChanged, "ERR_UID_VALIDITY_CHANGED"),
        ];
        for (code, expected) in cases {
            assert_eq!(code.as_str(), expected);
            assert_eq!(format!("{code}"), expected);
        }
    }

    #[test]
    fn cancelled_round_trips() {
        assert_eq!(ErrorCode::Cancelled.as_str(), "ERR_CANCELLED");
        let parsed = "ERR_CANCELLED".parse::<ErrorCode>();
        assert_eq!(parsed, Ok(ErrorCode::Cancelled));
    }

    #[test]
    fn uid_validity_changed_round_trips() {
        assert_eq!(
            ErrorCode::UidValidityChanged.as_str(),
            "ERR_UID_VALIDITY_CHANGED"
        );
        let parsed = "ERR_UID_VALIDITY_CHANGED".parse::<ErrorCode>();
        assert_eq!(parsed, Ok(ErrorCode::UidValidityChanged));
    }

    #[test]
    fn rimap_error_code_accessor_matches_variant() {
        let authz = RimapError::Authz {
            code: ErrorCode::RateLimited,
            message: "slow down".to_string(),
        };
        assert_eq!(authz.code(), ErrorCode::RateLimited);
        assert_eq!(RimapError::Config("x".into()).code(), ErrorCode::Config);
        assert_eq!(RimapError::Internal("x".into()).code(), ErrorCode::Internal);
        let sourced = RimapError::InternalSourced {
            message: "wrap".into(),
            source: Box::new(std::io::Error::other("inner")),
        };
        assert_eq!(sourced.code(), ErrorCode::Internal);
    }

    #[test]
    fn rimap_error_display_includes_code_prefix() {
        let err = RimapError::Authz {
            code: ErrorCode::PostureDenied,
            message: "tool disabled".to_string(),
        };
        assert_eq!(err.to_string(), "ERR_POSTURE_DENIED: tool disabled");
    }

    #[test]
    fn rimap_error_audit_display_does_not_duplicate_source() {
        use std::io;

        let inner: Box<dyn std::error::Error + Send + Sync> =
            Box::new(io::Error::other("disk full"));
        let err = RimapError::Audit {
            code: ErrorCode::Internal,
            message: inner.to_string(),
            source: inner,
        };
        let displayed = err.to_string();
        // The display string should contain "disk full" exactly once.
        assert_eq!(displayed.matches("disk full").count(), 1);
        assert!(displayed.starts_with("ERR_INTERNAL: "));
    }

    #[test]
    fn rimap_error_internal_sourced_display_omits_source() {
        use std::error::Error as _;
        use std::io;

        let err = RimapError::InternalSourced {
            message: "serialize tool catalog".into(),
            source: Box::new(io::Error::other("disk full")),
        };
        let displayed = err.to_string();
        // Display renders the message only; "disk full" is reachable via
        // the source chain so reporters can walk it without duplication.
        assert_eq!(displayed, "ERR_INTERNAL: serialize tool catalog");
        assert!(displayed.contains("serialize tool catalog"));
        assert!(!displayed.contains("disk full"));
        let source = err.source().expect("source present");
        assert_eq!(source.to_string(), "disk full");
    }

    #[test]
    fn uid_validity_changed_variant_maps_to_error_code() {
        let err = RimapError::UidValidityChanged {
            folder: "INBOX".to_string(),
            expected: 100,
            actual: 101,
        };
        assert_eq!(err.code(), ErrorCode::UidValidityChanged);
    }

    #[test]
    fn uid_validity_changed_display_includes_typed_fields() {
        let err = RimapError::UidValidityChanged {
            folder: "INBOX".to_string(),
            expected: 100,
            actual: 101,
        };
        let s = format!("{err}");
        assert!(s.contains("INBOX"), "Display must include folder; got {s}");
        assert!(s.contains("100"), "Display must include expected; got {s}");
        assert!(s.contains("101"), "Display must include actual; got {s}");
    }
}
