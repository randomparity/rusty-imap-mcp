//! Authorization-layer error type. Converts into `RimapError::Authz` with the
//! appropriate error code.

use rimap_core::error::{ErrorCode, RimapError};
use rimap_core::tool::ToolName;
use thiserror::Error;

/// Errors produced by `rimap-authz` stages: posture, breaker, rate limiter.
#[derive(Debug, Error, Clone)]
#[non_exhaustive]
pub enum AuthzError {
    /// Tool denied by the current posture matrix.
    #[error("tool `{0}` denied by current posture")]
    PostureDenied(ToolName),
    /// Rate limiter rejected the call; `retry_after_ms` is a hint.
    ///
    /// `From<AuthzError> for RimapError` routes this into the dedicated
    /// `RimapError::RateLimited { retry_after_ms }` variant, which surfaces
    /// the typed hint as structured MCP `data` (#303).
    #[error("rate limited; retry after {retry_after_ms} ms")]
    RateLimited {
        /// Hint for how long the caller should wait before retrying.
        retry_after_ms: u64,
    },
    /// Circuit breaker is open; fast-failing.
    ///
    /// # `retry_after_ms` semantics
    ///
    /// - `retry_after_ms > 0`: the breaker is in the `Open` state and cooling
    ///   down. Callers should wait at least this long before retrying.
    /// - `retry_after_ms == 0`: the breaker is in the `HalfOpen` state — the
    ///   cooldown has elapsed and a single probe call is already in flight (or
    ///   has been admitted ahead of this caller). This does *not* mean "retry
    ///   immediately with no delay"; it means "the probe slot is taken, back
    ///   off briefly and try again once the probe resolves." A short fixed
    ///   delay (e.g. tens of milliseconds) is the intended caller behavior.
    ///
    /// `From<AuthzError> for RimapError` routes this into the dedicated
    /// `RimapError::CircuitOpen { retry_after_ms }` variant, which surfaces
    /// the typed hint as structured MCP `data` (#303).
    #[error("circuit breaker open; retry after {retry_after_ms} ms")]
    CircuitOpen {
        /// Hint for how long the caller should wait before retrying. See the
        /// variant docs for the special `0` case (half-open probe in flight).
        retry_after_ms: u64,
    },
    /// Config-time error while constructing an authz component — currently
    /// the governor refusing a degenerate zero-rate limiter (validation
    /// should have rejected it first). Wrapped as a string because we don't
    /// want `rimap-authz` to depend on the full `ConfigError` variant surface
    /// just for display.
    #[error("authz config build failed: {0}")]
    ConfigBuild(String),
    /// Folder is in the `protected_folders` list.
    #[error(
        "folder `{folder}` is protected and cannot be {operation}d; \
         remove it from protected_folders to allow this"
    )]
    ProtectedFolder {
        /// The folder name.
        folder: String,
        /// "delete" or "rename".
        operation: &'static str,
    },
    /// Folder is not in the `expunge_folders` allowlist.
    #[error(
        "expunge denied for folder `{folder}`; add it to expunge_folders \
         in your config to allow permanent deletion"
    )]
    ExpungeDenied {
        /// The folder name.
        folder: String,
    },
    /// Folder name failed structural validation.
    #[error("invalid folder name: {reason}")]
    InvalidFolderName {
        /// Why the name was rejected.
        reason: String,
    },
}

impl AuthzError {
    /// Map to the stable top-level error code.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::PostureDenied(_) => ErrorCode::PostureDenied,
            Self::RateLimited { .. } => ErrorCode::RateLimited,
            Self::CircuitOpen { .. } => ErrorCode::CircuitOpen,
            Self::ConfigBuild(_) => ErrorCode::Config,
            Self::ProtectedFolder { .. } => ErrorCode::ProtectedFolder,
            Self::ExpungeDenied { .. } => ErrorCode::ExpungeDenied,
            Self::InvalidFolderName { .. } => ErrorCode::InvalidInput,
        }
    }
}

impl From<AuthzError> for RimapError {
    fn from(err: AuthzError) -> Self {
        // RateLimited / CircuitOpen get dedicated RimapError variants so the
        // typed retry hint survives into structured MCP `data` (#303),
        // mirroring the UidValidityChanged routing in `From<ImapError>`.
        // Everything else flattens through the generic `Authz` arm.
        match err {
            AuthzError::RateLimited { retry_after_ms } => {
                RimapError::RateLimited { retry_after_ms }
            }
            AuthzError::CircuitOpen { retry_after_ms } => {
                RimapError::CircuitOpen { retry_after_ms }
            }
            other => RimapError::Authz {
                code: other.code(),
                message: other.to_string(),
            },
        }
    }
}

impl From<rimap_core::folder_name::FolderNameError> for AuthzError {
    fn from(err: rimap_core::folder_name::FolderNameError) -> Self {
        Self::InvalidFolderName {
            reason: err.reason.to_string(),
        }
    }
}

#[cfg(test)]
#[expect(clippy::panic, clippy::unwrap_used, reason = "tests")]
mod tests {
    use crate::error::AuthzError;
    use rimap_core::error::{ErrorCode, RimapError};
    use rimap_core::tool::ToolName;
    use rimap_core::folder_name::{FolderName, FolderNameError};

    #[test]
    fn folder_name_rejection_maps_to_authz_invalid_folder_name() {
        let err: AuthzError = FolderName::new("test\0folder")
            .err()
            .map(FolderNameError::into)
            .unwrap();
        assert!(matches!(err, AuthzError::InvalidFolderName { .. }));
    }

    #[test]
    fn authz_error_carries_canonical_reason() {
        let err: AuthzError =
            FolderName::new("").err().map(FolderNameError::into).unwrap();
        match err {
            AuthzError::InvalidFolderName { reason } => {
                assert!(reason.contains("empty"), "got reason: {reason}");
            }
            other => panic!("expected InvalidFolderName, got {other:?}"),
        }
    }

    #[test]
    fn valid_inbox_round_trips_through_canonical() {
        let f = FolderName::new("INBOX").unwrap();
        assert_eq!(f.as_str(), "INBOX");
    }

    #[test]
    fn rate_limited_routes_to_typed_variant() {
        let err = AuthzError::RateLimited { retry_after_ms: 42 };
        let display = err.to_string();
        let mapped: RimapError = err.into();
        match mapped {
            RimapError::RateLimited { retry_after_ms } => {
                assert_eq!(retry_after_ms, 42);
            }
            other => panic!("expected RimapError::RateLimited, got {other:?}"),
        }
        // Display wording is preserved (only the ERR_ prefix differs upstream).
        assert_eq!(
            RimapError::RateLimited { retry_after_ms: 42 }.to_string(),
            display
        );
    }

    #[test]
    fn circuit_open_routes_to_typed_variant() {
        let err = AuthzError::CircuitOpen {
            retry_after_ms: 15_000,
        };
        let mapped: RimapError = err.into();
        match mapped {
            RimapError::CircuitOpen { retry_after_ms } => {
                assert_eq!(retry_after_ms, 15_000);
            }
            other => panic!("expected RimapError::CircuitOpen, got {other:?}"),
        }
    }

    #[test]
    fn posture_denied_still_flattens_to_authz() {
        let err = AuthzError::PostureDenied(ToolName::CreateDraft);
        let msg = err.to_string();
        let mapped: RimapError = err.into();
        match mapped {
            RimapError::Authz { code, message } => {
                assert_eq!(code, ErrorCode::PostureDenied);
                assert_eq!(message, msg);
            }
            other => panic!("expected Authz variant, got {other:?}"),
        }
    }

    #[test]
    fn error_codes_match_spec() {
        assert_eq!(
            AuthzError::PostureDenied(ToolName::CreateDraft).code(),
            ErrorCode::PostureDenied
        );
        assert_eq!(
            AuthzError::RateLimited {
                retry_after_ms: 250
            }
            .code(),
            ErrorCode::RateLimited
        );
        assert_eq!(
            AuthzError::CircuitOpen {
                retry_after_ms: 15_000
            }
            .code(),
            ErrorCode::CircuitOpen
        );
        assert_eq!(
            AuthzError::ConfigBuild("x".into()).code(),
            ErrorCode::Config
        );
        assert_eq!(
            AuthzError::ProtectedFolder {
                folder: "INBOX".into(),
                operation: "delete",
            }
            .code(),
            ErrorCode::ProtectedFolder
        );
        assert_eq!(
            AuthzError::ExpungeDenied {
                folder: "Sent".into(),
            }
            .code(),
            ErrorCode::ExpungeDenied
        );
        assert_eq!(
            AuthzError::InvalidFolderName {
                reason: "test".into(),
            }
            .code(),
            ErrorCode::InvalidInput
        );
    }
}
