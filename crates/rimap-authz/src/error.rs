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
    /// # Phase 2: structured `data` plumbing (deferred)
    ///
    /// Today `to_mcp_error` produces `ErrorData` with `data: None` for this
    /// code; the typed `retry_after_ms` is absorbed into the message string
    /// by `From<AuthzError> for RimapError` and lost. Plumbing it through
    /// requires either extending `RimapError::Authz` with a data field or
    /// introducing a dedicated variant. Tracked in GitHub issue #TBD; spec
    /// reference: `docs/superpowers/specs/2026-05-20-mcp-tool-catalog-richness-design.md`
    /// "Deferred work — Phase 2".
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
    /// # Phase 2: structured `data` plumbing (deferred)
    ///
    /// Today `to_mcp_error` produces `ErrorData` with `data: None` for this
    /// code; the typed `retry_after_ms` is absorbed into the message string
    /// by `From<AuthzError> for RimapError` and lost. Plumbing it through
    /// requires either extending `RimapError::Authz` with a data field or
    /// introducing a dedicated variant. Tracked in GitHub issue #TBD; spec
    /// reference: `docs/superpowers/specs/2026-05-20-mcp-tool-catalog-richness-design.md`
    /// "Deferred work — Phase 2".
    #[error("circuit breaker open; retry after {retry_after_ms} ms")]
    CircuitOpen {
        /// Hint for how long the caller should wait before retrying. See the
        /// variant docs for the special `0` case (half-open probe in flight).
        retry_after_ms: u64,
    },
    /// Config-time error during matrix build (e.g. unknown override tool).
    /// Wrapped as a string because we don't want `rimap-authz` to depend on
    /// the full `ConfigError` variant surface just for display.
    #[error("authz matrix build failed: {0}")]
    MatrixBuild(String),
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
            Self::MatrixBuild(_) => ErrorCode::Config,
            Self::ProtectedFolder { .. } => ErrorCode::ProtectedFolder,
            Self::ExpungeDenied { .. } => ErrorCode::ExpungeDenied,
            Self::InvalidFolderName { .. } => ErrorCode::InvalidInput,
        }
    }
}

impl From<AuthzError> for RimapError {
    fn from(err: AuthzError) -> Self {
        RimapError::Authz {
            code: err.code(),
            message: err.to_string(),
        }
    }
}

#[cfg(test)]
#[expect(clippy::panic, reason = "tests")]
mod tests {
    use crate::error::AuthzError;
    use rimap_core::error::{ErrorCode, RimapError};
    use rimap_core::tool::ToolName;

    #[test]
    fn from_impl_preserves_code_and_message() {
        let err = AuthzError::RateLimited { retry_after_ms: 42 };
        let msg = err.to_string();
        let mapped: RimapError = err.into();
        match mapped {
            RimapError::Authz { code, message } => {
                assert_eq!(code, ErrorCode::RateLimited);
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
            AuthzError::MatrixBuild("x".into()).code(),
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
