//! SMTP error type and conversion to `RimapError`.

use rimap_core::{ErrorCode, RimapError};
use thiserror::Error;

/// Errors produced by `rimap-smtp`.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SmtpError {
    /// Cannot reach the SMTP server.
    #[error("SMTP connection failed")]
    Connection(#[source] lettre::transport::smtp::Error),
    /// TLS handshake failed.
    #[error("SMTP TLS handshake failed")]
    Tls(#[source] lettre::transport::smtp::Error),
    /// Server rejected the message (4xx/5xx).
    #[error("SMTP send rejected: {reason}")]
    Rejected {
        /// Server response reason.
        reason: String,
    },
    /// Server rejected authentication (e.g. 535 5.7.8).
    #[error("SMTP authentication failed: {reason}")]
    Auth {
        /// Server response reason.
        reason: String,
    },
    /// SMTP command timed out.
    #[error("SMTP operation timed out")]
    Timeout,
    /// Catch-all for other lettre errors.
    #[error("SMTP error: {0}")]
    Transport(#[source] lettre::transport::smtp::Error),
}

impl From<SmtpError> for RimapError {
    fn from(err: SmtpError) -> Self {
        // Preserve Display detail (includes the lettre reason) so the
        // top-level message is not a generic placeholder; source chain
        // is still attached for callers that walk it.
        let message = err.to_string();
        let code = match &err {
            SmtpError::Connection(_) => ErrorCode::ConnectionLost,
            SmtpError::Tls(_) => ErrorCode::Tls,
            SmtpError::Rejected { .. } => ErrorCode::SmtpProtocol,
            SmtpError::Auth { .. } => ErrorCode::Auth,
            SmtpError::Timeout => ErrorCode::Timeout,
            SmtpError::Transport(_) => ErrorCode::Internal,
        };
        RimapError::Smtp {
            code,
            message,
            source: Some(Box::new(err)),
        }
    }
}

#[cfg(test)]
#[expect(clippy::panic, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn rejected_maps_to_smtp_protocol_code() {
        let err = SmtpError::Rejected {
            reason: "550 blocked".to_string(),
        };
        let mapped: RimapError = err.into();
        match mapped {
            RimapError::Smtp { code, message, .. } => {
                assert_eq!(code, ErrorCode::SmtpProtocol);
                assert!(message.contains("550 blocked"));
            }
            other => panic!("expected Smtp variant, got {other:?}"),
        }
    }

    #[test]
    fn auth_maps_to_auth_code() {
        let err = SmtpError::Auth {
            reason: "535 5.7.8 bad creds".into(),
        };
        let mapped: RimapError = err.into();
        match mapped {
            RimapError::Smtp { code, message, .. } => {
                assert_eq!(code, ErrorCode::Auth);
                assert!(message.contains("535 5.7.8 bad creds"));
            }
            other => panic!("expected Smtp variant, got {other:?}"),
        }
    }

    #[test]
    fn auth_display_includes_reason() {
        let err = SmtpError::Auth {
            reason: "credentials rejected".into(),
        };
        assert!(err.to_string().contains("credentials rejected"));
    }

    #[test]
    fn timeout_maps_to_timeout_code() {
        let err = SmtpError::Timeout;
        let mapped: RimapError = err.into();
        match mapped {
            RimapError::Smtp { code, .. } => assert_eq!(code, ErrorCode::Timeout),
            other => panic!("expected Smtp variant, got {other:?}"),
        }
    }

    #[test]
    fn rejected_display_includes_reason() {
        let err = SmtpError::Rejected {
            reason: "user unknown".into(),
        };
        assert!(err.to_string().contains("user unknown"));
    }

    #[test]
    fn rejected_error_code_is_smtp_protocol() {
        let err = SmtpError::Rejected {
            reason: "450 try later".into(),
        };
        let mapped: RimapError = err.into();
        assert_eq!(mapped.code(), ErrorCode::SmtpProtocol);
    }

    #[test]
    fn timeout_carries_error_code() {
        let mapped: RimapError = SmtpError::Timeout.into();
        assert_eq!(mapped.code(), ErrorCode::Timeout);
        assert!(mapped.to_string().contains("timed out"));
    }

    #[test]
    fn mapped_smtp_error_exposes_source_chain() {
        use std::error::Error as _;
        let err = SmtpError::Rejected {
            reason: "550 reject".into(),
        };
        let mapped: RimapError = err.into();
        // The source chain should bottom out at a SmtpError.
        let mut cur = mapped.source();
        let mut saw_smtp_error = false;
        while let Some(inner) = cur {
            if inner.downcast_ref::<SmtpError>().is_some() {
                saw_smtp_error = true;
                break;
            }
            cur = inner.source();
        }
        assert!(
            saw_smtp_error,
            "expected the RimapError source chain to surface the original SmtpError"
        );
    }
}
