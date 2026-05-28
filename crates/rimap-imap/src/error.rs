//! `rimap_imap::ImapError` and conversion into `rimap_core::RimapError`.

use rimap_core::{ErrorCode, RimapError, TlsFingerprint};
use thiserror::Error;

/// Errors produced by `rimap-imap`. Each variant maps to a stable
/// `ErrorCode` via `From<ImapError> for RimapError`.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ImapError {
    /// TLS leaf-cert fingerprint did not match the configured pin.
    #[error("fingerprint mismatch (observed={observed}, expected={expected})")]
    Tls {
        /// The fingerprint the server presented.
        observed: TlsFingerprint,
        /// The fingerprint configured in `imap.tls_fingerprint_sha256`.
        expected: TlsFingerprint,
    },
    /// TLS handshake failed for a reason other than fingerprint mismatch
    /// (signature algorithm, protocol version, webpki path error in unpinned mode).
    #[error("handshake failed")]
    TlsHandshake(#[source] rustls::Error),
    /// STARTTLS negotiation failed before TLS could be established.
    #[error("STARTTLS failed: {reason}")]
    Starttls {
        /// Specific failure mode.
        reason: StarttlsFailure,
    },
    /// TCP connect failed.
    #[error("connect failed")]
    Connect(#[source] std::io::Error),
    /// `tokio::time::timeout` fired around an IMAP command.
    #[error("{op} exceeded deadline")]
    Timeout {
        /// Short tag identifying the operation that timed out.
        op: &'static str,
    },
    /// Authentication-layer failure (LOGIN rejected, LOGIN disabled, BYE greeting).
    #[error("auth failed: {reason}")]
    Auth {
        /// Specific failure mode.
        reason: AuthFailure,
    },
    /// Body fetch exceeded the configured size cap; connection was dropped.
    #[error("body size exceeded limit of {limit} bytes")]
    SizeLimit {
        /// The configured `max_fetch_body_bytes`.
        limit: u64,
    },
    /// Underlying `async-imap` protocol error.
    #[error("IMAP protocol error: {0}")]
    Protocol(#[source] async_imap::error::Error),
    /// TCP half-open: detected dead connection during a command.
    #[error("connection torn down mid-command")]
    ConnectionLost,
    /// Caller supplied invalid input (e.g. control bytes in a search string).
    #[error("invalid input: {field}: {reason}")]
    InvalidInput {
        /// Short name identifying the field or parameter that is invalid.
        field: &'static str,
        /// Human-readable explanation of the validation failure.
        reason: &'static str,
    },
    /// Caller passed more UIDs than the per-command batch limit.
    #[error("batch too large: {count} UIDs exceeds limit of {limit}")]
    BatchTooLarge {
        /// Number of UIDs the caller provided.
        count: usize,
        /// Maximum UIDs allowed per command.
        limit: usize,
    },
    /// UIDVALIDITY observed by the server differs from the value the
    /// caller expected (recorded at its prior SELECT). The target UID may
    /// now refer to a different message than the caller intended.
    #[error("UIDVALIDITY changed for `{folder}`: expected {expected}, server reports {actual}")]
    UidValidityChanged {
        /// The folder that was selected.
        folder: String,
        /// The UIDVALIDITY value the caller expected.
        expected: u32,
        /// The UIDVALIDITY value the server reported.
        actual: u32,
    },
    /// A guarded fetch required UIDVALIDITY but the server omitted it.
    /// Distinct from `UidValidityChanged` (which carries a concrete
    /// mismatch); here the guard simply could not be verified.
    #[error("server omitted UIDVALIDITY for folder {folder} on a guarded fetch")]
    UidValidityUnavailable {
        /// The folder that was selected.
        folder: String,
    },
    /// Audit-subsystem failure during a tool call. The IMAP transport may
    /// be healthy; this variant exists so audit-write failures stay
    /// distinguishable from network failures in metrics and observability.
    #[error("audit failure: {message}")]
    Audit {
        /// Short identifier of the audit operation that failed
        /// (e.g. `"emit_auth"`).
        op: &'static str,
        /// Human-readable failure summary captured at construction.
        message: String,
        /// Underlying error from the audit subsystem.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },
}

/// Specific authentication failure mode for `ImapError::Auth`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthFailure {
    /// LOGIN command rejected by the server.
    LoginRejected,
    /// Server advertised `LOGINDISABLED` in CAPABILITY.
    CapabilityMissing {
        /// The capability that was required but missing.
        needed: &'static str,
    },
    /// Server sent `BYE` as its greeting.
    ServerRejected,
    /// The credential store had no entry for this `<user>@<host>` and the
    /// `RUSTY_IMAP_MCP_PASSWORD` env var fallback was empty or absent.
    /// The inner string is the operator-actionable reason from
    /// the injected [`rimap_core::CredentialResolver`] (production
    /// implementation: `rimap_config::credential::KeyringCredentialResolver`).
    CredentialUnavailable(String),
}

/// Server-side STARTTLS refusal status. Tagged IMAP response classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StarttlsRefusal {
    /// Server tagged NO response.
    No,
    /// Server tagged BAD response.
    Bad,
}

impl std::fmt::Display for StarttlsRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::No => f.write_str("NO"),
            Self::Bad => f.write_str("BAD"),
        }
    }
}

/// Specific STARTTLS negotiation failure mode for `ImapError::Starttls`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StarttlsFailure {
    /// Server's CAPABILITY response did not advertise STARTTLS.
    CapabilityMissing,
    /// Server returned a tagged NO or BAD in response to STARTTLS.
    ServerRefused {
        /// The tagged response status.
        tagged_status: StarttlsRefusal,
    },
    /// Server greeted with BYE instead of OK.
    UnexpectedBye,
    /// Server greeted with PREAUTH. RFC 3501 §6.2.1 requires STARTTLS
    /// before authentication; a PREAUTH greeting means the server
    /// considers us authenticated already, which is incompatible with
    /// our STARTTLS-then-LOGIN flow.
    UnexpectedPreauth,
}

impl std::fmt::Display for StarttlsFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CapabilityMissing => f.write_str("server did not advertise STARTTLS capability"),
            Self::ServerRefused { tagged_status } => {
                write!(f, "server refused STARTTLS with tagged {tagged_status}")
            }
            Self::UnexpectedBye => f.write_str("server sent BYE greeting"),
            Self::UnexpectedPreauth => {
                f.write_str("server sent PREAUTH greeting; STARTTLS requires pre-auth state")
            }
        }
    }
}

impl std::fmt::Display for AuthFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LoginRejected => f.write_str("LOGIN rejected"),
            Self::CapabilityMissing { needed } => write!(f, "missing capability `{needed}`"),
            Self::ServerRejected => f.write_str("server BYE greeting"),
            Self::CredentialUnavailable(reason) => write!(f, "credential unavailable: {reason}"),
        }
    }
}

impl ImapError {
    /// Map this error to the canonical [`ErrorCode`] used in audit
    /// records and the top-level [`RimapError`] envelope. Audit code
    /// strings flow through [`ErrorCode::as_str`] so they match the
    /// taxonomy instead of drifting as ad-hoc literals.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Tls { .. } | Self::TlsHandshake(_) | Self::Starttls { .. } => ErrorCode::Tls,
            Self::Connect(_) | Self::ConnectionLost => ErrorCode::ConnectionLost,
            Self::Timeout { .. } => ErrorCode::Timeout,
            Self::Auth { .. } => ErrorCode::Auth,
            Self::SizeLimit { .. } => ErrorCode::AttachmentTooLarge,
            Self::Protocol(_) => ErrorCode::ImapProtocol,
            Self::InvalidInput { .. } | Self::BatchTooLarge { .. } => ErrorCode::InvalidInput,
            Self::UidValidityChanged { .. } | Self::UidValidityUnavailable { .. } => {
                ErrorCode::UidValidityChanged
            }
            Self::Audit { .. } => ErrorCode::Internal,
        }
    }
}

impl From<ImapError> for RimapError {
    fn from(err: ImapError) -> Self {
        // UIDVALIDITY-change errors get a dedicated RimapError variant
        // so MCP clients receive the typed `folder`/`expected`/`actual`
        // fields via structured `data`. SizeLimit likewise gets the dedicated
        // AttachmentTooLarge variant so its typed `limit` reaches structured
        // `data` (#303). Every other ImapError flattens through the generic
        // `Imap` arm, which preserves the original `ImapError` as a `#[source]`
        // so reporters that walk `error.source().chain()` see consistent depth.
        // SizeLimit is the documented exception: it is a leaf whose payload is
        // now the typed `limit`, so it keeps no source.
        // UidValidityUnavailable has no concrete mismatch to surface, so it
        // intentionally flows through the generic Imap arm below — same
        // client-visible code() (UidValidityChanged) but no structured
        // expected/actual fields.
        if let ImapError::UidValidityChanged {
            folder,
            expected,
            actual,
        } = &err
        {
            RimapError::UidValidityChanged {
                folder: folder.clone(),
                expected: *expected,
                actual: *actual,
                source: Box::new(err),
            }
        } else if let ImapError::SizeLimit { limit } = &err {
            // SizeLimit routes to the dedicated AttachmentTooLarge variant so
            // its typed `limit` reaches structured MCP `data` (#303). It is a
            // leaf, so no source is kept — the documented exception on
            // RimapError::AttachmentTooLarge.
            RimapError::AttachmentTooLarge {
                kind: "fetch_body_bytes".to_string(),
                limit: *limit,
            }
        } else {
            let code = err.code();
            let message = err.to_string();
            RimapError::Imap {
                code,
                message,
                source: Some(Box::new(err)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ImapError;
    use super::{StarttlsFailure, StarttlsRefusal};

    #[test]
    fn uid_validity_changed_display_includes_numbers_and_folder() {
        let err = ImapError::UidValidityChanged {
            folder: "INBOX".to_string(),
            expected: 100,
            actual: 101,
        };
        let display = format!("{err}");
        assert!(display.contains("INBOX"));
        assert!(display.contains("100"));
        assert!(display.contains("101"));
    }

    #[test]
    fn starttls_capability_missing_display_mentions_starttls() {
        let err = ImapError::Starttls {
            reason: StarttlsFailure::CapabilityMissing,
        };
        let s = format!("{err}");
        assert!(s.contains("STARTTLS"));
        assert!(s.to_lowercase().contains("capability"));
    }

    #[test]
    fn starttls_server_refused_display_includes_status() {
        let err = ImapError::Starttls {
            reason: StarttlsFailure::ServerRefused {
                tagged_status: StarttlsRefusal::No,
            },
        };
        let s = format!("{err}");
        assert!(s.contains("NO"));
    }

    #[test]
    fn starttls_unexpected_bye_display() {
        let err = ImapError::Starttls {
            reason: StarttlsFailure::UnexpectedBye,
        };
        let s = format!("{err}");
        assert!(s.to_lowercase().contains("bye"));
    }

    #[test]
    fn starttls_unexpected_preauth_display() {
        let err = ImapError::Starttls {
            reason: StarttlsFailure::UnexpectedPreauth,
        };
        let s = format!("{err}");
        assert!(s.to_uppercase().contains("PREAUTH"));
    }

    #[test]
    fn starttls_maps_to_tls_error_code() {
        use rimap_core::ErrorCode;
        let err = ImapError::Starttls {
            reason: StarttlsFailure::CapabilityMissing,
        };
        assert_eq!(err.code(), ErrorCode::Tls);
    }

    #[test]
    fn uid_validity_changed_routes_to_dedicated_rimap_variant() {
        use rimap_core::RimapError;

        let imap_err = ImapError::UidValidityChanged {
            folder: "INBOX".to_string(),
            expected: 100,
            actual: 101,
        };
        let rimap_err: RimapError = imap_err.into();
        match rimap_err {
            RimapError::UidValidityChanged {
                folder,
                expected,
                actual,
                source,
            } => {
                assert_eq!(folder, "INBOX");
                assert_eq!(expected, 100);
                assert_eq!(actual, 101);
                assert!(
                    source
                        .downcast_ref::<ImapError>()
                        .is_some_and(|ie| { matches!(ie, ImapError::UidValidityChanged { .. }) }),
                    "source must wrap the original ImapError::UidValidityChanged",
                );
            }
            #[expect(clippy::panic, reason = "intentional test assertion failure path")]
            other => panic!("expected RimapError::UidValidityChanged, got {other:?}",),
        }
    }

    #[test]
    fn size_limit_routes_to_attachment_too_large() {
        use rimap_core::RimapError;
        let imap_err = ImapError::SizeLimit { limit: 26_214_400 };
        let mapped: RimapError = imap_err.into();
        match mapped {
            RimapError::AttachmentTooLarge { kind, limit } => {
                assert_eq!(kind, "fetch_body_bytes");
                assert_eq!(limit, 26_214_400);
            }
            #[expect(clippy::panic, reason = "intentional test assertion failure path")]
            other => panic!("expected RimapError::AttachmentTooLarge, got {other:?}"),
        }
    }
}
