//! Round-trip tests for `From<rimap_imap::ImapError> for RimapError` — assert
//! the source chain is preserved through `ImapError::source()`.

#![expect(clippy::unwrap_used, reason = "tests")]
#![expect(clippy::expect_used, reason = "tests")]

use std::error::Error as _;

use rimap_core::{ErrorCode, RimapError, TlsFingerprint};
use rimap_imap::error::{AuthFailure, ImapError};

const FP_HEX_A: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const FP_HEX_B: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

#[test]
fn tls_fingerprint_mismatch_maps_to_err_tls() {
    let observed = TlsFingerprint::from_hex(FP_HEX_A).unwrap();
    let expected = TlsFingerprint::from_hex(FP_HEX_B).unwrap();
    let err = ImapError::Tls { observed, expected };
    let rimap: RimapError = err.into();
    assert_eq!(rimap.code(), ErrorCode::Tls);
    assert!(rimap.source().is_some());
}

#[test]
fn auth_login_rejected_maps_to_err_auth() {
    let err = ImapError::Auth {
        reason: AuthFailure::LoginRejected,
    };
    let rimap: RimapError = err.into();
    assert_eq!(rimap.code(), ErrorCode::Auth);
}

#[test]
fn capability_missing_maps_to_err_auth() {
    let err = ImapError::Auth {
        reason: AuthFailure::CapabilityMissing { needed: "LOGIN" },
    };
    let rimap: RimapError = err.into();
    assert_eq!(rimap.code(), ErrorCode::Auth);
    let msg = rimap.to_string();
    assert!(msg.contains("LOGIN"), "got {msg}");
}

#[test]
fn timeout_maps_to_err_timeout() {
    let err = ImapError::Timeout { op: "fetch" };
    let rimap: RimapError = err.into();
    assert_eq!(rimap.code(), ErrorCode::Timeout);
}

#[test]
fn size_limit_maps_to_err_attachment_too_large() {
    let err = ImapError::SizeLimit { limit: 1024 };
    let rimap: RimapError = err.into();
    assert_eq!(rimap.code(), ErrorCode::AttachmentTooLarge);
    let chain = rimap.source().expect("source preserved");
    assert!(chain.to_string().contains("1024"));
}

#[test]
fn connection_lost_maps_to_err_connection_lost() {
    let err = ImapError::ConnectionLost;
    let rimap: RimapError = err.into();
    assert_eq!(rimap.code(), ErrorCode::ConnectionLost);
}

#[test]
fn connect_io_error_maps_to_err_connection_lost() {
    let io = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "nope");
    let err = ImapError::Connect(io);
    let rimap: RimapError = err.into();
    assert_eq!(rimap.code(), ErrorCode::ConnectionLost);
}

#[test]
fn uid_validity_unavailable_maps_to_err_uid_validity_changed() {
    let err = ImapError::UidValidityUnavailable {
        folder: "INBOX".to_string(),
    };
    let rimap: RimapError = err.into();
    assert_eq!(rimap.code(), ErrorCode::UidValidityChanged);
    assert!(rimap.source().is_some());
}

#[test]
fn audit_variant_maps_to_internal_error_code() {
    let err = ImapError::Audit {
        op: "emit_auth",
        message: "disk full".to_string(),
        source: Box::new(std::io::Error::other("disk full")),
    };
    let mapped: RimapError = err.into();
    assert_eq!(mapped.code(), ErrorCode::Internal);
    assert!(mapped.to_string().contains("ERR_INTERNAL"));
}
