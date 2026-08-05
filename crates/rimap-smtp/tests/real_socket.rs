//! Real-socket SMTP taxonomy: drive `SmtpClient` against a scripted
//! responder and assert each `SmtpError` variant and its `RimapError` code.
//!
//! The timeout case is covered at the lib level (a bare `TcpListener` that
//! withholds the banner); this binary covers the three dialog scenarios.
//!
//! No container runtime — runs on every PR.
#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests"
)]

mod support;

use rimap_config::model::{SmtpConfig, SmtpEncryption};
use rimap_smtp::{SendEnvelope, SmtpClient, SmtpError};
use support::smtp_responder::{Responder, Scenario};

fn config(port: u16, encryption: SmtpEncryption) -> SmtpConfig {
    let mut cfg = SmtpConfig::new(
        "127.0.0.1".into(),
        port,
        encryption,
        "user@example.com".into(),
    );
    cfg.command_timeout_seconds = 5;
    cfg
}

fn envelope() -> SendEnvelope {
    SendEnvelope {
        from: "a@example.com".into(),
        to: vec!["b@example.com".into()],
    }
}

async fn send(port: u16, enc: SmtpEncryption) -> SmtpError {
    let client = SmtpClient::new(&config(port, enc), "pw").unwrap();
    client
        .send_raw(
            &envelope(),
            b"From: a\r\nTo: b\r\nSubject: t\r\n\r\nbody\r\n",
        )
        .await
        .expect_err("scenario must fail")
}

#[tokio::test]
async fn auth_rejection_maps_to_auth() {
    let responder = Responder::spawn(Scenario::AuthReject).await;
    let err = send(responder.port, SmtpEncryption::None).await;
    let SmtpError::Auth { .. } = err else {
        panic!("expected Auth, got {err:?}");
    };
    let mapped: rimap_core::RimapError = err.into();
    assert_eq!(mapped.code(), rimap_core::ErrorCode::Auth);
}

#[tokio::test]
async fn rcpt_rejection_maps_to_rejected() {
    let responder = Responder::spawn(Scenario::RcptReject).await;
    let err = send(responder.port, SmtpEncryption::None).await;
    let SmtpError::Rejected { .. } = err else {
        panic!("expected Rejected, got {err:?}");
    };
    let mapped: rimap_core::RimapError = err.into();
    assert_eq!(mapped.code(), rimap_core::ErrorCode::SmtpProtocol);
}

#[tokio::test]
async fn starttls_bad_cert_maps_to_tls() {
    let responder = Responder::spawn(Scenario::StarttlsBadCert).await;
    let err = send(responder.port, SmtpEncryption::Starttls).await;
    let SmtpError::Tls(_) = err else {
        panic!("expected Tls, got {err:?}");
    };
    let mapped: rimap_core::RimapError = err.into();
    assert_eq!(mapped.code(), rimap_core::ErrorCode::Tls);
}
