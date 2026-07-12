//! Live TLS pin-mismatch rejection against the in-process rustls fake.
//!
//! The pin-mismatch path is the MITM defense. Before this test the only
//! live-handshake coverage was the Docker-gated Dovecot suite
//! (`tests/integration/dovecot.rs::case_02`), which silently skips on
//! standard CI — so the defense had never run on a real handshake in the
//! default PR gate. `rimap-fake-imap` serves a real self-signed leaf over
//! rustls and exposes its true fingerprint via `.pin()`, so a mismatch is
//! now a container-free, every-PR test: start the fake, pin a *different*
//! fingerprint, connect, and assert the handshake is rejected before any
//! IMAP command is exchanged.
//!
//! Fake, no container runtime — runs on every PR.

#![expect(clippy::expect_used, clippy::panic, reason = "tests")]

use rimap_core::TlsFingerprint;
use rimap_fake_imap::fake_imap::{FakeImapServer, Step, login_preamble};
use rimap_imap::error::ImapError;

/// A fingerprint that cannot match any freshly generated leaf. Mirrors the
/// Dovecot suite's wrong-pin sentinel so the two live-handshake tests read
/// the same way.
fn wrong_pin() -> TlsFingerprint {
    TlsFingerprint::from_cert_der(b"deliberately-wrong")
}

#[tokio::test]
async fn wrong_pin_rejected_at_handshake_before_any_imap_command() {
    // Full login script: if the client ever got past the handshake it would
    // drive this dialog and `recorded()` would be non-empty. It never does.
    let mut steps = login_preamble("IMAP4rev1");
    steps.extend([
        Step::Expect { verb: "LIST" },
        Step::Send(b"* LIST (\\HasNoChildren) \"/\" \"INBOX\"\r\n".to_vec()),
        Step::Reply {
            text: "OK LIST completed",
        },
    ]);
    let server = FakeImapServer::start(steps).await;

    let wrong = wrong_pin();
    assert_ne!(
        wrong,
        server.pin(),
        "wrong pin sentinel must differ from the fake's real leaf fingerprint",
    );

    let conn = server.connection_wrong_pin("user@example.com", wrong);
    let err = conn
        .list_folders("*")
        .await
        .expect_err("mismatched pin must reject the connection");

    // The handshake failure must be enriched to the typed `Tls` variant
    // carrying both fingerprints. In-process the `PinningVerifier` always
    // records the observed leaf before returning the mismatch, so the
    // enrichment is deterministic — assert it strictly (the Dovecot suite
    // tolerates a `TlsHandshake` fallback only for container-timing reasons).
    match err {
        ImapError::Tls { observed, expected } => {
            assert_eq!(
                observed,
                server.pin(),
                "observed fingerprint must be the fake's real leaf",
            );
            assert_eq!(
                expected, wrong,
                "expected fingerprint must be the configured (wrong) pin",
            );
        }
        other => panic!("expected ImapError::Tls {{ observed, expected }}, got {other:?}"),
    }

    // No application data crossed the wire: the connection failed at the TLS
    // handshake, before the greeting read or LOGIN. The fake records a line
    // only when it reads a client command, so `recorded()` must be empty.
    assert!(
        server.recorded().is_empty(),
        "no IMAP command must be sent on a pin mismatch; recorded: {:?}",
        server.recorded(),
    );
}
