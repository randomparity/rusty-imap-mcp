//! Self-signed cert for the STARTTLS-failure scenario. rustls' default
//! roots reject it — which is exactly the handshake failure under test.
#![expect(clippy::unwrap_used, reason = "tests")]

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// Generate a fresh self-signed cert/key for `127.0.0.1`. The key is the
/// PKCS#8 DER `rcgen` produces; the cert never chains to a trusted root, so
/// the connecting SMTP client fails verification during the TLS handshake.
pub fn self_signed() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let generated = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
    let cert_der = generated.cert.der().clone();
    let key_der = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(
        generated.signing_key.serialize_der(),
    ));
    (vec![cert_der], key_der)
}
