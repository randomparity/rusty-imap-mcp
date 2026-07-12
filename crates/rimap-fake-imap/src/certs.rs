//! Self-signed leaf for the in-process fake. The client pins its
//! fingerprint, so the `PinningVerifier` (which ignores hostname/chain)
//! accepts it while a system-trust client would reject it.
#![expect(
    clippy::unwrap_used,
    clippy::missing_panics_doc,
    reason = "in-process test fake: unwrap/panic on cert-gen failure is a test-infra failure"
)]

use rimap_core::TlsFingerprint;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// A generated self-signed cert bundle plus the leaf-cert pin the client
/// must configure to accept it.
pub struct SelfSigned {
    /// Leaf cert chain for the rustls server config.
    pub chain: Vec<CertificateDer<'static>>,
    /// PKCS#8 private key for the leaf.
    pub key: PrivateKeyDer<'static>,
    /// SHA-256 fingerprint of the leaf DER — the client's `pinned_fingerprint`.
    pub pin: TlsFingerprint,
}

/// Generate a fresh self-signed cert/key for `127.0.0.1` and its pin.
#[must_use]
pub fn self_signed() -> SelfSigned {
    let generated = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
    let cert_der = generated.cert.der().clone();
    let pin = TlsFingerprint::from_cert_der(cert_der.as_ref());
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(
        generated.signing_key.serialize_der(),
    ));
    SelfSigned {
        chain: vec![cert_der],
        key,
        pin,
    }
}

#[cfg(test)]
mod tests {
    use super::self_signed;

    #[test]
    fn pin_matches_leaf_der_and_is_fresh_each_call() {
        let a = self_signed();
        assert_eq!(
            a.pin,
            rimap_core::TlsFingerprint::from_cert_der(a.chain[0].as_ref()),
        );
        let b = self_signed();
        assert_ne!(a.pin, b.pin);
    }
}
