//! `PinningVerifier` and `TlsConfig` builder. Two modes: pinned (skip chain
//! validation) and system trust (`webpki-roots`).
//!
//! ## Capturing the observed fingerprint
//!
//! Both modes wrap their verifier so the fingerprint is recorded in a
//! `OnceLock` regardless of whether the handshake succeeds. After the
//! `tokio_rustls::TlsConnector::connect` call returns, `Connection` reads
//! the slot and uses it to populate the `Auth` audit record.
//!
//! ## Protocol version admission
//!
//! `build_tls_config` calls `with_safe_default_protocol_versions()`, which
//! admits both TLS 1.2 and TLS 1.3. This is deliberate: real-world IMAP
//! servers — Dovecot, Gmail, Proton Bridge, and most legacy deployments —
//! still require TLS 1.2 compatibility. Forcing TLS-1.3-only via
//! `with_protocol_versions(&[&rustls::version::TLS13])` would break the
//! Sprint 3 Dovecot integration suite and most production IMAP targets.
//! The modern rustls ring provider is safe with TLS 1.2 (no RC4, no CBC
//! without ETM, no weak ciphers). (MAIL-TLS-06)

use std::sync::{Arc, OnceLock};

use rimap_core::TlsFingerprint;
use tokio_rustls::rustls::DistinguishedName;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};

/// Pinned-mode verifier. Skips chain validation and accepts any cert whose
/// SHA-256 fingerprint matches the configured pin.
#[derive(Debug)]
pub(crate) struct PinningVerifier {
    pinned: TlsFingerprint,
    last_observed: Arc<OnceLock<TlsFingerprint>>,
    /// Default rustls crypto provider we delegate to for signature scheme
    /// verification (chain validation is skipped, but signature algorithm
    /// enforcement is not — rustls requires us to honor valid signatures
    /// even when we skip chain-of-trust).
    provider: Arc<tokio_rustls::rustls::crypto::CryptoProvider>,
}

/// Shared TLS 1.2 signature verification for the provider-delegating verifiers.
fn verify_tls12_signature_with_provider(
    provider: &tokio_rustls::rustls::crypto::CryptoProvider,
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
    tokio_rustls::rustls::crypto::verify_tls12_signature(
        message,
        cert,
        dss,
        &provider.signature_verification_algorithms,
    )
}

/// Shared TLS 1.3 signature verification for the provider-delegating verifiers.
fn verify_tls13_signature_with_provider(
    provider: &tokio_rustls::rustls::crypto::CryptoProvider,
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
    tokio_rustls::rustls::crypto::verify_tls13_signature(
        message,
        cert,
        dss,
        &provider.signature_verification_algorithms,
    )
}

impl ServerCertVerifier for PinningVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
        let observed = TlsFingerprint::from_cert_der(end_entity.as_ref());
        let _ = self.last_observed.set(observed);
        if self.pinned == observed {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(tokio_rustls::rustls::Error::General(format!(
                "tls fingerprint mismatch: observed={observed}, expected={pinned}",
                pinned = self.pinned,
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        verify_tls12_signature_with_provider(&self.provider, message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        verify_tls13_signature_with_provider(&self.provider, message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Wraps the system-trust verifier so we still capture the observed
/// fingerprint into the same `OnceLock` slot used by pinned mode.
#[derive(Debug)]
pub(crate) struct CapturingVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    last_observed: Arc<OnceLock<TlsFingerprint>>,
}

impl ServerCertVerifier for CapturingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
        let observed = TlsFingerprint::from_cert_der(end_entity.as_ref());
        let _ = self.last_observed.set(observed);
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }

    fn root_hint_subjects(&self) -> Option<&[DistinguishedName]> {
        self.inner.root_hint_subjects()
    }
}

/// A `ClientConfig` plus the slot the verifier writes the observed
/// fingerprint into. Construct via [`build_tls_config`]; pass the
/// `last_observed` handle to `Connection` so it can read the value after
/// the handshake.
#[non_exhaustive]
pub struct TlsConfigBundle {
    /// The `rustls::ClientConfig` ready to hand to `tokio_rustls::TlsConnector`.
    pub config: Arc<ClientConfig>,
    /// Slot the verifier sets exactly once during `verify_server_cert`.
    /// Empty if the handshake failed before the verifier ran.
    pub last_observed: Arc<OnceLock<TlsFingerprint>>,
}

/// Diagnostic-only verifier: captures the leaf-cert fingerprint and ALWAYS
/// accepts the cert. Used by `probe_preflight` in unpinned mode so an
/// operator can observe what the server presents during onboarding even
/// against a self-signed cert that the system trust store would reject.
///
/// **Never use this verifier on the auth path.** It accepts any cert,
/// including a network attacker's. The trust commitment for `--dry-run`
/// is identical to running `openssl s_client` over the same network: the
/// operator must trust the network at fingerprint-extraction time.
#[derive(Debug)]
pub(crate) struct CaptureOnlyVerifier {
    last_observed: Arc<OnceLock<TlsFingerprint>>,
    provider: Arc<tokio_rustls::rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for CaptureOnlyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
        let observed = TlsFingerprint::from_cert_der(end_entity.as_ref());
        let _ = self.last_observed.set(observed);
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        verify_tls12_signature_with_provider(&self.provider, message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        verify_tls13_signature_with_provider(&self.provider, message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Build a `TlsConfigBundle`. If `pinned.is_some()`, uses `PinningVerifier`
/// (skips chain validation). Otherwise uses webpki-roots with
/// `CapturingVerifier`.
///
/// # Errors
/// - `ImapError::TlsHandshake` if rustls cannot construct a `ClientConfig` with
///   the workspace's safe default protocol versions (would only fire if a
///   future ring provider drops every cipher suite or kx group).
/// - `ImapError::TlsHandshake` if `WebPkiServerVerifier::builder.build()` fails
///   (would only fire if `webpki_roots::TLS_SERVER_ROOTS` is somehow empty,
///   e.g. a corrupt webpki-roots release).
pub fn build_tls_config(
    pinned: Option<TlsFingerprint>,
) -> Result<TlsConfigBundle, crate::error::ImapError> {
    let last_observed = Arc::new(OnceLock::new());
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());

    let config = if let Some(pin) = pinned {
        let verifier = Arc::new(PinningVerifier {
            pinned: pin,
            last_observed: Arc::clone(&last_observed),
            provider: Arc::clone(&provider),
        });
        ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(crate::error::ImapError::TlsHandshake)?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth()
    } else {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let inner_verifier =
            tokio_rustls::rustls::client::WebPkiServerVerifier::builder_with_provider(
                Arc::new(roots),
                Arc::clone(&provider),
            )
            .build()
            // VerifierBuilderError has variants including `NoRootAnchors`
            // (unreachable because we extended from webpki_roots which
            // ships ~150 trust anchors) and `InvalidCrl(...)` (unreachable
            // because webpki-roots 1.0 ships only static trust anchors,
            // no CRLs — so `InvalidCrl` cannot fire from this builder).
            // Both failure paths are therefore extremely unlikely; we
            // still propagate them as TlsHandshake errors rather than
            // panicking. (MAIL-TLS-03)
            .map_err(|e| {
                crate::error::ImapError::TlsHandshake(tokio_rustls::rustls::Error::General(
                    format!("WebPkiServerVerifier builder failed: {e}"),
                ))
            })?;
        let capturing = Arc::new(CapturingVerifier {
            inner: inner_verifier,
            last_observed: Arc::clone(&last_observed),
        });
        ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(crate::error::ImapError::TlsHandshake)?
            .dangerous()
            .with_custom_certificate_verifier(capturing)
            .with_no_client_auth()
    };

    Ok(TlsConfigBundle {
        config: Arc::new(config),
        last_observed,
    })
}

/// Build a `TlsConfigBundle` whose verifier captures the leaf-cert
/// fingerprint and accepts any cert (no chain validation). Diagnostic-only
/// — `probe_preflight` uses this in unpinned mode so operators can see
/// what the server presents during onboarding, including for self-signed
/// certs that webpki-roots would reject.
///
/// **Trust on first use.** A network attacker's cert will be captured
/// and reported as if it were the server's. Document this in any
/// caller-facing UX.
///
/// # Errors
/// Same conditions as `build_tls_config`: would only fire if rustls
/// cannot construct a `ClientConfig` with the workspace's safe default
/// protocol versions.
pub fn build_tls_config_capture_only() -> Result<TlsConfigBundle, crate::error::ImapError> {
    let last_observed = Arc::new(OnceLock::new());
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());

    let verifier = Arc::new(CaptureOnlyVerifier {
        last_observed: Arc::clone(&last_observed),
        provider: Arc::clone(&provider),
    });
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(crate::error::ImapError::TlsHandshake)?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    Ok(TlsConfigBundle {
        config: Arc::new(config),
        last_observed,
    })
}
