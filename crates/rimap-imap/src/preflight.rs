//! Pre-auth `CAPABILITY` probe used by `--dry-run` and other diagnostic
//! paths. Performs TCP connect → TLS handshake → IMAP greeting → pre-auth
//! `CAPABILITY` command, then drops the connection. Captures the leaf-cert
//! SHA-256 fingerprint observed during the handshake (returned via
//! `PreflightInfo.tls_fingerprint`). Does NOT perform LOGIN and does NOT
//! emit any audit records.

use std::time::Instant;

use async_imap::Client as ImapPlainClient;
use async_imap::imap_proto::{Capability as ImapCapability, Response};
use async_imap::types::UnsolicitedResponse;
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::ConnectionConfig;
use crate::ImapEncryption;
use crate::connection::{starttls_upgrade, tls_handshake};
use crate::error::ImapError;
use crate::tls::build_tls_config;

/// Result of a successful preflight probe.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct PreflightInfo {
    /// Capability atoms returned by the server's pre-auth `CAPABILITY`
    /// response, upper-cased, de-duplicated, order preserved as received.
    pub capabilities: Vec<String>,
    /// Leaf-cert SHA-256 fingerprint observed during the TLS handshake.
    /// Captured from the verifier's `last_observed` slot. Always populated
    /// on a successful `probe_preflight` (the verifier runs before TLS
    /// completes); a `None` would indicate a programming bug, surfaced as
    /// `ImapError::TlsHandshake` rather than a panic.
    pub tls_fingerprint: rimap_core::TlsFingerprint,
}

#[cfg(any(test, feature = "test-support"))]
impl PreflightInfo {
    /// Construct a `PreflightInfo` for tests. Bypasses `#[non_exhaustive]`
    /// so test crates can synthesize fixtures without going through
    /// `probe_preflight`. Gated behind `test-support` to keep the constructor
    /// out of the production public API surface.
    #[must_use]
    pub fn new(capabilities: Vec<String>, tls_fingerprint: rimap_core::TlsFingerprint) -> Self {
        Self {
            capabilities,
            tls_fingerprint,
        }
    }
}

/// Run a TCP+TLS+greeting+CAPABILITY probe against `cfg`.
///
/// # Errors
/// Mirrors `ImapError` variants: `Connect`, `TlsHandshake`, `Timeout`,
/// `Protocol`. Never returns `Auth` variants — no credentials are used.
pub async fn probe_preflight(cfg: &ConnectionConfig) -> Result<PreflightInfo, ImapError> {
    // Pinned mode: enforce the configured fingerprint via PinningVerifier.
    // Unpinned mode: use the capture-only verifier so a self-signed cert
    // (e.g., Proton Bridge) does not abort the probe before we can surface
    // the fingerprint to the operator. Trust-on-first-use applies — same
    // posture as the openssl recipe in the quickstart.
    let bundle = match cfg.pinned_fingerprint {
        Some(_) => build_tls_config(cfg.pinned_fingerprint)?,
        None => crate::tls::build_tls_config_capture_only()?,
    };
    let total_deadline = cfg.connect_timeout;
    let started = Instant::now();

    // Map an elapsed per-step timeout to ImapError::Timeout { op }. Factors
    // the repeated timeout arm without wrapping the (large) step futures in
    // another async layer. Local to this fn because the error shape differs
    // from the handshake's `(error, None)` (#351).
    let timeout_err = |op: &'static str| move |_| ImapError::Timeout { op };

    let tcp = timeout(
        total_deadline,
        TcpStream::connect((cfg.host.as_str(), cfg.port)),
    )
    .await
    .map_err(timeout_err("tcp_connect"))?
    .map_err(ImapError::Connect)?;

    let remaining = total_deadline.saturating_sub(started.elapsed());
    // `already_greeted` mirrors the convention in `Connection::connect_with_bundle`:
    // STARTTLS consumes the plaintext greeting during negotiation, so the TLS
    // stream does not receive another greeting. Implicit TLS has not read the
    // greeting yet.
    let enrich =
        |e| crate::connection::enrich_tls_handshake_error(e, &bundle, cfg.pinned_fingerprint);
    let (tls_stream, already_greeted) = match cfg.encryption {
        ImapEncryption::Tls => {
            let s = timeout(remaining, tls_handshake(tcp, &bundle, &cfg.host))
                .await
                .map_err(timeout_err("tls_handshake"))?
                .map_err(enrich)?;
            (s, false)
        }
        ImapEncryption::Starttls => {
            let s = timeout(remaining, starttls_upgrade(tcp, &bundle, &cfg.host))
                .await
                .map_err(timeout_err("starttls_upgrade"))?
                .map_err(enrich)?;
            (s, true)
        }
    };

    let mut client = ImapPlainClient::new(tls_stream);
    // Greeting + CAPABILITY must also be bounded: a server that accepts
    // the socket and completes TLS but then stalls before sending the
    // greeting, or a server that stalls mid-CAPABILITY, would otherwise
    // hang `probe_preflight` forever. Reuse `command_timeout` for the
    // CAPABILITY leg (it is the per-command budget); apply the remaining
    // connect-budget to the greeting read.
    let greeting_budget = total_deadline.saturating_sub(started.elapsed());
    // cargo-mutants: only exercised by Dovecot integration (case_21 / starttls suite); no live IMAP server at unit level.
    if !already_greeted {
        timeout(greeting_budget, client.read_response())
            .await
            .map_err(timeout_err("imap_greeting"))?
            .map_err(ImapError::Connect)?
            .ok_or(ImapError::Connect(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "server closed before greeting",
            )))?;
    }

    let (tx, rx) = async_channel::bounded::<UnsolicitedResponse>(32);
    timeout(
        cfg.command_timeout,
        client.run_command_and_check_ok("CAPABILITY", Some(tx)),
    )
    .await
    .map_err(timeout_err("imap_capability"))?
    .map_err(ImapError::Protocol)?;

    // Extract capabilities using the same pattern as `capability_advertised`
    // in connection.rs. `ImapCapability::Atom` wraps `Cow<'_, str>`, so
    // `to_ascii_uppercase()` works directly. Atoms are upper-cased for stable
    // display and de-duplicated.
    let mut caps: Vec<String> = Vec::new();
    while let Ok(item) = rx.try_recv() {
        if let UnsolicitedResponse::Other(resp) = item
            && let Response::Capabilities(list) = resp.parsed()
        {
            for cap in list {
                if let ImapCapability::Atom(name) = cap {
                    let upper = name.to_ascii_uppercase();
                    // cargo-mutants: filter mutations only manifest with real CAPABILITY atoms; covered by case_21's `!info.capabilities.is_empty()` assertion.
                    if !upper.is_empty() && !caps.contains(&upper) {
                        caps.push(upper);
                    }
                }
            }
        }
    }

    let tls_fingerprint = bundle.last_observed.get().copied().ok_or_else(|| {
        ImapError::TlsHandshake(tokio_rustls::rustls::Error::General(
            "verifier did not capture fingerprint".into(),
        ))
    })?;
    Ok(PreflightInfo {
        capabilities: caps,
        tls_fingerprint,
    })
}
