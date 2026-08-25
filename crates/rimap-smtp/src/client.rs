//! `SmtpClient` — one-shot SMTP send via `lettre`.

use std::time::Duration;

use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Tokio1Executor};
use rimap_config::model::{SmtpConfig, SmtpEncryption};

use crate::error::SmtpError;

/// Addressing envelope for [`SmtpClient::send_raw`], expressed with
/// plain string addresses so callers do not need to depend on
/// `lettre`'s address types. Addresses are parsed here at the crate
/// boundary and surface as `SmtpError::Rejected` on malformed input.
///
/// ```compile_fail,E0639
/// let _ = rimap_smtp::SendEnvelope {
///     from: "sender@example.test".to_owned(),
///     to: vec!["recipient@example.test".to_owned()],
/// };
/// ```
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct SendEnvelope {
    /// Sender address (`MAIL FROM`).
    pub from: String,
    /// Recipient addresses (`RCPT TO`). All of To/Cc/Bcc collapsed.
    pub to: Vec<String>,
}

impl SendEnvelope {
    /// Construct an SMTP envelope.
    ///
    /// # Arguments
    ///
    /// * `from` - Envelope sender address.
    /// * `to` - Envelope recipient addresses.
    #[must_use]
    pub fn new(from: String, to: Vec<String>) -> Self {
        Self { from, to }
    }
}

/// SMTP client built from config. Each `send_raw` call opens a fresh
/// connection — no persistent session or connection pool.
pub struct SmtpClient {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    deadline: Duration,
}

impl SmtpClient {
    /// Build from validated SMTP config and a resolved password.
    ///
    /// # Errors
    ///
    /// Returns `SmtpError::Connection` if the transport cannot be built.
    pub fn new(config: &SmtpConfig, password: &str) -> Result<Self, SmtpError> {
        let creds = Credentials::new(config.username.clone(), password.to_string());
        let timeout = Duration::from_secs(u64::from(config.command_timeout_seconds));

        let builder = match config.encryption {
            SmtpEncryption::Tls => AsyncSmtpTransport::<Tokio1Executor>::relay(&config.host)
                .map_err(SmtpError::Connection)?
                .port(config.port),
            SmtpEncryption::Starttls => {
                AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.host)
                    .map_err(SmtpError::Connection)?
                    .port(config.port)
            }
            SmtpEncryption::None => {
                AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&config.host)
                    .port(config.port)
            }
        };

        let transport = builder.credentials(creds).timeout(Some(timeout)).build();

        Ok(Self {
            transport,
            deadline: timeout,
        })
    }

    /// Send raw RFC 5322 bytes with an explicit envelope.
    ///
    /// Use this when the message is already serialized (e.g. from
    /// `mail-builder`) and constructing a `lettre::Message` is not
    /// practical.
    ///
    /// # Errors
    ///
    /// Returns `SmtpError` variants for TLS, rejection, timeout, or
    /// transport failures.
    pub async fn send_raw(&self, envelope: &SendEnvelope, raw: &[u8]) -> Result<String, SmtpError> {
        let lettre_env = build_lettre_envelope(envelope)?;
        // lettre applies its timeout only to the TCP connect; bound the
        // whole dialog (banner, EHLO, AUTH, MAIL/RCPT/DATA) so a stalled or
        // hostile server cannot hang the send indefinitely. A timed-out send
        // is indeterminate — the server may already have accepted the
        // message — so callers must not blind-retry (see ADR-0001).
        let send = self.transport.send_raw(&lettre_env, raw);
        let response = match tokio::time::timeout(self.deadline, send).await {
            Ok(Ok(response)) => response,
            Ok(Err(e)) => return Err(classify_smtp_error(e)),
            Err(_elapsed) => return Err(SmtpError::Timeout),
        };
        Ok(format_response(&response))
    }
}

/// Parse the string-keyed [`SendEnvelope`] into a `lettre` envelope.
/// Malformed addresses or the empty-recipient case surface as
/// `SmtpError::Rejected` so the error taxonomy stays inside the crate.
fn build_lettre_envelope(env: &SendEnvelope) -> Result<lettre::address::Envelope, SmtpError> {
    let from = env
        .from
        .parse::<lettre::Address>()
        .map_err(|e| SmtpError::Rejected {
            reason: format!("invalid From address: {e}"),
        })?;
    let mut to = Vec::with_capacity(env.to.len());
    for addr in &env.to {
        let parsed = addr
            .parse::<lettre::Address>()
            .map_err(|e| SmtpError::Rejected {
                reason: format!("invalid recipient address: {e}"),
            })?;
        to.push(parsed);
    }
    lettre::address::Envelope::new(Some(from), to).map_err(|e| SmtpError::Rejected {
        reason: format!("envelope: {e}"),
    })
}

/// Format a lettre SMTP response as a human-readable string.
fn format_response(response: &lettre::transport::smtp::response::Response) -> String {
    format!(
        "{} {}",
        response.code(),
        response.message().collect::<Vec<_>>().join(" ")
    )
}

/// Whether a server negative-reply code is a recognized authentication
/// failure: the unambiguous credential-failure codes only — permanent `534`
/// (mechanism too weak), `535` (credentials invalid), `538` (encryption
/// required for the mechanism); transient `432` (password transition needed).
/// `530` ("must issue STARTTLS first" / "authentication required" /
/// relay-denied) and `454` ("TLS not available" / temporary auth failure) are
/// deliberately excluded: they carry transport-security meanings, so
/// classifying them as `Auth` would mis-signal a STARTTLS/TLS condition as a
/// credentials problem. They fall through to `Rejected` (`ERR_SMTP_PROTOCOL`).
fn code_is_auth(code: u16) -> bool {
    const AUTH_CODES: [u16; 4] = [534, 535, 538, 432];
    AUTH_CODES.contains(&code)
}

/// Sanitize server-supplied reply text before it enters an error message that
/// reaches the agent context and the logs. A hostile or MITM relay controls
/// this text: strip control characters (defeats CRLF log injection and keeps
/// smuggled prompt-injection control sequences out of the model's context),
/// collapse whitespace, and cap the length so a pathological reply cannot
/// flood either sink.
fn sanitize_reason(raw: &str) -> String {
    const MAX_LEN: usize = 200;
    let cleaned: String = raw
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let collapsed = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.chars().count() <= MAX_LEN {
        return collapsed;
    }
    let capped: String = collapsed.chars().take(MAX_LEN).collect();
    format!("{capped}…")
}

/// Whether a lettre SMTP error is a TLS failure.
///
/// `lettre::transport::smtp::Error::is_tls` only matches `Kind::Tls`, but
/// lettre's async rustls transport wraps every handshake failure — including
/// certificate rejection — as `Kind::Connection` (`async_net.rs`
/// `error::connection`). So `is_tls()` is effectively dead for this transport.
/// Walk the source chain and detect a `rustls::Error` (type-safe, no string
/// matching) so a cert/TLS failure classifies as `SmtpError::Tls` (`ERR_TLS`)
/// rather than collapsing into `Transport`/`ERR_INTERNAL`.
fn is_tls_error(err: &lettre::transport::smtp::Error) -> bool {
    if err.is_tls() {
        return true;
    }
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(current) = source {
        if let Some(io) = current.downcast_ref::<std::io::Error>()
            && io
                .get_ref()
                .is_some_and(|inner| inner.downcast_ref::<rustls::Error>().is_some())
        {
            return true;
        }
        source = current.source();
    }
    false
}

/// Coarse classification of an SMTP error derived from the public
/// predicates on `lettre::transport::smtp::Error`. Separated from the
/// error-to-variant mapping so the taxonomy can be unit-tested with
/// synthetic inputs — `lettre::transport::smtp::Error` has only
/// crate-private constructors, so variants cannot be fabricated directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SmtpErrorShape {
    /// Server sent a negative reply that is not an auth failure.
    Rejected,
    /// Server sent an authentication-failure reply code.
    Auth,
    /// The operation exceeded the configured timeout.
    Timeout,
    /// TLS handshake / certificate failure.
    Tls,
    /// Client-side / protocol-setup failure.
    Client,
    /// Anything else (network, connection, shutdown).
    Other,
}

impl SmtpErrorShape {
    fn of(err: &lettre::transport::smtp::Error) -> Self {
        // Timeout and TLS take precedence over the broader predicates. A
        // well-formed negative reply carries a status code (`Transient`/
        // `Permanent`), which `is_response` does NOT match — that predicate
        // is only true for a response-*parse* error. Splitting the status
        // code into Auth vs Rejected is what fixes the historical bug where
        // every 4xx/5xx reply collapsed into Transport/Internal.
        if err.is_timeout() {
            Self::Timeout
        } else if is_tls_error(err) {
            Self::Tls
        } else if let Some(code) = err.status() {
            if code_is_auth(u16::from(code)) {
                Self::Auth
            } else {
                Self::Rejected
            }
        } else if err.is_response() {
            Self::Rejected
        } else if err.is_client() {
            Self::Client
        } else {
            Self::Other
        }
    }
}

/// Classify a lettre SMTP error into our error taxonomy.
fn classify_smtp_error(err: lettre::transport::smtp::Error) -> SmtpError {
    match SmtpErrorShape::of(&err) {
        SmtpErrorShape::Rejected => SmtpError::Rejected {
            reason: sanitize_reason(&err.to_string()),
        },
        SmtpErrorShape::Auth => SmtpError::Auth {
            reason: sanitize_reason(&err.to_string()),
        },
        SmtpErrorShape::Timeout => SmtpError::Timeout,
        SmtpErrorShape::Tls => SmtpError::Tls(err),
        SmtpErrorShape::Client => SmtpError::Connection(err),
        SmtpErrorShape::Other => SmtpError::Transport(err),
    }
}

/// Which `SmtpError` variant a given shape maps to. Pure, testable mirror
/// of the match arms in [`classify_smtp_error`] — keeps the taxonomy
/// intention under test without depending on lettre's private error
/// constructors.
#[cfg(test)]
fn shape_to_variant_name(shape: SmtpErrorShape) -> &'static str {
    match shape {
        SmtpErrorShape::Rejected => "Rejected",
        SmtpErrorShape::Auth => "Auth",
        SmtpErrorShape::Timeout => "Timeout",
        SmtpErrorShape::Tls => "Tls",
        SmtpErrorShape::Client => "Connection",
        SmtpErrorShape::Other => "Transport",
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, clippy::panic, reason = "tests")]
mod tests {
    use rimap_config::model::{SmtpConfig, SmtpEncryption};

    use super::{
        SendEnvelope, SmtpClient, SmtpError, SmtpErrorShape, build_lettre_envelope,
        shape_to_variant_name,
    };

    fn test_config() -> SmtpConfig {
        let mut cfg = SmtpConfig::new(
            "localhost".into(),
            1025,
            SmtpEncryption::None,
            "test@example.com".into(),
        );
        cfg.command_timeout_seconds = 5;
        cfg
    }

    #[test]
    fn client_builds_with_no_encryption() {
        let client = SmtpClient::new(&test_config(), "password");
        assert!(client.is_ok());
    }

    #[test]
    fn send_envelope_new_preserves_fields() {
        let from = "sender@example.test".to_owned();
        let to = vec!["recipient@example.test".to_owned()];

        let envelope = SendEnvelope::new(from.clone(), to.clone());

        assert_eq!(envelope.from, from);
        assert_eq!(envelope.to, to);
    }

    #[tokio::test]
    async fn send_raw_times_out_when_server_withholds_banner() {
        // A listener that accepts the connection but never sends the 220
        // greeting. lettre's connect succeeds; the banner read would hang,
        // so the send_raw operation deadline must fire.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let _keep = listener.accept();
            std::thread::sleep(std::time::Duration::from_secs(5));
        });

        let mut cfg = SmtpConfig::new(
            "127.0.0.1".into(),
            port,
            SmtpEncryption::None,
            "user@example.com".into(),
        );
        cfg.command_timeout_seconds = 1;
        let client = SmtpClient::new(&cfg, "pw").unwrap();
        let env = SendEnvelope {
            from: "a@example.com".into(),
            to: vec!["b@example.com".into()],
        };

        let err = client
            .send_raw(&env, b"From: a\r\n\r\nhi")
            .await
            .unwrap_err();
        let SmtpError::Timeout = err else {
            panic!("expected Timeout, got {err:?}");
        };
    }

    #[test]
    fn envelope_rejects_malformed_from_address() {
        let env = SendEnvelope {
            from: "not-an-email".into(),
            to: vec!["to@example.com".into()],
        };
        let err = build_lettre_envelope(&env).unwrap_err();
        let SmtpError::Rejected { reason } = err else {
            panic!("expected Rejected, got {err:?}");
        };
        assert!(
            reason.contains("invalid From address"),
            "reason should identify the From field: {reason}"
        );
    }

    #[test]
    fn envelope_rejects_empty_recipient_list() {
        let env = SendEnvelope {
            from: "sender@example.com".into(),
            to: vec![],
        };
        let err = build_lettre_envelope(&env).unwrap_err();
        let SmtpError::Rejected { reason } = err else {
            panic!("expected Rejected, got {err:?}");
        };
        // lettre's Envelope::new surfaces the empty-recipient case via its
        // own error — we surface it under the `envelope:` prefix.
        assert!(
            reason.contains("envelope"),
            "reason should mention the envelope error: {reason}"
        );
    }

    #[test]
    fn envelope_rejects_malformed_to_address() {
        let env = SendEnvelope {
            from: "sender@example.com".into(),
            to: vec!["also-not-an-email".into()],
        };
        let err = build_lettre_envelope(&env).unwrap_err();
        let SmtpError::Rejected { reason } = err else {
            panic!("expected Rejected, got {err:?}");
        };
        assert!(
            reason.contains("invalid recipient address"),
            "reason should identify the recipient field: {reason}"
        );
    }

    #[test]
    fn envelope_accepts_valid_from_and_to() {
        let env = SendEnvelope {
            from: "sender@example.com".into(),
            to: vec!["to@example.com".into(), "cc@example.com".into()],
        };
        let lettre_env = build_lettre_envelope(&env).unwrap();
        assert_eq!(lettre_env.to().len(), 2);
        assert!(lettre_env.from().is_some());
    }

    #[test]
    fn shape_rejected_maps_to_rejected_variant() {
        assert_eq!(shape_to_variant_name(SmtpErrorShape::Rejected), "Rejected");
    }

    #[test]
    fn shape_auth_maps_to_auth_variant() {
        assert_eq!(shape_to_variant_name(SmtpErrorShape::Auth), "Auth");
    }

    #[test]
    fn code_535_is_auth() {
        assert!(super::code_is_auth(535));
    }

    #[test]
    fn code_454_is_not_auth() {
        // 454 ("TLS not available" / temporary auth) is transport-ambiguous and
        // deliberately not an auth code.
        assert!(!super::code_is_auth(454));
    }

    #[test]
    fn code_530_is_not_auth() {
        // 530 ("must issue STARTTLS first" / relay-denied) is not a credential
        // failure.
        assert!(!super::code_is_auth(530));
    }

    #[test]
    fn code_550_is_not_auth() {
        assert!(!super::code_is_auth(550));
    }

    #[test]
    fn sanitize_reason_strips_control_chars_and_caps_length() {
        // CRLF and other control chars are collapsed to spaces (log/prompt
        // injection defense).
        let dirty = "535 bad\r\ncreds\u{7}now";
        let clean = super::sanitize_reason(dirty);
        assert!(!clean.contains('\r') && !clean.contains('\n'));
        assert!(!clean.chars().any(char::is_control));
        assert_eq!(clean, "535 bad creds now");

        // Length is capped with an ellipsis marker.
        let long = "x".repeat(500);
        let capped = super::sanitize_reason(&long);
        assert!(capped.chars().count() <= 201, "capped: {}", capped.len());
        assert!(capped.ends_with('…'));
    }

    #[test]
    fn code_450_is_not_auth() {
        assert!(!super::code_is_auth(450));
    }

    #[test]
    fn shape_client_maps_to_connection_variant() {
        assert_eq!(shape_to_variant_name(SmtpErrorShape::Client), "Connection");
    }

    #[test]
    fn shape_other_maps_to_transport_variant() {
        assert_eq!(shape_to_variant_name(SmtpErrorShape::Other), "Transport");
    }

    #[test]
    fn shape_timeout_maps_to_timeout_variant() {
        assert_eq!(shape_to_variant_name(SmtpErrorShape::Timeout), "Timeout");
    }

    #[test]
    fn shape_tls_maps_to_tls_variant() {
        assert_eq!(shape_to_variant_name(SmtpErrorShape::Tls), "Tls");
    }
}
