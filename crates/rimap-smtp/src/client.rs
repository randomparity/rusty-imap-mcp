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
#[derive(Debug, Clone)]
pub struct SendEnvelope {
    /// Sender address (`MAIL FROM`).
    pub from: String,
    /// Recipient addresses (`RCPT TO`). All of To/Cc/Bcc collapsed.
    pub to: Vec<String>,
}

/// SMTP client built from config. Each `send_raw` call opens a fresh
/// connection — no persistent session or connection pool.
pub struct SmtpClient {
    transport: AsyncSmtpTransport<Tokio1Executor>,
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

        Ok(Self { transport })
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
        let response = self
            .transport
            .send_raw(&lettre_env, raw)
            .await
            .map_err(classify_smtp_error)?;
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

/// Coarse classification of an SMTP error derived from the public
/// predicates on `lettre::transport::smtp::Error`. Separated from the
/// error-to-variant mapping so the taxonomy can be unit-tested with
/// synthetic inputs — `lettre::transport::smtp::Error` has only
/// crate-private constructors, so variants cannot be fabricated directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SmtpErrorShape {
    /// Server replied with a 4xx/5xx response code.
    Response,
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
        // Order matters: timeout and TLS are checked before the broader
        // `is_client` so they map to their specific taxonomy entries
        // rather than collapsing into Connection/Transport.
        if err.is_response() {
            Self::Response
        } else if err.is_timeout() {
            Self::Timeout
        } else if err.is_tls() {
            Self::Tls
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
        SmtpErrorShape::Response => SmtpError::Rejected {
            reason: err.to_string(),
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
        SmtpErrorShape::Response => "Rejected",
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
        SmtpConfig {
            host: "localhost".into(),
            port: 1025,
            encryption: SmtpEncryption::None,
            username: "test@example.com".into(),
            command_timeout_seconds: 5,
        }
    }

    #[test]
    fn client_builds_with_no_encryption() {
        let client = SmtpClient::new(&test_config(), "password");
        assert!(client.is_ok());
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
    fn shape_response_maps_to_rejected_variant() {
        assert_eq!(shape_to_variant_name(SmtpErrorShape::Response), "Rejected");
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
