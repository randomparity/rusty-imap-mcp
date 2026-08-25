//! In-memory [`SmtpSender`] fake for driving the SMTP seam under test.
//!
//! Gated behind the `test-support` feature. [`FakeSmtpSender`] is a
//! cloneable spy: every clone shares one capture log, so a test can
//! inject one clone into an `AccountState` and keep another to inspect
//! what was submitted.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::client::SendEnvelope;
use crate::error::SmtpError;
use crate::sender::{SendRawFuture, SmtpSender};

/// One captured send: the envelope and raw RFC 5322 bytes submitted.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct CapturedSend {
    /// The envelope (`MAIL FROM` / `RCPT TO`) passed to `send_raw`.
    pub envelope: SendEnvelope,
    /// The raw RFC 5322 message bytes passed to `send_raw`.
    pub raw: Vec<u8>,
}

/// The outcome a [`FakeSmtpSender`] returns from every `send_raw` call.
#[derive(Debug, Clone)]
enum Outcome {
    /// Succeed, returning this SMTP status string.
    Ok(String),
    /// Fail with `SmtpError::Rejected { reason }`.
    Rejected(String),
}

/// In-memory SMTP sender that records each submission and returns a
/// preconfigured outcome. Clones share the capture log.
#[derive(Debug, Clone)]
pub struct FakeSmtpSender {
    calls: Arc<Mutex<Vec<CapturedSend>>>,
    outcome: Outcome,
}

impl FakeSmtpSender {
    /// A fake that succeeds, returning `"250 2.0.0 OK"`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            calls: Arc::new(Mutex::new(Vec::new())),
            outcome: Outcome::Ok("250 2.0.0 OK".to_string()),
        }
    }

    /// A fake that rejects every send with `SmtpError::Rejected`.
    #[must_use]
    pub fn rejecting(reason: impl Into<String>) -> Self {
        Self {
            calls: Arc::new(Mutex::new(Vec::new())),
            outcome: Outcome::Rejected(reason.into()),
        }
    }

    /// Snapshot of every captured send, in submission order.
    #[must_use]
    pub fn calls(&self) -> Vec<CapturedSend> {
        self.locked().clone()
    }

    /// Number of `send_raw` calls captured so far.
    #[must_use]
    pub fn call_count(&self) -> usize {
        self.locked().len()
    }

    fn locked(&self) -> MutexGuard<'_, Vec<CapturedSend>> {
        self.calls.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Default for FakeSmtpSender {
    fn default() -> Self {
        Self::new()
    }
}

impl SmtpSender for FakeSmtpSender {
    fn send_raw<'a>(&'a self, envelope: &'a SendEnvelope, raw: &'a [u8]) -> SendRawFuture<'a> {
        // Record eagerly (owned copies — the borrows do not outlive the
        // call) and drop the guard before building the future, so no lock
        // is held across an await.
        self.locked().push(CapturedSend {
            envelope: envelope.clone(),
            raw: raw.to_vec(),
        });
        let outcome = self.outcome.clone();
        Box::pin(async move {
            match outcome {
                Outcome::Ok(response) => Ok(response),
                Outcome::Rejected(reason) => Err(SmtpError::Rejected { reason }),
            }
        })
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::{FakeSmtpSender, SendEnvelope, SmtpSender};

    #[tokio::test]
    async fn captures_bytes_and_envelope_and_returns_ok() {
        let fake = FakeSmtpSender::new();
        let env = SendEnvelope {
            from: "a@x.test".into(),
            to: vec!["b@y.test".into()],
        };
        let sender: &dyn SmtpSender = &fake;
        let response = sender.send_raw(&env, b"From: a\r\n\r\nhi").await.unwrap();
        assert_eq!(response, "250 2.0.0 OK");

        let calls = fake.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].envelope.to, vec!["b@y.test".to_string()]);
        assert_eq!(calls[0].raw, b"From: a\r\n\r\nhi");
    }

    #[tokio::test]
    async fn rejecting_fake_errors_and_maps_to_smtp_protocol() {
        let fake = FakeSmtpSender::rejecting("550 blocked");
        let env = SendEnvelope {
            from: "a@x.test".into(),
            to: vec!["b@y.test".into()],
        };
        let err = fake.send_raw(&env, b"x").await.unwrap_err();
        let mapped: rimap_core::RimapError = err.into();
        assert_eq!(mapped.code(), rimap_core::ErrorCode::SmtpProtocol);
        assert_eq!(fake.call_count(), 1);
    }

    #[tokio::test]
    async fn clones_share_the_capture_log() {
        let fake = FakeSmtpSender::new();
        let spy = fake.clone();
        let env = SendEnvelope {
            from: "a@x.test".into(),
            to: vec!["b@y.test".into()],
        };
        fake.send_raw(&env, b"one").await.unwrap();
        // The clone observes the send the original recorded.
        assert_eq!(spy.call_count(), 1);
        assert_eq!(spy.calls()[0].raw, b"one");
    }
}
