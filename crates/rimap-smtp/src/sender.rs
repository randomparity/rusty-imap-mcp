//! `SmtpSender` — the mockable seam over one-shot SMTP delivery.
//!
//! The trait mirrors the single call `send_email`/`forward` make on a
//! configured client (`send_raw`). It is a `dyn`-safe async trait: the
//! method returns a hand-rolled boxed future ([`SendRawFuture`]) rather
//! than using `async fn`-in-trait (not `dyn`-compatible) or the
//! `async-trait` crate (a dependency this crate does not carry).

use core::future::Future;
use core::pin::Pin;

use crate::client::{SendEnvelope, SmtpClient};
use crate::error::SmtpError;

/// Boxed, `Send` future returned by [`SmtpSender::send_raw`]. Borrows the
/// sender, envelope, and bytes for the duration of the send.
pub type SendRawFuture<'a> = Pin<Box<dyn Future<Output = Result<String, SmtpError>> + Send + 'a>>;

/// Seam over one-shot SMTP delivery. Implemented by the real
/// [`SmtpClient`] and by in-memory test fakes.
pub trait SmtpSender: Send + Sync {
    /// Send raw RFC 5322 bytes with an explicit envelope. Mirrors
    /// [`SmtpClient::send_raw`]; returns the SMTP status string on
    /// success.
    fn send_raw<'a>(&'a self, envelope: &'a SendEnvelope, raw: &'a [u8]) -> SendRawFuture<'a>;
}

impl SmtpSender for SmtpClient {
    fn send_raw<'a>(&'a self, envelope: &'a SendEnvelope, raw: &'a [u8]) -> SendRawFuture<'a> {
        // Inherent `SmtpClient::send_raw` is preferred by method
        // resolution over this trait method, so this delegates to the
        // real implementation without recursing. (If resolution ever
        // picked the trait method, the return-type mismatch would fail
        // to compile — it cannot silently recurse.)
        Box::pin(self.send_raw(envelope, raw))
    }
}

#[cfg(test)]
mod tests {
    use crate::SmtpClient;
    use crate::sender::SmtpSender;

    fn assert_impls_sender<T: SmtpSender>() {}

    #[test]
    fn smtp_client_implements_sender() {
        // Compile-time proof that SmtpClient: SmtpSender (+ Send + Sync,
        // via the supertrait bounds). This is the spike's assertion:
        // it only compiles once lettre's send future is Send.
        assert_impls_sender::<SmtpClient>();
    }
}
