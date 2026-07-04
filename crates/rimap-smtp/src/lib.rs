//! SMTP client for rusty-imap-mcp.
//!
//! Thin wrapper around `lettre` providing connection management,
//! TLS via `rustls`, and error mapping. Does not construct messages —
//! message building is handled by the server layer.

#![deny(missing_docs)]

pub mod client;
pub mod error;
pub mod sender;

pub use crate::client::{SendEnvelope, SmtpClient};
pub use crate::error::SmtpError;
pub use crate::sender::{SendRawFuture, SmtpSender};
