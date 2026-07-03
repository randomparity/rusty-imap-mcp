//! Compose tools: build and send/save outgoing messages.
//!
//! `message_builder` is intentionally larger than its sibling modules: it
//! hosts the shared RFC 5322 construction primitives (header validation,
//! address parsing, threading header assembly, reference-list capping)
//! that both `send_email` and `create_draft` compose. The thin per-tool
//! handlers live in their own files and call into `message_builder`, so
//! the size asymmetry reflects the one-library / two-consumers shape, not
//! mixed concerns.

pub mod create_draft;
pub mod forward;
pub mod message_builder;
pub mod send_email;
