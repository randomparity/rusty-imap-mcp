//! Append-only JSONL audit log with exclusive file locking for rusty-imap-mcp.

#![deny(missing_docs)]

pub mod cancellation;
pub(crate) mod error;
pub(crate) mod fs;
pub mod reader;
pub mod record;
pub mod redact;
pub mod writer;

pub use cancellation::{
    CancelledToolEndReceiver, CancelledToolEndSender, cancellation_channel, spawn_drainer,
};

pub use crate::error::AuditError;
pub use crate::reader::{Filter, open_shared, parse_line, stream_records};
pub use crate::record::ids::{ProcessId, Seq, Timestamp};
pub use crate::record::{
    AccountSummary, AuditRecord, AuthEvent, AuthResult, ConfigEvent, Payload, ProcessEnd,
    ProcessEndReason, ProcessStart, Provenance, ResultSummary, ToolEnd, ToolStart, ToolStatus,
};
pub use crate::redact::{
    FieldPolicy, RedactionSalt, RedactionSchema, Redactor, ToolRedactionSchema, VerbatimType,
    hash_arguments, redact, schemas,
};
pub use crate::writer::self_check::{TrailingState, current_inode, read_trailing_state};
pub use crate::writer::{
    AuditOptions, AuditWriter, ProcessStartInputs, ToolEndInputs, ToolStartInputs,
};
