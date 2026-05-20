//! Append-only JSONL audit log with exclusive file locking for rusty-imap-mcp.

#![deny(missing_docs)]

pub mod cancellation;
pub(crate) mod fs;
pub mod reader;
pub mod record;
pub mod redact;
pub mod writer;

pub use cancellation::{
    CancelledToolEndReceiver, CancelledToolEndSender, cancellation_channel, spawn_drainer,
};

/// Re-export of [`reader::backup_exclude`] so external callers can continue to
/// use `rimap_audit::backup_exclude::exclude_from_backup` after the split.
pub use crate::reader::backup_exclude;
/// Re-export of [`record::ids`] so external callers can continue to use
/// `rimap_audit::ids::{ProcessId, Seq, Timestamp}` after the subsystem split.
pub use crate::record::ids;

pub use crate::reader::{Filter, open_shared, parse_line, stream_records};
pub use crate::record::error::AuditError;
pub use crate::record::ids::{ProcessId, Seq, Timestamp};
pub use crate::record::{
    AccountSummary, AuditRecord, Auth, AuthResult, ConfigEvent, Payload, ProcessEnd,
    ProcessEndReason, ProcessStart, Provenance, ResultSummary, ToolEnd, ToolStart, ToolStatus,
};
pub use crate::redact::{
    FieldPolicy, RedactionSalt, RedactionSchema, Redactor, ToolRedactionSchema, VerbatimType,
    hash_arguments, redact, schemas,
};
pub use crate::writer::provenance::ProvenanceBuffer;
pub use crate::writer::self_check::{TrailingState, current_inode, read_trailing_state};
pub use crate::writer::{
    AuditOptions, AuditWriter, ProcessStartInputs, ToolEndInputs, ToolStartInputs,
};
