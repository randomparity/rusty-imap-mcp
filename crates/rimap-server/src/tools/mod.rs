//! MCP tool handlers, grouped by concern:
//! - [`admin`]: account and folder discovery
//! - [`compose`]: outgoing message construction (send, draft)
//! - [`mailbox`]: server-side mutations (flags, labels, moves, deletes)
//! - [`retrieval`]: search, fetch, attachments
//!
//! Callers must reference the subdir path (`crate::tools::retrieval::fetch_message`);
//! no wildcard facade is provided so the partition stays meaningful.

pub mod admin;
pub mod compose;
pub(crate) mod fetch_by_uid;
pub(crate) mod lenient_int;
pub mod mailbox;
pub mod retrieval;
pub(crate) mod validation;
