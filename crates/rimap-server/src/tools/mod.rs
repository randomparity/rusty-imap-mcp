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
pub(crate) mod content_parse;
pub(crate) mod fetch_by_uid;
/// Re-export of the shared lenient-integer helpers, relocated to
/// `rimap-core` so tool-input types in both crates share one
/// implementation (issue #461). Kept at this path so the many
/// `deserialize_with`/`schema_with` string paths in tool inputs resolve
/// unchanged.
pub(crate) use rimap_core::lenient_int;
pub mod mailbox;
pub mod retrieval;
pub(crate) mod validation;
