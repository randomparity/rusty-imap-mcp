//! MCP tool handlers, grouped by concern:
//! - [`admin`]: account and folder discovery
//! - [`compose`]: outgoing message construction (send, draft)
//! - [`mailbox`]: server-side mutations (flags, labels, moves, deletes)
//! - [`retrieval`]: search, fetch, attachments
//!
//! Callers must reference the subdir path (`crate::tools::retrieval::fetch_message`);
//! no wildcard facade is provided so the partition stays meaningful.
//!
//! # Scalar vs batch `uid` shapes (#405)
//!
//! Batch-capable inputs (`uid` XOR `uids`, batch max 100) exist only on
//! commutative, idempotent mutations (`flag`, `add_label`,
//! `move_message`) where per-UID ordering does not matter and results
//! fan out uniformly. Read-side tools (`fetch_message`,
//! `list_attachments`, `download_attachment`) and destructive
//! single-target tools (`delete_message`) keep a scalar `uid` so the
//! response schema and error semantics stay unambiguous. The asymmetry
//! is deliberate; individual handlers carry only a pointer here.

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
