//! Message parsing via `mail-parser`.
//!
//! This module owns all interaction with `mail-parser`; no other
//! module in `rimap-content` imports `mail-parser` types directly.
//! It applies hard limits declared as compile-time constants and
//! routes every extracted string through [`crate::unicode::sanitize`]
//! so downstream consumers see only Unicode-clean text.

mod attachments;
mod bodies;
mod filename;
mod headers;
mod meta;
pub(crate) mod mime_scrub;
mod pipeline;
mod raw_parts;
pub(crate) mod safe_parser;
mod sniff;
mod threading;

pub use pipeline::{
    MAX_BODY_BYTES, MAX_HEADER_BYTES, MAX_HEADER_COUNT, MAX_MESSAGE_BYTES, MAX_MIME_DEPTH,
    MAX_MIME_PARTS, MAX_TOTAL_BODY_BYTES, parse_message,
};
pub use raw_parts::{RawPart, walk_attachment_parts};
pub use threading::{ThreadingHeaders, extract_threading_headers};
