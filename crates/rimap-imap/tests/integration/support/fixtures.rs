//! Path helpers and message builders for the seeded fixtures.
//!
//! This module is compiled into multiple test binaries (dovecot, proton)
//! that each use a different subset of helpers. Suppress dead-code
//! warnings at the module level rather than per-function.
#![expect(dead_code, reason = "shared across test binaries with partial use")]

use std::path::PathBuf;

#[must_use]
pub fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("integration")
        .join("dovecot")
        .join("fixtures")
}

/// Minimal RFC 5322 message for test seeding.
#[must_use]
pub fn minimal_rfc5322(subject: &str) -> Vec<u8> {
    format!(
        "From: test@example.com\r\n\
         To: recipient@example.com\r\n\
         Subject: {subject}\r\n\
         Date: Sat, 12 Apr 2026 12:00:00 +0000\r\n\
         Message-ID: <test-{subject}@example.com>\r\n\
         \r\n\
         Test body for {subject}.\r\n"
    )
    .into_bytes()
}

/// RFC 5322 reply referencing `parent_message_id` (the bracketed
/// `<local@domain>` form) via `In-Reply-To` and `References`, for
/// thread/reference-chain test seeding.
#[must_use]
pub fn reply_rfc5322(subject: &str, parent_message_id: &str) -> Vec<u8> {
    format!(
        "From: test@example.com\r\n\
         To: recipient@example.com\r\n\
         Subject: Re: {subject}\r\n\
         Date: Sat, 12 Apr 2026 12:05:00 +0000\r\n\
         Message-ID: <test-reply-{subject}@example.com>\r\n\
         In-Reply-To: {parent_message_id}\r\n\
         References: {parent_message_id}\r\n\
         \r\n\
         Reply body for {subject}.\r\n"
    )
    .into_bytes()
}
