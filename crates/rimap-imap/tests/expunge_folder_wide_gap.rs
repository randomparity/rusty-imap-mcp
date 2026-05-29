//! Placeholder marking the one untested-by-design runtime path: the
//! folder-wide `EXPUNGE` fallback taken when an IMAP server advertises
//! neither MOVE nor UIDPLUS.
//!
//! Dovecot — the only integration target on this host — always advertises
//! UIDPLUS, so the integration suite reaches the scoped `UID EXPUNGE` path
//! exclusively and never the folder-wide branch. The data-loss behavior
//! there (plain `EXPUNGE` removing every `\Deleted` message in the source
//! folder), the `warn!`, and the `used_fallback=true` /
//! `folder_wide_expunge=true` result surface are therefore unverified at
//! runtime.
//!
//! The pure pieces of that path are unit-tested elsewhere:
//! `rimap_imap::ops::expunge::fallback_uses_folder_wide_expunge` (the
//! data-loss predicate) and `rimap_server`'s `fallback_security_warnings`
//! (the warning mapping). Only the live wire behavior remains open.
//!
//! This test stays `#[ignore]`d so the gap is visible in `cargo nextest`
//! output rather than silently implied as covered.

/// Documented coverage gap. See the `#[ignore]` reason for the intended
/// harness; the body is a no-op so the placeholder compiles and the gap
/// surfaces as a skipped test.
#[test]
#[ignore = "folder-wide EXPUNGE runtime path is untested: needs an in-process \
            TLS-terminating mock (tokio-rustls + rcgen, pinned-fingerprint mode) \
            advertising neither MOVE nor UIDPLUS, scripting login -> SELECT -> \
            STORE -> COPY and asserting a plain EXPUNGE is issued"]
fn folder_wide_expunge_runtime_path_is_unverified() {}
