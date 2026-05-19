//! One-shot special-use discovery at account boot.
//!
//! Runs `LIST "" "*"` once against a freshly-opened `Connection` and
//! builds a `SpecialUseMap`. Called from the per-account boot path
//! before `FolderGuard` is constructed so the guard's protected list
//! can include discovered server-native folder names (e.g.
//! `[Gmail]/Sent Mail`) in addition to the config-supplied literals.
//!
//! Classification logic is unit-tested in `rimap_imap::special_use`;
//! the live LIST path is covered by the Dovecot integration harness.

use rimap_core::RimapError;
use rimap_imap::{Connection, SpecialUseMap};

/// Run one `LIST "*"` and classify the response into a `SpecialUseMap`.
///
/// Discovery failures propagate — if we cannot enumerate folders at
/// boot, the account is unusable regardless of what any downstream tool
/// call does later, so returning the error early gives the operator a
/// clean boot-time signal instead of a surprise on first compose.
///
/// # Errors
///
/// Returns `RimapError::Imap { ... }` when the underlying `LIST` call
/// fails (transport error, server protocol error, auth expired, etc.).
// cargo-mutants: known-equivalent (test-infrastructure gap) — the
// `replace ... with Ok(Default::default())` stub returns an empty
// SpecialUseMap, observably different from the populated map the
// real implementation returns on a non-empty mailbox. Unit-testing
// the mutation requires either a live IMAP server (covered by the
// dovecot integration harness in `crates/rimap-server/tests/e2e.rs`
// which is environment-gated and skipped by cargo-mutants runs that
// have no Docker available) or a stub `Connection` that intercepts
// `list_folders`. The latter would require either a new trait
// boundary across `rimap-imap` or a refactor of this two-line
// helper. Documented in `mutation-baseline.md` as a known coverage
// gap pending future test-infrastructure work.
pub async fn resolve_special_use(connection: &Connection) -> Result<SpecialUseMap, RimapError> {
    let folders = connection.list_folders("*").await?;
    Ok(SpecialUseMap::from_folders(&folders))
}
