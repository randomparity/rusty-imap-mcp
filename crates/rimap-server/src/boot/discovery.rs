//! One-shot special-use discovery at account boot.
//!
//! Classifies a folder list into a `SpecialUseMap` so the `FolderGuard`'s
//! protected list can include discovered server-native folder names (e.g.
//! `[Gmail]/Sent Mail`) in addition to the config-supplied literals.
//!
//! Two layers, and the split is deliberate. [`resolve_special_use`] and
//! [`merge_protected_folders`] are pure mappings over values, unit-tested
//! with synthetic `Folder`s and no live server. [`resolve_folder_policy`]
//! sits above them and owns the parts that need a session: the
//! `LIST "" "*"` itself, `FolderGuard::new`, and the `folder_policy` audit
//! record.
//!
//! That orchestration lives here rather than in `main.rs` because `main.rs`
//! is a binary target no integration test can link against, and #761's whole
//! point is that the recorded list must be provably the one the guard was
//! built from. A test can only prove that by driving this function.
//!
//! Classification logic is unit-tested in `rimap_imap::special_use`;
//! the live LIST path is covered by `tests/boot_folder_policy.rs` against the
//! in-process fake and by the Dovecot integration harness.

use anyhow::Context;
use rimap_audit::AuditWriter;
use rimap_audit::record::FolderPolicy;
use rimap_authz::{FolderGuard, normalize_folder_name};
use rimap_config::validate::ValidatedAccountConfig;
use rimap_imap::{Connection, SpecialUseMap, types::Folder};

/// What one account's boot-time folder resolution produced.
///
/// Returned together because they are one decision rendered twice: the guard
/// that enforces the policy and the map the session keeps. Splitting them
/// across two calls would reintroduce the possibility of a caller pairing a
/// guard with a map from a different `LIST`.
///
/// `#[non_exhaustive]` because `rimap-server` is a published crate (ADR-0004)
/// and its `pub` structs are born with the attribute — a third field here
/// would otherwise be a breaking change. The only construction and the only
/// destructure are both in-crate, where the attribute is a no-op.
#[non_exhaustive]
pub struct ResolvedFolderPolicy {
    /// The special-use classification of the account's folder list.
    pub special_use: SpecialUseMap,
    /// The guard built from the merged protected list.
    pub folder_guard: FolderGuard,
}

/// Run special-use discovery for one account, build its `FolderGuard`, and
/// record the policy the guard was built from.
///
/// The order is load-bearing and is the acceptance criterion of #761: the
/// merged list produced here is passed to `FolderGuard::new` and to
/// [`crate::boot::tool_matrix::account_tool_matrix`] as the *same* slice, so
/// the record cannot describe a policy other than the enforced one. Deriving
/// the record by re-merging instead would let the two drift.
///
/// Emits the `folder_policy` audit record and the `effective folder policy`
/// log line, in that order — the record first, because it is the durable one
/// and the log line is best-effort by nature.
///
/// # Blocking
///
/// The audit write is synchronous and fsynced, and this is an `async fn`, so
/// it is a third exception to `docs/architecture/audit-locking.md`'s rule that
/// async callers reach the writer through
/// `DispatchDrain::spawn_blocking_tracked`. It is justified by *when* it runs,
/// not by what it costs: `build_registry` completes before `spawn_drainer` and
/// before `rmcp::serve_server`, so the drain to register with does not exist
/// yet and boot has no other task to stall. **A change that boots accounts
/// concurrently invalidates that and must revisit this call site** — see
/// ADR-0021 and the exception list in `audit-locking.md`.
///
/// # Errors
/// Propagates a `LIST` failure (the account cannot be booted without one) and
/// an audit-write failure, which is fatal here for the same reason it is at
/// every other boot-record site: a boot that is not recorded is not one an
/// operator can later reconstruct.
pub async fn resolve_folder_policy(
    acfg: &ValidatedAccountConfig,
    imap: &Connection,
    audit: &AuditWriter,
) -> anyhow::Result<ResolvedFolderPolicy> {
    let folders = imap
        .list_folders("*")
        .await
        .with_context(|| format!("listing folders for account {}", acfg.id.as_str()))?;
    let special_use = resolve_special_use(&folders);
    let protected = merge_protected_folders(
        &acfg.security.protected_folders,
        special_use.all_discovered(),
    );

    let folder_guard = FolderGuard::new(&protected, &acfg.security.expunge_folders);

    // One producer for both renderings: the matrix classifies `protected`
    // entry by entry against the config, which is what makes the record's
    // `discovered` tags and the guard's contents the same list by
    // construction.
    let matrix = crate::boot::tool_matrix::account_tool_matrix(acfg, Some(&protected));
    audit
        .log_folder_policy(FolderPolicy::new(
            matrix.account.clone(),
            matrix.protected_folders.clone(),
            matrix.special_use_discovery,
            matrix.expunge_folders.clone(),
        ))
        .with_context(|| {
            format!(
                "writing folder_policy audit record for account {}",
                acfg.id.as_str(),
            )
        })?;
    crate::boot::tool_matrix::log_account_folder_policy(&matrix);

    Ok(ResolvedFolderPolicy {
        special_use,
        folder_guard,
    })
}

/// Classify a folder list into a `SpecialUseMap`.
///
/// Pure mapping over `&[Folder]` so tests can pin the
/// classifier-output relationship without a live IMAP connection. The
/// `LIST "" "*"` call that produces `folders` is the caller's job.
#[must_use]
pub fn resolve_special_use(folders: &[Folder]) -> SpecialUseMap {
    SpecialUseMap::from_folders(folders)
}

/// Expand the config-supplied protected-folders list with any
/// server-declared RFC 6154 special-use names (e.g. Gmail's
/// `[Gmail]/Sent Mail`), preserving the configured order and appending
/// only names not already present.
///
/// The dedup is normalization-aware so a user-configured literal (`"Gelöscht"`)
/// is not duplicated when the server reports the mUTF-7 wire form
/// (`"Gel&APY-scht"`) or a non-ASCII case variant (`"GELÖSCHT"`). Normalization
/// uses the same mUTF-7-decode-then-Unicode-lowercase path `FolderGuard` uses,
/// so the two cannot produce different answers for the same mailbox. Kept pure —
/// `discovered` is the output of [`rimap_imap::SpecialUseMap::all_discovered`] —
/// so the security-relevant merge is unit-testable without a live IMAP connection.
#[must_use]
pub fn merge_protected_folders(configured: &[String], discovered: Vec<String>) -> Vec<String> {
    let mut protected = configured.to_vec();
    for name in discovered {
        if !protected
            .iter()
            .any(|p| normalize_folder_name(p) == normalize_folder_name(&name))
        {
            protected.push(name);
        }
    }
    protected
}

#[cfg(test)]
mod tests {
    use rimap_imap::SpecialUse;
    use rimap_imap::types::Folder;

    use super::{merge_protected_folders, resolve_special_use};

    fn owned(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn merge_appends_discovered_names_after_configured() {
        let merged = merge_protected_folders(&owned(&["INBOX"]), owned(&["[Gmail]/Sent Mail"]));
        assert_eq!(merged, owned(&["INBOX", "[Gmail]/Sent Mail"]));
    }

    #[test]
    fn merge_dedups_case_insensitively() {
        // A configured literal must not be duplicated when the server
        // reports the same name in a different case.
        let merged = merge_protected_folders(&owned(&["Sent"]), owned(&["sent", "Trash"]));
        assert_eq!(merged, owned(&["Sent", "Trash"]));
    }

    #[test]
    fn merge_preserves_configured_order_and_keeps_empties() {
        let merged = merge_protected_folders(&owned(&["a", "b"]), Vec::new());
        assert_eq!(merged, owned(&["a", "b"]));

        let merged = merge_protected_folders(&[], owned(&["x"]));
        assert_eq!(merged, owned(&["x"]));
    }

    #[test]
    fn merge_dedups_within_discovered_against_running_result() {
        // Two discovered names that collide case-insensitively with each
        // other: the second is dropped because the first was appended.
        let merged = merge_protected_folders(&[], owned(&["Archive", "archive"]));
        assert_eq!(merged, owned(&["Archive"]));
    }

    #[test]
    fn merge_dedup_mutf7_and_unicode_form_treated_as_same() {
        // "Gelöscht" and its mUTF-7 wire form "Gel&APY-scht" are the same
        // mailbox. merge_protected_folders must recognise them as identical
        // and not add the server-reported form as a second entry.
        //
        // "APY" is the base64 encoding of U+00F6 ('ö'), the standard mUTF-7
        // shift sequence for that codepoint.
        let merged = merge_protected_folders(&owned(&["Gelöscht"]), owned(&["Gel&APY-scht"]));
        assert_eq!(
            merged,
            owned(&["Gelöscht"]),
            "mUTF-7 form must not be added when decoded form is already configured"
        );
    }

    #[test]
    fn merge_dedup_non_ascii_case_difference_is_single_entry() {
        // A non-ASCII case difference (GELÖSCHT vs Gelöscht) must not
        // produce a second entry: Unicode lowercasing treats Ö == ö.
        let merged = merge_protected_folders(&owned(&["Gelöscht"]), owned(&["GELÖSCHT"]));
        assert_eq!(
            merged,
            owned(&["Gelöscht"]),
            "non-ASCII case difference must not add a duplicate entry"
        );
    }

    fn folder(name: &str, special: Option<SpecialUse>) -> Folder {
        Folder {
            name: name.to_string(),
            attributes: Vec::new(),
            delimiter: Some('/'),
            special_use: special,
        }
    }

    #[test]
    fn resolve_special_use_empty_input_returns_default_map() {
        // Baseline: nothing to classify produces a fully-empty map.
        // The unmutated function returns this for an empty input; the
        // mutated form `with Default::default()` *also* returns this.
        // The kill comes from the populated-input cases below, not this
        // one — it stays as a sanity check that empty input does not
        // panic.
        let map = resolve_special_use(&[]);
        assert_eq!(map.drafts(), None);
        assert_eq!(map.sent(), None);
        assert_eq!(map.trash(), None);
    }

    #[test]
    fn resolve_special_use_gmail_drafts_populates_drafts_slot() {
        // Kills `replace resolve_special_use -> SpecialUseMap with
        // Default::default()`: the unmutated function classifies the
        // `\Drafts` folder and returns `drafts() == Some("[Gmail]/Drafts")`,
        // but the mutated stub returns an empty map with `drafts() ==
        // None`. The single populated slot is enough to distinguish.
        let folders = vec![folder("[Gmail]/Drafts", Some(SpecialUse::Drafts))];
        let map = resolve_special_use(&folders);
        assert_eq!(map.drafts(), Some("[Gmail]/Drafts"));
        assert_eq!(map.sent(), None);
        assert_eq!(map.trash(), None);
    }

    #[test]
    fn resolve_special_use_mixed_special_use_populates_all_slots() {
        // Pins the full classifier contract: Drafts, Sent, and Trash
        // each route to their slot, and folders without `special_use`
        // (`INBOX`, `Archive` without flag) do not occupy slots. A
        // single mutation to swap slot routing or to drop one branch
        // would observably change one of the asserted values.
        let folders = vec![
            folder("INBOX", None),
            folder("[Gmail]/Drafts", Some(SpecialUse::Drafts)),
            folder("[Gmail]/Sent Mail", Some(SpecialUse::Sent)),
            folder("[Gmail]/Trash", Some(SpecialUse::Trash)),
        ];
        let map = resolve_special_use(&folders);
        assert_eq!(map.drafts(), Some("[Gmail]/Drafts"));
        assert_eq!(map.sent(), Some("[Gmail]/Sent Mail"));
        assert_eq!(map.trash(), Some("[Gmail]/Trash"));
    }
}
