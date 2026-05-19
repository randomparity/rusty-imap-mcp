//! One-shot special-use discovery at account boot.
//!
//! Classifies a folder list into a `SpecialUseMap`. Called from the
//! per-account boot path before `FolderGuard` is constructed so the
//! guard's protected list can include discovered server-native folder
//! names (e.g. `[Gmail]/Sent Mail`) in addition to the config-supplied
//! literals.
//!
//! The `LIST "" "*"` fetch lives at the caller so this function stays
//! a pure mapping step exercisable by unit tests with synthetic
//! `Folder` values — no live IMAP server required.
//!
//! Classification logic is unit-tested in `rimap_imap::special_use`;
//! the live LIST path is covered by the Dovecot integration harness.

use rimap_imap::{SpecialUseMap, types::Folder};

/// Classify a folder list into a `SpecialUseMap`.
///
/// Pure mapping over `&[Folder]` so tests can pin the
/// classifier-output relationship without a live IMAP connection. The
/// `LIST "" "*"` call that produces `folders` is the caller's job.
#[must_use]
pub fn resolve_special_use(folders: &[Folder]) -> SpecialUseMap {
    SpecialUseMap::from_folders(folders)
}

#[cfg(test)]
mod tests {
    use rimap_imap::SpecialUse;
    use rimap_imap::types::Folder;

    use super::resolve_special_use;

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
