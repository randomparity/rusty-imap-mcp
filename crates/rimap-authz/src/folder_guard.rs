//! Folder safety checks: protected folders and expunge allowlist.

use crate::error::AuthzError;
use rimap_core::folder_name::FolderName;

/// Runtime folder safety guard built from config.
#[derive(Debug, Clone)]
pub struct FolderGuard {
    protected: Vec<String>,
    expunge_allowed: Vec<String>,
}

/// Decode Modified UTF-7 (if applicable) and lowercase for
/// case-insensitive comparison. If decoding fails, fall back to
/// ASCII-lowercased input — we compare against that so a malformed
/// encoding cannot silently bypass the guard.
///
/// Exposed for callers that must compare folder names through the same
/// normalization the guard uses — e.g. `merge_protected_folders` and
/// `protected_entries` in `rimap-server` — so the two cannot drift.
#[must_use]
pub fn normalize_folder_name(folder: &str) -> String {
    let decoded = utf7_imap::decode_utf7_imap(folder.to_string());
    decoded.to_lowercase()
}

/// Validate `folder`'s structure, then return its normalized comparison
/// key. The validate-then-normalize ordering is load-bearing security
/// code: a name that fails [`FolderName`] validation must be rejected
/// before it is ever compared against the protected/expunge lists.
fn validate_and_normalize(folder: &str) -> Result<String, AuthzError> {
    FolderName::new(folder)?;
    Ok(normalize_folder_name(folder))
}

impl FolderGuard {
    /// Build from config values. Both lists are normalized (Modified
    /// UTF-7 decoded, then lowercased) for IMAP-aware case-insensitive
    /// matching.
    #[must_use]
    pub fn new(protected_folders: &[String], expunge_folders: &[String]) -> Self {
        Self {
            protected: protected_folders
                .iter()
                .map(|f| normalize_folder_name(f))
                .collect(),
            expunge_allowed: expunge_folders
                .iter()
                .map(|f| normalize_folder_name(f))
                .collect(),
        }
    }

    /// Check whether folder can be deleted or renamed.
    /// INBOX is always rejected. Validates folder name structure
    /// before comparison.
    ///
    /// # Errors
    /// Returns [`AuthzError::InvalidFolderName`] if validation fails.
    /// Returns [`AuthzError::ProtectedFolder`] if the folder is INBOX
    /// or appears in the protected list.
    pub fn check_protected(&self, folder: &str, operation: &'static str) -> Result<(), AuthzError> {
        let norm = validate_and_normalize(folder)?;
        if norm == "inbox" || self.protected.contains(&norm) {
            return Err(AuthzError::ProtectedFolder {
                folder: folder.to_string(),
                operation,
            });
        }
        Ok(())
    }

    /// Check that neither `old_name` nor `new_name` is protected.
    /// Both names are validated and compared using IMAP-aware
    /// normalization.
    ///
    /// # Errors
    /// Returns [`AuthzError::InvalidFolderName`] if either name
    /// fails validation. Returns [`AuthzError::ProtectedFolder`]
    /// if either name is in the protected list or is INBOX.
    pub fn check_rename(&self, old_name: &str, new_name: &str) -> Result<(), AuthzError> {
        self.check_protected(old_name, "rename")?;
        self.check_protected(new_name, "rename")?;
        Ok(())
    }

    /// Check whether folder is in the expunge allowlist. Validates
    /// folder name structure before comparison.
    ///
    /// # Errors
    /// Returns [`AuthzError::InvalidFolderName`] if validation fails.
    /// Returns [`AuthzError::ExpungeDenied`] if the folder is not in
    /// the expunge allowlist.
    pub fn check_expunge(&self, folder: &str) -> Result<(), AuthzError> {
        let norm = validate_and_normalize(folder)?;
        if !self.expunge_allowed.contains(&norm) {
            return Err(AuthzError::ExpungeDenied {
                folder: folder.to_string(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::FolderGuard;
    use crate::error::AuthzError;

    fn guard() -> FolderGuard {
        FolderGuard::new(
            &[
                "INBOX".into(),
                "Sent".into(),
                "Drafts".into(),
                "Trash".into(),
            ],
            &["Trash".into()],
        )
    }

    #[test]
    fn inbox_always_protected_even_if_not_in_list() {
        let g = FolderGuard::new(&[], &[]);
        assert!(matches!(
            g.check_protected("INBOX", "delete"),
            Err(AuthzError::ProtectedFolder { .. })
        ));
        assert!(matches!(
            g.check_protected("inbox", "delete"),
            Err(AuthzError::ProtectedFolder { .. })
        ));
        assert!(matches!(
            g.check_protected("Inbox", "rename"),
            Err(AuthzError::ProtectedFolder { .. })
        ));
    }

    #[test]
    fn protected_folder_rejected_case_insensitive() {
        let g = guard();
        assert!(matches!(
            g.check_protected("sent", "delete"),
            Err(AuthzError::ProtectedFolder { .. })
        ));
        assert!(matches!(
            g.check_protected("SENT", "delete"),
            Err(AuthzError::ProtectedFolder { .. })
        ));
    }

    #[test]
    fn unprotected_folder_allowed() {
        let g = guard();
        assert!(g.check_protected("Archives", "delete").is_ok());
        assert!(g.check_protected("Old Mail", "rename").is_ok());
    }

    #[test]
    fn expunge_allowed_for_listed_folder() {
        let g = guard();
        assert!(g.check_expunge("Trash").is_ok());
        assert!(g.check_expunge("trash").is_ok());
        assert!(g.check_expunge("TRASH").is_ok());
    }

    #[test]
    fn expunge_denied_for_unlisted_folder() {
        let g = guard();
        assert!(matches!(
            g.check_expunge("INBOX"),
            Err(AuthzError::ExpungeDenied { .. })
        ));
        assert!(matches!(
            g.check_expunge("Sent"),
            Err(AuthzError::ExpungeDenied { .. })
        ));
    }

    #[test]
    fn empty_expunge_list_denies_everything() {
        let g = FolderGuard::new(&[], &[]);
        assert!(matches!(
            g.check_expunge("Trash"),
            Err(AuthzError::ExpungeDenied { .. })
        ));
    }

    #[test]
    fn folder_name_validation_runs_in_check_protected() {
        let g = FolderGuard::new(&[], &[]);
        assert!(matches!(
            g.check_protected("test\0folder", "delete"),
            Err(AuthzError::InvalidFolderName { .. })
        ));
    }

    #[test]
    fn folder_name_validation_runs_in_check_expunge() {
        let g = FolderGuard::new(&[], &["Trash".into()]);
        assert!(matches!(
            g.check_expunge("test\0folder"),
            Err(AuthzError::InvalidFolderName { .. })
        ));
    }

    #[test]
    fn rename_rejects_protected_old_name() {
        let g = guard();
        assert!(matches!(
            g.check_rename("Sent", "Archive"),
            Err(AuthzError::ProtectedFolder { .. })
        ));
    }

    #[test]
    fn rename_rejects_protected_new_name() {
        let g = guard();
        assert!(matches!(
            g.check_rename("MyFolder", "INBOX"),
            Err(AuthzError::ProtectedFolder { .. })
        ));
    }

    #[test]
    fn rename_allows_unprotected_both() {
        let g = guard();
        assert!(g.check_rename("Old", "New").is_ok());
    }

    #[test]
    fn protected_non_ascii_folder_rejected_in_both_mutf7_and_decoded_forms() {
        // "Café" — the é forces a Modified-UTF-7 base64 run.
        let decoded = "Caf\u{00e9}";
        let encoded = utf7_imap::encode_utf7_imap(decoded.to_string());
        assert_ne!(
            encoded, decoded,
            "test input must actually be mUTF-7 encoded"
        );

        // Configured in WIRE (encoded) form; request arrives DECODED.
        let g = FolderGuard::new(std::slice::from_ref(&encoded), &[]);
        assert!(
            matches!(
                g.check_protected(decoded, "delete"),
                Err(AuthzError::ProtectedFolder { .. })
            ),
            "decoded form must match an encoded protected entry",
        );
        assert!(
            matches!(
                g.check_protected(&encoded, "delete"),
                Err(AuthzError::ProtectedFolder { .. })
            ),
            "encoded form must match an encoded protected entry",
        );

        // Configured in DECODED form; request arrives ENCODED (and vice versa).
        let g2 = FolderGuard::new(&[decoded.to_string()], &[]);
        assert!(
            matches!(
                g2.check_protected(&encoded, "delete"),
                Err(AuthzError::ProtectedFolder { .. })
            ),
            "encoded form must match a decoded protected entry",
        );
        assert!(
            matches!(
                g2.check_protected(decoded, "rename"),
                Err(AuthzError::ProtectedFolder { .. })
            ),
            "decoded form must match a decoded protected entry",
        );
    }

    #[test]
    fn expunge_allowlist_matches_across_mutf7_forms() {
        let decoded = "Caf\u{00e9}";
        let encoded = utf7_imap::encode_utf7_imap(decoded.to_string());
        let g = FolderGuard::new(&[], std::slice::from_ref(&encoded));
        // Allowlisted in encoded form; both request forms must be allowed.
        assert!(g.check_expunge(decoded).is_ok());
        assert!(g.check_expunge(&encoded).is_ok());
        // A different non-ASCII folder must still be denied.
        assert!(matches!(
            g.check_expunge("Sp\u{00e4}m"),
            Err(AuthzError::ExpungeDenied { .. })
        ));
    }

    #[test]
    fn malformed_mutf7_input_does_not_panic() {
        // A dangling shift sequence ("&" with no terminating "-") is
        // malformed mUTF-7. normalize() must not panic on it, and an
        // unrelated plain protected name must remain protected afterward.
        let g = FolderGuard::new(&["Drafts".into()], &[]);
        let _ = g.check_protected("&malformed", "delete");
        assert!(
            g.check_protected("Drafts", "delete").is_err(),
            "plain protected name must remain protected after a malformed probe",
        );
    }

    #[test]
    fn protected_folder_not_bypassed_by_alternate_mutf7_encoding() {
        // Protect the folder by its decoded, non-ASCII name. An attacker
        // must not be able to slip the same folder past the guard by
        // presenting it in an alternate wire encoding or different casing.
        let decoded = "Caf\u{00e9}";
        let g = FolderGuard::new(std::slice::from_ref(&decoded.to_string()), &[]);

        // (a) The mUTF-7 wire form decodes back to the protected name.
        let encoded = utf7_imap::encode_utf7_imap(decoded.to_string());
        assert_ne!(
            encoded, decoded,
            "test input must actually be mUTF-7 encoded"
        );
        assert!(
            matches!(
                g.check_protected(&encoded, "delete"),
                Err(AuthzError::ProtectedFolder { .. })
            ),
            "the mUTF-7 wire form must not bypass the protected entry",
        );

        // (b) An uppercased decoded variant normalizes to the same name.
        assert!(
            matches!(
                g.check_protected("CAF\u{00c9}", "delete"),
                Err(AuthzError::ProtectedFolder { .. })
            ),
            "an uppercased variant must not bypass the protected entry",
        );
    }
}
