//! Mailbox mutation tools: flags, labels, moves, deletes, folder management.

pub mod delete_message;
pub mod expunge;
pub mod flags;
pub mod folder_management;
pub mod labels;
pub mod move_message;

/// Build the security warnings for a delete/move that may have fallen back
/// from atomic `UID MOVE` to COPY+EXPUNGE.
///
/// `used_fallback` (`!has_move`) flags the non-atomic fallback; it always
/// yields `ServerNonAtomicMoveFallback`. `folder_wide_expunge`
/// (`!has_move && !has_uidplus`) is the distinct data-loss condition and
/// additionally yields `ServerFolderWideExpungeDataLoss`. Shared by the
/// `delete_message` and `move_message` handlers so both surface the same
/// signals.
pub(crate) fn fallback_security_warnings(
    used_fallback: bool,
    folder_wide_expunge: bool,
) -> Vec<rimap_content::SecurityWarning> {
    let mut warnings = Vec::new();
    if used_fallback {
        warnings.push(rimap_content::SecurityWarning::new(
            rimap_content::WarningCode::ServerNonAtomicMoveFallback,
            None,
            None,
        ));
    }
    if folder_wide_expunge {
        warnings.push(rimap_content::SecurityWarning::new(
            rimap_content::WarningCode::ServerFolderWideExpungeDataLoss,
            None,
            None,
        ));
    }
    warnings
}

#[cfg(test)]
mod tests {
    use super::fallback_security_warnings;
    use rimap_content::WarningCode;

    #[test]
    fn no_fallback_yields_no_warnings() {
        assert!(fallback_security_warnings(false, false).is_empty());
    }

    #[test]
    fn scoped_fallback_yields_only_non_atomic_warning() {
        let warnings = fallback_security_warnings(true, false);
        let codes: Vec<WarningCode> = warnings.iter().map(|w| w.code).collect();
        assert_eq!(codes, vec![WarningCode::ServerNonAtomicMoveFallback]);
    }

    #[test]
    fn folder_wide_fallback_yields_both_warnings_in_order() {
        let warnings = fallback_security_warnings(true, true);
        let codes: Vec<WarningCode> = warnings.iter().map(|w| w.code).collect();
        assert_eq!(
            codes,
            vec![
                WarningCode::ServerNonAtomicMoveFallback,
                WarningCode::ServerFolderWideExpungeDataLoss,
            ],
        );
    }
}
