//! Runtime `EffectiveMatrix`: merges the base posture truth table (the
//! compile-time `const` table and `base_allows` live in `rimap_core`) with
//! per-tool overrides, then answers per-tool authorization lookups.
//!
//! Derived from design spec §4 "Posture matrix".

use std::collections::BTreeMap;

use rimap_config::model::Verdict;
use rimap_core::base_allows;
use rimap_core::posture::Posture;
use rimap_core::tool::ToolName;

use crate::error::AuthzError;

/// Effective authorization matrix: base posture merged with per-tool overrides.
///
/// Deny overrides Allow. An override pointing at a tool that is already in
/// the same state is a no-op (not an error).
#[derive(Debug, Clone)]
pub struct EffectiveMatrix {
    allowed: BTreeMap<ToolName, bool>,
    posture: Posture,
}

impl EffectiveMatrix {
    /// Build from a base [`Posture`] and per-tool overrides (already resolved
    /// to [`ToolName`] by config validation).
    #[must_use]
    pub fn build(posture: Posture, overrides: &BTreeMap<ToolName, Verdict>) -> Self {
        let mut allowed = BTreeMap::new();
        for tool in ToolName::all() {
            let base = base_allows(posture, tool);
            let effective = match overrides.get(&tool) {
                None => base,
                Some(Verdict::Allow) => true,
                Some(Verdict::Deny) => false,
            };
            allowed.insert(tool, effective);
        }
        Self { allowed, posture }
    }

    /// Base posture used for construction (for logging / display only).
    #[must_use]
    pub fn posture(&self) -> Posture {
        self.posture
    }

    /// `Ok(())` if allowed, `Err(PostureDenied)` otherwise.
    ///
    /// # Errors
    /// Returns `AuthzError::PostureDenied` if `tool` is not allowed.
    pub fn check(&self, tool: ToolName) -> Result<(), AuthzError> {
        if *self.allowed.get(&tool).unwrap_or(&false) {
            Ok(())
        } else {
            Err(AuthzError::PostureDenied(tool))
        }
    }

    /// Return the set of allowed tools in declaration order — the advertised
    /// set for `list_tools`.
    #[must_use]
    pub fn advertised(&self) -> Vec<ToolName> {
        ToolName::all()
            .into_iter()
            .filter(|t| *self.allowed.get(t).unwrap_or(&false))
            .collect()
    }

    /// Iterate `(tool, allowed)` in declaration order. Used by `--dry-run`
    /// printing.
    pub fn rows(&self) -> impl Iterator<Item = (ToolName, bool)> + '_ {
        ToolName::all()
            .into_iter()
            .map(move |t| (t, *self.allowed.get(&t).unwrap_or(&false)))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use rimap_config::model::Verdict;
    use rimap_core::posture::Posture;
    use rimap_core::tool::ToolName;

    use crate::error::AuthzError;
    use rimap_core::posture_matrix::POSTURE_MATRIX;

    use crate::matrix::EffectiveMatrix;
    use rimap_core::base_allows;

    #[test]
    fn matrix_covers_every_non_infrastructure_tool_variant() {
        use std::collections::BTreeSet;
        let mut seen = BTreeSet::new();
        for (tool, _) in POSTURE_MATRIX {
            assert!(seen.insert(tool), "duplicate row for {tool}");
        }
        let non_infra: Vec<_> = ToolName::all()
            .into_iter()
            .filter(|t| !t.is_infrastructure())
            .collect();
        assert_eq!(seen.len(), non_infra.len());
        for t in non_infra {
            assert!(seen.contains(&t), "missing row for {t}");
        }
    }

    #[test]
    fn base_readonly_row_matches_spec() {
        for t in [
            ToolName::ListFolders,
            ToolName::Search,
            ToolName::FetchMessage,
            ToolName::ListAttachments,
            ToolName::DownloadAttachment,
            ToolName::ListLabels,
        ] {
            assert!(base_allows(Posture::Readonly, t), "{t} should be allowed");
        }
        for t in [
            ToolName::SearchAdvanced,
            ToolName::FetchMessageHtml,
            ToolName::MarkRead,
            ToolName::MarkUnread,
            ToolName::Flag,
            ToolName::Unflag,
            ToolName::AddLabel,
            ToolName::RemoveLabel,
            ToolName::MoveMessage,
            ToolName::CreateDraft,
            ToolName::SendEmail,
            ToolName::Forward,
            ToolName::DeleteMessage,
            ToolName::Expunge,
            ToolName::CreateFolder,
            ToolName::RenameFolder,
            ToolName::DeleteFolder,
            ToolName::ExportMessages,
        ] {
            assert!(!base_allows(Posture::Readonly, t), "{t} should be denied");
        }
    }

    #[test]
    fn base_draft_safe_row_matches_spec() {
        let denied = [
            ToolName::SearchAdvanced,
            ToolName::FetchMessageHtml,
            ToolName::SendEmail,
            ToolName::Forward,
            ToolName::DeleteMessage,
            ToolName::Expunge,
            ToolName::CreateFolder,
            ToolName::RenameFolder,
            ToolName::DeleteFolder,
            ToolName::ExportMessages,
        ];
        for t in &denied {
            assert!(!base_allows(Posture::DraftSafe, *t), "{t} expected denied");
        }
        for t in ToolName::all() {
            if denied.contains(&t) || t.is_infrastructure() {
                continue;
            }
            assert!(base_allows(Posture::DraftSafe, t), "{t} expected allowed");
        }
    }

    #[test]
    fn base_full_allows_except_destructive() {
        let denied = [
            ToolName::Expunge,
            ToolName::DeleteFolder,
            ToolName::ExportMessages,
        ];
        for t in ToolName::all() {
            if t.is_infrastructure() {
                assert!(
                    !base_allows(Posture::Full, t),
                    "{t} infrastructure tool should not be in posture matrix"
                );
            } else if denied.contains(&t) {
                assert!(
                    !base_allows(Posture::Full, t),
                    "{t} expected denied at full"
                );
            } else {
                assert!(
                    base_allows(Posture::Full, t),
                    "{t} expected allowed at full"
                );
            }
        }
    }

    #[test]
    fn base_destructive_allows_all_non_infrastructure() {
        for t in ToolName::all() {
            if t.is_infrastructure() {
                assert!(
                    !base_allows(Posture::Destructive, t),
                    "{t} infrastructure tool should not be in posture matrix"
                );
            } else if t == ToolName::ExportMessages {
                assert!(
                    !base_allows(Posture::Destructive, t),
                    "export_messages is default-deny at every base posture"
                );
            } else {
                assert!(
                    base_allows(Posture::Destructive, t),
                    "destructive should allow {t}"
                );
            }
        }
    }

    #[test]
    fn exhaustive_posture_times_tool_lookup_is_stable() {
        for p in Posture::all() {
            for t in ToolName::all() {
                let a = base_allows(p, t);
                let b = base_allows(p, t);
                assert_eq!(a, b);
            }
        }
    }

    #[test]
    fn deny_override_beats_allow_in_base() {
        let mut overrides = BTreeMap::new();
        overrides.insert(ToolName::Search, Verdict::Deny);
        let m = EffectiveMatrix::build(Posture::DraftSafe, &overrides);
        assert!(matches!(
            m.check(ToolName::Search),
            Err(AuthzError::PostureDenied(_))
        ));
        assert!(m.check(ToolName::ListFolders).is_ok());
    }

    #[test]
    fn allow_override_promotes_denied_tool() {
        let mut overrides = BTreeMap::new();
        overrides.insert(ToolName::SearchAdvanced, Verdict::Allow);
        let m = EffectiveMatrix::build(Posture::DraftSafe, &overrides);
        assert!(m.check(ToolName::SearchAdvanced).is_ok());
    }

    #[test]
    fn override_same_as_base_is_noop() {
        let mut overrides = BTreeMap::new();
        overrides.insert(ToolName::ListFolders, Verdict::Allow);
        overrides.insert(ToolName::CreateDraft, Verdict::Deny);
        let m = EffectiveMatrix::build(Posture::Readonly, &overrides);
        assert!(m.check(ToolName::ListFolders).is_ok());
        assert!(matches!(
            m.check(ToolName::CreateDraft),
            Err(AuthzError::PostureDenied(_))
        ));
    }

    #[test]
    fn advertised_matches_allowed_set_in_order() {
        let m = EffectiveMatrix::build(Posture::Readonly, &BTreeMap::new());
        let adv = m.advertised();
        assert_eq!(
            adv,
            vec![
                ToolName::ListFolders,
                ToolName::Search,
                ToolName::FetchMessage,
                ToolName::ListAttachments,
                ToolName::DownloadAttachment,
                ToolName::ListLabels,
            ]
        );
    }

    #[test]
    fn rows_iterates_every_tool() {
        let m = EffectiveMatrix::build(Posture::Destructive, &BTreeMap::new());
        let rows: Vec<_> = m.rows().collect();
        assert_eq!(rows.len(), ToolName::all().len());
        for (tool, allowed) in &rows {
            if tool.is_infrastructure() {
                assert!(
                    !allowed,
                    "{tool} infrastructure tool should be denied in matrix"
                );
            } else if *tool == ToolName::ExportMessages {
                assert!(
                    !allowed,
                    "export_messages is default-deny at every base posture"
                );
            } else {
                assert!(allowed, "{tool} should be allowed at destructive");
            }
        }
    }

    #[test]
    fn posture_accessor_returns_construction_value() {
        let m = EffectiveMatrix::build(Posture::DraftSafe, &BTreeMap::new());
        assert_eq!(m.posture(), Posture::DraftSafe);
    }

    #[test]
    fn export_messages_denied_by_default_enabled_only_by_override() {
        // No override: denied at every posture.
        for p in Posture::all() {
            let m = EffectiveMatrix::build(p, &BTreeMap::new());
            assert!(
                m.check(ToolName::ExportMessages).is_err(),
                "export_messages must be default-denied at {p:?}"
            );
        }
        // Explicit allow override enables it.
        let mut overrides = BTreeMap::new();
        overrides.insert(ToolName::ExportMessages, Verdict::Allow);
        let m = EffectiveMatrix::build(Posture::Readonly, &overrides);
        assert!(m.check(ToolName::ExportMessages).is_ok());
    }
}
