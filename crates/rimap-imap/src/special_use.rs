//! RFC 6154 special-use mailbox attributes and per-account resolution.
//!
//! Special-use attributes (`\Drafts`, `\Sent`, `\Trash`, `\Junk`,
//! `\Archive`, `\All`, `\Flagged`) identify a mailbox's role without
//! relying on server-specific naming conventions. Gmail's `[Gmail]/Drafts`,
//! Proton's `Drafts`, and Dovecot's `Drafts` all carry `\Drafts`; clients
//! can target "the drafts folder" without hardcoding a name per server.

use async_imap::types::NameAttribute;

/// RFC 6154 special-use attribute, plus the pseudo-attribute for
/// unrecognized `\Sent`/`\Drafts`-style extension strings that some
/// servers emit instead of the structured enum variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SpecialUse {
    /// `\Drafts` — the mailbox where draft messages live.
    Drafts,
    /// `\Sent` — the mailbox where copies of outgoing messages live.
    Sent,
    /// `\Trash` — the mailbox for deleted messages.
    Trash,
    /// `\Junk` — the mailbox for spam.
    Junk,
    /// `\Archive` — the archive mailbox.
    Archive,
    /// `\All` — aggregate view (Gmail's "All Mail").
    All,
    /// `\Flagged` — aggregate view of flagged/starred messages.
    Flagged,
}

/// Classify the first recognized RFC 6154 special-use marker in the
/// attribute list. Returns `None` if no special-use marker is present.
///
/// Checks both the structured `NameAttribute` variants and
/// `Extension("\\Drafts")`-style strings (case-insensitive). Some
/// servers are known to report RFC 6154 attributes as raw extension
/// strings rather than the structured variant; the extension arm keeps
/// us compatible with that shape without requiring a protocol upgrade.
#[must_use]
pub fn classify_special_use(attrs: &[NameAttribute<'_>]) -> Option<SpecialUse> {
    attrs.iter().find_map(match_variant)
}

fn match_variant(attr: &NameAttribute<'_>) -> Option<SpecialUse> {
    match attr {
        NameAttribute::Drafts => Some(SpecialUse::Drafts),
        NameAttribute::Sent => Some(SpecialUse::Sent),
        NameAttribute::Trash => Some(SpecialUse::Trash),
        NameAttribute::Junk => Some(SpecialUse::Junk),
        NameAttribute::Archive => Some(SpecialUse::Archive),
        NameAttribute::All => Some(SpecialUse::All),
        NameAttribute::Flagged => Some(SpecialUse::Flagged),
        NameAttribute::Extension(ext) => match_extension(ext),
        _ => None,
    }
}

fn match_extension(ext: &str) -> Option<SpecialUse> {
    if ext.eq_ignore_ascii_case("\\Drafts") {
        Some(SpecialUse::Drafts)
    } else if ext.eq_ignore_ascii_case("\\Sent") {
        Some(SpecialUse::Sent)
    } else if ext.eq_ignore_ascii_case("\\Trash") {
        Some(SpecialUse::Trash)
    } else if ext.eq_ignore_ascii_case("\\Junk") {
        Some(SpecialUse::Junk)
    } else if ext.eq_ignore_ascii_case("\\Archive") {
        Some(SpecialUse::Archive)
    } else if ext.eq_ignore_ascii_case("\\All") {
        Some(SpecialUse::All)
    } else if ext.eq_ignore_ascii_case("\\Flagged") {
        Some(SpecialUse::Flagged)
    } else {
        None
    }
}

use crate::types::Folder;

/// Resolved special-use → folder-name map for a single account.
///
/// Built once at account boot from the `LIST` response. Lookup is
/// infallible; callers that want a "give me drafts or fall back" pattern
/// can combine the returned `Option<&str>` with `.unwrap_or("Drafts")` to
/// supply a literal fallback string.
#[derive(Debug, Clone, Default)]
pub struct SpecialUseMap {
    drafts: Option<String>,
    sent: Option<String>,
    trash: Option<String>,
    junk: Option<String>,
    archive: Option<String>,
    all: Option<String>,
    flagged: Option<String>,
}

impl SpecialUseMap {
    /// Build the map from the folders returned by one `LIST` call.
    /// When multiple folders claim the same special-use (pathological),
    /// the first one wins — matches the classifier's "first match"
    /// semantics.
    #[must_use]
    pub fn from_folders(folders: &[Folder]) -> Self {
        let mut out = Self::default();
        for folder in folders {
            let Some(su) = folder.special_use else {
                continue;
            };
            let slot = match su {
                SpecialUse::Drafts => &mut out.drafts,
                SpecialUse::Sent => &mut out.sent,
                SpecialUse::Trash => &mut out.trash,
                SpecialUse::Junk => &mut out.junk,
                SpecialUse::Archive => &mut out.archive,
                SpecialUse::All => &mut out.all,
                SpecialUse::Flagged => &mut out.flagged,
            };
            if slot.is_none() {
                *slot = Some(folder.name.clone());
            }
        }
        out
    }

    /// Discovered `\Drafts` folder name, or `None` if the server did not
    /// report one.
    #[must_use]
    pub fn drafts(&self) -> Option<&str> {
        self.drafts.as_deref()
    }

    /// Discovered `\Sent` folder name, or `None`.
    #[must_use]
    pub fn sent(&self) -> Option<&str> {
        self.sent.as_deref()
    }

    /// Discovered `\Trash` folder name, or `None`.
    #[must_use]
    pub fn trash(&self) -> Option<&str> {
        self.trash.as_deref()
    }

    /// Discovered `\Junk` folder name, or `None`.
    #[must_use]
    pub fn junk(&self) -> Option<&str> {
        self.junk.as_deref()
    }

    /// Discovered `\Archive` folder name, or `None`.
    #[must_use]
    pub fn archive(&self) -> Option<&str> {
        self.archive.as_deref()
    }

    /// Discovered `\All` folder name (e.g. Gmail "All Mail"), or `None`.
    #[must_use]
    pub fn all(&self) -> Option<&str> {
        self.all.as_deref()
    }

    /// Discovered `\Flagged` folder name (e.g. Gmail "Starred"), or `None`.
    #[must_use]
    pub fn flagged(&self) -> Option<&str> {
        self.flagged.as_deref()
    }

    /// All discovered folder names, in no particular order.
    #[must_use]
    pub fn all_discovered(&self) -> Vec<String> {
        [
            &self.drafts,
            &self.sent,
            &self.trash,
            &self.junk,
            &self.archive,
            &self.all,
            &self.flagged,
        ]
        .into_iter()
        .filter_map(Clone::clone)
        .collect()
    }
}

#[cfg(test)]
mod map_tests {
    use super::*;
    use crate::types::Folder;

    fn folder(name: &str, special: Option<SpecialUse>) -> Folder {
        Folder {
            name: name.to_string(),
            attributes: Vec::new(),
            delimiter: Some('/'),
            special_use: special,
        }
    }

    #[test]
    fn from_folders_gmail_layout_maps_drafts_to_gmail_subtree() {
        let folders = vec![
            folder("INBOX", None),
            folder("Drafts", None),
            folder("[Gmail]/Drafts", Some(SpecialUse::Drafts)),
            folder("[Gmail]/Sent Mail", Some(SpecialUse::Sent)),
            folder("[Gmail]/Trash", Some(SpecialUse::Trash)),
            folder("[Gmail]/Spam", Some(SpecialUse::Junk)),
            folder("[Gmail]/All Mail", Some(SpecialUse::All)),
        ];
        let map = SpecialUseMap::from_folders(&folders);
        assert_eq!(map.drafts(), Some("[Gmail]/Drafts"));
        assert_eq!(map.sent(), Some("[Gmail]/Sent Mail"));
        assert_eq!(map.trash(), Some("[Gmail]/Trash"));
    }

    #[test]
    fn from_folders_first_claimant_wins_on_conflict() {
        let folders = vec![
            folder("Drafts", Some(SpecialUse::Drafts)),
            folder("Other Drafts", Some(SpecialUse::Drafts)),
        ];
        let map = SpecialUseMap::from_folders(&folders);
        assert_eq!(map.drafts(), Some("Drafts"));
    }

    #[test]
    fn from_folders_no_special_use_yields_empty_map() {
        let folders = vec![folder("INBOX", None), folder("Drafts", None)];
        let map = SpecialUseMap::from_folders(&folders);
        assert_eq!(map.drafts(), None);
        assert!(map.all_discovered().is_empty());
    }

    #[test]
    fn all_discovered_collects_every_slot() {
        // All seven RFC 6154 slots must round-trip through `all_discovered`
        // so a future refactor to the slot iteration can't silently drop
        // one of the less-commonly-used slots (Junk, Archive, All, Flagged).
        let folders = vec![
            folder("D", Some(SpecialUse::Drafts)),
            folder("S", Some(SpecialUse::Sent)),
            folder("T", Some(SpecialUse::Trash)),
            folder("J", Some(SpecialUse::Junk)),
            folder("AR", Some(SpecialUse::Archive)),
            folder("AL", Some(SpecialUse::All)),
            folder("F", Some(SpecialUse::Flagged)),
        ];
        let map = SpecialUseMap::from_folders(&folders);
        let mut discovered = map.all_discovered();
        discovered.sort();
        assert_eq!(discovered, vec!["AL", "AR", "D", "F", "J", "S", "T"]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_matches_each_rfc6154_variant() {
        for (attr, expected) in [
            (NameAttribute::Drafts, SpecialUse::Drafts),
            (NameAttribute::Sent, SpecialUse::Sent),
            (NameAttribute::Trash, SpecialUse::Trash),
            (NameAttribute::Junk, SpecialUse::Junk),
            (NameAttribute::Archive, SpecialUse::Archive),
            (NameAttribute::All, SpecialUse::All),
            (NameAttribute::Flagged, SpecialUse::Flagged),
        ] {
            let attrs = [attr.clone()];
            assert_eq!(classify_special_use(&attrs), Some(expected));
        }
    }

    #[test]
    fn classify_matches_extension_strings_case_insensitive() {
        let attrs = [NameAttribute::Extension("\\drafts".into())];
        assert_eq!(classify_special_use(&attrs), Some(SpecialUse::Drafts));

        let attrs = [NameAttribute::Extension("\\SENT".into())];
        assert_eq!(classify_special_use(&attrs), Some(SpecialUse::Sent));
    }

    #[test]
    fn classify_returns_none_for_unrelated_attributes() {
        let attrs = [
            NameAttribute::Unmarked,
            NameAttribute::Extension("\\HasNoChildren".into()),
        ];
        assert_eq!(classify_special_use(&attrs), None);
    }

    #[test]
    fn classify_returns_first_match_when_multiple_present() {
        // \Drafts + \Sent on the same mailbox is pathological but possible
        // in misconfigured servers; we take the first match in iteration
        // order rather than erroring, to stay useful.
        let attrs = [NameAttribute::Drafts, NameAttribute::Sent];
        assert_eq!(classify_special_use(&attrs), Some(SpecialUse::Drafts));
    }

    #[test]
    fn classify_empty_attribute_list_returns_none() {
        assert_eq!(classify_special_use(&[]), None);
    }
}
