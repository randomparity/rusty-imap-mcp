//! Canonical structurally-validated IMAP folder name.
//!
//! The single workspace authority on what shapes of folder name are
//! acceptable from a client. Both `rimap-authz::FolderGuard` (APPEND
//! and folder-mutation paths) and `rimap-imap::ops` (CREATE / RENAME
//! / DELETE / STORE / etc.) delegate to [`FolderName::new`]. Each
//! crate maps [`FolderNameError`] into its own error type via `From`.
//!
//! Server-returned folder names (LIST responses) use a separate,
//! intentionally-permissive validator in `rimap-imap::ops::folders`
//! because rimap-server sanitizes them at the response boundary via
//! `rimap_content::unicode::sanitize`, which surfaces bidi /
//! zero-width chars as warnings rather than dropping the folder.

use std::fmt;

use thiserror::Error;

/// Why a folder name failed [`FolderName::new`].
///
/// Each variant carries the rejected name and a stable kind tag so
/// downstream error types can map to their own error variants without
/// pattern-matching on prose.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("invalid folder name: {reason}")]
#[non_exhaustive]
pub struct FolderNameError {
    /// Human-readable rejection reason. Stable enough for direct
    /// inclusion in user-facing error messages.
    pub reason: &'static str,
}

impl FolderNameError {
    fn new(reason: &'static str) -> Self {
        Self { reason }
    }
}

/// A structurally validated IMAP folder name.
///
/// Invariants enforced by [`FolderName::new`]:
/// - non-empty and not whitespace-only
/// - at most 255 bytes
/// - no NUL bytes
/// - no C0/C1 control characters (`0x01`–`0x1F` plus `0x7F`)
/// - no path traversal: no segment is exactly `.` or `..` when split
///   on `/` (the IMAP hierarchy delimiter)
/// - no bidi control codepoints (U+202A–U+202E, U+2066–U+2069)
/// - no zero-width or BOM codepoints (U+200B, U+200C, U+200D, U+2060,
///   U+FEFF)
/// - no Unicode Tag Characters (U+E0000–U+E007F)
///
/// # Scope
///
/// **Delimiter.** Traversal splits on `/` only — the common hierarchy
/// delimiter used by Gmail, Proton Bridge, and every pinned target.
/// Servers that use `.` as the hierarchy delimiter (some Cyrus
/// deployments) are out of the pinned target set; if support is added,
/// revisit the traversal check to split on the server-advertised
/// delimiter.
///
/// **Modified UTF-7.** This validator operates on raw wire bytes and
/// does NOT decode RFC 3501 Modified UTF-7 before applying the
/// Unicode checks. `FolderGuard::check_protected` decodes mUTF-7 as
/// part of its case-insensitive compare against the protected list;
/// the two layers have different responsibilities. A name like
/// `"&AP8-"` passes `FolderName::new` as pure ASCII (and is fine to
/// pass to IMAP) but its decoded form (`"\u{00FF}"`) is only seen by
/// the guard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderName(String);

impl FolderName {
    /// Validate `raw` and wrap it.
    ///
    /// # Errors
    /// Returns [`FolderNameError`] if any structural invariant is
    /// violated. The stable `reason` field is suitable for direct
    /// inclusion in user-facing errors.
    pub fn new(raw: &str) -> Result<Self, FolderNameError> {
        validate(raw)?;
        Ok(Self(raw.to_string()))
    }

    /// Borrow the inner string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for FolderName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Run all structural checks on a raw folder name.
fn validate(raw: &str) -> Result<(), FolderNameError> {
    if raw.is_empty() {
        return Err(FolderNameError::new("folder name must not be empty"));
    }
    if raw.trim().is_empty() {
        return Err(FolderNameError::new(
            "folder name must not be whitespace-only",
        ));
    }
    if raw.len() > 255 {
        return Err(FolderNameError::new("folder name exceeds 255-byte limit"));
    }
    for byte in raw.bytes() {
        if byte == 0x00 {
            return Err(FolderNameError::new("folder name contains NUL byte"));
        }
        // Reject all C0 control characters (0x01–0x1F) and DEL (0x7F).
        // Unlike the prior `rimap-authz` implementation, TAB (0x09) is
        // included in the rejection set: TAB has no legitimate use in
        // an IMAP folder name and previously slipped through here while
        // being rejected by `rimap-imap`'s parallel validator.
        let is_control = (0x01..=0x1F).contains(&byte) || byte == 0x7F;
        if is_control {
            return Err(FolderNameError::new(
                "folder name contains control character",
            ));
        }
    }
    // Delimiter-aware traversal check: split on `/` and reject any
    // segment that is exactly `.` or `..`. Substring-based checks
    // would falsely reject legitimate names like `Receipts..2024`.
    for segment in raw.split('/') {
        if segment == "." || segment == ".." {
            return Err(FolderNameError::new(
                "folder name contains path traversal segment",
            ));
        }
    }
    // Reject bidi control characters and zero-width / BOM codepoints.
    // These have no legitimate use in client-supplied folder names and
    // are a common spoofing vector (e.g., `INBOX\u{202e}txt.exe`).
    for c in raw.chars() {
        if is_rejected_display_codepoint(c) {
            return Err(FolderNameError::new(
                "folder name contains disallowed Unicode character",
            ));
        }
    }
    Ok(())
}

/// Returns `true` for codepoints that `rimap-content::unicode` would
/// silently strip from a display string: bidi controls (U+202A–U+202E,
/// U+2066–U+2069), zero-width and formatting codepoints (U+200B,
/// U+200C, U+200D, U+2060, U+FEFF), and the Unicode Tag Characters
/// block (U+E0000–U+E007F, used for invisible instruction smuggling
/// and prompt-injection payloads).
///
/// Stays in lock-step with the `ZERO_WIDTH` + `BIDI_OVERRIDE` tables
/// and the `is_unicode_tag` check in `rimap-content::unicode::
/// filter_codepoints` so a codepoint cannot slip through here
/// (folder-name validation) that the response-boundary sanitizer
/// would strip. U+2060 WORD JOINER and the Tag Characters block were
/// silently missing from earlier cuts; both are now covered.
///
/// Pulled out as a free function so the property tests can reuse the
/// same predicate when generating positive / negative cases.
///
/// `matches!` is used intentionally here: every arm is a single
/// codepoint or a non-overlapping range with no binding, so the macro
/// is the shortest form that avoids a wildcard arm (the workspace
/// style forbids `_ =>` in normal `match` expressions). Adding a new
/// codepoint is a single-line edit either way.
#[must_use]
pub fn is_rejected_display_codepoint(c: char) -> bool {
    matches!(
        c,
        '\u{202a}'..='\u{202e}'    // bidi embedding / override
        | '\u{2066}'..='\u{2069}'  // bidi isolate
        | '\u{200b}'               // zero-width space
        | '\u{200c}'               // zero-width non-joiner
        | '\u{200d}'               // zero-width joiner
        | '\u{2060}'               // word joiner
        | '\u{feff}'               // byte-order mark
        | '\u{e0000}'..='\u{e007f}' // Unicode Tag Characters block
    )
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::{FolderName, FolderNameError};

    #[test]
    fn accepts_inbox() {
        assert!(FolderName::new("INBOX").is_ok());
        assert_eq!(FolderName::new("INBOX").unwrap().as_str(), "INBOX");
    }

    #[test]
    fn accepts_hierarchy_with_slash() {
        assert!(FolderName::new("Work/Projects").is_ok());
    }

    #[test]
    fn accepts_legitimate_dots_in_segment() {
        // Substring-based traversal checks would falsely reject these.
        assert!(FolderName::new("Mail/Receipts..2024").is_ok());
        assert!(FolderName::new("my.folder").is_ok());
    }

    #[test]
    fn rejects_empty() {
        let err = FolderName::new("").unwrap_err();
        assert!(err.reason.contains("empty"));
    }

    #[test]
    fn rejects_whitespace_only() {
        assert!(FolderName::new("   ").is_err());
        assert!(FolderName::new("\t").is_err());
    }

    #[test]
    fn rejects_over_255_bytes() {
        let long = "a".repeat(256);
        assert!(FolderName::new(&long).is_err());
        // Exactly 255 is the boundary and is accepted.
        let boundary = "a".repeat(255);
        assert!(FolderName::new(&boundary).is_ok());
    }

    #[test]
    fn rejects_nul_byte() {
        assert!(FolderName::new("bad\0name").is_err());
    }

    #[test]
    fn rejects_c0_controls_including_tab() {
        // TAB (0x09) used to slip through rimap-authz; closing that gap
        // is part of the consolidation.
        for bad in ["bad\tname", "bad\rname", "bad\nname", "bad\x01name"] {
            let err = FolderName::new(bad).unwrap_err();
            assert!(err.reason.contains("control"));
        }
    }

    #[test]
    fn rejects_del_0x7f() {
        assert!(FolderName::new("bad\x7fname").is_err());
    }

    #[test]
    fn rejects_double_dot_segment() {
        assert!(FolderName::new("../escape").is_err());
        assert!(FolderName::new("a/../b").is_err());
        assert!(FolderName::new("a/..").is_err());
    }

    #[test]
    fn rejects_single_dot_segment() {
        assert!(FolderName::new("./a").is_err());
        assert!(FolderName::new("a/./b").is_err());
        assert!(FolderName::new("a/.").is_err());
    }

    #[test]
    fn rejects_bidi_override() {
        // U+202E RIGHT-TO-LEFT OVERRIDE — the prototypical spoof.
        assert!(FolderName::new("folder\u{202e}txt").is_err());
    }

    #[test]
    fn rejects_zero_width_joiner() {
        // U+200D ZERO WIDTH JOINER.
        assert!(FolderName::new("evil\u{200d}folder").is_err());
    }

    #[test]
    fn rejects_byte_order_mark() {
        assert!(FolderName::new("\u{feff}INBOX").is_err());
    }

    #[test]
    fn rejects_word_joiner() {
        // U+2060 WORD JOINER — stays in sync with
        // rimap-content::unicode's ZERO_WIDTH table. The first cut of
        // this validator silently allowed it while the response-boundary
        // sanitizer stripped it.
        assert!(FolderName::new("evil\u{2060}folder").is_err());
    }

    #[test]
    fn rejects_unicode_tag_characters() {
        // U+E0041 TAG LATIN CAPITAL LETTER A — used for invisible
        // instruction smuggling and prompt-injection payloads. Both
        // endpoints of the range and a middle codepoint are tested
        // to pin the full U+E0000..=U+E007F span.
        assert!(FolderName::new("Work\u{e0041}").is_err());
        assert!(FolderName::new("\u{e0000}").is_err());
        assert!(FolderName::new("end\u{e007f}").is_err());
        // Boundary: U+E0080 is outside the Tag block and must pass
        // every other check (Tag-block-only behavior).
        assert!(FolderName::new("just-outside-\u{e0080}").is_ok());
    }

    #[test]
    fn folder_name_error_display_includes_reason() {
        let err = FolderNameError::new("custom reason");
        assert_eq!(err.to_string(), "invalid folder name: custom reason");
    }
}

#[cfg(test)]
mod proptests {
    //! Property tests pinning the canonical validator's behavior.
    //!
    //! These exist to prevent the historical drift where two parallel
    //! validators (`rimap-authz::FolderName::new` and
    //! `rimap-imap::validate_folder_name`) accumulated different
    //! character policies. Now that both crates delegate to
    //! [`super::FolderName::new`], the property suite locks the
    //! reference implementation against accidental relaxation.

    use proptest::prelude::*;

    use super::{FolderName, is_rejected_display_codepoint};

    /// Reference implementation: an independent re-derivation of the
    /// rules from the [`super::FolderName::new`] doc comment, used to
    /// cross-check the production validator. If both definitions get
    /// quietly relaxed in lock-step the test would not catch it, but
    /// the diff between them will catch any drift introduced by
    /// editing only one site.
    fn reference_is_valid(s: &str) -> bool {
        if s.is_empty() {
            return false;
        }
        if s.trim().is_empty() {
            return false;
        }
        if s.len() > 255 {
            return false;
        }
        for b in s.bytes() {
            if b == 0x00 {
                return false;
            }
            if (0x01..=0x1F).contains(&b) || b == 0x7F {
                return false;
            }
        }
        for segment in s.split('/') {
            if segment == "." || segment == ".." {
                return false;
            }
        }
        for c in s.chars() {
            if is_rejected_display_codepoint(c) {
                return false;
            }
        }
        true
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 4096,
            max_shrink_iters: 10_000,
            ..ProptestConfig::default()
        })]

        /// `FolderName::new` agrees with the reference predicate over
        /// arbitrary unicode strings. Catches any silent relaxation
        /// of either rule set.
        #[test]
        fn agrees_with_reference(s in any::<String>()) {
            let actual = FolderName::new(&s).is_ok();
            let expected = reference_is_valid(&s);
            prop_assert_eq!(
                actual,
                expected,
                "FolderName::new({:?}) -> {} but reference -> {}",
                s,
                actual,
                expected,
            );
        }

        /// Boundary check: any name in the strict-ASCII letters/digits
        /// alphabet between 1 and 255 bytes is always accepted. Pins
        /// the happy path against accidental over-tightening.
        #[test]
        fn ascii_letters_digits_always_valid(s in r"[A-Za-z0-9]{1,255}") {
            prop_assert!(FolderName::new(&s).is_ok(), "{s:?} should be valid");
        }

        /// Any string containing a byte in the C0 control range is
        /// rejected, regardless of where in the string it appears.
        #[test]
        fn any_c0_byte_is_rejected(prefix in r"[A-Za-z]{0,10}", suffix in r"[A-Za-z]{0,10}", b in 0x00u8..=0x1F) {
            let s = format!("{prefix}{}{suffix}", char::from(b));
            prop_assert!(FolderName::new(&s).is_err());
        }

        /// Every codepoint in the Unicode Tag Characters block
        /// (U+E0000..=U+E007F) is rejected, independent of the shared
        /// [`is_rejected_display_codepoint`] predicate — if the predicate is
        /// silently edited to drop the Tag range, this test fails.
        #[test]
        fn any_unicode_tag_codepoint_is_rejected(
            prefix in r"[A-Za-z]{0,10}",
            suffix in r"[A-Za-z]{0,10}",
            cp in 0xE0000u32..=0xE007F,
        ) {
            let Some(tag_char) = char::from_u32(cp) else {
                return Ok(());
            };
            let s = format!("{prefix}{tag_char}{suffix}");
            prop_assert!(
                FolderName::new(&s).is_err(),
                "U+{cp:04X} must be rejected but {s:?} was accepted",
            );
        }
    }
}
