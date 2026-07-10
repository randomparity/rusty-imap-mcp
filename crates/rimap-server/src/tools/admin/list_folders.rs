//! `list_folders` tool handler.

use std::fmt::Write as _;

use rimap_content::output::SecurityWarning;
use serde::Serialize;

use crate::boot::registry::AccountState;
use crate::mcp::response::ToolResponse;

const MAX_FOLDER_NAME_BYTES: usize = 1024;

/// Escape a folder name into a display-safe ASCII string. Each
/// non-ASCII-printable codepoint becomes `\u{H..}` (one or more
/// lowercase hex digits); ASCII printables in 0x20..0x7E (excluding
/// backslash) are emitted literally, and backslash is always escaped.
///
/// This exists to surface the *raw bytes the server sent* as inert
/// ASCII for diagnostics, so bidi / zero-width / Unicode Tag codepoints
/// are neutralized rather than embedded live under the trusted `meta`
/// envelope (#98). It is NOT a round-trip encoding: no server input
/// path decodes it, and folders whose names required sanitization are
/// not addressable by folder-input tools (see [`FolderEntry::name_wire`]).
fn escape_wire_name(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars() {
        if (c as u32) >= 0x20 && (c as u32) < 0x7f && c != '\\' {
            out.push(c);
        } else {
            let _ = write!(out, "\\u{{{:x}}}", c as u32);
        }
    }
    out
}

/// Sanitize a single `Folder` entry, returning the cleaned name, optional
/// wire name, and flag list while appending any security warnings to
/// `warnings`.
fn sanitize_folder_entry(
    folder: &rimap_imap::types::Folder,
    warnings: &mut Vec<SecurityWarning>,
) -> (String, Option<String>, Vec<String>) {
    let (clean_name, name_warnings) = rimap_content::sanitize(
        folder.name.as_bytes(),
        None,
        MAX_FOLDER_NAME_BYTES,
        "folder.name",
    );
    // NFKC normalization, bidi stripping, or any sanitize transform counts
    // as a "name change" — the server owns the canonical wire bytes, so
    // the client must round-trip `name_wire` for subsequent commands.
    //
    // Cap raw input before escape. A hostile IMAP server can send a
    // multi-MB mailbox name; `clean_name` is already capped by
    // sanitize, but `folder.name` is not. Without this cap a 100 MB
    // name with bidi codepoints could force a ~270 MB allocation in
    // `escape_wire_name` (MCP-PRIV-04 / MAIL-DOS-04).
    let name_wire = if clean_name == folder.name {
        None
    } else {
        let capped = rimap_content::truncate_graphemes(&folder.name, MAX_FOLDER_NAME_BYTES * 4);
        Some(escape_wire_name(&capped))
    };
    warnings.extend(name_warnings);

    let flags: Vec<String> = folder
        .attributes
        .iter()
        .map(|attr| {
            let raw = attr.as_wire_str();
            let (clean, flag_warnings) =
                rimap_content::sanitize(raw.as_bytes(), None, MAX_FOLDER_NAME_BYTES, "folder.flag");
            warnings.extend(flag_warnings);
            clean
        })
        .collect();

    (clean_name, name_wire, flags)
}

/// A single folder entry in a `list_folders` response.
#[derive(Debug, Serialize, schemars::JsonSchema)]
#[non_exhaustive]
pub struct FolderEntry {
    /// Sanitized, display-safe folder name. Bidi / zero-width / Unicode
    /// Tag codepoints are stripped before this reaches the client.
    pub name: String,
    /// Display / diagnostic-only representation of the raw bytes the
    /// server sent, encoded as `\u{H..}` Unicode escape sequences and
    /// populated only when `name` differs from those bytes (i.e. the
    /// sanitizer changed something). This is NOT an input token: no
    /// tool decodes the escape, so passing it back verbatim will not
    /// select the folder. A folder whose name required sanitization
    /// (bidi / zero-width / control / Unicode Tag codepoints) is not
    /// addressable by folder-input tools — the input validator rejects
    /// those codepoints by design. Use this field to see what the
    /// server sent; there is no supported way to operate on such a
    /// folder. When `name_wire` is absent, `name` is the exact wire
    /// name and is safe to pass to SELECT / STATUS / MOVE / FETCH.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name_wire: Option<String>,
    /// Hierarchy delimiter character reported by the server.
    pub delimiter: Option<char>,
    /// IMAP folder attribute flags (e.g. `"\\HasNoChildren"`).
    pub flags: Vec<String>,
    /// Number of messages in the folder, if available.
    pub exists: Option<u32>,
    /// Number of unseen messages, if available.
    pub unseen: Option<u32>,
    /// UID validity value for the folder, if available.
    pub uid_validity: Option<u32>,
}

/// Trusted metadata for a `list_folders` response.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct ListFoldersMeta {
    /// All folders returned by the server.
    pub folders: Vec<FolderEntry>,
    /// Security warnings accumulated while sanitizing folder names and
    /// flags against bidi overrides, zero-width characters, and C0/C1
    /// control bytes (#98). Serialized only when non-empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub security_warnings: Vec<SecurityWarning>,
}

/// Sanitize a list of `Folder` entries for inclusion in the `list_folders`
/// MCP response. Returns the sanitized `FolderEntry` list and the
/// accumulated security warnings.
///
/// Folder names and flags are run through `rimap_content::sanitize`
/// so server-controlled bidi overrides, zero-width characters, and C0/C1
/// stripping are surfaced as structured warnings rather than riding
/// unfiltered under the trusted `meta` envelope (#98).
#[cfg(test)]
pub(crate) fn sanitize_folder_entries(
    folders: Vec<rimap_imap::types::Folder>,
) -> (Vec<FolderEntry>, Vec<SecurityWarning>) {
    let mut entries = Vec::with_capacity(folders.len());
    let mut warnings: Vec<SecurityWarning> = Vec::new();

    for folder in folders {
        let (clean_name, name_wire, flags) = sanitize_folder_entry(&folder, &mut warnings);

        entries.push(FolderEntry {
            name: clean_name,
            name_wire,
            delimiter: folder.delimiter,
            flags,
            exists: None,
            unseen: None,
            uid_validity: None,
        });
    }

    (entries, warnings)
}

/// Execute the `list_folders` tool.
///
/// Non-selectable folders (RFC 3501 `\Noselect` namespace parents such as
/// Gmail's `[Gmail]`, RFC 5258 `\NonExistent` entries) are returned with
/// `exists`/`unseen`/`uid_validity` left as `None`.
///
/// # Errors
///
/// Returns `RimapError::Imap { ... }` if the server rejects LIST or any
/// of the per-folder STATUS calls against a selectable folder. The
/// upstream `DispatchGuard::pre_dispatch` gate may also return
/// `PostureDenied`.
pub async fn handle(
    account: &AccountState,
) -> Result<ToolResponse<ListFoldersMeta>, rimap_core::RimapError> {
    let pairs = account.imap.list_folders_with_status("*").await?;

    let mut entries = Vec::with_capacity(pairs.len());
    let mut warnings: Vec<SecurityWarning> = Vec::new();

    for (folder, status) in pairs {
        let (clean_name, name_wire, flags) = sanitize_folder_entry(&folder, &mut warnings);

        entries.push(FolderEntry {
            name: clean_name,
            name_wire,
            delimiter: folder.delimiter,
            flags,
            exists: status.as_ref().and_then(|s| s.messages),
            unseen: status.as_ref().and_then(|s| s.unseen),
            uid_validity: status.as_ref().and_then(|s| s.uid_validity),
        });
    }

    Ok(ToolResponse::meta_only(ListFoldersMeta {
        folders: entries,
        security_warnings: warnings,
    }))
}

#[cfg(test)]
mod tests {
    use super::sanitize_folder_entries;
    use crate::tools::validation::validate_folder_input;
    use rimap_imap::types::{Folder, FolderAttribute};

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "test assertion — None is a hard failure"
    )]
    fn name_wire_is_display_only_not_a_valid_folder_input() {
        // Contract lock for #462: `name_wire` is a display/diagnostic
        // representation of the raw wire bytes, NOT a round-trip input.
        // A sanitizer-modified name populates `name_wire`, but the raw
        // name it stands for carries a disallowed codepoint (U+202E) that
        // `validate_folder_input` — the sole folder-input validator —
        // rejects. There is therefore no valid input path that addresses
        // this folder, which is exactly what the field doc must state.
        let raw = "Inbox\u{202e}gnilleS";
        let folders = vec![Folder {
            name: raw.to_string(),
            attributes: vec![FolderAttribute::HasNoChildren],
            delimiter: Some('/'),
            special_use: None,
        }];
        let (entries, _warnings) = sanitize_folder_entries(folders);
        assert_eq!(entries.len(), 1);

        let name_wire = entries[0]
            .name_wire
            .as_deref()
            .expect("sanitizer-modified name should populate name_wire");

        // The raw folder name is rejected on input by design.
        assert!(
            validate_folder_input("folder", raw).is_err(),
            "raw sanitized folder name must be rejected by the input validator",
        );
        // The escaped wire form is not a verbatim round-trip token: it is
        // a distinct ASCII string, not the raw name the server holds.
        assert_ne!(
            name_wire, raw,
            "name_wire must not be a verbatim copy of the raw folder name",
        );
    }

    #[test]
    fn sanitizes_bidi_in_folder_name_and_emits_warning() {
        let folders = vec![Folder {
            name: "Inbox\u{202e}gnilleS".to_string(),
            attributes: vec![FolderAttribute::HasNoChildren],
            delimiter: Some('/'),
            special_use: None,
        }];
        let (entries, warnings) = sanitize_folder_entries(folders);
        assert_eq!(entries.len(), 1);
        assert!(
            !entries[0].name.contains('\u{202e}'),
            "sanitized name should not contain U+202E, got: {:?}",
            entries[0].name,
        );
        assert!(
            !warnings.is_empty(),
            "sanitize should have produced a bidi-stripped warning",
        );
    }

    #[test]
    fn no_warnings_for_clean_folder_name() {
        let folders = vec![Folder {
            name: "INBOX".to_string(),
            attributes: vec![FolderAttribute::HasNoChildren],
            delimiter: Some('/'),
            special_use: None,
        }];
        let (entries, warnings) = sanitize_folder_entries(folders);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "INBOX");
        assert!(
            warnings.is_empty(),
            "clean name should produce no warnings, got: {warnings:?}"
        );
    }

    #[test]
    fn escape_wire_name_passes_ascii_printables_literally() {
        assert_eq!(super::escape_wire_name("INBOX/Sent"), "INBOX/Sent");
    }

    #[test]
    fn escape_wire_name_escapes_backslash() {
        assert_eq!(
            super::escape_wire_name("Archive\\2024"),
            "Archive\\u{5c}2024"
        );
    }

    #[test]
    fn escape_wire_name_escapes_supplementary_codepoint() {
        // U+1F4E7 ENVELOPE — supplementary plane. Confirms variable-width
        // hex output, not fixed four-digit HHHH.
        assert_eq!(super::escape_wire_name("\u{1f4e7}"), "\\u{1f4e7}");
    }

    #[test]
    fn wire_name_preserved_when_sanitizer_modifies_name() {
        let folders = vec![Folder {
            name: "Inbox\u{202e}gnilleS".to_string(),
            attributes: vec![FolderAttribute::HasNoChildren],
            delimiter: Some('/'),
            special_use: None,
        }];
        let (entries, _warnings) = sanitize_folder_entries(folders);
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].name_wire.as_deref(),
            Some("Inbox\\u{202e}gnilleS"),
            "wire name should preserve the original codepoints as escapes",
        );
    }

    #[test]
    fn wire_name_absent_for_clean_folder_name() {
        let folders = vec![Folder {
            name: "INBOX".to_string(),
            attributes: vec![FolderAttribute::HasNoChildren],
            delimiter: Some('/'),
            special_use: None,
        }];
        let (entries, _warnings) = sanitize_folder_entries(folders);
        assert_eq!(entries.len(), 1);
        assert!(
            entries[0].name_wire.is_none(),
            "clean name should have no wire-name field, got: {:?}",
            entries[0].name_wire,
        );
    }

    #[test]
    #[expect(
        clippy::expect_used,
        reason = "test assertion — None is a hard failure"
    )]
    fn name_wire_is_bounded_for_oversized_raw_name() {
        // Construct a 100 KiB folder name. Sanitize will truncate the
        // display form to MAX_FOLDER_NAME_BYTES (1024 bytes), so the
        // inequality branch fires and `escape_wire_name` runs on whatever
        // raw slice we forward. The cap in `sanitize_folder_entry` bounds
        // that input to at most MAX_FOLDER_NAME_BYTES * 4 bytes of raw
        // input, which at worst-case ~10x expansion produces a bounded
        // wire name.
        let oversized: String = "A\u{202e}".repeat(20_000); // ~80 KB
        let folders = vec![Folder {
            name: oversized,
            attributes: vec![FolderAttribute::HasNoChildren],
            delimiter: Some('/'),
            special_use: None,
        }];
        let (entries, _warnings) = sanitize_folder_entries(folders);
        assert_eq!(entries.len(), 1);
        // Worst-case cap: 4 * MAX_FOLDER_NAME_BYTES raw bytes, each
        // expanding to at most ~10 chars in the escape, plus a small
        // margin for format overhead.
        let wire = entries[0]
            .name_wire
            .as_ref()
            .expect("sanitizer-modified name should have name_wire");
        assert!(
            wire.len() <= 50 * 1024,
            "name_wire grew to {} bytes; cap not enforced",
            wire.len(),
        );
        // Lower bound pins the `MAX_FOLDER_NAME_BYTES * 4` raw-input cap: the
        // 4-byte `A\u{202e}` unit escapes to 9 chars, so a 4096-byte cap keeps
        // ~9216 wire chars. A shrunken cap (`+ 4` → ~2313, `/ 4` → ~576) would
        // fall below this floor, so the multiplier cannot silently change.
        assert!(
            wire.len() >= 6 * 1024,
            "name_wire only {} bytes; raw-input cap truncated too aggressively",
            wire.len(),
        );
    }

    #[test]
    fn escape_wire_name_escapes_del_boundary() {
        // U+007F DEL is the exclusive upper bound of the printable range; it
        // must be escaped, not emitted literally into display-safe output.
        assert_eq!(super::escape_wire_name("\u{7f}"), "\\u{7f}");
        // U+007E ~ is the last literal printable, pinning the other side.
        assert_eq!(super::escape_wire_name("\u{7e}"), "~");
    }
}
