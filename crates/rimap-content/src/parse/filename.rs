//! Attachment filename sanitisation and double-extension detection.
//!
//! Sibling of the MIME scrubber and attachment builder; called from
//! `attachments::build_attachment_meta` and reused by the crate's
//! filename-hardening tests.

use crate::output::{SecurityWarning, WarningCode};
use crate::parse::MAX_HEADER_BYTES;
use crate::unicode;

/// File extensions that look legitimate to humans and that attackers
/// frequently pair with executable extensions to spoof document
/// attachments. Consumed by [`detect_double_extension`].
pub(super) const DOCUMENT_EXTENSIONS: &[&str] = &[
    "pdf", "doc", "docx", "xls", "xlsx", "png", "jpg", "jpeg", "gif", "txt", "csv", "rtf",
];

/// Reserved Windows filename stems (case-insensitive). Used by
/// [`sanitize_filename`]. Non-enum input means we identify membership
/// via a named slice rather than a `matches!` pattern.
pub(super) const RESERVED_WINDOWS_STEMS: &[&str] = &[
    "con", "prn", "aux", "nul", "com0", "com1", "com2", "com3", "com4", "com5", "com6", "com7",
    "com8", "com9", "lpt0", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
];

/// Extensions that mark a file as directly executable on one or more
/// mainstream operating systems; used to spot double-extension spoofs
/// when paired with a [`DOCUMENT_EXTENSIONS`] penultimate component.
pub(super) const EXECUTABLE_EXTENSIONS: &[&str] = &[
    "exe", "dll", "bat", "cmd", "ps1", "vbs", "js", "scr", "msi", "app", "dmg", "sh", "com", "pif",
    "jar", "lnk",
];

/// Sanitize a raw attachment filename for safe downstream display.
///
/// The pipeline matches the invariants the rest of `build_attachment_meta`
/// relies on: bidi-override detection, double-extension detection, the
/// shared unicode sanitizer, and `sanitize_filename` rewriting. Every
/// step that triggers a warning pushes a [`SecurityWarning`] tagged
/// with the attachment index so the caller does not need to know the
/// per-warning codes.
pub(super) fn sanitize_attachment_filename(
    name: &str,
    idx: usize,
    warnings: &mut Vec<SecurityWarning>,
) -> String {
    if contains_bidi_override(name) {
        warnings.push(SecurityWarning::at(
            WarningCode::LookalikeFilenameExtensionSpoof,
            format!("raw={name:?},contains_bidi_override=true"),
            format!("attachment[{idx}]:filename"),
        ));
    }
    let (unicode_clean, mut ws) = unicode::sanitize(
        name.as_bytes(),
        Some("utf-8"),
        MAX_HEADER_BYTES,
        &format!("attachment[{idx}]:filename"),
    );
    warnings.append(&mut ws);
    let (safe, rewritten) = sanitize_filename(&unicode_clean, idx);
    if rewritten {
        warnings.push(SecurityWarning::at(
            WarningCode::ParseAttachmentFilenameRewritten,
            format!("original={unicode_clean:?}"),
            format!("attachment[{idx}]:filename"),
        ));
    }
    if let Some((penult, final_ext)) = detect_double_extension(&safe) {
        warnings.push(SecurityWarning::at(
            WarningCode::LookalikeFilenameExtensionSpoof,
            format!(
                "raw={name:?},reason=double_extension,visible=.{penult},\
                 declared=.{penult}.{final_ext}"
            ),
            format!("attachment[{idx}]:filename"),
        ));
    }
    safe
}

/// Sanitize an attachment filename into a safe form. Returns
/// `(sanitized, rewritten)` where `rewritten` is `true` if any
/// normalization step changed the input.
///
/// Rules:
/// - Split on `/` or `\`, collapse `..` components to `_`, rejoin with `_`.
/// - Drop any NUL bytes.
/// - Trim leading and trailing `.` and ASCII whitespace.
/// - Prefix reserved Windows names (`CON`, `PRN`, `AUX`, `NUL`,
///   `COM0..9`, `LPT0..9`, case-insensitive) with `_`.
/// - Truncate to 255 bytes at a grapheme-cluster boundary.
/// - If the result is empty, fall back to `attachment_{idx}`.
pub(super) fn sanitize_filename(name: &str, idx: usize) -> (String, bool) {
    let original = name;
    let mut parts: Vec<&str> = Vec::new();
    for segment in name.split(['/', '\\']) {
        parts.push(if segment == ".." { "_" } else { segment });
    }
    let joined = parts.join("_");
    let no_nul: String = joined.chars().filter(|&c| c != '\0').collect();
    let trimmed = no_nul
        .trim_start_matches(|c: char| c == '.' || c.is_ascii_whitespace())
        .trim_end_matches(|c: char| c == '.' || c.is_ascii_whitespace())
        .to_string();
    let lowered = trimmed.to_ascii_lowercase();
    let reserved_stem = lowered.split('.').next().unwrap_or("");
    let reserved = RESERVED_WINDOWS_STEMS.contains(&reserved_stem);
    let prefixed = if reserved {
        format!("_{trimmed}")
    } else {
        trimmed
    };
    let capped = crate::unicode::truncate_graphemes(&prefixed, 255);
    let final_name = if capped.is_empty() {
        format!("attachment_{idx}")
    } else {
        capped
    };
    let rewritten = final_name != original;
    (final_name, rewritten)
}

/// Return true if `s` contains any Unicode bidi-override codepoint.
/// These characters never appear in legitimate filenames or domains;
/// their presence is a strong adversarial signal.
pub(super) fn contains_bidi_override(s: &str) -> bool {
    // Non-enum input (`char`); the set of bidi-override codepoints is closed.
    // Explicit disjunction avoids `matches!` (banned by project style) and
    // the wildcard arm that `match { pat => true, _ => false }` would need.
    s.chars().any(|c| {
        c == '\u{202A}'
            || c == '\u{202B}'
            || c == '\u{202C}'
            || c == '\u{202D}'
            || c == '\u{202E}'
            || c == '\u{2066}'
            || c == '\u{2067}'
            || c == '\u{2068}'
            || c == '\u{2069}'
    })
}

/// Detect a `.document.executable` double-extension pair (e.g.
/// `invoice.pdf.exe`). Returns `(penultimate, final)` lowercase when a
/// document extension is followed by an executable extension; otherwise
/// `None`.
pub(super) fn detect_double_extension(name: &str) -> Option<(String, String)> {
    let segments: Vec<&str> = name.split('.').collect();
    if segments.len() < 3 {
        return None;
    }
    let penultimate = segments[segments.len() - 2].to_ascii_lowercase();
    let final_ext = segments[segments.len() - 1].to_ascii_lowercase();
    if DOCUMENT_EXTENSIONS.contains(&penultimate.as_str())
        && EXECUTABLE_EXTENSIONS.contains(&final_ext.as_str())
    {
        Some((penultimate, final_ext))
    } else {
        None
    }
}

/// Return the substring after the last `.` in `filename`, if any.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "retained for future visible/declared extension comparison"
    )
)]
pub(super) fn last_extension(filename: &str) -> Option<&str> {
    filename.rsplit_once('.').map(|(_, ext)| ext)
}

#[cfg(test)]
mod filename_helper_tests {
    use super::{contains_bidi_override, detect_double_extension, sanitize_attachment_filename};
    use crate::output::{SecurityWarning, WarningCode};

    fn sanitize(name: &str) -> (String, Vec<SecurityWarning>) {
        let mut warnings = Vec::new();
        let out = sanitize_attachment_filename(name, 0, &mut warnings);
        (out, warnings)
    }

    #[test]
    fn plain_name_produces_no_warnings() {
        let (out, warnings) = sanitize("notes.txt");
        assert_eq!(out, "notes.txt");
        assert!(warnings.is_empty());
    }

    #[test]
    fn bidi_override_raises_spoof_warning() {
        // U+202E RIGHT-TO-LEFT OVERRIDE embedded before a fake extension.
        let (_, warnings) = sanitize("invoice\u{202e}fdp.exe");
        assert!(
            warnings
                .iter()
                .any(|w| w.code == WarningCode::LookalikeFilenameExtensionSpoof),
            "expected a spoof warning for bidi override",
        );
    }

    #[test]
    fn double_extension_raises_spoof_warning() {
        let (_, warnings) = sanitize("report.pdf.exe");
        assert!(
            warnings
                .iter()
                .any(|w| w.code == WarningCode::LookalikeFilenameExtensionSpoof),
            "expected a spoof warning for double extension",
        );
    }

    #[test]
    fn cleaned_double_extensions_raise_spoof_warning() {
        for name in [
            "invoice.pdf.exe ",
            "invoice.pdf.exe\t",
            "invoice.pdf.exe.",
            "invoice.pdf\u{200b}.exe",
            "invoice.pdf.\u{200d}exe",
            "invoice.PDF.EXE ",
            "invoice.PD\u{200d}F.EX\u{200b}E.\t ",
        ] {
            let (out, warnings) = sanitize(name);
            assert_eq!(out.to_ascii_lowercase(), "invoice.pdf.exe", "{name:?}");
            let spoof = warnings.iter().find(|w| {
                w.code == WarningCode::LookalikeFilenameExtensionSpoof
                    && w.detail
                        .as_deref()
                        .is_some_and(|d| d.contains("reason=double_extension"))
            });
            assert!(spoof.is_some(), "missing spoof warning for {name:?}");
            let Some(spoof) = spoof else {
                continue;
            };
            let detail = spoof.detail.as_deref().unwrap_or("");
            assert!(detail.contains(&format!("raw={name:?}")), "{spoof:?}");
            assert!(detail.contains("visible=.pdf,declared=.pdf.exe"));
            assert_eq!(spoof.location.as_deref(), Some("attachment[0]:filename"));
        }
    }

    /// Sanitize the bare `sanitize_filename` helper without the
    /// `sanitize_attachment_filename` wrapper's warning emission.
    fn raw_sanitize(name: &str) -> (String, bool) {
        super::sanitize_filename(name, 0)
    }

    #[test]
    fn sanitize_filename_strips_leading_dot_and_whitespace() {
        // Kills `||` -> `&&` mutation in the trim_start_matches predicate
        // `c == '.' || c.is_ascii_whitespace()`. With `&&` the predicate
        // matches no character (no char is both `.` and whitespace), so
        // no leading bytes get trimmed.
        let (out, rewritten) = raw_sanitize(" .secret.txt");
        assert_eq!(out, "secret.txt", "expected leading dot+space trimmed");
        assert!(rewritten, "name was rewritten so the flag must be true");
    }

    /// Each bidi-override codepoint maps to one `||` operator in
    /// `contains_bidi_override`. Test each one individually to kill the
    /// per-line `|| -> &&` mutations: one bidi codepoint flipping its
    /// own `||` to `&&` short-circuits the entire chain to `false` (the
    /// `&&` chain demands *every* literal-comparison succeed at once,
    /// which is impossible since one `c` cannot equal multiple
    /// codepoints simultaneously).
    #[test]
    fn contains_bidi_override_detects_lre_u202a() {
        assert!(contains_bidi_override("\u{202A}"));
    }
    #[test]
    fn contains_bidi_override_detects_rle_u202b() {
        assert!(contains_bidi_override("\u{202B}"));
    }
    #[test]
    fn contains_bidi_override_detects_pdf_u202c() {
        assert!(contains_bidi_override("\u{202C}"));
    }
    #[test]
    fn contains_bidi_override_detects_lro_u202d() {
        assert!(contains_bidi_override("\u{202D}"));
    }
    #[test]
    fn contains_bidi_override_detects_lri_u2067() {
        assert!(contains_bidi_override("\u{2067}"));
    }
    #[test]
    fn contains_bidi_override_detects_fsi_u2068() {
        assert!(contains_bidi_override("\u{2068}"));
    }
    #[test]
    fn contains_bidi_override_detects_pdi_u2069() {
        assert!(contains_bidi_override("\u{2069}"));
    }

    #[test]
    fn contains_bidi_override_rejects_plain_ascii() {
        assert!(!contains_bidi_override("plain.txt"));
    }

    #[test]
    fn detect_double_extension_returns_none_for_too_few_segments() {
        // Kills `< with >` mutation on the `segments.len() < 3` guard.
        // With `>`, len=1 falls through to `segments[len-2]` and panics
        // on the unsigned wrap (debug) — which still fails the test, so
        // the mutation is caught either way.
        assert_eq!(detect_double_extension("nodot"), None);
    }

    #[test]
    fn detect_double_extension_picks_penultimate_segment() {
        // Kills `- with /` mutation on `segments.len() - 2`. With `-`,
        // a 5-segment name picks segments[3] for penultimate; with `/`
        // it picks segments[5/2]=segments[2]. The two yield different
        // results when segments[2] happens to be a document extension
        // and segments[3] is not — `a.b.pdf.x.exe` is constructed so
        // the original returns None (penultimate "x" is not a document
        // ext) but `/` returns Some (segments[2]=pdf, segments[4]=exe).
        assert_eq!(detect_double_extension("a.b.pdf.x.exe"), None);
    }

    #[test]
    fn detect_double_extension_requires_both_doc_and_executable() {
        // Kills `&& with ||` mutation on the
        // `DOCUMENT.contains(penultimate) && EXECUTABLE.contains(final)`
        // guard. With `||`, `pdf.txt` (penultimate is doc, final is
        // not executable) returns Some instead of None.
        assert_eq!(detect_double_extension("a.pdf.txt"), None);
    }
}
