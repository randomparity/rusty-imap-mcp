//! Attachment filename sanitisation and double-extension detection.
//!
//! Sibling of the MIME scrubber and attachment builder; called from
//! `attachments::build_attachment_meta` and reused by the crate's
//! filename-hardening tests.

use mail_parser::MimeHeaders;

use crate::output::{SecurityWarning, WarningCode};
use crate::parse::MAX_HEADER_BYTES;
use crate::parse::safe_parser::safe_parse;
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
    if let Some((penult, final_ext)) = detect_double_extension(name) {
        warnings.push(SecurityWarning::at(
            WarningCode::LookalikeFilenameExtensionSpoof,
            format!(
                "reason=double_extension,visible=.{penult},\
                 declared=.{penult}.{final_ext}"
            ),
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

/// Decode and sanitize an attachment filename from the `Content-Type` and
/// `Content-Disposition` parameters an IMAP server reports in
/// `BODYSTRUCTURE`.
///
/// Servers return parameters undecoded, so a non-ASCII name arrives as
/// RFC 2231 sections (`filename*0*=UTF-8''...`) or as an RFC 2047 encoded
/// word. The `name` / `filename` parameters are re-serialized into the two
/// headers and decoded by the same parser, and the same
/// `attachment_name()` precedence (disposition `filename`, then type
/// `name`), that the full-message path uses, so `list_attachments` and
/// `fetch_message` report the same name for a part. The decoded value then
/// goes through [`sanitize_attachment_filename`]; warnings are tagged with
/// `idx`.
///
/// A parameter whose name is not an RFC 2045 token, or whose value holds
/// CR, LF, or NUL, is dropped with a `ParseHeaderSmugglingBlocked` warning
/// rather than re-serialized. When the kept parameters exceed
/// [`MAX_HEADER_BYTES`] the name is withheld (`None`) with a
/// `ParseAttachmentFilenameRewritten` warning, which also bounds the
/// parser's continuation merging on hostile input.
pub fn attachment_filename_from_params(
    content_type_params: &[(String, String)],
    disposition_params: &[(String, String)],
    idx: usize,
    warnings: &mut Vec<SecurityWarning>,
) -> Option<String> {
    let location = format!("attachment[{idx}]:filename");
    let mut dropped = false;
    let mut header = String::from("Content-Type: application/octet-stream");
    append_name_params(&mut header, content_type_params, &mut dropped);
    header.push_str("\r\nContent-Disposition: attachment");
    append_name_params(&mut header, disposition_params, &mut dropped);
    header.push_str("\r\n\r\n");

    if dropped {
        warnings.push(SecurityWarning::at(
            WarningCode::ParseHeaderSmugglingBlocked,
            "reason=bodystructure_param_dropped".to_string(),
            location.clone(),
        ));
    }
    if header.len() > MAX_HEADER_BYTES {
        warnings.push(SecurityWarning::at(
            WarningCode::ParseAttachmentFilenameRewritten,
            format!(
                "reason=params_exceed_limit,bytes={},limit={MAX_HEADER_BYTES}",
                header.len()
            ),
            location,
        ));
        return None;
    }

    let message = safe_parse(header.as_bytes()).ok().flatten()?;
    let name = message.attachment_name().filter(|name| !name.is_empty())?;
    Some(sanitize_attachment_filename(name, idx, warnings))
}

/// Append the `name` / `filename` parameter family (plain and RFC 2231
/// `*` forms) from `params` to `header`. Other parameters cannot affect
/// the filename and are skipped. Sets `dropped` for a parameter that
/// cannot be re-serialized safely.
fn append_name_params(header: &mut String, params: &[(String, String)], dropped: &mut bool) {
    for (key, value) in params {
        let base = key.split('*').next().unwrap_or_default();
        if !(base.eq_ignore_ascii_case("name") || base.eq_ignore_ascii_case("filename")) {
            continue;
        }
        if !key.bytes().all(is_token_byte) || value.bytes().any(|b| matches!(b, b'\r' | b'\n' | 0))
        {
            *dropped = true;
            continue;
        }
        header.push_str(";\r\n ");
        header.push_str(key);
        header.push('=');
        if key.ends_with('*') && !value.is_empty() && value.bytes().all(is_token_byte) {
            // RFC 2231 extended value: a token, never a quoted string.
            header.push_str(value);
        } else {
            header.push('"');
            for c in value.chars() {
                if matches!(c, '"' | '\\') {
                    header.push('\\');
                }
                header.push(c);
            }
            header.push('"');
        }
    }
}

/// RFC 2045 `token` byte: printable US-ASCII except space and tspecials.
fn is_token_byte(b: u8) -> bool {
    b.is_ascii_graphic() && !b"()<>@,;:\\\"/[]?=".contains(&b)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod params_tests {
    use super::attachment_filename_from_params;
    use crate::output::{SecurityWarning, WarningCode};

    fn owned(params: &[(&str, &str)]) -> Vec<(String, String)> {
        params
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    /// Content-Type parameters only.
    fn decode(params: &[(&str, &str)]) -> (Option<String>, Vec<SecurityWarning>) {
        decode_both(params, &[])
    }

    fn decode_both(
        content_type: &[(&str, &str)],
        disposition: &[(&str, &str)],
    ) -> (Option<String>, Vec<SecurityWarning>) {
        let mut warnings = Vec::new();
        let name = attachment_filename_from_params(
            &owned(content_type),
            &owned(disposition),
            3,
            &mut warnings,
        );
        (name, warnings)
    }

    fn has(warnings: &[SecurityWarning], code: WarningCode) -> bool {
        warnings.iter().any(|w| w.code == code)
    }

    #[test]
    fn plain_name() {
        assert_eq!(decode(&[("name", "doc.pdf")]).0.as_deref(), Some("doc.pdf"));
    }

    #[test]
    fn disposition_filename_wins_over_type_name() {
        // Same precedence as mail-parser's attachment_name() on the full
        // message, so the listed name matches the fetched/downloaded one.
        let (name, warnings) = decode_both(
            &[("name", "Q3-invoice.pdf")],
            &[("filename", "Q3-invoice.pdf.lnk")],
        );
        assert_eq!(name.as_deref(), Some("Q3-invoice.pdf.lnk"));
        assert!(
            has(&warnings, WarningCode::LookalikeFilenameExtensionSpoof),
            "{warnings:?}"
        );
    }

    #[test]
    fn disposition_only_rfc2231_filename_is_decoded() {
        let (name, _) = decode_both(&[], &[("filename*", "utf-8''r%C3%A9sum%C3%A9.pdf")]);
        assert_eq!(name.as_deref(), Some("résumé.pdf"));
    }

    #[test]
    fn content_type_filename_param_is_ignored_like_the_full_path() {
        assert_eq!(decode(&[("filename", "evil.exe")]).0, None);
    }

    #[test]
    fn rfc2047_encoded_word_name_is_decoded() {
        let params = [("name", "=?utf-8?Q?=C3=9Cbersicht_f=C3=BCr.pdf?=")];
        assert_eq!(decode(&params).0.as_deref(), Some("Übersicht für.pdf"));
    }

    #[test]
    fn rfc2231_sections_are_joined_and_decoded() {
        let params = [
            ("name*1*", "%20Fassung.pdf"),
            ("name*0*", "UTF-8''%C3%9Cbersicht%20der"),
        ];
        assert_eq!(
            decode(&params).0.as_deref(),
            Some("Übersicht der Fassung.pdf")
        );
    }

    #[test]
    fn rfc2231_single_extended_value_is_decoded() {
        let params = [("name*", "utf-8''caf%C3%A9.txt")];
        assert_eq!(decode(&params).0.as_deref(), Some("café.txt"));
    }

    #[test]
    fn rfc2231_plain_sections_are_joined() {
        let params = [("name*0", "quarterly-"), ("name*1", "report.pdf")];
        assert_eq!(decode(&params).0.as_deref(), Some("quarterly-report.pdf"));
    }

    #[test]
    fn quotes_and_backslashes_survive_requoting() {
        let params = [("name", r#"a"b\c.txt"#)];
        let (name, _) = decode(&params);
        // The quote survives re-quoting; the sanitizer then rewrites the
        // backslash path separator.
        assert_eq!(name.as_deref(), Some("a\"b_c.txt"));
    }

    #[test]
    fn line_breaks_cannot_shape_the_synthesized_header() {
        let params = [("name", "a.txt\r\nContent-Type: text/html; name=evil.html")];
        let (name, warnings) = decode(&params);
        assert_eq!(name, None);
        assert!(
            has(&warnings, WarningCode::ParseHeaderSmugglingBlocked),
            "{warnings:?}"
        );
        let key = [("name\r\nX", "a.txt")];
        assert_eq!(decode(&key).0, None);
    }

    #[test]
    fn unrelated_params_are_not_reserialized() {
        // A stray CR in an unrelated parameter neither blocks the name nor
        // warns: only the name/filename family is synthesized.
        let params = [("charset", "x\ry"), ("name", "a.pdf")];
        let (name, warnings) = decode(&params);
        assert_eq!(name.as_deref(), Some("a.pdf"));
        assert!(warnings.is_empty(), "{warnings:?}");
    }

    #[test]
    fn oversized_params_withhold_the_name() {
        let sections: Vec<(String, String)> = (0..100_000)
            .map(|i| (format!("name*{i}"), "aaaaaaaaaa".to_string()))
            .collect();
        let mut warnings = Vec::new();
        let start = std::time::Instant::now();
        let name = attachment_filename_from_params(&sections, &[], 0, &mut warnings);
        assert_eq!(name, None);
        assert!(
            has(&warnings, WarningCode::ParseAttachmentFilenameRewritten),
            "{warnings:?}"
        );
        assert!(
            start.elapsed() < std::time::Duration::from_secs(1),
            "{:?}",
            start.elapsed()
        );
    }

    #[test]
    fn percent_decoded_controls_and_separators_are_sanitized() {
        let (name, warnings) = decode(&[("name*", "utf-8''a%00b%2F..%2Fetc.txt")]);
        let name = name.unwrap();
        assert!(!name.contains('\0') && !name.contains('/'), "{name:?}");
        assert!(!warnings.is_empty());
    }

    #[test]
    fn absent_or_empty_name_is_none() {
        assert_eq!(decode(&[]).0, None);
        assert_eq!(decode(&[("charset", "utf-8")]).0, None);
        assert_eq!(decode(&[("name", "")]).0, None);
    }

    #[test]
    fn decoded_name_is_sanitized() {
        // An encoded RLO override must be decoded and then flagged.
        let params = [("name", "=?utf-8?Q?invoice=E2=80=AEfdp.exe?=")];
        let (name, warnings) = decode(&params);
        assert!(!name.unwrap().contains('\u{202e}'));
        assert!(
            warnings
                .iter()
                .any(|w| w.code == WarningCode::LookalikeFilenameExtensionSpoof),
            "{warnings:?}",
        );
    }
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
