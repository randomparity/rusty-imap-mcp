//! Pure Unicode sanitization pipeline.
//!
//! The pipeline is a sequence of independent pure functions:
//! [`decode`] → [`normalize_nfkc`] → [`normalize_line_endings`] →
//! [`filter_codepoints`] → [`truncate_graphemes`]. The [`sanitize`]
//! composer runs the full sequence and returns the output string
//! alongside any [`SecurityWarning`]s emitted during filtering.
//!
//! This module has no I/O; intermediate allocations are bounded by
//! input length × a small constant. It knows nothing about MIME or
//! email structure, and it is the single chokepoint through which
//! every untrusted string in the crate passes.

use unicode_normalization::UnicodeNormalization;
use unicode_segmentation::UnicodeSegmentation;

use crate::output::{SecurityWarning, WarningCode};

/// Zero-width codepoints stripped by [`filter_codepoints`].
const ZERO_WIDTH: &[char] = &[
    '\u{200B}', // ZERO WIDTH SPACE
    '\u{200C}', // ZERO WIDTH NON-JOINER
    '\u{200D}', // ZERO WIDTH JOINER
    '\u{2060}', // WORD JOINER
    '\u{FEFF}', // ZERO WIDTH NO-BREAK SPACE / BOM
];

/// Bidi override/isolate codepoints stripped by [`filter_codepoints`].
const BIDI_OVERRIDE: &[char] = &[
    '\u{202A}', // LEFT-TO-RIGHT EMBEDDING
    '\u{202B}', // RIGHT-TO-LEFT EMBEDDING
    '\u{202C}', // POP DIRECTIONAL FORMATTING
    '\u{202D}', // LEFT-TO-RIGHT OVERRIDE
    '\u{202E}', // RIGHT-TO-LEFT OVERRIDE
    '\u{2066}', // LEFT-TO-RIGHT ISOLATE
    '\u{2067}', // RIGHT-TO-LEFT ISOLATE
    '\u{2068}', // FIRST STRONG ISOLATE
    '\u{2069}', // POP DIRECTIONAL ISOLATE
];

/// Decode `bytes` to a UTF-8 `String` using the label in `charset_label`.
/// Unknown labels and missing labels fall back to UTF-8 decoding with
/// replacement characters.
///
/// `encoding_rs` never fails for any byte slice — it substitutes
/// U+FFFD on decode errors — so this function returns an owned `String`
/// rather than `Result`.
#[must_use]
pub fn decode(bytes: &[u8], charset_label: Option<&str>) -> String {
    let encoding = charset_label
        .and_then(|label| encoding_rs::Encoding::for_label(label.as_bytes()))
        .unwrap_or(encoding_rs::UTF_8);
    let (cow, _encoding_used, _had_errors) = encoding.decode(bytes);
    cow.into_owned()
}

/// Apply Unicode NFKC normalization to `input`.
///
/// This is idempotent: `normalize_nfkc(normalize_nfkc(s)) == normalize_nfkc(s)`.
#[must_use]
pub fn normalize_nfkc(input: &str) -> String {
    input.nfkc().collect()
}

/// Filter disallowed codepoints from `input`, returning the filtered
/// string alongside per-class strip counts.
///
/// The strip set covers:
/// - Zero-width formatting codepoints (see the private `ZERO_WIDTH` table)
/// - Unicode Tag Characters (U+E0000..U+E007F), counted with zero-width
/// - Bidi overrides and isolates (see the private `BIDI_OVERRIDE` table)
/// - C0 controls (U+0000..U+001F) except `\t` (U+0009) and `\n` (U+000A)
/// - C1 controls (U+0080..U+009F)
///
/// This function does not emit [`SecurityWarning`]s directly; the
/// [`sanitize`] composer converts the counts in [`FilterResult`] into
/// warnings (at most one per strip class per call).
#[must_use]
pub fn filter_codepoints(input: &str) -> FilterResult {
    let mut out = String::with_capacity(input.len());
    let mut zero_width = 0_usize;
    let mut bidi = 0_usize;
    let mut c0_c1 = 0_usize;

    for ch in input.chars() {
        if ZERO_WIDTH.contains(&ch) || is_unicode_tag(ch) {
            zero_width += 1;
            continue;
        }
        if BIDI_OVERRIDE.contains(&ch) {
            bidi += 1;
            continue;
        }
        if is_c0_control_disallowed(ch) || is_c1_control(ch) {
            c0_c1 += 1;
            continue;
        }
        out.push(ch);
    }

    FilterResult {
        text: out,
        zero_width_stripped: zero_width,
        bidi_stripped: bidi,
        c0_c1_stripped: c0_c1,
    }
}

/// Outcome of [`filter_codepoints`]. The three count fields record how
/// many codepoints of each class were stripped from the input; the
/// [`sanitize`] composer converts non-zero counts into
/// [`SecurityWarning`] entries.
#[derive(Debug, Clone)]
pub struct FilterResult {
    /// Filtered text with disallowed codepoints removed.
    pub text: String,
    /// Number of zero-width codepoints stripped.
    pub zero_width_stripped: usize,
    /// Number of bidi-override codepoints stripped.
    pub bidi_stripped: usize,
    /// Number of C0/C1 control codepoints stripped.
    pub c0_c1_stripped: usize,
}

fn is_c0_control_disallowed(ch: char) -> bool {
    let c = ch as u32;
    c <= 0x1F && ch != '\t' && ch != '\n'
}

fn is_c1_control(ch: char) -> bool {
    let c = ch as u32;
    (0x80..=0x9F).contains(&c)
}

/// Unicode Tag Characters block (U+E0000..U+E007F): LANGUAGE TAG,
/// TAG codepoints, and CANCEL TAG. These are invisible formatting
/// codepoints used to smuggle instructions past visual review.
fn is_unicode_tag(ch: char) -> bool {
    let c = ch as u32;
    (0xE0000..=0xE007F).contains(&c)
}

/// Normalize all line endings to `\n`. Converts `\r\n` to `\n` and
/// any remaining bare `\r` to `\n`. Idempotent.
#[must_use]
pub fn normalize_line_endings(input: &str) -> String {
    // Two-pass: first collapse CRLF, then convert bare CR. A single
    // pass with a char iterator would also work but this is clearer.
    let crlf_collapsed = input.replace("\r\n", "\n");
    crlf_collapsed.replace('\r', "\n")
}

/// Find the largest byte offset `cut <= max_bytes` such that
/// `input[..cut]` ends at a grapheme-cluster boundary. Returns
/// `input.len()` when `input` already fits.
///
/// Exposed `pub(crate)` so callers that already hold a `&str` can
/// slice `&input[..cut]` without allocating (see `lookalike::scan_body_urls`).
pub(crate) fn grapheme_cut(input: &str, max_bytes: usize) -> usize {
    if input.len() <= max_bytes {
        return input.len();
    }
    let mut cut = 0;
    for (idx, cluster) in input.grapheme_indices(true) {
        if idx + cluster.len() > max_bytes {
            break;
        }
        cut = idx + cluster.len();
    }
    cut
}

/// Truncate `input` to at most `max_bytes` bytes, cutting at a
/// grapheme-cluster boundary. Returns an owned `String` that is
/// always a prefix of `input` (byte-wise).
///
/// If `input` is already ≤ `max_bytes`, returns a clone. If
/// `max_bytes == 0`, returns an empty string. Allocates; prefer
/// [`truncate_graphemes_in_place`] when you already own the string.
#[must_use]
pub fn truncate_graphemes(input: &str, max_bytes: usize) -> String {
    let cut = grapheme_cut(input, max_bytes);
    input[..cut].to_string()
}

/// Truncate `s` in-place to the largest prefix that ends at a
/// grapheme-cluster boundary and has byte length ≤ `max_bytes`.
/// No allocation: only `String::truncate` is called.
pub fn truncate_graphemes_in_place(s: &mut String, max_bytes: usize) {
    let cut = grapheme_cut(s, max_bytes);
    s.truncate(cut);
}

/// Run the full sanitization pipeline on `bytes`: decode with the
/// given charset, NFKC-normalize, filter disallowed codepoints,
/// normalize line endings, and truncate to at most `max_bytes` bytes
/// at a grapheme-cluster boundary.
///
/// Returns the sanitized string and the list of warnings produced by
/// the filter pass. `location` is embedded verbatim in each warning's
/// `location` field so callers can attribute strippings to a header
/// name or body part index.
#[must_use]
pub fn sanitize(
    bytes: &[u8],
    charset_label: Option<&str>,
    max_bytes: usize,
    location: &str,
) -> (String, Vec<SecurityWarning>) {
    let decoded = decode(bytes, charset_label);
    // Pre-cap before NFKC so pathological expansion (CJK compatibility
    // decompositions, ligatures) has a bounded work factor. 4x covers
    // realistic expansion for well-formed text while preventing memory
    // amplification DoS on inputs crafted to expand dramatically under
    // NFKC. The final per-part cap at the end of the pipeline is
    // unchanged.
    let pre_cap_budget = max_bytes.saturating_mul(4);
    let pre_capped = truncate_graphemes(&decoded, pre_cap_budget);
    let normalized = normalize_nfkc(&pre_capped);
    let line_normalized = normalize_line_endings(&normalized);
    let filter_result = filter_codepoints(&line_normalized);
    let truncated = truncate_graphemes(&filter_result.text, max_bytes);

    let warnings = build_warnings(&filter_result, location);
    (truncated, warnings)
}

fn build_warnings(result: &FilterResult, location: &str) -> Vec<SecurityWarning> {
    let mut warnings = Vec::new();
    if result.zero_width_stripped > 0 {
        warnings.push(SecurityWarning::at(
            WarningCode::UnicodeZeroWidthStripped,
            format!("count={}", result.zero_width_stripped),
            location,
        ));
    }
    if result.bidi_stripped > 0 {
        warnings.push(SecurityWarning::at(
            WarningCode::UnicodeBidiOverrideStripped,
            format!("count={}", result.bidi_stripped),
            location,
        ));
    }
    if result.c0_c1_stripped > 0 {
        warnings.push(SecurityWarning::at(
            WarningCode::UnicodeC0C1Stripped,
            format!("count={}", result.c0_c1_stripped),
            location,
        ));
    }
    warnings
}

#[cfg(test)]
mod tests {
    use super::*;
    use rimap_core::folder_name::is_rejected_display_codepoint;

    /// Lock-step guard for `rimap-core::folder_name`'s
    /// `is_rejected_display_codepoint`: the predicate must strip exactly
    /// the codepoints [`filter_codepoints`] strips as zero-width or bidi
    /// (C0/C1 controls are out of scope — folder names reject those by a
    /// different rule). Checked over *every* scalar value so a table
    /// edit on either side cannot silently diverge.
    #[test]
    fn folder_name_rejection_matches_filter_codepoints() {
        let mut checked = 0_usize;
        for scalar in 0_u32..=0x0010_FFFF {
            // Surrogates are not `char`s.
            let Ok(ch) = char::try_from(scalar) else {
                continue;
            };
            let result = filter_codepoints(&ch.to_string());
            let stripped_by_filter = result.zero_width_stripped + result.bidi_stripped == 1;
            assert_eq!(
                is_rejected_display_codepoint(ch),
                stripped_by_filter,
                "U+{scalar:04X}: folder_name rejection and unicode filter disagree"
            );
            checked += 1;
        }
        assert!(
            checked > 1_100_000,
            "expected to sweep every Unicode scalar, got {checked}"
        );
    }


    #[test]
    fn decode_utf8_passthrough() {
        let out = decode(b"hello world", Some("utf-8"));
        assert_eq!(out, "hello world");
    }

    #[test]
    fn decode_latin1_handles_high_bytes() {
        // "café" in ISO-8859-1 is [0x63, 0x61, 0x66, 0xE9].
        let out = decode(&[0x63, 0x61, 0x66, 0xE9], Some("iso-8859-1"));
        assert_eq!(out, "café");
    }

    #[test]
    fn decode_unknown_charset_falls_back_to_utf8() {
        let out = decode(b"hello", Some("pig-latin"));
        assert_eq!(out, "hello");
    }

    #[test]
    fn decode_none_charset_defaults_utf8() {
        let out = decode(b"hello", None);
        assert_eq!(out, "hello");
    }

    #[test]
    fn nfkc_compatibility_composes_decomposed() {
        // "e" + combining acute => precomposed "é"
        let decomposed = "e\u{0301}";
        let composed = normalize_nfkc(decomposed);
        assert_eq!(composed, "é");
    }

    #[test]
    fn nfkc_is_idempotent() {
        // Mixed input: precomposed é, NBSP, em-dash, and the LATIN SMALL LIGATURE FI.
        let input = "Café\u{00A0}—\u{FB01}ve";
        let once = normalize_nfkc(input);
        let twice = normalize_nfkc(&once);
        assert_eq!(once, twice);
    }

    #[test]
    fn nfkc_expands_ligature() {
        // U+FB01 LATIN SMALL LIGATURE FI -> "fi" under NFKC.
        let out = normalize_nfkc("\u{FB01}ve");
        assert_eq!(out, "five");
    }

    #[test]
    fn filter_strips_zero_width_codepoints() {
        let input = "he\u{200B}llo\u{FEFF} wor\u{2060}ld";
        let result = filter_codepoints(input);
        assert_eq!(result.text, "hello world");
        assert_eq!(result.zero_width_stripped, 3);
        assert_eq!(result.bidi_stripped, 0);
        assert_eq!(result.c0_c1_stripped, 0);
    }

    #[test]
    fn filter_strips_bidi_overrides() {
        let input = "safe\u{202E}evil\u{202C}.exe";
        let result = filter_codepoints(input);
        assert_eq!(result.text, "safeevil.exe");
        assert_eq!(result.bidi_stripped, 2);
        assert_eq!(result.zero_width_stripped, 0);
    }

    #[test]
    fn filter_strips_c0_controls_except_tab_newline() {
        let input = "a\tb\nc\x01d\x07e";
        let result = filter_codepoints(input);
        assert_eq!(result.text, "a\tb\ncde");
        assert_eq!(result.c0_c1_stripped, 2);
    }

    #[test]
    fn filter_strips_c1_controls() {
        let input = "a\u{0085}b\u{009F}c";
        let result = filter_codepoints(input);
        assert_eq!(result.text, "abc");
        assert_eq!(result.c0_c1_stripped, 2);
    }

    #[test]
    fn filter_preserves_legitimate_multilingual() {
        let inputs = [
            "こんにちは世界",   // Japanese
            "مرحبا بالعالم",    // Arabic
            "שלום עולם",        // Hebrew
            "Grüße aus Bayern", // German with umlauts
        ];
        for input in inputs {
            let result = filter_codepoints(input);
            assert_eq!(result.text, input, "input={input}");
            assert_eq!(result.zero_width_stripped, 0);
            assert_eq!(result.bidi_stripped, 0);
            assert_eq!(result.c0_c1_stripped, 0);
        }
    }

    #[test]
    fn line_endings_crlf_to_lf() {
        assert_eq!(normalize_line_endings("a\r\nb\r\nc"), "a\nb\nc");
    }

    #[test]
    fn line_endings_bare_cr_to_lf() {
        assert_eq!(normalize_line_endings("a\rb\rc"), "a\nb\nc");
    }

    #[test]
    fn line_endings_mixed() {
        assert_eq!(normalize_line_endings("a\r\nb\rc\nd"), "a\nb\nc\nd");
    }

    #[test]
    fn line_endings_idempotent() {
        let once = normalize_line_endings("a\r\nb\rc");
        let twice = normalize_line_endings(&once);
        assert_eq!(once, twice);
    }

    #[test]
    fn truncate_under_limit_is_passthrough() {
        assert_eq!(truncate_graphemes("hello", 10), "hello");
    }

    #[test]
    fn truncate_exact_limit() {
        assert_eq!(truncate_graphemes("hello", 5), "hello");
    }

    #[test]
    fn truncate_ascii_cuts_cleanly() {
        assert_eq!(truncate_graphemes("hello world", 5), "hello");
    }

    #[test]
    fn truncate_preserves_grapheme_cluster() {
        // "é" (e + combining acute) is 3 bytes as a single cluster.
        // Truncating at byte 2 must drop the whole cluster, not split it.
        let input = "ae\u{0301}b";
        let out = truncate_graphemes(input, 2);
        // "a" fits (1 byte). "e\u{0301}" would push total to 4 (> 2), so drop it.
        assert_eq!(out, "a");
    }

    #[test]
    fn truncate_zero_max_bytes_returns_empty() {
        assert_eq!(truncate_graphemes("hello", 0), "");
    }

    #[test]
    fn truncate_keeps_full_multibyte_cluster_when_exactly_fits() {
        // Regression: "中" is 3 bytes in UTF-8. "ab中cd" with max=5
        // must yield "ab中" — the trailing cluster ends exactly at
        // byte 5, a grapheme boundary that fits within the cap.
        // Guards against a `> vs >=` mutation on the cluster-fits
        // check inside `truncate_graphemes`.
        assert_eq!(truncate_graphemes("ab中cd", 5), "ab中");
    }

    #[test]
    fn truncate_in_place_matches_owned_variant() {
        // Cross-check the in-place and owned helpers on inputs that
        // exercise each branch of `grapheme_cut`: under-limit, exact
        // limit, ASCII cut, mid-cluster drop, exact-fit interior cut,
        // and zero cap.
        let cases: &[(&str, usize)] = &[
            ("hello", 10),      // under-limit passthrough
            ("hello", 5),       // exact-limit whole string
            ("hello world", 5), // ASCII cut
            ("ae\u{0301}b", 2), // grapheme cluster dropped
            ("ab中cd", 5),      // multi-byte cluster fits exactly
            ("hello", 0),       // zero cap
        ];
        for (input, max) in cases {
            let mut owned = (*input).to_string();
            truncate_graphemes_in_place(&mut owned, *max);
            assert_eq!(
                owned,
                truncate_graphemes(input, *max),
                "in-place vs owned diverged on ({input:?}, {max})",
            );
        }
    }

    #[test]
    fn sanitize_passthrough_ascii() {
        let (text, warnings) = sanitize(b"hello", Some("utf-8"), 1024, "header:subject");
        assert_eq!(text, "hello");
        assert!(warnings.is_empty());
    }

    #[test]
    fn sanitize_emits_zero_width_warning() {
        let input = "he\u{200B}llo".as_bytes();
        let (text, warnings) = sanitize(input, Some("utf-8"), 1024, "header:subject");
        assert_eq!(text, "hello");
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].code, WarningCode::UnicodeZeroWidthStripped);
        assert_eq!(warnings[0].location.as_deref(), Some("header:subject"));
        assert!(
            warnings[0]
                .detail
                .as_deref()
                .unwrap_or("")
                .contains("count=1")
        );
    }

    #[test]
    fn sanitize_emits_multiple_warnings() {
        let input = "a\u{200B}b\u{202E}c\x01d".as_bytes();
        let (text, warnings) = sanitize(input, Some("utf-8"), 1024, "body:part[0]");
        assert_eq!(text, "abcd");
        assert_eq!(warnings.len(), 3);
        let codes: Vec<WarningCode> = warnings.iter().map(|w| w.code).collect();
        assert!(codes.contains(&WarningCode::UnicodeZeroWidthStripped));
        assert!(codes.contains(&WarningCode::UnicodeBidiOverrideStripped));
        assert!(codes.contains(&WarningCode::UnicodeC0C1Stripped));
    }

    #[test]
    fn sanitize_truncates_oversized() {
        let input = "a".repeat(100);
        let (text, warnings) = sanitize(input.as_bytes(), Some("utf-8"), 10, "body:part[0]");
        assert_eq!(text.len(), 10);
        assert_eq!(text, "aaaaaaaaaa");
        assert!(warnings.is_empty()); // truncation warning is emitted by parse, not sanitize
    }

    #[test]
    fn sanitize_multilingual_clean() {
        let (text, warnings) =
            sanitize("こんにちは".as_bytes(), Some("utf-8"), 1024, "body:part[0]");
        assert_eq!(text, "こんにちは");
        assert!(warnings.is_empty());
    }

    #[test]
    fn filter_codepoints_strips_unicode_tag() {
        // Kills `is_unicode_tag -> bool with false`. With `false`, a
        // Unicode Tag char (U+E0001 LANGUAGE TAG) bypasses the
        // zero-width-class filter and gets pushed into the output.
        // Original: stripped via the same arm as ZERO_WIDTH chars,
        // counted in `zero_width_stripped`.
        let input = "ab\u{E0001}cd";
        let result = filter_codepoints(input);
        assert_eq!(
            result.text, "abcd",
            "Unicode Tag char must be stripped from output",
        );
        assert!(
            result.zero_width_stripped >= 1,
            "Unicode Tag char must increment zero_width_stripped, got {result:?}",
        );
    }
}
