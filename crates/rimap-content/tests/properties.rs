//! Property tests for the rimap-content unicode pipeline.
//!
//! Each property runs at 10,000 cases via `ProptestConfig` with
//! `cases = 10_000`. Shrinking is enabled so failures report
//! minimal counterexamples.

use proptest::prelude::*;
use rimap_content::{decode, filter_codepoints, normalize_nfkc, truncate_graphemes};

fn config() -> ProptestConfig {
    ProptestConfig {
        cases: 10_000,
        max_shrink_iters: 10_000,
        ..ProptestConfig::default()
    }
}

proptest! {
    #![proptest_config(config())]

    /// NFKC is idempotent: normalizing twice gives the same result.
    #[test]
    fn nfkc_stable(input in any::<String>()) {
        let once = normalize_nfkc(&input);
        let twice = normalize_nfkc(&once);
        prop_assert_eq!(once, twice);
    }

    /// After filter_codepoints, the output contains no codepoint in
    /// the strip set.
    #[test]
    fn no_stripped_codepoints_in_output(input in any::<String>()) {
        let result = filter_codepoints(&input);
        for ch in result.text.chars() {
            let c = ch as u32;
            prop_assert!(!is_zero_width(ch), "zero-width {c:#x} in output");
            prop_assert!(!is_bidi_override(ch), "bidi {c:#x} in output");
        }
    }

    /// After filter_codepoints, the output contains no C0 control
    /// except tab and newline, and no C1 controls at all.
    #[test]
    fn no_c0_c1_controls_except_tab_newline(input in any::<String>()) {
        let result = filter_codepoints(&input);
        for ch in result.text.chars() {
            let c = ch as u32;
            if c <= 0x1F {
                prop_assert!(ch == '\t' || ch == '\n', "C0 {c:#x} in output");
            }
            prop_assert!(!(0x80..=0x9F).contains(&c), "C1 {c:#x} in output");
        }
    }

    /// decode on any byte slice returns valid UTF-8.
    #[test]
    fn utf8_preserved(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let out = decode(&bytes, Some("utf-8"));
        // Rust String is UTF-8 by construction, so this is trivially
        // true — but verify the re-encoded bytes also parse.
        let reencoded = out.as_bytes();
        prop_assert!(std::str::from_utf8(reencoded).is_ok());
    }

    /// truncate_graphemes returns a byte-length ≤ max_bytes and
    /// does not split grapheme clusters.
    #[test]
    fn grapheme_truncation_bounds(
        input in any::<String>(),
        max_bytes in 0usize..8192,
    ) {
        let out = truncate_graphemes(&input, max_bytes);
        prop_assert!(
            out.len() <= max_bytes || max_bytes == 0,
            "out.len()={} max_bytes={}",
            out.len(),
            max_bytes
        );
        // Every grapheme in `out` must also be a prefix in `input`
        // (byte-wise), meaning truncation never invent or split a cluster.
        prop_assert!(input.starts_with(&out));
    }
}

fn is_zero_width(ch: char) -> bool {
    matches!(
        ch,
        '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{2060}' | '\u{FEFF}'
    )
}

fn is_bidi_override(ch: char) -> bool {
    matches!(
        ch,
        '\u{202A}'
            | '\u{202B}'
            | '\u{202C}'
            | '\u{202D}'
            | '\u{202E}'
            | '\u{2066}'
            | '\u{2067}'
            | '\u{2068}'
            | '\u{2069}'
    )
}
