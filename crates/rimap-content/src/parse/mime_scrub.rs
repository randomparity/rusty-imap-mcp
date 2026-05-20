//! Pre-parser header-smuggling scrubber.
//!
//! Strips logical header lines that participate in RFC 2047
//! encoded-word smuggling (raw CRLF inside an encoded-word) before
//! `mail-parser` sees the byte stream. Emits a single
//! [`WarningCode::ParseHeaderSmugglingBlocked`] aggregated warning.

use crate::output::{SecurityWarning, WarningCode};

// `pub` only because `test_support` re-exports through `pub mod test_support` (Rust
// E0364 forbids `pub use` of `pub(crate)` items). Module privacy
// (`pub(crate) mod mime_scrub` in `parse/mod.rs`) keeps this unreachable
// outside the crate; production callers reach it via
// [`crate::parse::parse_message`].
/// Scan the header block for raw CRLF inside RFC 2047 encoded-words.
/// Drop any offending logical header(s) and emit
/// [`WarningCode::ParseHeaderSmugglingBlocked`].
///
/// Returns a byte vector containing the message with the offending
/// header lines removed.
pub fn scrub_header_smuggling(raw: &[u8], warnings: &mut Vec<SecurityWarning>) -> Vec<u8> {
    let Some((header_end, _sep_len)) = find_header_end(raw) else {
        return raw.to_vec(); // no headers = no smuggling
    };

    let headers = &raw[..header_end];
    let body = &raw[header_end..];

    let logical = split_header_lines(headers);
    let drop_mask = detect_smuggling_spans(&logical);
    let dropped = drop_mask.iter().filter(|flag| **flag).count();

    let mut kept: Vec<u8> = Vec::with_capacity(headers.len());
    let mut dropped_names: Vec<String> = Vec::new();
    for (idx, line) in logical.iter().enumerate() {
        if drop_mask[idx] {
            // Capture the header name (bytes before first ':') for
            // audit reconstruction. Bounded at 8 names to cap log
            // growth; names are routed through the unicode sanitizer
            // so attacker-controlled bytes cannot leak into the
            // warning detail verbatim.
            if dropped_names.len() < 8
                && let Some(colon) = line.iter().position(|&b| b == b':')
                && let Ok(name) = std::str::from_utf8(&line[..colon])
            {
                let (sanitized, _) =
                    crate::unicode::sanitize(name.as_bytes(), Some("utf-8"), 64, "headers");
                if !sanitized.is_empty() {
                    dropped_names.push(sanitized);
                }
            }
        } else {
            kept.extend_from_slice(line);
        }
    }
    if dropped > 0 {
        let detail = if dropped_names.is_empty() {
            format!("count={dropped}")
        } else {
            format!("count={dropped} names=[{}]", dropped_names.join(","))
        };
        warnings.push(SecurityWarning::at(
            WarningCode::ParseHeaderSmugglingBlocked,
            detail,
            "headers",
        ));
    }
    kept.extend_from_slice(body);
    kept
}

/// Walk the logical-header slice and mark every header index that
/// participates in an RFC 2047 smuggling attempt: either an encoded-word
/// whose `=?` and `?=` terminators land in different logical headers,
/// or a dangling `=?` with no `?=` anywhere in the remaining block.
pub(super) fn detect_smuggling_spans(logical: &[&[u8]]) -> Vec<bool> {
    let mut mask = vec![false; logical.len()];
    let mut idx = 0_usize;
    let mut scan_from = 0_usize;
    while idx < logical.len() {
        let header = logical[idx];
        let search_start = scan_from.min(header.len());
        let Some(rel) = header[search_start..].windows(2).position(|w| w == b"=?") else {
            idx += 1;
            scan_from = 0;
            continue;
        };
        let start_pos = search_start + rel;
        match locate_encoded_word_end(logical, idx, start_pos + 2) {
            EncodedWordEnd::SameHeader(end_rel_to_header) => {
                scan_from = end_rel_to_header + 2;
            }
            EncodedWordEnd::LaterHeader(end_idx) => {
                for flag in mask.iter_mut().take(end_idx + 1).skip(idx) {
                    *flag = true;
                }
                idx = end_idx + 1;
                scan_from = 0;
            }
            EncodedWordEnd::Missing => {
                mask[idx] = true;
                idx += 1;
                scan_from = 0;
            }
        }
    }
    mask
}

/// Result of searching for the `?=` terminator of an encoded-word that
/// began at a known position inside a logical header.
enum EncodedWordEnd {
    /// Terminator found inside the same logical header as the opener.
    SameHeader(usize),
    /// Terminator found in a later logical header; carries that index.
    LaterHeader(usize),
    /// No terminator anywhere in the remaining header block.
    Missing,
}

/// Scan for `?=` starting at `start_offset` inside `logical[start_idx]`
/// and continuing through later logical headers if needed.
fn locate_encoded_word_end(
    logical: &[&[u8]],
    start_idx: usize,
    start_offset: usize,
) -> EncodedWordEnd {
    let first = logical[start_idx];
    // cargo-mutants: known-equivalent — `< first.len()` vs `<= first.len()`
    // are observably identical here. At `start_offset == first.len()`, the
    // empty subslice yields no `windows(2)` element, so the `let Some(rel)`
    // guard fails either way and control falls through to the outer scan.
    // Beyond `first.len()`, both predicates evaluate to false. See
    // `bodies_tests` and `parse::tests::scrub_*` for behavioural coverage.
    if start_offset < first.len()
        && let Some(rel) = first[start_offset..].windows(2).position(|w| w == b"?=")
    {
        return EncodedWordEnd::SameHeader(start_offset + rel);
    }
    for (offset, line) in logical.iter().enumerate().skip(start_idx + 1) {
        if line.windows(2).any(|w| w == b"?=") {
            return EncodedWordEnd::LaterHeader(offset);
        }
    }
    EncodedWordEnd::Missing
}

// `pub` only because `test_support` re-exports through `pub mod test_support` (Rust
// E0364 forbids `pub use` of `pub(crate)` items). Module privacy
// (`pub(crate) mod mime_scrub` in `parse/mod.rs`) keeps this unreachable
// outside the crate; production callers reach it via `scrub_header_smuggling`.
/// Find the byte offset where the header block ends (exclusive of the
/// blank-line separator). Handles both CRLF and LF line endings.
/// Returns `(header_end, separator_length)`.
#[must_use]
pub fn find_header_end(raw: &[u8]) -> Option<(usize, usize)> {
    if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
        return Some((pos + 2, 2));
    }
    if let Some(pos) = raw.windows(2).position(|w| w == b"\n\n") {
        return Some((pos + 1, 1));
    }
    None
}

/// Split a header block into individual logical header lines.
/// Preserves continuation (folded) lines as part of their parent line
/// by joining on leading whitespace. Each returned slice INCLUDES its
/// terminating CRLF or LF.
pub(super) fn split_header_lines(headers: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut line_start = 0_usize;
    let mut i = 0_usize;
    while i < headers.len() {
        let line_end = match headers[i..].iter().position(|&b| b == b'\n') {
            Some(off) => i + off + 1,
            None => headers.len(),
        };
        if line_end < headers.len() {
            let next = headers[line_end];
            if next == b' ' || next == b'\t' {
                i = line_end;
                continue;
            }
        }
        out.push(&headers[line_start..line_end]);
        line_start = line_end;
        i = line_end;
    }
    // cargo-mutants: known-equivalent — `< with >` here is observably
    // identical to the original. The inner loop always sets
    // `line_start = line_end` after each push, and the only `line_end`
    // value reachable when the loop exits is `headers.len()` (the
    // `None` branch of the `\n` search). On exit, `line_start ==
    // headers.len()`, so the predicate is false under both `<` and
    // `>`. The trailing block is defensive dead code in current usage.
    if line_start < headers.len() {
        out.push(&headers[line_start..]);
    }
    out
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "tests may expect on constructed values")]
mod mime_scrub_tests {
    use super::{detect_smuggling_spans, scrub_header_smuggling};
    use crate::output::WarningCode;

    #[test]
    fn scrub_smuggling_caps_dropped_names_at_eight() {
        // Kills `< with <=` on `dropped_names.len() < 8`. Build a header
        // block with 9 distinct smuggled headers; assert the warning's
        // `names=[...]` list has exactly 8 entries (original) — `<=`
        // would let the 9th name in.
        //
        // Each smuggled header has a unique name (`H0..H8`) and a
        // dangling `=?` that drops it. Headers without `?=` anywhere
        // later in the block are flagged via `EncodedWordEnd::Missing`,
        // which sets only that single line's mask bit — exactly the
        // shape of one-line-per-name we need.
        let mut raw = Vec::from(&b"From: real@example\r\n"[..]);
        for i in 0..9 {
            raw.extend_from_slice(format!("H{i}: =?\r\n").as_bytes());
        }
        raw.extend_from_slice(b"\r\nbody");
        let mut warnings = Vec::new();
        let _scrubbed = scrub_header_smuggling(&raw, &mut warnings);
        assert_eq!(
            warnings.len(),
            1,
            "exactly one aggregated smuggling warning"
        );
        assert_eq!(warnings[0].code, WarningCode::ParseHeaderSmugglingBlocked);
        let detail = warnings[0].detail.as_deref().unwrap_or("");
        // Original drops 9 headers with `count=9`, but lists at most 8 names.
        assert!(
            detail.contains("count=9"),
            "expected count=9, got detail={detail:?}",
        );
        // names list should have exactly 8 entries (commas separate them).
        let names_segment = detail
            .split("names=[")
            .nth(1)
            .and_then(|s| s.strip_suffix(']'))
            .expect("detail must include names=[...] when names list non-empty");
        let name_count = names_segment.split(',').count();
        assert_eq!(
            name_count, 8,
            "expected 8 names listed at the cap, got {name_count} from {names_segment:?}",
        );
    }

    #[test]
    fn detect_smuggling_does_not_revisit_processed_headers() {
        // Kills `+ with -` on `idx = end_idx + 1`. With `-`, idx jumps
        // backward to end_idx-1 = 0 after LaterHeader(1), causing
        // detect_smuggling_spans to re-process logical[0] and re-emit
        // LaterHeader(1) -> idx=0 -> infinite loop. The hung test then
        // fails via cargo-mutants timeout.
        //
        // Construction: 2 logical headers, smuggling spans both — the
        // minimal case where `end_idx == 1` and `end_idx - 1 == 0`.
        let logical: Vec<&[u8]> = vec![
            b"Subject: =?utf-8?B?x\r\n",
            b"X-Spliced: y@e?=\r\n", // `?=` closes the smuggled encoded-word
        ];
        let mask = detect_smuggling_spans(&logical);
        assert_eq!(mask, vec![true, true]);
    }

    #[test]
    fn detect_smuggling_uses_addition_for_start_pos() {
        // Kills `+ with *` on `start_pos = search_start + rel`. With `*`,
        // the second-pass search after the first encoded-word closes
        // computes start_pos = search_start * rel — wildly larger than
        // the additive offset — and overshoots the end of the header,
        // so locate_encoded_word_end returns Missing and flags the
        // line. The original adds and finds the second closer cleanly.
        let logical: Vec<&[u8]> = vec![b"X: =?u?B?p?= q =?v?B?r?=\r\n"];
        let mask = detect_smuggling_spans(&logical);
        assert_eq!(
            mask,
            vec![false],
            "two complete inline encoded-words are not smuggling",
        );
    }

    #[test]
    fn detect_smuggling_locates_encoded_word_end_using_addition() {
        // Kills `+ with -` on `start_pos + 2` in the call to
        // locate_encoded_word_end. With `-`, the closer search starts
        // four bytes earlier and picks up a stray `?=` immediately
        // before the genuine `=?` opener — classifying the dangling
        // encoded-word as SameHeader rather than Missing, and flipping
        // mask[0] from true to false.
        let logical: Vec<&[u8]> = vec![b"X: a?=?garbage\r\n"];
        let mask = detect_smuggling_spans(&logical);
        assert_eq!(
            mask,
            vec![true],
            "dangling `=?` opener with no `?=` after it must be flagged",
        );
    }

    #[test]
    fn detect_smuggling_skips_logical_end_idx_after_later_header() {
        // Kills `+ with *` on `idx = end_idx + 1`. With `*`, idx stays at
        // end_idx and re-scans logical[end_idx]. If logical[end_idx]
        // contains another `=?` whose closing falls in a later header,
        // the mutation flips an additional mask bit — mask differs from
        // the original.
        //
        // Construction:
        //   logical[0]: opens encoded-word; closes in logical[1]
        //   logical[1]: contains the closer `?=` AND a fresh opener `=?`
        //               whose own closer is in logical[2]
        //   logical[2]: closer `?=`; under original, never visited
        //               because idx jumps to 2 (= end_idx+1 = 1+1)... wait,
        //               LaterHeader(1) sets idx=2 which is the closer line;
        //               that line is then walked but contains no fresh `=?`.
        //               Under `*` mutant, idx=1: logical[1]'s fresh `=?`
        //               is detected, closes in logical[2] -> mask[2]=true.
        let logical: Vec<&[u8]> = vec![
            b"A: =?u?B?p\r\n",
            b"B: ?=garbage=?v?B?q\r\n",
            b"C: ?=\r\n",
            b"D: ok\r\n",
        ];
        let mask = detect_smuggling_spans(&logical);
        // Original: only logical[0..=1] are smuggling.
        assert_eq!(
            mask,
            vec![true, true, false, false],
            "original mask must not flag logical[2]",
        );
    }
}
