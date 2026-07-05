//! Text / HTML body extraction and MIME-depth enforcement.

use mail_parser::{Message, PartType};

use crate::error::ContentError;
use crate::html;
use crate::output::{SecurityWarning, WarningCode};
use crate::parse::{MAX_BODY_BYTES, MAX_MIME_DEPTH, MAX_MIME_PARTS, MAX_TOTAL_BODY_BYTES};
use crate::unicode;

/// Result of walking a message's text bodies: the primary text body,
/// any alternate text parts, an optional sanitized HTML rendering, the
/// anchor hrefs that survived sanitization, and whether any part was
/// truncated.
#[derive(Debug)]
pub(super) struct BodyExtraction {
    pub(super) primary_text: String,
    pub(super) alternates: Vec<String>,
    pub(super) body_html: Option<String>,
    pub(super) anchor_hrefs: Vec<String>,
    pub(super) body_truncated: bool,
}

/// Walk `message.text_body`, enforce MIME limits, and sanitize each
/// part into a `BodyExtraction`. Emits `ParseBodyTruncated` on any
/// part whose raw byte length exceeds `MAX_BODY_BYTES`; terminal
/// `LimitExceeded` errors for part count or depth overflow.
pub(super) fn extract_bodies(
    message: &Message<'_>,
    warnings: &mut Vec<SecurityWarning>,
) -> Result<BodyExtraction, ContentError> {
    let part_count = message.parts.len();
    if part_count > MAX_MIME_PARTS {
        warnings.push(SecurityWarning::at(
            WarningCode::ParseMimePartCountExceeded,
            format!("count={part_count} limit={MAX_MIME_PARTS}"),
            "mime",
        ));
        return Err(ContentError::LimitExceeded {
            kind: "mime_parts",
            limit: MAX_MIME_PARTS,
        });
    }

    check_mime_depth(message, warnings)?;

    // Determine the part id of the first HTML body so only one HTML
    // part per message flows through `html::sanitize`. mail-parser 0.11
    // exposes html bodies via `message.html_body: Vec<MessagePartId>`
    // (MessagePartId = u32).
    let primary_html_part_id: Option<usize> = message.html_body.first().map(|id| *id as usize);

    let mut state = BodyWalkState::default();

    for (idx, &part_id) in message.text_body.iter().enumerate() {
        let Some(part) = message.parts.get(part_id as usize) else {
            continue;
        };
        match &part.body {
            PartType::Text(s) => {
                let raw_bytes = s.as_bytes();
                decode_text_part(part, raw_bytes, idx, &mut state, warnings);
            }
            PartType::Html(cow) => {
                let is_primary = primary_html_part_id == Some(part_id as usize);
                if !is_primary {
                    continue;
                }
                sanitize_html_part(part, cow.as_bytes(), &mut state, warnings)?;
            }
            PartType::Message(_)
            | PartType::Binary(_)
            | PartType::InlineBinary(_)
            | PartType::Multipart(_) => continue,
        }
        if state.total_bytes >= MAX_TOTAL_BODY_BYTES {
            state.body_truncated = true;
            warnings.push(SecurityWarning::at(
                WarningCode::ParseBodyTruncated,
                format!("total={} limit={MAX_TOTAL_BODY_BYTES}", state.total_bytes),
                "body:aggregate",
            ));
            break;
        }
    }

    surface_alternative_html(message, primary_html_part_id, &mut state, warnings)?;

    Ok(BodyExtraction {
        primary_text: state.primary_text.unwrap_or_default(),
        alternates: state.alternates,
        body_html: state.body_html,
        anchor_hrefs: state.anchor_hrefs,
        body_truncated: state.body_truncated,
    })
}

/// Mutable accumulator threaded through `extract_bodies` and its
/// per-part helpers. Keeps the main loop body small enough to stay
/// inside the workspace function-length and complexity limits.
#[derive(Debug, Default)]
struct BodyWalkState {
    primary_text: Option<String>,
    alternates: Vec<String>,
    body_html: Option<String>,
    anchor_hrefs: Vec<String>,
    body_truncated: bool,
    total_bytes: usize,
}

/// Decode and sanitize a single `text/plain` part, updating `state`
/// and pushing any new warnings (including `ParseBodyTruncated` when
/// the raw part exceeds [`MAX_BODY_BYTES`]).
fn decode_text_part(
    part: &mail_parser::MessagePart<'_>,
    raw_bytes: &[u8],
    idx: usize,
    state: &mut BodyWalkState,
    warnings: &mut Vec<SecurityWarning>,
) {
    if raw_bytes.len() > MAX_BODY_BYTES {
        state.body_truncated = true;
        warnings.push(SecurityWarning::at(
            WarningCode::ParseBodyTruncated,
            format!("original={} limit={}", raw_bytes.len(), MAX_BODY_BYTES),
            format!("body:text[{idx}]"),
        ));
    }
    let location = format!("body:text[{idx}]");
    let charset = part_charset(part);
    let (text, mut new_warnings) =
        unicode::sanitize(raw_bytes, charset.as_deref(), MAX_BODY_BYTES, &location);
    warnings.append(&mut new_warnings);
    state.total_bytes = state.total_bytes.saturating_add(text.len());
    if state.primary_text.is_none() {
        state.primary_text = Some(text);
    } else {
        state.alternates.push(text);
    }
}

/// Run the primary `text/html` part through [`crate::html::sanitize`].
///
/// On success: merges the produced warnings into `warnings`, places
/// the extracted plain text at the primary text slot if empty (else
/// pushes to alternates), and stores the sanitized html and anchor
/// hrefs on `state`.
///
/// On `ContentError::LimitExceeded`: emits a `ParseBodyTruncated`
/// warning at `body:html` and continues. Other errors propagate.
fn sanitize_html_part(
    part: &mail_parser::MessagePart<'_>,
    raw_bytes: &[u8],
    state: &mut BodyWalkState,
    warnings: &mut Vec<SecurityWarning>,
) -> Result<(), ContentError> {
    let charset = part_charset(part);
    match html::sanitize(raw_bytes, charset.as_deref()) {
        Ok(result) => {
            warnings.extend(result.warnings);
            state.total_bytes = state.total_bytes.saturating_add(result.body_text.len());
            if state.primary_text.is_none() {
                state.primary_text = Some(result.body_text);
            } else {
                state.alternates.push(result.body_text);
            }
            state.body_html = Some(result.body_html);
            state.anchor_hrefs = result.anchor_hrefs;
            Ok(())
        }
        Err(ContentError::LimitExceeded { kind, limit }) => {
            state.body_truncated = true;
            warnings.push(SecurityWarning::at(
                WarningCode::ParseBodyTruncated,
                format!("original={} limit={limit} kind={kind}", raw_bytes.len()),
                "body:html",
            ));
            Ok(())
        }
        Err(err) => Err(err),
    }
}

/// Surface the primary `text/html` part when it was not already
/// reached by the `text_body` walk.
///
/// For `multipart/alternative`, mail-parser lists the `text/plain`
/// part in `text_body` and the `text/html` part in `html_body`, so the
/// main loop never visits the HTML part and `state.body_html` stays
/// `None`. This routes that part through the identical
/// [`sanitize_html_part`] path used for the in-loop primary HTML body,
/// so the surfaced HTML receives the same sanitization, hidden-content
/// detection, and anchor-href lookalike auditing. `text/plain` remains
/// the primary body: because `state.primary_text` is already set, the
/// HTML's extracted text lands in `alternates`.
///
/// No-ops when there is no primary HTML part, when HTML was already
/// surfaced (HTML-only messages, where the part is in `text_body`), or
/// when the aggregate body budget is already exhausted.
fn surface_alternative_html(
    message: &Message<'_>,
    primary_html_part_id: Option<usize>,
    state: &mut BodyWalkState,
    warnings: &mut Vec<SecurityWarning>,
) -> Result<(), ContentError> {
    let Some(part_id) = primary_html_part_id else {
        return Ok(());
    };
    if state.body_html.is_some() || state.body_truncated {
        return Ok(());
    }
    if state.total_bytes >= MAX_TOTAL_BODY_BYTES {
        return Ok(());
    }
    let Some(part) = message.parts.get(part_id) else {
        return Ok(());
    };
    let PartType::Html(cow) = &part.body else {
        return Ok(());
    };
    sanitize_html_part(part, cow.as_bytes(), state, warnings)
}

/// Read the `charset` attribute off a part's Content-Type header.
pub(super) fn part_charset(part: &mail_parser::MessagePart<'_>) -> Option<String> {
    use mail_parser::MimeHeaders as _;
    part.content_type()
        .and_then(|ct| ct.attribute("charset"))
        .map(str::to_string)
}

/// Enforce [`MAX_MIME_DEPTH`] by walking the part tree from part 0.
fn check_mime_depth(
    message: &Message<'_>,
    warnings: &mut Vec<SecurityWarning>,
) -> Result<(), ContentError> {
    let depth = compute_max_depth(message);
    if depth > MAX_MIME_DEPTH {
        warnings.push(SecurityWarning::at(
            WarningCode::ParseMimeDepthExceeded,
            format!("depth={depth} limit={MAX_MIME_DEPTH}"),
            "mime",
        ));
        return Err(ContentError::LimitExceeded {
            kind: "mime_depth",
            limit: MAX_MIME_DEPTH,
        });
    }
    Ok(())
}

/// Walk the MIME tree from part 0 and return the maximum depth.
fn compute_max_depth(message: &Message<'_>) -> usize {
    debug_assert!(
        message.parts.len() <= MAX_MIME_PARTS,
        "compute_max_depth must only be called after MAX_MIME_PARTS enforcement"
    );
    depth_recursive(message, 0, 1)
}

/// Recursive helper used by [`compute_max_depth`]; visits `part_id`
/// at level `current` and returns the deepest level reachable.
fn depth_recursive(message: &Message<'_>, part_id: usize, current: usize) -> usize {
    // Defensive short-circuit: bound recursion independently of any
    // mail-parser tree invariant. If current already exceeds
    // MAX_MIME_DEPTH, the caller will reject; no need to walk deeper.
    if current > MAX_MIME_DEPTH {
        return current;
    }
    let Some(part) = message.parts.get(part_id) else {
        return current;
    };
    match &part.body {
        PartType::Multipart(child_ids) => child_ids
            .iter()
            .map(|&child_id| depth_recursive(message, child_id as usize, current + 1))
            .max()
            .unwrap_or(current),
        PartType::Message(_) => current + 1,
        PartType::Text(_) | PartType::Html(_) | PartType::Binary(_) | PartType::InlineBinary(_) => {
            current
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests may unwrap on constructed values")]
#[expect(clippy::expect_used, reason = "tests may expect on constructed values")]
#[expect(clippy::panic, reason = "test failure paths")]
mod bodies_tests {
    use std::fmt::Write as _;

    use mail_parser::MessageParser;

    use super::part_charset;
    use crate::error::ContentError;
    use crate::output::WarningCode;
    use crate::parse::{MAX_BODY_BYTES, MAX_MIME_DEPTH, MAX_MIME_PARTS, parse_message};

    /// Build an N-leaf multipart/mixed message: one root multipart
    /// container plus `leaves` text/plain children. Total parts =
    /// `leaves + 1` (the root counts).
    fn build_flat_multipart(leaves: usize) -> Vec<u8> {
        let mut raw = String::from(
            "From: a@example\r\nContent-Type: multipart/mixed; boundary=\"B\"\r\n\r\n",
        );
        for i in 0..leaves {
            write!(raw, "--B\r\nContent-Type: text/plain\r\n\r\nleaf{i}\r\n").unwrap();
        }
        raw.push_str("--B--\r\n");
        raw.into_bytes()
    }

    #[test]
    fn parse_accepts_part_count_at_max() {
        // Kills both `> with ==` and `> with >=` mutations on the
        // `part_count > MAX_MIME_PARTS` guard. With root + 99 leaves =
        // 100 = MAX_MIME_PARTS:
        //  - original `>` :  100 > 100 -> false  -> Ok
        //  - `==` mutant  :  100 == 100 -> true  -> Err  (caught)
        //  - `>=` mutant  :  100 >= 100 -> true  -> Err  (caught)
        let raw = build_flat_multipart(MAX_MIME_PARTS - 1);
        let content = parse_message(&raw).expect("100-part message must parse");
        assert!(
            !content
                .security_warnings
                .iter()
                .any(|w| matches!(w.code, WarningCode::ParseMimePartCountExceeded)),
            "no ParseMimePartCountExceeded warning at the boundary",
        );
    }

    #[test]
    fn part_charset_returns_explicit_charset() {
        // Kills all three wholesale stubs at part_charset (None,
        // Some(""), Some("xyzzy")) by asserting an explicit
        // charset=iso-8859-1 round-trips through.
        let raw = b"From: a@example\r\n\
                    Content-Type: text/plain; charset=iso-8859-1\r\n\
                    \r\n\
                    body";
        let message = MessageParser::default().parse(raw).unwrap();
        let part = message.parts.first().expect("a single text/plain part");
        let charset = part_charset(part).expect("Content-Type's charset attribute populates");
        assert_eq!(charset, "iso-8859-1");
    }

    #[test]
    fn parse_does_not_truncate_body_at_max_bytes() {
        // Kills `> with >=` on `raw_bytes.len() > MAX_BODY_BYTES`. With
        // an exactly-MAX_BODY_BYTES body:
        //  - original `>` :  1MB > 1MB -> false -> no warning
        //  - `>=` mutant  :  1MB >= 1MB -> true  -> ParseBodyTruncated  (caught)
        let mut raw = Vec::from(&b"From: a@example\r\nContent-Type: text/plain\r\n\r\n"[..]);
        raw.extend(std::iter::repeat_n(b'x', MAX_BODY_BYTES));
        let content = parse_message(&raw).expect("MAX_BODY_BYTES body must parse");
        assert!(
            !content
                .security_warnings
                .iter()
                .any(|w| matches!(w.code, WarningCode::ParseBodyTruncated)),
            "no ParseBodyTruncated warning at the boundary",
        );
    }

    /// Build a `depth`-deep multipart/mixed nesting with a leaf
    /// text/plain at the bottom. mail-parser counts depth as the
    /// number of nested levels reachable from part 0; a value of N
    /// means N-1 nested multiparts plus the leaf (e.g. depth=8 ->
    /// 7 multipart containers + 1 text leaf).
    fn build_nested_multipart(depth: usize) -> Vec<u8> {
        let mut raw = String::from("From: a@example\r\n");
        write!(
            raw,
            "Content-Type: multipart/mixed; boundary=\"B0\"\r\n\r\n"
        )
        .unwrap();
        for i in 0..depth.saturating_sub(2) {
            write!(raw, "--B{i}\r\n").unwrap();
            write!(
                raw,
                "Content-Type: multipart/mixed; boundary=\"B{}\"\r\n\r\n",
                i + 1
            )
            .unwrap();
        }
        write!(raw, "--B{}\r\n", depth.saturating_sub(2)).unwrap();
        raw.push_str("Content-Type: text/plain\r\n\r\nleaf\r\n");
        for i in (0..depth.saturating_sub(1)).rev() {
            write!(raw, "--B{i}--\r\n").unwrap();
        }
        raw.into_bytes()
    }

    #[test]
    fn parse_accepts_mime_depth_at_max() {
        // Kills `> with >=` on `depth > MAX_MIME_DEPTH`. With the
        // 8-deep construction:
        //  - original `>` :  8 > 8  -> false -> Ok
        //  - `>=` mutant  :  8 >= 8 -> true  -> Err  (caught)
        let raw = build_nested_multipart(MAX_MIME_DEPTH);
        let content = parse_message(&raw).expect("MAX_MIME_DEPTH-deep message must parse");
        assert!(
            !content
                .security_warnings
                .iter()
                .any(|w| matches!(w.code, WarningCode::ParseMimeDepthExceeded)),
            "no ParseMimeDepthExceeded warning at the boundary",
        );
    }

    /// Build a 7-multipart-deep wrapper around a `message/rfc822`
    /// attachment. `depth_recursive` walks 7 multipart levels (`current`
    /// climbs 1..7), then the Message handler returns
    /// `current + 1 = 9` — one above `MAX_MIME_DEPTH`. Mutations on
    /// that `+ 1` (`-` returns 7, `*` returns 8) drop max depth to
    /// 7 or 8, both within the limit, so the error stops firing.
    fn build_message_rfc822_at_depth_8() -> Vec<u8> {
        let mut raw = String::from("From: outer@example\r\n");
        write!(
            raw,
            "Content-Type: multipart/mixed; boundary=\"B0\"\r\n\r\n"
        )
        .unwrap();
        for i in 0..6 {
            write!(raw, "--B{i}\r\n").unwrap();
            write!(
                raw,
                "Content-Type: multipart/mixed; boundary=\"B{}\"\r\n\r\n",
                i + 1
            )
            .unwrap();
        }
        // B6 contains a single message/rfc822 attachment.
        raw.push_str("--B6\r\n");
        raw.push_str("Content-Type: message/rfc822\r\n\r\n");
        raw.push_str("From: inner@example\r\n\r\ninner-body\r\n");
        // Close all the multipart containers.
        for i in (0..7).rev() {
            write!(raw, "--B{i}--\r\n").unwrap();
        }
        raw.into_bytes()
    }

    #[test]
    fn parse_rejects_message_rfc822_at_depth_above_max() {
        // Kills both `+ with -` and `+ with *` mutations on
        // `PartType::Message(_) => current + 1`. The construction
        // places the message/rfc822 part at depth 9 in the original;
        // both mutations drop it to <= 8, removing the error.
        let raw = build_message_rfc822_at_depth_8();
        let err = parse_message(&raw).expect_err("depth-9 via Message must error");
        match err {
            ContentError::LimitExceeded { kind, limit } => {
                assert_eq!(kind, "mime_depth");
                assert_eq!(limit, MAX_MIME_DEPTH);
            }
            other => panic!("expected LimitExceeded mime_depth, got {other:?}"),
        }
    }
}
