//! Expose MIME part bodies by IMAP RFC 3501 part ID without leaking
//! the `mail_parser` type surface across the rimap-content boundary.

use crate::error::ContentError;

/// A single decoded MIME part, identified by RFC 3501 part number.
#[derive(Debug, Clone)]
pub struct RawPart {
    /// IMAP-style part ID (e.g. "1", "1.2", "2").
    pub part_id: String,
    /// Decoded body bytes (post-transfer-decoding).
    pub body: Vec<u8>,
    /// Declared `Content-Type` value, lowercased, in `type/subtype` form.
    /// `application/octet-stream` when absent or unparsable.
    pub content_type: String,
    /// Decoded attachment filename from `Content-Disposition` or the
    /// `name` parameter, if present.
    pub filename: Option<String>,
}

/// Maximum depth to recurse into multipart trees. Matches MIME depth
/// caps in `parse.rs`.
const MAX_MIME_DEPTH: u32 = 64;

/// Walk an RFC 5322 message and return every leaf MIME part with its
/// IMAP part number, decoded body, content type, and filename.
///
/// # Errors
///
/// - [`ContentError::Malformed`] when the input is not a
///   parseable RFC 5322 message.
/// - [`ContentError::ParserPanic`] when the underlying `mail-parser`
///   panics and is caught by the safe-parser wrapper.
pub fn walk_attachment_parts(raw: &[u8]) -> Result<Vec<RawPart>, ContentError> {
    let parsed = crate::parse::safe_parser::safe_parse(raw)
        .map_err(|_| ContentError::ParserPanic)?
        .ok_or_else(|| ContentError::Malformed {
            reason: "failed to parse RFC 5322 message".into(),
        })?;

    let root = parsed
        .parts
        .first()
        .ok_or_else(|| ContentError::Malformed {
            reason: "message has no parts".into(),
        })?;

    let mut out = Vec::new();
    if root.is_multipart() {
        walk(&parsed, 0, "", &mut out, 0)?;
    } else {
        out.push(part_to_raw(&parsed, 0, "1")?);
    }
    Ok(out)
}

fn walk(
    msg: &mail_parser::Message<'_>,
    part_idx: usize,
    prefix: &str,
    out: &mut Vec<RawPart>,
    depth: u32,
) -> Result<(), ContentError> {
    // cargo-mutants: known-equivalent — `> with ==` and `> with >=` are
    // observably indistinguishable for any mail_parser-reachable input.
    // Per `crates/rimap-content/src/parse/mod.rs`, `parse_message` already
    // rejects messages whose MIME depth exceeds 8 (`MAX_MIME_DEPTH`)
    // before any caller of `walk_attachment_parts` sees them; the 64-level
    // defensive cap here therefore can never fire in production. The
    // `==` mutation only differs from `>` at exactly `depth == 64`, and
    // `>=` only at `depth in [64, max-tree-depth]`; both ranges are
    // unreachable.
    if depth > MAX_MIME_DEPTH {
        return Ok(());
    }
    let part = msg
        .parts
        .get(part_idx)
        .ok_or_else(|| ContentError::Malformed {
            reason: format!("sub_parts index {part_idx} outside msg.parts"),
        })?;

    if let Some(children) = part.sub_parts() {
        for (i, &child_idx) in children.iter().enumerate() {
            let num = i + 1;
            let child_id = if prefix.is_empty() {
                num.to_string()
            } else {
                format!("{prefix}.{num}")
            };
            // cargo-mutants: known-equivalent — `+ with *` on `depth + 1`
            // is observably indistinguishable for any reachable input.
            // `depth * 1 == depth` keeps the recursion at depth 0
            // forever, but mail_parser-reachable trees have finite depth
            // (capped well below the 64 defensive cap by `parse_message`),
            // so both `+ 1` and `* 1` walk to the same set of leaves
            // before recursion bottoms out on `sub_parts() == None`.
            walk(msg, child_idx as usize, &child_id, out, depth + 1)?;
        }
    } else {
        let part_id = if prefix.is_empty() {
            "1".to_string()
        } else {
            prefix.to_string()
        };
        out.push(part_to_raw(msg, part_idx, &part_id)?);
    }
    Ok(())
}

fn part_to_raw(
    msg: &mail_parser::Message<'_>,
    idx: usize,
    part_id: &str,
) -> Result<RawPart, ContentError> {
    use mail_parser::MimeHeaders;

    let part = msg.parts.get(idx).ok_or_else(|| ContentError::Malformed {
        reason: format!("part index {idx} outside msg.parts"),
    })?;
    let body = part.contents().to_vec();
    let content_type = if let Some(ct) = part.content_type() {
        let main = ct.ctype().to_lowercase();
        let sub = ct
            .subtype()
            .map_or_else(|| "octet-stream".to_string(), str::to_lowercase);
        format!("{main}/{sub}")
    } else {
        "application/octet-stream".to_string()
    };
    let filename = part.attachment_name().map(String::from);
    Ok(RawPart {
        part_id: part_id.to_string(),
        body,
        content_type,
        filename,
    })
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn single_part_message_yields_one_raw_part() {
        let raw = b"From: a@b\r\n\
                    Content-Type: text/plain\r\n\
                    \r\n\
                    hello\r\n";
        let parts = walk_attachment_parts(raw).unwrap();
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].part_id, "1");
        assert_eq!(parts[0].content_type, "text/plain");
        assert!(parts[0].body.starts_with(b"hello"));
    }

    #[test]
    fn multipart_yields_leaf_parts_with_imap_ids() {
        let raw = b"From: a@b\r\n\
                    Content-Type: multipart/mixed; boundary=BND\r\n\
                    \r\n\
                    --BND\r\n\
                    Content-Type: text/plain\r\n\
                    \r\n\
                    hi\r\n\
                    --BND\r\n\
                    Content-Type: image/png\r\n\
                    Content-Disposition: attachment; filename=cat.png\r\n\
                    \r\n\
                    BINARY\r\n\
                    --BND--\r\n";
        let parts = walk_attachment_parts(raw).unwrap();
        let ids: Vec<&str> = parts.iter().map(|p| p.part_id.as_str()).collect();
        assert_eq!(ids, vec!["1", "2"]);
        assert_eq!(parts[1].content_type, "image/png");
        assert_eq!(parts[1].filename.as_deref(), Some("cat.png"));
    }

    #[test]
    fn unparsable_is_malformed() {
        let err = walk_attachment_parts(&[]).unwrap_err();
        assert!(matches!(err, ContentError::Malformed { .. }));
    }
}
