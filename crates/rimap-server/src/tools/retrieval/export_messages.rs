//! `export_messages` tool handler: bulk raw export of multiple UIDs to a
//! single `git am`-able mbox file in the download sandbox.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::boot::registry::AccountState;
use crate::mcp::response::ToolResponse;

/// Hard ceiling on the aggregate export size, regardless of the
/// caller-supplied `max_total_bytes`.
pub const MAX_EXPORT_TOTAL_BYTES: u64 = 100 * 1024 * 1024;

/// Input for the `export_messages` tool.
#[derive(Debug, Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct ExportMessagesInput {
    /// IMAP folder containing the messages.
    pub folder: String,
    /// UIDs to export, in mbox (patch) order. Non-empty, max 100, de-duped.
    pub uids: Vec<core::num::NonZeroU32>,
    /// UIDVALIDITY observed when the UID list was discovered (e.g. from
    /// `search`). Required: pins mailbox identity across search→export.
    #[serde(deserialize_with = "crate::tools::lenient_int::deserialize_nonzero_u32")]
    #[schemars(schema_with = "crate::tools::lenient_int::schema_nonzero_u32")]
    pub expected_uidvalidity: core::num::NonZeroU32,
    /// Optional destination directory. Must be within the download root.
    pub dest_dir: Option<String>,
    /// Optional advisory basename prefix (sanitized).
    pub filename: Option<String>,
    /// Aggregate byte cap; clamped to `MAX_EXPORT_TOTAL_BYTES`.
    #[serde(
        default,
        deserialize_with = "crate::tools::lenient_int::deserialize_opt_u64"
    )]
    #[schemars(schema_with = "crate::tools::lenient_int::schema_opt_u64")]
    pub max_total_bytes: Option<u64>,
    /// When true, write the successes to a `.partial.mbox` artifact instead
    /// of failing the whole call. Default false (all-or-nothing).
    pub allow_partial: Option<bool>,
}

/// One successfully exported message.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct ExportedUid {
    pub uid: u32,
    pub size_bytes: usize,
}

/// Reason a requested UID was not exported. Both are determined at the size
/// preflight, before any body fetch — a UID that reaches the body fetch is
/// known-present and in-bounds, and any error there is fatal (never per-UID),
/// so there is no `FetchError` variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExportFailReason {
    NotFound,
    Oversize,
}

/// One requested UID that failed.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct FailedUid {
    pub uid: u32,
    pub reason: ExportFailReason,
}

/// Trusted metadata for an `export_messages` response.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct ExportMessagesMeta {
    /// Folder the messages were exported from.
    pub folder: String,
    /// True iff every requested UID was exported.
    pub complete: bool,
    /// `git am`-ready mbox path. Present only on a complete export;
    /// omitted from the response otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Path of a `.partial.mbox` artifact. Present only on a partial
    /// export; omitted otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partial_path: Option<String>,
    /// SHA-256 of the written mbox, hex-encoded.
    pub sha256: String,
    /// Number of messages written to the artifact.
    pub message_count: usize,
    /// Total bytes written.
    pub total_bytes: u64,
    /// UIDVALIDITY the export was pinned to.
    pub uid_validity: u32,
    /// Exported UIDs, in mbox order, with sizes.
    pub succeeded: Vec<ExportedUid>,
    /// Requested UIDs that failed, with reasons.
    pub failed: Vec<FailedUid>,
}

/// Pinned mboxrd separator. `git am`/`mailsplit` use it only as a delimiter
/// and take real authorship from each message's own `From:` header.
const MBOX_SEPARATOR: &[u8] = b"From mboxrd@rusty-imap-mcp Thu Jan  1 00:00:00 1970\n";

/// Assemble raw RFC822 messages into a single mboxrd byte buffer suitable
/// for `git am`. Each message is preceded by [`MBOX_SEPARATOR`] at column 0;
/// every line matching `^>*From ` is escaped with one extra leading `>`;
/// CRLF is preserved verbatim.
///
/// Callers must pass non-empty message bodies; an empty body would emit a
/// bare separator with no content. Task 7's handler validates this upstream.
#[cfg_attr(not(test), expect(dead_code, reason = "wired into handle in Task 7"))]
fn build_mbox(messages: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for msg in messages {
        // Ensure the previous message ended with a line feed so this
        // separator starts at column 0.
        if let Some(&last) = out.last()
            && last != b'\n'
        {
            out.push(b'\n');
        }
        out.extend_from_slice(MBOX_SEPARATOR);
        escape_from_lines_into(&mut out, msg);
    }
    // Trailing newline for a well-formed final message.
    if let Some(&last) = out.last()
        && last != b'\n'
    {
        out.push(b'\n');
    }
    out
}

/// Append `msg` to `out`, escaping each `^>*From ` line with one extra `>`.
fn escape_from_lines_into(out: &mut Vec<u8>, msg: &[u8]) {
    let mut line_start = 0;
    for i in 0..msg.len() {
        if msg[i] == b'\n' {
            write_mbox_line(out, &msg[line_start..=i]);
            line_start = i + 1;
        }
    }
    if line_start < msg.len() {
        write_mbox_line(out, &msg[line_start..]);
    }
}

/// Append `line` to `out`, prefixing it with `>` when it matches `^>*From `.
fn write_mbox_line(out: &mut Vec<u8>, line: &[u8]) {
    if line_is_from(line) {
        out.push(b'>');
    }
    out.extend_from_slice(line);
}

/// Whether `line` (from column 0) matches `^>*From ` — any run of `>` then
/// the literal `From `.
fn line_is_from(line: &[u8]) -> bool {
    let mut j = 0;
    while j < line.len() && line[j] == b'>' {
        j += 1;
    }
    line[j..].starts_with(b"From ")
}

/// Sanitize the advisory `filename` prefix to a safe single basename, or
/// return the default `"messages"` when absent.
///
/// Uses a conservative **allowlist** grammar — `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`
/// — because the prefix ends up in the `path` returned to the agent and the
/// documented flow is `git am <path>`. The allowlist rejects path separators,
/// `..` traversal, shell metacharacters, whitespace, quotes, and all non-ASCII
/// (so bidi / zero-width / tag display-spoofing codepoints cannot appear), and
/// the alphanumeric-first rule rejects leading `.`/`-`.
///
/// # Errors
///
/// `RimapError::Authz { code: InvalidInput }` if the prefix is empty after
/// trimming, longer than 64 bytes, or contains any character outside the
/// grammar.
#[cfg_attr(not(test), expect(dead_code, reason = "wired into handle in Task 7"))]
fn sanitize_filename_prefix(prefix: Option<&str>) -> Result<String, rimap_core::RimapError> {
    let Some(raw) = prefix else {
        return Ok("messages".to_string());
    };
    let trimmed = raw.trim();
    let valid = !trimmed.is_empty()
        && trimmed.len() <= 64
        && trimmed
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphanumeric())
        && trimmed
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if !valid {
        return Err(rimap_core::RimapError::invalid_input(
            "filename prefix must match [A-Za-z0-9][A-Za-z0-9._-]{0,63} \
             (conservative ASCII basename)",
        ));
    }
    Ok(trimmed.to_string())
}

/// Execute the `export_messages` tool.
///
/// # Errors
///
/// Returns `RimapError::Internal` — not yet implemented (filled in Task 7).
#[expect(
    clippy::unused_async,
    reason = "inert handler; dispatch awaits this future and the real \
              implementation (Task 7) performs IMAP I/O"
)]
pub async fn handle(
    _account: &AccountState,
    _input: ExportMessagesInput,
) -> Result<ToolResponse<ExportMessagesMeta, ()>, rimap_core::RimapError> {
    Err(rimap_core::RimapError::Internal(
        "export_messages not yet implemented".into(),
    ))
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod sanitize_tests {
    use super::sanitize_filename_prefix;

    #[test]
    fn default_when_absent() {
        assert_eq!(sanitize_filename_prefix(None).unwrap(), "messages");
    }

    #[test]
    fn accepts_plain_basename() {
        assert_eq!(
            sanitize_filename_prefix(Some("dpdk-series")).unwrap(),
            "dpdk-series"
        );
    }

    #[test]
    fn rejects_everything_outside_the_allowlist() {
        for bad in [
            "../escape",
            "/abs/path",
            "a/b",
            "a\\b",
            "",
            "  ",
            "a\u{0}b",
            "a\nb", // separators/control
            "a;b",
            "a b",
            "a'b",
            "a\"b",
            "a$b",
            "a|b",
            "a&b",
            "a`b", // shell metachars/spaces/quotes
            "-lead",
            ".hidden", // leading dash/dot
            "a\u{202E}b",
            "a\u{200B}b",
            "a\u{E0001}b", // bidi / zero-width / tag
        ] {
            assert!(
                sanitize_filename_prefix(Some(bad)).is_err(),
                "should reject {bad:?}"
            );
        }
        // Overlong (> 64 chars) is rejected.
        let long = "a".repeat(65);
        assert!(sanitize_filename_prefix(Some(&long)).is_err());
        // Exactly 64 chars is the accepted boundary.
        let max = "a".repeat(64);
        assert!(sanitize_filename_prefix(Some(&max)).is_ok());
    }

    #[test]
    fn accepts_conservative_ascii_basenames() {
        for ok in ["messages", "dpdk-series", "patch_set.v2", "AB12"] {
            assert!(
                sanitize_filename_prefix(Some(ok)).is_ok(),
                "should accept {ok:?}"
            );
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod build_mbox_tests {
    use super::build_mbox;

    const SEP: &[u8] = b"From mboxrd@rusty-imap-mcp Thu Jan  1 00:00:00 1970\n";

    #[test]
    fn single_message_gets_separator_and_trailing_newline() {
        let out = build_mbox(&[b"Subject: hi\r\n\r\nbody".to_vec()]);
        assert!(out.starts_with(SEP), "missing leading separator");
        assert!(out.ends_with(b"\n"), "must end with newline");
        assert!(out.ends_with(b"body\n"));
    }

    #[test]
    fn missing_terminal_newline_padded_before_next_separator() {
        // First message has no trailing newline; the second separator must
        // still start at column 0.
        let out = build_mbox(&[
            b"a: 1\r\n\r\nno-newline".to_vec(),
            b"b: 2\r\n\r\nx\n".to_vec(),
        ]);
        let text = String::from_utf8(out).unwrap();
        // Exactly two separators, each at the start of a line.
        let seps: Vec<_> = text.match_indices("From mboxrd@").collect();
        assert_eq!(seps.len(), 2);
        for (idx, _) in &seps {
            assert!(
                *idx == 0 || text.as_bytes()[idx - 1] == b'\n',
                "separator not at col 0"
            );
        }
    }

    #[test]
    fn escapes_every_from_line_including_nested_and_header_position() {
        let msg = b"From the desk of X\r\n>From already escaped\r\nFrom \r\nnormal\n".to_vec();
        let out = build_mbox(&[msg]);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains(">From the desk of X"));
        assert!(text.contains(">>From already escaped"));
        assert!(text.contains(">From \r\n"));
        assert!(text.contains("\nnormal"));
    }

    #[test]
    fn preserves_crlf_verbatim_in_body() {
        let out = build_mbox(&[b"H: 1\r\n\r\nline1\r\nline2\r\n".to_vec()]);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("line1\r\nline2\r\n"));
    }

    #[test]
    fn split_back_round_trips_messages() {
        // Build, then split on separator lines and un-escape; must equal inputs.
        let inputs = vec![
            b"A: 1\r\n\r\nFrom space\r\nbody1\r\n".to_vec(),
            b"B: 2\r\n\r\nbody2\n".to_vec(),
        ];
        let mbox = build_mbox(&inputs);
        let recovered = split_and_unescape(&mbox);
        assert_eq!(recovered.len(), inputs.len());
        // Compare ignoring a single trailing newline build_mbox may add.
        for (got, want) in recovered.iter().zip(inputs.iter()) {
            assert_eq!(trim_one_trailing_nl(got), trim_one_trailing_nl(want));
        }
    }

    fn trim_one_trailing_nl(b: &[u8]) -> &[u8] {
        b.strip_suffix(b"\n").unwrap_or(b)
    }

    // Test-only inverse of build_mbox's framing: split on separator lines,
    // strip one leading '>' from each `^>+From ` line.
    fn split_and_unescape(mbox: &[u8]) -> Vec<Vec<u8>> {
        let mut parts: Vec<Vec<u8>> = Vec::new();
        let mut cur: Option<Vec<u8>> = None;
        for line in split_keep_newlines(mbox) {
            if line == SEP {
                if let Some(c) = cur.take() {
                    parts.push(c);
                }
                cur = Some(Vec::new());
            } else if let Some(c) = cur.as_mut() {
                c.extend_from_slice(&unescape_line(line));
            }
        }
        if let Some(c) = cur.take() {
            parts.push(c);
        }
        parts
    }

    fn unescape_line(line: &[u8]) -> Vec<u8> {
        // If line is `>+From `, drop one leading '>'.
        let mut j = 0;
        while j < line.len() && line[j] == b'>' {
            j += 1;
        }
        if j >= 1 && line[j..].starts_with(b"From ") {
            line[1..].to_vec()
        } else {
            line.to_vec()
        }
    }

    fn split_keep_newlines(b: &[u8]) -> Vec<&[u8]> {
        let mut out = Vec::new();
        let mut start = 0;
        for i in 0..b.len() {
            if b[i] == b'\n' {
                out.push(&b[start..=i]);
                start = i + 1;
            }
        }
        if start < b.len() {
            out.push(&b[start..]);
        }
        out
    }
}
