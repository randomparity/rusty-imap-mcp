//! `search` tool handler.
//!
//! Search responses intentionally omit per-envelope `SecurityWarning`
//! entries. `sanitize_for_output` runs a header-appropriate subset of
//! the `rimap-content` Unicode pipeline (NFKC, line-ending
//! normalization, disallowed-codepoint filtering, grapheme truncation)
//! and skips the `decode` step that would surface warnings. Envelope
//! snippets (subject, date, addresses, `Message-ID`) are bounded and
//! already UTF-8, so no warnings are produced and the top-level
//! `security_warnings` on a `search` response is always empty. Full
//! warning propagation happens in `fetch_message`, where MIME bodies
//! flow through `unicode::sanitize`.

use rimap_imap::types::{
    Address, FetchSpec, FetchedMessage, Flag, SearchQuery, StructuredQuery, Uid,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::boot::registry::AccountState;
use crate::mcp::response::ToolResponse;

/// Maximum number of results per page.
const MAX_LIMIT: usize = 100;

/// Input for the `search` tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SearchInput {
    /// IMAP folder to search in.
    pub folder: String,
    /// Filter by `From` header substring.
    pub from: Option<String>,
    /// Filter by `To` header substring.
    pub to: Option<String>,
    /// Filter by `Subject` header substring.
    pub subject: Option<String>,
    /// Messages since this ISO date (inclusive), e.g. "2026-01-01".
    pub since: Option<String>,
    /// Messages before this ISO date (exclusive), e.g. "2026-02-01".
    pub before: Option<String>,
    /// Filter by seen/unseen status.
    pub seen: Option<bool>,
    /// Filter for messages with attachments.
    pub has_attachment: Option<bool>,
    /// Raw IMAP SEARCH query (full posture only).
    pub advanced_query: Option<String>,
    /// Max results to return (default 100, max 100).
    pub limit: Option<usize>,
    /// Offset into the result set (default 0).
    pub offset: Option<usize>,
}

/// A single message entry in a `search` untrusted payload.
#[derive(Debug, Serialize)]
#[cfg_attr(feature = "test-support", derive(schemars::JsonSchema))]
pub struct SearchResultEntry {
    /// UID of the message.
    pub uid: u32,
    /// Message size in bytes, if fetched.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u32>,
    /// IMAP flags on the message, if fetched.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flags: Option<Vec<String>>,
    /// Subject header, sanitized.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// Date header, sanitized.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
    /// From addresses, sanitized. Omitted when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub from: Vec<String>,
    /// To addresses, sanitized. Omitted when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub to: Vec<String>,
    /// RFC 2822 `Message-ID`, sanitized.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
}

/// Trusted metadata for a `search` response.
#[derive(Debug, Serialize)]
#[cfg_attr(feature = "test-support", derive(schemars::JsonSchema))]
pub struct SearchMeta {
    /// Folder that was searched.
    pub folder: String,
    /// Total number of messages matching the query (before pagination).
    pub total_matched: usize,
    /// Number of messages returned in this response.
    pub returned: usize,
    /// Whether there are more results beyond this page.
    pub truncated: bool,
}

/// Untrusted payload for a `search` response.
#[derive(Debug, Serialize)]
#[cfg_attr(feature = "test-support", derive(schemars::JsonSchema))]
pub struct SearchUntrusted {
    /// Matching messages with sanitized header fields.
    pub messages: Vec<SearchResultEntry>,
}

/// Execute the `search` tool.
///
/// # Errors
///
/// Returns `RimapError::Authz { code: InvalidInput, ... }` for malformed
/// `since`/`before` dates or control bytes in `advanced_query`. Returns
/// `RimapError::Imap { ... }` for IMAP-layer failures. The upstream
/// `DispatchGuard::pre_dispatch` layer may also return `Authz { code: PostureDenied }`
/// for `SearchAdvanced` when `advanced_query` is set and posture forbids it.
pub async fn handle(
    account: &AccountState,
    input: SearchInput,
) -> Result<ToolResponse<SearchMeta, SearchUntrusted>, rimap_core::RimapError> {
    crate::tools::validation::validate_folder_input("folder", &input.folder)?;

    let query = build_query(account, &input)?;

    let uids = Box::pin(account.imap.search(&input.folder, query)).await?;
    let total_matched = uids.len();

    let offset = input.offset.unwrap_or(0);
    let limit = input.limit.unwrap_or(MAX_LIMIT).min(MAX_LIMIT);

    let page_uids: Vec<Uid> = uids.into_iter().skip(offset).take(limit).collect();

    let truncated = total_matched > offset + page_uids.len();

    let messages: Vec<SearchResultEntry> = if page_uids.is_empty() {
        Vec::new()
    } else {
        let fetched = account
            .imap
            .fetch(
                &input.folder,
                &page_uids,
                FetchSpec {
                    envelope: true,
                    flags: true,
                    size: true,
                    ..FetchSpec::default()
                },
                None,
            )
            .await?;
        let (fetched, _uid_validity) = fetched;
        fetched.iter().map(format_search_result).collect()
    };

    Ok(ToolResponse::meta_only(SearchMeta {
        folder: input.folder,
        total_matched,
        returned: messages.len(),
        truncated,
    })
    .with_untrusted(SearchUntrusted { messages }))
}

/// Build a `SearchQuery` from the input. The `SearchAdvanced` posture
/// check happens upstream in `refine_tool_name` + `DispatchGuard::pre_dispatch`.
fn build_query(
    _account: &AccountState,
    input: &SearchInput,
) -> Result<SearchQuery, rimap_core::RimapError> {
    if let Some(raw) = &input.advanced_query {
        if raw.bytes().any(|b| b == b'\r' || b == b'\n' || b == b'\0') {
            return Err(rimap_core::RimapError::invalid_input(
                "advanced_query contains forbidden control bytes",
            ));
        }
        return Ok(SearchQuery::Raw(raw.clone()));
    }

    let since = input.since.as_deref().map(parse_iso_date).transpose()?;
    let before = input.before.as_deref().map(parse_iso_date).transpose()?;

    Ok(SearchQuery::Structured(StructuredQuery {
        from: input.from.clone(),
        to: input.to.clone(),
        subject: input.subject.clone(),
        since,
        before,
        seen: input.seen,
        has_attachment: input.has_attachment.unwrap_or(false),
        ..Default::default()
    }))
}

/// Parse an ISO 8601 date string ("YYYY-MM-DD") into a `time::Date`.
fn parse_iso_date(s: &str) -> Result<time::Date, rimap_core::RimapError> {
    let format = time::format_description::well_known::Iso8601::DATE;
    time::Date::parse(s, &format)
        .map_err(|e| rimap_core::RimapError::invalid_input(format!("invalid date '{s}': {e}")))
}

/// Route a string destined for MCP search-result output through the
/// shared rimap-content sanitization sub-pipeline: NFKC, line-ending
/// normalization, disallowed-codepoint filtering, grapheme truncation.
/// Skips the `decode` and warning-aggregation steps of the full
/// `unicode::sanitize` entry point — the input is already valid
/// UTF-8 and envelope snippets do not surface `SecurityWarning`.
fn sanitize_for_output(s: &str) -> String {
    use rimap_content::unicode::{
        filter_codepoints, normalize_line_endings, normalize_nfkc, truncate_graphemes,
    };
    let normalized = normalize_nfkc(s);
    let normalized = normalize_line_endings(&normalized);
    let filtered = filter_codepoints(&normalized);
    truncate_graphemes(&filtered.text, rimap_content::parse::MAX_HEADER_BYTES)
}

/// Format an address as `"name <mailbox@host>"` or `"mailbox@host"`.
fn format_address(addr: &Address) -> String {
    let mailbox = addr
        .mailbox
        .as_deref()
        .map(String::from_utf8_lossy)
        .unwrap_or_default();
    let host = addr
        .host
        .as_deref()
        .map(String::from_utf8_lossy)
        .unwrap_or_default();
    let email = format!("{mailbox}@{host}");

    match &addr.name {
        Some(name) => {
            let name = String::from_utf8_lossy(name);
            if name.is_empty() {
                email
            } else {
                format!("{name} <{email}>")
            }
        }
        None => email,
    }
}

/// Format addresses list.
fn format_addresses(addrs: &[Address]) -> Vec<String> {
    addrs.iter().map(format_address).collect()
}

/// Format a flag for JSON output.
fn format_flag(flag: &Flag) -> &str {
    match flag {
        Flag::Seen => "\\Seen",
        Flag::Answered => "\\Answered",
        Flag::Flagged => "\\Flagged",
        Flag::Deleted => "\\Deleted",
        Flag::Draft => "\\Draft",
        Flag::Recent => "\\Recent",
        Flag::Keyword(kw) => kw.as_str(),
    }
}

/// Format a single `FetchedMessage` into a typed search result entry.
fn format_search_result(msg: &FetchedMessage) -> SearchResultEntry {
    let size = msg.size;

    let flags = msg
        .flags
        .as_ref()
        .map(|f| f.iter().map(|flag| format_flag(flag).to_string()).collect());

    let (subject, date, from, to, message_id) = if let Some(env) = &msg.envelope {
        let subject = env.subject_raw.as_ref().map(|s| {
            let raw = String::from_utf8_lossy(s);
            sanitize_for_output(&raw)
        });
        let date = env.date.as_ref().map(|d| {
            let raw = String::from_utf8_lossy(d);
            sanitize_for_output(&raw)
        });
        let from = if env.from.is_empty() {
            Vec::new()
        } else {
            format_addresses(&env.from)
                .into_iter()
                .map(|a| sanitize_for_output(&a))
                .collect()
        };
        let to = if env.to.is_empty() {
            Vec::new()
        } else {
            format_addresses(&env.to)
                .into_iter()
                .map(|a| sanitize_for_output(&a))
                .collect()
        };
        let message_id = env.message_id.as_ref().map(|mid| {
            let raw = String::from_utf8_lossy(mid.as_bytes());
            sanitize_for_output(&raw)
        });
        (subject, date, from, to, message_id)
    } else {
        (None, None, Vec::new(), Vec::new(), None)
    };

    SearchResultEntry {
        uid: msg.uid.get(),
        size,
        flags,
        subject,
        date,
        from,
        to,
        message_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_strips_null_byte() {
        assert_eq!(sanitize_for_output("hello\x00world"), "helloworld");
    }

    #[test]
    fn sanitize_strips_bidi_overrides() {
        let input = "normal\u{202A}injected\u{202C}text";
        let result = sanitize_for_output(input);
        assert_eq!(result, "normalinjectedtext");
    }

    #[test]
    fn sanitize_strips_unicode_tags() {
        let input = "safe\u{E0001}tagged\u{E007F}end";
        let result = sanitize_for_output(input);
        assert_eq!(result, "safetaggedend");
    }

    #[test]
    fn sanitize_strips_zero_width_chars() {
        let input = "a\u{200B}b\u{200D}c\u{FEFF}d";
        // U+200D (ZWJ) is outside the filtered range 200B..200F,
        // so it passes through.
        let result = sanitize_for_output(input);
        assert!(!result.contains('\u{200B}'));
        assert!(!result.contains('\u{FEFF}'));
    }

    #[test]
    fn sanitize_preserves_newline_and_tab() {
        assert_eq!(sanitize_for_output("a\nb\tc"), "a\nb\tc");
    }

    #[test]
    fn sanitize_strips_c0_controls() {
        let input = "hello\x01\x02\x03world";
        assert_eq!(sanitize_for_output(input), "helloworld");
    }

    #[test]
    fn sanitize_nfkc_normalizes_decomposed_accents() {
        // NFKC precomposes "cafe" + combining acute into "café".
        // Other already-precomposed characters pass through unchanged.
        let input = "cafe\u{0301} naïve résumé 日本語";
        assert_eq!(sanitize_for_output(input), "café naïve résumé 日本語");
    }
}
