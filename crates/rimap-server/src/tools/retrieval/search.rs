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

/// Maximum number of `HEADER` filters per search request. IMAP servers
/// typically reject more than a handful in a single SEARCH command;
/// the cap also bounds CPU spent in `build_query`'s per-entry validation
/// for adversarial inputs.
const MAX_HEADERS: usize = 32;

/// One `HEADER name value` filter for the `search` tool. Converted to
/// [`rimap_imap::types::HeaderSearch`] in `build_query`.
#[derive(Debug, Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct HeaderInput {
    /// RFC 5322 field name (e.g. `"List-Id"`).
    pub name: String,
    /// Substring to match within the header value.
    pub value: String,
}

/// Input for the `search` tool.
#[derive(Debug, Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct SearchInput {
    /// IMAP folder to search in.
    pub folder: String,
    /// Filter by `From` header substring.
    pub from: Option<String>,
    /// Filter by `To` header substring.
    pub to: Option<String>,
    /// Filter by `Cc` header substring.
    pub cc: Option<String>,
    /// Filter by `Bcc` header substring. Content-oracle — requires
    /// `SearchAdvanced` posture (Full or Destructive).
    pub bcc: Option<String>,
    /// Filter by `Subject` header substring.
    pub subject: Option<String>,
    /// Substring search across body parts. Content-oracle — requires
    /// `SearchAdvanced` posture (Full or Destructive).
    pub body: Option<String>,
    /// Substring search across headers OR body. Content-oracle —
    /// requires `SearchAdvanced` posture (Full or Destructive).
    pub text: Option<String>,
    /// One or more `HEADER name value` filters. Content-oracle when
    /// non-empty — requires `SearchAdvanced` posture (Full or Destructive).
    pub headers: Option<Vec<HeaderInput>>,
    /// Match messages strictly larger than this many octets.
    #[serde(
        default,
        deserialize_with = "crate::tools::lenient_int::deserialize_opt_u64"
    )]
    #[schemars(schema_with = "crate::tools::lenient_int::schema_opt_u64")]
    pub larger: Option<u64>,
    /// Match messages strictly smaller than this many octets.
    #[serde(
        default,
        deserialize_with = "crate::tools::lenient_int::deserialize_opt_u64"
    )]
    #[schemars(schema_with = "crate::tools::lenient_int::schema_opt_u64")]
    pub smaller: Option<u64>,
    /// Messages since this ISO date (inclusive) by INTERNALDATE,
    /// e.g. "2026-01-01".
    pub since: Option<String>,
    /// Messages before this ISO date (exclusive) by INTERNALDATE.
    pub before: Option<String>,
    /// Messages since this ISO date (inclusive) by the message's
    /// `Date:` header — distinct from `since` which uses INTERNALDATE.
    pub sent_since: Option<String>,
    /// Messages before this ISO date (exclusive) by the message's
    /// `Date:` header — distinct from `before` which uses INTERNALDATE.
    pub sent_before: Option<String>,
    /// Filter by seen/unseen status.
    pub seen: Option<bool>,
    /// Filter by answered/unanswered status.
    pub answered: Option<bool>,
    /// Filter by flagged/unflagged status.
    pub flagged: Option<bool>,
    /// Filter by draft/non-draft status.
    pub draft: Option<bool>,
    /// Filter for messages with attachments.
    pub has_attachment: Option<bool>,
    /// Raw IMAP SEARCH query (full posture only).
    pub advanced_query: Option<String>,
    /// Max results to return (default 100, max 100).
    #[serde(
        default,
        deserialize_with = "crate::tools::lenient_int::deserialize_opt_usize"
    )]
    #[schemars(schema_with = "crate::tools::lenient_int::schema_opt_usize")]
    pub limit: Option<usize>,
    /// Offset into the result set (default 0).
    #[serde(
        default,
        deserialize_with = "crate::tools::lenient_int::deserialize_opt_usize"
    )]
    #[schemars(schema_with = "crate::tools::lenient_int::schema_opt_usize")]
    pub offset: Option<usize>,
}

/// A single message entry in a `search` untrusted payload.
#[derive(Debug, Serialize, schemars::JsonSchema)]
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
    /// Cc addresses, sanitized. Omitted when empty.
    ///
    /// Note: `bcc` is intentionally absent — exposing BCC recipients
    /// violates the privacy boundary enforced at the `SearchInput` and
    /// output layers. See the spec's Privacy subsection.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cc: Vec<String>,
    /// RFC 2822 `Message-ID`, sanitized.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
}

/// Trusted metadata for a `search` response.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct SearchMeta {
    /// Folder that was searched.
    pub folder: String,
    /// Total number of messages matching the query (before pagination).
    pub total_matched: usize,
    /// Number of messages returned in this response.
    pub returned: usize,
    /// Whether there are more results beyond this page.
    pub truncated: bool,
    /// UIDVALIDITY observed for the searched folder, from the same
    /// EXAMINE/UID SEARCH operation. Thread into `export_messages`'
    /// `expected_uidvalidity`. `None` if the server omitted it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid_validity: Option<u32>,
}

/// Untrusted payload for a `search` response.
#[derive(Debug, Serialize, schemars::JsonSchema)]
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

    let query = build_query(&input)?;

    let (uids, uid_validity) = Box::pin(account.imap.search(&input.folder, query)).await?;
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
        uid_validity,
    })
    .with_untrusted(SearchUntrusted { messages }))
}

/// Build a `SearchQuery` from the input. The `SearchAdvanced` posture
/// check happens upstream in `refine_tool_name` + `DispatchGuard::pre_dispatch`.
fn build_query(input: &SearchInput) -> Result<SearchQuery, rimap_core::RimapError> {
    if let Some(raw) = &input.advanced_query {
        if raw.bytes().any(|b| b == b'\r' || b == b'\n' || b == b'\0') {
            return Err(rimap_core::RimapError::invalid_input(
                "advanced_query contains forbidden control bytes",
            ));
        }
        return Ok(SearchQuery::Raw(raw.clone()));
    }

    // Reject empty/whitespace-only string filters at the MCP boundary —
    // the IMAP server happily executes broad scans like `BODY ""` and
    // the existing quote() only blocks CR/LF/NUL.
    let cc = require_non_empty("cc", input.cc.as_deref())?;
    let bcc = require_non_empty("bcc", input.bcc.as_deref())?;
    let body = require_non_empty("body", input.body.as_deref())?;
    let text = require_non_empty("text", input.text.as_deref())?;

    // Empty headers vec carries no filter intent — normalize to None
    // so the emitter does not have to special-case it.
    let headers = match &input.headers {
        Some(v) if v.is_empty() => None,
        Some(v) => {
            if v.len() > MAX_HEADERS {
                return Err(rimap_core::RimapError::invalid_input(format!(
                    "headers array exceeds maximum of {MAX_HEADERS} entries"
                )));
            }
            let mut converted = Vec::with_capacity(v.len());
            for h in v {
                if h.name.trim().is_empty() {
                    return Err(rimap_core::RimapError::invalid_input(
                        "headers[].name must not be empty or whitespace-only",
                    ));
                }
                if h.value.trim().is_empty() {
                    return Err(rimap_core::RimapError::invalid_input(
                        "headers[].value must not be empty or whitespace-only",
                    ));
                }
                converted.push(rimap_imap::types::HeaderSearch {
                    name: h.name.clone(),
                    value: h.value.clone(),
                });
            }
            Some(converted)
        }
        None => None,
    };

    let since = input.since.as_deref().map(parse_iso_date).transpose()?;
    let before = input.before.as_deref().map(parse_iso_date).transpose()?;
    let sent_since = input
        .sent_since
        .as_deref()
        .map(parse_iso_date)
        .transpose()?;
    let sent_before = input
        .sent_before
        .as_deref()
        .map(parse_iso_date)
        .transpose()?;

    Ok(SearchQuery::Structured(StructuredQuery {
        from: input.from.clone(),
        to: input.to.clone(),
        subject: input.subject.clone(),
        since,
        before,
        seen: input.seen,
        has_attachment: input.has_attachment.unwrap_or(false),
        cc,
        bcc,
        body,
        text,
        headers,
        larger: input.larger,
        smaller: input.smaller,
        sent_since,
        sent_before,
        answered: input.answered,
        flagged: input.flagged,
        draft: input.draft,
    }))
}

/// Reject empty/whitespace-only string filters. Returns `Ok(None)` for
/// `None`, `Ok(Some(s.to_string()))` for a non-trimmed-empty value, and
/// `Err(RimapError::invalid_input)` otherwise. The `field` label flows
/// straight into the error message.
fn require_non_empty(
    field: &str,
    value: Option<&str>,
) -> Result<Option<String>, rimap_core::RimapError> {
    let Some(s) = value else {
        return Ok(None);
    };
    if s.trim().is_empty() {
        return Err(rimap_core::RimapError::invalid_input(format!(
            "{field} must not be empty or whitespace-only"
        )));
    }
    Ok(Some(s.to_string()))
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

/// Apply the search-result envelope address pipeline: format each
/// address as `"name <mailbox@host>"`, then route through
/// `sanitize_for_output`. Returns an empty `Vec` when `addrs` is empty.
fn sanitize_address_list(addrs: &[Address]) -> Vec<String> {
    addrs
        .iter()
        .map(|a| sanitize_for_output(&format_address(a)))
        .collect()
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

    let (subject, date, from, to, cc, message_id) = if let Some(env) = &msg.envelope {
        let subject = env.subject_raw.as_ref().map(|s| {
            let raw = String::from_utf8_lossy(s);
            sanitize_for_output(&raw)
        });
        let date = env.date.as_ref().map(|d| {
            let raw = String::from_utf8_lossy(d);
            sanitize_for_output(&raw)
        });
        let from = sanitize_address_list(&env.from);
        let to = sanitize_address_list(&env.to);
        let cc = sanitize_address_list(&env.cc);
        let message_id = env.message_id.as_ref().map(|mid| {
            let raw = String::from_utf8_lossy(mid.as_bytes());
            sanitize_for_output(&raw)
        });
        (subject, date, from, to, cc, message_id)
    } else {
        (None, None, Vec::new(), Vec::new(), Vec::new(), None)
    };

    SearchResultEntry {
        uid: msg.uid.get(),
        size,
        flags,
        subject,
        date,
        from,
        to,
        cc,
        message_id,
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests"
)]
mod tests {
    use super::*;
    use rimap_imap::types::{Address, Envelope, FetchedMessage, HeaderSearch, StructuredQuery};

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

    fn input_with_folder() -> SearchInput {
        SearchInput {
            folder: "INBOX".to_string(),
            from: None,
            to: None,
            cc: None,
            bcc: None,
            subject: None,
            body: None,
            text: None,
            headers: None,
            larger: None,
            smaller: None,
            since: None,
            before: None,
            sent_since: None,
            sent_before: None,
            seen: None,
            answered: None,
            flagged: None,
            draft: None,
            has_attachment: None,
            advanced_query: None,
            limit: None,
            offset: None,
        }
    }

    fn build(
        input: &SearchInput,
    ) -> Result<rimap_imap::types::SearchQuery, rimap_core::RimapError> {
        super::build_query(input)
    }

    #[test]
    fn build_query_rejects_empty_cc() {
        let mut input = input_with_folder();
        input.cc = Some(String::new());
        let err = build(&input).unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("cc"),
            "expected cc-empty error, got: {err}",
        );
    }

    #[test]
    fn build_query_rejects_whitespace_cc() {
        let mut input = input_with_folder();
        input.cc = Some("   ".to_string());
        assert!(build(&input).is_err());
    }

    #[test]
    fn build_query_rejects_empty_bcc() {
        let mut input = input_with_folder();
        input.bcc = Some(String::new());
        assert!(build(&input).is_err());
    }

    #[test]
    fn build_query_rejects_whitespace_bcc() {
        let mut input = input_with_folder();
        input.bcc = Some("   ".to_string());
        assert!(build(&input).is_err());
    }

    #[test]
    fn build_query_rejects_empty_body() {
        let mut input = input_with_folder();
        input.body = Some(String::new());
        assert!(build(&input).is_err());
    }

    #[test]
    fn build_query_rejects_whitespace_body() {
        let mut input = input_with_folder();
        input.body = Some("\t ".to_string());
        assert!(build(&input).is_err());
    }

    #[test]
    fn build_query_rejects_empty_text() {
        let mut input = input_with_folder();
        input.text = Some(String::new());
        assert!(build(&input).is_err());
    }

    #[test]
    fn build_query_rejects_whitespace_text() {
        let mut input = input_with_folder();
        input.text = Some("\t ".to_string());
        assert!(build(&input).is_err());
    }

    #[test]
    fn build_query_rejects_empty_header_name() {
        let mut input = input_with_folder();
        input.headers = Some(vec![HeaderInput {
            name: String::new(),
            value: "x".to_string(),
        }]);
        assert!(build(&input).is_err());
    }

    #[test]
    fn build_query_rejects_whitespace_header_name() {
        let mut input = input_with_folder();
        input.headers = Some(vec![HeaderInput {
            name: "   ".to_string(),
            value: "x".to_string(),
        }]);
        assert!(build(&input).is_err());
    }

    #[test]
    fn build_query_rejects_empty_header_value() {
        let mut input = input_with_folder();
        input.headers = Some(vec![HeaderInput {
            name: "List-Id".to_string(),
            value: String::new(),
        }]);
        assert!(build(&input).is_err());
    }

    #[test]
    fn build_query_rejects_whitespace_header_value() {
        let mut input = input_with_folder();
        input.headers = Some(vec![HeaderInput {
            name: "List-Id".to_string(),
            value: "  ".to_string(),
        }]);
        assert!(build(&input).is_err());
    }

    #[test]
    fn build_query_rejects_empty_name_in_second_header() {
        let mut input = input_with_folder();
        input.headers = Some(vec![
            HeaderInput {
                name: "List-Id".to_string(),
                value: "rust".to_string(),
            },
            HeaderInput {
                name: String::new(),
                value: "x".to_string(),
            },
        ]);
        assert!(build(&input).is_err());
    }

    #[test]
    fn build_query_rejects_headers_array_over_cap() {
        let mut input = input_with_folder();
        let too_many: Vec<HeaderInput> = (0..=MAX_HEADERS)
            .map(|i| HeaderInput {
                name: format!("X-Test-{i}"),
                value: "v".to_string(),
            })
            .collect();
        input.headers = Some(too_many);
        let err = build(&input).unwrap_err();
        assert!(
            err.to_string().contains("headers array exceeds maximum"),
            "expected over-cap error, got: {err}",
        );
    }

    #[test]
    fn build_query_accepts_empty_headers_array_as_no_filter() {
        let mut input = input_with_folder();
        input.headers = Some(Vec::new());
        let q = build(&input).expect("empty headers vec is accepted");
        match q {
            rimap_imap::types::SearchQuery::Structured(s) => {
                assert!(s.headers.is_none(), "headers should be normalized to None");
            }
            rimap_imap::types::SearchQuery::Raw(r) => panic!("unexpected raw: {r}"),
        }
    }

    #[test]
    fn build_query_threads_cc_into_structured_query() {
        let mut input = input_with_folder();
        input.cc = Some("alice@example.com".to_string());
        let q = build(&input).unwrap();
        match q {
            rimap_imap::types::SearchQuery::Structured(s) => {
                assert_eq!(s.cc.as_deref(), Some("alice@example.com"));
            }
            rimap_imap::types::SearchQuery::Raw(r) => panic!("unexpected raw: {r}"),
        }
    }

    fn addr(name: &str, mailbox: &str, host: &str) -> Address {
        Address {
            name: if name.is_empty() {
                None
            } else {
                Some(name.as_bytes().to_vec())
            },
            adl: None,
            mailbox: Some(mailbox.as_bytes().to_vec()),
            host: Some(host.as_bytes().to_vec()),
        }
    }

    fn uid(n: u32) -> rimap_imap::types::Uid {
        use std::num::NonZeroU32;
        rimap_imap::types::Uid::from(NonZeroU32::new(n).expect("non-zero"))
    }

    fn fetched_with_envelope(env: Envelope) -> FetchedMessage {
        FetchedMessage {
            uid: uid(42),
            envelope: Some(env),
            bodystructure: None,
            flags: None,
            size: None,
        }
    }

    #[test]
    fn format_search_result_populates_cc_from_envelope() {
        let env = Envelope {
            date: None,
            subject_raw: None,
            from: vec![],
            sender: vec![],
            reply_to: vec![],
            to: vec![],
            cc: vec![addr("Carol", "carol", "example.com")],
            bcc: vec![],
            in_reply_to: None,
            message_id: None,
        };
        let entry = format_search_result(&fetched_with_envelope(env));
        assert_eq!(entry.cc, vec!["Carol <carol@example.com>"]);
    }

    #[test]
    fn format_search_result_returns_empty_cc_when_envelope_omits_it() {
        let env = Envelope {
            date: None,
            subject_raw: None,
            from: vec![],
            sender: vec![],
            reply_to: vec![],
            to: vec![],
            cc: vec![],
            bcc: vec![],
            in_reply_to: None,
            message_id: None,
        };
        let entry = format_search_result(&fetched_with_envelope(env));
        assert!(entry.cc.is_empty());

        let json = serde_json::to_string(&entry).expect("serialize");
        assert!(
            !json.contains("\"cc\""),
            "empty cc must be skipped on serialize; got {json}",
        );
    }

    #[test]
    fn format_search_result_never_emits_bcc_even_when_envelope_has_it() {
        // Privacy boundary: bcc must NOT appear in SearchResultEntry in
        // any posture. format_search_result must ignore env.bcc.
        let env = Envelope {
            date: None,
            subject_raw: None,
            from: vec![],
            sender: vec![],
            reply_to: vec![],
            to: vec![],
            cc: vec![],
            bcc: vec![addr("Blind", "blind", "example.com")],
            in_reply_to: None,
            message_id: None,
        };
        let entry = format_search_result(&fetched_with_envelope(env));
        let json = serde_json::to_string(&entry).expect("serialize");
        assert!(
            !json.contains("bcc"),
            "bcc key must not appear in serialized SearchResultEntry; got {json}",
        );
        assert!(
            !json.contains("blind@example.com"),
            "bcc address must not leak via any other field; got {json}",
        );
    }

    #[test]
    fn build_query_threads_all_new_fields_into_structured_query() {
        let mut input = input_with_folder();
        input.cc = Some("c@example.com".to_string());
        input.bcc = Some("b@example.com".to_string());
        input.body = Some("hi".to_string());
        input.text = Some("anywhere".to_string());
        input.headers = Some(vec![HeaderInput {
            name: "List-Id".to_string(),
            value: "rust".to_string(),
        }]);
        input.larger = Some(1024);
        input.smaller = Some(2_048_000);
        input.sent_since = Some("2026-01-01".to_string());
        input.sent_before = Some("2026-02-01".to_string());
        input.answered = Some(true);
        input.flagged = Some(false);
        input.draft = Some(true);
        let q = build(&input).unwrap();
        let s: StructuredQuery = match q {
            rimap_imap::types::SearchQuery::Structured(s) => s,
            rimap_imap::types::SearchQuery::Raw(r) => panic!("unexpected raw: {r}"),
        };
        assert_eq!(s.cc.as_deref(), Some("c@example.com"));
        assert_eq!(s.bcc.as_deref(), Some("b@example.com"));
        assert_eq!(s.body.as_deref(), Some("hi"));
        assert_eq!(s.text.as_deref(), Some("anywhere"));
        let hs = s.headers.expect("headers");
        assert_eq!(hs.len(), 1);
        assert_eq!(
            hs[0],
            HeaderSearch {
                name: "List-Id".to_string(),
                value: "rust".to_string()
            }
        );
        assert_eq!(s.larger, Some(1024));
        assert_eq!(s.smaller, Some(2_048_000));
        assert_eq!(
            s.sent_since,
            Some(::time::Date::from_calendar_date(2026, ::time::Month::January, 1).unwrap()),
        );
        assert_eq!(
            s.sent_before,
            Some(::time::Date::from_calendar_date(2026, ::time::Month::February, 1).unwrap()),
        );
        assert_eq!(s.answered, Some(true));
        assert_eq!(s.flagged, Some(false));
        assert_eq!(s.draft, Some(true));
    }

    #[test]
    fn search_meta_serializes_uid_validity() {
        let meta = SearchMeta {
            folder: "INBOX".to_string(),
            total_matched: 0,
            returned: 0,
            truncated: false,
            uid_validity: Some(12345),
        };
        let v = serde_json::to_value(meta).unwrap();
        assert_eq!(v["uid_validity"], serde_json::json!(12345));
    }
}
