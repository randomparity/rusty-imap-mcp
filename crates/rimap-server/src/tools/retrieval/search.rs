//! `search` tool handler.
//!
//! Search responses intentionally omit per-envelope `SecurityWarning`
//! entries. `sanitize_for_output` runs a header-appropriate subset of
//! the `rimap-content` Unicode pipeline (NFKC, line-ending
//! normalization, disallowed-codepoint filtering, grapheme truncation)
//! and skips the `decode` step that would surface warnings. Envelope
//! snippets (subject, date, addresses, `Message-ID`) are bounded and
//! already UTF-8, so they produce no warnings.
//!
//! The exception is `body_preview_bytes`: previews are real MIME bodies
//! parsed through `parse_message`, so their sanitization warnings ARE
//! aggregated into the response's top-level `security_warnings` (without
//! per-message attribution — use `fetch_message` for that). A `search`
//! without `body_preview_bytes` still returns an empty `security_warnings`.

use rimap_imap::types::{
    Address, FetchSpec, FetchedMessage, Flag, SearchQuery, StructuredQuery, Uid,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::boot::registry::AccountState;
use crate::mcp::response::ToolResponse;

/// Maximum number of results per page. `pub(crate)` so the
/// `rimap://docs/workflows` resource's limits table can be pinned
/// against it in `crate::mcp::server`'s tests.
pub(crate) const MAX_LIMIT: usize = 100;

/// Maximum bytes of sanitized body text returned per result when
/// `body_preview_bytes` is requested. Larger requests are clamped to this.
const MAX_BODY_PREVIEW_BYTES: usize = 1024;

/// Maximum number of results per page that receive a `body_preview`.
/// Bounds the number of sequential body fetches one `search` performs;
/// entries beyond this omit the preview.
const MAX_PREVIEW_MESSAGES: usize = 50;

/// Maximum number of `HEADER` filters per search request. IMAP servers
/// typically reject more than a handful in a single SEARCH command;
/// the cap also bounds CPU spent in `build_query`'s per-entry validation
/// for adversarial inputs.
const MAX_HEADERS: usize = 32;

/// One `HEADER name value` filter for the `search` tool.
#[derive(Debug, Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct HeaderInput {
    /// RFC 5322 field name (e.g. `"List-Id"`).
    pub name: String,
    /// Substring to match within the header value.
    pub value: String,
}

/// # Result ordering
///
/// Results are ordered by UID ascending — oldest message first — unless
/// `newest_first` is set, which reverses the order to newest first.
/// UIDs are assigned in strictly increasing order within a folder's
/// `UIDVALIDITY` epoch (RFC 3501 §2.3.1.1), so ascending UID order is
/// equivalent to arrival order. Use `offset`/`limit` to page through
/// results in whichever order is selected, and read `next_offset` from
/// the response to fetch the following page without recomputing it.
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
    /// Filter by `Bcc` header substring. Gated like a content search
    /// (it can expose recipients): denied unless the account posture is
    /// `full` or `destructive`. Check the `rimap://accounts/<name>`
    /// resource for this account's posture and available tools.
    pub bcc: Option<String>,
    /// Filter by `Subject` header substring.
    pub subject: Option<String>,
    /// Substring search across body parts. Searches message content, so
    /// it is denied unless the account posture is `full` or
    /// `destructive`. Check the `rimap://accounts/<name>` resource for
    /// this account's posture and available tools.
    pub body: Option<String>,
    /// Substring search across headers OR body. Searches message
    /// content, so it is denied unless the account posture is `full` or
    /// `destructive`. Check the `rimap://accounts/<name>` resource for
    /// this account's posture and available tools.
    pub text: Option<String>,
    /// One or more `HEADER name value` filters. When non-empty this is
    /// gated like a content search: denied unless the account posture is
    /// `full` or `destructive`. Check the `rimap://accounts/<name>`
    /// resource for this account's posture and available tools.
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
    /// Raw IMAP SEARCH query. Denied unless the account posture is
    /// `full` or `destructive`. Check the `rimap://accounts/<name>`
    /// resource for this account's posture and available tools.
    pub advanced_query: Option<String>,
    /// Max results to return (default 100, max 100).
    #[serde(
        default,
        deserialize_with = "crate::tools::lenient_int::deserialize_opt_usize"
    )]
    #[schemars(schema_with = "crate::tools::lenient_int::schema_opt_usize")]
    pub limit: Option<usize>,
    /// Offset into the result set (default 0), counted in whichever
    /// order `newest_first` selects. See "Result ordering" above.
    #[serde(
        default,
        deserialize_with = "crate::tools::lenient_int::deserialize_opt_usize"
    )]
    #[schemars(schema_with = "crate::tools::lenient_int::schema_opt_usize")]
    pub offset: Option<usize>,
    /// Return results newest-first (UID descending) instead of the
    /// default oldest-first (UID ascending). Reverses the already
    /// matched UID list before paginating — no IMAP SORT extension is
    /// used or required. Default `false`.
    pub newest_first: Option<bool>,
    /// When set, include a short plain-text body preview per result under
    /// `untrusted.messages[].body_preview` — the first N bytes of the
    /// sanitized body, capped at 1024. This turns "summarize my inbox"
    /// into a single call instead of one `fetch_message` per message.
    /// Previews are provided for up to the first 50 results of the page;
    /// request `limit` ≤ 50 or page with `next_offset` to preview more.
    /// Available at every posture `search` is: a preview returns a
    /// truncated body of an already-matched message (like `fetch_message`)
    /// and does not filter on content, so it is not gated like `body`/
    /// `text`. `0` or omitted returns no previews.
    #[serde(
        default,
        deserialize_with = "crate::tools::lenient_int::deserialize_opt_usize"
    )]
    #[schemars(schema_with = "crate::tools::lenient_int::schema_opt_usize")]
    pub body_preview_bytes: Option<usize>,
    /// Return the whole conversation containing this UID instead of a
    /// filtered search: the target message, every ancestor named in
    /// its own `References`/`In-Reply-To` chain, and every descendant
    /// whose `References`/`In-Reply-To` names the target's
    /// `Message-ID`. A Message-ID chain-walk within `folder` only — no
    /// IMAP THREAD extension. Mutually exclusive with `advanced_query`.
    /// All other filters are ignored when set. Available at every
    /// posture: the header values compared come from the target
    /// message itself, not caller-supplied text, so this cannot probe
    /// arbitrary header/value pairs the way `headers`/`body`/`text`
    /// can.
    #[serde(
        default,
        deserialize_with = "crate::tools::lenient_int::deserialize_opt_nonzero_u32"
    )]
    #[schemars(schema_with = "crate::tools::lenient_int::schema_opt_nonzero_u32")]
    pub thread_of_uid: Option<core::num::NonZeroU32>,
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
    /// First bytes of the sanitized plain-text body, present only when
    /// `body_preview_bytes` was requested and a body was retrievable.
    /// Attacker-controlled email content.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_preview: Option<String>,
    /// Whether the body extended beyond `body_preview`. Present only
    /// alongside `body_preview`; `true` means fetch the message with
    /// `fetch_message` for the full body.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_preview_truncated: Option<bool>,
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
    /// Offset to pass on the next call to fetch the following page in
    /// the same order (see `SearchInput`'s "Result ordering" section).
    /// Present only when `truncated` is `true`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<u64>,
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

    if let Some(target) = input.thread_of_uid {
        return Box::pin(handle_thread(account, input, target)).await;
    }

    let query = build_query(&input)?;

    let (uids, uid_validity) = Box::pin(account.imap.search(&input.folder, query)).await?;
    let total_matched = uids.len();

    let offset = input.offset.unwrap_or(0);
    let limit = input.limit.unwrap_or(MAX_LIMIT).min(MAX_LIMIT);
    let newest_first = input.newest_first.unwrap_or(false);

    let (page_uids, truncated, next_offset) = paginate_uids(uids, offset, limit, newest_first);

    let mut messages = fetch_and_format_page(account, &input.folder, &page_uids).await?;

    // Body previews (option (b) of #410): best-effort, per-UID isolated.
    let preview_warnings =
        attach_body_previews(account, &input.folder, uid_validity, &mut messages, &input).await;

    Ok(ToolResponse::meta_only(SearchMeta {
        folder: input.folder,
        total_matched,
        returned: messages.len(),
        truncated,
        next_offset,
        uid_validity,
    })
    .with_untrusted(SearchUntrusted { messages })
    .with_warnings(preview_warnings))
}

/// `thread_of_uid` path (option (c) of #410): return the conversation
/// containing `target`, in place of a normal filtered search.
///
/// Fetches the target message's own `Message-ID`/`References`/
/// `In-Reply-To` headers, then issues one combined `SEARCH` for every
/// message causally connected to it (see
/// `rimap_imap`'s `Connection::thread_related`), unions the result
/// with the target UID itself, and paginates/formats identically to
/// the normal `search` path.
async fn handle_thread(
    account: &AccountState,
    input: SearchInput,
    target: core::num::NonZeroU32,
) -> Result<ToolResponse<SearchMeta, SearchUntrusted>, rimap_core::RimapError> {
    validate_thread_request(&input)?;

    let target_uid = Uid::from(target);
    let (own_message_id, ancestor_ids) =
        fetch_thread_headers(account, &input.folder, target_uid).await?;

    let (mut related, uid_validity) = Box::pin(account.imap.thread_related(
        &input.folder,
        own_message_id.as_deref(),
        &ancestor_ids,
    ))
    .await?;

    if !related.contains(&target_uid) {
        related.push(target_uid);
        related.sort_unstable();
    }
    let total_matched = related.len();

    let offset = input.offset.unwrap_or(0);
    let limit = input.limit.unwrap_or(MAX_LIMIT).min(MAX_LIMIT);
    let newest_first = input.newest_first.unwrap_or(false);

    let (page_uids, truncated, next_offset) = paginate_uids(related, offset, limit, newest_first);

    let mut messages = fetch_and_format_page(account, &input.folder, &page_uids).await?;

    let preview_warnings =
        attach_body_previews(account, &input.folder, uid_validity, &mut messages, &input).await;

    Ok(ToolResponse::meta_only(SearchMeta {
        folder: input.folder,
        total_matched,
        returned: messages.len(),
        truncated,
        next_offset,
        uid_validity,
    })
    .with_untrusted(SearchUntrusted { messages })
    .with_warnings(preview_warnings))
}

/// Fetch `target`'s raw body and extract its own `Message-ID` plus the
/// list of ancestor Message-IDs from its `References` and
/// `In-Reply-To` headers (closest ancestors first — see
/// `cap_ancestor_ids`). Reuses the same header-extraction pipeline as
/// `fetch_message`'s `include_headers` (#409).
async fn fetch_thread_headers(
    account: &AccountState,
    folder: &str,
    target: Uid,
) -> Result<(Option<String>, Vec<String>), rimap_core::RimapError> {
    let raw = account.imap.fetch_body(folder, target, None).await?;
    let wanted = vec![
        "Message-ID".to_string(),
        "References".to_string(),
        "In-Reply-To".to_string(),
    ];
    let (_, selected) =
        crate::tools::content_parse::parse_message_with_headers_async(raw, wanted).await?;

    let mut own_message_id = None;
    let mut ancestor_ids = Vec::new();
    for header in selected {
        match header.name.as_str() {
            "Message-ID" => {
                own_message_id = header.values.into_iter().next();
            }
            "References" | "In-Reply-To" => {
                for value in &header.values {
                    ancestor_ids.extend(parse_message_id_tokens(value));
                }
            }
            _ => {}
        }
    }
    Ok((own_message_id, cap_ancestor_ids(ancestor_ids)))
}

/// Reject a `thread_of_uid` request combined with `advanced_query` —
/// both are "special mode" flags that each determine the whole query,
/// so combining them is ambiguous about which one actually runs.
/// Pure and independent of the async IMAP layer so it is unit-testable
/// without a live connection.
fn validate_thread_request(input: &SearchInput) -> Result<(), rimap_core::RimapError> {
    if input.advanced_query.is_some() {
        return Err(rimap_core::RimapError::invalid_input(
            "thread_of_uid cannot be combined with advanced_query",
        ));
    }
    Ok(())
}

/// Split a `References`/`In-Reply-To` header value into individual RFC
/// 5322 msg-id tokens (`<local@domain>`). Ignores anything that is not
/// a bracketed msg-id (stray whitespace or comments some clients emit).
fn parse_message_id_tokens(raw: &str) -> Vec<String> {
    raw.split_whitespace()
        .filter(|tok| tok.starts_with('<') && tok.ends_with('>') && tok.len() > 2)
        .map(str::to_string)
        .collect()
}

/// Maximum number of ancestor Message-IDs to search for when walking a
/// target message's `References`/`In-Reply-To` chain. Bounds IMAP
/// command length and search cost against pathologically long chains.
const MAX_THREAD_ANCESTOR_IDS: usize = 50;

/// Deduplicate (preserving first occurrence) and cap `ids` at
/// [`MAX_THREAD_ANCESTOR_IDS`], keeping the *last* entries when the
/// list is longer than the cap. `References` is ordered oldest-first
/// per RFC 5322 §3.6.4 (each hop appends its own `Message-ID`), so the
/// tail holds the closest ancestors — the most useful ones to keep
/// when a chain must be truncated.
fn cap_ancestor_ids(ids: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::with_capacity(ids.len());
    let mut deduped = Vec::with_capacity(ids.len());
    for id in ids {
        if seen.insert(id.clone()) {
            deduped.push(id);
        }
    }
    let start = deduped.len().saturating_sub(MAX_THREAD_ANCESTOR_IDS);
    deduped.split_off(start)
}

/// Fetch envelope/flags/size for `page_uids` and format each as a
/// `SearchResultEntry`, in `page_uids`' order (not the FETCH response
/// order — see the comment on the `fetch` call for why).
async fn fetch_and_format_page(
    account: &AccountState,
    folder: &str,
    page_uids: &[Uid],
) -> Result<Vec<SearchResultEntry>, rimap_core::RimapError> {
    if page_uids.is_empty() {
        return Ok(Vec::new());
    }
    let fetched = account
        .imap
        .fetch(
            folder,
            page_uids,
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
    // `fetch` streams FETCH responses back in the server's own
    // (ascending) order regardless of the order `page_uids` was passed
    // in, so reassemble in `page_uids`' order — the only place the
    // requested ordering (oldest-first, newest-first, or thread
    // membership order) is actually recorded — rather than trusting
    // the fetch order.
    let mut by_uid: std::collections::HashMap<Uid, &FetchedMessage> =
        fetched.iter().map(|m| (m.uid, m)).collect();
    Ok(page_uids
        .iter()
        .filter_map(|uid| by_uid.remove(uid))
        .map(format_search_result)
        .collect())
}

/// Fill `body_preview` on the first [`MAX_PREVIEW_MESSAGES`] entries when
/// `body_preview_bytes` is requested, returning the aggregated
/// sanitization warnings from parsing those bodies. A no-op (empty
/// warnings) when no preview was requested.
///
/// Each body is fetched and parsed sequentially over the single IMAP
/// session, so peak heap stays at roughly one body: fetch, parse, keep
/// the preview, drop the body. A per-UID failure yields a `None` preview
/// for that entry and never fails the search.
async fn attach_body_previews(
    account: &AccountState,
    folder: &str,
    expected_uidvalidity: Option<u32>,
    messages: &mut [SearchResultEntry],
    input: &SearchInput,
) -> Vec<rimap_content::SecurityWarning> {
    let Some(max_bytes) = clamp_preview_bytes(input.body_preview_bytes) else {
        return Vec::new();
    };
    let mut warnings = Vec::new();
    for entry in messages.iter_mut().take(MAX_PREVIEW_MESSAGES) {
        let Some(uid_nz) = std::num::NonZeroU32::new(entry.uid) else {
            continue;
        };
        let mut outcome = Box::pin(fetch_body_preview(
            account,
            folder,
            Uid::from(uid_nz),
            max_bytes,
            expected_uidvalidity,
        ))
        .await;
        if let Some(text) = outcome.text {
            entry.body_preview = Some(text);
            entry.body_preview_truncated = Some(outcome.truncated);
        }
        warnings.append(&mut outcome.warnings);
    }
    warnings
}

/// Result of building one message's body preview.
struct PreviewOutcome {
    /// Sanitized preview text, or `None` when the body was empty or
    /// could not be fetched/parsed.
    text: Option<String>,
    /// Whether the full body extended beyond the returned preview.
    truncated: bool,
    /// Sanitization warnings emitted while parsing this body.
    warnings: Vec<rimap_content::SecurityWarning>,
}

/// Fetch and parse a single message body, returning its sanitized preview
/// (first `max_bytes`), a truncation flag, and any sanitization warnings.
/// Any fetch or parse failure — including an oversize body rejected by the
/// `max_fetch_body_bytes` preflight — is swallowed into `text: None` so one
/// bad message never fails the batch.
async fn fetch_body_preview(
    account: &AccountState,
    folder: &str,
    uid: Uid,
    max_bytes: usize,
    expected_uidvalidity: Option<u32>,
) -> PreviewOutcome {
    let raw = match account
        .imap
        .fetch_body(folder, uid, expected_uidvalidity)
        .await
    {
        Ok(raw) => raw,
        Err(err) => {
            tracing::debug!(uid = uid.get(), %err, "body_preview: fetch_body failed");
            return PreviewOutcome {
                text: None,
                truncated: false,
                warnings: Vec::new(),
            };
        }
    };
    let content = match crate::tools::content_parse::parse_message_async(raw).await {
        Ok(content) => content,
        Err(err) => {
            tracing::debug!(uid = uid.get(), %err, "body_preview: parse failed");
            return PreviewOutcome {
                text: None,
                truncated: false,
                warnings: Vec::new(),
            };
        }
    };
    let (text, truncated) = make_preview(content.untrusted.body_text, max_bytes);
    PreviewOutcome {
        text,
        truncated,
        warnings: content.security_warnings,
    }
}

/// Clamp a requested `body_preview_bytes` to the supported range: `None`
/// or `0` means no preview; anything larger than [`MAX_BODY_PREVIEW_BYTES`]
/// is capped to it.
fn clamp_preview_bytes(requested: Option<usize>) -> Option<usize> {
    requested
        .filter(|&n| n > 0)
        .map(|n| n.min(MAX_BODY_PREVIEW_BYTES))
}

/// Truncate sanitized `body_text` to at most `max_bytes` on a grapheme
/// boundary. Returns the preview (`None` if empty) and whether the body
/// extended beyond it.
fn make_preview(mut body_text: String, max_bytes: usize) -> (Option<String>, bool) {
    let original_len = body_text.len();
    rimap_content::truncate_graphemes_in_place(&mut body_text, max_bytes);
    let truncated = body_text.len() < original_len;
    if body_text.is_empty() {
        (None, false)
    } else {
        (Some(body_text), truncated)
    }
}

/// Select one page of UIDs from a full search result set, plus the
/// pagination metadata to report back to the caller. Pure and
/// independent of the async IMAP layer so it is unit-testable without
/// a live connection.
///
/// When `newest_first` is set, `uids` is reversed before paginating, so
/// `offset` counts from the newest message and consecutive pages (via
/// `next_offset`) walk backward through time without overlapping.
fn paginate_uids(
    mut uids: Vec<Uid>,
    offset: usize,
    limit: usize,
    newest_first: bool,
) -> (Vec<Uid>, bool, Option<u64>) {
    if newest_first {
        uids.reverse();
    }
    let total = uids.len();
    let page: Vec<Uid> = uids.into_iter().skip(offset).take(limit).collect();
    let consumed = offset.saturating_add(page.len());
    let truncated = total > consumed;
    let next_offset = truncated.then(|| u64::try_from(consumed).unwrap_or(u64::MAX));
    (page, truncated, next_offset)
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
    use rimap_content::{
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
        // Filled by `attach_body_previews` when `body_preview_bytes` is set.
        body_preview: None,
        body_preview_truncated: None,
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

    /// The published `search` input schema must not leak posture jargon
    /// to agents (#406): no "Content-oracle" threat-model vocabulary and
    /// no bare `SearchAdvanced` posture-enum variant name. The
    /// posture-gated fields must instead point at the account resource.
    #[test]
    fn input_schema_uses_plain_language_not_posture_jargon() {
        let schema = serde_json::to_string(&schemars::schema_for!(SearchInput))
            .expect("SearchInput schema serializes");
        assert!(
            !schema.contains("Content-oracle"),
            "input schema must not use 'Content-oracle' jargon",
        );
        assert!(
            !schema.contains("SearchAdvanced"),
            "input schema must not use the bare 'SearchAdvanced' variant name",
        );
        assert!(
            schema.contains("rimap://accounts/<name>"),
            "posture-gated fields must point at the account resource",
        );
        assert!(
            schema.contains("full` or `destructive"),
            "posture-gated fields must name the postures that permit them",
        );
    }

    #[test]
    fn clamp_preview_bytes_none_and_zero_disable() {
        assert_eq!(clamp_preview_bytes(None), None);
        assert_eq!(clamp_preview_bytes(Some(0)), None);
    }

    #[test]
    fn clamp_preview_bytes_caps_at_max() {
        assert_eq!(clamp_preview_bytes(Some(10)), Some(10));
        assert_eq!(
            clamp_preview_bytes(Some(MAX_BODY_PREVIEW_BYTES + 500)),
            Some(MAX_BODY_PREVIEW_BYTES),
        );
    }

    #[test]
    fn make_preview_flags_truncation_when_body_exceeds_cap() {
        let (text, truncated) = make_preview("hello world".to_string(), 5);
        assert_eq!(text.as_deref(), Some("hello"));
        assert!(truncated);
    }

    #[test]
    fn make_preview_no_truncation_when_body_fits() {
        let (text, truncated) = make_preview("hi".to_string(), 100);
        assert_eq!(text.as_deref(), Some("hi"));
        assert!(!truncated);
    }

    #[test]
    fn make_preview_empty_body_yields_none() {
        let (text, truncated) = make_preview(String::new(), 100);
        assert_eq!(text, None);
        assert!(!truncated);
    }

    #[test]
    fn make_preview_truncates_on_grapheme_boundary() {
        // A 4-byte cap must not split the 4-byte "é… " sequence mid-codepoint;
        // grapheme truncation keeps whole clusters, so a multi-byte char at
        // the boundary is dropped rather than cut.
        let (text, truncated) = make_preview("aé".to_string(), 2);
        // "a" is 1 byte; "é" is 2 bytes → including it would be 3 > 2, so the
        // preview keeps only "a".
        assert_eq!(text.as_deref(), Some("a"));
        assert!(truncated);
    }

    #[test]
    fn output_schema_exposes_body_preview_fields() {
        let schema = serde_json::to_string(&schemars::schema_for!(SearchResultEntry))
            .expect("SearchResultEntry schema serializes");
        assert!(
            schema.contains("body_preview"),
            "output schema must expose body_preview",
        );
        assert!(
            schema.contains("body_preview_truncated"),
            "output schema must expose body_preview_truncated",
        );
    }

    #[test]
    fn input_schema_exposes_body_preview_bytes() {
        let schema = serde_json::to_string(&schemars::schema_for!(SearchInput))
            .expect("SearchInput schema serializes");
        assert!(
            schema.contains("body_preview_bytes"),
            "input schema must expose body_preview_bytes",
        );
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
            newest_first: None,
            body_preview_bytes: None,
            thread_of_uid: None,
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
            next_offset: None,
            uid_validity: Some(12345),
        };
        let v = serde_json::to_value(meta).unwrap();
        assert_eq!(v["uid_validity"], serde_json::json!(12345));
    }

    #[test]
    fn search_meta_omits_next_offset_when_absent() {
        let meta = SearchMeta {
            folder: "INBOX".to_string(),
            total_matched: 5,
            returned: 5,
            truncated: false,
            next_offset: None,
            uid_validity: None,
        };
        let v = serde_json::to_value(meta).unwrap();
        assert!(
            v.get("next_offset").is_none(),
            "next_offset must be omitted, not null, when absent; got {v}",
        );
    }

    #[test]
    fn search_meta_serializes_next_offset_when_present() {
        let meta = SearchMeta {
            folder: "INBOX".to_string(),
            total_matched: 150,
            returned: 100,
            truncated: true,
            next_offset: Some(100),
            uid_validity: None,
        };
        let v = serde_json::to_value(meta).unwrap();
        assert_eq!(v["next_offset"], serde_json::json!(100));
    }

    fn uids(range: std::ops::RangeInclusive<u32>) -> Vec<rimap_imap::types::Uid> {
        range.map(uid).collect()
    }

    #[test]
    fn paginate_uids_not_truncated_yields_no_next_offset() {
        let (page, truncated, next_offset) = paginate_uids(uids(1..=5), 0, 10, false);
        assert_eq!(page.len(), 5);
        assert!(!truncated);
        assert_eq!(next_offset, None);
    }

    #[test]
    fn paginate_uids_truncated_yields_correct_next_offset() {
        let (page, truncated, next_offset) = paginate_uids(uids(1..=150), 0, 100, false);
        assert_eq!(page.len(), 100);
        assert!(truncated);
        assert_eq!(next_offset, Some(100));

        // Following the returned next_offset picks up exactly where the
        // first page left off, with no gap or overlap.
        let (page2, truncated2, next_offset2) = paginate_uids(uids(1..=150), 100, 100, false);
        assert_eq!(page2.len(), 50);
        assert!(!truncated2);
        assert_eq!(next_offset2, None);
        assert_eq!(page2.first().map(|u| u.get()), Some(101));
        assert_eq!(page2.last().map(|u| u.get()), Some(150));
    }

    #[test]
    fn paginate_uids_offset_past_end_yields_empty_page_and_no_next_offset() {
        let (page, truncated, next_offset) = paginate_uids(uids(1..=5), 1000, 100, false);
        assert!(page.is_empty());
        assert!(!truncated);
        assert_eq!(next_offset, None);
    }

    #[test]
    fn paginate_uids_offset_exactly_at_end_yields_empty_page_and_no_next_offset() {
        let (page, truncated, next_offset) = paginate_uids(uids(1..=5), 5, 100, false);
        assert!(page.is_empty());
        assert!(!truncated);
        assert_eq!(next_offset, None);
    }

    #[test]
    fn paginate_uids_newest_first_orders_descending() {
        let (page, _, _) = paginate_uids(uids(1..=5), 0, 100, true);
        let nums: Vec<u32> = page.iter().map(|u| u.get()).collect();
        assert_eq!(nums, vec![5, 4, 3, 2, 1]);
    }

    #[test]
    fn paginate_uids_newest_first_pages_do_not_overlap() {
        let (page1, truncated1, next_offset1) = paginate_uids(uids(1..=10), 0, 4, true);
        assert_eq!(
            page1.iter().map(|u| u.get()).collect::<Vec<_>>(),
            vec![10, 9, 8, 7],
        );
        assert!(truncated1);
        assert_eq!(next_offset1, Some(4));

        let (page2, truncated2, next_offset2) = paginate_uids(uids(1..=10), 4, 4, true);
        assert_eq!(
            page2.iter().map(|u| u.get()).collect::<Vec<_>>(),
            vec![6, 5, 4, 3],
        );
        assert!(truncated2);
        assert_eq!(next_offset2, Some(8));

        let (page3, truncated3, next_offset3) = paginate_uids(uids(1..=10), 8, 4, true);
        assert_eq!(
            page3.iter().map(|u| u.get()).collect::<Vec<_>>(),
            vec![2, 1]
        );
        assert!(!truncated3);
        assert_eq!(next_offset3, None);
    }

    #[test]
    fn parse_message_id_tokens_splits_whitespace_separated_ids() {
        let tokens = parse_message_id_tokens("<a@x.com> <b@y.com>  <c@z.com>");
        assert_eq!(tokens, vec!["<a@x.com>", "<b@y.com>", "<c@z.com>"]);
    }

    #[test]
    fn parse_message_id_tokens_ignores_non_bracketed_stray_text() {
        // Some clients emit comments or malformed References; only
        // well-formed <...> tokens should survive.
        let tokens = parse_message_id_tokens("<a@x.com> (comment) not-an-id <b@y.com>");
        assert_eq!(tokens, vec!["<a@x.com>", "<b@y.com>"]);
    }

    #[test]
    fn parse_message_id_tokens_rejects_bare_angle_brackets() {
        assert_eq!(parse_message_id_tokens("<>"), Vec::<String>::new());
    }

    #[test]
    fn parse_message_id_tokens_empty_input_yields_empty_vec() {
        assert!(parse_message_id_tokens("").is_empty());
        assert!(parse_message_id_tokens("   ").is_empty());
    }

    #[test]
    fn cap_ancestor_ids_dedupes_preserving_first_occurrence() {
        let ids = vec!["<a>".to_string(), "<b>".to_string(), "<a>".to_string()];
        assert_eq!(cap_ancestor_ids(ids), vec!["<a>", "<b>"]);
    }

    #[test]
    fn cap_ancestor_ids_under_cap_returns_all() {
        let ids: Vec<String> = (0..5).map(|i| format!("<{i}>")).collect();
        assert_eq!(cap_ancestor_ids(ids.clone()), ids);
    }

    #[test]
    fn cap_ancestor_ids_over_cap_keeps_closest_ancestors() {
        // References is oldest-first (RFC 5322 §3.6.4), so when a chain
        // exceeds the cap, the *last* (closest/most recent) entries are
        // the useful ones to keep.
        let ids: Vec<String> = (0..MAX_THREAD_ANCESTOR_IDS + 10)
            .map(|i| format!("<{i}>"))
            .collect();
        let capped = cap_ancestor_ids(ids);
        assert_eq!(capped.len(), MAX_THREAD_ANCESTOR_IDS);
        assert_eq!(capped.first().map(String::as_str), Some("<10>"));
        assert_eq!(
            capped.last().map(String::as_str),
            Some(format!("<{}>", MAX_THREAD_ANCESTOR_IDS + 9).as_str()),
        );
    }

    #[test]
    fn validate_thread_request_rejects_advanced_query_combination() {
        let mut input = input_with_folder();
        input.advanced_query = Some("ALL".to_string());
        input.thread_of_uid = std::num::NonZeroU32::new(1);
        let err = validate_thread_request(&input)
            .expect_err("advanced_query + thread_of_uid must be rejected");
        assert!(
            err.to_string().contains("thread_of_uid"),
            "expected thread_of_uid/advanced_query conflict error, got: {err}",
        );
    }

    #[test]
    fn validate_thread_request_accepts_thread_of_uid_alone() {
        let mut input = input_with_folder();
        input.thread_of_uid = std::num::NonZeroU32::new(1);
        assert!(validate_thread_request(&input).is_ok());
    }
}
