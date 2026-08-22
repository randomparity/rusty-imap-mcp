//! `fetch_message` tool handler.

use std::collections::BTreeMap;

use rimap_content::truncate_graphemes_in_place;
use rimap_imap::types::Uid;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::boot::registry::AccountState;
use crate::mcp::response::ToolResponse;

// Scalar-uid rationale: this tool intentionally has no batch shape, see
// the `Scalar vs batch uid shapes` section of `crate::tools` module docs (#405).
#[derive(Debug, Deserialize, JsonSchema)]
pub struct FetchMessageInput {
    /// IMAP folder containing the message.
    pub folder: String,
    /// UID of the message to fetch.
    #[serde(deserialize_with = "crate::tools::lenient_int::deserialize_nonzero_u32")]
    #[schemars(schema_with = "crate::tools::lenient_int::schema_nonzero_u32")]
    pub uid: core::num::NonZeroU32,
    /// Include sanitized HTML body in the response.
    pub include_html: Option<bool>,
    /// Truncate body text (and HTML if included) to this many bytes. When
    /// omitted, the full sanitized body is returned with no size cap; set
    /// this to bound response size for long messages or threads. Whenever
    /// truncation occurs (from this cap or otherwise), `meta.truncated` is
    /// `true`.
    #[serde(
        default,
        deserialize_with = "crate::tools::lenient_int::deserialize_opt_usize"
    )]
    #[schemars(schema_with = "crate::tools::lenient_int::schema_opt_usize")]
    pub max_body_bytes: Option<usize>,
    /// Opt-in allowlist of raw header names to return (e.g.
    /// `["List-Unsubscribe", "List-Id"]`). Matching is case-insensitive;
    /// repeated headers are returned as an array of values. Requested
    /// names that are not present on the message are simply omitted from
    /// the response (not an error). At most 16 names per call; each value
    /// is sanitized and length-capped like every other header. Values
    /// appear under `untrusted.headers` because header content is
    /// attacker-controlled. Available at every posture that permits
    /// `fetch_message`; there is no separate capability gate for headers.
    #[serde(default)]
    pub include_headers: Option<Vec<String>>,
}

/// Trusted metadata for a `fetch_message` response.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct FetchMessageMeta {
    /// IMAP folder the message was fetched from.
    pub folder: String,
    /// UID of the fetched message.
    pub uid: u32,
    /// RFC 2822 `Message-ID` header, if present.
    pub message_id: Option<String>,
    /// Raw size of the message body in bytes.
    pub size: usize,
    /// Whether the body was truncated to `max_body_bytes`.
    pub truncated: bool,
}

/// Sanitized untrusted payload for a `fetch_message` response.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct FetchMessageUntrusted {
    /// Plain-text body (sanitized).
    pub body_text: String,
    /// Sanitized HTML body, present only when `include_html=true`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_html: Option<String>,
    /// `Subject` header.
    pub subject: Option<String>,
    /// `From` header.
    pub from: Option<String>,
    /// `To` header recipients.
    pub to: Vec<String>,
    /// `Cc` header recipients.
    pub cc: Vec<String>,
    /// `Reply-To` header.
    pub reply_to: Option<String>,
    /// `Date` header as an RFC 3339 / ISO 8601 timestamp in UTC, e.g.
    /// `"2025-01-29T17:35:39Z"`; `null` when the header is absent. The
    /// instant is normalized to UTC by the content pipeline, so the
    /// offset is always `Z`. Mirrors `search`'s string-valued `date`.
    #[serde(with = "time::serde::rfc3339::option")]
    #[schemars(schema_with = "rfc3339_date_time_schema")]
    pub date: Option<time::OffsetDateTime>,
    /// MIME attachment parts found in the message.
    pub attachments: Vec<rimap_content::AttachmentMeta>,
    /// Requested raw headers (from `include_headers`), each mapped to its
    /// sanitized value(s). Present only when `include_headers` was
    /// supplied; contains only the requested names that were present on
    /// the message. Values are attacker-controlled email content.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<BTreeMap<String, Vec<String>>>,
}

/// Execute the `fetch_message` tool.
///
/// # Errors
///
/// Returns `RimapError::Authz { code: InvalidInput, ... }` when
/// `rimap-content` rejects the body as malformed RFC 5322, or when
/// `include_headers` exceeds the count cap or names a structurally
/// invalid header (validated before any IMAP work).
/// Returns `RimapError::AttachmentTooLarge { kind, limit }` when a
/// content-pipeline cap (MIME depth/parts, header count, HTML size) is
/// exceeded during parse, or when the IMAP fetch-body cap is hit
/// (`kind = "fetch_body_bytes"`); the typed fields surface as structured
/// MCP `data` (#303). Returns `RimapError::Internal` if the
/// `parse_message_async` blocking task panics or the parse semaphore
/// is closed — those are infrastructure failures, not input failures.
/// Returns `RimapError::Imap { ... }` for other IMAP-layer failures
/// (network, timeout, protocol). The upstream
/// `DispatchGuard::pre_dispatch` layer may also return `Authz { code: PostureDenied }`
/// for `FetchMessageHtml` when `include_html=true` and posture forbids it.
pub async fn handle(
    account: &AccountState,
    input: FetchMessageInput,
) -> Result<ToolResponse<FetchMessageMeta, FetchMessageUntrusted>, rimap_core::RimapError> {
    crate::tools::validation::validate_folder_input("folder", &input.folder)?;

    // The `FetchMessageHtml` posture check happens upstream in
    // `refine_tool_name` + `DispatchGuard::pre_dispatch`; this handler just reads
    // the include_html flag.
    let include_html = input.include_html.unwrap_or(false);

    // Validate the header allowlist before any IMAP work so a malformed
    // request fails fast. `None` and `Some([])` both mean "no headers".
    let wanted_headers = match &input.include_headers {
        Some(names) => crate::tools::validation::validate_include_headers(names)?,
        None => Vec::new(),
    };
    let requested_headers = input.include_headers.is_some();

    let uid = Uid::from(input.uid);

    let raw = account.imap.fetch_body(&input.folder, uid, None).await?;
    let raw_size = raw.len();

    // Only pay for header extraction when the caller asked for headers;
    // the common path stays a plain parse.
    let (content, selected_headers) = if wanted_headers.is_empty() {
        let content = crate::tools::content_parse::parse_message_async(raw).await?;
        (content, Vec::new())
    } else {
        crate::tools::content_parse::parse_message_with_headers_async(raw, wanted_headers).await?
    };

    // Present the `headers` map whenever the caller opted in, even if none
    // of the requested names were found (empty object), so the response
    // shape reflects the request rather than the message.
    let headers = requested_headers.then(|| {
        selected_headers
            .into_iter()
            .map(|h| (h.name, h.values))
            .collect::<BTreeMap<_, _>>()
    });

    let mut body_text = content.untrusted.body_text;
    let mut body_html = if include_html {
        content.untrusted.body_html
    } else {
        None
    };

    let mut truncated = content.meta.body_truncated;

    // cargo-mutants: best-effort — the `> with </>=/==` mutants on this
    // `max_body_bytes` truncation survive because `body_text` comes from an IMAP
    // fetch + content parse inside this handler. Exercising the boundary needs a
    // fetched message body straddling `max`, i.e. the integration harness.
    if let Some(max) = input.max_body_bytes {
        if body_text.len() > max {
            truncate_graphemes_in_place(&mut body_text, max);
            truncated = true;
        }
        if let Some(html) = &mut body_html
            && html.len() > max
        {
            truncate_graphemes_in_place(html, max);
            truncated = true;
        }
    }

    Ok(ToolResponse::meta_only(FetchMessageMeta {
        folder: input.folder,
        uid: input.uid.get(),
        message_id: content.meta.message_id,
        size: raw_size,
        truncated,
    })
    .with_untrusted(FetchMessageUntrusted {
        body_text,
        body_html,
        subject: content.meta.subject,
        from: content.meta.from,
        to: content.meta.to,
        cc: content.meta.cc,
        reply_to: content.meta.reply_to,
        date: content.meta.date,
        attachments: content.meta.attachments,
        headers,
    })
    .with_warnings(content.security_warnings))
}

/// JSON Schema for the RFC 3339 string form of `FetchMessageUntrusted::date`.
///
/// The field serializes via `time::serde::rfc3339::option`, producing a UTC
/// timestamp string (or `null`). A plain `["string", "null"]` schema validates
/// identically under every JSON Schema draft.
///
/// This replaces the `time` crate's default integer-tuple serialization, whose
/// schema required Draft 2020-12 `prefixItems` + `items: false`. Draft-07
/// validators (e.g. Ajv, the default in the official TypeScript MCP SDK) ignore
/// `prefixItems` and read `items: false` as "the array must be empty", rejecting
/// every element of a valid timestamp tuple and failing structured-output
/// validation.
///
/// Used via `#[schemars(schema_with = "rfc3339_date_time_schema")]` on
/// `FetchMessageUntrusted::date`.
fn rfc3339_date_time_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
    use schemars::json_schema;
    json_schema!({
        "type": ["string", "null"],
        "format": "date-time"
    })
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "tests")]
mod tests {
    use super::*;

    fn untrusted_with_date(date: Option<time::OffsetDateTime>) -> FetchMessageUntrusted {
        FetchMessageUntrusted {
            body_text: "hello".to_string(),
            body_html: None,
            subject: None,
            from: None,
            to: Vec::new(),
            cc: Vec::new(),
            reply_to: None,
            date,
            attachments: Vec::new(),
            headers: None,
        }
    }

    #[test]
    fn date_serializes_as_rfc3339_utc_string() {
        // The content pipeline normalizes the Date header to UTC, so the
        // RFC 3339 form always carries a `Z` offset and no fractional part
        // for whole-second timestamps.
        let dt = time::macros::datetime!(2025-01-29 17:35:39 UTC);
        let value = serde_json::to_value(untrusted_with_date(Some(dt))).expect("serialize");
        assert_eq!(value["date"], serde_json::json!("2025-01-29T17:35:39Z"));
    }

    #[test]
    fn absent_date_serializes_as_null() {
        let value = serde_json::to_value(untrusted_with_date(None)).expect("serialize");
        assert_eq!(value["date"], serde_json::Value::Null);
    }
}
