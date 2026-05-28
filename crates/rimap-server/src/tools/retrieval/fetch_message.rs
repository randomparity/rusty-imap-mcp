//! `fetch_message` tool handler.

use rimap_content::unicode::truncate_graphemes_in_place;
use rimap_imap::types::Uid;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::boot::registry::AccountState;
use crate::mcp::response::ToolResponse;

/// Input for the `fetch_message` tool.
///
/// # Shape
///
/// This tool intentionally takes a single scalar `uid` (non-zero) rather than a
/// batch. The asymmetry with batch-capable tools (`flag`, `add_label`,
/// `move_message`) is deliberate: batch shapes (`uid` XOR `uids`) are
/// reserved for commutative, idempotent mutations where per-UID ordering
/// does not matter and results fan out uniformly. Read-side and
/// destructive single-target tools keep a scalar `uid` so the response
/// schema and error semantics stay unambiguous.
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
    /// Truncate body text (and HTML if included) to this many bytes.
    #[serde(
        default,
        deserialize_with = "crate::tools::lenient_int::deserialize_opt_usize"
    )]
    #[schemars(schema_with = "crate::tools::lenient_int::schema_opt_usize")]
    pub max_body_bytes: Option<usize>,
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
}

/// Execute the `fetch_message` tool.
///
/// # Errors
///
/// Returns `RimapError::Authz { code: InvalidInput, ... }` when
/// `rimap-content` rejects the body as malformed RFC 5322.
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

    let uid = Uid::from(input.uid);

    let raw = account.imap.fetch_body(&input.folder, uid, None).await?;
    let raw_size = raw.len();

    let content = crate::mcp::content::parse_message_async(raw).await?;

    let mut body_text = content.untrusted.body_text;
    let mut body_html = if include_html {
        content.untrusted.body_html
    } else {
        None
    };

    let mut truncated = content.meta.body_truncated;

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
