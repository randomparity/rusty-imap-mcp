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
    /// `Date` header. Serialized as a 9-element integer tuple:
    /// `[year, ordinal, hour, minute, second, nanosecond,
    ///   offset_whole_hours, offset_minutes_past_hour,
    ///   offset_seconds_past_minute]`.
    ///
    /// Note: the `time` crate does not enable `serde-human-readable` in
    /// this workspace, so `OffsetDateTime` always serializes as a tuple
    /// regardless of the serializer's `is_human_readable()` flag.
    #[schemars(schema_with = "offset_date_time_tuple_schema")]
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
/// Returns `RimapError::Authz { code: AttachmentTooLarge, ... }` when a
/// content-pipeline cap (MIME depth/parts, header count, HTML size) is
/// exceeded during parse. Returns `RimapError::Internal` if the
/// `parse_message_async` blocking task panics or the parse semaphore
/// is closed — those are infrastructure failures, not input failures.
/// Returns `RimapError::Imap { ... }` for IMAP-layer failures (network,
/// timeout, protocol, attachment-too-large). The upstream
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

    let raw = account.imap.fetch_body(&input.folder, uid).await?;
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

/// JSON Schema for `time::OffsetDateTime` as serialized by the `time` crate
/// without the `serde-human-readable` feature.
///
/// The `time` crate serializes `OffsetDateTime` as a 9-element integer tuple:
/// `[year, day_of_year, hour, minute, second, nanosecond,
///   offset_whole_hours, offset_minutes_past_hour, offset_seconds_past_minute]`.
/// This matches the actual wire bytes produced by `serde_json::to_string` when
/// the workspace does not enable `serde-human-readable` on the `time` crate.
///
/// Used via `#[schemars(schema_with = "offset_date_time_tuple_schema")]` on
/// `FetchMessageUntrusted::date`.
fn offset_date_time_tuple_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
    use schemars::json_schema;
    json_schema!({
        "type": ["array", "null"],
        "description": concat!(
            "time::OffsetDateTime as a 9-element integer tuple: ",
            "[year, day_of_year, hour, minute, second, nanosecond, ",
            "offset_whole_hours, offset_minutes_past_hour, ",
            "offset_seconds_past_minute]. Null when the header is absent."
        ),
        "prefixItems": [
            { "type": "integer", "description": "year" },
            { "type": "integer", "description": "day_of_year (ordinal 1–366)" },
            { "type": "integer", "description": "hour (0–23)" },
            { "type": "integer", "description": "minute (0–59)" },
            { "type": "integer", "description": "second (0–60)" },
            { "type": "integer", "description": "nanosecond (0–999999999)" },
            { "type": "integer", "description": "UTC offset: whole hours (-23–23)" },
            { "type": "integer", "description": "UTC offset: minutes past hour (-59–59)" },
            { "type": "integer", "description": "UTC offset: seconds past minute (-59–59)" }
        ],
        "minItems": 9,
        "maxItems": 9,
        "items": false
    })
}
