//! Records the ordered request→response exchanges of a wire session and renders
//! them as a normalized, CR-stripped string for `insta` snapshotting. See
//! `docs/superpowers/specs/2026-07-13-issue-524-golden-agent-transcripts-design.md`.

use std::fmt::Write as _;

use serde_json::{Value, json};

use super::harness::Harness;

/// Replace run-varying substrings with stable placeholders. Pure; each mask has
/// a positive AND a negative unit test in `tests/transcript_normalize.rs`. Masks
/// are added only for values TDD confirms appear in the rendered transcript.
///
/// Implemented with plain string ops (no `regex` dependency). Two masks:
/// - `serverInfo.version` — always masked (churns every release, not on drift).
/// - `message_id` — masked ONLY when the value is a server-*generated* draft
///   Message-ID (`create_draft` stamps `<pid>.<nanos>@<host>`, which varies per
///   run). Deterministic fixture message-ids (`clean-0001@example.com`) are the
///   guarded payload and are left intact — see [`is_generated_message_id`].
#[must_use]
pub fn normalize(raw: &str) -> String {
    let out = mask_json_string_field_if(raw, "version", "<VERSION>", |_| true);
    mask_json_string_field_if(
        &out,
        "message_id",
        "<GENERATED-MESSAGE-ID>",
        is_generated_message_id,
    )
}

/// True for a server-generated draft Message-ID: local-part (before `@`, angle
/// brackets stripped) is entirely digits and dots with at least one dot — the
/// `<pid>.<nanos>` timestamp shape `create_draft` emits. Fixture ids like
/// `clean-0001@example.com` (letters/hyphen) and `<x@example.com>` are NOT
/// generated, so they survive normalization.
fn is_generated_message_id(value: &str) -> bool {
    let trimmed = value.trim_start_matches('<').trim_end_matches('>');
    let local = trimmed.split('@').next().unwrap_or("");
    !local.is_empty()
        && local.contains('.')
        && local.chars().all(|c| c.is_ascii_digit() || c == '.')
}

/// Replace the quoted value of every `"<field>": "<value>"` occurrence with
/// `"<field>": "<placeholder>"` when `should_mask(value)` is true. Anchored to
/// the `"field":` token, so it cannot match a bare number or a clock time. The
/// closing-quote scan skips backslash-escaped quotes, so a value containing an
/// escaped `\"` is not truncated mid-value.
///
/// Scope: masks JSON **string** values only — a numeric or object value at the
/// field is copied through unchanged. Intended for whole-value replacement of
/// stable identifier/timestamp strings. Do not use it to mask a *substring* of a
/// free-text field.
fn mask_json_string_field_if(
    raw: &str,
    field: &str,
    placeholder: &str,
    should_mask: impl Fn(&str) -> bool,
) -> String {
    let needle = format!("\"{field}\":");
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(pos) = rest.find(&needle) {
        let after = &rest[pos + needle.len()..];
        // Skip whitespace, require an opening quote, find the closing quote.
        let trimmed = after.trim_start();
        let ws_len = after.len() - trimmed.len();
        let Some(inner) = trimmed.strip_prefix('"') else {
            // Not a string value (e.g. numeric) — copy through and continue.
            let copy_to = pos + needle.len();
            out.push_str(&rest[..copy_to]);
            rest = &rest[copy_to..];
            continue;
        };
        // Find the closing quote, skipping any backslash-escaped quote.
        let mut close = None;
        let bytes = inner.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            match bytes[i] {
                b'\\' => i += 2, // skip the escaped char (e.g. \" or \\)
                b'"' => {
                    close = Some(i);
                    break;
                }
                _ => i += 1,
            }
        }
        let Some(close) = close else {
            out.push_str(rest);
            return out;
        };
        let consumed =
            pos + needle.len() + ws_len + 1 /* open quote */ + close + 1 /* close quote */;
        if should_mask(&inner[..close]) {
            out.push_str(&rest[..pos + needle.len()]);
            out.push_str(&" ".repeat(ws_len));
            out.push('"');
            out.push_str(placeholder);
            out.push('"');
        } else {
            out.push_str(&rest[..consumed]);
        }
        rest = &rest[consumed..];
    }
    out.push_str(rest);
    out
}

/// Reduce a JSON-RPC response to the agent-facing payload the transcript pins.
///
/// Errors record their `error` object. Successes record `result`, with two
/// noise-reducing projections:
///
/// - **`tools/list`**: each advertised tool's `inputSchema`/`outputSchema` is
///   dropped, because those schemas are already pinned byte-for-byte by the
///   dedicated schema-drift gate (`just regen-tool-schemas` +
///   `tests/fixtures/rimap-tool-schemas/`). Re-pinning them here would add
///   thousands of lines that churn on any unrelated tool-schema edit — noise that
///   buries the surface #524 actually guards: the agent-facing prose (`name`,
///   `title`, `description`, `annotations`).
/// - **`tools/call`**: when the result carries `structuredContent`, the
///   `content` array is dropped. `content[0].text` is a byte-identical JSON
///   stringification of `structuredContent` (the MCP dual representation), so
///   pinning `structuredContent` already guards every field; keeping both would
///   double the snapshot and force every volatile value to be masked twice (once
///   escaped, once not). `isError` is preserved.
pub fn record_response(method: &str, resp: &Value) -> Value {
    if resp.get("error").is_some_and(|e| !e.is_null()) {
        return json!({ "error": resp["error"].clone() });
    }
    let result = &resp["result"];
    if method == "tools/list"
        && let Some(tools) = result["tools"].as_array()
    {
        let projected: Vec<Value> = tools
            .iter()
            .map(|tool| {
                let mut tool = tool.clone();
                if let Some(obj) = tool.as_object_mut() {
                    obj.remove("inputSchema");
                    obj.remove("outputSchema");
                }
                tool
            })
            .collect();
        return json!({ "result": { "tools": projected } });
    }
    if !result["structuredContent"].is_null() {
        return json!({ "result": {
            "isError": result["isError"].clone(),
            "structuredContent": result["structuredContent"].clone(),
        }});
    }
    json!({ "result": result.clone() })
}

/// One recorded request→response exchange with its stable display id.
struct Exchange {
    id: u64,
    request: Value,
    response: Value,
}

/// Captures request→response exchanges for a golden transcript.
pub struct Recorder {
    exchanges: Vec<Exchange>,
    next_display_id: u64,
}

impl Recorder {
    #[must_use]
    pub fn new() -> Self {
        Self {
            exchanges: Vec::new(),
            next_display_id: 1,
        }
    }

    /// Drive one request through the harness, record request+response with a
    /// stable sequential display id, and return the response so the flow's
    /// mandatory non-vacuity assertions can run on it.
    pub async fn call(&mut self, h: &mut Harness, method: &str, params: Value) -> Value {
        let display_id = self.next_display_id;
        self.next_display_id += 1;
        let resp = h.request(method, params.clone()).await;
        self.exchanges.push(Exchange {
            id: display_id,
            request: json!({ "method": method, "params": params }),
            response: record_response(method, &resp),
        });
        resp
    }

    /// Render the recorded exchanges to a normalized, CR-stripped snapshot string.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::new();
        for ex in &self.exchanges {
            let id = ex.id;
            let req = serde_json::to_string_pretty(&ex.request).unwrap_or_default();
            let resp = serde_json::to_string_pretty(&ex.response).unwrap_or_default();
            // `writeln!` to a String is infallible; `let _ =` discards the Result
            // without an `unwrap`/`expect` (both denied in this crate). Labels go
            // through `writeln!` (no trailing `\n` in the literal, so
            // `write_with_newline` stays quiet); the pre-rendered JSON bodies are
            // plain `push_str` of a variable (not a `format!`, so
            // `format_push_string` stays quiet).
            let _ = writeln!(out, ">>> request {id}");
            out.push_str(&req);
            let _ = writeln!(out);
            let _ = writeln!(out, "<<< response {id}");
            out.push_str(&resp);
            let _ = writeln!(out);
            let _ = writeln!(out);
        }
        normalize(&out.replace('\r', ""))
    }
}

impl Default for Recorder {
    fn default() -> Self {
        Self::new()
    }
}
