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
/// Implemented with plain string ops (no `regex` dependency). The only mask
/// required up front is the `serverInfo.version` value, anchored to the JSON
/// `"version": "…"` field so it never touches envelope/body text.
#[must_use]
pub fn normalize(raw: &str) -> String {
    mask_json_string_field(raw, "version", "<VERSION>")
}

/// Replace the quoted value of every `"<field>": "<value>"` occurrence with
/// `"<field>": "<placeholder>"`. Anchored to the `"field":` token, so it cannot
/// match a bare number or a clock time. The closing-quote scan skips
/// backslash-escaped quotes, so a value containing an escaped `\"` is not
/// truncated mid-value.
///
/// Scope: masks JSON **string** values only — a numeric or object value at the
/// field is copied through unchanged. Intended for stable identifier/timestamp
/// strings (`version`, `Message-ID`, `Date`, `boundary`) whose whole value is
/// replaced. Do not use it to mask a *substring* of a free-text field.
fn mask_json_string_field(raw: &str, field: &str, placeholder: &str) -> String {
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
        out.push_str(&rest[..pos + needle.len()]);
        out.push_str(&" ".repeat(ws_len));
        out.push('"');
        out.push_str(placeholder);
        out.push('"');
        // Advance past the closing quote of the original value.
        let consumed = pos + needle.len() + ws_len + 1 /* open quote */ + close + 1 /* close quote */;
        rest = &rest[consumed..];
    }
    out.push_str(rest);
    out
}

/// Captures request→response exchanges for a golden transcript.
pub struct Recorder {
    exchanges: Vec<Value>,
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
        let recorded = if resp.get("error").is_some_and(|e| !e.is_null()) {
            json!({ "error": resp["error"].clone() })
        } else {
            json!({ "result": resp["result"].clone() })
        };
        self.exchanges.push(json!({
            "id": display_id,
            "request": { "method": method, "params": params },
            "response": recorded,
        }));
        resp
    }

    /// Render the recorded exchanges to a normalized, CR-stripped snapshot string.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::new();
        for ex in &self.exchanges {
            let id = ex["id"].as_u64().unwrap_or(0);
            let req = serde_json::to_string_pretty(&ex["request"]).unwrap_or_default();
            let resp = serde_json::to_string_pretty(&ex["response"]).unwrap_or_default();
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
