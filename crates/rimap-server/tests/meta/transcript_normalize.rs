//! Unit tests for the transcript `normalize` helper. A dedicated binary so the
//! pure-function tests run without needing a full wire session. Includes the
//! wire support tree because `transcript.rs` lives under it.
//!
//! The tests use `assert!`/`assert_eq!` only (no `expect`/`panic`/`unwrap`), so
//! this root file carries no blanket `#![expect(...)]` — the included support
//! modules keep their own module-scoped attributes.

#[path = "../support/wire/mod.rs"]
mod wire;

use serde_json::json;
use wire::transcript::{normalize, record_response};

#[test]
fn masks_server_version() {
    let raw = r#""version": "0.1.1-dev""#;
    let out = normalize(raw);
    assert!(out.contains(r#""version": "<VERSION>""#), "got: {out}");
    assert!(!out.contains("0.1.1-dev"), "version leaked: {out}");
}

#[test]
fn leaves_envelope_clock_time_untouched() {
    // The greediest risk: a naive `:<digits>` mask would eat this.
    let raw = "Date: Wed, 01 Jan 2020 10:30:00 +0000";
    assert_eq!(normalize(raw), raw, "clock time must survive normalize");
}

#[test]
fn leaves_small_scripted_numbers_untouched() {
    let raw = r#""uid": 2, "size": 42, "total_matched": 3"#;
    assert_eq!(normalize(raw), raw, "scripted numerics must survive");
}

#[test]
fn leaves_security_warning_text_untouched() {
    let raw = r#""security_warnings": ["hidden-instructions detected"]"#;
    assert_eq!(normalize(raw), raw, "warning text is the guarded payload");
}

#[test]
fn masks_generated_draft_message_id() {
    let raw = r#""message_id": "71963.1784005514632003000@rimap-test""#;
    let out = normalize(raw);
    assert!(
        out.contains(r#""message_id": "<GENERATED-MESSAGE-ID>""#),
        "got: {out}"
    );
    assert!(
        !out.contains("1784005514632003000"),
        "generated id leaked: {out}"
    );
}

#[test]
fn leaves_fixture_message_ids_untouched() {
    // Deterministic fixture ids (with and without angle brackets) are the guarded
    // payload — the letters/hyphen local-part is not the generated timestamp shape.
    let raw = r#""message_id": "clean-0001@example.com""#;
    assert_eq!(
        normalize(raw),
        raw,
        "fixture message-id must survive: {raw}"
    );
    let bracketed = r#""message_id": "<hostile-0001@example.com>""#;
    assert_eq!(
        normalize(bracketed),
        bracketed,
        "bracketed fixture id must survive"
    );
}

#[test]
fn record_response_drops_content_keeps_structured() {
    let resp = json!({
        "result": {
            "isError": false,
            "content": [{ "type": "text", "text": "{\"meta\":{\"folder\":\"INBOX\"}}" }],
            "structuredContent": { "meta": { "folder": "INBOX" } },
        }
    });
    let out = record_response("tools/call", &resp);
    assert!(
        out["result"].get("content").is_none(),
        "content must be dropped: {out}"
    );
    assert_eq!(out["result"]["isError"], json!(false));
    assert_eq!(
        out["result"]["structuredContent"]["meta"]["folder"],
        json!("INBOX")
    );
}

#[test]
fn tools_list_projection_drops_schemas_keeps_prose() {
    let resp = json!({
        "result": { "tools": [
            {
                "name": "agent.search",
                "title": "Search",
                "description": "Find message UIDs.",
                "inputSchema": { "type": "object", "properties": { "folder": {} } },
                "outputSchema": { "type": "object" },
            }
        ]}
    });
    let out = record_response("tools/list", &resp);
    let tool = &out["result"]["tools"][0];
    assert_eq!(tool["name"], json!("agent.search"));
    assert_eq!(tool["description"], json!("Find message UIDs."));
    assert!(
        tool.get("inputSchema").is_none(),
        "inputSchema must be dropped: {out}"
    );
    assert!(
        tool.get("outputSchema").is_none(),
        "outputSchema must be dropped: {out}"
    );
}

#[test]
fn record_response_passes_non_tools_list_through() {
    let resp = json!({ "result": { "structuredContent": { "meta": { "folder": "INBOX" } } } });
    let out = record_response("tools/call", &resp);
    assert_eq!(
        out["result"]["structuredContent"]["meta"]["folder"],
        json!("INBOX")
    );
}

#[test]
fn record_response_records_error_object() {
    let resp = json!({ "error": { "code": -32601, "message": "method not found" } });
    let out = record_response("tools/list", &resp);
    assert_eq!(out["error"]["code"], json!(-32601));
    assert!(
        out.get("result").is_none(),
        "error response must not carry result: {out}"
    );
}

#[test]
fn version_value_with_escaped_quote_is_fully_replaced() {
    // Guards the escaped-quote scan: the close-quote search must skip \" so the
    // whole value is masked, not truncated at the inner escaped quote.
    let raw = r#""version": "1.0\"weird""#;
    let out = normalize(raw);
    assert!(out.contains(r#""version": "<VERSION>""#), "got: {out}");
    assert!(
        !out.contains("weird"),
        "value tail leaked past escaped quote: {out}"
    );
}
