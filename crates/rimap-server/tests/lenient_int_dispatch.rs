//! Integration test: confirm input types accept both integer-form and
//! string-form values for integer fields (#292). This exercises the
//! same `parse_args` deserialization path the MCP dispatch layer runs.

#![expect(clippy::unwrap_used, reason = "integration tests")]

use rimap_server::tools::compose::create_draft::CreateDraftInput;
use rimap_server::tools::retrieval::search::SearchInput;
use serde_json::json;

#[test]
fn search_input_accepts_integer_limit() {
    let v = json!({"folder": "INBOX", "limit": 100});
    let input: SearchInput = serde_json::from_value(v).unwrap();
    assert_eq!(input.limit, Some(100));
}

#[test]
fn search_input_accepts_string_limit() {
    let v = json!({"folder": "INBOX", "limit": "100"});
    let input: SearchInput = serde_json::from_value(v).unwrap();
    assert_eq!(input.limit, Some(100));
}

#[test]
fn search_input_accepts_null_limit() {
    let v = json!({"folder": "INBOX", "limit": null});
    let input: SearchInput = serde_json::from_value(v).unwrap();
    assert_eq!(input.limit, None);
}

#[test]
fn search_input_accepts_absent_limit() {
    let v = json!({"folder": "INBOX"});
    let input: SearchInput = serde_json::from_value(v).unwrap();
    assert_eq!(input.limit, None);
}

#[test]
fn search_input_accepts_string_offset() {
    let v = json!({"folder": "INBOX", "offset": "5"});
    let input: SearchInput = serde_json::from_value(v).unwrap();
    assert_eq!(input.offset, Some(5));
}

#[test]
fn search_input_rejects_non_digit_string() {
    let v = json!({"folder": "INBOX", "limit": "abc"});
    let err = serde_json::from_value::<SearchInput>(v).unwrap_err();
    assert!(err.to_string().contains("integer"), "got: {err}");
}

#[test]
fn create_draft_input_accepts_integer_reply_uid() {
    let v = json!({
        "to": [{"address": "a@b.test"}],
        "subject": "s",
        "body_text": "b",
        "in_reply_to_uid": 42,
    });
    let input: CreateDraftInput = serde_json::from_value(v).unwrap();
    assert_eq!(
        input.in_reply_to_uid.map(core::num::NonZeroU32::get),
        Some(42)
    );
}

#[test]
fn create_draft_input_accepts_string_reply_uid() {
    let v = json!({
        "to": [{"address": "a@b.test"}],
        "subject": "s",
        "body_text": "b",
        "in_reply_to_uid": "42",
    });
    let input: CreateDraftInput = serde_json::from_value(v).unwrap();
    assert_eq!(
        input.in_reply_to_uid.map(core::num::NonZeroU32::get),
        Some(42)
    );
}

#[test]
fn create_draft_input_rejects_zero_reply_uid() {
    let v = json!({
        "to": [{"address": "a@b.test"}],
        "subject": "s",
        "body_text": "b",
        "in_reply_to_uid": "0",
    });
    let err = serde_json::from_value::<CreateDraftInput>(v).unwrap_err();
    assert!(
        err.to_string().contains("nonzero") || err.to_string().contains("non-zero"),
        "got: {err}",
    );
}
