//! JSON-RPC 2.0 envelope validator (#277).
//!
//! Wraps rmcp's stdio transport: reads stdin, validates each line as a
//! JSON-RPC 2.0 envelope, forwards valid envelopes to rmcp via an
//! in-memory duplex stream, and synthesizes `-32600 Invalid Request` /
//! `-32700 Parse error` envelopes for malformed input. Without this
//! layer rmcp 1.5's `JsonRpcMessageCodec` silently drops envelopes
//! that fail its compatibility shim — see
//! `docs/superpowers/specs/2026-05-15-issue-277-envelope-validator-design.md`.

use std::sync::Arc;

use serde_json::Value;
use tokio::io::{DuplexStream, Stdout};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

/// Bridge-task duplex buffer. Large enough that one well-formed
/// envelope fits in a single write; both directions are independent
/// tasks so inbound stalls cannot cause outbound deadlock.
#[expect(
    dead_code,
    reason = "consumed by validate_inbound/passthrough_outbound in Tasks 2.1/2.2"
)]
const BUF_SIZE: usize = 64 * 1024;

/// What the validator decides for a given line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ValidationOutcome {
    /// Forward the line byte-for-byte to rmcp.
    Forward,
    /// Empty or whitespace-only line — drop silently.
    Skip,
    /// Reject with the synthesized error envelope.
    Reject(ErrorEnvelope),
}

/// A synthesized JSON-RPC error response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ErrorEnvelope {
    pub code: i32,
    pub message: &'static str,
    pub id: Value, // `Value::Null` if absent or invalid; otherwise echoed string/number.
}

/// Public bundle handed back to `main.rs::run`. `transport` plugs into
/// `rmcp::serve_server(server, validated.transport)`; `stdout` is the
/// shared writer that all synchronized output paths (validator
/// rejections, passthrough frames, AND `emit_pre_init_error_envelope`)
/// lock; `supervisor` exposes the bridge-task lifecycle.
pub struct ValidatedStdio {
    pub transport: (DuplexStream, DuplexStream),
    pub stdout: Arc<Mutex<Stdout>>,
    pub supervisor: ValidatorSupervisor,
}

/// Supervises the two bridge tasks (`validate_inbound` and
/// `passthrough_outbound`). See the spec for the three-method lifecycle
/// contract: race-phase fail-fast (`watch_for_error`), success-path
/// drain (`drain`), and failure-path abort+drain (`shutdown_after_failure`).
#[expect(
    dead_code,
    reason = "inbound/outbound are read by watch_for_error/drain/shutdown_after_failure in Task 2.4"
)]
pub struct ValidatorSupervisor {
    pub(crate) inbound: JoinHandle<std::io::Result<()>>,
    pub(crate) outbound: JoinHandle<std::io::Result<()>>,
}

// ============================================================
// Pure validator (no I/O — unit-testable in isolation).
// ============================================================

/// `id` accepted by rmcp's `RxJsonRpcMessage`. Null is excluded
/// because rmcp 1.5's `RequestId = NumberOrString` rejects null.
pub(crate) fn is_forwardable_id(v: &Value) -> bool {
    v.is_string() || v.is_number()
}

/// `error` body matches JSON-RPC §5.1: an object with numeric
/// `code` and string `message`. `data` is optional.
pub(crate) fn is_well_formed_error(v: &Value) -> bool {
    let Some(obj) = v.as_object() else {
        return false;
    };
    obj.get("code").is_some_and(Value::is_number)
        && obj.get("message").is_some_and(Value::is_string)
}

/// Read the top-level `id` field for echo on a rejection envelope.
/// Returns `Value::Null` if `id` is missing or of a disallowed type;
/// otherwise echoes the original value verbatim. JSON-RPC §5 says
/// the id on a synthesized error response MUST be null when the
/// original could not be detected.
pub(crate) fn extract_id(obj: &serde_json::Map<String, Value>) -> Value {
    match obj.get("id") {
        Some(v) if v.is_string() || v.is_number() || v.is_null() => v.clone(),
        _ => Value::Null,
    }
}

pub(crate) fn parse_error() -> ErrorEnvelope {
    ErrorEnvelope {
        code: -32700,
        message: "Parse error",
        id: Value::Null,
    }
}

pub(crate) fn invalid_request(id: Value) -> ErrorEnvelope {
    ErrorEnvelope {
        code: -32600,
        message: "Invalid Request",
        id,
    }
}

/// Validate one line of input and decide what to do with it.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "consumed by validate_inbound bridge task in Task 2.1"
    )
)]
pub(crate) fn validate(line: &str) -> ValidationOutcome {
    if line.trim().is_empty() {
        return ValidationOutcome::Skip;
    }
    let parsed: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(_) => return ValidationOutcome::Reject(parse_error()),
    };
    let Some(obj) = parsed.as_object() else {
        return ValidationOutcome::Reject(invalid_request(Value::Null));
    };
    if obj.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return ValidationOutcome::Reject(invalid_request(extract_id(obj)));
    }

    // id (if present) must be string|number — null is rejected here
    // because rmcp's RequestId = NumberOrString won't deserialize null.
    let id_present_and_valid = match obj.get("id") {
        None => false,
        Some(v) if is_forwardable_id(v) => true,
        Some(_) => return ValidationOutcome::Reject(invalid_request(Value::Null)),
    };

    let method = obj.get("method");
    let result = obj.get("result");
    let error = obj.get("error");

    match (method, result, error) {
        // Request: method+id, no result, no error
        (Some(m), None, None) if m.is_string() && id_present_and_valid => {
            ValidationOutcome::Forward
        }
        // Notification: method, no id, no result, no error
        (Some(m), None, None) if m.is_string() && !id_present_and_valid => {
            ValidationOutcome::Forward
        }
        // Response: id+result, no method, no error
        (None, Some(_), None) if id_present_and_valid => ValidationOutcome::Forward,
        // Error response: id+error, no method, no result, error well-formed
        (None, None, Some(err)) if id_present_and_valid && is_well_formed_error(err) => {
            ValidationOutcome::Forward
        }
        // Catch-all: non-string method, empty object, response/error without
        // id, malformed error, both result+error, method mixed with
        // result/error.
        _ => ValidationOutcome::Reject(invalid_request(extract_id(obj))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn reject(code: i32, id: Value) -> ValidationOutcome {
        ValidationOutcome::Reject(ErrorEnvelope {
            code,
            message: if code == -32700 {
                "Parse error"
            } else {
                "Invalid Request"
            },
            id,
        })
    }

    #[test]
    fn empty_line_skips() {
        assert_eq!(validate(""), ValidationOutcome::Skip);
        assert_eq!(validate("   "), ValidationOutcome::Skip);
        assert_eq!(validate("\r"), ValidationOutcome::Skip);
    }

    #[test]
    fn invalid_json_returns_parse_error() {
        assert_eq!(validate("not valid json"), reject(-32700, Value::Null));
    }

    #[test]
    fn non_object_returns_invalid_request() {
        assert_eq!(validate("[1, 2, 3]"), reject(-32600, Value::Null));
        assert_eq!(validate("\"a string\""), reject(-32600, Value::Null));
        assert_eq!(validate("42"), reject(-32600, Value::Null));
        assert_eq!(validate("null"), reject(-32600, Value::Null));
    }

    #[test]
    fn missing_jsonrpc_returns_invalid_request() {
        assert_eq!(validate(r#"{"method":"a"}"#), reject(-32600, Value::Null));
    }

    #[test]
    fn wrong_jsonrpc_value_returns_invalid_request() {
        assert_eq!(
            validate(r#"{"jsonrpc":"1.0","method":"x","id":1}"#),
            reject(-32600, json!(1))
        );
    }

    #[test]
    fn valid_request_forwards() {
        assert_eq!(
            validate(r#"{"jsonrpc":"2.0","method":"tools/list","id":1}"#),
            ValidationOutcome::Forward
        );
        assert_eq!(
            validate(r#"{"jsonrpc":"2.0","method":"tools/list","id":"abc"}"#),
            ValidationOutcome::Forward
        );
    }

    #[test]
    fn valid_notification_forwards() {
        assert_eq!(
            validate(r#"{"jsonrpc":"2.0","method":"notifications/cancelled"}"#),
            ValidationOutcome::Forward
        );
    }

    #[test]
    fn null_id_returns_invalid_request() {
        // Even though JSON-RPC §5 allows null id on responses, rmcp's
        // RequestId = NumberOrString rejects it on the wire; we match
        // that grammar.
        assert_eq!(
            validate(r#"{"jsonrpc":"2.0","method":"x","id":null}"#),
            reject(-32600, Value::Null)
        );
    }

    #[test]
    fn array_or_object_id_returns_invalid_request() {
        assert_eq!(
            validate(r#"{"jsonrpc":"2.0","method":"x","id":[1,2]}"#),
            reject(-32600, Value::Null)
        );
        assert_eq!(
            validate(r#"{"jsonrpc":"2.0","method":"x","id":{"k":"v"}}"#),
            reject(-32600, Value::Null)
        );
    }

    #[test]
    fn non_string_method_returns_invalid_request() {
        assert_eq!(
            validate(r#"{"jsonrpc":"2.0","method":42,"id":1}"#),
            reject(-32600, json!(1))
        );
    }

    #[test]
    fn valid_response_forwards() {
        assert_eq!(
            validate(r#"{"jsonrpc":"2.0","id":99,"result":{"x":1}}"#),
            ValidationOutcome::Forward
        );
    }

    #[test]
    fn valid_error_response_forwards() {
        assert_eq!(
            validate(r#"{"jsonrpc":"2.0","id":99,"error":{"code":-32601,"message":"not found"}}"#),
            ValidationOutcome::Forward
        );
    }

    #[test]
    fn response_without_id_returns_invalid_request() {
        assert_eq!(
            validate(r#"{"jsonrpc":"2.0","result":{}}"#),
            reject(-32600, Value::Null)
        );
        assert_eq!(
            validate(r#"{"jsonrpc":"2.0","error":{"code":1,"message":"x"}}"#),
            reject(-32600, Value::Null)
        );
    }

    #[test]
    fn both_result_and_error_returns_invalid_request() {
        assert_eq!(
            validate(r#"{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":1,"message":"x"}}"#),
            reject(-32600, json!(1))
        );
    }

    #[test]
    fn malformed_error_body_returns_invalid_request() {
        assert_eq!(
            validate(r#"{"jsonrpc":"2.0","id":1,"error":{"code":"x","message":"y"}}"#),
            reject(-32600, json!(1))
        );
        assert_eq!(
            validate(r#"{"jsonrpc":"2.0","id":1,"error":{"message":"only message"}}"#),
            reject(-32600, json!(1))
        );
        assert_eq!(
            validate(r#"{"jsonrpc":"2.0","id":1,"error":"not even an object"}"#),
            reject(-32600, json!(1))
        );
    }

    #[test]
    fn empty_object_returns_invalid_request() {
        assert_eq!(validate(r"{}"), reject(-32600, Value::Null));
    }

    #[test]
    fn mixed_method_and_result_returns_invalid_request() {
        assert_eq!(
            validate(r#"{"jsonrpc":"2.0","method":"x","id":1,"result":{}}"#),
            reject(-32600, json!(1))
        );
    }
}
