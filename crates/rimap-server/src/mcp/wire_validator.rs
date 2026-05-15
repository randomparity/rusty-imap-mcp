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
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWriteExt, BufReader, DuplexStream, Stdout};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

/// Bridge-task duplex buffer. Large enough that one well-formed
/// envelope fits in a single write; both directions are independent
/// tasks so inbound stalls cannot cause outbound deadlock.
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

/// Serialize a rejection envelope to a single wire line, terminated
/// with `\n`. The shape matches JSON-RPC §5: `{jsonrpc, id, error}`
/// with `error.{code, message}` and no `data`.
pub(crate) fn synthesize_error_line(env: &ErrorEnvelope) -> String {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": env.id,
        "error": {
            "code": env.code,
            "message": env.message,
        },
    });
    // Use to_string (not pretty) so it's exactly one line.
    let mut line = body.to_string();
    line.push('\n');
    line
}

/// Inbound bridge task. Reads from real stdin one line at a time
/// (preserving the trailing `\n`), validates each line, and forwards
/// or rejects.
///
/// Returns `Ok(())` on stdin EOF. Returns `Err(io::Error)` if a write
/// to either the inbound duplex (forwarding) or shared stdout
/// (rejection) fails — `BrokenPipe` on stdout is the most common
/// failure mode and surfaces to `main.rs::run` via the supervisor so
/// `process_end.reason: Error` is recorded.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "consumed by stdio_with_validation entry point in Task 2.4"
    )
)]
pub(crate) async fn validate_inbound<R>(
    stdin: R,
    mut to_rmcp: DuplexStream,
    stdout: Arc<Mutex<Stdout>>,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut reader = BufReader::new(stdin);
    let mut buf = Vec::with_capacity(BUF_SIZE);

    loop {
        buf.clear();
        let n = reader.read_until(b'\n', &mut buf).await?;
        if n == 0 {
            return Ok(()); // stdin EOF — clean shutdown.
        }

        // Strip trailing \n and optional \r for the validation view.
        // rmcp's codec also strips \r; matching its grammar.
        let trimmed: &[u8] = match buf.last() {
            Some(&b'\n') => &buf[..buf.len() - 1],
            _ => &buf[..],
        };
        let trimmed: &[u8] = match trimmed.last() {
            Some(&b'\r') => &trimmed[..trimmed.len() - 1],
            _ => trimmed,
        };
        let line_for_validation = std::str::from_utf8(trimmed).unwrap_or("");

        match validate(line_for_validation) {
            ValidationOutcome::Skip => {}
            ValidationOutcome::Forward => {
                // Forward the buffer including its trailing \n so
                // rmcp's framed reader sees the complete envelope.
                if buf.last() != Some(&b'\n') {
                    buf.push(b'\n');
                }
                to_rmcp.write_all(&buf).await?;
                to_rmcp.flush().await?;
            }
            ValidationOutcome::Reject(env) => {
                let line = synthesize_error_line(&env);
                let mut sout = stdout.lock().await;
                sout.write_all(line.as_bytes()).await?;
                sout.flush().await?;
                // Lock released here; loop continues.
            }
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
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
        assert_eq!(
            validate(r#"{"jsonrpc":"2.0","method":"x","id":true}"#),
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

    #[test]
    fn synthesize_invalid_request_with_null_id() {
        let env = ErrorEnvelope {
            code: -32600,
            message: "Invalid Request",
            id: Value::Null,
        };
        let line = synthesize_error_line(&env);
        assert!(line.ends_with('\n'));
        let parsed: Value = serde_json::from_str(line.trim_end()).unwrap();
        assert_eq!(parsed["jsonrpc"], "2.0");
        assert_eq!(parsed["id"], Value::Null);
        assert_eq!(parsed["error"]["code"], -32600);
        assert_eq!(parsed["error"]["message"], "Invalid Request");
        // No data field.
        assert!(parsed["error"].get("data").is_none());
    }

    #[test]
    fn synthesize_parse_error_has_correct_code() {
        let line = synthesize_error_line(&parse_error());
        let parsed: Value = serde_json::from_str(line.trim_end()).unwrap();
        assert_eq!(parsed["error"]["code"], -32700);
        assert_eq!(parsed["error"]["message"], "Parse error");
    }

    #[test]
    fn synthesize_echoes_numeric_id() {
        let env = invalid_request(json!(42));
        let line = synthesize_error_line(&env);
        let parsed: Value = serde_json::from_str(line.trim_end()).unwrap();
        assert_eq!(parsed["id"], 42);
    }

    #[test]
    fn synthesize_echoes_string_id() {
        let env = invalid_request(json!("abc"));
        let line = synthesize_error_line(&env);
        let parsed: Value = serde_json::from_str(line.trim_end()).unwrap();
        assert_eq!(parsed["id"], "abc");
    }

    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn validate_inbound_forwards_valid_envelope() {
        let stdin = std::io::Cursor::new(
            b"{\"jsonrpc\":\"2.0\",\"method\":\"tools/list\",\"id\":1}\n".to_vec(),
        );
        let (our_end, mut rmcp_end) = tokio::io::duplex(BUF_SIZE);
        let stdout = Arc::new(Mutex::new(tokio::io::stdout()));

        // Spawn the validator and consume rmcp's side concurrently.
        let consumer = tokio::spawn(async move {
            let mut buf = Vec::new();
            rmcp_end.read_to_end(&mut buf).await.unwrap();
            buf
        });
        validate_inbound(stdin, our_end, stdout).await.unwrap();
        let forwarded = consumer.await.unwrap();

        let s = std::str::from_utf8(&forwarded).unwrap();
        assert!(
            s.contains("\"method\":\"tools/list\""),
            "expected forwarded line, got {s:?}",
        );
        assert!(s.ends_with('\n'));
    }

    #[tokio::test]
    async fn validate_inbound_skips_empty_lines() {
        let stdin =
            std::io::Cursor::new(b"\n\n{\"jsonrpc\":\"2.0\",\"method\":\"x\",\"id\":1}\n".to_vec());
        let (our_end, mut rmcp_end) = tokio::io::duplex(BUF_SIZE);
        let stdout = Arc::new(Mutex::new(tokio::io::stdout()));

        let consumer = tokio::spawn(async move {
            let mut buf = Vec::new();
            rmcp_end.read_to_end(&mut buf).await.unwrap();
            buf
        });
        validate_inbound(stdin, our_end, stdout).await.unwrap();
        let forwarded = consumer.await.unwrap();

        let s = std::str::from_utf8(&forwarded).unwrap();
        assert_eq!(s.lines().count(), 1);
    }
}
