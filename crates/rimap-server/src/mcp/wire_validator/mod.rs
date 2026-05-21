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

mod envelope;
mod inbound;
mod outbound;
mod supervisor;

#[cfg(any(test, feature = "fuzzing"))]
pub(crate) use envelope::{synthesize_error_line, validate};
pub(crate) use inbound::validate_inbound;
pub(crate) use outbound::passthrough_outbound;

/// Bridge-task duplex buffer. Large enough that one well-formed
/// envelope fits in a single write; both directions are independent
/// tasks so inbound stalls cannot cause outbound deadlock.
// cargo-mutants: known-equivalent — `64 * 1024` vs `64 + 1024` is a
// buffer-size constant; no test asserts on the value and both sizes
// are large enough to hold one envelope per write.
pub(crate) const BUF_SIZE: usize = 64 * 1024;

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
///
/// **`JoinHandle` lifecycle.** `watch_for_error` may poll either or
/// both `JoinHandle`s to completion. Once a `JoinHandle` has been
/// polled to completion, re-polling panics (tokio invariant: see
/// `tokio::runtime::task::core` line 422 — "`JoinHandle` polled after
/// completion"). The `_consumed` flags track this so the success-path
/// `drain` and failure-path `shutdown_after_failure` can skip the
/// re-await on already-consumed handles. The skipped result is treated
/// as `Ok(())` per the invariant that `drain` is only called after
/// `watch_for_error` returned `Ok` (both bridges exited cleanly) and
/// `shutdown_after_failure` always aborts before awaiting.
pub struct ValidatorSupervisor {
    pub(crate) inbound: JoinHandle<std::io::Result<()>>,
    pub(crate) outbound: JoinHandle<std::io::Result<()>>,
    pub(crate) inbound_consumed: bool,
    pub(crate) outbound_consumed: bool,
}

/// Build the validated stdio transport. The two bridge tasks are
/// spawned immediately; their lifecycle is exposed via `supervisor`.
/// The returned `transport` plugs into `rmcp::serve_server(server,
/// validated.transport)` and the returned `stdout` is the shared
/// writer that `main.rs::run`'s pre-init error emitter must also
/// lock so all stdout writes (validator rejections, passthrough
/// frames, pre-init envelopes) serialize through a single mutex.
///
/// Drop the returned `transport` ends to signal EOF to rmcp; drop
/// the supervisor (via `drain`/`shutdown_after_failure`) to await
/// the bridge tasks' final exits.
#[must_use]
pub fn stdio_with_validation() -> ValidatedStdio {
    let (inbound_our_end, inbound_rmcp_end) = tokio::io::duplex(BUF_SIZE);
    let (outbound_rmcp_end, outbound_our_end) = tokio::io::duplex(BUF_SIZE);

    let stdout = Arc::new(Mutex::new(tokio::io::stdout()));

    let inbound = tokio::spawn(validate_inbound(
        tokio::io::stdin(),
        inbound_our_end,
        Arc::clone(&stdout),
    ));
    let outbound = tokio::spawn(passthrough_outbound(outbound_our_end, Arc::clone(&stdout)));

    ValidatedStdio {
        transport: (inbound_rmcp_end, outbound_rmcp_end),
        stdout,
        supervisor: ValidatorSupervisor {
            inbound,
            outbound,
            inbound_consumed: false,
            outbound_consumed: false,
        },
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
    use super::envelope::{invalid_request, parse_error};
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
    fn duplicate_top_level_keys_reject() {
        assert_eq!(
            validate(r#"{"jsonrpc":"2.0","id":99,"res":"2.0","id":99,"result":{"x":1}}"#),
            reject(-32600, Value::Null)
        );
    }

    #[test]
    fn duplicate_keys_inside_error_body_reject() {
        assert_eq!(
            validate(r#"{"jsonrpc":"2.0","id":1,"error":{"code":175,"message":75,"message":"x"}}"#),
            reject(-32600, Value::Null)
        );
    }

    #[test]
    fn duplicate_keys_inside_params_still_forwards() {
        assert_eq!(
            validate(r#"{"jsonrpc":"2.0","method":"x","id":1,"params":{"k":1,"k":2}}"#),
            ValidationOutcome::Forward
        );
    }

    #[test]
    fn duplicate_keys_inside_error_data_still_forwards() {
        assert_eq!(
            validate(
                r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"x","data":{"k":1,"k":2}}}"#
            ),
            ValidationOutcome::Forward
        );
    }

    #[test]
    fn typoed_jsonrpc_with_fractional_id_does_not_echo_id() {
        assert_eq!(
            validate(r#"{".sonrpc":"2.0","id":2.5}"#),
            reject(-32600, Value::Null)
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
    fn fractional_id_rejects() {
        assert_eq!(
            validate(r#"{"jsonrpc":"2.0","method":"x","id":1.5}"#),
            reject(-32600, Value::Null)
        );
    }

    #[test]
    fn out_of_i64_range_id_rejects() {
        assert_eq!(
            validate(r#"{"jsonrpc":"2.0","method":"x","id":9223372036854775808}"#),
            reject(-32600, Value::Null)
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
    fn fractional_error_code_rejects() {
        assert_eq!(
            validate(r#"{"jsonrpc":"2.0","id":1,"error":{"code":1.5,"message":"x"}}"#),
            reject(-32600, json!(1))
        );
    }

    #[test]
    fn out_of_i32_range_error_code_rejects() {
        assert_eq!(
            validate(r#"{"jsonrpc":"2.0","id":1,"error":{"code":2147483648,"message":"x"}}"#),
            reject(-32600, json!(1))
        );
    }

    #[test]
    fn params_as_number_rejects() {
        assert_eq!(
            validate(r#"{"jsonrpc":"2.0","method":"tools/list","id":0,"params":0}"#),
            reject(-32600, json!(0))
        );
    }

    #[test]
    fn params_as_string_rejects() {
        assert_eq!(
            validate(r#"{"jsonrpc":"2.0","method":"x","id":1,"params":"foo"}"#),
            reject(-32600, json!(1))
        );
    }

    #[test]
    fn params_as_bool_rejects() {
        assert_eq!(
            validate(r#"{"jsonrpc":"2.0","method":"x","id":1,"params":true}"#),
            reject(-32600, json!(1))
        );
    }

    #[test]
    fn params_as_array_rejects() {
        assert_eq!(
            validate(r#"{"jsonrpc":"2.0","method":"x","id":1,"params":[1,2,3]}"#),
            reject(-32600, json!(1))
        );
    }

    #[test]
    fn params_as_null_forwards() {
        assert_eq!(
            validate(r#"{"jsonrpc":"2.0","method":"x","id":1,"params":null}"#),
            ValidationOutcome::Forward
        );
    }

    #[test]
    fn notification_with_bad_params_rejects() {
        assert_eq!(
            validate(r#"{"jsonrpc":"2.0","method":"notifications/x","params":0}"#),
            reject(-32600, Value::Null)
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
    fn synthesize_invalid_request_with_null_id_omits_id_field() {
        let env = ErrorEnvelope {
            code: -32600,
            message: "Invalid Request",
            id: Value::Null,
        };
        let line = synthesize_error_line(&env);
        assert!(line.ends_with('\n'));
        let parsed: Value = serde_json::from_str(line.trim_end()).unwrap();
        assert_eq!(parsed["jsonrpc"], "2.0");
        let obj = parsed.as_object().unwrap();
        assert!(
            !obj.contains_key("id"),
            "id field MUST be omitted when null; got {parsed}",
        );
        assert_eq!(parsed["error"]["code"], -32600);
        assert_eq!(parsed["error"]["message"], "Invalid Request");
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

    #[tokio::test]
    async fn validate_inbound_non_utf8_returns_parse_error() {
        let stdin = std::io::Cursor::new(vec![0xFF, 0xFE, b'\n']);
        let (our_end, mut rmcp_end) = tokio::io::duplex(BUF_SIZE);
        let stdout = Arc::new(Mutex::new(tokio::io::stdout()));

        let consumer = tokio::spawn(async move {
            let mut buf = Vec::new();
            rmcp_end.read_to_end(&mut buf).await.unwrap();
            buf
        });
        validate_inbound(stdin, our_end, stdout).await.unwrap();
        let forwarded = consumer.await.unwrap();

        assert!(
            forwarded.is_empty(),
            "non-UTF-8 line should not be forwarded to rmcp, got {forwarded:?}"
        );
    }

    #[tokio::test]
    async fn invalid_utf8_inside_valid_json_string_returns_parse_error() {
        let mut line: Vec<u8> = br#"{"jsonrpc":"2.0","id":1,"method":"x","params":{"k":""#.to_vec();
        line.push(0xFF);
        line.extend_from_slice(br#""}}"#);
        line.push(b'\n');

        let stdin = std::io::Cursor::new(line);
        let (our_end, mut rmcp_end) = tokio::io::duplex(BUF_SIZE);
        let stdout = Arc::new(Mutex::new(tokio::io::stdout()));

        let consumer = tokio::spawn(async move {
            let mut buf = Vec::new();
            rmcp_end.read_to_end(&mut buf).await.unwrap();
            buf
        });
        validate_inbound(stdin, our_end, stdout).await.unwrap();
        let forwarded = consumer.await.unwrap();
        assert!(
            forwarded.is_empty(),
            "bad UTF-8 inside JSON string must NOT be forwarded, got {forwarded:?}",
        );
    }

    #[tokio::test]
    async fn passthrough_outbound_drops_on_eof() {
        let (rmcp_end, our_end) = tokio::io::duplex(BUF_SIZE);
        let stdout = Arc::new(Mutex::new(tokio::io::stdout()));

        drop(rmcp_end);
        let result = passthrough_outbound(our_end, stdout).await;
        assert!(result.is_ok(), "expected Ok on EOF, got {result:?}");
    }

    #[tokio::test]
    async fn drain_returns_ok_when_both_bridges_exit_ok() {
        let inbound = tokio::spawn(async { Ok::<(), std::io::Error>(()) });
        let outbound = tokio::spawn(async { Ok::<(), std::io::Error>(()) });
        let supervisor = ValidatorSupervisor {
            inbound,
            outbound,
            inbound_consumed: false,
            outbound_consumed: false,
        };
        assert!(supervisor.drain().await.is_ok());
    }

    #[tokio::test]
    async fn drain_surfaces_first_error() {
        let inbound = tokio::spawn(async {
            Err::<(), std::io::Error>(std::io::Error::other("inbound boom"))
        });
        let outbound = tokio::spawn(async { Ok::<(), std::io::Error>(()) });
        let supervisor = ValidatorSupervisor {
            inbound,
            outbound,
            inbound_consumed: false,
            outbound_consumed: false,
        };
        let r = supervisor.drain().await;
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("inbound boom"));
    }

    #[tokio::test]
    async fn shutdown_after_failure_aborts_inbound() {
        let inbound = tokio::spawn(async { std::future::pending::<std::io::Result<()>>().await });
        let outbound = tokio::spawn(async { Ok::<(), std::io::Error>(()) });
        let supervisor = ValidatorSupervisor {
            inbound,
            outbound,
            inbound_consumed: false,
            outbound_consumed: false,
        };

        let r = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            supervisor.shutdown_after_failure(),
        )
        .await;
        assert!(r.is_ok(), "shutdown_after_failure did not abort inbound");
        assert!(r.unwrap().is_ok());
    }

    #[tokio::test]
    async fn watch_for_error_returns_on_first_error() {
        let inbound = tokio::spawn(async {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            Err::<(), std::io::Error>(std::io::Error::other("inbound failed"))
        });
        let outbound = tokio::spawn(async { std::future::pending::<std::io::Result<()>>().await });
        let mut supervisor = ValidatorSupervisor {
            inbound,
            outbound,
            inbound_consumed: false,
            outbound_consumed: false,
        };

        let r = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            supervisor.watch_for_error(),
        )
        .await;
        assert!(r.is_ok());
        let inner = r.unwrap();
        assert!(inner.is_err());
        assert!(inner.unwrap_err().to_string().contains("inbound failed"));
    }

    #[tokio::test]
    async fn watch_for_error_returns_ok_when_both_bridges_finish() {
        let inbound = tokio::spawn(async { Ok::<(), std::io::Error>(()) });
        let outbound = tokio::spawn(async { Ok::<(), std::io::Error>(()) });
        tokio::task::yield_now().await;
        let mut supervisor = ValidatorSupervisor {
            inbound,
            outbound,
            inbound_consumed: false,
            outbound_consumed: false,
        };
        let r = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            supervisor.watch_for_error(),
        )
        .await
        .expect("watch_for_error must return promptly when both bridges have finished");
        assert!(r.is_ok(), "expected Ok, got {r:?}");
    }

    #[tokio::test]
    async fn stdio_with_validation_constructs_cleanly() {
        let validated = stdio_with_validation();
        drop(validated.transport);
        let r = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            validated.supervisor.drain(),
        )
        .await;
        assert!(r.is_ok(), "drain hung after dropping transport");
    }

    #[test]
    fn error_body_as_primitive_echoes_id() {
        let cases: &[(&str, Value, &str)] = &[
            (
                r#"{"jsonrpc":"2.0","id":1,"error":-175}"#,
                json!(1),
                "visit_i64",
            ),
            (
                r#"{"jsonrpc":"2.0","id":2,"error":18446744073709551615}"#,
                json!(2),
                "visit_u64",
            ),
            (
                r#"{"jsonrpc":"2.0","id":3,"error":1.5}"#,
                json!(3),
                "visit_f64",
            ),
            (
                r#"{"jsonrpc":"2.0","id":4,"error":true}"#,
                json!(4),
                "visit_bool",
            ),
            (
                r#"{"jsonrpc":"2.0","id":5,"error":null}"#,
                json!(5),
                "visit_unit",
            ),
        ];
        for (line, expected_id, label) in cases {
            let outcome = validate(line);
            let ValidationOutcome::Reject(env) = outcome else {
                panic!("{label}: expected Reject, got {outcome:?}");
            };
            assert_eq!(
                env.id, *expected_id,
                "{label}: id MUST echo original (not Null); line={line}",
            );
            assert_eq!(env.code, -32600, "{label}: expected -32600 invalid-request");
        }
    }

    #[tokio::test]
    async fn validate_inbound_strips_crlf_line_ending() {
        let stdin = std::io::Cursor::new(
            b"{\"jsonrpc\":\"2.0\",\"method\":\"tools/list\",\"id\":1}\r\n".to_vec(),
        );
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
        assert!(
            s.contains("\"method\":\"tools/list\""),
            "expected forwarded line, got {s:?}",
        );
    }

    #[tokio::test]
    async fn shutdown_after_failure_surfaces_outbound_error() {
        let inbound = tokio::spawn(async { std::future::pending::<std::io::Result<()>>().await });
        let outbound = tokio::spawn(async {
            Err::<(), std::io::Error>(std::io::Error::other("outbound boom"))
        });
        let supervisor = ValidatorSupervisor {
            inbound,
            outbound,
            inbound_consumed: false,
            outbound_consumed: false,
        };
        let r = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            supervisor.shutdown_after_failure(),
        )
        .await
        .expect("shutdown_after_failure must not hang");
        assert!(r.is_err(), "outbound error must surface");
        assert!(
            r.unwrap_err().to_string().contains("outbound boom"),
            "expected outbound error message",
        );
    }

    #[tokio::test]
    async fn watch_for_error_surfaces_bridge_task_panic() {
        let inbound: JoinHandle<std::io::Result<()>> = tokio::spawn(async move {
            panic!("intentional bridge-task panic for flatten guard test");
        });
        let outbound = tokio::spawn(async { std::future::pending::<std::io::Result<()>>().await });
        let mut supervisor = ValidatorSupervisor {
            inbound,
            outbound,
            inbound_consumed: false,
            outbound_consumed: false,
        };
        let r = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            supervisor.watch_for_error(),
        )
        .await
        .expect("watch_for_error must surface bridge panic promptly");
        assert!(r.is_err(), "panic must surface as Err, got {r:?}");
        assert!(
            r.unwrap_err().to_string().contains("bridge task panic"),
            "expected bridge-panic error message",
        );
    }

    #[tokio::test]
    async fn watch_for_error_treats_cancellation_as_ok() {
        let inbound = tokio::spawn(async { std::future::pending::<std::io::Result<()>>().await });
        inbound.abort();
        let outbound = tokio::spawn(async { Ok::<(), std::io::Error>(()) });
        tokio::task::yield_now().await;
        let mut supervisor = ValidatorSupervisor {
            inbound,
            outbound,
            inbound_consumed: false,
            outbound_consumed: false,
        };
        let r = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            supervisor.watch_for_error(),
        )
        .await
        .expect("watch_for_error must return promptly when bridges finish");
        assert!(
            r.is_ok(),
            "cancelled inbound + Ok outbound must yield Ok, got {r:?}",
        );
    }
}
