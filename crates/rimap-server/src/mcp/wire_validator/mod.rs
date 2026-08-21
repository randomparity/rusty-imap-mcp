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
use std::sync::atomic::AtomicBool;

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
/// lock; `supervisor` exposes the bridge-task lifecycle; and
/// `pre_init_intercepted` reports ADR-0025 interception.
pub struct ValidatedStdio {
    pub transport: (DuplexStream, DuplexStream),
    pub stdout: Arc<Mutex<Stdout>>,
    pub supervisor: ValidatorSupervisor,
    /// Raised by the inbound bridge when it intercepts a pre-init
    /// request (ADR-0025): the -32002 envelope has been written and the
    /// rmcp inbound duplex closed. `serve_mcp` polls this before
    /// interpreting the init race so the interception reads as a clean
    /// exit. Stored strictly before the duplex drop, so it is observable
    /// regardless of which arm of the race resolves first.
    pub pre_init_intercepted: Arc<AtomicBool>,
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
    let initialized = Arc::new(AtomicBool::new(false));
    let pre_init_intercepted = Arc::new(AtomicBool::new(false));

    let inbound = tokio::spawn(validate_inbound(
        tokio::io::stdin(),
        inbound_our_end,
        Arc::clone(&stdout),
        initialized,
        Arc::clone(&pre_init_intercepted),
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
        pre_init_intercepted,
    }
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "tests")]
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
            validate(r#"{"jsonrpc":"2.0","result":{},"id":1}"#),
            ValidationOutcome::Forward
        );
    }

    #[test]
    fn valid_error_forwards() {
        assert_eq!(
            validate(r#"{"jsonrpc":"2.0","error":{"code":-32000,"message":"x"},"id":1}"#),
            ValidationOutcome::Forward
        );
    }

    #[test]
    fn params_without_id_forwards() {
        assert_eq!(
            validate(r#"{"jsonrpc":"2.0","method":"initialize","params":{}}"#),
            ValidationOutcome::Forward
        );
    }

    #[test]
    fn result_without_id_rejects() {
        assert_eq!(
            validate(r#"{"jsonrpc":"2.0","result":{}}"#),
            reject(-32600, Value::Null)
        );
    }

    #[test]
    fn error_without_id_rejects() {
        assert_eq!(
            validate(r#"{"jsonrpc":"2.0","error":{"code":-32000,"message":"x"}}"#),
            reject(-32600, Value::Null)
        );
    }

    #[test]
    fn parse_error_returns_valid_envelope() {
        let env = parse_error();
        let line = synthesize_error_line(&env);
        let parsed: Value = serde_json::from_str(line.trim_end()).expect("valid JSON");
        assert_eq!(parsed["jsonrpc"], "2.0");
        assert_eq!(parsed["error"]["code"], -32700);
        assert_eq!(parsed["error"]["message"], "Parse error");
        assert_eq!(parsed["id"], Value::Null);
    }

    #[test]
    fn invalid_request_returns_valid_envelope() {
        let env = invalid_request(json!(42));
        let line = synthesize_error_line(&env);
        let parsed: Value = serde_json::from_str(line.trim_end()).expect("valid JSON");
        assert_eq!(parsed["jsonrpc"], "2.0");
        assert_eq!(parsed["error"]["code"], -32600);
        assert_eq!(parsed["error"]["message"], "Invalid Request");
        assert_eq!(parsed["id"], json!(42));
    }

    #[test]
    fn envelope_lines_are_newline_terminated() {
        let env = invalid_request(json!(1));
        let line = synthesize_error_line(&env);
        assert!(line.ends_with('\n'), "must be newline-terminated");
    }

    #[test]
    fn envelope_lines_contain_exactly_one_newline() {
        let env = invalid_request(json!(1));
        let line = synthesize_error_line(&env);
        assert_eq!(line.matches('\n').count(), 1, "exactly one newline");
    }
}

#[cfg(test)]
mod tests_integration {
    use super::*;

    #[test]
    fn validate_integration_rejects_malformed_envelope() {
        let malformed = r#"{"jsonrpc":"2.0","id":1,"result":{"x":1},"result":{"y":2}}"#;
        assert!(matches!(validate(malformed), ValidationOutcome::Reject(_)));
    }

    #[test]
    fn validate_integration_forwards_valid_envelope() {
        let valid = r#"{"jsonrpc":"2.0","method":"tools/list","id":1}"#;
        assert_eq!(validate(valid), ValidationOutcome::Forward);
    }

    #[test]
    fn validate_integration_skips_empty_lines() {
        assert_eq!(validate(""), ValidationOutcome::Skip);
        assert_eq!(validate("\n"), ValidationOutcome::Skip);
        assert_eq!(validate("  \t  \r\n"), ValidationOutcome::Skip);
    }
}
