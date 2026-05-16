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
///
/// **`id` is omitted when null**, not emitted as `"id": null`. MCP's
/// `RequestId` schema (`integer | string`) disallows null, so emitting
/// `null` would make the envelope fail the MCP schema validator the
/// test harness applies via `assert_envelope_valid`. JSON-RPC 2.0 §5
/// requires `id: null` for parse / invalid-request errors, but MCP's
/// `JSONRPCErrorResponse` schema marks `id` as OPTIONAL — so omitting
/// it satisfies both the MCP contract (the protocol we serve) and
/// the JSON-RPC §5 intent of "no recoverable id available."
pub(crate) fn synthesize_error_line(env: &ErrorEnvelope) -> String {
    let body = if env.id.is_null() {
        serde_json::json!({
            "jsonrpc": "2.0",
            "error": {
                "code": env.code,
                "message": env.message,
            },
        })
    } else {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": env.id,
            "error": {
                "code": env.code,
                "message": env.message,
            },
        })
    };
    // Use to_string (not pretty) so it's exactly one line.
    let mut line = body.to_string();
    line.push('\n');
    line
}

/// Inbound bridge task. Reads from real stdin one line at a time
/// (preserving the trailing `\n`), validates each line, and forwards
/// or rejects.
///
/// # Cancellation
///
/// This function is intended to be `tokio::spawn`'d and managed by
/// `ValidatorSupervisor`. If `JoinHandle::abort()` lands between
/// `write_all` and `flush` on the rejection path, a partial line
/// may reach real stdout — breaking the stdout serialization
/// invariant. The supervisor's `shutdown_after_failure` (Task 2.3)
/// uses abort only on failure paths where stdout integrity is
/// already lost (e.g. `BrokenPipe`). Cooperative cancellation via
/// `tokio_util::sync::CancellationToken` could close this gap if
/// stronger guarantees become necessary; deferred per Task 2.3
/// design.
///
/// Returns `Ok(())` on stdin EOF. Returns `Err(io::Error)` if a write
/// to either the inbound duplex (forwarding) or shared stdout
/// (rejection) fails — `BrokenPipe` on stdout is the most common
/// failure mode and surfaces to `main.rs::run` via the supervisor so
/// `process_end.reason: Error` is recorded.
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
        let line_for_validation = String::from_utf8_lossy(trimmed);

        match validate(&line_for_validation) {
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

/// Outbound bridge task. Reads newline-framed frames from rmcp's
/// outbound duplex (rmcp's `FramedWrite` terminates each envelope
/// with `\n`) and writes each frame through the shared stdout mutex.
///
/// Returns `Ok(())` when rmcp drops its outbound duplex end (EOF).
/// Returns `Err(io::Error)` if writing to real stdout fails —
/// typically `BrokenPipe`, which surfaces to `main.rs::run` via the
/// supervisor so `process_end.reason: Error` is recorded.
///
/// # Cancellation
///
/// Same caveat as `validate_inbound`: an abort between `write_all`
/// and `flush` may leave a partial frame on stdout. The supervisor's
/// `shutdown_after_failure` (Task 2.3) uses abort only on failure
/// paths where stdout integrity is already suspect.
pub(crate) async fn passthrough_outbound(
    from_rmcp: DuplexStream,
    stdout: Arc<Mutex<Stdout>>,
) -> std::io::Result<()> {
    let mut reader = BufReader::new(from_rmcp);
    let mut buf = Vec::with_capacity(BUF_SIZE);

    loop {
        buf.clear();
        let n = reader.read_until(b'\n', &mut buf).await?;
        if n == 0 {
            return Ok(()); // rmcp dropped outbound — clean shutdown.
        }
        let mut sout = stdout.lock().await;
        sout.write_all(&buf).await?;
        sout.flush().await?;
        // Lock released; loop.
    }
}

impl ValidatorSupervisor {
    /// Polls each bridge `JoinHandle` in turn. Resolves with the
    /// first bridge-task error encountered, OR `Ok(())` once both
    /// bridges exit `Ok` cleanly (exotic mid-service condition —
    /// usually one side stays alive until the service ends). Used for
    /// fail-fast during the `service.waiting()` / `serve_server` race
    /// in `main.rs::run`.
    ///
    /// **Side effect.** When an arm fires, the corresponding
    /// `JoinHandle` has been polled to completion and its value
    /// consumed; the `*_consumed` flag is set so the success-path
    /// `drain` and failure-path `shutdown_after_failure` skip the
    /// already-polled handle (tokio panics on re-poll of a completed
    /// `JoinHandle`). The skipped result is treated as `Ok(())` per
    /// the invariant that this method only returns `Ok` when both
    /// bridges exited `Ok` (the `Err` arms return early and `drain`
    /// is not called on the error path).
    pub async fn watch_for_error(&mut self) -> std::io::Result<()> {
        loop {
            tokio::select! {
                biased;
                r = &mut self.inbound, if !self.inbound_consumed => {
                    self.inbound_consumed = true;
                    match Self::flatten(r) {
                        Ok(()) if self.outbound_consumed => return Ok(()),
                        Ok(()) => {}
                        Err(e) => return Err(e),
                    }
                }
                r = &mut self.outbound, if !self.outbound_consumed => {
                    self.outbound_consumed = true;
                    match Self::flatten(r) {
                        Ok(()) if self.inbound_consumed => return Ok(()),
                        Ok(()) => {}
                        Err(e) => return Err(e),
                    }
                }
                else => return Ok(()),
            }
        }
    }

    /// Success-path shutdown. Awaits both bridge tasks; returns the
    /// first error encountered, else `Ok(())`. Use when
    /// `service.waiting()` resolved `Ok` (which implies rmcp saw EOF
    /// on its read, which implies inbound already exited — drain is
    /// then essentially instant on inbound and bounded on outbound).
    ///
    /// **Do not call on failure paths** — the inbound bridge only
    /// exits on real stdin EOF, but a client may legitimately keep
    /// stdin open while waiting for the error response, causing this
    /// to hang. Use `shutdown_after_failure` instead.
    ///
    /// **Already-consumed handles are skipped.** If `watch_for_error`
    /// previously polled a `JoinHandle` to completion, its `_consumed`
    /// flag is set and the await is skipped (re-polling panics).
    /// The invariant guarantees the skipped result was `Ok`.
    pub async fn drain(mut self) -> std::io::Result<()> {
        let in_r = Self::take_or_await(&mut self.inbound, &mut self.inbound_consumed).await;
        let out_r = Self::take_or_await(&mut self.outbound, &mut self.outbound_consumed).await;
        in_r.and(out_r)
    }

    /// Failure-path shutdown. Aborts the inbound bridge (the client
    /// may keep stdin open while waiting for an error response;
    /// without abort, we'd block forever in `read_until` on real
    /// stdin), then awaits the outbound bridge to drain rmcp's
    /// queued error envelope plus any validator-synthesized
    /// rejections. Returns the first error from the outbound path;
    /// inbound cancellation is expected and ignored.
    ///
    /// Used on EVERY failure path — pre-init `ExpectedInitializeRequest`,
    /// `InitializeFailed`, post-init bridge race error, and post-init
    /// `service.waiting()` error.
    ///
    /// **Already-consumed handles are skipped.** Same contract as
    /// `drain` — re-polling a completed `JoinHandle` panics, so the
    /// `_consumed` flags gate the awaits.
    pub async fn shutdown_after_failure(mut self) -> std::io::Result<()> {
        // `abort` is always safe (no-op on a finished task); it does
        // not poll the `JoinHandle` so the consumed flag is irrelevant.
        self.inbound.abort();
        // Either it raced to EOF (Ok), got aborted (JoinError), or
        // was already consumed by `watch_for_error`. We don't care
        // about the inbound result on this path — the outbound may
        // still have queued frames to flush.
        let _ = Self::take_or_await(&mut self.inbound, &mut self.inbound_consumed).await;
        Self::take_or_await(&mut self.outbound, &mut self.outbound_consumed).await
    }

    /// Await `handle` if its `consumed` flag is `false`, then mark it
    /// consumed. Returns `Ok(())` if already consumed — guarded by
    /// the invariant documented on `drain` and `shutdown_after_failure`.
    async fn take_or_await(
        handle: &mut JoinHandle<std::io::Result<()>>,
        consumed: &mut bool,
    ) -> std::io::Result<()> {
        if *consumed {
            return Ok(());
        }
        *consumed = true;
        Self::flatten(handle.await)
    }

    fn flatten(r: Result<std::io::Result<()>, tokio::task::JoinError>) -> std::io::Result<()> {
        match r {
            Ok(inner) => inner,
            Err(je) if je.is_cancelled() => Ok(()),
            Err(je) => Err(std::io::Error::other(format!("bridge task panic: {je}"))),
        }
    }
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
#[expect(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
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
    fn synthesize_invalid_request_with_null_id_omits_id_field() {
        // Pins the MCP-schema accommodation: when the original request
        // had no recoverable id, the synthesizer OMITS `id` rather than
        // emitting `"id": null`. MCP's `JSONRPCErrorResponse` schema
        // marks `id` optional but its type is `integer | string` —
        // emitting null would fail `assert_envelope_valid` and break
        // the negative-path wire tests (e.g.
        // `valid_json_invalid_envelope_returns_minus_32600`).
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

    #[tokio::test]
    async fn validate_inbound_non_utf8_returns_parse_error() {
        // Pass invalid UTF-8 bytes (\xFF is not valid UTF-8) followed
        // by EOF. The validator should see lossy-decoded U+FFFD which
        // serde_json rejects → validator emits -32700 to stdout (not
        // observable from the test) AND does not forward to rmcp.
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

        // Nothing reaches rmcp (the invalid-UTF-8 line was rejected
        // and the rejection went to stdout, not the duplex).
        assert!(
            forwarded.is_empty(),
            "non-UTF-8 line should not be forwarded to rmcp, got {forwarded:?}"
        );
    }

    #[tokio::test]
    async fn passthrough_outbound_drops_on_eof() {
        let (rmcp_end, our_end) = tokio::io::duplex(BUF_SIZE);
        let stdout = Arc::new(Mutex::new(tokio::io::stdout()));

        // Drop the rmcp side immediately — passthrough should see EOF
        // and return Ok cleanly.
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
        // Inbound never completes on its own — simulates a client
        // holding stdin open.
        let inbound = tokio::spawn(async { std::future::pending::<std::io::Result<()>>().await });
        let outbound = tokio::spawn(async { Ok::<(), std::io::Error>(()) });
        let supervisor = ValidatorSupervisor {
            inbound,
            outbound,
            inbound_consumed: false,
            outbound_consumed: false,
        };

        // Should return promptly (within a few ms) thanks to abort.
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
        // Both bridges exit Ok cleanly. watch_for_error must return
        // Ok(()) without panicking, even if both `is_finished()`
        // guards evaluate to false in the same select! iteration.
        let inbound = tokio::spawn(async { Ok::<(), std::io::Error>(()) });
        let outbound = tokio::spawn(async { Ok::<(), std::io::Error>(()) });
        // Give the runtime a tick so both handles transition to finished.
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
        // Verify the supervisor is present and we can drop everything.
        drop(validated.transport);
        // After dropping the duplex ends, both bridges should exit cleanly
        // (stdin EOF or read 0 bytes from a dropped duplex).
        let r = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            validated.supervisor.drain(),
        )
        .await;
        // Either Ok (drained cleanly) OR Err (stdin returned an error
        // on the test runner) is acceptable — we mainly want to confirm
        // no panic and no hang.
        assert!(r.is_ok(), "drain hung after dropping transport");
    }
}
