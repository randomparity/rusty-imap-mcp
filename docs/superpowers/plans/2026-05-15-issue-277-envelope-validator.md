# JSON-RPC Envelope Validator Implementation Plan (#277)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wrap rmcp's stdio transport with a JSON-RPC 2.0 envelope validator that rejects malformed envelopes with `-32600` / `-32700` instead of letting rmcp's `try_parse_with_compatibility` silently drop them. Un-ignore `prop_envelope_never_panics`. Add a bridge-task supervisor with two-phase shutdown so write failures surface to `process_end.reason: Error` on every failure path.

**Architecture:** A new `mcp/wire_validator.rs` module owns: a pure `validate()` function recognizing all four JSON-RPC envelope shapes (Request, Notification, Response, Error); two async bridge tasks (`validate_inbound`, `passthrough_outbound`) that sandwich rmcp's transport via `tokio::io::duplex`; a `ValidatorSupervisor` with `watch_for_error` / `drain` / `shutdown_after_failure`; a `stdio_with_validation()` entry point returning `ValidatedStdio { transport, stdout, supervisor }`. `main.rs::run` races both init and post-init against the supervisor (`tokio::select! { biased; ... }`) and uses `shutdown_after_failure` on every error path so clients holding stdin open don't cause shutdown to hang.

**Tech Stack:** Rust (workspace MSRV 1.88.0), tokio (`io::duplex`, `select!`, async Mutex, `JoinHandle::abort()`), rmcp 1.5 (`IntoTransport<RoleServer, _, _>` over a `(DuplexStream, DuplexStream)` pair), serde_json, anyhow, tracing. Wire-level integration tests use the `Harness` from `crates/rimap-server/tests/support/wire/`.

**Spec:** [`docs/superpowers/specs/2026-05-15-issue-277-envelope-validator-design.md`](../specs/2026-05-15-issue-277-envelope-validator-design.md)

---

## File Structure

**Create:**
- `crates/rimap-server/src/mcp/wire_validator.rs` — validator module + `ValidatedStdio` / `ValidatorSupervisor` types + unit tests

**Modify:**
- `crates/rimap-server/src/mcp/mod.rs` — `pub mod wire_validator;`
- `crates/rimap-server/src/main.rs` — transport swap, `emit_pre_init_error_envelope` signature thread-through, init-phase race, post-init two-phase shutdown
- `crates/rimap-server/tests/support/wire/harness.rs` — new closed-stdout-with-open-stdin harness variant
- `crates/rimap-server/tests/mcp_wire_negative.rs` — 25 new wire-pinned tests
- `crates/rimap-server/tests/mcp_wire_proptest.rs` — `prop_filter` on `arb_envelope`, un-ignore `prop_envelope_never_panics`

---

## Task 0: Pre-flight — sanity-check the working tree

**Files:** none (verification only)

**Context:** The branch is `feature/issue-266-mcp-fuzzing`. The #275 and #276 fixes have already merged here. The harness (`tests/support/wire/harness.rs`) is present with the closed-stdout variants added for #275. The pinned ignored test `prop_envelope_never_panics` is at `tests/mcp_wire_proptest.rs:311`. This task confirms the tree shape before any changes.

- [ ] **Step 1: Confirm branch and tree are clean**

Run:
```bash
git rev-parse --abbrev-ref HEAD && git status --short
```

Expected: `feature/issue-266-mcp-fuzzing` on the first line; empty `git status` on the second. If not on this branch, halt — the plan assumes #275 and #276 are merged into the current HEAD.

- [ ] **Step 2: Confirm the prop test we will un-ignore is present and ignored**

Run:
```bash
rg -n 'prop_envelope_never_panics|blocked on #277' crates/rimap-server/tests/mcp_wire_proptest.rs
```

Expected: a match showing `#[ignore = "blocked on #277: server hangs on unknown-method envelopes missing jsonrpc/id fields; re-enable once rmcp responds or closes cleanly"]` above an `fn prop_envelope_never_panics(...)`. If the line is absent or already un-ignored, halt.

- [ ] **Step 3: Confirm the closed-stdout harness variant from #275 is present**

Run:
```bash
rg -n 'spawn_with_closed_stdout|DetachedStdoutHarness' crates/rimap-server/tests/support/wire/harness.rs
```

Expected: at least two matches. This variant gets reused for tests 12-14 of this plan, and a new sibling variant gets added in Task 4.1.

- [ ] **Step 4: Confirm the workspace builds clean before changes**

Run:
```bash
cargo check --workspace --all-targets --locked
```

Expected: clean exit, no errors.

- [ ] **Step 5: No commit. Move to Task 1.1.**

---

## Task 1.1: Create `wire_validator.rs` skeleton with types

**Files:**
- Create: `crates/rimap-server/src/mcp/wire_validator.rs`
- Modify: `crates/rimap-server/src/mcp/mod.rs`

This task creates the module file with the core data types and stubs for the public surface. No implementations yet; later tasks fill them in. Compiling this task confirms the module declaration and type signatures are correct before TDD on `validate()` begins.

- [ ] **Step 1: Create the module file with type stubs**

Create `crates/rimap-server/src/mcp/wire_validator.rs`:

```rust
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
pub struct ValidatorSupervisor {
    pub(crate) inbound: JoinHandle<std::io::Result<()>>,
    pub(crate) outbound: JoinHandle<std::io::Result<()>>,
}
```

- [ ] **Step 2: Register the module**

Open `crates/rimap-server/src/mcp/mod.rs` and add the line `pub mod wire_validator;` alongside the other `pub mod` declarations. Place it alphabetically (after `tool_catalog` if present, before `server` if not — verify by reading the file first):

```bash
cat crates/rimap-server/src/mcp/mod.rs
```

Make the addition with `Edit` so the alphabetical ordering is preserved.

- [ ] **Step 3: Verify the workspace still compiles**

Run:
```bash
cargo check --workspace --all-targets --locked
```

Expected: clean. The new types are pub(crate) or pub but unused; cargo will not warn at this stage because unused items in lib crates flow through to bin without warning unless `-W dead_code` is set.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-server/src/mcp/wire_validator.rs crates/rimap-server/src/mcp/mod.rs
git commit -m "feat(rimap-server): wire_validator module skeleton + types (#277)"
```

---

## Task 1.2: Implement `validate()` with unit tests

**Files:**
- Modify: `crates/rimap-server/src/mcp/wire_validator.rs`

This is the heart of the validator. Pure function, no I/O — every JSON-RPC 2.0 shape check goes here. The spec defines the decision logic in detail (see `### validate() decision logic` section). Write the unit tests first; the implementation is mechanical once the test cases are in place.

- [ ] **Step 1: Add the unit-test scaffold**

Append to `crates/rimap-server/src/mcp/wire_validator.rs`:

```rust
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
    let obj = match parsed.as_object() {
        Some(o) => o,
        None => return ValidationOutcome::Reject(invalid_request(Value::Null)),
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
        // Non-string method
        (Some(_), None, None) => {
            ValidationOutcome::Reject(invalid_request(extract_id(obj)))
        }
        // Response: id+result, no method, no error
        (None, Some(_), None) if id_present_and_valid => ValidationOutcome::Forward,
        // Error response: id+error, no method, no result, error well-formed
        (None, None, Some(err)) if id_present_and_valid && is_well_formed_error(err) => {
            ValidationOutcome::Forward
        }
        // Catch-all: empty object, response/error without id, malformed error,
        // both result+error, method mixed with result/error.
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
            message: if code == -32700 { "Parse error" } else { "Invalid Request" },
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
        // error must be object with numeric code + string message
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
        assert_eq!(validate(r#"{}"#), reject(-32600, Value::Null));
    }

    #[test]
    fn mixed_method_and_result_returns_invalid_request() {
        assert_eq!(
            validate(r#"{"jsonrpc":"2.0","method":"x","id":1,"result":{}}"#),
            reject(-32600, json!(1))
        );
    }
}
```

- [ ] **Step 2: Run the unit tests**

Run:
```bash
cargo nextest run -p rimap-server --lib wire_validator
```

Expected: all 16 tests in `mcp::wire_validator::tests` PASS. The lib already has many unrelated tests; the `--lib wire_validator` filter narrows the run.

If anything fails, the implementation has a logic error — re-check the match arms against the spec's "Validation rules" table.

- [ ] **Step 3: Run clippy on the new module**

Run:
```bash
cargo clippy -p rimap-server --lib --all-targets --locked -- -D warnings
```

Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-server/src/mcp/wire_validator.rs
git commit -m "feat(rimap-server): pure JSON-RPC envelope validator (#277)"
```

---

## Task 1.3: Synthesize error envelope as a wire string

**Files:**
- Modify: `crates/rimap-server/src/mcp/wire_validator.rs`

The `ErrorEnvelope` value type from Task 1.1 carries the structured rejection. This task adds a helper that serializes it to the exact JSON-RPC wire shape (single line, terminating `\n`, flushed). The async tasks in Phase 2 use this helper when writing rejections.

- [ ] **Step 1: Add the helper and its tests**

Append to `crates/rimap-server/src/mcp/wire_validator.rs`, BEFORE the `#[cfg(test)] mod tests` block:

```rust
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
```

Add corresponding tests inside the existing `#[cfg(test)] mod tests` block:

```rust
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
```

- [ ] **Step 2: Run the new tests**

```bash
cargo nextest run -p rimap-server --lib wire_validator
```

Expected: all tests (16 from Task 1.2 + 4 new) PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/rimap-server/src/mcp/wire_validator.rs
git commit -m "feat(rimap-server): synthesize_error_line wire serializer (#277)"
```

---

## Task 2.1: Implement `validate_inbound` bridge task

**Files:**
- Modify: `crates/rimap-server/src/mcp/wire_validator.rs`

The inbound bridge reads lines from real stdin, runs `validate()`, and either forwards the line byte-for-byte to its duplex end or synthesizes a rejection through the shared stdout mutex. Reading uses `AsyncBufReadExt::read_until(b'\n', ...)` so the trailing newline is preserved verbatim (matches rmcp's framing).

- [ ] **Step 1: Add the function**

Append to `crates/rimap-server/src/mcp/wire_validator.rs` (after `synthesize_error_line`, before the test module):

```rust
use tokio::io::{AsyncRead, AsyncReadExt, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};

/// Inbound bridge task. Reads from real stdin one line at a time
/// (preserving the trailing `\n`), validates each line, and forwards
/// or rejects.
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
        let line_for_validation = std::str::from_utf8(trimmed).unwrap_or("");

        match validate(line_for_validation) {
            ValidationOutcome::Skip => continue,
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
```

Note: the `use` statements may already exist higher in the file (`AsyncRead`, etc.). Consolidate so each item is imported exactly once.

- [ ] **Step 2: Add a unit test**

Inside the existing `#[cfg(test)] mod tests` block, add:

```rust
    use tokio::io::AsyncReadExt as _;

    #[tokio::test]
    async fn validate_inbound_forwards_valid_envelope() {
        let stdin = std::io::Cursor::new(b"{\"jsonrpc\":\"2.0\",\"method\":\"tools/list\",\"id\":1}\n".to_vec());
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
        assert!(s.contains("\"method\":\"tools/list\""), "expected forwarded line, got {s:?}");
        assert!(s.ends_with('\n'));
    }

    #[tokio::test]
    async fn validate_inbound_skips_empty_lines() {
        let stdin = std::io::Cursor::new(b"\n\n{\"jsonrpc\":\"2.0\",\"method\":\"x\",\"id\":1}\n".to_vec());
        let (our_end, mut rmcp_end) = tokio::io::duplex(BUF_SIZE);
        let stdout = Arc::new(Mutex::new(tokio::io::stdout()));

        let consumer = tokio::spawn(async move {
            let mut buf = Vec::new();
            rmcp_end.read_to_end(&mut buf).await.unwrap();
            buf
        });
        validate_inbound(stdin, our_end, stdout).await.unwrap();
        let forwarded = consumer.await.unwrap();

        // Only the third (valid) line should reach rmcp.
        let s = std::str::from_utf8(&forwarded).unwrap();
        assert_eq!(s.lines().count(), 1);
    }
```

Reject-path testing uses real stdout, which is not capturable in a unit test — defer to the integration tests in Phase 5.

- [ ] **Step 3: Run the new tests**

```bash
cargo nextest run -p rimap-server --lib wire_validator
```

Expected: all tests pass (Task 1.2 + 1.3 + 2 new = 22).

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-server/src/mcp/wire_validator.rs
git commit -m "feat(rimap-server): validate_inbound bridge task (#277)"
```

---

## Task 2.2: Implement `passthrough_outbound` bridge task

**Files:**
- Modify: `crates/rimap-server/src/mcp/wire_validator.rs`

The outbound bridge reads complete frames from rmcp's duplex (line-framed because rmcp's framed writer terminates each envelope with `\n`) and writes each frame through the shared stdout mutex. Line-framed rather than `tokio::io::copy` so the lock is acquired per envelope, never held across an await on rmcp's writer.

- [ ] **Step 1: Add the function**

Append to `crates/rimap-server/src/mcp/wire_validator.rs`:

```rust
/// Outbound bridge task. Reads frames from the outbound duplex
/// (rmcp's writes land here) and writes each frame through the
/// shared stdout mutex.
///
/// Returns `Ok(())` when rmcp drops its outbound duplex end (EOF).
/// Returns `Err(io::Error)` if writing to real stdout fails — typically
/// `BrokenPipe`, which surfaces to `main.rs::run` via the supervisor.
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
```

- [ ] **Step 2: Add a unit test**

Append inside the existing `#[cfg(test)] mod tests`:

```rust
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
```

A "writes are actually forwarded" test would need to redirect real stdout; defer to integration.

- [ ] **Step 3: Run tests**

```bash
cargo nextest run -p rimap-server --lib wire_validator
```

Expected: pass.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-server/src/mcp/wire_validator.rs
git commit -m "feat(rimap-server): passthrough_outbound bridge task (#277)"
```

---

## Task 2.3: Implement `ValidatorSupervisor` with three methods

**Files:**
- Modify: `crates/rimap-server/src/mcp/wire_validator.rs`

The supervisor owns the two `JoinHandle`s and exposes three lifecycle methods: `watch_for_error` (non-consuming, fail-fast during racing), `drain` (consuming, success-path post-init shutdown), and `shutdown_after_failure` (consuming, failure-path shutdown that aborts inbound first).

- [ ] **Step 1: Implement the methods**

Append to `crates/rimap-server/src/mcp/wire_validator.rs`:

```rust
impl ValidatorSupervisor {
    /// Non-consuming. Resolves with the first bridge-task error
    /// encountered, OR `Ok(())` once both bridges exit `Ok` cleanly
    /// (exotic mid-service condition — usually one side stays alive
    /// until the service ends). Used for fail-fast during the
    /// `service.waiting()` / `serve_server` race.
    pub async fn watch_for_error(&mut self) -> std::io::Result<()> {
        loop {
            tokio::select! {
                biased;
                r = &mut self.inbound, if !self.inbound.is_finished() => {
                    match Self::flatten(r) {
                        Ok(()) if self.outbound.is_finished() => return Ok(()),
                        Ok(()) => continue,
                        Err(e) => return Err(e),
                    }
                }
                r = &mut self.outbound, if !self.outbound.is_finished() => {
                    match Self::flatten(r) {
                        Ok(()) if self.inbound.is_finished() => return Ok(()),
                        Ok(()) => continue,
                        Err(e) => return Err(e),
                    }
                }
            }
        }
    }

    /// Success-path shutdown. Awaits both bridge tasks; returns the
    /// first error encountered, else `Ok(())`. Use when
    /// `service.waiting()` resolved `Ok` (which implies rmcp saw EOF
    /// on its read, which implies inbound already exited — drain is
    /// then essentially instant on inbound and bounded on outbound).
    pub async fn drain(self) -> std::io::Result<()> {
        let (in_r, out_r) = tokio::join!(self.inbound, self.outbound);
        let in_r = Self::flatten(in_r);
        let out_r = Self::flatten(out_r);
        in_r.and(out_r)
    }

    /// Failure-path shutdown. Aborts the inbound bridge (the client
    /// may keep stdin open while waiting for an error response;
    /// without abort, we'd block forever in `read_until` on real
    /// stdin), then awaits the outbound bridge to drain rmcp's
    /// queued error envelope plus any validator-synthesized
    /// rejections. Returns the first error from the outbound path;
    /// inbound cancellation is expected and ignored.
    pub async fn shutdown_after_failure(self) -> std::io::Result<()> {
        self.inbound.abort();
        // We don't care about the inbound result on this path —
        // either it raced to EOF (Ok) or got aborted (JoinError).
        let _ = self.inbound.await;
        Self::flatten(self.outbound.await)
    }

    fn flatten(
        r: Result<std::io::Result<()>, tokio::task::JoinError>,
    ) -> std::io::Result<()> {
        match r {
            Ok(inner) => inner,
            Err(je) if je.is_cancelled() => Ok(()),
            Err(je) => Err(std::io::Error::other(format!("bridge task panic: {je}"))),
        }
    }
}
```

- [ ] **Step 2: Add unit tests**

Append inside `#[cfg(test)] mod tests`:

```rust
    #[tokio::test]
    async fn drain_returns_ok_when_both_bridges_exit_ok() {
        let inbound = tokio::spawn(async { Ok::<(), std::io::Error>(()) });
        let outbound = tokio::spawn(async { Ok::<(), std::io::Error>(()) });
        let supervisor = ValidatorSupervisor { inbound, outbound };
        assert!(supervisor.drain().await.is_ok());
    }

    #[tokio::test]
    async fn drain_surfaces_first_error() {
        let inbound = tokio::spawn(async {
            Err::<(), std::io::Error>(std::io::Error::other("inbound boom"))
        });
        let outbound = tokio::spawn(async { Ok::<(), std::io::Error>(()) });
        let supervisor = ValidatorSupervisor { inbound, outbound };
        let r = supervisor.drain().await;
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("inbound boom"));
    }

    #[tokio::test]
    async fn shutdown_after_failure_aborts_inbound() {
        // Inbound never completes on its own — simulates a client
        // holding stdin open.
        let inbound = tokio::spawn(async {
            std::future::pending::<std::io::Result<()>>().await
        });
        let outbound = tokio::spawn(async { Ok::<(), std::io::Error>(()) });
        let supervisor = ValidatorSupervisor { inbound, outbound };

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
        let outbound = tokio::spawn(async {
            std::future::pending::<std::io::Result<()>>().await
        });
        let mut supervisor = ValidatorSupervisor { inbound, outbound };

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
```

- [ ] **Step 3: Run tests**

```bash
cargo nextest run -p rimap-server --lib wire_validator
```

Expected: all pass.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-server/src/mcp/wire_validator.rs
git commit -m "feat(rimap-server): ValidatorSupervisor lifecycle (#277)"
```

---

## Task 2.4: Implement `stdio_with_validation()` entry point

**Files:**
- Modify: `crates/rimap-server/src/mcp/wire_validator.rs`

Wire the pieces together. This is the public entry point `main.rs` calls.

- [ ] **Step 1: Add the function**

Append to `crates/rimap-server/src/mcp/wire_validator.rs`:

```rust
/// Build the validated stdio transport. The two bridge tasks are
/// spawned immediately; their lifecycle is exposed via `supervisor`.
/// The returned `transport` plugs into `rmcp::serve_server(server, transport)`.
pub fn stdio_with_validation() -> ValidatedStdio {
    let (inbound_our_end, inbound_rmcp_end) = tokio::io::duplex(BUF_SIZE);
    let (outbound_rmcp_end, outbound_our_end) = tokio::io::duplex(BUF_SIZE);

    let stdout = Arc::new(Mutex::new(tokio::io::stdout()));

    let inbound = tokio::spawn(validate_inbound(
        tokio::io::stdin(),
        inbound_our_end,
        Arc::clone(&stdout),
    ));
    let outbound = tokio::spawn(passthrough_outbound(
        outbound_our_end,
        Arc::clone(&stdout),
    ));

    ValidatedStdio {
        transport: (inbound_rmcp_end, outbound_rmcp_end),
        stdout,
        supervisor: ValidatorSupervisor { inbound, outbound },
    }
}
```

- [ ] **Step 2: Smoke-test that it constructs**

Add inside `#[cfg(test)] mod tests`:

```rust
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
```

- [ ] **Step 3: Run tests**

```bash
cargo nextest run -p rimap-server --lib wire_validator
```

Expected: pass.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-server/src/mcp/wire_validator.rs
git commit -m "feat(rimap-server): stdio_with_validation entry point (#277)"
```

---

## Task 3.1: Thread `Arc<Mutex<Stdout>>` into `emit_pre_init_error_envelope`

**Files:**
- Modify: `crates/rimap-server/src/main.rs`

`emit_pre_init_error_envelope` currently writes directly to `tokio::io::stdout()` (`main.rs:199-211`). After the transport swap in Task 3.2, that would race the bridge tasks. Thread the shared mutex through the signature so pre-init envelopes lock the same writer.

- [ ] **Step 1: Update the function signature**

Open `crates/rimap-server/src/main.rs`. Locate `emit_pre_init_error_envelope` (currently starts around line 199). Change its signature and body:

```rust
async fn emit_pre_init_error_envelope(
    msg: &rmcp::model::ClientJsonRpcMessage,
    stdout: &std::sync::Arc<tokio::sync::Mutex<tokio::io::Stdout>>,
) -> anyhow::Result<()> {
    let Some(line) = rimap_server::mcp::preinit::synthesize_pre_init_error_envelope(msg) else {
        return Ok(());
    };
    let mut out = stdout.lock().await;
    out.write_all(line.as_bytes())
        .await
        .context("writing pre-init error envelope to stdout")?;
    out.flush()
        .await
        .context("flushing pre-init error envelope")?;
    Ok(())
}
```

Add the necessary `use` for `tokio::io::AsyncWriteExt` at the top if not already imported.

- [ ] **Step 2: Update the call site to compile (placeholder — will be reworked in Task 3.3)**

The call site in `run()` currently passes no extra arg. To keep the file compiling between this task and Task 3.2, temporarily construct a local `Arc::new(Mutex::new(stdout()))` at the call site:

```rust
// In run(), where ExpectedInitializeRequest is matched:
let _temp_stdout = std::sync::Arc::new(tokio::sync::Mutex::new(tokio::io::stdout()));
emit_pre_init_error_envelope(&msg, &_temp_stdout).await?;
```

This is intentionally ugly — Task 3.3 replaces it with `validated.stdout`.

- [ ] **Step 3: Verify the workspace compiles**

```bash
cargo check --workspace --all-targets --locked
```

Expected: clean.

- [ ] **Step 4: Run the existing pre-init tests to confirm no regression**

```bash
cargo nextest run -p rimap-server pre_init
```

Expected: all existing #275 pre-init wire tests still pass — the I/O behavior is the same (one mutex-acquisition per write), just routed through a local mutex for now.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-server/src/main.rs
git commit -m "refactor(rimap-server): emit_pre_init_error_envelope takes shared stdout (#277)"
```

---

## Task 3.2: Swap the transport constructor

**Files:**
- Modify: `crates/rimap-server/src/main.rs`

Replace `rmcp::transport::io::stdio()` with `wire_validator::stdio_with_validation()`. Update the `ExpectedInitializeRequest` arm to use the now-real `validated.stdout` instead of the temporary mutex from Task 3.1.

- [ ] **Step 1: Construct `ValidatedStdio` once**

Near the top of the `rt.block_on` block in `run()`, before the `rmcp::serve_server` call, add:

```rust
let validated = rimap_server::mcp::wire_validator::stdio_with_validation();
let stdout_for_preinit = std::sync::Arc::clone(&validated.stdout);
```

Then replace:

```rust
let transport = rmcp::transport::io::stdio();
```

with:

```rust
let transport = validated.transport;
```

If `let transport` doesn't appear and `rmcp::transport::io::stdio()` is inlined, modify the inlined call site to use `validated.transport` instead.

- [ ] **Step 2: Replace the temp mutex in `ExpectedInitializeRequest` with the real one**

In the `Err(ServerInitializeError::ExpectedInitializeRequest(Some(msg)))` arm, remove the `_temp_stdout` placeholder added in Task 3.1 and pass `&stdout_for_preinit` instead:

```rust
Err(ServerInitializeError::ExpectedInitializeRequest(Some(msg))) => {
    emit_pre_init_error_envelope(&msg, &stdout_for_preinit).await?;
    return Ok(()); // shutdown handling added in Task 3.4
}
```

- [ ] **Step 3: Verify compilation**

```bash
cargo check --workspace --all-targets --locked
```

Expected: clean. There will be an unused-variable warning for `validated.supervisor` until Task 3.4 — that's OK for now; the linter denies warnings only on `clippy -- -D warnings`, not `cargo check`. Don't run clippy here.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-server/src/main.rs
git commit -m "feat(rimap-server): swap rmcp stdio for wire_validator (#277)"
```

---

## Task 3.3: Init-phase race against the supervisor

**Files:**
- Modify: `crates/rimap-server/src/main.rs`

Race `rmcp::serve_server(...).await` against `supervisor.watch_for_error()` so a bridge `BrokenPipe` during the pre-init phase doesn't leave the supervisor unobserved. Local `InitOutcome` enum disambiguates the failure sources.

- [ ] **Step 1: Add the `InitOutcome` enum and rewrite the init block**

Define a local enum at the start of the `rt.block_on` body (before constructing `validated`):

```rust
// Local enum to disambiguate init-phase failure sources for the
// tokio::select! arms below.
enum InitOutcome {
    Bridge(std::io::Result<()>),
    Rmcp(rmcp::service::ServerInitializeError),
}
```

Then replace the existing `let service = match Box::pin(rmcp::serve_server(...)).await { ... };` block with the race-and-dispatch logic:

```rust
type InitResult = Result<rmcp::service::RunningService<rmcp::RoleServer, ImapMcpServer>, InitOutcome>;

let init_result: InitResult = tokio::select! {
    biased;
    bridge = supervisor.watch_for_error() => Err(InitOutcome::Bridge(bridge)),
    result = &mut init_fut => match result {
        Ok(svc) => Ok(svc),
        Err(e) => Err(InitOutcome::Rmcp(e)),
    },
};
drop(init_fut);

let service = match init_result {
    Ok(svc) => svc,
    Err(InitOutcome::Bridge(bridge_result)) => {
        let primary = bridge_result.err().map_or_else(
            || anyhow::anyhow!("validator bridges exited before init completed"),
            |e| anyhow::anyhow!("validator bridge during init: {e}"),
        );
        let _ = supervisor.shutdown_after_failure().await;
        return Err(primary);
    }
    Err(InitOutcome::Rmcp(ServerInitializeError::ExpectedInitializeRequest(Some(msg)))) => {
        emit_pre_init_error_envelope(&msg, &stdout_for_preinit).await?;
        return match supervisor.shutdown_after_failure().await {
            Ok(()) => Ok(()),
            Err(e) => Err(anyhow::anyhow!("validator bridge after pre-init: {e}")),
        };
    }
    Err(InitOutcome::Rmcp(ServerInitializeError::InitializeFailed(error_data))) => {
        let handled = handle_initialize_failed(&error_data);
        return match supervisor.shutdown_after_failure().await {
            Ok(()) => handled,
            Err(e) => Err(anyhow::anyhow!("validator bridge after init failure: {e}")),
        };
    }
    Err(InitOutcome::Rmcp(other)) => {
        let _ = supervisor.shutdown_after_failure().await;
        return Err(anyhow::anyhow!("MCP server init: {other}"));
    }
};
```

The exact `RunningService<...>` generic may need adjustment depending on rmcp 1.5's type — verify with `cargo check` and tweak the `InitResult` type alias if rustc complains.

- [ ] **Step 2: Verify compilation**

```bash
cargo check --workspace --all-targets --locked
```

Expected: clean. If rustc complains about the `RunningService<...>` type alias, copy the exact type from the error message into the alias.

- [ ] **Step 3: Run all existing pre-init wire tests**

```bash
cargo nextest run -p rimap-server pre_init
```

Expected: pass. The init-phase race doesn't change observable behavior for the existing #275 / #276 paths; it only adds the new Bridge arm.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-server/src/main.rs
git commit -m "feat(rimap-server): race init against validator supervisor (#277)"
```

---

## Task 3.4: Post-init two-phase shutdown

**Files:**
- Modify: `crates/rimap-server/src/main.rs`

Add the post-init race-then-drain logic that replaces the current plain `service.waiting().await?`. On `service.waiting() == Ok`, use `drain()` (inbound already exited). On any failure, use `shutdown_after_failure()` (inbound may be blocked on real stdin).

- [ ] **Step 1: Rewrite the post-init block**

After `let service = ... ;` (from Task 3.3), replace whatever currently follows the service binding (`service.waiting().await...`) with:

```rust
let mut service_fut = Box::pin(service.waiting());

// Phase 1: race service against bridge errors.
let service_outcome: anyhow::Result<()> = tokio::select! {
    biased;
    bridge = supervisor.watch_for_error() => match bridge {
        Err(e) => Err(anyhow::anyhow!("validator bridge: {e}")),
        Ok(()) => {
            // Both bridges exited cleanly while service still running
            // (exotic). Let service finish — it'll see EOF.
            (&mut service_fut)
                .await
                .map_err(|e| anyhow::anyhow!("rmcp: {e}"))
        }
    },
    result = &mut service_fut => result.map_err(|e| anyhow::anyhow!("rmcp: {e}")),
};

// Phase 2: drop service future to release rmcp's transport ends,
// then shutdown supervisor.
drop(service_fut);
let shutdown_outcome = match &service_outcome {
    Ok(()) => supervisor.drain().await,
    Err(_) => supervisor.shutdown_after_failure().await,
}
.map_err(|e| anyhow::anyhow!("validator bridge shutdown: {e}"));

let mcp_result: anyhow::Result<()> = match (service_outcome, shutdown_outcome) {
    (Err(e), _) => Err(e),
    (Ok(()), Err(e)) => Err(e),
    (Ok(()), Ok(())) => Ok(()),
};

// Existing drainer_handle.await stays as-is below this block.
```

Make sure the existing `drainer_handle.await` and `emit_process_end(&audit, &mcp_result)` continue to run after this block.

- [ ] **Step 2: Verify compilation**

```bash
cargo check --workspace --all-targets --locked
```

Expected: clean.

- [ ] **Step 3: Run the workspace tests (post-init paths)**

```bash
cargo nextest run -p rimap-server --locked
```

Expected: existing wire tests pass. The new shutdown logic preserves observable behavior on success and on the existing failure paths (because today's `service.waiting()?` Err equivalently propagates to `mcp_result`).

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-server/src/main.rs
git commit -m "feat(rimap-server): two-phase post-init shutdown via supervisor (#277)"
```

---

## Task 4.1: Add harness variant — closed-stdout + open-stdin

**Files:**
- Modify: `crates/rimap-server/tests/support/wire/harness.rs`

Tests 20-22 need a harness that closes stdout (to force write failures) but keeps stdin open (to exercise the failure-path shutdown that aborts inbound). The existing `spawn_with_closed_stdout` from #275 closes both; we need a sibling.

- [ ] **Step 1: Add the variant**

Open `crates/rimap-server/tests/support/wire/harness.rs`. Locate `spawn_with_closed_stdout` (added for #275). Add an adjacent constructor:

```rust
/// Spawn the server with stdout redirected to a closed pipe (forcing
/// write failures) but keep stdin open under our control. Tests
/// 20-22 of #277 use this to verify bounded shutdown when a client
/// holds stdin open after the server hits an error.
pub async fn spawn_with_closed_stdout_open_stdin() -> Self {
    // Copy the construction logic from spawn_with_closed_stdout, but
    // keep stdin under our control instead of closing it. See
    // spawn_with_closed_stdout for the closed-stdout setup pattern.
    todo!("see spawn_with_closed_stdout — keep self.stdin as ChildStdin instead of closing it")
}
```

Then fill in the implementation by copying the body of `spawn_with_closed_stdout` and removing only the lines that close stdin (or equivalent — read the existing function to see the exact pattern). The key invariant: after construction, `self.stdin` must still be `Some(ChildStdin)` (writable) and `self.stdout` must be on a closed pipe.

- [ ] **Step 2: Add a self-test for the harness variant**

In the same file, in an existing `#[cfg(test)] mod tests` if present (or a new one at the bottom):

```rust
    #[tokio::test]
    async fn closed_stdout_open_stdin_keeps_stdin_writable() {
        let mut h = Harness::spawn_with_closed_stdout_open_stdin().await;
        // We should be able to write at least one line to stdin without error.
        h.send_line(r#"{"jsonrpc":"2.0","method":"initialize","id":1,"params":{}}"#).await;
        // Don't assert on the response — stdout is closed.
        // Drop will tear the harness down.
    }
```

- [ ] **Step 3: Run the harness self-test**

```bash
cargo nextest run -p rimap-server --test mcp_wire_negative closed_stdout
```

Expected: the test passes (or compiles if it requires waiting for the next task's coverage). At minimum, no compile errors.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-server/tests/support/wire/harness.rs
git commit -m "test(rimap-server): closed-stdout + open-stdin harness variant (#277)"
```

---

## Task 5.1: Wire-pinned tests 1-10 (validation rules)

**Files:**
- Modify: `crates/rimap-server/tests/mcp_wire_negative.rs`

The ten validation-rule tests from the spec. Each test sends a single envelope and asserts the validator's wire response (code + id). Same shape; one test per row.

- [ ] **Step 1: Add the test functions**

Append to `crates/rimap-server/tests/mcp_wire_negative.rs`:

```rust
// ============================================================
// #277 — validation rules (tests 1-10).
// Each test sends one malformed envelope and asserts the
// validator's wire response shape.
// ============================================================

async fn assert_invalid_request_response(
    h: &mut Harness,
    line: &str,
    expected_id: serde_json::Value,
    expected_code: i32,
) {
    h.send_line(line).await;
    let outcome = h.response_or_close(REQUEST_TIMEOUT).await;
    match outcome {
        CloseOrResponse::Response(resp_line) => {
            let env: serde_json::Value = serde_json::from_str(resp_line.trim_end())
                .expect("validator response must be valid JSON");
            assert_eq!(env["jsonrpc"], "2.0");
            assert_eq!(env["id"], expected_id, "id mismatch on {line:?}");
            assert_eq!(env["error"]["code"], expected_code, "code mismatch on {line:?}");
        }
        other => panic!("expected validator response, got {other:?} for {line:?}"),
    }
}

#[tokio::test]
async fn envelope_missing_jsonrpc_returns_invalid_request() {
    let mut h = Harness::spawn().await;
    h.initialize_handshake().await.expect("init");
    h.send_initialized().await;
    assert_invalid_request_response(&mut h, r#"{"method":"a"}"#, serde_json::Value::Null, -32600).await;
}

#[tokio::test]
async fn envelope_missing_jsonrpc_with_numeric_id_echoes_id() {
    let mut h = Harness::spawn().await;
    h.initialize_handshake().await.expect("init");
    h.send_initialized().await;
    assert_invalid_request_response(&mut h, r#"{"method":"a","id":42}"#, serde_json::json!(42), -32600).await;
}

#[tokio::test]
async fn envelope_missing_jsonrpc_with_string_id_echoes_id() {
    let mut h = Harness::spawn().await;
    h.initialize_handshake().await.expect("init");
    h.send_initialized().await;
    assert_invalid_request_response(&mut h, r#"{"method":"a","id":"abc"}"#, serde_json::json!("abc"), -32600).await;
}

#[tokio::test]
async fn envelope_missing_jsonrpc_with_malformed_id_uses_null() {
    let mut h = Harness::spawn().await;
    h.initialize_handshake().await.expect("init");
    h.send_initialized().await;
    assert_invalid_request_response(&mut h, r#"{"method":"a","id":[1,2]}"#, serde_json::Value::Null, -32600).await;
}

#[tokio::test]
async fn envelope_with_wrong_jsonrpc_value_returns_invalid_request() {
    let mut h = Harness::spawn().await;
    h.initialize_handshake().await.expect("init");
    h.send_initialized().await;
    assert_invalid_request_response(&mut h, r#"{"jsonrpc":"1.0","method":"x","id":1}"#, serde_json::json!(1), -32600).await;
}

#[tokio::test]
async fn envelope_with_non_string_method_returns_invalid_request() {
    let mut h = Harness::spawn().await;
    h.initialize_handshake().await.expect("init");
    h.send_initialized().await;
    assert_invalid_request_response(&mut h, r#"{"jsonrpc":"2.0","method":42,"id":1}"#, serde_json::json!(1), -32600).await;
}

#[tokio::test]
async fn envelope_batch_array_returns_invalid_request() {
    let mut h = Harness::spawn().await;
    h.initialize_handshake().await.expect("init");
    h.send_initialized().await;
    assert_invalid_request_response(
        &mut h,
        r#"[{"jsonrpc":"2.0","method":"x","id":1}]"#,
        serde_json::Value::Null,
        -32600,
    ).await;
}

#[tokio::test]
async fn envelope_invalid_json_returns_parse_error() {
    let mut h = Harness::spawn().await;
    h.initialize_handshake().await.expect("init");
    h.send_initialized().await;
    assert_invalid_request_response(&mut h, "not valid json", serde_json::Value::Null, -32700).await;
}

#[tokio::test]
async fn envelope_empty_line_is_skipped() {
    let mut h = Harness::spawn().await;
    h.initialize_handshake().await.expect("init");
    h.send_initialized().await;
    // Empty line then a valid request. Validator should skip the empty
    // line silently; the next line on stdout should be the tools/list
    // response (not a -32600 envelope).
    h.send_line("").await;
    let resp = h.request("tools/list", serde_json::json!({})).await;
    let body: serde_json::Value = serde_json::from_str(resp.trim_end())
        .expect("tools/list response must be valid JSON");
    assert!(
        body.get("result").is_some(),
        "tools/list after empty line must respond with a result, got {body}",
    );
    assert!(
        body.get("error").is_none(),
        "tools/list after empty line must not carry an error envelope, got {body}",
    );
}

#[tokio::test]
async fn session_survives_invalid_envelope() {
    let mut h = Harness::spawn().await;
    h.initialize_handshake().await.expect("init");
    h.send_initialized().await;
    // Send an invalid envelope first.
    h.send_line(r#"{"method":"garbage"}"#).await;
    let _ = h.response_or_close(REQUEST_TIMEOUT).await; // consume the -32600
    // Then a valid request — must succeed.
    let resp = h.request("tools/list", serde_json::json!({})).await;
    let body: serde_json::Value = serde_json::from_str(resp.trim_end()).expect("valid JSON");
    assert!(body.get("result").is_some(), "session should be alive: {body}");
}
```

The exact existing `Harness::request` / `initialize_handshake` / `send_initialized` API names should be verified against the harness file before submitting — adjust if the actual method names differ.

- [ ] **Step 2: Run the new tests**

```bash
cargo nextest run -p rimap-server --test mcp_wire_negative envelope_ session_survives
```

Expected: all ten new tests PASS. If `envelope_empty_line_is_skipped` fails because the assertion shape is awkward, simplify to "assert the response was a `result` envelope with no preceding error line — there's a helper for that on Harness if present."

- [ ] **Step 3: Commit**

```bash
git add crates/rimap-server/tests/mcp_wire_negative.rs
git commit -m "test(rimap-server): validation-rule wire tests 1-10 (#277)"
```

---

## Task 5.2: Wire-pinned test 11 (pre-init ordering)

**Files:**
- Modify: `crates/rimap-server/tests/mcp_wire_negative.rs`

Test 11 pins the shared-stdout invariant: send a pre-init `ping` (rmcp may answer it) immediately followed by a pre-init `tools/list` (which `emit_pre_init_error_envelope` rejects with `-32002`). Both stdout lines must parse as well-formed, distinct JSON-RPC envelopes with the expected id mapping — proves no mid-line interleaving.

- [ ] **Step 1: Add the test**

Append to `crates/rimap-server/tests/mcp_wire_negative.rs`:

```rust
#[tokio::test]
async fn preinit_envelope_does_not_interleave_with_rmcp_frame() {
    let mut h = Harness::spawn().await;
    // Do NOT call initialize_handshake — both messages below are pre-init.

    // Send ping (rmcp may respond on the standard MCP method) then
    // tools/list (rmcp rejects pre-init → server emits -32002 via the
    // shared stdout mutex).
    h.send_line(r#"{"jsonrpc":"2.0","method":"ping","id":1}"#).await;
    h.send_line(r#"{"jsonrpc":"2.0","method":"tools/list","id":2}"#).await;

    // Read up to two response lines and verify both parse cleanly.
    let first = h.response_or_close(REQUEST_TIMEOUT).await;
    let second = h.response_or_close(REQUEST_TIMEOUT).await;

    let extract_line = |o: CloseOrResponse| -> Option<String> {
        match o {
            CloseOrResponse::Response(s) => Some(s),
            _ => None,
        }
    };
    let lines: Vec<String> = [first, second].into_iter().filter_map(extract_line).collect();

    // We expect at least the pre-init -32002 envelope; ping handling is
    // implementation-defined for pre-init.
    let any_preinit_reject = lines.iter().any(|line| {
        let env: serde_json::Value = serde_json::from_str(line.trim_end()).expect("valid JSON");
        env["error"]["code"] == -32002
    });
    assert!(any_preinit_reject, "expected -32002 envelope, got {lines:?}");

    // Every emitted line must parse as a complete JSON-RPC envelope
    // (no mid-line interleaving).
    for line in &lines {
        let env: serde_json::Value = serde_json::from_str(line.trim_end())
            .unwrap_or_else(|e| panic!("malformed line {line:?}: {e}"));
        assert_eq!(env["jsonrpc"], "2.0");
    }
}
```

- [ ] **Step 2: Run**

```bash
cargo nextest run -p rimap-server --test mcp_wire_negative preinit_envelope_does_not_interleave
```

Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/rimap-server/tests/mcp_wire_negative.rs
git commit -m "test(rimap-server): pre-init/rmcp-frame ordering test (#277)"
```

---

## Task 5.3: Wire-pinned tests 12-14 (closed-stdout audit semantics)

**Files:**
- Modify: `crates/rimap-server/tests/mcp_wire_negative.rs`

Three tests on closed-stdout: validator rejection write failure (12), rmcp response write failure during race phase (13), drain-phase write failure (14). All must record `process_end.reason: Error` and exit non-zero.

- [ ] **Step 1: Add the three tests**

Append to `crates/rimap-server/tests/mcp_wire_negative.rs`:

```rust
#[tokio::test]
async fn process_end_on_validator_rejection_write_failure() {
    // Closed stdout: validator can't write its -32600 rejection.
    let mut h = Harness::spawn_with_closed_stdout().await;
    // Don't bother with init; just send a malformed line.
    h.send_line(r#"{"method":"a"}"#).await;
    // Wait for the child to exit (it will, because the supervisor
    // surfaces the write error).
    let status = h.wait_with_timeout(std::time::Duration::from_secs(5)).await;
    assert!(!status.success(), "expected non-zero exit, got {status:?}");
    // Audit log assertion: process_end record reason is Error.
    let audit = h.read_audit_log().await;
    assert!(
        audit.contains("\"reason\":\"Error\""),
        "expected process_end.reason=Error, audit was {audit}"
    );
}

#[tokio::test]
async fn process_end_on_rmcp_response_write_failure() {
    // Closed stdout, race-phase: client completes init and sends a
    // valid tools/list while stdout is closed. rmcp's response write
    // into the passthrough fails downstream.
    let mut h = Harness::spawn_with_closed_stdout().await;
    h.send_line(r#"{"jsonrpc":"2.0","method":"initialize","id":1,"params":{}}"#).await;
    h.send_line(r#"{"jsonrpc":"2.0","method":"tools/list","id":2}"#).await;
    let status = h.wait_with_timeout(std::time::Duration::from_secs(5)).await;
    assert!(!status.success());
    let audit = h.read_audit_log().await;
    assert!(audit.contains("\"reason\":\"Error\""), "audit: {audit}");
}

#[tokio::test]
async fn process_end_on_drain_phase_write_failure() {
    // Drain-phase: client completes init, sends tools/list, then
    // closes stdin so service.waiting() resolves Ok. The queued
    // response cannot flush through closed stdout; drain catches
    // the BrokenPipe.
    let mut h = Harness::spawn_with_closed_stdout().await;
    h.send_line(r#"{"jsonrpc":"2.0","method":"initialize","id":1,"params":{}}"#).await;
    h.send_line(r#"{"jsonrpc":"2.0","method":"tools/list","id":2}"#).await;
    h.close_stdin().await; // forces service.waiting() to resolve
    let status = h.wait_with_timeout(std::time::Duration::from_secs(5)).await;
    assert!(!status.success());
    let audit = h.read_audit_log().await;
    assert!(audit.contains("\"reason\":\"Error\""), "audit: {audit}");
}
```

The exact `close_stdin`, `wait_with_timeout`, `read_audit_log` methods may need to be added to `Harness` if not already present. Check the harness file first; if missing, add small helpers using existing primitives (`self.child.wait()` with `timeout`, etc.). The audit log path is stored on `Harness` per the #275 work; use the existing accessor.

- [ ] **Step 2: Run**

```bash
cargo nextest run -p rimap-server --test mcp_wire_negative process_end_on
```

Expected: all three PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/rimap-server/tests/mcp_wire_negative.rs crates/rimap-server/tests/support/wire/harness.rs
git commit -m "test(rimap-server): closed-stdout audit semantics 12-14 (#277)"
```

---

## Task 5.4: Wire-pinned test 15 (fixed-case notification)

**Files:**
- Modify: `crates/rimap-server/tests/mcp_wire_negative.rs`

Replaces the property-strategy notification coverage. Send a standard MCP notification (`notifications/cancelled`), then a `tools/list` request, and assert `tools/list` responds. Proves notifications don't poison or hang the session.

- [ ] **Step 1: Add the test**

```rust
#[tokio::test]
async fn valid_notification_does_not_hang_session() {
    let mut h = Harness::spawn().await;
    h.initialize_handshake().await.expect("init");
    h.send_initialized().await;
    // Send a standard MCP notification (rmcp dispatches it; no response).
    h.send_line(r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":0}}"#).await;
    // Immediately follow with a request that MUST respond.
    let resp = h.request("tools/list", serde_json::json!({})).await;
    let body: serde_json::Value = serde_json::from_str(resp.trim_end()).expect("valid JSON");
    assert!(body.get("result").is_some(), "tools/list after notification failed: {body}");
}
```

- [ ] **Step 2: Run**

```bash
cargo nextest run -p rimap-server --test mcp_wire_negative valid_notification_does_not_hang
```

Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/rimap-server/tests/mcp_wire_negative.rs
git commit -m "test(rimap-server): valid notification keeps session alive (#277)"
```

---

## Task 5.5: Wire-pinned tests 16-19 (Response/Error envelope handling)

**Files:**
- Modify: `crates/rimap-server/tests/mcp_wire_negative.rs`

Tests 16-17 verify the validator forwards valid client-side Response/Error envelopes (MCP server-initiated flow). Tests 18-19 verify it rejects malformed ones.

- [ ] **Step 1: Add the four tests**

```rust
#[tokio::test]
async fn valid_response_envelope_forwards() {
    // Send a client-shaped Response envelope after init. The validator
    // must NOT reject. rmcp probably ignores it (no pending server
    // request to match), but we just verify no -32600 response appears
    // and the session is still alive afterward.
    let mut h = Harness::spawn().await;
    h.initialize_handshake().await.expect("init");
    h.send_initialized().await;
    h.send_line(r#"{"jsonrpc":"2.0","id":99,"result":{"x":1}}"#).await;
    // Wait briefly to confirm no spurious validator rejection.
    if let CloseOrResponse::Response(line) = h.response_or_close(std::time::Duration::from_millis(250)).await {
        let env: serde_json::Value = serde_json::from_str(line.trim_end()).expect("valid JSON");
        assert!(env["error"]["code"].as_i64() != Some(-32600),
                "validator wrongly rejected a valid response envelope: {env}");
    }
    // Then a normal request must succeed.
    let resp = h.request("tools/list", serde_json::json!({})).await;
    let body: serde_json::Value = serde_json::from_str(resp.trim_end()).expect("valid JSON");
    assert!(body.get("result").is_some(), "session should be alive after forwarded response: {body}");
}

#[tokio::test]
async fn valid_error_envelope_forwards() {
    let mut h = Harness::spawn().await;
    h.initialize_handshake().await.expect("init");
    h.send_initialized().await;
    h.send_line(r#"{"jsonrpc":"2.0","id":99,"error":{"code":-32601,"message":"not found"}}"#).await;
    if let CloseOrResponse::Response(line) = h.response_or_close(std::time::Duration::from_millis(250)).await {
        let env: serde_json::Value = serde_json::from_str(line.trim_end()).expect("valid JSON");
        assert!(env["error"]["code"].as_i64() != Some(-32600),
                "validator wrongly rejected a valid error envelope: {env}");
    }
    let resp = h.request("tools/list", serde_json::json!({})).await;
    let body: serde_json::Value = serde_json::from_str(resp.trim_end()).expect("valid JSON");
    assert!(body.get("result").is_some(), "session should be alive after forwarded error: {body}");
}

#[tokio::test]
async fn envelope_with_both_result_and_error_returns_invalid_request() {
    let mut h = Harness::spawn().await;
    h.initialize_handshake().await.expect("init");
    h.send_initialized().await;
    assert_invalid_request_response(
        &mut h,
        r#"{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":1,"message":"x"}}"#,
        serde_json::json!(1),
        -32600,
    ).await;
}

#[tokio::test]
async fn envelope_response_without_id_returns_invalid_request() {
    let mut h = Harness::spawn().await;
    h.initialize_handshake().await.expect("init");
    h.send_initialized().await;
    assert_invalid_request_response(
        &mut h,
        r#"{"jsonrpc":"2.0","result":{}}"#,
        serde_json::Value::Null,
        -32600,
    ).await;
}
```

- [ ] **Step 2: Run**

```bash
cargo nextest run -p rimap-server --test mcp_wire_negative valid_response valid_error envelope_with_both envelope_response_without
```

Expected: all four PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/rimap-server/tests/mcp_wire_negative.rs
git commit -m "test(rimap-server): Response/Error envelope forwarding 16-19 (#277)"
```

---

## Task 5.6: Wire-pinned tests 20-22 (bounded shutdown on open stdin)

**Files:**
- Modify: `crates/rimap-server/tests/mcp_wire_negative.rs`

Tests 20-22 use `spawn_with_closed_stdout_open_stdin` (from Task 4.1) to verify that init-failure paths, post-init failure paths, and init-phase bridge errors all exit within bounded time even when the client holds stdin open.

- [ ] **Step 1: Add the three tests**

```rust
#[tokio::test]
async fn init_failure_with_open_stdin_returns_promptly() {
    // Client sends initialize with unsupported protocolVersion → rmcp
    // emits -32602; does NOT close stdin.
    let mut h = Harness::spawn().await;
    h.send_line(r#"{"jsonrpc":"2.0","method":"initialize","id":1,"params":{"protocolVersion":"1999-01-01","capabilities":{}}}"#).await;
    // Hold stdin open (don't call close_stdin); rely on the server
    // to shutdown_after_failure within bounded time.
    let status = h.wait_with_timeout(std::time::Duration::from_secs(2)).await;
    // shutdown_after_failure should classify InitializeFailed (INVALID_PARAMS)
    // as a handled rejection → exit 0.
    assert!(status.success(), "init failure should exit 0, got {status:?}");
}

#[tokio::test]
async fn process_end_on_post_init_service_error_with_open_stdin() {
    // Closed stdout + open stdin: client completes init, sends
    // tools/list, but never closes stdin. The supervisor must
    // shutdown_after_failure and exit within bounded time.
    let mut h = Harness::spawn_with_closed_stdout_open_stdin().await;
    h.send_line(r#"{"jsonrpc":"2.0","method":"initialize","id":1,"params":{}}"#).await;
    h.send_line(r#"{"jsonrpc":"2.0","method":"tools/list","id":2}"#).await;
    // Hold stdin open — do NOT call close_stdin.
    let status = h.wait_with_timeout(std::time::Duration::from_secs(2)).await;
    assert!(!status.success(), "expected non-zero exit, got {status:?}");
    let audit = h.read_audit_log().await;
    assert!(audit.contains("\"reason\":\"Error\""), "audit: {audit}");
}

#[tokio::test]
async fn process_end_on_pre_init_bridge_error_with_open_stdin() {
    // Closed stdout + open stdin: client sends a pre-init ping
    // (rmcp queues a response). Passthrough fails on the closed
    // stdout while rmcp is still waiting for initialize. Client
    // never closes stdin.
    let mut h = Harness::spawn_with_closed_stdout_open_stdin().await;
    h.send_line(r#"{"jsonrpc":"2.0","method":"ping","id":1}"#).await;
    let status = h.wait_with_timeout(std::time::Duration::from_secs(2)).await;
    assert!(!status.success(), "expected non-zero exit, got {status:?}");
    let audit = h.read_audit_log().await;
    assert!(audit.contains("\"reason\":\"Error\""), "audit: {audit}");
}
```

- [ ] **Step 2: Run**

```bash
cargo nextest run -p rimap-server --test mcp_wire_negative init_failure_with_open_stdin process_end_on_post_init_service_error process_end_on_pre_init_bridge_error
```

Expected: all three PASS within their bounded timeouts.

- [ ] **Step 3: Commit**

```bash
git add crates/rimap-server/tests/mcp_wire_negative.rs
git commit -m "test(rimap-server): bounded shutdown on open stdin 20-22 (#277)"
```

---

## Task 5.7: Wire-pinned tests 23-25 (rmcp grammar matching)

**Files:**
- Modify: `crates/rimap-server/tests/mcp_wire_negative.rs`

Tests 23-25 pin the rmcp-grammar tightenings: null id rejected, malformed error body rejected.

- [ ] **Step 1: Add the three tests**

```rust
#[tokio::test]
async fn envelope_request_with_null_id_returns_invalid_request() {
    let mut h = Harness::spawn().await;
    h.initialize_handshake().await.expect("init");
    h.send_initialized().await;
    assert_invalid_request_response(
        &mut h,
        r#"{"jsonrpc":"2.0","method":"tools/list","id":null}"#,
        serde_json::Value::Null,
        -32600,
    ).await;
}

#[tokio::test]
async fn envelope_error_response_with_malformed_body_returns_invalid_request() {
    let mut h = Harness::spawn().await;
    h.initialize_handshake().await.expect("init");
    h.send_initialized().await;
    assert_invalid_request_response(
        &mut h,
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":"not-a-number","message":"x"}}"#,
        serde_json::json!(1),
        -32600,
    ).await;
}

#[tokio::test]
async fn envelope_error_response_without_code_returns_invalid_request() {
    let mut h = Harness::spawn().await;
    h.initialize_handshake().await.expect("init");
    h.send_initialized().await;
    assert_invalid_request_response(
        &mut h,
        r#"{"jsonrpc":"2.0","id":1,"error":{"message":"oops"}}"#,
        serde_json::json!(1),
        -32600,
    ).await;
}
```

- [ ] **Step 2: Run**

```bash
cargo nextest run -p rimap-server --test mcp_wire_negative envelope_request_with_null envelope_error_response
```

Expected: all three PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/rimap-server/tests/mcp_wire_negative.rs
git commit -m "test(rimap-server): rmcp grammar matching 23-25 (#277)"
```

---

## Task 6.1: Filter spec-legal notifications out of `arb_envelope`

**Files:**
- Modify: `crates/rimap-server/tests/mcp_wire_proptest.rs`

Adds `prop_filter` to `arb_envelope()` so the property no longer generates valid JSON-RPC notifications (which would produce no response and false-positive as `Hung`).

- [ ] **Step 1: Modify the strategy**

Locate `fn arb_envelope() -> impl Strategy<Value = Value>` (around line 217 of the current file). At the end of the `.prop_map(...)` chain, add:

```rust
        .prop_filter(
            "exclude spec-legal notifications (jsonrpc==\"2.0\" + missing id + present method) — \
             their silent-ignore is JSON-RPC §4.1 compliant and covered separately by \
             valid_notification_does_not_hang_session",
            |env| {
                let is_notification = env.get("jsonrpc").and_then(|v| v.as_str()) == Some("2.0")
                    && env.get("id").is_none()
                    && env.get("method").and_then(|v| v.as_str()).is_some();
                !is_notification
            },
        )
```

- [ ] **Step 2: Verify compilation**

```bash
cargo check -p rimap-server --tests --locked
```

Expected: clean.

- [ ] **Step 3: Commit**

```bash
git add crates/rimap-server/tests/mcp_wire_proptest.rs
git commit -m "test(rimap-server): filter notifications out of arb_envelope (#277)"
```

---

## Task 6.2: Un-ignore `prop_envelope_never_panics`

**Files:**
- Modify: `crates/rimap-server/tests/mcp_wire_proptest.rs`

With the validator in place and notifications filtered, the property should pass at the default 1000 cases.

- [ ] **Step 1: Remove the `#[ignore]` attribute**

Locate the `#[ignore = "blocked on #277: ..."]` line above `fn prop_envelope_never_panics` (around line 309-310). Delete the line entirely.

- [ ] **Step 2: Run the property**

```bash
PROPTEST_CASES=1000 cargo nextest run -p rimap-server --test mcp_wire_proptest prop_envelope_never_panics
```

Expected: PASS at 1000 cases. If a panic occurs, the validator missed a case — capture the shrunk envelope, add a fixed-case test for it, and either tighten `validate()` or document why the case is non-fatal.

- [ ] **Step 3: Commit**

```bash
git add crates/rimap-server/tests/mcp_wire_proptest.rs
git commit -m "test(rimap-server): un-ignore prop_envelope_never_panics (#277)"
```

---

## Task 7.1: Tighten `is_forwardable_id` to rmcp's `i64` grammar

**Files:**
- Modify: `crates/rimap-server/src/mcp/wire_validator.rs`

Round-6 follow-up. rmcp's `RequestId::Number` is `i64`. Fractional and out-of-i64-range JSON numbers fail rmcp's deserialization; the validator should reject them too.

- [ ] **Step 1: Tighten the helper**

In `crates/rimap-server/src/mcp/wire_validator.rs`, replace:

```rust
pub(crate) fn is_forwardable_id(v: &Value) -> bool {
    v.is_string() || v.is_number()
}
```

with:

```rust
pub(crate) fn is_forwardable_id(v: &Value) -> bool {
    // rmcp 1.5's RequestId = NumberOrString. Strings are unrestricted;
    // numbers must be i64-representable (rejects fractional values and
    // numbers outside i64 range — serde_json parses very large ints as
    // f64 which `as_i64` also rejects).
    if v.is_string() {
        return true;
    }
    v.as_i64().is_some()
}
```

- [ ] **Step 2: Add unit tests**

Inside the existing `mod tests` block in `wire_validator.rs`:

```rust
    #[test]
    fn fractional_id_rejects() {
        assert_eq!(
            validate(r#"{"jsonrpc":"2.0","method":"x","id":1.5}"#),
            reject(-32600, Value::Null)
        );
    }

    #[test]
    fn out_of_i64_range_id_rejects() {
        // serde_json may parse very large integers as f64; either way
        // as_i64() returns None and we reject.
        assert_eq!(
            validate(r#"{"jsonrpc":"2.0","method":"x","id":9223372036854775808}"#),
            reject(-32600, Value::Null)
        );
    }
```

- [ ] **Step 3: Run**

```bash
cargo nextest run -p rimap-server --lib wire_validator
```

Expected: all tests PASS, including the two new ones.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-server/src/mcp/wire_validator.rs
git commit -m "fix(rimap-server): is_forwardable_id matches rmcp i64 range (#277)"
```

---

## Task 7.2: Tighten `is_well_formed_error.code` to rmcp's `i32`

**Files:**
- Modify: `crates/rimap-server/src/mcp/wire_validator.rs`

Same shape as 7.1 but for the error envelope's `code` field. rmcp's `ErrorCode = i32`.

- [ ] **Step 1: Tighten the helper**

Replace:

```rust
pub(crate) fn is_well_formed_error(v: &Value) -> bool {
    let Some(obj) = v.as_object() else {
        return false;
    };
    obj.get("code").is_some_and(Value::is_number)
        && obj.get("message").is_some_and(Value::is_string)
}
```

with:

```rust
pub(crate) fn is_well_formed_error(v: &Value) -> bool {
    let Some(obj) = v.as_object() else {
        return false;
    };
    let code_ok = obj
        .get("code")
        .and_then(Value::as_i64)
        .is_some_and(|n| i32::try_from(n).is_ok());
    let message_ok = obj.get("message").is_some_and(Value::is_string);
    code_ok && message_ok
}
```

- [ ] **Step 2: Add unit tests**

```rust
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
```

- [ ] **Step 3: Run**

```bash
cargo nextest run -p rimap-server --lib wire_validator
```

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-server/src/mcp/wire_validator.rs
git commit -m "fix(rimap-server): is_well_formed_error.code matches rmcp i32 range (#277)"
```

---

## Task 8: Full local CI sweep

**Files:** none

**Context:** Final gate — run `just ci` and verify everything green before opening PR #278 out of draft.

- [ ] **Step 1: Run the full local CI sweep**

```bash
just ci
```

Expected: all stages green (nextest workspace, cargo deny, mcp-conformance, typos, etc.). If any failure surfaces, attribute it to one of the prior tasks and fix in a focused follow-up commit.

- [ ] **Step 2: Verify `prop_envelope_never_panics` runs at a higher case count**

```bash
PROPTEST_CASES=10000 cargo nextest run -p rimap-server --test mcp_wire_proptest prop_envelope_never_panics
```

Expected: PASS at 10k cases. (Nightly runs 100k via the existing `mcp-fuzz-nightly.yml`.) If a panic surfaces at 10k that didn't at 1k, capture the shrunk envelope and add a fixed-case test before merging.

- [ ] **Step 3: No commit — just CI confirmation.**

---

## Spec coverage check

- **Problem / Root cause** (spec §Problem, §Root cause) → addressed by Tasks 1.2 + 2.1 (validator + inbound bridge); see also task assertions in Task 5.1.
- **Two cases collapsed** (spec §Two cases collapsed) → case 1 = Task 1.2 + 5.1; case 2 = Task 6.1 strategy filter + Task 5.4 fixed-case.
- **Desired behavior** (5 numbered behaviors) → 1: Tasks 1.2/2.1/2.2; 2: Task 1.2 empty-line test; 3: Task 1.2 parse-error test + 5.1 test 8; 4: Task 1.2 invalid-request tests + 5.1 tests 1-7; 5: Task 5.1 `session_survives_invalid_envelope`.
- **Approach: validator architecture diagram** (spec §Approach) → Tasks 2.1-2.4 implement the diagram.
- **Validator entry point + struct** (spec §Validator entry point) → Task 2.4.
- **Bridge-task supervisor** (spec §Bridge-task supervisor, all three methods + the two-phase shutdown rationale) → Task 2.3 (methods) + Tasks 3.3/3.4 (usage in main.rs) + Tasks 5.3/5.6 (closed-stdout audit tests).
- **Pre-init shares the validator stdout** (spec §Pre-init shares the validator stdout) → Task 3.1 + Task 5.2 (interleave test).
- **Validation rules table + decision logic** (spec §Validation rules, §validate() decision logic) → Task 1.2 (all rule rows have matching unit tests) + Task 5.1 (wire-pinned tests 1-10).
- **`id`-echo policy** (spec §id-echo policy) → Task 1.2 `extract_id` + assertions in Task 5.1 (numeric/string/null echo cases).
- **Error envelope shapes** (spec §Error envelope shapes) → Task 1.3 `synthesize_error_line` + unit tests.
- **File layout** (spec §File layout) → matches plan's File Structure section.
- **Property strategy adjustment** (spec §Property strategy adjustment) → Task 6.1.
- **Fixed-case notification coverage** (spec §Fixed-case notification coverage) → Task 5.4.
- **Testing — all 25 tests** → Tasks 5.1 (10) + 5.2 (1) + 5.3 (3) + 5.4 (1) + 5.5 (4) + 5.6 (3) + 5.7 (3) = 25. ✓
- **Risks / mitigations** — covered by the test plan (each risk has a pinning test in Task 5.*).
- **Implementation follow-ups (round 6)** → Tasks 7.1 + 7.2.
- **Dependencies and merge plan** → final task list (1.1 → 8) lands all six items in the spec's merge-plan numbering.

No spec gaps.
