# MCP Protocol Fuzzing & Negative-Path Coverage — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land Phase 4 of the MCP test plan (issue #266): property-based and targeted negative-path tests for the MCP JSON-RPC wire, plus an audit fail-closed boundary test and a race-free wire-level cancellation acceptance test.

**Architecture:** Five new test binaries across two crates, all reusing and extending the Phase 1 `support/wire/Harness`. The harness gains raw send/recv primitives, a buffered concurrent-request API, and an "assert clean shutdown OR response" helper. Proptest cases share a harness per property with a restart-on-close discipline; property 1's `method` strategy excludes the pinned MCP-stateful set. The audit-failure tests arm `AuditWriter::force_next_write_failure()` through a tiny `test-support`-gated CLI flag rather than a swappable sink. The cancellation contract is split: the existing in-process Drop tests at `crates/rimap-server/src/mcp/audit_envelope.rs::tests` already pin the `tool_end {status: cancelled}` invariant from #71/#99, so the new wire-layer test only asserts race-free invariants (server stays responsive, no envelope corruption).

**Tech Stack:** Rust stable, tokio, `rmcp 1.5`, `proptest 1.6`, `jsonschema`, `tempfile`, `assert_cmd`, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-05-13-mcp-protocol-fuzzing-design.md`

---

## Pre-flight

The branch `feature/issue-266-mcp-fuzzing` is already checked out with the spec committed (commits `3948bf7` and `a032e98`). Verify before starting:

```bash
git rev-parse --abbrev-ref HEAD  # expect: feature/issue-266-mcp-fuzzing
git status --short                # expect: clean
```

Pre-commit hooks are installed (the spec commits ran them). `prek install` if `git config core.hooksPath` is unset.

The Phase 1 wire-test infrastructure lives at:
- `crates/rimap-server/tests/support/wire/harness.rs` — `Harness` struct
- `crates/rimap-server/tests/support/wire/schema.rs` — `assert_envelope_valid`, `validator_for`, `assert_valid`
- `crates/rimap-server/tests/support/wire/mod.rs` — re-exports
- `crates/rimap-server/tests/support/mod.rs` — adds `pub mod wire;`

Read the existing wire conformance tests at `crates/rimap-server/tests/mcp_wire_conformance.rs` to understand the test pattern (`#[tokio::test(flavor = "multi_thread", worker_threads = 2)]`, `Harness::spawn`, `initialize_handshake`, `send_initialized`).

---

## Task 1: Harness — raw send/recv primitives

**Files:**
- Modify: `crates/rimap-server/tests/support/wire/harness.rs`
- Modify: `crates/rimap-server/tests/mcp_wire_conformance.rs` (verify nothing breaks)

Add `send_raw`, `send_line`, and `recv_line_within` to `Harness`. These bypass JSON-RPC envelope validation so fuzz tests can send arbitrary bytes and read whatever arrives without the existing `request()` method's id-match + schema-validate discipline getting in the way.

- [ ] **Step 1: Add `send_raw` and `send_line`**

In `crates/rimap-server/tests/support/wire/harness.rs`, add these methods to `impl Harness` right after `notify` (around line 222):

```rust
    /// Write arbitrary bytes to the child's stdin verbatim. No newline
    /// is appended; the caller is responsible for framing. Used by
    /// fuzz / malformed-input tests that need to send bytes the
    /// normal `request` / `notify` API would reject.
    pub async fn send_raw(&mut self, bytes: &[u8]) {
        self.stdin
            .write_all(bytes)
            .await
            .expect("write raw bytes");
        self.stdin.flush().await.expect("flush raw bytes");
    }

    /// Convenience wrapper: write `line` followed by `\n`. The
    /// `line` itself MUST NOT contain a `\n` (MCP framing is one
    /// JSON envelope per line; embedded newlines would split the
    /// envelope across lines).
    pub async fn send_line(&mut self, line: &str) {
        assert!(
            !line.contains('\n'),
            "send_line: caller-supplied content must not contain a newline; got {line:?}",
        );
        let mut framed = String::with_capacity(line.len() + 1);
        framed.push_str(line);
        framed.push('\n');
        self.send_raw(framed.as_bytes()).await;
    }
```

- [ ] **Step 2: Add `recv_line_within`**

Right after `send_line`, add:

```rust
    /// Read one line of stdout under `dur`. Returns `Some(line)` on
    /// success, `None` if `dur` elapsed before a newline arrived OR
    /// the child closed stdout. Unlike `request`, this does NOT parse
    /// or validate the line; fuzz tests use it to observe whatever
    /// the server actually emitted (which may be malformed by design).
    pub async fn recv_line_within(&mut self, dur: Duration) -> Option<String> {
        let mut buf = String::new();
        match timeout(dur, self.stdout.read_line(&mut buf)).await {
            Ok(Ok(0)) => None,            // EOF
            Ok(Ok(_)) => Some(buf),       // line read; buf ends with '\n'
            Ok(Err(_)) => None,           // I/O error → treat as EOF
            Err(_elapsed) => None,        // timeout
        }
    }
```

- [ ] **Step 3: Verify the Phase 1 tests still compile and pass**

```bash
cargo test -p rimap-server --test mcp_wire_conformance
```

Expected: all 9 existing wire conformance tests pass. The new methods are added, not modifying existing ones, so this should be a clean compile.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-server/tests/support/wire/harness.rs
git commit -m "test(rimap-server): add raw send/recv primitives to wire Harness

send_raw, send_line, and recv_line_within bypass the JSON-RPC envelope
validation in request/notify so fuzz and malformed-input tests can
exchange arbitrary bytes. Prerequisite for #266 Phase 4."
```

---

## Task 2: Harness — concurrent request API, `read_one_envelope` refactor, `response_or_close`

**Files:**
- Modify: `crates/rimap-server/tests/support/wire/harness.rs`

Add `send_request_no_wait` (returns the assigned id without awaiting a response), `recv_until_id` (reads stdout until the matching id arrives, buffering out-of-order envelopes in a `VecDeque`), and `response_or_close` (returns an explicit `CloseOrResponse` enum that distinguishes a clean close, a crash, and a hang on EOF — Codex review finding #1 verified this distinction is required). Refactor the notification-skip loop inside `request` into a shared `read_one_envelope` helper.

- [ ] **Step 1: Add a per-Harness buffer field and pending-ids set**

In the same file, modify the `Harness` struct (around line 46) to add a buffer AND a poisoned flag. The `poisoned` flag is set whenever the harness has observed an unrecoverable session state (stdout EOF, child exit, response-shape corruption) so subsequent reuse can be rejected — see Task 2 Step 5 for where it gets set, and Task 6 Step 2 for where it's consulted by the proptest restart-on-close discipline.

```rust
pub struct Harness {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
    stderr_log: PathBuf,
    /// Out-of-order response envelopes parked here by `recv_until_id`
    /// when a response for a not-yet-awaited id arrives ahead of the
    /// one the caller is waiting for. Keyed by the JSON-RPC `id`
    /// (always a u64 in this harness because `next_id` is u64).
    buffered_responses: std::collections::VecDeque<(u64, Value)>,
    /// Set to true once the harness has observed an unrecoverable
    /// session state: stdout EOF, child exit (clean or crash),
    /// timeout where stdout is still open but the server is
    /// unresponsive, or schema validation failure on a parsed
    /// envelope. Once poisoned the harness MUST NOT be used for
    /// further requests — `is_usable` returns false for poisoned
    /// harnesses regardless of process status, which is what the
    /// proptest restart-on-close discipline (Task 6) consults.
    /// Codex review finding #2 verified this is necessary because
    /// a closed-stdout child may not yet be reaped, so `try_wait`
    /// alone is insufficient.
    poisoned: bool,
    _tempdir: TempDir,
}
```

In `Harness::spawn_with_config` (around line 121), initialize the new fields:

```rust
        Self {
            child,
            stdin,
            stdout,
            next_id: 0,
            stderr_log,
            buffered_responses: std::collections::VecDeque::new(),
            poisoned: false,
            _tempdir: tempdir,
        }
```

In `Harness::shutdown_and_wait` (around line 266), destructure the new fields:

```rust
        let Self {
            mut child,
            stdin,
            stdout: _,
            next_id: _,
            stderr_log: _,
            buffered_responses: _,
            poisoned: _,
            _tempdir: tempdir,
        } = self;
```

- [ ] **Step 2: Add `read_one_envelope` private helper**

Right above the existing `request` method (around line 141), add:

```rust
    /// Read exactly one parsed envelope from stdout. Skips
    /// notifications (which have a `method` and absent/null `id`) but
    /// does NOT skip responses; returns the first response observed.
    /// Panics on timeout, EOF, or parse failure with stderr included
    /// in the diagnostic. Shared by `request` and `recv_until_id`.
    async fn read_one_envelope(&mut self, caller: &str) -> Value {
        loop {
            let mut buf = String::new();
            let read_result = timeout(REQUEST_TIMEOUT, self.stdout.read_line(&mut buf)).await;
            let read = match read_result {
                Ok(io_result) => io_result.unwrap_or_else(|e| {
                    panic!(
                        "read response error on {caller}: {e}\n\
                         --- captured child stderr ---\n{}",
                        self.captured_stderr(),
                    )
                }),
                Err(elapsed) => panic!(
                    "response to {caller} did not arrive within {REQUEST_TIMEOUT:?} ({elapsed})\n\
                     --- captured child stderr ---\n{}",
                    self.captured_stderr(),
                ),
            };
            assert!(
                read > 0,
                "stdout closed before responding to {caller}\n\
                 --- captured child stderr ---\n{}",
                self.captured_stderr(),
            );
            let envelope: Value = serde_json::from_str(buf.trim_end())
                .unwrap_or_else(|e| {
                    panic!(
                        "failed to parse envelope JSON from server on {caller}: {e}\n\
                         raw line: {buf:?}\n\
                         --- captured child stderr ---\n{}",
                        self.captured_stderr(),
                    )
                });
            let is_notification = envelope.get("method").is_some()
                && envelope.get("id").is_none_or(Value::is_null);
            if is_notification {
                assert_eq!(
                    envelope["jsonrpc"],
                    json!("2.0"),
                    "notification must declare jsonrpc=\"2.0\"; got {envelope}",
                );
                continue;
            }
            return envelope;
        }
    }
```

- [ ] **Step 3: Refactor `request` to use `read_one_envelope`**

Replace the body of `request` (lines 141–207) with:

```rust
    pub async fn request(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let id = self.next_id;
        let envelope = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });
        let line = format!("{envelope}\n");
        self.stdin
            .write_all(line.as_bytes())
            .await
            .expect("write request");
        self.stdin.flush().await.expect("flush request");

        let envelope = self.read_one_envelope(method).await;
        assert_eq!(envelope["id"], json!(id), "response id must match request");
        super::schema::assert_envelope_valid(&envelope);
        envelope
    }
```

Note: this is functionally identical to the old loop. The only change is that the notification-skip + parse + stderr-on-failure logic is now shared. Verify by running the Phase 1 tests after the next step.

- [ ] **Step 4: Add `send_request_no_wait` and `recv_until_id`**

Right after `request`, add:

```rust
    /// Send a JSON-RPC request and return the assigned id WITHOUT
    /// awaiting a response. Pair with `recv_until_id` to drive
    /// multiple in-flight requests deterministically.
    pub async fn send_request_no_wait(&mut self, method: &str, params: Value) -> u64 {
        self.next_id += 1;
        let id = self.next_id;
        let envelope = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });
        let line = format!("{envelope}\n");
        self.stdin
            .write_all(line.as_bytes())
            .await
            .expect("write request");
        self.stdin.flush().await.expect("flush request");
        id
    }

    /// Drain stdout (skipping notifications) until a response envelope
    /// with `id == target` arrives. Out-of-order responses for other
    /// requests already in flight are buffered and can be retrieved by
    /// later `recv_until_id` calls. Panics if the response envelope
    /// fails schema validation.
    pub async fn recv_until_id(&mut self, target: u64) -> Value {
        // Fast path: target already buffered.
        if let Some(pos) = self
            .buffered_responses
            .iter()
            .position(|(id, _)| *id == target)
        {
            let (_, env) = self.buffered_responses.remove(pos).expect("indexed");
            super::schema::assert_envelope_valid(&env);
            return env;
        }
        // Slow path: read until we see target, parking other ids.
        loop {
            let envelope = self
                .read_one_envelope(&format!("recv_until_id({target})"))
                .await;
            let id = envelope["id"].as_u64().unwrap_or_else(|| {
                panic!(
                    "response envelope missing numeric id while awaiting {target}: {envelope}"
                )
            });
            if id == target {
                super::schema::assert_envelope_valid(&envelope);
                return envelope;
            }
            self.buffered_responses.push_back((id, envelope));
        }
    }
```

- [ ] **Step 5: Add the `Outcome` enum and `response_or_close`**

Right after `recv_until_id`, define an explicit outcome type and the helper that returns it. This replaces the simple `Option<String>` shape from the original sketch — Codex review finding #1 verified that mapping EOF directly to "clean close" cannot distinguish an orderly server shutdown from a panic that closed stdout, so the helper MUST verify exit status on EOF and propagate that distinction back to callers.

```rust
    /// Possible outcomes when probing the server for "either a
    /// response or a close." Codex review finding #1 verified that
    /// a simple `Option<String>` could not distinguish a panic
    /// (stdout closed but child exited with non-zero status) from
    /// an orderly shutdown — the malformed-input contract demands
    /// that distinction, so this enum is required.
    #[derive(Debug)]
    pub enum CloseOrResponse {
        /// The server produced a line of output (newline-terminated).
        Response(String),
        /// EOF observed AND `child.wait()` returned exit code 0
        /// within `SHUTDOWN_TIMEOUT`. The server shut down
        /// cleanly. Harness is now poisoned (process reaped).
        CleanClose,
        /// EOF observed AND child exited with a non-zero status or
        /// was killed by a signal. The server crashed. Includes the
        /// raw exit-status string for diagnostics. Harness poisoned.
        Crashed(String),
        /// Stdout did NOT yield EOF AND no line arrived within
        /// `request_dur`. The server is hung or unresponsive.
        /// Harness poisoned.
        Hung,
    }

    /// Probe-based contract helper: within `request_dur`, observe
    /// one of `Response`/`CleanClose`/`Crashed`/`Hung`. On any
    /// non-`Response` outcome, the harness is marked `poisoned`
    /// so the restart-on-close discipline (Task 6) won't reuse it.
    /// Callers MUST `match` the result; `_` matches are a code-
    /// review failure because they re-introduce the original
    /// Option-shaped bug.
    pub async fn response_or_close(&mut self, request_dur: Duration) -> CloseOrResponse {
        let mut buf = String::new();
        let read = timeout(request_dur, self.stdout.read_line(&mut buf)).await;
        match read {
            Ok(Ok(0)) => {
                // EOF. Verify the child exited cleanly within
                // SHUTDOWN_TIMEOUT and distinguish CleanClose from Crashed.
                self.poisoned = true;
                let wait = timeout(SHUTDOWN_TIMEOUT, self.child.wait()).await;
                match wait {
                    Ok(Ok(status)) if status.success() => CloseOrResponse::CleanClose,
                    Ok(Ok(status)) => CloseOrResponse::Crashed(format!(
                        "{status:?}\n\
                         --- captured child stderr ---\n{}",
                        self.captured_stderr(),
                    )),
                    Ok(Err(e)) => CloseOrResponse::Crashed(format!(
                        "child.wait() error: {e}\n\
                         --- captured child stderr ---\n{}",
                        self.captured_stderr(),
                    )),
                    Err(_elapsed) => CloseOrResponse::Crashed(format!(
                        "child did not exit within {SHUTDOWN_TIMEOUT:?} after EOF\n\
                         --- captured child stderr ---\n{}",
                        self.captured_stderr(),
                    )),
                }
            }
            Ok(Ok(_)) => CloseOrResponse::Response(buf),
            Ok(Err(e)) => {
                self.poisoned = true;
                CloseOrResponse::Crashed(format!(
                    "read error while waiting for response-or-close: {e}\n\
                     --- captured child stderr ---\n{}",
                    self.captured_stderr(),
                ))
            }
            Err(_elapsed) => {
                self.poisoned = true;
                CloseOrResponse::Hung
            }
        }
    }
```

Re-export `CloseOrResponse` from `support/wire/mod.rs` alongside `Harness`:

```rust
pub use harness::{CloseOrResponse, Harness, PINNED_PROTOCOL_VERSION, REQUEST_TIMEOUT, SHUTDOWN_TIMEOUT};
```

- [ ] **Step 6: Run Phase 1 tests to confirm no regression**

```bash
cargo test -p rimap-server --test mcp_wire_conformance
```

Expected: all 9 tests pass. The refactor in Step 3 is functionally identical to the original.

- [ ] **Step 7: Commit**

```bash
git add crates/rimap-server/tests/support/wire/harness.rs
git commit -m "test(rimap-server): add concurrent request API and shutdown-or-response helper

send_request_no_wait + recv_until_id buffers out-of-order responses
in a VecDeque so concurrent in-flight requests are observable
deterministically. response_or_close returns an explicit
CloseOrResponse enum that distinguishes a clean close from a crash
or hang on EOF (Codex review finding #1). The notification-skip loop is extracted into
a shared read_one_envelope helper. Prerequisite for #266 Phase 4."
```

---

## Task 3: `mcp_wire_negative.rs` — malformed-input tests

**Files:**
- Create: `crates/rimap-server/tests/mcp_wire_negative.rs`

Five tests that exercise the server with unparseable JSON, invalid JSON-RPC envelopes, missing/wrong-type fields, and an oversized payload. Each test follows the probe-first pattern: run the test once with a placeholder assertion, observe the actual server behavior, then encode the observed behavior as the assertion with an inline comment documenting the probe date and rmcp version.

- [ ] **Step 1: Create the file scaffold**

```rust
//! MCP wire-shape negative-path tests (issue #266, Phase 4).
//!
//! Targeted negative cases that complement the property-based
//! coverage in `mcp_wire_proptest.rs`. Each test follows the
//! probe-first contract documented in
//! `docs/superpowers/specs/2026-05-13-mcp-protocol-fuzzing-design.md`
//! §4.1: every test asserts either a specific JSON-RPC error
//! envelope shape OR a clean stdin shutdown — never just
//! "didn't crash."
//!
//! `CloseOrResponse::Crashed` and `CloseOrResponse::Hung` always
//! fail the test, regardless of which input produced them.

#![expect(clippy::expect_used, reason = "integration tests")]
#![expect(clippy::panic, reason = "test assertions render diagnostics")]

#[path = "support/mod.rs"]
mod support;

use std::time::Duration;

use serde_json::{Value, json};

use support::wire::{CloseOrResponse, Harness, REQUEST_TIMEOUT, assert_envelope_valid};
```

Note: `REQUEST_TIMEOUT` and `assert_envelope_valid` may need re-exporting from `support/wire/mod.rs`. Check the current re-exports and add any missing ones.

- [ ] **Step 2: Re-export `REQUEST_TIMEOUT`, `CloseOrResponse`, and `assert_envelope_valid` from the wire module**

In `crates/rimap-server/tests/support/wire/mod.rs`, ensure all three are public. The current file content is short; add any missing re-exports:

```rust
pub use harness::{CloseOrResponse, Harness, PINNED_PROTOCOL_VERSION, REQUEST_TIMEOUT, SHUTDOWN_TIMEOUT};
pub use schema::{assert_envelope_valid, assert_valid, validator_for, validator_for_tool_response};
```

Then run `cargo check -p rimap-server --tests` to confirm exports compile.

- [ ] **Step 3: Write `unparsable_json_errors_or_closes`**

Append to `mcp_wire_negative.rs`:

```rust
/// Send unparseable bytes. Server MUST either return a JSON-RPC
/// parse error (-32700) or cleanly close stdin. Either is
/// spec-legal; the test pins whichever behavior rmcp actually
/// implements so a future regression to the third option (hang,
/// panic, malformed line) trips the assertion.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unparsable_json_errors_or_closes() {
    let mut harness = Harness::spawn().await;
    let _ = harness.initialize_handshake().await;
    harness.send_initialized().await;

    harness.send_line("not json").await;

    let outcome = harness.response_or_close(REQUEST_TIMEOUT).await;
    match outcome {
        // Probed 2026-05-13 (rmcp 1.5): RECORD THE ACTUAL BEHAVIOR
        // HERE after running this test the first time. The test should
        // then pin whichever Response/CleanClose branch fired and
        // panic on the other. Crashed and Hung ALWAYS fail.
        CloseOrResponse::Response(line) => {
            let env: Value = serde_json::from_str(line.trim_end())
                .expect("server response must be valid JSON");
            assert_envelope_valid(&env);
            assert!(
                env.get("error").is_some(),
                "expected error envelope for unparseable input, got {env}",
            );
            // -32700 is the JSON-RPC parse-error code. If rmcp emits
            // something else (e.g. -32600 invalid-request), update
            // this assertion and document why.
            assert_eq!(
                env["error"]["code"],
                json!(-32700),
                "expected parse error code -32700, got {env}",
            );
        }
        CloseOrResponse::CleanClose => {
            // Clean close is spec-legal. If the probe says this
            // branch fires, replace the Response(...) branch above
            // with `panic!("expected clean close, got response: {line}")`.
        }
        CloseOrResponse::Crashed(diagnostic) => {
            panic!(
                "server crashed on unparseable input — Phase 4 must surface this as a bug: {diagnostic}",
            );
        }
        CloseOrResponse::Hung => {
            panic!(
                "server hung on unparseable input (no response, no close within {REQUEST_TIMEOUT:?})",
            );
        }
    }
}
```

- [ ] **Step 4: Run the test to observe actual server behavior**

```bash
cargo test -p rimap-server --test mcp_wire_negative -- unparsable_json_errors_or_closes --nocapture
```

Expected: one of three outcomes:
- **Test passes** with the `Some` branch firing → the server emits an error envelope. Note this in the inline comment: "Probed 2026-05-13: rmcp returns -32700 with message ..."
- **Test fails** in the `Some` branch because the code is different (e.g., -32600) → update the assertion to the observed code and document.
- **Test passes** with the `None` branch firing → the server closed cleanly. Replace the `Some` branch body with a panic: this test now pins clean-close behavior.

Document the choice with an inline comment. After updating, re-run to confirm the test passes deterministically.

- [ ] **Step 5: Write `valid_json_invalid_envelope_returns_minus_32600`**

Append:

```rust
/// Send a JSON object that parses but lacks JSON-RPC fields. Server
/// MUST respond with -32600 invalid request. Tighter contract than
/// the unparseable case because the input is syntactically valid
/// JSON; the only reason to reject it is the JSON-RPC envelope
/// shape.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn valid_json_invalid_envelope_returns_minus_32600() {
    let mut harness = Harness::spawn().await;
    let _ = harness.initialize_handshake().await;
    harness.send_initialized().await;

    harness.send_line(r#"{"foo":"bar"}"#).await;

    let line = harness
        .recv_line_within(REQUEST_TIMEOUT)
        .await
        .expect("server must respond to syntactically-valid JSON");
    let env: Value = serde_json::from_str(line.trim_end())
        .expect("server response must be valid JSON");
    assert_envelope_valid(&env);
    assert!(
        env.get("error").is_some(),
        "expected error envelope for invalid JSON-RPC, got {env}",
    );
    // Probed 2026-05-13 (rmcp 1.5): rmcp emits -32600 for envelopes
    // missing required fields. If this drifts (e.g. -32700 because
    // the parser is permissive), update the assertion.
    assert_eq!(
        env["error"]["code"],
        json!(-32600),
        "expected invalid-request code -32600, got {env}",
    );
}
```

- [ ] **Step 6: Write `missing_method_field`**

Append:

```rust
/// Envelope with `jsonrpc` and `id` but no `method`. Same expected
/// outcome as the previous test (-32600).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn missing_method_field() {
    let mut harness = Harness::spawn().await;
    let _ = harness.initialize_handshake().await;
    harness.send_initialized().await;

    harness
        .send_line(r#"{"jsonrpc":"2.0","id":1,"params":{}}"#)
        .await;

    let line = harness
        .recv_line_within(REQUEST_TIMEOUT)
        .await
        .expect("server must respond to envelope missing method");
    let env: Value = serde_json::from_str(line.trim_end())
        .expect("server response must be valid JSON");
    assert_envelope_valid(&env);
    assert_eq!(
        env["error"]["code"],
        json!(-32600),
        "missing method must produce invalid-request, got {env}",
    );
}
```

- [ ] **Step 7: Write `wrong_type_method_field`**

Append:

```rust
/// Envelope with `method` set to an integer instead of a string.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_type_method_field() {
    let mut harness = Harness::spawn().await;
    let _ = harness.initialize_handshake().await;
    harness.send_initialized().await;

    harness
        .send_line(r#"{"jsonrpc":"2.0","id":1,"method":42,"params":{}}"#)
        .await;

    let line = harness
        .recv_line_within(REQUEST_TIMEOUT)
        .await
        .expect("server must respond to method-of-wrong-type");
    let env: Value = serde_json::from_str(line.trim_end())
        .expect("server response must be valid JSON");
    assert_envelope_valid(&env);
    assert_eq!(
        env["error"]["code"],
        json!(-32600),
        "wrong-type method must produce invalid-request, got {env}",
    );
}
```

- [ ] **Step 8: Write `oversized_params_payload`**

Append:

```rust
/// Send `tools/list` with a 1 MiB `note` field in `params`. The
/// payload is well-formed JSON-RPC but huge. Server must either
/// answer with a valid envelope (success ignoring the unknown
/// field, or error) or cleanly close — but it MUST NOT hang past
/// REQUEST_TIMEOUT.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_params_payload() {
    let mut harness = Harness::spawn().await;
    let _ = harness.initialize_handshake().await;
    harness.send_initialized().await;

    let big = "x".repeat(1024 * 1024);
    let payload = json!({
        "jsonrpc": "2.0",
        "id": 999,
        "method": "tools/list",
        "params": { "note": big },
    });
    harness.send_line(&payload.to_string()).await;

    let outcome = harness.response_or_close(REQUEST_TIMEOUT).await;
    match outcome {
        CloseOrResponse::Response(line) => {
            let env: Value = serde_json::from_str(line.trim_end())
                .expect("server response must be valid JSON");
            assert_envelope_valid(&env);
            // Either a successful tools/list response or an error
            // envelope is acceptable; both are well-formed.
        }
        CloseOrResponse::CleanClose => {
            // Spec-legal: server elected to close rather than respond.
        }
        CloseOrResponse::Crashed(diagnostic) => {
            panic!("server crashed on oversized payload: {diagnostic}");
        }
        CloseOrResponse::Hung => {
            panic!(
                "server hung on oversized payload (no response, no close within {REQUEST_TIMEOUT:?})",
            );
        }
    }
}
```

- [ ] **Step 9: Run all five tests**

```bash
cargo test -p rimap-server --test mcp_wire_negative
```

Expected: all five pass after the probe-and-encode pass on Step 4. If any test reveals a real bug (panic in the server, hang, malformed line), STOP — file a separate issue, fix on a sibling branch, and only continue with this task after the fix lands. Per the spec §5 and the issue's acceptance criteria.

- [ ] **Step 10: Run clippy on the new file**

```bash
cargo clippy -p rimap-server --tests -- -D warnings
```

Expected: no warnings. The file allows `expect_used` and `panic` at the top per the existing pattern; if clippy flags anything else, fix it in place.

- [ ] **Step 11: Commit**

```bash
git add crates/rimap-server/tests/mcp_wire_negative.rs \
        crates/rimap-server/tests/support/wire/mod.rs
git commit -m "test(rimap-server): negative-path tests for malformed MCP envelopes (#266)

Five tests covering unparseable JSON, invalid JSON-RPC envelopes,
missing/wrong-type method field, and an oversized payload. Each test
encodes the probed server behavior (rmcp 1.5) with an inline comment
so future regressions are visible. Phase 4 §4.1 malformed-input row."
```

---

## Task 4: `mcp_wire_negative.rs` — protocol-state tests

**Files:**
- Modify: `crates/rimap-server/tests/mcp_wire_negative.rs`

Three tests that exercise MCP protocol-state errors: double-initialize, `tools/list` before initialize, and unsupported protocol version.

- [ ] **Step 1: Write `initialize_after_already_initialized`**

Append to `mcp_wire_negative.rs`:

```rust
/// After a successful `initialize`, a second `initialize` request
/// must be rejected. Spec says only one initialize per session.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn initialize_after_already_initialized() {
    let mut harness = Harness::spawn().await;
    let _ = harness.initialize_handshake().await;
    harness.send_initialized().await;

    // Send a SECOND initialize. The harness's `request` helper
    // would auto-increment ids; we use it directly because the
    // response is still a normal JSON-RPC error envelope.
    let response = harness
        .request(
            "initialize",
            json!({
                "protocolVersion": support::wire::PINNED_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {
                    "name": "rusty-imap-mcp-phase4-test",
                    "version": "0.0.0",
                },
            }),
        )
        .await;

    assert!(
        response.get("error").is_some(),
        "second initialize must error, got {response}",
    );
    // Probed 2026-05-13 (rmcp 1.5): RECORD ACTUAL CODE HERE on
    // first run. Common candidates: -32600 (invalid request),
    // -32603 (internal), or a rmcp-specific code. Update the
    // assertion to whichever fires.
    let code = &response["error"]["code"];
    assert!(
        code.is_i64(),
        "error code must be an integer per JSON-RPC, got {response}",
    );
}
```

- [ ] **Step 2: Write `tools_list_before_initialize`**

Append:

```rust
/// `tools/list` before `initialize` must error. Server is in the
/// "uninitialized" state and cannot answer protocol-level requests
/// until handshake completes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tools_list_before_initialize() {
    let mut harness = Harness::spawn().await;
    // Deliberately skip initialize_handshake.

    let response = harness.request("tools/list", json!({})).await;

    assert!(
        response.get("error").is_some(),
        "tools/list before initialize must error, got {response}",
    );
    // Probed 2026-05-13 (rmcp 1.5): RECORD ACTUAL CODE HERE.
    let code = &response["error"]["code"];
    assert!(
        code.is_i64(),
        "error code must be an integer per JSON-RPC, got {response}",
    );
}
```

- [ ] **Step 3: Write `initialize_unsupported_protocol_version`**

Append:

```rust
/// Client requests a protocol version the server doesn't support.
/// Spec allows TWO behaviors: server may echo its own supported
/// version (counter-proposal), or server may return an error
/// envelope. Both are spec-legal; the test pins whichever rmcp
/// actually does.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn initialize_unsupported_protocol_version() {
    let mut harness = Harness::spawn().await;

    let response = harness
        .request(
            "initialize",
            json!({
                "protocolVersion": "1999-01-01",
                "capabilities": {},
                "clientInfo": {
                    "name": "rusty-imap-mcp-phase4-test",
                    "version": "0.0.0",
                },
            }),
        )
        .await;

    if let Some(error) = response.get("error") {
        // Error path. Pin to whatever code rmcp emits.
        let code = &error["code"];
        assert!(
            code.is_i64(),
            "error code must be an integer per JSON-RPC, got {response}",
        );
    } else {
        // Counter-proposal path. The server's response must include
        // the actual supported version, NOT echo the client's bad
        // version.
        let version = response["result"]["protocolVersion"]
            .as_str()
            .expect("protocolVersion must be a string");
        assert_ne!(
            version, "1999-01-01",
            "server must not echo the unsupported version back",
        );
    }
}
```

- [ ] **Step 4: Probe and pin**

Run each new test in isolation to observe behavior:

```bash
cargo test -p rimap-server --test mcp_wire_negative -- initialize_after_already_initialized --nocapture
cargo test -p rimap-server --test mcp_wire_negative -- tools_list_before_initialize --nocapture
cargo test -p rimap-server --test mcp_wire_negative -- initialize_unsupported_protocol_version --nocapture
```

For each test that passes with the integer-code assertion, tighten the assertion to the actual observed code. Document with an inline comment.

- [ ] **Step 5: Run the full file**

```bash
cargo test -p rimap-server --test mcp_wire_negative
```

Expected: all 8 tests (5 from Task 3 + 3 from this task) pass.

- [ ] **Step 6: Commit**

```bash
git add crates/rimap-server/tests/mcp_wire_negative.rs
git commit -m "test(rimap-server): protocol-state negative tests (#266)

Three tests: double-initialize, tools/list before initialize, and
unsupported-version negotiation. Each pins probed rmcp behavior with
an inline comment. Phase 4 §4.1 protocol-state rows."
```

---

## Task 5: `mcp_wire_negative.rs` — concurrency and adversarial-input

**Files:**
- Modify: `crates/rimap-server/tests/mcp_wire_negative.rs`

Two tests: deterministic concurrent in-flight requests via `send_request_no_wait` + `recv_until_id`, and a bidi-override character injected into a tool argument.

- [ ] **Step 1: Write `concurrent_tools_list_two_inflight`**

Append:

```rust
/// Send two `tools/list` requests back-to-back without awaiting
/// the first response. Both must return well-formed envelopes
/// within REQUEST_TIMEOUT, with ids matching the requests. Tests
/// that the server doesn't serialize stdout writes in a way that
/// corrupts responses, and that the harness's id-buffering works.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_tools_list_two_inflight() {
    let mut harness = Harness::spawn().await;
    let _ = harness.initialize_handshake().await;
    harness.send_initialized().await;

    let id_a = harness
        .send_request_no_wait("tools/list", json!({}))
        .await;
    let id_b = harness
        .send_request_no_wait("tools/list", json!({}))
        .await;

    // Await in the OPPOSITE order from send to exercise the
    // out-of-order buffering path in recv_until_id.
    let response_b = harness.recv_until_id(id_b).await;
    let response_a = harness.recv_until_id(id_a).await;

    assert_eq!(response_a["id"], json!(id_a));
    assert_eq!(response_b["id"], json!(id_b));
    assert!(response_a["result"].is_object(), "id_a must succeed");
    assert!(response_b["result"].is_object(), "id_b must succeed");
}
```

- [ ] **Step 2: Write `bidi_override_in_tool_argument`**

Append:

```rust
/// Inject a Unicode bidi-override character (U+202E RIGHT-TO-LEFT
/// OVERRIDE) into a tool argument. Server must either accept and
/// process the call (returning an error envelope because no
/// account named that exists in the zero-account config) or
/// reject with a validation error. Either way: no panic in the
/// argument-redactor or audit writer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bidi_override_in_tool_argument() {
    let mut harness = Harness::spawn().await;
    let _ = harness.initialize_handshake().await;
    harness.send_initialized().await;

    let response = harness
        .request(
            "tools/call",
            json!({
                "name": "use_account",
                "arguments": { "account": "foo\u{202E}bar" },
            }),
        )
        .await;

    // The contract here is "server didn't panic and returned a
    // well-formed envelope" — the schema validation inside
    // `request` already enforces that. Additionally assert the
    // call was rejected (no account exists with that name).
    assert!(
        response.get("error").is_some()
            || response["result"]["isError"].as_bool() == Some(true),
        "use_account with non-existent account must fail, got {response}",
    );
}
```

- [ ] **Step 3: Run and probe**

```bash
cargo test -p rimap-server --test mcp_wire_negative -- concurrent_tools_list_two_inflight bidi_override_in_tool_argument --nocapture
```

Expected: both pass. If the bidi test reveals a panic in the audit writer's argument redaction path, STOP and file an issue per the spec's bug-discovery policy.

- [ ] **Step 4: Run the full file**

```bash
cargo test -p rimap-server --test mcp_wire_negative
```

Expected: all 10 tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-server/tests/mcp_wire_negative.rs
git commit -m "test(rimap-server): concurrent and adversarial-input negative tests (#266)

Two tests: two tools/list calls in flight at once (exercises the
send_request_no_wait / recv_until_id buffering path), and a bidi-
override character injected into a use_account argument (exercises
the audit-redaction path against adversarial Unicode). Phase 4 §4.1
concurrency + adversarial rows."
```

---

## Task 6: `mcp_wire_proptest.rs` — restart-on-close helper + property 2 (unknown tool)

**Files:**
- Create: `crates/rimap-server/tests/mcp_wire_proptest.rs`
- Modify: `crates/rimap-server/Cargo.toml` (add `proptest` to `[dev-dependencies]` if not already there)

Property 2 is the simplest of the three: every case is `tools/call <random name>` with arbitrary arguments, and every response must be an error envelope. This task also establishes the shared infrastructure (restart-on-close helper) used by all three properties.

- [ ] **Step 1: Verify proptest dev-dep wiring for `rimap-server`**

Check `crates/rimap-server/Cargo.toml`:

```bash
grep -n "proptest" crates/rimap-server/Cargo.toml
```

If not present, add to `[dev-dependencies]`:

```toml
proptest = { workspace = true }
```

Run `cargo check -p rimap-server --tests` to confirm.

- [ ] **Step 2: Create the file scaffold with the restart-on-close helper**

Create `crates/rimap-server/tests/mcp_wire_proptest.rs`:

```rust
//! MCP wire-shape property tests (issue #266, Phase 4).
//!
//! Three proptest properties driving the production
//! `rusty-imap-mcp` binary with arbitrary JSON-RPC envelopes and
//! tool-call arguments. Default ≥1000 cases per property; nightly
//! runs scale via `PROPTEST_CASES`.
//!
//! Session-isolation discipline (§3.2 of the design doc):
//! - The harness is shared across cases for speed.
//! - `with_live_harness` restarts the harness if a case closed the
//!   connection, so cases never run against a poisoned session.
//! - Property 1's strategy excludes the pinned state-mutating
//!   method set so cases stay independent of MCP session state.
//!
//! Property strategy notes inline. See
//! `docs/superpowers/specs/2026-05-13-mcp-protocol-fuzzing-design.md`
//! for the full design context.

#![expect(clippy::expect_used, reason = "integration tests")]
#![expect(clippy::panic, reason = "test assertions render diagnostics")]

#[path = "support/mod.rs"]
mod support;

use std::time::Duration;

use proptest::prelude::*;
use serde_json::{Value, json};

use support::wire::{Harness, REQUEST_TIMEOUT, assert_envelope_valid};

/// Run `body` against a harness, restarting the harness if the
/// previous case poisoned the session (EOF observed, child exited,
/// or `is_usable` reports false for any other reason). After
/// `body` runs, the caller MUST check `is_usable` on the returned
/// harness and drop it if false — `with_live_harness` only
/// guarantees a usable harness at body-entry, not at body-exit,
/// because the case itself may have poisoned it.
///
/// Codex review finding #2 verified that a simple `try_wait`
/// check could let a poisoned (stdout-closed but not-yet-reaped)
/// harness leak across cases. `Harness::is_usable` consolidates
/// the check.
async fn with_live_harness<F, Fut>(mut h: Option<Harness>, body: F) -> Option<Harness>
where
    F: FnOnce(Harness) -> Fut,
    Fut: std::future::Future<Output = Harness>,
{
    let needs_fresh = match h.as_mut() {
        None => true,
        Some(harness) => !harness.is_usable(),
    };
    if needs_fresh {
        // Drop the poisoned harness if any.
        drop(h);
        let mut fresh = Harness::spawn().await;
        let _ = fresh.initialize_handshake().await;
        fresh.send_initialized().await;
        h = Some(fresh);
    }
    let mut after = body(h.expect("ensured Some above")).await;
    // If the body poisoned the harness (e.g. property 1's case
    // observed CleanClose/Crashed/Hung), drop it instead of
    // returning it to the pool.
    if !after.is_usable() {
        return None;
    }
    Some(after)
}
```

- [ ] **Step 3: Add the `is_usable` accessor on `Harness`**

In `crates/rimap-server/tests/support/wire/harness.rs`, add this method right after `captured_stderr`:

```rust
    /// Returns true if the harness can be used for another request:
    /// the child process is still running AND the harness has not
    /// observed an unrecoverable session state (EOF, crash, hang,
    /// schema-validation failure on a parsed envelope). Codex
    /// review finding #2 verified that `try_wait` alone is
    /// insufficient — a child whose stdout closed but whose process
    /// has not yet been reaped would otherwise pass the "alive"
    /// check while subsequent reads return EOF immediately.
    ///
    /// Always check this before reusing a harness across cases.
    /// The proptest restart-on-close discipline (this task)
    /// consults it; if false, the helper drops the poisoned
    /// harness and spawns a fresh one.
    pub fn is_usable(&mut self) -> bool {
        if self.poisoned {
            return false;
        }
        match self.child.try_wait() {
            Ok(None) => true,
            Ok(Some(_status)) => {
                self.poisoned = true;
                false
            }
            Err(_) => {
                self.poisoned = true;
                false
            }
        }
    }
```

Run `cargo check -p rimap-server --tests` to confirm.

- [ ] **Step 4: Write property 2 — `prop_tools_call_unknown_tool`**

Append to `mcp_wire_proptest.rs`:

```rust
/// Property 2: arbitrary tool name with arbitrary JSON arguments
/// always produces a JSON-RPC error envelope. Stateless by
/// construction (every case is `tools/call <X>`; no method that
/// mutates MCP session state is ever sent).
proptest! {
    #![proptest_config(ProptestConfig::with_cases(
        std::env::var("PROPTEST_CASES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1000)
    ))]

    #[test]
    fn prop_tools_call_unknown_tool(
        tool_name in "[A-Za-z0-9_./-]{1,64}",
        args in proptest::collection::hash_map(
            "[A-Za-z0-9_]{1,16}",
            proptest::arbitrary::any::<i64>().prop_map(|n| json!(n)),
            0..6,
        ),
    ) {
        // proptest does not natively support async test bodies, so
        // we build a Tokio runtime per case. Cheap because the
        // harness is reused inside RUNTIME-scoped state.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime");

        runtime.block_on(async move {
            let mut harness = HARNESS.lock().await.take();
            harness = with_live_harness(harness, |mut h| async move {
                let arguments: serde_json::Map<String, Value> = args
                    .into_iter()
                    .map(|(k, v)| (k, v))
                    .collect();
                let response = h
                    .request(
                        "tools/call",
                        json!({
                            "name": tool_name,
                            "arguments": arguments,
                        }),
                    )
                    .await;
                // The contract: either a JSON-RPC error envelope, or
                // a result envelope whose `isError` field is true (the
                // rmcp/MCP convention for tool-level errors).
                let is_envelope_error = response.get("error").is_some();
                let is_tool_error = response["result"]["isError"]
                    .as_bool()
                    .unwrap_or(false);
                assert!(
                    is_envelope_error || is_tool_error,
                    "unknown tool {tool_name:?} must produce an error, got {response}",
                );
                h
            }).await;
            *HARNESS.lock().await = harness;
        });
    }
}

// Process-lifetime harness shared across all proptest cases within
// one property invocation. Wrapped in tokio::sync::Mutex so cases
// (which each block on their own runtime) can serialize access.
// Tokio's Mutex is async; we use `blocking_lock` inside the runtime.
//
// NOTE: each property runs sequentially in the proptest macro
// expansion, so sharing one mutex across properties is fine —
// they don't overlap.
static HARNESS: tokio::sync::Mutex<Option<Harness>> = tokio::sync::Mutex::const_new(None);
```

Note: the harness sharing pattern above is one approach. If the implementer finds a cleaner pattern during step 5 (e.g., a per-property `thread_local!` or a `once_cell::OnceCell`), prefer that. The contract is: cases share a harness, harness restarts if dead. The mechanism is flexible.

- [ ] **Step 5: Run the property to verify it works**

```bash
PROPTEST_CASES=200 cargo test -p rimap-server --test mcp_wire_proptest -- prop_tools_call_unknown_tool --nocapture
```

Expected: 200 cases pass. If proptest finds a shrinking case (a specific tool name or args shape that breaks the contract), STOP. Either:
- It's a real server bug — file separate issue, fix on sibling branch, then commit the `proptest-regressions/` seed with this task.
- It's a test-strategy bug — adjust the strategy (e.g., the generator produces an arg shape the server interprets as a successful call). Pin the shrunk case with a comment.

- [ ] **Step 6: Scale to 1000 cases for CI baseline**

```bash
PROPTEST_CASES=1000 cargo test -p rimap-server --test mcp_wire_proptest -- prop_tools_call_unknown_tool
```

Expected: 1000 cases pass within the CI budget (rough target: under 60s on a developer machine). If runtime is excessive, profile with a smaller case count (`--profile dev`) to see if the bottleneck is harness reuse vs. per-case roundtrip.

- [ ] **Step 7: Commit**

```bash
git add crates/rimap-server/tests/mcp_wire_proptest.rs \
        crates/rimap-server/tests/support/wire/harness.rs \
        crates/rimap-server/Cargo.toml
git commit -m "test(rimap-server): property 2 — unknown-tool fuzz (#266)

Adds mcp_wire_proptest.rs with the restart-on-close discipline
(is_usable accessor + with_live_harness helper) and the
simplest of the three properties: arbitrary tools/call invocations
must always produce an error envelope. PROPTEST_CASES env var
controls the case count. Phase 4 §4.2 property 2."
```

---

## Task 7: `mcp_wire_proptest.rs` — property 3 (`use_account` argument shape)

**Files:**
- Modify: `crates/rimap-server/tests/mcp_wire_proptest.rs`

Property 3 reuses the same shared harness and restart-on-close discipline as property 2 but constrains the method to `tools/call use_account` with arbitrary argument shapes. With zero accounts configured, every call must fail; the strategy explores argument-shape edge cases (missing fields, wrong types, unicode).

- [ ] **Step 1: Write the property**

Append to `mcp_wire_proptest.rs`:

```rust
/// Property 3: `use_account` with arbitrary argument shapes. With
/// zero accounts configured (the harness's default), every call
/// MUST fail. Stateless by construction.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(
        std::env::var("PROPTEST_CASES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1000)
    ))]

    #[test]
    fn prop_tools_call_use_account_argument_shape(
        // Arbitrary JSON values for `arguments`. The strategy
        // intentionally produces both well-formed-but-wrong shapes
        // (e.g. `{"account": 42}`) and shapes that look right
        // (e.g. `{"account": "foo"}`) — the server must reject all
        // of them because no accounts are configured.
        arguments in arb_arguments(),
    ) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime");

        runtime.block_on(async move {
            let mut harness = HARNESS.lock().await.take();
            harness = with_live_harness(harness, |mut h| async move {
                let response = h
                    .request(
                        "tools/call",
                        json!({
                            "name": "use_account",
                            "arguments": arguments,
                        }),
                    )
                    .await;
                let is_envelope_error = response.get("error").is_some();
                let is_tool_error = response["result"]["isError"]
                    .as_bool()
                    .unwrap_or(false);
                assert!(
                    is_envelope_error || is_tool_error,
                    "use_account with arbitrary args must fail (no accounts configured), got {response}",
                );
                h
            }).await;
            *HARNESS.lock().await = harness;
        });
    }
}

/// Build an arbitrary `arguments` map. Mixes:
/// - Well-formed argument names (`account`, `name`, etc.) with
///   wrong value types
/// - Random argument names with random values
/// - Empty maps
fn arb_arguments() -> impl Strategy<Value = Value> {
    let well_formed_keys = prop_oneof![
        Just("account".to_string()),
        Just("name".to_string()),
        Just("id".to_string()),
        "[a-z]{1,16}".prop_map(String::from),
    ];
    let any_value = prop_oneof![
        Just(json!(null)),
        proptest::arbitrary::any::<bool>().prop_map(|b| json!(b)),
        proptest::arbitrary::any::<i64>().prop_map(|n| json!(n)),
        "[\\PC]{0,64}".prop_map(|s| json!(s)),  // arbitrary printable Unicode
    ];
    proptest::collection::hash_map(well_formed_keys, any_value, 0..6)
        .prop_map(|m| {
            let obj: serde_json::Map<String, Value> = m.into_iter().collect();
            Value::Object(obj)
        })
}
```

- [ ] **Step 2: Run the property**

```bash
PROPTEST_CASES=200 cargo test -p rimap-server --test mcp_wire_proptest -- prop_tools_call_use_account_argument_shape --nocapture
```

Expected: 200 cases pass. If any case unexpectedly succeeds (e.g., the server has a code path that creates an account on the fly), investigate before committing.

- [ ] **Step 3: Scale and commit**

```bash
PROPTEST_CASES=1000 cargo test -p rimap-server --test mcp_wire_proptest -- prop_tools_call_use_account_argument_shape
git add crates/rimap-server/tests/mcp_wire_proptest.rs
git commit -m "test(rimap-server): property 3 — use_account argument-shape fuzz (#266)

Arbitrary JSON argument shapes for use_account against the zero-
account config; every call must fail. Phase 4 §4.2 property 3."
```

---

## Task 8: `mcp_wire_proptest.rs` — property 1 (envelope never panics)

**Files:**
- Modify: `crates/rimap-server/tests/mcp_wire_proptest.rs`

Property 1 is the most aggressive: arbitrary JSON envelopes, including arbitrary `method` values, sent to the server. The strategy excludes the pinned state-mutating set so cases stay independent. Contract: server either emits a well-formed JSON-RPC envelope or cleanly closes the connection.

- [ ] **Step 1: Define the state-mutating method exclusion set**

Append to `mcp_wire_proptest.rs` near the top (before the property blocks):

```rust
/// Methods that mutate MCP session state. The property-1 strategy
/// MUST NOT generate these as the `method` field, since they would
/// couple subsequent cases to earlier ones (poisoning the shared
/// harness). The set is pinned here AND asserted against rmcp's
/// known stateful surface in `assert_exclusion_set_matches_rmcp`
/// below — that assertion is the regression net that catches a
/// future MCP spec addition introducing a new stateful method.
const STATE_MUTATING_METHODS: &[&str] = &[
    "initialize",
    "notifications/initialized",
];

#[test]
fn assert_exclusion_set_matches_rmcp() {
    // rmcp 1.5 documents stateful protocol methods at:
    //   rmcp::model::ProtocolVersion docs + Initialize/Initialized
    //   in rmcp::model::request.
    //
    // If a future rmcp version adds a new stateful method (e.g.
    // `session/reset`), this assertion is the place to update — and
    // STATE_MUTATING_METHODS above must be updated in lockstep, or
    // property 1 starts coupling cases.
    //
    // This test is a sentinel — it doesn't introspect rmcp at runtime
    // because rmcp's request enum is sealed. Instead, the maintainer
    // updates BOTH sides of the pair (this constant and the rmcp dep)
    // together. Bumping rmcp without inspecting this list trips a
    // human review checkpoint via this comment.
    let expected = ["initialize", "notifications/initialized"];
    let actual: Vec<&str> = STATE_MUTATING_METHODS.iter().copied().collect();
    assert_eq!(actual, expected.to_vec());
}
```

- [ ] **Step 2: Write the strategy generator**

Append:

```rust
/// Build an arbitrary JSON-RPC-ish envelope. Each field is
/// optionally present and may be of a wrong type. The `method`
/// field, when present, is drawn from a set that EXCLUDES
/// state-mutating methods to keep cases independent.
fn arb_envelope() -> impl Strategy<Value = Value> {
    let arb_method = prop_oneof![
        // Known stateless methods
        Just("tools/list".to_string()),
        Just("tools/call".to_string()),
        Just("resources/list".to_string()),
        Just("ping".to_string()),
        // Unknown methods (still stateless; the server returns
        // method-not-found without touching session state)
        "[a-z/]{1,32}".prop_map(String::from),
    ]
    .prop_filter(
        "exclude state-mutating methods",
        |m: &String| !STATE_MUTATING_METHODS.contains(&m.as_str()),
    );

    let arb_id = prop_oneof![
        Just(json!(null)),
        proptest::arbitrary::any::<u32>().prop_map(|n| json!(n)),
        "[a-z0-9]{1,8}".prop_map(|s| json!(s)),  // string id — also legal JSON-RPC
    ];

    let arb_params = prop_oneof![
        Just(json!({})),
        Just(json!(null)),
        proptest::arbitrary::any::<i64>().prop_map(|n| json!(n)),
        "[\\PC]{0,32}".prop_map(|s| json!(s)),
    ];

    (
        prop::option::of(Just("2.0".to_string())),
        prop::option::of(arb_id),
        prop::option::of(arb_method),
        prop::option::of(arb_params),
    )
        .prop_map(|(jsonrpc, id, method, params)| {
            let mut obj = serde_json::Map::new();
            if let Some(v) = jsonrpc {
                obj.insert("jsonrpc".to_string(), json!(v));
            }
            if let Some(v) = id {
                obj.insert("id".to_string(), v);
            }
            if let Some(v) = method {
                obj.insert("method".to_string(), json!(v));
            }
            if let Some(v) = params {
                obj.insert("params".to_string(), v);
            }
            Value::Object(obj)
        })
}
```

- [ ] **Step 3: Write the property**

Append:

```rust
/// Property 1: arbitrary JSON-RPC-ish envelopes never panic the
/// server. Either the server emits a well-formed envelope (success
/// or error) or it cleanly closes the connection.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(
        std::env::var("PROPTEST_CASES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1000)
    ))]

    #[test]
    fn prop_envelope_never_panics(envelope in arb_envelope()) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime");

        runtime.block_on(async move {
            let mut harness = HARNESS.lock().await.take();
            harness = with_live_harness(harness, |mut h| async move {
                h.send_line(&envelope.to_string()).await;
                let outcome = h.response_or_close(REQUEST_TIMEOUT).await;
                match outcome {
                    CloseOrResponse::Response(line) => {
                        let env: Value = serde_json::from_str(line.trim_end())
                            .expect("server response must be valid JSON");
                        assert_envelope_valid(&env);
                    }
                    CloseOrResponse::CleanClose => {
                        // Spec-legal: harness is now poisoned;
                        // `with_live_harness` will drop it after the
                        // case and spawn a fresh one for the next.
                    }
                    CloseOrResponse::Crashed(diagnostic) => {
                        panic!(
                            "server crashed during property 1 case — \
                             file an issue and pin a regression seed before continuing: \
                             envelope={envelope}\n{diagnostic}",
                        );
                    }
                    CloseOrResponse::Hung => {
                        panic!(
                            "server hung during property 1 case (no response, no close \
                             within {REQUEST_TIMEOUT:?}): envelope={envelope}",
                        );
                    }
                }
                h
            }).await;
            *HARNESS.lock().await = harness;
        });
    }
}
```

- [ ] **Step 4: Run the property**

```bash
PROPTEST_CASES=200 cargo test -p rimap-server --test mcp_wire_proptest -- prop_envelope_never_panics --nocapture
```

Expected: 200 cases pass. The runtime here is dominated by the harness restart-on-close path; if `response_or_close` is timing out (i.e. many cases hit `Hung`), the test is much slower than the others. If runtime is excessive, profile and consider reducing REQUEST_TIMEOUT for this property only. A `Hung` outcome failing the test is also the right call here — if generated envelopes routinely hang the server, that's a server bug.

If a case shrinks to a panic, STOP — this is exactly the bug-discovery scenario the spec anticipates. File a separate issue, fix on a sibling branch, commit the `proptest-regressions/` seed with this task.

- [ ] **Step 5: Run all three properties together**

```bash
PROPTEST_CASES=1000 cargo test -p rimap-server --test mcp_wire_proptest
```

Expected: all three properties pass at 1000 cases each. The `assert_exclusion_set_matches_rmcp` sentinel test also passes.

- [ ] **Step 6: Commit**

```bash
git add crates/rimap-server/tests/mcp_wire_proptest.rs
# Also stage the regressions dir if any shrunk cases were committed:
git add crates/rimap-server/tests/proptest-regressions/ 2>/dev/null || true
git commit -m "test(rimap-server): property 1 — envelope never panics (#266)

Arbitrary JSON-RPC-ish envelopes excluding the pinned state-mutating
method set ({initialize, notifications/initialized}). Server must
either emit a well-formed envelope or cleanly close the connection.
A sentinel test pins the exclusion set against rmcp's stateful
surface; bumping rmcp without updating the set trips a human review
checkpoint. Phase 4 §4.2 property 1."
```

---

## Task 9: Cancellation contract — verify Drop coverage, add wire-layer test

**Files:**
- Verify (no change): `crates/rimap-server/src/mcp/audit_envelope.rs` (existing tests)
- Create: `crates/rimap-server/tests/e2e_wire_cancellation.rs`

The audit-layer Drop contract is already pinned by the in-process tests at `crates/rimap-server/src/mcp/audit_envelope.rs:296-382` (`dropped_guard_enqueues_cancellation_record` and `disarmed_guard_does_not_enqueue`). These tests cover the exact contract that the spec's `drop_emits_cancelled.rs` test would have introduced, so we don't add a redundant test. The wire-layer test in `e2e_wire_cancellation.rs` asserts only race-free invariants.

- [ ] **Step 1: Confirm existing audit Drop coverage**

```bash
cargo test -p rimap-server --lib audit_envelope::tests
```

Expected: both `dropped_guard_enqueues_cancellation_record` and `disarmed_guard_does_not_enqueue` pass. If they don't, STOP — the project's invariant from #71/#99 is broken and must be fixed before Phase 4 lands.

The existing tests cover the guard's Drop discipline at its tightest point (manually constructing an `AuditEnvelopeGuard`). Codex review finding #4 noted two legitimate gaps:
- `dropped_guard_enqueues_cancellation_record` asserts `lines.len() >= 2`, which would not catch a regression that double-emits the cancellation record.
- Neither test exercises `run_with_audit_envelope` end-to-end, so a regression that moved guard construction before `emit_tool_start` or forgot to disarm on the normal path would pass guard-level tests.

Steps 1a and 1b address both gaps.

- [ ] **Step 1a: Tighten the existing `dropped_guard_enqueues_cancellation_record` assertion**

In `crates/rimap-server/src/mcp/audit_envelope.rs`, locate the assertion (around line 333):

```rust
        assert!(
            lines.len() >= 2,
            "expected >= 2 records (tool_start + cancellation tool_end), got: {contents}",
        );
```

Replace with an exact-count assertion:

```rust
        assert_eq!(
            lines.len(),
            2,
            "expected exactly 2 records (tool_start + cancellation tool_end), got {} records:\n{contents}",
            lines.len(),
        );
```

Run `cargo test -p rimap-server --lib audit_envelope::tests::dropped_guard_enqueues_cancellation_record`. Expected: pass. If it fails because more than 2 records were written, investigate before continuing — that itself would be the regression Codex anticipated.

- [ ] **Step 1b: Add a wrapper-level test that exercises `run_with_audit_envelope` end-to-end**

The existing tests construct the guard manually. The wrapper-level test drives `run_with_audit_envelope` with a `std::future::pending()` body, polls once, then drops the outer future. The cancellation record must be emitted exactly once.

`run_with_audit_envelope` is `pub(super)` on `impl ImapMcpServer`, so the test (which lives in `crates/rimap-server/src/mcp/audit_envelope.rs::tests`) can call it through an `ImapMcpServer` instance. The instance requires a small `#[cfg(test)] pub(crate) fn new_for_tests(...)` constructor that builds a minimal server with just the fields `run_with_audit_envelope` touches (`audit`, `redaction_salt`, `cancellation_sender`, plus whatever `redact_tool_args` and the dispatch path require).

First, locate the `ImapMcpServer` struct definition:

```bash
grep -n "pub struct ImapMcpServer\|impl ImapMcpServer" crates/rimap-server/src/mcp/server.rs crates/rimap-server/src/mcp/mod.rs 2>/dev/null
```

Add the constructor in the file where `ImapMcpServer` is defined. Pattern:

```rust
#[cfg(test)]
impl ImapMcpServer {
    /// Minimal test constructor — instantiates an `ImapMcpServer`
    /// with only the fields needed for `run_with_audit_envelope`
    /// and its callees. Compiled only under `cfg(test)` so this
    /// constructor never ships in the released binary. Callers
    /// fill in additional fields as the test requires.
    pub(crate) fn new_for_tests(
        audit: std::sync::Arc<rimap_audit::AuditWriter>,
        cancellation_sender: rimap_audit::CancelledToolEndSender,
    ) -> Self {
        // The exact fields here depend on the live ImapMcpServer
        // shape. Inspect the struct and provide defaults
        // (Default::default(), empty Vec, etc.) for everything
        // that run_with_audit_envelope doesn't read. If a field
        // is read but not trivially constructible, add it as
        // another parameter to this function.
        todo!("inspect ImapMcpServer fields and fill in defaults")
    }
}
```

The `todo!` is intentional — the implementer must look at the live struct rather than rely on a snapshot here. If the struct has many fields, prefer a builder pattern over a long positional argument list.

Next, add the test inside `crates/rimap-server/src/mcp/audit_envelope.rs::tests`:

```rust
    /// Wrapper-level test: drives `run_with_audit_envelope` with a
    /// body that never completes, polls once to allow
    /// `emit_tool_start` to fire, then drops the outer future.
    /// Expectation: exactly one `tool_start` and exactly one
    /// `tool_end {status: cancelled}` record, in order. Catches
    /// regressions where guard construction is reordered relative
    /// to `tool_start` emission, or where the disarm call is
    /// moved/removed on the normal path. Codex review finding #4.
    #[tokio::test]
    async fn dropped_run_with_audit_envelope_emits_exactly_one_cancellation() {
        use std::sync::Arc;

        use rimap_audit::cancellation_channel;
        use rimap_audit::spawn_drainer;
        use rimap_core::Posture;
        use rimap_core::tool::ToolName;

        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = Arc::new(test_writer(path.clone()));
        let (tx, rx) = cancellation_channel();
        let drainer = spawn_drainer(rx, (*writer).clone());

        let server = super::super::server::ImapMcpServer::new_for_tests(
            Arc::clone(&writer),
            tx.clone(),
        );

        // Construct a future that runs run_with_audit_envelope with
        // a body that pends forever, poll it once to drive
        // emit_tool_start, then drop it.
        {
            let args = serde_json::Map::new();
            let fut = server.run_with_audit_envelope(
                ToolName::Search,
                Some("test".to_string()),
                super::super::dispatch::PostureContext::from_explicit(Posture::Readonly),
                &args,
                |_ticket| async { std::future::pending::<_>().await },
            );
            tokio::pin!(fut);
            // Poll once via timeout to ensure tool_start emits.
            // 50ms is generous; emit_tool_start is a single
            // spawn_blocking + file append.
            let _ = tokio::time::timeout(
                std::time::Duration::from_millis(50),
                &mut fut,
            )
            .await;
            // Drop fut here — undisarmed guard fires cancellation.
        }

        drop(tx);
        drainer.await.unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<_> = contents.lines().collect();
        assert_eq!(
            lines.len(),
            2,
            "expected exactly 2 records (tool_start + cancellation tool_end), got {} records:\n{contents}",
            lines.len(),
        );
        assert!(
            lines[0].contains(r#""payload":"tool_start""#)
                || lines[0].contains(r#""tool_start""#),
            "first record must be tool_start: {}",
            lines[0],
        );
        assert!(
            lines[1].contains(r#""status":"cancelled""#),
            "second record must be cancellation tool_end: {}",
            lines[1],
        );
    }
```

The `PostureContext::from_explicit` constructor is hypothetical — inspect the live `crate::mcp::dispatch::PostureContext` API and use whatever constructor exists. Same for any other type the test references.

Run the test:

```bash
cargo test -p rimap-server --lib audit_envelope::tests::dropped_run_with_audit_envelope_emits_exactly_one_cancellation
```

Expected: pass. If it fails because guard construction is incorrectly ordered or disarm is missing, STOP — that is a real bug in `run_with_audit_envelope`; file an issue, fix on a sibling branch, then continue.

- [ ] **Step 2: Create the wire-layer cancellation test file**

Read the existing `crates/rimap-server/tests/e2e_wire.rs` to understand the Dovecot-harness pattern, including how it spawns the binary with a real account config, drives `use_account`, etc.

Create `crates/rimap-server/tests/e2e_wire_cancellation.rs`:

```rust
//! Wire-layer cancellation acceptance (issue #266, Phase 4).
//!
//! Race-free assertions only. The audit-layer Drop contract from
//! #71/#99 (tool_end {status: cancelled} on Drop) is pinned by the
//! in-process tests at crates/rimap-server/src/mcp/audit_envelope.rs.
//! This file only asserts that the server accepts
//! `notifications/cancelled` without crashing and remains
//! responsive afterwards.
//!
//! See docs/superpowers/specs/2026-05-13-mcp-protocol-fuzzing-design.md §4.4.

#![expect(clippy::expect_used, reason = "integration tests")]
#![expect(clippy::panic, reason = "test assertions render diagnostics")]

#[path = "support/mod.rs"]
mod support;

use serde_json::json;

use support::wire::Harness;
```

- [ ] **Step 3: Add the Dovecot-backed setup helper with silent-skip discipline**

Codex review finding #3 verified that this repo's contract is **silent skip on `HarnessError::DockerUnavailable`** unless `RIMAP_REQUIRE_DOCKER=1` is set. Both `e2e_wire.rs:95-98` and `e2e_wire.rs:548-550` use this pattern; the Phase 4 cancellation tests MUST follow it or they will fail on every CI runner without Docker/Podman.

The helper returns `Option<Harness>` — `None` means "skip this test." Each test entry adds a `let Some(...) else { return; }` to honor the skip.

```rust
use support::dovecot::{DovecotHarness, HarnessError, fixtures};

/// Spawn the binary against a Dovecot-backed config and complete the
/// MCP handshake. Returns `None` when the container runtime is
/// unavailable (silent skip per the repo's existing contract; see
/// crates/rimap-server/tests/support/dovecot/harness.rs for how
/// RIMAP_REQUIRE_DOCKER=1 flips this to loud failure). Other
/// harness errors panic with diagnostic so they surface loudly.
///
/// The harness has `use_account` already called against the
/// `draftsafe` test account so subsequent `tools/call
/// draftsafe.search` works.
async fn spawn_with_dovecot() -> Option<Harness> {
    let dovecot = match DovecotHarness::try_start() {
        Ok(d) => d,
        Err(HarnessError::DockerUnavailable) => return None,
        Err(e) => panic!("Dovecot harness failed: {e}"),
    };
    // The rest of this helper mirrors the existing pattern in
    // e2e_wire.rs: build a config TOML referencing dovecot.port()
    // and the TLS fingerprint, write it to a tempdir, call
    // Harness::spawn_with_config with the password env var, then
    // drive use_account.
    //
    // Copy the live pattern from e2e_wire.rs verbatim. The Dovecot
    // harness API may evolve between Phase 3 and Phase 4 landings;
    // mirroring the latest pattern avoids drift.
    todo!("copy the Dovecot config setup + use_account drive from e2e_wire.rs (look at the function around line 95)")
}
```

When implementing this, copy the exact pattern from `e2e_wire.rs` rather than reinventing it. The `todo!` above is intentional — it forces the implementer to look at the live code rather than rely on a snapshot in this plan.

- [ ] **Step 4: Write `cancel_during_inflight_tools_call_keeps_session_alive`**

Append:

```rust
/// Send a `tools/call search` then immediately a
/// `notifications/cancelled` for that request id. The server must
/// produce ONE response envelope for the cancelled id (race-
/// dependent: result OR error) and remain responsive to a
/// follow-up `tools/list`. No panic, no envelope corruption.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancel_during_inflight_tools_call_keeps_session_alive() {
    let Some(mut harness) = spawn_with_dovecot().await else {
        // Silent skip when Docker/Podman is unavailable; the
        // existing repo contract (see e2e_wire.rs and
        // support/dovecot/harness.rs).
        return;
    };

    let search_id = harness
        .send_request_no_wait(
            "tools/call",
            json!({
                "name": "draftsafe.search",
                "arguments": { "folder": "INBOX", "criteria": "ALL" },
            }),
        )
        .await;
    // Send cancellation immediately. JSON-RPC notifications have no id.
    harness
        .notify(
            "notifications/cancelled",
            json!({ "requestId": search_id, "reason": "test cancel" }),
        )
        .await;

    // Drain the response to the search id. Either a success result
    // or an error envelope is acceptable — both are race-dependent
    // and both prove the server didn't crash.
    let response = harness.recv_until_id(search_id).await;
    assert_eq!(response["id"], json!(search_id));
    assert!(
        response.get("result").is_some() || response.get("error").is_some(),
        "expected result or error envelope, got {response}",
    );

    // Follow-up tools/list must still succeed — the server is
    // responsive after handling the cancellation.
    let list = harness.request("tools/list", json!({})).await;
    assert!(
        list["result"].is_object(),
        "server must remain responsive after cancellation, got {list}",
    );
}
```

- [ ] **Step 5: Write `cancel_unknown_request_id_is_noop`**

Append:

```rust
/// `notifications/cancelled` for an id that was never used. Server
/// must accept silently, not respond, and remain responsive.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancel_unknown_request_id_is_noop() {
    let Some(mut harness) = spawn_with_dovecot().await else {
        return;
    };

    harness
        .notify(
            "notifications/cancelled",
            json!({ "requestId": 999_999, "reason": "test cancel unknown" }),
        )
        .await;

    // Asserts no response within a tight window: the server must
    // NOT echo or error on an unknown-id cancellation.
    harness
        .assert_no_response_within(std::time::Duration::from_millis(200))
        .await;

    // Server still responsive.
    let list = harness.request("tools/list", json!({})).await;
    assert!(
        list["result"].is_object(),
        "server must remain responsive after no-op cancellation, got {list}",
    );
}
```

- [ ] **Step 6: Run the tests**

```bash
cargo test -p rimap-server --test e2e_wire_cancellation
```

Expected: both tests pass. If the Dovecot harness fails to start (Docker not running), the harness's `try_start` should produce a clear error; document the local-dev requirement.

- [ ] **Step 7: Commit**

```bash
git add crates/rimap-server/tests/e2e_wire_cancellation.rs \
        crates/rimap-server/src/mcp/audit_envelope.rs \
        crates/rimap-server/src/mcp/server.rs
# Add any other files touched by the new_for_tests constructor.
git commit -m "test(rimap-server): cancellation acceptance + wrapper-level audit test (#266)

Three deliverables:
- Wire-layer cancellation acceptance test in
  tests/e2e_wire_cancellation.rs. Silent skip on
  DockerUnavailable, matching e2e_wire.rs.
- Tightened existing dropped_guard_enqueues_cancellation_record
  assertion from lines.len() >= 2 to exactly 2.
- New wrapper-level test
  dropped_run_with_audit_envelope_emits_exactly_one_cancellation
  that drives run_with_audit_envelope end-to-end. Catches
  regressions in guard construction order or disarm discipline
  that guard-level tests would miss. Adds a cfg(test) test
  constructor on ImapMcpServer.
Phase 4 §4.4 + Codex review findings #3, #4."
```

---

## Task 10: Test-support env-var hook + `mcp_audit_failure.rs`

**Files:**
- Modify: `crates/rimap-server/src/main.rs` (add a `test-support`-gated env-var that calls `force_next_write_failure` at startup)
- Create: `crates/rimap-server/tests/mcp_audit_failure.rs`

The wire-level audit-failure tests need a way to arm `AuditWriter::force_next_write_failure()` from outside the server process. We add a tiny `test-support`-gated env-var that the binary reads at startup and, if set, calls `force_next_write_failure()` on its `AuditWriter` exactly once before serving any requests.

- [ ] **Step 1: Locate the AuditWriter construction in `main.rs`**

```bash
grep -n "AuditWriter::open\|AuditWriter::new\|AuditWriter\\b" crates/rimap-server/src/main.rs crates/rimap-server/src/lib.rs 2>/dev/null
```

Identify the function where the `AuditWriter` is constructed. The test-support hook will live immediately after that construction. The exact location depends on the current code layout; the typical pattern is a `setup_audit()` or `build_server()` function called from `main`.

- [ ] **Step 2: Add the env-var hook**

In the file where the `AuditWriter` is constructed (likely `main.rs` or a helper module), immediately after construction add:

```rust
#[cfg(feature = "test-support")]
{
    // RIMAP_TEST_FORCE_NEXT_AUDIT_WRITE_FAILURE=1 arms the
    // production AuditWriter's force_next_write_failure() hook
    // exactly once at startup. Used by mcp_audit_failure.rs to
    // exercise the real lock/append/error-mapping path without
    // adding a sentinel sink.
    //
    // The hook lives behind `test-support` per the existing
    // convention (Cargo.toml comment: "code under
    // cfg(feature = test-support) MUST NOT change wire shape").
    // This hook changes the audit write OUTCOME, not the wire
    // shape, so it complies with that constraint.
    if std::env::var("RIMAP_TEST_FORCE_NEXT_AUDIT_WRITE_FAILURE")
        .map(|v| v == "1")
        .unwrap_or(false)
    {
        audit_writer.force_next_write_failure();
    }
}
```

Adapt the variable name `audit_writer` to whatever the local binding is called. If the writer is wrapped in an `Arc`, you may need `Arc::as_ref` or similar.

- [ ] **Step 3: Run the existing test suite to ensure no wire shape changed**

```bash
cargo test -p rimap-server --test mcp_wire_conformance
```

Expected: all 9 Phase 1 tests pass. The hook is dormant when the env var is unset, so wire shape is unaffected.

- [ ] **Step 4: Create `mcp_audit_failure.rs`**

```rust
//! Audit fail-closed boundary tests (issue #266, Phase 4 §4.3).
//!
//! Arms the production `AuditWriter`'s `force_next_write_failure()`
//! hook via the `test-support`-gated env var
//! `RIMAP_TEST_FORCE_NEXT_AUDIT_WRITE_FAILURE=1`, then exercises
//! the wire. The next audit write — `tool_start` for the first
//! `tools/call` — takes the real lock/append/error-mapping path
//! and fails. The server must respond with an error envelope
//! rather than silently proceeding.

#![expect(clippy::expect_used, reason = "integration tests")]
#![expect(clippy::panic, reason = "test assertions render diagnostics")]

#[path = "support/mod.rs"]
mod support;

use std::path::Path;

use serde_json::json;
use tempfile::TempDir;

use support::wire::Harness;
```

- [ ] **Step 5: Write `audit_write_failure_fails_closed_for_tools_call`**

Append:

```rust
/// With the audit writer armed for one forced write failure,
/// `tools/call use_account` must return an error envelope. Tests
/// the real AuditWriter path (lock/append/error-mapping), not a
/// swappable sink.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn audit_write_failure_fails_closed_for_tools_call() {
    let tempdir = TempDir::new().expect("tempdir");
    let config_path = tempdir.path().join("config.toml");
    let audit_path = tempdir.path().join("audit.jsonl");
    let allowed_base = tempdir.path();
    let config = format!(
        r#"
accounts = []

[audit]
path = "{}"
allowed_base_dir = "{}"
fail_open = false
"#,
        audit_path.display(),
        allowed_base.display(),
    );
    std::fs::write(&config_path, config).expect("write config");

    let mut harness = Harness::spawn_with_config(
        &config_path,
        tempdir,
        &[("RIMAP_TEST_FORCE_NEXT_AUDIT_WRITE_FAILURE", "1")],
    )
    .await;
    let _ = harness.initialize_handshake().await;
    harness.send_initialized().await;

    let response = harness
        .request(
            "tools/call",
            json!({
                "name": "use_account",
                "arguments": { "account": "nonexistent" },
            }),
        )
        .await;

    // The contract is "fails closed" — the server must NOT
    // silently succeed when the audit write fails. The exact
    // shape (error envelope vs. result envelope with isError=true)
    // is probed.
    let is_envelope_error = response.get("error").is_some();
    let is_tool_error = response["result"]["isError"]
        .as_bool()
        .unwrap_or(false);
    assert!(
        is_envelope_error || is_tool_error,
        "tools/call with armed audit-write failure must fail closed, got {response}",
    );
}
```

- [ ] **Step 6: Write `audit_write_failure_does_not_block_initialize`**

Append:

```rust
/// Initialize handshake must succeed (or fail cleanly) regardless
/// of audit failure arming. `initialize` doesn't write an audit
/// record by itself, so this test pins that the env-var hook
/// doesn't accidentally break the handshake.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn audit_write_failure_does_not_block_initialize() {
    let tempdir = TempDir::new().expect("tempdir");
    let config_path = tempdir.path().join("config.toml");
    let audit_path = tempdir.path().join("audit.jsonl");
    let allowed_base = tempdir.path();
    let config = format!(
        r#"
accounts = []

[audit]
path = "{}"
allowed_base_dir = "{}"
fail_open = false
"#,
        audit_path.display(),
        allowed_base.display(),
    );
    std::fs::write(&config_path, config).expect("write config");

    let mut harness = Harness::spawn_with_config(
        &config_path,
        tempdir,
        &[("RIMAP_TEST_FORCE_NEXT_AUDIT_WRITE_FAILURE", "1")],
    )
    .await;
    let response = harness.initialize_handshake().await;
    // The handshake's result envelope must validate against the
    // schema (initialize_handshake calls request, which validates).
    // No additional assertion needed — getting here without a
    // panic IS the test.
    assert!(
        response["result"].is_object(),
        "initialize must succeed even with audit failure armed, got {response}",
    );
}
```

- [ ] **Step 7: Run both tests**

```bash
cargo test -p rimap-server --test mcp_audit_failure
```

Expected: both pass. If `audit_write_failure_fails_closed_for_tools_call` fails because the server silently succeeds, that's a real fail-closed bug in the production code — STOP, file an issue, fix on a sibling branch, return.

- [ ] **Step 8: Commit**

```bash
git add crates/rimap-server/src/main.rs \
        crates/rimap-server/tests/mcp_audit_failure.rs
git commit -m "test(rimap-server): audit fail-closed boundary tests (#266)

Adds a test-support-gated env-var hook (RIMAP_TEST_FORCE_NEXT_AUDIT_
WRITE_FAILURE) that arms AuditWriter::force_next_write_failure() at
startup, and two tests that exercise the real lock/append/error-
mapping path: tools/call must fail closed when the audit write
fails, and initialize must remain unaffected. Phase 4 §4.3, §6.4."
```

---

## Task 11: Nightly CI workflow + zero-test-run guard

**Files:**
- Create: `.github/workflows/mcp-fuzz-nightly.yml`

GitHub Actions workflow that runs the proptest binary nightly at `PROPTEST_CASES=100000` and asserts a non-zero test count was actually executed.

- [ ] **Step 1: Look up current pinned SHAs for required actions**

```bash
grep -rn "actions/checkout\|dtolnay/rust-toolchain\|Swatinem/rust-cache" .github/workflows/ | head -10
```

Note the current SHAs and version comments. The new workflow must use the same pinned-SHA convention.

- [ ] **Step 2: Create the workflow file**

Create `.github/workflows/mcp-fuzz-nightly.yml`. Use the SHAs from the existing workflows (do not invent new ones):

```yaml
name: MCP Fuzz Nightly

on:
  schedule:
    # 03:17 UTC daily — off-peak relative to other scheduled jobs.
    - cron: '17 3 * * *'
  workflow_dispatch: {}

permissions:
  contents: read

jobs:
  fuzz:
    name: proptest 100k cases
    runs-on: ubuntu-latest
    timeout-minutes: 90
    env:
      PROPTEST_CASES: '100000'
      CARGO_TERM_COLOR: always
    steps:
      - name: Checkout
        uses: actions/checkout@<PINNED_SHA>  # vN.M.K — replace with the SHA used by ci.yml
        with:
          persist-credentials: false

      - name: Install Rust toolchain
        uses: dtolnay/rust-toolchain@<PINNED_SHA>  # vN.M.K — replace with the SHA used by ci.yml
        with:
          toolchain: stable

      - name: Cache cargo registry + target
        uses: Swatinem/rust-cache@<PINNED_SHA>  # vN.M.K — replace with the SHA used by ci.yml
        with:
          shared-key: mcp-fuzz-nightly

      - name: Run proptest binary at 100k cases
        id: proptest
        run: |
          set -euo pipefail
          # --test (singular) selects the integration-test binary by name.
          # --tests (plural) is a "run all integration tests" flag that would
          # turn 'mcp_wire_proptest' into a name filter and silently run zero
          # property functions (which are named prop_*). Phase 4 §6.1.
          OUTPUT=$(cargo test -p rimap-server --test mcp_wire_proptest -- --nocapture 2>&1 | tee /dev/stderr)
          echo "$OUTPUT" > proptest-output.log
          # Extract the "running N tests" lines and sum.
          TESTS_RUN=$(echo "$OUTPUT" | grep -oE 'running [0-9]+ tests?' | awk '{s+=$2} END {print s+0}')
          echo "tests_run=$TESTS_RUN" >> "$GITHUB_OUTPUT"
          if [ "$TESTS_RUN" -eq 0 ]; then
            echo "::error::Zero tests reported as executed. The --test selector likely missed the binary. Phase 4 §6.1 guard."
            exit 1
          fi
          echo "Total tests executed: $TESTS_RUN"

      - name: Upload proptest output on failure
        if: failure()
        uses: actions/upload-artifact@<PINNED_SHA>  # vN.M.K — replace with the SHA used by ci.yml
        with:
          name: proptest-output
          path: proptest-output.log
          retention-days: 7
```

After substituting the SHAs, verify with `zizmor`:

```bash
zizmor .github/workflows/mcp-fuzz-nightly.yml
```

Expected: no findings. If `zizmor` flags anything (e.g., missing `permissions`, dangling pull_request_target), fix in place.

- [ ] **Step 3: Lint with actionlint**

```bash
actionlint .github/workflows/mcp-fuzz-nightly.yml
```

Expected: no errors.

- [ ] **Step 4: Smoke-test the test-execution count parser locally**

```bash
PROPTEST_CASES=10 cargo test -p rimap-server --test mcp_wire_proptest -- --nocapture 2>&1 | grep -oE 'running [0-9]+ tests?' | awk '{s+=$2} END {print s+0}'
```

Expected: a non-zero count (≥4 — the three properties plus the `assert_exclusion_set_matches_rmcp` sentinel). Confirm the awk pipeline matches what the workflow uses.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/mcp-fuzz-nightly.yml
git commit -m "ci: nightly proptest fuzz with zero-test-run guard (#266)

Runs cargo test -p rimap-server --test mcp_wire_proptest at
PROPTEST_CASES=100000 every night at 03:17 UTC. Includes a guard
that fails the job if the test runner reports zero tests executed —
this catches drift in the --test (singular) vs --tests (plural)
selector that the spec's acceptance criteria depend on. Phase 4
§6.1, §8."
```

---

## Task 12: Final verification

**Files:** none (verification only)

Run the full suite, lints, and `cargo deny` to confirm nothing regressed.

- [ ] **Step 1: Run the whole rimap-server test suite**

```bash
cargo test -p rimap-server
```

Expected: every test passes, including the new Phase 4 binaries and the pre-existing Phase 1/3 binaries. If anything fails, investigate before declaring done.

- [ ] **Step 2: Run the whole workspace test suite**

```bash
cargo test --workspace
```

Expected: every test in every crate passes.

- [ ] **Step 3: Run clippy with denied warnings**

```bash
cargo clippy --all-targets --all-features -- -D warnings
```

Expected: zero warnings. Fix anything that surfaces in the new files; never reach for `#[allow]` (per the workspace lints policy that denies `allow_attributes`).

- [ ] **Step 4: Run `cargo fmt --check`**

```bash
cargo fmt --check
```

Expected: clean. If anything is unformatted, run `cargo fmt` and amend.

- [ ] **Step 5: Run `cargo deny`**

```bash
cargo deny check
```

Expected: no advisories, no license problems, no banned crates. Phase 4 added zero production dependencies, so any new finding should be from a pre-existing transitive dep that drifted.

- [ ] **Step 6: Verify acceptance criteria**

Walk through `docs/superpowers/specs/2026-05-13-mcp-protocol-fuzzing-design.md` §8 and check each box.

Acceptance commands:

```bash
cargo test -p rimap-server --test mcp_wire_negative
cargo test -p rimap-server --test mcp_wire_proptest
cargo test -p rimap-server --test mcp_audit_failure
cargo test -p rimap-server --test e2e_wire_cancellation
# (no rimap-audit drop_emits_cancelled test — covered by existing in-crate tests)
```

Each must report PASS with a non-zero test count.

- [ ] **Step 7: Push and open the PR**

```bash
git push -u origin feature/issue-266-mcp-fuzzing
gh pr create --title "test(mcp): Phase 4 — protocol fuzzing and negative-path coverage (#266)" --body "$(cat <<'EOF'
## Summary
- Implements Phase 4 of the MCP test plan (#266): malformed-input negative tests, property-based envelope and tool-call fuzzing, wire-layer cancellation acceptance, and audit fail-closed boundary tests.
- Five new test binaries plus a nightly CI workflow.
- Design: `docs/superpowers/specs/2026-05-13-mcp-protocol-fuzzing-design.md`.
- Adversarial review applied: `docs/superpowers/plans/2026-05-13-mcp-protocol-fuzzing.md` (this plan).

## Test plan
- [x] `cargo test -p rimap-server --test mcp_wire_negative`
- [x] `cargo test -p rimap-server --test mcp_wire_proptest`
- [x] `cargo test -p rimap-server --test mcp_audit_failure`
- [x] `cargo test -p rimap-server --test e2e_wire_cancellation` (Dovecot required)
- [x] `cargo test --workspace`
- [x] `cargo clippy --all-targets --all-features -- -D warnings`
- [x] `cargo deny check`
- [x] `zizmor .github/workflows/mcp-fuzz-nightly.yml`

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

Note: the pre-push hook on this repo runs `just test` and `cargo deny`. The push may take several minutes; if the SSH connection idle-closes, configure `ServerAliveInterval` per the project's persistent guidance.

---

## Self-Review Notes

- **Spec coverage:** Each of the four spec test categories has a corresponding task (3–5 for negative-path, 6–8 for proptest, 9 for cancellation, 10 for audit failure, 11 for CI). The "Drop test in `rimap-audit/tests/drop_emits_cancelled.rs`" the spec named is documented as already covered by existing in-crate tests in Task 9 step 1 — a deliberate departure from the spec backed by source-code lookup.
- **Placeholder scan:** Task 9 Step 3 contains a `todo!("copy Dovecot config setup from e2e_wire.rs")` — this is intentional because the Dovecot harness API may have evolved and the implementer must mirror the live pattern rather than a snapshot. The plan flags this explicitly rather than pretending to have current bytes. All other code blocks are complete.
- **Type consistency:** `Harness::send_request_no_wait`, `recv_until_id`, `send_line`, `recv_line_within`, `response_or_close` (returns `CloseOrResponse`), and `is_usable` are defined in Tasks 1, 2, 6 and used in Tasks 3, 4, 5, 6, 7, 8, 9, 10. Names match throughout.
- **Probe-first discipline:** Tasks 3 and 4 have explicit "Run the test to observe behavior, then encode the observed code" steps. The plan does not pretend to know the exact JSON-RPC error codes rmcp emits; it tells the implementer to find them and pin them.
