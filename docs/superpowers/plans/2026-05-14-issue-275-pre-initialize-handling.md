# Pre-Initialize Request Handling Implementation Plan (#275)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the `exit 1` crash on pre-`initialize` requests with a JSON-RPC `-32002` error envelope (echoing the request id) followed by a clean exit `0`, while preserving non-zero exit + `process_end.reason: Error` on transport write failures.

**Architecture:** New `mcp/preinit.rs` module owns one pure helper that converts an offending `ClientJsonRpcMessage::Request` into a newline-terminated JSON-RPC error line. `main.rs::run` matches on `rmcp::service::server::ServerInitializeError::ExpectedInitializeRequest`, writes the line through a fresh `tokio::io::stdout()`, and returns `Ok(())` on success or propagates the write error via `?`. Notifications and Responses are dropped silently with `Ok(())`.

**Tech Stack:** Rust (workspace MSRV 1.88.0), tokio async I/O, rmcp 1.5, serde_json, anyhow, tracing. Wire-level integration tests use the `Harness` from `crates/rimap-server/tests/support/wire/`.

**Spec:** [`docs/superpowers/specs/2026-05-14-issue-275-pre-initialize-handling-design.md`](../specs/2026-05-14-issue-275-pre-initialize-handling-design.md)

---

## File Structure

**Create:**
- `crates/rimap-server/src/mcp/preinit.rs` — pure helper + unit tests

**Modify:**
- `crates/rimap-server/src/mcp/mod.rs` — add `preinit` module declaration
- `crates/rimap-server/src/mcp/error.rs` — add `NOT_INITIALIZED` constant
- `crates/rimap-server/src/main.rs` — match arm in `run()` and import the helper
- `crates/rimap-server/tests/mcp_wire_negative.rs` — un-ignore one test, add three new tests, add audit-log assertions
- `crates/rimap-server/tests/support/wire/harness.rs` — new `audit_path()` accessor and `DetachedStdoutHarness` + `spawn_with_closed_stdout()`

---

## Task 0: Pre-flight — Sanity-check the working tree

**Files:** none (verification only)

**Context:** This branch is stacked on `feature/issue-266-mcp-fuzzing` so the wire harness from #266 (`mcp_wire_negative.rs` + `support/wire/harness.rs`) is present. The PR opened from this branch targets `feature/issue-266-mcp-fuzzing` as its base — see the spec's Dependencies section for why. This task confirms the working tree is in the expected shape before any code changes begin.

- [ ] **Step 1: Confirm the harness files exist**

Run:
```bash
test -f crates/rimap-server/tests/mcp_wire_negative.rs && \
test -f crates/rimap-server/tests/support/wire/harness.rs && \
echo "OK: harness present"
```

Expected: `OK: harness present`. If either file is missing, the rebase onto `feature/issue-266-mcp-fuzzing` did not land — halt and consult the spec's Dependencies section.

- [ ] **Step 2: Confirm the ignored test we plan to un-ignore is present and ignored**

Run:
```bash
rg -n 'tools_list_before_initialize|blocked on #275' crates/rimap-server/tests/mcp_wire_negative.rs
```

Expected: a match showing `#[ignore = "blocked on #275: server crashes on pre-initialize requests"]` above an `async fn tools_list_before_initialize()`. If the line is absent or unignored, halt — the test harness has drifted from the spec and the test assertions in this plan need re-alignment.

- [ ] **Step 3: Confirm the workspace builds clean before changes**

Run:
```bash
cargo check --workspace --tests
```

Expected: clean exit, no errors. If errors, stop and address them first.

- [ ] **Step 4: No commit. Move to Task 1.**

---

## Task 1: Add `NOT_INITIALIZED` error-code constant

**Files:**
- Modify: `crates/rimap-server/src/mcp/error.rs`

The wire code `-32002` is reserved for "Server not initialized" in the LSP/MCP ecosystem. Add it alongside the existing custom codes (`POSTURE_DENIED`, `RATE_LIMITED`, etc.). The constant is consumed by `preinit.rs` in Task 2.

- [ ] **Step 1: Write the failing test**

Add this test in `crates/rimap-server/src/mcp/error.rs` inside the existing `mod tests` block (find the existing `#[test] fn message_is_preserved()` and add after it):

```rust
    #[test]
    fn not_initialized_code_value() {
        assert_eq!(super::NOT_INITIALIZED, McpCode(-32002));
    }
```

- [ ] **Step 2: Run to verify it fails**

Run:
```bash
cargo test -p rimap-server --lib mcp::error::tests::not_initialized_code_value
```

Expected: FAIL with `cannot find value 'NOT_INITIALIZED' in module 'super'`.

- [ ] **Step 3: Add the constant**

In `crates/rimap-server/src/mcp/error.rs`, add (after the existing `ATTACHMENT_TOO_LARGE` constant near line 23, before `pub fn to_mcp_error`):

```rust
/// Server has not yet received the MCP `initialize` request. The first
/// message a client sends MUST be `initialize` (or `ping`). Any other
/// pre-initialize request is rejected with this code and a clean
/// session shutdown.
pub const NOT_INITIALIZED: McpCode = McpCode(-32002);
```

Also update the module-level doc-comment listing custom codes (top of `error.rs`, lines 1-9). Replace the existing list with:

```rust
//! Map `RimapError` to rmcp `ErrorData` for MCP tool error responses.
//!
//! Custom error codes in the JSON-RPC "server error" range
//! (-32000 to -32099):
//! - -32001: posture denied
//! - -32002: server not initialized (pre-initialize request)
//! - -32003: rate limited
//! - -32004: circuit breaker open
//! - -32005: attachment too large
```

- [ ] **Step 4: Run to verify it passes**

Run:
```bash
cargo test -p rimap-server --lib mcp::error::tests::not_initialized_code_value
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-server/src/mcp/error.rs
git commit -m "$(cat <<'EOF'
feat(rimap-server): add NOT_INITIALIZED -32002 error code (#275)

Reserve the JSON-RPC server-error code -32002 for the
"server has not yet received the MCP initialize request"
case, alongside the existing POSTURE_DENIED / RATE_LIMITED /
CIRCUIT_OPEN / ATTACHMENT_TOO_LARGE codes. Consumed by the
pre-initialize envelope synthesizer in a follow-up commit.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Create the `preinit` module with envelope synthesizer

**Files:**
- Create: `crates/rimap-server/src/mcp/preinit.rs`

The helper is pure (no I/O, no transport access) so we can unit-test it directly against the rmcp types. `RequestId` is `rmcp::model::NumberOrString` — either an `i64` or an `Arc<str>` — so only those two id flavors are reachable. (JSON `null` ids would have failed rmcp's deserializer before reaching us; no test case needed for that.)

- [ ] **Step 1: Write the failing test file with the synthesizer's contract pinned**

Create `crates/rimap-server/src/mcp/preinit.rs` with the body below. The tests reference `synthesize_pre_init_error_envelope`, which does not yet exist — compilation will fail.

```rust
//! Pre-initialize request handler.
//!
//! Synthesizes the JSON-RPC error envelope that the MCP server sends
//! when a client violates the lifecycle by issuing any non-`initialize`,
//! non-`ping` request as its first message (#275). The helper is pure:
//! it does no I/O and holds no state. The transport write happens in
//! `main.rs::run`.
//!
//! Notifications and Responses pre-initialize return `None`: per
//! JSON-RPC §4.1 notifications never receive a response, and a
//! standalone Response is malformed (no matching server request).

use rmcp::model::ClientJsonRpcMessage;
use serde_json::json;

use crate::mcp::error::NOT_INITIALIZED;

/// Build the newline-terminated JSON-RPC error line to emit for an
/// offending pre-initialize message. Returns `Some` only for the
/// `Request` variant.
pub(crate) fn synthesize_pre_init_error_envelope(
    msg: &ClientJsonRpcMessage,
) -> Option<String> {
    match msg {
        ClientJsonRpcMessage::Request(req) => {
            let id = req.id.clone().into_json_value();
            let envelope = json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": NOT_INITIALIZED.0,
                    "message": "Server not initialized: send `initialize` \
                                before any other request",
                },
            });
            Some(format!("{envelope}\n"))
        }
        ClientJsonRpcMessage::Notification(_)
        | ClientJsonRpcMessage::Response(_)
        | ClientJsonRpcMessage::Error(_) => None,
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "tests")]
    #![expect(clippy::unwrap_used, reason = "tests")]

    use std::sync::Arc;

    use rmcp::model::{
        ClientJsonRpcMessage, ClientNotification, ClientRequest, ErrorData,
        JsonRpcError, JsonRpcNotification, JsonRpcRequest, JsonRpcResponse,
        JsonRpcVersion2_0, ListToolsRequest, NumberOrString,
        PaginatedRequestParamInner, ProgressNotification, ProgressNotificationParam,
    };
    use serde_json::{Value, json};

    use super::synthesize_pre_init_error_envelope;

    /// Build a Request variant carrying a `tools/list` request with the
    /// supplied id.
    fn request_msg(id: NumberOrString) -> ClientJsonRpcMessage {
        let list_tools = ListToolsRequest {
            method: Default::default(),
            params: Some(PaginatedRequestParamInner { cursor: None }),
            extensions: Default::default(),
        };
        ClientJsonRpcMessage::Request(JsonRpcRequest {
            jsonrpc: JsonRpcVersion2_0,
            id,
            request: ClientRequest::ListToolsRequest(list_tools),
        })
    }

    #[test]
    fn request_with_numeric_id_produces_minus_32002_envelope() {
        let msg = request_msg(NumberOrString::Number(42));
        let line = synthesize_pre_init_error_envelope(&msg).expect("Some line");
        assert!(line.ends_with('\n'), "must be newline-terminated");
        let parsed: Value = serde_json::from_str(line.trim_end())
            .expect("envelope is valid JSON");
        assert_eq!(parsed["jsonrpc"], json!("2.0"));
        assert_eq!(parsed["id"], json!(42));
        assert_eq!(parsed["error"]["code"], json!(-32002));
        assert!(parsed["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Server not initialized"));
    }

    #[test]
    fn request_with_string_id_preserves_string_id() {
        let msg = request_msg(NumberOrString::String(Arc::from("abc-123")));
        let line = synthesize_pre_init_error_envelope(&msg).expect("Some line");
        let parsed: Value = serde_json::from_str(line.trim_end()).unwrap();
        assert_eq!(parsed["id"], json!("abc-123"));
        assert_eq!(parsed["error"]["code"], json!(-32002));
    }

    #[test]
    fn line_is_single_line_with_one_trailing_newline() {
        let msg = request_msg(NumberOrString::Number(1));
        let line = synthesize_pre_init_error_envelope(&msg).expect("Some line");
        assert_eq!(line.matches('\n').count(), 1, "exactly one newline");
        assert!(line.ends_with('\n'), "newline is trailing");
        assert!(!line.trim_end().contains('\n'), "no embedded newlines");
    }

    #[test]
    fn notification_returns_none() {
        let progress = ProgressNotification {
            method: Default::default(),
            params: ProgressNotificationParam {
                progress: 0,
                total: None,
                progress_token: NumberOrString::Number(1),
                message: None,
            },
            extensions: Default::default(),
        };
        let msg = ClientJsonRpcMessage::Notification(JsonRpcNotification {
            jsonrpc: JsonRpcVersion2_0,
            notification: ClientNotification::ProgressNotification(progress),
        });
        assert!(synthesize_pre_init_error_envelope(&msg).is_none());
    }

    #[test]
    fn response_returns_none() {
        let msg = ClientJsonRpcMessage::Response(JsonRpcResponse {
            jsonrpc: JsonRpcVersion2_0,
            id: NumberOrString::Number(1),
            result: Default::default(),
        });
        assert!(synthesize_pre_init_error_envelope(&msg).is_none());
    }

    #[test]
    fn error_variant_returns_none() {
        let msg = ClientJsonRpcMessage::Error(JsonRpcError {
            jsonrpc: JsonRpcVersion2_0,
            id: NumberOrString::Number(1),
            error: ErrorData::internal_error("synthetic".to_string(), None),
        });
        assert!(synthesize_pre_init_error_envelope(&msg).is_none());
    }
}
```

- [ ] **Step 2: Verify the tests fail to compile**

Run:
```bash
cargo test -p rimap-server --lib mcp::preinit 2>&1 | head -30
```

Expected: compile error — `unresolved import` for `crate::mcp::preinit` (the module is not declared in `mcp/mod.rs` yet). That's the next task.

- [ ] **Step 3: No commit yet — proceed to Task 3 to wire the module in.**

---

## Task 3: Declare the `preinit` module

**Files:**
- Modify: `crates/rimap-server/src/mcp/mod.rs`

- [ ] **Step 1: Add the module declaration**

In `crates/rimap-server/src/mcp/mod.rs`, add `pub(crate) mod preinit;` alphabetically. After this change the top of the file reads:

```rust
//! MCP runtime: server handler, response/error types, content parsing.

pub(crate) mod audit_envelope;
pub mod content;
pub(crate) mod dispatch;
pub mod error;
pub(crate) mod preinit;
pub mod response;
pub mod server;
// `tool_catalog` is `pub` (doc-hidden via the parent `#[doc(hidden)] pub mod
// mcp` in `lib.rs`) so the binary's test-support `dump-tool-catalog`
// subcommand (#264) can reach `TOOL_DEFS`. Production callers route through
// `dispatch` and `server` and do not import this module directly.
pub mod tool_catalog;
pub(crate) mod tool_name;
```

- [ ] **Step 2: Run the preinit tests**

Run:
```bash
cargo test -p rimap-server --lib mcp::preinit
```

Expected: all six tests pass:
- `request_with_numeric_id_produces_minus_32002_envelope`
- `request_with_string_id_preserves_string_id`
- `line_is_single_line_with_one_trailing_newline`
- `notification_returns_none`
- `response_returns_none`
- `error_variant_returns_none`

If any test fails to compile because an rmcp type name differs in your local rmcp 1.5 (e.g. `ProgressNotificationParam` vs `ProgressNotificationParams`), fix the test to match the actual rmcp type — the helper's contract is what matters, not the exact constructor shape.

- [ ] **Step 3: Run clippy on the new module**

Run:
```bash
cargo clippy -p rimap-server --lib --all-features -- -D warnings
```

Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-server/src/mcp/preinit.rs crates/rimap-server/src/mcp/mod.rs
git commit -m "$(cat <<'EOF'
feat(rimap-server): add pre-initialize envelope synthesizer (#275)

New `mcp/preinit.rs` module exposes a pure helper that converts an
offending pre-initialize ClientJsonRpcMessage into a newline-terminated
JSON-RPC error line with code -32002 and the request id echoed
verbatim. Notifications, Responses, and Error variants return None
(no envelope, silent close at the call site).

Includes unit tests for numeric id, string id, framing (single line,
trailing newline), and all None-returning variants. Not yet wired into
the server entrypoint — that's the next commit.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Wire the helper into `main.rs::run`

**Files:**
- Modify: `crates/rimap-server/src/main.rs`

This is the behavior-change commit. Lines 136-140 currently wrap any `rmcp::serve_server` error in `anyhow!` and exit 1. We split that into three cases: `Ok` (normal run), `ExpectedInitializeRequest(Some(msg))` (synthesize envelope, return `Ok(())`), and everything else (preserve today's behavior).

- [ ] **Step 1: Add the imports near the top of `main.rs`**

Find the existing `use` block (lines 7-29 approximately). Add these imports alphabetically with the other module-level uses:

```rust
use rmcp::service::server::ServerInitializeError;
use tokio::io::AsyncWriteExt;
```

`anyhow::Context` is already imported via line 16 (`use anyhow::Context;`) — no change there.

- [ ] **Step 2: Replace the serve_server call block**

In `crates/rimap-server/src/main.rs`, locate the existing block (currently `main.rs:136-147`):

```rust
        let mcp_server = server::ImapMcpServer::new(registry, audit, cancellation_tx);
        let transport = rmcp::transport::io::stdio();
        let service = Box::pin(rmcp::serve_server(mcp_server, transport))
            .await
            .map_err(|e| anyhow::anyhow!("MCP server init: {e}"))?;
        // waiting() takes ownership of service, consuming it and dropping the
        // ImapMcpServer (including all cancellation sender clones) when it
        // returns. The drainer task exits once all senders have dropped.
        service
            .waiting()
            .await
            .map_err(|e| anyhow::anyhow!("MCP server error: {e}"))?;
```

Replace with:

```rust
        let mcp_server = server::ImapMcpServer::new(registry, audit, cancellation_tx);
        let transport = rmcp::transport::io::stdio();
        let service = match Box::pin(rmcp::serve_server(mcp_server, transport)).await {
            Ok(svc) => svc,
            Err(ServerInitializeError::ExpectedInitializeRequest(Some(msg))) => {
                if let Some(line) = rimap_server::mcp::preinit::synthesize_pre_init_error_envelope(&msg) {
                    let mut out = tokio::io::stdout();
                    out.write_all(line.as_bytes())
                        .await
                        .context("writing pre-init error envelope to stdout")?;
                    out.flush()
                        .await
                        .context("flushing pre-init error envelope")?;
                    tracing::info!(
                        "rejected pre-initialize request with -32002 envelope",
                    );
                }
                return Ok(());
            }
            Err(other) => return Err(anyhow::anyhow!("MCP server init: {other}")),
        };
        // waiting() takes ownership of service, consuming it and dropping the
        // ImapMcpServer (including all cancellation sender clones) when it
        // returns. The drainer task exits once all senders have dropped.
        service
            .waiting()
            .await
            .map_err(|e| anyhow::anyhow!("MCP server error: {e}"))?;
```

Note the path: `rimap_server::mcp::preinit::synthesize_pre_init_error_envelope`. `main.rs` is the binary crate's entry point and reaches into the library crate `rimap_server` (see existing line 7-8). The function is `pub(crate)` in `mcp/preinit.rs`, so the path needs adjustment.

- [ ] **Step 3: Adjust the function visibility**

Because `main.rs` calls the helper through the library crate boundary, change the visibility in `crates/rimap-server/src/mcp/preinit.rs` from `pub(crate)` to `pub`:

```rust
pub fn synthesize_pre_init_error_envelope(
    msg: &ClientJsonRpcMessage,
) -> Option<String> {
```

Also export it from the `mcp` module hierarchy. In `crates/rimap-server/src/mcp/mod.rs`, change the line you added in Task 3 from:

```rust
pub(crate) mod preinit;
```

to:

```rust
pub mod preinit;
```

The `mcp` module itself is `#[doc(hidden)] pub` (see `crates/rimap-server/src/lib.rs`) so this widens reachability only across the same workspace, not for external consumers.

- [ ] **Step 4: Build the workspace and verify the binary still compiles**

Run:
```bash
cargo check --workspace --tests
```

Expected: clean. If errors mention `rmcp::service::server::ServerInitializeError` not being in scope, your rmcp version may re-export it from a different path — check `rg "pub use.*ServerInitializeError" ~/.cargo/registry/src/index.crates.io-*/rmcp-*/src/lib.rs` and adjust the use statement.

- [ ] **Step 5: Run lints**

Run:
```bash
cargo clippy -p rimap-server --all-targets --all-features -- -D warnings
```

Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add crates/rimap-server/src/main.rs crates/rimap-server/src/mcp/mod.rs crates/rimap-server/src/mcp/preinit.rs
git commit -m "$(cat <<'EOF'
fix(rimap-server): handle pre-initialize requests with -32002 envelope (#275)

Match on ServerInitializeError::ExpectedInitializeRequest in main.rs::run
and reply with a JSON-RPC -32002 error envelope (request id echoed
verbatim) instead of exiting 1. Write errors are propagated via `?` so
broken-pipe / closed-reader cases still record process_end.reason: Error
and exit non-zero. Notification / Response variants are dropped silently
with a clean exit 0.

Widens synthesize_pre_init_error_envelope visibility to pub so main.rs
can reach it through the rimap_server library crate.

Wire-level regression tests follow.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: Un-ignore `tools_list_before_initialize` and tighten assertions

**Files:**
- Modify: `crates/rimap-server/tests/mcp_wire_negative.rs`
- Modify: `crates/rimap-server/tests/support/wire/harness.rs` (add `audit_path()` accessor)

This is the first wire-level verification of the Task 4 change.

- [ ] **Step 1: Add `audit_path()` accessor on `Harness`**

In `crates/rimap-server/tests/support/wire/harness.rs`, find the `impl Harness {` block and add this method near the other accessors (e.g., next to `captured_stderr`). The audit log path is `{_tempdir}/audit.jsonl` per `spawn()`'s config template.

```rust
    /// Path to the audit log file for this harness. Used by tests
    /// that need to read `process_end` records post-shutdown.
    pub fn audit_path(&self) -> std::path::PathBuf {
        self._tempdir.path().join("audit.jsonl")
    }
```

The `_tempdir` field has a leading underscore to indicate "held only for lifetime"; accessing it through `self._tempdir.path()` is still legal — the underscore convention is purely visual.

Also add a reference to this accessor in the `force_use_for_dead_code_link` function near the top of the file so it isn't flagged as unused in test binaries that don't call it:

```rust
    // Method used by mcp_wire_negative (pre-initialize tests), not by
    // other binaries.
    let _ = Harness::audit_path;
```

Add this line alongside the other `let _ = Harness::...` lines in that function.

- [ ] **Step 2: Replace the un-ignored test**

In `crates/rimap-server/tests/mcp_wire_negative.rs`, locate the existing `tools_list_before_initialize` test (around line 326-368). Replace the entire test (docstring + attributes + body) with:

```rust
// ---------------------------------------------------------------------------
// Test 7: `tools/list` before `initialize`
// ---------------------------------------------------------------------------

/// `tools/list` before `initialize` must return a JSON-RPC error
/// envelope with code -32002 (Server not initialized), echo the
/// request id verbatim, then close stdin and exit `0`. Fixed by #275.
///
/// Audit log MUST record `process_end.reason: Eof` on the success
/// path — this is the contract the bug report flagged as broken.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tools_list_before_initialize() {
    let mut harness = Harness::spawn().await;
    let audit_path = harness.audit_path();

    // Deliberately skip initialize_handshake.
    let id = harness.send_request_no_wait("tools/list", json!({})).await;

    // Phase 1: error envelope arrives with -32002.
    let envelope = match harness.response_or_close(REQUEST_TIMEOUT).await {
        CloseOrResponse::Response(line) => parse_response_line(&line),
        other => panic!(
            "expected -32002 error envelope for pre-initialize tools/list, got {other:?}"
        ),
    };
    assert!(
        envelope["error"].is_object(),
        "must be an error envelope, got {envelope}",
    );
    assert_eq!(
        envelope["error"]["code"],
        json!(-32002),
        "must be code -32002 (Server not initialized), got {envelope}",
    );
    assert_eq!(
        envelope["id"],
        json!(id),
        "id must be echoed verbatim, got {envelope}",
    );
    assert_envelope_valid(&envelope);

    // Phase 2: stdout closes and the server exits 0.
    match harness.response_or_close(REQUEST_TIMEOUT).await {
        CloseOrResponse::CleanClose => {}
        other => panic!(
            "expected clean close after envelope on pre-initialize tools/list, got {other:?}"
        ),
    }

    // Phase 3: audit log captured the success path as reason Eof.
    let reason = read_process_end_reason(&audit_path);
    assert_eq!(
        reason,
        rimap_audit::ProcessEndReason::Eof,
        "process_end.reason must be Eof on successful pre-initialize handling",
    );
}
```

- [ ] **Step 3: Add the audit-reading helper at the top of `mcp_wire_negative.rs`**

Below the existing `parse_response_line` helper (around line 26-30), add:

```rust
/// Read the `process_end.reason` from the audit log produced by the
/// harness. Panics if no `process_end` record is found.
fn read_process_end_reason(path: &std::path::Path) -> rimap_audit::ProcessEndReason {
    let contents = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read audit log at {}: {e}", path.display()));
    for line in contents.lines() {
        let record: rimap_audit::AuditRecord = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("parse audit record {line:?}: {e}"));
        if let rimap_audit::Payload::ProcessEnd(p) = record.payload {
            return p.reason;
        }
    }
    panic!("no process_end record found in audit log at {}", path.display());
}
```

- [ ] **Step 4: Confirm `rimap-audit` is a dev-dependency of `rimap-server`**

Run:
```bash
rg -n 'rimap-audit\|rimap_audit' crates/rimap-server/Cargo.toml
```

If `rimap-audit` is only listed under `[dependencies]` and not `[dev-dependencies]`, add it under `[dev-dependencies]` too. Typically the entry exists in both — confirm before adding.

- [ ] **Step 5: Run the un-ignored test**

Run:
```bash
cargo test -p rimap-server --test mcp_wire_negative tools_list_before_initialize -- --nocapture
```

Expected: PASS. If it fails:
- Crashed (non-zero exit): Task 4 didn't land — check `main.rs` for the match arm.
- Wrong error code: check the constant in `error.rs` (Task 1) and the synthesizer in `preinit.rs` (Task 2).
- `no process_end record found`: the audit log may not be flushed; check the existing `log_process_end` block in `main.rs:168-171` is still on the early-return path.

- [ ] **Step 6: Commit**

```bash
git add crates/rimap-server/tests/mcp_wire_negative.rs crates/rimap-server/tests/support/wire/harness.rs crates/rimap-server/Cargo.toml
git commit -m "$(cat <<'EOF'
test(rimap-server): pin -32002 contract for pre-init tools/list (#275)

Un-ignore tools_list_before_initialize with strict assertions:
- response envelope must be code -32002 with the request id echoed
- server must close stdin cleanly with exit 0
- audit log must record process_end.reason: Eof

Adds the audit_path() accessor on Harness and a read_process_end_reason
helper in the test file so subsequent audit-reason assertions can reuse
the pattern.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: Add `tools_list_before_initialize_str_id` test

**Files:**
- Modify: `crates/rimap-server/tests/mcp_wire_negative.rs`

Pins the string-id roundtrip at the wire layer. Catches future regressions where the helper accidentally coerces ids through `as_u64()`.

- [ ] **Step 1: Write the test**

Add this test in `crates/rimap-server/tests/mcp_wire_negative.rs` immediately after `tools_list_before_initialize`:

```rust
/// Same contract as `tools_list_before_initialize`, but with a string
/// id. Pins id-type preservation at the wire layer: numeric coercion
/// of `id` in the synthesizer would surface here.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tools_list_before_initialize_str_id() {
    let mut harness = Harness::spawn().await;

    // Send a hand-crafted request with a STRING id rather than using
    // send_request_no_wait (which auto-assigns a u64).
    let raw = r#"{"jsonrpc":"2.0","id":"abc-123","method":"tools/list","params":{}}"#;
    harness.send_line(raw).await;

    let envelope = match harness.response_or_close(REQUEST_TIMEOUT).await {
        CloseOrResponse::Response(line) => parse_response_line(&line),
        other => panic!(
            "expected -32002 error envelope for pre-initialize tools/list w/ str id, got {other:?}"
        ),
    };
    assert_eq!(envelope["error"]["code"], json!(-32002));
    assert_eq!(
        envelope["id"],
        json!("abc-123"),
        "string id must survive verbatim through the envelope synthesizer, got {envelope}",
    );
    assert_envelope_valid(&envelope);

    match harness.response_or_close(REQUEST_TIMEOUT).await {
        CloseOrResponse::CleanClose => {}
        other => panic!("expected clean close, got {other:?}"),
    }
}
```

- [ ] **Step 2: Run the test**

Run:
```bash
cargo test -p rimap-server --test mcp_wire_negative tools_list_before_initialize_str_id -- --nocapture
```

Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/rimap-server/tests/mcp_wire_negative.rs
git commit -m "$(cat <<'EOF'
test(rimap-server): pin string-id roundtrip for pre-init reject (#275)

Hand-crafts a pre-initialize tools/list request with a string id and
verifies the -32002 envelope echoes the same string. Guards against
future regressions where the synthesizer might coerce ids through
as_u64() or similar.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: Add `pre_initialize_notification_silent_close` test

**Files:**
- Modify: `crates/rimap-server/tests/mcp_wire_negative.rs`

Pins the Notification-path contract: no envelope, clean close, audit reason Eof.

- [ ] **Step 1: Write the test**

Add this test in `crates/rimap-server/tests/mcp_wire_negative.rs` immediately after `tools_list_before_initialize_str_id`:

```rust
/// Pre-initialize NOTIFICATION (no `id`) must NOT receive an error
/// envelope — per JSON-RPC §4.1 notifications never get a response.
/// Server closes cleanly and exits 0 with audit reason Eof.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pre_initialize_notification_silent_close() {
    let mut harness = Harness::spawn().await;
    let audit_path = harness.audit_path();

    // Send a pre-initialize notification (not a request — no id).
    harness
        .notify(
            "notifications/cancelled",
            json!({"requestId": 1, "reason": "client decided not to initialize"}),
        )
        .await;

    // No response should arrive; the server should close cleanly.
    match harness.response_or_close(REQUEST_TIMEOUT).await {
        CloseOrResponse::CleanClose => {}
        CloseOrResponse::Response(line) => {
            let envelope = parse_response_line(&line);
            panic!(
                "pre-initialize notification must NOT produce an envelope, got {envelope}"
            );
        }
        other => panic!("expected clean close, got {other:?}"),
    }

    // Audit log captured the success path as reason Eof.
    let reason = read_process_end_reason(&audit_path);
    assert_eq!(reason, rimap_audit::ProcessEndReason::Eof);
}
```

- [ ] **Step 2: Run the test**

Run:
```bash
cargo test -p rimap-server --test mcp_wire_negative pre_initialize_notification_silent_close -- --nocapture
```

Expected: PASS. The server's match arm in `main.rs` returns `Ok(())` because `synthesize_pre_init_error_envelope` returned `None` for the Notification variant.

- [ ] **Step 3: Commit**

```bash
git add crates/rimap-server/tests/mcp_wire_negative.rs
git commit -m "$(cat <<'EOF'
test(rimap-server): pin silent-close for pre-init notifications (#275)

Asserts notifications/cancelled before initialize produces NO wire
response and the server exits 0 with audit reason Eof. Per JSON-RPC
§4.1, notifications never receive a response.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: Add the closed-stdout harness variant

**Files:**
- Modify: `crates/rimap-server/tests/support/wire/harness.rs`

Adds a separate spawn helper that closes the stdout read end before the child writes, so the broken-pipe test in Task 9 has scaffolding. We introduce a small sister struct (`DetachedStdoutHarness`) rather than refactoring `Harness::stdout` to `Option<BufReader<...>>` — that refactor would touch every existing harness call site for one new test.

- [ ] **Step 1: Define the sister struct and its accessors**

Add to `crates/rimap-server/tests/support/wire/harness.rs`, after the `Harness` struct definition (and after any existing `impl Harness {` blocks — keep the file's existing structure intact):

```rust
/// Lightweight harness variant used by transport-failure regression
/// tests that intentionally close the server's stdout read end before
/// sending input. The server's pre-initialize envelope write will
/// fail with `BrokenPipe`. This struct cannot read stdout responses;
/// it exists only to drive stdin, wait for the child exit, and read
/// the resulting audit log + captured stderr.
pub struct DetachedStdoutHarness {
    pub child: Child,
    pub stdin: ChildStdin,
    stderr_log: PathBuf,
    audit_path: PathBuf,
    // Held until drop so the audit log path stays valid.
    _tempdir: TempDir,
}

impl DetachedStdoutHarness {
    /// Path to the audit log produced by the spawned binary.
    pub fn audit_path(&self) -> &std::path::Path {
        &self.audit_path
    }

    /// Read the captured stderr file. Empty string on read failure.
    pub fn captured_stderr(&self) -> String {
        std::fs::read_to_string(&self.stderr_log).unwrap_or_default()
    }
}
```

- [ ] **Step 2: Add the spawn helper**

Add this method inside the existing `impl Harness { ... }` block (the one that contains `spawn()` and `spawn_with_config()`):

```rust
    /// Spawn the binary with the legacy zero-account config, then
    /// immediately drop the BufReader<ChildStdout> read handle. The
    /// child's stdout pipe write end is now connected to a closed
    /// reader; the next write the server attempts will fail with
    /// `BrokenPipe`. Used by `pre_initialize_envelope_write_failure`
    /// to exercise the propagated-error path on transport failure.
    pub async fn spawn_with_closed_stdout() -> DetachedStdoutHarness {
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
"#,
            audit_path.display(),
            allowed_base.display(),
        );
        std::fs::write(&config_path, config).expect("write config");

        let stderr_log = tempdir.path().join("rusty-imap-mcp.stderr.log");
        let stderr_file = File::create(&stderr_log).expect("create stderr log file");

        let mut cmd = Command::new(cargo_bin("rusty-imap-mcp"));
        cmd.arg("--config")
            .arg(&config_path)
            .arg("--allow-empty-accounts")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(stderr_file))
            .kill_on_drop(true);
        let mut child = cmd.spawn().expect("spawn rusty-imap-mcp binary");

        let stdin = child.stdin.take().expect("stdin");
        // Take the read end of the stdout pipe and drop it immediately.
        // The child's write end is now connected to a closed reader.
        let stdout = child.stdout.take().expect("stdout");
        drop(stdout);

        DetachedStdoutHarness {
            child,
            stdin,
            stderr_log,
            audit_path,
            _tempdir: tempdir,
        }
    }
```

- [ ] **Step 3: Suppress per-binary dead-code on the new symbol**

Add to the `force_use_for_dead_code_link` function near the top of the file (this prevents the new method from being flagged as unused in test binaries that don't use it):

```rust
    // Method used by mcp_wire_negative (pre-initialize write-failure
    // test), not by other binaries.
    let _ = Harness::spawn_with_closed_stdout;
```

Same for `DetachedStdoutHarness`'s methods if needed — if clippy complains in CI, add `let _ = DetachedStdoutHarness::audit_path;` and `let _ = DetachedStdoutHarness::captured_stderr;` lines.

- [ ] **Step 4: Build the harness**

Run:
```bash
cargo check -p rimap-server --tests
```

Expected: clean. If unused-import warnings fire on `File`, `Command`, etc. — they're already imported by `spawn_with_config()`, no new imports should be needed.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-server/tests/support/wire/harness.rs
git commit -m "$(cat <<'EOF'
test(rimap-server): add closed-stdout harness variant (#275)

Adds Harness::spawn_with_closed_stdout() and a sister
DetachedStdoutHarness struct for the upcoming pre-initialize
write-failure regression test. The spawn helper drops the
BufReader<ChildStdout> immediately so the child's stdout-write end
is connected to a closed reader; the server's next write fails with
BrokenPipe.

Scaffolding only — no behavior change. Used in the next commit.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 9: Add the write-failure regression test

**Files:**
- Modify: `crates/rimap-server/tests/mcp_wire_negative.rs`

Pins the Codex finding #2 contract: write failures while emitting the envelope must record `process_end.reason: Error` and exit non-zero.

- [ ] **Step 1: Write the test**

Add this test in `crates/rimap-server/tests/mcp_wire_negative.rs` immediately after `pre_initialize_notification_silent_close`:

```rust
/// Codex review finding 2026-05-14 (medium): transport-level write
/// failures while emitting the pre-initialize envelope must NOT be
/// classified as clean EOF. Server's stdout read end is closed
/// before the request arrives; the envelope write fails with
/// BrokenPipe; the server exits non-zero and the audit log records
/// `reason: Error`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pre_initialize_envelope_write_failure_records_error() {
    use support::wire::harness::SHUTDOWN_TIMEOUT;
    use tokio::time::timeout;

    let mut detached =
        support::wire::harness::Harness::spawn_with_closed_stdout().await;

    // Send a pre-initialize request. Server will read it, attempt to
    // write the envelope, and fail with BrokenPipe because stdout's
    // read end is already closed.
    let line = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#.to_string()
        + "\n";
    use tokio::io::AsyncWriteExt;
    detached
        .stdin
        .write_all(line.as_bytes())
        .await
        .expect("write request");
    detached.stdin.flush().await.expect("flush request");

    // Wait for the child to exit.
    let status = timeout(SHUTDOWN_TIMEOUT, detached.child.wait())
        .await
        .expect("child exit within SHUTDOWN_TIMEOUT")
        .expect("child wait");

    // Server must NOT exit 0 on a broken-pipe write failure. It may
    // exit with a non-zero status (anyhow propagated) or, if Rust's
    // SIGPIPE handling regresses, be killed by signal 13 — both are
    // failures we want to surface but only the first is the
    // contract we lock in.
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        assert!(
            status.signal().is_none(),
            "server must not be killed by SIGPIPE (regression in Rust runtime); got {status:?}\n--- captured stderr ---\n{}",
            detached.captured_stderr(),
        );
    }
    assert!(
        !status.success(),
        "server must exit non-zero when envelope write fails; got {status:?}\n--- captured stderr ---\n{}",
        detached.captured_stderr(),
    );

    // Audit log must record reason Error, NOT Eof.
    let reason = read_process_end_reason(detached.audit_path());
    assert_eq!(
        reason,
        rimap_audit::ProcessEndReason::Error,
        "process_end.reason must be Error when envelope delivery fails, not Eof — \
         masking transport failures as clean EOF defeats the audit-correctness goal",
    );

    // The propagated anyhow context must surface in stderr.
    let stderr = detached.captured_stderr();
    assert!(
        stderr.contains("pre-init error envelope"),
        "expected propagated 'pre-init error envelope' anyhow context in stderr, got:\n{stderr}",
    );
}
```

- [ ] **Step 2: Run the test**

Run:
```bash
cargo test -p rimap-server --test mcp_wire_negative pre_initialize_envelope_write_failure_records_error -- --nocapture
```

Expected: PASS.

Common failure modes:
- **Killed by signal 13**: Rust's SIGPIPE handler regression — the cargo-built binary inherited a SIGPIPE handler that terminates the process. Check that nothing in `main.rs::main()` calls `signal_hook::register` or similar before `init()`.
- **`process_end.reason == Eof`**: the `?` propagation in `main.rs` was lost — re-check Task 4.
- **`no process_end record found`**: the binary panicked before `audit_for_shutdown.log_process_end(...)` fired. Check `main.rs:158-171` is still reachable on the early-return path.

- [ ] **Step 3: Commit**

```bash
git add crates/rimap-server/tests/mcp_wire_negative.rs
git commit -m "$(cat <<'EOF'
test(rimap-server): pin Error reason on pre-init envelope write fail (#275)

Closes the harness's stdout read end before sending a pre-initialize
tools/list request, then asserts:
- server exits non-zero (not killed by SIGPIPE)
- process_end.reason: Error (not Eof — would mask the failure)
- propagated anyhow context surfaces in stderr

Addresses Codex adversarial-review finding 2026-05-14 (medium).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 10: Full local-CI sweep and final commit (if needed)

**Files:** none expected; this task verifies everything composes.

- [ ] **Step 1: Run `just ci`**

Run:
```bash
just ci
```

Expected: PASS. This runs fmt-check, clippy with `-D warnings`, the workspace test suite, and `cargo deny`.

Common late-stage failures:
- **Clippy `unused_imports` in `mcp_wire_negative.rs`**: the test file gained `use tokio::time::timeout` / `use tokio::io::AsyncWriteExt` inside one test function. If a sibling test binary compiles the same `support/` module and doesn't use them, no warning fires. If it does, lift the `use` statements to the top of `mcp_wire_negative.rs` so they're shared.
- **`AuditRecord` / `Payload` / `ProcessEndReason` not in scope**: confirm the `rimap-audit` dev-dependency in `crates/rimap-server/Cargo.toml` is present.
- **`audit_path` field is private on `DetachedStdoutHarness`**: confirm the accessor method exists and returns `&Path`.
- **`stderr_log` field also private**: the `captured_stderr` accessor must be `pub` on `DetachedStdoutHarness`.

- [ ] **Step 2: Verify no `#[ignore]` remains pinned to #275**

Run:
```bash
rg -n '#\[ignore.*#275' crates/
```

Expected: no matches. If a match appears, un-ignore it (it was missed during Task 5) and re-run tests.

- [ ] **Step 3: Verify the issue-closing references are accurate**

Run:
```bash
rg -n '#275' crates/ docs/superpowers/
```

Expected: references in the spec file, the plan file, and any commit messages. No stale "blocked on #275" comments.

- [ ] **Step 4: Final commit (only if any cleanup happened)**

Only commit if there were fixups in Steps 1-3. If nothing was changed:

```bash
git status
# (should report nothing to commit)
```

Otherwise:

```bash
git add -p   # stage cleanup hunks
git commit -m "$(cat <<'EOF'
chore(rimap-server): tidy after #275 implementation

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 5: Open the PR**

```bash
git push -u origin fix/issue-275-pre-initialize-handling
gh pr create --base feature/issue-266-mcp-fuzzing --title "fix(rimap-server): handle pre-initialize requests with -32002 envelope (#275)" --body "$(cat <<'EOF'
## Summary

- Pre-initialize Request → JSON-RPC `-32002` "Server not initialized" envelope (request id echoed verbatim), clean close, exit 0, audit `reason: Eof`.
- Pre-initialize Notification / Response → silent clean close, exit 0, audit `reason: Eof`.
- Envelope write failure → propagated `anyhow::Error`, non-zero exit, audit `reason: Error` (Codex adversarial-review finding 2026-05-14).

Fixes #275. One of three merge blockers (#275, #276, #277) for PR #278; targets `feature/issue-266-mcp-fuzzing` so the un-ignore commit travels with the fix.

## Test plan

- [ ] `cargo test -p rimap-server --test mcp_wire_negative` passes — four pre-initialize cases covered (numeric id, string id, notification silent close, write-failure).
- [ ] `cargo test -p rimap-server --lib mcp::preinit` passes — six unit tests on the envelope synthesizer.
- [ ] `just ci` passes locally.

Spec: `docs/superpowers/specs/2026-05-14-issue-275-pre-initialize-handling-design.md`
Plan: `docs/superpowers/plans/2026-05-14-issue-275-pre-initialize-handling.md`

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

---

## Done

All tasks complete. Verify with one final read-through of `git log fix/issue-275-pre-initialize-handling ^main` — should show:

1. `docs(spec): pre-initialize request handling design (#275)` (already present)
2. `docs(spec): address Codex adversarial-review findings (#275)` (already present)
3. `feat(rimap-server): add NOT_INITIALIZED -32002 error code (#275)` (Task 1)
4. `feat(rimap-server): add pre-initialize envelope synthesizer (#275)` (Task 3)
5. `fix(rimap-server): handle pre-initialize requests with -32002 envelope (#275)` (Task 4)
6. `test(rimap-server): pin -32002 contract for pre-init tools/list (#275)` (Task 5)
7. `test(rimap-server): pin string-id roundtrip for pre-init reject (#275)` (Task 6)
8. `test(rimap-server): pin silent-close for pre-init notifications (#275)` (Task 7)
9. `test(rimap-server): add closed-stdout harness variant (#275)` (Task 8)
10. `test(rimap-server): pin Error reason on pre-init envelope write fail (#275)` (Task 9)
