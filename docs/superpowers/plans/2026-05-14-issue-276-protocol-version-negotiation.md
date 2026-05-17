# Protocol-Version Negotiation Implementation Plan (#276)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reject any `initialize` request whose `protocolVersion` is not exactly `ProtocolVersion::LATEST` with a JSON-RPC `-32602` error envelope, then exit cleanly; classify `InitializeFailed` outcomes by error code so server-faults stay observable.

**Architecture:** Override `ServerHandler::initialize` on `ImapMcpServer` to validate the peer's version against `ProtocolVersion::LATEST`. A pure helper builds the `-32602` `ErrorData` listing the one supported version. `main.rs::run` adds a code-gated `InitializeFailed` arm that routes `INVALID_PARAMS` to clean exit (audit `Eof`) and other codes to propagated `anyhow::Error` (audit `Error`).

**Tech Stack:** Rust (MSRV 1.88.0), tokio async I/O, rmcp 1.5, serde_json, anyhow, tracing. Wire-level tests use the harness from `crates/rimap-server/tests/support/wire/`.

**Spec:** [`docs/superpowers/specs/2026-05-14-issue-276-protocol-version-negotiation-design.md`](../specs/2026-05-14-issue-276-protocol-version-negotiation-design.md)

---

## File Structure

**Modify:**
- `crates/rimap-server/src/mcp/server.rs` — add `InitializeRequestParams`, `InitializeResult`, `ProtocolVersion` to imports; add `async fn initialize` override inside `impl ServerHandler for ImapMcpServer`; add private free function `unsupported_protocol_version_error` near the bottom; add `#[cfg(test)] mod tests` block with helper unit tests
- `crates/rimap-server/src/main.rs` — add `rmcp::model::ErrorCode` import; add private free function `initialize_failure_is_handled_rejection`; insert two new code-gated `InitializeFailed` match arms into `run()`; extend the existing `#[cfg(all(test, unix))] mod resolve_download_dir_tests` (or add a sibling test module) with classifier unit tests
- `crates/rimap-server/tests/mcp_wire_negative.rs` — un-ignore `initialize_unsupported_protocol_version` with strict assertions; add two new tests

---

## Task 0: Pre-flight — Sanity-check the working tree

**Files:** none (verification only)

**Context:** This branch is stacked on `fix/issue-275-pre-initialize-handling`. The wire-test harness from #266 is present (via the same stack), and #275's pre-initialize match arm (`ExpectedInitializeRequest`) is the structural neighbor of the new `InitializeFailed` arms we're adding. The ignored test we'll un-ignore is `initialize_unsupported_protocol_version` at `crates/rimap-server/tests/mcp_wire_negative.rs:612-668`.

- [ ] **Step 1: Confirm the working tree is clean**

Run:
```bash
git status --short && git rev-parse --abbrev-ref HEAD
```

Expected: empty status; `fix/issue-276-protocol-version-negotiation` (or a stacked descendant).

- [ ] **Step 2: Confirm the harness, the ignored test, and #275's helper are all present**

Run:
```bash
test -f crates/rimap-server/tests/mcp_wire_negative.rs && \
test -f crates/rimap-server/tests/support/wire/harness.rs && \
test -f crates/rimap-server/src/mcp/preinit.rs && \
rg -q 'blocked on #276: server echoes unsupported protocol versions' crates/rimap-server/tests/mcp_wire_negative.rs && \
echo "OK: prerequisites present"
```

Expected: `OK: prerequisites present`. If any check fails, the rebase onto `fix/issue-275-pre-initialize-handling` (or its merged base) did not land — halt and consult the spec's Dependencies section.

- [ ] **Step 3: Confirm the workspace builds clean before changes**

Run:
```bash
cargo check --workspace --tests
```

Expected: clean exit, no errors.

- [ ] **Step 4: No commit. Move to Task 1.**

---

## Task 1: Add the `unsupported_protocol_version_error` helper with unit tests

**Files:**
- Modify: `crates/rimap-server/src/mcp/server.rs`

The helper is pure (no I/O, no state) so we TDD it directly. It produces the `ErrorData` payload that the override in Task 2 returns when the peer's version isn't `ProtocolVersion::LATEST`.

- [ ] **Step 1: Add the new types to the rmcp model import**

In `crates/rimap-server/src/mcp/server.rs`, find the existing `use rmcp::model::{ ... };` block at lines 19-24. Replace it with the expanded form below (adds `InitializeRequestParams`, `InitializeResult`, `ProtocolVersion`):

```rust
use rmcp::model::{
    CallToolRequestParams, CallToolResult, ErrorCode as McpCode, ErrorData, Implementation,
    InitializeRequestParams, InitializeResult, ListResourcesResult, ListToolsResult,
    PaginatedRequestParams, ProtocolVersion, RawResource, ReadResourceRequestParams,
    ReadResourceResult, Resource, ResourceContents, ServerCapabilities, ServerInfo, Tool,
};
```

- [ ] **Step 2: Write the failing helper-shape test**

At the very bottom of `crates/rimap-server/src/mcp/server.rs`, after the closing brace of `impl ServerHandler for ImapMcpServer { ... }`, add this `#[cfg(test)]` module. Mark all tests; they'll fail until Step 3 adds the helper. (If a `#[cfg(test)] mod tests` block already exists at the file bottom, merge these tests into it instead of creating a duplicate module.)

```rust
#[cfg(test)]
mod protocol_version_tests {
    #![expect(clippy::expect_used, reason = "tests")]
    #![expect(clippy::unwrap_used, reason = "tests")]

    use rmcp::model::{ErrorCode as McpCode, ProtocolVersion};
    use serde_json::{Value, json};

    use super::unsupported_protocol_version_error;

    /// Build a `ProtocolVersion` carrying an arbitrary version string.
    /// The rmcp deserializer accepts any string and produces a
    /// `ProtocolVersion(Cow::Owned(s))` for unknown values, so this is
    /// the cleanest way to construct one for tests.
    fn version_from_str(s: &str) -> ProtocolVersion {
        serde_json::from_value(json!(s)).expect("deserialize ProtocolVersion")
    }

    #[test]
    fn shape_matches_spec() {
        let v = version_from_str("1999-01-01");
        let err = unsupported_protocol_version_error(&v);

        assert_eq!(err.code, McpCode::INVALID_PARAMS);
        assert!(
            err.message.contains("1999-01-01"),
            "message must echo the peer version, got {:?}",
            err.message,
        );
        assert!(
            err.message.contains("2025-11-25"),
            "message must include the supported version, got {:?}",
            err.message,
        );

        let data = err.data.as_ref().expect("data field present");
        assert_eq!(
            data["supported_versions"],
            json!(["2025-11-25"]),
            "supported_versions must be a single-element array of LATEST, got {data}",
        );
    }

    #[test]
    fn uses_runtime_latest() {
        // Pins the contract that `supported_versions[0]` is built from
        // `ProtocolVersion::LATEST.as_str()` at runtime, not a hard-
        // coded literal. If a future rmcp bump shifts LATEST, this
        // test stays green; the literal-pinning `shape_matches_spec`
        // test will then surface the change visibly.
        let v = version_from_str("anything-goes");
        let err = unsupported_protocol_version_error(&v);
        let data = err.data.as_ref().expect("data field present");
        let arr = data["supported_versions"]
            .as_array()
            .expect("supported_versions is an array");
        assert_eq!(arr.len(), 1, "single-element array");
        assert_eq!(
            arr[0].as_str().expect("string"),
            ProtocolVersion::LATEST.as_str(),
        );
    }

    #[test]
    fn empty_peer_version_still_produces_envelope() {
        let v = version_from_str("");
        let err = unsupported_protocol_version_error(&v);
        assert_eq!(err.code, McpCode::INVALID_PARAMS);
        // Single-quoted empty string in the message: "...'%s'..."
        assert!(
            err.message.contains("''"),
            "empty peer version should appear as '' in message, got {:?}",
            err.message,
        );
    }

    #[test]
    fn data_field_is_present() {
        // Guards against accidentally constructing the error without
        // the data payload (would break machine-readable retry).
        let v = version_from_str("1999-01-01");
        let err = unsupported_protocol_version_error(&v);
        assert!(err.data.is_some(), "data field must be present");
    }

    // Suppress unused-binding warning when the bound is not consumed
    // in every test under conditional compilation.
    #[expect(dead_code, reason = "shared test fixture")]
    fn _ensure_value_used(_: Value) {}
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run:
```bash
cargo test -p rimap-server --lib mcp::server::protocol_version_tests 2>&1 | head -30
```

Expected: compile error — `cannot find function 'unsupported_protocol_version_error' in module 'super'`.

- [ ] **Step 4: Add the helper at the bottom of `mcp/server.rs`**

Add this private free function immediately BEFORE the `#[cfg(test)] mod protocol_version_tests` block you just added (so it's in module scope, reachable via `super::`):

```rust
/// Build the `ErrorData` payload returned by `ImapMcpServer::initialize`
/// when the peer's `protocolVersion` is not exactly
/// `ProtocolVersion::LATEST`. The envelope's `data` field carries
/// `supported_versions` as a single-element array so clients have a
/// machine-readable retry hint, and the message echoes the offending
/// version in single quotes for log readability. (#276)
fn unsupported_protocol_version_error(peer_version: &ProtocolVersion) -> ErrorData {
    let supported = [ProtocolVersion::LATEST.as_str()];
    let message = format!(
        "Unsupported protocol version: '{}'. Server supports: {}.",
        peer_version.as_str(),
        supported.join(", "),
    );
    let data = serde_json::json!({ "supported_versions": supported });
    ErrorData::invalid_params(message, Some(data))
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run:
```bash
cargo test -p rimap-server --lib mcp::server::protocol_version_tests
```

Expected: 4 tests pass:
- `shape_matches_spec`
- `uses_runtime_latest`
- `empty_peer_version_still_produces_envelope`
- `data_field_is_present`

- [ ] **Step 6: Run clippy on the modified file**

Run:
```bash
cargo clippy -p rimap-server --lib --all-features -- -D warnings
```

Expected: clean. If clippy reports `dead_code` on the helper (because no call site exists yet — the `initialize` override is in Task 2), add a one-line `#[cfg_attr(not(test), expect(dead_code, reason = "wired into ImapMcpServer::initialize in the next commit (#276 task 2)"))]` attribute immediately above the function. The `#[expect]` form is mandated by the workspace's `allow_attributes = "deny"` clippy rule; Task 2 will remove the attribute as a natural consequence of adding the call site.

- [ ] **Step 7: Commit**

```bash
git add crates/rimap-server/src/mcp/server.rs
git commit -m "$(cat <<'EOF'
feat(rimap-server): add unsupported_protocol_version_error helper (#276)

Pure helper that builds the JSON-RPC -32602 ErrorData payload for
peers whose protocolVersion isn't ProtocolVersion::LATEST. Message
echoes the peer version in single quotes; data field carries
supported_versions as a single-element array so clients have a
machine-readable retry hint.

Not yet wired into ImapMcpServer::initialize — that's the next commit.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Override `ImapMcpServer::initialize` to validate the protocol version

**Files:**
- Modify: `crates/rimap-server/src/mcp/server.rs`

This is the behavior-change commit. The override delegates to default behavior when the peer's version matches `LATEST`, and short-circuits with `Err(unsupported_protocol_version_error(...))` otherwise. rmcp at `service/server.rs:222` converts the Err into a wire `-32602` envelope and returns `Err(ServerInitializeError::InitializeFailed(...))` from `serve_server`; Task 4 will classify that as a handled rejection.

- [ ] **Step 1: Add the `initialize` override**

In `crates/rimap-server/src/mcp/server.rs`, find the `impl ServerHandler for ImapMcpServer { ... }` block (starts around line 254). The first method is `fn get_info(&self) -> ServerInfo`. Insert the new `async fn initialize` IMMEDIATELY AFTER `get_info` and BEFORE `async fn list_tools`. The exact placement keeps the trait methods in the same order rmcp's trait declaration uses (initialize-related first, then list/call methods).

```rust
    async fn initialize(
        &self,
        request: InitializeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<InitializeResult, ErrorData> {
        // LATEST-only acceptance per spec §"Why LATEST-only" (#276):
        // rmcp 1.5 emits LATEST wire shapes regardless of negotiated
        // version, so accepting older known versions would echo the
        // peer's version string while serving 2025-11-25 capabilities.
        // The exact-equality check is the only honest option.
        if request.protocol_version != ProtocolVersion::LATEST {
            return Err(unsupported_protocol_version_error(&request.protocol_version));
        }
        // Preserve the default-impl behavior for the happy path so the
        // peer's ClientInfo is captured for subsequent dispatch.
        if context.peer.peer_info().is_none() {
            context.peer.set_peer_info(request);
        }
        Ok(self.get_info())
    }
```

- [ ] **Step 2: Remove the dead_code suppression from Task 1 (if you added it)**

If Step 6 of Task 1 added `#[cfg_attr(not(test), expect(dead_code, reason = "..."))]` above `unsupported_protocol_version_error`, delete those lines now. The `initialize` override is the call site that makes the helper live. The `#[expect]` form would now fail compilation because the underlying `dead_code` lint no longer fires.

- [ ] **Step 3: Build the workspace**

Run:
```bash
cargo check --workspace --tests
```

Expected: clean. If errors mention `InitializeRequestParams`, `InitializeResult`, or `ProtocolVersion` not in scope, verify that Task 1 Step 1's expanded `use rmcp::model::{ ... };` block landed.

- [ ] **Step 4: Run clippy**

Run:
```bash
cargo clippy -p rimap-server --all-targets --all-features -- -D warnings
```

Expected: clean. If clippy complains about `must_use_candidate` on the helper (now that it has a caller and might be a future public surface), add `#[must_use]` immediately above the helper declaration — same pattern as #275's `synthesize_pre_init_error_envelope`.

- [ ] **Step 5: Run the existing test suite to confirm no regressions**

Run:
```bash
cargo test -p rimap-server --lib
```

Expected: all tests pass, including the 4 new helper tests from Task 1 and the existing #275 `mcp::preinit::tests::*`. Do NOT run the ignored wire test `initialize_unsupported_protocol_version` — that's Task 5's job.

- [ ] **Step 6: Commit**

```bash
git add crates/rimap-server/src/mcp/server.rs
git commit -m "$(cat <<'EOF'
fix(rimap-server): reject non-LATEST protocolVersion in initialize (#276)

Override ServerHandler::initialize on ImapMcpServer to return
Err(unsupported_protocol_version_error(...)) when the peer's
protocolVersion is not exactly ProtocolVersion::LATEST. rmcp converts
the Err into a JSON-RPC -32602 wire envelope and short-circuits with
ServerInitializeError::InitializeFailed; main.rs's match arm (next
commit) classifies that as a handled rejection (clean exit 0, audit
Eof).

The strict LATEST-only narrowing matches what rmcp 1.5 actually
emits — its serde types target LATEST exclusively. Accepting older
versions would echo the peer's version string while serving
2025-11-25 capabilities, recreating the unproven-semantics bug class
#276 is fixing. See spec §"Why LATEST-only".

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Add the `initialize_failure_is_handled_rejection` classifier with unit tests

**Files:**
- Modify: `crates/rimap-server/src/main.rs`

The classifier is a one-line `matches!` on `ErrorCode`. We unit-test it directly so the boundary between handled-client-rejection (INVALID_PARAMS) and server-fault (INTERNAL_ERROR and others) is pinned without needing a full integration test with a test-support hook.

- [ ] **Step 1: Add the `ErrorCode` import**

In `crates/rimap-server/src/main.rs`, find the existing `use rmcp::service::ServerInitializeError;` at line 27. Add a sibling import directly above or below it:

```rust
use rmcp::model::ErrorCode as McpErrorCode;
```

The local alias `McpErrorCode` matches the pattern `mcp/error.rs` uses (`ErrorCode as McpCode`); it avoids a name collision with `rimap_core::ErrorCode` if that ever surfaces in main.rs.

- [ ] **Step 2: Write the failing classifier test**

In `crates/rimap-server/src/main.rs`, find the `#[cfg(all(test, unix))] mod resolve_download_dir_tests { ... }` block at the bottom of the file (around line 428). After its closing brace, add a NEW sibling test module:

```rust
#[cfg(test)]
mod initialize_failure_classifier_tests {
    use rmcp::model::ErrorCode as McpErrorCode;

    use super::initialize_failure_is_handled_rejection;

    #[test]
    fn invalid_params_is_handled_rejection() {
        assert!(initialize_failure_is_handled_rejection(McpErrorCode::INVALID_PARAMS));
    }

    #[test]
    fn internal_error_is_not_handled_rejection() {
        assert!(!initialize_failure_is_handled_rejection(McpErrorCode::INTERNAL_ERROR));
    }

    #[test]
    fn method_not_found_is_not_handled_rejection() {
        assert!(!initialize_failure_is_handled_rejection(McpErrorCode::METHOD_NOT_FOUND));
    }

    #[test]
    fn unknown_codes_are_not_handled_rejection() {
        // Future-proofing: any code we haven't explicitly allow-listed
        // must propagate as a server fault.
        assert!(!initialize_failure_is_handled_rejection(McpErrorCode(-32099)));
        assert!(!initialize_failure_is_handled_rejection(McpErrorCode(-32603 - 1)));
        assert!(!initialize_failure_is_handled_rejection(McpErrorCode(-32700)));
    }
}
```

This test module uses `#[cfg(test)]` (not the platform-gated `#[cfg(all(test, unix))]` of its neighbor) because the classifier has no platform-specific behavior.

- [ ] **Step 3: Run the test to verify it fails**

Run:
```bash
cargo test -p rimap-server --bin rusty-imap-mcp initialize_failure_classifier 2>&1 | head -20
```

Expected: compile error — `cannot find function 'initialize_failure_is_handled_rejection' in module 'super'`.

- [ ] **Step 4: Add the classifier helper**

In `crates/rimap-server/src/main.rs`, find a clear location for a small helper function — a good spot is immediately AFTER `emit_pre_init_error_envelope` (the #275 helper currently at lines 188-203). Add:

```rust
/// Classify a `ServerInitializeError::InitializeFailed` outcome by its
/// inner `ErrorData.code`. Returns `true` for client-side bad-input
/// codes that the wire envelope already communicated cleanly; the
/// caller treats these as handled rejections (exit 0, audit `Eof`).
/// Returns `false` for server-fault classes (`INTERNAL_ERROR` and
/// anything else) so they propagate as non-zero exit with audit
/// `Error`, keeping initialize-time outages observable. (#276)
fn initialize_failure_is_handled_rejection(code: McpErrorCode) -> bool {
    matches!(code, McpErrorCode::INVALID_PARAMS)
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run:
```bash
cargo test -p rimap-server --bin rusty-imap-mcp initialize_failure_classifier
```

Expected: 4 tests pass.

- [ ] **Step 6: Run clippy**

Run:
```bash
cargo clippy -p rimap-server --bin rusty-imap-mcp --all-features -- -D warnings
```

Expected: clean. If clippy fires `dead_code` on `initialize_failure_is_handled_rejection` (because the call site in `main.rs::run` comes in Task 4), add a one-line `#[cfg_attr(not(test), expect(dead_code, reason = "wired into main.rs::run in the next commit (#276 task 4)"))]` attribute above the function. Task 4 removes it as a natural consequence of adding the call site.

- [ ] **Step 7: Commit**

```bash
git add crates/rimap-server/src/main.rs
git commit -m "$(cat <<'EOF'
feat(rimap-server): add initialize_failure_is_handled_rejection helper (#276)

One-line matches! on rmcp::model::ErrorCode that distinguishes
client-side bad-input (INVALID_PARAMS) from server-fault classes
(INTERNAL_ERROR, METHOD_NOT_FOUND, anything else). Unit tests pin the
boundary directly without needing a wire-level test-support hook.

Not yet wired into main.rs::run — that's the next commit.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Wire the code-gated `InitializeFailed` arms into `main.rs::run`

**Files:**
- Modify: `crates/rimap-server/src/main.rs`

This is the second behavior-change commit. The new arms sit between #275's existing `ExpectedInitializeRequest` arm and the fallback `Err(other) => return Err(...)` catch-all. INVALID_PARAMS routes to clean exit; everything else propagates as today.

- [ ] **Step 1: Update the `serve_server` match block**

In `crates/rimap-server/src/main.rs`, locate the existing match block in `run()` (currently lines 140-147):

```rust
        let service = match Box::pin(rmcp::serve_server(mcp_server, transport)).await {
            Ok(svc) => svc,
            Err(ServerInitializeError::ExpectedInitializeRequest(Some(msg))) => {
                emit_pre_init_error_envelope(&msg).await?;
                return Ok(());
            }
            Err(other) => return Err(anyhow::anyhow!("MCP server init: {other}")),
        };
```

Replace with the expanded version below, inserting TWO new arms between the existing pre-init arm and the catch-all:

```rust
        let service = match Box::pin(rmcp::serve_server(mcp_server, transport)).await {
            Ok(svc) => svc,
            Err(ServerInitializeError::ExpectedInitializeRequest(Some(msg))) => {
                emit_pre_init_error_envelope(&msg).await?;
                return Ok(());
            }
            Err(ServerInitializeError::InitializeFailed(error_data))
                if initialize_failure_is_handled_rejection(error_data.code) =>
            {
                // rmcp already sent the error envelope to the client.
                // INVALID_PARAMS at the initialize boundary is a handled
                // client rejection (e.g. unsupported protocol version per
                // #276), not a server fault — clean exit 0, audit Eof.
                tracing::info!(
                    code = error_data.code.0,
                    "rejected initialize with error envelope",
                );
                return Ok(());
            }
            Err(ServerInitializeError::InitializeFailed(error_data)) => {
                // Server-fault classes (INTERNAL_ERROR and others) must
                // surface as non-zero exit with process_end.reason: Error
                // so initialize-time outages stay observable in the audit
                // trail. (Codex adversarial-review finding 2026-05-14)
                return Err(anyhow::anyhow!(
                    "MCP server init failed: code {}: {}",
                    error_data.code.0,
                    error_data.message,
                ));
            }
            Err(other) => return Err(anyhow::anyhow!("MCP server init: {other}")),
        };
```

Match-arm ordering matters: the guarded arm MUST come before the unguarded one with the same pattern, otherwise the unguarded arm will absorb every `InitializeFailed`.

- [ ] **Step 2: Remove the dead_code suppression from Task 3 (if you added it)**

If Step 6 of Task 3 added `#[cfg_attr(not(test), expect(dead_code, reason = "..."))]` above `initialize_failure_is_handled_rejection`, delete it now. The match arm is the call site that makes the helper live.

- [ ] **Step 3: Build the workspace**

Run:
```bash
cargo check --workspace --tests
```

Expected: clean. If errors mention `error_data.code.0`, the rmcp `ErrorCode` type may have a different inner-field name in your local rmcp 1.5 — verify with `grep "pub struct ErrorCode" ~/.cargo/registry/src/index.crates.io-*/rmcp-1.5*/src/model.rs`. The inner field is `0` because `ErrorCode(i32)` is a single-field tuple struct (per earlier exploration, `pub struct ErrorCode(pub i32)`).

- [ ] **Step 4: Run clippy**

Run:
```bash
cargo clippy -p rimap-server --all-targets --all-features -- -D warnings
```

Expected: clean.

- [ ] **Step 5: Run lib + binary test suites to confirm no regressions**

Run:
```bash
cargo test -p rimap-server --lib
```

Expected: all pass, including:
- 4 new `mcp::server::protocol_version_tests::*` from Task 1
- 6 existing `mcp::preinit::tests::*` from #275

Run:
```bash
cargo test -p rimap-server --bin rusty-imap-mcp
```

Expected: all pass, including:
- 4 new `initialize_failure_classifier_tests::*` from Task 3
- existing `resolve_download_dir_tests::*`

- [ ] **Step 6: Commit**

```bash
git add crates/rimap-server/src/main.rs
git commit -m "$(cat <<'EOF'
fix(rimap-server): code-gate InitializeFailed handling in main::run (#276)

Adds two match arms to the serve_server result:

- InitializeFailed with INVALID_PARAMS: rmcp already sent the wire
  envelope (e.g. for unsupported protocol version per #276); exit 0
  with process_end.reason: Eof. Same audit semantics as #275's
  pre-init handled path.
- InitializeFailed with anything else (INTERNAL_ERROR, etc.):
  propagate as anyhow::Error so process_end.reason: Error and the
  process exits non-zero. Keeps initialize-time outages observable
  in the audit trail.

Closes Codex adversarial-review finding 2026-05-14 (medium).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: Un-ignore `initialize_unsupported_protocol_version` with strict assertions

**Files:**
- Modify: `crates/rimap-server/tests/mcp_wire_negative.rs`

This is the first wire-level verification of Tasks 1-4. The test already exists at lines 612-668 with `#[ignore = "blocked on #276: ..."]`; we un-ignore and tighten.

- [ ] **Step 1: Replace the existing test body**

In `crates/rimap-server/tests/mcp_wire_negative.rs`, locate the existing `initialize_unsupported_protocol_version` test (around lines 600-668, beginning with the `// Test 8: \`initialize\` with unsupported protocol version` banner). Replace the entire test region (docstring + attributes + body) with:

```rust
// ---------------------------------------------------------------------------
// Test 8: `initialize` with unsupported protocol version
// ---------------------------------------------------------------------------

/// Client requests a protocol version the server doesn't support. Per
/// spec §"Desired behavior" (#276), the server must reply with a
/// JSON-RPC -32602 error envelope listing `supported_versions ==
/// ["2025-11-25"]`, then close cleanly and exit 0 with audit reason
/// Eof. Fixed by #276.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn initialize_unsupported_protocol_version() {
    let mut harness = Harness::spawn().await;
    let audit_path = harness.audit_path();

    let _id = harness
        .send_request_no_wait(
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

    // Phase 1: error envelope arrives with -32602.
    let envelope = match harness.response_or_close(REQUEST_TIMEOUT).await {
        CloseOrResponse::Response(line) => parse_response_line(&line),
        other => panic!(
            "expected -32602 error envelope for unsupported protocol version, got {other:?}"
        ),
    };
    assert!(
        envelope["error"].is_object(),
        "must be an error envelope, got {envelope}",
    );
    assert_eq!(
        envelope["error"]["code"],
        json!(-32602),
        "must be code -32602 (INVALID_PARAMS), got {envelope}",
    );
    assert_eq!(
        envelope["error"]["data"]["supported_versions"],
        json!(["2025-11-25"]),
        "supported_versions must be exactly [\"2025-11-25\"] — locks in LATEST-only \
         posture and prevents older version names from sneaking onto the wire; got {envelope}",
    );
    let message = envelope["error"]["message"]
        .as_str()
        .expect("error.message is a string");
    assert!(
        message.contains("1999-01-01"),
        "message must echo the peer version 1999-01-01, got {message:?}",
    );
    assert!(
        message.contains("2025-11-25"),
        "message must include the supported version 2025-11-25, got {message:?}",
    );
    assert_envelope_valid(&envelope);

    // Phase 2: stdout closes and the server exits 0.
    match harness.response_or_close(REQUEST_TIMEOUT).await {
        CloseOrResponse::CleanClose => {}
        other => panic!(
            "expected clean close after envelope on unsupported protocol version, got {other:?}"
        ),
    }

    // Phase 3: audit log captured the success path as reason Eof.
    let reason = read_process_end_reason(&audit_path);
    assert_eq!(
        reason,
        rimap_audit::ProcessEndReason::Eof,
        "process_end.reason must be Eof on handled INVALID_PARAMS rejection",
    );
}
```

- [ ] **Step 2: Run the test**

Run:
```bash
cargo test -p rimap-server --test mcp_wire_negative initialize_unsupported_protocol_version -- --nocapture
```

Expected: PASS. The test:
- Receives a `-32602` envelope with `supported_versions == ["2025-11-25"]`
- Sees the server close stdin cleanly (exit 0)
- Reads `process_end.reason == Eof` from the audit log

If it fails:
- Got a success response with `protocolVersion: "1999-01-01"` echoed back: Task 2 didn't land — check `mcp/server.rs` for the `initialize` override.
- Got crashed / non-zero exit: Task 4 didn't land — check `main.rs::run` for the two new arms.
- `supported_versions` mismatch: check Task 1's helper produces a single-element array.
- `no process_end record found`: see Task 5 of the #275 plan; same root cause if it surfaces here.

- [ ] **Step 3: Run clippy on the test binary**

Run:
```bash
cargo clippy -p rimap-server --test mcp_wire_negative -- -D warnings
```

Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-server/tests/mcp_wire_negative.rs
git commit -m "$(cat <<'EOF'
test(rimap-server): pin -32602 contract for unsupported version (#276)

Un-ignore initialize_unsupported_protocol_version with strict
assertions matching the LATEST-only posture:
- response envelope must be code -32602 with the peer version echoed
- supported_versions must equal ["2025-11-25"] exactly
- server must close stdin cleanly with exit 0
- audit log must record process_end.reason: Eof

The exact-array assertion on supported_versions is the tripwire
against any future relaxation that would re-add older version names.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: Add `initialize_with_known_older_version_is_rejected`

**Files:**
- Modify: `crates/rimap-server/tests/mcp_wire_negative.rs`

Pins the strict LATEST-only posture against any future permissive relaxation. Sends a known older version (`"2024-11-05"`) — which would silently succeed under the original buggy rmcp behavior — and verifies the same `-32602` rejection.

- [ ] **Step 1: Write the test**

In `crates/rimap-server/tests/mcp_wire_negative.rs`, add this test immediately after `initialize_unsupported_protocol_version`:

```rust
/// Strict-posture tripwire (#276 Codex adversarial-review Finding 1):
/// known older MCP versions (`2024-11-05`, etc.) MUST also be rejected
/// with -32602, even though they appear in `ProtocolVersion::KNOWN_VERSIONS`.
/// rmcp 1.5 doesn't actually emit older wire shapes — accepting them
/// would echo "2024-11-05" while serving 2025-11-25-shaped responses.
/// This test fails if a future change ever broadens the acceptance set,
/// forcing the relaxation to be a deliberate spec revision.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn initialize_with_known_older_version_is_rejected() {
    let mut harness = Harness::spawn().await;

    let _id = harness
        .send_request_no_wait(
            "initialize",
            json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "rusty-imap-mcp-phase4-test",
                    "version": "0.0.0",
                },
            }),
        )
        .await;

    let envelope = match harness.response_or_close(REQUEST_TIMEOUT).await {
        CloseOrResponse::Response(line) => parse_response_line(&line),
        other => panic!(
            "expected -32602 rejection for known older version 2024-11-05, got {other:?}"
        ),
    };
    assert_eq!(
        envelope["error"]["code"],
        json!(-32602),
        "known older version must be rejected, not silently accepted; got {envelope}",
    );
    assert_eq!(
        envelope["error"]["data"]["supported_versions"],
        json!(["2025-11-25"]),
        "supported_versions must remain [\"2025-11-25\"] even when peer asks for a known older version, got {envelope}",
    );
    let message = envelope["error"]["message"]
        .as_str()
        .expect("error.message is a string");
    assert!(
        message.contains("2024-11-05"),
        "message must echo the rejected peer version 2024-11-05, got {message:?}",
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
cargo test -p rimap-server --test mcp_wire_negative initialize_with_known_older_version_is_rejected -- --nocapture
```

Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/rimap-server/tests/mcp_wire_negative.rs
git commit -m "$(cat <<'EOF'
test(rimap-server): pin LATEST-only posture against known older versions (#276)

Adds a tripwire test that sends a KNOWN_VERSIONS member (2024-11-05)
and asserts it gets the same -32602 rejection as unknown garbage.
Locks in the Codex Finding 1 resolution: rmcp 1.5 doesn't actually
emit older wire shapes, so the server must not advertise compatibility
with versions it cannot serve.

This test BLOCKS any future change that relaxes the protocol-version
acceptance set without first adding per-version conformance.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: Add `initialize_with_empty_string_protocol_version`

**Files:**
- Modify: `crates/rimap-server/tests/mcp_wire_negative.rs`

Pins the edge case: an empty `protocolVersion` string is valid JSON but a degenerate value. Must be rejected.

- [ ] **Step 1: Write the test**

In `crates/rimap-server/tests/mcp_wire_negative.rs`, add this test immediately after `initialize_with_known_older_version_is_rejected`:

```rust
/// Edge case: `protocolVersion: ""` is valid JSON but a degenerate
/// version string. Must be rejected with -32602. Pins the boundary
/// against any future code that might special-case empty strings.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn initialize_with_empty_string_protocol_version() {
    let mut harness = Harness::spawn().await;

    let _id = harness
        .send_request_no_wait(
            "initialize",
            json!({
                "protocolVersion": "",
                "capabilities": {},
                "clientInfo": {
                    "name": "rusty-imap-mcp-phase4-test",
                    "version": "0.0.0",
                },
            }),
        )
        .await;

    let envelope = match harness.response_or_close(REQUEST_TIMEOUT).await {
        CloseOrResponse::Response(line) => parse_response_line(&line),
        other => panic!(
            "expected -32602 rejection for empty protocolVersion, got {other:?}"
        ),
    };
    assert_eq!(envelope["error"]["code"], json!(-32602));
    assert_eq!(
        envelope["error"]["data"]["supported_versions"],
        json!(["2025-11-25"]),
    );
    let message = envelope["error"]["message"]
        .as_str()
        .expect("error.message is a string");
    assert!(
        message.contains("''"),
        "empty peer version should appear as '' in the human-readable message, got {message:?}",
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
cargo test -p rimap-server --test mcp_wire_negative initialize_with_empty_string_protocol_version -- --nocapture
```

Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/rimap-server/tests/mcp_wire_negative.rs
git commit -m "$(cat <<'EOF'
test(rimap-server): pin empty-string protocolVersion rejection (#276)

Edge case: protocolVersion: "" is valid JSON but degenerate. Must be
rejected with the same -32602 contract as any non-LATEST version.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: Full local-CI sweep and PR creation

**Files:** none expected; this task verifies everything composes.

- [ ] **Step 1: Run the full mcp_wire_negative binary to confirm no regressions across the suite**

Run:
```bash
cargo test -p rimap-server --test mcp_wire_negative
```

Expected: all tests pass (no `#[ignore]`'d tests blocking on #276 remain; the one blocked on #277, `prop_envelope_never_panics`, is in a different binary).

- [ ] **Step 2: Run `just ci`**

Run:
```bash
just ci
```

Expected: PASS. This runs fmt-check, clippy with `-D warnings`, the workspace test suite via nextest, and `cargo deny`.

Common late-stage failures:
- **`cargo deny` advisory failure for lettre or another crate**: the #275 PR (#279) already bumped lettre. If a new advisory has landed since then, address it in a sibling commit on this branch and re-run.
- **Clippy `dead_code` on either helper**: confirm Task 2 Step 2 and Task 4 Step 2 removed the placeholder `#[cfg_attr]` attributes.
- **Test failure on `tools_list_before_initialize` (or another #275 test)**: this plan should NOT have affected #275 paths. If it did, the new `InitializeFailed` arms in `main.rs::run` are absorbing a case they shouldn't — re-check the match-arm ordering (guarded INVALID_PARAMS arm comes BEFORE the unguarded `InitializeFailed` catch-all).

- [ ] **Step 3: Verify no stale `#[ignore]` referencing #276 remains**

Run:
```bash
rg -n '#\[ignore.*#276' crates/
```

Expected: no matches.

- [ ] **Step 4: Verify the commit log matches the plan**

Run:
```bash
git log --oneline HEAD ^fix/issue-275-pre-initialize-handling
```

Expected:
1. `feat(rimap-server): add unsupported_protocol_version_error helper (#276)` (Task 1)
2. `fix(rimap-server): reject non-LATEST protocolVersion in initialize (#276)` (Task 2)
3. `feat(rimap-server): add initialize_failure_is_handled_rejection helper (#276)` (Task 3)
4. `fix(rimap-server): code-gate InitializeFailed handling in main::run (#276)` (Task 4)
5. `test(rimap-server): pin -32602 contract for unsupported version (#276)` (Task 5)
6. `test(rimap-server): pin LATEST-only posture against known older versions (#276)` (Task 6)
7. `test(rimap-server): pin empty-string protocolVersion rejection (#276)` (Task 7)
8. (Plus the two earlier docs commits from the brainstorming/Codex-review phase, depending on what's in `^fix/issue-275-pre-initialize-handling`)

- [ ] **Step 5: Push and open the PR**

The branch target depends on whether PR #279 (the #275 PR) has merged yet. Pick the matching command:

**If PR #279 is still open** (this PR stacks on #275):

```bash
GIT_SSH_COMMAND='ssh -o ServerAliveInterval=30 -o ServerAliveCountMax=10' git push -u origin fix/issue-276-protocol-version-negotiation
gh pr create --base fix/issue-275-pre-initialize-handling --title "fix(rimap-server): reject non-LATEST protocolVersion in initialize (#276)" --body "$(cat <<'EOF'
## Summary

- Override `ServerHandler::initialize` to reject any `protocolVersion` other than `ProtocolVersion::LATEST` (currently `"2025-11-25"`) with a JSON-RPC `-32602` error envelope listing `supported_versions == ["2025-11-25"]`.
- Code-gate `ServerInitializeError::InitializeFailed` handling in `main.rs::run`: `INVALID_PARAMS` → clean exit (audit `Eof`); `INTERNAL_ERROR` and other server-fault codes → propagated `anyhow::Error` (audit `Error`).
- Per Codex adversarial-review Finding 1, posture is strict LATEST-only (not permissive `KNOWN_VERSIONS`) — rmcp 1.5 has no per-version serialization, so accepting older versions would echo the peer's version while serving 2025-11-25-shaped responses.

Fixes #276. Stacked on PR #279 (#275). Targets `fix/issue-275-pre-initialize-handling` while #279 is open; rebase onto `feature/issue-266-mcp-fuzzing` once #279 merges.

## Test plan

- [ ] `cargo test -p rimap-server --test mcp_wire_negative` — 3 new wire tests pass (`initialize_unsupported_protocol_version` un-ignored, plus `initialize_with_known_older_version_is_rejected` and `initialize_with_empty_string_protocol_version` added)
- [ ] `cargo test -p rimap-server --lib mcp::server::protocol_version_tests` — 4 helper unit tests pass
- [ ] `cargo test -p rimap-server --bin rusty-imap-mcp initialize_failure_classifier_tests` — 4 classifier unit tests pass
- [ ] `just ci` passes locally

Spec: `docs/superpowers/specs/2026-05-14-issue-276-protocol-version-negotiation-design.md`
Plan: `docs/superpowers/plans/2026-05-14-issue-276-protocol-version-negotiation.md`

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

**If PR #279 has merged into `feature/issue-266-mcp-fuzzing`** (rebase first, then target the feature branch):

```bash
git fetch origin
git rebase origin/feature/issue-266-mcp-fuzzing
GIT_SSH_COMMAND='ssh -o ServerAliveInterval=30 -o ServerAliveCountMax=10' git push -u origin fix/issue-276-protocol-version-negotiation
gh pr create --base feature/issue-266-mcp-fuzzing --title "fix(rimap-server): reject non-LATEST protocolVersion in initialize (#276)" --body "$(cat <<'EOF'
## Summary

(same body as above)

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

The `GIT_SSH_COMMAND` keepalive override is required on this repo per the auto-memory note (`project_push_ssh_keepalive.md`); without it, the pre-push hook's long `just test` + `cargo deny` run lets GitHub idle-close the SSH connection and the push exits 0 with no ref transfer.

After push, verify the remote ref landed:

```bash
git ls-remote origin fix/issue-276-protocol-version-negotiation
```

Expected: the local HEAD SHA matches the remote ref.

---

## Done

All tasks complete. Verify with one final read-through of `git log fix/issue-276-protocol-version-negotiation ^fix/issue-275-pre-initialize-handling` — should show the 7 implementation/test commits plus the two docs commits from the brainstorming phase (the design spec + Codex-review revisions).
