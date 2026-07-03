# Return tool-execution failures as `CallToolResult { isError: true }` (#402)

## Context

Every runtime tool failure is currently returned as a JSON-RPC **protocol
error**. The single choke point is `run_with_audit_envelope`
(`crates/rimap-server/src/mcp/audit_envelope.rs:102-105`):

```rust
match result {
    Ok(value) => Ok(CallToolResult::structured(value)),
    Err(e) => Err(crate::mcp::error::to_mcp_error(&e)),
}
```

`to_mcp_error` (`crates/rimap-server/src/mcp/error.rs`) maps every
`RimapError` to an `ErrorData` with a JSON-RPC / custom code (`-32001`
posture, `-32003` rate limit, `-32004` breaker, `-32005` size,
`RESOURCE_NOT_FOUND`, `INVALID_PARAMS`, `INTERNAL_ERROR`). The typed
recovery `data` built by #303 (`retry_after_ms`, expected/actual
uidvalidity, `kind`/`limit`, available accounts) rides on the JSON-RPC
`error.data` channel.

The MCP spec distinguishes **protocol errors** (the framework could not
route or execute the request at all — unknown method, unknown tool, bad
params shape) from **tool-execution errors** (the tool ran and failed).
The spec says the latter SHOULD be returned inside a normal
`CallToolResult` with `isError: true` so the host reliably surfaces the
`content` to the model, which can then self-correct. Host handling of
protocol errors varies (some render opaquely, some abort the turn), so
the recoverable messages this server produces are on the channel with
the weakest delivery guarantee. `rmcp`'s own `CallToolResult::error`
docstring states the same rule: "This is the right choice for almost
every 'the tool ran and didn't work' case."

## Goal

Return domain / execution failures as `CallToolResult { is_error: true }`
carrying the human-readable message as `content` text and the
machine-readable `error_code` + typed `data` as `structured_content`.
Keep genuine protocol/routing/infrastructure failures as JSON-RPC
`ErrorData`. Leave the audit pipeline unchanged.

## The boundary: classify by `ErrorCode`, decided at the envelope choke point

The decision is made in `run_with_audit_envelope`'s terminal `match` —
the one place every executed-tool result already funnels through, so the
change stays contained (as the issue notes). The branch is driven by a
classifier over the error's stable `ErrorCode`, NOT by where the error
was produced. Classifying by code (not by call-site) makes the mapping
consistent no matter which path raised the error: e.g. `UnknownAccount`
is a protocol error whether it came from per-call account resolution
(pre-envelope, in `call_tool`) or from the `use_account` tool
(in-envelope).

### Tool-execution errors → `CallToolResult { isError: true }`

| `ErrorCode` | today's wire code | rationale |
|-------------|-------------------|-----------|
| `NotFound` | `RESOURCE_NOT_FOUND` | UID / folder / part missing — agent can retry with a valid target |
| `UidValidityChanged` | `INVALID_PARAMS` | expected/actual carried in `data`; agent re-SELECTs and retries |
| `RateLimited` | `-32003` | `retry_after_ms` is a retry hint the agent must read |
| `CircuitOpen` | `-32004` | `retry_after_ms` retry hint (0 = half-open probe) |
| `AttachmentTooLarge` | `-32005` | `kind`/`limit` let the agent request a smaller slice |
| `ImapProtocol` | `INTERNAL_ERROR` | server-side IMAP failure the agent may retry |
| `SmtpProtocol` | `INTERNAL_ERROR` | send rejected; message is actionable |
| `Tls` | `INTERNAL_ERROR` | connection-layer failure surfaced to the agent |
| `Auth` | `INTERNAL_ERROR` | credential failure surfaced to the agent |
| `ConnectionLost` | `INTERNAL_ERROR` | mid-call disconnect; retryable |
| `Timeout` | `INTERNAL_ERROR` | retryable |
| `PostureDenied` | `-32001` | denial the agent must read (opaque message preserved) |
| `ProtectedFolder` | `-32001` | folder-policy denial (opaque message preserved) |
| `ExpungeDenied` | `-32001` | folder-policy denial (opaque message preserved) |

### Protocol / routing / infrastructure errors → `ErrorData` (unchanged)

| `ErrorCode` | wire code | rationale |
|-------------|-----------|-----------|
| `InvalidInput` | `INVALID_PARAMS` | malformed / invalid **params shape** — a framework-layer routing failure, per the issue's explicit carve-out |
| `NoAccount` | `INVALID_PARAMS` | account **selection** is a routing concern resolved (for account-scoped tools) before the tool executes; `data.available` still travels |
| `UnknownAccount` | `INVALID_PARAMS` | named account does not resolve — same routing concern as `NoAccount` |
| `Config` | `INTERNAL_ERROR` | server misconfiguration — not agent-recoverable |
| `Internal` | `INTERNAL_ERROR` | server bug / invariant violation — not agent-recoverable |
| `Cancelled` | `INTERNAL_ERROR` | call was cancelled; no meaningful result to return |

Also unchanged (all raised **before** the envelope opens, so they never
reach the choke point): unknown tool name (`ToolName::from_str` →
`INVALID_PARAMS`), tool-not-advertised (`RESOURCE_NOT_FOUND`), bad
namespace (`validate_bare_tool_namespace`), infrastructure-namespaced
rejection, unsupported protocol version (`initialize` →
`INVALID_PARAMS`), and wire-validator / framing rejections. These are
genuine protocol errors and stay `ErrorData`.

### Why `NoAccount` / `UnknownAccount` stay protocol errors

They are the one debatable case: their `data.available` payload is
recovery information, which argues for `isError`. But (a) account
selection is resolved at the routing layer — for account-scoped tools it
happens in `call_tool` **before** `run_with_audit_envelope` opens (no
`tool_start` is emitted for a call that never resolved a tool to run),
so treating it as a params/routing failure matches where it lives; (b)
the issue's recommended-fix list enumerates the `isError` classes and
does not include them; (c) classifying by code keeps the `use_account`
path (which raises `UnknownAccount` in-envelope) consistent with the
account-resolution path. The `available` payload continues to ride
`error.data` exactly as it does today. If a future need surfaces (e.g.
`use_account` remediation), this is a one-line classifier change.

## Result shape

`to_error_call_result(err: &RimapError) -> CallToolResult` builds:

- `content`: `[Content::text(message)]` — the human-readable message,
  with the folder-denial opacity preserved (`ProtectedFolder` /
  `ExpungeDenied` → `"operation denied for this folder"`, never the
  folder name or the `protected_folders` / `expunge_folders` field
  names). This is the exact message `to_mcp_error` would have used.
- `structured_content`: the `data` object #303 already builds for the
  six structured variants (`error_code` + typed fields). For codes with
  no typed `data` (`NotFound`, IMAP/SMTP/TLS/auth/timeout, posture /
  folder denials) it is `{ "error_code": "ERR_…" }` so the agent always
  has the machine code.
- `is_error`: `Some(true)`.

`CallToolResult` is `#[non_exhaustive]`, so it is built via
`CallToolResult::error(content)` (sets `is_error = Some(true)`) followed
by assigning the public `structured_content` field — no struct literal.

`error.rs` is refactored so message-opaquing and `data`-building are two
small shared helpers (`wire_message`, `structured_error_data`) used by
BOTH `to_mcp_error` (protocol path, behavior unchanged) and
`to_error_call_result` (new isError path). One source of truth for the
error → wire payload.

## Audit pipeline — unchanged

`run_with_audit_envelope` derives the `tool_end` outcome from the inner
`Result<Value, RimapError>` **before** the isError mapping (status
`Error`, `error_code = Some(e.code())`). The mapping to `isError` happens
after `emit_tool_end`, on the value already returned to the client. So
`tool_start` / `tool_end` records — including `status` and `error_code`
— are byte-identical to today for every failure. `docs/audit-log.md`
needs no schema change; a one-line note records that a failed
`tool_end` now corresponds to an `isError` result for execution-class
codes.

The per-account circuit breaker is likewise unaffected: `on_failure` /
`on_success` run inside the body closure in `dispatch_account_scoped`
against the `RimapError`, before the envelope maps it.

## Test-surface bridge

`execute_tool_for_test` (`#[cfg(any(test, feature = "test-support"))]`)
returns `Result<Value, RimapError>`. Execution failures now return
`Ok(CallToolResult { is_error: true })` from the pipeline, so the helper
inspects `is_error == Some(true)` and bridges it back to a `RimapError`
(message from the `content` text; code recovered from
`structured_content.error_code` via `ErrorCode::from_str`) so existing
integration tests keep their `Result`-based assertions
(`err.to_string()` contains the message). Protocol errors continue to
bridge through the existing `error_data_to_rimap_error`.

## Wire-contract / semver impact

This changes observable behavior for **all** existing clients: a
posture denial, `NotFound`, `UidValidityChanged`, rate-limit,
breaker-open, size-cap, and IMAP/SMTP/TLS/timeout failure now arrive as a
`result` with `isError: true` instead of a JSON-RPC `error` envelope.
The stable `error_code` string and typed `data` fields are preserved,
now under `structuredContent` instead of `error.data`. Flag in
CHANGELOG under Changed. Protocol-error paths (unknown tool, bad params,
account resolution, protocol version) are unchanged.

## Test plan

- **`error.rs` unit tests:** existing `to_mcp_error` tests stay green
  (protocol path unchanged). Add `to_error_call_result` tests asserting,
  for a representative execution error of each shape: `is_error ==
  Some(true)`, `content[0]` text equals the (opaque where applicable)
  message, `structured_content.error_code` is the stable code, and the
  typed fields round-trip (`retry_after_ms`, expected/actual,
  `kind`/`limit`). Add an `is_tool_execution_error` no-wildcard
  classification test enumerating every `ErrorCode` (mirrors
  `breaker_reason_maps_every_error_code`) so a new code fails the build
  until its channel is declared.
- **`audit_envelope.rs`:** a test driving `run_with_audit_envelope` with
  a body returning an execution-class `RimapError` asserts the result is
  `Ok(CallToolResult { is_error: Some(true) })` with structured content,
  AND the `tool_end` record still carries `status = "error"` +
  `error_code`. A second test with a protocol-class error
  (`InvalidInput`) asserts the result is still `Err(ErrorData)`.
- **`e2e_wire.rs` (Dovecot-gated conformance):** rewrite the posture,
  sub-capability, and body denials in `assert_readonly_denial` to assert
  an `isError` result (`result.isError == true`,
  `structuredContent.error_code == "ERR_POSTURE_DENIED"`, opaque
  message) instead of an `error` envelope. Add NotFound (fetch a
  missing UID) and UidValidityChanged (stale `expected_uidvalidity`)
  isError assertions where a deterministic trigger is cheap.
- **`e2e.rs` (Dovecot-gated):** unchanged assertions keep passing via
  the `execute_tool_for_test` bridge (`err.to_string()` still contains
  the message).
- **Node conformance harness:** the unknown-tool test (`-32602`
  protocol error) is unchanged. The harness spawns with zero accounts
  and cannot reach a live-IMAP execution failure, so account-scoped
  isError coverage lives in the Rust Dovecot harness above.

## Rejected alternatives

- **Convert everything inside the envelope to `isError`.** Would turn
  `parse_args` shape failures (`InvalidInput`) and `use_account`
  `UnknownAccount` into `isError`, contradicting the issue's "malformed
  params shape stays protocol error" carve-out. Classifying by
  `ErrorCode` is finer-grained and matches the issue.
- **Also convert the pre-envelope account-resolution path.** Spreads the
  change beyond the choke point for no benefit — `NoAccount` /
  `UnknownAccount` are classified as protocol errors either way, so the
  pre-envelope `ErrorData` path is already correct.
- **Put the human message inside `structured_content` and let `content`
  be the JSON string** (what `CallToolResult::structured_error` does).
  The issue asks for the message as result **text**; assigning the
  public `structured_content` field after `error(vec![text])` gives both
  cleanly.
