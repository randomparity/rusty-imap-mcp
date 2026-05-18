# Pre-Initialize Request Handling (#275)

**Date:** 2026-05-14
**Issue:** [#275](https://github.com/randomparity/rusty-imap-mcp/issues/275)
**Discovered by:** Phase 4 negative-path testing (#266)
**Status:** Design approved; implementation pending

## Problem

A JSON-RPC client that sends any non-`initialize`, non-`ping` request as its
first message causes `rusty-imap-mcp` to exit with code `1` and a stderr log:

```
expect initialized request, but received: Some(Request(ListToolsRequest(...)))
```

The crash corrupts audit trails (the `process_end` record is emitted with
`reason: Error`) and gives misbehaving clients no actionable wire-level signal.

## Root cause

The rmcp 1.5 service loop
([`rmcp-1.5.0/src/service/server.rs:172-204`](https://docs.rs/rmcp/1.5.0/src/rmcp/service/server.rs.html))
accepts only `PingRequest` or `InitializeRequest` as the first message; anything
else short-circuits to
`ServerInitializeError::ExpectedInitializeRequest(Some(msg))`. The server
entrypoint at `crates/rimap-server/src/main.rs:138-140` wraps that error with
`anyhow!`, which propagates to `main()` and triggers `ExitCode::FAILURE`.

The originating test —
`crates/rimap-server/tests/mcp_wire_negative.rs:339-368`
(`tools_list_before_initialize`) — is currently `#[ignore]`'d pending this fix.

## Desired behavior

1. **Pre-initialize Request** (e.g. `tools/list`): reply with a JSON-RPC error
   envelope echoing the request's `id`, then close cleanly and exit `0`.
2. **Pre-initialize Notification or Response**: drop silently, close cleanly,
   exit `0`. (Per JSON-RPC §4.1, notifications never receive a response;
   a response without a matching server request is malformed.)
3. **Audit log**: `process_end` emits with `reason: Eof` (not `Error`)
   on the success path. Transport-level write failures while emitting
   the envelope remain classified as `reason: Error` and exit non-zero
   — those are real server faults, not misbehaving-client input.

## Approach

A new `crates/rimap-server/src/mcp/preinit.rs` module exposes one pure helper:

```rust
pub(crate) fn synthesize_pre_init_error_envelope(
    msg: &ClientJsonRpcMessage,
) -> Option<String>
```

The helper returns `Some(<newline-terminated JSON line>)` for the `Request`
variant and `None` for `Notification` / `Response` / other variants. No I/O,
no transport access — it is trivially unit-testable against
`serde_json::Value` snapshots.

The call site in `main.rs::run` matches on the specific rmcp error variant:

```rust
let service = match Box::pin(rmcp::serve_server(mcp_server, transport)).await {
    Ok(svc) => svc,
    Err(ServerInitializeError::ExpectedInitializeRequest(Some(msg))) => {
        if let Some(line) = synthesize_pre_init_error_envelope(&msg) {
            let mut out = tokio::io::stdout();
            out.write_all(line.as_bytes())
                .await
                .context("writing pre-init error envelope to stdout")?;
            out.flush()
                .await
                .context("flushing pre-init error envelope")?;
            tracing::info!("rejected pre-initialize request with -32002 envelope");
        }
        return Ok(());
    }
    Err(other) => return Err(anyhow::anyhow!("MCP server init: {other}")),
};
```

Returning `Ok(())` on the success path causes the outer `mcp_result` to
be `Ok`, which the existing `process_end` block at `main.rs:158-171`
records as `reason: Eof` and the process exits `0`.

Write/flush failures are propagated with `?`. A failed stdout write is
a genuine server fault: the client never received the envelope and we
have no other transport to recover. The `?` returns `Err` to
`mcp_result`, which records `reason: Error` and exits non-zero —
correct for that case. The bug we are fixing was misclassifying a
successful handling of a misbehaving client as an error; propagating
real transport faults to the same shutdown machinery preserves that
audit-correctness goal at the failure boundary.

Because rmcp has already consumed its `tokio::io::Stdout` by the time the
error returns, the helper writes through a freshly acquired
`tokio::io::stdout()` handle. This is safe: both handles wrap the same
process stdout file descriptor.

The cancellation channel + drainer (`main.rs:133-134`) only matter for
mid-dispatch cancellation; the early-return path skips them entirely.

## Dependencies

This spec exercises the wire-level negative-test harness introduced in
#266 / PR #278:

- `crates/rimap-server/tests/mcp_wire_negative.rs` — file under
  which `tools_list_before_initialize` is `#[ignore]`'d, plus the
  three new pre-initialize tests added by this fix
- `crates/rimap-server/tests/support/wire/harness.rs` — the
  `Harness` / `CloseOrResponse` / `response_or_close` plumbing the
  test plan below references

#275 is one of three merge blockers (#275, #276, #277) explicitly
listed on PR #278. The blocker policy from #266's plan §5 — "bugs
found during implementation are fixed before this phase merges" —
keeps it literally true: by the time PR #278 reaches `main`, no
`#[ignore]`'d Phase 4 tests remain in history.

**Branching strategy.** The fix PR targets `feature/issue-266-mcp-fuzzing`
as its merge base:

- It un-ignores `tools_list_before_initialize` and adds the three new
  pre-initialize tests in the same PR as the production fix.
  Reviewers see "this server change makes this previously-ignored test
  pass" in one diff.
- Once #275, #276, and #277 have all landed on
  `feature/issue-266-mcp-fuzzing`, PR #278 is marked ready for review
  and merges to `main` carrying all three fixes + un-ignores together.

Note: targeting the feature branch is a *workflow* decision that keeps
the un-ignore commit attached to the fix. The fix itself can be
verified against the harness in a working copy regardless of which
branch the PR ultimately targets. The constraint is only on PR base,
not on local development.

Cherry-picking the negative harness from #266 into a standalone #275
PR off `main` is explicitly rejected: it duplicates ~600 lines of
#266's contribution and guarantees a merge conflict.

## Envelope shape

```json
{
  "jsonrpc": "2.0",
  "id": <echoed verbatim>,
  "error": {
    "code": -32002,
    "message": "Server not initialized: send `initialize` before any other request"
  }
}
```

- **Code `-32002`** lives in the JSON-RPC server-error band (`-32000..=-32099`)
  and is the conventional "Server not initialized" code in the LSP / MCP
  ecosystem. It does not collide with existing codes in
  `crates/rimap-server/src/mcp/error.rs`: `-32001` posture-denied,
  `-32003` rate-limited, `-32004` breaker, `-32005` attachment-too-large.
  A new `pub const NOT_INITIALIZED: McpCode = McpCode(-32002);` is added
  to that file so the code registry remains in one place; `preinit.rs`
  references it from there.
- **`id` echoing**: numbers, strings, and `null` pass through unchanged
  via `serde_json::Value`. No `as_u64()` coercion.
- **Message text**: a fixed string. No echo of the offending method name
  or any client-supplied content (matches the opaque-message pattern
  already used for `ProtectedFolder` / `ExpungeDenied` at
  `crates/rimap-server/src/mcp/error.rs:41-44`).
- **No `data` field**.

## Test plan

### Unit (`crates/rimap-server/src/mcp/preinit.rs`)

1. `Request` with numeric id → envelope with same numeric id,
   `error.code == -32002`, valid JSON-RPC framing.
2. `Request` with string id → envelope with same string id.
3. `Request` with `null` id → envelope with `id: null`.
4. `Notification` → returns `None`.
5. `Response` → returns `None`.
6. Output ends with exactly one `\n`, is single-line, parses round-trip
   via `serde_json::from_str`.

### Integration

**Un-ignore `tools_list_before_initialize`** at
`crates/rimap-server/tests/mcp_wire_negative.rs:339-368`:

- Remove `#[ignore]`.
- Replace the accept-either-envelope-or-close branch with a strict
  envelope assertion (`error.code == -32002`, `id` matches the id the
  harness sent).
- Add a follow-up `response_or_close` call that asserts `CleanClose`
  (proves the server exited `0` after the envelope was written).
- Update the docstring to reference #275 as fixed.

**New wire tests in `mcp_wire_negative.rs`:**

- `pre_initialize_notification_silent_close`: first message is
  `notifications/cancelled`; assert `CleanClose` only (no envelope).
- `tools_list_before_initialize_str_id`: same as the un-ignored test
  but with a string id; pins id-type preservation at the wire layer.

### Audit log

Two cases, both reading the audit log post-shutdown via the pattern
established by existing audit-tail tests under
`crates/rimap-server/tests/`:

1. **Success path.** `tools_list_before_initialize` (and the string-id
   variant) asserts `process_end.reason == Eof` after the envelope is
   written and the server exits `0`. This is the case the bug report
   is asking us to fix.
2. **Write-failure path.** A new wire test
   `pre_initialize_envelope_write_failure_records_error` closes the
   harness's child-stdout read end before the server attempts to write
   the envelope (Codex review finding 2026-05-14, medium). Asserts:
   - server exits non-zero
   - `process_end.reason == Error`
   - the rejected envelope is observable in stderr or via the
     `tracing::error!` machinery (no silent audit success on
     transport failure)

   This test requires a new harness helper —
   `Harness::drop_stdout_reader()` or equivalent — that drops the
   `BufReader<ChildStdout>` while keeping `child` alive so its exit
   status can still be observed. Adding this helper is in scope for
   #275 (small, ~10 lines in `support/wire/harness.rs`).

### SIGPIPE handling

The broken-stdout test relies on Rust's default SIGPIPE behavior
(`SIG_IGN` since 1.0): writes to a closed pipe return `Err(BrokenPipe)`
rather than terminating the process. This is checked by the test
itself — if the assertion that the server exits non-zero (rather than
being killed by SIGPIPE with `status.signal() == Some(13)`) ever
fails, the test surfaces a SIGPIPE regression.

### Out of scope

- `mcp_wire_proptest.rs` already runs `initialize` first; no proptest
  changes.
- No e2e (Dovecot) test changes — this is a wire-level behavior.

## Risks

1. **rmcp upstream variant rename.** `ServerInitializeError` is
   `#[non_exhaustive]`. If rmcp renames `ExpectedInitializeRequest`
   or splits Request / Notification cases, the explicit match arm
   becomes a compile error — the desired failure mode. The fallback
   `Err(other) =>` arm preserves today's behavior for every other
   initialization failure (transport errors, unsupported protocol
   version, etc.) so we do not silently swallow real bugs.
2. **stderr behavior.** Two distinct outcomes:
   - **Success** (envelope written, exit 0, `reason: Eof`): one
     `tracing::info!` entry so audit operators can correlate the
     wire event. Kept at `info` because this is a normal handled
     case, not a fault.
   - **Write failure** (envelope could not be delivered, exit
     non-zero, `reason: Error`): the existing `tracing::error!("{e:#}")`
     in `main.rs:49` fires from the propagated `anyhow::Error`,
     same as today's behavior for other transport faults. No silent
     classification of write failures as clean EOF.
3. **stdout fd reuse.** Acquiring a fresh `tokio::io::stdout()` after
   rmcp drops its handle is safe because both wrap the same OS file
   descriptor. Anything rmcp wrote on this path (e.g. a ping response
   if the client sent `ping` before the offending request) is a
   well-formed JSON-RPC line; our envelope simply follows it on a new
   line. No partial writes or interleaving.

## What does not change

- Tool dispatch after `initialize` completes.
- Audit-envelope guarantees for in-flight tool calls.
- Other negative-path tests in `mcp_wire_negative.rs`.
- The `RimapError` / `ErrorCode` taxonomy in `crates/rimap-core`
  (the pre-init code lives only in the wire-level `McpCode` registry).

## Explicitly out of scope

- Issue #276 (protocol-version negotiation echoes unsupported versions).
- Reorganizing `main.rs::run` (currently ~119 lines, over the 100-line
  cap; flagged but addressed only if it becomes load-bearing).
- Adding a new `ErrorCode` variant to `rimap_core::ErrorCode`.

## Acceptance

Mirrors the issue:

- Pre-initialize Request results in a JSON-RPC error envelope with
  `code == -32002`; pre-initialize Notification / Response is dropped
  silently.
- `tools_list_before_initialize` (un-ignored) plus the three new wire
  tests (`tools_list_before_initialize_str_id`,
  `pre_initialize_notification_silent_close`,
  `pre_initialize_envelope_write_failure_records_error`) pass with
  strict assertions on the chosen behavior.
- `rusty-imap-mcp` exits `0` (not `1`) on misbehaving-client input
  when the envelope is delivered successfully.
- `process_end` audit record reports `reason: Eof` on the success
  path.
- Pre-initialize handling does **not** mask transport-level write
  failures: if the server cannot deliver the envelope, exit
  non-zero and audit `reason: Error`. The new
  `pre_initialize_envelope_write_failure_records_error` wire test
  pins this contract.
