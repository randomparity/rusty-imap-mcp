# Initialize Protocol-Version Negotiation (#276)

**Date:** 2026-05-14
**Issue:** [#276](https://github.com/randomparity/rusty-imap-mcp/issues/276)
**Discovered by:** Phase 4 negative-path testing (#266)
**Status:** Design approved; implementation pending
**Depends on:** [#275](https://github.com/randomparity/rusty-imap-mcp/issues/275) (pre-initialize handling)

## Problem

A client sending `initialize` with `protocolVersion: "1999-01-01"` (or any
unknown string) receives a success response with `protocolVersion: "1999-01-01"`
echoed back. The server silently advertises support for any version the
client names. Clients cannot detect version-negotiation failure, and a client
speaking an MCP version we cannot handle proceeds with mismatched semantics.

## Root cause

rmcp 1.5's `serve_server_with_ct_inner`
([`rmcp-1.5.0/src/service/server.rs:230-238`](https://docs.rs/rmcp/1.5.0/src/rmcp/service/server.rs.html))
computes the wire response's `protocol_version` as:

```rust
let protocol_version = match peer_protocol_version
    .partial_cmp(&init_response.protocol_version)
    .ok_or(ServerInitializeError::UnsupportedProtocolVersion(...))?
{
    std::cmp::Ordering::Less => peer_info.params.protocol_version.clone(),
    _ => init_response.protocol_version,
};
init_response.protocol_version = protocol_version;
```

`ProtocolVersion` (`rmcp/model.rs:140`) derives `PartialOrd` on a single
`Cow<'static, str>` field, so `partial_cmp` performs lexicographic string
comparison. For peer `"1999-01-01"` vs server `"2025-11-25"`,
`"1999-01-01".cmp("2025-11-25") == Less` → rmcp's downgrade branch picks
the peer's version and overwrites our response. `ProtocolVersion::KNOWN_VERSIONS`
exists in rmcp (`model.rs:162-167`) but the negotiation logic never
consults it.

Consequence: even if we override `ServerHandler::initialize` to set a
specific `protocol_version` on the response, rmcp's post-handler overwrite
still echoes any peer string that lex-sorts lower than `LATEST`.

The originating test —
`crates/rimap-server/tests/mcp_wire_negative.rs:612-668`
(`initialize_unsupported_protocol_version`) — is currently `#[ignore]`'d
pending this fix.

## Desired behavior

1. **Peer's `protocolVersion` is exactly `ProtocolVersion::LATEST`**
   (`"2025-11-25"`): accept and complete the handshake normally.
2. **Peer's `protocolVersion` is anything else** — including known
   older versions (`2024-11-05`, `2025-03-26`, `2025-06-18`), unknown
   strings, empty strings, garbage: reply with a JSON-RPC `-32602`
   error envelope listing the one supported version, then close
   cleanly and exit `0`.
3. **Audit log:** `process_end.reason: Eof` on the rejection path
   when the failure is an `INVALID_PARAMS` (`-32602`) handled
   rejection. Server-fault classes (`INTERNAL_ERROR` and others)
   that surface through `initialize` continue to propagate as
   non-zero exit with `process_end.reason: Error`.

### Why LATEST-only, not permissive

rmcp 1.5's serde types target the LATEST schema only — a grep across
`rmcp-1.5.0/src/` for version-conditional code returns no hits.
`ProtocolVersion` is a string label; the "downgrade" in rmcp's
negotiation rewrites only the `protocol_version` field in the
`InitializeResult`, not the rest of the wire shapes. So accepting a
2024-11-05 peer would produce an `InitializeResult` that echoes
`"2024-11-05"` but carries 2025-11-25-shaped capabilities, tool
definitions, and notifications. That's the same bug class #276 is
fixing — clients proceeding under unproven semantics — re-introduced
in a smaller form.

LATEST-only is the honest narrowing: we accept what rmcp 1.5 actually
speaks. The acceptance set can broaden later when (a) rmcp adds true
per-version serialization or (b) we add a version-shape translation
layer in this crate. Both are explicitly out of scope.

## Approach

Override `ServerHandler::initialize` on `ImapMcpServer`
(`crates/rimap-server/src/mcp/server.rs`):

```rust
async fn initialize(
    &self,
    request: InitializeRequestParams,
    context: RequestContext<RoleServer>,
) -> Result<InitializeResult, ErrorData> {
    if request.protocol_version != ProtocolVersion::LATEST {
        return Err(unsupported_protocol_version_error(&request.protocol_version));
    }
    if context.peer.peer_info().is_none() {
        context.peer.set_peer_info(request);
    }
    Ok(self.get_info())
}
```

The exact-equality check is the only safe option given rmcp 1.5's
LATEST-only serialization (see "Why LATEST-only" above). A small
private helper `unsupported_protocol_version_error` lives near the
bottom of `mcp/server.rs`:

```rust
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

Using a single-element array (rather than a scalar) for
`supported_versions` keeps the wire shape stable if the server ever
broadens the supported set: clients consuming the field don't need to
change their decoder.

When the handler returns `Err`, rmcp at `service/server.rs:222` calls
`transport.send(ServerJsonRpcMessage::error(...))` to write the envelope,
then returns `Err(ServerInitializeError::InitializeFailed(error_data))`
from `serve_server`. Our `main.rs::run` adds two match arms that
classify by error-code:

```rust
Err(ServerInitializeError::InitializeFailed(error_data))
    if initialize_failure_is_handled_rejection(error_data.code) =>
{
    // rmcp already sent the error envelope. INVALID_PARAMS at the
    // initialize boundary is a handled client rejection (e.g.
    // unsupported protocol version), not a server fault.
    tracing::info!(
        code = error_data.code.0,
        "rejected initialize with error envelope",
    );
    return Ok(());
}
Err(ServerInitializeError::InitializeFailed(error_data)) => {
    // Server-fault classes (INTERNAL_ERROR and others) must surface
    // as non-zero exit with process_end.reason: Error so initialize
    // outages remain observable in the audit trail.
    return Err(anyhow::anyhow!(
        "MCP server init failed: code {}: {}",
        error_data.code.0,
        error_data.message,
    ));
}
```

The classifier helper is a one-line `matches!` so it's
unit-testable in isolation:

```rust
fn initialize_failure_is_handled_rejection(code: ErrorCode) -> bool {
    matches!(code, ErrorCode::INVALID_PARAMS)
}
```

Returning `Ok(())` on the handled-rejection arm causes `process_end`
to record `reason: Eof` and the process to exit `0` — the same audit
semantics as #275's pre-init handled path. Server-fault propagation
flows through the existing `tracing::error!("{e:#}")` in `main.rs:49`
and `ExitCode::FAILURE`, same as today's behavior for transport
errors.

### Why counter-proposal isn't viable through rmcp

The MCP spec's preferred path is "respond with a version we support":

> "If the server supports the requested protocol version, it MUST respond
> with the same version. Otherwise, the server MUST respond with a version
> it does support."

Setting `init_response.protocol_version = ProtocolVersion::LATEST` in our
override does not work — rmcp's downgrade logic overwrites it with
`min(peer, server)` lexicographically. The only paths that produce a
spec-legal wire outcome without an upstream rmcp patch are:

1. Return `Err` from `initialize` → wire error envelope (this design).
2. Wrap rmcp's transport to intercept and rewrite the InitializeResult.

Option 2 costs significantly more code and is explicitly out of scope.
The spec's bug report accepts either "success result with a server-
supported version OR a JSON-RPC error"; option 1 satisfies the latter.

Even if counter-proposal were viable, it would face the same wire-shape
limitation that drives the LATEST-only acceptance set: rmcp emits the
LATEST shapes regardless of the negotiated version string. A counter-
proposal of `"2024-11-05"` wrapping a 2025-11-25-shaped capabilities
payload would be dishonest in the same way permissive acceptance would
be.

## Dependencies

This branch is stacked on
[`fix/issue-275-pre-initialize-handling`](https://github.com/randomparity/rusty-imap-mcp/pull/279).
#276's match-arm addition to `main.rs::run` sits right next to #275's
`ExpectedInitializeRequest` arm; the two changes touch adjacent lines.

Like #275, this is a merge blocker for PR #278 — the test
`initialize_unsupported_protocol_version` is `#[ignore]`'d on
`feature/issue-266-mcp-fuzzing` pending this fix.

**Branching strategy.** Fix PR targets either:

1. `fix/issue-275-pre-initialize-handling` directly while #279 is open;
   merging this PR rolls #275 + #276 into #275's branch. Practical
   choice while #279 is in review.
2. `feature/issue-266-mcp-fuzzing` once #279 merges; rebase
   `fix/issue-276-protocol-version-negotiation` onto the merged base
   and re-point the PR.

Either path lands the un-ignore commit alongside the production fix in
one diff, matching the #266 merge-blocker policy.

## Error envelope shape

```json
{
  "jsonrpc": "2.0",
  "id": <echoed verbatim>,
  "error": {
    "code": -32602,
    "message": "Unsupported protocol version: '<peer-version>'. Server supports: 2025-11-25.",
    "data": {
      "supported_versions": ["2025-11-25"]
    }
  }
}
```

- **Code `-32602` (`INVALID_PARAMS`)**: the protocol version is structured
  data inside `params`. The standard JSON-RPC code for bad `params` is
  -32602. Reusing `ErrorData::invalid_params` keeps the envelope
  consistent with the rest of the dispatch path (`ErrorCode::InvalidInput`
  in `crates/rimap-server/src/mcp/error.rs:37` already maps here). Avoids
  burning a custom `-3200X` code for a single semantically-standard case.
- **Message text**: echoes the peer's bad version in single quotes for
  actionability. The peer-supplied protocol version is a client-asserted
  protocol string, not adversarial content like email body — reflection
  here doesn't carry the leakage risk #275 guards against. The supported
  version is read from `ProtocolVersion::LATEST.as_str()` at runtime, so
  a future rmcp bump auto-updates the message without code changes.
- **`data` field**: machine-readable `{"supported_versions": [...]}` as
  a single-element array so a smart client can detect the field
  uniformly. JSON-RPC §5.1 allows the field; MCP doesn't require it but
  doesn't forbid it. If the supported set ever broadens, this same
  array shape carries the new versions without forcing client decoders
  to change.

**No new `McpCode` constant.** `INVALID_PARAMS` is already in
`rmcp::model::ErrorCode`; the `NOT_INITIALIZED: McpCode(-32002)` added
in #275 stays.

## Test plan

### Integration

**Un-ignore `initialize_unsupported_protocol_version`** at
`crates/rimap-server/tests/mcp_wire_negative.rs:612-668`:

- Remove `#[ignore]`.
- Replace the accept-either-branch with strict assertions on the error
  envelope path:
  - `envelope["error"]["code"] == -32602`
  - `envelope["error"]["data"]["supported_versions"]` equals
    `["2025-11-25"]` exactly (one-element array — locks in the
    LATEST-only posture, no other version names sneak into the wire)
  - `envelope["error"]["message"]` contains `"1999-01-01"` (the
    peer's version, echoed back per the message-text rule above)
  - `envelope["error"]["message"]` contains `"2025-11-25"` (the
    supported version, surfaced in the human-readable message)
- Add a follow-up `response_or_close` call asserting `CleanClose`
  (proves the server exited `0` after rmcp sent the envelope).
- Add an audit-log assertion: `read_process_end_reason(...) == Eof`.
- Update the docstring to reference #276 as fixed.

**New wire test — `initialize_with_known_older_version_is_rejected`**:

- Send `initialize` with `protocolVersion: "2024-11-05"` (a known
  older MCP version per `ProtocolVersion::KNOWN_VERSIONS`).
- Assert error envelope with `code == -32602`,
  `supported_versions == ["2025-11-25"]`, message contains
  `"2024-11-05"`.
- Pins the strict LATEST-only posture: even known-old versions are
  rejected because rmcp 1.5 doesn't actually emit older wire shapes.
- This test BLOCKS a future "permissive" relaxation that would re-
  introduce the unproven-semantics bug class.

**New wire test — `initialize_with_empty_string_protocol_version`**:

- Send `protocolVersion: ""` — edge case where the client sends valid
  JSON but a degenerate version string.
- Assert error envelope with `code == -32602` (`""` is not the
  LATEST version).
- Pins the boundary so future code that special-cases empty strings
  is caught.

### Unit

**`mcp/server.rs::tests` — `unsupported_protocol_version_error_shape`**:

- Construct a `ProtocolVersion` from `"1999-01-01"` (the rmcp
  deserializer's fallback path produces an arbitrary string).
- Call `unsupported_protocol_version_error(&version)`.
- Assert: returned `ErrorData.code == INVALID_PARAMS`,
  message contains `"1999-01-01"` AND `"2025-11-25"`,
  `data["supported_versions"] == ["2025-11-25"]` exactly.
- Lives at the bottom of `mcp/server.rs` next to the helper. No I/O,
  fast.

**`mcp/server.rs::tests` — `unsupported_protocol_version_error_uses_runtime_latest`**:

- Same helper, any peer version.
- Assert `data["supported_versions"][0] == ProtocolVersion::LATEST.as_str()`.
- Pins the contract that the list is constructed from
  `ProtocolVersion::LATEST` at runtime (not hard-coded). If a future
  rmcp bump shifts LATEST, the message updates automatically without
  this test breaking.

**`main.rs::tests` (or a new module) — `initialize_failure_classifier`**:

- `initialize_failure_is_handled_rejection(ErrorCode::INVALID_PARAMS) == true`
- `initialize_failure_is_handled_rejection(ErrorCode::INTERNAL_ERROR) == false`
- `initialize_failure_is_handled_rejection(ErrorCode::METHOD_NOT_FOUND) == false`
- `initialize_failure_is_handled_rejection(ErrorCode(-32099)) == false` —
  future-proofs the gate against new server-fault codes being
  accidentally classified as client rejections.

This unit-tests the Codex-Finding-2 boundary directly. An
integration test that triggers a non-`INVALID_PARAMS` error from
`initialize` would require a `#[cfg(feature = "test-support")]`
env-var hook (~30 lines of scaffolding); the helper-level unit test
is sufficient because the gate is a pure function on the error
code, with no I/O or state.

### Out of scope

- `mcp_wire_proptest.rs` — proptest harness uses
  `PINNED_PROTOCOL_VERSION` so this code path is never hit fuzzily.
  No proptest changes.
- No e2e (Dovecot) test changes — this is a wire-level concern.

## Risks

1. **`ProtocolVersion::LATEST` is rmcp-1.5-specific.** If we bump
   rmcp later, the constant may shift to a newer version string.
   Mitigation: we reference `ProtocolVersion::LATEST` live — bumping
   rmcp adjusts the acceptance string automatically. The unit test
   that asserts `supported_versions[0] == LATEST.as_str()` keeps the
   wire message in lockstep. The negative-path wire tests assert
   `["2025-11-25"]` literally, so an rmcp bump that changes LATEST
   will fail those tests visibly and force a deliberate update —
   the test will document, by failure, that the supported version
   shifted.

2. **LATEST-only rejects clients that could otherwise work.** Some
   well-behaved clients send older known versions
   (`2024-11-05` etc.). After this change they get -32602 instead of
   a working session. This is the deliberate honesty trade: rmcp 1.5
   doesn't actually emit older wire shapes, so accepting older
   version strings would be a misrepresentation. When (a) rmcp adds
   per-version serialization or (b) we add a translation layer in
   this crate, the acceptance set can broaden — guarded by the
   `initialize_with_known_older_version_is_rejected` test, which
   makes any broadening an explicit decision rather than an
   accident.

3. **Code-gated `InitializeFailed` arm trusts rmcp's error-data
   passthrough.** The classifier (`initialize_failure_is_handled_rejection`)
   reads `error_data.code` to decide between clean rejection and
   server-fault propagation. rmcp at `service/server.rs:222` calls
   `transport.send(ServerJsonRpcMessage::error(e.clone(), id))` and
   then `return Err(ServerInitializeError::InitializeFailed(e))` —
   so the `e` we match on is the same `ErrorData` we constructed in
   `initialize`. No transformation layer; the code we put in is the
   code we see back. Confirmed by reading the rmcp source.

4. **rmcp upstream lex-comparison fix.** If rmcp ever fixes the
   downgrade logic to consult `KNOWN_VERSIONS` directly, our override
   becomes a no-op (the peer's bad version would already be rejected
   upstream). That's fine — the override is defensive, costs nothing
   when redundant.

5. **rmcp upstream adds per-version serialization.** Different
   problem class: our LATEST-only rejection would then over-reject
   clients rmcp *could* serve. Mitigation: the
   `initialize_with_known_older_version_is_rejected` test would
   fail at the next rmcp bump that introduces per-version
   serialization (the test asserts rejection at the wire layer,
   regardless of rmcp's internal capability). The failure surfaces
   the now-actionable broadening as a deliberate spec revision.

## What does not change

- `synthesize_pre_init_error_envelope` and #275's pre-initialize
  handling.
- `get_info()` continues to advertise `ProtocolVersion::LATEST` as
  the server's preferred version.
- Tool dispatch, audit envelopes, other negative-path tests.
- The `RimapError` / `ErrorCode` taxonomy in `crates/rimap-core`.

## Explicitly out of scope

- Counter-proposal via transport wrapper (requires significantly more
  code; rmcp's lex-min logic blocks the direct path).
- Supporting any protocol version other than `ProtocolVersion::LATEST`.
  Older known versions (`2024-11-05`, `2025-03-26`, `2025-06-18`)
  are deliberately rejected. Broadening requires either an rmcp
  upstream fix that adds true per-version serialization or a
  translation layer in `rimap-server`; both belong in a separate
  spec.
- Patching rmcp upstream to use `KNOWN_VERSIONS` instead of lex
  comparison (worth filing but separate from #276).
- An integration test that injects `INTERNAL_ERROR` from `initialize`
  via a test-support hook. The classifier unit test on
  `initialize_failure_is_handled_rejection` is sufficient to pin the
  Codex-Finding-2 boundary; a wire-level test would require ~30 lines
  of `#[cfg(feature = "test-support")]` scaffolding for marginal
  signal.
- #277 (hung-on-unknown-method) — separate bug, separate plan.

## Acceptance

Mirrors the issue, with the LATEST-only narrowing per Codex Finding 1:

- `initialize` with any version other than `ProtocolVersion::LATEST`
  (`"2025-11-25"`) returns a JSON-RPC `-32602` error envelope with
  `supported_versions == ["2025-11-25"]`; the server exits `0` and
  the audit log records `process_end.reason: Eof`.
- This applies to both unknown versions (e.g., `"1999-01-01"`) and
  known-older versions (`"2024-11-05"`, `"2025-03-26"`,
  `"2025-06-18"`). Known-older versions are not silently accepted.
- `initialize` with `"2025-11-25"` succeeds; the handshake completes
  and the response's `protocolVersion` is `"2025-11-25"`.
- `initialize_unsupported_protocol_version` and the new wire tests
  (`initialize_with_known_older_version_is_rejected`,
  `initialize_with_empty_string_protocol_version`) pass with strict
  assertions on the chosen behavior.
- Server-fault classes (`INTERNAL_ERROR` and other non-`INVALID_PARAMS`
  codes) returned from `initialize` propagate as non-zero exit with
  `process_end.reason: Error`. Pinned by the
  `initialize_failure_classifier` unit test.
- No crash, no `Crashed(...)` outcome from the harness on
  unsupported-version input.
