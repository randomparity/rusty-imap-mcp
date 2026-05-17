# JSON-RPC Envelope Validator (#277)

**Date:** 2026-05-15
**Issue:** [#277](https://github.com/randomparity/rusty-imap-mcp/issues/277)
**Discovered by:** Phase 4 property testing (#266) — `mcp_wire_proptest::prop_envelope_never_panics`
**Status:** Design approved; implementation pending
**Depends on:** PR #278 (the un-ignore of `prop_envelope_never_panics` lands in the same diff)

## Problem

A client sending a JSON envelope that fails JSON-RPC 2.0 shape validation
— e.g. `{"method":"a"}` (no `jsonrpc`, no `id`) — gets no response and the
connection does not close. The proptest harness times out after
`REQUEST_TIMEOUT` (2 s) and records a `Hung` outcome.

Either response shape — a JSON-RPC `-32600 Invalid Request` envelope or
a clean connection close — would satisfy the spec. Hanging does not.

## Root cause

rmcp 1.5's `JsonRpcMessageCodec::decode`
([`rmcp-1.5.0/src/transport/async_rw.rs:350-354`](https://docs.rs/rmcp/1.5.0/src/rmcp/transport/async_rw.rs.html))
calls `try_parse_with_compatibility` and silently drops the line whenever
that helper returns `Ok(None)`:

```rust
let item = match try_parse_with_compatibility(line, "decode")? {
    Some(item) => item,
    None => return Ok(None), // Skip non-standard message
};
```

`try_parse_with_compatibility`
(`async_rw.rs:245-279`) tries to deserialize as the typed message enum;
on failure it consults `should_ignore_notification`
(`async_rw.rs:223-243`):

```rust
let is_notification = json_value.get("id").is_none();
if is_notification && !is_standard_method(method) {
    return true; // silently ignore
}
```

For the shrunk failing case `{"method":"a"}`: typed deserialization
fails (no `jsonrpc` field), the value parses as a JSON object with a
string `method`, `id` is absent so `is_notification=true`, method `"a"`
isn't on rmcp's `is_standard_method` allowlist, and the helper returns
`true`. The codec returns `Ok(None)`, which `tokio_util::codec::Decoder`
interprets as "not enough data yet — call me again." `FramedRead`
treats this as backpressure and silently waits for the next line. The
dropped line never surfaces on the `Stream`, `service.waiting()` never
sees it, and no response is emitted. The client request id sits
unresolved forever — the observed hang.

The same path applies on EOF: `decode_eof`
(`async_rw.rs:373-393`) routes unparsable terminal lines through
`try_parse_with_compatibility` and returns `Ok(None)` on failure, so
EOF after a malformed line also produces no diagnostic.

The originating property —
`crates/rimap-server/tests/mcp_wire_proptest.rs:311`
(`prop_envelope_never_panics`) — is currently `#[ignore]`'d pending
this fix. The nightly fuzz workflow's per-property guard fails until
the property un-ignores.

### Two cases collapsed under #277

rmcp's silent-drop branch fires for two distinct input classes that
both manifest as `Hung` in the proptest harness:

1. **Invalid JSON-RPC 2.0 envelope** — e.g. `{"method":"a"}` (missing
   `jsonrpc`). The original #277 hang. The server-side fix is to
   respond `-32600` or `-32700` per the validation rules below.
2. **Valid JSON-RPC notification with non-standard method** — e.g.
   `{"jsonrpc":"2.0","method":"foo"}`. Per JSON-RPC 2.0 §4.1, the
   server "MUST NOT reply to a Notification." rmcp's silent-ignore is
   spec-compliant; the proptest's `Hung` outcome is the bug, not the
   server's silence. The fix here is in the property body, not the
   server.

The implementation must address both. The validator (below) closes
case 1; a property-strategy filter excludes case 2 from the property
entirely (notifications get their own fixed-case test instead).

## Desired behavior

For every line received on stdin after the initialize handshake
completes:

1. **Valid JSON-RPC 2.0 envelope** (request or notification): forward
   unchanged to rmcp.
2. **Empty or whitespace-only line**: skip silently. (Transport noise;
   not part of the JSON-RPC spec.)
3. **Invalid JSON**: emit `-32700 Parse error` envelope with `id: null`.
4. **Valid JSON failing shape checks** (missing `jsonrpc`, wrong
   `jsonrpc` value, missing/non-string `method`, malformed `id`,
   batches): emit `-32600 Invalid Request` envelope with `id` echoed
   if it's the right shape, else `null`.
5. **Session stays alive after rejection**: the next valid envelope on
   the wire continues to dispatch normally.

Pre-initialize handling is otherwise unchanged — `preinit` still owns
`ServerInitializeError::ExpectedInitializeRequest` (a
semantically-wrong-but-syntactically-valid first message), and the
validator catches everything that rmcp's codec would otherwise silently
drop, both pre- and post-initialize. **One mechanical change is
required**: `emit_pre_init_error_envelope` in `main.rs` writes to real
stdout and so must lock the validator's shared mutex — see "Pre-init
shares the validator stdout" below.

### Why respond rather than close

Both are spec-legal. Responding is preferable because:

- **Diagnostic clarity** for real MCP clients with a transient bug — a
  `-32600` envelope tells them what's wrong; a connection close looks
  like an unrelated transport failure.
- **Property-test throughput**: `prop_envelope_never_panics` runs 1000
  cases per invocation. Closing the connection forces the harness to
  respawn the server between cases. Pinned tests in
  `mcp_wire_negative.rs` already prove session-keepalive after
  `-32602` rejections (#276); the same pattern extends here.
- **Consistency**: pre-init rejection (#275) emits `-32002`, version
  rejection (#276) emits `-32602`. Wire-shape rejection joining as
  `-32600` keeps the rejection surface uniform.

## Approach

Replace `rmcp::transport::io::stdio()` in
`crates/rimap-server/src/main.rs:140` with a validator that sandwiches
rmcp's transport via `tokio::io::duplex`:

```
                       ┌──── Arc<Mutex<Stdout>> ─ shared writer ────┐
                       ↑ rejections     ↑ rmcp frames     ↑ pre-init envelope
                       │                │                 │
real stdin → [validator] ──valid line→ duplex_in.our_end  │     main.rs::run
                                       duplex_in.rmcp_end →─→ rmcp transport
                       [passthrough] ← duplex_out.our_end ←─ duplex_out.rmcp_end
                                          │
                                          └──── locks shared writer ──→ real stdout

   supervisor.join() races service.waiting() in main.rs:
     - validator/passthrough JoinHandle errors → mcp_outcome: Err → process_end.reason: Error
     - clean EOF on both directions               → mcp_outcome: Ok  → process_end.reason: Eof
```

Two background tokio tasks live for the lifetime of the MCP session,
plus a shared `Arc<tokio::sync::Mutex<tokio::io::Stdout>>` that
serializes all writes to real `stdout` so the validator's rejection
envelopes and rmcp's frames never interleave mid-line:

- **Inbound validator** (`validate_inbound`): reads from real
  `tokio::io::stdin()` via `AsyncBufReadExt::read_until(b'\n', ...)`
  so the terminating `\n` is preserved verbatim. Runs shape
  validation on each line. Valid lines (including the trailing
  newline) are forwarded byte-for-byte to the inbound duplex;
  rmcp's codec sees exactly what the client sent. Invalid lines
  synthesize an error envelope and write it through the shared
  stdout mutex.
- **Outbound passthrough** (`passthrough_outbound`): reads
  newline-framed frames from the outbound duplex via
  `read_until(b'\n', ...)` and writes each complete frame through
  the shared stdout mutex. Line-framed (rather than `tokio::io::copy`)
  so the lock is acquired per complete envelope and never held
  across an await on rmcp's writer.

**Stdout serialization invariant:** all writes to real `stdout` go
through `Arc<Mutex<Stdout>>`; each lock acquisition writes exactly
one complete line (terminating `\n` included) plus a `flush()`, then
releases. Both tasks observe this contract.

EOF on real stdin → validator's `read_until` returns 0 → validator
drops its inbound duplex end → rmcp's `FramedRead` sees EOF on its
next poll → `service.waiting()` resolves cleanly. EOF on the
outbound duplex (rmcp dropped) → passthrough exits → tasks complete.
Broken pipe on real stdout propagates as `io::Error` from the locked
write; the affected bridge task returns that error from its
`JoinHandle` and the supervisor surfaces it to `main.rs::run` so
`process_end.reason: Error` is recorded (see "Bridge-task supervisor"
below).

rmcp's `IntoTransport` impl
(`rmcp/transport/async_rw.rs:22-31`) accepts any
`(R: AsyncRead, W: AsyncWrite)` pair. Our pair is two
`tokio::io::DuplexStream` ends — substitution requires zero changes to
rmcp.

### Validator entry point

The validator returns a struct rather than a bare tuple so the bridge
tasks' lifecycle, the shared stdout writer, and the rmcp-facing
transport are owned together. The shared stdout is exposed so all
synchronized stdout writers in the process (validator rejections,
passthrough frames, **and** the pre-init error envelope emitted from
`main.rs`) lock the same mutex — see "Pre-init shares the validator
stdout" below.

```rust
// crates/rimap-server/src/mcp/wire_validator.rs

pub struct ValidatedStdio {
    /// Hand to rmcp via `rmcp::serve_server(server, validated.transport)`.
    pub transport: (DuplexStream, DuplexStream),
    /// Shared writer for synchronized stdout output. `main.rs`'s
    /// pre-init error path locks this same mutex; the bridge tasks
    /// hold `Arc::clone`s.
    pub stdout: Arc<tokio::sync::Mutex<tokio::io::Stdout>>,
    /// Bridge-task supervisor; must be polled alongside
    /// `service.waiting()` so write errors propagate.
    pub supervisor: ValidatorSupervisor,
}

pub struct ValidatorSupervisor {
    inbound: JoinHandle<io::Result<()>>,
    outbound: JoinHandle<io::Result<()>>,
}

impl ValidatorSupervisor {
    /// Resolves with the first bridge-task error encountered, or
    /// `Ok(())` once both tasks exit cleanly (the normal EOF path).
    ///
    /// On error from either task, the other is aborted; both
    /// duplex ends are dropped, which surfaces to rmcp as a
    /// transport error on its next read/write.
    pub async fn join(mut self) -> io::Result<()> { ... }
}

/// Build the validated stdio transport. The two bridge tasks are
/// spawned immediately; their lifecycle is exposed via `supervisor`.
pub fn stdio_with_validation() -> ValidatedStdio {
    let (inbound_our_end, inbound_rmcp_end) = tokio::io::duplex(BUF_SIZE);
    let (outbound_rmcp_end, outbound_our_end) = tokio::io::duplex(BUF_SIZE);

    let stdout = Arc::new(tokio::sync::Mutex::new(tokio::io::stdout()));

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

`BUF_SIZE = 64 * 1024`. Generous enough that one well-formed envelope
fits in a single write; both directions are independent tasks so
inbound stalls cannot cause outbound deadlock.

### Bridge-task supervisor

The supervisor has two methods so the shutdown logic can both
**fail-fast** during service runtime and **drain** after service
completion — `service.waiting()` resolving `Ok(())` only proves
rmcp finished writing to the duplex, not that the passthrough
flushed those bytes to real stdout. Without the drain phase, a
`BrokenPipe` on the final response would be silently lost.

```rust
impl ValidatorSupervisor {
    /// Non-consuming. Resolves when either bridge task returns
    /// `Err`, OR when both bridges exit `Ok` cleanly (an exotic
    /// mid-service condition — usually one side stays alive
    /// until the service ends and drains it). Used for fail-fast
    /// during the `service.waiting()` race.
    pub async fn watch_for_error(&mut self) -> io::Result<()>;

    /// Consuming. Awaits both bridge tasks to completion;
    /// returns the first error encountered. Used after
    /// `service.waiting()` resolves so final-write failures
    /// surface.
    ///
    /// **Do not call on init-failure paths** — the inbound bridge
    /// only exits on real stdin EOF, but a client may legitimately
    /// keep stdin open while waiting for the error response,
    /// causing this to hang. Use `shutdown_after_failure`
    /// instead.
    pub async fn drain(self) -> io::Result<()>;

    /// Failure-path shutdown. Aborts the inbound bridge (the
    /// client may keep stdin open while waiting for an error
    /// response; without abort, we'd block forever in `read_until`
    /// on real stdin), then awaits the outbound bridge to drain
    /// rmcp's queued error envelope plus any validator-synthesized
    /// rejections. Returns the first error from the outbound path;
    /// inbound cancellation is expected and ignored.
    ///
    /// Used on EVERY failure path — pre-init `ExpectedInitializeRequest`,
    /// `InitializeFailed`, post-init bridge race error, and post-init
    /// `service.waiting()` error. The only path that uses `drain` is
    /// the clean post-init success, where `service.waiting()`
    /// returning `Ok` already implies the inbound bridge exited
    /// (rmcp saw EOF on its read).
    pub async fn shutdown_after_failure(self) -> io::Result<()>;
}
```

`main.rs::run` runs two phases — race, then drain:

```rust
let validated = wire_validator::stdio_with_validation();
let stdout_for_preinit = Arc::clone(&validated.stdout);

let mut supervisor = validated.supervisor;
let mut init_fut = Box::pin(rmcp::serve_server(mcp_server, validated.transport));

// Race init against bridge errors. Without this, a bridge BrokenPipe
// during the pre-initialize phase (e.g. client sends a pre-init `ping`
// rmcp accepts, then stdout breaks before the response flushes) goes
// unobserved while rmcp waits indefinitely for `initialize`. The
// process would hang and never record `process_end.reason: Error`.
let init_outcome = tokio::select! {
    biased;
    bridge = supervisor.watch_for_error() => {
        // Bridge failed (or both bridges exited) before init resolved.
        Err(InitOutcome::Bridge(bridge))
    }
    result = &mut init_fut => match result {
        Ok(svc) => Ok(svc),
        Err(e) => Err(InitOutcome::Rmcp(e)),
    },
};
drop(init_fut); // releases rmcp's transport handles on any error path

let service = match init_outcome {
    Ok(svc) => svc,
    Err(InitOutcome::Bridge(bridge_result)) => {
        let primary = bridge_result
            .err()
            .map(|e| anyhow!("validator bridge during init: {e}"))
            .unwrap_or_else(|| anyhow!("validator bridges exited before init completed"));
        return match supervisor.shutdown_after_failure().await {
            Ok(()) => Err(primary),
            Err(_secondary) => Err(primary), // primary already captures the failure
        };
    }
    Err(InitOutcome::Rmcp(ServerInitializeError::ExpectedInitializeRequest(Some(msg)))) => {
        emit_pre_init_error_envelope(&msg, &stdout_for_preinit).await?;
        return match supervisor.shutdown_after_failure().await {
            Ok(()) => Ok(()),
            Err(e) => Err(anyhow!("validator bridge after pre-init: {e}")),
        };
    }
    Err(InitOutcome::Rmcp(ServerInitializeError::InitializeFailed(error_data))) => {
        let handled = handle_initialize_failed(&error_data);
        return match supervisor.shutdown_after_failure().await {
            Ok(()) => handled,
            Err(e) => Err(anyhow!("validator bridge after init failure: {e}")),
        };
    }
    Err(InitOutcome::Rmcp(other)) => {
        // Any non-handled init error: clean shutdown then propagate.
        let _ = supervisor.shutdown_after_failure().await;
        return Err(anyhow!("MCP server init: {other}"));
    }
};
```

`InitOutcome` is a small local enum:

```rust
enum InitOutcome<Svc> {
    Bridge(io::Result<()>),
    Rmcp(ServerInitializeError),
}
```

After this block, `service` is bound and `supervisor` is still owned
locally for the post-init race below.

```rust
let mut service_fut = Box::pin(service.waiting());

// Phase 1: race service against bridge errors.
let service_outcome: anyhow::Result<()> = tokio::select! {
    biased;
    bridge = supervisor.watch_for_error() => {
        match bridge {
            Err(e) => Err(anyhow!("validator bridge: {e}")),
            Ok(()) => {
                // Both bridges exited cleanly while service still
                // running (exotic). Treat as a transport teardown
                // and let service finish — it will see EOF.
                (&mut service_fut).await.map_err(|e| anyhow!("rmcp: {e}"))
            }
        }
    }
    result = &mut service_fut => result.map_err(|e| anyhow!("rmcp: {e}")),
};

// Phase 2: drop service to release rmcp's transport ends, then
// shut down the supervisor. Dispatch on service_outcome — clean
// success can wait for natural EOF on both bridges; any failure
// must abort inbound first because the client may keep stdin open.
drop(service_fut);
let shutdown_outcome = match &service_outcome {
    Ok(()) => {
        // service.waiting() Ok implies rmcp saw EOF on its read,
        // which implies the inbound bridge already exited. drain()
        // resolves inbound instantly and waits for outbound to
        // flush any queued frames.
        supervisor.drain().await
    }
    Err(_) => {
        // Any failure path: inbound may still be blocked in
        // `read_until` on real stdin. Abort before awaiting
        // outbound drain.
        supervisor.shutdown_after_failure().await
    }
}
.map_err(|e| anyhow!("validator bridge shutdown: {e}"));

let mcp_outcome = match (service_outcome, shutdown_outcome) {
    (Err(e), _) => Err(e),         // race-phase failure dominates
    (Ok(()), Err(e)) => Err(e),    // shutdown-phase failure surfaces
    (Ok(()), Ok(())) => Ok(()),
};
```

The `biased` discriminator gives the supervisor arm priority on
race-phase ties; the shutdown phase is unconditional after the race
resolves so a final-write `BrokenPipe` always lands in
`mcp_outcome: Err` → `process_end.reason: Error`. Any audit work
still flushes via the existing `drainer_handle.await` further down
in `main.rs::run`.

**Why two shutdown methods.** `drain()` is the natural success path —
it waits for both bridges to exit, which on `service.waiting() == Ok`
is essentially immediate. `shutdown_after_failure()` aborts the
inbound bridge first because a client legitimately keeping stdin open
after a server error would otherwise cause `drain()` to hang forever
in inbound's `read_until`. Tests 12-14 (race-phase and drain-phase
write failures), 20 (init-failure with open stdin), and 21 (post-init
failure with open stdin) pin the bounded-exit invariant on all paths.

### Pre-init shares the validator stdout

`main.rs`'s `emit_pre_init_error_envelope` currently writes directly to
`tokio::io::stdout()` (`main.rs:199-211`). After the transport swap,
the bridge tasks hold the synchronized stdout writer; a direct
`tokio::io::stdout()` write from `emit_pre_init_error_envelope` races
the passthrough task and can corrupt line-delimited output (e.g. a
pre-init `ping` request arrives, rmcp emits a response via passthrough,
and the next line is a `tools/list` rejection envelope — interleaved
mid-line).

Mechanical change to `main.rs`:

```rust
async fn emit_pre_init_error_envelope(
    msg: &rmcp::model::ClientJsonRpcMessage,
    stdout: &Arc<tokio::sync::Mutex<tokio::io::Stdout>>,
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

`preinit::synthesize_pre_init_error_envelope` itself is unchanged — it
remains a pure formatter. Only the caller in `main.rs` and the
function's signature change.

The new pre-init wire test
`preinit_envelope_does_not_interleave_with_rmcp_frame` (see "Testing")
exercises the formerly racy ordering and asserts both stdout lines
parse cleanly.

### Validation rules

JSON-RPC 2.0 §4-5 defines four valid envelope shapes from a peer:

- **Request**: `{jsonrpc:"2.0", method:string, id:string|number, params?}`
- **Notification**: `{jsonrpc:"2.0", method:string, params?}` (no `id`)
- **Response (success)**: `{jsonrpc:"2.0", id:string|number, result:any}` (no `method`, no `error`)
- **Error response**: `{jsonrpc:"2.0", id:string|number, error:{code:number, message:string, data?:any}}` (no `method`, no `result`)

The validator forwards all four; rejects everything else. Responses
and Errors from the client side are part of MCP's server-initiated
flow (e.g. sampling requests where the server asks the client to
invoke its LLM and the client returns a response) — rejecting them
would be a feature regression, not just a test gap.

**`id` is string|number — NOT null — on incoming envelopes.** rmcp 1.5
deserializes id fields via `RequestId = NumberOrString`; null ids fail
deserialization on `JsonRpcRequest`, `JsonRpcResponse`, and
`JsonRpcError`. The JSON-RPC 2.0 spec allows null id only on
*synthesized server responses* when the server couldn't detect the
request's id (e.g. parse errors). The validator emits null in those
synthesized responses (see "`id`-echo policy") but rejects incoming
envelopes with null id. This matches rmcp's accepted grammar and
upholds the "validator forwards only what rmcp can parse" promise.

| Input shape | Decision | Wire response | Notes |
|---|---|---|---|
| Empty / whitespace-only line | Skip silently | (none) | Transport noise; rmcp tolerates the same today. |
| Bytes that are not valid JSON | Reject | `-32700 Parse error`, `id: null` | The id is unknowable — `null` per JSON-RPC §5. |
| Valid JSON, not an object (incl. JSON arrays — MCP forbids batches) | Reject | `-32600 Invalid Request`, `id: null` | rmcp 1.5 doesn't speak batches; we reject for forward-compat. |
| Object missing `jsonrpc` | Reject | `-32600`, `id: <echoed or null>` | The #277 minimal failing case. |
| Object with `jsonrpc` ≠ `"2.0"` | Reject | `-32600`, `id: <echoed or null>` | E.g. `"1.0"`, `2.0` (number), `"2.00"`. |
| Object with `id` field of disallowed type (object/array/boolean) | Reject | `-32600`, `id: null` | Per JSON-RPC §5: "if there was an error in detecting the id … it MUST be Null." |
| Object with `id: null` | Reject | `-32600`, `id: null` | rmcp's `RequestId` = `NumberOrString`; null isn't deserializable on Request/Response/Error. |
| **Has `method` (string)** with `id: string|number`, no `result`, no `error` | Forward | — | Request. |
| **Has `method` (string)** with no `id`, no `result`, no `error` | Forward | — | Notification. |
| **Has `method` (non-string)** | Reject | `-32600`, `id: <echoed or null>` | |
| **Has `result`** with `id: string|number`, no `method`, no `error` | Forward | — | Client Response to a server-initiated request. |
| **Has `error`** with `id: string|number`, valid error object, no `method`, no `result` | Forward | — | Client Error response to a server-initiated request. |
| **Has `error`** but error is not an object, or missing numeric `code`, or missing string `message` | Reject | `-32600`, `id: <echoed or null>` | JSON-RPC §5.1 grammar for `error`. |
| **Has both `result` AND `error`** | Reject | `-32600`, `id: <echoed or null>` | Per JSON-RPC §5: exactly one of result/error. |
| Has `result` or `error` but no `id` | Reject | `-32600`, `id: null` | Response/Error envelopes MUST have an `id`. |
| Empty object (no `method`, no `result`, no `error`) | Reject | `-32600`, `id: <echoed or null>` | |
| Mixes `method` with `result` or `error` | Reject | `-32600`, `id: <echoed or null>` | A line is exactly one envelope shape. |

The forward set is the JSON-RPC 2.0 envelope grammar restricted to
non-batch shapes. The only behavior change vs today is: malformed
inputs that rmcp silently drops now get a `-32600`/`-32700` response.

### `validate()` decision logic

```rust
/// `id` accepted by rmcp's RxJsonRpcMessage. Null is excluded
/// because rmcp's RequestId = NumberOrString.
fn is_forwardable_id(v: &Value) -> bool {
    v.is_string() || v.is_number()
}

/// `error` body matches JSON-RPC §5.1: an object with numeric
/// `code` and string `message`. `data` is optional.
fn is_well_formed_error(v: &Value) -> bool {
    let Some(obj) = v.as_object() else { return false; };
    obj.get("code").is_some_and(Value::is_number)
        && obj.get("message").is_some_and(Value::is_string)
}

fn validate(line: &str) -> ValidationOutcome {
    if line.trim().is_empty() {
        return ValidationOutcome::Skip;
    }
    let parsed: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(_) => return ValidationOutcome::Reject(parse_error()),
    };
    let obj = match parsed.as_object() {
        Some(o) => o,
        None => return ValidationOutcome::Reject(invalid_request(None)),
    };
    if obj.get("jsonrpc").and_then(|v| v.as_str()) != Some("2.0") {
        return ValidationOutcome::Reject(invalid_request(extract_id(obj)));
    }

    let id_present_and_valid = match obj.get("id") {
        None => false,                                   // notification or invalid response
        Some(v) if is_forwardable_id(v) => true,         // string|number
        Some(_) => return ValidationOutcome::Reject(invalid_request(None)), // null/array/object/bool
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
        (Some(_), None, None) => ValidationOutcome::Reject(invalid_request(extract_id(obj))),
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
```

`extract_id(obj)` returns `Some(Value)` if `obj["id"]` is
`string|number`, else `None` (we use `null` on the wire — note that
synthesized rejection envelopes can carry `id: null` per JSON-RPC §5,
but incoming envelopes with `id: null` are rejected at the third
check above). The catch-all arm covers: empty object, both `result`
and `error`, method mixed with result/error, response/error without
id, and malformed `error` bodies — all single-line `-32600` rejections.

### `id`-echo policy

Decision tree for the `id` field on a **synthesized rejection
envelope** (validator → wire). Note: incoming envelopes with `id: null`
are *rejected* by the validator (see "Validation rules" — null doesn't
deserialize on rmcp's `RequestId`), but the rejection envelope itself
emits `id: null` per JSON-RPC §5 when the original id couldn't be
detected:

- Top-level `"id"` is a JSON string → echo as-is.
- Top-level `"id"` is a JSON number → echo as-is.
- Top-level `"id"` is JSON `null` → echo `null` (envelope rejected
  for null id, but we preserve the spec's "couldn't detect id" path
  by reflecting it on the wire — alternative is `null` either way).
- Top-level `"id"` is missing → `null`.
- Top-level `"id"` is any other shape (object, array, bool) → `null`.
- Input not parseable as JSON → `null`.

Matches `preinit.rs::synthesize_pre_init_error_envelope` and JSON-RPC §5.

## Error envelope shapes

**Invalid Request** (`-32600`):

```json
{
  "jsonrpc": "2.0",
  "id": <echoed-or-null>,
  "error": {
    "code": -32600,
    "message": "Invalid Request"
  }
}
```

**Parse error** (`-32700`):

```json
{
  "jsonrpc": "2.0",
  "id": null,
  "error": {
    "code": -32700,
    "message": "Parse error"
  }
}
```

No `data` field on either — JSON-RPC §5.1 makes it optional and the
envelope shape is self-describing. Pre-init envelopes (#275) and
version-rejection envelopes (#276) likewise omit `data` unless adding
machine-readable detail (supported-version array for #276); there is no
analogous structured detail for "your envelope was malformed."

Lines are emitted with a trailing `\n` and flushed, same as
`preinit.rs:emit_pre_init_error_envelope`.

## File layout

- **New:** `crates/rimap-server/src/mcp/wire_validator.rs`
  - `pub struct ValidatedStdio { transport, stdout, supervisor }` and
    `pub fn stdio_with_validation() -> ValidatedStdio` — entry point
    used by `main.rs`.
  - `pub struct ValidatorSupervisor` with `pub async fn join(self) -> io::Result<()>`.
  - `fn validate(line: &str) -> ValidationOutcome` — pure
    function, no I/O. Unit-testable in isolation.
  - `enum ValidationOutcome { Forward, Skip, Reject(ErrorEnvelope) }`
  - `fn synthesize_error_envelope(code: i32, message: &str, id: Option<Value>) -> String`
  - `async fn validate_inbound(...)` and `async fn passthrough_outbound(...)` —
    the two bridge tasks, each returning `io::Result<()>` so write
    failures surface via the supervisor's `JoinHandle`s.
- **Modified:** `crates/rimap-server/src/main.rs` —
  - swap the transport constructor (`stdio_with_validation()`),
  - thread `Arc<Mutex<Stdout>>` into `emit_pre_init_error_envelope` so
    pre-init rejections share the validator's stdout writer,
  - two-phase shutdown: race `service.waiting()` against
    `supervisor.watch_for_error()` via `tokio::select! { biased; ... }`,
    then unconditionally `supervisor.drain().await` before classifying
    `mcp_outcome`.
- **Modified:** `crates/rimap-server/src/mcp/mod.rs` — `pub mod wire_validator;`
- **Modified:** `crates/rimap-server/tests/mcp_wire_proptest.rs` —
  - add `prop_filter` to `arb_envelope()` excluding spec-legal
    notifications (see "Property strategy adjustment"),
  - remove the `#[ignore]` from `prop_envelope_never_panics` so it
    runs at the default 1000 cases and nightly 100k.
  - No changes to the property body; no liveness probe needed.
- **No changes to** `tests/support/wire/harness.rs` for the
  notification path — earlier drafts proposed a non-poisoning
  `assert_notification_then_alive` method but the strategy filter
  approach removes the need. The closed-stdout helpers added for
  #275 remain in use for tests 12-14.
- **Modified:** `crates/rimap-server/tests/mcp_wire_negative.rs` — new
  pinned tests (see "Testing" below).
- **No changes to** `crates/rimap-server/src/mcp/preinit.rs` itself —
  its `synthesize_pre_init_error_envelope` remains a pure formatter;
  the I/O caller in `main.rs` is what changes.

## Property strategy adjustment (case 2)

`prop_envelope_never_panics` currently treats `CloseOrResponse::Hung`
as a `panic!`. After the validator lands, the only remaining `Hung`
source is the spec-compliant silent-ignore path: valid JSON-RPC 2.0
notifications (`jsonrpc:"2.0"`, no `id`, non-standard `method`).

**Approach: filter notifications out of the property strategy
entirely; cover the notification path via a fixed-case test.**

This is the simplest design that keeps the property meaningful and
the nightly workflow within budget. Earlier drafts threaded an
in-test liveness probe to distinguish spec-legal silence from a real
hang; that approach was rejected because it (a) added a non-trivial
non-poisoning harness API, and (b) extrapolated to ~104 minutes on
nightly runs at `PROPTEST_CASES=100000`, exceeding the workflow's
90-minute timeout.

### Strategy filter

```rust
fn arb_envelope() -> impl Strategy<Value = Value> {
    (
        prop::option::of(Just("2.0".to_string())),
        prop::option::of(arb_id),
        prop::option::of(arb_method),
        prop::option::of(arb_params),
    )
        .prop_map(/* ... unchanged ... */)
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
}
```

`prop_filter` drops cases that fail the predicate — proptest will
generate replacement cases until the strategy yields a non-
notification envelope. The missing-`jsonrpc` cases that originally
triggered #277 stay in coverage (they aren't notifications because
the first clause of the filter fails). Request-shaped, invalid, and
batch envelopes all flow unchanged.

### Property body

With notifications filtered out, the body reverts to the simple
original form — no liveness probe, no non-poisoning machinery:

```rust
h.send_line(&envelope.to_string()).await;
let outcome = h.response_or_close(REQUEST_TIMEOUT).await;
match outcome {
    CloseOrResponse::Response(line) => {
        let env: Value = serde_json::from_str(line.trim_end())
            .expect("server response must be valid JSON");
        assert_envelope_valid(&env);
    }
    CloseOrResponse::CleanClose => {} // spec-legal; harness drops + respawns
    CloseOrResponse::Crashed(d) => panic!("crashed on {envelope}: {d}"),
    CloseOrResponse::Hung => panic!(
        "hung on {envelope} (validator should reject malformed or rmcp should respond)",
    ),
}
```

### Fixed-case notification coverage

One wire-pinned test in `mcp_wire_negative.rs` covers the notification
path explicitly:

- `valid_notification_does_not_hang_session` — send a standard MCP
  notification (`notifications/cancelled` with `params.requestId: 0`),
  then a `tools/list` request, and assert `tools/list` returns a
  well-formed response within `REQUEST_TIMEOUT`. Proves notifications
  don't poison or hang the session, without needing a property-level
  liveness probe.

This is sufficient regression coverage because rmcp's notification
handling is a single control-flow path (silent-ignore for non-MCP
notifications, dispatch for standard ones). One test exercises both
sides — `notifications/cancelled` is on the standard list, so rmcp
dispatches it; the subsequent `tools/list` proves the session is
still alive.

### Overhead

Filtering removes the ~25% notification share of generated cases.
The remaining strategy still generates 1000 cases per invocation;
proptest's `prop_filter` may generate slightly more upstream
candidates to maintain that, but the cost is negligible (proptest
strategies are cheap). Nightly remains within its 90-minute
budget; no env-overridable timeouts needed.

## Testing

**Property — must un-ignore and pass:**

- `prop_envelope_never_panics` at 1000 cases (`PROPTEST_CASES=1000`,
  the default). Nightly scales via the existing
  `mcp-fuzz-nightly.yml` workflow. The property body is amended per
  the section above before un-ignoring.

**Wire-pinned negative tests** in `mcp_wire_negative.rs` (mirrors the
#275 / #276 conventions — one test per row, strict assertions on code
and id):

1. `envelope_missing_jsonrpc_returns_invalid_request` — input
   `{"method":"a"}` → `-32600`, `id: null`.
2. `envelope_missing_jsonrpc_with_numeric_id_echoes_id` —
   `{"method":"a","id":42}` → `-32600`, `id: 42`.
3. `envelope_missing_jsonrpc_with_string_id_echoes_id` —
   `{"method":"a","id":"abc"}` → `-32600`, `id: "abc"`.
4. `envelope_missing_jsonrpc_with_malformed_id_uses_null` —
   `{"method":"a","id":[1,2]}` → `-32600`, `id: null`.
5. `envelope_with_wrong_jsonrpc_value_returns_invalid_request` —
   `{"jsonrpc":"1.0","method":"x","id":1}` → `-32600`, `id: 1`.
6. `envelope_with_non_string_method_returns_invalid_request` —
   `{"jsonrpc":"2.0","method":42,"id":1}` → `-32600`, `id: 1`.
7. `envelope_batch_array_returns_invalid_request` —
   `[{"jsonrpc":"2.0","method":"x","id":1}]` → `-32600`, `id: null`.
8. `envelope_invalid_json_returns_parse_error` — `not valid json` →
   `-32700`, `id: null`.
9. `envelope_empty_line_is_skipped` — empty line followed by valid
   `tools/list` request → `tools/list` response arrives on time, no
   spurious error envelope precedes it.
10. `session_survives_invalid_envelope` — valid `initialize` →
    invalid envelope → valid `tools/list`. The third message gets a
    normal response; the session is not closed.
11. `preinit_envelope_does_not_interleave_with_rmcp_frame` — pre-init
    `ping` (which rmcp answers via the passthrough) immediately
    followed by a pre-init `tools/list` (which `emit_pre_init_error_envelope`
    rejects with `-32002`) → both stdout lines parse as well-formed,
    distinct JSON-RPC envelopes with the expected `id` mapping. Pins
    the new shared-stdout invariant.
12. `process_end_on_validator_rejection_write_failure` — closed-stdout
    harness variant: client sends an invalid envelope, validator's
    `-32600` write fails with `BrokenPipe`, supervisor surfaces the
    error to `mcp_outcome`, audit records `process_end.reason: Error`,
    exit is non-zero. Mirrors #275's `process_end_on_pre_init_write_failure`.
13. `process_end_on_rmcp_response_write_failure` — closed-stdout
    harness variant during race phase: client sends a valid
    `tools/list`, rmcp's response write into the passthrough fails
    while `service.waiting()` is still running, `watch_for_error`
    catches it, audit records `process_end.reason: Error`, exit
    non-zero. Companion to test 12 for the outbound bridge.
14. `process_end_on_drain_phase_write_failure` — closed-stdout
    harness variant during drain phase: client sends valid
    `initialize` + `tools/list`, then closes stdin so `service.waiting()`
    resolves `Ok(())`. rmcp's `tools/list` response is queued in the
    outbound duplex but the passthrough's write to (closed) stdout
    fails. `supervisor.drain()` surfaces the error, audit records
    `process_end.reason: Error`, exit non-zero. Pins the race-vs-drain
    distinction.
15. `valid_notification_does_not_hang_session` — fixed-case
    notification coverage (replaces the property's notification
    strategy). Send a standard MCP notification
    (`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":0}}`),
    then a `tools/list` request, and assert `tools/list` returns a
    well-formed response within `REQUEST_TIMEOUT`. Proves the
    notification path doesn't poison or hang the session.
16. `valid_response_envelope_forwards` — send a client-shaped
    Response envelope (`{"jsonrpc":"2.0","id":99,"result":{"x":1}}`)
    after init. The validator must NOT reject. rmcp handles the
    spurious response (likely a `notifications/cancelled`-style
    silent drop since there's no pending server request), so the
    test asserts no `-32600` envelope appears within
    `REQUEST_TIMEOUT`, then issues a `tools/list` and verifies the
    session is alive. Pins that the validator does not regress
    MCP's server-initiated flow.
17. `valid_error_envelope_forwards` — send a client-shaped Error
    envelope (`{"jsonrpc":"2.0","id":99,"error":{"code":-32601,"message":"not found"}}`)
    after init. Same shape as test 16: no validator rejection,
    session stays alive.
18. `envelope_with_both_result_and_error_returns_invalid_request`
    — `{"jsonrpc":"2.0","id":1,"result":{},"error":{}}` → `-32600`
    with `id: 1`.
19. `envelope_response_without_id_returns_invalid_request` —
    `{"jsonrpc":"2.0","result":{}}` → `-32600` with `id: null`.
20. `init_failure_with_open_stdin_returns_promptly` — client sends
    `initialize` with an unsupported `protocolVersion` (rmcp emits
    `-32602`), then **does NOT close stdin**. The server must
    `shutdown_after_failure`, write the `-32602` envelope, abort
    inbound, drain outbound, and exit within a bounded timeout
    (e.g. 2 s). Pins that the failure-shutdown path does not require
    real stdin EOF.
21. `process_end_on_post_init_service_error_with_open_stdin` —
    closed-stdout harness variant for a POST-init failure: client
    completes `initialize`, sends a valid `tools/list`, rmcp's
    response write into the passthrough fails (closed stdout) →
    `service.waiting()` returns Err. **Client keeps stdin open**
    and sends nothing more. The server must `shutdown_after_failure`
    (abort inbound, drain outbound), exit within a bounded timeout
    (e.g. 2 s), record `process_end.reason: Error`, and exit
    non-zero. Pins the bounded-exit invariant for the post-init
    failure path; companion to test 20 for the post-init equivalent.
22. `process_end_on_pre_init_bridge_error_with_open_stdin` —
    closed-stdout harness variant for an INIT-PHASE bridge failure:
    client sends a pre-init `ping` (rmcp accepts and queues a
    response). The passthrough write to (closed) stdout fails
    while rmcp is still waiting for `initialize`. **Client keeps
    stdin open** and never sends `initialize`. The init-phase
    `tokio::select!` (race `serve_server` against
    `watch_for_error`) must observe the bridge error and route
    through `shutdown_after_failure`, exit within bounded time,
    record `process_end.reason: Error`. Pins the init-phase
    supervisor visibility added in revision 15.
23. `envelope_request_with_null_id_returns_invalid_request` —
    `{"jsonrpc":"2.0","method":"tools/list","id":null}` → `-32600`
    with `id: null`. Pins that the validator rejects null ids that
    rmcp's `RequestId = NumberOrString` cannot deserialize — without
    this, the envelope would pass the validator and produce an
    inconsistent error path inside rmcp.
24. `envelope_error_response_with_malformed_body_returns_invalid_request`
    — `{"jsonrpc":"2.0","id":1,"error":{"code":"not-a-number"}}` →
    `-32600` with `id: 1`. Pins the `is_well_formed_error` check
    (`code` must be number, `message` must be string).
25. `envelope_error_response_without_code_returns_invalid_request`
    — `{"jsonrpc":"2.0","id":1,"error":{"message":"oops"}}` →
    `-32600` with `id: 1`. Same `is_well_formed_error` check —
    missing-`code` variant.

Note: tests 16-17 use **non-null integer ids** (e.g. `99`) so they
pass the validator's `is_forwardable_id` check.

All tests run against the production binary via the existing
`Harness`. Tests 12-14 and 22 use the closed-stdout harness variant
added in `tests/support/wire/harness.rs` for #275. Tests 16-17 add
small client-side helpers (`send_line` + bounded silence wait)
reusing existing primitives. Tests 20-22 need a harness variant
that holds stdin open after sending — small extension.

**Unit tests** in `wire_validator.rs::tests` covering `validate()` in
isolation, one assertion per row of the validation rules table. Pure
function, no async, ~30 lines of test code.

**Integration regression** — full `mcp_wire_negative.rs` and
`mcp_wire_proptest.rs` suites must pass with the validator in place
without ANY existing test going from pass → fail. The validator's
forward set is a strict superset of the JSON-RPC 2.0 grammar, so
this should hold by construction.

## Risks & mitigations

- **Validator framing drift from rmcp's codec.** rmcp splits on `\n`
  and tolerates a trailing `\r` (`without_carriage_return` in
  `async_rw.rs`). Validator uses `read_until(b'\n', ...)` and forwards
  the buffer (including the trailing `\n`) verbatim — rmcp's codec
  then strips `\r` and parses normally. Strict validation runs on
  the buffer minus the trailing `\n`/`\r`, matching rmcp's view.
  Pin a wire-level test with `\r\n` line endings.
- **Validator stricter than rmcp on a shape rmcp accepts.** The
  forward set is the JSON-RPC 2.0 envelope grammar — rmcp's
  compatibility shim is a strict subset of that. Mitigation: every
  existing `mcp_wire_negative.rs` test continues to pass unchanged.
- **Duplex buffer deadlock.** The two duplex pairs are independent;
  one direction stalling cannot block the other. Buffer is 64 KiB,
  far larger than any sane envelope. Mitigation: leave the buffer
  generous; the proptest will exercise heterogeneous envelope sizes.
- **Async cancellation safety.** The validator and passthrough tasks
  are spawned with `tokio::spawn`; the supervisor owns their
  `JoinHandle`s. On `service.waiting()` resolution the supervisor's
  `join()` is dropped, which aborts the tasks; the tasks own their
  I/O handles and drop them on exit, surfacing EOF/write-error to
  rmcp. Same shutdown shape as today's direct stdio transport, with
  the added guarantee that a write error from either task is
  captured by `tokio::select!` before the supervisor is dropped.
- **Backpressure under sustained malformed input.** Each rejection
  writes to real stdout from the validator task. A slow consumer
  could stall the validator; that's identical to today's stall
  behavior on rmcp's outbound write under a slow consumer, and is
  out of scope.
- **Audit-record masking by silent task failures.** Without the
  supervisor (the original spec draft), a bridge task could die
  with `BrokenPipe` and `service.waiting()` could resolve `Ok(())`
  on its own EOF path, recording `process_end.reason: Eof` even
  though no response ever reached the client. Mitigation: the
  supervisor uses two-phase shutdown — `watch_for_error()` for
  race-phase fail-fast plus an unconditional `drain()` after
  service completion. Tests 12, 13, and 14 pin the audit
  semantics on both bridges across both shutdown phases.
- **Drain-phase write failure invisibility.** If we only raced
  `service.waiting()` against the supervisor and short-circuited
  on whichever resolved first, `service.waiting() → Ok(())` could
  fire while a final passthrough frame is still queued in the
  duplex; a subsequent `BrokenPipe` on that write would be lost.
  Mitigation: drain is unconditional after the race; test 14
  exercises exactly this ordering.
- **Notification path narrows proptest coverage.** Filtering
  spec-legal notifications out of the property strategy means the
  property no longer exercises the ~25% notification share of the
  case space. Mitigation: notifications collapse to a single
  control-flow path (silent-ignore for non-MCP, dispatch for
  standard); test 15 exercises both ends explicitly. The
  alternative (in-test liveness probe) was rejected on nightly-
  budget grounds (~104 min at 100k cases) and complexity.
- **Shutdown hang on open stdin.** A naïve `drain()` waits for both
  bridge tasks; the inbound bridge only exits on real stdin EOF.
  A client legitimately keeping stdin open while waiting for an
  error response (pre-init OR post-init failure) would otherwise
  cause the server to hang forever instead of exiting with
  `process_end.reason: Error`. Mitigation: every failure path
  routes through `shutdown_after_failure` (abort inbound, drain
  outbound); only the clean post-init success path uses plain
  `drain`. Tests 20 (pre-init) and 21 (post-init) pin bounded exit
  with stdin held open by the client.
- **Validator rejecting server-initiated flow responses.** MCP's
  sampling and similar flows send a server-initiated request and
  expect a client-shaped Response or Error envelope back. An
  over-strict validator (rejecting any envelope without `method`)
  would silently break these. Mitigation: validator forwards all
  four spec-defined envelope shapes (Request, Notification,
  Response, Error); tests 16-19 pin the inclusive forward set.
- **Validator forwarding what rmcp can't deserialize.** The
  validator's grammar must be a subset of rmcp's accepted grammar
  — forwarding an envelope rmcp then rejects with a deserialization
  error defeats the "no silent drop" promise (the result is not a
  hang, but an inconsistent error path). Specifically: rmcp 1.5's
  `RequestId = NumberOrString` excludes null ids. The validator
  rejects `id: null` on incoming envelopes, restricting the forward
  set to `id: string|number` per rmcp. Test 23 pins this.
- **Init-phase bridge errors going unobserved.** Until rmcp returns
  a service, the supervisor isn't being polled. A bridge `BrokenPipe`
  during the pre-init handshake (e.g. rmcp answers a pre-init
  `ping` and stdout breaks) would otherwise let rmcp wait
  indefinitely for `initialize` while the validator is dead.
  Mitigation: `rmcp::serve_server(...).await` is itself wrapped in
  `tokio::select!` against `supervisor.watch_for_error()`; test 22
  pins bounded exit on this path.

## Dependencies and merge plan

This fix is the final merge blocker for PR #278 (the #266 fuzzing
umbrella). The implementation lands on
`feature/issue-266-mcp-fuzzing` directly, in one diff that includes:

1. `wire_validator.rs` with `ValidatedStdio` / `ValidatorSupervisor`
   (three methods: `watch_for_error`, `drain`,
   `shutdown_after_failure`), the `validate()` pure function
   recognizing all four spec envelope shapes, and the two bridge
   tasks.
2. `main.rs` updates: transport swap, `emit_pre_init_error_envelope`
   signature thread-through, init-phase race (`rmcp::serve_server`
   future against `supervisor.watch_for_error()`), two-phase
   post-init shutdown (race then dispatch — `drain` on success,
   `shutdown_after_failure` on failure), and `shutdown_after_failure`
   for both init-failure arms (`ExpectedInitializeRequest` and
   `InitializeFailed`) plus the new init-phase bridge-error arm.
   Local `InitOutcome` enum disambiguates init-phase failure
   sources.
3. `mcp_wire_proptest.rs`: `prop_filter` on `arb_envelope()` to
   exclude spec-legal notifications; un-ignore
   `prop_envelope_never_panics`. No property-body changes beyond
   that (no liveness probe, no non-poisoning harness method).
4. Small harness extension for test 20: variant that holds stdin
   open after sending. Existing closed-stdout helpers cover
   tests 12-14 unchanged.
5. 25 new wire-pinned tests in `mcp_wire_negative.rs`:
   - 10 for validation rules (tests 1-10)
   - 1 for pre-init ordering (test 11)
   - 3 for closed-stdout audit semantics during post-init phases
     (tests 12-14)
   - 1 fixed-case notification path (test 15)
   - 2 for Response/Error envelope forwarding (tests 16-17)
   - 2 for malformed Response/Error rejection (tests 18-19)
   - 3 for bounded-exit with open stdin on failure paths
     (tests 20 pre-init init-failure, 21 post-init service error,
     22 init-phase bridge error)
   - 3 for rmcp-grammar id and error-body matching
     (test 23 null id, tests 24-25 malformed error body)
6. Mirror docs (this spec, committed before implementation starts).

Once green, PR #278 comes out of draft and goes to review with all
three blockers (#275, #276, #277) resolved.

## Implementation follow-ups

These items are NOT spec gaps that need design work — they're
narrow tightenings the implementer applies at the `validate()` call
site, captured here so they don't get lost between spec and code.
Each is bounded to a few lines plus matching tests.

- **Tighten `is_forwardable_id` to rmcp's numeric grammar.** rmcp 1.5
  deserializes `RequestId::Number` as `i64`. The current
  `Value::is_number()` check accepts fractional or out-of-range
  values that pass the validator but fail inside rmcp — defeating
  the "no silent drop" promise. Replace with
  `v.as_i64().is_some()` (which already rejects fractional and
  out-of-i64-range values via serde_json's number representation).
  Add tests for fractional id (`{"jsonrpc":"2.0","method":"x","id":1.5}`
  → -32600) and out-of-range id (`{...,"id":9223372036854775808}` →
  -32600 — note: serde_json may parse very large integers as f64,
  also rejected by `as_i64()`).
- **Tighten `is_well_formed_error.code` to rmcp's `ErrorCode = i32`.**
  Same class of issue: replace `Value::is_number()` on `code` with
  `v.as_i64().is_some_and(|n| i32::try_from(n).is_ok())`. Add tests
  for fractional `code` (`{"code":1.5,"message":"x"}` → -32600 on
  the parent envelope) and out-of-i32-range `code` (`{"code":2147483648,...}` →
  -32600).

These were surfaced by Codex round 6 after the agreed stop on spec
iteration. The implementer applies them when writing the actual
validator; no further spec change is needed.

## Out of scope

- **Upstream rmcp fix.** Filing a separate issue against rmcp to make
  `JsonRpcMessageCodec::decode` propagate rejections is reasonable
  future work but not on this critical path. The local validator
  closes the contract independently.
- **Outbound validation.** Our server's outbound envelopes come
  through rmcp's typed `ServerJsonRpcMessage` and are well-formed by
  construction. The passthrough side does not need to validate.
- **Custom error data fields.** Sticking to `{code, message}` for
  these envelopes is sufficient. Re-evaluate if a client reports
  needing structured diagnostics.
