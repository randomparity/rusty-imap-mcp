# ADR-0024: Pre-initialize request wire sequence carries rmcp's -32602 before our -32002 envelope

**Status:** Accepted · 2026-08-21 · issue [#733](https://github.com/randomparity/rusty-imap-mcp/issues/733)

## Context

Issue #275 (spec
[`docs/superpowers/specs/2026-05-14-issue-275-pre-initialize-handling-design.md`](../superpowers/specs/2026-05-14-issue-275-pre-initialize-handling-design.md))
fixed the pre-`initialize` crash: a non-ping, non-initialize request arriving
before `initialize` gets exactly one JSON-RPC error envelope — code `-32002`
(Server not initialized), id echoed verbatim — then a clean exit `0` with
`process_end.reason: Eof`. The mechanism relies on rmcp's serve loop returning
`ServerInitializeError::ExpectedInitializeRequest` for the offending first
message; `main.rs::handle_init_failure` synthesizes and writes the envelope.

rmcp 3.x (`service/server.rs`, pre-init branch) changed that flow: before
returning `ExpectedInitializeRequest`, it validates every such request against
the **2026-07-28** `_meta` requirements — `io.modelcontextprotocol/protocolVersion`
and `io.modelcontextprotocol/clientCapabilities` — because no protocol version
has been negotiated yet, so the newest spec's sender rules are the only ones
that can be applied. A request missing those keys is answered `-32602`
(invalid params) by rmcp itself, before our handler or init-failure path runs.
There is no configuration knob; the handler never sees the message.

The observed wire sequence for a meta-less pre-init request under rmcp 3.1.4 is
therefore:

1. `-32602` from rmcp's pre-init `_meta` enforcement (id echoed),
2. our `-32002` #275 envelope (id echoed, fixed opaque message),
3. clean close, exit `0`, audit `process_end.reason: Eof`.

Two candidates were evaluated.

## Decision

**Accept the two-envelope sequence.** Adapt the pinning tests to assert the
full sequence rather than intercepting the first message ourselves.

The `-32002` contract is unchanged in every property #275 recorded: same code,
same fixed opaque message, id echoed verbatim (numbers and strings), no `data`
field, clean exit `0`, `Eof` audit reason. What changes is that an additional,
distinct error envelope precedes it on an already-invalid client path.

The rejected alternative was to preserve single-envelope output by
pre-validating the first client message in
`wire_validator::stdio_with_validation()` (#277's interception layer) and
synthesizing the `-32002` envelope without forwarding the request to rmcp.
That was rejected because it adds permanent, bespoke logic to the most
security-sensitive transport layer solely to hide upstream behavior — logic
whose failure modes would need their own pinned test surface — to remove noise
on a path only a broken or hostile client ever reaches.

## Consequences

- `crates/rimap-server/tests/mcp_wire_negative.rs`
  (`tools_list_before_initialize`, `tools_list_before_initialize_str_id`) now
  pin both envelopes in order: `-32602` then `-32002`, each echoing the
  request id verbatim, followed by the unchanged clean-close/Eof assertions.
  Any future shift in either envelope fails loudly.
- Clients written against the documented #275 contract observe one extra
  JSON-RPC error line before the expected `-32002` envelope, and only when
  they send a well-formed-but-premature *request*. Notifications and responses
  remain silent (no id to answer), matching the existing
  `pre_initialize_notification_silent_close` behavior.
- The `-32002` code registry (`crates/rimap-server/src/mcp/error.rs`),
  `preinit.rs` synthesizer, and `main.rs` init-failure handling are untouched.
