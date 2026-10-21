# ADR-0032: Modern first requests and legacy pre-init interception

## Status

Accepted · 2026-10-21 · issue [#837](https://github.com/randomparity/rusty-imap-mcp/issues/837).
Supersedes [ADR-0025](0025-pre-init-single-envelope-validator-interception.md).

## Context

rmcp 3.1.4 supports a non-initialize first request when its required MCP 2026-07-28
metadata decodes correctly: protocolVersion and clientCapabilities, with clientInfo optional.
Its `serve_server_with_ct_inner` uses `GetMeta::missing_required_keys` to decide this,
then requires metadata on ongoing requests. ADR-0025's method-only interception hides this path.
Missing required metadata instead makes rmcp send -32602 and fail initialization; EOF before
initialize is also an initialization error, not a clean dependency shutdown.

## Decision

Retain interception only for legacy pre-init requests that lack complete modern metadata.
Use rmcp's typed completeness predicate rather than duplicating its key/type rules. Validate
the envelope before letting a modern request disable interception, and forward modern requests
unchanged. A modern session stays established so rmcp owns ongoing metadata errors and recovery.
Ping alone does not establish a session; the existing legacy initialize path is preserved.

For intercepted legacy requests, write exactly one opaque -32002, echo the ID, flush, then
raise `pre_init_intercepted` before dropping the duplex. The local `serve_mcp` flag check
overrides rmcp's EOF initialization failure and returns success (exit0, audit reason Eof).
It is this local policy, not rmcp's EOF behavior, that produces the clean close.

With broken stdout (#830), either rmcp can report `ConnectionClosed("initialize request")`
before validator dispatch, or the validator's envelope write can fail after dispatch. Neither
winning arm nor stderr context is deterministic. The durable invariant is non-zero exit,
`process_end.reason = Error`, and no SIGPIPE; the interception flag is not raised on write failure.

## Consequences

Metadata-complete clients can use the modern lifecycle; legacy clients retain the single-error
contract. Validation and shutdown use existing paths and no new dependency. Tests must pin
both protocol eras and their transitions. ADR-0025 remains immutable; its broader interception
and clean-rmcp-EOF statements no longer govern. The ADR index is updated by the campaign owner.

## Considered & rejected

- **Keep method-only interception.** verified: rmcp3.1.4 `service/server.rs`
  `serve_server_with_ct_inner` accepts metadata-complete first requests; swallowing them prevents
  that supported lifecycle and contradicts #837.
- **Remove interception and restore two envelopes.** verified: #821's dedicated issue,
  confirming review and single-envelope wire tests establish the required legacy behavior.
  That demonstrated client contract outweighs ADR-0024's judgment against bespoke transport
  interception. Narrowing interception preserves its benefit without swallowing modern requests.
- **Copy metadata validation locally.** judgment: duplicating the dependency's existing typed
  predicate creates drift without improving this lifecycle boundary.
