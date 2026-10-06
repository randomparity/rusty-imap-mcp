# Issue #867: validator rejects `params._meta` shapes rmcp rejects

Scope: [#867](https://github.com/randomparity/rusty-imap-mcp/issues/867). Decision:
[ADR-0031](../../ADR/0031-validator-mirrors-rmcp-params-meta-grammar.md). Excluded:
metadata-complete modern first-request initialization (#837).

## Problem

The `validate` fuzz target saved unit `crash-79232b86fb09d5f22522a667fe334593c4f93807`
(sha1 matches its name): `fuzz_validate` returned `Forward`, but rmcp's
`ClientJsonRpcMessage` rejected the line. The bisection below was run against rmcp 3.1.4 at
commit 32cb997, using one `serde_json::from_str::<ClientJsonRpcMessage>` call per probe:

| Probe (request `id:0` unless noted) | rmcp |
|---|---|
| original unit | reject |
| original with `"_meta":"x"` removed, or replaced by `"_meta":{}` | accept |
| `params:{"_meta":"x"}` / `1` / `[]`; the same as a notification | reject |
| `params:{"_meta":null}` / `{}` / `{"a":1,"a":2}` | accept |
| `params:{"_meta":{},"_meta":{}}` and `{"_meta":null,"_meta":null}` | reject |
| duplicate non-`_meta` keys in params, an out-of-i64 integer in params | accept |
| `initialize` request with `"_meta":"x"` | reject |
| response or error line with a stray `params:{"_meta":{},"_meta":{}}` | accept |
| `params:{"a":{"_meta":"x"}}` (nested `_meta`) | accept |

**Cause:** on a request or notification, a non-object, non-null `params._meta`, or a duplicated
`_meta` key in `params`.
Duplicate keys elsewhere in the unit and its large numeric literal are not causal.
**Minimized unit:** `{"jsonrpc":"2.0","method":"x","id":0,"params":{"_meta":"x"}}`.

When the validator forwards such a line, rmcp drops it and the client gets no response. Before
`initialize`, the ADR-0025 interception parse also fails on this line, so the line skips
interception and still reaches `validate`. Initialization handling therefore does not mask the
mismatch; it reaches the same forward/drop path.

## Design

All changes live in `crates/rimap-server/src/mcp/wire_validator/envelope.rs`. No ownership
moves.

1. `is_valid_params(v)` accepts an object only when its `_meta` is absent, an object, or `null`.
   It still accepts `null` params.
2. The streaming duplicate-key scan returns two findings instead of one bool: `envelope` (the
   existing top-level/`error` duplicates) and `params_meta` (a repeated `_meta` key directly
   inside top-level `params`). Other repeated `params` keys stay unflagged because rmcp accepts
   them (unit test `duplicate_keys_inside_params_still_forwards`).
3. `envelope` keeps its existing rejection, `invalid_request(Null)`. `params_meta` counts as
   invalid params, so only the request and notification branches are affected (response and
   error lines are accepted per the table). Both new rules reject through the catch-all branch
   with `invalid_request(extract_id(obj))`, which echoes a forwardable id.

`inbound.rs`, the pre-init interception, and the response and error branches are unchanged.

## Failure model

1. **Actors and deployments:** one MCP client on the stdio wire, local operator deployment.
   The client is untrusted for envelope shape.
2. **Invariants and assets:** a `Forward` decision means rmcp accepts the line (the fuzz oracle);
   every rejection is a schema-valid `-32600`; the existing rejection and initialization
   contracts, including ADR-0025 pre-init behavior, stay the same.
3. **Accepted failure classes:**
   - Other rmcp strictness gaps not yet observed. Accepted per ADR-0031; the nightly fuzz oracle
     is the guardrail that surfaces them.
   - Typed-parameter mismatches on known methods (e.g. `tools/call` with `name:5`). These are
     outside this unit: rmcp accepts them as custom requests (probed).
4. **Covered elsewhere:** modern-first-request initialization interception belongs to #837.

### Threat model

- **Boundary:** stdin line → `validate` (existing; not widened). No new boundary.
- **Actor:** the stdio client.
- **Control:** shape validation before forwarding. A failure leaks only the fixed `-32600`
  envelope and the client's own forwardable id.
- **Out of scope:** resource exhaustion. The scan descends exactly one level into `params`,
  and the line was already being parsed in full.

## Success

1. `validate` rejects the original and minimized units, every rejecting row in the table above,
   and each `_meta` shape in those rows sent both as a request and as a notification. Each rejection is `-32600` and echoes the line's
   forwardable id (none for a notification).
2. Every accepting row above, plus all existing validator unit tests, still returns `Forward`.
3. The full wire, after `initialize`, answers the minimized unit with one schema-valid `-32600`
   that echoes `id:0`, then still serves `tools/list`. Before `initialize`, the same line gets
   the same envelope, and a later `initialize` still succeeds.
4. Both units are committed to `crates/rimap-server/fuzz/corpus/validate/`. Replaying them with
   the fuzz target exits 0.

## Validation

- Success 1–2: unit tests in `wire_validator/mod.rs`; red before the change on Forward.
- Success 3: `mcp_wire_negative` tests; red before the change on Hung.
- Success 4: `cargo +nightly fuzz run validate <unit>` (single-input replay).
- Guardrails: `just fmt-check`, `just lint`, `just test`, `just check-fuzz-lock-parity`.
