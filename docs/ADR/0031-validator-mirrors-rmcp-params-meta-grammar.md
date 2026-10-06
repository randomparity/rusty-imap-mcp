# ADR-0031: The validator mirrors rmcp's `params._meta` grammar explicitly

## Status

Accepted

## Context

The envelope validator (`wire_validator::envelope::validate`) promises that every line it
forwards deserializes as rmcp's `ClientJsonRpcMessage`; the `validate` fuzz target asserts that
promise against rmcp itself. Issue #867's nightly unit broke it. rmcp 3.1.4 routes request and
notification `params` through a `_meta`-aware wrapper, so it rejects `params._meta` that is not
an object or `null`, and rejects `params` carrying `_meta` twice. The validator checked neither,
forwarded the line, and rmcp dropped it, so the client got no response.

## Decision

The validator grows two explicit rules, scoped to request and notification `params`:

- `params._meta`, when present, must be an object or `null`;
- `params` must not contain the key `_meta` more than once.

A line breaking either rule gets the existing `-32600 Invalid Request` rejection, with the id
echoed like every other invalid-params rejection. The duplicate-key scan reports a `params._meta`
duplicate separately from envelope-level duplicates, because rmcp accepts that duplicate on a
response line. No other key inside `params` is newly checked.

## Consequences

Clients that send a malformed `_meta` now get an error envelope instead of no response. The fuzz
target's Forward oracle stays an independent differential check, so the next rmcp strictness gap
still shows up as a fuzz crash rather than going unnoticed. Each such gap still needs its own
rule.

## Considered & rejected

- **rmcp-acceptance backstop: after a Forward decision, require
  `serde_json::from_str::<ClientJsonRpcMessage>` to succeed.** judgment: it closes the whole class
  in one place, but the fuzz target's Forward oracle runs that same call, so the oracle becomes a
  check of itself and stops finding validator/rmcp disagreements. The operator chose targeted
  rules on 2026-10-06.
- **Backstop plus explicit rules.** judgment: the oracle becomes a self-check in the same way,
  and a rule plus a backstop are two code paths for one decision.
- **Do nothing (treat it as rmcp's bug).** verified: `ClientJsonRpcMessage` rejects
  `{"jsonrpc":"2.0","method":"x","id":0,"params":{"_meta":"x"}}` with "data did not match any
  variant of untagged enum JsonRpcMessage" (rmcp 3.1.4, commit 32cb997). The validator exists so
  that such lines get an envelope instead of a silent drop.
