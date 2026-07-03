# Honest multi-account selection semantics: namespaced dispatch, `use_account` as advertise-scope (#401)

## Context

The server's `instructions` text (`SERVER_INSTRUCTIONS_MULTI_ACCOUNT`,
`crates/rimap-server/src/mcp/server.rs`) promises two account-selection
mechanisms that the dispatcher rejects in every real multi-account
deployment:

1. *"call `use_account` first"* then invoke a bare account-scoped tool.
2. *"pass `account: <name>` per call."*

Both are dead. In any non-legacy deployment (anything other than exactly
one account named `default`), `validate_bare_tool_namespace`
(`crates/rimap-server/src/mcp/tool_name.rs`) rejects every bare simple
tool name with `INVALID_PARAMS` before any argument is read (#73). The
only invocation that works is the advertised `<account>.<tool>` form.

Consequently:

- The session default set by `use_account` (`AccountRegistry::active`)
  is only consulted by `AccountRegistry::resolve(None)`
  (`crates/rimap-server/src/boot/registry.rs`). Account-scoped dispatch
  always passes an explicit namespaced account, so `resolve` never sees
  `None` for those tools. The session-default resolution branch is dead.
- The `args["account"]` resolution branch in `call_tool` is only reached
  for a bare name with no namespace — which multi-account mode rejects,
  and which single-account mode makes redundant (one account). No tool's
  `inputSchema` declares an `account` property either (F7). Dead.
- `use_account` emits `notifications/tools/list_changed`, but `list_tools`
  advertised the union across all accounts regardless of the session
  default, so a re-fetch returned an identical list. The notification was
  untruthful.

`instructions` is the highest-authority text an agent receives; an agent
that follows it fails its first multi-account tool call. Verified on
`main` @ `9fd8dc24`.

## Goal

Make the advertised contract honest and remove every dead resolution
path, satisfying issue #401's acceptance criteria:

- Every invocation pattern in the `SERVER_INSTRUCTIONS_*` constants is
  exercised by a conformance test and succeeds.
- No dead resolution paths: `args["account"]` and the session default
  are each either reachable or removed.
- `notifications/tools/list_changed` fires only when the `tools/list`
  response actually changes.
- `docs/multi-account.md` matches the final contract.

## Decision

Implement issue option **(a)** — "make namespaced-only the honest
contract" — in its **repurpose** variant (the issue's own suggested
repurpose of `use_account`):

1. **Namespaced-only dispatch.** Account-scoped tools are invoked as
   `<account>.<tool>`, exactly as advertised in `tools/list`. Bare simple
   names stay rejected in non-legacy mode (unchanged; #73). Legacy
   single-`default` deployments keep bare names (unchanged).

2. **`use_account` becomes an advertise-scope selector.** Its sole effect
   is to narrow the `tools/list` advertisement to the active account's
   namespaced tools (infrastructure tools are always advertised). It does
   **not** gate dispatch: every account's tools remain callable by their
   `<account>.<tool>` name regardless of which account is active. This is
   the issue's suggested repurpose ("advisory default that changes which
   account's tools are advertised"). Because the advertised list now
   genuinely changes, the `list_changed` notification becomes truthful.

3. **`list_accounts`** is unchanged: always bare, always lists every
   configured account, unaffected by the active selection. It is the
   discovery path for account names needed to build `<account>.<tool>`.

4. **Delete the dead `args["account"]` branch** in `call_tool`. No schema
   declares the field; the mechanism never worked.

5. **Delete the dead session-default branch** in
   `AccountRegistry::resolve`. `active` is now read by `list_tools`
   (advertise scope), so the state stays reachable while the dead
   resolution branch is gone. `resolve` keeps: explicit name → auto-select
   when exactly one account → `NoAccount`.

6. **Emit `list_changed` only when the advertised set changes.** After a
   successful `use_account`, compare the advertised account set before and
   after: `None → Some(x)` changes the set only when more than one account
   is configured; `Some(prev) → Some(new)` changes it only when
   `prev != new`. Suppress the no-op re-selection.

### `use_account` retained, not removed

Issue option (a) lists two fates for `use_account`: remove it, or
repurpose it. Repurpose is chosen because:

- It is honest and in scope. Retaining `use_account` as an advertise-scope
  selector keeps the tool's catalog entry, schema, redaction schema, and
  annotations untouched, and confines the change to the account-resolution
  and advertisement paths (`server.rs`, `registry.rs`, `accounts.rs`) plus
  docs and tests.
- Removal would delete the `ToolName::UseAccount` variant, rippling across
  `rimap-core` (exhaustive matches, parsing, annotations), `rimap-audit`
  (redaction schema, record scope), the CLI schema dumps, and the Node
  conformance fixtures — a large cross-crate change disproportionate to a
  gating, minimal issue, and one that collides with sibling work on the
  same error/dispatch surface.
- The repurpose is the mechanism the issue notes "helps" the multi-account
  `tools/list` payload sub-issue (#411). This issue establishes the
  gating semantic (active selection narrows advertisement); #411 remains
  free to reduce the default (pre-`use_account`) payload further.

### Rejected alternatives

- **Option (b)** — honor the documented paths by dropping bare-name
  rejection. Explicitly off the table without maintainer sign-off; it
  reverses the #73 namespace contract.
- **Remove `use_account` entirely.** Coherent and eliminates the
  process-wide `active` slot, but a large cross-crate deletion beyond this
  issue's minimal, gating scope (see above).
- **Keep `args["account"]` reachable.** Would require a schema-declared
  `account` property on every tool and a resolution precedence versus the
  namespace — reintroducing the ambiguity #73 removed.

## Known limitation (unchanged by this issue)

`AccountRegistry::active` is a single process-wide slot, so `use_account`
affects advertisement for every client session sharing the process. This
predates #401 and is not introduced here. A per-session active selection
is left to a future issue; the common single-client stdio deployment is
unaffected.

## Test plan

- Unit (`registry.rs`): `resolve` no longer consults `active`; explicit
  name and single-account auto-select still resolve; `resolve(None)` with
  0 or ≥2 accounts returns `NoAccount`.
- Unit (`server.rs` / `tool_name.rs`): namespaced call resolves; bare
  simple call rejected in multi mode; `list_tools` advertises the union
  when no account is active and narrows to the active account after
  `use_account`; `list_changed` change-detection helper returns the
  precise verdict for the None→Some / Some→Some / single-account cases.
- Instruction fixtures: the rewritten `SERVER_INSTRUCTIONS_MULTI_ACCOUNT`
  matches its golden fixture and states the namespaced contract, and does
  not promise a bare `use_account`-then-tool flow or a per-call `account`
  argument.
- Docs: `docs/multi-account.md` describes namespaced dispatch,
  `use_account` as advertise-scope, and drops the per-call `account`
  parameter and the old resolution order.
