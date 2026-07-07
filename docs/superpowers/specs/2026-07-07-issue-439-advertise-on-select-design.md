# Advertise-on-select for multi-account `tools/list` (#439)

## Context

In a genuine multi-account deployment (more than one configured account),
the server currently advertises **every** account's posture-filtered tools
on the initial `tools/list`, before any `use_account` selection. This is the
"advertise-all-initially, `use_account` narrows" contract established by #401
(`SERVER_INSTRUCTIONS_MULTI_ACCOUNT`, `crates/rimap-server/src/mcp/server.rs`)
and documented in `docs/multi-account.md`.

Measurement (current `main`, after #401 + #405): a 3-account, full-posture
INITIAL `tools/list` — before any `use_account` — is **59 entries,
~616 KB compact / ~862 KB pretty**. This resident tool-definition payload is
what the epic-#400 "F10" work targets. #401's `use_account` narrowing only
helps *after* selection; the pre-selection default still advertises every
account's tools, so the initial bloat is fully present on connect.

#411 shipped cursor pagination (`list_tools`, `TOOLS_PER_PAGE = 25`) as the
conservative bound on any single `tools/list` response. #411's acceptance
criteria explicitly anticipated a follow-up that reduces the *total*
pre-selection payload and noted it would require a spec note because it
reverses a documented #401 behavior. #401's own spec anticipated this:
"#411 remains free to reduce the default (pre-`use_account`) payload further"
(`docs/superpowers/specs/2026-07-02-issue-401-account-semantics-design.md`).

This spec is that follow-up, and this document **is** the spec note the #411
acceptance criteria called for.

## Goal

Satisfy issue #439's acceptance criteria:

- Decision recorded (this spec note) on reversing #401's
  advertise-all-initially default.
- Multi-account + no active account advertises infrastructure tools only
  (`use_account`, `list_accounts`); per-account tools are revealed after
  `use_account` selects one; `notifications/tools/list_changed` fires on the
  selection that changes the advertised set.
- The advertised set never contains a tool that is not dispatchable.
- `SERVER_INSTRUCTIONS_MULTI_ACCOUNT` rewritten to describe reveal-on-select.
- Before/after payload recorded; single-account deployments unchanged;
  conformance + multi-account e2e green.

## Decision

Implement issue option **A (advertise-on-select)**. Two maintainer decisions
frame it (recorded 2026-07-07):

1. **Reverse #401's default.** In a multi-account deployment with no active
   account, advertise infra tools only; `use_account` *reveals* a chosen
   account's tools rather than *narrowing* from an all-accounts baseline.

2. **Advertising-only, not dispatch-gating.** Keep #401's dispatch
   architecture untouched: every `<account>.<tool>` stays callable by its
   namespace regardless of the active selection. Option A changes only what
   `list_tools` *advertises*, never what `call_tool` accepts. The acceptance
   criterion "advertised set matches the dispatchable set" is honored in its
   safe direction — the server never advertises a tool it would reject — not
   by newly rejecting namespaced calls that #401 accepts. Gating dispatch was
   considered and rejected (see below).

### The gate

`build_tool_catalog` gains one predicate. Let `accounts` be the configured
set and `active` the session-active account name (`None` if unset):

- **`accounts.len() > 1 && active.is_none()`** → advertise infra tools only.
- Otherwise → current behavior (infra tools + the active account's tools if
  `active` is `Some`, else the sole account's tools).

Single-account deployments — whether the legacy `default`-named account or a
single non-`default` account — are unaffected: with exactly one account,
`AccountRegistry::resolve(None)` auto-selects it, so its tools stay actionable
without `use_account`, and advertising them initially remains correct.

### `list_changed` change detection is unchanged

`active_selection_changes_advertisement(prior, now, account_count)` already
returns the correct answer under Option A, because the set-membership deltas
are identical to #401's:

| transition       | #401 meaning                     | Option A meaning                | changes? |
|------------------|----------------------------------|---------------------------------|----------|
| `None → None`    | all → all                        | infra → infra                   | no       |
| `None → Some(x)` | all → only x (count>1)           | infra → infra+x (count>1)       | `count > 1` |
| `Some(x) → None` | only x → all (count>1)           | infra+x → infra (count>1)       | `count > 1` |
| `Some(p)→Some(n)`| only p → only n                  | infra+p → infra+n               | `p != n` |

The helper's logic and its unit tests stay green. Only its doc comment
changes (from "`None` means advertise every account" to Option A semantics).

## Considered & rejected

- **Do nothing / keep #401 default, rely on #411 pagination.** Pagination
  bounds a *single response* but not the *total* pre-selection payload: a
  client that walks `next_cursor` still fetches all ~616 KB. Rejected because
  it leaves the F10 win on the table; #439 exists specifically to capture it.

- **Gate dispatch to the active account** (reject `<account>.<tool>` for a
  non-active account until `use_account` selects it, making advertised ==
  dispatchable in the strict sense). Rejected: it re-couples what #401
  deliberately decoupled, is a larger and riskier behavior change, and breaks
  agents that dispatch by namespace without a `use_account` round-trip — a
  supported #401 flow. Maintainer decision 2 chose advertising-only.

- **Suppress per-account advertisement for a single non-`default` account
  too** (advertise infra-only until `use_account` even with one account).
  Rejected: with one account `resolve(None)` auto-selects it, so its tools are
  immediately dispatchable; hiding them would make the advertised set *less*
  than the dispatchable set and force a pointless `use_account` round-trip.
  "Single-account unchanged" is an explicit acceptance criterion.

## Consequences

- A multi-account client sees only `use_account` + `list_accounts` on connect
  (initial payload ~2 KB vs ~616 KB for 3 full-posture accounts). It calls
  `use_account`, receives `notifications/tools/list_changed`, re-fetches
  `tools/list`, and sees the selected account's namespaced tools.
- The server-process-wide `active` slot (#401's known consequence) is
  inherited unchanged: `use_account` affects advertisement for every client
  session sharing the process. Not made worse by Option A.
- A client that already knows a namespace can still dispatch
  `<account>.<tool>` without selecting — decision 2 preserves this.
- Single-account deployments: zero behavior change (advertised set, byte
  count, and pagination all identical to today).

## Implementation surface

- `crates/rimap-server/src/mcp/server.rs`
  - `build_tool_catalog`: add the `accounts.len() > 1 && active.is_none()`
    gate. Extract a free `build_tool_catalog_for(accounts, active)` seam so
    the catalog is unit-testable socket-free via `make_test_account_state`.
  - `SERVER_INSTRUCTIONS_MULTI_ACCOUNT`: rewrite "`use_account` narrows" →
    "server advertises `use_account`/`list_accounts` initially; `use_account`
    reveals the chosen account's tools."
  - `active_selection_changes_advertisement`: update doc comment only.
- `crates/rimap-server/tests/server_capabilities.rs`: update the exact-text
  fixture for the rewritten instructions.
- `docs/multi-account.md`: update the "Account selection" / "`use_account`"
  section to describe reveal-on-select.

## Test plan

Unit (socket-free, `make_test_account_state`, via `build_tool_catalog_for`):

- `multi_account_no_active_advertises_infra_only`: 2 accounts, `active=None`
  → catalog tool names == `{use_account, list_accounts}` exactly.
- `multi_account_active_reveals_only_that_account`: accounts `work`+`personal`,
  `active=Some("work")` → infra + `work.*` tools, no `personal.*`.
- `single_non_default_account_advertises_its_tools_with_no_active`: one
  account `solo`, `active=None` → infra + `solo.*` (unchanged).
- `legacy_single_default_advertises_bare_tools`: one `default` account,
  `active=None` → infra + bare tools (unchanged).

The 2-entry assertion in `multi_account_no_active_advertises_infra_only` is
the structural proxy for the byte win (payload = infra defs only); byte-count
assertions are intentionally avoided as brittle.

Instructions text: existing `server_capabilities.rs` fixture assertion,
updated to the rewritten constant, keeps the constant honest.

Conformance + multi-account e2e: the existing wire suites must stay green; add
a wire assertion (or extend `e2e_wire_tool_advertisement.rs`) that a
multi-account boot advertises infra-only before `use_account` and the selected
account's tools after, if the harness supports two accounts against the shared
Dovecot fixture without disproportionate cost; otherwise cover reveal-on-select
at the unit seam and keep the existing e2e green.

## Rollback

Single, self-contained diff. Revert restores #401's advertise-all default;
no persisted state, schema, or migration is involved.
