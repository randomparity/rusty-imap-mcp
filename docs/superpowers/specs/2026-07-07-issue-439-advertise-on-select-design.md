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

**The deltas are identical to #401 except when a selected account advertises
an empty tool set** (reachable via a `[security.tools]` override that denies
every tool). In that class the helper over-reports: `None → Some(x)` with `x`
empty is really infra → infra (no change), and `Some(p) → Some(n)` where both
advertise nothing is infra → infra (no change), yet the helper returns `true`
in both and fires a `notifications/tools/list_changed`. Under #401 those
transitions always added/removed other accounts' tools, so they were genuine
changes. The consequence under Option A is a single spurious, best-effort
notification prompting one redundant re-fetch — harmless in every case in this
class, and not worth complicating the gate to suppress. All empty-advertised
spurious notifications are the same harmless class; the test plan pins one
representative (`None → Some(empty)`) unit case rather than leaving the claim
unqualified, and intentionally does not enumerate the rest.

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
- A client that already knows a namespace can still dispatch
  `<account>.<tool>` without selecting — decision 2 preserves this.
- Single-account deployments: zero behavior change (advertised set, byte
  count, and pagination all identical to today).

### Client compatibility — this is a real, intended trade-off

Option A deliberately replaces #401's *always-visible* multi-account catalog
with a select-then-see handshake. That is a behavior change for clients, and
this section states the contract rather than assuming a cooperative client.

**Assumed client contract (multi-account only):** to discover and call an
account's tools, a client must either (a) act on the `instructions` text —
which directs it to `use_account` — or (b) call `use_account` on its own, and
then re-fetch `tools/list` (proactively after the call, or on receipt of the
`notifications/tools/list_changed` it triggers).

**What a non-conforming multi-account client sees:**

- A client that never calls `use_account` sees only `use_account` +
  `list_accounts`. It can *still dispatch* any `<account>.<tool>` it knows by
  name (decision 2), and it can enumerate each account's available tool
  **names** — without touching the process-wide active slot — via the
  `rimap://accounts/<name>` MCP resource (`available_tools`,
  `server.rs`). That resource is the schema-free discovery fallback; it does
  not expose full `inputSchema`, so a client that needs a tool's input schema
  must select the account. This is the accepted floor: naive non-agent clients
  that ignore both `instructions` and the accounts resource are out of scope —
  the server is an agent-facing MCP server whose highest-authority text tells
  the agent to select an account.
- A client that ignores `notifications/tools/list_changed` still sees the
  selected account's tools if it re-fetches `tools/list` after `use_account`
  returns; the notification is an optimization, not the only path.

**Concurrent clients sharing one process — a genuine regression, scoped:**
`active` is a single process-wide slot (#401's known consequence:
`AccountRegistry` holds one `ArcSwapOption<AccountId>`; `use_account` flips it
for every session sharing the process). Under #401 every session always saw
every account's full tool definitions, so two clients could observe two
different accounts' `inputSchema` simultaneously. Under Option A the advertised
set is at most infra + the single active account, so two concurrent clients
**cannot** simultaneously observe two different accounts' tool schemas via
`tools/list`: client B selecting `personal` yanks `work.*` out of client A's
advertised set. Worse, the `list_changed` notification reaches **only the
calling session** — `context.peer.notify_tool_list_changed()` targets client B,
the caller (`server.rs`), with no cross-session broadcast — so client A gets
*no* signal and sees its advertised catalog change silently on its next
`tools/list`. This *is* made worse by Option A for the shared-process
multi-client case. It is scoped out on two grounds:
the deployed shape is single-client stdio (see
`2026-05-02-multi-client-stdio-design.md`), and per-account tool-*name*
discovery remains available to every session, slot-independent, via
`rimap://accounts/<name>`. Callers needing full schemas for multiple accounts
concurrently in one process are not a supported configuration.

## Implementation surface

- `crates/rimap-server/src/mcp/server.rs`
  - `build_tool_catalog`: add the `accounts.len() > 1 && active.is_none()`
    gate. Extract a free `build_tool_catalog_for(accounts, active)` seam so
    the catalog is unit-testable socket-free via `make_test_account_state`.
  - `SERVER_INSTRUCTIONS_MULTI_ACCOUNT`: rewrite "`use_account` narrows" →
    "server advertises `use_account`/`list_accounts` initially; `use_account`
    reveals the chosen account's tools." The rewrite **must preserve** two
    guarantees the rest of this spec depends on: (1) "every account stays
    callable by `<account>.<tool>` regardless of the active selection" — the
    namespace-dispatch fallback the Client-compatibility section relies on for
    clients that never select; and (2) the single-account "auto-selects"
    wording. It must keep containing the literal `use_account` and `auto-selects`
    and must **not** introduce the phrase `"With more than one account
    configured"` (see the in-file constant tests below).
  - `active_selection_changes_advertisement`: update doc comment only.
- `crates/rimap-server/tests/server_capabilities.rs`: update the exact-text
  fixture for the rewritten instructions.
- `crates/rimap-server/src/mcp/server.rs` in-file constant tests to reconcile
  with the rewritten text (they pin the guarantees above):
  `instructions_constants_tests::server_instructions_constants_exist_and_differ`
  (multi text must contain `use_account`; single must not) and
  `multi_account_text_acknowledges_single_account_auto_resolve` (multi text
  must contain `auto-selects`, must not contain `"With more than one account
  configured"`).
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

- `selecting_empty_tool_account_still_reports_change`: 2 accounts where the
  selected one advertises an empty tool set (`[security.tools]` denies all),
  `active=None → Some(x)`; assert `active_selection_changes_advertisement`
  returns `true` (documents the harmless spurious-`list_changed` edge from the
  "list_changed change detection" section rather than leaving it unpinned).

The 2-entry assertion in `multi_account_no_active_advertises_infra_only` is
the structural proxy for the byte win (payload = infra defs only); byte-count
assertions are intentionally avoided as brittle.

Instructions text: existing `server_capabilities.rs` fixture assertion,
updated to the rewritten constant, keeps the constant honest.

Conformance + multi-account e2e (hard requirement, no waiver): add a
wire-driven multi-account test — a new `e2e_wire_*` binary or an extension of
`e2e_wire_tool_advertisement.rs` — that boots a **two-account** config against
the shared Dovecot fixture (both accounts may target the same Dovecot user, as
the existing per-posture advertisement test already targets one user across
four servers) and asserts the reveal-on-select handshake on the wire:

1. Initial `tools/list` (walking cursor pagination) advertises exactly the
   infra tools — no `<account>.<tool>` entries.
2. After a `use_account` call succeeds, a re-fetched `tools/list` advertises
   the selected account's namespaced tools and none of the other account's.

This exercises the two-request client cycle the unit seam cannot observe. The
`list_changed` emission itself is already wire-asserted for the
selection-changes case by the existing suites; this test does not duplicate
that. Container-gated with the same silent-skip / `RIMAP_REQUIRE_DOCKER=1`
convention as the sibling `e2e_wire_*` suites.

### Payload measurement — where "recorded" lives

The before/after payload numbers (~616 KB → ~2 KB for 3 full-posture accounts)
are recorded in this spec's Context section and restated in the PR
description; they are **illustrative, not asserted** (byte counts vary with
account count/posture/tool set). The regression guard for the win is the
`multi_account_no_active_advertises_infra_only` 2-entry structural assertion,
which fails loudly if any future change re-adds account tools to the initial
multi-account catalog. No byte-count test is added.

## Rollback

Single, self-contained diff. Revert restores #401's advertise-all default;
no persisted state, schema, or migration is involved.
