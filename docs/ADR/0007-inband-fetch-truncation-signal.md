# ADR-0007: In-band partial-result signal for skipped FETCH items

- **Status:** Accepted
- **Date:** 2026-07-11
- **Issue:** [#535](https://github.com/randomparity/rusty-imap-mcp/issues/535) (P2, robustness)
- **Spec:** [docs/superpowers/specs/2026-07-11-issue-535-fetch-inband-truncation-design.md](../superpowers/specs/2026-07-11-issue-535-fetch-inband-truncation-design.md)
- **Follows:** #518 / PR #534 (introduced the skip-with-warning counter)
- **Supersedes:** none

## Context

`ops::fetch::fetch` skips FETCH response items whose UID is missing or zero and
returns fewer `FetchedMessage`s than requested. #518 / PR #534 scoped this to
"skip-with-warning": the loop counts skipped items and emits one aggregated
`tracing::warn!(folder, skipped_uids, …)` for operators, but throws the count
away — `Connection::fetch` returns only `(Vec<FetchedMessage>, Option<u32>)`.

Under the threat model (the IMAP server is a potential adversary), a hostile or
MITM'd server can omit/zero UIDs to make a folder appear to hold fewer messages
than it does. Today that manipulation is visible only in the operator log; the
MCP agent — the party that acts on the result — sees a silently shorter list.

The one genuine in-band blind spot is the multi-UID `search` path
(`fetch_and_format_page`): it fetches a whole page in one `FETCH` and reports
`returned = messages.len()`, so a drop is indistinguishable from a naturally
smaller page. The single-UID path already fails closed (`NotFound`) and
`export_messages` already reconciles requested-vs-returned per UID.

The `search` path can drop a requested UID for **three** reasons — a malformed
(missing/zero) UID item, an **omitted** FETCH line, or a **wrong-UID
substitution** — all of which lower `returned` below the requested page size and
achieve the hiding manipulation. The operator `skipped_uids` counter sees only
the first. The right signal is therefore the **page shortfall**
(`page_requested − returned`), which subsumes all three, not the malformed-only
count.

## Decision

Surface the drop **in-band** as an additive **count** on the `search` tool's
`meta`: an always-present `SearchMeta.fetch_skipped: usize` defined as
`page_requested − returned` (the page shortfall), computed in `rimap-server` at
the reassembly layer where the loss actually occurs. Fetch semantics are
unchanged (skip-with-warning); the operator `warn!` is retained.

This is the agent-native choice: the agent can observe any outcome an operator
can. It is additive (a new meta field), so behavioral risk is lowest and no
conformant-server interaction changes. Because the shortfall is derivable
server-side from locals the handler already holds, **`rimap-imap` is not
touched** — no change to `Connection::fetch` / `ops::fetch`.

## Consequences

- The `search` tool schema gains `fetch_skipped`; `just regen-tool-schemas` must
  regenerate `search.schema.json` and the diff is committed (CI-gated).
- `fetch_skipped == 0` is a trustworthy "page complete" signal: it accounts for
  omitted and substituted UIDs, not just malformed ones. A non-zero value can
  also arise from a benign expunge race between the SEARCH and the FETCH; the
  agent's action ("treat the listing as partial") is the same regardless of cause.
- Agents can branch on `fetch_skipped > 0` to treat a listing as incomplete
  (e.g. re-fetch, warn, or refuse a destructive follow-up). Older agents that
  ignore the field are unaffected (additive).
- The mapping is unit-tested at the `rimap-server` layer via a pure
  `build_search_meta` helper shared by both search paths. A full JSON-RPC-wire
  assertion against the server binary is out of scope (a conformant Dovecot
  fixture cannot produce a short page and there is no adversarial-fake seam behind
  the binary); see the spec's "AC interpretation" note.

## Considered & rejected

- **Fail closed on a UID-FETCH protocol violation.** Return a typed `ImapError`
  when an item omits/zeros its UID (UID is always requested, so it is arguably a
  violation). Strongest guarantee, but changes behavior for any real-world server
  that legitimately emits such items, with a larger blast radius (it can fail a
  whole `search`/`fetch`), and no survey exists proving omitted/zero UIDs never
  occur against conformant servers. The issue itself scopes this as defensible
  *only* given such a survey. Rejected for this change; can be revisited if a
  survey lands.
- **Keep warn-only.** Leave the operator log as the only trace. Rejected: it
  leaves the agent — the acting party — blind to attacker-induced truncation,
  contradicting the agent-native posture. This is the status quo the issue was
  filed to close.
- **Boolean `partial` / `truncated` flag instead of a count.** Simpler, but
  loses magnitude and collides with `SearchMeta`'s existing pagination
  `truncated` field. Rejected in favor of a count.
