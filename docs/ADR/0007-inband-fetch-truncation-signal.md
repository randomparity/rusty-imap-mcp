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

## Decision

Surface the skip **in-band** as an additive **count**. Thread the existing skip
counter out of the fetch path via a named `FetchOutcome { messages, uid_validity,
skipped }` struct, and expose it as an always-present `SearchMeta.fetch_skipped:
usize` on the `search` tool response. Fetch semantics are unchanged
(skip-with-warning); the operator `warn!` is retained.

This is the agent-native choice: the agent can observe any outcome an operator
can. It is additive (a new meta field), so behavioral risk is lowest and no
conformant-server interaction changes.

## Consequences

- The IMAP crate's `Connection::fetch` / `ops::fetch::fetch` return type changes
  from a tuple to `FetchOutcome` — a cross-crate contract change touching four
  call sites (all internal to this workspace).
- The `search` tool schema gains `fetch_skipped`; `just regen-tool-schemas` must
  regenerate `search.schema.json` and the diff is committed (CI-gated).
- Agents can branch on `fetch_skipped > 0` to treat a listing as incomplete
  (e.g. re-fetch, warn, or refuse a destructive follow-up). Older agents that
  ignore the field are unaffected (additive).
- The truncation signal is authoritatively tested at the `rimap-imap` layer
  (the adversarial fake), not on the server wire, because a conformant Dovecot
  fixture cannot emit malformed UIDs and there is no adversarial-fake seam behind
  the server binary. See the spec's "AC interpretation" note.

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
