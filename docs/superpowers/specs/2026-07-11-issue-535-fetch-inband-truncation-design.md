# Surface skipped/truncated FETCH items in-band to the MCP agent — design

**Status:** Draft 2026-07-11 · issue [#535](https://github.com/randomparity/rusty-imap-mcp/issues/535)
**ADR:** [ADR-0007](../../ADR/0007-inband-fetch-truncation-signal.md)
**Scope:** Expose an in-band count on the `search` tool's response `meta` that
tells an MCP agent how many messages it asked for on this page but did **not**
get back, so the agent can observe that a listing is partial. Additive;
preserves current fetch semantics (skip-with-warning). No fail-closed behavior
change.

## Problem

`ops::fetch::fetch` skips FETCH response items whose UID is **missing or zero**
and returns a shorter `Vec<FetchedMessage>` than requested. PR #534 (closing
#518) made that skip observable to **operators** via a single aggregated
`tracing::warn!(folder, skipped_uids, …)`, but the count never reaches the MCP
tool consumer. Worse, that malformed-UID skip is only **one** of the ways the
`search` path can silently return fewer messages than requested (see below), so
even threading the operator counter out would leave a hole. The agent sees a
shorter list with no marker that items were dropped.

Under the project threat model (the IMAP server is a potential adversary), a
compromised or MITM'd server can therefore make a folder appear to hold fewer
messages than it does — hiding a message from a summary or from a subsequent
select-and-act decision — with the operator log as the only trace.

### Where messages are actually dropped on the search path

The `search` handler (`handle` / `handle_thread`) fetches a page in one
`FETCH`, then reassembles into the requested order:

```rust
// fetch_and_format_page, search.rs:500-506
let mut by_uid: HashMap<Uid, &FetchedMessage> = fetched.iter().map(|m| (m.uid, m)).collect();
page_uids.iter().filter_map(|uid| by_uid.remove(uid)).map(format_search_result).collect()
```

A requested `page_uid` is dropped from the result whenever `by_uid.remove(uid)`
returns `None`. That happens for **three** distinct reasons, only the first of
which the operator `skipped_uids` counter sees:

1. **Malformed item** — the server returned a FETCH line with a missing/zero
   UID. `ops::fetch` skips it (never enters `fetched`), so the `page_uid` it was
   meant to answer gets no entry. *Counted by `skipped_uids`.*
2. **Omitted line** — the server simply returned no FETCH line for a requested
   UID. `by_uid` has no entry; the UID is dropped. *Not counted by anything.*
3. **Wrong-UID substitution** — the server returned a valid item under a UID that
   was not requested. It lands in `by_uid` but is never `remove`d (not in
   `page_uids`), and the requested UID it displaced gets no entry. *Not counted
   by anything.*

All three lower `returned` (= `messages.len()`) below the page size the server
was asked for, and all three achieve the ADR's motivating manipulation. A benign
cause also exists: a message **expunged between the SEARCH and the FETCH** (a
TOCTOU race) drops the same way. The correct in-band signal is therefore the
**page shortfall** — how many requested page UIDs came back with no usable
message — not the malformed-only subset.

### Which call sites are *not* blind spots

`Connection::fetch` has other callers, but they do not have this gap:

- **`fetch_single_by_uid`** (single UID → `fetch_message`, `list_attachments`,
  `list_labels`, …) already fails **closed**: an empty result maps to
  `RimapError::Authz { code: NotFound }`.
- **`export_messages`** already reconciles requested-vs-returned per UID via
  `succeeded` / `failed` / `complete`.
- **`download_attachment`** fetches a single UID; an empty result is handled by
  its existing guard.

So the change is scoped to the `search` tool only.

## Acceptance criteria (from the issue)

- [ ] A decision recorded (in-band signal vs fail-closed vs keep warn-only) with
      rationale. → **In-band signal.** Recorded in ADR-0007 and below.
- [ ] The skipped/truncated signal reaches the MCP tool result the agent sees;
      tool schemas regenerated and committed; a test asserts the signal on a
      short-page result.
- [ ] The `ops/fetch.rs` policy comment and the #518 spec note are updated to
      match the chosen behavior.

## Decision

**Option 1 — in-band count (additive).** Keep skip-with-warning semantics. Add an
always-present count to the `search` tool's `meta` reporting the page shortfall.
Rejected alternatives (fail-closed typed error; keep warn-only; boolean flag) are
recorded in ADR-0007.

**Signal definition:** `fetch_skipped = page_requested − returned`, computed at
the reassembly layer where the loss actually occurs. A **count**, not a boolean:
it preserves magnitude, and — unlike a `bool` — does not collide with
`SearchMeta`'s existing pagination `truncated` field. Defining it as the shortfall
(rather than the malformed-only `skipped_uids`) makes `fetch_skipped == 0` a
trustworthy "this page is complete" signal that also covers omitted lines and
wrong-UID substitution.

**Notably, this requires no change to `rimap-imap`.** The shortfall is derivable
entirely in `rimap-server` from data the handler already holds (`page_uids.len()`
and `messages.len()`), so the `Connection::fetch` / `ops::fetch::fetch` return
type is unchanged and the operator `warn!` stays as-is.

## Design

### 1. `rimap-server`: compute the shortfall and expose `SearchMeta.fetch_skipped`

Add an **always-present** field to `SearchMeta`:

```rust
/// Count of messages requested for this page that the server did not return a
/// usable message for: a missing/zero UID, an omitted FETCH line, a wrong-UID
/// substitution, or a message expunged between the search and the fetch. `0`
/// in the normal case. When non-zero, the page is incomplete — `returned` is
/// smaller than the page the server was asked for — and the agent should treat
/// the listing as partial (possible malformed or hostile server; see the
/// account resource's threat notes).
pub fetch_skipped: usize,
```

Always-present (not `Option` / `skip_serializing_if`), consistent with the
existing always-present count fields (`total_matched`, `returned`), so the agent
can rely on the field existing and check `fetch_skipped == 0`.

Both `handle` and `handle_thread` build `SearchMeta` from the same locals
(`page_uids`, `messages`, `total_matched`, `truncated`, `next_offset`,
`uid_validity`). Extract that construction into one **pure helper** so both paths
share it and it is directly unit-testable:

```rust
fn build_search_meta(
    folder: String,
    total_matched: usize,
    page_requested: usize,     // page_uids.len()
    returned: usize,           // messages.len()
    truncated: bool,
    next_offset: Option<u64>,
    uid_validity: Option<u32>,
) -> SearchMeta
```

`fetch_skipped = page_requested.saturating_sub(returned)` (saturating is
defensive; `returned` can never exceed `page_requested` because the reassembly
`filter_map` only ever removes from `page_uids`). `handle` and `handle_thread`
pass `page_uids.len()` and `messages.len()`.

Then `just regen-tool-schemas` regenerates `search.schema.json`; the diff is
committed. CI hard-gates a non-empty schema diff.

### 2. Docs

- Rewrite the `ops/fetch.rs` policy comment: the malformed-UID skip is now
  observable to the agent as part of the `search` tool's `fetch_skipped` page
  shortfall (which also covers omitted/substituted UIDs), so it is no longer
  "invisible to the agent." The operator `warn!` remains the operator-facing
  signal and is unchanged.
- Update the #518 spec (`2026-07-09-issue-518-adversarial-imap-fake-design.md`)
  scenario-3 "Accepted risk" note to record that #535 closed the in-band gap for
  the `search` path (via the page-shortfall count, superseding the malformed-only
  framing).
- ADR-0007 records the in-band-vs-fail-closed decision and the shortfall-vs-
  malformed-only signal choice.

## Testing

The shortfall is now pure `rimap-server` arithmetic over the handler's own
locals, which makes the headline behavior directly unit-testable without a live
or fake IMAP server:

1. **`build_search_meta` behavior (authoritative mapping test).** Drive the pure
   helper with `page_requested > returned` (e.g. requested 5, returned 3) and
   assert `fetch_skipped == 2` and `returned == 3`; drive it with
   `page_requested == returned` and assert `fetch_skipped == 0`. Because both
   `handle` and `handle_thread` construct `SearchMeta` **only** through this
   helper, a regression that fails to propagate the shortfall fails this test.
   This is a real behavioral assertion, not a serde tautology — no hand-built
   `SearchMeta`.
2. **Signal reaches the tool contract.** A schema test asserting the published
   `search` schema contains `fetch_skipped` (mirrors the existing
   `input_schema_uses_plain_language_not_posture_jargon` test), so the field is
   guaranteed present in the agent-visible contract.
3. **`rimap-imap` malformed-skip path (unchanged).** The existing adversarial
   test (`adversarial_imap.rs::missing_and_zero_uid_fetch_items_are_skipped_with_one_warn`)
   continues to assert that a malformed FETCH item is dropped and the aggregated
   `warn!` fires. `ops::fetch` is unchanged, so this test needs no edit; it is
   listed here to confirm the malformed → dropped-from-`fetched` link the
   shortfall relies on remains covered.

### AC interpretation (flagged)

The AC phrase "an e2e/wire test asserts the signal is present on a truncated
response" is met at the behavior level (test 1 drives the exact mapping that
populates the field) plus the contract level (test 2), but **not** as a full
JSON-RPC-wire assertion against the server binary. A conformant Dovecot fixture
cannot produce a short page, and there is no adversarial-fake seam behind the
server binary. Introducing one (bind the scriptable fake to a socket the binary
connects to, script it to omit a FETCH line, assert `fetch_skipped > 0` on the
wire) would be a substantial new harness — out of scope for this P2. Unlike the
prior draft, the feature's core logic is no longer "verified only in spirit": the
mapping is exercised by a non-tautological unit test. If true server-wire coverage
is later wanted, it is tracked as a follow-up issue rather than silently claimed
here.

## Out of scope / non-goals

- Fail-closed handling of missing/zero UIDs (ADR-0007 rejected alternative).
- Any change to `rimap-imap` (`Connection::fetch` / `ops::fetch`), or to
  `fetch_message`, `export_messages`, `download_attachment`, or `list_*` — they
  already fail closed or reconcile per-UID, and the shortfall is computed server-
  side.
- A server-binary adversarial harness for a full-wire `fetch_skipped` assertion
  (possible follow-up, see above).
- Attributing the shortfall to a specific cause (malformed vs omitted vs
  substituted vs expunge race). The agent's actionable decision is "is this page
  complete?"; a single count answers it. Splitting causes is speculative (YAGNI).

## Guardrails

`just ci` (rustfmt, clippy `--all-features -D warnings`, check-macOS, test
stable, test MSRV 1.88.0, cargo-deny, zizmor) plus the schema-regen diff gate.
Branch: `feat/fetch-surface-truncation-535`, base `main`.
