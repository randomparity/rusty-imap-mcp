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

This is the specific gap #518 / PR #534 deferred: the malformed-UID skip is a
server whose FETCH answer is **inconsistent with its own SEARCH answer** (it
listed a UID, then corrupted or dropped it in the FETCH response), and today the
agent cannot see that inconsistency.

**What this signal does and does not defend against.** `fetch_skipped` detects a
SEARCH↔FETCH inconsistency (plus the benign expunge race below). It does **not**
detect a server that lies at the SEARCH layer: a hostile server hiding a message
simply omits its UID from the `UID SEARCH` response, so the UID never enters the
page and `fetch_skipped` stays `0`. Detecting SEARCH-level omission would require
an independent count to cross-check against (e.g. `STATUS MESSAGES`) and is out of
scope. So `fetch_skipped == 0` means "the server returned a usable message for
every UID it listed for this page," **not** "the folder was not truncated." This
signal's value is catching inconsistent/buggy servers and the benign
search-then-expunge race — a robustness and honesty improvement, not an
anti-adversarial completeness guarantee. SEARCH-level omission is recorded as
residual risk below.

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
(rather than the malformed-only `skipped_uids`) makes `fetch_skipped == 0` mean
"the server returned a usable message for every UID it listed for this page,"
covering malformed items, omitted lines, and wrong-UID substitution in one number.
As noted in the Problem section, this is a SEARCH↔FETCH consistency check, not a
defense against SEARCH-level omission.

**Notably, this requires no change to `rimap-imap`.** The shortfall is derivable
entirely in `rimap-server` from data the handler already holds (`page_uids.len()`
and `messages.len()`), so the `Connection::fetch` / `ops::fetch::fetch` return
type is unchanged and the operator `warn!` stays as-is.

## Design

### 1. `rimap-server`: compute the shortfall and expose `SearchMeta.fetch_skipped`

Add an **always-present** field to `SearchMeta`:

```rust
/// Count of UIDs the server listed for this page (in its SEARCH answer) but
/// did not return a usable message for in the FETCH answer: a missing/zero
/// UID, an omitted FETCH line, a wrong-UID substitution, or a message expunged
/// between the search and the fetch. `0` in the normal case. When non-zero, the
/// page is incomplete — `returned` is smaller than the page the server was
/// asked for. This flags a server whose FETCH answer is inconsistent with its
/// own SEARCH answer (or a benign search-then-expunge race); it does NOT detect
/// a server that omits a message from the SEARCH answer in the first place.
pub fetch_skipped: usize,
```

Always-present (not `Option` / `skip_serializing_if`), consistent with the
existing always-present count fields (`total_matched`, `returned`), so the agent
can rely on the field existing and check `fetch_skipped == 0`.

Both `handle` and `handle_thread` build `SearchMeta` from the same locals
(`page_uids`, `messages`, `total_matched`, `truncated`, `next_offset`,
`uid_validity`). Extract that construction into one **pure helper** so both paths
share it and it is directly unit-testable. The helper takes the `page_uids` and
`messages` **slices** — not two adjacent `usize` counts — so the load-bearing
`page_requested`/`returned` values cannot be transposed at a call site or with
`total_matched`; passing the wrong local fails to typecheck:

```rust
fn build_search_meta(
    folder: String,
    total_matched: usize,
    page_uids: &[Uid],
    messages: &[SearchResultEntry],
    truncated: bool,
    next_offset: Option<u64>,
    uid_validity: Option<u32>,
) -> SearchMeta
```

Inside: `returned = messages.len()`,
`fetch_skipped = page_uids.len().saturating_sub(returned)` (saturating is
defensive; `returned` can never exceed `page_uids.len()` because the reassembly
`filter_map` only ever removes from `page_uids`). `handle` and `handle_thread`
call it with `&page_uids` and `&messages` (borrowing before `messages` is moved
into `SearchUntrusted`).

**Precondition — `page_uids` must be duplicate-free.** The invariant
"`fetch_skipped == 0` ⟺ the server answered every listed UID" holds only if no
UID appears twice in `page_uids`: a duplicate would be answered once by a correct
server, and the reassembly `HashMap::remove` returns the entry on the first
occurrence and `None` on the second, inflating `fetch_skipped` against a
consistent server. This holds today because both UID sources route through a
deduped `HashSet` (`ops/search.rs` `sorted_uids`; the thread path guards its one
extra push) and `paginate_uids` only slices. The precondition is stated on the
helper so a future UID-sourcing change that drops dedup does not silently turn
`fetch_skipped` into a false-positive generator.

### Detection-only; recovery is a full re-search

`fetch_skipped` is a **detection** signal, not a repair mechanism. The response
carries a count, not the identities of the dropped UIDs (a deliberate non-goal —
see below), and `next_offset` advances by the requested page size, not by
`returned` (`paginate_uids` consumes `offset + page.len()`). A UID dropped on page
N is therefore stepped over by page N+1 and is **not** reachable by continuing
forward pagination. The only recovery is re-running the search from `offset 0`
(and hoping the server is consistent on the retry). The field lets an agent
*notice* a partial page and decide to warn, refuse a destructive follow-up, or
re-search — it does not let it issue a targeted re-fetch of the missing UIDs.

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
   helper with a `page_uids` slice longer than the `messages` slice (e.g. 5 UIDs,
   3 messages) and assert `fetch_skipped == 2` and `returned == 3`; drive it with
   equal lengths and assert `fetch_skipped == 0`. Both cases use distinct UIDs
   (the helper's duplicate-free precondition). Because both `handle` and
   `handle_thread` construct `SearchMeta` **only** through this helper, and the
   helper computes the shortfall from the same slices the call sites pass, a
   regression in the arithmetic fails this test. This is a real behavioral
   assertion over the real slice types, not a serde tautology and not a
   transposable-`usize` shim.
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

**What is and isn't covered.** Tests 1–2 pin the arithmetic and the contract. The
remaining wiring — that `handle`/`handle_thread` pass the *correct* slices — is
type-guarded (slices, not transposable counts) and exercised on the happy path by
the existing `search` e2e against Dovecot, where a conformant server returns a
message for every requested UID and `fetch_skipped` must therefore serialize as
`0`. The one residual not directly asserted is a call site passing a wrong but
same-typed slice; the slice-typed signature makes that a low-risk error, and the
spec does not claim more coverage than this.

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

## Residual risk

- **SEARCH-level omission is undetected.** A hostile server that omits a UID from
  its `UID SEARCH` answer hides that message with `fetch_skipped == 0`; this
  signal only cross-checks the FETCH answer against the SEARCH answer. Detecting
  SEARCH-level omission needs an independent count (`STATUS MESSAGES`, a prior
  known count, etc.) to compare against and is out of scope. Agents must not read
  `fetch_skipped == 0` as "the folder was not truncated."

## Out of scope / non-goals

- Cross-checking the SEARCH answer against an independent message count (see
  residual risk).
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
- Exposing the identities of the dropped UIDs (to enable a targeted re-fetch).
  The signal is detection-only; recovery is a full re-search (see "Detection-only"
  above). Surfacing the dropped set is a larger contract and possible follow-up,
  not part of this change.

## Guardrails

`just ci` (rustfmt, clippy `--all-features -D warnings`, check-macOS, test
stable, test MSRV 1.88.0, cargo-deny, zizmor) plus the schema-regen diff gate.
Branch: `feat/fetch-surface-truncation-535`, base `main`.
