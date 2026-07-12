# Surface skipped/truncated FETCH items in-band to the MCP agent — design

**Status:** Draft 2026-07-11 · issue [#535](https://github.com/randomparity/rusty-imap-mcp/issues/535)
**ADR:** [ADR-0007](../../ADR/0007-inband-fetch-truncation-signal.md)
**Scope:** Thread the existing per-item "skipped FETCH item" counter out of
`rimap-imap`'s fetch path and expose it as an in-band count on the `search`
tool's response `meta`, so an MCP agent can observe that a result is partial.
Additive; preserves current fetch semantics (skip-with-warning). No fail-closed
behavior change.

## Problem

`ops::fetch::fetch` skips FETCH response items whose UID is **missing or zero**
and returns a shorter `Vec<FetchedMessage>` than requested. PR #534 (closing
#518) made that skip observable to **operators** via a single aggregated
`tracing::warn!(folder, skipped_uids, …)`, but the count is thrown away after
logging: `Connection::fetch` returns only `(Vec<FetchedMessage>, Option<u32>)`,
so the skip is **invisible in-band** to the MCP tool consumer. The agent sees
only a shorter message list, with no marker that items were dropped.

Under the project threat model (the IMAP server is a potential adversary), a
compromised or MITM'd server can therefore make a folder appear to hold fewer
messages than it does — hiding a message from a summary or from a subsequent
select-and-act decision — with the operator log as the only trace.

### Where the gap actually is

`Connection::fetch` has four call sites, but only one is a genuine in-band blind
spot:

1. **`fetch_single_by_uid`** (single UID → `fetch_message`, `list_attachments`,
   `list_labels`, …) already fails **closed**: an empty result maps to
   `RimapError::Authz { code: NotFound }`. A skipped item surfaces as an error.
2. **`export_messages::fetch_sizes`** already reconciles requested-vs-returned:
   it fetches sizes into a UID→size map, then fetches each body **one UID at a
   time** with its own `RFC822.SIZE` preflight, and reports per-UID outcome via
   `succeeded` / `failed` / `complete`. A metadata skip is absorbed there.
3. **`search::fetch_and_format_page`** (both the normal and the `thread_of_uid`
   paths) fetches the whole page in a **single** `FETCH`. `SearchMeta.returned`
   is set to `messages.len()`, which silently reflects any drop. The agent
   **cannot distinguish** "server dropped 2 malformed items from this page" from
   "this page legitimately held 8." **This is the blind spot #535 targets.**
4. **`download_attachment`** fetches a single UID's bodystructure; a skip there
   yields an empty result handled by the existing `if let Ok(...)` guard. Not a
   multi-item blind spot.

## Acceptance criteria (from the issue)

- [ ] A decision recorded (in-band signal vs fail-closed vs keep warn-only) with
      rationale. → **In-band signal.** Recorded in ADR-0007 and below.
- [ ] The skipped/truncated signal reaches the MCP tool result the agent sees;
      tool schemas regenerated and committed; a test asserts the signal is
      present on a truncated response.
- [ ] The `ops/fetch.rs` policy comment and the #518 spec note are updated to
      match the chosen behavior.

## Decision

**Option 1 — in-band count (additive).** Keep skip-with-warning semantics.
Return the existing skip count from the fetch path and surface it as a count on
the `search` tool's `meta`. Rejected alternatives (fail-closed typed error;
keep warn-only) are recorded in ADR-0007.

**Signal shape:** a **count**, not a boolean. The count preserves magnitude,
matches the existing operator-log counter, and — unlike a `bool` — does not
collide with `SearchMeta`'s existing pagination `truncated` field.

## Design

### 1. `rimap-imap`: thread the count out via a struct return

Today:

```rust
pub async fn fetch(...) -> Result<(Vec<FetchedMessage>, Option<u32>), ImapError>
```

The tuple is replaced by a named struct in `rimap_imap::types` (repo convention:
structs/newtypes over positional tuples):

```rust
/// Outcome of a multi-UID `FETCH`. `skipped` counts response items the
/// server returned but that were dropped because their UID was missing or
/// zero — a partial result under the threat model (possible malformed or
/// hostile server). `0` in the normal case.
pub struct FetchOutcome {
    pub messages: Vec<FetchedMessage>,
    pub uid_validity: Option<u32>,
    pub skipped: usize,
}
```

- `ops::fetch::fetch` returns `FetchOutcome`. `skipped` is the **same** value
  that already drives the aggregated `warn!` (today typed `u64`; narrowed to
  `usize`, the natural type for a count of in-memory response items — the count
  is bounded by the requested UID set). The `warn!` is retained: the operator
  signal remains useful and is orthogonal to the in-band signal.
- `Connection::fetch` (in `connection/dispatch.rs`) returns `FetchOutcome`.
- **Four callers updated** to the struct: `fetch_single_by_uid`,
  `search::fetch_and_format_page`, `export_messages::fetch_sizes`,
  `download_attachment`. Callers that ignore `skipped` (single-UID and export,
  per the analysis above) simply read `outcome.messages` / `outcome.uid_validity`
  and do not regress.

### 2. `rimap-server`: expose `SearchMeta.fetch_skipped`

Add an **always-present** field to `SearchMeta`:

```rust
/// Count of messages the server returned in the FETCH response but that were
/// dropped because their UID was missing or zero — a partial result (possible
/// malformed or hostile server; see the account resource's threat notes).
/// `0` in the normal case. When non-zero, `returned` is smaller than the page
/// the server was asked for and the agent should treat the listing as
/// incomplete.
pub fetch_skipped: usize,
```

Always-present (not `Option` / `skip_serializing_if`) so the agent can rely on
the field existing and check `fetch_skipped == 0`, consistent with the existing
always-present count fields (`total_matched`, `returned`). `fetch_and_format_page`
returns the page's `skipped` count alongside the formatted messages; both
`handle` and `handle_thread` thread it into `SearchMeta`.

Then `just regen-tool-schemas` regenerates `search.schema.json`; the diff is
committed. CI hard-gates a non-empty schema diff.

### 3. Docs

- Rewrite the `ops/fetch.rs` policy comment: the drop is now surfaced in-band via
  `FetchOutcome.skipped` → `SearchMeta.fetch_skipped`, so it is no longer
  "intentionally unchanged / invisible to the agent." The operator `warn!`
  remains the operator-facing signal.
- Update the #518 spec (`2026-07-09-issue-518-adversarial-imap-fake-design.md`)
  scenario-3 "Accepted risk" note to record that #535 closed the in-band gap for
  the `search` path.
- ADR-0007 records the in-band-vs-fail-closed decision.

## Testing

The **only** component that can produce a truncated response is the in-process
scriptable adversarial fake (`crates/rimap-imap/tests/support/fake_imap.rs`); a
conformant IMAP server does not emit missing/zero-UID FETCH items. The
server-level wire harness (`e2e_wire*.rs`) runs against **Dovecot**, which is
conformant, and there is **no adversarial-fake seam behind the server binary**.
The test strategy reflects that reality:

1. **`rimap-imap` adversarial (authoritative truncation test).** Extend the
   existing scenario
   (`adversarial_imap.rs::missing_and_zero_uid_fetch_items_are_skipped_with_one_warn`)
   — or add a sibling — to assert the returned `FetchOutcome.skipped` equals the
   empirically observed skip count (2: one missing-UID item, one zero-UID item),
   alongside the existing single-`warn!` assertion. This proves the count threads
   correctly out of `ops::fetch` against a real misbehaving server, over the IMAP
   transport.
2. **`rimap-server` — signal reaches the tool contract.** A test asserting the
   published `search` schema contains `fetch_skipped` (mirrors the existing
   `input_schema_uses_plain_language_not_posture_jargon` schema test), plus a
   semantic test that a non-zero `FetchOutcome.skipped` maps to
   `SearchMeta.fetch_skipped`. Because the search handler operates on a concrete
   `AccountState` with no fake-IMAP seam, the mapping is verified either by
   extracting the `SearchMeta` construction into a small pure helper that takes
   the skip count, or by a serialization assertion on a directly constructed
   `SearchMeta` — whichever keeps the test behavior-focused.

### AC interpretation (flagged)

The AC phrase "an e2e/wire test asserts the signal is present on a truncated
response" is satisfied in **spirit**, not literally at the server-wire layer: the
authoritative truncation assertion lives at the `rimap-imap` layer (the only
place a truncated response exists), and the server layer gets schema + mapping
coverage. Driving the adversarial fake **behind the server binary** to assert
`fetch_skipped` on the JSON-RPC wire would require a new server-level adversarial
harness (bind the scriptable fake to a socket the binary connects to) — a
substantial addition out of scope for this P2. If true server-wire coverage of
the signal is later wanted, it is tracked as a follow-up issue rather than
silently claimed here.

## Out of scope / non-goals

- Fail-closed handling of missing/zero UIDs (ADR-0007 rejected alternative).
- Any change to `fetch_message`, `export_messages`, `download_attachment`, or
  `list_*` behavior — they already fail closed or reconcile per-UID.
- A server-binary adversarial harness (possible follow-up, see above).
- Distinguishing *absent* items (server returned no line for a UID) from
  *skipped* items (server returned a malformed line). Only the latter is
  attacker-controlled malformed input and is what `skipped` counts; absence is
  already reflected by `returned < requested` and is not a protocol violation.

## Guardrails

`just ci` (rustfmt, clippy `--all-features -D warnings`, check-macOS, test
stable, test MSRV 1.88.0, cargo-deny, zizmor) plus the schema-regen diff gate.
Branch: `feat/fetch-surface-truncation-535`, base `main`.
