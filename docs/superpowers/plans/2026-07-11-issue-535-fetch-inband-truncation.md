# In-band FETCH truncation signal (#535) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expose an always-present `fetch_skipped` count on the `search` tool's
response `meta` reporting how many UIDs the server listed for a page but did not
return a usable message for, so an MCP agent can observe a partial listing.

**Architecture:** Compute the page shortfall (`page_uids.len() − messages.len()`)
entirely in `rimap-server`'s `search` handler, via a pure `build_search_meta`
helper shared by both search paths. No change to `rimap-imap`. Regenerate the
`search` tool schema. Update the `ops/fetch.rs` policy comment and the #518 spec
note to reflect that the drop is now surfaced in-band.

**Tech Stack:** Rust (edition 2024, MSRV 1.88.0), `serde` + `schemars` for the
tool contract, `just` task runner, `cargo nextest`.

**Spec:** `docs/superpowers/specs/2026-07-11-issue-535-fetch-inband-truncation-design.md`
**ADR:** `docs/ADR/0007-inband-fetch-truncation-signal.md`

## Global Constraints

- **Branch:** `feat/fetch-surface-truncation-535`, base `main`. Never commit on `main`.
- **Zero warnings.** `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` must be clean.
- **No `unwrap()` / `expect()` / `panic!` in non-test code.** Tests may `#[expect(clippy::unwrap_used, reason = "...")]` the `mod tests`.
- **No `#[allow(...)]`** — use `#[expect(...)]` with a `reason`.
- **100-char line length**; absolute imports only; Google-style docstrings on public APIs (`rimap-server` has `#![deny(missing_docs)]`).
- **Newtypes/structs over primitives; enums over bool flags** (already satisfied — `fetch_skipped` is a documented count, not a bool).
- **Guardrail suite:** `just ci` = `fmt-check lint test test-msrv deny check-no-openssl mcp-conformance-node check-tools-doc check-metadata test-publish-script test-installer` (justfile:363). Adding a `SearchMeta` field drifts **two** generated artifacts, both gated by `just ci`: the schema fixture (via the host lib test `every_tool_output_schema_matches_fixture` in `just test`) and `docs/tools.md` (via `check-tools-doc`). So the field and the regenerated artifacts MUST land in one commit (Task 1), or `just ci` reddens. **Only** zizmor and `check (macOS)` are GitHub-only (not in `just ci`); they run post-push. Run `just test-fast` in the inner loop; `just ci` before pushing.
- **prek** runs on every commit; editing a `.rs` file triggers a full clippy recompile in the hook — allow a long commit timeout, and stage explicit paths only (never `git add -A`).

---

### Task 1: Add `fetch_skipped` to `SearchMeta`, regenerate the tool contract, in one green commit

Add the always-present count field, a pure `build_search_meta` helper that
computes it from the `page_uids`/`messages` slices, route both search paths
through the helper, **and** regenerate the two generated artifacts that derive
from `SearchMeta` — all in a single commit. This must be one commit because a
host-runnable lib test (`crates/rimap-server/src/mcp/tool_catalog.rs:765`
`every_tool_output_schema_matches_fixture`, "covers all 24 without docker")
asserts each tool's runtime schema equals its committed fixture: the moment the
field is added, that test (and `docs/tools.md` via `check-tools-doc`) goes red
until the fixture and doc are regenerated. Splitting the field and the regen into
two commits ships a transiently-red tree and breaks the green-commit / `git
bisect` contract.

**Files:**
- Modify: `crates/rimap-server/src/tools/retrieval/search.rs`
  - `SearchMeta` struct (currently lines 238–258): add `fetch_skipped` field.
  - `handle` (SearchMeta literal at ~303–312) and `handle_thread` (~363–372):
    replace the literal with a `build_search_meta(...)` call.
  - Add the free function `build_search_meta` near the handlers.
  - `mod tests` (~888+): add helper + schema-presence tests; update the three
    existing `SearchMeta { … }` literals (search_meta_serializes_uid_validity
    ~1422, search_meta_omits_next_offset_when_absent ~1436,
    search_meta_serializes_next_offset_when_present ~1453) to include
    `fetch_skipped: 0`.
- Modify (generated): `crates/rimap-server/tests/fixtures/rimap-tool-schemas/search.schema.json`
- Modify (generated): `docs/tools.md` (search `meta` table — a `fetch_skipped` row)
- Test: same file's `mod tests`, plus the existing fixture-parity lib test.

**Interfaces:**
- Produces:
  - `SearchMeta` gains `pub fetch_skipped: usize` (always serialized; no `skip_serializing_if`).
  - `fn build_search_meta(folder: String, total_matched: usize, page_uids: &[Uid], messages: &[SearchResultEntry], truncated: bool, next_offset: Option<u64>, uid_validity: Option<u32>) -> SearchMeta` — pure; `returned = messages.len()`, `fetch_skipped = page_uids.len().saturating_sub(returned)`. **Precondition:** `page_uids` must be duplicate-free (guaranteed today by the `HashSet`-sourced `sorted_uids` in `ops/search.rs`).
  - `search.schema.json` `meta` object with a `fetch_skipped` integer property in `properties` and `required`; `docs/tools.md` search-meta table with a `fetch_skipped` row.
- Consumes: existing local types `SearchMeta`, `SearchResultEntry`, and `rimap_imap::types::Uid` (already imported at the top of the file).

- [ ] **Step 1: Write the failing tests**

Add to `mod tests` in `crates/rimap-server/src/tools/retrieval/search.rs`. A
local `entry(uid)` builder keeps the test focused on the count. Reuse the
existing `uids(range)` helper (already defined in the test module, ~line 1464).

```rust
fn entry(uid: u32) -> SearchResultEntry {
    SearchResultEntry {
        uid,
        size: None,
        flags: None,
        subject: None,
        date: None,
        from: Vec::new(),
        to: Vec::new(),
        cc: Vec::new(),
        message_id: None,
        body_preview: None,
        body_preview_truncated: None,
    }
}

#[test]
fn build_search_meta_counts_page_shortfall() {
    let page = uids(1..=5); // server listed 5 UIDs for this page
    let messages: Vec<SearchResultEntry> = (1..=3).map(entry).collect(); // 3 came back
    let meta = build_search_meta("INBOX".to_string(), 42, &page, &messages, false, None, None);
    assert_eq!(meta.returned, 3);
    assert_eq!(meta.fetch_skipped, 2);
}

#[test]
fn build_search_meta_zero_when_page_complete() {
    let page = uids(1..=3);
    let messages: Vec<SearchResultEntry> = (1..=3).map(entry).collect();
    let meta = build_search_meta("INBOX".to_string(), 3, &page, &messages, false, None, None);
    assert_eq!(meta.returned, 3);
    assert_eq!(meta.fetch_skipped, 0);
}

#[test]
fn search_meta_serializes_fetch_skipped_always() {
    let page = uids(1..=4);
    let messages: Vec<SearchResultEntry> = (1..=4).map(entry).collect();
    let meta = build_search_meta("INBOX".to_string(), 4, &page, &messages, false, None, None);
    let v = serde_json::to_value(meta).unwrap();
    assert_eq!(v["fetch_skipped"], serde_json::json!(0));
}

#[test]
fn search_meta_schema_exposes_fetch_skipped() {
    // Guards the agent-visible contract against a future removal of the field
    // (mirrors input_schema_uses_plain_language_not_posture_jargon).
    let schema = serde_json::to_string(&schemars::schema_for!(SearchMeta))
        .expect("SearchMeta schema serializes");
    assert!(
        schema.contains("fetch_skipped"),
        "search meta schema must expose fetch_skipped so the agent sees partial pages",
    );
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p rimap-server --lib tools::retrieval::search::tests 2>&1 | tail -20`
Expected: FAIL to compile — `build_search_meta` not found and `SearchMeta` has no field `fetch_skipped`.

- [ ] **Step 3: Add the field to `SearchMeta`**

Insert into the `SearchMeta` struct (after `uid_validity`):

```rust
    /// Count of UIDs the server listed for this page (in its SEARCH answer)
    /// but did not return a usable message for in the FETCH answer: a
    /// missing/zero UID, an omitted FETCH line, a wrong-UID substitution, or a
    /// message expunged between the search and the fetch. `0` in the normal
    /// case. When non-zero, the page is incomplete (`returned` is smaller than
    /// the page the server was asked for). This is a SEARCH↔FETCH consistency
    /// check and a benign search-then-expunge-race signal — it does NOT detect
    /// a server that omits a UID from its SEARCH answer in the first place.
    /// Detection-only: recovery is a full re-search from offset 0, since
    /// `next_offset` steps over the dropped UIDs.
    pub fetch_skipped: usize,
```

- [ ] **Step 4: Add the `build_search_meta` helper**

Place directly above `fn fetch_and_format_page` (or adjacent to the handlers):

```rust
/// Build a `SearchMeta`, computing the page shortfall from the request/response
/// slices so the two load-bearing counts cannot be transposed at a call site.
///
/// `returned` is `messages.len()`; `fetch_skipped` is
/// `page_uids.len() - returned` — the number of UIDs the server listed for this
/// page but did not return a usable message for.
///
/// # Preconditions
/// `page_uids` must be duplicate-free (guaranteed today: SEARCH and thread UIDs
/// are sourced from a deduped `HashSet` via `ops::search::sorted_uids`). A
/// duplicate would inflate `fetch_skipped` against a consistent server.
fn build_search_meta(
    folder: String,
    total_matched: usize,
    page_uids: &[Uid],
    messages: &[SearchResultEntry],
    truncated: bool,
    next_offset: Option<u64>,
    uid_validity: Option<u32>,
) -> SearchMeta {
    let returned = messages.len();
    SearchMeta {
        folder,
        total_matched,
        returned,
        truncated,
        next_offset,
        uid_validity,
        fetch_skipped: page_uids.len().saturating_sub(returned),
    }
}
```

- [ ] **Step 5: Route `handle` through the helper**

Replace the `SearchMeta { … }` literal in `handle` (~303–312). Before:

```rust
    Ok(ToolResponse::meta_only(SearchMeta {
        folder: input.folder,
        total_matched,
        returned: messages.len(),
        truncated,
        next_offset,
        uid_validity,
    })
    .with_untrusted(SearchUntrusted { messages })
    .with_warnings(preview_warnings))
```

After (borrow the slices before `messages` is moved into `SearchUntrusted`):

```rust
    let meta = build_search_meta(
        input.folder,
        total_matched,
        &page_uids,
        &messages,
        truncated,
        next_offset,
        uid_validity,
    );
    Ok(ToolResponse::meta_only(meta)
        .with_untrusted(SearchUntrusted { messages })
        .with_warnings(preview_warnings))
```

- [ ] **Step 6: Route `handle_thread` through the helper**

Apply the identical replacement to the `SearchMeta { … }` literal in
`handle_thread` (~363–372); it has the same locals (`input.folder`,
`total_matched`, `page_uids`, `messages`, `truncated`, `next_offset`,
`uid_validity`).

- [ ] **Step 7: Update the three existing `SearchMeta` literal tests**

In each of `search_meta_serializes_uid_validity`,
`search_meta_omits_next_offset_when_absent`, and
`search_meta_serializes_next_offset_when_present`, add `fetch_skipped: 0,` to the
`SearchMeta { … }` literal so it compiles.

- [ ] **Step 8: Regenerate BOTH generated artifacts**

`SearchMeta` feeds the schema fixture and `docs/tools.md`. Regenerate both so the
tree is green:

Run: `just regen-tool-schemas && just gen-tools-doc`
Then confirm only the expected files changed and inspect the diffs:

Run: `git status --short crates/rimap-server/tests/fixtures/rimap-tool-schemas/ docs/tools.md && git diff crates/rimap-server/tests/fixtures/rimap-tool-schemas/search.schema.json docs/tools.md | head -60`
Expected:
- only `search.schema.json` is modified under `rimap-tool-schemas/`; its diff adds
  a `fetch_skipped` integer property (`"type": "integer", "format": "uint",
  "minimum": 0`) to the `meta` object's `properties` and to its `required` array.
- `docs/tools.md` gains one `fetch_skipped` row in the `search` tool's `meta`
  table (near the existing `returned` / `total_matched` rows, ~line 89).

If any OTHER schema file or any unrelated part of `docs/tools.md` changed, stop —
an unintended struct change slipped in.

- [ ] **Step 9: Run the FULL lib suite + the tool-doc gate to verify green**

Run the whole `rimap-server` lib suite — not just the search tests — because the
fixture-parity test `mcp::tool_catalog::tests::every_tool_output_schema_matches_fixture`
lives outside the search module and must now match the regenerated fixture:

Run: `cargo test -p rimap-server --lib 2>&1 | tail -15 && just check-tools-doc`
Expected: PASS (new `build_search_meta_*` / `search_meta_serializes_fetch_skipped_always`
/ `search_meta_schema_exposes_fetch_skipped` green; the three edited literal tests
green; `every_tool_output_schema_matches_fixture` green against the regenerated
fixture); `check-tools-doc` clean.

- [ ] **Step 10: Lint and format**

Run: `just fmt && cargo clippy -p rimap-server --all-targets --all-features --locked -- -D warnings 2>&1 | tail -15`
Expected: no warnings.

- [ ] **Step 11: Commit (single green commit — code + regenerated artifacts together)**

```bash
git add crates/rimap-server/src/tools/retrieval/search.rs \
        crates/rimap-server/tests/fixtures/rimap-tool-schemas/search.schema.json \
        docs/tools.md
git commit -m "feat(535): add SearchMeta.fetch_skipped page-shortfall count"
```

---

### Task 2: Update the `ops/fetch.rs` policy comment and the #518 spec note

Bring the two documented "accepted risk / invisible to the agent" notes in line
with the new behavior. No code logic changes.

**Files:**
- Modify: `crates/rimap-imap/src/ops/fetch.rs` (policy comment, ~lines 155–167).
- Modify: `docs/superpowers/specs/2026-07-09-issue-518-adversarial-imap-fake-design.md` (Accepted-risk paragraph, ~lines 249–258).

**Interfaces:** none (documentation only).

- [ ] **Step 1: Rewrite the `ops/fetch.rs` policy comment**

Replace the trailing "Consequence: … accepted, documented risk; surfacing the
drop in-band … is a possible follow-up" sentence (fetch.rs ~lines 164–167) so it
reads:

```rust
    // The aggregated `warn!` below is the operator-facing signal. The per-item
    // skip is now ALSO observable to the agent: the `search` tool reports a page
    // shortfall (`SearchMeta.fetch_skipped = requested - returned`) that counts a
    // skipped item along with any omitted/substituted UID (issue #535). The
    // single-UID fetch path already fails closed (`NotFound`); `export_messages`
    // reconciles per UID. So a hostile server that omits/zeroes UIDs is no longer
    // invisible in-band on the search path.
```

Keep the rest of the comment (the fail-open-vs-fail-closed contrast with
`require_uidvalidity`) intact.

- [ ] **Step 2: Update the #518 spec Accepted-risk note**

In `2026-07-09-issue-518-adversarial-imap-fake-design.md`, append to the
"Accepted risk" paragraph (after "visible only in the operator log."):

```markdown
(Update: issue #535 closed the in-band gap for the `search` path — the tool's
`meta.fetch_skipped` now reports the page shortfall, a SEARCH↔FETCH consistency
signal; see `docs/ADR/0007-inband-fetch-truncation-signal.md`. SEARCH-level
omission remains undetected residual risk.)
```

Leave the rest of the #518 spec unchanged (it documents the #518 behavior as
shipped).

- [ ] **Step 3: Lint the touched Rust file**

Run: `cargo clippy -p rimap-imap --all-targets --all-features --locked -- -D warnings 2>&1 | tail -10`
Expected: no warnings (comment-only change).

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-imap/src/ops/fetch.rs \
        docs/superpowers/specs/2026-07-09-issue-518-adversarial-imap-fake-design.md
git commit -m "docs(535): update fetch skip policy note + #518 accepted-risk"
```

---

### Task 3: Full guardrail suite + generated-artifact drift guard

- [ ] **Step 1: Confirm no uncommitted generated-artifact drift**

Fixture parity IS enforced locally (the `every_tool_output_schema_matches_fixture`
lib test, run by `just test`/`just ci`) and `docs/tools.md` by `check-tools-doc`
— both are in `just ci`. This step catches the narrower case of a regenerated but
**uncommitted** artifact (the lib test compares the runtime schema to the on-disk
fixture, so an uncommitted regen still passes the test while the tree is dirty):

Run: `git diff --exit-code crates/rimap-server/tests/fixtures/rimap-tool-schemas/ docs/tools.md`
Expected: exit 0, no output (both regenerated and committed in Task 1). A non-empty
diff means a regen was not committed — re-run Task 1 Steps 8–11 before continuing.
(Note: zizmor and `check (macOS)` run only in GitHub CI after push.)

- [ ] **Step 2: Run the full local-CI equivalent**

Run: `just ci 2>&1 | tail -30`
Expected: all recipes pass — `fmt-check`, `lint` (clippy `-D warnings`), `test`,
`test-msrv`, `deny`, `check-no-openssl`, `mcp-conformance-node`,
`check-tools-doc`, `check-metadata`, `test-publish-script`, `test-installer`.
(zizmor, `check (macOS)`, and `tool-schema-drift` run only in GitHub CI after
push — see Global Constraints.)

- [ ] **Step 3: If any check fails, fix and re-run**

Address the specific failure; do not proceed with a red guardrail. Re-run the
relevant scoped check, then `just ci` again.

---

## Self-Review

**Spec coverage:**
- AC "decision recorded with rationale" → ADR-0007 + spec (already committed).
- AC "signal reaches the tool result; schemas regenerated and committed; a test
  asserts the signal" → Task 1 (field + helper + behavioral tests + schema-presence
  test + schema/doc regen, all in one green commit).
- AC "ops/fetch.rs policy comment and #518 spec note updated" → Task 2.
- Spec test 1 (build_search_meta behavior) → Task 1 Step 1.
- Spec test 2 (schema exposes field) → Task 1 Step 1 (`search_meta_schema_exposes_fetch_skipped`).
- Spec test 3 (rimap-imap malformed-skip warn unchanged) → no edit needed;
  verified green by Task 3 `just ci` (the adversarial test still runs).

**Type consistency:** `build_search_meta` signature is identical in the
Interfaces block, Task 1 Step 4, and both call sites (Steps 5–6). `fetch_skipped:
usize` matches struct, helper, tests, and the regenerated schema
(`integer`/`uint`).

**No placeholders:** every code step shows the exact code; every run step shows
the command and expected result.
