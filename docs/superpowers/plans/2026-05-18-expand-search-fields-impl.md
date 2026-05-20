# Expand searchable email fields — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add 12 new structured SEARCH fields (`cc`, `bcc`, `body`, `text`, `headers`, `larger`, `smaller`, `sent_since`, `sent_before`, `answered`, `flagged`, `draft`) plus `cc` on the search result envelope, with content-oracle inputs gated to `SearchAdvanced` and empty-string filters rejected at the MCP boundary.

**Architecture:** Two-layer extension. `rimap-imap` gains a public `HeaderSearch` value type plus extra `StructuredQuery` fields; its `structured_to_key` emits the new IMAP keys with a `validate_header_name` helper for RFC 5322 field-name syntax. `rimap-server` extends `SearchInput`/`SearchResultEntry`, threads inputs through `build_query` with empty-string rejection, populates `cc` on output from the already-fetched envelope, and extends the `refine_tool_name` predicate so `body`/`text`/non-empty `headers`/`bcc` promote `Search` → `SearchAdvanced` (denied under Readonly/DraftSafe by the existing posture matrix).

**Tech Stack:** Rust 2021 (workspace), `time` crate for dates, `schemars` for JSON Schema derivation, `serde` for wire serialization, `cargo test` for unit/integration tests, `cargo clippy --all-targets --all-features -- -D warnings` for lint, Dovecot Docker container fixture for e2e.

**Spec:** `docs/superpowers/specs/2026-05-18-expand-search-fields-design.md` (commit `32facf9`).

**Branch:** `feat/expand-search-fields` (already checked out; original spec commit `2ffa9a0` and revision `32facf9` already on it).

---

## File Structure

**Modified:**
- `crates/rimap-imap/src/types.rs` — extend `StructuredQuery`; add `HeaderSearch` public struct.
- `crates/rimap-imap/src/ops/search.rs` — extend `structured_to_key`; add `validate_header_name`; add unit tests.
- `crates/rimap-server/src/mcp/tool_name.rs` — extend `refine_tool_name` predicate; add unit tests.
- `crates/rimap-server/src/tools/retrieval/search.rs` — extend `SearchInput` (add `HeaderInput` schemars-aware sibling type), extend `SearchResultEntry` with `cc`, thread inputs through `build_query` with empty-string rejection, populate `cc` in `format_search_result`; add unit tests.
- `crates/rimap-server/tests/e2e_wire.rs` — add one positive case (`cc` filter against Dovecot) and one negative case (`body` under `readonly` posture returns `PostureDenied`).
- `crates/rimap-server/tests/fixtures/rimap-tool-schemas/search.schema.json` — regenerated via `scripts/regen-tool-schemas.sh` after `SearchInput`/`SearchResultEntry` changes land.

**No new files.**

---

## Pre-flight checks

- [ ] **Step P1: Confirm branch and clean working tree**

```bash
cd /Users/dave/src/rusty-imap-mcp
git status
git rev-parse --abbrev-ref HEAD
```

Expected: clean working tree on `feat/expand-search-fields`. If a different branch or dirty tree, stop and ask.

- [ ] **Step P2: Confirm baseline tests pass**

```bash
cargo test -p rimap-imap --lib structured_to_key
cargo test -p rimap-server --lib refine_tool_name
```

Expected: all pass (the pre-existing tests at `crates/rimap-imap/src/ops/search.rs:114-201` and `crates/rimap-server/src/mcp/tool_name.rs:175-302`).

If any baseline test fails, STOP — investigate before adding scope.

---

## Task 1: Add `HeaderSearch` and extend `StructuredQuery` (rimap-imap types)

**Files:**
- Modify: `crates/rimap-imap/src/types.rs:302-319`

This task only changes data shape — no behavior. Tests come with Task 2.

- [ ] **Step 1.1: Add the `HeaderSearch` struct**

Insert immediately before the `StructuredQuery` definition (currently at `crates/rimap-imap/src/types.rs:302`). The doc comment mirrors the existing tone in the file.

```rust
/// A single `HEADER name value` SEARCH clause built into a
/// [`StructuredQuery`]. The `name` must satisfy RFC 5322 field-name
/// syntax (printable ASCII, no `:`); the `value` is quoted on emission
/// and CR/LF/NUL bytes are rejected. Both are enforced when the
/// query is compiled to an IMAP search key — see
/// `crates/rimap-imap/src/ops/search.rs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderSearch {
    /// RFC 5322 field name (e.g. `"List-Id"`, `"X-Spam-Score"`).
    pub name: String,
    /// Substring to match within the header value.
    pub value: String,
}
```

- [ ] **Step 1.2: Extend `StructuredQuery`**

Replace the existing `StructuredQuery` struct definition (at `crates/rimap-imap/src/types.rs:302-319`) with the extended version below. Keep the existing fields in their original order; append the new fields after `has_attachment`.

```rust
/// Structured SEARCH builder. Empty builder = `ALL`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StructuredQuery {
    /// Match `FROM` substring.
    pub from: Option<String>,
    /// Match `TO` substring.
    pub to: Option<String>,
    /// Match `SUBJECT` substring.
    pub subject: Option<String>,
    /// `SINCE` (inclusive lower bound by INTERNALDATE).
    pub since: Option<::time::Date>,
    /// `BEFORE` (exclusive upper bound by INTERNALDATE).
    pub before: Option<::time::Date>,
    /// Restrict to messages with `\Seen`.
    pub seen: Option<bool>,
    /// Restrict to messages with attachments (`HAS_ATTACHMENT` heuristic;
    /// emitted as `BODY "Content-Disposition: attachment"`).
    pub has_attachment: bool,
    /// Match `CC` header substring.
    pub cc: Option<String>,
    /// Match `BCC` header substring. (Content-oracle — gated to
    /// `SearchAdvanced` at the MCP dispatch seam.)
    pub bcc: Option<String>,
    /// Match `BODY` substring (body parts only). Content-oracle.
    pub body: Option<String>,
    /// Match `TEXT` substring (headers OR body). Content-oracle.
    pub text: Option<String>,
    /// One or more `HEADER name value` clauses. Content-oracle when
    /// non-empty.
    pub headers: Option<Vec<HeaderSearch>>,
    /// `LARGER N` (messages strictly greater than N octets).
    pub larger: Option<u64>,
    /// `SMALLER N` (messages strictly less than N octets).
    pub smaller: Option<u64>,
    /// `SENTSINCE` (inclusive lower bound by `Date:` header, not
    /// INTERNALDATE — distinct from [`Self::since`]).
    pub sent_since: Option<::time::Date>,
    /// `SENTBEFORE` (exclusive upper bound by `Date:` header).
    pub sent_before: Option<::time::Date>,
    /// Restrict to messages with `\Answered`.
    pub answered: Option<bool>,
    /// Restrict to messages with `\Flagged`.
    pub flagged: Option<bool>,
    /// Restrict to messages with `\Draft`.
    pub draft: Option<bool>,
}
```

- [ ] **Step 1.3: Confirm the crate still compiles**

```bash
cargo check -p rimap-imap --all-targets
```

Expected: compiles clean. `StructuredQuery::default()` will still work because all new fields are `Option` / `bool` defaults.

- [ ] **Step 1.4: Run the existing search tests to confirm zero regression**

```bash
cargo test -p rimap-imap --lib search
```

Expected: all pre-existing tests pass.

- [ ] **Step 1.5: Commit**

```bash
git add crates/rimap-imap/src/types.rs
git commit -m "$(cat <<'EOF'
feat(rimap-imap): add HeaderSearch + StructuredQuery search fields

Extend StructuredQuery with cc, bcc, body, text, headers (Vec<HeaderSearch>),
larger, smaller, sent_since, sent_before, answered, flagged, draft.
Add public HeaderSearch { name, value } struct for HEADER clauses.

No behavior change — emitter extensions and validation in the next commit.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Emit the new IMAP keys + `validate_header_name` (rimap-imap ops)

**Files:**
- Modify: `crates/rimap-imap/src/ops/search.rs`

- [ ] **Step 2.1: Write the failing tests for new keys**

Append the following test functions inside the existing `#[cfg(test)] mod tests` block at `crates/rimap-imap/src/ops/search.rs:107-202`, immediately before the closing `}` of the module.

```rust
    #[test]
    fn structured_to_key_emits_cc_and_bcc() {
        let q = StructuredQuery {
            cc: Some("alice@example.com".to_string()),
            bcc: Some("bob@example.com".to_string()),
            ..StructuredQuery::default()
        };
        let key = structured_to_key(&q).unwrap();
        assert!(key.contains(r#"CC "alice@example.com""#), "got {key}");
        assert!(key.contains(r#"BCC "bob@example.com""#), "got {key}");
    }

    #[test]
    fn structured_to_key_emits_body_and_text() {
        let q = StructuredQuery {
            body: Some("hello".to_string()),
            text: Some("world".to_string()),
            ..StructuredQuery::default()
        };
        let key = structured_to_key(&q).unwrap();
        assert!(key.contains(r#"BODY "hello""#), "got {key}");
        assert!(key.contains(r#"TEXT "world""#), "got {key}");
    }

    #[test]
    fn structured_to_key_emits_single_header() {
        use crate::types::HeaderSearch;
        let q = StructuredQuery {
            headers: Some(vec![HeaderSearch {
                name: "List-Id".to_string(),
                value: "rust-users".to_string(),
            }]),
            ..StructuredQuery::default()
        };
        assert_eq!(
            structured_to_key(&q).unwrap(),
            r#"HEADER List-Id "rust-users""#,
        );
    }

    #[test]
    fn structured_to_key_emits_multiple_headers_in_input_order() {
        use crate::types::HeaderSearch;
        let q = StructuredQuery {
            headers: Some(vec![
                HeaderSearch {
                    name: "List-Id".to_string(),
                    value: "rust-users".to_string(),
                },
                HeaderSearch {
                    name: "X-Mailer".to_string(),
                    value: "thunderbird".to_string(),
                },
            ]),
            ..StructuredQuery::default()
        };
        assert_eq!(
            structured_to_key(&q).unwrap(),
            r#"HEADER List-Id "rust-users" HEADER X-Mailer "thunderbird""#,
        );
    }

    #[test]
    fn structured_to_key_treats_empty_headers_vec_as_no_clause() {
        let q = StructuredQuery {
            headers: Some(Vec::new()),
            ..StructuredQuery::default()
        };
        // Empty headers carries no filter intent — emitter must not
        // produce any HEADER clause. With no other criteria the query
        // collapses to ALL.
        assert_eq!(structured_to_key(&q).unwrap(), "ALL");
    }

    #[test]
    fn structured_to_key_emits_larger_and_smaller_numeric() {
        let q = StructuredQuery {
            larger: Some(1024),
            smaller: Some(1_048_576),
            ..StructuredQuery::default()
        };
        let key = structured_to_key(&q).unwrap();
        assert!(key.contains("LARGER 1024"), "got {key}");
        assert!(key.contains("SMALLER 1048576"), "got {key}");
    }

    #[test]
    fn structured_to_key_emits_sent_since_and_sent_before() {
        let q = StructuredQuery {
            sent_since: Some(
                ::time::Date::from_calendar_date(2026, ::time::Month::January, 1).unwrap(),
            ),
            sent_before: Some(
                ::time::Date::from_calendar_date(2026, ::time::Month::February, 1).unwrap(),
            ),
            ..StructuredQuery::default()
        };
        let key = structured_to_key(&q).unwrap();
        assert!(key.contains("SENTSINCE 01-Jan-2026"), "got {key}");
        assert!(key.contains("SENTBEFORE 01-Feb-2026"), "got {key}");
    }

    #[test]
    fn structured_to_key_emits_answered_flagged_draft_per_option() {
        let q = StructuredQuery {
            answered: Some(true),
            flagged: Some(false),
            draft: Some(true),
            ..StructuredQuery::default()
        };
        let key = structured_to_key(&q).unwrap();
        assert!(key.contains("ANSWERED"), "got {key}");
        assert!(key.contains("UNFLAGGED"), "got {key}");
        assert!(key.contains("DRAFT"), "got {key}");

        let q = StructuredQuery {
            answered: Some(false),
            flagged: Some(true),
            draft: Some(false),
            ..StructuredQuery::default()
        };
        let key = structured_to_key(&q).unwrap();
        assert!(key.contains("UNANSWERED"), "got {key}");
        assert!(key.contains("FLAGGED"), "got {key}");
        assert!(key.contains("UNDRAFT"), "got {key}");
    }

    #[test]
    fn structured_to_key_combines_old_and_new_fields_in_emit_order() {
        use crate::types::HeaderSearch;
        let q = StructuredQuery {
            from: Some("alice@example.com".to_string()),
            cc: Some("team@example.com".to_string()),
            body: Some("ship it".to_string()),
            headers: Some(vec![HeaderSearch {
                name: "List-Id".to_string(),
                value: "rust".to_string(),
            }]),
            larger: Some(2048),
            sent_since: Some(
                ::time::Date::from_calendar_date(2026, ::time::Month::March, 15).unwrap(),
            ),
            answered: Some(true),
            ..StructuredQuery::default()
        };
        assert_eq!(
            structured_to_key(&q).unwrap(),
            r#"FROM "alice@example.com" CC "team@example.com" BODY "ship it" HEADER List-Id "rust" LARGER 2048 SENTSINCE 15-Mar-2026 ANSWERED"#,
        );
    }

    #[test]
    fn validate_header_name_accepts_canonical_names() {
        validate_header_name("Message-ID").unwrap();
        validate_header_name("X-Foo").unwrap();
        validate_header_name("List-Id").unwrap();
        validate_header_name("Content-Type").unwrap();
    }

    #[test]
    #[expect(clippy::panic, reason = "test failure path")]
    fn validate_header_name_rejects_empty() {
        let Err(ImapError::InvalidInput { field, reason }) = validate_header_name("") else {
            panic!("expected InvalidInput error");
        };
        assert_eq!(field, "header name");
        assert!(reason.contains("empty"), "reason was: {reason}");
    }

    #[test]
    fn validate_header_name_rejects_colon() {
        assert!(validate_header_name("X-Foo:").is_err());
    }

    #[test]
    fn validate_header_name_rejects_space() {
        assert!(validate_header_name("X Foo").is_err());
    }

    #[test]
    fn validate_header_name_rejects_crlf() {
        assert!(validate_header_name("X-Foo\r\nBCC").is_err());
        assert!(validate_header_name("X\rFoo").is_err());
        assert!(validate_header_name("X\nFoo").is_err());
    }

    #[test]
    fn validate_header_name_rejects_nul() {
        assert!(validate_header_name("X-Foo\0").is_err());
    }

    #[test]
    fn validate_header_name_rejects_high_bit_byte() {
        assert!(validate_header_name("X-Föo").is_err());
    }
```

The test for `validate_header_name` references a function that does not exist yet — that is the failing-test driver for Steps 2.2 and 2.3.

- [ ] **Step 2.2: Run the tests and confirm they fail**

```bash
cargo test -p rimap-imap --lib search 2>&1 | tail -40
```

Expected: compile error from `validate_header_name` not being defined.

- [ ] **Step 2.3: Add the `validate_header_name` helper**

Insert the following function immediately after `quote()` (currently at `crates/rimap-imap/src/ops/search.rs:67-84`) and before `format_imap_date()`.

```rust
/// Validate an RFC 5322 field name for use in a `HEADER` SEARCH clause.
///
/// Every byte must be in the printable ASCII range `33..=126`
/// (`!`..`~`) and must not be `b':'` (which terminates a field name).
/// This is stricter than the IMAP wire format requires but matches the
/// shape of all real-world header names and blocks command injection
/// via CR/LF/NUL or whitespace.
///
/// # Errors
///
/// Returns [`ImapError::InvalidInput`] with `field = "header name"` for
/// any disallowed byte or an empty name.
fn validate_header_name(name: &str) -> Result<(), ImapError> {
    if name.is_empty() {
        return Err(ImapError::InvalidInput {
            field: "header name",
            reason: "empty",
        });
    }
    for b in name.bytes() {
        if !(33..=126).contains(&b) || b == b':' {
            return Err(ImapError::InvalidInput {
                field: "header name",
                reason: "must be printable ASCII without ':'",
            });
        }
    }
    Ok(())
}
```

- [ ] **Step 2.4: Extend `structured_to_key` to emit the new keys**

Replace the body of `structured_to_key` (currently at `crates/rimap-imap/src/ops/search.rs:33-65`) with the extended version below. The emit order matters — the combined test in Step 2.1 pins it.

```rust
fn structured_to_key(q: &StructuredQuery) -> Result<String, ImapError> {
    let mut parts: Vec<String> = Vec::new();
    if let Some(s) = &q.from {
        parts.push(format!("FROM {}", quote(s)?));
    }
    if let Some(s) = &q.to {
        parts.push(format!("TO {}", quote(s)?));
    }
    if let Some(s) = &q.cc {
        parts.push(format!("CC {}", quote(s)?));
    }
    if let Some(s) = &q.bcc {
        parts.push(format!("BCC {}", quote(s)?));
    }
    if let Some(s) = &q.subject {
        parts.push(format!("SUBJECT {}", quote(s)?));
    }
    if let Some(s) = &q.body {
        parts.push(format!("BODY {}", quote(s)?));
    }
    if let Some(s) = &q.text {
        parts.push(format!("TEXT {}", quote(s)?));
    }
    if let Some(hs) = &q.headers {
        for h in hs {
            validate_header_name(&h.name)?;
            parts.push(format!("HEADER {} {}", h.name, quote(&h.value)?));
        }
    }
    if let Some(n) = q.larger {
        parts.push(format!("LARGER {n}"));
    }
    if let Some(n) = q.smaller {
        parts.push(format!("SMALLER {n}"));
    }
    if let Some(d) = q.since {
        parts.push(format!("SINCE {}", format_imap_date(d)));
    }
    if let Some(d) = q.before {
        parts.push(format!("BEFORE {}", format_imap_date(d)));
    }
    if let Some(d) = q.sent_since {
        parts.push(format!("SENTSINCE {}", format_imap_date(d)));
    }
    if let Some(d) = q.sent_before {
        parts.push(format!("SENTBEFORE {}", format_imap_date(d)));
    }
    match q.seen {
        Some(true) => parts.push("SEEN".to_string()),
        Some(false) => parts.push("UNSEEN".to_string()),
        None => {}
    }
    match q.answered {
        Some(true) => parts.push("ANSWERED".to_string()),
        Some(false) => parts.push("UNANSWERED".to_string()),
        None => {}
    }
    match q.flagged {
        Some(true) => parts.push("FLAGGED".to_string()),
        Some(false) => parts.push("UNFLAGGED".to_string()),
        None => {}
    }
    match q.draft {
        Some(true) => parts.push("DRAFT".to_string()),
        Some(false) => parts.push("UNDRAFT".to_string()),
        None => {}
    }
    if q.has_attachment {
        // Heuristic: scan the message body for the literal Content-Disposition
        // header. False negatives for unusual capitalization or nested MIME
        // structures are accepted — see StructuredQuery::has_attachment doc.
        parts.push("BODY \"Content-Disposition: attachment\"".to_string());
    }
    if parts.is_empty() {
        return Ok("ALL".to_string());
    }
    Ok(parts.join(" "))
}
```

- [ ] **Step 2.5: Import `validate_header_name` in the test module**

The test module's `use super::{...}` already pulls in private items via `super::`. Update the `use` line at `crates/rimap-imap/src/ops/search.rs:110` from:

```rust
    use super::{format_imap_date, quote, structured_to_key};
```

to:

```rust
    use super::{format_imap_date, quote, structured_to_key, validate_header_name};
```

- [ ] **Step 2.6: Run the tests and confirm they pass**

```bash
cargo test -p rimap-imap --lib search
```

Expected: every test in the search module passes, including the new ones from Step 2.1 and the pre-existing ones.

- [ ] **Step 2.7: Lint the crate**

```bash
cargo clippy -p rimap-imap --all-targets --all-features -- -D warnings
```

Expected: zero warnings.

- [ ] **Step 2.8: Commit**

```bash
git add crates/rimap-imap/src/ops/search.rs
git commit -m "$(cat <<'EOF'
feat(rimap-imap): emit CC/BCC/BODY/TEXT/HEADER/LARGER/SMALLER/SENT*/flag keys

Extend structured_to_key to render every new StructuredQuery field as
its RFC 3501 SEARCH key. Add validate_header_name helper (RFC 5322
field-name byte check: printable ASCII, no ':'). HEADER clauses run
through both validate_header_name and the existing quote() escape.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Fix sub-capability dispatch order (rimap-server)

**Files:**
- Modify: `crates/rimap-server/src/mcp/server.rs:444-463`
- Modify: `crates/rimap-server/tests/e2e_wire.rs` (extend `assert_readonly_denial` + `assert_readonly_audit_records`)

**Why this task exists:** A preexisting bug in `call_tool` makes refined sub-capabilities unreachable. The current order is `refine_tool_name` → `TOOL_DEFS.get(&refined_name).is_none()`, but `TOOL_DEFS` intentionally excludes sub-capability variants (`SearchAdvanced`, `FetchMessageHtml`) per `crates/rimap-server/src/mcp/tool_catalog.rs:178`. The check therefore returns `RESOURCE_NOT_FOUND` for any refined call, short-circuiting `DispatchGuard::pre_dispatch` (and its posture matrix). Nothing in HEAD exercises `advanced_query` or `include_html=true` end-to-end at the wire level (`grep` for those fields in `tests/` finds only schema fixtures), so the bug has gone undetected. Task 4 expands the refined surface — without this fix, Task 10's posture-denial test would observe `RESOURCE_NOT_FOUND` instead of `PostureDenied`, and every new content-oracle path would be unreachable.

The fix: the `TOOL_DEFS` check answers "is this advertised MCP tool implemented?" — a question about the *parsed* (parent) name, not the refined sub-capability. Move the check above `refine_tool_name`.

- [ ] **Step 3.1: Add a wire regression test for the existing `advanced_query` sub-capability**

This test fails today (returns `RESOURCE_NOT_FOUND`, code `-32002`) and passes after Step 3.2 lands (returns `PostureDenied`, code `-32001`). It pins the fix and shields against future regressions on the existing sub-capability paths.

Append the following inside `assert_readonly_denial` at `crates/rimap-server/tests/e2e_wire.rs:627-649`, after the existing `move_message` assertion block:

```rust
    // Regression coverage for the sub-capability dispatch order bug.
    // refine_tool_name promotes Search -> SearchAdvanced when
    // `advanced_query` is set; the TOOL_DEFS check must run on the
    // parsed (parent) name so the refined name reaches DispatchGuard
    // and returns PostureDenied (not RESOURCE_NOT_FOUND).
    let advanced_denial = harness
        .request(
            "tools/call",
            json!({
                "name": "readonly.search",
                "arguments": {"folder": "INBOX", "advanced_query": "FROM x"},
            }),
        )
        .await;
    assert!(
        advanced_denial["error"].is_object(),
        "expected error envelope for readonly.search advanced_query, got {advanced_denial}",
    );
    assert_eq!(
        advanced_denial["error"]["code"].as_i64(),
        Some(POSTURE_DENIAL_CODE),
        "readonly.search advanced_query must be posture-denied (sub-capability \
         dispatch reaches DispatchGuard); got {advanced_denial}",
    );
```

- [ ] **Step 3.2: Run the test and confirm it fails today**

```bash
RIMAP_REQUIRE_DOCKER=1 cargo test -p rimap-server --test e2e_wire wire_e2e_readonly_posture_denial -- --nocapture 2>&1 | tail -40
```

Expected: the new assertion fails. The error envelope's `code` is `-32002` (`RESOURCE_NOT_FOUND`) instead of `-32001` (`POSTURE_DENIAL_CODE`). This is the bug.

If Docker is unavailable, skip the loud failure and proceed to Step 3.3 — the unit-level evidence in `tool_catalog.rs:178` and `server.rs:452-457` is sufficient to justify the fix.

- [ ] **Step 3.3: Reorder the check in `call_tool`**

In `crates/rimap-server/src/mcp/server.rs:444-463`, replace:

```rust
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let (namespaced_account, bare_name) = split_tool_name(&request.name);

        let tool_name = ToolName::from_str(bare_name)
            .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
        // Refine the tool name based on argument shape BEFORE DispatchGuard::pre_dispatch
        // so the posture check covers sub-capabilities (FetchMessageHtml vs
        // FetchMessage, SearchAdvanced vs Search) at a single seam rather
        // than being re-checked inside every handler.
        let tool_name = refine_tool_name(tool_name, request.arguments.as_ref());

        // Reject tools that have no definition (not yet implemented).
        // This prevents unimplemented v2 tools from consuming rate
        // limiter tokens and producing misleading INTERNAL_ERROR.
        if TOOL_DEFS.get(&tool_name).is_none() {
            return Err(ErrorData::new(
                McpCode::RESOURCE_NOT_FOUND,
                format!("tool `{}` is not available", request.name),
                None,
            ));
        }
```

with:

```rust
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let (namespaced_account, bare_name) = split_tool_name(&request.name);

        let parsed_tool = ToolName::from_str(bare_name)
            .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;

        // Reject tools that have no MCP definition.
        //
        // This check answers "is this advertised tool implemented?" —
        // a property of the *parsed* (parent) name, not the refined
        // sub-capability. Sub-capabilities (`SearchAdvanced`,
        // `FetchMessageHtml`) intentionally have no `TOOL_DEFS` entry
        // (`crates/rimap-server/src/mcp/tool_catalog.rs:178`); they
        // share the parent's schema. Running this check on the
        // post-refinement name would short-circuit every refined
        // sub-capability call with RESOURCE_NOT_FOUND, defeating
        // `refine_tool_name` and bypassing `DispatchGuard::pre_dispatch`.
        if TOOL_DEFS.get(&parsed_tool).is_none() {
            return Err(ErrorData::new(
                McpCode::RESOURCE_NOT_FOUND,
                format!("tool `{}` is not available", request.name),
                None,
            ));
        }

        // Refine the tool name based on argument shape AFTER the
        // TOOL_DEFS check, so sub-capability promotion reaches
        // DispatchGuard::pre_dispatch and the posture matrix governs
        // the gated variant.
        let tool_name = refine_tool_name(parsed_tool, request.arguments.as_ref());
```

The remainder of `call_tool` (the bare-name multi-account check, infrastructure-bypass branch, account resolution, dispatch) is unchanged — every downstream use of `tool_name` continues to see the refined variant.

- [ ] **Step 3.4: Update `assert_readonly_audit_records` to expect the new pair**

The added wire test in Step 3.1 triggers a third audit pair (`tool=search` start + end, account `readonly`). Append the following inside `assert_readonly_audit_records` at `crates/rimap-server/tests/e2e_wire.rs:652-717`, after the existing `move_message` block:

```rust
    // Denial path: search pair, account="readonly" (advanced_query
    // sub-capability, denied by DispatchGuard after the reordered
    // TOOL_DEFS check).
    let s_starts: Vec<&Value> = records
        .iter()
        .filter(|r| r["kind"] == "tool_start" && r["tool"] == "search")
        .collect();
    assert_eq!(s_starts.len(), 1, "expected exactly one search tool_start");
    assert_eq!(
        s_starts[0]["account"].as_str(),
        Some("readonly"),
        "readonly.search tool_start must record account=\"readonly\": {records:#?}",
    );
    let s_ends: Vec<&Value> = records
        .iter()
        .filter(|r| r["kind"] == "tool_end" && r["tool"] == "search")
        .collect();
    assert_eq!(s_ends.len(), 1, "expected exactly one search tool_end");
    assert_eq!(
        s_ends[0]["account"].as_str(),
        Some("readonly"),
        "readonly.search tool_end must record account=\"readonly\": {records:#?}",
    );
    assert_eq!(s_ends[0]["start_seq"], s_starts[0]["seq"]);
```

If the audit writer logs `search_advanced` instead of `search` after refinement, change both `r["tool"] == "search"` matches to `r["tool"] == "search_advanced"`. Verify empirically once via:

```bash
RIMAP_REQUIRE_DOCKER=1 cargo test -p rimap-server --test e2e_wire wire_e2e_readonly_posture_denial -- --nocapture 2>&1 | grep -E '"tool":|"kind":' | head -20
```

Note: Task 10 adds another `search` denial pair (for `body`). If Task 10 lands after this task, update both audit-record assertions to expect a count of `2` instead of `1` (or fold the assertion into a single block that counts the sum). The simplest pattern is to expect `s_starts.len() >= 1` here and adjust Task 10's audit block to do the same. The plan keeps the strict `== 1` form so a regression surfaces; Task 10's commit must update this count to match.

- [ ] **Step 3.5: Run the test and confirm it now passes**

```bash
RIMAP_REQUIRE_DOCKER=1 cargo test -p rimap-server --test e2e_wire wire_e2e_readonly_posture_denial 2>&1 | tail -30
```

Expected: passes when Docker is available.

- [ ] **Step 3.6: Lint**

```bash
cargo clippy -p rimap-server --all-targets --all-features -- -D warnings
```

Expected: zero warnings.

- [ ] **Step 3.7: Commit**

```bash
git add crates/rimap-server/src/mcp/server.rs crates/rimap-server/tests/e2e_wire.rs
git commit -m "$(cat <<'EOF'
fix(rimap-server): run TOOL_DEFS check before refine_tool_name

call_tool refined the tool name before checking TOOL_DEFS, but
sub-capability variants (SearchAdvanced, FetchMessageHtml) are
intentionally absent from TOOL_DEFS — they share the parent's
schema. The check therefore short-circuited every refined call with
RESOURCE_NOT_FOUND, bypassing DispatchGuard::pre_dispatch and the
posture matrix. Reorder the check to run on the parsed (parent)
name, then refine.

Adds wire-level regression coverage: readonly.search +
advanced_query must now return PostureDenied (-32001), not
RESOURCE_NOT_FOUND (-32002).

This is a prerequisite for the content-oracle search fields landing
in subsequent commits — body/text/bcc/non-empty-headers refine to
SearchAdvanced and depend on the same dispatch path being live.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Extend `refine_tool_name` predicate (rimap-server)

**Files:**
- Modify: `crates/rimap-server/src/mcp/tool_name.rs`

- [ ] **Step 4.1: Write the failing posture refinement tests**

Append the following test functions inside the existing `#[cfg(test)] mod tests` block at `crates/rimap-server/src/mcp/tool_name.rs:125-303`, immediately before the closing `}` of the module.

```rust
    #[test]
    fn refine_tool_name_promotes_search_on_body() {
        let mut args = serde_json::Map::new();
        args.insert("body".into(), serde_json::Value::String("hello".into()));
        assert_eq!(
            refine_tool_name(ToolName::Search, Some(&args)),
            ToolName::SearchAdvanced,
        );
    }

    #[test]
    fn refine_tool_name_promotes_search_on_text() {
        let mut args = serde_json::Map::new();
        args.insert("text".into(), serde_json::Value::String("anywhere".into()));
        assert_eq!(
            refine_tool_name(ToolName::Search, Some(&args)),
            ToolName::SearchAdvanced,
        );
    }

    #[test]
    fn refine_tool_name_promotes_search_on_bcc() {
        let mut args = serde_json::Map::new();
        args.insert(
            "bcc".into(),
            serde_json::Value::String("blind@example.com".into()),
        );
        assert_eq!(
            refine_tool_name(ToolName::Search, Some(&args)),
            ToolName::SearchAdvanced,
        );
    }

    #[test]
    fn refine_tool_name_promotes_search_on_non_empty_headers() {
        let mut args = serde_json::Map::new();
        args.insert(
            "headers".into(),
            serde_json::json!([{"name": "List-Id", "value": "rust"}]),
        );
        assert_eq!(
            refine_tool_name(ToolName::Search, Some(&args)),
            ToolName::SearchAdvanced,
        );
    }

    #[test]
    fn refine_tool_name_does_not_promote_on_empty_headers_array() {
        let mut args = serde_json::Map::new();
        args.insert("headers".into(), serde_json::json!([]));
        assert_eq!(
            refine_tool_name(ToolName::Search, Some(&args)),
            ToolName::Search,
        );
    }

    #[test]
    fn refine_tool_name_does_not_promote_on_envelope_or_flag_fields() {
        // cc/larger/sent_since/answered are NOT content-oracle inputs;
        // they ride the existing low-posture Search seat.
        for field in ["cc", "larger", "sent_since", "answered"] {
            let mut args = serde_json::Map::new();
            args.insert(field.into(), serde_json::json!("payload"));
            assert_eq!(
                refine_tool_name(ToolName::Search, Some(&args)),
                ToolName::Search,
                "{field} unexpectedly promoted",
            );
        }
    }
```

- [ ] **Step 4.2: Run the tests and confirm they fail**

```bash
cargo test -p rimap-server --lib refine_tool_name 2>&1 | tail -30
```

Expected: the four "promotes" assertions fail (the predicate currently only triggers on `advanced_query`), the two "does not promote" assertions pass.

- [ ] **Step 4.3: Extend the predicate**

Replace the `ToolName::Search` arm of the match in `refine_tool_name` (at `crates/rimap-server/src/mcp/tool_name.rs:50`):

```rust
        ToolName::Search if args.get("advanced_query").is_some() => ToolName::SearchAdvanced,
```

with the multi-condition form below. Keep the rest of the match unchanged.

```rust
        ToolName::Search if promotes_search_to_advanced(args) => ToolName::SearchAdvanced,
```

Then insert the helper just below `refine_tool_name` (after the closing `}` at line 76, before `is_bare_simple_tool_name`):

```rust
/// Whether the `search` argument shape forces promotion to
/// `SearchAdvanced`. Triggers on any content-oracle input:
/// `advanced_query`, `body`, `text`, `bcc`, or a non-empty `headers`
/// array. Envelope/flag fields (`cc`, `larger`, `sent_*`, `answered`,
/// `flagged`, `draft`) do NOT promote — they map to IMAP-indexed
/// metadata, not content scans, and stay under the low-posture
/// `Search` seat.
fn promotes_search_to_advanced(args: &serde_json::Map<String, serde_json::Value>) -> bool {
    if args.get("advanced_query").is_some()
        || args.get("body").is_some()
        || args.get("text").is_some()
        || args.get("bcc").is_some()
    {
        return true;
    }
    // headers triggers only when present AND non-empty.
    matches!(
        args.get("headers").and_then(serde_json::Value::as_array),
        Some(arr) if !arr.is_empty(),
    )
}
```

Note: `matches!` is normally avoided per the global Rust style guide, but the global rule says "explicit destructuring catches field changes" — for a single-shape JSON array check there is no struct to destructure. The arm above is local and well-scoped; if a reviewer prefers `if let Some(arr) = ... { !arr.is_empty() } else { false }`, that's fine too.

- [ ] **Step 4.4: Run the tests and confirm they pass**

```bash
cargo test -p rimap-server --lib refine_tool_name
```

Expected: every refinement test passes, including the pre-existing `refine_tool_name_promotes_sub_capabilities` and `refine_tool_name_is_identity_for_all_other_variants`.

- [ ] **Step 4.5: Lint**

```bash
cargo clippy -p rimap-server --all-targets --all-features -- -D warnings
```

Expected: zero warnings.

- [ ] **Step 4.6: Commit**

```bash
git add crates/rimap-server/src/mcp/tool_name.rs
git commit -m "$(cat <<'EOF'
feat(rimap-server): promote Search to SearchAdvanced on content-oracle args

Extend refine_tool_name so body, text, bcc, or non-empty headers
trigger the same Search -> SearchAdvanced promotion that advanced_query
already does. DispatchGuard then denies these under Readonly/DraftSafe
via the existing posture matrix — no new gating layer.

Envelope/flag fields (cc, larger, sent_*, answered, flagged, draft)
keep the low-posture Search seat: they map to IMAP-indexed metadata,
not content scans.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: Extend `SearchInput` + add `HeaderInput` (rimap-server)

**Files:**
- Modify: `crates/rimap-server/src/tools/retrieval/search.rs:27-51`

Shape-only change. `build_query` threading happens in Task 6; the file will still compile after this task because the new fields are unused (allowed by Rust on plain struct fields).

- [ ] **Step 5.1: Add the `HeaderInput` sibling type**

Insert immediately before `SearchInput` (currently at `crates/rimap-server/src/tools/retrieval/search.rs:27`):

```rust
/// One `HEADER name value` filter for the `search` tool. Converted to
/// [`rimap_imap::types::HeaderSearch`] in `build_query`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct HeaderInput {
    /// RFC 5322 field name (e.g. `"List-Id"`).
    pub name: String,
    /// Substring to match within the header value.
    pub value: String,
}
```

- [ ] **Step 5.2: Extend `SearchInput`**

Replace the existing `SearchInput` struct definition (at `crates/rimap-server/src/tools/retrieval/search.rs:27-51`) with the extended version below. Append the new fields after the existing ones; keep `advanced_query`, `limit`, `offset` last.

```rust
/// Input for the `search` tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SearchInput {
    /// IMAP folder to search in.
    pub folder: String,
    /// Filter by `From` header substring.
    pub from: Option<String>,
    /// Filter by `To` header substring.
    pub to: Option<String>,
    /// Filter by `Cc` header substring.
    pub cc: Option<String>,
    /// Filter by `Bcc` header substring. Content-oracle — requires
    /// `SearchAdvanced` posture (Full or Destructive).
    pub bcc: Option<String>,
    /// Filter by `Subject` header substring.
    pub subject: Option<String>,
    /// Substring search across body parts. Content-oracle — requires
    /// `SearchAdvanced` posture.
    pub body: Option<String>,
    /// Substring search across headers OR body. Content-oracle —
    /// requires `SearchAdvanced` posture.
    pub text: Option<String>,
    /// One or more `HEADER name value` filters. Content-oracle when
    /// non-empty — requires `SearchAdvanced` posture.
    pub headers: Option<Vec<HeaderInput>>,
    /// Match messages strictly larger than this many octets.
    pub larger: Option<u64>,
    /// Match messages strictly smaller than this many octets.
    pub smaller: Option<u64>,
    /// Messages since this ISO date (inclusive) by INTERNALDATE,
    /// e.g. "2026-01-01".
    pub since: Option<String>,
    /// Messages before this ISO date (exclusive) by INTERNALDATE.
    pub before: Option<String>,
    /// Messages since this ISO date (inclusive) by the message's
    /// `Date:` header — distinct from `since` which uses INTERNALDATE.
    pub sent_since: Option<String>,
    /// Messages before this ISO date (exclusive) by the message's
    /// `Date:` header — distinct from `before` which uses INTERNALDATE.
    pub sent_before: Option<String>,
    /// Filter by seen/unseen status.
    pub seen: Option<bool>,
    /// Filter by answered/unanswered status.
    pub answered: Option<bool>,
    /// Filter by flagged/unflagged status.
    pub flagged: Option<bool>,
    /// Filter by draft/non-draft status.
    pub draft: Option<bool>,
    /// Filter for messages with attachments.
    pub has_attachment: Option<bool>,
    /// Raw IMAP SEARCH query (full posture only).
    pub advanced_query: Option<String>,
    /// Max results to return (default 100, max 100).
    pub limit: Option<usize>,
    /// Offset into the result set (default 0).
    pub offset: Option<usize>,
}
```

- [ ] **Step 5.3: Confirm the crate still compiles**

```bash
cargo check -p rimap-server --all-targets
```

Expected: compiles clean. (New fields are unused but Rust does not warn on unread struct fields when the struct is `pub` and used externally.)

- [ ] **Step 5.4: Commit**

```bash
git add crates/rimap-server/src/tools/retrieval/search.rs
git commit -m "$(cat <<'EOF'
feat(rimap-server): extend SearchInput with new search filter fields

Add cc, bcc, body, text, headers (Vec<HeaderInput>), larger, smaller,
sent_since, sent_before, answered, flagged, draft to SearchInput.
Add HeaderInput sibling type with schemars/serde derives.

Shape-only change — build_query threading and empty-string rejection
land in the next commit.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: Thread new inputs through `build_query` + empty-string rejection (rimap-server)

**Files:**
- Modify: `crates/rimap-server/src/tools/retrieval/search.rs` (extend `build_query` at line 163; add unit tests in the existing `#[cfg(test)] mod tests` block)

- [ ] **Step 6.0: Add a module-level clippy exemption to the test module**

The existing `crates/rimap-server/src/tools/retrieval/search.rs` test module (at lines 313-364) has no clippy attributes — its current tests only use `assert!` / `assert_eq!`. The new tests in Steps 6.1 and 7.1 use `unwrap`, `expect`, and `panic!`, which the workspace lints (`unwrap_used = "deny"`, `panic = "deny"`, `expect_used = "warn"` → fatal under `-D warnings`) would reject.

Mirror the pattern already used in `crates/rimap-imap/src/ops/search.rs:108` (`#[expect(clippy::unwrap_used, reason = "tests")]` directly above `mod tests`). Insert above the existing `#[cfg(test)]` at `crates/rimap-server/src/tools/retrieval/search.rs:313`:

```rust
#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests"
)]
mod tests {
```

(Replace the existing `#[cfg(test)]\nmod tests {` with the multi-attribute form above.)

- [ ] **Step 6.1: Write the failing unit tests**

Append the following inside the existing `#[cfg(test)] mod tests` block at `crates/rimap-server/src/tools/retrieval/search.rs:313-364`, immediately before its closing `}`.

```rust
    use rimap_imap::types::{HeaderSearch, StructuredQuery};

    fn input_with_folder() -> SearchInput {
        SearchInput {
            folder: "INBOX".to_string(),
            from: None,
            to: None,
            cc: None,
            bcc: None,
            subject: None,
            body: None,
            text: None,
            headers: None,
            larger: None,
            smaller: None,
            since: None,
            before: None,
            sent_since: None,
            sent_before: None,
            seen: None,
            answered: None,
            flagged: None,
            draft: None,
            has_attachment: None,
            advanced_query: None,
            limit: None,
            offset: None,
        }
    }

    fn build(input: &SearchInput) -> Result<rimap_imap::types::SearchQuery, rimap_core::RimapError> {
        // build_query's `_account` parameter is unused; pass a zero-sized
        // placeholder via an unsafe-free workaround would require
        // touching AccountState plumbing. Easier: call build_query
        // through a thin local wrapper that pretends to have an account.
        // Since `_account: &AccountState` is unused in the body, we
        // construct a minimal AccountState only if absolutely required.
        // For these tests we exercise build_query indirectly via the
        // pure validation paths exposed below; if that proves awkward,
        // extract the validation into a free helper and test that
        // directly.
        let _ = input;
        unimplemented!("see Step 6.2 — wire to build_query once it accepts &SearchInput only")
    }

    #[test]
    fn build_query_rejects_empty_cc() {
        let mut input = input_with_folder();
        input.cc = Some(String::new());
        let err = build(&input).unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("cc"),
            "expected cc-empty error, got: {err}",
        );
    }

    #[test]
    fn build_query_rejects_whitespace_cc() {
        let mut input = input_with_folder();
        input.cc = Some("   ".to_string());
        assert!(build(&input).is_err());
    }

    #[test]
    fn build_query_rejects_empty_bcc() {
        let mut input = input_with_folder();
        input.bcc = Some(String::new());
        assert!(build(&input).is_err());
    }

    #[test]
    fn build_query_rejects_empty_body() {
        let mut input = input_with_folder();
        input.body = Some(String::new());
        assert!(build(&input).is_err());
    }

    #[test]
    fn build_query_rejects_whitespace_body() {
        let mut input = input_with_folder();
        input.body = Some("\t ".to_string());
        assert!(build(&input).is_err());
    }

    #[test]
    fn build_query_rejects_empty_text() {
        let mut input = input_with_folder();
        input.text = Some(String::new());
        assert!(build(&input).is_err());
    }

    #[test]
    fn build_query_rejects_empty_header_name() {
        let mut input = input_with_folder();
        input.headers = Some(vec![HeaderInput {
            name: String::new(),
            value: "x".to_string(),
        }]);
        assert!(build(&input).is_err());
    }

    #[test]
    fn build_query_rejects_whitespace_header_name() {
        let mut input = input_with_folder();
        input.headers = Some(vec![HeaderInput {
            name: "   ".to_string(),
            value: "x".to_string(),
        }]);
        assert!(build(&input).is_err());
    }

    #[test]
    fn build_query_rejects_empty_header_value() {
        let mut input = input_with_folder();
        input.headers = Some(vec![HeaderInput {
            name: "List-Id".to_string(),
            value: String::new(),
        }]);
        assert!(build(&input).is_err());
    }

    #[test]
    fn build_query_rejects_whitespace_header_value() {
        let mut input = input_with_folder();
        input.headers = Some(vec![HeaderInput {
            name: "List-Id".to_string(),
            value: "  ".to_string(),
        }]);
        assert!(build(&input).is_err());
    }

    #[test]
    fn build_query_accepts_empty_headers_array_as_no_filter() {
        let mut input = input_with_folder();
        input.headers = Some(Vec::new());
        let q = build(&input).expect("empty headers vec is accepted");
        match q {
            rimap_imap::types::SearchQuery::Structured(s) => {
                assert!(s.headers.is_none(), "headers should be normalized to None");
            }
            rimap_imap::types::SearchQuery::Raw(r) => panic!("unexpected raw: {r}"),
        }
    }

    #[test]
    fn build_query_threads_cc_into_structured_query() {
        let mut input = input_with_folder();
        input.cc = Some("alice@example.com".to_string());
        let q = build(&input).unwrap();
        match q {
            rimap_imap::types::SearchQuery::Structured(s) => {
                assert_eq!(s.cc.as_deref(), Some("alice@example.com"));
            }
            rimap_imap::types::SearchQuery::Raw(r) => panic!("unexpected raw: {r}"),
        }
    }

    #[test]
    fn build_query_threads_all_new_fields_into_structured_query() {
        let mut input = input_with_folder();
        input.cc = Some("c@example.com".to_string());
        input.bcc = Some("b@example.com".to_string());
        input.body = Some("hi".to_string());
        input.text = Some("anywhere".to_string());
        input.headers = Some(vec![HeaderInput {
            name: "List-Id".to_string(),
            value: "rust".to_string(),
        }]);
        input.larger = Some(1024);
        input.smaller = Some(2_048_000);
        input.sent_since = Some("2026-01-01".to_string());
        input.sent_before = Some("2026-02-01".to_string());
        input.answered = Some(true);
        input.flagged = Some(false);
        input.draft = Some(true);
        let q = build(&input).unwrap();
        let s: StructuredQuery = match q {
            rimap_imap::types::SearchQuery::Structured(s) => s,
            rimap_imap::types::SearchQuery::Raw(r) => panic!("unexpected raw: {r}"),
        };
        assert_eq!(s.cc.as_deref(), Some("c@example.com"));
        assert_eq!(s.bcc.as_deref(), Some("b@example.com"));
        assert_eq!(s.body.as_deref(), Some("hi"));
        assert_eq!(s.text.as_deref(), Some("anywhere"));
        let hs = s.headers.expect("headers");
        assert_eq!(hs.len(), 1);
        assert_eq!(hs[0], HeaderSearch { name: "List-Id".to_string(), value: "rust".to_string() });
        assert_eq!(s.larger, Some(1024));
        assert_eq!(s.smaller, Some(2_048_000));
        assert_eq!(
            s.sent_since,
            Some(::time::Date::from_calendar_date(2026, ::time::Month::January, 1).unwrap()),
        );
        assert_eq!(
            s.sent_before,
            Some(::time::Date::from_calendar_date(2026, ::time::Month::February, 1).unwrap()),
        );
        assert_eq!(s.answered, Some(true));
        assert_eq!(s.flagged, Some(false));
        assert_eq!(s.draft, Some(true));
    }
```

The tests reference a `build(&input)` helper that does not exist yet, and the `_account: &AccountState` parameter on `build_query` blocks direct testing. Step 6.2 refactors `build_query` to remove that block.

- [ ] **Step 6.2: Refactor `build_query` to drop the unused `_account` parameter**

Confirm `_account` is currently unused by reading `crates/rimap-server/src/tools/retrieval/search.rs:163-188` — it is, the parameter is prefixed `_`. Change the signature so the tests can call it directly.

At `crates/rimap-server/src/tools/retrieval/search.rs:163-188`, replace:

```rust
fn build_query(
    _account: &AccountState,
    input: &SearchInput,
) -> Result<SearchQuery, rimap_core::RimapError> {
```

with:

```rust
fn build_query(input: &SearchInput) -> Result<SearchQuery, rimap_core::RimapError> {
```

Then update the single caller in `handle()` (at `crates/rimap-server/src/tools/retrieval/search.rs:119`):

```rust
    let query = build_query(account, &input)?;
```

becomes:

```rust
    let query = build_query(&input)?;
```

- [ ] **Step 6.3: Update the test `build` helper to call `build_query` directly**

In the new test code from Step 6.1, replace the `build` function with a one-liner:

```rust
    fn build(input: &SearchInput) -> Result<rimap_imap::types::SearchQuery, rimap_core::RimapError> {
        super::build_query(input)
    }
```

- [ ] **Step 6.4: Run the tests and confirm they fail**

```bash
cargo test -p rimap-server --lib search 2>&1 | tail -40
```

Expected: every new test fails (the existing `build_query` still ignores the new fields and has no empty-string rejection).

- [ ] **Step 6.5: Extend `build_query`**

Replace the entire body of `build_query` (the version with the signature now from Step 6.2) with:

```rust
fn build_query(input: &SearchInput) -> Result<SearchQuery, rimap_core::RimapError> {
    if let Some(raw) = &input.advanced_query {
        if raw.bytes().any(|b| b == b'\r' || b == b'\n' || b == b'\0') {
            return Err(rimap_core::RimapError::invalid_input(
                "advanced_query contains forbidden control bytes",
            ));
        }
        return Ok(SearchQuery::Raw(raw.clone()));
    }

    // Reject empty/whitespace-only string filters at the MCP boundary —
    // the IMAP server happily executes broad scans like `BODY ""` and
    // the existing quote() only blocks CR/LF/NUL.
    let cc = require_non_empty("cc", input.cc.as_deref())?;
    let bcc = require_non_empty("bcc", input.bcc.as_deref())?;
    let body = require_non_empty("body", input.body.as_deref())?;
    let text = require_non_empty("text", input.text.as_deref())?;

    // Empty headers vec carries no filter intent — normalize to None
    // so the emitter does not have to special-case it.
    let headers = match &input.headers {
        Some(v) if v.is_empty() => None,
        Some(v) => {
            let mut converted = Vec::with_capacity(v.len());
            for h in v {
                if h.name.trim().is_empty() {
                    return Err(rimap_core::RimapError::invalid_input(
                        "headers[].name must not be empty or whitespace-only",
                    ));
                }
                if h.value.trim().is_empty() {
                    return Err(rimap_core::RimapError::invalid_input(
                        "headers[].value must not be empty or whitespace-only",
                    ));
                }
                converted.push(rimap_imap::types::HeaderSearch {
                    name: h.name.clone(),
                    value: h.value.clone(),
                });
            }
            Some(converted)
        }
        None => None,
    };

    let since = input.since.as_deref().map(parse_iso_date).transpose()?;
    let before = input.before.as_deref().map(parse_iso_date).transpose()?;
    let sent_since = input.sent_since.as_deref().map(parse_iso_date).transpose()?;
    let sent_before = input.sent_before.as_deref().map(parse_iso_date).transpose()?;

    Ok(SearchQuery::Structured(StructuredQuery {
        from: input.from.clone(),
        to: input.to.clone(),
        subject: input.subject.clone(),
        since,
        before,
        seen: input.seen,
        has_attachment: input.has_attachment.unwrap_or(false),
        cc,
        bcc,
        body,
        text,
        headers,
        larger: input.larger,
        smaller: input.smaller,
        sent_since,
        sent_before,
        answered: input.answered,
        flagged: input.flagged,
        draft: input.draft,
    }))
}

/// Reject empty/whitespace-only string filters. Returns `Ok(None)` for
/// `None`, `Ok(Some(s.to_string()))` for a non-trimmed-empty value, and
/// `Err(RimapError::invalid_input)` otherwise. The `field` label flows
/// straight into the error message.
fn require_non_empty(
    field: &str,
    value: Option<&str>,
) -> Result<Option<String>, rimap_core::RimapError> {
    let Some(s) = value else {
        return Ok(None);
    };
    if s.trim().is_empty() {
        return Err(rimap_core::RimapError::invalid_input(format!(
            "{field} must not be empty or whitespace-only"
        )));
    }
    Ok(Some(s.to_string()))
}
```

The header loop inlines its own trim check rather than calling `require_non_empty`, because `require_non_empty` returns `Result<Option<String>, _>` and unwrapping the inner `Option` after a known-Some input would need `.expect(...)`, which trips `clippy::expect_used = "warn"` in non-test code. Inline trim checks keep the helper signature clean and avoid the lint.

- [ ] **Step 6.6: Run the tests and confirm they pass**

```bash
cargo test -p rimap-server --lib search
```

Expected: every test passes, including all new rejection / threading tests and the pre-existing sanitize tests.

- [ ] **Step 6.7: Lint**

```bash
cargo clippy -p rimap-server --all-targets --all-features -- -D warnings
```

Expected: zero warnings.

- [ ] **Step 6.8: Commit**

```bash
git add crates/rimap-server/src/tools/retrieval/search.rs
git commit -m "$(cat <<'EOF'
feat(rimap-server): thread new search fields through build_query

Pass cc, bcc, body, text, headers (with empty-array -> None
normalization), larger, smaller, sent_since, sent_before, answered,
flagged, draft into the StructuredQuery built for each search call.
Reject empty/whitespace-only string filters with
RimapError::invalid_input at the MCP boundary.

Drop the unused _account parameter from build_query so the validation
logic is unit-testable without an AccountState fixture.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: Add `cc` to `SearchResultEntry` + populate from envelope

**Files:**
- Modify: `crates/rimap-server/src/tools/retrieval/search.rs:54-80,259-311`

- [ ] **Step 7.1: Write the failing output tests**

Append inside the existing `#[cfg(test)] mod tests` block at `crates/rimap-server/src/tools/retrieval/search.rs`:

```rust
    use rimap_imap::types::{Address, Envelope, FetchedMessage};

    fn addr(name: &str, mailbox: &str, host: &str) -> Address {
        Address {
            name: if name.is_empty() { None } else { Some(name.as_bytes().to_vec()) },
            adl: None,
            mailbox: Some(mailbox.as_bytes().to_vec()),
            host: Some(host.as_bytes().to_vec()),
        }
    }

    fn fetched_with_envelope(env: Envelope) -> FetchedMessage {
        FetchedMessage {
            uid: rimap_imap::types::tests::uid(42),
            envelope: Some(env),
            bodystructure: None,
            flags: None,
            size: None,
        }
    }

    #[test]
    fn format_search_result_populates_cc_from_envelope() {
        let env = Envelope {
            date: None,
            subject_raw: None,
            from: vec![],
            sender: vec![],
            reply_to: vec![],
            to: vec![],
            cc: vec![addr("Carol", "carol", "example.com")],
            bcc: vec![],
            in_reply_to: None,
            message_id: None,
        };
        let entry = format_search_result(&fetched_with_envelope(env));
        assert_eq!(entry.cc, vec!["Carol <carol@example.com>"]);
    }

    #[test]
    fn format_search_result_returns_empty_cc_when_envelope_omits_it() {
        let env = Envelope {
            date: None,
            subject_raw: None,
            from: vec![],
            sender: vec![],
            reply_to: vec![],
            to: vec![],
            cc: vec![],
            bcc: vec![],
            in_reply_to: None,
            message_id: None,
        };
        let entry = format_search_result(&fetched_with_envelope(env));
        assert!(entry.cc.is_empty());

        let json = serde_json::to_string(&entry).expect("serialize");
        assert!(
            !json.contains("\"cc\""),
            "empty cc must be skipped on serialize; got {json}",
        );
    }

    #[test]
    fn format_search_result_never_emits_bcc_even_when_envelope_has_it() {
        // Privacy boundary: bcc must NOT appear in SearchResultEntry in
        // any posture. format_search_result must ignore env.bcc.
        let env = Envelope {
            date: None,
            subject_raw: None,
            from: vec![],
            sender: vec![],
            reply_to: vec![],
            to: vec![],
            cc: vec![],
            bcc: vec![addr("Blind", "blind", "example.com")],
            in_reply_to: None,
            message_id: None,
        };
        let entry = format_search_result(&fetched_with_envelope(env));
        let json = serde_json::to_string(&entry).expect("serialize");
        assert!(
            !json.contains("bcc"),
            "bcc key must not appear in serialized SearchResultEntry; got {json}",
        );
        assert!(
            !json.contains("blind@example.com"),
            "bcc address must not leak via any other field; got {json}",
        );
    }
```

The first two tests fail to compile (no `cc` field on `SearchResultEntry`); the third compiles only after the first two are addressed.

Note: `rimap_imap::types::tests::uid` is the test-only constructor exposed at `crates/rimap-imap/src/types.rs:557-559`; it is `pub(crate)` inside `mod tests`, which is `pub(crate) mod`. To use it from `rimap-server` tests it must either be exposed under a `test-support` feature or rebuilt locally. Check accessibility with:

```bash
grep -n "pub(crate) mod tests\|pub mod tests\|pub fn uid" /Users/dave/src/rusty-imap-mcp/crates/rimap-imap/src/types.rs
```

If `pub(crate) mod tests` keeps `uid` inside the crate, rebuild it locally in the test module (no feature flag needed). The test module already has `#[cfg(test)]` so `expect` is allowed:

```rust
    #[expect(clippy::expect_used, reason = "tests")]
    fn uid(n: u32) -> rimap_imap::types::Uid {
        use std::num::NonZeroU32;
        rimap_imap::types::Uid::from(NonZeroU32::new(n).expect("non-zero"))
    }
```

Then call `uid(42)` instead of `rimap_imap::types::tests::uid(42)`. If the surrounding test module is already wrapped in `#[expect(clippy::expect_used, reason = "tests")]` at the `mod` level, drop the per-item attribute.

- [ ] **Step 7.2: Run and confirm failure**

```bash
cargo test -p rimap-server --lib search 2>&1 | tail -30
```

Expected: compile error on missing `cc` field on `SearchResultEntry`.

- [ ] **Step 7.3: Add the `cc` field to `SearchResultEntry`**

In the `SearchResultEntry` struct (at `crates/rimap-server/src/tools/retrieval/search.rs:54-80`), insert immediately after the `to` field (currently at lines 75-76):

```rust
    /// Cc addresses, sanitized. Omitted when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cc: Vec<String>,
```

- [ ] **Step 7.4: Populate `cc` in `format_search_result`**

In `format_search_result` (at `crates/rimap-server/src/tools/retrieval/search.rs:259-311`), update the envelope destructuring tuple to include `cc`. The current pattern is `(subject, date, from, to, message_id)`; extend to `(subject, date, from, to, cc, message_id)`.

Replace the `let (subject, date, from, to, message_id) = ...` block with:

```rust
    let (subject, date, from, to, cc, message_id) = if let Some(env) = &msg.envelope {
        let subject = env.subject_raw.as_ref().map(|s| {
            let raw = String::from_utf8_lossy(s);
            sanitize_for_output(&raw)
        });
        let date = env.date.as_ref().map(|d| {
            let raw = String::from_utf8_lossy(d);
            sanitize_for_output(&raw)
        });
        let from = if env.from.is_empty() {
            Vec::new()
        } else {
            format_addresses(&env.from)
                .into_iter()
                .map(|a| sanitize_for_output(&a))
                .collect()
        };
        let to = if env.to.is_empty() {
            Vec::new()
        } else {
            format_addresses(&env.to)
                .into_iter()
                .map(|a| sanitize_for_output(&a))
                .collect()
        };
        let cc = if env.cc.is_empty() {
            Vec::new()
        } else {
            format_addresses(&env.cc)
                .into_iter()
                .map(|a| sanitize_for_output(&a))
                .collect()
        };
        let message_id = env.message_id.as_ref().map(|mid| {
            let raw = String::from_utf8_lossy(mid.as_bytes());
            sanitize_for_output(&raw)
        });
        (subject, date, from, to, cc, message_id)
    } else {
        (None, None, Vec::new(), Vec::new(), Vec::new(), None)
    };
```

And update the `SearchResultEntry` constructor at the bottom of `format_search_result`:

```rust
    SearchResultEntry {
        uid: msg.uid.get(),
        size,
        flags,
        subject,
        date,
        from,
        to,
        cc,
        message_id,
    }
```

`env.bcc` is intentionally not read — see the spec's *Privacy* subsection.

- [ ] **Step 7.5: Run the tests and confirm they pass**

```bash
cargo test -p rimap-server --lib search
```

Expected: every test passes.

- [ ] **Step 7.6: Lint**

```bash
cargo clippy -p rimap-server --all-targets --all-features -- -D warnings
```

Expected: zero warnings.

- [ ] **Step 7.7: Commit**

```bash
git add crates/rimap-server/src/tools/retrieval/search.rs
git commit -m "$(cat <<'EOF'
feat(rimap-server): add cc to SearchResultEntry (bcc intentionally not)

Populate SearchResultEntry.cc from env.cc using the same
sanitize_for_output pipeline as from/to. env.bcc is intentionally not
read — privacy boundary documented in the spec.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: Regenerate the tool-schema fixture

**Files:**
- Regenerate: `crates/rimap-server/tests/fixtures/rimap-tool-schemas/search.schema.json` (and any sibling files the regen script touches).

This is mechanical — the script in `scripts/regen-tool-schemas.sh` rebuilds every fixture from the live Rust types.

- [ ] **Step 8.1: Run the regen script**

```bash
./scripts/regen-tool-schemas.sh
```

Expected: script exits 0; `git diff --stat crates/rimap-server/tests/fixtures/rimap-tool-schemas/` shows changes to at least `search.schema.json`.

- [ ] **Step 8.2: Sanity-check the diff**

```bash
git --no-pager diff crates/rimap-server/tests/fixtures/rimap-tool-schemas/search.schema.json | head -120
```

Expected (manual checklist):
- New properties in the input schema: `cc`, `bcc`, `body`, `text`, `headers`, `larger`, `smaller`, `sent_since`, `sent_before`, `answered`, `flagged`, `draft`.
- New `$defs/HeaderInput` block with `name` and `value` properties.
- New property `cc` on `SearchResultEntry`.
- NO new `bcc` property on `SearchResultEntry` — privacy boundary.

If `bcc` appears on `SearchResultEntry`, STOP — return to Task 7 and remove the leak before continuing.

- [ ] **Step 8.3: Run the dump-tool-catalog smoke test**

```bash
cargo test -p rimap-server --test dump_tool_catalog
```

Expected: passes. (This test only counts tool defs and verifies `inputSchema.type == "object"`; it does not diff against the fixture, but a compilation failure in `dump-tool-schemas` would surface here.)

- [ ] **Step 8.4: Commit**

```bash
git add crates/rimap-server/tests/fixtures/rimap-tool-schemas/
git commit -m "$(cat <<'EOF'
chore(rimap-server): regen search.schema.json for expanded fields

Picks up the new SearchInput fields (cc, bcc, body, text, headers,
larger, smaller, sent_since, sent_before, answered, flagged, draft)
and the new SearchResultEntry.cc output field. bcc remains absent
from SearchResultEntry by design.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 9: E2E wire test — `cc` filter against Dovecot

**Files:**
- Modify: `crates/rimap-server/tests/e2e_wire.rs:284-306` (extend `assert_search`).

The existing `wire_e2e_full_session_draft_safe` test seeds one message, runs `search` with `subject: "e2e-wire-test-smoke"`, and asserts a hit. Extend it with a second call that filters by `cc` and asserts the same hit (or a deliberate non-hit) plus the new `cc` output field.

- [ ] **Step 9.1: Inspect the seed message's CC address**

```bash
grep -n "Cc:\|cc:\|multipart_with_attachment\|fn multipart" /Users/dave/src/rusty-imap-mcp/crates/rimap-server/tests/support/dovecot/fixtures.rs
```

If the seed message has no `Cc:` header, add one in the seed fixture OR pick a CC filter that the existing message satisfies. The intent of this step is to identify a CC value that the seeded message already has — adjust the test to that value rather than mutate the fixture (smaller blast radius).

If no CC is present in the seed, the test's `cc` assertion should target the negative case: `cc: "noone@example.com"` returns `total_matched == 0`. That still exercises the wire-format path for the new field.

- [ ] **Step 9.2: Extend `assert_search`**

Append the following at the end of `assert_search` (just before the `uid` return at `crates/rimap-server/tests/e2e_wire.rs:305`).

```rust
    // Exercise the new `cc` input field. The seeded message has no
    // Cc header (verified in Step 9.1), so this asserts that the
    // wire path round-trips the new field and the IMAP server
    // honors the `CC` SEARCH key (returning zero matches).
    let cc_body = call_tool(
        harness,
        "draftsafe.search",
        json!({ "folder": "INBOX", "cc": "noone@example.com" }),
    )
    .await;
    assert_eq!(
        cc_body["meta"]["total_matched"].as_u64(),
        Some(0),
        "cc filter against unseeded address must yield zero hits: {cc_body}",
    );
```

If Step 9.1 shows the seed actually has a `Cc:` header (the spec only mentions CC adoption on output and the existing fixture may already include a recipient), adapt the assertion to match the seeded CC value and assert `total_matched >= 1` plus that the first result entry's `cc` array contains the seeded address.

- [ ] **Step 9.3: Run the test**

```bash
cargo test -p rimap-server --test e2e_wire wire_e2e_full_session_draft_safe -- --nocapture 2>&1 | tail -40
```

Expected: passes if Docker is available. If Docker is unavailable, the test silently skips — set `RIMAP_REQUIRE_DOCKER=1` to make the skip loud while iterating locally.

- [ ] **Step 9.4: Commit**

```bash
git add crates/rimap-server/tests/e2e_wire.rs
git commit -m "$(cat <<'EOF'
test(rimap-server): e2e wire-format check for cc search filter

Extend assert_search to issue a second search with the new `cc` field
against the seeded message and assert the IMAP server honors it.
Locks in the wire-shape round-trip for the new field.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 10: E2E wire test — `body` under Readonly returns PostureDenied

**Files:**
- Modify: `crates/rimap-server/tests/e2e_wire.rs:627-649` (extend `assert_readonly_denial`).

The existing `wire_e2e_readonly_posture_denial` test verifies `move_message` is denied. Extend it to also verify `search` with `body` is denied — exercising the new `refine_tool_name` promotion path end-to-end.

- [ ] **Step 10.1: Extend `assert_readonly_denial`**

Append at the end of `assert_readonly_denial` (at `crates/rimap-server/tests/e2e_wire.rs:627-649`):

```rust
    // The new `body` input is a content-oracle; refine_tool_name
    // promotes Search -> SearchAdvanced, which the posture matrix
    // denies under Readonly. Pin the wire error to the posture-denial
    // code so silent drift in refinement OR the matrix surfaces here.
    let body_denial = harness
        .request(
            "tools/call",
            json!({
                "name": "readonly.search",
                "arguments": {"folder": "INBOX", "body": "hello"},
            }),
        )
        .await;
    assert!(
        body_denial["error"].is_object(),
        "expected error envelope for readonly.search body, got {body_denial}",
    );
    assert_eq!(
        body_denial["error"]["code"].as_i64(),
        Some(POSTURE_DENIAL_CODE),
        "readonly.search body must be posture-denied; got {body_denial}",
    );
```

- [ ] **Step 10.2: Consider the audit-record assertions**

`assert_readonly_audit_records` (at `crates/rimap-server/tests/e2e_wire.rs:652-717`) counts `move_message` audit pairs. The new `search` denial will produce an additional pair under `tool=search`. Either:

(a) Add a third block to `assert_readonly_audit_records` that asserts exactly one `tool=search` start/end pair with `account=readonly`, mirroring the `move_message` block, OR

(b) Leave the audit assertions as-is (they only count `move_message` records and never assert "no other records present"; adding another tool call does not break them).

Pick (a) — the audit-record block is the strongest cross-check that posture denial flows through the audit writer with the right account scoping. The version below mirrors the existing `move_message` block exactly.

Append at the end of `assert_readonly_audit_records`:

```rust
    // Denial path: search pair, account="readonly".
    let s_starts: Vec<&Value> = records
        .iter()
        .filter(|r| r["kind"] == "tool_start" && r["tool"] == "search")
        .collect();
    assert_eq!(s_starts.len(), 1, "expected exactly one search tool_start");
    assert_eq!(
        s_starts[0]["account"].as_str(),
        Some("readonly"),
        "readonly.search tool_start must record account=\"readonly\": {records:#?}",
    );
    let s_ends: Vec<&Value> = records
        .iter()
        .filter(|r| r["kind"] == "tool_end" && r["tool"] == "search")
        .collect();
    assert_eq!(s_ends.len(), 1, "expected exactly one search tool_end");
    assert_eq!(
        s_ends[0]["account"].as_str(),
        Some("readonly"),
        "readonly.search tool_end must record account=\"readonly\": {records:#?}",
    );
    assert_eq!(s_ends[0]["start_seq"], s_starts[0]["seq"]);
```

If the audit records use a different `tool` value for refined sub-capabilities (e.g. `tool=search_advanced` after refinement), update the filter accordingly. Verify by running the test once and inspecting the audit JSONL:

```bash
RIMAP_REQUIRE_DOCKER=1 cargo test -p rimap-server --test e2e_wire wire_e2e_readonly_posture_denial -- --nocapture 2>&1 | grep -E '"tool":|"kind":' | head -20
```

If the `tool` field reads `search_advanced` instead of `search`, change both `r["tool"] == "search"` strings above to `r["tool"] == "search_advanced"`.

- [ ] **Step 10.3: Run the test**

```bash
cargo test -p rimap-server --test e2e_wire wire_e2e_readonly_posture_denial 2>&1 | tail -40
```

Expected: passes when Docker is available.

- [ ] **Step 10.4: Commit**

```bash
git add crates/rimap-server/tests/e2e_wire.rs
git commit -m "$(cat <<'EOF'
test(rimap-server): e2e posture denial for body search under Readonly

Pin the wire-format error envelope for `readonly.search` with `body`:
refine_tool_name promotes to SearchAdvanced, DispatchGuard denies under
Readonly, and the audit writer records the matching tool_start/tool_end
pair scoped to account=readonly.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 11: Full-workspace verification

- [ ] **Step 11.1: Run the full workspace test suite**

```bash
cargo test --workspace --all-features --locked
```

Expected: all tests pass. Docker-gated tests silently skip if Docker is unavailable; that's fine for local iteration but a Linux CI run should hit them.

- [ ] **Step 11.2: Run the full workspace clippy**

```bash
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
```

Expected: zero warnings.

- [ ] **Step 11.3: Confirm formatting**

```bash
cargo fmt --all -- --check
```

Expected: no diff. Run `cargo fmt --all` to auto-fix if there's drift.

- [ ] **Step 11.4: Run `cargo deny`**

```bash
cargo deny check
```

Expected: no advisories, license, or ban violations. This is part of the pre-push hook, so it must pass before the push step.

- [ ] **Step 11.5: Verify the commit history**

```bash
git log --oneline origin/main..HEAD
```

Expected: ten new commits on top of `32facf9`:
1. Task 1 commit (rimap-imap types)
2. Task 2 commit (rimap-imap emitter)
3. Task 3 commit (sub-capability dispatch order fix + advanced_query regression test)
4. Task 4 commit (refine_tool_name)
5. Task 5 commit (SearchInput shape)
6. Task 6 commit (build_query threading + validation)
7. Task 7 commit (SearchResultEntry.cc)
8. Task 8 commit (schema regen)
9. Task 9 commit (e2e cc)
10. Task 10 commit (e2e body posture denial)

(The two earlier commits — `2ffa9a0` spec and `32facf9` spec revision — remain in place at the base of the feature.)

- [ ] **Step 11.6: Push to origin and open the PR**

This step is interactive — confirm with the user before running.

```bash
git push -u origin feat/expand-search-fields
```

If the push exits 0 with no ref transferred (the known SSH-idle issue documented in the user's memory), retry once. If a second push silently succeeds without transferring, surface the issue rather than re-trying in a loop.

Then open the PR with:

```bash
gh pr create --title "Expand searchable email fields in the search tool" --body "$(cat <<'EOF'
## Summary

- Adds 12 structured SEARCH fields to the `search` MCP tool (`cc`, `bcc`, `body`, `text`, `headers`, `larger`, `smaller`, `sent_since`, `sent_before`, `answered`, `flagged`, `draft`).
- Content-oracle inputs (`body`, `text`, non-empty `headers`, `bcc`) promote `Search` → `SearchAdvanced` via `refine_tool_name`; existing posture matrix denies them under Readonly/DraftSafe.
- Adds `cc` to `SearchResultEntry` from the already-fetched envelope. `bcc` is intentionally not exposed on output (privacy boundary documented in the spec).
- Rejects empty/whitespace-only string filters at the MCP boundary.
- Fixes a preexisting bug in `call_tool` where refined sub-capability variants (`SearchAdvanced`, `FetchMessageHtml`) were rejected with `RESOURCE_NOT_FOUND` before reaching the posture matrix. The `TOOL_DEFS` lookup now runs on the parsed (parent) name; refinement runs after.

Spec: `docs/superpowers/specs/2026-05-18-expand-search-fields-design.md`.

## Test plan

- [x] `cargo test --workspace --all-features --locked` passes locally.
- [x] `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` clean.
- [x] `cargo fmt --all -- --check` clean.
- [x] `cargo deny check` clean.
- [x] `scripts/regen-tool-schemas.sh` produces the committed `search.schema.json`.
- [x] Docker-gated `wire_e2e_full_session_draft_safe` exercises the new `cc` field; `wire_e2e_readonly_posture_denial` exercises both the `body` and `advanced_query` posture denial paths.
EOF
)"
```

---

## Risks during execution

- **Test-helper visibility for `Uid`.** `rimap_imap::types::tests::uid` is `pub(crate)`; tests outside the crate must reconstruct it locally (Step 7.1 covers this). If a `test-support` feature exists on `rimap-imap`, prefer that over local reconstruction.
- **`build_query` refactor (Step 6.2).** Dropping the `_account` parameter is a small public-ish API change inside the file; it only has one caller (`handle`) so the blast radius is local. If any other crate imports `build_query`, surface that before changing.
- **Audit `tool` field for promoted dispatch (Step 10.2).** The audit writer may log either `search` or `search_advanced` after refinement; verify empirically before pinning the test.
- **Pre-push SSH keepalive (Step 11.6).** Per the user's memory, cold-cache pushes can exit 0 without transferring refs. Verify the ref landed (`git ls-remote origin feat/expand-search-fields`) before claiming the push succeeded.
- **Docker availability.** E2E tests silently skip without Docker; the value of Tasks 3, 9, and 10 depends on Docker being up at execution time. If Docker is unavailable locally, flag that the e2e signal is missing rather than declaring the task complete. (Task 3's reorder fix can still be reasoned about from the unit-level evidence — see Step 3.2.)
- **Audit-record counts in `assert_readonly_audit_records`.** Tasks 3 and 10 each add a new `search` denial pair. Task 3 lands first with a strict `== 1` assertion; Task 10 must update both `s_starts.len() == 1` and `s_ends.len() == 1` to `== 2` (or relax to `>= 1`). The plan keeps strict counts so a regression surfaces, but the implementer needs to remember to update Task 3's assertion when Task 10 lands.

---

## Out of scope (do not implement)

- BCC visibility on output in any posture.
- `DELETED`/`UNDELETED`, `OR`/`NOT`/`KEYWORD`, `OLDER`/`YOUNGER` SEARCH keys.
- Fuzz/mutation baseline expansion for the new keys (issue #289).
- Rate limiting or cost accounting for content-oracle searches under SearchAdvanced.

---

## Self-Review

**Spec coverage:**
- `cc` input — Task 1 (struct), Task 2 (emit), Task 5 (input), Task 6 (thread).
- `bcc` input + posture promotion — Task 1, Task 2, Task 4 (promote), Task 5, Task 6.
- `body` input + posture promotion — Task 1, Task 2, Task 4, Task 5, Task 6, Task 10 (e2e denial).
- `text` input + posture promotion — Task 1, Task 2, Task 4, Task 5, Task 6.
- `headers` input + posture promotion (non-empty only) — Task 1, Task 2 (with `validate_header_name`), Task 4 (non-empty check), Task 5 (`HeaderInput`), Task 6 (empty-array normalization).
- `larger`/`smaller` inputs — Task 1, Task 2, Task 5, Task 6.
- `sent_since`/`sent_before` inputs (ISO date parsing) — Task 1 (`time::Date`), Task 2, Task 5 (`Option<String>`), Task 6 (parse).
- `answered`/`flagged`/`draft` inputs — Task 1, Task 2, Task 5, Task 6.
- `cc` on `SearchResultEntry` — Task 7.
- `bcc` NOT on `SearchResultEntry` — Task 7 (negative test), Task 8 (schema check).
- Empty/whitespace string rejection — Task 6 (per-field tests).
- `headers: []` normalized to `None` — Task 6 (test + implementation), Task 2 (emitter still passes empty-vec test).
- `validate_header_name` — Task 2.
- Refinement triggers covered — Task 4.
- Refinement non-triggers covered — Task 4 (low-posture fields don't promote, empty headers don't promote).
- Sub-capability dispatch reaches posture matrix — Task 3 (dispatch reorder + `advanced_query` regression e2e), Task 10 (`body` e2e).
- E2E `cc` wire round-trip — Task 9.
- E2E posture denial wire path — Task 3 (existing `advanced_query`), Task 10 (new `body`).
- Schema regen — Task 8.
- File-level summary — all five files in the spec's File-level summary are touched, plus `crates/rimap-server/src/mcp/server.rs` (Task 3 dispatch reorder, not in the spec's File-level summary because the bug was unknown at spec time).
- Lint-policy compliance for new tests — Task 6 adds module-level `#[expect(clippy::unwrap_used, clippy::expect_used, clippy::panic, reason = "tests")]` to the `crates/rimap-server/src/tools/retrieval/search.rs` test module before inserting the new tests; Task 7 reuses that exemption.

**Placeholder scan:** no TBD/TODO/FIXME; every step contains the actual code or an exact command.

**Type consistency:**
- `HeaderSearch` (rimap-imap) and `HeaderInput` (rimap-server) are deliberately distinct types — the conversion happens in `build_query`. Field names match (`name`, `value`).
- `StructuredQuery` field names match between the struct definition (Task 1), the emitter (Task 2), and the threading code (Task 6).
- `SearchResultEntry.cc: Vec<String>` (Task 7) matches the test assertions (Task 7 tests) and the schema regen check (Task 8).
- `require_non_empty` returns `Result<Option<String>, RimapError>` consistently in Step 6.5.
- `POSTURE_DENIAL_CODE` already exists in `e2e_wire.rs:544`; Tasks 3 and 10 reuse it.
