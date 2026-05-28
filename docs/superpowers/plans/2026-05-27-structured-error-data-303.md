# Structured ErrorData.data for RateLimited / CircuitOpen / AttachmentTooLarge (#303) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Surface the typed recovery fields (`retry_after_ms`, attachment `kind`/`limit`) as structured MCP `ErrorData.data` on the rate-limit, circuit-open, and attachment-too-large error paths, instead of flattening them into prose.

**Architecture:** Follow the Phase 1 `UidValidityChanged` precedent (issue option b): add dedicated `RimapError` variants carrying typed fields, route the upstream `AuthzError` / `ImapError` / `ContentError` producers into them via the existing `From` impls, and build the `data` JSON in short-circuit arms of `to_mcp_error`. Design: `docs/superpowers/specs/2026-05-27-issue-303-structured-error-data-design.md`.

**Tech Stack:** Rust (workspace), `thiserror`, `serde_json`, `rmcp` (`ErrorData`), `cargo nextest`.

---

## File Structure

- `crates/rimap-core/src/error.rs` — three new `RimapError` variants + `code()` arms + unit tests. (Single source of truth for the error enum.)
- `crates/rimap-authz/src/error.rs` — route `RateLimited` / `CircuitOpen` in `From<AuthzError>`; rewrite the pinning test.
- `crates/rimap-imap/src/error.rs` — route `SizeLimit` into `AttachmentTooLarge` in `From<ImapError>`.
- `crates/rimap-server/src/mcp/content.rs` — `classify_content_error` builds `AttachmentTooLarge { kind, limit }`; extend its test.
- `crates/rimap-server/src/mcp/error.rs` — three structured-`data` short-circuit arms in `to_mcp_error` + three shape tests.

Adding variants to the `#[non_exhaustive]` `RimapError` only forces an update to the in-crate exhaustive match in `code()`; all out-of-crate matches already carry a `_` arm. A full `cargo build` after Task 1 confirms no other in-crate exhaustive match broke.

---

## Task 1: New `RimapError` variants (rimap-core)

**Files:**
- Modify: `crates/rimap-core/src/error.rs` (enum body after `UidValidityChanged`, ~line 272; `code()` match ~line 290-302)
- Test: same file, `#[cfg(test)] mod tests`

- [ ] **Step 1: Write the failing tests**

Add to `mod tests` in `crates/rimap-core/src/error.rs`:

```rust
    #[test]
    fn rate_limited_variant_code_and_display() {
        let err = RimapError::RateLimited { retry_after_ms: 250 };
        assert_eq!(err.code(), ErrorCode::RateLimited);
        let s = err.to_string();
        assert!(s.contains("250"), "Display must include retry_after_ms; got {s}");
        assert!(!s.starts_with("ERR_"), "structured variants drop the ERR_ prefix; got {s}");
    }

    #[test]
    fn circuit_open_variant_code_and_display() {
        let err = RimapError::CircuitOpen { retry_after_ms: 0 };
        assert_eq!(err.code(), ErrorCode::CircuitOpen);
        // retry_after_ms == 0 is the half-open probe case, still a valid hint.
        assert!(err.to_string().contains('0'));
    }

    #[test]
    fn attachment_too_large_variant_code_and_display() {
        let err = RimapError::AttachmentTooLarge {
            kind: "mime_depth".to_string(),
            limit: 8,
        };
        assert_eq!(err.code(), ErrorCode::AttachmentTooLarge);
        let s = err.to_string();
        assert!(s.contains("mime_depth"), "Display must include kind; got {s}");
        assert!(s.contains('8'), "Display must include limit; got {s}");
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo nextest run -p rimap-core --locked rate_limited_variant_code_and_display circuit_open_variant_code_and_display attachment_too_large_variant_code_and_display`
Expected: FAIL — `no variant named RateLimited` / `CircuitOpen` / `AttachmentTooLarge` (compile error).

- [ ] **Step 3: Add the variants**

In `crates/rimap-core/src/error.rs`, immediately after the `UidValidityChanged { ... }` variant closes (before the enum's closing `}`), add:

```rust
    /// Rate limiter rejected the call. Carries the typed `retry_after_ms`
    /// hint so MCP clients can implement programmatic backoff without
    /// parsing prose. Routed from `AuthzError::RateLimited` by
    /// `From<AuthzError> for RimapError`. See
    /// `docs/superpowers/specs/2026-05-27-issue-303-structured-error-data-design.md`.
    #[error("rate limited; retry after {retry_after_ms} ms")]
    RateLimited {
        /// How long the caller should wait before retrying, in milliseconds.
        retry_after_ms: u64,
    },
    /// Circuit breaker is open; fast-failing. Carries the typed
    /// `retry_after_ms` hint. `retry_after_ms == 0` means the breaker is
    /// half-open and a probe is already in flight — back off briefly, it is
    /// *not* "retry immediately". Routed from `AuthzError::CircuitOpen`.
    #[error("circuit breaker open; retry after {retry_after_ms} ms")]
    CircuitOpen {
        /// How long the caller should wait before retrying, in milliseconds.
        /// `0` is the half-open probe case (see variant docs).
        retry_after_ms: u64,
    },
    /// A hard size/structure cap was hit. Carries the typed `kind` (which
    /// limit) and `limit` (the cap value) so clients can choose a smaller
    /// request. Fed by `ContentError::LimitExceeded` (content pipeline) and
    /// `ImapError::SizeLimit` (IMAP fetch body cap, `kind = "fetch_body_bytes"`).
    ///
    /// Unlike `UidValidityChanged`, this variant carries no `#[source]`:
    /// both producers are leaves whose only payload is now surfaced as the
    /// typed `limit` field, and the content producer is classified from a
    /// borrow and cannot supply one. This is the documented exception to the
    /// "every IMAP-origin variant carries a source" rule above.
    #[error("content limit exceeded: {kind} (limit={limit})")]
    AttachmentTooLarge {
        /// Which limit tripped (e.g. `"mime_depth"`, `"message_bytes"`,
        /// `"fetch_body_bytes"`).
        kind: String,
        /// The cap value that was exceeded.
        limit: u64,
    },
```

- [ ] **Step 4: Add the `code()` arms**

In the `code()` match in `impl RimapError` (the exhaustive match ~line 290-302), add three arms before the closing brace:

```rust
            Self::RateLimited { .. } => ErrorCode::RateLimited,
            Self::CircuitOpen { .. } => ErrorCode::CircuitOpen,
            Self::AttachmentTooLarge { .. } => ErrorCode::AttachmentTooLarge,
```

- [ ] **Step 5: Run the new tests + full core build**

Run: `cargo nextest run -p rimap-core --locked`
Expected: PASS (all, including the three new tests).
Run: `cargo build --workspace --locked`
Expected: success — confirms no other in-crate exhaustive match over `RimapError` broke.

- [ ] **Step 6: Commit**

```bash
git add crates/rimap-core/src/error.rs
git commit -m "feat(core): add RateLimited/CircuitOpen/AttachmentTooLarge RimapError variants (#303)"
```

---

## Task 2: Route AuthzError into the typed variants (rimap-authz)

**Files:**
- Modify: `crates/rimap-authz/src/error.rs:108-115` (`From<AuthzError>`); test `from_impl_preserves_code_and_message` ~line 124-136

- [ ] **Step 1: Rewrite the pinning test to assert the new routing**

Replace `from_impl_preserves_code_and_message` in `crates/rimap-authz/src/error.rs` with:

```rust
    #[test]
    fn rate_limited_routes_to_typed_variant() {
        let err = AuthzError::RateLimited { retry_after_ms: 42 };
        let display = err.to_string();
        let mapped: RimapError = err.into();
        match mapped {
            RimapError::RateLimited { retry_after_ms } => {
                assert_eq!(retry_after_ms, 42);
            }
            other => panic!("expected RimapError::RateLimited, got {other:?}"),
        }
        // Display wording is preserved (only the ERR_ prefix differs upstream).
        assert_eq!(
            RimapError::RateLimited { retry_after_ms: 42 }.to_string(),
            display
        );
    }

    #[test]
    fn circuit_open_routes_to_typed_variant() {
        let err = AuthzError::CircuitOpen { retry_after_ms: 15_000 };
        let mapped: RimapError = err.into();
        match mapped {
            RimapError::CircuitOpen { retry_after_ms } => {
                assert_eq!(retry_after_ms, 15_000);
            }
            other => panic!("expected RimapError::CircuitOpen, got {other:?}"),
        }
    }

    #[test]
    fn posture_denied_still_flattens_to_authz() {
        let err = AuthzError::PostureDenied(ToolName::CreateDraft);
        let msg = err.to_string();
        let mapped: RimapError = err.into();
        match mapped {
            RimapError::Authz { code, message } => {
                assert_eq!(code, ErrorCode::PostureDenied);
                assert_eq!(message, msg);
            }
            other => panic!("expected Authz variant, got {other:?}"),
        }
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo nextest run -p rimap-authz --locked rate_limited_routes_to_typed_variant circuit_open_routes_to_typed_variant`
Expected: FAIL — both map to `RimapError::Authz` today (panic "expected RimapError::RateLimited").

- [ ] **Step 3: Route the two variants in `From<AuthzError>`**

Replace the `from` body in `impl From<AuthzError> for RimapError` (`crates/rimap-authz/src/error.rs:108-115`) with:

```rust
    fn from(err: AuthzError) -> Self {
        // RateLimited / CircuitOpen get dedicated RimapError variants so the
        // typed retry hint survives into structured MCP `data` (#303),
        // mirroring the UidValidityChanged routing in `From<ImapError>`.
        // Everything else flattens through the generic `Authz` arm.
        match err {
            AuthzError::RateLimited { retry_after_ms } => {
                RimapError::RateLimited { retry_after_ms }
            }
            AuthzError::CircuitOpen { retry_after_ms } => {
                RimapError::CircuitOpen { retry_after_ms }
            }
            other => RimapError::Authz {
                code: other.code(),
                message: other.to_string(),
            },
        }
    }
```

- [ ] **Step 4: Run the authz tests**

Run: `cargo nextest run -p rimap-authz --locked`
Expected: PASS (new routing tests + the unchanged `error_codes_match_spec`).

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-authz/src/error.rs
git commit -m "feat(authz): route RateLimited/CircuitOpen into typed RimapError variants (#303)"
```

---

## Task 3: Route ImapError::SizeLimit into AttachmentTooLarge (rimap-imap)

**Files:**
- Modify: `crates/rimap-imap/src/error.rs:217-251` (`From<ImapError>`)
- Test: same file, `mod tests`

- [ ] **Step 1: Write the failing test**

Add to `mod tests` in `crates/rimap-imap/src/error.rs`:

```rust
    #[test]
    fn size_limit_routes_to_attachment_too_large() {
        use rimap_core::RimapError;
        let imap_err = ImapError::SizeLimit { limit: 26_214_400 };
        let mapped: RimapError = imap_err.into();
        match mapped {
            RimapError::AttachmentTooLarge { kind, limit } => {
                assert_eq!(kind, "fetch_body_bytes");
                assert_eq!(limit, 26_214_400);
            }
            other => panic!("expected RimapError::AttachmentTooLarge, got {other:?}"),
        }
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo nextest run -p rimap-imap --locked size_limit_routes_to_attachment_too_large`
Expected: FAIL — `SizeLimit` flows through the generic `Imap` arm today (panic "expected RimapError::AttachmentTooLarge").

- [ ] **Step 3: Add the routing arm**

Replace the entire `from` body in `impl From<ImapError> for RimapError` (`crates/rimap-imap/src/error.rs:218-250`) with the form below. It keeps the existing borrow-then-move `if let` for `UidValidityChanged` (a by-value `match` cannot both destructure and move `err` into `source`) and inserts the `SizeLimit` route as an `else if`:

```rust
    fn from(err: ImapError) -> Self {
        // UIDVALIDITY-change errors keep a dedicated variant with a #[source]
        // (consistent depth for IMAP-origin errors). SizeLimit routes to the
        // dedicated AttachmentTooLarge variant so its typed `limit` reaches
        // structured MCP `data` (#303); it is a leaf, so no source is kept —
        // the documented exception on RimapError::AttachmentTooLarge.
        // Everything else flattens through the generic `Imap` arm.
        if let ImapError::UidValidityChanged {
            folder,
            expected,
            actual,
        } = &err
        {
            RimapError::UidValidityChanged {
                folder: folder.clone(),
                expected: *expected,
                actual: *actual,
                source: Box::new(err),
            }
        } else if let ImapError::SizeLimit { limit } = &err {
            RimapError::AttachmentTooLarge {
                kind: "fetch_body_bytes".to_string(),
                limit: *limit,
            }
        } else {
            let code = err.code();
            let message = err.to_string();
            RimapError::Imap {
                code,
                message,
                source: Some(Box::new(err)),
            }
        }
    }
```

- [ ] **Step 4: Run the imap error tests**

Run: `cargo nextest run -p rimap-imap --locked`
Expected: PASS — new `size_limit_routes_to_attachment_too_large` plus existing `uid_validity_changed_*` tests.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-imap/src/error.rs
git commit -m "feat(imap): route SizeLimit into typed AttachmentTooLarge variant (#303)"
```

---

## Task 4: classify_content_error builds AttachmentTooLarge (rimap-server)

**Files:**
- Modify: `crates/rimap-server/src/mcp/content.rs:29-46` (`classify_content_error`); test `limit_exceeded_classifies_as_attachment_too_large` ~line 137-160

- [ ] **Step 1: Strengthen the existing test**

In `crates/rimap-server/src/mcp/content.rs`, replace the body of `limit_exceeded_classifies_as_attachment_too_large` with an assertion on the typed fields, not just `code()`:

```rust
    #[test]
    fn limit_exceeded_classifies_as_attachment_too_large() {
        let err = ContentError::LimitExceeded {
            kind: "mime_depth",
            limit: 8,
        };
        match classify_content_error(&err) {
            RimapError::AttachmentTooLarge { kind, limit } => {
                assert_eq!(kind, "mime_depth");
                assert_eq!(limit, 8);
            }
            other => panic!("expected AttachmentTooLarge, got {other:?}"),
        }

        // Malformed → InvalidInput (same as `_` fallback).
        let malformed = ContentError::Malformed {
            reason: "unterminated boundary".into(),
        };
        assert_eq!(
            classify_content_error(&malformed).code(),
            ErrorCode::InvalidInput
        );
    }
```

No module-attribute change is needed: `panic!` inside `#[cfg(test)]` is not flagged in this workspace (see the existing `panic!` at `crates/rimap-imap/src/error.rs:347` in a test module with no such attribute; `clippy.toml` sets only `future-size-threshold`). Adding `#[expect(clippy::panic)]` here would instead become an unfulfilled-expectation warning and fail the `cargo clippy -- -D warnings` gate in Task 6. Keep the module's existing `#[expect(clippy::unwrap_used, reason = "tests")]` — it stays fulfilled by `parse_message_async_matches_sync`.

- [ ] **Step 2: Run to verify failure**

Run: `cargo nextest run -p rimap-server --locked limit_exceeded_classifies_as_attachment_too_large`
Expected: FAIL — current code returns `RimapError::Authz { code: AttachmentTooLarge, .. }`, so the match hits `other` (panic).

- [ ] **Step 3: Update the classifier**

In `classify_content_error` (`crates/rimap-server/src/mcp/content.rs`), replace the `ContentError::LimitExceeded { .. }` arm with:

```rust
        ContentError::LimitExceeded { kind, limit } => RimapError::AttachmentTooLarge {
            kind: (*kind).to_string(),
            limit: *limit as u64,
        },
```

Update the function's doc comment block (lines 30-37) to drop the "Phase 2 — deferred" note and state the fields are now plumbed through.

- [ ] **Step 4: Run server content tests**

Run: `cargo nextest run -p rimap-server --locked content`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-server/src/mcp/content.rs
git commit -m "feat(server): classify LimitExceeded into typed AttachmentTooLarge (#303)"
```

---

## Task 5: Structured `data` in to_mcp_error + shape tests (rimap-server)

**Files:**
- Modify: `crates/rimap-server/src/mcp/error.rs:44-76` (the short-circuit `match err`); tests in same file

- [ ] **Step 1: Write the three shape tests**

Add to `mod tests` in `crates/rimap-server/src/mcp/error.rs`:

```rust
    #[test]
    fn rate_limited_carries_structured_data() {
        let err = RimapError::RateLimited { retry_after_ms: 250 };
        let mcp = to_mcp_error(&err);
        assert_eq!(mcp.code, super::RATE_LIMITED);
        let data = mcp.data.as_ref().expect("data populated");
        let v = serde_json::to_value(data).expect("data serializes");
        assert_eq!(v["error_code"], "ERR_RATE_LIMITED");
        assert_eq!(v["retry_after_ms"], 250);
    }

    #[test]
    fn circuit_open_carries_structured_data() {
        let err = RimapError::CircuitOpen { retry_after_ms: 0 };
        let mcp = to_mcp_error(&err);
        assert_eq!(mcp.code, super::CIRCUIT_OPEN);
        let data = mcp.data.as_ref().expect("data populated");
        let v = serde_json::to_value(data).expect("data serializes");
        assert_eq!(v["error_code"], "ERR_CIRCUIT_OPEN");
        // 0 is the half-open probe value and must round-trip, not be omitted.
        assert_eq!(v["retry_after_ms"], 0);
    }

    #[test]
    fn attachment_too_large_carries_structured_data() {
        let err = RimapError::AttachmentTooLarge {
            kind: "message_bytes".to_string(),
            limit: 26_214_400,
        };
        let mcp = to_mcp_error(&err);
        assert_eq!(mcp.code, super::ATTACHMENT_TOO_LARGE);
        let data = mcp.data.as_ref().expect("data populated");
        let v = serde_json::to_value(data).expect("data serializes");
        assert_eq!(v["error_code"], "ERR_ATTACHMENT_TOO_LARGE");
        assert_eq!(v["kind"], "message_bytes");
        assert_eq!(v["limit"], 26_214_400);
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo nextest run -p rimap-server --locked rate_limited_carries_structured_data circuit_open_carries_structured_data attachment_too_large_carries_structured_data`
Expected: FAIL — `data` is `None` today for these codes (`expect("data populated")` panics).

- [ ] **Step 3: Add the short-circuit arms**

In `to_mcp_error` (`crates/rimap-server/src/mcp/error.rs`), add three arms inside the first `match err { ... }` block, before `_ => {}`:

```rust
        RimapError::RateLimited { retry_after_ms } => {
            let data = serde_json::json!({
                "error_code": ErrorCode::RateLimited.as_str(),
                "retry_after_ms": retry_after_ms,
            });
            return ErrorData::new(RATE_LIMITED, message, Some(data));
        }
        RimapError::CircuitOpen { retry_after_ms } => {
            let data = serde_json::json!({
                "error_code": ErrorCode::CircuitOpen.as_str(),
                "retry_after_ms": retry_after_ms,
            });
            return ErrorData::new(CIRCUIT_OPEN, message, Some(data));
        }
        RimapError::AttachmentTooLarge { kind, limit } => {
            let data = serde_json::json!({
                "error_code": ErrorCode::AttachmentTooLarge.as_str(),
                "kind": kind,
                "limit": limit,
            });
            return ErrorData::new(ATTACHMENT_TOO_LARGE, message, Some(data));
        }
```

(The Phase-1 arms use `ErrorData::invalid_params`; these use `ErrorData::new` with the custom code so the wire `code` matches the existing `code()`-based mapping at lines 98-100. The `code()`-based arms stay as defensive fallbacks.)

- [ ] **Step 4: Run the shape tests + existing error tests**

Run: `cargo nextest run -p rimap-server --locked --no-tests=pass error`
Expected: PASS — new shape tests plus the unchanged `message_is_preserved`, `custom_codes_lie_in_jsonrpc_server_error_range`, etc.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-server/src/mcp/error.rs
git commit -m "feat(server): emit structured data for RateLimited/CircuitOpen/AttachmentTooLarge (#303)"
```

---

## Task 6: Clear the in-code Phase 2 deferral notes + final gates

**Files:**
- Modify: `crates/rimap-authz/src/error.rs:15-58` (the two `# Phase 2: structured data plumbing (deferred)` docblocks on `RateLimited` / `CircuitOpen`)
- Modify: `crates/rimap-server/src/mcp/content.rs` (already touched in Task 4 — verify the deferral note is gone)

- [ ] **Step 1: Replace the deferral docblocks**

In `crates/rimap-authz/src/error.rs`, on `RateLimited` and `CircuitOpen`, delete the `# Phase 2: structured data plumbing (deferred)` sections and replace with one line each noting the field now reaches MCP `data` via `From<AuthzError> for RimapError` → `RimapError::RateLimited` / `CircuitOpen`. Keep the `CircuitOpen` `retry_after_ms` semantics block (it is still accurate and load-bearing).

- [ ] **Step 2: Grep for stale references**

Run: `rg -n "Phase 2|deferred" crates/`
Expected: no remaining "deferred" plumbing notes in `rimap-authz`/`rimap-server` source. (The intentional `(#303)` issue-tracking refs added in Tasks 2-3 are expected and are matched by a separate `rg -n "#303" crates/` if you want to confirm them — do not treat those as stale.)

- [ ] **Step 3: Full workspace gates**

Run: `cargo fmt --all`
Run: `cargo clippy --all-targets --all-features --locked -- -D warnings`
Expected: clean.
Run: `cargo nextest run --workspace --locked --no-tests=pass`
Expected: all pass.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "docs(authz): clear Phase 2 deferral notes now that #303 is implemented"
```

---

## Self-Review checklist (run before handing off)

- **Spec coverage:** Delta 1 → Task 1; Delta 2 → Task 2; Delta 3 (content) → Task 4; Delta 3 (imap SizeLimit) → Task 3; Delta 4 → Task 5; deferral-note cleanup → Task 6. Test plan's routing+shape pairs: routing tests in Tasks 2/3/4, shape tests in Task 5. ✔
- **Type consistency:** variant field names `retry_after_ms: u64`, `kind: String`, `limit: u64` used identically across Tasks 1, 2, 3, 4, 5. `kind` from content is `&'static str` → `(*kind).to_string()`; `limit: usize` → `*limit as u64`. ✔
- **Display wording:** unified `"content limit exceeded: {kind} (limit={limit})"` (Task 1) matches the spec's chosen lower-churn wording; shape tests assert `data`, not message text, so wording churn is isolated. ✔
