# rmcp 2.1 migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Adapt the server source to rmcp 2.1's MCP-2025-11-25-aligned model API so the workspace compiles, all existing tests pass, and the first release ships on rmcp 2.x.

**Architecture:** The dependency bump (rmcp `2.0`/lock 2.1.0, phf 0.14) is already committed by dependabot (`3d87b1bb`). This plan is the *source* adaptation only: rmcp 2.0 removed `RawResource` and the `Resource.raw` field (flat builder now) and renamed the `Content` enum to `ContentBlock`. The break is 11 sites in exactly two files (8 surface on `cargo check`; 3 test-module reads appear once the lib compiles). No behavior changes; existing wire/e2e/conformance tests are the specification.

**Tech Stack:** Rust (workspace), rmcp 2.1.0 (stdio `transport-io`), tokio, `cargo`/`clippy`/`cargo-deny`, Node `mcp-conformance`.

## Global Constraints

- MSRV **1.88.0**; must pass `test (stable)` and `test (MSRV 1.88.0)`.
- `clippy -D warnings`; `rustfmt` clean; 100-char line length; absolute imports.
- `rmcp` stays pinned as `version = "2.0"` (caret) resolving to lock **2.1.0**; do **not** widen or change the requirement.
- `ProtocolVersion::LATEST` **must remain `2025-11-25`** (verified: rmcp 2.1 `LATEST = V_2025_11_25`). If a future change moves it, STOP and escalate — that is a protocol/lockout change, not part of this migration (spec §"Protocol version").
- No new dependencies; no adapter layer; no unrelated refactors.
- Commit trailer required: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.

## Verified facts (compiler + rmcp 2.1 source, already checked)

- Full break set = **11 sites in 2 files**: `error.rs` (`Content` import + `Content::text`); `server.rs` (`RawResource` import, 3 `Resource { raw: … }` production sites, **and 3 `r.raw.{uri,mime_type}` reads in the `static_doc_resource_tests` module at :902/905/908**). A lib+bins `cargo check` reports only the first 8 because the lib fails to compile before its test module is built; the 3 test-module reads (`E0609 no field 'raw'`) surface once the lib compiles. The unrelated `.raw` hits in `registry.rs` / `tools/compose/*` are the SMTP message-builder's byte field, **not** rmcp `Resource`.
- rmcp 2.1 API present: `Resource::new(uri,name).with_description(_).with_mime_type(_)` (resource.rs:41/60/65); `ContentBlock::text` (content.rs:280); `CallToolResult::error(Vec<ContentBlock>)` and `::structured(Value)` (model.rs:3047/3069).
- `phf_codegen` `build.rs` and `ToolAnnotations::from_raw` compile unchanged under 0.14 / 2.1 → **spec's conditional phf-`build.rs` commit is NOT needed** (omit it).
- `ProtocolVersion` deserialize is still lenient (unknown strings → `Cow::Owned`, model.rs:198-209) → the anti-downgrade control and the existing `mcp_wire_negative.rs` garbage-version tests remain valid guards (F1/F2 satisfied by existing tests).

## Commits (per spec, phf-build commit dropped)

1. `deps: migrate to rmcp 2.1 API` — Tasks 1–4 (error.rs + server.rs + guard-test confirmation).
2. *(omitted — phf `build.rs` needs no change).*
3. `chore: SC-PROC-01 re-audit for rmcp 2.1 and phf 0.14` — Task 6 (comment-only).

---

### Task 1: Gate — confirm rmcp 2.1 `LATEST` is still `2025-11-25`

**Files:**
- Inspect only (no edit): resolved `rmcp` in `~/.cargo/registry/.../rmcp-2.1.0/src/model.rs`.

**Interfaces:**
- Produces: a go/no-go gate for the whole migration.

- [ ] **Step 1: Verify LATEST**

Run: `RMCP=$(find ~/.cargo -type d -name 'rmcp-2.1.0'|head -1); rg -n 'pub const LATEST|V_2025_11_25: Self' "$RMCP/src/model.rs"`
Expected: `LATEST: Self = Self::V_2025_11_25` and `V_2025_11_25 … "2025-11-25"`.

- [ ] **Step 2: Decision**

If LATEST is `2025-11-25` → proceed. If NOT → STOP, do not continue; report to the operator (spec stop-and-escalate rule). No commit.

---

### Task 2: Migrate `error.rs` `Content` → `ContentBlock`

**Files:**
- Modify: `crates/rimap-server/src/mcp/error.rs:12` (import), `:148` (call site)
- Test (guard): `crates/rimap-server/src/mcp/error.rs` `#[cfg(test)]` (`result_text` / `to_error_call_result` tests)

**Interfaces:**
- Consumes: rmcp `ContentBlock::text`, `CallToolResult::error(Vec<ContentBlock>)`.
- Produces: unchanged public signature `to_error_call_result(&RimapError) -> CallToolResult`.

- [ ] **Step 1: Confirm the guard test fails to compile now**

Run: `cargo test -p rimap-server --lib mcp::error:: 2>&1 | rg 'unresolved import .rmcp::model::Content.'`
Expected: the `E0432` import error (the test can't build against the old symbol).

- [ ] **Step 2: Fix the import (`error.rs:12`)**

Change:
```rust
use rmcp::model::{CallToolResult, Content, ErrorCode as McpCode, ErrorData};
```
to:
```rust
use rmcp::model::{CallToolResult, ContentBlock, ErrorCode as McpCode, ErrorData};
```

- [ ] **Step 3: Fix the call site (`error.rs:148`)**

Change:
```rust
    let mut result = CallToolResult::error(vec![Content::text(message)]);
```
to:
```rust
    let mut result = CallToolResult::error(vec![ContentBlock::text(message)]);
```

- [ ] **Step 4: Do not test yet — the lib cannot compile until Task 3**

`cargo test --lib` builds the *entire* `rimap-server` lib test binary; a
`mcp::error::` filter only selects which tests RUN, not which modules compile.
While `server.rs` still references removed symbols (production sites + the
`r.raw` test reads), the lib test binary will not link, so no `error.rs` test
can run yet. Apply Steps 2–3 and proceed to Task 3; `error.rs`'s tests are
verified in Task 3 Step 7 once the whole crate compiles.

---

### Task 3: Migrate `server.rs` `Resource` construction (3 sites) + drop `RawResource`

**Files:**
- Modify: `crates/rimap-server/src/mcp/server.rs:23` (import), `:565-570` (account), `:821-828` (postures), `:830-…` (workflows), **`:902/905/908` (`static_doc_resource_tests` `r.raw` reads)**
- Test (guard): `crates/rimap-server/tests/e2e_wire.rs` (`resources/list` `:783`, `resources/read` `:755`); `server.rs` `static_doc_resource_tests`

**Interfaces:**
- Consumes: `Resource::new(uri,name).with_description(_).with_mime_type(_)`.
- Produces: `list_resources` / `static_doc_resources()` returning `Vec<Resource>`, same URIs/descriptions/mime-types as before.

- [ ] **Step 1: Drop `RawResource` from the import (`server.rs:23`)**

Change:
```rust
    PaginatedRequestParams, ProtocolVersion, RawResource, ReadResourceRequestParams,
```
to:
```rust
    PaginatedRequestParams, ProtocolVersion, ReadResourceRequestParams,
```

- [ ] **Step 2: Migrate the account resource (`server.rs:565-570`)**

Change:
```rust
            Resource {
                raw: RawResource::new(format!("rimap://accounts/{name}"), name)
                    .with_description(desc)
                    .with_mime_type("application/json"),
                annotations: None,
            }
```
to:
```rust
            Resource::new(format!("rimap://accounts/{name}"), name)
                .with_description(desc)
                .with_mime_type("application/json")
```

- [ ] **Step 3: Migrate the postures doc resource (`server.rs:821-828`)**

Change:
```rust
        Resource {
            raw: RawResource::new(POSTURES_DOC_URI, "postures")
                .with_description(
                    "Security posture matrix: the four levels, per-tool gating, \
                     sub-capabilities, and the [security.tools] override mechanism.",
                )
                .with_mime_type("text/markdown"),
            annotations: None,
        },
```
to:
```rust
        Resource::new(POSTURES_DOC_URI, "postures")
            .with_description(
                "Security posture matrix: the four levels, per-tool gating, \
                 sub-capabilities, and the [security.tools] override mechanism.",
            )
            .with_mime_type("text/markdown"),
```

- [ ] **Step 4: Migrate the workflows doc resource (`server.rs:830-…`)**

Apply the identical transform to the `WORKFLOWS_DOC_URI` block: replace `Resource { raw: RawResource::new(WORKFLOWS_DOC_URI, "workflows").with_description(…).with_mime_type("text/markdown"), annotations: None }` with `Resource::new(WORKFLOWS_DOC_URI, "workflows").with_description(…).with_mime_type("text/markdown")`, preserving the exact description string and the surrounding `vec![ … ]` comma.

- [ ] **Step 5: Migrate the test-module `.raw` reads (`server.rs:902/905/908`)**

`Resource` is flat in 2.1 (`uri`, `mime_type` fields; no `raw` wrapper), so the
`static_doc_resource_tests` assertions must drop `.raw`. Change:
```rust
                r.raw.mime_type.as_deref(),
```
to `r.mime_type.as_deref(),`; change `r.raw.uri,` to `r.uri,`; and change
`resources.iter().map(|r| r.raw.uri.as_str())` to
`resources.iter().map(|r| r.uri.as_str())`.

- [ ] **Step 6: Verify the whole workspace compiles**

Run: `cargo check --workspace --all-targets`
Expected: no errors (all 11 sites resolved — 8 lib/prod + 3 test-module reads).

- [ ] **Step 7: Run the resource + error guards (both files, now that the crate links)**

Run: `cargo test -p rimap-server --lib mcp::error:: mcp::server:: && cargo test -p rimap-server --test e2e_wire`
Expected: PASS — `error.rs` `to_error_call_result` tests, `static_doc_resource_tests`, and the `resources/list` + `resources/read` wire guards all green against the 2025-11-25 schema fixture.

---

### Task 4: Confirm the anti-downgrade control (F1/F2) survives the bump

**Files:**
- Test (guard, no edit expected): `crates/rimap-server/tests/mcp_wire_negative.rs` (garbage `"1999-01-01"` `:617`, old `"2024-11-05"` `:694`); `server.rs` `#[cfg(test)]` protocol tests.

**Interfaces:**
- Consumes: full `initialize` JSON-RPC frames through the real deserialize path (the transport-boundary test F2 requires).

- [ ] **Step 1: Run the wire-negative + capabilities suites**

Run: `cargo test -p rimap-server --test mcp_wire_negative --test server_capabilities`
Expected: PASS — a garbage `protocolVersion` still deserializes (lenient `ProtocolVersion`) and is rejected with the crafted `unsupported_protocol_version_error` (`-32602`) envelope, not a transport deserialize error. This is the F1/F2 guard; it exercises the container boundary.

- [ ] **Step 2: Decision on new tests**

These existing tests already cover F1/F2 at the deserialize boundary → **no new test needed**. Only if either suite is absent/skips the garbage-version case, add a test that deserializes an `initialize` frame with `"protocolVersion":"1999-01-01"` and asserts a `-32602` `unsupported_protocol_version_error`. (Verified present, so expected to be a no-op.)

---

### Task 5: Full guardrail suite + commit 1

**Files:**
- No source change; runs the repo guardrails.

- [ ] **Step 1: Format + lint**

Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings`
Expected: clean.

- [ ] **Step 2: Tests (stable) + drift + deny**

Run: `cargo test --workspace && cargo deny check`
Expected: all pass. Also run the schema/doc drift gates the repo uses (`just` targets or the CI equivalents for `tool-schema drift` / `tools-doc drift`) and `mcp-conformance` (Node) if runnable locally; otherwise rely on CI.

- [ ] **Step 3: MSRV check**

Run: `cargo +1.88.0 check --workspace` (or the repo's MSRV task) if the toolchain is installed; otherwise rely on the `test (MSRV 1.88.0)` CI job.
Expected: compiles on 1.88.0.

- [ ] **Step 4: Commit 1**

```bash
git add crates/rimap-server/src/mcp/error.rs crates/rimap-server/src/mcp/server.rs
git commit -m "deps: migrate to rmcp 2.1 API

Adapt to rmcp 2.0's MCP-2025-11-25 model realignment: RawResource and
Resource.raw removed (flat Resource::new builder); Content enum renamed to
ContentBlock. No behavior change; existing e2e_wire/mcp_wire_negative
guards cover resource emit shapes and the anti-downgrade control.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: SC-PROC-01 re-audit + comment refresh + commit 3

**Files:**
- Modify: `crates/../Cargo.toml` — rmcp comment (`:194-198`, "Reviewed v1.4" → "v2.1") and phf audit block (`:148-183`, provenance date + attestation).

**Interfaces:**
- Produces: current audit trail; no code/version change.

- [ ] **Step 1: Dispatch the supply-chain reviewer**

Dispatch the `supply-chain-reviewer` agent to confirm on this diff: rmcp 2.1 + rmcp-macros 2.1 add no new `build.rs`/network/fs/process access and no new crate names to the graph; phf/phf_codegen 0.14 license unchanged (MIT/Apache-2.0); `cargo deny check` green. Record its findings verbatim in the commit body.

- [ ] **Step 2: Refresh the rmcp audit comment (`Cargo.toml:194-198`)**

Update "Reviewed v1.4 … Re-audit on minor bump" to reflect **Reviewed v2.1** (major bump acknowledged), noting the reviewer's "no new crates added to the graph" finding.

- [ ] **Step 3: Refresh the phf audit block (`Cargo.toml:148-183`)**

Update the provenance date ("as of 2026-05-20") and the version attestation to cover phf/phf_codegen 0.14 (the re-audit trigger at `:182-183` fired on this bump).

- [ ] **Step 4: Guardrails + commit 3**

Run: `cargo deny check && cargo fmt --all --check`
Then:
```bash
git add Cargo.toml
git commit -m "chore: SC-PROC-01 re-audit for rmcp 2.1 and phf 0.14

<supply-chain-reviewer findings summary>

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Self-Review

**Spec coverage:** rmcp API sites (Tasks 2–3) ✓; input-side F1/F2 anti-downgrade control (Task 4) ✓; protocol-version gate/stop-and-escalate (Task 1) ✓; conformance safety net for the 3 emit shapes (Tasks 3/5 via e2e_wire + conformance) ✓; SC-PROC-01 rmcp+phf re-audit and both stale comments (Task 6) ✓; phf `build.rs` conditional (verified unneeded, commit dropped) ✓; new `Resource` field set (builders only set title/description/mime/annotations — no field silently emitted; `Resource::new` defaults the rest, asserted by the e2e_wire schema-validation guard) ✓; commit structure (1 + 3, no phf-build commit) ✓.

**Placeholder scan:** Task 4 Step 2 and Task 6 Step 1 reference reviewer findings to be recorded at run time — not placeholders, they are the actual instruction; every code step shows exact before/after.

**Type consistency:** `ContentBlock::text`, `CallToolResult::error(Vec<ContentBlock>)`, `Resource::new(_,_).with_description(_).with_mime_type(_)` used consistently across Tasks 2–3 and match the verified rmcp 2.1 signatures.
