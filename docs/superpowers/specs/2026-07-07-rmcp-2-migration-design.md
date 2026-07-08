# rmcp 1.8 → 2.1 migration

**Date:** 2026-07-07
**Status:** Approved (design)
**PR:** #510 (reuses dependabot branch `dependabot/cargo/cargo-major-3d7d689a84`)

Version precision: origin/main pins `rmcp = "1.6"` (caret), which resolves in
`Cargo.lock` to **1.8.0**. The dependabot bump sets the requirement to `"2.0"`;
`cargo update` resolves the lock to **2.1.0**. So the real migration is lock
**1.8.0 → 2.1.0** (guide reference is still the rust-sdk v1→v2 guide).

## Motivation

The first tagged release should ship on the current MCP spec, and moving to
rmcp 2.x now avoids a breaking SDK migration on a released `1.0`. The operative
driver is spec alignment plus release timing:

- rmcp 2.0 aligns all model types to the **MCP 2025-11-25 spec** (rust-sdk
  #927) — the exact spec this codebase already hand-targets on top of rmcp 1.8
  (`server.rs` serves 2025-11-25 capabilities, validates against
  `tests/fixtures/mcp-spec/2025-11-25/schema.json`). rmcp 2.0 is the release
  that natively provides what this project emulates today.

Not a driver for this build: rmcp 2.0's three security fixes — OAuth resource
spoofing (#937), OAuth metadata SSRF (#935), streamable-HTTP session leak
(#934) — all live in the HTTP/OAuth transport layer. This project compiles only
`features = ["server", "macros", "transport-io"]` (stdio, no HTTP, no OAuth), so
those fixes do not apply here and are not part of the justification. They also
introduce no new attack surface (the vulnerable code is not built).

## Scope

- **In:** migrate the rmcp API usage from 1.8 to **2.1.0**; keep the
  `phf`/`phf_codegen` `0.13.1 → 0.14.0` bumps that dependabot grouped into
  #510, with the SC-PROC-01 supply-chain re-audit the bump triggers, extended
  to rmcp itself (see below).
- **Out:** no internal adapter layer over rmcp model types (YAGNI for the small
  break surface); no unrelated refactors; no other dependency bumps.
- **No incidental lock movement.** The branch is already based on current
  `origin/main` (`HEAD..origin/main` = 0), which includes the four dependabot
  PRs merged earlier (#506–#509). `arc-swap 1.9.2`, `jsonschema 0.46.10`, and
  the new dev-only crate `jsonschema-regex 0.46.10` are already on `main` via
  the merged #508 — they are **not** this PR's changes. (An earlier review saw
  them only because a stale *local* `main` was 4 commits behind; against
  `origin/main` the branch adds only the rmcp + phf bump.)

## Branch & version mechanics

- Work on the existing dependabot branch; the first human push stops dependabot
  from managing it, and PR #510 carries the work. Push is a **normal (non-force)
  push** of our commits atop the current remote head. Dependabot has already
  force-updated this branch once this session, so if the push is rejected as
  non-fast-forward, re-fetch and rebase our commits onto the new head — never
  force-push over a dependabot update.
- `Cargo.toml` keeps `rmcp = { version = "2.0", ... }` (caret admits 2.1.0);
  `cargo update -p rmcp` resolves `Cargo.lock` to **2.1.0**.
- Two commits, so `git bisect` can separate concerns:
  1. `deps: migrate to rmcp 2.1 API` (includes the SC-PROC-01 rmcp/rmcp-macros
     re-audit and the `Cargo.toml` audit-comment refresh)
  2. `deps: bump phf to 0.14 (SC-PROC-01 re-audit)`

## Concrete code changes

All in `crates/rimap-server/src/mcp/`. These are the server→client **output**
types. The migration is *not* output-only, though — rmcp 2.0 realigned input
types too (see "Input side" in Risk items); those have no struct-literal break
but carry the security-relevant items F1/F2 below.

| Site | v1 | v2 |
|------|----|----|
| `server.rs` import | `…, RawResource, …` | drop `RawResource` |
| `server.rs` ×3 (account / postures / workflows resources) | `Resource { raw: RawResource::new(uri, name).with_description(d).with_mime_type(m), annotations: None }` | `Resource::new(uri, name).with_description(d).with_mime_type(m)` |
| `error.rs` import | `…, Content, …` | `…, ContentBlock, …` |
| `error.rs` (`to_error_call_result`) | `CallToolResult::error(vec![Content::text(msg)])` | `CallToolResult::error(vec![ContentBlock::text(msg)])` |

Confirmed against the rmcp v1→v2 migration guide (rust-sdk discussion #926):
`RawResource` + `Annotated<T>` wrappers removed; flat `Resource::new(...)`
builder; `Content::text` → `ContentBlock::text`.

## Risk items (compiler is the oracle for shape; tests are the oracle for behavior)

**Output-type shape (compile-time):**

- `ToolAnnotations::from_raw` (`tool_catalog.rs`) — verify the constructor
  signature still exists in 2.x; adapt if renamed.
- `CallToolResult::structured` / `::error` still present.
- `Resource` new field set — `Resource::new(uri, name)` drops the explicit
  `annotations: None`. Enumerate rmcp 2.1's `Resource` fields and confirm no
  newly-defaulting field (e.g. `title`) silently appears in emitted descriptors.
- `schemars` ↔ `rmcp` version compatibility in the resolved lock.

**Input side / security-relevant (behavior, not just shape) — F1, F2:**

- `initialize` / `InitializeRequestParams` / `InitializeResult`
  (`server.rs:490-511`). This overridden handler enforces the anti-downgrade
  control (`if request.protocol_version != ProtocolVersion::LATEST { reject }`,
  `server.rs:500`). A major rmcp bump is exactly when the `initialize`
  negotiation default or param shape could shift and still compile with
  weakened semantics. **Add/keep a test** asserting a non-LATEST `initialize`
  yields the crafted `unsupported_protocol_version_error` envelope, not a
  transport-layer deserialize error.
- `ProtocolVersion` deserialization leniency (`server.rs:1012-1016`). The
  downgrade path *depends on* rmcp deserializing any string into
  `ProtocolVersion(Cow::Owned(s))` so unknown/hostile version strings route into
  the server's controlled error envelope. If rmcp 2.0 made `ProtocolVersion` a
  strict enum, a garbage version now fails at transport deserialize, **bypassing
  `unsupported_protocol_version_error`**. Confirm leniency is unchanged with a
  test feeding a garbage version string through `initialize`. This is the one
  path the conformance suite does **not** cover — it validates emitted output
  shapes, not client→server input strictness.

## Protocol version / conformance

Expectation: `ProtocolVersion::LATEST` remains `2025-11-25`; no fixture changes
needed. Confirm this at runtime via `ProtocolVersion::LATEST.as_str()` and record
the confirmation in commit (1).

**Decision rule — a moved LATEST is a client-lockout, not a fixture tweak (F8).**
`server.rs:496-500` does **exact-equality LATEST-only rejection**. If rmcp 2.1
(or any future bump) advances `LATEST` past `2025-11-25`, the server would
immediately **reject every existing 2025-11-25 client** (a self-inflicted
availability cliff) while still serving capabilities validated against the
2025-11-25 fixture. If `LATEST` ≠ `2025-11-25`, **stop and escalate** — this is a
security- and availability-relevant protocol change requiring its own decision,
not an auto-updated fixture. Also re-validate the now-stale in-code rationale at
`server.rs:496` ("rmcp 1.5 emits LATEST wire shapes regardless of negotiated
version"), which is premised on 1.x behavior; 2.0 aligns wire emission to the
spec, so the comment must be re-checked.

**The output safety net covers the changed emit shapes (spot-confirmed).**
Existing tests assert all three output types end-to-end: `e2e_wire.rs` drives
`resources/list` (`:783`) and `resources/read` (`:755`) against the schema
fixture, and asserts the **error** `CallToolResult` shape — `isError` (`:350`,
`:873`) and `content[0].text` (`:883`), which exercises the `to_error_call_result`
`ContentBlock` path specifically. So an emit-shape regression fails CI. This net
does **not** extend to input strictness (see F2). Any fixture update that is
genuinely warranted (wire shape changed but protocol version did not) lands as
its own commit with written justification.

## Supply-chain re-audit (SC-PROC-01) — rmcp + rmcp-macros + phf

`Cargo.toml` documents phf as a re-audit trigger, but rmcp itself took a
**major** bump (1.8 → 2.1) and `rmcp-macros 2.1.0` executes arbitrary Rust at
build time — the exact class SC-PROC-01 requires per-crate acknowledgement for.
The existing `Cargo.toml:194-198` audit note is stale ("Reviewed v1.4 … Re-audit
on minor bump"); a major bump plainly qualifies.

Dispatch the `supply-chain-reviewer` agent to confirm — do not assume — and
record its actual findings in the commits:

- **rmcp 2.1 + rmcp-macros 2.1** (commit 1): source diff carries no new
  `build.rs` / network / fs / process access; proc-macro remains
  Apache-2.0 OR MIT. Mitigating fact to record: the 1.8→2.1 bump added **no new
  crate names** to the compiled graph, so the delta is the changed
  `rmcp`/`rmcp-macros` source itself, not new transitive surface. Refresh the
  stale `Cargo.toml:194-198` comment to "Reviewed v2.1."
- **phf / phf_codegen 0.14** (commit 2): license unchanged (expected
  MIT/Apache-2.0); no new `build.rs` / network / fs / process access in the
  macro source; `cargo-deny` green (advisories, bans, licenses, sources).

If any check fails, that bump is not mergeable as-is and is escalated separately
from the rest of the migration.

## Verification (all green before ready-for-merge)

`cargo build`, `clippy -D warnings`, `rustfmt`, `test (stable)`,
`test (MSRV 1.88.0)`, `cargo-deny`, `mcp-conformance (Node)`,
`tool-schema drift`, `tools-doc drift`, `pr-smoke`. Local run drives
build/clippy/test + conformance + the two new/kept downgrade-rejection tests;
CI confirms the full matrix.
