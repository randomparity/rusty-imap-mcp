# rmcp 1.6 → 2.1 migration

**Date:** 2026-07-07
**Status:** Approved (design)
**PR:** #510 (reuses dependabot branch `dependabot/cargo/cargo-major-3d7d689a84`)

## Motivation

The first tagged release should ship on the current MCP spec with the latest
SDK security fixes rather than on a soon-stale one. rmcp 2.0:

- Aligns all model types to the **MCP 2025-11-25 spec** (rust-sdk #927) — the
  exact spec this codebase already hand-targets on top of rmcp 1.6
  (`server.rs` serves 2025-11-25 capabilities, validates against
  `tests/fixtures/mcp-spec/2025-11-25/schema.json`).
- Fixes three security issues: OAuth resource spoofing (#937), OAuth metadata
  SSRF (#935), streamable-HTTP session leak (#934).

Doing this before the release avoids a breaking SDK migration on a released
`1.0`.

## Scope

- **In:** migrate the rmcp API usage from 1.6 to **2.1.0**; keep the
  `phf`/`phf_codegen` `0.13.1 → 0.14.0` bumps that dependabot grouped into
  #510, with the SC-PROC-01 supply-chain re-audit the bump triggers.
- **Out:** no internal adapter layer over rmcp model types (YAGNI for the small
  break surface); no unrelated refactors; no other dependency bumps.

## Branch & version mechanics

- Work on the existing dependabot branch; the first human push stops dependabot
  from managing it, and PR #510 carries the work.
- `Cargo.toml` keeps `rmcp = { version = "2.0", ... }` (caret admits 2.1.0);
  `cargo update -p rmcp` resolves `Cargo.lock` to **2.1.0**.
- Two commits, so `git bisect` can separate concerns:
  1. `deps: migrate to rmcp 2.1 API`
  2. `deps: bump phf to 0.14 (SC-PROC-01 re-audit)`

## Concrete code changes

All in `crates/rimap-server/src/mcp/`.

| Site | v1 | v2 |
|------|----|----|
| `server.rs` import | `…, RawResource, …` | drop `RawResource` |
| `server.rs` ×3 (account / postures / workflows resources) | `Resource { raw: RawResource::new(uri, name).with_description(d).with_mime_type(m), annotations: None }` | `Resource::new(uri, name).with_description(d).with_mime_type(m)` |
| `error.rs` import | `…, Content, …` | `…, ContentBlock, …` |
| `error.rs` (`to_error_call_result`) | `CallToolResult::error(vec![Content::text(msg)])` | `CallToolResult::error(vec![ContentBlock::text(msg)])` |

Confirmed against the rmcp v1→v2 migration guide (rust-sdk discussion #926):
`RawResource` + `Annotated<T>` wrappers removed; flat `Resource::new(...)`
builder; `Content::text` → `ContentBlock::text`.

## Risk items (compiler is the oracle — resolve during implementation)

- `ToolAnnotations::from_raw` (`tool_catalog.rs`) — verify the constructor
  signature still exists in 2.x; adapt if renamed.
- `ServerHandler` trait method signatures (`list_tools`, `call_tool`,
  `list_resources`, `read_resource`, `RequestContext<RoleServer>`) — confirm
  unchanged.
- `CallToolResult::structured` / `::error` still present.
- `schemars` ↔ `rmcp` version compatibility in the resolved lock.

## Protocol version / conformance

Expectation: `ProtocolVersion::LATEST` remains `2025-11-25`; no fixture changes
needed. If rmcp 2.1's LATEST or any wire shape differs, the detection mechanism
is the existing suite — `mcp-conformance (Node)`, `mcp_wire_*` tests, and the
`tool-schema drift` gate. Any resulting fixture update lands as its own commit
with a written justification, not pre-planned here.

## phf 0.14 re-audit (SC-PROC-01)

`Cargo.toml` documents phf as a re-audit trigger. Re-audit on the 0.14 bump:
license unchanged (MIT/Apache-2.0), no new `build.rs` / network / fs / process
access in the macro source, `cargo-deny` green. Dispatch the
`supply-chain-reviewer` agent; record the outcome in commit (2)'s message.

## Verification (all green before ready-for-merge)

`cargo build`, `clippy -D warnings`, `rustfmt`, `test (stable)`,
`test (MSRV 1.88.0)`, `cargo-deny`, `mcp-conformance (Node)`,
`tool-schema drift`, `tools-doc drift`, `pr-smoke`. Local run drives
build/clippy/test + conformance; CI confirms the full matrix.
