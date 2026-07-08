# rmcp 1.6 → 2.1 migration

**Date:** 2026-07-07
**Status:** Approved (design)
**PR:** #510 (reuses dependabot branch `dependabot/cargo/cargo-major-3d7d689a84`)

## Motivation

The first tagged release should ship on the current MCP spec, and moving to
rmcp 2.x now avoids a breaking SDK migration on a released `1.0`. The operative
driver is spec alignment plus release timing:

- rmcp 2.0 aligns all model types to the **MCP 2025-11-25 spec** (rust-sdk
  #927) — the exact spec this codebase already hand-targets on top of rmcp 1.6
  (`server.rs` serves 2025-11-25 capabilities, validates against
  `tests/fixtures/mcp-spec/2025-11-25/schema.json`). rmcp 2.0 is the release
  that natively provides what this project emulates today.

Not a driver for this build: rmcp 2.0's three security fixes — OAuth resource
spoofing (#937), OAuth metadata SSRF (#935), streamable-HTTP session leak
(#934) — all live in the HTTP/OAuth transport layer. This project compiles only
`features = ["server", "macros", "transport-io"]` (stdio, no HTTP, no OAuth), so
those fixes do not apply here and are not part of the justification.

## Scope

- **In:** migrate the rmcp API usage from 1.6 to **2.1.0**; keep the
  `phf`/`phf_codegen` `0.13.1 → 0.14.0` bumps that dependabot grouped into
  #510, with the SC-PROC-01 supply-chain re-audit the bump triggers.
- **Out:** no internal adapter layer over rmcp model types (YAGNI for the small
  break surface); no unrelated refactors; no other dependency bumps.

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
needed.

**Decision rule — protocol version is not a fixture tweak.** If rmcp 2.1's
`LATEST` is **not** `2025-11-25`, stop and escalate. `server.rs` enforces
LATEST-only acceptance and the negative tests hard-pin `"2025-11-25"`; a moved
LATEST means the server advertises and accepts a different protocol version,
which is a security-relevant protocol change requiring its own decision — not an
auto-updated fixture. Do not silently re-pin fixtures to a new version.

**The safety net covers the changed shapes (spot-confirmed).** This migration
changes exactly the `resources/list`, `resources/read`, and
error-`CallToolResult` (`Content` → `ContentBlock`) wire shapes. Existing tests
assert all three end-to-end: `e2e_wire.rs` drives `resources/list`
(`:783`) and `resources/read` (`:755`) against the schema fixture, and asserts
the error `CallToolResult` shape — `isError` (`:350`, `:873`) and
`content[0].text` (`:883`). So a shape regression fails CI rather than shipping
green-but-unchecked. If implementation reveals a shape the current tests do not
cover, add a targeted assertion rather than widening a fixture. Any fixture
update that is genuinely warranted (wire shape changed but protocol version did
not) lands as its own commit with written justification.

## phf 0.14 re-audit (SC-PROC-01)

`Cargo.toml` documents phf as a re-audit trigger. Dispatch the
`supply-chain-reviewer` agent to confirm — do not assume — the following on the
0.14 bump, and record its actual findings in commit (2)'s message:

- license unchanged (expected MIT/Apache-2.0);
- no new `build.rs` / network / fs / process access in the macro source;
- no new or unexpected transitive deps pulled in by phf 0.14 (or by rmcp 2.1);
- `cargo-deny` green (advisories, bans, licenses, sources).

If any check fails, the phf bump is not mergeable as-is and is escalated
separately from the rmcp migration commit.

## Verification (all green before ready-for-merge)

`cargo build`, `clippy -D warnings`, `rustfmt`, `test (stable)`,
`test (MSRV 1.88.0)`, `cargo-deny`, `mcp-conformance (Node)`,
`tool-schema drift`, `tools-doc drift`, `pr-smoke`. Local run drives
build/clippy/test + conformance; CI confirms the full matrix.
