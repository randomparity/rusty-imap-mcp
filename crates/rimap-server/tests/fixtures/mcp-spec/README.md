# Vendored MCP Specification Schemas

This directory holds verbatim copies of the JSON Schema documents
published by the [Model Context Protocol specification][spec-repo].
They are consumed exclusively by the wire-conformance test
(`crates/rimap-server/tests/mcp_wire_conformance.rs`, issue #263).

## Pinned version

`2025-11-25/schema.json` — fetched from

    https://raw.githubusercontent.com/modelcontextprotocol/modelcontextprotocol/main/schema/2025-11-25/schema.json

This matches `SUPPORTED_PROTOCOL_VERSION` in
`crates/rimap-server/src/mcp/server.rs`, the one version
`rusty-imap-mcp` accepts and advertises during the `initialize`
handshake. It is pinned explicitly rather than taken from
`rmcp::model::ProtocolVersion::LATEST`, which rmcp 3.5 moved to
2026-07-28.

## Refresh / drift workflow

- `scripts/refresh-mcp-spec.sh <version>` overwrites the vendored
  copy with the current upstream contents.
- `scripts/refresh-mcp-spec.sh --check <version>` exits non-zero if
  the vendored copy differs from upstream.
- `.github/workflows/mcp-spec-drift.yml` runs the check weekly and
  opens (or updates) a tracking issue when drift is detected.

## Local diffs

None. The vendored copy is byte-for-byte verbatim; if a future
rmcp / spec mismatch forces us to relax a strict constraint (e.g. a
fragment with `additionalProperties: false` that rmcp violates),
document the diff here and link the rationale.

## Naming notes for downstream code

The 2025-11-25 schema's `$defs` splits the JSON-RPC envelope into
three definitions:

- `JSONRPCResponse` — `anyOf` union of the two leaves below
- `JSONRPCResultResponse` — successful result envelope
- `JSONRPCErrorResponse` — error envelope (NOT `JSONRPCError`)

When validating wire payloads in the conformance harness, prefer the
leaf names (`JSONRPCResultResponse` / `JSONRPCErrorResponse`) over
the union.

[spec-repo]: https://github.com/modelcontextprotocol/modelcontextprotocol
