# Preserve modern first-request negotiation (#837)

## Scope and provenance

WORK:SCOPE q837-9a3ae579 governs C1–C4. Exclusions and owners are explicitly empty,
approved by the operator on 2026-10-21. Full-spec; fixed denominator 250 changed lines (M).
The inbound validator remains the owner of local legacy pre-init interception; rmcp remains
owner of metadata completeness and ongoing protocol enforcement. No ownership migration.
See [ADR-0032](../../ADR/0032-modern-first-request-and-legacy-interception.md).

## Design

Use rmcp `GetMeta::missing_required_keys(ProtocolVersion::V_2026_07_28)` on a typed request.
A non-ping, non-initialize request with no missing required keys starts the modern path:
forward it through the existing envelope validation and latch initialization so subsequent
requests reach rmcp, including requests with missing metadata that rmcp must reject itself.
Do not substitute a local key list or require optional clientInfo. A pre-init ping stays
non-negotiating. Legacy initialize keeps its existing behavior. Incomplete non-ping metadata
retains the existing single -32002 write, flag-before-duplex-drop ordering and clean close.
Envelope validation remains mandatory before an untrusted line can establish modern state;
a rejected modern candidate must not disable legacy interception for a later request.
No dependency changes, new transport, or shutdown coordination changes are needed.

## Success

C1: metadata-complete tools/list as the first non-ping request returns a normal tools result.
C2: metadata-less legacy requests retain exactly one -32002, echoed ID, no data, exit0/Eof.
C3: test modern repeat requests, incomplete request rejection and recovery in modern sessions,
pre-init ping then modern request, partial/malformed required metadata and invalid-envelope
then legacy request. Retain the existing legacy numeric/string-ID and broken-stdout tests.
C4: ADR-0032 supersedes ADR-0025 without altering it, distinguishes rmcp EOF init failure from
local clean-close policy, explains the reversal of ADR-0024, and bounds broken-stdout races.

## Global Constraints

Rust dev 1.94.0; MSRV 1.88.0; edition 2024. No added runtime dependencies.
Preserve the five declared release targets and the shared stdout serialization lock.
Do not modify accepted ADR-0025 or the campaign-owned ADR index.

## Failure model

- Actors and deployments: local stdio MCP clients and CI wire harness on supported hosts;
  request bytes are untrusted even for a configured local client.
- Invariants and assets at stake: valid modern sessions remain usable; legacy clients see
  one -32002 and clean close; malformed modern candidates do not establish session state; stdout writes
  stay serialized; broken stdout yields non-zero/Error/no SIGPIPE.
- Accepted failure classes: none newly accepted. Existing unbounded line buffering remains
  unchanged; this change adds no new size policy.
- Covered elsewhere: rmcp owns typed metadata semantics and modern per-request rejection;
  envelope validator owns malformed JSON/duplicate envelope keys; existing posture checks
  own authorization of advertised and called tools; #830 test owns broken-stdout invariant.

## Threat model

- Boundary inventory: existing client stdin → envelope validator → rmcp dispatch; no new
  boundary. The modern first-request path is restored to rmcp.
- Actor model: untrusted local MCP clients can choose method, IDs, envelope and metadata.
- Control per boundary: retain envelope validation, reuse typed rmcp required-field checks,
  retain downstream tool posture checks and existing stdout mutex. Legacy error is opaque.
- Explicitly out of scope: no new threats excluded from the frozen outcome; unrelated email
  content sanitization is held by the existing content pipeline and adversarial corpus.

## Validation

Run focused `cargo nextest run -p rimap-server -E 'binary(mcp_wire_negative)'` against the
production stdio binary, with a new modern-first test failing -32002 before the fix. Cover
session latch, metadata errors, optional clientInfo, ping and invalid-envelope transition.
Run `just fmt-check`, `just lint`, and one coordinated background `just ci` before push.
ADR prose is human-reviewed against pinned rmcp3.1.4 source and #830 test: a prose-search test
cannot establish whether its reasoning accurately describes dependency and local policy.
