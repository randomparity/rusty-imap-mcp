# ADR-0009: Golden agent-transcript snapshots on the fake, not Dovecot

**Status:** Accepted · 2026-07-13 · issue [#524](https://github.com/randomparity/rusty-imap-mcp/issues/524)

## Context

The server's agent-facing surface — `initialize` instructions, the advertised
tool catalog (descriptions + schemas), and each tool's response shape
(`meta` / `untrusted` / `security_warnings`, sanitized content) — is the "UI for
agents" that both usability and prompt-injection defenses depend on. Struct-level
schema-drift gates pin individual shapes, but nothing pins the **rendered
transcript an agent sees across a realistic multi-step session**. #524 asks for
golden ("day in the life") transcript snapshots that turn any change to that
surface into a reviewable diff.

A golden/characterization snapshot only guards drift if it **actually runs in the
gating CI**. That constraint drives the backend choice, because the two available
IMAP backends have opposite CI-visibility properties:

- **Seeded Dovecot** (`e2e_wire*` harness): realistic, but **container-gated** —
  it *silent-skips* when no runtime is present (`RIMAP_REQUIRE_DOCKER=1` flips
  skips to failures only in CI lanes that opt in). Its dynamic UIDs, dates, and
  ports need heavy normalization.
- **In-process fake** (`crates/rimap-fake-imap`, ADR-0008): container-free and
  **PR-blocking on every runner**, byte-deterministic (scripted UIDs, dates,
  sizes, and body bytes), and — uniquely — able to serve **adversarial** message
  bytes a conformant server never produces (the hostile fixture #524 calls for).

## Decision

Drive **all** #524 transcript snapshots against the in-process fake, and pin
**two** flows (`triage`, `cleanup`) as the headline snapshots, with the hostile
`fetch_message` folded into the triage flow.

Normalization is deliberately minimal — ports, temp paths, server version, and
any server-generated timestamp — because byte-determinism removes the rest.
Everything else (tool descriptions, warning text, `meta` fields, sanitized body
text, scripted envelope values) is left visible on purpose: it is the payload the
snapshot exists to guard. The `normalize` helper is a pure, unit-tested function
so the mask list is itself falsifiable, not an opaque part of a large snapshot.

## Consequences

- The transcript snapshots run on **every PR** on every runner (no Docker), so a
  reworded `security_warning`, a dropped `meta` field, or a silent sanitizer
  change fails CI as a `.snap` diff — the drift-guard the issue wants.
- Normalization is small and each mask is justified, so the snapshots stay
  **faithful** (they don't mask the drift they exist to catch).
- The hostile fixture is expressible: the fake emits injection-corpus `.eml`
  bytes as the `UID FETCH BODY[]` literal, so the sanitized output and
  `security_warnings` for a known attack class are pinned in-line.
- The cost is hand-scripting the full IMAP dialog (SELECT/EXAMINE, UID
  SEARCH/FETCH/STORE, APPEND, UID MOVE/EXPUNGE) per flow, calibrated via the
  established `server.recorded()` + `DumpOnPanic` TDD workflow. This is the first
  fake scenario to script `STORE`/`APPEND`/`MOVE`/`EXPUNGE` and multi-tool
  sessions on one connection.
- Intentional changes to the agent surface update two `.snap` files via
  `cargo insta review` — a reviewed, one-command update, documented in `AGENTS.md`.
- Realistic conformance behavior remains guarded separately by the Dovecot
  `e2e_wire` suite; this ADR does not change that split.

## Considered & rejected

- **Seeded-Dovecot transcripts for the realistic flows** (the issue's original
  framing, and a natural reading of "seeded Dovecot state"): container-gated, so
  the snapshot silent-skips on any runner without Docker and fails to guard drift
  on exactly those PRs — a golden test that doesn't run is not a guard. Also needs
  heavy UID/date/port normalization, which erodes faithfulness. The owner's #524
  comment already steers the hostile fixture to the fake and notes the fake
  "shrinks the normalization problem." Rejected as the backend for the pinned
  snapshots; Dovecot keeps its conformance role.
- **Both backends** (fake snapshot for the PR-gate + Dovecot snapshot for
  realism): roughly double the harness, two normalizers, and two `.snap` sets to
  keep in sync, for marginal added assurance over the fake — the realistic path is
  already covered behaviorally by `e2e_wire`. Rejected as disproportionate.
- **Snapshot the response bodies only (drop the request side):** loses the
  self-describing "which call produced this" context for near-zero churn savings
  (request args are authored in the test and change only when the test does).
  Rejected.
- **A third hostile-only snapshot:** the issue's triage flow explicitly fetches
  "one clean, one hostile fixture," so the hostile output belongs in the triage
  snapshot. A separate snapshot is a later option if triage grows unwieldy, not a
  day-one requirement. Deferred, not adopted.
