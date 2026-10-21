# Rust dependency consolidation

## Authority and scope

Interaction: dispatched under the user’s dependency reconciliation request.
Scope identity: dependency unit rust, selected PRs #892 and #894.
Outcome: integrate the selected updates while preserving current behavior.
Completion criteria: legacy 2025-11-25 initialization and modern 2026-07-28
metadata-complete first requests and continuation remain functional; adversarial
content corpus including filename protection remains green; MSRV 1.88, deny,
fuzz/oracle/compiler-probe lock parity, and local `just ci` pass.
Provenance: the operator explicitly requested deduplication, selection and
necessary source fixes; the orchestrator validated this exact charter, empty
exclusions, full-spec lane and S=100 source-line denominator on 2026-10-21.
Exclusions: empty; no excluded work has an owner.
Surface: workspace manifests and lockfiles, necessary internal MCP/content code
and tests, audit comments and this design. No new runtime dependency or feature.
Ambiguities: none. A new external contract or architectural decision checkpoints.

## Problem and evidence

PR #892 updates rmcp 3.1.4 to 3.6.0, whose LATEST is now 2026-07-28.
The server’s legacy initialize gate and error retry hint currently follow LATEST;
three existing wire-negative tests fail repeatedly because they now advertise
2026-07-28 instead of 2025-11-25. `just lint` fails on three ServerInfo
deprecations. The initial PR lock also downgrades rustls-webpki .16 to .15.
The ammonia 4.2.4 update uses html5ever .40 and cssparser .38, while scraper .27
still uses .39/.37, creating duplicate tokenizer generations. Released scraper
.29 uses .40/.38 and selectors .41 and provides the existing API entry points.
PR #894 overlaps the oracle lock and must resolve against the resulting graph.

## Design

Retain ADR-0032’s split lifecycle and its existing typed metadata completeness
predicate and forward-only initialization latch. Replace deprecated ServerInfo
with ServerConfig. Explicitly pin the initialize-only version to 2025-11-25 in
the server configuration, gate, and error hint. Use the same explicit legacy
version in handshake test clients; replace the obsolete SDK-LATEST assertion
with an assertion that the SDK still knows the pinned legacy version plus the
actual response/schema assertion. Keep the SDK’s modern support available;
do not import #878’s legacy-only supported-version override.

Update the existing scraper requirement to .29 and ammonia minimum to 4.2.4,
so the sanitizer and parser share their HTML/CSS generations. Align the oracle’s
existing scraper requirement too: it documents the same-engine decoding contract.
Delete obsolete phf.13 duplicate exceptions after unification. Regenerate locks,
retaining baseline floors, then realign fuzz, oracle and compiler-probe locks
using existing recipes. Keep no extra duplicate-ban exceptions.

Update supply-chain comments from actual released source and enabled graphs.
In particular, #877’s encoding_rs no-build-script/unchanged-unsafe claim is stale:
.42 has a rustversion-controlled SIMD workaround build script and SIMD dispatch.
No audit statement or snapshot acceptance is inherited without verification.

## Failure model

Prevent: legacy clients locked out by SDK defaults; modern lifecycle intercepted;
security dependency downgrades; duplicate sanitizer tokenizer generations;
unreviewed output changes and lock drift.
Detect: compiler and strict clippy; wire-negative/conformance/transcript tests;
content corpus/oracle; MSRV, deny and parity guardrails.
Contain: all changes stay on the assigned isolated branch; no remote writes.
Accept: only host arm64 macOS is executed locally; other declared release target
architectures and Ubuntu require CI. Architecture-specific encoding changes are
reported as coverage exposure, never inferred tested from the host.

## Validation

Existing lint is the red test for the deprecated alias. Existing wire-negative
initialization cases are repeatedly red for the retry hint. Wire conformance
pins the legacy handshake; its existing modern-first cases pin modern recovery.
Run focused wire binaries and protocol tests after migration, then content tests
and existing corpus; inspect every changed snapshot and output before acceptance.
Manifest/lock coherence uses deny plus the existing parity scripts. Audit prose
has no executable semantic oracle and uses source review, not prose assertions.
The assembled result requires local `just ci` on Rust1.94 and MSRV1.88, including
real Dovecot paths under the configured usable arm64 container runtime.
