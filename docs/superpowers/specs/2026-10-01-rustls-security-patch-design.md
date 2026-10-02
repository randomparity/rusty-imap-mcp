# Rustls security patch

## Problem

The root, server-fuzz and IMAP compiler-fixture lockfiles resolve rustls 0.23.42.
`just deny` fails on RUSTSEC-2026-0285, blocking dependency maintenance.
Rustls 0.23.45 is the current patched 0.23 release.

## Scope

User authorization: approved incremental update plan, step 1 only.
Raise the workspace rustls requirement from 0.23 to 0.23.45 (caret-compatible).
Resolve 0.23.45 in the root lock, then use the existing fuzz and compiler-probe
realignment recipes. Review the resulting package deltas before accepting them.
Keep independent oracle dependencies unchanged; inspect its graph for rustls.
No new runtime dependency, ownership transition, API or MSRV change is required.
Remaining Dependabot/config updates and unrelated refactors belong to later steps.

## Success

The three affected tracked graphs resolve patched rustls; no vulnerable rustls
remains in the six tracked lockfiles. Existing ring/TLS feature selection stays.
`just deny`, lockfile guards, focused TLS/SMTP tests and `just ci` pass.
Real container tests require a working runtime; do not treat a silent skip as proof.
Linux/release-platform coverage remains CI-owned; local proof is macOS arm64.

## Failure model

- Actors/deployments: local/CI builds; IMAP/SMTP peers including hostile TLS peers.
- Invariants/assets: certificate pinning, TLS rejection before credentials, MSRV
  1.88.0, locked reproducible graphs, existing message/audit behavior.
- Accepted classes: live Proton Bridge unavailable locally; existing fake and
  Dovecot fixtures provide bounded transport proof, not provider certification.
- Covered elsewhere: release-platform builds by existing CI; protocol parsing
  and authorization by their unchanged implementations and regression suites.

## Threat model

- Boundaries: existing peer-controlled TLS bytes enter rustls; no boundary added
  or widened. Registry packages/checksums enter the locked build graph.
- Actors/trust: hostile remote peers; configured certificate identity and pinned
  registry checksums remain trusted. No credential or permission change.
- Controls: upstream handshake fix, existing pin verifier, rustls-only build
  policy, cargo-deny and real socket regressions. Failures must remain typed.
- Out of scope: compromised endpoints/local accounts and unrelated advisories;
  those are existing threat-model/maintenance concerns, not solved by this patch.
