# CODEOWNERS CI control-plane coverage — design

Issue: [#768](https://github.com/randomparity/rusty-imap-mcp/issues/768).
Decision: [ADR-0028](../../ADR/0028-advisory-codeowners-cover-ci-control-plane.md).

## Frozen scope

- **Scope identity:** issue #768, token `q768-f147762e`.
- **Outcome:** decide and document the complete advisory CODEOWNERS path set,
  make `.github/CODEOWNERS` match it, and replace the yanked `chacha20` lock
  entry that blocked delivery.
- **Completion criteria:** record the decision in the CODEOWNERS header; make
  entries match it; deliver a branch for which GitHub reports no CODEOWNERS
  errors; resolve `chacha20` without the yanked `0.10.0` release across every
  coupled lockfile; keep lock parity, MSRV, and the full repository guardrail
  suite green.
- **Provenance:** issue #768; issue #744 and merged PR #764; the operator's
  `$adept:quest 768` request; frozen `WORK:SCOPE` comment `5447208280`; the
  operator's choice `2` authorizing the minimum dependency-lock correction;
  authorization trajectory comment `5448022536`; charter-cycle-2
  `WORK:SCOPE` comment `5448022972`.
- **Exclusions:** branch protection, binding review, new owners, manifest
  requirement changes, unrelated package upgrades, runtime features, and
  unrelated CI or build behavior.
- **Surface:** `.github/CODEOWNERS`, this decision record, this specification,
  the implementation plan, `Cargo.lock`,
  `crates/rimap-audit/tests/fixtures/e0639-probe/Cargo.lock`,
  `crates/rimap-server/fuzz/Cargo.lock`, and `fuzz/Cargo.lock`.
- **Ambiguities:** none.
- **Interaction:** interactive.

## Decision boundary

CODEOWNERS will cover dedicated CI control-plane files: repository-level
standalone files and external-automation directories whose primary purpose is
to select, configure, or implement required checks and automated fuzz builds,
plus supply-chain policy files wherever they live. Existing coverage of
`.github/`, `scripts/`, and `deny.toml` remains. Coverage expands to `justfile`,
`.pre-commit-config.yaml`, `.config/nextest.toml`, `.clusterfuzzlite/`,
`.dockerignore`, `clippy.toml`, `rustfmt.toml`, `typos.toml`, and
`sonar-project.properties`, plus `html-oracle/deny.toml`. Those surfaces
respectively select guardrail recipes; configure commit and push hooks, test
execution, compiler lints, formatting, typo exclusions, and Sonar analysis;
define and bound the fuzz container build context; or govern the nested
oracle's required supply-chain audit.

Multipurpose build inputs such as `Cargo.toml`, `Cargo.lock`, and
`rust-toolchain.toml` are outside the selected boundary. They affect compiled
inputs and may carry lint settings, but configuring gates is not their primary
purpose. Component-local harness configuration and fixtures remain ordinary
source rather than recursively expanding this ownership policy.
`.cargo/mutants.toml` is also outside because mutation testing is not a required
CI check. This keeps the policy tied to dedicated control-plane files and
avoids assigning the owner on routine dependency updates if the policy later
becomes binding.

The CODEOWNERS header will state the inclusion rule, enumerate the covered
groups, and name the general-build-input exclusion. The existing advisory
posture and solo-maintainer explanation remain unchanged.

## Implementation and verification

Add exact root-anchored patterns for the nine files and one directory. Keep one
owner per line and the existing `@randomparity` identity. Run one focused
presence assertion against all ten patterns: require a nonzero exit before the
edit and exit zero after the edit. Run repository hooks, then validate
the pushed branch with GitHub's `codeowners/errors` endpoint and require an
empty `errors` array.

Delivery encountered a newly yanked locked transitive release after the first
full guardrail run. Charter cycle 2 authorizes only the minimum correction:
resolve `chacha20` from `0.10.0` to a non-yanked compatible release in the root
lockfile and regenerate only lockfiles coupled by the repository parity gates.
Do not change a manifest requirement or update another package. Lockfiles
remain outside the CODEOWNERS boundary because they are multipurpose build
inputs, not dedicated CI control-plane policy.

The correction changes supply-chain resolution but not runtime features,
public contracts, secrets, permissions, or input parsers. Verify the exact
four-lockfile diff, fuzz and compiler-probe lock parity, MSRV behavior through
the repository suite, advisories and bans, and the full `just ci` guardrail.

## Resume checkpoint

- Branch: `feat/codeowners-ci-config-768`
- Base branch: `main`
- Focused checks: exact-pattern assertion; exact four-lockfile package diff;
  fuzz and compiler-probe lock parity; advisories and bans; `just hooks`;
  GitHub CODEOWNERS errors endpoint after push.
- Full guardrail before delivery: `just ci`.
