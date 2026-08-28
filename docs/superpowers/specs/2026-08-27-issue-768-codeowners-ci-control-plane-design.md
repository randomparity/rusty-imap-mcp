# CODEOWNERS CI control-plane coverage — design

Issue: [#768](https://github.com/randomparity/rusty-imap-mcp/issues/768).
Decision: [ADR-0028](../../ADR/0028-advisory-codeowners-cover-ci-control-plane.md).

## Frozen scope

- **Scope identity:** issue #768, token `q768-f147762e`.
- **Outcome:** decide and document the complete advisory CODEOWNERS path set and
  make `.github/CODEOWNERS` match it.
- **Completion criteria:** record the decision in the CODEOWNERS header; make
  entries match it; deliver a branch for which GitHub reports no CODEOWNERS
  errors.
- **Provenance:** issue #768; issue #744 and merged PR #764; the operator's
  `$adept:quest 768` request; frozen `WORK:SCOPE` comment `5447208280`.
- **Exclusions:** branch protection, binding review, new owners, and unrelated
  CI or build behavior.
- **Surface:** `.github/CODEOWNERS`, this decision record, this specification,
  and the implementation plan.
- **Ambiguities:** none.
- **Interaction:** interactive.

## Decision boundary

CODEOWNERS will cover dedicated CI control-plane files: standalone repository
files and directories whose primary purpose is to select, configure, or
implement required checks and automated fuzz builds. Existing coverage of
`.github/`, `scripts/`, and `deny.toml` remains. Coverage expands to `justfile`,
`.pre-commit-config.yaml`, `.config/nextest.toml`, `.clusterfuzzlite/`,
`.dockerignore`, `clippy.toml`, `rustfmt.toml`, `typos.toml`, and
`sonar-project.properties`. Those surfaces respectively select guardrail
recipes; configure commit and push hooks, test execution, compiler lints,
formatting, typo exclusions, and Sonar analysis; or define and bound the fuzz
container build context.

Multipurpose build inputs such as `Cargo.toml`, `Cargo.lock`, and
`rust-toolchain.toml` are outside the selected boundary. They affect compiled
inputs and may carry lint settings, but configuring gates is not their primary
purpose. `.cargo/mutants.toml` is also outside because mutation testing is not a
required CI check. This keeps the policy tied to dedicated control-plane files
and avoids assigning the owner on routine dependency updates if the policy
later becomes binding.

The CODEOWNERS header will state the inclusion rule, enumerate the covered
groups, and name the general-build-input exclusion. The existing advisory
posture and solo-maintainer explanation remain unchanged.

## Implementation and verification

Add exact root-anchored patterns for the seven files and two directories. Keep
one owner per line and the existing `@randomparity` identity. A focused
pre-change assertion must demonstrate that the nine patterns are absent; the
same assertion must pass after the edit. Run repository hooks, then validate
the pushed branch with GitHub's `codeowners/errors` endpoint and require an
empty `errors` array.

No runtime behavior, dependency, public contract, secret, permission, or input
parser changes. The change does not widen an untrusted actor's reach, so it
does not add a security boundary or require a threat model.

## Resume checkpoint

- Branch: `feat/codeowners-ci-config-768`
- Base branch: `main`
- Focused checks: exact-pattern assertion; `just hooks`; GitHub CODEOWNERS
  errors endpoint after push.
- Full guardrail before delivery: `just ci`.
