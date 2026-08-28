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

CODEOWNERS will cover the CI control plane: repository files that select,
configure, or implement required checks and automated fuzz builds. Existing
coverage of `.github/`, `scripts/`, and `deny.toml` remains. Coverage expands to
`justfile`, `.pre-commit-config.yaml`, `.config/nextest.toml`, and
`.clusterfuzzlite/` because those surfaces respectively select the guardrail
recipes, configure commit and push hooks, configure the CI test runner, and
define the fuzz build.

General build inputs such as `Cargo.toml`, `Cargo.lock`, and
`rust-toolchain.toml` are outside the selected boundary. They affect compiled
inputs but do not select which required checks run. This keeps the policy tied
to the issue's protection rationale and avoids assigning the owner on routine
dependency updates if the policy later becomes binding.

The CODEOWNERS header will state the inclusion rule, enumerate the covered
groups, and name the general-build-input exclusion. The existing advisory
posture and solo-maintainer explanation remain unchanged.

## Implementation and verification

Add exact root-anchored patterns for the three files and one directory. Keep
one owner per line and the existing `@randomparity` identity. A focused
pre-change assertion must demonstrate that the four patterns are absent; the
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
