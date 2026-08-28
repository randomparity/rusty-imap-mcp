# CODEOWNERS CI Control-Plane Coverage Implementation Plan

**Goal:** Make advisory CODEOWNERS coverage match the documented CI
control-plane boundary selected for issue #768.

**Architecture:** `.github/CODEOWNERS` remains the sole executable policy. Its
header explains the boundary, and four exact root-anchored patterns add the
previously omitted control-plane surfaces without owning general build inputs.

**Tech Stack:** GitHub CODEOWNERS syntax, Markdown comments, shell assertions,
GitHub REST API.

**Spec:** `docs/superpowers/specs/2026-08-27-issue-768-codeowners-ci-control-plane-design.md`

## Global Constraints

- Keep CODEOWNERS advisory; do not change branch protection.
- Keep `@randomparity` as the only owner.
- Add no dependency, script, generated artifact, runtime behavior, public
  contract, or new guardrail.
- Own exactly `/justfile`, `/.pre-commit-config.yaml`,
  `/.config/nextest.toml`, and `/.clusterfuzzlite/` in this change.
- Preserve existing `.github/`, `scripts/`, and `deny.toml` coverage.
- Run `just ci` before delivery and require GitHub's CODEOWNERS error list to
  be empty for the pushed branch.

## Task 1: Record and apply the selected path set

**Files:**
- Modify: `.github/CODEOWNERS`

**Interfaces:**
- Consumes: GitHub's root-anchored CODEOWNERS pattern syntax and existing
  `@randomparity` owner identity.
- Produces: automatic reviewer assignment and owner attribution for the four
  selected control-plane surfaces.

- [ ] Run a shell assertion that requires all four exact patterns and confirm
  it fails because none is currently present:
  `for p in '/justfile' '/.pre-commit-config.yaml' '/.config/nextest.toml' '/.clusterfuzzlite/'; do rg -Fxq "$p @randomparity" .github/CODEOWNERS || exit 1; done`.
- [ ] Update the header to state the control-plane inclusion rule and the
  general-build-input exclusion. Add the four exact patterns, grouped with
  short comments describing the protection each provides.
- [ ] Re-run the exact-pattern assertion and expect exit 0.
- [ ] Run `just hooks` and expect every hook to pass.
- [ ] Commit the implementation as one conventional commit.

**Acceptance criteria:** the header records the full boundary; the entries
match it; existing coverage and advisory posture remain; focused and hook
checks pass.

## Task 2: Verify the complete branch and publish

**Files:** no additional repository files.

**Interfaces:**
- Consumes: the committed branch and GitHub's CODEOWNERS parser.
- Produces: local-CI proof and an empty parser-error response for the delivered
  branch.

- [ ] Run `just ci` in the background and expect exit 0.
- [ ] Push the branch through the delivery workflow.
- [ ] Run
  `gh api 'repos/randomparity/rusty-imap-mcp/codeowners/errors?ref=feat/codeowners-ci-config-768'`
  and require `{"errors":[]}`.

**Acceptance criteria:** `just ci` passes; the pushed branch has no CODEOWNERS
parser or owner errors; the PR closes #768.

## Resume checkpoint

- Branch: `feat/codeowners-ci-config-768`
- Base branch: `main`
- Guardrails: focused exact-pattern assertion, `just hooks`, `just ci`, GitHub
  CODEOWNERS errors endpoint.
- Current phase: design complete; scope audit next.
