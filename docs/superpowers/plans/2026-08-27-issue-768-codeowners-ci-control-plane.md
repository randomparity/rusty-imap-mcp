# CODEOWNERS CI Control-Plane Coverage Implementation Plan

**Goal:** Make advisory CODEOWNERS coverage match the documented CI
control-plane boundary selected for issue #768.

**Architecture:** `.github/CODEOWNERS` remains the sole executable policy. Its
header explains the boundary, and ten exact root-anchored patterns add the
previously omitted control-plane surfaces without owning general build inputs.
Charter cycle 2 also replaces the yanked `chacha20` lock entry across the four
lockfiles coupled by repository parity gates, without changing manifests.

**Tech Stack:** GitHub CODEOWNERS syntax, Markdown comments, shell assertions,
GitHub REST API.

**Spec:** `docs/superpowers/specs/2026-08-27-issue-768-codeowners-ci-control-plane-design.md`

## Global Constraints

- Keep CODEOWNERS advisory; do not change branch protection.
- Keep `@randomparity` as the only owner.
- Add no manifest requirement, script, runtime behavior, public contract, or
  new guardrail; update no package except the yanked `chacha20` lock entry.
- Own exactly `/justfile`, `/.pre-commit-config.yaml`,
  `/.config/nextest.toml`, `/.clusterfuzzlite/`, `/.dockerignore`,
  `/clippy.toml`, `/rustfmt.toml`, `/typos.toml`, and
  `/sonar-project.properties`, plus `/html-oracle/deny.toml` in this change.
- Preserve existing `.github/`, `scripts/`, and `deny.toml` coverage.
- Run `just ci` before delivery and require GitHub's CODEOWNERS error list to
  be empty for the pushed branch.

## Task 1: Record and apply the selected path set

**Files:**
- Modify: `.github/CODEOWNERS`

**Interfaces:**
- Consumes: GitHub's root-anchored CODEOWNERS pattern syntax and existing
  `@randomparity` owner identity.
- Produces: automatic reviewer assignment and owner attribution for the ten
  selected control-plane surfaces.

- [ ] Run a shell assertion that requires all ten exact patterns and confirm
  it fails because none is currently present:
  `for p in '/justfile' '/.pre-commit-config.yaml' '/.config/nextest.toml' '/.clusterfuzzlite/' '/.dockerignore' '/clippy.toml' '/rustfmt.toml' '/typos.toml' '/sonar-project.properties' '/html-oracle/deny.toml'; do rg -Fxq "$p @randomparity" .github/CODEOWNERS || exit 1; done`.
- [ ] Update the header to state the control-plane inclusion rule and the
  general-build-input exclusion. Add the ten exact patterns, grouped with
  short comments describing the protection each provides.
- [ ] Re-run the exact-pattern assertion and expect exit 0.
- [ ] Run `just hooks` and expect every hook to pass.
- [ ] Commit the implementation as one conventional commit.

**Acceptance criteria:** the header records the full boundary; the entries
match it; existing coverage and advisory posture remain; focused and hook
checks pass.

## Task 2: Replace the yanked lock entry

**Files:**
- Modify: `Cargo.lock`
- Modify: `crates/rimap-audit/tests/fixtures/e0639-probe/Cargo.lock`
- Modify: `crates/rimap-server/fuzz/Cargo.lock`
- Modify: `fuzz/Cargo.lock`

**Interfaces:**
- Consumes: the existing manifest requirements and repository lock-parity
  recipes.
- Produces: non-yanked, parity-aligned `chacha20` resolution without changing
  any manifest requirement or unrelated package.

- [ ] Update only `chacha20` from yanked `0.10.0` to a compatible non-yanked
  release in the root lockfile.
- [ ] Regenerate only the fuzz and compiler-probe lockfiles coupled by parity
  gates.
- [ ] Verify the four lockfile diffs contain no package change except
  `chacha20` and its checksum.
- [ ] Run `just check-fuzz-lock-parity`,
  `just check-compiler-probe-locks`, and `cargo deny check advisories bans`.
- [ ] Run `cargo check --workspace --lib --bins --locked` to cover the locked
  workspace before the full suite.
- [ ] Commit the lock correction as one conventional commit.

**Acceptance criteria:** no lockfile resolves yanked `chacha20` `0.10.0`; all
four resolve the same compatible replacement; manifests and unrelated package
resolutions are unchanged; focused parity, advisory, and workspace checks pass.

## Task 3: Verify the complete branch and publish

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
- Current phase: implementation and charter-cycle-2 lock correction complete;
  final review and full guardrails next.
