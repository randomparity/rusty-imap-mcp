# Manifest `-dev` Version Model Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Adopt bzr's manifest-`-dev` version convention (Phase 2A) — store the next planned version with a `-dev` suffix, strip it at release, and automate the post-release bump.

**Architecture:** `build.rs` stops synthesizing `-dev` (it now lives in `Cargo.toml`); it appends `+g<sha>` provenance unless HEAD is the release tag. The 8-crate workspace version is moved with `cargo set-version --workspace`; the excluded `html-oracle` tool is decoupled to path-only deps. A `post-release-bump` job in `release.yml` opens the next-`-dev` PR automatically.

**Tech Stack:** Rust workspace, `cargo-edit` (`cargo set-version`), GitHub Actions, `peter-evans/create-pull-request`.

**Spec:** [2026-07-10-dev-version-model-design.md](../specs/2026-07-10-dev-version-model-design.md) · **ADR:** [0003](../../ADR/0003-manifest-dev-version-model.md)

## Global Constraints

- Guardrails per commit: `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, relevant `cargo test`, `cargo-deny`, and for workflow changes `actionlint` + `zizmor .github/workflows/release.yml`. The umbrella is `just ci`; `check-no-openssl` and `check-tools-doc` must stay green.
- Never push directly to `main`. Branch is `feat/dev-version-model` (already created).
- CI runs `--locked` pervasively: any `Cargo.toml`/version change must regenerate and commit **both** `Cargo.lock` and `html-oracle/Cargo.lock`.
- `cargo-edit` must be installed locally for the version tasks (`cargo install cargo-edit --locked`); it is already installed in this environment.
- Line length ≤100, absolute imports only, Google-style docstrings on public APIs.

---

### Task 1: Rework the `build.rs` version composer and re-anchor the test

**Files:**
- Modify: `crates/rimap-core/build.rs`
- Modify: `crates/rimap-core/src/version.rs` (docstrings only)
- Modify: `crates/rimap-core/tests/version.rs`

**Interfaces:**
- Produces: unchanged public API (`version()`, `commit()`, `is_release()`); only the composed string semantics change.

Ordering: do this **before** the manifest bump so the intermediate state is clean (`version()` becomes `0.1.0+g<sha>` rather than a double-`-dev`).

- [ ] **Step 1: Write the failing test that pins the behavior change**

Add to `crates/rimap-core/tests/version.rs` a test asserting `build.rs` does
not synthesize its own `-dev` (any `-dev` must come only from the manifest
base). This gives a clean red→green: with manifest `0.1.0`, the old
`build.rs` appends `-dev` and fails; the new one appends only `+g…` and passes.

```rust
#[test]
fn build_script_does_not_synthesize_dev_suffix() {
    // Any `-dev` must come from the manifest base (CARGO_PKG_VERSION), never
    // from build.rs. Inspect only the part build.rs appended to the base.
    let v = version();
    let base = env!("CARGO_PKG_VERSION");
    let appended = v.strip_prefix(base).unwrap_or(v);
    assert!(
        !appended.contains("-dev"),
        "build.rs must not synthesize -dev; version() = {v:?}, base = {base:?}"
    );
}
```

Also re-anchor `release_flag_agrees_with_version_shape` (defensive: it does not
break in this PR's dev state, but the old `-dev` check fails in the
release-prep state where a stripped-clean base has no `-dev`):

```rust
#[test]
fn release_flag_agrees_with_version_shape() {
    let v = version();
    // A release build is exactly one with no `+g…` build-metadata suffix:
    // release = clean base; dev / release-prep / no-git all carry `+g…`.
    let has_build_metadata = v.contains("+g");
    assert_eq!(
        is_release(),
        !has_build_metadata,
        "is_release() must be true exactly when version() lacks a +g build-metadata suffix"
    );
}
```

- [ ] **Step 2: Run the new test — expect FAIL under the old `build.rs`**

Run: `cargo test -p rimap-core --test version build_script_does_not_synthesize_dev_suffix`
Expected: FAIL — old `build.rs` emits `0.1.0-dev+g<sha>`; stripping base `0.1.0`
leaves `-dev+g<sha>`, which contains `-dev`. (This is the true red; the
re-anchored `release_flag_*` test passes under both old and new here, so it is
a correctness guard, not the red.)

- [ ] **Step 3: Change `build.rs` to stop synthesizing `-dev`**

In `crates/rimap-core/build.rs`, change the dev-branch version composition — the only logic change is dropping the `-dev` literal:

```rust
        (format!("{base}{suffix}"), commit)
```
(was `format!("{base}-dev{suffix}")`).

Update the module doc comment (lines 3-13) to describe the new model:

```rust
//! - `RIMAP_VERSION` — the user-facing version string. Bare `CARGO_PKG_VERSION`
//!   when HEAD is exactly the tag `v<CARGO_PKG_VERSION>` (a clean base);
//!   otherwise `<CARGO_PKG_VERSION>+g<short-sha>[.dirty]`. The `-dev`
//!   pre-release now lives in `Cargo.toml` (the next planned version), so this
//!   script only appends git provenance — it never synthesizes `-dev`.
```

- [ ] **Step 4: Update `version.rs` docstrings**

In `crates/rimap-core/src/version.rs`, update the `version()` doc:

```rust
/// The user-facing version string.
///
/// `X.Y.Z` for release builds (HEAD is exactly the tag `v<X.Y.Z>`);
/// `X.Y.Z[-dev]+g<short-sha>[.dirty]` otherwise, where the `-dev` (if any)
/// comes from the workspace `Cargo.toml` version. Outside a git checkout the
/// suffix is `+gunknown`.
```

- [ ] **Step 5: Run the version tests — expect PASS**

Run: `cargo test -p rimap-core --test version`
Expected: PASS. With manifest `0.1.0`, `version()` is `0.1.0+g<sha>` (no `-dev`, has `+g`), `is_release()==false`, `!has_build_metadata==false` → holds. `version_starts_with_workspace_base` holds (`0.1.0+g…`.starts_with(`0.1.0`)).

- [ ] **Step 6: Guardrails + commit**

Run: `cargo fmt --check && cargo clippy -p rimap-core --all-targets -- -D warnings && cargo test -p rimap-core`
```bash
git add crates/rimap-core/build.rs crates/rimap-core/src/version.rs crates/rimap-core/tests/version.rs
git commit -m "feat(version): compose git provenance without synthesizing -dev"
```

---

### Task 2: Move the workspace to `0.1.1-dev` and decouple `html-oracle`

**Files:**
- Modify (via tool): `Cargo.toml`, all 8 `crates/*/Cargo.toml`, `Cargo.lock`
- Modify: `html-oracle/Cargo.toml` (path-only intra-deps), `html-oracle/Cargo.lock`
- Modify: `AGENTS.md` (de-hardcode `0.1.0`)

**Interfaces:**
- Consumes: Task 1's `build.rs` (so dev builds now read `0.1.1-dev` → `0.1.1-dev+g<sha>`).

- [ ] **Step 1: Decouple `html-oracle` intra-deps to path-only**

In `html-oracle/Cargo.toml`, drop the `version` key from the two intra-workspace deps (lines ~15-16):

```toml
rimap-content = { path = "../crates/rimap-content", features = ["test-support"] }
rimap-core = { path = "../crates/rimap-core" }
```

- [ ] **Step 2: Bump the workspace version with `cargo set-version`**

Run:
```bash
cargo set-version --workspace 0.1.1-dev
cargo update --workspace                # refresh Cargo.lock member versions (no compile)
cargo update --manifest-path html-oracle/Cargo.toml -p rimap-core -p rimap-content
```

- [ ] **Step 3: Verify resolution and the version test in the dev state**

Run:
```bash
cargo build --locked --workspace
cargo test -p rimap-core --test version
cargo build --locked --manifest-path html-oracle/Cargo.toml
```
Expected: all succeed. `version()` is now `0.1.1-dev+g<sha>`; the re-anchored test still holds. `--locked` proves both lockfiles are in sync. If `html-oracle`'s `--locked` build fails, re-run its `cargo update` for every `rimap-*` crate the lock lists (`rg 'name = "rimap-' html-oracle/Cargo.lock`).

- [ ] **Step 4: De-hardcode the version in `AGENTS.md`**

In `AGENTS.md` (~line 44), change the parenthetical so it does not pin a released version, e.g. `The workspace (v0.1.0) is feature-complete` → `The workspace is feature-complete for its 0.1.x line`. (Preserve surrounding wording.)

- [ ] **Step 5: Guardrails + commit**

Run: `cargo fmt --check && cargo clippy --all-targets --all-features -- -D warnings && cargo test -p rimap-core && cargo deny check && just check-no-openssl`
```bash
git add Cargo.toml crates/*/Cargo.toml Cargo.lock html-oracle/Cargo.toml html-oracle/Cargo.lock AGENTS.md
git commit -m "chore(version): move workspace to 0.1.1-dev; decouple html-oracle deps"
```

---

### Task 3: CHANGELOG `## [Unreleased]` and rewritten `RELEASING.md`

**Files:**
- Modify: `CHANGELOG.md`, `RELEASING.md`

- [ ] **Step 1: Add the `## [Unreleased]` section**

In `CHANGELOG.md`, insert directly above `## [0.1.0] - 2026-07-10`:

```markdown
## [Unreleased]

### Changed

- Version model: `Cargo.toml` now carries the next planned version with a
  `-dev` suffix (e.g. `0.1.1-dev`); release-prep strips it and a
  `post-release-bump` job re-bumps after each release. See ADR-0003.

```

- [ ] **Step 2: Confirm the release-notes extractor is unaffected**

Run: `awk -v v="0.1.0" '$0 ~ "^## \\[" v "\\]" {print; exit}' CHANGELOG.md`
Expected: prints `## [0.1.0] - 2026-07-10` (the `## [Unreleased]` heading never matches a numeric version).

- [ ] **Step 3: Rewrite the `RELEASING.md` version convention + checklist**

Replace the "Release checklist" version steps with the bzr flow. Add a "Version-number convention" section stating: `main` carries `X.Y.(Z+1)-dev` between releases; the actual bump is chosen at release-prep. Rewrite checklist step 1 to:

```markdown
1. On a `release/vX.Y.Z-prep` branch, run
   `cargo set-version --workspace X.Y.Z` (strips `-dev`; choose patch/minor per
   what landed), then `cargo build` to refresh `Cargo.lock`. Requires
   `cargo-edit` (`cargo install cargo-edit --locked`).
2. Rename the CHANGELOG `## [Unreleased]` heading to `## [X.Y.Z] - YYYY-MM-DD`.
```

Add a note under "What automation does" describing the `post-release-bump` job and the **hard prerequisite** that its PR needs a CI kick-off (push an empty commit or run `just ci` locally) before it can merge, because `GITHUB_TOKEN`-opened PRs do not trigger `pull_request` CI.

- [ ] **Step 4: Guardrails + commit**

Run: `just check-tools-doc` (if it touches docs indexing) and re-run the extractor check.
```bash
git add CHANGELOG.md RELEASING.md
git commit -m "docs(release): adopt -dev version convention and bump flow"
```

---

### Task 4: Add the `post-release-bump` job to `release.yml`

**Files:**
- Modify: `.github/workflows/release.yml`

**Interfaces:**
- Consumes: the `release` job (via `needs`).

- [ ] **Step 1: Look up and pin the action + cargo-edit versions**

Pin `peter-evans/create-pull-request`: `gh api repos/peter-evans/create-pull-request/releases/latest --jq '.tag_name'`, then resolve the tag to its commit SHA (`gh api repos/peter-evans/create-pull-request/git/ref/tags/<tag> --jq '.object.sha'`). Use the 40-char SHA with a `# <tag>` comment.

Also look up the current stable `cargo-edit` version (`cargo search cargo-edit` or crates.io) and pin it in the install step below — do not assume a version from memory.

- [ ] **Step 2: Add the job**

Append to `.github/workflows/release.yml` (after `bottles-merge`):

```yaml
  post-release-bump:
    name: Open post-release version-bump PR
    needs: [release]
    if: ${{ github.event_name == 'push' && !contains(github.ref_name, '-') }}
    runs-on: ubuntu-24.04
    permissions:
      contents: write
      pull-requests: write
    steps:
      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0  # v7.0.0
        with:
          ref: main
          persist-credentials: false
      - uses: dtolnay/rust-toolchain@e97e2d8cc328f1b50210efc529dca0028893a2d9  # v1 (toolchain: stable) # zizmor: ignore[superfluous-actions]
        with:
          toolchain: stable
      - name: Install cargo-edit
        run: cargo install cargo-edit --locked --version <PINNED_VERSION>  # from Step 1
      - name: Compute next -dev and rewrite versions
        id: bump
        env:
          TAG: ${{ github.ref_name }}
        run: |
          set -euo pipefail
          released="${TAG#v}"
          IFS=. read -r major minor patch <<< "$released"
          next="${major}.${minor}.$((patch + 1))-dev"
          cargo set-version --workspace "$next"
          cargo update --workspace
          cargo update --manifest-path html-oracle/Cargo.toml -p rimap-core -p rimap-content
          if ! grep -q '^## \[Unreleased\]' CHANGELOG.md; then
            awk 'BEGIN{done=0} /^## \[/ && !done {print "## [Unreleased]"; print ""; done=1} {print}' \
              CHANGELOG.md > CHANGELOG.tmp && mv CHANGELOG.tmp CHANGELOG.md
          fi
          echo "next=$next" >> "$GITHUB_OUTPUT"
      - uses: peter-evans/create-pull-request@<PINNED_SHA>  # <tag>
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
          base: main
          branch: chore/post-release-bump-v${{ steps.bump.outputs.next }}
          commit-message: "chore: bump version to ${{ steps.bump.outputs.next }} after ${{ github.ref_name }} release"
          title: "chore: bump version to ${{ steps.bump.outputs.next }} after ${{ github.ref_name }}"
          add-paths: |
            Cargo.toml
            Cargo.lock
            crates/*/Cargo.toml
            html-oracle/Cargo.lock
            CHANGELOG.md
          body: |
            Automated post-release bump to `${{ steps.bump.outputs.next }}` after the `${{ github.ref_name }}` release (ADR-0003).

            **CI kick-off required before merge:** PRs opened by `GITHUB_TOKEN` do not trigger `pull_request` CI. Push an empty commit to this branch, or run `just ci` locally, to get a green signal. If the next release is a minor/major bump, edit the version on this PR first.
```

The `awk` prepend inserts `## [Unreleased]` immediately **before the first
`## [` version heading** (below the Keep-a-Changelog preamble), matching Task 3's
manual placement — not after the title line.

- [ ] **Step 3: Lint the workflow**

Run: `actionlint .github/workflows/release.yml && zizmor .github/workflows/release.yml`
Expected: no errors; no new zizmor findings.

- [ ] **Step 4: Unit-check the version math locally**

Run (sanity, not committed):
```bash
for t in v0.1.1 v0.2.0 v1.0.0 v0.9.9; do
  r="${t#v}"; IFS=. read -r a b c <<< "$r"; echo "$t -> ${a}.${b}.$((c+1))-dev"
done
```
Expected: `v0.1.1 -> 0.1.2-dev`, `v0.2.0 -> 0.2.1-dev`, `v1.0.0 -> 1.0.1-dev`, `v0.9.9 -> 0.9.10-dev`.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "ci(release): add post-release version-bump PR job"
```

---

### Final verification (before opening the PR)

Run the full local guardrail sweep once — the per-task tests only covered
`rimap-core`, but version strings are embedded in `rimap-server` (`--version`,
MCP `server_info.version`) and audit records, so the whole workspace must be
exercised against the `0.1.1-dev` manifest:

- [ ] `just ci` (the umbrella: fmt-check, clippy, test, test-MSRV, deny,
  mcp-conformance-node, check-tools-doc) — note `typos`/`pr-smoke` are
  non-required and may be pre-existing red on `main`.
- [ ] `actionlint .github/workflows/release.yml && zizmor .github/workflows/release.yml`
- [ ] `cargo build --locked --workspace && cargo build --locked --manifest-path html-oracle/Cargo.toml`
  (both lockfiles in sync).

---

## Self-Review

- **Spec coverage:** Task 1 (build.rs + test + version.rs), Task 2 (bump + html-oracle + locks + AGENTS.md), Task 3 (CHANGELOG + RELEASING.md), Task 4 (post-release-bump job) cover every item in the spec's "Files touched". `check-release-version.sh` is intentionally unchanged (spec §Release flow).
- **Ordering:** Task 1 before Task 2 keeps the intermediate state clean; Task 2 must precede any release. Tasks 3–4 are independent of each other.
- **Type consistency:** `version()`/`is_release()`/`commit()` signatures unchanged across tasks; the `next` output format (`X.Y.Z-dev`) matches `cargo set-version` input.
- **Guardrail note:** the `--locked` builds in Task 2 Step 3 are the real gate that both lockfiles are refreshed.
