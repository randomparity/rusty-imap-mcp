# Manifest `-dev` Version Model Design

Date: 2026-07-10
Status: Approved (pending implementation plan)

## Summary

Adopt bzr's manifest-`-dev` version convention (Phase 2A of the bzr-parity
release process, [ADR-0002](../../ADR/0002-phased-bzr-release-parity-and-direct-publish.md)).
Between releases, `[workspace.package].version` in `Cargo.toml` carries a
SemVer pre-release `-dev` suffix marking the **next** planned release
(e.g. after `v0.1.0` ships, `main` lives at `0.1.1-dev`). At release time a
release-prep PR strips `-dev` to the clean version the tag points at; after
the release publishes, an automated `post-release-bump` job opens a PR
bumping the manifest to the next `-dev` and prepending a `## [Unreleased]`
CHANGELOG section.

This reverses the "no `-dev` in the manifest, no automatic version bumping"
non-goals of the [2026-05-11 release-versioning design](2026-05-11-release-versioning-design.md),
as anticipated by ADR-0002. It is recorded in
[ADR-0003](../../ADR/0003-manifest-dev-version-model.md).

## Motivation

The current model stores the **last released** version in the manifest
(`0.1.0`) and `build.rs` synthesizes `-dev` for non-release builds, yielding
`0.1.0-dev+g<sha>` for every commit *after* 0.1.0 shipped. Per SemVer,
`0.1.0-dev` is a **pre-release of 0.1.0** — it orders *before* the released
`0.1.0`. So today's post-release dev builds sort as if they predate the
release they follow. Storing the *next* version with `-dev` fixes the
ordering: `0.1.1-dev` correctly sorts after `0.1.0` and before `0.1.1`, and
makes dev builds unambiguously "working toward the next release."

It also establishes the clean-version-at-tag flow that Phase 2B (crates.io
publish, [#544](https://github.com/randomparity/rusty-imap-mcp/issues/544))
consumes: crates.io publishes only clean SemVer, and the `-`-in-version guard
keeps `-dev` builds from ever publishing.

## Goals

- Store the next planned version with a `-dev` suffix in `Cargo.toml`, so dev
  builds identify as "heading toward X.Y.Z", ordered correctly by SemVer.
- Keep `build.rs` the single composer of the runtime version string, now
  *appending* git provenance rather than *synthesizing* `-dev`.
- Automate the post-release bump so `main` never lingers on a released
  version, mirroring bzr's `post-release-bump` job.
- Keep the existing `verify-tag` / `check-release-version.sh` guards, which
  now also catch a forgotten `-dev` strip at tag time.
- Add no new runtime dependencies. Reuse `git` and the existing CI tooling.

## Non-goals

- Pre-release identifiers beyond `-dev` (`-rc.N`, `-beta.N`): the release
  guards still reject any `-` at tag time. (bzr supports RC tags; deferred.)
- crates.io publish (Phase 2B, #544) and deb/rpm/manpages/installers
  (Phase 2C, [#545](https://github.com/randomparity/rusty-imap-mcp/issues/545)).
- Conventional-commits-driven CHANGELOG generation.

## Version model

`base` = `[workspace.package].version` from `Cargo.toml`.
`at_tag` = HEAD is exactly the tag `v<base>` (so `base` must be clean).

| State | `base` | HEAD | `RIMAP_VERSION` | `is_release` |
|-------|--------|------|-----------------|--------------|
| Development (main, PR, local) | `0.1.1-dev` | any | `0.1.1-dev+g<sha>[.dirty]` | false |
| Release (tagged) | `0.1.1` | `v0.1.1` | `0.1.1` | true |
| Release-prep (stripped, untagged) | `0.1.1` | branch | `0.1.1+g<sha>[.dirty]` | false |
| No git checkout | `0.1.1-dev` | — | `0.1.1-dev+gunknown` | false |

### `build.rs` behavior (rimap-core)

`build.rs` stops synthesizing `-dev`. New logic:

```
base       = CARGO_PKG_VERSION            # may already contain "-dev"
at_tag     = git describe --tags --exact-match HEAD == "v{base}"
is_release = at_tag
version    = if is_release { base }
             else { format!("{base}+g{sha}{dirty_suffix}") }   # dirty_suffix = ".dirty" or ""
```

`RIMAP_COMMIT` (`<sha>` / `<sha>-dirty` / `unknown`) and `RIMAP_RELEASE`
(`"true"`/`"false"`) are emitted as today. Git-failure fallback:
`version = "{base}+gunknown"`, `is_release = false`. The `cargo:rerun-if-*`
lines are unchanged.

**Key invariant:** a build is a release **iff** its version has no `+g…`
build-metadata suffix. Release = clean `base`; every other state carries
`+g…`. This replaces the old "`-dev` present ⟺ not a release" invariant,
which no longer holds because a release-prep build has a clean (`-dev`-less)
base but is not a release.

### Workspace version propagation (the 8-crate wrinkle)

`rusty-imap-mcp` is an 8-crate workspace: each member declares its
intra-workspace deps with **both** a path and an explicit version requirement
(e.g. `rimap-core = { path = "../rimap-core", version = "0.1.0" }`) — 24 such
lines. crates.io needs the version (Phase 2B), so it must stay. But a `-dev`
pre-release does **not** satisfy a caret requirement on a clean base:
`^0.1.0` rejects `0.1.1-dev` (SemVer only matches a pre-release when a
comparator carries a pre-release with the same `major.minor.patch`). So
bumping only `[workspace.package].version` makes the workspace fail to
resolve — verified empirically.

**Mechanism:** all version transitions use
`cargo set-version --workspace <version>` (cargo-edit), which rewrites the
workspace version **and** all 24 intra-workspace requirements in lockstep,
then refresh the lock. This is required at release-prep (strip), by the
`post-release-bump` job, and for the initial bump in this change. `cargo-edit`
becomes a release-time tool dependency (documented in RELEASING.md; installed
in the bump job).

**Excluded packages:** `html-oracle` and `fuzz` are `exclude`d from the
workspace, so `cargo set-version --workspace` does not touch them. `fuzz`
already uses path-only deps (no version) and nothing runs it `--locked`, so it
is immune. `html-oracle` pins `version = "0.1.0"` on its two intra-deps and
would break; since it is an internal, never-published tool, this change makes
its intra-deps **path-only** (dropping the version), permanently removing it
from *requirement* churn.

`html-oracle` still keeps its **own `Cargo.lock`**, which records the resolved
version of those path deps — and `nightly-html-oracle.yml` runs
`cargo … --locked --manifest-path html-oracle/Cargo.toml` daily. So the lock
goes stale the moment the workspace version changes and must be refreshed in
lockstep: this change regenerates and commits `html-oracle/Cargo.lock`, and the
`post-release-bump` job includes a step to refresh it (e.g.
`cargo update --manifest-path html-oracle/Cargo.toml -p rimap-core -p rimap-content`
covering every `rimap-*` crate it locks) and stages it in the bump PR.

### Version test contract (`rimap-core/tests/version.rs`)

- `version_is_non_empty` — unchanged.
- `version_starts_with_workspace_base` — unchanged; holds in every state
  (`0.1.1-dev+g…`.starts_with(`0.1.1-dev`), `0.1.1`.starts_with(`0.1.1`)).
- `commit_matches_expected_shape` — unchanged.
- `release_flag_agrees_with_version_shape` — **re-anchored**: assert
  `is_release() == !version().contains("+g")` (the build-metadata suffix is
  the real release/dev discriminator), replacing the `-dev` check. Note this
  is a self-consistency check on `build.rs`'s own string composition — like
  the old `-dev` check, it documents the discriminator rather than
  independently verifying the `git describe` comparison.

## Release flow

### `check-release-version.sh` and `verify-tag`

**Unchanged.** The script already rejects a tag not matching
`^v[0-9]+\.[0-9]+\.[0-9]+$` and a workspace version containing `-`. Under the
new model these run at tag time against the **stripped** (clean) manifest, so
they pass on a correct release — and now also serve as the "forgot to strip
`-dev`" safety net (tagging `v0.1.1` with manifest `0.1.1-dev` fails the
clean-version check; `v0.1.1-dev` fails the tag regex).

### RELEASING.md checklist (rewritten)

1. On a `release/vX.Y.Z-prep` branch, run
   `cargo set-version --workspace X.Y.Z` (choose patch/minor per what landed)
   to **strip `-dev`** across the workspace version and all 24 intra-workspace
   requirements at once, then `cargo build` to refresh `Cargo.lock`.
2. Rename the CHANGELOG `## [Unreleased]` heading to `## [X.Y.Z] - YYYY-MM-DD`.
3. Run local checks (`just ci`, `scripts/check-release-version.sh vX.Y.Z`).
4. Open the prep PR, merge to `main`; tag the merge commit and push (as today).
5. After the release publishes, the `post-release-bump` job opens the bump PR
   automatically (see below); merge it.

### `post-release-bump` job (release.yml)

Runs after a **stable** release publishes; skipped for pre-release tags.

- `needs: [release]`, `if: ${{ !contains(github.ref_name, '-') }}`.
- `runs-on: ubuntu-24.04`; `permissions: { contents: write, pull-requests: write }`.
- Steps:
  1. `actions/checkout` of `main` (default branch) with
     `persist-credentials: false` (matches every other checkout in
     `release.yml`; avoids zizmor's `artipacked`).
  2. `dtolnay/rust-toolchain@… stable` + `cargo install cargo-edit --locked
     --version <pinned>`.
  3. Compute `RELEASED=${GITHUB_REF_NAME#v}` (e.g. `0.1.1`) and the next
     **patch** `-dev`: `0.1.2-dev`. Patch is the safe default (RELEASING.md
     tells the maintainer to edit the PR to a minor bump if that's next).
  4. `cargo set-version --workspace <next-dev>` (rewrites the version + all 24
     intra-workspace requirements), then `cargo build` to refresh `Cargo.lock`.
  5. Refresh `html-oracle/Cargo.lock` for the new `rimap-*` versions
     (`cargo update --manifest-path html-oracle/Cargo.toml -p rimap-core -p rimap-content`).
  6. Prepend `## [Unreleased]` to `CHANGELOG.md` (idempotent — skip if present).
  7. Open the PR with `peter-evans/create-pull-request@<sha>` (SHA-pinned;
     `token: ${{ secrets.GITHUB_TOKEN }}`, `branch: chore/post-release-bump-vX.Y.Z-dev`,
     commit `chore: bump version to X.Y.Z-dev after <tag> release`). Using the
     action with an explicit token avoids persisted credentials and any
     token-in-URL. It stages the changed member manifests, **`Cargo.lock`, and
     `html-oracle/Cargo.lock`** (CI runs `--locked` pervasively, so an
     un-refreshed lock fails).
- **CI caveat / merge prerequisite:** a PR opened via `GITHUB_TOKEN` does not
  trigger `pull_request` workflows (GitHub's workflow-recursion safeguard). If
  branch protection requires those checks, the PR **cannot merge** until the
  maintainer kicks CI. The PR body carries the recipe (push an empty commit,
  or run `just ci` locally); the diff is small, so the local path is fastest.
  RELEASING.md states this as a hard prerequisite. This mirrors bzr and needs
  no extra secret.

## CHANGELOG convention

Adopt Keep-a-Changelog's `## [Unreleased]` section. This spec's own
implementation adds it (the first post-0.1.0 change); thereafter the
`post-release-bump` job re-adds it each release, and release-prep renames it
to the dated version heading. The release-notes extractor is unaffected — it
matches `## [X.Y.Z]`, never `## [Unreleased]`.

## Files touched

- `Cargo.toml` + all 8 `crates/*/Cargo.toml` — bumped to `0.1.1-dev` via
  `cargo set-version --workspace 0.1.1-dev` (workspace version + 24
  intra-workspace requirements); `Cargo.lock` refreshed and committed.
- `html-oracle/Cargo.toml` — intra-deps made path-only (drop `version`);
  `html-oracle/Cargo.lock` regenerated for the new `rimap-*` versions (the
  nightly oracle runs `--locked`).
- `crates/rimap-core/build.rs` — new composer logic (above).
- `crates/rimap-core/src/version.rs` — docstrings describe the new model.
- `crates/rimap-core/tests/version.rs` — re-anchor the release invariant.
- `CHANGELOG.md` — prepend `## [Unreleased]`.
- `RELEASING.md` — version convention + rewritten checklist + automation note
  (incl. `cargo-edit` requirement and the bump-PR CI-kickoff prerequisite).
- `.github/workflows/release.yml` — add the `post-release-bump` job.
- `AGENTS.md` — the `(v0.1.0)` feature-complete note no longer hardcodes the
  released version.
- `docs/ADR/0003-manifest-dev-version-model.md` + `docs/ADR/README.md` index.

## Testing strategy

- Unit/integration: the re-anchored `tests/version.rs` runs green in the dev
  state (manifest `0.1.1-dev` → `is_release() == false`, version has `+g`).
- Release path: exercised only on a real tag. `verify-tag` +
  `check-release-version.sh` guard tag/manifest agreement; the successful
  v0.1.0 run is the proof the surrounding pipeline works.
- `post-release-bump`: workflow logic (version math, file edits) is unit-
  testable as a shell snippet; the PR-open step is exercised on the next real
  stable tag. Validate with `actionlint` + `zizmor`.

## Rollback

The change is a manifest bump + build-script logic + a workflow job. Reverting
the commit restores the prior model; no persisted state or external service is
affected. `main` carrying a `-dev` version is inert until the next release.
