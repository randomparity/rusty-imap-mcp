# ADR-0003: Manifest `-dev` version model with automated post-release bump

- **Status:** Accepted
- **Date:** 2026-07-10
- **Issue:** none (Phase 2A of the bzr-parity release process)
- **Spec:** [docs/superpowers/specs/2026-07-10-dev-version-model-design.md](../superpowers/specs/2026-07-10-dev-version-model-design.md)
- **Supersedes:** the version-model decision of [2026-05-11-release-versioning-design.md](../superpowers/specs/2026-05-11-release-versioning-design.md) (its "no `-dev` in the manifest, no automatic version bumping" non-goals)
- **Refines:** [ADR-0002](0002-phased-bzr-release-parity-and-direct-publish.md) (this is its Phase 2A)

## Context

The 2026-05-11 versioning model stores the **last released** version in
`Cargo.toml` (`0.1.0`) and has `build.rs` synthesize a `-dev` suffix for
non-release builds. This produces `0.1.0-dev+g<sha>` for every commit *after*
0.1.0 shipped — but per SemVer `0.1.0-dev` is a pre-release of `0.1.0`, so it
orders *before* the release it follows. ADR-0002 committed the project to
bzr-parity, which flips the 2026-05-11 non-goals "manifest `-dev`" and
"automatic version bumping." This ADR records the resulting version-model
decision so a future reader does not re-litigate the flip.

## Decision

Store the **next** planned version with a `-dev` SemVer pre-release suffix in
`[workspace.package].version` (e.g. `0.1.1-dev` after `v0.1.0`). `build.rs`
stops synthesizing `-dev` and instead appends `+g<sha>[.dirty]` git
provenance to the manifest base unless HEAD is exactly the release tag
`v<base>` (a clean base), in which case the version is the bare base and
`is_release` is true.

The release/dev discriminator becomes the presence of the `+g…`
build-metadata suffix (release = no suffix), replacing the old "`-dev` ⟺ not
a release" rule, which breaks for a release-prep build whose base is already
stripped clean but is not yet tagged.

Release-prep strips `-dev` to the clean tag version; a `post-release-bump`
job in `release.yml` opens a PR after each stable release bumping the manifest
to the next **patch** `-dev` and prepending `## [Unreleased]` to the CHANGELOG.
The job uses `GITHUB_TOKEN`; PRs it opens do not trigger `pull_request` CI (a
GitHub safeguard), so the PR body carries a kick-off recipe. The existing
`check-release-version.sh` / `verify-tag` guards are unchanged and now also
catch a forgotten `-dev` strip at tag time.

## Consequences

- Dev builds order correctly relative to the last release (`0.1.1-dev` sorts
  after `0.1.0`, before `0.1.1`).
- Cutting a release now requires editing the manifest (strip `-dev`) on the
  prep PR — no longer pure "tag and push." This is the bzr flow and the price
  of correct ordering + crates.io readiness (ADR-0002 Phase 2B).
- `main` briefly carries the released version between the tag and the merged
  bump PR; this is inert (the next prep PR still lands cleanly).
- Because each of the 8 members pins its intra-workspace deps with an explicit
  `version` (required for crates.io), a `-dev` bump must rewrite the workspace
  version **and** all 24 requirements in lockstep — `^0.1.0` does not match
  `0.1.1-dev`. All version transitions therefore use
  `cargo set-version --workspace`, making `cargo-edit` a release-time tool.
  The excluded `html-oracle` tool drops its intra-dep versions (path-only) so
  it is immune to the churn.

## Considered & rejected

- **Keep the build-synthesized `-dev` model (status quo).** Simplest, no
  manifest edit at release, but leaves post-release dev builds mis-ordered and
  does not set up the clean-version-at-tag flow crates.io needs. Rejected by
  the ADR-0002 bzr-parity commitment.
- **Next-*minor* `-dev` default (`0.2.0-dev`).** bzr defaults to next *patch*
  because the actual bump is chosen at release-prep per what landed; patch is
  the conservative placeholder. Mirrored here.
- **Manual post-release bump (documented, not automated).** Smaller, but the
  maintainer chose full bzr parity, and an un-bumped `main` silently reuses
  the released version in `--version` until someone remembers.
- **Dedicated PAT so the bump PR triggers CI.** Avoids the kick-off caveat but
  adds a standing secret and blast surface; bzr accepts the `GITHUB_TOKEN`
  caveat and so do we (the bump is a tiny, locally-verifiable diff).
