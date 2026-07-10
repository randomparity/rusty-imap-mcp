# ADR-0002: Phased bzr-parity release process and direct-publish releases

- **Status:** Accepted
- **Date:** 2026-07-10
- **Issue:** none (driven from the Phase 1 spec)
- **Spec:** [docs/superpowers/specs/2026-07-10-release-homebrew-phase1-design.md](../superpowers/specs/2026-07-10-release-homebrew-phase1-design.md)
- **Supersedes:** none (amends non-goals of [2026-05-11-release-versioning-design.md](../superpowers/specs/2026-05-11-release-versioning-design.md))

## Context

`rusty-imap-mcp` has never cut a release. The
[2026-05-11 release-versioning design](../superpowers/specs/2026-05-11-release-versioning-design.md)
established a `build.rs`-computed version model and a `verify-tag` guard, and
listed as explicit **non-goals**: publishing to crates.io, automatic version
bumping / a `-dev` suffix stored in the manifest, deb/rpm packaging, and
install scripts.

The maintainer has since decided to model the full release process on
[`randomparity/bzr`](https://github.com/randomparity/bzr), which does all of
those: crates.io publish, a `-dev`-in-`Cargo.toml` model with release-prep and
post-release-bump PRs, deb/rpm packages, manpages, `install.sh`/`install.ps1`,
Homebrew tap automation, and native Homebrew bottles. That reverses several of
the 2026-05-11 non-goals. A future reader comparing the two specs would
otherwise re-litigate "why did the non-goals flip?"

bzr is a single crate; `rusty-imap-mcp` is an 8-crate workspace whose binary
(`rimap-server`) depends on 7 path crates. crates.io forbids path dependencies,
so crates.io publish means publishing all 8 crates in dependency order — a
materially larger and higher-iteration effort than bzr's single `cargo publish`.
bzr itself reached its current pipeline incrementally (Homebrew at v0.2.0,
deb/rpm and installers later), not in one release.

Two decisions need recording.

## Decision

**1. Adopt bzr-parity incrementally, not all at once.** The bzr-parity work is
split into phases, each with its own spec → plan → implementation cycle:

- **Phase 1 (this spec):** `.tar.gz` release artifacts, Homebrew tap automation,
  native bottles, `RELEASING.md`. Keeps the current `build.rs`-computed version
  model unchanged. Ships `v0.1.0`.
- **Phase 2:** the `-dev`-in-`Cargo.toml` version model (release-prep +
  post-release-bump), reworking `build.rs` and `verify-tag`.
- **Phase 3:** crates.io publish of all 8 workspace crates.
- **Phase 4:** deb/rpm packaging, manpages, `install.sh`/`install.ps1`,
  `installer-smoke`.

The 2026-05-11 non-goals for crates.io, the `-dev` model, deb/rpm, and
installers are hereby **amended**: they are no longer non-goals but deferred,
sequenced work.

**2. Publish releases directly (drop the draft gate) starting in Phase 1.** The
current `release` job creates a `--draft` GitHub Release. The Homebrew and
bottle jobs download release assets from the public
`releases/download/<tag>/` CDN, which only serves a **published** release. To
let tap + bottle automation run on tag push, the `release` job publishes
directly. The human review gate that a draft provided is deferred to Phase 2,
where a `release-prep` PR (reviewed before the tag is pushed) restores a
pre-publish checkpoint.

## Consequences

- Phase 1 stays small and low-risk: no version-model change, no multi-crate
  crates.io reservation, no lintian/rpmlint iteration on the debut tag.
- Once a stable `v*` tag is pushed, the release is immediately public and the
  tap formula + bottles resolve against live assets. A bad release cannot be
  quietly reverted without breaking `brew install` for anyone who already
  tapped; a fix requires a new patch tag. Between Phase 1 and Phase 2 the only
  pre-publish safety net is the local pre-release checklist in `RELEASING.md`
  plus branch-protected CI on `main` before tagging.
- Each later phase can reference this ADR for the sequencing rationale rather
  than re-deriving it. When Phase 2 lands the `-dev` model it will add an ADR
  that supersedes the 2026-05-11 spec's version-model section.
- crates.io name availability for all 8 `rimap-*` crates (and the binary's
  install name) is an open risk carried into Phase 3, not Phase 1.

## Considered & rejected

- **Build the entire pipeline before cutting `v0.1.0`.** Rejected: blocks the
  first release on crates.io name reservation, deb/rpm packaging, and
  cross-repo bottle builds all landing green on the debut tag — the highest
  failure surface at the worst time. bzr's own incremental history is the
  precedent.
- **Keep the draft gate and have the tap/bottle jobs authenticate against the
  draft.** Rejected for Phase 1: the formula would embed URLs that 404 until a
  human publishes the draft, so any user who taps in the window between push
  and publish gets a broken install. Direct publish removes that window. The
  review gate returns in Phase 2 via the release-prep PR, a cleaner checkpoint
  than a draft.
- **Never support Intel macOS.** Deferred, not rejected: Phase 1 keeps a
  source-build fallback in the formula (`cargo install --path crates/rimap-server`)
  so Intel-mac users are not silently unsupported, at the cost of a slower
  first install on that platform.
