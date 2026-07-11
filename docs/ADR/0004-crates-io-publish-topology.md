# ADR-0004: crates.io publish topology for the 8-crate workspace

- **Status:** Accepted
- **Date:** 2026-07-10
- **Issue:** [#544](https://github.com/randomparity/rusty-imap-mcp/issues/544)
- **Spec:** [docs/superpowers/specs/2026-07-10-issue-544-crates-io-publish-design.md](../superpowers/specs/2026-07-10-issue-544-crates-io-publish-design.md)
- **Depends on:** [ADR-0003](0003-manifest-dev-version-model.md) (clean-version
  invariant at release-prep)
- **Sequencing context:** [ADR-0002](0002-phased-bzr-release-parity-and-direct-publish.md)
  (crates.io is ADR-0002's "Phase 3"; issue #544 labels it "Phase 2B" — same
  work)

## Context

`rusty-imap-mcp` is an 8-crate workspace whose binary (`rimap-server`) depends
on seven library crates via `path` dependencies that already carry `version =`.
crates.io forbids path-only dependencies, so publishing means publishing all
eight crates in dependency order — a materially larger and higher-iteration
effort than a single-crate `cargo publish`, and an **irreversible** one
(crates.io versions can only be yanked, never replaced or deleted).

Four decisions with viable alternatives need recording so a future reader does
not re-litigate them.

## Decision

**1. Publish as a downstream leaf of `release`, gated to stable tags.** A new
`publish-crates` job in `release.yml` runs `needs: release` (after the GitHub
Release and artifacts publish) and only on `push` of a stable `v*` tag
(`!contains(github.ref_name, '-')`), mirroring the `homebrew` job. Publish
failure does not un-publish the GitHub Release.

**2. Fully automatic once configured — no required reviewer.** The job runs
behind an `environment: crates-io` holding `CARGO_REGISTRY_TOKEN`, with no
approval stall (operator's choice). The existing `v*` tag protection
(RELEASING.md) is the human control on what gets published. Until the
environment and secret are configured the job simply fails at `cargo publish`
(a harmless downstream leaf).

**3. Ordered, idempotent-by-version publish script.**
`scripts/publish-crates.sh` publishes in the topological order
`core → config → audit → content → authz → imap → smtp → server`, skipping any
crate whose exact current version is already on crates.io. This makes a
same-tag re-run resumable after a mid-run failure and tolerates the
partial-publish reality of an 8-crate chain.

**4. `cargo-semver-checks` gates the publish.**
`cargo semver-checks check-release --workspace` runs before the publish loop.
It no-ops on the first release (no baseline) and, from the second release
onward, fails the publish when a crate's public API changed incompatibly
without an appropriate version bump.

A supporting non-topology decision: **`rimap-content` is relicensed** to
`(MIT OR Apache-2.0) AND Unicode-DFS-2016` (it vendors Unicode TR39
`confusables.txt`, which `build.rs` compiles in, so the data must ship), and
`Unicode-DFS-2016` is added to `deny.toml`'s allow list.

## Consequences

- The first stable tag with the `crates-io` environment configured publishes
  all eight crates and thereby reserves the names. A bad publish cannot be
  reverted — only yanked and superseded by a new patch version.
- Re-running a tag is safe (idempotent skip); fixing a publish bug requires a
  new patch tag rather than overwriting a version.
- The publish job depends on the ADR-0003 clean-version invariant: it must
  never run for a `-dev` tag. This is enforced by the job `if:` (stable-only)
  and a redundant in-script `-dev` assertion.
- `cargo-semver-checks` becomes a standing gate on API stability across
  releases, aligning the crates' public surfaces with SemVer.

## Considered & rejected

- **Manual-approval environment (required reviewer) on every publish.**
  Rejected by the operator in favor of automatic publish; tag protection
  already gates who can trigger a release. (Recorded because it is the safer
  default for an irreversible operation and a future maintainer may want it —
  it is a one-line `environment` protection change, no code change.)
- **A dedicated publish tag/trigger separate from `v*`.** Rejected: the issue
  specifies the same `v*` tag as the GitHub Release, after artifacts publish;
  a second trigger doubles the release surface for no benefit.
- **`cargo publish --workspace` / a publish tool (`cargo-release`,
  `cargo-workspaces`).** Rejected for now: a small, auditable, dependency-free
  Bash script with explicit ordering and idempotent skip is easier to reason
  about, needs no extra CI tool trust, and makes the partial-publish/resume
  behavior explicit. Revisit if the crate count or ordering complexity grows.
- **Excluding `confusables.txt` from the `rimap-content` package to avoid the
  Unicode-DFS-2016 license.** Rejected: `build.rs` reads the file at build
  time, so an excluded file breaks the published crate's build. The data must
  ship; the license expression must cover it.
- **Reserving the eight names inside this PR's diff.** Rejected: an irreversible
  external write does not belong in a reviewable code branch. Reservation is a
  discrete operational step; the pipeline makes publishing possible.
