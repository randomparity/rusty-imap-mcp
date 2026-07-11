# Release Versioning Design

Date: 2026-05-11
Status: Implemented; version-model decision superseded by [ADR-0003](../../ADR/0003-manifest-dev-version-model.md)

> **Superseded (2026-07-10):** the "no `-dev` in the manifest" and "no
> automatic version bumping" non-goals below are reversed by
> [ADR-0003](../../ADR/0003-manifest-dev-version-model.md) /
> [the manifest `-dev` version-model design](2026-07-10-dev-version-model-design.md)
> (Phase 2A of the bzr-parity release process). The `build.rs` /
> `verify-tag` machinery this spec established otherwise still stands.

## Summary

Establish a semver-compliant release workflow for `rusty-imap-mcp`. Builds
produced from a `vX.Y.Z` git tag identify as the bare semver `X.Y.Z`. All
other builds — local development, pull-request CI, branch builds — identify
as `X.Y.Z-dev+g<short-sha>` (with `.dirty` appended when the worktree has
uncommitted changes). The workspace version drops from the current
aspirational `1.0.0` to `0.1.0`, reflecting the project's pre-release reality.

The version string is computed once at compile time by a build script in
`rimap-core` and consumed via a `rimap_core::version()` helper. It flows to
every runtime surface that previously read `CARGO_PKG_VERSION`: the clap CLI
`--version`, the MCP `server_info.version` field, and the audit-record
`version` field.

The release workflow gains a tag-vs-Cargo guard that hard-fails before any
build job runs if the pushed tag does not match the workspace version.

## Goals

- Make every build identify itself unambiguously: a release build prints a
  clean semver; a dev build prints the commit it was built from.
- Keep `Cargo.toml` as the single source of truth for the base version.
  Cutting a release is "tag and push" — no manifest edit required at the
  moment of release.
- Catch tag/manifest drift in CI before any artifact is built, so the
  published version always matches what was tagged.
- Add no new runtime dependencies and no new heavyweight build-time
  dependencies. Use only `git` (already required for the repo).

## Non-goals

- Pre-release identifiers beyond `-dev` (no `-rc.N`, `-beta.N`, `-alpha`).
- Conventional-commits-driven CHANGELOG generation.
- Automatic version bumping (no `cargo-release` / `cargo-edit` integration).
- Reproducible builds beyond honoring `SOURCE_DATE_EPOCH` as a rerun trigger.
- Publishing to crates.io. The project ships binaries via GitHub Releases.
- Changing the existing tag format. `v` prefix stays.

## Architecture

### Version composition

The workspace `Cargo.toml` carries the canonical base version with no
suffix. At build time, `rimap-core/build.rs` decides whether the build is a
release or a dev build and emits the appropriate version string as a
`cargo:rustc-env` variable:

```
RIMAP_VERSION = "X.Y.Z"                          (release: HEAD is tag vX.Y.Z)
RIMAP_VERSION = "X.Y.Z-dev+g<sha>"               (dev: clean worktree)
RIMAP_VERSION = "X.Y.Z-dev+g<sha>.dirty"         (dev: uncommitted changes)
RIMAP_VERSION = "X.Y.Z-dev+gunknown"             (no .git present)
```

The format follows semver 2.0:

- `-dev` is the pre-release identifier (everything after `-`, before `+`).
- `+g<sha>` is build metadata. The `g` prefix follows the `git describe`
  convention. Semver tools ignore build metadata for ordering, which is
  the correct behavior: two dev builds at different commits are not
  comparable.

The base version (`X.Y.Z`) is parsed from `Cargo.toml`'s workspace
`[workspace.package].version`. On initial implementation it is `0.1.0`.

### Build script

`crates/rimap-core/build.rs` runs three `git` subprocesses via
`std::process::Command`:

1. `git describe --tags --exact-match HEAD` — succeeds only when HEAD is
   an annotated tag. If the tag matches `v<workspace-version>`, the build is
   a release. Any other outcome (no tag, mismatched tag, error) falls through
   to the dev path.
2. `git rev-parse --short=7 HEAD` — short commit SHA (7 hex chars).
3. `git status --porcelain` — non-empty output flips the `.dirty` flag.

Outputs emitted to cargo:

```
cargo:rustc-env=RIMAP_VERSION=<computed>
cargo:rustc-env=RIMAP_COMMIT=<sha-or-"unknown">
cargo:rustc-env=RIMAP_RELEASE=<"true"|"false">
cargo:rerun-if-changed=.git/HEAD
cargo:rerun-if-changed=.git/refs/tags
cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH
```

Failure handling: the build script never errors out of cargo. Every `git`
failure path produces the `gunknown` fallback. This keeps `cargo build` in
a vendored source tarball, a Docker layer without `.git`, or a future
crates.io publish working without surprise breakage.

The script shells out via `Command::new("git")` directly — no `sh -c`, no
shell interpolation of any variable. Worst-case behavior on a malicious
`git` binary on `$PATH` is identical to the rest of `cargo build`. A
one-line acknowledgment is added to the supply-chain audit (SC-PROC-01)
since this is a new build script in the workspace.

### Public API

`rimap-core` exposes:

```rust
pub fn version() -> &'static str { env!("RIMAP_VERSION") }
pub fn commit() -> &'static str  { env!("RIMAP_COMMIT") }
pub fn is_release() -> bool      { env!("RIMAP_RELEASE") == "true" }
```

No other public surface change. Downstream crates use these helpers
instead of `env!("CARGO_PKG_VERSION")` at the three call sites listed below.

### Runtime surfaces

Three sites switch from `CARGO_PKG_VERSION` to `rimap_core::version()`:

1. `crates/rimap-server/src/cli/mod.rs:24` — the `#[command(version)]`
   attribute is removed from the derive, and `crates/rimap-server/src/main.rs`
   switches to clap's `CommandFactory` builder pattern
   (`Cli::command().version(rimap_core::version::version()).get_matches()`).
   Short `--version` prints `rusty-imap-mcp <version>`. The richer
   `long_version` (commit + target triple + release flag) is deferred
   until a real user asks for it — wiring it through the builder also
   requires a `String`-with-`'static`-lifetime workaround that adds
   little for support diagnostics, since the audit log already carries
   the commit.
2. `crates/rimap-server/src/mcp/server.rs:228` — `server_info.version`
   announced to MCP clients during the initialize handshake.
3. `crates/rimap-server/src/boot/audit_init.rs:66` — the `version` field
   stamped into every audit record at startup.

The single source of truth means a captured audit log, an MCP client
session record, and an operator's `--version` output all reference the
same commit hash for a given build.

Other uses of `env!("CARGO_PKG_VERSION")` in the tree (test fixtures,
manifest-dir resolution) are unrelated and stay as-is.

### Cargo.toml changes

```toml
[workspace.package]
version = "0.1.0"   # was "1.0.0"
```

22 `version = "1.0.0"` literals on path-dependency entries (including
dev-deps and the self-referencing test-support entries in `rimap-server`)
across the seven dependent member crates (`rimap-imap`, `rimap-content`, `rimap-config`,
`rimap-audit`, `rimap-smtp`, `rimap-authz`, `rimap-server`) update to
`"0.1.0"`. The existing comment in `crates/rimap-imap/Cargo.toml`
(`# Internal — direct path + explicit version to satisfy cargo-deny's
wildcard ban.`) records that explicit version literals are required by
`cargo-deny`'s `wildcards = "deny"` rule, so the version cannot simply be
inherited from the workspace at these sites. The duplication is accepted
and updated by a single `sed`-style pass; the `verify-tag` guard
(below) and pre-merge CI prevent drift from the workspace value.

### Release workflow guard

`.github/workflows/release.yml` gains a new first job, `verify-tag`, that
the existing five build jobs depend on via `needs:`. The job:

1. Checks out the source with `persist-credentials: false`.
2. Parses the workspace version out of `Cargo.toml` (a small awk or
   grep-cut one-liner — no new tool dependency).
3. Strips the leading `v` from `${{ github.ref_name }}`.
4. Hard-fails if any of:
   - The pushed tag and the Cargo version disagree.
   - The Cargo version contains a `-` (catches a stray `0.1.0-dev` in the
     manifest).
   - The tag does not match `^v[0-9]+\.[0-9]+\.[0-9]+$` exactly. Pre-release
     tag formats are deferred to a future design.
5. Echoes the verified version into `$GITHUB_OUTPUT` for downstream use.

The existing per-tag CHANGELOG extraction step runs unchanged after the
guard.

A `workflow_dispatch` trigger is added with a `dry_run` boolean input. When
`dry_run` is true, the verify job runs but the build and release jobs skip,
allowing the guard logic to be exercised without cutting a real tag.

### Local mirror script

`scripts/check-release-version.sh` runs the same comparison locally:

```
just release-check v0.1.0
```

Pure bash, `set -euo pipefail`, shellcheck-clean, no new dependencies. The
`justfile` gets a `release-check` recipe that invokes it. A `prek` hook
on the script itself keeps it clean.

### CHANGELOG migration

The current `CHANGELOG.md` has both an `[Unreleased]` section and an
aspirational `[1.0.0] - 2026-04-13` section, plus a duplicate `[Unreleased]`
heading at the bottom that looks like a copy-paste artifact. There is no
`v1.0.0` git tag and no published release.

The migration:

1. Remove the duplicate trailing `[Unreleased]` heading.
2. Rename `## [1.0.0] - 2026-04-13` → `## [0.1.0] - Unreleased`.
3. Fold the existing top `[Unreleased]` content (multi-account credential-
   namespacing entries) into the `[0.1.0]` section — they ship together as
   the first real release.
4. Leave an empty `## [Unreleased]` heading at the top for post-0.1.0 work.
5. Update or add the reference-link footer:
   `[0.1.0]: https://github.com/randomparity/rusty-imap-mcp/releases/tag/v0.1.0`.

Keep-a-Changelog formatting is preserved throughout.

## Data flow

```
                  Cargo.toml workspace version "X.Y.Z"
                            │
              ┌─────────────┴─────────────┐
              ▼                           ▼
   rimap-core/build.rs           release.yml verify-tag
   ├ git describe ...HEAD        ├ parse Cargo.toml version
   ├ git rev-parse --short HEAD  ├ strip "v" from github.ref_name
   └ git status --porcelain      ├ regex check ^v\d+\.\d+\.\d+$
              │                  └ hard-fail on any mismatch
              ▼
   cargo:rustc-env=RIMAP_VERSION, RIMAP_COMMIT, RIMAP_RELEASE
              │
              ▼
   rimap_core::version() / commit() / is_release()
              │
   ┌──────────┼──────────┐
   ▼          ▼          ▼
  CLI        MCP        Audit
 --version   server_info version field
```

The build-script branch (left) decides the runtime version on every
`cargo build`. The workflow-guard branch (right) is independent — it
runs only on tag pushes and gates the release build jobs from starting.
Both read the same `Cargo.toml` workspace version as input.

## Error handling

| Path                                | Outcome                              |
|-------------------------------------|--------------------------------------|
| `git` not installed                 | `RIMAP_VERSION = X.Y.Z-dev+gunknown` |
| No `.git` directory                 | `RIMAP_VERSION = X.Y.Z-dev+gunknown` |
| `git describe` returns no match     | Dev path with real SHA               |
| `git describe` matches mismatched tag (e.g. tag is `v0.0.9` but Cargo is `0.1.0`) | Dev path with real SHA |
| Worktree dirty                      | `.dirty` suffix appended             |
| Tag pushed but Cargo.toml not bumped | `verify-tag` job hard-fails CI      |
| Cargo.toml contains `-dev` literal   | `verify-tag` job hard-fails CI      |
| Tag is `v0.1` or `v0.1.0-rc1`        | `verify-tag` job hard-fails CI      |

## Testing strategy

- **`rimap-core` unit tests**: `version()` returns a non-empty string;
  `commit()` matches `unknown|[0-9a-f]{7}(-dirty)?`; `is_release()` is
  boolean and consistent with whether `version()` contains `-dev`.
- **CLI smoke**: `assert_cmd` test that `rusty-imap-mcp --version` prints
  a string starting with `rusty-imap-mcp ` followed by a non-empty version
  token.
- **Workflow dry-run**: `workflow_dispatch` invocation of `release.yml`
  with `dry_run: true` exercises the verify job against the current
  `Cargo.toml` and a synthetic tag name.
- **Local check**: `just release-check v0.1.0` exits 0 when in sync,
  non-zero otherwise. A negative test (`just release-check v9.9.9`) is
  documented in the script's help text.
- **Mutation coverage**: not in scope for this change; the new logic is
  small and exercised by the smoke tests above.

## Migration / rollout

This is a single coordinated change because the Cargo version bump, the
crate path-dep update, and the build-script wiring must land together to
keep the workspace compiling. No staged rollout. Order of operations
within the PR:

1. Drop the workspace version to `0.1.0`; update the seven path-dep
   pins; verify `cargo check --workspace` succeeds.
2. Add `rimap-core/build.rs` plus the public `version()` / `commit()` /
   `is_release()` helpers.
3. Switch the three runtime call sites to the helpers.
4. Add the `verify-tag` job and `workflow_dispatch` trigger to
   `release.yml`. Add `scripts/check-release-version.sh` and the
   `justfile` recipe.
5. Migrate `CHANGELOG.md` as described above.
6. Update `SC-PROC-01` audit comment in `Cargo.toml` (or the relevant
   tracking doc) to acknowledge the new `rimap-core/build.rs`.

Each step is independently committable; the PR can be reviewed as a single
unit or split into commits in the order above.

## Open questions

None at design time. The implementation plan will address ordering of
commits within the PR and any edge cases discovered during build-script
testing on each release target (linux-x86_64, linux-aarch64, macos-arm64,
linux-ppc64le, linux-s390x).
