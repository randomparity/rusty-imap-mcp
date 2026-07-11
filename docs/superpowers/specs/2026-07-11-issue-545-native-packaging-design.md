# Native Packaging: deb/rpm, Manpages, and Shell Installer (Phase 4) Design

Date: 2026-07-11
Status: Draft (pre adversarial review)
Issue: [#545](https://github.com/randomparity/rusty-imap-mcp/issues/545) — "Phase 2C: deb/rpm packages, manpages, and shell installer"
ADR: [ADR-0006](../../ADR/0006-native-packaging-build-topology.md) — native packaging build topology; extends [ADR-0002](../../ADR/0002-phased-bzr-release-parity-and-direct-publish.md) Phase 4
Reference: [`randomparity/bzr`](https://github.com/randomparity/bzr) — the same four subsystems, already shipped

## Summary

Complete the bzr-parity end-user distribution surface for `rusty-imap-mcp`:

1. **Manpages** generated from the clap CLI via `clap_mangen`, shipped in every
   release tarball and in the native packages.
2. **`.deb`** packages for amd64 + arm64 via `cargo-deb` + Cargo package metadata.
3. **`.rpm`** packages for amd64 + arm64 via `cargo-generate-rpm` + Cargo package
   metadata.
4. **`install.sh`** — a `curl … | sh` installer that detects OS/arch, downloads
   the matching release tarball, verifies its SHA-256 against the release
   `SHA256SUMS.txt`, and installs the binary to a prefix.

All four are wired into `.github/workflows/release.yml` and attached to the
GitHub Release on every stable `v*` tag, and documented in `README.md` /
`RELEASING.md`.

This is ADR-0002's **Phase 4** (the issue label "Phase 2C" refers to the same
work). Phases 1–3 (tarballs + Homebrew, the `-dev` version model, crates.io
topology) already shipped; this is the last deferred bzr-parity subsystem.

## Goals

- On every stable `v*` tag, the GitHub Release additionally carries, alongside
  the existing 5 tarballs + `SHA256SUMS.txt` + provenance:
  - `rusty-imap-mcp_<version>_amd64.deb`, `rusty-imap-mcp_<version>_arm64.deb`
  - `rusty-imap-mcp-<version>-1.x86_64.rpm`, `…aarch64.rpm` (names per tool defaults)
  - `install.sh` (with the release version baked in as the default)
- Every release tarball (all 5 arches) contains `share/man/man1/rusty-imap-mcp.1`
  plus one page per subcommand (`rusty-imap-mcp-login.1`, `-audit.1`, etc.).
- `curl -fsSL <raw install.sh URL> | sh` installs the latest stable release on
  Linux (x86_64/aarch64/ppc64le/s390x) and macOS (aarch64), verifying the
  download's checksum before extraction, and prints an actionable error on an
  unsupported platform.
- Installing the `.deb` on a minimal Debian image and the `.rpm` on a minimal
  Fedora image (neither carrying `libdbus-1-3` / `dbus-libs`) yields a working
  `rusty-imap-mcp --version` — proving the vendored static-libdbus contract.
- `RELEASING.md` moves #545 from "Planned" to documented behavior; `README.md`
  gains install instructions for packages and the installer.
- `just man` regenerates manpages locally; `just ci` stays green; the workflow
  passes `actionlint` + `zizmor`; `install.sh` passes `shellcheck` + `shfmt`.

## Non-goals

- **ppc64le/s390x packages.** Tarball-only (ADR-0006 decision 2). Non-vendored,
  near-zero packaged audience; packaging them would reintroduce per-arch libdbus
  dependency declarations.
- **Windows `install.ps1` / zip artifacts.** No Windows binary is built.
- **A distro-hosted apt/dnf repository, an APT/YUM signing key, or Debian/Fedora
  submission.** Packages are attached to the GitHub Release only.
- **Homebrew manpage installation.** The tap formula template gains a
  `man1.install` line (in-scope, cheap) but native bottle regeneration and tap
  behavior remain governed by the Phase 1 spec; a bottle without the man page
  still installs.
- **Changing the version model, the tarball set, or the existing homebrew /
  bottles / publish-crates / post-release-bump jobs** beyond what packaging
  requires (adding `--target` to two build commands; adding the man page to
  tarball staging; adding `install.sh` + packages to the release-asset set).

## Current state (baseline)

- `.github/workflows/release.yml`: `verify-tag` → five per-target build jobs
  (`build-linux-x86_64`, `build-linux-aarch64`, `build-macos-aarch64`,
  `build-linux-ppc64le`, `build-linux-s390x`) → `release` → `{homebrew →
  bottles → bottles-merge, publish-crates, post-release-bump}`. Each build job
  stages a tarball inline from `target/release/rusty-imap-mcp` + `LICENSE-MIT
  LICENSE-APACHE NOTICE README.md`. The aarch64/ppc64le/s390x legs build inside
  emulated `docker run --platform` containers; x86_64 and macOS build natively.
  The x86_64 and aarch64 legs pass `--features vendored-keyring`.
- `release` downloads all tarball artifacts, generates `SHA256SUMS.txt` (over
  `rusty-imap-mcp-*.tar.gz` only), attaches a build-provenance attestation, and
  publishes the release directly (no draft — ADR-0002). `homebrew` parses
  `SHA256SUMS.txt` by exact filename.
- CLI: `crates/rimap-server/src/cli/mod.rs` defines `Cli` (`#[derive(Parser)]`)
  with subcommands `login`, `migrate-keyring`, `audit merge`, and
  test-support-gated `dump-tool-*`. `main.rs` declares `mod cli` (binary-private)
  and parses via `Cli::command().version(rimap_core::version::version())`. The
  library (`lib.rs`) exposes `boot`/`mcp`/`tools` as `#[doc(hidden)] pub` but not
  `cli`.
- `crates/rimap-server/Cargo.toml`: binary `rusty-imap-mcp`; features `default`,
  `test-support`, `vendored-keyring`, `fuzzing`. No packaging metadata.
- Workspace `Cargo.toml`: `members = [...]`, `exclude = ["fuzz", "html-oracle"]`.
- `homebrew/rusty-imap-mcp.rb.template` renders the tap formula; no man handling.
- prek hooks include `shellcheck`, `shfmt`, `actionlint`; CI required checks
  include `zizmor self-check`. Dual-licensed `MIT OR Apache-2.0` with
  `LICENSE-MIT`, `LICENSE-APACHE`, `NOTICE`.
- Dev toolchain Rust 1.94.0; MSRV 1.88.0; edition 2024; workspace-inherited deps.

## Design

### 1. Manpage generation (`xtask` crate)

**Expose the CLI from the library.** Move the `cli` module from `main.rs` into
`lib.rs` as `#[doc(hidden)] pub mod cli`. Add a builder helper so the version
wiring lives in one place:

```rust
// crates/rimap-server/src/cli/mod.rs
/// The fully-configured top-level `clap::Command`, carrying the runtime version.
/// Shared by the binary's arg parser and the `xtask` manpage generator so
/// generated pages match the CLI users actually run.
pub fn command() -> clap::Command {
    <Cli as clap::CommandFactory>::command().version(rimap_core::version::version())
}
```

`main.rs::parse_cli` becomes `cli::command().get_matches()` (behavior-preserving;
the `.version(...)` call moves into the helper). `main.rs` consumes `cli` via
`rimap_server::cli`.

**New `xtask/` workspace member.** A minimal binary crate (mirroring bzr):

```toml
# xtask/Cargo.toml
[package]
name = "xtask"
version = "0.0.0"
publish = false
edition = "2024"
rust-version.workspace = true
# ...
[dependencies]
rimap-server = { path = "../crates/rimap-server", default-features = false }
clap = { workspace = true }
clap_mangen = { workspace = true }   # new workspace dep
anyhow = { workspace = true }
```

Add `xtask` to the workspace `members`. `xtask -- man --out <dir>` calls
`fs::create_dir_all`, then `clap_mangen::generate_to(rimap_server::cli::command(),
&out)`, which recursively writes `rusty-imap-mcp.1` + one page per subcommand.
Default `--out` is `man/man1`. Because `xtask` builds `rimap-server` with
`default-features = false`, the test-support subcommands are absent from the
generated pages.

**`just man`** wraps `cargo run -p xtask --release --locked -- man --out man/man1`.

**Tests (TDD-able logic):** `xtask` unit test generates into a `tempdir` and
asserts (a) `rusty-imap-mcp.1` exists and is non-empty, (b) a page exists for
each production subcommand (`rusty-imap-mcp-login.1`, `rusty-imap-mcp-audit.1`,
`rusty-imap-mcp-migrate-keyring.1`), (c) **no** page exists for a test-support
subcommand (`rusty-imap-mcp-dump-tool-catalog.1`), (d) the top page contains the
`about` string. This is the failing-test-first anchor for the feature.

### 2. Package metadata (`crates/rimap-server/Cargo.toml`)

`[package.metadata.deb]` — no libdbus dependency (vendored static link):

```toml
[package.metadata.deb]
maintainer = "David Christensen <randomparity@gmail.com>"
copyright = "2026 David Christensen <randomparity@gmail.com>"
license-file = ["../../LICENSE-MIT", "0"]
extended-description = "Security-first Model Context Protocol server for IMAP email access."
section = "mail"
priority = "optional"
depends = "libc6"
recommends = "ca-certificates"
assets = [
    ["target/release/rusty-imap-mcp", "usr/bin/", "755"],
    ["../../man/man1/rusty-imap-mcp.1", "usr/share/man/man1/", "644"],
    ["../../man/man1/rusty-imap-mcp-*.1", "usr/share/man/man1/", "644"],
    ["../../README.md", "usr/share/doc/rusty-imap-mcp/README.md", "644"],
    ["../../CHANGELOG.md", "usr/share/doc/rusty-imap-mcp/CHANGELOG.md", "644"],
    ["../../LICENSE-MIT", "usr/share/doc/rusty-imap-mcp/LICENSE-MIT", "644"],
    ["../../LICENSE-APACHE", "usr/share/doc/rusty-imap-mcp/LICENSE-APACHE", "644"],
    ["../../NOTICE", "usr/share/doc/rusty-imap-mcp/NOTICE", "644"],
]
```

`[package.metadata.generate-rpm]` — `auto-req = "no"` (host `ldd` is wrong for a
cross-built binary), explicit `glibc` requires, dual-license assets. Man pages,
README, CHANGELOG, NOTICE, both LICENSE files mapped to standard paths.

Notes:
- `cargo-deb`/`cargo-generate-rpm` resolve `assets`/`license-file` `source`
  paths **relative to the package manifest** (`crates/rimap-server/`), hence the
  `../../` prefixes for workspace-root files. The binary `source` uses the
  literal `target/release/rusty-imap-mcp` string but the actual file is located
  via `--target <triple>` (see §4); confirm the tools honor `--target` for the
  binary asset path (they do: `--target` rewrites the profile dir).
- `cargo-deb`'s `$auto` dependency detection is **not** used (it would `ldd` the
  wrong architecture when packaging the arm64 binary on an x86_64 host).

### 3. Manpage in tarballs

Each of the 5 build jobs, after downloading the shared manpage artifact, copies
`man/man1/*.1` into `<stage>/share/man/man1/` before `tar czf`. The installer
(§4) installs only the binary, so tarball layout is additive and backward
compatible.

### 4. Release workflow wiring (`.github/workflows/release.yml`)

- **New `manpages` job** (`needs: verify-tag`, `permissions: contents: read`):
  checks out, installs stable Rust, `cargo run -p xtask --no-default-features
  --release --locked -- man --out man/man1`, uploads `man/man1/*.1` as artifact
  `rusty-imap-mcp-manpages` (`if-no-files-found: error`). All 5 build jobs gain
  `needs: [verify-tag, manpages]` and a "Download manpages" step.
- **x86_64 leg:** add `--target x86_64-unknown-linux-gnu` to the `cargo auditable
  build`; update tarball staging to copy from
  `target/x86_64-unknown-linux-gnu/release/`; add man page to stage. After
  staging: install `cargo-deb` + `cargo-generate-rpm` (via
  `taiki-e/install-action`, SHA-pinned), run `cargo deb --no-build --no-strip
  --target x86_64-unknown-linux-gnu` and `cargo generate-rpm --target
  x86_64-unknown-linux-gnu`, copy the `.deb`/`.rpm` next to the tarball,
  `lintian`/`rpmlint` (warn-only, `continue-on-error`), and a Debian/Fedora
  container **install-test** asserting `rusty-imap-mcp --version`. Upload
  `.deb`/`.rpm` alongside the tarball.
- **aarch64 leg:** add `--target aarch64-unknown-linux-gnu` to the in-container
  `cargo auditable build` so output lands at `target/aarch64-unknown-linux-gnu/
  release/`; `chown -R` `target/` back to the runner user (it is root-owned from
  the container). Update tarball staging path + add man page. Host-side (runner
  is x86_64): install `cargo-deb`/`cargo-generate-rpm`, run them with `--target
  aarch64-unknown-linux-gnu`, copy artifacts, `lintian`/`rpmlint` warn-only.
  **No** emulated install-test for arm64 (structural lint only; x86_64
  install-test + static-link guarantee cover the dependency contract — ADR-0006).
- **macOS / ppc64le / s390x legs:** unchanged except adding the man page to
  tarball staging (download-manpages step + copy).
- **`release` job:** after downloading artifacts, stage `install.sh` with the tag
  baked into its default-version line (a marker-replacement step; assert the
  marker was found so a silent no-op fails the release). Expand `SHA256SUMS.txt`
  generation to hash **every** release file — tarballs, `.deb`, `.rpm`, and
  `install.sh` — so the installer's own integrity can be checked and packages get
  published checksums. Attach `install.sh` + `.deb` + `.rpm` to the release
  (extend the `gh release create` asset globs). Keep the provenance attestation
  covering tarballs + `SHA256SUMS.txt` (optionally extend to packages).
  - **Compatibility guard:** `homebrew`'s `sum_for` greps `SHA256SUMS.txt` by
    exact tarball filename; adding `.deb`/`.rpm`/`install.sh` lines does not
    change the tarball lines it matches. Verified by keeping tarball filenames
    identical.
- **New `installer-smoke` job** (`needs: release`, `runs-on: ubuntu-latest`,
  `contents: read`): downloads `install.sh` + `SHA256SUMS.txt` from the published
  release, verifies `install.sh`'s checksum against the manifest, runs it with
  `RUSTY_IMAP_MCP_INSTALL_DIR` set, and asserts the installed
  `rusty-imap-mcp --version` output contains the `Cargo.toml` version. Stable
  tags only.

### 5. `install.sh` (repo root)

POSIX `sh` (`set -eu`), shellcheck/shfmt-clean. Adapted from bzr's installer:

- Env knobs: `RUSTY_IMAP_MCP_VERSION` (default: latest stable via the GitHub
  releases API; the release-staged copy bakes the tag as the default),
  `RUSTY_IMAP_MCP_INSTALL_DIR` (default `$HOME/.local/bin`). Undocumented test
  overrides: `RUSTY_IMAP_MCP_BASE_URL` (release download base) and
  `RUSTY_IMAP_MCP_SKIP_SMOKE`.
- `detect_target` maps `uname -s`/`-m` to the 5 built triples; unsupported →
  exit 2 with fallbacks (`cargo install`, distro `.deb`/`.rpm`, Homebrew).
- Downloads `rusty-imap-mcp-<tag>-<triple>.tar.gz` and `SHA256SUMS.txt`, verifies
  the tarball's SHA-256 (`sha256sum -c` / `shasum -a 256 -c`), extracts, installs
  the binary `0755` to the prefix, and (unless skipped) runs `--version` as a
  smoke check. On smoke failure emits a libdbus hint scoped to the non-vendored
  arches (ppc64le/s390x): install `libdbus-1-3`/`dbus-libs`, or use the
  `.deb`/`.rpm`, or `cargo install`. Prints a PATH hint if the prefix is not on
  `PATH`. Distinct non-zero exit codes per failure class (missing cmd, unsupported
  platform, download, checksum, extract).
- A marker line (`RUSTY_IMAP_MCP_VERSION="${RUSTY_IMAP_MCP_VERSION:-}"`) is what
  the release job rewrites to bake the tag; the version-pin comment documents it.

### 6. Documentation

- `RELEASING.md`: move #545 out of "Planned"; document the `manpages` and
  `installer-smoke` jobs and the package/installer assets in "What automation
  does"; update the pipeline order diagram.
- `README.md`: add an install section covering the one-line installer, the
  `.deb`/`.rpm` packages (with the "no libdbus needed on amd64/arm64" note), and
  a pointer to `man rusty-imap-mcp`.
- Homebrew template: add `man1.install "..."` so a source/bottle install also
  places the man page (best-effort; does not gate the bottle).

## Failure modes & edge cases

- **Manpage artifact missing in a build job** → `download-artifact` fails the
  job (fail-loud); tarball would otherwise silently omit the page.
- **`xtask` fails to build** (e.g., `cli` not exposed) → `manpages` job fails,
  gating all builds. This is why the `cli`-exposure change and the xtask test
  land first (TDD).
- **RPM version with a `-` (prerelease)** → `cargo-generate-rpm` hard-errors
  (`-` separates Version from Release in NVR). `verify-tag` already rejects tags
  containing `-`, so stable releases never hit this; no `~`-rewrite is needed
  here (unlike bzr, which supports rc tags). Documented as a known constraint.
- **arm64 `target/` root-owned after container build** → host-side packaging
  hits EACCES. Mitigated by `chown -R "$(id -u):$(id -g)" target` after the
  container step (same pattern bzr uses).
- **`install.sh` marker not found during release staging** → the replacement
  step asserts a change occurred and fails the release, preventing an installer
  that defaults to "latest" being shipped as a version-pinned asset silently.
- **Unsupported platform in installer** → exit 2 with actionable alternatives,
  not a confusing tar error.
- **Neither curl nor wget / neither sha256sum nor shasum present** → exit 3
  before any download.
- **`SHA256SUMS.txt` now lists packages/installer** → homebrew job unaffected
  (exact-filename grep on tarball names). Guard: a note + unchanged tarball names.

## Testing & verification

- **Unit:** `xtask` manpage-generation test (see §1) — the TDD anchor. Runs in
  `just test` / `just ci` on the host.
- **Static:** `shellcheck` + `shfmt` on `install.sh` (prek); `actionlint` +
  `zizmor` on the workflow (prek + CI required check). `cargo deb`/`cargo
  generate-rpm` config is validated implicitly by the release job; add a
  `just`-runnable local packaging smoke is **out of scope** (requires the tools
  installed) but the commands are documented.
- **CI (release-time, not PR):** `lintian`/`rpmlint` warn-only; x86_64
  Debian+Fedora container install-tests; `installer-smoke` end-to-end against the
  published release.
- **Manual (post-first-tag):** install the `.deb` in a clean `debian:stable`
  container without `libdbus-1-3`; install the `.rpm` in `fedora:latest` without
  `dbus-libs`; run `curl … | sh`; confirm `man rusty-imap-mcp`.

## Rollback / cleanup

- The change is additive to the release pipeline; reverting the branch restores
  the prior release behavior. No persisted state, no schema/migration.
- If packaging proves flaky on the debut tag, the package steps are `if:`-guarded
  per matrix leg and the release still publishes tarballs + installer; a follow-up
  patch tag can re-enable. (Unlike a bad Homebrew push, a missing package asset
  does not break an existing install path.)
- `man/man1/` is a generated directory; it is git-ignored (add to `.gitignore`)
  and never committed — regenerated each release and locally via `just man`.

## Open questions (for spec review)

- Should the build-provenance attestation cover the `.deb`/`.rpm` (Scorecard
  Signed-Releases) as bzr does, or is tarball+SHA256SUMS coverage sufficient for
  this phase? (Leaning: extend to packages; cheap and closes the gap.)
- Confirm `cargo-deb` / `cargo-generate-rpm` current stable versions to pin in
  `taiki-e/install-action` at implementation time (look up, do not assume).
