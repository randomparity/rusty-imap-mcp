# Native Packaging: deb/rpm, Manpages, and Shell Installer (Phase 4) Design

Date: 2026-07-11
Status: Reviewed (adversarial spec review, 2 iterations — 7 findings addressed: feature-unification hazard, package-content assertion, installer security framing, installer-variant/smoke coverage; then checksummed-copy identity, installer-smoke API flakiness/leaf semantics, and error-path test coverage)
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
  plus one page per subcommand (`rusty-imap-mcp-login.1`, `-audit.1`, etc.), and
  the built amd64/arm64 `.deb`/`.rpm` **provably** contain
  `usr/share/man/man1/rusty-imap-mcp.1` (asserted at release time — §4).
- `curl -fsSL <raw install.sh URL> | sh` installs the latest stable release on
  Linux (x86_64/aarch64/ppc64le/s390x) and macOS (aarch64), checking the
  download's SHA-256 against `SHA256SUMS.txt` to detect corruption/truncation
  **before** extraction (integrity, not authenticity — see "Security posture"),
  and prints an actionable error (distinct exit code) on an unsupported platform
  or when the latest-version lookup fails.
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
Default `--out` is `man/man1`.

**Feature-unification hazard (must not be ignored).** `rimap-server` carries a
self dev-dependency that enables `test-support` unconditionally for its own tests
(`crates/rimap-server/Cargo.toml`), and `just test`/`just ci` run
`cargo nextest run --workspace`. Under such a run, `rimap-server`'s tests build
with `test-support` ON. Whether Cargo shares that feature-unified `rimap-server`
lib with `xtask`'s in-process `rimap_server::cli::command()` call is
resolver-dependent and not something the spec should rely on. Two consequences:
1. An in-process unit test that asserts "*no* `dump-tool-*` page exists" is
   **fragile** — it can observe a `test-support`-ON CLI under `just ci` and fail
   (or, worse, be reordered away and silently validate the wrong CLI).
2. The pages that actually **ship** come from the release `manpages` job, which
   builds `xtask` alone with `test-support` OFF — a *different* feature-set than a
   `--workspace` test run sees. A green in-process test would not prove the
   shipped pages are clean.

Resolution (both required):
- **Unit test asserts only robust positives** (feature-independent): (a)
  `rusty-imap-mcp.1` exists and is non-empty; (b) a page exists for each
  *always-present* production subcommand (`login`, `audit`, `migrate-keyring`);
  (c) the top page contains the `about` string. It does **not** assert the
  absence of a `test-support` page.
- **The clean-page guarantee lives at the generating build**, not the unit test:
  the release `manpages` job (and `just man`) run
  `cargo run -p xtask --no-default-features …` and then a guard step **fails** if
  any `rusty-imap-mcp-dump-tool-*.1` was emitted. This asserts the negative at the
  exact build that produces the shipped pages, immune to workspace-test
  unification. Before treating any of this as an anchor, confirm empirically that
  `just ci` emits zero `dump-tool-*` pages.

Both `just man` and the workflow use the **same** invocation
(`cargo run -p xtask --no-default-features --release --locked -- man --out
man/man1`) so local and CI generation cannot diverge.

**`just man`** wraps that exact command.

The unit test (robust positives above) is the failing-test-first TDD anchor for
the feature; the `manpages`-job guard is the ship-gate for the negative.

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
  checks out, installs stable Rust, runs the shared invocation `cargo run -p
  xtask --no-default-features --release --locked -- man --out man/man1`, then a
  **guard step fails the job** if any `man/man1/rusty-imap-mcp-dump-tool-*.1`
  exists (proves the shipped pages carry no test-support subcommand — the F1
  negative asserted at the generating build). Uploads `man/man1/*.1` as artifact
  `rusty-imap-mcp-manpages` (`if-no-files-found: error`). All 5 build jobs gain
  `needs: [verify-tag, manpages]` and a "Download manpages" step.
- **x86_64 leg:** add `--target x86_64-unknown-linux-gnu` to the `cargo auditable
  build`; update tarball staging to copy from
  `target/x86_64-unknown-linux-gnu/release/`; add man page to stage. After
  staging: install `cargo-deb` + `cargo-generate-rpm` (via
  `taiki-e/install-action`, SHA-pinned), run `cargo deb --no-build --no-strip
  --target x86_64-unknown-linux-gnu` and `cargo generate-rpm --target
  x86_64-unknown-linux-gnu`, copy the `.deb`/`.rpm` next to the tarball, then a
  **package-content assertion** (F2): `dpkg-deb --contents *.deb` and `rpm -qlp
  *.rpm` must each list `usr/share/man/man1/rusty-imap-mcp.1` **and** at least one
  `rusty-imap-mcp-*.1` subcommand page — the step `grep`s and fails on a miss, so
  a wrong download path, step-ordering slip, or zero-match asset glob cannot ship
  a man-page-less package silently. Then `lintian`/`rpmlint` (warn-only,
  `continue-on-error`) and a Debian/Fedora container **install-test** asserting
  `rusty-imap-mcp --version`. Upload `.deb`/`.rpm` alongside the tarball.
- **aarch64 leg:** add `--target aarch64-unknown-linux-gnu` to the in-container
  `cargo auditable build` so output lands at `target/aarch64-unknown-linux-gnu/
  release/`; `chown -R` `target/` back to the runner user (it is root-owned from
  the container). Update tarball staging path + add man page. Host-side (runner
  is x86_64): install `cargo-deb`/`cargo-generate-rpm`, run them with `--target
  aarch64-unknown-linux-gnu`, copy artifacts, run the **same package-content
  assertion** as the x86_64 leg (`dpkg-deb --contents` / `rpm -qlp` are arch-
  agnostic and run fine host-side), then `lintian`/`rpmlint` warn-only. **No**
  emulated install-test for arm64 (structural lint + content assertion only;
  x86_64 install-test + static-link guarantee cover the dependency contract —
  ADR-0006).
- **macOS / ppc64le / s390x legs:** unchanged except adding the man page to
  tarball staging (download-manpages step + copy).
- **`release` job:** after downloading artifacts, stage `install.sh` with the tag
  baked into its default-version line (a marker-replacement step; assert the
  marker was found so a silent no-op fails the release). Expand `SHA256SUMS.txt`
  generation to hash **every** release file — tarballs, `.deb`, `.rpm`, and the
  staged (tag-baked) `install.sh`. **Which `install.sh` the checksum covers
  (finding A):** the hashed file is the **release-asset copy** (marker baked), so
  `SHA256SUMS.txt` gives the *pinned, verifiable* install path — download that
  asset, check it against the manifest, run it (no API call, deterministic
  version). It does **not** cover the convenience raw one-liner (`curl raw | sh`),
  whose repo copy has the marker unset and therefore a different hash; that path
  rests on TLS+origin trust only (Security posture). README documents the two
  paths distinctly and never implies the piped raw script is checksum-verifiable.
  Attach `install.sh` + `.deb` + `.rpm` to the release
  (extend the `gh release create` asset globs). Extend the provenance attestation
  `subject-path` to cover the `.deb`/`.rpm` alongside the tarballs +
  `SHA256SUMS.txt` (resolved decision — closes the Scorecard Signed-Releases gap
  and gives the installer's `gh attestation verify` advice packages to verify).
  - **Compatibility guard:** `homebrew`'s `sum_for` greps `SHA256SUMS.txt` by
    exact tarball filename; adding `.deb`/`.rpm`/`install.sh` lines does not
    change the tarball lines it matches. Verified by keeping tarball filenames
    identical.
- **New `installer-smoke` job** (`needs: release`, `runs-on: ubuntu-latest`,
  `contents: read`): a **downstream leaf** — like `publish-crates`/`homebrew`, its
  failure does **not** un-publish the already-created release (finding B); it is a
  post-publish signal, not a gate. It checks out the repo (for the `Cargo.toml`
  version and the user-facing `install.sh`) and runs the **checked-out repo copy**
  with **`RUSTY_IMAP_MCP_VERSION=<the just-pushed tag>`** — pinning the version
  **deterministically** so the job never touches the unauthenticated latest-version
  API (whose 60-req/hr/IP limit the spec flags as a real hazard — driving it live
  from a shared GitHub-runner IP would make this a self-inflicted flaky gate,
  finding B). Pinning still exercises the whole user-facing chain that can break in
  a release: `detect_target` → tarball + `SHA256SUMS.txt` download → checksum →
  extract → install → `--version` matches `Cargo.toml`. The one branch pinning
  skips — the API latest-version resolve (exit 4) — is covered **deterministically**
  by the host shell test's fixture/mock (below), not by a live API call. Stable
  tags only.

### 5. `install.sh` (repo root)

POSIX `sh` (`set -eu`), shellcheck/shfmt-clean. Adapted from bzr's installer:

- Env knobs: `RUSTY_IMAP_MCP_VERSION` (release tag to install),
  `RUSTY_IMAP_MCP_INSTALL_DIR` (default `$HOME/.local/bin`). Undocumented test
  overrides: `RUSTY_IMAP_MCP_BASE_URL` (release download base) and
  `RUSTY_IMAP_MCP_SKIP_SMOKE`.
- **Two copies, one script (F4).** The single `install.sh` source lives at the
  repo root. The README one-liner fetches the **raw repo copy** (marker unset →
  resolves the latest stable tag via the GitHub releases API). The release job
  additionally attaches a **release-asset copy** with the tag baked into the
  marker default, for reproducible/pinned installs. They are the same code; only
  the default version differs. The `installer-smoke` job tests the marker-unset
  (raw) behavior — the file users run.
- `detect_target` maps `uname -s`/`-m` to the 5 built triples; unsupported →
  exit 2 with fallbacks (`cargo install`, distro `.deb`/`.rpm`, Homebrew).
- **Latest-version resolution failure is a first-class path (F4):** when
  `RUSTY_IMAP_MCP_VERSION` is unset, the resolver calls the unauthenticated
  releases API (subject to the 60-req/hr/IP limit — a real hazard behind shared
  NAT/CI). API unreachable, HTTP non-2xx (incl. 403 rate-limit), or an
  unparsable `tag_name` → **exit 4** with an actionable message that names the
  reliable workaround: re-run with `RUSTY_IMAP_MCP_VERSION=vX.Y.Z`. This keeps the
  "installs the latest stable" criterion falsifiable and gives shared-IP users a
  deterministic path.
- Downloads `rusty-imap-mcp-<tag>-<triple>.tar.gz` and `SHA256SUMS.txt`, checks
  the tarball's SHA-256 (`sha256sum -c` / `shasum -a 256 -c`) **for corruption/
  truncation** (see "Security posture" — integrity, not authenticity), extracts,
  installs the binary `0755` to the prefix, and (unless skipped) runs `--version`
  as a smoke check. On smoke failure emits a libdbus hint scoped to the
  non-vendored arches (ppc64le/s390x): install `libdbus-1-3`/`dbus-libs`, or use
  the `.deb`/`.rpm`, or `cargo install`. Prints a PATH hint if the prefix is not
  on `PATH`. Distinct non-zero exit codes per failure class (3 = missing cmd, 2 =
  unsupported platform, 4 = version-resolve/download, 5 = checksum, 6 = extract).
- A marker line (`RUSTY_IMAP_MCP_VERSION="${RUSTY_IMAP_MCP_VERSION:-}"`) is what
  the release job rewrites to bake the tag; the version-pin comment documents it.
  The rewrite step asserts the marker was found (else the release fails), so a
  version-pinned asset can never be shipped silently unchanged.

### Security posture (F3)

The installer's SHA-256 check is **integrity, not authenticity**. `SHA256SUMS.txt`
is fetched from the same GitHub release origin as the tarball and is **unsigned**,
so it defends against a corrupted/truncated download and against a
staging bug where `install.sh` and its recorded checksum disagree — **not**
against an attacker who can tamper with the release assets or MITM the transport
(TLS is the only authenticity control in that path). The advertised `curl … | sh`
one-liner also executes the fetched script under implicit origin+TLS trust. This
is a deliberate scope boundary for this phase: verifying the pipeline's existing
build-provenance attestation (`gh attestation verify`) would add a `gh`/cosign
runtime dependency to a minimal POSIX installer, which is out of scope here (and
distinct from the distro-signing-key path ADR-0006 rejected). The README states
this residual trust model plainly and points security-sensitive users at
`gh attestation verify` on the downloaded tarball as the authenticity upgrade.

### 6. Documentation

- `RELEASING.md`: move #545 out of "Planned"; document the `manpages` and
  `installer-smoke` jobs and the package/installer assets in "What automation
  does"; update the pipeline order diagram.
- `README.md`: add an install section covering the `.deb`/`.rpm` packages (with
  the "no libdbus needed on amd64/arm64" note), a pointer to `man rusty-imap-mcp`,
  and **two clearly-distinguished installer paths** (finding A):
  1. *Convenience:* `curl -fsSL <raw install.sh URL> | sh` — TLS+origin trust
     only, resolves the latest tag via the API; **not** checksum-verifiable
     (you're piping). Pin with `RUSTY_IMAP_MCP_VERSION=vX.Y.Z` when the
     unauthenticated API is rate-limited.
  2. *Verifiable:* download the release-asset `install.sh`, check it against
     `SHA256SUMS.txt`, then run it — pinned version, no API call, and the file
     you verify is the file you run.

  State the installer's **residual trust model** (integrity-not-authenticity —
  "Security posture") and point security-sensitive users at `gh attestation
  verify` on the downloaded tarball/package for authenticity.
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
- **Latest-version API unreachable / rate-limited (403) / unparsable** (F4) →
  exit 4 naming the `RUSTY_IMAP_MCP_VERSION=vX.Y.Z` workaround, rather than
  proceeding to build a download URL from an empty tag. The 60-req/hr/IP
  unauthenticated limit is the expected trigger behind shared NAT/CI.
- **Man page missing from a built package** (F2) → the `dpkg-deb --contents` /
  `rpm -qlp` assertion greps for `rusty-imap-mcp.1` + a subcommand page and fails
  the job; a zero-match asset glob or path slip cannot ship silently.
- **`just ci` emits `dump-tool-*` pages** (F1) → the `manpages`-job guard fails
  the release; the unit test deliberately does not depend on this (feature
  unification makes an in-process negative assertion unreliable under
  `--workspace`).
- **Neither curl nor wget / neither sha256sum nor shasum present** → exit 3
  before any download.
- **`SHA256SUMS.txt` now lists packages/installer** → homebrew job unaffected
  (exact-filename grep on tarball names). Guard: a note + unchanged tarball names.

## Testing & verification

- **Unit:** `xtask` manpage-generation test — robust positive assertions only
  (§1): top page + always-present subcommand pages + `about` string. Runs in
  `just test` / `just ci` on the host. The negative (no test-support page) is
  enforced by the `manpages`-job guard, not this test (F1).
- **Installer shell test:** a host-runnable test (fixtures via
  `RUSTY_IMAP_MCP_BASE_URL`; no network) that exercises the happy version-pin path
  **and deliberately triggers every handled error path** (finding C — repo
  standard: each handled error has a triggering test):
  - exit 2 — unsupported platform (`uname` shim / forced unknown arch).
  - exit 3 — a required command absent (`sha256sum`/`shasum`, `curl`/`wget`).
  - **exit 4** — latest-version resolve failure: fixture API endpoint returning a
    403 / unparsable `tag_name`, and a missing tarball (download 404).
  - **exit 5** — checksum mismatch: fixture `SHA256SUMS.txt` records a wrong hash
    for the tarball (this is the F3 integrity control — its trigger must be
    tested).
  - **exit 6** — extract failure: a fixture "tarball" that is garbage but whose
    recorded checksum matches (so it clears exit 5 and fails at `tar`).

  This gives installer logic a deterministic signal independent of a live
  release, and keeps the API-resolve branch off the flaky live path (finding B).
- **Static:** `shellcheck` + `shfmt` on `install.sh` (prek); `actionlint` +
  `zizmor` on the workflow (prek + CI required check). A `just`-runnable local
  packaging smoke is **out of scope** (requires the tools installed) but the
  commands are documented.
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

## Resolved decisions

- **Build-provenance attestation covers `.deb`/`.rpm`** (not just tarballs) —
  cheap, closes the Scorecard Signed-Releases gap, and gives the installer's
  authenticity-upgrade advice (`gh attestation verify`) something to verify on
  packages too.
- **Installer security framing is integrity-not-authenticity** — the checksum
  defends corruption/truncation, not tampering; the residual trust model is
  documented in README and "Security posture" (F3).

## Open questions (implementation-time lookups)

- Pin `cargo-deb` / `cargo-generate-rpm` / `clap_mangen` to their current stable
  versions in `taiki-e/install-action` and `[workspace.dependencies]` at
  implementation time (look up, do not assume from memory — repo convention).
