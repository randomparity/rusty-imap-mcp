# ADR-0006: Native packaging build topology — xtask manpages, host-side deb/rpm, amd64+arm64 only

- **Status:** Accepted
- **Date:** 2026-07-11
- **Issue:** [#545](https://github.com/randomparity/rusty-imap-mcp/issues/545) (labelled "Phase 2C"; this is ADR-0002's **Phase 4**)
- **Spec:** [docs/superpowers/specs/2026-07-11-issue-545-native-packaging-design.md](../superpowers/specs/2026-07-11-issue-545-native-packaging-design.md)
- **Extends:** [ADR-0002](0002-phased-bzr-release-parity-and-direct-publish.md) (Phase 4 line)
- **Supersedes:** none

## Context

ADR-0002 sequenced bzr-parity release work into phases and deferred "deb/rpm
packaging, manpages, `install.sh`/`install.ps1`, `installer-smoke`" to its
**Phase 4** (issue #545 calls the same work "Phase 2C" — the label differs, the
scope is identical). Phases 1–3 (tarballs + Homebrew, the `-dev` model, crates.io
topology) are recorded in ADR-0002/0003/0004. This ADR records the build-topology
decisions specific to native packaging, which a future reader would otherwise
re-derive from the reference repo [`randomparity/bzr`](https://github.com/randomparity/bzr).

Three facts about `rusty-imap-mcp` diverge from bzr and force distinct decisions:

1. **It is an 8-crate workspace, not a single crate.** The binary
   `rusty-imap-mcp` is built by `crates/rimap-server`. Cargo package metadata for
   `cargo-deb` / `cargo-generate-rpm` therefore lives in
   `crates/rimap-server/Cargo.toml`, and the CLI type an manpage generator must
   introspect (`Cli`) is currently binary-private (`mod cli` in `main.rs`), not
   reachable from the library.
2. **The amd64/arm64 release binaries static-link libdbus** via the
   `vendored-keyring` feature (ADR-0002 Phase 1 / the release workflow). bzr's
   `.deb` declares a `libdbus-1-3` runtime dependency; a vendored binary needs
   none.
3. **The release matrix builds no Windows target** and builds the non-x86_64
   Linux legs inside **emulated QEMU containers** (`docker run --platform`) that
   emit their binary to `target/release/`, not `cross`'s `target/<triple>/release/`.

## Decision

**1. Generate manpages with a workspace `xtask` crate that introspects a
library-exposed CLI builder.** Add `xtask/` as a new **excluded**-from-`publish`,
in-workspace member crate depending on `rimap-server` (`default-features = false`)
and exposing `cargo run -p xtask -- man --out man/man1`. It calls a new
`rimap_server::cli::command() -> clap::Command` helper — the *same* builder
`main.rs` uses to parse args, carrying `.version(rimap_core::version::version())`
— and feeds it to `clap_mangen::generate_to`, which recursively emits
`rusty-imap-mcp.1` plus one page per subcommand. To make `Cli` reachable, the
existing `cli` module moves from `main.rs` into `lib.rs` as `#[doc(hidden)] pub
mod cli` (matching the existing `boot`/`mcp`/`tools` pattern); `main.rs` consumes
it via the library. Building `xtask` with `default-features = false` keeps the
`#[cfg(feature = "test-support")]` subcommands (`dump-tool-*`,
`--allow-empty-accounts`) out of the shipped manpages, so they reflect the
production CLI.

**2. Package `.deb` and `.rpm` for amd64 + arm64 only; declare no libdbus
dependency.** Both packaged arches are the `vendored-keyring` (static-libdbus)
legs, so `[package.metadata.deb]` and `[package.metadata.generate-rpm]` declare
only the C runtime (`libc6` / `glibc`) plus `ca-certificates` (recommended).
`powerpc64le` and `s390x` remain **tarball-only** (they are not vendored and have
a near-zero packaged audience), which is why no per-arch libdbus-dependency
handling is needed at all.

**3. Build packages host-side with `cargo-deb` / `cargo-generate-rpm --target`,
reconciling the emulated arm64 binary path.** `cargo deb --no-build --no-strip
--target <triple>` and `cargo generate-rpm --target <triple>` package an
already-built binary and derive the Debian/RPM `Architecture` field from the Rust
target triple. The x86_64 leg builds natively into
`target/x86_64-unknown-linux-gnu/release/` (add `--target` to its `cargo
auditable build`). The aarch64 leg builds in an emulated container; its command
gains `--target aarch64-unknown-linux-gnu` so the binary lands at
`target/aarch64-unknown-linux-gnu/release/` on the shared volume, where the
host-side packaging tools (running as the runner user after a `chown -R` of the
root-owned `target/`) find it with the correct architecture metadata. Packaging
tools thus never run under emulation.

## Consequences

- Manpages are generated once (a `manpages` job, mirroring bzr) and shared to the
  build legs via an artifact; the man page ships in **every** tarball (all 5
  arches) and in the amd64/arm64 packages. Regenerating requires only
  `cargo run -p xtask -- man`, addable as `just man`.
- The `cli` module becoming library-visible is a deliberate, `#[doc(hidden)]`
  surface addition — not a stable public API. `xtask` is the only in-tree
  consumer besides `main.rs`.
- Adding `--target` to the x86_64 and aarch64 build commands moves their release
  binaries from `target/release/` to `target/<triple>/release/`; the tarball
  staging steps for those two legs update their copy source accordingly. The
  macOS/ppc64le/s390x legs are unchanged except for adding the man page to their
  tarball staging.
- Packages carry no libdbus dependency and install cleanly on minimal
  Debian/Fedora images without `libdbus-1-3` / `dbus-libs` — verified by an
  x86_64 container install-test in CI. The trade-off is that the arm64 package is
  install-tested only structurally (host-side lint), not by an emulated
  `apt-get install`, because that would require QEMU in the packaging step; the
  x86_64 install-test plus the static-link guarantee cover the dependency
  contract.
- If a future release wants ppc64le/s390x packages, this ADR must be revisited:
  those arches would reintroduce the per-arch libdbus dependency declarations
  that decision 2 avoids, which a single shared `[package.metadata.*]` block
  cannot express without a build-time rewrite.

## Considered & rejected

- **Generate manpages in `build.rs`.** Rejected: `build.rs` runs before the
  crate's own types exist and cannot cleanly introspect the `clap` derive tree;
  it would also regenerate on every build and pull `clap_mangen` into the normal
  build graph. The `xtask` pattern isolates the generator, runs it on demand, and
  is bzr's established approach.
- **A hidden `gen-manpages` subcommand on the shipped binary.** Rejected: it adds
  `clap_mangen` to the production binary's dependency tree and puts a
  build-tooling command on the user-facing CLI (even if hidden). `xtask` keeps
  `clap_mangen` out of the shipped artifact entirely.
- **Package all five arches (full bzr parity).** Rejected for this issue
  (confirmed with the maintainer): the issue scopes "amd64/arm64 debs", and
  ppc64le/s390x are non-vendored, so packaging them reintroduces libdbus
  dependency handling the vendored simplification exists to avoid, for a
  negligible packaged audience.
- **Build the arm64 packages inside the emulated container** (install
  `cargo-deb`/`cargo-generate-rpm` in the arm64 image). Rejected: `cargo install`
  of the packaging tools under QEMU compiles them emulated (minutes of avoidable
  wall-clock each release). Relocating the build output to the `--target` path and
  packaging host-side is faster and keeps one packaging code path for both arches.
- **Windows `install.ps1` + zip artifacts** (bzr ships them). Rejected: the
  release matrix builds no Windows binary, so there is nothing to install; the
  installer is shell-only (`install.sh`), matching the issue scope.
