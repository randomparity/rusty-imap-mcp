# Native Packaging (deb/rpm, Manpages, Installer) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship bzr-parity native distribution for `rusty-imap-mcp` — clap_mangen manpages, amd64/arm64 `.deb`/`.rpm` packages, and a `curl … | sh` installer — wired into `release.yml`.

**Architecture:** A workspace `xtask` crate introspects a library-exposed `rimap_server::cli::command()` to generate roff manpages; Cargo package metadata drives host-side `cargo-deb`/`cargo-generate-rpm` (amd64/arm64 only, no libdbus dep — the binaries static-link it via `vendored-keyring`); a POSIX-`sh` `install.sh` downloads+checksums the release tarball. The release workflow gains a `manpages` job, package steps on the two vendored Linux legs, installer staging, and an `installer-smoke` leaf.

**Tech Stack:** Rust (clap 4.5, clap_mangen 0.3.0), cargo-deb 3.7.0, cargo-generate-rpm 0.21.0, GitHub Actions, POSIX sh.

**Spec:** `docs/superpowers/specs/2026-07-11-issue-545-native-packaging-design.md`
**ADR:** `docs/ADR/0006-native-packaging-build-topology.md`
**Reference impl:** `~/src/bzr` (single-crate; ships the same four subsystems).

## Global Constraints

- **Branch:** `feat/native-packaging-545`. **Base:** `main`. Never commit on `main`.
- **Guardrails (must stay green):** `just ci` (= `fmt-check lint test test-msrv deny check-no-openssl mcp-conformance-node check-tools-doc check-metadata test-publish-script typos`). Prek hooks run `shellcheck`, `shfmt`, `actionlint`, `zizmor` on commit. Clippy is `-D warnings`, workspace-wide.
- **Rust:** edition 2024, MSRV 1.88.0 (`just test-msrv`), dev toolchain 1.94.0. Dependencies declared once in root `[workspace.dependencies]`; member crates use `{ workspace = true }` — never inline versions.
- **Clippy invariants:** no `unwrap()`/`panic!`/`todo!`/`print_stdout`/`print_stderr` in non-test code; no `#[allow]` (use `#[expect(reason=…)]`); `thiserror` for libs, `anyhow` for `rimap-server`/`xtask`; newtypes over primitives; explicit destructuring (no `matches!`); 100-char lines; absolute imports only; Google-style docstrings on public APIs; `#![deny(missing_docs)]` on public crates.
- **Package arch scope:** amd64 + arm64 only (both `vendored-keyring`). Packages declare **no** libdbus dependency. ppc64le/s390x stay tarball-only.
- **Installer:** POSIX `sh`, `set -eu`, shellcheck+shfmt clean. Env prefix `RUSTY_IMAP_MCP_`. Reads `SHA256SUMS.txt` (this repo's name — **not** bzr's `SHA256SUMS`). Exit codes: 2=unsupported platform, 3=missing command, 4=version-resolve/download, 5=checksum mismatch, 6=extract; post-install `--version` smoke is **advisory → exit 0**.
- **Actions pinning:** every `uses:` is a 40-char SHA + version comment. Reuse existing pins already in the repo (do not introduce floating tags): `actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0`, `actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1`, `actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1`, `dtolnay/rust-toolchain@e97e2d8cc328f1b50210efc529dca0028893a2d9 # v1`, `docker/setup-qemu-action@06116385d9baf250c9f4dcb4858b16962ea869c3 # v4.1.0`, `taiki-e/install-action@16b05812d776ae1dfaabc8277e421fb6d2506419 # v2.82.7`, `actions/attest-build-provenance@0f67c3f4856b2e3261c31976d6725780e5e4c373 # v4.1.1`.

---

## File Structure

- **Modify** `crates/rimap-server/src/lib.rs` — add `#[doc(hidden)] pub mod cli;`.
- **Modify** `crates/rimap-server/src/main.rs` — drop `mod cli;`, consume `rimap_server::cli`.
- **Modify** `crates/rimap-server/src/cli/mod.rs` — add `pub fn command()`; widen submodule visibility (`pub(crate) mod` → `pub mod`).
- **Create** `xtask/Cargo.toml`, `xtask/src/main.rs`, `xtask/src/main_tests.rs`.
- **Modify** root `Cargo.toml` — add `xtask` to `members`; add `clap_mangen` to `[workspace.dependencies]`.
- **Modify** `crates/rimap-server/Cargo.toml` — add `[package.metadata.deb]` + `[package.metadata.generate-rpm]`.
- **Create** `install.sh` (repo root), `scripts/install.test.sh`.
- **Modify** `justfile` — add `man` and `test-installer` recipes; append `test-installer` to `ci`.
- **Modify** `.gitignore` — ignore generated `/man/`.
- **Modify** `.github/workflows/release.yml` — `manpages` job, package steps, installer staging, `installer-smoke`.
- **Modify** `RELEASING.md`, `README.md`, `homebrew/rusty-imap-mcp.rb.template`.

---

## Task 1: Expose the CLI from the library + shared `command()` builder

**Why:** `xtask` (Task 2) can only introspect library-visible types; `Cli` is currently binary-private (`mod cli` in `main.rs`). Exposing it via the lib and centralizing the `.version(...)` wiring in one builder means generated manpages match the CLI users run.

**Files:**
- Modify: `crates/rimap-server/src/lib.rs`
- Modify: `crates/rimap-server/src/cli/mod.rs`
- Modify: `crates/rimap-server/src/main.rs:5`, `:33`, `:35-40`
- Test: `crates/rimap-server/src/cli/mod.rs` (existing `#[cfg(test)] mod tests`)

**Interfaces:**
- Produces: `rimap_server::cli::command() -> clap::Command` (carries `.version(rimap_core::version::version())`); `rimap_server::cli::{Cli, Command, AuditAction}` become library-public; the `cli` submodules (`audit_merge`, `dry_run`, `migrate_keyring`, and the `test-support`-gated `dump_tool_*`) become `pub`.

- [ ] **Step 1: Write the failing test** — append to the `mod tests` block in `crates/rimap-server/src/cli/mod.rs`:

```rust
    #[test]
    fn command_builder_exposes_production_subcommands() {
        let cmd = crate::cli::command();
        assert_eq!(cmd.get_name(), "rusty-imap-mcp");
        assert!(cmd.get_version().is_some(), "version must be wired");
        let subs: Vec<&str> = cmd.get_subcommands().map(clap::Command::get_name).collect();
        for expected in ["login", "audit", "migrate-keyring"] {
            assert!(subs.contains(&expected), "missing subcommand {expected}; got {subs:?}");
        }
    }
```

- [ ] **Step 2: Run it, watch it fail** — `cargo test -p rimap-server --lib cli::tests::command_builder 2>&1 | tail -20`. Expected: FAIL — `command` not found in `crate::cli`.

- [ ] **Step 3: Add the builder + import** — in `crates/rimap-server/src/cli/mod.rs`, change the clap import and add the function after the `Cli` struct:

```rust
use clap::{CommandFactory, Parser, Subcommand};
```

```rust
/// The fully-configured top-level [`clap::Command`], carrying the runtime
/// version string.
///
/// Shared by the binary's argument parser (`main.rs`) and the `xtask` manpage
/// generator so generated pages match the CLI users actually run.
#[must_use]
pub fn command() -> clap::Command {
    <Cli as CommandFactory>::command().version(rimap_core::version::version())
}
```

- [ ] **Step 4: Expose `cli` from the library** — in `crates/rimap-server/src/lib.rs`, after the `pub mod tools;` block add:

```rust
#[doc(hidden)]
pub mod cli;
```

- [ ] **Step 5: Widen submodule visibility** — in `crates/rimap-server/src/cli/mod.rs`, change every submodule declaration from `pub(crate) mod` to `pub mod` (keep the `#[cfg(feature = "test-support")]` attributes exactly where they are):

```rust
pub mod audit_merge;
pub mod dry_run;
#[cfg(feature = "test-support")]
pub mod dump_tool_catalog;
#[cfg(feature = "test-support")]
pub mod dump_tool_doc;
#[cfg(feature = "test-support")]
pub mod dump_tool_schemas;
pub mod migrate_keyring;
```

- [ ] **Step 6: Point `main.rs` at the library module** — in `crates/rimap-server/src/main.rs`:
  - Delete line 5 `mod cli;`.
  - Change line 17 `use clap::{CommandFactory, FromArgMatches};` → `use clap::FromArgMatches;`. (After Step 6 the only `CommandFactory` user moves into `cli::command()`; leaving the import here trips `unused_imports` under `just lint`'s `-D warnings`.)
  - Change line 33 `use crate::cli::{AuditAction, Cli, Command};` → `use rimap_server::cli::{self, AuditAction, Cli, Command};`.
  - Replace `parse_cli` (lines 35-40) body's command construction so it reuses the shared builder:

```rust
fn parse_cli() -> Result<Cli, clap::Error> {
    let matches = cli::command().get_matches();
    Cli::from_arg_matches(&matches)
}
```

  - Any remaining `crate::cli::…` paths in `main.rs` (e.g. `cli::audit_merge::run`, `cli::migrate_keyring::migrate_one`, `cli::dump_tool_*`) now resolve via the `use …cli::{self,…}` import — no path change needed since they already read `cli::…`.

- [ ] **Step 7: Resolve `missing_docs` fallout** — making the submodules `pub` may surface `#![deny(missing_docs)]` on newly-public items. Run `just lint 2>&1 | rg -A2 missing_docs`. For each flagged item, add a one-line Google-style `///` doc (describe WHY/what it returns, not restate the name). Do **not** add `#[allow]`.

- [ ] **Step 8: Run the test + full lint** — `cargo test -p rimap-server --lib cli:: 2>&1 | tail -20` (expect PASS, existing cli tests still green) and `just lint` (expect clean). Also `cargo build -p rimap-server` to confirm the binary still links.

- [ ] **Step 9: Commit**

```bash
git add crates/rimap-server/src/lib.rs crates/rimap-server/src/cli/mod.rs crates/rimap-server/src/main.rs
git commit -m "refactor(cli): expose cli module + shared command() builder"
```

---

## Task 2: `xtask` crate — clap_mangen manpage generation

**Files:**
- Create: `xtask/Cargo.toml`, `xtask/src/main.rs`, `xtask/src/main_tests.rs`
- Modify: root `Cargo.toml` (`members`, `[workspace.dependencies]`)
- Modify: `justfile` (add `man` recipe), `.gitignore`

**Interfaces:**
- Consumes: `rimap_server::cli::command()` (Task 1).
- Produces: `cargo run -p xtask --no-default-features -- man --out <dir>` writing `<dir>/rusty-imap-mcp.1` + one page per subcommand.

- [ ] **Step 1: Add the workspace dependency + member** — in root `Cargo.toml`, add `"xtask",` to `members`, and under `[workspace.dependencies]` add (alphabetical placement near `clap`):

```toml
clap_mangen = "0.3.0"
```

- [ ] **Step 2: Create `xtask/Cargo.toml`**

```toml
[package]
name = "xtask"
version = "0.0.0"
edition.workspace = true
rust-version.workspace = true
publish = false
description = "Internal build helpers for rusty-imap-mcp (manpage generation)."
license.workspace = true

[lints]
workspace = true

[[bin]]
name = "xtask"
path = "src/main.rs"

[dependencies]
rimap-server = { path = "../crates/rimap-server", default-features = false }
clap = { workspace = true }
clap_mangen = { workspace = true }
anyhow = { workspace = true }
```

- [ ] **Step 3: Write the failing test** — `xtask/src/main_tests.rs`:

```rust
use std::fs;

use tempfile::tempdir;

use crate::generate_man;

#[test]
fn generates_top_and_production_subcommand_pages() {
    let dir = tempdir().unwrap();
    generate_man(dir.path()).unwrap();

    let top = dir.path().join("rusty-imap-mcp.1");
    let top_body = fs::read_to_string(&top).unwrap();
    assert!(!top_body.is_empty(), "top page empty");
    assert!(
        top_body.contains("Security-first MCP server"),
        "top page missing the CLI 'about' text",
    );

    // Always-present production subcommands (feature-independent — the negative
    // 'no dump-tool page' guarantee lives in the release manpages-job guard, not
    // here, because a --workspace test run may unify rimap-server with
    // test-support ON. See spec finding F1.)
    for page in [
        "rusty-imap-mcp-login.1",
        "rusty-imap-mcp-audit.1",
        "rusty-imap-mcp-migrate-keyring.1",
    ] {
        assert!(dir.path().join(page).is_file(), "missing page {page}");
    }
}
```

  Add `tempfile = { workspace = true }` to a new `[dev-dependencies]` table in `xtask/Cargo.toml`.

- [ ] **Step 4: Create `xtask/src/main.rs`**

```rust
//! Build helpers for the `rusty-imap-mcp` workspace.
//!
//! Exposes a `man` subcommand that generates roff manpages for `rusty-imap-mcp`
//! and all of its subcommands by introspecting the clap CLI tree at
//! `rimap_server::cli::command()`.
//!
//! Run via `cargo run -p xtask --no-default-features -- man [--out DIR]`.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "xtask", about = "Internal build helpers for rusty-imap-mcp")]
struct Xtask {
    #[command(subcommand)]
    cmd: XtaskCmd,
}

#[derive(Subcommand)]
enum XtaskCmd {
    /// Generate roff manpages for `rusty-imap-mcp` and all subcommands.
    Man {
        /// Output directory; created if missing. Defaults to `man/man1` at the
        /// workspace root so packagers can consume a stable path.
        #[arg(long, default_value = "man/man1")]
        out: PathBuf,
    },
}

fn main() -> Result<()> {
    let xtask = Xtask::parse();
    match xtask.cmd {
        XtaskCmd::Man { out } => generate_man(&out),
    }
}

/// Render `rusty-imap-mcp.1` and one page per subcommand into `out`.
fn generate_man(out: &Path) -> Result<()> {
    fs::create_dir_all(out)
        .with_context(|| format!("creating manpage output directory {}", out.display()))?;
    clap_mangen::generate_to(rimap_server::cli::command(), out)
        .with_context(|| format!("writing manpages to {}", out.display()))?;
    Ok(())
}

#[cfg(test)]
// The workspace denies `clippy::unwrap_used`; tests opt out with an #[expect]
// (matches crates/rimap-server/src/cli/mod.rs). Without this, `just lint`
// (`--all-targets -D warnings`) fails on the test's .unwrap()s.
#[expect(clippy::unwrap_used, reason = "tests")]
#[path = "main_tests.rs"]
mod tests;
```

- [ ] **Step 5: Run the test, watch it fail then pass** — `cargo test -p xtask --no-default-features 2>&1 | tail -20`. (First run before main.rs existed = compile fail; after Step 4 = PASS.)

- [ ] **Step 6: Add the `just man` recipe** — in `justfile`, near the build recipes, add:

```makefile
# Generate roff manpages into man/man1/ (consumed by tarball/deb/rpm packaging).
# The pages exclude test-support subcommands because xtask depends on rimap-server
# with default-features = false (its `default = []`), so those #[cfg(feature =
# "test-support")] subcommands are compiled out of the CLI entirely (they are also
# #[command(hide = true)]). `--no-default-features` here is xtask-scoped defense
# (xtask has no features today) and matches the release job's invocation exactly.
man:
    cargo run -p xtask --no-default-features --release --locked -- man --out man/man1
```

- [ ] **Step 7: Ignore generated manpages** — append to `.gitignore`:

```gitignore
# Generated manpages (xtask / `just man`; shipped in release artifacts, never committed)
/man/
```

- [ ] **Step 8: Smoke the recipe** — `just man && ls man/man1/`. Expected: `rusty-imap-mcp.1`, `rusty-imap-mcp-login.1`, `rusty-imap-mcp-audit.1`, `rusty-imap-mcp-migrate-keyring.1`, `rusty-imap-mcp-audit-merge.1` (nested), and **no** `rusty-imap-mcp-dump-tool-*.1`. Confirm the F1 guarantee empirically: `ls man/man1/ | rg dump-tool` prints nothing.

- [ ] **Step 9: Commit**

```bash
git add xtask/ Cargo.toml justfile .gitignore
git commit -m "feat(xtask): generate clap_mangen manpages"
```

---

## Task 3: `install.sh` + shell unit test

**Files:**
- Create: `install.sh` (repo root), `scripts/install.test.sh`
- Modify: `justfile` (add `test-installer`, append to `ci`)

**Interfaces:**
- Produces (sourceable pure functions for the test): `map_target os arch` (echoes triple or returns 1), `verify_sha256 sums fname dir`, `resolve_version`, `main`. `main` is guarded so `source` does not run it.

- [ ] **Step 1: Write the failing test** — `scripts/install.test.sh`:

```bash
#!/usr/bin/env bash
# Unit + fixture tests for install.sh. Sources it with RUSTY_IMAP_MCP_SOURCED=1
# (which guards `main`) and drives the download/checksum/install flow against a
# local file:// fixture — no network, no live release. Run: `just test-installer`.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/.." && pwd)"
RUSTY_IMAP_MCP_SOURCED=1
export RUSTY_IMAP_MCP_SOURCED
# Fixtures hit missing file:// URLs on purpose; skip the production retry backoff
# so the two exit-4 negative cases fail fast instead of spinning ~25s each.
export RUSTY_IMAP_MCP_RETRY=0 RUSTY_IMAP_MCP_RETRY_DELAY=0
# shellcheck source=install.sh
. "$repo/install.sh"

failures=0
check() { # desc expected actual
    if [ "$2" = "$3" ]; then echo "ok: $1"; else
        echo "FAIL: $1 — expected [$2] got [$3]" >&2; failures=$((failures + 1)); fi
}
expect_exit() { # desc want-code cmd...
    local desc="$1" want="$2"; shift 2
    local got=0; ( "$@" ) >/dev/null 2>&1 || got=$?
    check "$desc" "$want" "$got"
}

# --- map_target (pure) -------------------------------------------------------
check "linux x86_64"  "x86_64-unknown-linux-gnu"     "$(map_target Linux x86_64)"
check "linux aarch64" "aarch64-unknown-linux-gnu"    "$(map_target Linux aarch64)"
check "linux arm64"   "aarch64-unknown-linux-gnu"    "$(map_target Linux arm64)"
check "linux ppc64le" "powerpc64le-unknown-linux-gnu" "$(map_target Linux ppc64le)"
check "linux s390x"   "s390x-unknown-linux-gnu"      "$(map_target Linux s390x)"
check "macos arm64"   "aarch64-apple-darwin"         "$(map_target Darwin arm64)"
expect_exit "unsupported platform -> 1" 1 map_target Linux riscv64

# --- verify_sha256 (pure) ----------------------------------------------------
fix="$(mktemp -d)"; trap 'rm -rf "$fix"' EXIT
echo payload > "$fix/pkg.tar.gz"
good="$(cd "$fix" && { command -v sha256sum >/dev/null 2>&1 && sha256sum pkg.tar.gz || shasum -a 256 pkg.tar.gz; })"
echo "$good" > "$fix/SHA256SUMS.txt"
expect_exit "checksum match -> 0" 0 verify_sha256 "$fix/SHA256SUMS.txt" pkg.tar.gz "$fix"
echo "deadbeef  pkg.tar.gz" > "$fix/bad.txt"
expect_exit "checksum mismatch -> 5" 5 verify_sha256 "$fix/bad.txt" pkg.tar.gz "$fix"

# --- main end-to-end via file:// fixture -------------------------------------
# The fixtures use file:// URLs; install.sh's http_get uses curl (which supports
# file://) and falls back to wget (which does NOT). Skip the e2e block on a
# curl-less host rather than report false exit-4 failures.
if ! command -v curl >/dev/null 2>&1; then
    echo "skip: curl not present; skipping file:// fixture tests"
    [ "$failures" -eq 0 ] && { echo "pure-function tests passed"; exit 0; } || exit 1
fi

# Build a fixture release: a tarball whose inner binary prints a version.
rel="$(mktemp -d)"; trap 'rm -rf "$fix" "$rel"' EXIT
tag="v9.9.9"; triple="$(map_target "$(uname -s)" "$(uname -m)")"
stage="rusty-imap-mcp-$tag-$triple"
mkdir -p "$rel/$tag/$stage"
printf '#!/bin/sh\necho "rusty-imap-mcp 9.9.9"\n' > "$rel/$tag/$stage/rusty-imap-mcp"
chmod +x "$rel/$tag/$stage/rusty-imap-mcp"
( cd "$rel/$tag" && tar czf "$stage.tar.gz" "$stage" && rm -rf "$stage" )
( cd "$rel/$tag" && { command -v sha256sum >/dev/null 2>&1 && sha256sum ./*.tar.gz || shasum -a 256 ./*.tar.gz; } > SHA256SUMS.txt )

# Happy path: install + advisory smoke succeeds.
out_dir="$(mktemp -d)"
( RUSTY_IMAP_MCP_BASE_URL="file://$rel" RUSTY_IMAP_MCP_VERSION="$tag" \
  RUSTY_IMAP_MCP_INSTALL_DIR="$out_dir/bin" sh "$repo/install.sh" ) >/dev/null 2>&1
check "happy install places binary" "yes" \
  "$( [ -x "$out_dir/bin/rusty-imap-mcp" ] && echo yes || echo no )"

# exit 5: corrupt the SHA256SUMS entry.
bad_rel="$(mktemp -d)"; cp -r "$rel/$tag" "$bad_rel/"; echo "deadbeef  $stage.tar.gz" > "$bad_rel/$tag/SHA256SUMS.txt"
expect_exit "tampered checksum -> 5" 5 env \
  RUSTY_IMAP_MCP_BASE_URL="file://$bad_rel" RUSTY_IMAP_MCP_VERSION="$tag" \
  RUSTY_IMAP_MCP_INSTALL_DIR="$(mktemp -d)/bin" sh "$repo/install.sh"

# exit 6: garbage tarball whose recorded checksum matches (clears 5, fails tar).
g_rel="$(mktemp -d)/x"; mkdir -p "$g_rel/$tag"; echo "not a tarball" > "$g_rel/$tag/$stage.tar.gz"
( cd "$g_rel/$tag" && { command -v sha256sum >/dev/null 2>&1 && sha256sum ./*.tar.gz || shasum -a 256 ./*.tar.gz; } > SHA256SUMS.txt )
expect_exit "garbage tarball -> 6" 6 env \
  RUSTY_IMAP_MCP_BASE_URL="file://$g_rel" RUSTY_IMAP_MCP_VERSION="$tag" \
  RUSTY_IMAP_MCP_INSTALL_DIR="$(mktemp -d)/bin" sh "$repo/install.sh"

# exit 4: missing tarball (download failure).
expect_exit "missing tarball -> 4" 4 env \
  RUSTY_IMAP_MCP_BASE_URL="file://$rel" RUSTY_IMAP_MCP_VERSION="v0.0.0" \
  RUSTY_IMAP_MCP_INSTALL_DIR="$(mktemp -d)/bin" sh "$repo/install.sh"

# exit 4: latest-version API failure (unset version + unreachable API override).
expect_exit "api resolve failure -> 4" 4 env \
  RUSTY_IMAP_MCP_BASE_URL="file://$rel" RUSTY_IMAP_MCP_API_URL="file:///nonexistent/api.json" \
  RUSTY_IMAP_MCP_INSTALL_DIR="$(mktemp -d)/bin" sh "$repo/install.sh"

# Advisory smoke: binary installs but --version fails -> installer still exits 0.
as_rel="$(mktemp -d)/y"; mkdir -p "$as_rel/$tag/$stage"
printf '#!/bin/sh\nexit 1\n' > "$as_rel/$tag/$stage/rusty-imap-mcp"; chmod +x "$as_rel/$tag/$stage/rusty-imap-mcp"
( cd "$as_rel/$tag" && tar czf "$stage.tar.gz" "$stage" && rm -rf "$stage" )
( cd "$as_rel/$tag" && { command -v sha256sum >/dev/null 2>&1 && sha256sum ./*.tar.gz || shasum -a 256 ./*.tar.gz; } > SHA256SUMS.txt )
expect_exit "advisory smoke failure -> 0" 0 env \
  RUSTY_IMAP_MCP_BASE_URL="file://$as_rel" RUSTY_IMAP_MCP_VERSION="$tag" \
  RUSTY_IMAP_MCP_INSTALL_DIR="$(mktemp -d)/bin" sh "$repo/install.sh"

if [ "$failures" -ne 0 ]; then echo "$failures test(s) failed" >&2; exit 1; fi
echo "all installer tests passed"
```

- [ ] **Step 2: Run it, watch it fail** — `bash scripts/install.test.sh 2>&1 | tail`. Expected: fails (no `install.sh` yet).

- [ ] **Step 3: Write `install.sh`** (repo root):

```sh
#!/bin/sh
# rusty-imap-mcp installer for Linux and macOS.
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/randomparity/rusty-imap-mcp/main/install.sh | sh
# Env vars:
#   RUSTY_IMAP_MCP_VERSION      release tag to install (default: latest stable)
#   RUSTY_IMAP_MCP_INSTALL_DIR  install directory (default: $HOME/.local/bin)
#
# The SHA-256 check is integrity, not authenticity: SHA256SUMS.txt is fetched
# from the same unsigned release origin. For authenticity, verify the downloaded
# tarball with `gh attestation verify`. See RELEASING.md / README.md.
set -eu

# RELEASE_VERSION_PIN — release.yml rewrites the next line to bake the tag into
# the release-asset copy. The raw repo copy leaves it unset (resolves latest).
RUSTY_IMAP_MCP_VERSION="${RUSTY_IMAP_MCP_VERSION:-}"
RUSTY_IMAP_MCP_INSTALL_DIR="${RUSTY_IMAP_MCP_INSTALL_DIR:-$HOME/.local/bin}"

# Undocumented test overrides.
RUSTY_IMAP_MCP_BASE_URL="${RUSTY_IMAP_MCP_BASE_URL:-https://github.com/randomparity/rusty-imap-mcp/releases/download}"
RUSTY_IMAP_MCP_API_URL="${RUSTY_IMAP_MCP_API_URL:-https://api.github.com/repos/randomparity/rusty-imap-mcp/releases/latest}"
RUSTY_IMAP_MCP_SKIP_SMOKE="${RUSTY_IMAP_MCP_SKIP_SMOKE:-}"

err() { printf 'install.sh: %s\n' "$*" >&2; }

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || { err "missing required command: $1"; exit 3; }
}

# Pure OS/arch -> Rust target triple map. Returns 1 on an unsupported pair.
map_target() {
    case "$1/$2" in
    Linux/x86_64) echo x86_64-unknown-linux-gnu ;;
    Linux/aarch64 | Linux/arm64) echo aarch64-unknown-linux-gnu ;;
    Linux/ppc64le) echo powerpc64le-unknown-linux-gnu ;;
    Linux/s390x) echo s390x-unknown-linux-gnu ;;
    Darwin/arm64) echo aarch64-apple-darwin ;;
    *) return 1 ;;
    esac
}

# Retry knobs — overridable so the hermetic fixture tests (which hit missing
# file:// URLs on purpose) don't spin through the full production backoff.
RUSTY_IMAP_MCP_RETRY="${RUSTY_IMAP_MCP_RETRY:-5}"
RUSTY_IMAP_MCP_RETRY_DELAY="${RUSTY_IMAP_MCP_RETRY_DELAY:-5}"

http_get() { # url dest
    # --retry absorbs releases/download CDN propagation lag: installer-smoke runs
    # seconds after publish and the CDN can briefly 404/5xx a live asset (the
    # homebrew job in release.yml added the same for the same reason). Also a UX
    # win for real users on flaky networks.
    if command -v curl >/dev/null 2>&1; then
        curl --fail --silent --show-error --location \
            --retry "$RUSTY_IMAP_MCP_RETRY" --retry-all-errors \
            --retry-delay "$RUSTY_IMAP_MCP_RETRY_DELAY" "$1" -o "$2"
    else
        wget --quiet --tries="$((RUSTY_IMAP_MCP_RETRY + 1))" \
            --waitretry="$RUSTY_IMAP_MCP_RETRY_DELAY" "$1" -O "$2"
    fi
}

resolve_version() {
    if [ -n "$RUSTY_IMAP_MCP_VERSION" ]; then
        echo "$RUSTY_IMAP_MCP_VERSION"
        return
    fi
    tmp="$(mktemp)"
    if ! http_get "$RUSTY_IMAP_MCP_API_URL" "$tmp" 2>/dev/null; then
        err "failed to query the latest release; set RUSTY_IMAP_MCP_VERSION=vX.Y.Z to pin"
        rm -f "$tmp"; exit 4
    fi
    tag="$(sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' "$tmp" | head -n 1)"
    rm -f "$tmp"
    if [ -z "$tag" ]; then
        err "could not parse tag_name; set RUSTY_IMAP_MCP_VERSION=vX.Y.Z to pin"
        exit 4
    fi
    echo "$tag"
}

verify_sha256() { # sums fname dir  -> exit 5 on mismatch
    line="$(grep "$2\$" "$1" | sed 's|  \./|  |' || true)"
    if [ -z "$line" ]; then err "no checksum entry for $2"; return 5; fi
    if command -v sha256sum >/dev/null 2>&1; then
        echo "$line" | ( cd "$3" && sha256sum -c - >/dev/null 2>&1 ) || return 5
    else
        echo "$line" | ( cd "$3" && shasum -a 256 -c - >/dev/null 2>&1 ) || return 5
    fi
}

main() {
    require_cmd uname
    require_cmd mktemp
    require_cmd tar
    command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 || {
        err "neither curl nor wget is installed"; exit 3; }
    command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1 || {
        err "neither sha256sum nor shasum is installed"; exit 3; }

    target="$(map_target "$(uname -s)" "$(uname -m)")" || {
        err "unsupported platform: $(uname -s)/$(uname -m)"
        err "Try:  cargo install rusty-imap-mcp --locked"
        err "  or  a .deb/.rpm from the GitHub release page (amd64/arm64)"
        err "  or  brew install randomparity/tap/rusty-imap-mcp"
        exit 2
    }

    tag="$(resolve_version)"
    archive="rusty-imap-mcp-$tag-$target.tar.gz"
    workdir="$(mktemp -d)"
    trap 'rm -rf "$workdir"' EXIT INT TERM

    printf 'install.sh: downloading %s/%s/%s\n' "$RUSTY_IMAP_MCP_BASE_URL" "$tag" "$archive" >&2
    http_get "$RUSTY_IMAP_MCP_BASE_URL/$tag/$archive" "$workdir/$archive" || {
        err "download failed: $archive"; exit 4; }
    http_get "$RUSTY_IMAP_MCP_BASE_URL/$tag/SHA256SUMS.txt" "$workdir/SHA256SUMS.txt" || {
        err "download failed: SHA256SUMS.txt"; exit 4; }

    verify_sha256 "$workdir/SHA256SUMS.txt" "$archive" "$workdir" || {
        err "SHA-256 verification failed (corrupted download?)"; exit 5; }

    ( cd "$workdir" && tar xzf "$archive" ) || { err "tar extraction failed"; exit 6; }

    mkdir -p "$RUSTY_IMAP_MCP_INSTALL_DIR"
    cp "$workdir/rusty-imap-mcp-$tag-$target/rusty-imap-mcp" "$RUSTY_IMAP_MCP_INSTALL_DIR/rusty-imap-mcp"
    chmod 0755 "$RUSTY_IMAP_MCP_INSTALL_DIR/rusty-imap-mcp"

    # Advisory: the binary is already installed, so a --version failure prints a
    # hint but does NOT change the exit status (exit 0 = binary installed).
    if [ -z "$RUSTY_IMAP_MCP_SKIP_SMOKE" ]; then
        if ! "$RUSTY_IMAP_MCP_INSTALL_DIR/rusty-imap-mcp" --version >/dev/null 2>&1; then
            err "installed but --version failed. On ppc64le/s390x install libdbus:"
            err "  Debian/Ubuntu: sudo apt-get install libdbus-1-3"
            err "  Fedora/RHEL:   sudo dnf install dbus-libs"
            err "Or use the .deb/.rpm, or: cargo install rusty-imap-mcp --locked"
        fi
    fi

    printf 'install.sh: installed to %s/rusty-imap-mcp\n' "$RUSTY_IMAP_MCP_INSTALL_DIR"
    case ":$PATH:" in
    *":$RUSTY_IMAP_MCP_INSTALL_DIR:"*) ;;
    *) err "note: $RUSTY_IMAP_MCP_INSTALL_DIR is not on PATH; add it to your shell rc" ;;
    esac
}

# Guard so the test harness can source and unit-test the functions above.
if [ "${RUSTY_IMAP_MCP_SOURCED:-}" != "1" ]; then
    main "$@"
fi
```

- [ ] **Step 4: Run the test to PASS** — `bash scripts/install.test.sh 2>&1 | tail -25`. Expected: `all installer tests passed`.

- [ ] **Step 5: Lint the shell** — `shellcheck install.sh scripts/install.test.sh` and `shfmt -d install.sh` (expect no diff; run `shfmt -w install.sh` if needed). Fix all warnings — no suppressions.

- [ ] **Step 6: Wire into `just` + CI** — in `justfile` add:

```makefile
# Unit + fixture tests for install.sh (no network; file:// fixtures).
test-installer:
    bash scripts/install.test.sh
```

  and append `test-installer` to the `ci` recipe's dependency list (the line beginning `ci: fmt-check lint …`).

- [ ] **Step 7: Confirm CI wiring** — `just test-installer` (expect pass) and `just --evaluate 2>/dev/null; rg -n '^ci:' justfile` shows `test-installer` in the list.

- [ ] **Step 8: Commit**

```bash
git add install.sh scripts/install.test.sh justfile
git commit -m "feat(installer): add install.sh with fixture-driven tests"
```

---

## Task 4: `.deb` / `.rpm` package metadata

**Files:**
- Modify: `crates/rimap-server/Cargo.toml` (add two `[package.metadata.*]` blocks)

**Note:** Package metadata is config, not testable by a Rust unit test; the real gate is the release job (Task 5) plus `just check-metadata`. Verify locally with the tools if available.

- [ ] **Step 1: Add the deb + rpm metadata** — append to `crates/rimap-server/Cargo.toml` (after the `[dev-dependencies]` block). Paths are relative to this manifest (`crates/rimap-server/`), hence `../../` for workspace-root files. **No libdbus dependency** — the packaged amd64/arm64 binary static-links it via `vendored-keyring`.

```toml
# --- Native packaging (issue #545, ADR-0006). amd64/arm64 only; the packaged
# binary static-links libdbus (vendored-keyring), so no libdbus runtime dep.
# Man pages come from `just man` / the release `manpages` job into ../../man/man1.
[package.metadata.deb]
maintainer = "David Christensen <randomparity@gmail.com>"
copyright = "2026 David Christensen <randomparity@gmail.com>"
license-file = ["../../LICENSE-MIT", "0"]
extended-description = "Security-first Model Context Protocol server for IMAP email access."
section = "mail"
priority = "optional"
# Explicit deps only: cargo-deb's $auto would ldd the wrong arch when packaging
# the arm64 binary on an x86_64 host. The binary is self-contained (vendored
# static libdbus), so libc6 is the sole runtime requirement.
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

# NOTE — asset source path bases differ between the two tools (source-verified,
# not assumed):
#  * cargo-deb resolves non-`target/` sources relative to THIS package manifest
#    dir (crates/rimap-server/) — documented — so the deb block above uses
#    `../../` for workspace-root files.
#  * cargo-generate-rpm's `generate_expanded_path` (src/config/asset_info.rs)
#    globs each non-`target/` source relative to the process CWD FIRST (the
#    workspace root, where `cargo generate-rpm -p crates/rimap-server` runs),
#    falling back to the package base; so the rpm block below uses NO `../../`.
#  * Both tools special-case the `target/release/` binary prefix and rewrite it
#    for `--target` (cargo-generate-rpm: `get_asset_rel_path` strips it and joins
#    the target dir).
# Task-5's `dpkg-deb --contents`/`rpm -qlp` assertion (extended to cover a
# license + README, not just man pages) is the hard gate that still catches any
# path-base slip before a release ships.
[package.metadata.generate-rpm]
summary = "Security-first MCP server for IMAP email access"
# Disable rpm-build's automatic Requires (host ldd is wrong for a cross-built,
# statically-linked binary); declare the sole runtime dep explicitly.
auto-req = "no"

[package.metadata.generate-rpm.requires]
glibc = "*"

[[package.metadata.generate-rpm.assets]]
source = "target/release/rusty-imap-mcp"
dest = "/usr/bin/rusty-imap-mcp"
mode = "755"
[[package.metadata.generate-rpm.assets]]
source = "man/man1/rusty-imap-mcp.1"
dest = "/usr/share/man/man1/rusty-imap-mcp.1"
mode = "644"
doc = true
[[package.metadata.generate-rpm.assets]]
source = "man/man1/rusty-imap-mcp-*.1"
dest = "/usr/share/man/man1/"
mode = "644"
doc = true
[[package.metadata.generate-rpm.assets]]
source = "README.md"
dest = "/usr/share/doc/rusty-imap-mcp/README.md"
mode = "644"
doc = true
[[package.metadata.generate-rpm.assets]]
source = "CHANGELOG.md"
dest = "/usr/share/doc/rusty-imap-mcp/CHANGELOG.md"
mode = "644"
doc = true
[[package.metadata.generate-rpm.assets]]
source = "LICENSE-MIT"
dest = "/usr/share/licenses/rusty-imap-mcp/LICENSE-MIT"
mode = "644"
[[package.metadata.generate-rpm.assets]]
source = "LICENSE-APACHE"
dest = "/usr/share/licenses/rusty-imap-mcp/LICENSE-APACHE"
mode = "644"
[[package.metadata.generate-rpm.assets]]
source = "NOTICE"
dest = "/usr/share/licenses/rusty-imap-mcp/NOTICE"
mode = "644"
```

- [ ] **Step 2: Verify existing metadata guardrails still pass** — `just check-metadata` (runs `scripts/check-publishable-metadata.sh`) and `cargo metadata --format-version 1 >/dev/null` (parses the manifest). Expected: both clean. If `check-metadata` objects to the new tables, read the script and adjust (it validates publish-relevant fields; `[package.metadata.*]` is ignored by `cargo publish`).

- [ ] **Step 3: Optional local package smoke** (only if the tools are installed; skip cleanly otherwise):

```bash
if command -v cargo-deb >/dev/null && command -v cargo-generate-rpm >/dev/null; then
  cargo build --release -p rimap-server --target x86_64-unknown-linux-gnu
  just man
  cargo deb --no-build --no-strip -p rimap-server --target x86_64-unknown-linux-gnu
  cargo generate-rpm -p crates/rimap-server --target x86_64-unknown-linux-gnu
  dpkg-deb --contents target/x86_64-unknown-linux-gnu/debian/*.deb | rg 'man1/rusty-imap-mcp'
  rpm -qlp target/x86_64-unknown-linux-gnu/generate-rpm/*.rpm | rg 'man1/rusty-imap-mcp'
fi
```

  Expected (if run): each `rg` prints the `rusty-imap-mcp.1` + subcommand pages.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-server/Cargo.toml
git commit -m "feat(packaging): add deb/rpm metadata (amd64/arm64, no libdbus dep)"
```

---

## Task 5: Wire packaging into `release.yml`

**Files:**
- Modify: `.github/workflows/release.yml`

**Note:** Verified locally by `actionlint` + `zizmor` (prek hooks); full behavior only exercises at tag time. Make edits surgical — do not disturb the `homebrew`/`bottles`/`publish-crates`/`post-release-bump` jobs.

- [ ] **Step 1: Add the `manpages` job** — after the `verify-tag` job, insert:

```yaml
  # Generate manpages once and share to every build leg. Test-support subcommands
  # are absent because xtask's rimap-server dep sets default-features = false
  # (cfg-gating them out); the guard step below is belt-and-suspenders that fails
  # loudly if that ever regresses.
  manpages:
    name: Generate manpages
    needs: verify-tag
    runs-on: ubuntu-24.04
    if: github.event_name != 'workflow_dispatch' || inputs.dry_run != true
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0  # v7.0.0
        with:
          persist-credentials: false
      - uses: dtolnay/rust-toolchain@e97e2d8cc328f1b50210efc529dca0028893a2d9  # v1 (toolchain: stable) # zizmor: ignore[superfluous-actions]
        with:
          toolchain: stable
      - name: Generate manpages
        run: cargo run -p xtask --no-default-features --release --locked -- man --out man/man1
      - name: Guard — no test-support pages shipped
        run: |
          if ls man/man1/rusty-imap-mcp-dump-tool-*.1 >/dev/null 2>&1; then
            echo "::error::test-support subcommand manpages were generated" >&2
            exit 1
          fi
      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a  # v7.0.1
        with:
          name: rusty-imap-mcp-manpages
          path: man/man1/*.1
          if-no-files-found: error
```

- [ ] **Step 2: Give every build job the manpage** — for **all five** build jobs, add `manpages` to `needs` (e.g. `needs: [verify-tag, manpages]`), and add a download step **before** the "Package tarball" step:

```yaml
      - name: Download manpages
        uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c  # v8.0.1
        with:
          name: rusty-imap-mcp-manpages
          path: man/man1
```

  In each job's "Package tarball" step, add these two lines before `tar czf`:

```bash
          mkdir -p "$stage/share/man/man1"
          cp man/man1/*.1 "$stage/share/man/man1/"
```

- [ ] **Step 3: Add `--target` + package steps to the x86_64 leg** — in `build-linux-x86_64`:
  - Change the build to `cargo auditable build --release --locked -p rimap-server --features vendored-keyring --target x86_64-unknown-linux-gnu`.
  - In "Package tarball", change the copy source to `target/x86_64-unknown-linux-gnu/release/${BINARY_NAME}`.
  - After the tarball upload's sibling steps, add (before `upload-artifact`):

```yaml
      - uses: taiki-e/install-action@16b05812d776ae1dfaabc8277e421fb6d2506419  # v2.82.7
        with:
          tool: cargo-deb@3.7.0,cargo-generate-rpm@0.21.0
      - name: Build .deb + .rpm
        run: |
          set -euo pipefail
          cargo deb --no-build --no-strip -p rimap-server --target x86_64-unknown-linux-gnu
          cargo generate-rpm -p crates/rimap-server --target x86_64-unknown-linux-gnu
          cp target/x86_64-unknown-linux-gnu/debian/*.deb .
          cp target/x86_64-unknown-linux-gnu/generate-rpm/*.rpm .
      - name: Assert man pages, license, and README are in the packages
        run: |
          set -euo pipefail
          sudo apt-get update && sudo apt-get install -y --no-install-recommends rpm
          # Require: top man page + >=1 subcommand page + a LICENSE + README.
          # Catches an asset-source path-base slip that would otherwise silently
          # ship a man-less or (compliance-critical) license-less package.
          for pkg in ./*.deb; do
            c="$(dpkg-deb --contents "$pkg")"
            printf '%s' "$c" | grep -q 'usr/share/man/man1/rusty-imap-mcp\.1' \
              && printf '%s' "$c" | grep -Eq 'usr/share/man/man1/rusty-imap-mcp-[a-z-]+\.1' \
              && printf '%s' "$c" | grep -q 'usr/share/doc/rusty-imap-mcp/LICENSE-MIT' \
              && printf '%s' "$c" | grep -q 'usr/share/doc/rusty-imap-mcp/README.md' \
              || { echo "::error::$pkg missing man/license/README asset" >&2; exit 1; }
          done
          for pkg in ./*.rpm; do
            c="$(rpm -qlp "$pkg")"
            printf '%s' "$c" | grep -q '/usr/share/man/man1/rusty-imap-mcp\.1' \
              && printf '%s' "$c" | grep -Eq '/usr/share/man/man1/rusty-imap-mcp-[a-z-]+\.1' \
              && printf '%s' "$c" | grep -q '/usr/share/licenses/rusty-imap-mcp/LICENSE-MIT' \
              && printf '%s' "$c" | grep -q '/usr/share/doc/rusty-imap-mcp/README.md' \
              || { echo "::error::$pkg missing man/license/README asset" >&2; exit 1; }
          done
      - name: Lint packages (warn-only)
        continue-on-error: true
        run: |
          sudo apt-get install -y --no-install-recommends lintian rpmlint
          lintian --no-tag-display-limit ./*.deb || true
          rpmlint ./*.rpm || true
      - name: Install-test .deb (no libdbus present)
        run: |
          docker run --rm -v "$PWD:/pkg" -w /pkg debian:stable bash -c \
            'apt-get update && apt-get install -y ./*.deb && rusty-imap-mcp --version'
      - name: Install-test .rpm (no dbus-libs present)
        run: |
          docker run --rm -v "$PWD:/pkg" -w /pkg fedora:latest bash -c \
            'dnf install -y ./*.rpm && rusty-imap-mcp --version'
```

  - Extend the job's `upload-artifact` `path:` to include the packages (multi-line):

```yaml
          path: |
            ${{ env.BINARY_NAME }}-${{ github.ref_name }}-x86_64-unknown-linux-gnu.tar.gz
            *.deb
            *.rpm
```

- [ ] **Step 4: Add `--target` + host-side package steps to the aarch64 leg** — in `build-linux-aarch64`:
  - Append `--target aarch64-unknown-linux-gnu` to the in-container `cargo auditable build …` command, and after the `docker run …` line add `sudo chown -R "$(id -u):$(id -g)" target`.
  - In "Package tarball", change the copy source to `target/aarch64-unknown-linux-gnu/release/${BINARY_NAME}`.
  - Add the same `taiki-e/install-action` (cargo-deb/cargo-generate-rpm) and a **Build .deb + .rpm** step with `--target aarch64-unknown-linux-gnu`, the copy of artifacts, and the **same "Assert man pages are in the packages"** step (arch-agnostic — `dpkg-deb`/`rpm -qlp` run host-side). Add `lintian`/`rpmlint` warn-only. **Do not** add an emulated install-test (structural + content assertion only — ADR-0006). Extend `upload-artifact` `path:` to include `*.deb`/`*.rpm` (as in Step 3).

- [ ] **Step 5: Release job — stage installer, expand checksums + assets + attestation** — in the `release` job:
  - Add `manpages` is not needed here (it needs the build jobs, unchanged).
  - Before "Generate SHA256 checksums", add the installer-staging step:

```yaml
      - name: Stage install.sh with version baked in
        env:
          TAG: ${{ github.ref_name }}
        run: |
          set -euo pipefail
          marker='RUSTY_IMAP_MCP_VERSION="${RUSTY_IMAP_MCP_VERSION:-}"'
          replace='RUSTY_IMAP_MCP_VERSION="${RUSTY_IMAP_MCP_VERSION:-'"$TAG"'}"'
          python3 - "$marker" "$replace" <<'PY'
          import sys, pathlib
          marker, replace = sys.argv[1], sys.argv[2]
          p = pathlib.Path("install.sh"); s = p.read_text()
          out = s.replace(marker, replace, 1)
          assert out != s, f"install.sh marker not found: {marker!r}"
          pathlib.Path("artifacts/install.sh").write_text(out)
          PY
          chmod +x artifacts/install.sh
```

  - Change "Generate SHA256 checksums" to hash **every** release file (tarballs, packages, installer) rather than only tarballs:

```bash
          cd artifacts
          find . -maxdepth 1 -type f ! -name 'SHA256SUMS.txt' -printf '%f\n' \
            | sort | xargs -d '\n' sha256sum > SHA256SUMS.txt
          cat SHA256SUMS.txt
```

  - Extend the attestation `subject-path` to cover packages:

```yaml
          subject-path: |
            artifacts/rusty-imap-mcp-*.tar.gz
            artifacts/*.deb
            artifacts/*.rpm
            artifacts/SHA256SUMS.txt
```

  - Extend `gh release create` asset args to include the new files:

```bash
          gh release create "$TAG_NAME" \
            --title "$TAG_NAME" \
            --notes-file RELEASE_NOTES.md \
            artifacts/${{ env.BINARY_NAME }}-*.tar.gz \
            artifacts/*.deb \
            artifacts/*.rpm \
            artifacts/install.sh \
            artifacts/SHA256SUMS.txt
```

  **Homebrew-compat check:** the `homebrew` job's `sum_for` greps `SHA256SUMS.txt` by exact tarball filename; the added `.deb`/`.rpm`/`install.sh` lines do not change tarball lines. Confirm tarball filenames are unchanged by this task (they are).

- [ ] **Step 6: Add the `installer-smoke` job** — after `post-release-bump` (a downstream leaf; its failure must not un-publish):

```yaml
  # Post-publish signal (not a gate): its failure does not un-publish the release.
  # Pins the version so it never touches the rate-limited latest-version API from
  # a shared runner IP. Verifies --version INDEPENDENTLY of install.sh's advisory
  # (always-0) exit code (spec finding).
  installer-smoke:
    name: Installer smoke
    needs: release
    if: ${{ github.event_name == 'push' && !contains(github.ref_name, '-') }}
    runs-on: ubuntu-24.04
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0  # v7.0.0
        with:
          persist-credentials: false
      - name: Install via the user-facing install.sh and verify version
        env:
          TAG: ${{ github.ref_name }}
        run: |
          set -euo pipefail
          export RUSTY_IMAP_MCP_INSTALL_DIR="$HOME/.local/bin"
          export RUSTY_IMAP_MCP_VERSION="$TAG"   # pin: no live API call
          sh ./install.sh
          expected="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)"
          got="$("$RUSTY_IMAP_MCP_INSTALL_DIR/rusty-imap-mcp" --version)"
          echo "expected contains: $expected ; got: $got"
          case "$got" in
            *"$expected"*) echo "version OK" ;;
            *) echo "::error::version mismatch: want *$expected* got $got" >&2; exit 1 ;;
          esac
```

- [ ] **Step 7: Lint the workflow** — `actionlint .github/workflows/release.yml` and `zizmor .github/workflows/release.yml`. Expected: clean. Fix every finding (add `# zizmor: ignore[...]` only with a justification comment if genuinely unavoidable, matching existing usage).

- [ ] **Step 8: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "ci(release): build+attach deb/rpm, manpages, installer + smoke"
```

---

## Task 6: Documentation — RELEASING, README, Homebrew template

**Files:**
- Modify: `RELEASING.md`, `README.md`, `homebrew/rusty-imap-mcp.rb.template`

- [ ] **Step 1: RELEASING.md** — remove the "Planned" bullet that lists #545. In "What automation does", add entries for the `manpages` job, the `.deb`/`.rpm` build + man-page-content assertion + install-tests on the two vendored legs, `install.sh` staging + expanded `SHA256SUMS.txt` + attestation over packages, and the `installer-smoke` leaf. Update the "After tagging" pipeline order to include `manpages` (before builds) and `installer-smoke` (after release).

- [ ] **Step 2: README.md install section** — add a section documenting, in this order:
  1. Homebrew (existing).
  2. `.deb`/`.rpm`: download from the release page (amd64/arm64), `sudo dpkg -i …` / `sudo rpm -i …`; note **no** `libdbus-1-3`/`dbus-libs` needed (static libdbus).
  3. Installer — **two distinct paths**:
     - Convenience: `curl -fsSL https://raw.githubusercontent.com/randomparity/rusty-imap-mcp/main/install.sh | sh` — TLS+origin trust only, resolves latest via the API (rate-limited on shared IPs → pin with `RUSTY_IMAP_MCP_VERSION=vX.Y.Z`); **not** checksum-verifiable when piped.
     - Verifiable: download the release-asset `install.sh`, check it against `SHA256SUMS.txt`, then run it (pinned, no API call, the file you verify is the file you run).
  4. Trust note: the checksum is **integrity, not authenticity**; for authenticity run `gh attestation verify` on the downloaded tarball/package.
  5. `man rusty-imap-mcp` resolves after a `.deb`/`.rpm` install; the `curl|sh` installer places only the binary — its man page ships inside the tarball under `share/man/man1/`.

- [ ] **Step 3: Homebrew template** — in `homebrew/rusty-imap-mcp.rb.template`, in the `install` block add man-page installation guarded on presence (best-effort; must not break a bottle that predates man pages):

```ruby
    man1.install Dir["share/man/man1/*.1"] if Dir.exist?("share/man/man1")
```

  Place it after the existing `bin.install` line. (The tarball now carries `share/man/man1/`.)

- [ ] **Step 4: Verify docs guardrails** — `just` prek doc hooks run `typos` and markdown checks on commit; run `prek run typos --files RELEASING.md README.md` if available, else rely on the commit hook. Re-read each edit for accuracy against the implemented behavior.

- [ ] **Step 5: Commit**

```bash
git add RELEASING.md README.md homebrew/rusty-imap-mcp.rb.template
git commit -m "docs(packaging): document deb/rpm, installer, manpages"
```

---

## Final verification (before handing to review)

- [ ] `just man && ls man/man1/ | rg -v dump-tool` shows the expected pages; `ls man/man1/ | rg dump-tool` is empty.
- [ ] `just test-installer` passes.
- [ ] `just ci` is green (includes `fmt-check lint test test-msrv deny … test-installer typos`).
- [ ] `actionlint .github/workflows/release.yml` and `zizmor .github/workflows/release.yml` clean.
- [ ] `git status` clean except intended files; `man/man1/` is untracked/ignored (never staged).
- [ ] Working tree diff touches only the files in "File Structure"; no unrelated edits.

## Rollback / cleanup

- The change is additive to the release pipeline; reverting the branch restores prior behavior. No persisted state, no migration.
- Generated `man/man1/` must never be committed (gitignored). If it appears staged, `git rm --cached -r man` and re-check `.gitignore`.
- If a build leg's packaging proves flaky on the debut tag, the tarball + installer still publish; a follow-up patch tag can re-enable packaging.
