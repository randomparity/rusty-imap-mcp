# Developer entry points for rusty-imap-mcp.
#
# Golden rule: if `just ci` passes locally, CI will pass. Never run bare cargo
# for checks — use these targets so CI and local dev stay in lockstep.

set shell := ["bash", "-uc"]
set positional-arguments
MSRV := "1.88.0"

# cargo-nextest version floor, stated once and enforced by `setup` below.
# 0.9.95 is the first release supporting the leak-timeout table form
# (`{ period = "...", result = "fail" }`, nextest changelog 2025-04-30),
# which .config/nextest.toml uses; it also covers the
# profile.ci `fail-fast = { max-fail = N }` table form already in use here
# (0.9.89+, #625/#637). An older nextest hits a bare config-parse error on
# either table form with no hint that upgrading nextest is the fix (#639).
NEXTEST_MIN := "0.9.95"

# Default: print available targets.
default:
    @just --list

# Verify required tooling is installed. Idempotent — run this on first clone
# and any time tooling seems off.
setup:
    #!/usr/bin/env bash
    set -euo pipefail
    # Detect host OS / Linux distro family once, then build one install hint
    # per tool targeted at that platform. Language-native package managers
    # (cargo, go) are the fallback when a distro does not ship the tool.
    os="$(uname -s)"
    flavor="unknown"
    if [ "$os" = "Darwin" ]; then
        flavor="mac"
    elif [ "$os" = "Linux" ] && [ -r /etc/os-release ]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        for id in ${ID:-} ${ID_LIKE:-}; do
            case "$id" in
                fedora|rhel|centos)  flavor="fedora"; break ;;
                debian|ubuntu)       flavor="debian"; break ;;
                arch)                flavor="arch";   break ;;
                opensuse*|suse|sles) flavor="suse";   break ;;
            esac
        done
    fi
    # Per-flavor install commands. Only the selected flavor's hints are built.
    case "$flavor" in
        mac)
            H_JUST='brew install just'
            H_PREK='brew install prek'
            H_SHELLCHECK='brew install shellcheck'
            H_SHFMT='brew install shfmt'
            H_ACTIONLINT='brew install actionlint'
            H_ZIZMOR='brew install zizmor'
            H_TYPOS='brew install typos-cli'
            H_PNPM='brew install pnpm'
            ;;
        fedora)
            H_JUST='sudo dnf install just'
            H_PREK='cargo install --locked prek'
            H_SHELLCHECK='sudo dnf install ShellCheck'
            H_SHFMT='sudo dnf install shfmt'
            H_ACTIONLINT='go install github.com/rhysd/actionlint/cmd/actionlint@latest'
            H_ZIZMOR='cargo install --locked zizmor'
            H_TYPOS='cargo install --locked typos-cli'
            H_PNPM='npm install -g pnpm@11.1.1'
            H_PKGCONFIG='sudo dnf install pkgconf-pkg-config'
            H_DBUS='sudo dnf install dbus-devel'
            ;;
        debian)
            H_JUST='sudo apt install just'
            H_PREK='cargo install --locked prek'
            H_SHELLCHECK='sudo apt install shellcheck'
            H_SHFMT='sudo apt install shfmt'
            H_ACTIONLINT='go install github.com/rhysd/actionlint/cmd/actionlint@latest'
            H_ZIZMOR='cargo install --locked zizmor'
            H_TYPOS='cargo install --locked typos-cli'
            H_PNPM='npm install -g pnpm@11.1.1'
            H_PKGCONFIG='sudo apt install pkg-config'
            H_DBUS='sudo apt install libdbus-1-dev'
            ;;
        arch)
            H_JUST='sudo pacman -S just'
            H_PREK='cargo install --locked prek'
            H_SHELLCHECK='sudo pacman -S shellcheck'
            H_SHFMT='sudo pacman -S shfmt'
            H_ACTIONLINT='go install github.com/rhysd/actionlint/cmd/actionlint@latest'
            H_ZIZMOR='cargo install --locked zizmor'
            H_TYPOS='cargo install --locked typos-cli'
            H_PNPM='sudo pacman -S pnpm'
            H_PKGCONFIG='sudo pacman -S pkgconf'
            H_DBUS='sudo pacman -S dbus'
            ;;
        suse)
            H_JUST='sudo zypper install just'
            H_PREK='cargo install --locked prek'
            H_SHELLCHECK='sudo zypper install ShellCheck'
            H_SHFMT='sudo zypper install shfmt'
            H_ACTIONLINT='go install github.com/rhysd/actionlint/cmd/actionlint@latest'
            H_ZIZMOR='cargo install --locked zizmor'
            H_TYPOS='cargo install --locked typos-cli'
            H_PNPM='npm install -g pnpm@11.1.1'
            H_PKGCONFIG='sudo zypper install pkg-config'
            H_DBUS='sudo zypper install dbus-1-devel'
            ;;
        *)
            H_JUST='cargo install --locked just'
            H_PREK='cargo install --locked prek'
            H_SHELLCHECK='install shellcheck via your package manager'
            H_SHFMT='go install mvdan.cc/sh/v3/cmd/shfmt@latest'
            H_ACTIONLINT='go install github.com/rhysd/actionlint/cmd/actionlint@latest'
            H_ZIZMOR='cargo install --locked zizmor'
            H_TYPOS='cargo install --locked typos-cli'
            H_PNPM='npm install -g pnpm@11.1.1'
            H_PKGCONFIG='install pkg-config via your package manager'
            H_DBUS='install libdbus-1 development headers via your package manager'
            ;;
    esac
    missing=()
    need() {
        if ! command -v "$1" >/dev/null 2>&1; then
            missing+=("$1 ($2)")
        fi
    }
    need rustup     "install from https://rustup.rs"
    need cargo      "bundled with rustup"
    need just       "$H_JUST"
    need prek       "$H_PREK"
    need shellcheck "$H_SHELLCHECK"
    need shfmt      "$H_SHFMT"
    need actionlint "$H_ACTIONLINT"
    need zizmor     "$H_ZIZMOR"
    need typos      "$H_TYPOS"
    need node       "install Node 22 LTS via your package manager or nvm"
    need pnpm       "$H_PNPM"
    # Linux only: `keyring` pulls in `dbus-secret-service`, which links
    # against `libdbus-1` at build time via pkg-config. macOS uses the
    # Security framework instead, so no system headers are required there.
    if [ "$os" = "Linux" ]; then
        if ! command -v pkg-config >/dev/null 2>&1; then
            missing+=("pkg-config ($H_PKGCONFIG)")
        elif ! pkg-config --exists 'dbus-1 >= 1.6' 2>/dev/null; then
            missing+=("libdbus-1 development headers ($H_DBUS)")
        fi
    fi
    if [ "${#missing[@]}" -ne 0 ]; then
        echo "Missing required tools:"
        printf '  - %s\n' "${missing[@]}"
        exit 1
    fi
    # Ensure MSRV toolchain is installed.
    rustup toolchain install {{MSRV}} --component clippy --component rustfmt --profile minimal
    # Ensure dev toolchain components are present (rust-toolchain.toml installs the channel).
    rustup component add clippy rustfmt
    # Cargo subcommands — check then optionally install.
    cargo deny --version >/dev/null 2>&1 || cargo install --locked cargo-deny
    # `cargo install`, unlike the `--version >/dev/null || install` pattern
    # above, upgrades an existing binary in place — needed here since an
    # installed-but-too-old nextest passes the bare existence check but not
    # the version floor. `head -1`: `cargo nextest --version` prints five
    # lines (release/commit-hash/commit-date/host besides the version line);
    # without it awk emits $2 of every line instead of just the version.
    nextest_ver="$(cargo nextest --version 2>/dev/null | head -1 | awk '{print $2}')"
    if [ -z "$nextest_ver" ] || ! printf '%s\n%s\n' "{{NEXTEST_MIN}}" "$nextest_ver" | sort -V -C; then
        echo "installing/upgrading cargo-nextest to >= {{NEXTEST_MIN}} (have: ${nextest_ver:-none})"
        cargo install --locked cargo-nextest
    fi
    cargo msrv --version >/dev/null 2>&1 || cargo install --locked cargo-msrv
    # Pinned to the version the CI `semver-checks` job installs, so a local
    # `just ci` and the gate agree on which lints are in force.
    cargo semver-checks --version >/dev/null 2>&1 || cargo install --locked cargo-semver-checks --version 0.48.0
    # Optional, warn only.
    cargo mutants --version >/dev/null 2>&1 || echo "warn: cargo-mutants not installed (optional)"
    # Install pre-commit hooks.
    prek install
    echo "setup complete"

# Fast inner loop: compile-check only.
check:
    cargo check --workspace --all-targets

# Format the entire workspace in place.
fmt:
    cargo fmt --all

# Verify formatting without modifying files.
fmt-check:
    cargo fmt --all -- --check

# Strict clippy — same flags CI uses.
lint:
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings

# Remove stale rimap-it-* pods/volumes left by SIGKILL'd test runs. Picks the
# runtime the same way the Rust test harnesses do (#674/#688): first of
# docker, podman whose daemon actually answers, not just the first binary on
# PATH — see scripts/prune-containers.sh for why (issue #689).
[private]
prune-containers:
    ./scripts/prune-containers.sh

# Unit-test prune-containers.sh's runtime selection and pruning logic against
# fake docker/podman binaries (autodetect order, explicit-override-with-no-
# fallback, daemon-down vs no-binary messaging, pod/volume counting). No real
# container runtime, no network. Mirrored in the `publish-checks` CI job.
test-prune-containers:
    ./scripts/prune-containers.test.sh

# Generate roff manpages into man/man1/ (consumed by tarball/deb/rpm packaging).
# The pages exclude test-support subcommands because xtask depends on rimap-server
# with default-features = false (its `default = []`), so those #[cfg(feature =
# "test-support")] subcommands are compiled out of the CLI entirely (they are also
# #[command(hide = true)]). `--no-default-features` here is xtask-scoped defense
# and matches the release job's invocation exactly.
man:
    cargo run -p xtask --no-default-features --release --locked -- man --out man/man1

# Unit + fixture tests for install.sh (no network; file:// fixtures). Covers the
# target map, checksum verify, and every handled exit code. Part of `ci`.
test-installer:
    bash scripts/install.test.sh

# Unit and fast tests (no Proton Bridge). --profile ci matches CI's "test
# (stable)" job (#625): a bounded number of independent failures all get
# reported, instead of the first one cancelling the rest of the run.
#
# Extra args pass through to `cargo nextest run` verbatim (#827): nextest
# flags like `--no-capture`, or positional substring filters for scoping
# (`just test some_test`). A leading `--` separator is stripped — just would
# otherwise forward it and nextest rejects flags after `--`. Never document
# additional `-E` expressions as scoping — multiple filtersets are ORed and
# would widen past any default filter rather than narrow it.
test *args: prune-containers
    #!/usr/bin/env bash
    set -euo pipefail
    [ "${1:-}" = "--" ] && shift
    exec cargo nextest run --workspace --locked --no-tests=pass --profile ci "$@"

# Doctests. Separate from `test` because nextest does not run doctests at all
# (upstream limitation), so `cargo nextest run` above silently skips every one
# of them. That gap is not cosmetic: the `compile_fail,E0639` blocks that
# enforce `#[non_exhaustive]` on `rimap_config::model::ImapConfig` (#665) and
# `rimap_audit::record::ProcessEnd` (#706) are doctests, because a doctest
# compiles as its own crate and is therefore the only place in the workspace
# where the attribute is in force at compile time. Without this recipe those
# blocks never execute, and dropping an attribute in a conflict resolution
# would leave CI green. Part of `ci`.
test-doc:
    cargo test --workspace --doc --locked

# Inner-loop unit tests. Skips every container-backed test binary — the
# list lives in scripts/container-test-binaries.txt and a test in
# rimap-container-gate fails when it drifts from the binaries that link
# container harnesses (#811) — plus the slow HTML lookalike proptest. Use
# this between `cargo check` cycles during inner-loop iteration. Before
# pushing, run `just test` (or `just ci`) for the full sweep. See
# docs/superpowers/specs/2026-05-20-local-test-runtime-trim-design.md and
# docs/superpowers/specs/2026-08-20-issue-811-container-arch-gate-design.md.
#
# Intentionally keeps nextest's built-in fail-fast=true (not --profile ci):
# this target is for iterating on one failure at a time, so stopping at the
# first one is the wanted behavior, not the bug #625 fixes.
#
# Extra args pass through to `cargo nextest run` verbatim (#827), appended
# AFTER the -E exclusion filter: positional substring filters intersect with
# the filterset union, so `just test-fast some_test` narrows the run while
# keeping the container-binary exclusion. A leading `--` separator is
# stripped — just would otherwise forward it and nextest rejects flags after
# `--`. Additional `-E` flags would OR into the union and widen past the
# exclusion — do not use them for scoping.
test-fast *args:
    #!/usr/bin/env bash
    set -euo pipefail
    [ "${1:-}" = "--" ] && shift
    containers=$(sed -e '/^[[:space:]]*$/d' -e 's/.*/binary(&)/' \
        scripts/container-test-binaries.txt | paste -sd '|' -)
    exec cargo nextest run --workspace --locked --no-tests=pass \
        -E "not (${containers} | binary(proptest_html_lookalike))" "$@"

# Verify the MSRV toolchain still builds and tests the workspace. --profile
# ci matches CI's "test (MSRV 1.88.0)" job (#625).
test-msrv:
    cargo +{{MSRV}} check --workspace --all-targets --all-features --locked
    cargo +{{MSRV}} nextest run --workspace --locked --no-tests=pass --profile ci

# Cargo-mutants survey. In-place is required on macOS; see docs/security/cargo-mutants-runbook.md.
mutants *args:
    cargo mutants --in-place {{args}}

# Proton Bridge integration suite (gated on PROTON_BRIDGE_TEST=1). --profile
# ci for the same reason as `test`/`test-msrv` (#639): this is a
# container-backed suite, so an unrelated flake or a Bridge-container hiccup
# should not cancel every other result still in flight.
test-integration:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ "${PROTON_BRIDGE_TEST:-0}" != "1" ]; then
        echo "set PROTON_BRIDGE_TEST=1 to run Proton Bridge integration tests"
        exit 1
    fi
    cargo nextest run --workspace --locked --features proton-bridge-tests --profile ci

# Adversarial email corpus against the content pipeline. --profile ci (#639)
# for consistency with the other non-inner-loop suites above: a corpus
# regression shouldn't cancel the run before the rest of the binary reports.
test-injection:
    cargo nextest run -p rimap-content --locked --test injection_corpus --profile ci

# Run a single fuzz target for a fixed time budget. Requires nightly.
# Example: just fuzz content_mime
fuzz TARGET *ARGS:
    cd fuzz && cargo +nightly fuzz run {{TARGET}} -- -max_total_time=30 {{ARGS}}

# List the available fuzz targets.
fuzz-list:
    cd fuzz && cargo +nightly fuzz list

# Bulk regression runner for the external EPVME malicious-email dataset.
test-epvme *args:
    ./scripts/test-epvme.sh {{args}}

# Supply-chain audit. `--all-features` mirrors CI (the cargo-deny-action
# defaults its `arguments` input to `--all-features`) so the fuzzing-gated
# subtree — and its MIT-0 license allowance — is scanned locally too.
deny:
    cargo deny --all-features check


# Unused-direct-dependency gate. cargo-machete is the same tool the
# `[package.metadata.cargo-machete]` blocks (e.g. rimap-content's `phf`)
# already assume; wiring it here makes the manual pass a CI-enforced one.
machete:
    cargo machete

# Enforce the rustls-only invariant: OpenSSL may be pinned in Cargo.lock (via
# dbus-secret-service's `vendored` -> `openssl?/vendored` weak edge) but must
# never enter the *build* graph. Fails if openssl-sys is reachable for any
# target under any feature. See docs/security/supply-chain-watchlist.md.
check-no-openssl:
    #!/usr/bin/env bash
    set -euo pipefail
    if cargo tree -i openssl-sys --all-features --target all 2>/dev/null | grep -q openssl-sys; then
        echo "::error::openssl-sys entered the build graph — rustls-only invariant broken"
        cargo tree -i openssl-sys --all-features --target all
        exit 1
    fi
    echo "ok: openssl-sys is not in the build graph"

# Verify declared MSRV is still accurate.
audit-msrv:
    cargo msrv verify

# Run the Node strict-client conformance suite (issue #264, Phase 2).
# The binary is built with `--features test-support` so the
# `--allow-empty-accounts` CLI flag (#[cfg(feature = "test-support")]
# in rimap-server) is compiled in. A plain `cargo build` produces a
# binary where clap rejects that flag before the MCP handshake runs.
# `pnpm lint` (tsc --noEmit) runs BEFORE `pnpm test` so local CI
# parity matches GitHub Actions, which runs both gates.
mcp-conformance-node:
    cargo build -p rimap-server --bin rusty-imap-mcp \
        --features test-support --locked
    cd tests/mcp-conformance && pnpm install --frozen-lockfile
    cd tests/mcp-conformance && pnpm lint
    cd tests/mcp-conformance && pnpm format:check
    cd tests/mcp-conformance && \
        RUSTY_IMAP_MCP_BIN="{{justfile_directory()}}/target/debug/rusty-imap-mcp" \
        pnpm test

# Regenerate per-tool JSON Schemas under
# crates/rimap-server/tests/fixtures/rimap-tool-schemas/. Run after
# changing any tool response struct (<Tool>Meta or <Tool>Untrusted).
# CI fails on a non-empty diff under that directory.
regen-tool-schemas:
    #!/usr/bin/env bash
    ./scripts/regen-tool-schemas.sh

# Regenerate docs/tools.md from the live tool catalog (dump-tool-doc).
# Run after changing any tool description, parameter, or response struct.
# CI fails on a non-empty diff (see `check-tools-doc`).
gen-tools-doc:
    #!/usr/bin/env bash
    ./scripts/gen-tools-doc.sh

# Fail if docs/tools.md has drifted from the live tool catalog. Part of
# `ci`; mirrors the tool-schema drift check.
check-tools-doc:
    #!/usr/bin/env bash
    set -euo pipefail
    ./scripts/gen-tools-doc.sh
    if ! git diff --exit-code docs/tools.md; then
        git diff --stat docs/tools.md
        echo "::error::docs/tools.md is out of sync — run 'just gen-tools-doc' and commit the result"
        exit 1
    fi

# Validate per-crate crates.io publish metadata (description, category slugs,
# keyword limits). Mirrored in the `publish-checks` CI job (issue #544).
check-metadata:
    ./scripts/check-publishable-metadata.sh

# Unit-test the pure functions in publish-crates.sh (429 parse, -dev guard,
# publish order). No crates.io access. Mirrored in the `publish-checks` CI job.
test-publish-script:
    ./scripts/publish-crates.test.sh

# Unit-test the pure functions in post-release-bump.sh (tag -> next -dev,
# forward-bump guard, the derived-file-set assertions, step-output emission).
# No cargo, no network; one read-only case reads HEAD of this repo. The job it
# guards runs once per release, so this is the only thing that exercises it on
# a normal branch (issue #662). Mirrored in the `publish-checks` CI job.
test-post-release-bump:
    ./scripts/post-release-bump.test.sh

# Fail if a tracked fuzz workspace's Cargo.lock resolves a dependency shared
# with the root workspace to a version the workspace lockfile does not hold.
# `fuzz` and `crates/rimap-server/fuzz` are each their own cargo workspace, so
# no Dependabot entry reaches them and nothing else keeps them in step with the
# root workspace (issues #608, #611). Pure lockfile
# text analysis — no cargo resolution, no network. See docs/ADR/0011.
check-fuzz-lock-parity:
    ./scripts/check-fuzz-lock-parity.sh

# Restore fuzz-lockfile parity after a workspace dependency bump: seed each
# fuzz lockfile from the workspace one and let cargo prune/add around it, then
# re-verify. This is the fix `check-fuzz-lock-parity` points at on failure.
# Rebuild the fuzz targets afterwards (`cargo +nightly fuzz build -O`).
realign-fuzz-locks:
    ./scripts/check-fuzz-lock-parity.sh --fix

# Restore html-oracle/Cargo.lock after a workspace dependency bump. The oracle
# is workspace-excluded but path-depends on rimap-content/rimap-core, whose
# requirements come from the root `[workspace.dependencies]` — so a root bump
# across a semver boundary leaves the oracle lockfile unsatisfiable and the
# `html-oracle checks` CI job fails on `--locked` with a bare cargo error.
# `check-fuzz-lock-parity` deliberately does not cover this lockfile (the
# oracle's own deps are meant to float), so this is the manual fix path (#699).
# `-w` is the minimal form: it relocks the path deps and what they pulled in,
# not the oracle's own registry pins. scripts/post-release-bump.sh does the
# same re-resolution for the version-bump case; keep the two in step.
realign-oracle-lock:
    cargo update --manifest-path html-oracle/Cargo.toml --workspace
    cargo check --locked --all-targets --manifest-path html-oracle/Cargo.toml

# The workspace-excluded html-oracle crate (#529, #699). `fmt-check`, `lint`,
# `test` and `deny` above are all `--workspace`/`--all`, and none descends into
# an excluded member, so without these two recipes `just ci` would go green
# while the required `html-oracle checks` job goes red — breaking this file's
# golden rule. The CI job runs exactly these, so the two cannot drift.
oracle-checks:
    cargo fmt --manifest-path html-oracle/Cargo.toml -- --check
    cargo clippy --locked --all-targets --manifest-path html-oracle/Cargo.toml -- -D warnings
    cargo test --locked --all-targets --manifest-path html-oracle/Cargo.toml
    cargo run --locked --manifest-path html-oracle/Cargo.toml -- --repo-root .

# Scoped to the oracle's own dependency graph via html-oracle/deny.toml, which
# the root `deny` recipe cannot see. Separate from `oracle-checks` so CI can run
# it even when a build step above failed — a compile break must not mask an
# advisory on the dependency-bump PRs this gate exists for.
oracle-deny:
    cargo deny --locked --manifest-path html-oracle/Cargo.toml check advisories bans licenses sources

# Unit-test check-fuzz-lock-parity.sh against synthetic lockfiles (containment
# vs. equality, drift in both directions, malformed input). No cargo or repo
# state. Mirrored in the `publish-checks` CI job.
test-fuzz-lock-parity:
    ./scripts/check-fuzz-lock-parity.test.sh

# Unit-test check-env-deployment-policies.sh against synthetic API fixtures.
# No network, no real gh, no repo state.
test-env-deployment-policies:
    ./scripts/check-env-deployment-policies.test.sh

# Fail when any Actions environment's deployment-branch-policy configuration
# drifts from the matrix issue #755 settled (read-only; needs gh auth).
# Mirrored in the ci.yml `zizmor self-check` job.
check-env-deployment-policies:
    ./scripts/check-env-deployment-policies.sh

# Dry-run the crates.io publish: package all 8 crates (workspace) without
# uploading. Validates manifests/metadata; runs on a normal -dev branch.
publish-dry-run:
    ./scripts/publish-crates.sh --dry-run

# Check the workspace public APIs against the last release tag for accidental
# SemVer breakage (issues #544, #633). Requires `cargo-semver-checks`
# (`just setup` installs it).
#
# The baseline is the last reachable `vX.Y.Z` tag, NOT the crates.io release.
# Every publishable crate is currently reserved on crates.io as a bare `0.0.0`
# placeholder, so a registry baseline diffs the real API against an empty crate:
# every item reads as an addition and nothing can ever be reported as a break.
# A tag baseline is version-aware — `0.1.1-dev` is a patch bump from `0.1.0`, so
# a break reddens here until the planned version moves to `0.2.0-dev`. Multiple
# breaking PRs in one release cycle all diff against the same tag, so that one
# bump covers all of them. See RELEASING.md, "Breaking a public API".
#
# A tag baseline has one sharp edge a registry baseline does not: a crate that
# does not exist at the baseline tag is an error ("package not found"), not a
# skip. A PR adding a new publishable crate must pass `--exclude <crate>` for
# that one PR — see RELEASING.md.
#
# This is also release.yml's publish gate (issue #650), so the baseline is
# resolved by scripts/semver-baseline.sh rather than inline: at release time HEAD
# is the tag being released, and the script is what keeps the gate from diffing
# that tree against itself. See the header comment there.
semver-checks:
    #!/usr/bin/env bash
    set -euo pipefail
    baseline="$(./scripts/semver-baseline.sh)"
    echo "semver baseline: $baseline ($(git rev-parse --short "$baseline"))"
    cargo semver-checks check-release --workspace --baseline-rev "$baseline"

# Unit-test semver-baseline.sh (baseline selection, the HEAD-is-the-tag case
# release.yml hits, prerelease and unreachable tags, missing-baseline errors)
# against throwaway git repos in a temp dir. No cargo, no network, no repo
# state. Mirrored in the `publish-checks` CI job.
test-semver-baseline:
    ./scripts/semver-baseline.test.sh

# Full local-CI equivalent. If this passes, CI will pass.
ci: fmt-check lint test test-doc test-msrv deny machete check-no-openssl mcp-conformance-node check-tools-doc check-metadata test-publish-script test-post-release-bump test-semver-baseline test-fuzz-lock-parity check-fuzz-lock-parity test-env-deployment-policies test-installer test-prune-containers semver-checks oracle-checks oracle-deny
    typos

# Re-run pre-commit hooks across all files.
hooks:
    prek install
    prek run --all-files

# Verify a candidate tag against the Cargo.toml workspace version.
# Run this before pushing a `vX.Y.Z` tag.
#   just release-check v0.1.0
release-check TAG:
    ./scripts/check-release-version.sh {{TAG}}
