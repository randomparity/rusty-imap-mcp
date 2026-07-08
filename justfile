# Developer entry points for rusty-imap-mcp.
#
# Golden rule: if `just ci` passes locally, CI will pass. Never run bare cargo
# for checks — use these targets so CI and local dev stay in lockstep.

set shell := ["bash", "-uc"]

MSRV := "1.88.0"

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
    cargo nextest --version >/dev/null 2>&1 || cargo install --locked cargo-nextest
    cargo msrv --version >/dev/null 2>&1 || cargo install --locked cargo-msrv
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

# Remove stale rimap-it-* pods/volumes left by SIGKILL'd test runs.
# Operates below compose to avoid the lock-exhaustion cascade where
# compose-down itself fails because podman has no free locks.
[private]
prune-containers:
    #!/usr/bin/env bash
    set -euo pipefail
    tool="${RIMAP_CONTAINER_TOOL:-}"
    if [ -z "$tool" ]; then
        if command -v docker >/dev/null 2>&1; then tool=docker
        elif command -v podman >/dev/null 2>&1; then tool=podman
        else exit 0; fi
    fi
    cutoff=$(($(date +%s) - 1800))
    # Remove stale pods (podman) or containers (docker) whose names
    # start with rimap-it- and that were created more than 30min ago.
    if [ "$tool" = "podman" ]; then
        podman pod ls --format '{{{{.Name}}' --noheading 2>/dev/null \
        | grep '^rimap-it-' \
        | while read -r pod; do
            created=$(podman pod inspect "$pod" --format '{{{{.Created}}' 2>/dev/null) || continue
            ts=$(date -d "$created" +%s 2>/dev/null) || continue
            if [ "$ts" -lt "$cutoff" ]; then
                podman pod rm -f "$pod" 2>/dev/null || true
            fi
        done || true
    fi
    # Prune orphaned rimap-it-* volumes regardless of runtime.
    "$tool" volume ls --format '{{{{.Name}}' 2>/dev/null \
    | grep '^rimap-it-' \
    | while read -r vol; do
        "$tool" volume rm -f "$vol" 2>/dev/null || true
    done || true

# Unit and fast tests (no Proton Bridge).
test: prune-containers
    cargo nextest run --workspace --locked --no-tests=pass

# Inner-loop unit tests. Skips the five heaviest test binaries
# (dovecot integration, e2e/e2e_wire MCP suites, and the slow HTML
# lookalike proptest). Use this between `cargo check` cycles during
# inner-loop iteration. Before pushing, run `just test` (or `just ci`)
# for the full sweep. See
# docs/superpowers/specs/2026-05-20-local-test-runtime-trim-design.md.
test-fast:
    cargo nextest run --workspace --locked --no-tests=pass \
        -E 'not (binary(dovecot) | binary(e2e) | binary(e2e_wire) | binary(e2e_wire_cancellation) | binary(proptest_html_lookalike))'

# Verify the MSRV toolchain still builds and tests the workspace.
test-msrv:
    cargo +{{MSRV}} check --workspace --all-targets --all-features --locked
    cargo +{{MSRV}} nextest run --workspace --locked --no-tests=pass

# Cargo-mutants survey. In-place is required on macOS; see docs/security/cargo-mutants-runbook.md.
mutants *args:
    cargo mutants --in-place {{args}}

# Proton Bridge integration suite (gated on PROTON_BRIDGE_TEST=1).
test-integration:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ "${PROTON_BRIDGE_TEST:-0}" != "1" ]; then
        echo "set PROTON_BRIDGE_TEST=1 to run Proton Bridge integration tests"
        exit 1
    fi
    cargo nextest run --workspace --locked --features proton-bridge-tests

# Adversarial email corpus against the content pipeline.
test-injection:
    cargo nextest run -p rimap-content --locked --test injection_corpus

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

# Full local-CI equivalent. If this passes, CI will pass.
ci: fmt-check lint test test-msrv deny mcp-conformance-node check-tools-doc
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
