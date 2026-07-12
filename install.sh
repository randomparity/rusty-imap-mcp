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

# Retry knobs — overridable so the hermetic fixture tests (which hit missing
# file:// URLs on purpose) don't spin through the full production backoff.
RUSTY_IMAP_MCP_RETRY="${RUSTY_IMAP_MCP_RETRY:-5}"
RUSTY_IMAP_MCP_RETRY_DELAY="${RUSTY_IMAP_MCP_RETRY_DELAY:-5}"

err() { printf 'install.sh: %s\n' "$*" >&2; }

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        err "missing required command: $1"
        exit 3
    }
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
        rm -f "$tmp"
        exit 4
    fi
    tag="$(sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' "$tmp" | head -n 1)"
    rm -f "$tmp"
    if [ -z "$tag" ]; then
        err "could not parse tag_name; set RUSTY_IMAP_MCP_VERSION=vX.Y.Z to pin"
        exit 4
    fi
    echo "$tag"
}

verify_sha256() { # sums fname dir  -> return 5 on mismatch
    line="$(grep "$2\$" "$1" | sed 's|  \./|  |' || true)"
    if [ -z "$line" ]; then
        err "no checksum entry for $2"
        return 5
    fi
    if command -v sha256sum >/dev/null 2>&1; then
        echo "$line" | (cd "$3" && sha256sum -c - >/dev/null 2>&1) || return 5
    else
        echo "$line" | (cd "$3" && shasum -a 256 -c - >/dev/null 2>&1) || return 5
    fi
}

main() {
    require_cmd uname
    require_cmd mktemp
    require_cmd tar
    command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 || {
        err "neither curl nor wget is installed"
        exit 3
    }
    command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1 || {
        err "neither sha256sum nor shasum is installed"
        exit 3
    }

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
        err "download failed: $archive"
        exit 4
    }
    http_get "$RUSTY_IMAP_MCP_BASE_URL/$tag/SHA256SUMS.txt" "$workdir/SHA256SUMS.txt" || {
        err "download failed: SHA256SUMS.txt"
        exit 4
    }

    verify_sha256 "$workdir/SHA256SUMS.txt" "$archive" "$workdir" || {
        err "SHA-256 verification failed (corrupted download?)"
        exit 5
    }

    (cd "$workdir" && tar xzf "$archive") || {
        err "tar extraction failed"
        exit 6
    }

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
