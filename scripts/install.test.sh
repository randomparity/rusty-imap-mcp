#!/usr/bin/env bash
# Unit + fixture tests for install.sh. Sources it with RUSTY_IMAP_MCP_SOURCED=1
# (which guards `main`) and drives the download/checksum/install flow against a
# local file:// fixture — no network, no live release. Run: `just test-installer`.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/.." && pwd)"
# NOT exported: it must guard the `. install.sh` source below (skip main) without
# leaking into the `sh install.sh` e2e subprocesses (which must run main).
# shellcheck disable=SC2034  # read by the sourced install.sh main-guard
RUSTY_IMAP_MCP_SOURCED=1
# Fixtures hit missing file:// URLs on purpose; skip the production retry backoff
# so the two exit-4 negative cases fail fast instead of spinning ~25s each.
export RUSTY_IMAP_MCP_RETRY=0 RUSTY_IMAP_MCP_RETRY_DELAY=0
# shellcheck source=install.sh
. "$repo/install.sh"

failures=0
check() { # desc expected actual
    if [ "$2" = "$3" ]; then echo "ok: $1"; else
        echo "FAIL: $1 — expected [$2] got [$3]" >&2
        failures=$((failures + 1))
    fi
}
expect_exit() { # desc want-code cmd...
    local desc="$1" want="$2"
    shift 2
    local got=0
    ("$@") >/dev/null 2>&1 || got=$?
    check "$desc" "$want" "$got"
}

sum_file() { # file (relative to cwd) -> "hash  file" line
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a 256 "$1"; fi
}

# --- map_target (pure) -------------------------------------------------------
check "linux x86_64" "x86_64-unknown-linux-gnu" "$(map_target Linux x86_64)"
check "linux aarch64" "aarch64-unknown-linux-gnu" "$(map_target Linux aarch64)"
check "linux arm64" "aarch64-unknown-linux-gnu" "$(map_target Linux arm64)"
check "linux ppc64le" "powerpc64le-unknown-linux-gnu" "$(map_target Linux ppc64le)"
check "linux s390x" "s390x-unknown-linux-gnu" "$(map_target Linux s390x)"
check "macos arm64" "aarch64-apple-darwin" "$(map_target Darwin arm64)"
expect_exit "unsupported platform -> 1" 1 map_target Linux riscv64

# --- verify_sha256 (pure) ----------------------------------------------------
fix="$(mktemp -d)"
trap 'rm -rf "$fix"' EXIT
echo payload >"$fix/pkg.tar.gz"
(cd "$fix" && sum_file pkg.tar.gz) >"$fix/SHA256SUMS.txt"
expect_exit "checksum match -> 0" 0 verify_sha256 "$fix/SHA256SUMS.txt" pkg.tar.gz "$fix"
# A full-length but wrong hash: Darwin sha256sum treats a short/malformed hash as
# "improperly formatted" (exit 0), so the mismatch must be a valid 64-hex value.
echo "0000000000000000000000000000000000000000000000000000000000000000  pkg.tar.gz" >"$fix/bad.txt"
expect_exit "checksum mismatch -> 5" 5 verify_sha256 "$fix/bad.txt" pkg.tar.gz "$fix"

# --- main end-to-end via file:// fixture -------------------------------------
# The fixtures use file:// URLs; install.sh's http_get uses curl (which supports
# file://) and falls back to wget (which does NOT). Skip the e2e block on a
# curl-less host rather than report false exit-4 failures.
if ! command -v curl >/dev/null 2>&1; then
    echo "skip: curl not present; skipping file:// fixture tests"
    if [ "$failures" -eq 0 ]; then
        echo "pure-function tests passed"
        exit 0
    else exit 1; fi
fi

# Build a fixture release: a tarball whose inner binary prints a version.
rel="$(mktemp -d)"
trap 'rm -rf "$fix" "$rel"' EXIT
tag="v9.9.9"
triple="$(map_target "$(uname -s)" "$(uname -m)")"
stage="rusty-imap-mcp-$tag-$triple"
mkdir -p "$rel/$tag/$stage"
printf '#!/bin/sh\necho "rusty-imap-mcp 9.9.9"\n' >"$rel/$tag/$stage/rusty-imap-mcp"
chmod +x "$rel/$tag/$stage/rusty-imap-mcp"
(cd "$rel/$tag" && tar czf "$stage.tar.gz" "$stage" && rm -rf "$stage")
(cd "$rel/$tag" && sum_file ./*.tar.gz >SHA256SUMS.txt)

# Happy path: install + advisory smoke succeeds.
out_dir="$(mktemp -d)"
(RUSTY_IMAP_MCP_BASE_URL="file://$rel" RUSTY_IMAP_MCP_VERSION="$tag" \
    RUSTY_IMAP_MCP_INSTALL_DIR="$out_dir/bin" sh "$repo/install.sh") >/dev/null 2>&1
check "happy install places binary" "yes" \
    "$([ -x "$out_dir/bin/rusty-imap-mcp" ] && echo yes || echo no)"

# exit 5: corrupt the SHA256SUMS entry.
bad_rel="$(mktemp -d)"
cp -r "$rel/$tag" "$bad_rel/"
echo "0000000000000000000000000000000000000000000000000000000000000000  $stage.tar.gz" >"$bad_rel/$tag/SHA256SUMS.txt"
expect_exit "tampered checksum -> 5" 5 env \
    RUSTY_IMAP_MCP_BASE_URL="file://$bad_rel" RUSTY_IMAP_MCP_VERSION="$tag" \
    RUSTY_IMAP_MCP_INSTALL_DIR="$(mktemp -d)/bin" sh "$repo/install.sh"

# exit 6: garbage tarball whose recorded checksum matches (clears 5, fails tar).
g_rel="$(mktemp -d)/x"
mkdir -p "$g_rel/$tag"
echo "not a tarball" >"$g_rel/$tag/$stage.tar.gz"
(cd "$g_rel/$tag" && sum_file ./*.tar.gz >SHA256SUMS.txt)
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
as_rel="$(mktemp -d)/y"
mkdir -p "$as_rel/$tag/$stage"
printf '#!/bin/sh\nexit 1\n' >"$as_rel/$tag/$stage/rusty-imap-mcp"
chmod +x "$as_rel/$tag/$stage/rusty-imap-mcp"
(cd "$as_rel/$tag" && tar czf "$stage.tar.gz" "$stage" && rm -rf "$stage")
(cd "$as_rel/$tag" && sum_file ./*.tar.gz >SHA256SUMS.txt)
expect_exit "advisory smoke failure -> 0" 0 env \
    RUSTY_IMAP_MCP_BASE_URL="file://$as_rel" RUSTY_IMAP_MCP_VERSION="$tag" \
    RUSTY_IMAP_MCP_INSTALL_DIR="$(mktemp -d)/bin" sh "$repo/install.sh"

if [ "$failures" -ne 0 ]; then
    echo "$failures test(s) failed" >&2
    exit 1
fi
echo "all installer tests passed"
