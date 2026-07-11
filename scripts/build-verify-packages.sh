#!/usr/bin/env bash
# Build the .deb/.rpm for a target triple, copy them into the CWD, assert each
# package actually contains the man pages + a license + the README (catches an
# asset-path-base slip that would otherwise ship a man-less/license-less
# package), then lint (warn-only). Shared by both Linux packaging legs in
# .github/workflows/release.yml so the content-assertion is single-source.
#
# Requires cargo-deb + cargo-generate-rpm on PATH, a binary already built at
# target/<triple>/release/rusty-imap-mcp, and (for the assertion) an
# apt-based runner. Run: build-verify-packages.sh <target-triple>
set -euo pipefail

triple="${1:?usage: build-verify-packages.sh <target-triple>}"

cargo deb --no-build --no-strip -p rimap-server --target "$triple"
cargo generate-rpm -p crates/rimap-server --target "$triple"
cp "target/$triple/debian/"*.deb .
cp "target/$triple/generate-rpm/"*.rpm .

# Require: top man page + >=1 subcommand page + a LICENSE + README in each
# package. dpkg-deb/rpm -qlp are arch-agnostic, so this runs host-side for both
# the native x86_64 and the cross-packaged arm64 leg.
sudo apt-get update && sudo apt-get install -y --no-install-recommends rpm
for pkg in ./*.deb; do
    c="$(dpkg-deb --contents "$pkg")"
    if ! { printf '%s' "$c" | grep -q 'usr/share/man/man1/rusty-imap-mcp\.1' &&
        printf '%s' "$c" | grep -Eq 'usr/share/man/man1/rusty-imap-mcp-[a-z-]+\.1' &&
        printf '%s' "$c" | grep -q 'usr/share/doc/rusty-imap-mcp/LICENSE-MIT' &&
        printf '%s' "$c" | grep -q 'usr/share/doc/rusty-imap-mcp/README.md'; }; then
        echo "::error::$pkg missing man/license/README asset" >&2
        exit 1
    fi
done
for pkg in ./*.rpm; do
    c="$(rpm -qlp "$pkg")"
    if ! { printf '%s' "$c" | grep -q '/usr/share/man/man1/rusty-imap-mcp\.1' &&
        printf '%s' "$c" | grep -Eq '/usr/share/man/man1/rusty-imap-mcp-[a-z-]+\.1' &&
        printf '%s' "$c" | grep -q '/usr/share/licenses/rusty-imap-mcp/LICENSE-MIT' &&
        printf '%s' "$c" | grep -q '/usr/share/doc/rusty-imap-mcp/README.md'; }; then
        echo "::error::$pkg missing man/license/README asset" >&2
        exit 1
    fi
done

# Lint is advisory: surface packaging nits without failing the release.
sudo apt-get install -y --no-install-recommends lintian rpmlint || true
lintian --no-tag-display-limit ./*.deb || true
rpmlint ./*.rpm || true
