#!/usr/bin/env bash
# Unit tests for the pure functions in post-release-bump.sh (issue #662).
# Sources the script (which guards `main` behind BASH_SOURCE==$0) and asserts
# behavior without invoking cargo, git, or the network. Run:
# `bash scripts/post-release-bump.test.sh` (or `just test-post-release-bump`).
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=scripts/post-release-bump.sh
# shellcheck disable=SC1091  # sourced file not followed when linted in isolation
source "${here}/post-release-bump.sh"

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

failures=0

check() {
    local desc="$1" expected="$2" actual="$3"
    if [ "$expected" = "$actual" ]; then
        echo "ok: ${desc}"
    else
        echo "FAIL: ${desc} — expected [${expected}], got [${actual}]" >&2
        failures=$((failures + 1))
    fi
}

expect_ok() {
    local desc="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        echo "ok: ${desc}"
    else
        echo "FAIL: ${desc} — command failed, expected success" >&2
        failures=$((failures + 1))
    fi
}

expect_fail() {
    local desc="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        echo "FAIL: ${desc} — command succeeded, expected failure" >&2
        failures=$((failures + 1))
    else
        echo "ok: ${desc}"
    fi
}

# --- next_dev_version -------------------------------------------------------
check "next_dev_version bumps the patch and adds -dev" \
    "0.2.1-dev" "$(next_dev_version v0.2.0)"
check "next_dev_version tolerates a tag without the v prefix" \
    "0.2.1-dev" "$(next_dev_version 0.2.0)"
check "next_dev_version carries past 9 without touching minor" \
    "1.9.100-dev" "$(next_dev_version v1.9.99)"
# A zero-padded field must not be read as octal (`08` is not a valid octal).
check "next_dev_version reads a zero-padded patch as decimal" \
    "0.2.9-dev" "$(next_dev_version v0.2.08)"

# The job's `if:` already excludes pre-release tags, but a bad version here
# would produce a nonsense manifest version rather than failing, so the script
# refuses anything that is not exactly vX.Y.Z.
expect_fail "next_dev_version rejects a pre-release tag" next_dev_version v0.2.0-rc1
expect_fail "next_dev_version rejects a two-field version" next_dev_version v0.2
expect_fail "next_dev_version rejects a non-numeric field" next_dev_version vX.Y.Z
expect_fail "next_dev_version rejects an empty tag" next_dev_version ""

# --- ensure_unreleased_heading ----------------------------------------------
changelog="${tmp}/CHANGELOG.md"
printf '# Changelog\n\nIntro line.\n\n## [0.2.0] - 2026-08-01\n\n- shipped\n' >"$changelog"
ensure_unreleased_heading "$changelog"
check "ensure_unreleased_heading inserts the heading above the top release" \
    "## [Unreleased]" "$(sed -n '5p' "$changelog")"
check "ensure_unreleased_heading leaves the preamble alone" \
    "# Changelog" "$(sed -n '1p' "$changelog")"
check "ensure_unreleased_heading keeps the release section" \
    "## [0.2.0] - 2026-08-01" "$(sed -n '7p' "$changelog")"

before="$(cat "$changelog")"
ensure_unreleased_heading "$changelog"
check "ensure_unreleased_heading is idempotent" "$before" "$(cat "$changelog")"

# --- assert_known_lockfiles -------------------------------------------------
# The real repo layout: root workspace, both fuzz workspaces, html-oracle.
expect_ok "assert_known_lockfiles accepts the current repo layout" \
    assert_known_lockfiles "$(printf '%s\n' \
        Cargo.lock crates/rimap-server/fuzz/Cargo.lock fuzz/Cargo.lock \
        html-oracle/Cargo.lock)"

# The point of the guard: a workspace added later that nothing re-resolves
# would otherwise stay clean, never reach the derived commit set, and pin the
# pre-bump versions forever.
expect_fail "assert_known_lockfiles rejects an unrecognised workspace" \
    assert_known_lockfiles "$(printf '%s\n' Cargo.lock tools/Cargo.lock)"
# Not a fuzz workspace — the directory merely ends in "fuzz". Mirrors the same
# distinction check-fuzz-lock-parity.sh draws for its discovery globs.
expect_fail "assert_known_lockfiles rejects a notfuzz/ lookalike" \
    assert_known_lockfiles "$(printf '%s\n' Cargo.lock notfuzz/Cargo.lock)"
expect_ok "assert_known_lockfiles accepts a newly added nested fuzz workspace" \
    assert_known_lockfiles "$(printf '%s\n' Cargo.lock crates/rimap-imap/fuzz/Cargo.lock)"

# --- assert_bump_complete ---------------------------------------------------
# The set a real bump produces, captured by running one: `cargo set-version
# --workspace` + xtask restore + `cargo update` + realign. rimap-core is absent
# on purpose — it inherits the workspace version and has no intra-workspace
# deps to rewrite, so its manifest is untouched.
real_set="$(printf '%s\n' \
    Cargo.lock Cargo.toml \
    crates/rimap-audit/Cargo.toml crates/rimap-authz/Cargo.toml \
    crates/rimap-config/Cargo.toml crates/rimap-content/Cargo.toml \
    crates/rimap-fake-imap/Cargo.toml crates/rimap-imap/Cargo.toml \
    crates/rimap-server/Cargo.toml crates/rimap-server/fuzz/Cargo.lock \
    crates/rimap-smtp/Cargo.toml fuzz/Cargo.lock html-oracle/Cargo.lock \
    CHANGELOG.md)"
expect_ok "assert_bump_complete accepts a real bump's file set" \
    assert_bump_complete "$real_set"

expect_fail "assert_bump_complete rejects an empty set" assert_bump_complete ""
expect_fail "assert_bump_complete rejects a set missing the root manifest" \
    assert_bump_complete "$(printf '%s\n' Cargo.lock crates/rimap-audit/Cargo.toml)"
# The restore is what preserves xtask's deliberate 0.0.0; a dirty xtask
# manifest means it did not happen.
expect_fail "assert_bump_complete rejects an unrestored xtask manifest" \
    assert_bump_complete "$(printf '%s\n' Cargo.toml Cargo.lock xtask/Cargo.toml)"
# A path that merely contains the name must not trip the exact-match guard.
expect_ok "assert_bump_complete does not confuse a substring path with xtask" \
    assert_bump_complete "$(printf '%s\n' Cargo.toml crates/xtask/Cargo.toml.bak)"

# --- emit_output ------------------------------------------------------------
check "emit_output prints key=value when not running under Actions" \
    "next=0.2.1-dev" "$(GITHUB_OUTPUT="" emit_output next 0.2.1-dev)"

out="${tmp}/github_output"
: >"$out"
GITHUB_OUTPUT="$out" emit_output paths "$(printf 'Cargo.toml\nCargo.lock\n')"
check "emit_output writes a multiline value in the heredoc form Actions parses" \
    "paths<<POST_RELEASE_BUMP_EOF|Cargo.toml|Cargo.lock|POST_RELEASE_BUMP_EOF" \
    "$(tr '\n' '|' <"$out" | sed 's/|$//')"

# ---------------------------------------------------------------------------
if [ "$failures" -ne 0 ]; then
    echo "${failures} test(s) failed" >&2
    exit 1
fi
echo "all post-release-bump.sh tests passed"
