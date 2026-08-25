#!/usr/bin/env bash
# Unit tests for the pure functions in post-release-bump.sh (issue #662).
# Sources the script (which guards `main` behind BASH_SOURCE==$0) and asserts
# behavior without invoking cargo, git, or the network.
# Run: `bash scripts/post-release-bump.test.sh` (or `just
# test-post-release-bump`, which `just ci` and the `publish-checks` CI job
# both invoke).
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

check_contains() {
    local desc="$1" haystack="$2" needle="$3"
    if [[ "$haystack" == *"$needle"* ]]; then
        echo "ok: ${desc}"
    else
        echo "FAIL: ${desc} — missing [${needle}]" >&2
        failures=$((failures + 1))
    fi
}

check_ordered() {
    local desc="$1" log="$2"
    shift 2
    local needle remaining
    remaining="$log"
    for needle in "$@"; do
        if [[ "$remaining" != *"$needle"* ]]; then
            echo "FAIL: ${desc} — missing or out of order [${needle}]" >&2
            failures=$((failures + 1))
            return
        fi
        remaining="${remaining#*"$needle"}"
    done
    echo "ok: ${desc}"
}

# --- next_dev_version -------------------------------------------------------
check "next_dev_version bumps the patch and adds -dev" \
    "0.2.1-dev" "$(next_dev_version v0.2.0)"
check "next_dev_version tolerates a tag without the v prefix" \
    "0.2.1-dev" "$(next_dev_version 0.2.0)"
check "next_dev_version carries past 9 without touching minor" \
    "1.9.100-dev" "$(next_dev_version v1.9.99)"
# A zero-padded field must not be read as octal (`08` is not valid octal).
check "next_dev_version reads a zero-padded patch as decimal" \
    "0.2.9-dev" "$(next_dev_version v0.2.08)"

# The job's `if:` already excludes pre-release tags, but a bad version here
# would produce a nonsense manifest version rather than failing, so the script
# refuses anything that is not exactly vX.Y.Z.
expect_fail "next_dev_version rejects a pre-release tag" next_dev_version v0.2.0-rc1
expect_fail "next_dev_version rejects a two-field version" next_dev_version v0.2
expect_fail "next_dev_version rejects a non-numeric field" next_dev_version vX.Y.Z
expect_fail "next_dev_version rejects an empty tag" next_dev_version ""

# --- version_sort_key / assert_forward_bump ---------------------------------
check "version_sort_key pads each field to a fixed width" \
    "000010000200003" "$(version_sort_key 1.2.3)"
check "version_sort_key ignores a pre-release suffix" \
    "$(version_sort_key 0.2.0)" "$(version_sort_key 0.2.0-dev)"
check "version_sort_key ignores build metadata" \
    "$(version_sort_key 0.2.0)" "$(version_sort_key 0.2.0+g1234abc)"
expect_fail "version_sort_key rejects a two-field version" version_sort_key 0.2

# The job checks out `main`, not the tag, so the version it rewrites is
# whatever main holds at job time — which is not necessarily the released one.
expect_ok "assert_forward_bump accepts the ordinary post-release case" \
    assert_forward_bump 0.2.0 0.2.1-dev
expect_ok "assert_forward_bump accepts a main still carrying the old -dev" \
    assert_forward_bump 0.2.0-dev 0.2.1-dev
# Re-running an older release's workflow, or a main bumped ahead by hand. A
# downgrade is internally consistent, so no other gate here would notice it.
expect_fail "assert_forward_bump rejects a bump that moves main backwards" \
    assert_forward_bump 0.3.0-dev 0.2.1-dev
expect_fail "assert_forward_bump rejects a bump to the version main already has" \
    assert_forward_bump 0.2.1-dev 0.2.1-dev
expect_fail "assert_forward_bump rejects an unparseable current version" \
    assert_forward_bump "" 0.2.1-dev

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

# awk copies a changelog with no release section through unchanged, which would
# leave the bump PR quietly missing its heading.
printf '# Changelog\n\nNothing released yet.\n' >"${tmp}/empty-CHANGELOG.md"
expect_fail "ensure_unreleased_heading fails on a changelog with no release section" \
    ensure_unreleased_heading "${tmp}/empty-CHANGELOG.md"

# --- assert_known_lockfiles -------------------------------------------------
# The real repo layout: root workspace, both fuzz workspaces, html-oracle, and
# both committed exact-E0639 downstream fixtures.
expect_ok "assert_known_lockfiles accepts the current repo layout" \
    assert_known_lockfiles "$(printf '%s\n' \
        Cargo.lock crates/rimap-server/fuzz/Cargo.lock fuzz/Cargo.lock \
        html-oracle/Cargo.lock \
        crates/rimap-audit/tests/fixtures/e0639-probe/Cargo.lock \
        crates/rimap-imap/tests/fixtures/e0639-probe/Cargo.lock)"

# The point of the guard: a workspace added later that nothing re-resolves
# would otherwise stay clean, never reach the derived commit set, and pin the
# pre-bump versions forever.
expect_fail "assert_known_lockfiles rejects an unrecognised workspace" \
    assert_known_lockfiles "$(printf '%s\n' Cargo.lock tools/Cargo.lock)"
expect_fail "assert_known_lockfiles rejects an unknown compiler-probe fixture" \
    assert_known_lockfiles "$(printf '%s\n' Cargo.lock \
        crates/demo/tests/fixtures/e0639-probe/Cargo.lock)"
# Not a fuzz workspace — the directory merely ends in "fuzz". Mirrors the same
# distinction check-fuzz-lock-parity.sh draws for its discovery globs.
expect_fail "assert_known_lockfiles rejects a notfuzz/ lookalike" \
    assert_known_lockfiles "$(printf '%s\n' Cargo.lock notfuzz/Cargo.lock)"
expect_ok "assert_known_lockfiles accepts a newly added nested fuzz workspace" \
    assert_known_lockfiles "$(printf '%s\n' Cargo.lock crates/rimap-imap/fuzz/Cargo.lock)"
# A guard that reads nothing must not report success.
expect_fail "assert_known_lockfiles rejects an empty list rather than passing vacuously" \
    assert_known_lockfiles ""

# --- assert_expected_shape --------------------------------------------------
# The set a real bump produces, captured by running one: `cargo set-version
# --workspace` + opt-out restore + `cargo update` + realign. rimap-core is
# absent on purpose — it inherits the workspace version and has no
# intra-workspace deps to rewrite, so its manifest is untouched.
real_set="$(printf '%s\n' \
    Cargo.lock Cargo.toml \
    crates/rimap-audit/Cargo.toml crates/rimap-authz/Cargo.toml \
    crates/rimap-config/Cargo.toml crates/rimap-content/Cargo.toml \
    crates/rimap-fake-imap/Cargo.toml crates/rimap-imap/Cargo.toml \
    crates/rimap-server/Cargo.toml crates/rimap-server/fuzz/Cargo.lock \
    crates/rimap-smtp/Cargo.toml fuzz/Cargo.lock html-oracle/Cargo.lock \
    CHANGELOG.md)"
expect_ok "assert_expected_shape accepts a real bump's file set" \
    assert_expected_shape "$real_set"
expect_ok "assert_expected_shape accepts a workspace this repo has not grown yet" \
    assert_expected_shape "$(printf '%s\n' Cargo.toml tools/newthing/Cargo.lock)"
# The derived set is whatever the job dirtied, so a build step that writes to a
# tracked source file must not be able to smuggle it into the bump PR.
expect_fail "assert_expected_shape rejects a source file" \
    assert_expected_shape "$(printf '%s\n' Cargo.toml crates/rimap-core/src/lib.rs)"
expect_fail "assert_expected_shape rejects a workflow file" \
    assert_expected_shape "$(printf '%s\n' Cargo.toml .github/workflows/ci.yml)"

# --- assert_bump_complete ---------------------------------------------------
# `xtask` today; discovered from HEAD rather than named, so a sibling opt-out
# added later is covered too. Both fuzz manifests also pin 0.0.0 but are not
# workspace members, so they are never swept and never appear in `changed`.
optouts="$(printf '%s\n' xtask/Cargo.toml fuzz/Cargo.toml crates/rimap-server/fuzz/Cargo.toml)"

expect_ok "assert_bump_complete accepts a real bump's file set" \
    assert_bump_complete "$real_set" "$optouts"
expect_fail "assert_bump_complete rejects an empty set" \
    assert_bump_complete "" "$optouts"
expect_fail "assert_bump_complete rejects a set missing the root manifest" \
    assert_bump_complete "$(printf '%s\n' Cargo.lock crates/rimap-audit/Cargo.toml)" "$optouts"
# The restore is what preserves the deliberate 0.0.0; a dirty opt-out manifest
# means it did not happen, and committing it would normalise the opt-out away.
expect_fail "assert_bump_complete rejects an unrestored xtask manifest" \
    assert_bump_complete "$(printf '%s\n' Cargo.toml Cargo.lock xtask/Cargo.toml)" "$optouts"
expect_fail "assert_bump_complete rejects an unrestored opt-out added after xtask" \
    assert_bump_complete "$(printf '%s\n' Cargo.toml Cargo.lock ytask/Cargo.toml)" \
    "$(printf '%s\n' xtask/Cargo.toml ytask/Cargo.toml)"
# A path that merely contains the name must not trip the exact-match guard.
expect_ok "assert_bump_complete does not confuse a substring path with an opt-out" \
    assert_bump_complete "$(printf '%s\n' Cargo.toml crates/xtask/Cargo.toml)" "$optouts"
expect_ok "assert_bump_complete tolerates a repo with no opt-out manifests" \
    assert_bump_complete "$(printf '%s\n' Cargo.toml Cargo.lock)" ""

# --- emit_output ------------------------------------------------------------
check "emit_output prints key=value when not running under Actions" \
    "next=0.2.1-dev" "$(GITHUB_OUTPUT="" emit_output next 0.2.1-dev)"

out="${tmp}/github_output"
: >"$out"
GITHUB_OUTPUT="$out" emit_output paths "$(printf 'Cargo.toml\nCargo.lock\n')"
check "emit_output writes a multiline value in the heredoc form Actions parses" \
    "paths<<POST_RELEASE_BUMP_EOF|Cargo.toml|Cargo.lock|POST_RELEASE_BUMP_EOF" \
    "$(tr '\n' '|' <"$out" | sed 's/|$//')"

# A value carrying the delimiter on its own line would close the block early
# and let everything after it parse as further step outputs.
: >"$out"
# Single-quoted on purpose: the body is bash source for the child, which must
# expand it, not this shell.
# shellcheck disable=SC2016
expect_fail "emit_output refuses a value containing the output delimiter" \
    env GITHUB_OUTPUT="$out" bash -c \
    'source "$1"; emit_output paths "$(printf "Cargo.toml\nPOST_RELEASE_BUMP_EOF\nnext=9.9.9\n")"' \
    _ "${here}/post-release-bump.sh"
check "emit_output writes nothing when it refuses" "" "$(cat "$out")"

# --- main orchestration (hermetic) ------------------------------------------
release_repo="${tmp}/release-repo"
fake_bin="${tmp}/fake-bin"
call_log="${tmp}/calls.log"
github_output="${tmp}/release-output"
mkdir -p \
    "${release_repo}/html-oracle" \
    "${release_repo}/crates/rimap-audit/tests/fixtures/e0639-probe" \
    "${release_repo}/crates/rimap-imap/tests/fixtures/e0639-probe" \
    "$fake_bin"
printf '[workspace.package]\nversion = "0.2.0"\n' >"${release_repo}/Cargo.toml"
printf 'version = 4\n' >"${release_repo}/Cargo.lock"
printf '[package]\nname = "oracle"\nversion = "0.0.0"\n' \
    >"${release_repo}/html-oracle/Cargo.toml"
printf 'version = 4\n' >"${release_repo}/html-oracle/Cargo.lock"
for crate in rimap-audit rimap-imap; do
    fixture="${release_repo}/crates/${crate}/tests/fixtures/e0639-probe"
    printf '[package]\nname = "%s-e0639-probe"\nversion = "0.0.0"\n' "$crate" \
        >"${fixture}/Cargo.toml"
    printf 'version = 4\n' >"${fixture}/Cargo.lock"
done
printf '# Changelog\n\n## [0.2.0] - 2026-08-25\n' >"${release_repo}/CHANGELOG.md"
: >"$call_log"
: >"$github_output"

cat >"${fake_bin}/git" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf 'git %s\n' "$*" >>"$CALL_LOG"
case "$1" in
rev-parse)
    printf '%s\n' "$FAKE_ROOT"
    ;;
ls-files)
    printf '%s\n' \
        Cargo.lock \
        html-oracle/Cargo.lock \
        crates/rimap-audit/tests/fixtures/e0639-probe/Cargo.lock \
        crates/rimap-imap/tests/fixtures/e0639-probe/Cargo.lock
    ;;
grep)
    exit 1
    ;;
show)
    cat "$FAKE_ROOT/${3#HEAD:}"
    ;;
diff)
    exit 0
    ;;
-c)
    printf '%s\n' \
        Cargo.toml Cargo.lock html-oracle/Cargo.lock \
        crates/rimap-audit/tests/fixtures/e0639-probe/Cargo.lock \
        crates/rimap-imap/tests/fixtures/e0639-probe/Cargo.lock CHANGELOG.md
    ;;
*)
    printf 'unexpected fake git call: %s\n' "$*" >&2
    exit 2
    ;;
esac
SH

cat >"${fake_bin}/cargo" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf 'cargo %s\n' "$*" >>"$CALL_LOG"
case "$1" in
set-version | update | metadata) ;;
*)
    printf 'unexpected fake cargo call: %s\n' "$*" >&2
    exit 2
    ;;
esac
SH

cat >"${fake_bin}/just" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf 'just %s\n' "$*" >>"$CALL_LOG"
SH
chmod +x "${fake_bin}/git" "${fake_bin}/cargo" "${fake_bin}/just"

if (
    cd "$release_repo"
    PATH="${fake_bin}:$PATH" CALL_LOG="$call_log" FAKE_ROOT="$release_repo" \
        GITHUB_OUTPUT="$github_output" bash -euo pipefail -c \
        'source "$1"; main v0.2.0' _ "${here}/post-release-bump.sh" >/dev/null
); then
    echo "ok: main completes through hermetic release orchestration"
else
    echo "FAIL: main failed through hermetic release orchestration" >&2
    failures=$((failures + 1))
fi

release_calls="$(cat "$call_log")"
check_ordered "main orders compiler-probe realignment and verification" "$release_calls" \
    "cargo set-version --workspace 0.2.1-dev" \
    "cargo update --workspace" \
    "just realign-fuzz-locks" \
    "just realign-compiler-probe-locks" \
    "cargo metadata --locked --offline --manifest-path crates/rimap-audit/tests/fixtures/e0639-probe/Cargo.toml --format-version 1" \
    "cargo metadata --locked --offline --manifest-path crates/rimap-imap/tests/fixtures/e0639-probe/Cargo.toml --format-version 1" \
    "just check-compiler-probe-locks"
release_paths="$(cat "$github_output")"
check_contains "main emits the audit fixture lock" "$release_paths" \
    "crates/rimap-audit/tests/fixtures/e0639-probe/Cargo.lock"
check_contains "main emits the IMAP fixture lock" "$release_paths" \
    "crates/rimap-imap/tests/fixtures/e0639-probe/Cargo.lock"

# --- version_optout_manifests (real repo, read-only) ------------------------
# Deliberately not hermetic, and writes nothing: it reads HEAD of the real
# repo, so it is unaffected by the worktree state. This is the only case that
# exercises the actual `git grep` invocation — an earlier draft passed a
# `--line-regexp` flag `git grep` does not have, which every hermetic test
# above sailed straight past.
real_optouts="$(cd "${here}/.." && version_optout_manifests)"
expect_ok "version_optout_manifests finds xtask's deliberate 0.0.0 in HEAD" \
    grep -Fxq 'xtask/Cargo.toml' <<<"$real_optouts"
expect_fail "version_optout_manifests does not report a version-inheriting member" \
    grep -Fxq 'crates/rimap-core/Cargo.toml' <<<"$real_optouts"

# ---------------------------------------------------------------------------
if [ "$failures" -ne 0 ]; then
    echo "${failures} test(s) failed" >&2
    exit 1
fi
echo "all post-release-bump.sh tests passed"
