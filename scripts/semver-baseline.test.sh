#!/usr/bin/env bash
# Unit tests for semver-baseline.sh (issue #650). Every case builds a throwaway
# git repository in a temp dir and drives the script against it — no cargo, no
# network, no state from this repo. The temp tree is removed on exit.
#
# The case that carries the issue is "HEAD is the tag being released": the
# release workflow runs on a tag push, so the naive `git describe --abbrev=0`
# resolves to the tag being released and the gate compares a tree with itself.
#
# Run: `bash scripts/semver-baseline.test.sh` (or `just test-semver-baseline`).
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="${here}/semver-baseline.sh"

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

failures=0
case_n=0

# Hermetic git: the developer's global config must not decide whether a fixture
# repo can commit (signing, hooks, templates, user identity).
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_SYSTEM=/dev/null
export GIT_AUTHOR_NAME='semver baseline test'
export GIT_AUTHOR_EMAIL='test@example.invalid'
export GIT_COMMITTER_NAME="${GIT_AUTHOR_NAME}"
export GIT_COMMITTER_EMAIL="${GIT_AUTHOR_EMAIL}"

# A fresh repo per case, so tag sets never leak between them. Sets `repo`
# rather than printing it: a command substitution would run the counter bump in
# a subshell and hand every case the same directory.
new_repo() {
    case_n=$((case_n + 1))
    repo="${tmp}/repo${case_n}"
    mkdir -p "${repo}"
    # Pin the initial branch: with no global config there is no
    # `init.defaultBranch`, and git then prints an advisory to stderr.
    git -C "${repo}" init -q -b main
}

commit() {
    local repo="$1" msg="$2"
    echo "${msg}" >>"${repo}/log"
    git -C "${repo}" add log
    git -C "${repo}" commit -q -m "${msg}"
}

expect_baseline() {
    local desc="$1" repo="$2" want="$3"
    local got status=0
    got="$(cd "${repo}" && "${script}" 2>/dev/null)" || status=$?
    if [ "${status}" -ne 0 ]; then
        echo "FAIL: ${desc} — script exited ${status}, expected [${want}]" >&2
        failures=$((failures + 1))
    elif [ "${got}" = "${want}" ]; then
        echo "ok: ${desc}"
    else
        echo "FAIL: ${desc} — got [${got}], want [${want}]" >&2
        failures=$((failures + 1))
    fi
}

# Assert failure AND that the message names the reason. An unexplained non-zero
# exit is not good enough: the operator has to know whether to fetch tags or to
# go looking at the tag they just pushed.
expect_error() {
    local desc="$1" repo="$2" needle="$3"
    local out status=0
    out="$(cd "${repo}" && "${script}" 2>&1)" || status=$?
    if [ "${status}" -eq 0 ]; then
        echo "FAIL: ${desc} — expected a non-zero exit, got [${out}]" >&2
        failures=$((failures + 1))
    elif [ "${out#*"${needle}"}" != "${out}" ]; then
        echo "ok: ${desc}"
    else
        echo "FAIL: ${desc} — output did not contain [${needle}]:" >&2
        echo "${out}" >&2
        failures=$((failures + 1))
    fi
}

# --- the ordinary PR-branch shape -------------------------------------------

new_repo
commit "${repo}" one
git -C "${repo}" tag v0.1.0
commit "${repo}" two
expect_baseline "an untagged HEAD after one release resolves that release" \
    "${repo}" v0.1.0

new_repo
commit "${repo}" one
git -C "${repo}" tag v0.1.0
commit "${repo}" two
git -C "${repo}" tag v0.2.0
commit "${repo}" three
expect_baseline "an untagged HEAD resolves the most recent release, not the first" \
    "${repo}" v0.2.0

# --- HEAD is the tag being released (the issue) -----------------------------

# What release.yml's `publish-crates` job sees. A plain `git describe
# --abbrev=0` answers v0.2.0 here, which would diff the release against itself.
new_repo
commit "${repo}" one
git -C "${repo}" tag v0.1.0
commit "${repo}" two
git -C "${repo}" tag v0.2.0
expect_baseline "a tagged HEAD resolves the PREVIOUS release, not its own tag" \
    "${repo}" v0.1.0

# Cross-check the same fixture against the naive command, so this suite fails if
# someone "simplifies" the script back to it and the case above stops biting.
naive="$(cd "${repo}" && git describe --tags --abbrev=0 --match 'v[0-9]*.[0-9]*.[0-9]*')"
if [ "${naive}" = "v0.2.0" ]; then
    echo "ok: the naive describe really does self-compare on that fixture"
else
    echo "FAIL: fixture no longer reproduces the self-comparison (naive gave [${naive}])" >&2
    failures=$((failures + 1))
fi

# A re-tag or a version-alias tag can leave several release tags on one commit.
new_repo
commit "${repo}" one
git -C "${repo}" tag v0.1.0
commit "${repo}" two
git -C "${repo}" tag v0.2.0
git -C "${repo}" tag v0.3.0
expect_baseline "every release tag on HEAD is excluded, not just the newest" \
    "${repo}" v0.1.0

# Two releases cut from the same commit: the baseline is still the earlier
# *reachable* release, which here is the one before them both.
new_repo
commit "${repo}" one
git -C "${repo}" tag v0.1.0
commit "${repo}" two
git -C "${repo}" tag v0.2.0
commit "${repo}" three
git -C "${repo}" tag v0.3.0
expect_baseline "a tagged HEAD skips only HEAD's tags, keeping the rest" \
    "${repo}" v0.2.0

# --- tags that are not releases ---------------------------------------------

new_repo
commit "${repo}" one
git -C "${repo}" tag v0.1.0
commit "${repo}" two
git -C "${repo}" tag v0.2.0-rc1
commit "${repo}" three
expect_baseline "a prerelease tag is not a baseline" "${repo}" v0.1.0

new_repo
commit "${repo}" one
git -C "${repo}" tag v0.1.0
commit "${repo}" two
git -C "${repo}" tag v0.2.0-rc1
expect_baseline "a prerelease tag on HEAD is skipped like any other" \
    "${repo}" v0.1.0

new_repo
commit "${repo}" one
git -C "${repo}" tag v0.1.0
commit "${repo}" two
git -C "${repo}" tag nightly
git -C "${repo}" tag v1
expect_baseline "a tag that is not vX.Y.Z is not a baseline" "${repo}" v0.1.0

# A tag on a branch HEAD cannot see is not a candidate — `cargo semver-checks`
# would be handed a tree that is not an ancestor of what is being released.
new_repo
commit "${repo}" one
git -C "${repo}" tag v0.1.0
git -C "${repo}" checkout -q -b side
commit "${repo}" side-work
git -C "${repo}" tag v9.9.9
git -C "${repo}" checkout -q -
commit "${repo}" two
expect_baseline "an unreachable tag is not a baseline" "${repo}" v0.1.0

# --- no baseline exists -----------------------------------------------------

new_repo
commit "${repo}" one
expect_error "a repo with no release tag fails with the fetch hint" \
    "${repo}" "hint: run 'git fetch --tags'"

# The first release ever: nothing precedes the tag being cut, so the gate cannot
# run. It fails rather than passing empty — a shallow clone reaches this same
# state, and that one is a broken gate, not a genuine first release.
new_repo
commit "${repo}" one
git -C "${repo}" tag v0.1.0
expect_error "a tagged HEAD with no earlier release says so specifically" \
    "${repo}" "the only release tags reachable from HEAD are on HEAD itself"

mkdir -p "${tmp}/not-a-repo"
expect_error "a directory outside any git repo fails" \
    "${tmp}/not-a-repo" "error:"

# --- stdout is machine-readable ---------------------------------------------

# Callers substitute this into `--baseline-rev`, so a diagnostic leaking onto
# stdout would be passed to cargo as part of the revision.
new_repo
commit "${repo}" one
git -C "${repo}" tag v0.1.0
commit "${repo}" two
out="$(cd "${repo}" && "${script}" 2>/dev/null)"
if [ "$(printf '%s\n' "${out}" | wc -l | tr -d ' ')" = "1" ]; then
    echo "ok: stdout carries the tag and nothing else"
else
    echo "FAIL: stdout was not a single line:" >&2
    printf '%s\n' "${out}" >&2
    failures=$((failures + 1))
fi

# --- result -----------------------------------------------------------------

if [ "${failures}" -ne 0 ]; then
    echo "${failures} semver-baseline test(s) failed" >&2
    exit 1
fi
echo "all semver-baseline tests passed"
