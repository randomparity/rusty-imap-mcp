#!/usr/bin/env bash
# Rewrite the workspace to the next patch `-dev` version after a stable release,
# re-resolve every lockfile the rewrite touches, and report the exact set of
# files that must be committed (ADR-0003).
#
# Called by `.github/workflows/release.yml`'s `post-release-bump` job with the
# released tag. Runnable by hand for the same effect:
#
#   ./scripts/post-release-bump.sh v0.2.0
#
# Why the committed file set is *derived* rather than hardcoded in the workflow
# (issue #662): a bump dirties one file per workspace manifest plus one lockfile
# per cargo workspace, and this repo grew both after the original hand-written
# `add-paths` list was written — `xtask` on 2026-07-11 and the nested
# `crates/rimap-server/fuzz` workspace before it. The list silently omitted all
# three. A partial commit is not a cosmetic problem:
#
#   - `Cargo.lock` committed without `xtask/Cargo.toml` records a version the
#     manifest does not have, so every `--locked` build on the branch fails —
#     including `release.yml`'s own `manpages` job;
#   - fuzz lockfiles left behind fail `check-fuzz-lock-parity`, which is a
#     *required* status context (ADR-0011).
#
# And the bump PR is opened by `GITHUB_TOKEN`, so it triggers no `pull_request`
# CI: a required check would go red where nobody is told. That absent CI is also
# why every assertion below runs here, in the job, rather than being left to the
# PR: this is the last place a broken bump can be caught by a machine.
#
# Derivation is bounded, not blind — `assert_expected_shape` refuses to commit
# anything that is not a manifest, a lockfile, or the changelog, so a build step
# that dirties a source file cannot smuggle it into the bump PR.
#
# Tested by scripts/post-release-bump.test.sh.
set -euo pipefail

# Lockfiles outside the root workspace that this script re-resolves explicitly,
# by path. Fuzz lockfiles are NOT listed: `just realign-fuzz-locks` discovers
# them from git, so a new fuzz workspace is covered without editing anything.
# `assert_known_lockfiles` fails on any tracked lockfile covered by neither
# mechanism, so a future workspace cannot be forgotten in silence.
KNOWN_EXTRA_LOCKS="html-oracle/Cargo.lock"

# The next patch `-dev` version for a released `vX.Y.Z` tag. bzr's default and
# ADR-0003's: patch is the conservative placeholder, edited on the bump PR when
# the next release is a minor or major.
next_dev_version() {
    local tag="$1" released
    released="${tag#v}"
    if [[ ! "$released" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
        echo "::error::not a stable release tag: '${tag}' (want vX.Y.Z)" >&2
        return 1
    fi
    # 10# so a zero-padded field (`v0.2.08`) is not read as octal.
    printf '%s.%s.%s-dev\n' \
        "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "$((10#${BASH_REMATCH[3]} + 1))"
}

# A version's major.minor.patch as a fixed-width key, pre-release and build
# suffixes dropped. Fixed width makes a string compare a numeric one, so callers
# need no arithmetic and `0.2.0-dev` and `0.2.0` compare equal — which is what
# "has main already moved past this release?" means.
version_sort_key() {
    local core="${1%%[-+]*}"
    if [[ ! "$core" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
        return 1
    fi
    printf '%05d%05d%05d\n' \
        "$((10#${BASH_REMATCH[1]}))" "$((10#${BASH_REMATCH[2]}))" "$((10#${BASH_REMATCH[3]}))"
}

# Refuse a bump that would not move the workspace forward. The job checks out
# `main`, not the tag, so a re-run of an older release's workflow — or a `main`
# somebody bumped ahead by hand — would otherwise rewrite the version
# *backwards*. Every other gate here would still pass, because a downgrade is
# internally consistent: `--locked` holds, parity holds, the file set looks
# exactly like a routine bump. Only the version itself gives it away.
assert_forward_bump() {
    local current="$1" next="$2" current_key next_key
    if ! current_key="$(version_sort_key "$current")"; then
        echo "::error::cannot parse the workspace version on main: '${current}'" >&2
        return 1
    fi
    next_key="$(version_sort_key "$next")"
    if [[ "$current_key" < "$next_key" ]]; then
        return 0
    fi
    echo "::error::refusing to bump: main is at ${current}, which is not behind ${next}" >&2
    echo "Either this re-runs an older release's job, or main was bumped by hand." >&2
    return 1
}

# Prepend an `## [Unreleased]` heading above the topmost release section, unless
# one is already there. Idempotent: the bump may run against a CHANGELOG on
# which someone already opened the section by hand. Fails rather than no-ops on
# a changelog with no release section, which awk would otherwise copy through
# unchanged and leave the bump PR quietly missing its heading.
ensure_unreleased_heading() {
    local changelog="$1"
    if grep -q '^## \[Unreleased\]' "$changelog"; then
        return 0
    fi
    awk 'BEGIN{done=0} /^## \[/ && !done {print "## [Unreleased]"; print ""; done=1} {print}' \
        "$changelog" >"${changelog}.tmp"
    mv "${changelog}.tmp" "$changelog"
    if ! grep -q '^## \[Unreleased\]' "$changelog"; then
        echo "::error::${changelog} has no '## [' release section to insert above" >&2
        return 1
    fi
}

# Refuse to run against a repo layout this script does not know how to
# re-resolve. Every tracked lockfile (newline-separated in $1) must be the root
# workspace's, a fuzz workspace's — handled by `just realign-fuzz-locks` — or
# listed in KNOWN_EXTRA_LOCKS. Without this, adding a second
# `html-oracle`-shaped tool workspace would reintroduce #662 one layer down: the
# new lockfile would keep the pre-bump versions, stay clean, and so never reach
# the derived commit set.
assert_known_lockfiles() {
    local locks="$1" lock unknown=""
    # A guard that reads nothing passes vacuously, so require the one lockfile
    # that must always be there rather than trusting a possibly-empty list.
    if ! grep -Fxq 'Cargo.lock' <<<"$locks"; then
        echo "::error::no root Cargo.lock in the tracked lockfile list — nothing was checked" >&2
        return 1
    fi
    while IFS= read -r lock; do
        [ -n "$lock" ] || continue
        case "$lock" in
        Cargo.lock | fuzz/Cargo.lock | */fuzz/Cargo.lock) continue ;;
        esac
        case " ${KNOWN_EXTRA_LOCKS} " in
        *" ${lock} "*) continue ;;
        esac
        unknown="${unknown}${lock} "
    done <<<"$locks"
    if [ -n "$unknown" ]; then
        echo "::error::post-release-bump does not know how to re-resolve: ${unknown% }" >&2
        echo "A cargo workspace was added without teaching this script about it." >&2
        echo "Add its lockfile to KNOWN_EXTRA_LOCKS and re-resolve it in main()." >&2
        return 1
    fi
}

# Bound the derived set. Deriving from `git diff` is what stops the list rotting,
# but it also means anything a step in this job dirties gets committed to a PR
# against `main` that no `pull_request` CI ever looks at. A version bump touches
# manifests, lockfiles, and the changelog — nothing else — and that shape holds
# for workspaces this repo has not grown yet, so bounding it costs no
# rot-resistance.
assert_expected_shape() {
    local changed="$1" path unexpected=""
    while IFS= read -r path; do
        [ -n "$path" ] || continue
        case "$path" in
        CHANGELOG.md) continue ;;
        esac
        case "${path##*/}" in
        Cargo.toml | Cargo.lock) continue ;;
        esac
        unexpected="${unexpected}${path} "
    done <<<"$changed"
    if [ -n "$unexpected" ]; then
        echo "::error::the bump dirtied files a version bump has no business touching: ${unexpected% }" >&2
        return 1
    fi
}

# Sanity-check the derived commit set (newline-separated in $1) against the
# manifests that deliberately opt out of the workspace version ($2). Deriving
# the set removes the omission failure mode; these catch the two ways the bump
# itself can go wrong and still leave a plausible-looking set behind.
assert_bump_complete() {
    local changed="$1" optouts="$2" path swept=""
    if [ -z "$changed" ]; then
        echo "::error::the bump changed no tracked files — nothing to commit" >&2
        return 1
    fi
    if ! grep -Fxq 'Cargo.toml' <<<"$changed"; then
        echo "::error::the bump did not rewrite the root Cargo.toml" >&2
        return 1
    fi
    while IFS= read -r path; do
        [ -n "$path" ] || continue
        if grep -Fxq "$path" <<<"$changed"; then
            swept="${swept}${path} "
        fi
    done <<<"$optouts"
    if [ -n "$swept" ]; then
        echo "::error::deliberate 0.0.0 opt-out(s) were swept and not restored: ${swept% }" >&2
        echo "Committing them would normalise an opt-out into the workspace version." >&2
        return 1
    fi
}

# Append a step output when running under Actions; print it otherwise so a hand
# run still shows what the job would commit.
emit_output() {
    local key="$1" value="$2" delimiter="POST_RELEASE_BUMP_EOF"
    if [ -z "${GITHUB_OUTPUT:-}" ]; then
        printf '%s=%s\n' "$key" "$value"
        return 0
    fi
    # The runner ends a heredoc block at the first line equal to the delimiter
    # and reads what follows as further commands, so a value carrying that line
    # could forge another step output. Nothing reaching here can (the values are
    # a validated version and a set of manifest paths), which is exactly why
    # refusing is free.
    if grep -Fxq "$delimiter" <<<"$value"; then
        echo "::error::refusing to emit '${key}': its value contains the output delimiter" >&2
        return 1
    fi
    {
        printf '%s<<%s\n' "$key" "$delimiter"
        printf '%s\n' "$value"
        printf '%s\n' "$delimiter"
    } >>"$GITHUB_OUTPUT"
}

# Manifests that pin a literal `version = "0.0.0"` instead of inheriting the
# workspace version, read from HEAD before the bump rewrites them. `xtask` is
# the only *member* with that shape today — `publish = false`, `rimap-server`
# pinned by path with no version requirement, the churn-immune shape ADR-0003
# records for `html-oracle` — but `cargo set-version --workspace` sweeps any
# such member, so they are discovered rather than named. Both fuzz manifests
# match too; they are not workspace members, are never swept, and so never reach
# the restore or the guard.
version_optout_manifests() {
    local matches line status=0
    matches="$(git grep -l --fixed-strings --line-regexp 'version = "0.0.0"' HEAD -- '*Cargo.toml')" ||
        status=$?
    # Exit 1 is "no matches", a legitimate answer; anything higher is a failure
    # that must not be read as one.
    if [ "$status" -gt 1 ]; then
        echo "::error::git grep failed while looking for 0.0.0 manifests (exit ${status})" >&2
        return 1
    fi
    [ -n "$matches" ] || return 0
    # `git grep <rev>` prefixes every path with `HEAD:`; strip it so the paths
    # are comparable with the worktree-relative ones everything else uses.
    while IFS= read -r line; do
        printf '%s\n' "${line#HEAD:}"
    done <<<"$matches"
}

# Undo the sweep over each opt-out manifest, before anything re-resolves against
# it, so the lockfiles record 0.0.0 rather than a version its manifest no longer
# claims. See assert_bump_complete for why committing the sweep is wrong.
restore_version_optouts() {
    local optouts="$1" manifest
    while IFS= read -r manifest; do
        [ -n "$manifest" ] || continue
        if ! git diff --quiet -- "$manifest"; then
            git checkout -- "$manifest"
            printf 'restored %s (deliberate 0.0.0 opt-out)\n' "$manifest"
        fi
    done <<<"$optouts"
}

main() {
    if [ $# -ne 1 ]; then
        echo "usage: $0 <released-tag>   # e.g. v0.2.0" >&2
        return 2
    fi
    local root
    root="$(git rev-parse --show-toplevel)"
    cd "$root"

    local next current locks optouts changed
    next="$(next_dev_version "$1")"
    current="$(awk -F'"' '/^version = /{print $2; exit}' Cargo.toml)"
    assert_forward_bump "$current" "$next"
    locks="$(git ls-files '*Cargo.lock')"
    assert_known_lockfiles "$locks"
    optouts="$(version_optout_manifests)"

    cargo set-version --workspace "$next"
    restore_version_optouts "$optouts"
    cargo update --workspace
    # Re-resolving is enough to pull the moved rimap-* path-dep versions into
    # this lockfile; no package list to fall out of date, the same reason
    # check-fuzz-lock-parity.sh's realign uses `cargo metadata`.
    cargo metadata --manifest-path html-oracle/Cargo.toml --format-version 1 >/dev/null
    # Every rimap-* path dep a fuzz workspace resolves just moved, so both fuzz
    # lockfiles now violate ADR-0011 parity. Realign discovers them from git.
    just realign-fuzz-locks
    ensure_unreleased_heading CHANGELOG.md

    # Gates, run against the state that is about to be committed rather than
    # left to a CI run the bump PR does not get. `--locked` is the direct test
    # of the manifest/lockfile agreement a partial commit destroys.
    cargo metadata --locked --format-version 1 >/dev/null
    cargo metadata --locked --manifest-path html-oracle/Cargo.toml --format-version 1 >/dev/null
    just check-fuzz-lock-parity

    # --name-only HEAD, not bare: staged changes count too, so a step added
    # later that stages its work cannot drop a file from the set silently.
    # quotePath=false keeps a non-ASCII path literal, since `git add` would not
    # match the C-quoted form create-pull-request would hand it.
    changed="$(git -c core.quotePath=false diff --name-only HEAD)"
    assert_expected_shape "$changed"
    assert_bump_complete "$changed" "$optouts"

    printf 'bumped %s -> %s; committing:\n%s\n' "$current" "$next" "$changed"
    emit_output next "$next"
    emit_output paths "$changed"
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
