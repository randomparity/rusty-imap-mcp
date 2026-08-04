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
# CI: a required check would go red where nobody is told. Deriving the set from
# `git diff --name-only` cannot rot, and the assertions below refuse to hand
# back a set this script knows to be wrong.
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

# Prepend an `## [Unreleased]` heading above the topmost release section, unless
# one is already there. Idempotent: the bump may run against a CHANGELOG on
# which someone already opened the section by hand.
ensure_unreleased_heading() {
    local changelog="$1"
    if grep -q '^## \[Unreleased\]' "$changelog"; then
        return 0
    fi
    awk 'BEGIN{done=0} /^## \[/ && !done {print "## [Unreleased]"; print ""; done=1} {print}' \
        "$changelog" >"${changelog}.tmp"
    mv "${changelog}.tmp" "$changelog"
}

# Refuse to run against a repo layout this script does not know how to
# re-resolve. Every tracked lockfile (newline-separated on stdin) must be the
# root workspace's, a fuzz workspace's — handled by `just realign-fuzz-locks` —
# or listed in KNOWN_EXTRA_LOCKS. Without this, adding a second
# `html-oracle`-shaped tool workspace would reintroduce #662 one layer down:
# the new lockfile would keep the pre-bump versions, stay clean, and so never
# reach the derived commit set.
assert_known_lockfiles() {
    local locks="$1" lock unknown=""
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

# Sanity-check the derived commit set (newline-separated on stdin) before it
# becomes `add-paths`. Deriving the set removes the omission failure mode; these
# catch the two ways the bump itself can go wrong and still leave a
# plausible-looking set behind.
assert_bump_complete() {
    local changed="$1"
    if [ -z "$changed" ]; then
        echo "::error::the bump changed no tracked files — nothing to commit" >&2
        return 1
    fi
    if ! grep -Fxq 'Cargo.toml' <<<"$changed"; then
        echo "::error::the bump did not rewrite the root Cargo.toml" >&2
        return 1
    fi
    # `xtask` is deliberately `version = "0.0.0"`, `publish = false`, and pins
    # `rimap-server` by path with no version requirement — the churn-immune
    # shape ADR-0003 records for `html-oracle`. It is a workspace *member*
    # though, so `cargo set-version --workspace` sweeps it up anyway and main()
    # restores it. A dirty xtask manifest here means that restore did not
    # happen, and committing it would silently normalise a deliberate opt-out.
    if grep -Fxq 'xtask/Cargo.toml' <<<"$changed"; then
        echo "::error::xtask/Cargo.toml is modified; its 0.0.0 opt-out was not restored" >&2
        return 1
    fi
}

# Append a step output when running under Actions; print it otherwise so a hand
# run still shows what the job would commit.
emit_output() {
    local key="$1" value="$2"
    if [ -z "${GITHUB_OUTPUT:-}" ]; then
        printf '%s=%s\n' "$key" "$value"
        return 0
    fi
    {
        printf '%s<<POST_RELEASE_BUMP_EOF\n' "$key"
        printf '%s\n' "$value"
        printf 'POST_RELEASE_BUMP_EOF\n'
    } >>"$GITHUB_OUTPUT"
}

main() {
    if [ $# -ne 1 ]; then
        echo "usage: $0 <released-tag>   # e.g. v0.2.0" >&2
        return 2
    fi
    cd "$(git rev-parse --show-toplevel)"

    local next changed
    next="$(next_dev_version "$1")"
    assert_known_lockfiles "$(git ls-files '*Cargo.lock')"

    cargo set-version --workspace "$next"
    # Restore before re-resolving, so Cargo.lock records xtask at 0.0.0 rather
    # than at a version its manifest no longer claims. See assert_bump_complete.
    git checkout -- xtask/Cargo.toml
    cargo update --workspace
    cargo update --manifest-path html-oracle/Cargo.toml -p rimap-core -p rimap-content
    # Every rimap-* path dep a fuzz workspace resolves just moved, so both fuzz
    # lockfiles now violate ADR-0011 parity. Realign discovers them from git.
    just realign-fuzz-locks
    ensure_unreleased_heading CHANGELOG.md

    # Gates, run against the state that is about to be committed rather than
    # left to a CI run the bump PR does not get. `--locked` is the direct test
    # of the manifest/lockfile agreement a partial commit destroys.
    cargo metadata --locked --format-version 1 >/dev/null
    just check-fuzz-lock-parity

    changed="$(git diff --name-only)"
    assert_bump_complete "$changed"

    printf 'bumped to %s; committing:\n%s\n' "$next" "$changed"
    emit_output next "$next"
    emit_output paths "$changed"
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
