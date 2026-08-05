#!/usr/bin/env bash
# Resolve the SemVer baseline for `cargo semver-checks --baseline-rev`: the most
# recent `vX.Y.Z` tag reachable from HEAD that is *not* HEAD itself.
#
# Prints the tag name on stdout and nothing else, so callers can use `$(...)`.
# Diagnostics go to stderr; a missing baseline is a non-zero exit, never a
# silent empty string (issues #633, #650).
#
# Why "not HEAD itself" (issue #650): the release workflow runs on a `v*` tag
# push, so in the `publish-crates` job HEAD *is* the tag being released. A plain
# `git describe --abbrev=0` resolves to that tag, and diffing a tree against
# itself reports no breaks by construction — a gate that is green whatever it is
# handed. Excluding every `vX.Y.Z` tag that points at HEAD makes the release-time
# baseline the *previous* release, which is the comparison the gate is for.
#
# On a PR branch no tag points at the branch head, so the exclusion is a no-op
# and the resolved baseline is unchanged. One definition serves both callers.
#
# Prereleases are excluded (`--exclude '*-*'`): `verify-tag` rejects any tag
# containing `-`, so no `-dev` or `-rc` tag is ever a released baseline.
#
# Run: `bash scripts/semver-baseline.sh` (usually via `just semver-checks`).
set -euo pipefail

# Stable-release tags only. Used both to select candidates for `git describe`
# and to decide which tags on HEAD are release tags worth excluding.
tag_glob='v[0-9]*.[0-9]*.[0-9]*'

if ! head_tags="$(git tag --list "${tag_glob}" --points-at HEAD 2>&1)"; then
    echo "error: could not list the tags on HEAD" >&2
    echo "  git tag: ${head_tags}" >&2
    exit 1
fi

# `--exclude` takes a glob; a `vX.Y.Z` tag name has no glob metacharacters (`.`
# is literal), so the name is its own pattern.
exclude_args=()
while IFS= read -r tag; do
    [ -n "${tag}" ] || continue
    exclude_args+=(--exclude "${tag}")
done <<EOF
${head_tags}
EOF

# Capture stderr rather than discarding it: "no tag found" and "not a git repo"
# both exit non-zero, and only the first deserves the fetch hint. `${a[@]+...}`
# keeps an empty array from tripping `set -u` under bash 3.2 (macOS).
if baseline="$(git describe --tags --abbrev=0 \
    --match "${tag_glob}" --exclude '*-*' \
    ${exclude_args[@]+"${exclude_args[@]}"} 2>&1)"; then
    printf '%s\n' "${baseline}"
    exit 0
fi

if [ -n "${head_tags}" ]; then
    echo "error: the only release tags reachable from HEAD are on HEAD itself" >&2
    echo "  tags on HEAD: $(printf '%s' "${head_tags}" | tr '\n' ' ')" >&2
    echo "  so there is no earlier release to diff the public API against" >&2
else
    echo "error: no ${tag_glob} tag found, so there is no SemVer baseline" >&2
fi
echo "  git describe: ${baseline}" >&2
echo "hint: run 'git fetch --tags' (a shallow or tagless clone hides them)" >&2
exit 1
