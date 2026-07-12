#!/usr/bin/env bash
# Unit tests for the pure functions in publish-crates.sh. Sources the script
# (which guards `main` behind BASH_SOURCE==$0) and asserts behavior without ever
# touching crates.io. Run: `bash scripts/publish-crates.test.sh` (or `just
# test-publish-script`).
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=scripts/publish-crates.sh
# shellcheck disable=SC1091  # sourced file not followed when linted in isolation
source "${here}/publish-crates.sh"

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

# Assert a command succeeds / fails, reusing the failures bookkeeping.
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

# --- parse_retry_after ------------------------------------------------------
# Real crates.io new-crate 429 message shape (cargo 1.94.0): the retry time is
# an RFC 2822 / HTTP-date after "try again after", NOT a seconds value.
future_msg='the remote server responded with an error (status 429 Too Many Requests): You have published too many new crates in a short period of time. Please try again after Fri, 01 Jan 2100 00:00:00 GMT or email help@crates.io to have your limit increased.'
past_msg='status 429 Too Many Requests): ... Please try again after Tue, 27 Dec 2022 17:25:13 GMT or email help@crates.io ...'
non_429='error: failed to verify package tarball: some unrelated build error'

future_secs="$(parse_retry_after "$future_msg")"
if [ "$future_secs" -gt 0 ]; then
    echo "ok: parse_retry_after returns a positive delta for a future timestamp (${future_secs}s)"
else
    echo "FAIL: parse_retry_after future timestamp — expected >0, got [${future_secs}]" >&2
    failures=$((failures + 1))
fi

check "parse_retry_after clamps a past timestamp to 0" "0" "$(parse_retry_after "$past_msg")"
check "parse_retry_after returns -1 sentinel when no timestamp present" "-1" "$(parse_retry_after "$non_429")"

# --- publish_outcome (silent-failure guard, issue #544) ---------------------
# A genuine (non-429, non-already-exists) failure MUST classify as `fail` so the
# caller exits non-zero — otherwise a broken/partial release goes green in CI.
check "publish_outcome: rc=0 is ok" "ok" "$(publish_outcome 0 'Uploading rimap-core v0.1.0')"
check "publish_outcome: already-exists race is skip" "skip" \
    "$(publish_outcome 101 'error: crate version 0.1.0 already exists on crates.io index')"
check "publish_outcome: 429 is retry" "retry" \
    "$(publish_outcome 101 'the remote server responded with an error (status 429 Too Many Requests): ... too many new crates ...')"
check "publish_outcome: 403 auth error is fail" "fail" \
    "$(publish_outcome 101 'error: failed to publish: the remote server responded with an error (status 403 Forbidden): must be authenticated')"
check "publish_outcome: verify build error is fail" "fail" \
    "$(publish_outcome 101 'error: could not compile rimap-core (lib) due to 1 previous error')"
check "publish_outcome: 5xx server error is fail" "fail" \
    "$(publish_outcome 101 'error: failed to get a 200 OK response, got 502 Bad Gateway')"

# --- version_ok_to_publish --------------------------------------------------
expect_ok "version_ok_to_publish allows a clean version in real mode" \
    version_ok_to_publish "0.1.0" "real"
expect_fail "version_ok_to_publish blocks a -dev version in real mode" \
    version_ok_to_publish "0.1.1-dev" "real"
expect_ok "version_ok_to_publish allows a -dev version under --dry-run" \
    version_ok_to_publish "0.1.1-dev" "dry-run"

# --- publish order is a valid topological sort of the real workspace DAG -----
# Not a tautology against a hand-copied list: derive the workspace members and
# their intra-workspace normal/build dependency edges from `cargo metadata` and
# assert CRATES is exactly those members, each published after its deps. Guards
# the hand-maintained CRATES order against a new crate or a new dep edge.
order_problems="$(
    CRATES="${CRATES[*]}" python3 - <<'PY'
import json
import os
import subprocess

order = os.environ["CRATES"].split()
meta = json.loads(
    subprocess.check_output(["cargo", "metadata", "--no-deps", "--format-version", "1"])
)
# Exclude publish=false members (cargo metadata reports `publish: []`), e.g. the
# `xtask` build-helper crate, which is never published and so is not in CRATES.
members = {p["name"] for p in meta["packages"] if p.get("publish") != []}
# Publish ordering depends on normal + build deps only (dev-deps are not in the
# published dependency graph); exclude self-edges (the path-only self dev-deps).
edges = {
    p["name"]: {
        d["name"]
        for d in p["dependencies"]
        if d["name"] in members and d["name"] != p["name"] and d.get("kind") in (None, "build")
    }
    for p in meta["packages"]
}

problems = []
if set(order) != members:
    problems.append(f"CRATES {sorted(order)} != workspace members {sorted(members)}")
pos = {name: i for i, name in enumerate(order)}
for crate in order:
    for dep in edges.get(crate, ()):
        if pos.get(dep, len(order)) >= pos[crate]:
            problems.append(f"{crate} published before its dependency {dep}")
print("; ".join(problems))
PY
)"
check "CRATES is a valid topological order of the workspace DAG" "" "$order_problems"

if [ "$failures" -eq 0 ]; then
    echo "all publish-script unit tests passed"
    exit 0
fi
echo "${failures} publish-script unit test(s) failed" >&2
exit 1
