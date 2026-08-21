#!/usr/bin/env bash
# Fail when any repository Actions environment's deployment-branch-policy
# configuration drifts from the matrix issue #755 settled.
#
# Why this exists: environment settings live outside git, so nothing in a PR
# review or a lockfile diff keeps them honest. The gap this guards is real and
# asymmetric: GitHub auto-creates an environment, with no protections at all,
# the first time a workflow names it — `crates-io` would have sprung into
# existence unprotected on the first tagged release after release.yml gained
# its publish job. The matrix below is the decision record's answer (#755,
# comment thread verified against the live API); this gate makes drift loud
# instead of silent.
#
# The matrix:
#   fuzz-lock-realign  protected branches only, no required reviewers.
#                      Consumed by dependabot-fuzz-lock.yml's pull_request_target
#                      job, whose ref is refs/heads/main; main is protected, so
#                      the policy matches without reinstating the manual step
#                      ADR-0016 refuses. Reviewers must stay at zero.
#   release            custom policies: tag v* + branch main. Reached by tag
#                      pushes and non-dry-run workflow_dispatch from main.
#   homebrew-tap       custom policies: tag v* + branch main. Same triggers as
#                      `release` within release.yml.
#   crates-io          custom policies: tag v*. Its job is push-gated, so it is
#                      never reached from a branch ref.
#   sonarcloud         NO deployment branch policy — deliberate carve-out. The
#                      sonarqube job runs on plain pull_request, whose ref
#                      refs/pull/N/merge matches no branch-name pattern; a
#                      policy there reddens a required check on every PR. It
#                      also holds no environment secrets today, so a policy
#                      would guard nothing. See the ci.yml comment above
#                      `environment: sonarcloud` and #755's thread.
#
# Any environment outside the matrix fails closed: a new `environment:` key
# added to a workflow must come here and get an explicit row, because "new
# environment, unprotected" is exactly the state this gate exists to catch.
#
# This checks the branch dimension only. It cannot see whether the secrets an
# environment appears to scope actually live on the environment rather than at
# repository level — that half of #755 needs plaintext only the operator holds.
#
# Usage:
#   check-env-deployment-policies.sh [OWNER/REPO]
#
# Defaults to GITHUB_REPOSITORY inside Actions, else the origin remote. Set
# RIMAP_GH_BIN to route the API calls through a stub in tests.
#
# Wired into the ci.yml `zizmor self-check` job and `just ci`
# (`check-env-deployment-policies`). Tested by
# scripts/check-env-deployment-policies.test.sh.
set -euo pipefail

REPO="${1:-${GITHUB_REPOSITORY:-}}"
if [[ -z "$REPO" ]]; then
    REPO="$(git config --get remote.origin.url | sed -E 's#.*[:/]([^/]+/[^/.]+)(\.git)?$#\1#')"
fi

GH_BIN="${RIMAP_GH_BIN:-gh}"

python3 - "$REPO" "$GH_BIN" <<'PY'
import json
import subprocess
import sys
import urllib.parse

repo, gh = sys.argv[1], sys.argv[2]

# (mode, policies) where mode is "protected" (branches-with-protection only),
# "custom" (explicit {type, name} set), or "none" (carve-out). Only "custom"
# has policies. Every row also forbids required reviewers: ADR-0016 refuses
# them on fuzz-lock-realign, and the remaining environments hold no secrets a
# reviewer gate could protect anyway (#755).
MATRIX = {
    "fuzz-lock-realign": ("protected", frozenset()),
    "release": ("custom", frozenset({("tag", "v*"), ("branch", "main")})),
    "homebrew-tap": ("custom", frozenset({("tag", "v*"), ("branch", "main")})),
    "crates-io": ("custom", frozenset({("tag", "v*")})),
    "sonarcloud": ("none", frozenset()),
}


def api(path):
    proc = subprocess.run([gh, "api", path], capture_output=True, text=True)
    if proc.returncode != 0:
        print(f"error: gh api {path} failed: {proc.stderr.strip()}", file=sys.stderr)
        sys.exit(2)
    return json.loads(proc.stdout)


def env_path(name):
    return f"repos/{repo}/environments/{urllib.parse.quote(name, safe='')}"


drift = []

listing = api(f"repos/{repo}/environments")
actual_names = [e["name"] for e in listing.get("environments", [])]

for name in sorted(set(actual_names) - set(MATRIX)):
    drift.append(
        f"{name}: not in the policy matrix — add a row to "
        f"scripts/check-env-deployment-policies.sh (a new environment is born "
        f"unprotected)"
    )
for name in sorted(set(MATRIX) - set(actual_names)):
    mode = MATRIX[name][0]
    if mode == "none":
        continue  # a carved-out environment that was deleted stays deleted
    drift.append(f"{name}: missing — expected a configured environment")

for name in actual_names:
    if name not in MATRIX:
        continue
    mode, policies = MATRIX[name]
    detail = api(env_path(name))
    dbp = detail.get("deployment_branch_policy")
    rules = [
        r for r in (detail.get("protection_rules") or [])
        if r.get("type") != "branch_policy"
    ]
    if rules:
        drift.append(
            f"{name}: has protection rule(s) of types "
            f"{sorted({r.get('type') for r in rules})}; required reviewers "
            f"must stay at zero (ADR-0016, #755)"
        )
    if mode == "none":
        if dbp is not None:
            drift.append(
                f"{name}: carries a deployment branch policy but the matrix "
                f"carves it out — remove it (see ci.yml's sonarcloud comment)"
            )
        continue
    if dbp is None:
        drift.append(f"{name}: has no deployment branch policy")
        continue
    if mode == "protected":
        if not dbp.get("protected_branches") or dbp.get("custom_branch_policies"):
            drift.append(
                f"{name}: expected protected-branches-only, got "
                f"{{protected_branches={dbp.get('protected_branches')}, "
                f"custom_branch_policies={dbp.get('custom_branch_policies')}}}"
            )
        continue
    if not dbp.get("custom_branch_policies"):
        drift.append(
            f"{name}: expected custom branch policies "
            f"{sorted(policies)}, got protected_branches="
            f"{dbp.get('protected_branches')}"
        )
        continue
    listed = api(f"{env_path(name)}/deployment-branch-policies")
    actual = {(p["type"], p["name"]) for p in listed.get("branch_policies", [])}
    for missing in sorted(policies - actual):
        drift.append(f"{name}: missing {missing[0]} policy {missing[1]!r}")
    for extra in sorted(actual - policies):
        drift.append(
            f"{name}: unexpected {extra[0]} policy {extra[1]!r} — tighten it or "
            f"amend the matrix with a recorded reason"
        )

if drift:
    print("environment deployment-policy drift detected:", file=sys.stderr)
    for line in drift:
        print(f"  - {line}", file=sys.stderr)
    sys.exit(1)

print("environment deployment policies match the #755 matrix")
PY
