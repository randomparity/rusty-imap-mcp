#!/usr/bin/env bash
# Unit tests for check-env-deployment-policies.sh (issue #755). Every case
# drives the script through its RIMAP_GH_BIN seam against synthetic API
# fixtures in a temp dir, touching no network, no real gh, and no repo state.
#
# The fixtures encode the expected deployment-branch-policy matrix from the
# issue's comment thread; the drift cases each break one dimension of it so a
# regression in the checker reports as a failure here rather than as a green
# gate that stopped looking.
#
# Run: `bash scripts/check-env-deployment-policies.test.sh` (or `just
# test-env-deployment-policies`).
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="${here}/check-env-deployment-policies.sh"

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

failures=0

# A stub `gh` that answers `api <path>` from fixture files named by the path
# with `/` folded to `_`. Unknown paths exit 3, which the checker must treat
# as an error, never silently as "no policy".
cat >"${tmp}/gh" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" != "api" ]]; then
    echo "stub gh: unsupported invocation: $*" >&2
    exit 64
fi
key="${2%%\?*}"
key="${key//\//_}"
if [[ ! -s "${FIXTURE_DIR}/${key}.json" ]]; then
    echo "stub gh: no fixture for ${2}" >&2
    exit 3
fi
cat "${FIXTURE_DIR}/${key}.json"
STUB
chmod +x "${tmp}/gh"

# The all-green matrix. `environments` lists exactly the names the guard
# covers; per-environment files carry the shape GET /environments/{name}
# returns; deployment-branch-policies listings carry {name, type} pairs.

write_green_fixtures() {
    local d="${1}"
    cat >"${d}/repos_ownerr_repo_environments.json" <<'JSON'
{"total_count": 7, "environments": [
  {"name": "fuzz-lock-realign", "deployment_branch_policy": {"protected_branches": true, "custom_branch_policies": false}, "protection_rules": []},
  {"name": "release", "deployment_branch_policy": {"protected_branches": false, "custom_branch_policies": true}, "protection_rules": []},
  {"name": "homebrew-tap", "deployment_branch_policy": {"protected_branches": false, "custom_branch_policies": true}, "protection_rules": []},
  {"name": "crates-io", "deployment_branch_policy": {"protected_branches": false, "custom_branch_policies": true}, "protection_rules": []},
  {"name": "corpus-oracle", "deployment_branch_policy": {"protected_branches": false, "custom_branch_policies": true}, "protection_rules": []},
  {"name": "github-pages", "deployment_branch_policy": {"protected_branches": false, "custom_branch_policies": true}, "protection_rules": []},
  {"name": "sonarcloud", "deployment_branch_policy": null, "protection_rules": []}
]}
JSON
    for env in release homebrew-tap crates-io corpus-oracle github-pages sonarcloud fuzz-lock-realign; do
        printf '{"name": "%s", "deployment_branch_policy": null, "protection_rules": [{"type": "branch_policy"}]}\n' "$env" \
            >"${d}/repos_ownerr_repo_environments_${env}.json"
    done
    # Per-environment detail is only consulted for the policy-bearing set; the
    # live GET surfaces the branch policy itself as a protection_rules entry,
    # which the checker must not mistake for a reviewer gate.
    for env in release homebrew-tap crates-io corpus-oracle github-pages; do
        printf '{"name": "%s", "deployment_branch_policy": {"protected_branches": false, "custom_branch_policies": true}, "protection_rules": [{"type": "branch_policy"}]}\n' "$env" \
            >"${d}/repos_ownerr_repo_environments_${env}.json"
    done
    printf '{"name": "fuzz-lock-realign", "deployment_branch_policy": {"protected_branches": true, "custom_branch_policies": false}, "protection_rules": [{"type": "branch_policy"}]}\n' \
        >"${d}/repos_ownerr_repo_environments_fuzz-lock-realign.json"
    cat >"${d}/repos_ownerr_repo_environments_release_deployment-branch-policies.json" <<'JSON'
{"total_count": 2, "branch_policies": [
  {"name": "v*", "type": "tag"},
  {"name": "main", "type": "branch"}
]}
JSON
    cp "${d}/repos_ownerr_repo_environments_release_deployment-branch-policies.json" \
        "${d}/repos_ownerr_repo_environments_homebrew-tap_deployment-branch-policies.json"
    cat >"${d}/repos_ownerr_repo_environments_corpus-oracle_deployment-branch-policies.json" <<'JSON'
{"total_count": 1, "branch_policies": [
  {"name": "main", "type": "branch"}
]}
JSON
    cp "${d}/repos_ownerr_repo_environments_corpus-oracle_deployment-branch-policies.json" \
        "${d}/repos_ownerr_repo_environments_github-pages_deployment-branch-policies.json"
    cat >"${d}/repos_ownerr_repo_environments_crates-io_deployment-branch-policies.json" <<'JSON'
{"total_count": 1, "branch_policies": [
  {"name": "v*", "type": "tag"}
]}
JSON
}

expect_ok() {
    local label="$1"
    if RIMAP_GH_BIN="${tmp}/gh" RIMAP_RETRY_SLEEP=0 FIXTURE_DIR="$fixture_dir" \
        bash "$script" ownerr/repo >"${tmp}/out.txt" 2>&1; then
        : # pass
    else
        failures=$((failures + 1))
        printf 'FAIL %s: expected exit 0\n' "$label"
        cat "${tmp}/out.txt"
    fi
}

expect_fail() {
    local label="$1" needle="$2"
    if RIMAP_GH_BIN="${tmp}/gh" RIMAP_RETRY_SLEEP=0 FIXTURE_DIR="$drift_dir" \
        bash "$script" ownerr/repo >"${tmp}/out.txt" 2>&1; then
        failures=$((failures + 1))
        printf 'FAIL %s: expected nonzero exit\n' "$label"
    elif ! grep -q "$needle" "${tmp}/out.txt"; then
        failures=$((failures + 1))
        printf 'FAIL %s: output does not mention %q\n' "$label" "$needle"
        cat "${tmp}/out.txt"
    fi
}

fixture_dir="${tmp}/green"
mkdir -p "$fixture_dir"
write_green_fixtures "$fixture_dir"
expect_ok "all-green matrix passes"

drift_dir="${tmp}/missing-release-policy"
cp -r "$fixture_dir" "$drift_dir"
rm "${drift_dir}/repos_ownerr_repo_environments_release_deployment-branch-policies.json"
printf '{"total_count": 0, "branch_policies": []}\n' \
    >"${drift_dir}/repos_ownerr_repo_environments_release_deployment-branch-policies.json"
expect_fail "empty policy list on release fails" "release"

drift_dir="${tmp}/sonarcloud-has-policy"
cp -r "$fixture_dir" "$drift_dir"
python3 - "$drift_dir" <<'PY'
import json, sys
path = sys.argv[1] + "/repos_ownerr_repo_environments_sonarcloud.json"
data = json.load(open(path))
data["deployment_branch_policy"] = {"protected_branches": False, "custom_branch_policies": True}
json.dump(data, open(path, "w"))
PY
expect_fail "sonarcloud carrying a policy fails the carve-out" "sonarcloud"

drift_dir="${tmp}/reviewers-on-realign"
cp -r "$fixture_dir" "$drift_dir"
python3 - "$drift_dir" <<'PY'
import json, sys
path = sys.argv[1] + "/repos_ownerr_repo_environments_fuzz-lock-realign.json"
data = json.load(open(path))
data["protection_rules"] = [{"type": "required_reviewers", "reviewers": [{"login": "someone"}]}]
json.dump(data, open(path, "w"))
PY
expect_fail "required reviewers on fuzz-lock-realign fail" "fuzz-lock-realign"

drift_dir="${tmp}/unknown-environment"
cp -r "$fixture_dir" "$drift_dir"
python3 - "$drift_dir" <<'PY'
import json, sys
path = sys.argv[1] + "/repos_ownerr_repo_environments.json"
data = json.load(open(path))
data["environments"].append({"name": "surprise", "deployment_branch_policy": None, "protection_rules": []})
data["total_count"] = len(data["environments"])
json.dump(data, open(path, "w"))
PY
expect_fail "unplanned environment fails closed" "surprise"

drift_dir="${tmp}/crates-io-absent"
cp -r "$fixture_dir" "$drift_dir"
python3 - "$drift_dir" <<'PY'
import json, sys
path = sys.argv[1] + "/repos_ownerr_repo_environments.json"
data = json.load(open(path))
data["environments"] = [e for e in data["environments"] if e["name"] != "crates-io"]
data["total_count"] = len(data["environments"])
json.dump(data, open(path, "w"))
PY
expect_fail "absent crates-io fails" "crates-io"

drift_dir="${tmp}/wrong-policy-type"
cp -r "$fixture_dir" "$drift_dir"
python3 - "$drift_dir" <<'PY'
import json, sys
path = sys.argv[1] + "/repos_ownerr_repo_environments_crates-io_deployment-branch-policies.json"
data = json.load(open(path))
data["branch_policies"][0]["type"] = "branch"
json.dump(data, open(path, "w"))
PY
expect_fail "policy of the wrong ref kind fails" "crates-io"

drift_dir="${tmp}/extra-policy"
cp -r "$fixture_dir" "$drift_dir"
python3 - "$drift_dir" <<'PY'
import json, sys
path = sys.argv[1] + "/repos_ownerr_repo_environments_crates-io_deployment-branch-policies.json"
data = json.load(open(path))
data["branch_policies"].append({"name": "develop", "type": "branch"})
data["total_count"] = len(data["branch_policies"])
json.dump(data, open(path, "w"))
PY
expect_fail "unexpected extra policy on crates-io fails" "crates-io"

drift_dir="${tmp}/realign-custom-mode"
cp -r "$fixture_dir" "$drift_dir"
python3 - "$drift_dir" <<'PY'
import json, sys
path = sys.argv[1] + "/repos_ownerr_repo_environments_fuzz-lock-realign.json"
data = json.load(open(path))
data["deployment_branch_policy"] = {"protected_branches": False, "custom_branch_policies": True}
json.dump(data, open(path, "w"))
PY
expect_fail "fuzz-lock-realign flipped off protected-branches-only fails" "fuzz-lock-realign"

# The exit-2 contract: an API failure must be distinguishable from drift
# (exit 1), because a required check that reports outages as policy drift
# misdirects triage. Both failure shapes get a case so neither can regress
# back to a traceback-driven exit 1.
expect_api_failure() {
    local label="$1"

    local status=0
    RIMAP_GH_BIN="${tmp}/gh" RIMAP_RETRY_SLEEP=0 FIXTURE_DIR="$drift_dir" \
        bash "$script" ownerr/repo >"${tmp}/out.txt" 2>&1 || status=$?
    if [[ "$status" -ne 2 ]]; then
        failures=$((failures + 1))
        printf 'FAIL %s: expected exit 2, got %d\n' "$label" "$status"
        cat "${tmp}/out.txt"
    elif ! grep -q "not drift" "${tmp}/out.txt"; then
        failures=$((failures + 1))
        printf 'FAIL %s: output does not say it is an API failure\n' "$label"
        cat "${tmp}/out.txt"
    fi
}

drift_dir="${tmp}/api-error"
cp -r "$fixture_dir" "$drift_dir"
rm "${drift_dir}/repos_ownerr_repo_environments.json"
expect_api_failure "unreachable listing endpoint fails as API error, not drift"

drift_dir="${tmp}/wrong-shape-json"
cp -r "$fixture_dir" "$drift_dir"
printf '{}\n' >"${drift_dir}/repos_ownerr_repo_environments.json"
expect_api_failure "wrong-shape JSON listing fails as API error, not drift"

drift_dir="${tmp}/non-json-body"
cp -r "$fixture_dir" "$drift_dir"
printf '<html>maintenancing</html>\n' \
    >"${drift_dir}/repos_ownerr_repo_environments.json"
expect_api_failure "non-JSON HTTP-200 body fails as API error, not drift"

if [[ "$failures" -ne 0 ]]; then
    printf '%d test(s) failed\n' "$failures"
    exit 1
fi
echo "all check-env-deployment-policies tests passed"
