#!/usr/bin/env bash
# Unit tests for check-fuzz-lock-parity.sh (issue #608). Most cases drive the
# script against synthetic lockfiles in a temp dir via its explicit-path form,
# touching no cargo, network, or repo state.
#
# Two cases are deliberately not hermetic, and neither writes anything:
#   - the last block runs the script in discovery mode against the real repo
#     (read-only) to prove discovery is anchored to the repo root;
#   - the realign-failure case invokes the real `cargo`, in a temp directory
#     with no Cargo.toml so that it fails immediately without network access.
#
# Run: `bash scripts/check-fuzz-lock-parity.test.sh` (or `just
# test-fuzz-lock-parity`).
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="${here}/check-fuzz-lock-parity.sh"

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

failures=0

# Write a lockfile from `name@version` specs, in the canonical shape cargo
# emits — including the `dependencies = [...]` array, whose entries look like
# package names and must not be mistaken for one.
write_lock() {
    local path="$1"
    shift
    printf 'version = 4\n\n' >"$path"
    local spec
    for spec in "$@"; do
        {
            printf '[[package]]\n'
            printf 'name = "%s"\n' "${spec%%@*}"
            printf 'version = "%s"\n' "${spec##*@}"
            printf 'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
            printf 'dependencies = [\n "some-other-crate",\n]\n\n'
        } >>"$path"
    done
}

# A fuzz lockfile always resolves libfuzzer-sys, and the checker now requires
# it so that a verbatim copy of the workspace lockfile cannot pass. Add it
# unless a case is deliberately exercising its absence.
write_fuzz_lock() {
    local path="$1"
    shift
    write_lock "$path" "$@" "libfuzzer-sys@0.4.13"
}

expect_parity() {
    local desc="$1"
    shift
    local out
    if out="$("$script" "$@" 2>&1)"; then
        echo "ok: ${desc}"
    else
        echo "FAIL: ${desc} — expected parity, got:" >&2
        echo "${out}" >&2
        failures=$((failures + 1))
    fi
}

# Assert the check fails AND that its output contains `needle` — the acceptance
# criterion is that failure output names the drifted crate and both versions,
# so an unexplained non-zero exit is not good enough.
expect_drift() {
    local desc="$1" needle="$2"
    shift 2
    local out
    if out="$("$script" "$@" 2>&1)"; then
        echo "FAIL: ${desc} — expected drift to fail the check, but it passed" >&2
        failures=$((failures + 1))
    elif [ "${out#*"${needle}"}" != "${out}" ]; then
        echo "ok: ${desc}"
    else
        echo "FAIL: ${desc} — output did not contain [${needle}]:" >&2
        echo "${out}" >&2
        failures=$((failures + 1))
    fi
}

ws="${tmp}/Cargo.lock"
fz="${tmp}/fuzz/Cargo.lock"
mkdir -p "${tmp}/fuzz"

# --- parity holds -----------------------------------------------------------

write_lock "$ws" "rmcp@2.2.0" "syn@2.0.117" "serde@1.0.0"
write_fuzz_lock "$fz" "rmcp@2.2.0" "syn@2.0.117" "serde@1.0.0"
expect_parity "identical lockfiles are in parity" "$ws" "$fz"

# The fuzz crate pulls libfuzzer-sys and its deps, which the workspace never
# resolves. Names absent from the workspace are out of scope, not drift.
write_fuzz_lock "$fz" "rmcp@2.2.0" "syn@2.0.117" "serde@1.0.0" "arbitrary@1.4.2"
expect_parity "fuzz-only packages are ignored" "$ws" "$fz"

# The regression this check must not have: the fuzz graph is a subgraph, so it
# legitimately resolves fewer versions of a multi-version package. Set equality
# would fail here; containment passes.
write_lock "$ws" "base64@0.13.1" "base64@0.22.1" "base64@0.23.0" "hashbrown@0.15.5" "hashbrown@0.17.0"
write_fuzz_lock "$fz" "base64@0.13.1" "base64@0.22.1" "hashbrown@0.17.0"
expect_parity "a subset of a multi-version package is not drift" "$ws" "$fz"

# --- drift is caught, in both directions ------------------------------------

write_lock "$ws" "rmcp@2.2.0"
write_fuzz_lock "$fz" "rmcp@2.1.0"
expect_drift "fuzz lagging the workspace is drift" \
    "rmcp: ${fz} has 2.1.0, ${ws} has 2.2.0" "$ws" "$fz"

write_lock "$ws" "bitflags@2.11.1"
write_fuzz_lock "$fz" "bitflags@2.13.0"
expect_drift "fuzz running ahead of the workspace is drift" \
    "bitflags: ${fz} has 2.13.0, ${ws} has 2.11.1" "$ws" "$fz"

# No shared compatibility bucket: there is no same-major counterpart to name,
# so the message falls back to every version the workspace holds.
write_lock "$ws" "ulid@3.0.0"
write_fuzz_lock "$fz" "ulid@1.2.1"
expect_drift "a whole-major gap is drift and still names both versions" \
    "ulid: ${fz} has 1.2.1, ${ws} has 3.0.0" "$ws" "$fz"

# Drift inside one bucket of a multi-version package must be reported against
# that bucket's counterpart, not against the unrelated 1.x line.
write_lock "$ws" "thiserror@1.0.69" "thiserror@2.0.19"
write_fuzz_lock "$fz" "thiserror@1.0.69" "thiserror@2.0.18"
expect_drift "drift is reported against the same-major workspace version" \
    "thiserror: ${fz} has 2.0.18, ${ws} has 2.0.19" "$ws" "$fz"

# Build metadata is part of the version string but not of the bucket.
write_lock "$ws" "toml@1.1.3+spec-1.1.0"
write_fuzz_lock "$fz" "toml@1.1.2+spec-1.1.0"
expect_drift "versions carrying build metadata compare correctly" \
    "toml: ${fz} has 1.1.2+spec-1.1.0, ${ws} has 1.1.3+spec-1.1.0" "$ws" "$fz"

# --- a verbatim workspace copy must not pass --------------------------------

# The wreckage a half-finished realign leaves behind. Containment is trivially
# satisfied by an identical version set, so without the fuzz-only-package
# requirement the checker would bless a fuzz lockfile that is really just a
# copy of the workspace one.
write_lock "$ws" "rmcp@2.2.0" "syn@2.0.117" "serde@1.0.0"
cp "$ws" "$fz"
expect_drift "a verbatim copy of the workspace lockfile is rejected" \
    "does not look like a fuzz workspace lockfile" "$ws" "$fz"

# --- malformed input fails loudly rather than passing vacuously -------------

write_lock "$ws" "rmcp@2.2.0"
: >"$fz"
expect_drift "an empty lockfile is a parse error, not silent parity" \
    "no [[package]] entries found" "$ws" "$fz"

write_fuzz_lock "$fz" "rmcp@2.2.0"
expect_drift "a missing lockfile fails with an ::error:: line, not a traceback" \
    "::error::cannot read ${tmp}/fuzz/absent.lock: No such file" \
    "$ws" "${tmp}/fuzz/absent.lock"

# A block the parser cannot read would be dropped silently, letting the gate
# pass on a lockfile it only partly understood.
printf 'version = 4\n\n[[package]]\nname = "rmcp"\nversion = "2.2.0"\n\n[[package]]\nname = "no-version-field"\n\n' >"$fz"
expect_drift "a [[package]] block the parser cannot read is an error" \
    "read 1 of 2 [[package]] blocks" "$ws" "$fz"

# A workspace-lock argument with no fuzz lockfiles must not report success.
expect_drift "no fuzz lockfiles to compare is an error" \
    "no fuzz lockfiles to check" "$ws"

# --- --fix must not destroy the lockfile it fails to rebuild ----------------

# realign() has to copy the workspace lockfile to the fuzz lockfile's real path
# before cargo can resolve against it, so a cargo failure would otherwise leave
# the fuzz lockfile overwritten — wreckage that used to pass the check. ${tmp}
# has no Cargo.toml in it or any parent, so cargo fails at once without network.
write_lock "$ws" "rmcp@2.2.0" "syn@2.0.117"
write_fuzz_lock "$fz" "rmcp@2.1.0"
before="$(cat "$fz")"
fix_out="$("$script" --fix "$ws" "$fz" 2>&1)" && fix_rc=0 || fix_rc=$?

if [ "$fix_rc" -eq 0 ]; then
    echo "FAIL: --fix reported success despite cargo failing" >&2
    failures=$((failures + 1))
else
    echo "ok: --fix fails when cargo cannot resolve the fuzz workspace"
fi

if [ "$(cat "$fz")" = "$before" ]; then
    echo "ok: a failed --fix leaves the original fuzz lockfile intact"
else
    echo "FAIL: a failed --fix destroyed the fuzz lockfile" >&2
    echo "${fix_out}" >&2
    failures=$((failures + 1))
fi

if [ "${fix_out#*has been restored}" != "${fix_out}" ]; then
    echo "ok: a failed --fix says the lockfile was restored"
else
    echo "FAIL: a failed --fix did not report the restore:" >&2
    echo "${fix_out}" >&2
    failures=$((failures + 1))
fi

# --- discovery is anchored to the repo root, not the caller's cwd -----------

# `git ls-files` only lists files beneath the working directory, so running
# from a subdirectory must not silently find nothing to check.
discovery_out="$(cd "${here}" && "$script" 2>&1)" || true
if [ "${discovery_out#*no fuzz lockfiles to check}" != "${discovery_out}" ]; then
    echo "FAIL: discovery from a subdirectory found no lockfiles:" >&2
    echo "${discovery_out}" >&2
    failures=$((failures + 1))
else
    echo "ok: discovery works from a subdirectory"
fi

# --- result -----------------------------------------------------------------

if [ "$failures" -ne 0 ]; then
    echo "${failures} check-fuzz-lock-parity test(s) failed" >&2
    exit 1
fi
echo "all check-fuzz-lock-parity tests passed"
