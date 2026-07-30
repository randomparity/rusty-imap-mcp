#!/usr/bin/env bash
# Fail when a tracked fuzz workspace's Cargo.lock resolves a shared dependency
# to a version the root workspace's Cargo.lock does not hold (issue #608).
#
# Why this exists: `crates/rimap-server/fuzz` declares its own `[workspace]`
# (the root manifest's `exclude = ["fuzz"]` is a bare path that only matches
# `./fuzz/`, not this nested location), so the root `/` Dependabot cargo entry
# never resolves it. Nothing — not Dependabot, not CI — kept its lockfile in
# step with the workspace, and the two silently diverged; that drift is what
# produced #512. The fuzz target instruments the code that actually ships, so
# once the two lockfiles resolve different parser-stack versions the
# differential fuzzer is no longer differential against production.
#
# The invariant is *parity*, not freshness. A Dependabot entry for the fuzz
# directory would keep it moving, but on its own schedule — pushing the fuzz
# lockfile ahead of the workspace, which is the same drift in the opposite
# direction. See docs/ADR/0011-fuzz-lockfile-workspace-parity.md.
#
# What is compared: the fuzz dependency graph is a *subgraph* of the
# workspace's, so it legitimately resolves fewer versions of a package the
# workspace holds several times (base64, hashbrown, thiserror, windows-sys...).
# Set equality would false-positive on every one of those. The invariant that
# actually holds is containment: every version a fuzz lockfile resolves for a
# package name the workspace also has must appear in the workspace lockfile.
# That catches drift in both directions — a stale fuzz pin is absent from the
# workspace, and so is one that has run ahead.
#
# Usage:
#   check-fuzz-lock-parity.sh [--fix] [WORKSPACE_LOCK FUZZ_LOCK...]
#
# With no lockfile arguments the tracked set is discovered from git, so a fuzz
# workspace whose lockfile gets committed later is covered without editing this
# script. Explicit paths exist for the companion test. `--fix` realigns each
# fuzz lockfile from the workspace lockfile and re-verifies.
#
# Wired into `just check-fuzz-lock-parity` (part of `just ci`) and the
# `publish-checks` CI job. Tested by scripts/check-fuzz-lock-parity.test.sh.
set -euo pipefail

# All logic lives in python3 (present on CI runners and used the same way by
# scripts/check-publishable-metadata.sh). Cargo.lock is TOML, but `tomllib` is
# Python 3.11+ and this gate has to run under `just ci` on developer machines
# with the older system python3, so the lockfile is parsed directly — cargo
# writes `[[package]]` blocks in a fixed, canonical shape.
python3 - "$@" <<'PY'
import collections
import os
import shutil
import subprocess
import sys

WORKSPACE_LOCK = "Cargo.lock"

# Tracked lockfiles under any directory named `fuzz`. The root `Cargo.lock`
# does not match (it is the comparison baseline), and neither does
# `html-oracle/Cargo.lock` — html-oracle is an independent tool workspace with
# its own Dependabot entry and is meant to float free of the workspace pins.
FUZZ_LOCK_GLOB = "*fuzz/Cargo.lock"


def compat_key(version):
    """Cargo's semver-compatibility bucket for a version.

    Cargo permits at most one version per bucket within a lockfile, so the
    bucket identifies which workspace version a drifted fuzz version is the
    counterpart of. Build metadata (`1.1.3+spec-1.1.0`) and pre-release tags
    are not part of the bucket.
    """
    core = version.split("+", 1)[0].split("-", 1)[0]
    parts = []
    for field in core.split(".")[:3]:
        parts.append(int(field) if field.isdigit() else 0)
    while len(parts) < 3:
        parts.append(0)
    major, minor, patch = parts
    if major:
        return str(major)
    if minor:
        return "0.{}".format(minor)
    return "0.0.{}".format(patch)


def load_lock(path):
    """Map package name -> set of locked versions."""
    packages = collections.defaultdict(set)
    name = None
    in_package = False
    with open(path, encoding="utf-8") as handle:
        for raw in handle:
            line = raw.strip()
            if line == "[[package]]":
                in_package, name = True, None
            elif line.startswith("["):
                # Any other table ends the block (e.g. `[[patch.unused]]`).
                in_package, name = False, None
            elif not in_package or not line.endswith('"'):
                continue
            elif line.startswith('name = "'):
                name = line[len('name = "') : -1]
            elif line.startswith('version = "') and name is not None:
                packages[name].add(line[len('version = "') : -1])
                name = None
    if not packages:
        sys.exit(
            "::error::cannot parse {}: no [[package]] entries found — the "
            "lockfile is empty, missing, or in an unexpected format".format(path)
        )
    return packages


def discover_fuzz_locks():
    result = subprocess.run(
        ["git", "ls-files", FUZZ_LOCK_GLOB],
        stdout=subprocess.PIPE,
        check=True,
        universal_newlines=True,
    )
    return [line for line in result.stdout.splitlines() if line]


def realign(workspace_lock, fuzz_lock):
    """Seed a fuzz lockfile from the workspace lockfile and let cargo settle it.

    Copying the workspace lockfile in preserves every shared pin verbatim;
    `cargo metadata` then prunes the packages the fuzz graph cannot reach and
    adds the fuzz-only ones (libfuzzer-sys and its deps). Regenerating from
    scratch instead would re-resolve everything to latest and reintroduce the
    drift this gate exists to prevent.
    """
    # flush: cargo writes straight to the inherited fd, so an unflushed
    # buffer would print this line after cargo's own progress output.
    print("realigning {} from {}".format(fuzz_lock, workspace_lock), flush=True)
    shutil.copyfile(workspace_lock, fuzz_lock)
    subprocess.run(
        ["cargo", "metadata", "--format-version", "1"],
        cwd=os.path.dirname(fuzz_lock) or ".",
        stdout=subprocess.DEVNULL,
        check=True,
    )


args = sys.argv[1:]
fix = bool(args) and args[0] == "--fix"
if fix:
    args = args[1:]

if args:
    workspace_lock, fuzz_locks = args[0], args[1:]
else:
    workspace_lock, fuzz_locks = WORKSPACE_LOCK, discover_fuzz_locks()

if not fuzz_locks:
    sys.exit(
        "::error::no fuzz lockfiles to check — expected at least "
        "crates/rimap-server/fuzz/Cargo.lock to be tracked and to match "
        "{!r}".format(FUZZ_LOCK_GLOB)
    )

if fix:
    for fuzz_lock in fuzz_locks:
        realign(workspace_lock, fuzz_lock)

workspace = load_lock(workspace_lock)
errors = []

for fuzz_lock in fuzz_locks:
    fuzz = load_lock(fuzz_lock)
    for name in sorted(set(fuzz) & set(workspace)):
        for version in sorted(fuzz[name] - workspace[name]):
            bucket = compat_key(version)
            counterpart = sorted(
                v for v in workspace[name] if compat_key(v) == bucket
            )
            # No same-bucket counterpart means the fuzz lockfile is a whole
            # semver major behind or ahead; show every workspace version so the
            # reader sees what it should have resolved to.
            expected = ", ".join(counterpart or sorted(workspace[name]))
            errors.append(
                "{}: {} has {}, {} has {}".format(
                    name, fuzz_lock, version, workspace_lock, expected
                )
            )

if errors:
    print(
        "::error::fuzz lockfile parity check failed: {} drifted "
        "package(s)".format(len(errors)),
        file=sys.stderr,
    )
    for err in errors:
        print("  - {}".format(err), file=sys.stderr)
    print(
        "\nEvery version a fuzz lockfile resolves must also appear in "
        "{}.\nRealign and rebuild the fuzz targets with:\n"
        "  just realign-fuzz-locks".format(workspace_lock),
        file=sys.stderr,
    )
    sys.exit(1)

print(
    "ok: {} fuzz lockfile(s) in parity with {}".format(
        len(fuzz_locks), workspace_lock
    )
)
PY
