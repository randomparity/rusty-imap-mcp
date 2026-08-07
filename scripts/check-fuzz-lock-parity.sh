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
# Containment alone is not sufficient, though: a fuzz lockfile that is a
# verbatim copy of the workspace one satisfies it trivially, which is exactly
# the wreckage a half-finished realign leaves behind. So each fuzz lockfile
# must also still contain the fuzz-only packages that prove it is one.
#
# Usage:
#   check-fuzz-lock-parity.sh [--fix | --list] [WORKSPACE_LOCK FUZZ_LOCK...]
#
# With no lockfile arguments the tracked set is discovered from git, so a fuzz
# workspace whose lockfile gets committed later is covered without editing this
# script. Explicit paths exist for the companion test. `--fix` realigns each
# fuzz lockfile from the workspace lockfile and re-verifies. `--list` reports
# which lockfiles the selection reached and does not rule on parity, so a
# caller can check glob coverage without its answer depending on whether the
# tree currently drifts (issue #736).
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

# Tracked lockfiles in a directory named exactly `fuzz`, at the repo root or
# nested. Two anchored pathspecs rather than one `*fuzz/Cargo.lock`, which
# would also match a directory merely *ending* in "fuzz" (`notfuzz/`). The
# root `Cargo.lock` does not match (it is the comparison baseline), and
# neither does `html-oracle/Cargo.lock` — html-oracle is an independent tool
# workspace with its own Dependabot entry, meant to float free of the
# workspace pins.
FUZZ_LOCK_GLOBS = ["fuzz/Cargo.lock", "*/fuzz/Cargo.lock"]

# Every cargo-fuzz workspace resolves libfuzzer-sys. Requiring it is what stops
# the check blessing a fuzz lockfile that is really a verbatim copy of the
# workspace lockfile: containment is trivially satisfied by an identical set,
# so without this the corrupt state would pass.
REQUIRED_FUZZ_PACKAGES = ["libfuzzer-sys"]


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
    blocks = 0
    parsed = 0
    try:
        handle = open(path, encoding="utf-8")
    except OSError as exc:
        sys.exit("::error::cannot read {}: {}".format(path, exc.strerror))
    with handle:
        for raw in handle:
            line = raw.strip()
            if line == "[[package]]":
                in_package, name = True, None
                blocks += 1
            elif line.startswith("["):
                # Any other table ends the block (e.g. `[[patch.unused]]`,
                # whose entries are not resolved dependencies).
                in_package, name = False, None
            elif not in_package or not line.endswith('"'):
                # Skips `dependencies = [`, its entries, and the top-of-file
                # `version = 4`, none of which are a package's own fields.
                continue
            elif line.startswith('name = "'):
                name = line[len('name = "') : -1]
            elif line.startswith('version = "') and name is not None:
                packages[name].add(line[len('version = "') : -1])
                name = None
                parsed += 1
    if not blocks:
        sys.exit(
            "::error::cannot parse {}: no [[package]] entries found — the "
            "lockfile is empty, missing, or in an unexpected format".format(path)
        )
    # A block whose name/version did not parse would be silently dropped, and
    # a gate that under-reads its input passes vacuously. Fail instead.
    if parsed != blocks:
        sys.exit(
            "::error::cannot parse {}: read {} of {} [[package]] blocks — the "
            "lockfile format is not what this script expects".format(
                path, parsed, blocks
            )
        )
    return packages


def discover_fuzz_locks():
    """Tracked fuzz lockfiles, with paths relative to the repo root.

    `git ls-files` reports paths relative to the working directory and only
    lists files beneath it, so discovery is anchored to the repo root rather
    than trusting the caller's cwd. The default WORKSPACE_LOCK path is
    relative to the same root.
    """
    root = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        stdout=subprocess.PIPE,
        check=True,
        universal_newlines=True,
    ).stdout.strip()
    os.chdir(root)
    result = subprocess.run(
        ["git", "ls-files"] + FUZZ_LOCK_GLOBS,
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

    The copy has to land at the lockfile's real path for cargo to resolve
    against it, so this cannot stage the work in a temp file and move it in
    afterwards. Instead the original bytes are held and written back if cargo
    fails — otherwise a failed realign (cargo must reach the registry index to
    add the fuzz-only packages, so it cannot run offline) would leave the fuzz
    lockfile overwritten with a verbatim copy of the workspace lockfile.
    """
    # flush: cargo writes straight to the inherited fd, so an unflushed
    # buffer would print this line after cargo's own progress output.
    print("realigning {} from {}".format(fuzz_lock, workspace_lock), flush=True)
    original = None
    if os.path.exists(fuzz_lock):
        with open(fuzz_lock, "rb") as handle:
            original = handle.read()
    shutil.copyfile(workspace_lock, fuzz_lock)
    try:
        subprocess.run(
            ["cargo", "metadata", "--format-version", "1"],
            cwd=os.path.dirname(fuzz_lock) or ".",
            stdout=subprocess.DEVNULL,
            check=True,
        )
    except BaseException:
        if original is not None:
            with open(fuzz_lock, "wb") as handle:
                handle.write(original)
            print(
                "restored the original {} after a failed realign".format(
                    fuzz_lock
                ),
                file=sys.stderr,
            )
        raise


args = sys.argv[1:]
fix = False
list_only = False
while args and args[0].startswith("--"):
    flag = args.pop(0)
    if flag == "--fix":
        fix = True
    elif flag == "--list":
        list_only = True
    else:
        sys.exit(
            "::error::unknown option {!r}. Usage: check-fuzz-lock-parity.sh "
            "[--fix | --list] [WORKSPACE_LOCK FUZZ_LOCK...]".format(flag)
        )

if fix and list_only:
    sys.exit(
        "::error::--fix and --list are mutually exclusive: --list reports "
        "which lockfiles were selected and changes nothing."
    )

if args:
    workspace_lock, fuzz_locks = args[0], args[1:]
else:
    workspace_lock, fuzz_locks = WORKSPACE_LOCK, discover_fuzz_locks()

if list_only:
    # A coverage report, not a verdict. It exits 0 even when the selection is
    # empty, so a caller comparing discovery against its own expectation gets
    # an answer that the parity result cannot confound — that coupling is the
    # bug in #736. The empty case is still an error for every other mode.
    for lock in fuzz_locks:
        print(lock)
    sys.exit(0)

if not fuzz_locks:
    sys.exit(
        "::error::no fuzz lockfiles to check — expected at least "
        "crates/rimap-server/fuzz/Cargo.lock to be tracked and to match one "
        "of {!r}".format(FUZZ_LOCK_GLOBS)
    )

if fix:
    for fuzz_lock in fuzz_locks:
        try:
            realign(workspace_lock, fuzz_lock)
        except subprocess.CalledProcessError as exc:
            sys.exit(
                "::error::realigning {} failed: cargo exited {}. The original "
                "lockfile has been restored. Note cargo must reach the "
                "registry index to add the fuzz-only packages, so --fix "
                "cannot run offline.".format(fuzz_lock, exc.returncode)
            )
        except OSError as exc:
            # cargo missing entirely. Same guarantee, different cause — say so
            # rather than letting a traceback stand in for the explanation.
            sys.exit(
                "::error::realigning {} failed: could not run cargo ({}). The "
                "original lockfile has been restored.".format(
                    fuzz_lock, exc.strerror
                )
            )

workspace = load_lock(workspace_lock)
errors = []

for fuzz_lock in fuzz_locks:
    fuzz = load_lock(fuzz_lock)
    missing = [pkg for pkg in REQUIRED_FUZZ_PACKAGES if pkg not in fuzz]
    if missing:
        sys.exit(
            "::error::{} does not look like a fuzz workspace lockfile: no {} "
            "entry. A verbatim copy of the workspace lockfile would satisfy "
            "the parity check trivially, so it is rejected here. Rebuild it "
            "with `just realign-fuzz-locks` rather than copying by "
            "hand.".format(fuzz_lock, ", ".join(repr(m) for m in missing))
        )
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
