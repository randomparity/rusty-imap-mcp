#!/usr/bin/env bash
# Remove stale rimap-it-* pods/volumes/networks left by SIGKILL'd integration
# test runs. Operates below compose to avoid the lock-exhaustion cascade where
# compose-down itself fails because podman has no free locks.
#
# Runtime selection mirrors the Rust test harnesses' select_runtime()
# (crates/rimap-server/tests/support/*/harness.rs, issue #674 / PR #688): the
# first of docker, podman whose daemon actually answers `<tool> info` wins, not
# just the first binary on PATH. Before #689 this recipe selected on binary
# presence alone, so a host with Docker Desktop installed-but-stopped and a
# working podman pruned nothing while the test suite ran under podman — and
# every command here was `|| true`, so the mismatch was silent.
#
# An explicit RIMAP_CONTAINER_TOOL is honoured verbatim, exactly as the
# harnesses do: only that runtime is probed, with no fallback, so a
# deliberately unusable override fails on its own terms instead of quietly
# running elsewhere. A RIMAP_CONTAINER_TOOL naming neither docker nor podman
# is not treated as an override by the harnesses either (they fall through to
# autodetect) — this script does the same, so the two never disagree about
# which runtime a given host lands on, but says so on stdout, since (unlike
# the harnesses) it is free to log.
#
# Pruning stays opportunistic — this must never fail a developer's `just test`
# run over a missing or unreachable container runtime. But opportunistic no
# longer means silent: every path reports which runtime it selected (or why
# none was usable) and how many resources it removed, so "nothing to clean"
# and "probed the wrong runtime" read differently.
#
# Arch exemption (#811 / ADR-0023): pruning never pulls or runs the fixture
# image — it only removes stale rimap-it-* resources — so the fixture-image
# architecture check the Rust harnesses run does not apply here. The runtime
# *selection* contract above is still mirrored exactly.
#
# Usage: scripts/prune-containers.sh
set -euo pipefail

# Runtimes tried, in order, when no override applies. Must match
# AUTODETECT_ORDER in the Rust harnesses.
AUTODETECT_ORDER=(docker podman)

# Probe one runtime: an absent binary is "no-binary", otherwise `<tool> info`
# decides "ready" vs "daemon-down".
probe_tool() {
    local tool="$1"
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "no-binary"
        return
    fi
    if "$tool" info >/dev/null 2>&1; then
        echo "ready"
    else
        echo "daemon-down"
    fi
}

# Pick the runtime to use given a validated override ("docker", "podman", or
# empty for autodetect). Prints "<tool> <verdict>" on stdout, verdict being
# ready / no-binary / daemon-down.
select_runtime() {
    local override="${1:-}"
    if [ -n "$override" ]; then
        echo "$override $(probe_tool "$override")"
        return
    fi
    local tool verdict rank fallback_tool="" fallback_verdict="" fallback_rank=-1
    for tool in "${AUTODETECT_ORDER[@]}"; do
        verdict="$(probe_tool "$tool")"
        if [ "$verdict" = "ready" ]; then
            echo "$tool ready"
            return
        fi
        # daemon-down outranks no-binary as the reported fallback: "podman is
        # installed but its daemon is unreachable" tells an operator what to
        # start, where "docker is not installed" does not. Strictly-greater
        # keeps the first-found tool on a tie, matching failure_rank() /
        # is_none_or() in the Rust harnesses.
        [ "$verdict" = "daemon-down" ] && rank=1 || rank=0
        if [ "$rank" -gt "$fallback_rank" ]; then
            fallback_tool="$tool"
            fallback_verdict="$verdict"
            fallback_rank="$rank"
        fi
    done
    echo "$fallback_tool $fallback_verdict"
}

# Prune orphaned rimap-it-* volumes for $tool. Echoes the count removed.
prune_volumes() {
    local tool="$1" vol removed=0
    while IFS= read -r vol; do
        [ -n "$vol" ] || continue
        if "$tool" volume rm -f "$vol" 2>/dev/null; then
            removed=$((removed + 1))
        fi
    done < <("$tool" volume ls --format '{{.Name}}' 2>/dev/null | grep '^rimap-it-' || true)
    echo "$removed"
}

# Remove stale podman pods (podman-only concept: docker has no pods) whose
# names start with rimap-it- and were created more than 30min ago. Echoes the
# count removed.
prune_pods() {
    local cutoff="$1" pod created ts removed=0
    while IFS= read -r pod; do
        [ -n "$pod" ] || continue
        created=$(podman pod inspect "$pod" --format '{{.Created}}' 2>/dev/null) || continue
        ts=$(date -d "$created" +%s 2>/dev/null) || continue
        if [ "$ts" -lt "$cutoff" ]; then
            if podman pod rm -f "$pod" 2>/dev/null; then
                removed=$((removed + 1))
            fi
        fi
    done < <(podman pod ls --format '{{.Name}}' --noheading 2>/dev/null | grep '^rimap-it-' || true)
    echo "$removed"
}

main() {
    local override="${RIMAP_CONTAINER_TOOL:-}"
    case "$override" in
    "" | docker | podman) ;;
    *)
        echo "prune-containers: RIMAP_CONTAINER_TOOL=$override is not docker or podman; autodetecting instead"
        override=""
        ;;
    esac

    local selection tool verdict
    selection="$(select_runtime "$override")"
    tool="${selection%% *}"
    verdict="${selection#* }"

    case "$verdict" in
    ready) ;;
    no-binary)
        echo "prune-containers: $tool is not installed; skipping"
        exit 0
        ;;
    daemon-down)
        echo "prune-containers: $tool is installed but its daemon is unreachable; skipping"
        exit 0
        ;;
    esac

    echo "prune-containers: using $tool"

    local cutoff pods_removed=0 vols_removed=0
    cutoff=$(($(date +%s) - 1800))

    if [ "$tool" = "podman" ]; then
        pods_removed="$(prune_pods "$cutoff")"
    fi
    vols_removed="$(prune_volumes "$tool")"

    # Prune orphaned docker/podman networks. Not counted individually: `network
    # prune` reports no count of its own, and it is the least common case in
    # practice (compose down normally reclaims networks on a clean exit).
    "$tool" network prune -f >/dev/null 2>&1 || true

    if [ "$pods_removed" -eq 0 ] && [ "$vols_removed" -eq 0 ]; then
        echo "prune-containers: nothing to clean"
    else
        echo "prune-containers: removed ${pods_removed} pod(s), ${vols_removed} volume(s)"
    fi
}

main
