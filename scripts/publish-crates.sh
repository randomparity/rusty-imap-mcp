#!/usr/bin/env bash
# Publish the 8 rimap-* workspace crates to crates.io in dependency order.
#
# Ordered (topological), idempotent (skips versions already on crates.io so a
# mid-run failure resumes on re-run), and rate-limit-aware (crates.io throttles
# NEW crate names to a burst of 5 then 1 every 10 min — an 8-new-crate first
# publish 429s at crate #6, so we parse the "try again after <RFC2822>" and
# sleep). Publishing new *versions* of existing crates is far less limited
# (burst 30), so steady-state releases fly through. See issue #544 / ADR-0004.
#
# Usage:
#   scripts/publish-crates.sh            # real publish (needs CARGO_REGISTRY_TOKEN)
#   scripts/publish-crates.sh --dry-run  # validate packaging only, no upload
#
# The first 8-new-name publish exceeds the burst limit and is best run locally
# (free sleeps) — see RELEASING.md. Run from the repo root.
set -euo pipefail

# Topological publish order (rimap-core has no intra-workspace deps; rimap-server
# depends on all seven). See ADR-0004.
CRATES=(
    rimap-core
    rimap-config
    rimap-audit
    rimap-content
    rimap-authz
    rimap-imap
    rimap-smtp
    rimap-server
)

USER_AGENT="rusty-imap-mcp-publish (+https://github.com/randomparity/rusty-imap-mcp)"
# Per-429 wait cap; a required wait above this exits for a later resume rather
# than idling. Sized to cover one ~10-min new-crate refill with margin.
MAX_RATE_WAIT="${MAX_RATE_WAIT:-900}"
# Fallback sleep when a 429's retry time cannot be parsed (~10 min + margin).
FALLBACK_SLEEP="${FALLBACK_SLEEP:-660}"
# How long to poll the sparse index for a just-published version before moving on.
INDEX_TIMEOUT="${INDEX_TIMEOUT:-120}"

# Read the workspace version (uniform across members).
workspace_version() {
    cargo metadata --no-deps --format-version 1 |
        python3 -c 'import json,sys; d=json.load(sys.stdin); print(next(p["version"] for p in d["packages"] if p["name"]=="rimap-core"))'
}

# Guard: in real mode refuse a -dev version (defense in depth beside verify-tag);
# in dry-run mode always allow (main lives at X.Y.Z-dev). Returns non-zero to block.
version_ok_to_publish() {
    local version="$1" mode="$2"
    if [ "$mode" = "dry-run" ]; then
        return 0
    fi
    case "$version" in
    *-dev*)
        echo "error: refusing to publish a -dev version ($version); run at a clean release version" >&2
        return 1
        ;;
    *)
        return 0
        ;;
    esac
}

# Extract crates.io's "try again after <RFC2822>" from a 429 message and return
# seconds to sleep (>=0). Returns -1 when no timestamp can be parsed so the
# caller falls back to a bounded fixed sleep instead of guessing. Pure function.
parse_retry_after() {
    local text="$1" ts
    ts=$(printf '%s' "$text" |
        grep -oE 'after [A-Za-z]{3}, [0-9]{2} [A-Za-z]{3} [0-9]{4} [0-9:]{8} GMT' |
        head -1 || true)
    ts="${ts#after }"
    if [ -z "$ts" ]; then
        echo "-1"
        return 0
    fi
    RIMAP_RETRY_TS="$ts" python3 -c '
import email.utils, os, time
dt = email.utils.parsedate_to_datetime(os.environ["RIMAP_RETRY_TS"])
print(max(0, int(dt.timestamp() - time.time())))
' 2>/dev/null || echo "-1"
}

# True (0) when <crate>@<version> is already on crates.io (web API).
already_published() {
    local crate="$1" version="$2" code
    code=$(curl -sS -o /dev/null -w '%{http_code}' -A "$USER_AGENT" \
        "https://crates.io/api/v1/crates/${crate}/${version}" || echo "000")
    [ "$code" = "200" ]
}

# True (0) when <crate>@<version> is visible in the sparse index (the surface a
# dependent's verify build resolves against). All rimap-* names are 4+ chars.
index_has_version() {
    local crate="$1" version="$2" prefix
    prefix="${crate:0:2}/${crate:2:2}"
    curl -sS -A "$USER_AGENT" "https://index.crates.io/${prefix}/${crate}" 2>/dev/null |
        grep -q "\"vers\":\"${version}\""
}

# Publish one crate, retrying on a new-crate 429. Skips if crates.io reports the
# version already exists (race with our own check). Exits on any other failure.
publish_one() {
    local crate="$1" version="$2" out rc wait
    while true; do
        if out=$(cargo publish -p "$crate" --locked 2>&1); then
            printf '%s\n' "$out"
            echo "published: ${crate}@${version}"
            return 0
        fi
        rc=$?
        printf '%s\n' "$out" >&2
        if printf '%s' "$out" | grep -qiE 'already (exists|uploaded)'; then
            echo "skip: ${crate}@${version} already published"
            return 0
        fi
        if printf '%s' "$out" | grep -qiE '429|too many'; then
            wait=$(parse_retry_after "$out")
            if [ "$wait" -lt 0 ]; then
                wait="$FALLBACK_SLEEP"
                echo "rate limited: retry time unparsed, falling back to ${wait}s" >&2
            fi
            if [ "$wait" -gt "$MAX_RATE_WAIT" ]; then
                echo "error: required wait ${wait}s exceeds MAX_RATE_WAIT ${MAX_RATE_WAIT}s;" >&2
                echo "       re-run later to resume (already-published crates are skipped)" >&2
                exit 75
            fi
            echo "rate limited: sleeping $((wait + 30))s then retrying ${crate} ..." >&2
            sleep "$((wait + 30))"
            continue
        fi
        echo "error: publishing ${crate} failed (rc=${rc}); fix and re-run to resume" >&2
        exit "$rc"
    done
}

# Block until <crate>@<version> is resolvable from the sparse index, so the next
# dependent's verify build can find it. cargo's own publish-wait only warns on
# timeout, so this is the authoritative guard.
wait_for_index() {
    local crate="$1" version="$2" waited=0
    while [ "$waited" -lt "$INDEX_TIMEOUT" ]; do
        if index_has_version "$crate" "$version"; then
            return 0
        fi
        sleep 5
        waited=$((waited + 5))
    done
    echo "warning: ${crate}@${version} not visible in the sparse index after ${INDEX_TIMEOUT}s; proceeding" >&2
}

main() {
    local mode="real"
    if [ "${1:-}" = "--dry-run" ]; then
        mode="dry-run"
    fi

    local version
    version=$(workspace_version)

    if ! version_ok_to_publish "$version" "$mode"; then
        exit 1
    fi

    if [ "$mode" = "dry-run" ]; then
        echo "dry-run: packaging all ${#CRATES[@]} crates (version ${version}) ..."
        # A single --workspace invocation resolves unpublished siblings locally;
        # a per-crate --no-verify would fail sibling resolution against the
        # registry. --allow-dirty lets this run on a working branch. See #544.
        cargo publish --dry-run --no-verify --locked --allow-dirty --workspace
        echo "dry-run: all crates packaged"
        return 0
    fi

    echo "publishing ${#CRATES[@]} crates at version ${version} in dependency order"
    local crate
    for crate in "${CRATES[@]}"; do
        if already_published "$crate" "$version"; then
            echo "skip: ${crate}@${version} already on crates.io"
            continue
        fi
        publish_one "$crate" "$version"
        wait_for_index "$crate" "$version"
    done
    echo "done: all ${#CRATES[@]} crates published at ${version}"
}

# Only run main when executed directly, so the test file can source the
# functions without publishing.
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
