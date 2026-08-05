#!/usr/bin/env bash
# Unit tests for prune-containers.sh (issue #689). Runs the real script as a
# subprocess against fake `docker`/`podman`/`date` binaries in an isolated
# PATH — no real container runtime, no network, no repo state.
#
# The isolation is deliberate: GitHub-hosted ubuntu runners ship a real
# `docker` on PATH, so a "no-binary" case built on a merely-restricted PATH
# (e.g. /usr/bin:/bin) would still find it there and silently test the wrong
# scenario. The sandbox is built from resolved absolute paths to the handful
# of real coreutils the script needs (bash, grep), so it does not depend on
# where this host happens to keep them.
#
# Run: `bash scripts/prune-containers.test.sh` (or `just test-prune-containers`).
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="${here}/prune-containers.sh"

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

failures=0

# --- sandbox setup -----------------------------------------------------------

# The fake docker/podman below run under whatever `bash` this PATH resolves
# to (their own `#!/usr/bin/env bash` shebang), so it must not be macOS's
# system /bin/bash 3.2 — bash-4-only syntax (${var^^}) hits "bad
# substitution" there. Prefer a modern bash if one is on the tester's PATH;
# fall back to whatever `command -v bash` finds otherwise.
real_bash="$(command -v bash)"
for candidate in /opt/homebrew/bin/bash /usr/local/bin/bash; do
    if [ -x "$candidate" ]; then
        real_bash="$candidate"
        break
    fi
done
real_grep="$(command -v grep)"
real_basename="$(command -v basename)"
real_tr="$(command -v tr)"

sandbox="${tmp}/sandbox"
mkdir -p "$sandbox"
ln -s "$real_bash" "$sandbox/bash"
ln -s "$real_grep" "$sandbox/grep"
ln -s "$real_basename" "$sandbox/basename"
ln -s "$real_tr" "$sandbox/tr"

fakebin="${tmp}/fakebin"
mkdir -p "$fakebin"

# `date +%s` needs a real answer; `date -d <sentinel> +%s` is driven by the
# OLD/NEW sentinels the pod-cutoff tests below feed through fake `podman pod
# inspect` output, so cutoff arithmetic is portable across the GNU/BSD `date
# -d` divide instead of depending on it.
cat >"${fakebin}/date" <<EOF
#!/usr/bin/env bash
real_date="$(command -v date)"
if [ "\${1:-}" = "-d" ]; then
    case "\$2" in
    OLD) echo \$(( \$("\$real_date" +%s) - 7200 )) ;;
    NEW) echo "\$("\$real_date" +%s)" ;;
    *) exit 1 ;;
    esac
else
    exec "\$real_date" "\$@"
fi
EOF
chmod +x "${fakebin}/date"

# One generic runtime stub, installed as both `docker` and `podman`; it reads
# its own behavior from env vars named after its basename (DOCKER_* /
# PODMAN_*), so the same file drives both fakes. Every invocation is appended
# to <TOOL>_LOG so tests can assert a runtime was never touched (the
# explicit-override "no fallback probing" requirement).
write_runtime_stub() {
    local path="$1"
    cat >"$path" <<'EOF'
#!/usr/bin/env bash
tool="$(basename "$0")"
upper="$(printf '%s' "$tool" | tr '[:lower:]' '[:upper:]')"
log_var="${upper}_LOG"
log="${!log_var:-/dev/null}"
printf '%s\n' "$*" >>"$log"

info_var="${upper}_INFO_OK"
info_ok="${!info_var:-1}"

case "${1:-}" in
info)
    [ "$info_ok" = "1" ]
    exit $?
    ;;
volume)
    case "${2:-}" in
    ls)
        vols_var="${upper}_VOLUMES"
        vols="${!vols_var:-}"
        [ -n "$vols" ] && printf '%s\n' $vols
        exit 0
        ;;
    rm) exit 0 ;;
    esac
    ;;
network)
    exit 0
    ;;
pod)
    case "${2:-}" in
    ls)
        pods_var="${upper}_PODS"
        pods="${!pods_var:-}"
        [ -n "$pods" ] && printf '%s\n' $pods
        exit 0
        ;;
    inspect)
        safe="${3//-/_}"
        created_var="${upper}_CREATED_${safe}"
        echo "${!created_var:-NEW}"
        exit 0
        ;;
    rm) exit 0 ;;
    esac
    ;;
esac
exit 0
EOF
    chmod +x "$path"
}

install_docker() { write_runtime_stub "${fakebin}/docker"; }
install_podman() { write_runtime_stub "${fakebin}/podman"; }

# Known control vars, unset between cases so one case's config cannot leak
# into the next.
reset_env() {
    unset -v RIMAP_CONTAINER_TOOL \
        DOCKER_INFO_OK DOCKER_VOLUMES DOCKER_PODS DOCKER_LOG \
        PODMAN_INFO_OK PODMAN_VOLUMES PODMAN_PODS PODMAN_LOG \
        DOCKER_CREATED_rimap_it_old DOCKER_CREATED_rimap_it_new \
        PODMAN_CREATED_rimap_it_old PODMAN_CREATED_rimap_it_new \
        2>/dev/null || true
    rm -f "${fakebin}/docker" "${fakebin}/podman"
    docker_log="${tmp}/docker.log"
    podman_log="${tmp}/podman.log"
    rm -f "$docker_log" "$podman_log"
    export DOCKER_LOG="$docker_log" PODMAN_LOG="$podman_log"
}

run() {
    PATH="${fakebin}:${sandbox}" "$script"
}

expect_exit0() {
    local desc="$1"
    shift
    local out status=0
    out="$(run 2>&1)" || status=$?
    if [ "$status" -ne 0 ]; then
        echo "FAIL: ${desc} — exited ${status}, expected 0:" >&2
        echo "${out}" >&2
        failures=$((failures + 1))
        return
    fi
    local check
    for check in "$@"; do
        if [ "${out#*"${check}"}" = "${out}" ]; then
            echo "FAIL: ${desc} — output missing [${check}]:" >&2
            echo "${out}" >&2
            failures=$((failures + 1))
            return
        fi
    done
    echo "ok: ${desc}"
}

# --- autodetect prefers the runtime whose daemon actually answers ----------

reset_env
install_docker
install_podman
export DOCKER_INFO_OK=1 PODMAN_INFO_OK=1
export DOCKER_VOLUMES="" PODMAN_VOLUMES=""
expect_exit0 "docker and podman both ready: docker wins (autodetect order)" \
    "using docker" "nothing to clean"

reset_env
install_docker
install_podman
export DOCKER_INFO_OK=0 PODMAN_INFO_OK=1
export PODMAN_VOLUMES=""
expect_exit0 "docker installed-but-stopped, podman ready: podman wins (#689 core case)" \
    "using podman" "nothing to clean"
if grep -qv '^info$' "$docker_log" 2>/dev/null; then
    echo "FAIL: docker was probed beyond 'info' after podman was selected:" >&2
    cat "$docker_log" >&2
    failures=$((failures + 1))
else
    echo "ok: docker is only probed, never used, once podman is selected"
fi

reset_env
install_podman
export PODMAN_INFO_OK=1 PODMAN_VOLUMES=""
# docker not installed at all
expect_exit0 "docker not installed, podman ready: podman wins" \
    "using podman" "nothing to clean"

reset_env
# neither installed
expect_exit0 "no runtime installed: not a silent exit 0" \
    "not installed; skipping"

reset_env
install_docker
install_podman
export DOCKER_INFO_OK=0 PODMAN_INFO_OK=0
expect_exit0 "both installed but daemon-down: reports the more actionable reason" \
    "docker is installed but its daemon is unreachable; skipping"

# --- explicit RIMAP_CONTAINER_TOOL is honoured verbatim, no fallback -------

reset_env
install_docker
install_podman
export RIMAP_CONTAINER_TOOL=podman
export DOCKER_INFO_OK=1 PODMAN_INFO_OK=0
expect_exit0 "explicit podman override, but its daemon is down: does not fall back to ready docker" \
    "podman is installed but its daemon is unreachable; skipping"
if [ -s "$docker_log" ]; then
    echo "FAIL: docker was probed despite an explicit podman override:" >&2
    cat "$docker_log" >&2
    failures=$((failures + 1))
else
    echo "ok: an unusable explicit override never probes the other runtime"
fi

reset_env
install_docker
install_podman
export RIMAP_CONTAINER_TOOL=docker
export DOCKER_INFO_OK=1 DOCKER_VOLUMES="" PODMAN_INFO_OK=1
expect_exit0 "explicit docker override: used verbatim" "using docker"
if [ -s "$podman_log" ]; then
    echo "FAIL: podman was probed despite an explicit docker override:" >&2
    cat "$podman_log" >&2
    failures=$((failures + 1))
else
    echo "ok: explicit docker override never touches podman"
fi

# --- an unrecognized override is not silent, and still autodetects ---------

reset_env
install_docker
export RIMAP_CONTAINER_TOOL=colima
export DOCKER_INFO_OK=1 DOCKER_VOLUMES=""
expect_exit0 "unrecognized RIMAP_CONTAINER_TOOL: reported, then autodetects" \
    "RIMAP_CONTAINER_TOOL=colima is not docker or podman; autodetecting instead" \
    "using docker"

# --- messaging distinguishes "nothing found" from "wrong runtime probed" ---

reset_env
install_docker
export DOCKER_INFO_OK=1 DOCKER_VOLUMES="rimap-it-a rimap-it-b"
expect_exit0 "matching volumes are pruned and counted" \
    "using docker" "removed 0 pod(s), 2 volume(s)"

reset_env
install_docker
export DOCKER_INFO_OK=1 DOCKER_VOLUMES="unrelated-volume"
expect_exit0 "non-matching volumes are left alone and reported as nothing to clean" \
    "using docker" "nothing to clean"

# --- podman pod pruning respects the 30-minute cutoff -----------------------

reset_env
install_podman
export PODMAN_INFO_OK=1 PODMAN_VOLUMES=""
export PODMAN_PODS="rimap-it-old rimap-it-new"
export PODMAN_CREATED_rimap_it_old=OLD
export PODMAN_CREATED_rimap_it_new=NEW
expect_exit0 "only the pod older than 30min is pruned" \
    "using podman" "removed 1 pod(s), 0 volume(s)"

# --- result -----------------------------------------------------------------

if [ "$failures" -ne 0 ]; then
    echo "${failures} prune-containers test(s) failed" >&2
    exit 1
fi
echo "all prune-containers tests passed"
