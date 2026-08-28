#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
checker="$repo_root/scripts/check-nextest-leak-policy.sh"
nextest_bin="${NEXTEST_BIN:-cargo-nextest}"
tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/rimap-nextest-leak-policy.XXXXXX")"
background_pids=()
known_child_pid=""

stop_known_child() {
    [ -n "$known_child_pid" ] || return 0
    kill "$known_child_pid" 2>/dev/null || true
    for _ in $(seq 1 100); do
        kill -0 "$known_child_pid" 2>/dev/null || return 0
        sleep 0.01
    done
    echo "positive-control child $known_child_pid did not terminate" >&2
    return 1
}

cleanup() {
    local pid
    stop_known_child || true
    for pid in "${background_pids[@]-}"; do
        [ -n "$pid" ] || continue
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    rm -rf "$tmp_dir"
}
trap cleanup EXIT INT TERM

write_config() {
    local path="$1"
    local platform_line="$2"
    local default_policy='leak-timeout = { period = "5s", result = "fail" }'
    local macos_policy='leak-timeout = { period = "30s", result = "fail" }'
    [ "$#" -lt 3 ] || default_policy="$3"
    [ "$#" -lt 4 ] || macos_policy="$4"

    {
        printf '[profile.default]\n%s\n\n' "$default_policy"
        printf '[[profile.default.overrides]]\n%s\n%s\n' "$platform_line" "$macos_policy"
    } >"$path"
}

expect_rejected() {
    local name="$1"
    local config="$2"
    if "$checker" "$config" >"$tmp_dir/$name.stdout" 2>"$tmp_dir/$name.stderr"; then
        echo "expected $name policy to be rejected" >&2
        return 1
    fi
    if ! grep -q 'nextest leak policy:' "$tmp_dir/$name.stderr"; then
        echo "$name rejection lacked an actionable diagnostic" >&2
        return 1
    fi
}

valid="$tmp_dir/valid.toml"
write_config "$valid" 'platform = { host = '\''cfg(target_os = "macos")'\'' }'
"$checker" "$valid"

target_only="$tmp_dir/target-only.toml"
write_config "$target_only" 'platform = '\''cfg(target_os = "macos")'\'''
expect_rejected target-only "$target_only"

wrong_default="$tmp_dir/wrong-default.toml"
write_config "$wrong_default" 'platform = { host = '\''cfg(target_os = "macos")'\'' }' \
    'leak-timeout = { period = "4s", result = "fail" }'
expect_rejected wrong-default "$wrong_default"

advisory="$tmp_dir/advisory.toml"
write_config "$advisory" 'platform = { host = '\''cfg(target_os = "macos")'\'' }' \
    'leak-timeout = { period = "5s", result = "pass" }'
expect_rejected advisory "$advisory"

wrong_macos="$tmp_dir/wrong-macos.toml"
write_config "$wrong_macos" 'platform = { host = '\''cfg(target_os = "macos")'\'' }' \
    'leak-timeout = { period = "5s", result = "fail" }' \
    'leak-timeout = { period = "29s", result = "fail" }'
expect_rejected wrong-macos "$wrong_macos"

duplicate="$tmp_dir/duplicate.toml"
write_config "$duplicate" 'platform = { host = '\''cfg(target_os = "macos")'\'' }'
printf '\n[[profile.default.overrides]]\nplatform = { host = '\''cfg(target_os = "macos")'\'' }\nleak-timeout = { period = "30s", result = "fail" }\n' >>"$duplicate"
expect_rejected duplicate "$duplicate"

duplicate_key="$tmp_dir/duplicate-key.toml"
write_config "$duplicate_key" 'platform = { host = '\''cfg(target_os = "macos")'\'' }'
printf 'leak-timeout = { period = "30s", result = "fail" }\n' >>"$duplicate_key"
expect_rejected duplicate-key "$duplicate_key"

generic_advisory="$tmp_dir/generic-advisory.toml"
write_config "$generic_advisory" 'platform = { host = '\''cfg(target_os = "macos")'\'' }'
printf '\n[[profile.default.overrides]]\nfilter = '\''all()'\''\nleak-timeout = { period = "1s", result = "pass" }\n' >>"$generic_advisory"
expect_rejected generic-advisory "$generic_advisory"

fixture="$tmp_dir/fixture"
mkdir -p "$fixture/src" "$fixture/.config" "$fixture/pids"
write_config "$fixture/.config/nextest.toml" \
    'platform = { host = '\''cfg(target_os = "macos")'\'' }' \
    'leak-timeout = { period = "100ms", result = "fail" }' \
    'leak-timeout = { period = "100ms", result = "fail" }'

cat >"$fixture/Cargo.toml" <<'EOF'
[package]
name = "leak-policy-fixture"
version = "0.0.0"
edition = "2021"
EOF

{
    cat <<'EOF'
use std::fs;
use std::process::Command;
use std::thread;
use std::time::Duration;

fn clean() {
    let directory = std::env::var("LEAK_POLICY_PID_DIR").expect("PID directory");
    fs::write(format!("{directory}/{}", std::process::id()), b"clean\n").expect("write PID");
    println!("bounded clean fixture output");
    thread::sleep(Duration::from_millis(50));
}

#[test]
fn inherited_pipe_child() {
    let directory = std::env::var("LEAK_POLICY_PID_DIR").expect("PID directory");
    let child = Command::new("sleep").arg("2").spawn().expect("spawn sleep");
    fs::write(
        format!("{directory}/edge"),
        format!("{} {}\n", std::process::id(), child.id()),
    )
    .expect("write edge");
    thread::sleep(Duration::from_millis(500));
}
EOF
    for number in $(seq -w 1 32); do
        printf '#[test]\nfn clean_%s() { clean(); }\n' "$number"
    done
} >"$fixture/src/lib.rs"

sample_clean_processes() {
    local observed=0
    local deadline=$((SECONDS + 10))
    local pid child
    while ((SECONDS < deadline)); do
        for pid_file in "$fixture"/pids/[0-9]*; do
            [ -e "$pid_file" ] || continue
            pid="${pid_file##*/}"
            if kill -0 "$pid" 2>/dev/null; then
                observed=1
                child="$(pgrep -P "$pid" 2>/dev/null || true)"
                if [ -n "$child" ]; then
                    echo "clean fixture PID $pid unexpectedly has child $child" >&2
                    return 1
                fi
            fi
        done
        if [ -e "$fixture/clean.done" ]; then
            break
        fi
        sleep 0.01
    done
    if [ "$observed" -ne 1 ]; then
        echo "sampler did not observe a clean fixture process" >&2
        sed -n '1,120p' "$tmp_dir/clean.out" >&2
        return 1
    fi
}

clean_args=(nextest run --manifest-path "$fixture/Cargo.toml" -E 'test(clean_)')
clean_runs=1
if [ "$(uname -s)" = "Darwin" ]; then
    clean_args+=(--test-threads 18)
    clean_runs=10
fi
cargo test --manifest-path "$fixture/Cargo.toml" --no-run >"$tmp_dir/build.out" 2>&1
(
    set +e
    status=0
    for _ in $(seq 1 "$clean_runs"); do
        LEAK_POLICY_PID_DIR="$fixture/pids" "$nextest_bin" "${clean_args[@]}" \
            >>"$tmp_dir/clean.out" 2>&1
        status=$?
        [ "$status" -eq 0 ] || break
    done
    touch "$fixture/clean.done"
    exit "$status"
) &
clean_run_pid=$!
background_pids+=("$clean_run_pid")
sample_clean_processes
wait "$clean_run_pid"
background_pids=()

rm -f "$fixture/pids/edge"
set +e
LEAK_POLICY_PID_DIR="$fixture/pids" "$nextest_bin" nextest run \
    --manifest-path "$fixture/Cargo.toml" -E 'test(inherited_pipe_child)' \
    >"$tmp_dir/leak.out" 2>&1 &
leak_run_pid=$!
background_pids+=("$leak_run_pid")
set -e

for _ in $(seq 1 200); do
    [ -s "$fixture/pids/edge" ] && break
    sleep 0.01
done
if [ ! -s "$fixture/pids/edge" ]; then
    echo "positive-control edge was not recorded" >&2
    exit 1
fi
read -r parent_pid child_pid <"$fixture/pids/edge"
case "$parent_pid $child_pid" in
*[!0-9\ ]*)
    echo "positive-control edge contained non-numeric PIDs" >&2
    exit 1
    ;;
esac
known_child_pid="$child_pid"
observed_parent="$(ps -o ppid= -p "$child_pid" | tr -d ' ')"
if [ "$observed_parent" != "$parent_pid" ]; then
    echo "sampler did not observe expected edge $parent_pid -> $child_pid" >&2
    exit 1
fi

if wait "$leak_run_pid"; then
    echo "inherited pipe child unexpectedly passed fatal leak detection" >&2
    exit 1
fi
background_pids=()
if ! grep -q 'LEAK-FAIL' "$tmp_dir/leak.out"; then
    echo "fatal leak run did not report LEAK-FAIL" >&2
    exit 1
fi
stop_known_child
if kill -0 "$child_pid" 2>/dev/null; then
    echo "positive-control child remained alive after the leak run" >&2
    exit 1
fi

echo "nextest leak policy tests passed"
