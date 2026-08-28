#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "nextest leak policy: usage: $0 <nextest-config>" >&2
    exit 2
fi

config="$1"
if [ ! -f "$config" ]; then
    echo "nextest leak policy: config does not exist: $config" >&2
    exit 2
fi

if ! awk '
    function trim(value) {
        sub(/^[[:space:]]+/, "", value)
        sub(/[[:space:]]+$/, "", value)
        return value
    }

    function finish_override() {
        if (!in_override) {
            return
        }
        if (mac_host) {
            mac_blocks++
            if (filter_count == 0 && leak_count == 1 && leak == "leak-timeout = { period = \"30s\", result = \"fail\" }") {
                valid_mac++
            }
        } else if (leak_count != 0) {
            other_leak_blocks++
        }
    }

    /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }

    /^\[\[/ {
        finish_override()
        in_default = 0
        in_override = ($0 == "[[profile.default.overrides]]")
        mac_host = 0
        leak = ""
        leak_count = 0
        filter_count = 0
        next
    }

    /^\[/ {
        finish_override()
        in_override = 0
        in_default = ($0 == "[profile.default]")
        next
    }

    {
        line = trim($0)
        if (in_default && line ~ /^leak-timeout[[:space:]]*=/) {
            default_blocks++
            if (line == "leak-timeout = { period = \"5s\", result = \"fail\" }") {
                valid_default++
            }
        }
        if (in_override && line == "platform = { host = '\''cfg(target_os = \"macos\")'\'' }") {
            mac_host = 1
        }
        if (in_override && line ~ /^platform = '\''cfg\(target_os = \"macos\"\)'\''$/) {
            target_only++
        }
        if (in_override && line ~ /^leak-timeout[[:space:]]*=/) {
            leak = line
            leak_count++
        }
        if (in_override && line ~ /^filter[[:space:]]*=/) {
            filter_count++
        }
    }

    END {
        finish_override()
        if (default_blocks != 1 || valid_default != 1) {
            print "nextest leak policy: require exactly one fatal 5s [profile.default] policy" > "/dev/stderr"
            failed = 1
        }
        if (mac_blocks != 1 || valid_mac != 1) {
            print "nextest leak policy: require exactly one fatal 30s macOS host override" > "/dev/stderr"
            failed = 1
        }
        if (target_only != 0) {
            print "nextest leak policy: macOS selector must use platform.host, not target-only syntax" > "/dev/stderr"
            failed = 1
        }
        if (other_leak_blocks != 0) {
            print "nextest leak policy: leak-timeout overrides are forbidden outside the exact macOS host policy" > "/dev/stderr"
            failed = 1
        }
        exit failed
    }
' "$config"; then
    exit 1
fi
