#!/usr/bin/env bash
#
# ClusterFuzzLite build entry point. Builds every fuzz target in both:
#   - `fuzz/fuzz_targets/`                       (workspace-level)
#   - `crates/rimap-server/fuzz/fuzz_targets/`   (nested standalone workspace,
#                                                isolated to keep nightly
#                                                instrumentation off the root —
#                                                see docs/superpowers/specs/
#                                                2026-05-17-cargo-fuzz-validator-design.md)
# and copies each binary + seed corpus to $OUT.
#
# Target names across the two fuzz dirs must be globally unique: the binary
# and `<target>_seed_corpus.zip` both land in a flat $OUT/ directory.
#
# Release mode (-O) is required: debug builds trip upstream
# `debug_assert!` guards on malformed input.
set -euo pipefail

host_triple="$(cargo +nightly -vV | awk '/^host:/ {print $2}')"

build_fuzz_dir() {
    local fuzz_dir="$1"
    (
        cd "$fuzz_dir"
        cargo +nightly fuzz build -O
    )
    local release_dir="${fuzz_dir}/target/${host_triple}/release"
    local target
    for f in "$fuzz_dir"/fuzz_targets/*.rs; do
        target="$(basename "${f%.*}")"
        cp "$release_dir/$target" "$OUT/"
        if [ -d "$fuzz_dir/corpus/$target" ]; then
            zip -j -r "$OUT/${target}_seed_corpus.zip" "$fuzz_dir/corpus/$target"
        fi
    done
}

build_fuzz_dir "$SRC/rusty-imap-mcp/fuzz"
build_fuzz_dir "$SRC/rusty-imap-mcp/crates/rimap-server/fuzz"
