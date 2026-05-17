# rimap-server fuzz

Coverage-guided fuzzing of `crate::mcp::wire_validator::validate()` via cargo-fuzz + libFuzzer.

## Requirements

- Nightly Rust toolchain (`rustup toolchain install nightly`)
- cargo-fuzz (`cargo install cargo-fuzz`)

## Running

From this directory (or from the repo root with `cd crates/rimap-server`):

```sh
# 1-minute smoke
cargo +nightly fuzz run validate -- -max_total_time=60

# 1-hour focused run
cargo +nightly fuzz run validate -- -max_total_time=3600

# Overnight (8 hours)
cargo +nightly fuzz run validate -- -max_total_time=28800
```

libFuzzer adds newly-interesting inputs to `corpus/validate/` as it discovers them. These are local working state and NOT committed by default. To shrink the corpus while preserving coverage:

```sh
cargo +nightly fuzz cmin validate
```

## Findings

Crashes land in `artifacts/validate/<sha>` as raw bytes. Reproduce with:

```sh
cargo +nightly fuzz run validate artifacts/validate/<sha>
```

For every finding:
1. Convert the artifact bytes to a `#[test]` regression in `crates/rimap-server/src/mcp/wire_validator.rs` under `mod tests`.
2. Verify the test fails on the current `validate()`.
3. Fix `validate()` to handle the input.
4. Verify the test passes; keep the artifact in `artifacts/` as historical record.

## Why local-only

This target is run on-demand, not in CI. The proptest nightly workflow (`.github/workflows/mcp-fuzz-nightly.yml`) handles regression prevention with `prop_envelope_never_panics` at 100k cases. cargo-fuzz benefits from a long-lived growing corpus and dedicated runner time; that operational commitment isn't in scope today. See `docs/superpowers/specs/2026-05-17-cargo-fuzz-validator-design.md` for the full rationale.
