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

## Lockfile parity

This directory is its own cargo workspace (see the `[workspace]` note in
`Cargo.toml`), so no Dependabot entry reaches it. Its `Cargo.lock` is tracked
and **must agree with the root workspace `Cargo.lock` on every shared
dependency** — the target builds `rimap-server` with `features = ["fuzzing"]`
and re-checks its decisions against rmcp's deserializer, so once the two
lockfiles resolve different parser-stack versions the fuzzer is no longer
differential against the code that ships. Drift of exactly this kind produced
[#512](https://github.com/randomparity/rusty-imap-mcp/issues/512).

`just check-fuzz-lock-parity` enforces this on every PR. After a workspace
dependency bump it will fail; restore parity and rebuild with:

```sh
just realign-fuzz-locks
cargo +nightly fuzz build -O
```

The invariant is parity, not freshness — this lockfile follows the workspace
rather than moving on its own schedule. See
[ADR-0011](../../../docs/ADR/0011-fuzz-lockfile-workspace-parity.md) for why a
Dependabot entry here would reintroduce the same drift in the other direction.

On a Dependabot PR the realign is automatic:
`.github/workflows/dependabot-fuzz-lock.yml` runs the command above and pushes
the result, so the gate clears without anyone cloning the branch. Two things
follow from that. It needs a `FUZZ_LOCK_REALIGN_TOKEN` secret on the
`fuzz-lock-realign` environment and fails loudly without one, and once it has
pushed, Dependabot stops
auto-rebasing that PR — comment `@dependabot rebase` to hand the branch back.
The workflow declines any PR whose diff reaches past cargo manifests and
lockfiles; those still get the manual command. See
[ADR-0016](../../../docs/ADR/0016-dependabot-fuzz-lock-auto-realign.md).

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

The fuzz target runs three oracles (see `crates/rimap-server/src/mcp/fuzz_oracle.rs`). The panic message identifies which one fired:

- `"validator FORWARDED an envelope rmcp rejects: …"` — the validator's grammar drifted from rmcp's deserializer. The line was forwarded, but rmcp's `serde(untagged)` + `serde(flatten)` chain on `JsonRpcMessage` rejected it (silent-drop class). Tighten `validate()` / `is_valid_params` / `is_forwardable_id` / `has_duplicate_top_level_keys` until the divergence closes.
- `"validator synthesized a schema-INVALID error envelope: …"` — the rejection path produced output that fails the vendored MCP `JSONRPCErrorResponse` schema. Fix `synthesize_error_line` or the helper that fed it (e.g. `extract_id` echoing a value the MCP `RequestId` schema rejects).
- Anything else — an unhandled panic inside `validate()` or one of the oracle helpers. Fix the panic source.

## Why local-only

This target is run on-demand, not in CI. The proptest nightly workflow (`.github/workflows/mcp-fuzz-nightly.yml`) handles regression prevention with `prop_envelope_never_panics` at 100k cases. cargo-fuzz benefits from a long-lived growing corpus and dedicated runner time; that operational commitment isn't in scope today. See `docs/superpowers/specs/2026-05-17-cargo-fuzz-validator-design.md` for the full rationale.

The target's oracle is not panic-only: every `Forward` decision is re-checked against rmcp's deserializer for `ClientJsonRpcMessage`, and every `Reject` decision is re-checked against the vendored MCP `JSONRPCErrorResponse` schema. The proptest workflow checks panics only, so cargo-fuzz remains the right tool for catching grammar / synthesis divergences from rmcp and the MCP schema. Throughput on `feature/cargo-fuzz-validator` measures ~19k execs/sec on Apple Silicon, down from the prior panic-only target's ~26k/sec.
