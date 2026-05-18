# cargo-fuzz Validator Target — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a coverage-guided cargo-fuzz target that exercises `crates/rimap-server/src/mcp/wire_validator.rs::validate()` against arbitrary UTF-8 input, with a seed corpus committed to the repo.

**Architecture:** A new fuzz subcrate at `crates/rimap-server/fuzz/` (its own workspace, isolated from the top-level workspace per cargo-fuzz convention). A `fuzzing` feature flag on `rimap-server` exposes a `#[doc(hidden)] pub` re-export of the currently-`pub(crate)` `validate` function; production builds without the feature see no API change. One fuzz target, raw `&[u8]` → `&str` → `validate()`, panic-only assertion. ~20 hand-crafted seed envelopes bootstrap libFuzzer's coverage map.

**Tech Stack:** cargo-fuzz 0.13.1, libFuzzer (via Rust nightly toolchain), `rimap-server` workspace member.

**Reference spec:** [`docs/superpowers/specs/2026-05-17-cargo-fuzz-validator-design.md`](../specs/2026-05-17-cargo-fuzz-validator-design.md)

---

## File Structure

| File | Purpose | New / Modified |
|---|---|---|
| `crates/rimap-server/Cargo.toml` | Add `fuzzing = []` feature flag | Modified |
| `crates/rimap-server/src/mcp/wire_validator.rs` | Add `#[cfg(feature = "fuzzing")]` re-export of `validate` | Modified |
| `crates/rimap-server/fuzz/Cargo.toml` | Subcrate manifest; depends on `rimap-server` with `features = ["fuzzing"]` | New (cargo-fuzz generates, then edited) |
| `crates/rimap-server/fuzz/.gitignore` | Excludes `target/`, `artifacts/`, `coverage/` from git | New (cargo-fuzz generates) |
| `crates/rimap-server/fuzz/fuzz_targets/validate.rs` | The 8-line fuzz target | New (cargo-fuzz generates, then rewritten) |
| `crates/rimap-server/fuzz/corpus/validate/*` | ~20 hand-crafted seed envelopes | New |
| `crates/rimap-server/fuzz/README.md` | Usage notes — how to run, where artifacts land, reproduce-finding workflow | New |

The top-level workspace `Cargo.toml` already carries `exclude = ["fuzz"]` (root-level), and its `members` list is explicit (no globs), so `crates/rimap-server/fuzz/` is automatically excluded from the main workspace — no top-level changes needed.

---

## Task 1: Add `fuzzing` feature flag and re-export `validate`

**Files:**
- Modify: `crates/rimap-server/Cargo.toml`
- Modify: `crates/rimap-server/src/mcp/wire_validator.rs`

Production-facing change: zero. The re-export is `#[doc(hidden)]` and gated on a feature only the fuzz subcrate enables.

- [ ] **Step 1: Add the feature flag**

In `crates/rimap-server/Cargo.toml`, locate the `[features]` block (currently starts with `default = []` and includes `test-support = [...]`). Add a `fuzzing = []` entry directly below `default`, with the rationale inline:

```toml
[features]
default = []

# Exposes `mcp::wire_validator::__fuzz_validate` for the cargo-fuzz
# target at `crates/rimap-server/fuzz/`. NEVER enable from another
# workspace member — the fuzz subcrate is the only legitimate
# consumer. See docs/superpowers/specs/2026-05-17-cargo-fuzz-validator-design.md.
fuzzing = []

# Gated entry points for integration tests …
test-support = [
    …existing…
]
```

- [ ] **Step 2: Add the re-export**

In `crates/rimap-server/src/mcp/wire_validator.rs`, append the following at the end of the file (after the existing `mod tests` block, OUTSIDE the `#[cfg(test)]` gate). Place it after the closing `}` of the test module:

```rust
/// `validate` re-export for the cargo-fuzz target at
/// `crates/rimap-server/fuzz/`. Production builds (no `--features
/// fuzzing`) do not see this symbol; `cargo doc` hides it via
/// `doc(hidden)`. The feature MUST NOT be enabled from any other
/// workspace member.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub use validate as __fuzz_validate;
```

- [ ] **Step 3: Verify production build still works (no feature)**

Run: `cargo check -p rimap-server --locked`
Expected: clean compile, exit 0.

- [ ] **Step 4: Verify feature-on build works**

Run: `cargo check -p rimap-server --features fuzzing --locked`
Expected: clean compile, exit 0.

- [ ] **Step 5: Verify clippy still clean**

Run: `cargo clippy -p rimap-server --all-targets --locked -- -D warnings`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add crates/rimap-server/Cargo.toml crates/rimap-server/src/mcp/wire_validator.rs
git commit -m "feat(rimap-server): fuzzing feature flag exposes validate for cargo-fuzz"
```

---

## Task 2: Initialize the fuzz subcrate and wire the target

**Files:**
- Create: `crates/rimap-server/fuzz/Cargo.toml`
- Create: `crates/rimap-server/fuzz/.gitignore`
- Create: `crates/rimap-server/fuzz/fuzz_targets/validate.rs`

cargo-fuzz's `init` command scaffolds the subcrate. Then edit two of the generated files to point at our re-export.

- [ ] **Step 1: Initialize the fuzz subcrate**

From the repo root, run:

```bash
cd crates/rimap-server && cargo +nightly fuzz init --target validate
```

This creates `crates/rimap-server/fuzz/{Cargo.toml,.gitignore,fuzz_targets/validate.rs}`. The generated `Cargo.toml` will look approximately like:

```toml
[package]
name = "rimap-server-fuzz"
version = "0.0.0"
publish = false
edition = "2021"

[package.metadata]
cargo-fuzz = true

[dependencies]
libfuzzer-sys = "0.4"

[dependencies.rimap-server]
path = ".."

# Prevent this from being treated as a member of the parent workspace.
[workspace]
members = ["."]

[profile.release]
debug = 1

[[bin]]
name = "validate"
path = "fuzz_targets/validate.rs"
test = false
doc = false
bench = false
```

- [ ] **Step 2: Enable the `fuzzing` feature on the rimap-server dep**

Edit `crates/rimap-server/fuzz/Cargo.toml` — change the `[dependencies.rimap-server]` block from:

```toml
[dependencies.rimap-server]
path = ".."
```

to:

```toml
[dependencies.rimap-server]
path = ".."
features = ["fuzzing"]
```

- [ ] **Step 3: Pin the `edition` to match the workspace**

The workspace uses `edition = "2024"` (top-level `[workspace.package]`). cargo-fuzz's scaffold defaults to `2021`. Change the `[package]` block in `crates/rimap-server/fuzz/Cargo.toml`:

```toml
[package]
name = "rimap-server-fuzz"
version = "0.0.0"
publish = false
edition = "2024"
```

This is not strictly required for the build to work, but matches the rest of the workspace and avoids edition-mismatch surprises if the fuzz target ever uses edition-2024-only syntax.

- [ ] **Step 4: Replace the generated fuzz target**

Replace the entire contents of `crates/rimap-server/fuzz/fuzz_targets/validate.rs` with:

```rust
#![no_main]

use libfuzzer_sys::fuzz_target;
use rimap_server::mcp::wire_validator::__fuzz_validate as validate;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = validate(s);
    }
});
```

- [ ] **Step 5: Verify the fuzz target builds**

cargo-fuzz auto-detects the `fuzz/` directory in the current working dir, so `cd` is the simplest invocation:

```bash
cd crates/rimap-server && cargo +nightly fuzz build
```

Expected: builds cleanly. First build takes a few minutes (instrumentation compile); subsequent ones cache. Exit code 0.

- [ ] **Step 6: Commit**

```bash
git add crates/rimap-server/fuzz/Cargo.toml crates/rimap-server/fuzz/.gitignore crates/rimap-server/fuzz/fuzz_targets/validate.rs
git commit -m "feat(rimap-server): cargo-fuzz target for wire_validator::validate (#266)"
```

---

## Task 3: Add the seed corpus

**Files:**
- Create: `crates/rimap-server/fuzz/corpus/validate/` (directory)
- Create: 19 files in that directory, one per envelope shape

Each file is the raw envelope bytes — no JSON pretty-printing, no trailing newline, exactly as `validate()` would receive after `validate_inbound`'s `\n` / `\r` stripping. File names are for human readability; libFuzzer only reads the contents.

- [ ] **Step 1: Create the directory**

```bash
mkdir -p crates/rimap-server/fuzz/corpus/validate
```

- [ ] **Step 2: Write the seed files**

Use the Write tool (NOT `echo` / heredocs — to avoid shell-quoting bugs in the JSON) to create each of the following files with the exact byte contents shown. Each file's contents are ONE line (no trailing newline).

`crates/rimap-server/fuzz/corpus/validate/valid-request-numeric-id`:
```
{"jsonrpc":"2.0","method":"tools/list","id":1}
```

`crates/rimap-server/fuzz/corpus/validate/valid-request-string-id`:
```
{"jsonrpc":"2.0","method":"tools/list","id":"abc"}
```

`crates/rimap-server/fuzz/corpus/validate/valid-notification`:
```
{"jsonrpc":"2.0","method":"notifications/cancelled"}
```

`crates/rimap-server/fuzz/corpus/validate/valid-response`:
```
{"jsonrpc":"2.0","id":99,"result":{"x":1}}
```

`crates/rimap-server/fuzz/corpus/validate/valid-error-response`:
```
{"jsonrpc":"2.0","id":99,"error":{"code":-32601,"message":"not found"}}
```

`crates/rimap-server/fuzz/corpus/validate/parse-error-malformed-json`:
```
not valid json
```

`crates/rimap-server/fuzz/corpus/validate/parse-error-truncated`:
```
{"jsonrpc":"2.0","method":"x"
```

`crates/rimap-server/fuzz/corpus/validate/invalid-request-no-jsonrpc`:
```
{"method":"x","id":1}
```

`crates/rimap-server/fuzz/corpus/validate/invalid-request-wrong-jsonrpc`:
```
{"jsonrpc":"1.0","method":"x","id":1}
```

`crates/rimap-server/fuzz/corpus/validate/invalid-request-null-id`:
```
{"jsonrpc":"2.0","method":"x","id":null}
```

`crates/rimap-server/fuzz/corpus/validate/invalid-request-array-id`:
```
{"jsonrpc":"2.0","method":"x","id":[1,2]}
```

`crates/rimap-server/fuzz/corpus/validate/params-as-array`:
```
{"jsonrpc":"2.0","method":"x","id":1,"params":[1,2,3]}
```

`crates/rimap-server/fuzz/corpus/validate/params-as-null`:
```
{"jsonrpc":"2.0","method":"x","id":1,"params":null}
```

`crates/rimap-server/fuzz/corpus/validate/params-as-number`:
```
{"jsonrpc":"2.0","method":"x","id":1,"params":0}
```

`crates/rimap-server/fuzz/corpus/validate/params-as-string`:
```
{"jsonrpc":"2.0","method":"x","id":1,"params":"foo"}
```

`crates/rimap-server/fuzz/corpus/validate/error-fractional-code`:
```
{"jsonrpc":"2.0","id":1,"error":{"code":1.5,"message":"x"}}
```

`crates/rimap-server/fuzz/corpus/validate/error-out-of-i32-code`:
```
{"jsonrpc":"2.0","id":1,"error":{"code":2147483648,"message":"x"}}
```

`crates/rimap-server/fuzz/corpus/validate/id-fractional`:
```
{"jsonrpc":"2.0","method":"x","id":1.5}
```

`crates/rimap-server/fuzz/corpus/validate/id-out-of-i64`:
```
{"jsonrpc":"2.0","method":"x","id":9223372036854775808}
```

`crates/rimap-server/fuzz/corpus/validate/mixed-method-and-result`:
```
{"jsonrpc":"2.0","method":"x","id":1,"result":{}}
```

(That's 20 files total.)

- [ ] **Step 3: Verify file count and contents**

```bash
ls crates/rimap-server/fuzz/corpus/validate | wc -l
```

Expected output: `20`

Spot-check that no file has a trailing newline:

```bash
for f in crates/rimap-server/fuzz/corpus/validate/*; do
    tail -c 1 "$f" | xxd | head -1
done
```

Expected: none of the lines should end with `0a` (which is `\n`); each file's last byte should be the closing `}` (0x7d) or another non-newline character. If any file has a trailing newline, re-write it.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-server/fuzz/corpus/validate
git commit -m "feat(rimap-server): seed corpus for validate fuzz target (#266)"
```

---

## Task 4: Smoke test + usage README

**Files:**
- Create: `crates/rimap-server/fuzz/README.md`

Run a 60-second smoke fuzz against the new target to confirm the pipeline (build → libFuzzer init → corpus replay → mutation loop) is working end-to-end, then document the usage so a future operator can pick it up cold.

- [ ] **Step 1: Run a 60-second smoke fuzz**

```bash
cd crates/rimap-server && cargo +nightly fuzz run validate -- -max_total_time=60
```

Expected:
- libFuzzer banner mentions corpus size ~20
- "Done <N> runs in 60 second(s)" near the end
- Exit code 0
- No new files in `crates/rimap-server/fuzz/artifacts/validate/` (no crashes found)

If libFuzzer reports a crash, capture the artifact and the reproduction command — convert it to a `#[test]` regression in `wire_validator.rs::tests` and fix `validate()` before continuing this plan (treat it as a discovered bug, the same way Task 5a was handled in `2026-05-15-issue-277-envelope-validator.md`).

- [ ] **Step 2: Write the README**

Create `crates/rimap-server/fuzz/README.md` with the following contents:

````markdown
# rimap-server fuzz

Coverage-guided fuzzing of `crate::mcp::wire_validator::validate()` via cargo-fuzz + libFuzzer.

## Requirements

- Nightly Rust toolchain (`rustup toolchain install nightly`)
- cargo-fuzz (`cargo install cargo-fuzz`)

## Running

From this directory (or from the repo root with `--fuzz-dir crates/rimap-server/fuzz`):

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
````

- [ ] **Step 3: Commit**

```bash
git add crates/rimap-server/fuzz/README.md
git commit -m "docs(rimap-server/fuzz): usage notes for validate fuzz target"
```

---

## Verification

After all four tasks land:

1. **Per-task verifications** — each task's `cargo check` / `cargo clippy` / `cargo +nightly fuzz build` / smoke run must pass on its own commit.

2. **Confirm production builds are untouched:**
   ```sh
   cargo build -p rimap-server --locked
   cargo nextest run -p rimap-server --locked --no-tests=pass
   cargo clippy -p rimap-server --all-targets --locked -- -D warnings
   ```
   All three commands must succeed without the `--features fuzzing` flag. The fuzz subcrate is not in the workspace, so these commands do not exercise it.

3. **Confirm the fuzz harness works:**
   ```sh
   cd crates/rimap-server && cargo +nightly fuzz run validate -- -max_total_time=30
   ```
   Expected: clean 30-second run, zero crashes, corpus replay reports 20 initial inputs.

4. **Push.** The branch should be pushed with `GIT_SSH_COMMAND="ssh -o ServerAliveInterval=30"` per the repo's pre-push-hook keepalive memo.

## Out of scope

- CI integration for cargo-fuzz (proptest nightly suffices for now).
- Fuzzing `synthesize_error_line`, `is_*` helpers, or `validate_inbound` async.
- Coverage report generation (`cargo +nightly fuzz coverage`).
- Wiring `mcp_wire_proptest.proptest-regressions` into the corpus (those are harness-level, not validator-level).
- Sanitizer tuning beyond cargo-fuzz defaults (ASan on; MSan/UBSan off).
