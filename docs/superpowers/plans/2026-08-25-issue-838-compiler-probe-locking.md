# Locked Nested Cargo Probes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make both exact-E0639 downstream Cargo probes use committed, workspace-reviewed dependency graphs under `--locked --offline`, and prevent focused recurrence.

**Architecture:** Each probe owns a minimal fixture workspace and copies its manifest and lock byte-for-byte into a unique sibling temporary directory before invoking Cargo. A focused Git-aware shell/Python guard discovers direct nested Cargo checks in tracked integration-test Rust sources, validates every invocation, proves fixture lock reachability and root-lock identity containment, and atomically realigns locks. Existing release and required-CI paths invoke the same recipes.

**Tech Stack:** Rust 2024 on MSRV 1.88.0, Cargo lockfile v4, Bash, Python 3 without `tomllib`, `just`, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-08-25-issue-838-compiler-probe-locking-design.md`

## Global Constraints

- Preserve every existing positive E0639 assertion and unrelated-failure negative control in both harnesses.
- Scan only tracked integration-test Rust sources under `crates/*/tests/`; crate `src/`, `build.rs`, examples, benches, non-Rust launchers, direct compilers, and unrelated Cargo commands are excluded.
- Resolve standard and Tokio process constructors through qualified paths, imports, and import aliases.
- Validate each in-scope Cargo invocation independently; file-level flags cannot satisfy another builder.
- Fixture manifests and locks are copied byte-for-byte. Do not parse or rewrite TOML in the Rust harnesses.
- Every nested check runs `cargo check --locked --offline --message-format=short` with `CARGO_TARGET_DIR` inside its temporary root.
- Fixture locks must contain exactly one fixture package root, have no unreachable package blocks, and contain no registry identity absent from root `Cargo.lock`.
- Lock replacement is same-filesystem and atomic: fully stage beside the tracked lock, then `os.replace`.
- No new dependency, production behavior, public API, config, authentication, persistence, or migration change.
- Keep Rust 1.88.0 compatibility, zero warnings, 100-character lines, absolute imports, and no non-test `unwrap()` or `#[allow]`.
- Use focused checks during implementation; run `just ci` in the background only after all focused behavior is green.

---

## File Map

- Create `scripts/check-compiler-probe-locks.sh`: focused source discovery, per-invocation validation, lock parser/reachability/parity, and atomic `--fix`.
- Create `scripts/check-compiler-probe-locks.test.sh`: hermetic synthetic repository contract tests plus the real-repository discovery assertion.
- Create `crates/rimap-audit/tests/fixtures/e0639-probe/Cargo.toml`: audit fixture package and local path dependencies.
- Create `crates/rimap-audit/tests/fixtures/e0639-probe/Cargo.lock`: pruned graph seeded from root lock.
- Create `crates/rimap-audit/tests/fixtures/e0639-probe/src/main.rs`: valid empty lock-generation target.
- Create `crates/rimap-imap/tests/fixtures/e0639-probe/Cargo.toml`: IMAP fixture package and local path dependencies.
- Create `crates/rimap-imap/tests/fixtures/e0639-probe/Cargo.lock`: pruned graph seeded from root lock.
- Create `crates/rimap-imap/tests/fixtures/e0639-probe/src/main.rs`: valid empty lock-generation target.
- Modify `crates/rimap-audit/tests/non_exhaustive_e0639.rs`: byte-copy the audit fixture and run locked/offline in a sibling temporary root.
- Modify `crates/rimap-imap/tests/non_exhaustive_e0639.rs`: byte-copy the IMAP fixture and run locked/offline in a sibling temporary root.
- Modify `scripts/post-release-bump.sh`: recognize, realign, verify, and emit both fixture locks.
- Modify `scripts/post-release-bump.test.sh`: cover known sets and execute `main` hermetically through fake external tools.
- Modify `justfile`: add check, test, and repair recipes and wire the check/test recipes into `just ci`.
- Modify `.github/workflows/ci.yml`: run both focused recipes in required `cargo-deny` before the audit action.
- Modify `CHANGELOG.md`: record locked/offline downstream compiler probes under Unreleased/Changed.

---

### Task 1: Focused Probe and Lock Guard

**Files:**
- Create: `scripts/check-compiler-probe-locks.sh`
- Create: `scripts/check-compiler-probe-locks.test.sh`

**Interfaces:**
- Consumes: Git tracked paths, canonical Cargo lockfile v4 text, fixture `Cargo.toml` package name/version, `CARGO` environment override for realignment tests.
- Produces: `./scripts/check-compiler-probe-locks.sh [--fix] [--repo-root PATH]`; exit 0 only when at least one in-scope probe exists and every source/fixture/lock invariant holds.
- Produces frozen internal Python records:
  - `Function(name, body_start, body_end, body, code, callees)`
  - `CommandCall(path, function, start, end, executable, chain)`
  - `FunctionFacts(callees, cargo_return, temporary_root, writes_manifest,
    uses_fixture, copies_manifest, copies_lock)`
  - `Probe(path, function, command_start, fixture)`
  - `Package(name, version, source, checksum, dependencies)`, hashable by all
    fields so graph traversal can return `set[Package]`.

- [ ] **Step 1: Write the synthetic contract test before the guard exists**

Create an executable Bash test with `set -euo pipefail`, a `mktemp -d` cleanup trap, and helpers `new_repo`, `write_good_tree`, `expect_ok`, and `expect_fail`. Each synthetic repository must initialize Git, write `Cargo.lock`, a tracked `crates/demo/tests/probe.rs`, and a tracked fixture manifest/lock/source, then `git add` them before invoking the real script with `--repo-root`.

The canonical good Rust source must contain these observable markers:

```rust
use std::path::PathBuf;
use std::process::Command;

const COMPILER_PROBE_FIXTURE: &str = "tests/fixtures/e0639-probe";

fn cargo_bin() -> PathBuf {
    std::env::var("CARGO").map_or_else(|_| PathBuf::from("cargo"), PathBuf::from)
}

fn check_probe() {
    let fixture = fixture_root().join(COMPILER_PROBE_FIXTURE);
    let dir = tempfile::Builder::new().tempdir_in(fixture.parent().expect("parent")).expect("temp");
    std::fs::copy(fixture.join("Cargo.toml"), dir.path().join("Cargo.toml")).expect("manifest");
    std::fs::copy(fixture.join("Cargo.lock"), dir.path().join("Cargo.lock")).expect("lock");
    let _ = Command::new(cargo_bin())
        .args(["check", "--locked", "--offline", "--message-format=short"])
        .current_dir(dir.path())
        .output();
}
```

The good synthetic lock must contain a unique `probe-fixture 0.0.0` root, a registry child whose full identity occurs in the root lock, and no unreachable package. Add named cases that independently assert:

```text
good
mixed-good-and-missing-offline
std-qualified / std-imported / std-import-alias
tokio-qualified / tokio-imported / tokio-import-alias
cargo-literal / cargo-pathbuf / cargo-env / cargo-env-os / cargo-env-macro
cargo-local-alias / cargo-helper-return
split-temporary-project-helper
excluded-crate-src / excluded-build-rs / excluded-repository-metadata
unresolved-cargo-helper / unresolved-temporary-project-helper
missing-locked / missing-offline
missing-registration / duplicate-registration
absolute-registration / escaping-registration / untracked-registration
missing-manifest / missing-lock / missing-source
missing-manifest-copy / missing-lock-copy
malformed-lock / empty-lock
missing-fixture-root / duplicate-fixture-root
unresolved-dependency-edge / unreachable-package
root-seed-plus-fixture-block
registry-identity-absent / registry-checksum-different
root-has-additional-package
empty-discovery
```

Run:

```bash
bash scripts/check-compiler-probe-locks.test.sh
```

Expected: FAIL with `scripts/check-compiler-probe-locks.sh: No such file or directory`.

- [ ] **Step 2: Implement the shell entry point and fail-loud repository discovery**

Create `scripts/check-compiler-probe-locks.sh` as an executable Bash wrapper:

```bash
#!/usr/bin/env bash
set -euo pipefail
python3 - "$@" <<'PY'
import collections
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
PY
```

Parse only `--fix` and `--repo-root PATH`; reject duplicates, missing values,
unknown flags, and positional arguments with an actionable usage error. Resolve
the default repository root with `git rev-parse --show-toplevel`, then use
`git -C <root> ls-files -z` and select paths under
`crates/<crate>/tests/**/*.rs`. Do not select `src`, root `build.rs`, examples,
or benches. Exit non-zero when Git fails or discovery yields no in-scope probe.

- [ ] **Step 3: Implement deterministic Rust lexical boundaries and function extraction**

Inside the embedded Python, implement `code_mask(source)`,
`matching_delimiter(mask, start, opening, closing)`,
`extract_functions(source, mask)`, and
`command_constructors(source, mask, function)` with the frozen record types
above. `command_constructors` returns every constructor's start/end offsets and
original builder-chain text; it never returns an undelimited partial chain.

`code_mask` must preserve byte/character positions and newlines while replacing line comments, nested block comments, normal strings, raw strings with any hash count, byte strings, and character literals with spaces. Delimiter matching operates only on the mask. Function extraction recognizes local free functions, retains the original body for literal checks, and fails on an unterminated construct rather than under-reading it.

Constructor resolution must recognize:

```text
std::process::Command::new
tokio::process::Command::new
Command::new after use std::process::Command
Command::new after use tokio::process::Command
StdCommand::new after use std::process::Command as StdCommand
TokioCommand::new after use tokio::process::Command as TokioCommand
```

An unresolved local type named `Command` is not silently classified as process execution. An imported standard or Tokio constructor whose chain cannot be delimited is a hard parse error.

- [ ] **Step 4: Implement Cargo and temporary-project fixed-point resolution**

Implement pure functions `function_facts(functions)`,
`resolve_fixed_point(facts)`, `classify_probe(command, facts)`, and
`validate_probe(command, facts, source)`. The first returns
`dict[str, FunctionFacts]`; the second mutates those facts until stable; the
classifier returns `bool`; and validation returns the literal registered
fixture path or raises the script's diagnostic exception.

Each `FunctionFacts` records direct callees, whether it returns a recognized Cargo expression, creates a temporary directory, writes `Cargo.toml`, references `COMPILER_PROBE_FIXTURE`, copies the registered `Cargo.toml`, copies the registered `Cargo.lock`, and returns/uses the temporary root. Propagate Cargo-return and temporary-project provenance through local calls until no fact changes.

Classify a command only when all structural facts hold: resolved executable is Cargo; the command contains literal `check`; it uses `current_dir` or `--manifest-path`; and that root is a temporary project whose setup writes `Cargo.toml`, directly or through a local helper. For each classified command, inspect that command's own builder chain for `--locked` and `--offline`; do not let another command chain satisfy them. Require exactly one file-level literal registration and require the enclosing/helper closure to reference it and copy both registered files.

A helper whose body partly resembles a recognized Cargo or temporary-root producer but cannot be resolved must fail closed with path, function, and expression. A direct `cargo metadata` command and nested-Cargo-shaped production/build-script files remain unclassified.

- [ ] **Step 5: Implement canonical lock parsing, reachability, and root containment**

Implement `load_manifest_identity(path) -> tuple[str, str]`,
`load_lock(path) -> list[Package]`,
`resolve_dependency(reference, packages) -> Package`,
`reachable_packages(root, packages) -> set[Package]`, and
`verify_fixture_lock(root_lock, fixture_manifest, fixture_lock) -> None` using
the frozen `Package` record above.

Parse Cargo's canonical `[[package]]` blocks without `tomllib`; require exactly one name and version per block, at most one source/checksum, and a complete string-only dependency array. Resolve a dependency reference against package name, optional version, and optional parenthesized source; zero or multiple matches are errors. Require exactly one package matching the fixture manifest's `[package]` name/version. Traverse from it and reject every unvisited package block. Compare each reachable registry package as `(name, version, source, checksum)` against the root lock. Root-only packages remain valid.

Diagnostics must include the fixture lock path and the exact missing, ambiguous, unreachable, or mismatched identity. The `root-seed-plus-fixture-block` case must fail on unreachable root packages, not merely on a missing fixture root.

- [ ] **Step 6: Implement atomic realignment**

For each unique registered fixture discovered by the source scan, `--fix` must:

```python
stage_path = None
try:
    with tempfile.TemporaryDirectory(
        prefix=".e0639-lock-realign-", dir=fixture.parent
    ) as raw_work:
        work = Path(raw_work)
        shutil.copyfile(fixture / "Cargo.toml", work / "Cargo.toml")
        shutil.copytree(fixture / "src", work / "src")
        shutil.copyfile(repo / "Cargo.lock", work / "Cargo.lock")
        subprocess.run(
            [
                os.environ.get("CARGO", "cargo"),
                "metadata",
                "--manifest-path",
                str(work / "Cargo.toml"),
                "--format-version",
                "1",
            ],
            cwd=work,
            check=True,
            stdout=subprocess.DEVNULL,
        )
        verify_fixture_lock(
            repo / "Cargo.lock", work / "Cargo.toml", work / "Cargo.lock"
        )
        with tempfile.NamedTemporaryFile(
            prefix=".Cargo.lock.", dir=fixture, delete=False
        ) as stage:
            stage_path = Path(stage.name)
            stage.write((work / "Cargo.lock").read_bytes())
            stage.flush()
            os.fsync(stage.fileno())
        os.replace(stage_path, fixture / "Cargo.lock")
        stage_path = None
finally:
    if stage_path is not None:
        stage_path.unlink(missing_ok=True)
```

Never overwrite the tracked lock before metadata and verification pass. Re-run
normal verification after all replacements.

Extend the synthetic test with fake Cargo success/failure scripts. Assert successful `--fix` prunes the root seed, a Cargo failure leaves the original bytes unchanged, and an unwritable/failed adjacent stage leaves the original bytes unchanged.

- [ ] **Step 7: Run the synthetic guard contract**

Run:

```bash
bash scripts/check-compiler-probe-locks.test.sh
```

Expected: PASS with one line per named case and final `all check-compiler-probe-locks.sh tests passed`; no real-repository assertion exists yet.

- [ ] **Step 8: Commit the focused guard**

```bash
git add scripts/check-compiler-probe-locks.sh scripts/check-compiler-probe-locks.test.sh
git commit -m "test: guard nested Cargo probe locks"
```

---

### Task 2: Fixture-Backed Exact-E0639 Harnesses

**Files:**
- Create: `crates/rimap-audit/tests/fixtures/e0639-probe/Cargo.toml`
- Create: `crates/rimap-audit/tests/fixtures/e0639-probe/Cargo.lock`
- Create: `crates/rimap-audit/tests/fixtures/e0639-probe/src/main.rs`
- Create: `crates/rimap-imap/tests/fixtures/e0639-probe/Cargo.toml`
- Create: `crates/rimap-imap/tests/fixtures/e0639-probe/Cargo.lock`
- Create: `crates/rimap-imap/tests/fixtures/e0639-probe/src/main.rs`
- Modify: `crates/rimap-audit/tests/non_exhaustive_e0639.rs:30-86`
- Modify: `crates/rimap-imap/tests/non_exhaustive_e0639.rs:9-60`
- Modify: `scripts/check-compiler-probe-locks.test.sh`

**Interfaces:**
- Consumes: Task 1's literal `COMPILER_PROBE_FIXTURE` registration and byte-copy/flag checks.
- Produces: `fn fixture_root() -> PathBuf`, `fn new_probe_root(fixture: &Path) -> TempDir`, and unchanged `fn check_probe(&str) -> (bool, String)` in each integration test.
- Produces: two fixture packages named `rimap-audit-e0639-probe` and `rimap-imap-e0639-probe`, version `0.0.0`.

- [ ] **Step 1: Add the real-repository regression and observe the current harnesses fail**

Append a final test case that invokes:

```bash
expect_fail "real repository rejects unlocked probes" \
  "$guard" --repo-root "$repo_root"
```

Run:

```bash
bash scripts/check-compiler-probe-locks.test.sh
```

Expected: FAIL because both current `check_probe` functions create a temporary `Cargo.toml` but lack `COMPILER_PROBE_FIXTURE`, copied fixture locks, `--locked`, and `--offline`.

- [ ] **Step 2: Create the two fixture manifests and empty sources**

Create the audit manifest exactly as:

```toml
[package]
name = "rimap-audit-e0639-probe"
version = "0.0.0"
edition = "2024"
publish = false

[dependencies]
rimap-audit = { path = "../../.." }
rimap-core = { path = "../../../../rimap-core" }

[workspace]
```

Create the IMAP manifest exactly as:

```toml
[package]
name = "rimap-imap-e0639-probe"
version = "0.0.0"
edition = "2024"
publish = false

[dependencies]
rimap-imap = { path = "../../.." }
rimap-authz = { path = "../../../../rimap-authz" }

[workspace]
```

Each `src/main.rs` is:

```rust
fn main() {}
```

Seed both fixture `Cargo.lock` files from root `Cargo.lock` and stage the six files so tracked-file validation can see them:

```bash
cp Cargo.lock crates/rimap-audit/tests/fixtures/e0639-probe/Cargo.lock
cp Cargo.lock crates/rimap-imap/tests/fixtures/e0639-probe/Cargo.lock
git add crates/rimap-audit/tests/fixtures/e0639-probe crates/rimap-imap/tests/fixtures/e0639-probe
```

- [ ] **Step 3: Replace audit's generated manifest with byte-exact fixture copies**

Add:

```rust
const COMPILER_PROBE_FIXTURE: &str = "tests/fixtures/e0639-probe";

fn fixture_root() -> PathBuf {
    audit_crate_root().join(COMPILER_PROBE_FIXTURE)
}

fn new_probe_root(fixture: &Path) -> TempDir {
    tempfile::Builder::new()
        .prefix(".e0639-probe-")
        .tempdir_in(fixture.parent().expect("probe fixture parent exists"))
        .expect("create sibling probe tempdir")
}
```

In `check_probe`, remove the formatted manifest. Copy `Cargo.toml` and `Cargo.lock` from `fixture_root()` to `dir.path()`, create `src`, write only the supplied `main.rs`, and invoke:

```rust
let output = Command::new(cargo_bin())
    .args([
        "check",
        "--locked",
        "--offline",
        "--message-format=short",
    ])
    .env("CARGO_TARGET_DIR", dir.path().join("target"))
    .current_dir(dir.path())
    .output()
    .expect("spawn locked offline cargo check");
```

Keep `audit_crate_root` because it anchors the fixture. Remove `core_crate_root` because the fixture manifest owns the path. Preserve every source snippet and assertion below `check_probe` byte-for-byte.

- [ ] **Step 4: Apply the same fixture-copy path to IMAP**

Add the same registration and helpers, anchored by `imap_crate_root()`. Remove `authz_crate_root` and the formatted manifest. Copy both fixture files byte-for-byte, overwrite only `src/main.rs`, retain the existing per-temp `CARGO_TARGET_DIR`, and use the same four Cargo arguments. Preserve all three probe snippets and all assertions.

- [ ] **Step 5: Generate and verify the committed fixture locks**

Run:

```bash
./scripts/check-compiler-probe-locks.sh --fix
./scripts/check-compiler-probe-locks.sh
```

Expected: both locks are pruned from the root seed, each contains exactly one `0.0.0` fixture package, every package is reachable from it, and the check exits 0.

- [ ] **Step 6: Run both exact compiler-error binaries**

Run:

```bash
cargo nextest run -p rimap-audit -E 'binary(non_exhaustive_e0639)'
cargo nextest run -p rimap-imap -E 'binary(non_exhaustive_e0639)'
```

Expected: 3 audit tests and 3 IMAP tests pass. Positive probes still contain `error[E0639]`; unrelated failures still do not.

- [ ] **Step 7: Make the real-repository guard assertion green**

Change the temporary `expect_fail` from Step 1 to:

```bash
expect_ok "real repository recognizes both locked probes" \
  "$guard" --repo-root "$repo_root"
```

The test must also assert the guard's summary says exactly two in-scope invocations. Run:

```bash
bash scripts/check-compiler-probe-locks.test.sh
```

Expected: all synthetic cases and the real-repository case pass.

- [ ] **Step 8: Commit fixture-backed probes**

```bash
git add crates/rimap-audit/tests/non_exhaustive_e0639.rs \
  crates/rimap-audit/tests/fixtures/e0639-probe \
  crates/rimap-imap/tests/non_exhaustive_e0639.rs \
  crates/rimap-imap/tests/fixtures/e0639-probe \
  scripts/check-compiler-probe-locks.test.sh
git commit -m "test: lock downstream Cargo probes"
```

---

### Task 3: Dependency-Bump, Release, and Required-CI Wiring

**Files:**
- Modify: `scripts/post-release-bump.sh:38-44,263-309`
- Modify: `scripts/post-release-bump.test.sh:1-227`
- Modify: `justfile:408-468,522-524`
- Modify: `.github/workflows/ci.yml:390-412`
- Modify: `CHANGELOG.md:8-18`

**Interfaces:**
- Consumes: `check-compiler-probe-locks.sh`, its `--fix`, and the two exact fixture paths from Task 2.
- Produces Just recipes `test-compiler-probe-locks`, `check-compiler-probe-locks`, and `realign-compiler-probe-locks`.
- Produces release helper `verify_compiler_probe_locks()` that runs locked/offline metadata for both fixture manifests.

- [ ] **Step 1: Extend release tests first**

Add pure-function expectations that `KNOWN_EXTRA_LOCKS` accepts:

```text
crates/rimap-audit/tests/fixtures/e0639-probe/Cargo.lock
crates/rimap-imap/tests/fixtures/e0639-probe/Cargo.lock
```

and still rejects an unknown `crates/demo/tests/fixtures/e0639-probe/Cargo.lock`.

Add a hermetic main-path case in a fresh temporary tree containing minimal root/oracle/fixture manifests, lockfiles, changelog, and fake executables at the front of `PATH`. Each fake appends its argv to `$CALL_LOG`. Fake `git` must answer the exact `rev-parse`, `ls-files`, `grep`, `show`, and `diff --name-only` calls used by `main`; fake `cargo` must allow `set-version`, `update`, and `metadata`; fake `just` must allow the realignment and parity recipes. Invoke `main v0.2.0` in a subshell.

Assert ordered log fragments:

```text
cargo set-version --workspace 0.2.1-dev
cargo update --workspace
just realign-fuzz-locks
just realign-compiler-probe-locks
cargo metadata --locked --offline --manifest-path crates/rimap-audit/tests/fixtures/e0639-probe/Cargo.toml --format-version 1
cargo metadata --locked --offline --manifest-path crates/rimap-imap/tests/fixtures/e0639-probe/Cargo.toml --format-version 1
just check-compiler-probe-locks
```

Assert both fixture lock paths occur in emitted `paths`, and assert the compiler-probe realignment occurs after workspace update but before locked/offline verification.

Run:

```bash
bash scripts/post-release-bump.test.sh
```

Expected: FAIL because `KNOWN_EXTRA_LOCKS`, orchestration, and verification do not yet include the fixtures.

- [ ] **Step 2: Wire fixture locks through post-release bump**

Set:

```bash
KNOWN_EXTRA_LOCKS="html-oracle/Cargo.lock \
crates/rimap-audit/tests/fixtures/e0639-probe/Cargo.lock \
crates/rimap-imap/tests/fixtures/e0639-probe/Cargo.lock"
```

Add:

```bash
verify_compiler_probe_locks() {
    local manifest
    for manifest in \
        crates/rimap-audit/tests/fixtures/e0639-probe/Cargo.toml \
        crates/rimap-imap/tests/fixtures/e0639-probe/Cargo.toml; do
        cargo metadata --locked --offline --manifest-path "$manifest" \
            --format-version 1 >/dev/null
    done
}
```

In `main`, call `just realign-compiler-probe-locks` immediately after `just realign-fuzz-locks`. In the gate section, call `verify_compiler_probe_locks` and `just check-compiler-probe-locks` after the root/oracle metadata checks and fuzz parity. Do not hardcode fixture lock paths in the emitted change set; existing `git diff --name-only HEAD` derivation must include them naturally.

Run:

```bash
bash scripts/post-release-bump.test.sh
```

Expected: all pure and hermetic main-path cases pass.

- [ ] **Step 3: Add Just recipes and make local CI depend on them**

Add beside the fuzz-lock recipes:

```just
# Unit-test the focused tracked-integration-test nested-Cargo guard.
test-compiler-probe-locks:
    ./scripts/check-compiler-probe-locks.test.sh

# Require reviewed, reachable fixture graphs and locked/offline nested checks.
check-compiler-probe-locks:
    ./scripts/check-compiler-probe-locks.sh

# Seed fixture locks from the root graph, prune, verify, and replace atomically.
realign-compiler-probe-locks:
    ./scripts/check-compiler-probe-locks.sh --fix
```

Add `test-compiler-probe-locks check-compiler-probe-locks` to the `ci:` dependency list. Do not add `realign-compiler-probe-locks` to CI because gates must not mutate the tree.

Run:

```bash
just test-compiler-probe-locks
just check-compiler-probe-locks
just test-post-release-bump
```

Expected: all pass.

- [ ] **Step 4: Add the guard to the required cargo-deny job**

Before the `cargo-deny-action` step, after the fuzz-lock steps, add:

```yaml
      - name: Unit-test locked compiler probes
        run: just test-compiler-probe-locks
      - name: Check locked compiler probes
        run: just check-compiler-probe-locks
```

Keep the existing `if: ${{ !cancelled() }}` on the audit action so a guard failure cannot mask the advisory result.

Run:

```bash
actionlint
zizmor .github/workflows/
```

Expected: both exit 0 with no findings.

- [ ] **Step 5: Add the changelog entry**

Append under `## [Unreleased]` / `### Changed`:

```markdown
- Exact-E0639 downstream compiler probes now copy committed fixture lockfiles
  and run Cargo with `--locked --offline`. A required focused guard keeps every
  tracked integration-test nested Cargo check and both fixture graphs pinned to
  the reviewed workspace lock. See #838 and ADR-0027.
```

- [ ] **Step 6: Run focused format, lint, and behavior checks**

Run:

```bash
just fmt
just fmt-check
just lint
just test-compiler-probe-locks
just check-compiler-probe-locks
just test-post-release-bump
cargo nextest run -p rimap-audit -E 'binary(non_exhaustive_e0639)'
cargo nextest run -p rimap-imap -E 'binary(non_exhaustive_e0639)'
```

Expected: every command exits 0, with exactly six E0639-binary tests passing across the two packages.

- [ ] **Step 7: Commit maintenance and CI wiring**

```bash
git add scripts/post-release-bump.sh scripts/post-release-bump.test.sh \
  justfile .github/workflows/ci.yml CHANGELOG.md
git commit -m "ci: enforce locked compiler probes"
```

---

### Task 4: Full Guardrail Proof

**Files:**
- Verify only: all files changed in Tasks 1-3

**Interfaces:**
- Consumes: all focused recipes and repository guardrails.
- Produces: evidence suitable for adversarial branch review and PR delivery.

- [ ] **Step 1: Re-run focused behavioral proof from a clean implementation state**

Run:

```bash
just test-compiler-probe-locks
just check-compiler-probe-locks
just test-post-release-bump
cargo nextest run -p rimap-audit -E 'binary(non_exhaustive_e0639)'
cargo nextest run -p rimap-imap -E 'binary(non_exhaustive_e0639)'
```

Expected: guard tests pass, exactly two real in-scope invocations are reported, post-release orchestration passes, and all six compiler-error tests pass.

- [ ] **Step 2: Verify workflow-specific gates**

Run:

```bash
actionlint
zizmor .github/workflows/
```

Expected: both exit 0 without warnings or findings.

- [ ] **Step 3: Run full local CI in the background**

Start `just ci` as the single repository background job and wait for its real exit status. Do not pipe, truncate, or add `|| true`.

Expected: `just ci` exits 0. If it fails, ingest the direct command output and current nextest JUnit file only when its mtime is newer than the run start, fix the source cause, rerun the smallest failing recipe, then rerun `just ci`.

- [ ] **Step 4: Review the final diff for clean cutover**

Confirm all of the following from the actual diff:

```text
both old formatted-manifest builders removed
both obsolete sibling crate-root helpers removed
both harnesses copy manifest and lock byte-for-byte
both Cargo builders carry --locked and --offline
both target directories stay inside the temporary roots
no online retry or generated fallback lock exists
both fixture locks are tracked and reachable subgraphs
release maintenance and required CI call shared Just recipes
no dependency or public API changed
```

- [ ] **Step 5: Commit only if verification produced a corrective diff**

If verification required code changes, commit that one logical correction with a Conventional Commit subject at most 72 characters. If the tree is already clean, create no empty commit.
