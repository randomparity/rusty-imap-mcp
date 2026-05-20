# Local Test Runtime Trim — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cut local commit/push hook compile cost and inner-loop test runtime by narrowing `--all-targets` to `--lib --bins` in two prek hooks and adding `just test-fast` (a nextest filter that skips the five heaviest test binaries).

**Architecture:** Configuration-only changes across three files (`.pre-commit-config.yaml`, `justfile`, `AGENTS.md`). No Rust code, test code, or CI workflow changes. Verification is empirical (timing + behavior observation) rather than via unit tests, because the artifacts being changed are themselves the build/test tooling.

**Tech Stack:** prek (pre-commit-in-Rust), cargo, cargo-nextest, just.

**Spec:** [`docs/superpowers/specs/2026-05-20-local-test-runtime-trim-design.md`](../specs/2026-05-20-local-test-runtime-trim-design.md). Read the spec before starting; the rationale for each flag and exclusion is there, not duplicated here.

**Branch:** Work continues on `docs/local-test-runtime-trim-spec` (the branch that holds the spec commit). The branch name predates the renamed scope; that's fine — rename at PR time if desired.

---

## Pre-flight check

Before starting, verify your workspace state matches the spec's assumptions.

- [ ] **Pre-flight 1: Confirm branch and clean tree**

Run:
```bash
git rev-parse --abbrev-ref HEAD
git status -s
```
Expected: branch is `docs/local-test-runtime-trim-spec`; working tree is clean (the spec commit `bec7b0e` is already on this branch).

- [ ] **Pre-flight 2: Confirm tooling is present**

Run:
```bash
command -v just cargo cargo-nextest prek
just --version && cargo --version && cargo nextest --version && prek --version
```
Expected: all four resolve and print versions. If `cargo-nextest` is missing, install with `cargo install --locked cargo-nextest`. If `prek` is missing, install per `justfile`'s `setup` target hints.

- [ ] **Pre-flight 3: Confirm the five heavy binaries actually exist**

Run:
```bash
cargo nextest list --workspace --locked --list-type binaries-only 2>&1 \
  | grep -E '::(dovecot|e2e|e2e_wire|e2e_wire_cancellation|proptest_html_lookalike)$'
```
Expected: exactly five lines:
```
rimap-content::proptest_html_lookalike
rimap-imap::dovecot
rimap-server::e2e
rimap-server::e2e_wire
rimap-server::e2e_wire_cancellation
```
If any are missing or renamed, STOP and revisit the spec — the filter expression in Task 1 assumes these names. Update the filter and the spec together if needed.

---

## Task 1: Add `just test-fast` target

**Why first:** This is the headline win (91.9 s → 4.2 s warm) and has no dependency on the hook changes. Ships independently if the hook tasks slip.

**Files:**
- Modify: `justfile` (insert after the existing `test:` target, around line 189)

- [ ] **Step 1: Capture the baseline `just test` timing for the commit message**

Run:
```bash
{ /usr/bin/time -f "baseline just test: %e s" just test ; } 2>&1 | tail -3
```
Expected: a line like `baseline just test: 90-130 s` (warm cache). Record this number; it goes in the commit message as evidence.

If `just test` fails before producing a timing line (e.g., container daemon down), STOP and resolve the environment issue before continuing. The fast target's value claim relies on having a real baseline.

- [ ] **Step 2: Add the `test-fast` target to the justfile**

Open `justfile` and locate the existing `test` target (around line 187-189):
```just
# Unit and fast tests (no Proton Bridge).
test: prune-containers
    cargo nextest run --workspace --locked --no-tests=pass
```

Insert this new target immediately after it (before `# Verify the MSRV toolchain still builds and tests the workspace.`):
```just
# Inner-loop unit tests. Skips the five heaviest test binaries
# (dovecot integration, e2e/e2e_wire MCP suites, and the slow HTML
# lookalike proptest). Use this between `cargo check` cycles during
# inner-loop iteration. Before pushing, run `just test` (or `just ci`)
# for the full sweep. See
# docs/superpowers/specs/2026-05-20-local-test-runtime-trim-design.md.
test-fast:
    cargo nextest run --workspace --locked --no-tests=pass \
        -E 'not (binary(dovecot) | binary(e2e) | binary(e2e_wire) | binary(e2e_wire_cancellation) | binary(proptest_html_lookalike))'
```

Note: `test-fast` deliberately does **not** depend on `prune-containers` — the fast tier does not spawn containers, so the prune step is unnecessary work.

- [ ] **Step 3: Verify the just target parses**

Run:
```bash
just --list
```
Expected: `test-fast` appears in the listing with its first-line comment as the description.

- [ ] **Step 4: Verify the filter selects the expected test count**

Run:
```bash
cargo nextest list --workspace --locked \
  -E 'not (binary(dovecot) | binary(e2e) | binary(e2e_wire) | binary(e2e_wire_cancellation) | binary(proptest_html_lookalike))' 2>&1 \
  | grep -c "::"
```
Expected: `1381` (or within ±20 if the test count has shifted since the spec was written; if it's drastically different, investigate before continuing).

- [ ] **Step 5: Run `just test-fast` and time it**

Run:
```bash
{ /usr/bin/time -f "just test-fast: %e s" just test-fast ; } 2>&1 | tail -3
```
Expected: all selected tests pass; total wall clock ≤ 10 s on a workstation, ≤ 30 s on a weak laptop. The line ends with `tests run: <N> passed, 0 skipped` where N is the count from Step 4.

If any test fails, STOP. A failure here is unrelated to this change (these tests already pass in `just test`); investigate as a separate bug before proceeding.

- [ ] **Step 6: Confirm the five excluded binaries did NOT run**

Run:
```bash
just test-fast 2>&1 | grep -E "(dovecot|e2e_wire|e2e_wire_cancellation|::e2e |proptest_html_lookalike)" || echo "filter working: no excluded binary names appeared"
```
Expected: prints `filter working: no excluded binary names appeared`. If the grep matches anything, the filter is broken — re-verify the syntax against the nextest documentation.

- [ ] **Step 7: Commit**

```bash
git add justfile
git commit -m "$(cat <<'EOF'
feat(just): add `test-fast` for inner-loop unit tests

Filters out the five heaviest nextest binaries (dovecot, e2e, e2e_wire,
e2e_wire_cancellation, proptest_html_lookalike) which collectively
account for ~97% of `just test` wall clock. Measured locally:
`just test` warm = ~92 s; `just test-fast` warm = ~4 s. All ~1380 unit
tests still run.

Container-backed integration suites and the slow HTML lookalike proptest
stay in `just test` and CI. No coverage lost; faster inner loop added.

See docs/superpowers/specs/2026-05-20-local-test-runtime-trim-design.md.
EOF
)"
```

---

## Task 2: Document `just test-fast` in AGENTS.md

**Why now:** Same logical change as Task 1; agents and human contributors discovering the command via documentation should find it the same day the target ships.

**Files:**
- Modify: `AGENTS.md` (the `## Development commands` code block, around line 49-62)

- [ ] **Step 1: Update the commands list in `AGENTS.md`**

Open `AGENTS.md` and locate the `## Development commands` section. The current block (lines 49-62) reads:

```markdown
```bash
just setup           # one-time: install tooling, MSRV toolchain, prek hooks
just check           # fast compile-check (inner loop)
just fmt             # format the workspace in place
just fmt-check       # verify formatting without modifying
just lint            # cargo clippy with -D warnings
just test            # cargo nextest run --workspace
just test-msrv       # same as `test` but on the MSRV toolchain (1.88.0)
just deny            # cargo deny check (advisories, licenses, bans, sources)
just ci              # full local-CI equivalent — run this before pushing
just hooks           # re-run prek on all files
just test-injection  # adversarial email corpus (content pipeline, future)
just test-integration  # Proton Bridge integration tests (gated, future)
```
```

Replace the `just test` line and surrounding lines so the block reads:

```markdown
```bash
just setup           # one-time: install tooling, MSRV toolchain, prek hooks
just check           # fast compile-check (inner loop)
just fmt             # format the workspace in place
just fmt-check       # verify formatting without modifying
just lint            # cargo clippy with -D warnings
just test-fast       # inner-loop unit tests (~4 s; skips heavy integration/proptest)
just test            # full nextest workspace — run before pushing
just test-msrv       # same as `test` but on the MSRV toolchain (1.88.0)
just deny            # cargo deny check (advisories, licenses, bans, sources)
just ci              # full local-CI equivalent — run this before pushing
just hooks           # re-run prek on all files
just test-injection  # adversarial email corpus (content pipeline, future)
just test-integration  # Proton Bridge integration tests (gated, future)
```
```

The changes:
1. Insert a new line `just test-fast       # inner-loop unit tests (~4 s; skips heavy integration/proptest)` immediately before the `just test` line.
2. Change the comment on `just test` from `# cargo nextest run --workspace` to `# full nextest workspace — run before pushing`.

Leave the rest of the block (including the `**If just ci passes locally, CI will pass.**` line above it) unchanged.

- [ ] **Step 2: Verify the edit landed where intended**

Run:
```bash
grep -n "test-fast\|just test " AGENTS.md | head -5
```
Expected (line numbers approximate):
```
55:just test-fast       # inner-loop unit tests (~4 s; skips heavy integration/proptest)
56:just test            # full nextest workspace — run before pushing
```

- [ ] **Step 3: Verify typos hook is still happy**

Run:
```bash
typos AGENTS.md
```
Expected: no output (exit 0). If typos flags anything in the new line, adjust wording until clean.

- [ ] **Step 4: Commit**

```bash
git add AGENTS.md
git commit -m "$(cat <<'EOF'
docs: list `just test-fast` in AGENTS.md commands

Adds the new fast-tier test target to the documented inner-loop commands
and clarifies that `just test` is the full sweep to run before pushing.
EOF
)"
```

---

## Task 3: Narrow pre-commit clippy from `--all-targets` to `--lib --bins`

**Why next:** Pre-commit fires more often than pre-push; landing this first gives the most immediate per-commit feedback that the change is working as intended.

**Files:**
- Modify: `.pre-commit-config.yaml` (the `cargo-clippy` hook entry, around line 56-62)

- [ ] **Step 1: Capture the baseline warm clippy timing**

Run:
```bash
# Warm the cache first
cargo clippy --workspace --all-targets --locked -- -D warnings > /dev/null 2>&1
# Then measure
{ /usr/bin/time -f "baseline pre-commit clippy (warm): %e s" cargo clippy --workspace --all-targets --locked -- -D warnings ; } 2>&1 | tail -3
```
Expected: ~2-5 s on this hardware. Record for the commit message.

- [ ] **Step 2: Edit `.pre-commit-config.yaml`**

Open `.pre-commit-config.yaml`. The current `cargo-clippy` hook (lines 56-62) reads:

```yaml
      - id: cargo-clippy
        name: cargo clippy
        entry: cargo clippy --workspace --all-targets --locked -- -D warnings
        language: system
        types: [rust]
        pass_filenames: false
        stages: [pre-commit]
```

Change the `entry:` line so the block reads:

```yaml
      - id: cargo-clippy
        name: cargo clippy
        entry: cargo clippy --workspace --lib --bins --locked -- -D warnings
        language: system
        types: [rust]
        pass_filenames: false
        stages: [pre-commit]
```

Only `--all-targets` becomes `--lib --bins`. Do **not** change `--locked`, `--workspace`, `-D warnings`, or any other field.

- [ ] **Step 3: Verify the new entry behaves identically on a clean tree**

Run:
```bash
prek run cargo-clippy --all-files
```
Expected: prints `Passed` (or `cargo clippy.................................................................Passed`). If it prints `Failed`, the workspace has a real lint error in lib/bin code; resolve before continuing — this would have failed under the old configuration too.

- [ ] **Step 4: Measure the new warm timing**

Run:
```bash
# Warm
cargo clippy --workspace --lib --bins --locked -- -D warnings > /dev/null 2>&1
# Measure
{ /usr/bin/time -f "narrowed pre-commit clippy (warm): %e s" cargo clippy --workspace --lib --bins --locked -- -D warnings ; } 2>&1 | tail -3
```
Expected: ~1-3 s. Should be at least as fast as the baseline (often noticeably faster on warm-repeat).

- [ ] **Step 5: Confirm the hook still rejects a deliberate lint regression**

In a separate scratch space (do **not** commit this), introduce a temporary clippy warning to a non-test file. For example, append to the end of `crates/rimap-server/src/lib.rs`:

```rust
#[allow(dead_code)]
fn _scratch_unused() { let _x = 5_u8 as u32; }
```

(`unnecessary_cast` is a clippy default-warn lint.)

Run:
```bash
prek run cargo-clippy --all-files
```
Expected: `Failed` with a clippy diagnostic mentioning `unnecessary_cast` (or similar). Then revert the scratch edit:

```bash
git checkout -- crates/rimap-server/src/lib.rs
prek run cargo-clippy --all-files
```
Expected on second run: `Passed`.

If the deliberate regression did **not** fail the hook, the `--lib --bins` scope is wrong; STOP and verify the file you edited is reachable from `--lib` or `--bins` (it must be one of those — that's the whole point).

- [ ] **Step 6: Commit**

```bash
git add .pre-commit-config.yaml
git commit -m "$(cat <<'EOF'
chore(prek): narrow pre-commit clippy to --lib --bins

Drops --all-targets from the pre-commit clippy hook. Test/example/bench
compile + lint enforcement moves to CI (already runs the full
--all-features --all-targets clippy on every push and PR).

Warm-repeat: ~2.5 s → ~1.4 s on this hardware. Cold target/: ~23 s →
~20 s. Proportionally larger improvements expected on lower-core-count
laptops.

See docs/superpowers/specs/2026-05-20-local-test-runtime-trim-design.md.
EOF
)"
```

---

## Task 4: Narrow pre-push check from `--all-targets` to `--lib --bins`

**Files:**
- Modify: `.pre-commit-config.yaml` (the `cargo-check` hook, around lines 129-135)

- [ ] **Step 1: Capture the baseline warm timing (post-clippy)**

Run:
```bash
# Pre-commit clippy --lib --bins (from Task 3) has already run, so target/
# is in the right warm state for the post-clippy pre-push scenario.
{ /usr/bin/time -f "baseline pre-push check (warm post-clippy): %e s" cargo check --workspace --all-targets --locked ; } 2>&1 | tail -3
```
Expected: ~1-4 s. Record for the commit message.

- [ ] **Step 2: Edit `.pre-commit-config.yaml`**

Open `.pre-commit-config.yaml`. The current `cargo-check` hook (lines 129-135) reads:

```yaml
      - id: cargo-check
        name: cargo check --workspace --all-targets --locked
        entry: cargo check --workspace --all-targets --locked
        language: system
        always_run: true
        pass_filenames: false
        stages: [pre-push]
```

Change the `name:` and `entry:` lines so the block reads:

```yaml
      - id: cargo-check
        name: cargo check --workspace --lib --bins --locked
        entry: cargo check --workspace --lib --bins --locked
        language: system
        always_run: true
        pass_filenames: false
        stages: [pre-push]
```

Both `name:` and `entry:` are updated so the hook's reported name matches what it actually runs. Do **not** change `language:`, `always_run:`, `pass_filenames:`, or `stages:` — those preserve the prior spec's invariants (the `always_run: true` decision is explained in the prior pre-push-hook-trim spec; don't revisit it here).

- [ ] **Step 3: Verify the new entry passes**

Run:
```bash
prek run cargo-check --hook-stage pre-push --all-files
```
Expected: `cargo check --workspace --lib --bins --locked....................Passed`. If `Failed`, a real compile error exists in lib/bin code; resolve before continuing.

- [ ] **Step 4: Confirm `--locked` still rejects stale lockfile**

Make a temporary edit that perturbs `Cargo.lock`. The safest way is to add a no-op `[patch]` entry to `Cargo.toml` that forces a lockfile recompute. **Skip this step if you're not confident you can revert cleanly** — the hook's `--locked` behavior was already exercised by the prior pre-push-hook-trim spec and hasn't changed here.

If you do test:
```bash
# Save current Cargo.lock
cp Cargo.lock /tmp/Cargo.lock.bak
# Hand-edit Cargo.lock to perturb the [[package]] version of any dep slightly
# (e.g., change one resolved version's checksum by one hex digit)
# Then:
prek run cargo-check --hook-stage pre-push --all-files
# Expected: Failed, with cargo's "the lock file ... needs to be updated" error
# Revert:
cp /tmp/Cargo.lock.bak Cargo.lock
rm /tmp/Cargo.lock.bak
prek run cargo-check --hook-stage pre-push --all-files
# Expected: Passed
```

- [ ] **Step 5: Measure the new warm timing**

Run:
```bash
{ /usr/bin/time -f "narrowed pre-push check (warm post-clippy): %e s" cargo check --workspace --lib --bins --locked ; } 2>&1 | tail -3
```
Expected: ~1-3 s. Should be at least as fast as the baseline.

- [ ] **Step 6: Commit**

```bash
git add .pre-commit-config.yaml
git commit -m "$(cat <<'EOF'
chore(prek): narrow pre-push cargo check to --lib --bins

Drops --all-targets from the pre-push cargo-check hook to match Task 3's
pre-commit clippy change. Test-target compile errors continue to be
caught by `just test` locally and by CI on every push.

Warm post-clippy: ~1.1 s → ~2 s (within noise). Cold target/: ~22 s →
~19 s. Bigger relative win expected on weaker hardware.

See docs/superpowers/specs/2026-05-20-local-test-runtime-trim-design.md.
EOF
)"
```

---

## Task 5: End-to-end verification and PR

**Why last:** Confirms the three landed commits together still produce a clean local state, and that `just ci` and the prek hook bundle both pass before the push.

**Files:** none modified in this task; all work is verification.

- [ ] **Step 1: Confirm the branch state**

Run:
```bash
git log --oneline main..HEAD
```
Expected: four commits on top of `main`:
1. `bec7b0e docs: spec for local test-runtime trim (hook scope + just test-fast)` (already in place)
2. `<sha> feat(just): add `test-fast` for inner-loop unit tests` (Task 1)
3. `<sha> docs: list `just test-fast` in AGENTS.md commands` (Task 2)
4. `<sha> chore(prek): narrow pre-commit clippy to --lib --bins` (Task 3)
5. `<sha> chore(prek): narrow pre-push cargo check to --lib --bins` (Task 4)

If the count is off, list and reconcile before continuing.

- [ ] **Step 2: Run `prek run --all-files` to confirm every hook passes**

Run:
```bash
prek run --all-files
```
Expected: every hook reports `Passed`. This covers pre-commit hooks against the whole tree (not just changed files), so it's the strongest local signal that the hook changes didn't break anything.

If any hook fails, fix the underlying issue. If `cargo-clippy` fails specifically on test code, that's expected (it now lints only lib/bin); confirm by running:
```bash
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
```
This is what CI runs. If CI's flags also fail, the test code has a real lint regression — fix it as a separate commit before merging.

- [ ] **Step 3: Run `just test-fast` once more and time it**

Run:
```bash
{ /usr/bin/time -f "final just test-fast: %e s" just test-fast ; } 2>&1 | tail -3
```
Expected: ≤ 10 s on this hardware, all tests pass.

- [ ] **Step 4: Run `just test` to confirm full coverage still works**

Run:
```bash
{ /usr/bin/time -f "final just test: %e s" just test ; } 2>&1 | tail -3
```
Expected: ~90-130 s warm, 1438 tests pass. Confirms the five "skipped in fast" binaries still run under `just test` itself.

- [ ] **Step 5: Push the branch**

```bash
git push -u origin docs/local-test-runtime-trim-spec
```
If the push hangs or drops mid-transfer (the very symptom this spec addresses), apply the documented escape hatch:
```bash
GIT_SSH_COMMAND='ssh -o ServerAliveInterval=15 -o ServerAliveCountMax=20' git push -u origin docs/local-test-runtime-trim-spec
```
Note this incident in the PR description so future readers see the cold-laptop case in the wild.

- [ ] **Step 6: Open the PR**

Use the GitHub CLI:
```bash
gh pr create --title "Trim local test runtime: hook scope + just test-fast" --body "$(cat <<'EOF'
## Summary
- Narrows pre-commit clippy and pre-push cargo check from `--workspace --all-targets --locked` to `--workspace --lib --bins --locked`. Test-target lint/compile enforcement moves to CI.
- Adds `just test-fast`: a nextest filter that runs ~1380 unit tests in ~4 s (versus ~92 s for `just test`), skipping the five heaviest binaries (dovecot, e2e, e2e_wire, e2e_wire_cancellation, proptest_html_lookalike).
- Documents the new command in AGENTS.md.

## Why
Local hook + test runtime had grown past the SSH idle window on cold target/ and past contributor patience on warm. Builds on (does not replace) the prior pre-push-hook-trim spec. See `docs/superpowers/specs/2026-05-20-local-test-runtime-trim-design.md` for full measurement table and rationale.

## Test plan
- [x] `prek run --all-files` passes
- [x] `just test-fast` runs and finishes in ≤ 10 s
- [x] `just test` still runs the full 1438-test sweep
- [x] CI runs `cargo clippy --workspace --all-targets --all-features --locked` (unchanged) on every push and PR, so test-code lint regressions are still caught before merge
- [x] Pre-commit clippy still rejects a deliberate `unnecessary_cast` regression in lib code
- [x] Pre-push cargo check still rejects a deliberate compile error in lib code

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 7: Wait for CI and address any failures**

CI runs the full `--all-targets --all-features` clippy and the full nextest workspace plus MSRV plus mcp-conformance. If anything fails, treat it as a pre-existing issue uncovered by the broader CI sweep (this change does not modify any code that CI tests). Resolve in this PR or split into a follow-up before merging.

---

## Out of scope reminders (do NOT do these in this plan)

- Do **not** touch `.github/workflows/ci.yml`. CI keeps the full `--all-targets --all-features` sweep as the safety net.
- Do **not** change `.config/nextest.toml`. The filter is at the call site in `justfile`.
- Do **not** add or modify any `.rs` file. No test code refactor.
- Do **not** install or configure `sccache`, `mold`, or any other build accelerator. Future spec if needed.
- Do **not** touch `crates/rimap-server/src/mcp/fuzz_oracle.rs` or the `include_bytes!` schema path. Out-of-scope flag in the spec.
- Do **not** trim or remove `just test-msrv`. Coverage decision, out of scope.

## If something goes wrong

- **`prek run cargo-clippy --all-files` fails after Task 3 edit:** Either there's a real lint error in lib/bin code (fix it, commit as a separate fix), or the YAML edit broke the hook structure (re-read the file, verify it's still valid YAML with `yq . .pre-commit-config.yaml` or `python -c 'import yaml; yaml.safe_load(open(".pre-commit-config.yaml"))'`).
- **`just test-fast` selects zero tests or fails to parse:** The nextest filter syntax may have changed. Run `cargo nextest list --workspace --locked -E 'binary(dovecot)'` as a smoke test of the `binary()` predicate. If even that fails, the cargo-nextest version is incompatible — check `cargo nextest --version` against what's documented.
- **A test that passed under `just test` fails under `just test-fast`:** The test depends on side effects from one of the excluded binaries. Investigate the dependency before working around it; if the dependency is real, the test belongs in the excluded set's surface and the filter needs adjustment.
- **Push hangs on Step 5 of Task 5:** Expected on cold laptops; use the documented `GIT_SSH_COMMAND` keepalive (per the `project-push-ssh-keepalive` memory). Note in the PR description.
