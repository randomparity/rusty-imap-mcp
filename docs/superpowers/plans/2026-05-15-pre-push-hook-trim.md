# Pre-push Hook Trim Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the slow `just test` step in the `pre-push` stage of `.pre-commit-config.yaml` with `cargo check --workspace --all-targets --locked`, so `git push` completes under github.com's ~30s SSH idle window and stops silently dropping ref transfers.

**Architecture:** Single-file edit to `.pre-commit-config.yaml`. The existing `cargo-nextest` hook becomes a `cargo-check` hook with the same `pre-push` stage, no Rust-type filter (`always_run: true`) so dependency-only / lockfile-only pushes also get gated. `cargo-deny check advisories bans` stays unchanged. No new files; no `just` target changes.

**Tech Stack:** prek (pre-commit-in-Rust), `.pre-commit-config.yaml`, cargo. Manual verification only — no automated regression tests for the hook itself.

**Spec:** [`docs/superpowers/specs/2026-05-15-pre-push-hook-trim-design.md`](../specs/2026-05-15-pre-push-hook-trim-design.md)

---

## File Structure

**Modify:**
- `.pre-commit-config.yaml` — swap one hook entry (line ~127-133 in the current file)

**No other repo changes.** The `project-push-ssh-keepalive` auto-memory gets a session-local "Resolved by" update *after* the commit lands; that lives outside the repo.

---

## Task 0: Pre-flight — Confirm current hook shape

**Files:** none (verification only)

**Context:** The plan touches one block of `.pre-commit-config.yaml`. This task pins the current contents so the edit in Task 1 targets exactly what the spec describes; if the file has drifted, halt rather than guess.

- [ ] **Step 1: Confirm the cargo-nextest hook is on the `pre-push` stage today**

Run:
```bash
grep -n -B1 -A6 "id: cargo-nextest" .pre-commit-config.yaml
```

Expected output (the exact bytes the edit replaces):

```
      - id: cargo-nextest
        name: just test (prune stale containers + cargo nextest)
        entry: just test
        language: system
        types: [rust]
        pass_filenames: false
        stages: [pre-push]
```

If any of those seven lines differ, halt. The spec assumes this block; an edited or moved hook breaks the assumption.

- [ ] **Step 2: Confirm the cargo-deny hook is also on `pre-push` and unchanged by this plan**

Run:
```bash
grep -n -B1 -A4 "id: cargo-deny" .pre-commit-config.yaml
```

Expected: the existing `cargo-deny` hook entry. This task will NOT modify it; the grep is just a snapshot.

- [ ] **Step 3: Confirm prek is installed and the working tree is clean**

Run:
```bash
prek --version && git status --short
```

Expected: a prek version line, and an empty git status (no uncommitted changes in the working tree). If `prek` is not found, install it per the project setup notes (`brew install prek` on macOS, or `cargo install --locked prek`). If the working tree has uncommitted changes, commit or stash them before starting Task 1.

- [ ] **Step 4: No commit. Move to Task 1.**

---

## Task 1: Replace the cargo-nextest pre-push hook with cargo-check

**Files:**
- Modify: `.pre-commit-config.yaml` (one block, ~7 lines)

The edit swaps `just test` for `cargo check --workspace --all-targets --locked` and replaces the `types: [rust]` file filter with `always_run: true` so dependency-only and lockfile-only pushes still trigger the hook (this is the regression Codex caught in adversarial review — `Cargo.toml` and `Cargo.lock` are not prek's `rust` type, so the `--locked` stale-lockfile check would otherwise be silently skipped).

- [ ] **Step 1: Make the edit**

Find this block in `.pre-commit-config.yaml`:

```yaml
      - id: cargo-nextest
        name: just test (prune stale containers + cargo nextest)
        entry: just test
        language: system
        types: [rust]
        pass_filenames: false
        stages: [pre-push]
```

Replace it with:

```yaml
      - id: cargo-check
        name: cargo check --workspace --all-targets --locked
        entry: cargo check --workspace --all-targets --locked
        language: system
        always_run: true
        pass_filenames: false
        stages: [pre-push]
```

The four lines that changed: `id`, `name`, `entry`, and `types: [rust]` → `always_run: true`. `language`, `pass_filenames`, and `stages` are unchanged.

- [ ] **Step 2: Verify the YAML still parses**

Run:
```bash
prek run --hook-stage pre-push --help >/dev/null 2>&1 && echo "OK: prek parsed config"
```

Expected: `OK: prek parsed config`. If prek errors with a YAML or schema complaint, re-check the edit for indentation drift (this file uses 2-space indents under `hooks:`).

- [ ] **Step 3: Run the new hook on the current branch's HEAD to prove it executes**

Run:
```bash
prek run cargo-check --hook-stage pre-push --all-files
```

Expected: `cargo check --workspace --all-targets --locked` runs and exits 0 (the workspace is clean at HEAD). Wall-time should be roughly the cargo-check duration (~5s on warm cache).

If the hook id `cargo-check` isn't found, prek may have cached the old hooks list — run `prek clean` and retry.

- [ ] **Step 4: Run the unchanged cargo-deny hook for comparison**

Run:
```bash
prek run cargo-deny --hook-stage pre-push --all-files
```

Expected: `cargo deny check advisories bans` runs and exits 0. This confirms the cargo-deny entry was not disturbed by the YAML edit.

- [ ] **Step 5: Commit**

```bash
git add .pre-commit-config.yaml
git commit -m "$(cat <<'EOF'
chore(prek): trim pre-push hook from nextest to cargo check

Replaces `just test` (cargo-nextest workspace ~25-60s) with
`cargo check --workspace --all-targets --locked` (~5s) at the
pre-push stage so git push completes under github.com's ~30s
SSH idle window. Tests move entirely to CI; pre-push retains a
fast compile+lockfile gate plus the existing cargo-deny
advisory check.

`always_run: true` (instead of `types: [rust]`) ensures
Cargo.toml / Cargo.lock-only pushes still trigger the
--locked check.
EOF
)"
```

Verify the commit landed:

```bash
git log --oneline -1
```

Expected: the commit subject above shows on the latest line.

---

## Task 2: Manual verification — happy path (compile-clean push)

**Files:** none (live verification)

**Context:** The hook itself is the test. Task 2 verifies the everyday case: a trivial commit pushes through without the `GIT_SSH_COMMAND` keepalive workaround.

- [ ] **Step 1: Create a trivial probe commit on a throwaway branch**

```bash
git checkout -b verify/pre-push-trim
echo "# Pre-push trim verification probe ($(date -u +%FT%TZ))" >> .gitignore
# (.gitignore is a low-risk file; we'll revert this branch entirely after)
git add .gitignore
git commit -m "test: pre-push trim verification probe (will be deleted)"
```

- [ ] **Step 2: Push WITHOUT the keepalive workaround**

```bash
git push -u origin verify/pre-push-trim
```

Expected:
- pre-push hook runs and prints `cargo check` + `cargo deny` lines, both Passed
- the push completes with a real ref-transfer summary, e.g. `To github.com:randomparity/rusty-imap-mcp.git ... verify/pre-push-trim -> verify/pre-push-trim`
- total wall-time well under 30s

Verify the ref reached origin (per the `project-push-ssh-keepalive` memory: exit-0 is not sufficient evidence):

```bash
git ls-remote --heads origin verify/pre-push-trim
```

Expected: one line with the probe commit's SHA. If this returns empty, the push silently dropped the ref — Task 1's fix did not solve the problem (or your network/SSH conditions are exceptional). Halt and investigate before continuing.

- [ ] **Step 3: Clean up the probe branch**

```bash
git checkout feature/issue-266-mcp-fuzzing
git branch -D verify/pre-push-trim
git push origin --delete verify/pre-push-trim
```

Expected: branch removed locally and on origin. No commit; the probe branch was throwaway.

---

## Task 3: Manual verification — compile-fail rejection

**Files:** none (live verification — uses a temporary local edit, never committed)

**Context:** Prove that the new hook actually catches compile-fail. This is what makes pre-push a meaningful gate.

- [ ] **Step 1: Introduce a deliberate compile error in a throwaway file**

Edit `crates/rimap-server/src/lib.rs` (or whichever file is open):

Add a single line near the top after the existing imports:

```rust
const DELIBERATE_ERROR: u32 = "not a number";
```

This is a type-mismatch error that `cargo check` will reject.

- [ ] **Step 2: Stage the change but DO NOT commit**

```bash
git add crates/rimap-server/src/lib.rs
```

- [ ] **Step 3: Run the hook directly to confirm rejection**

```bash
prek run cargo-check --hook-stage pre-push --all-files
```

Expected: the hook fails with non-zero exit; the output includes a Rust compile-error referencing `expected u32, found &str`. The push (if attempted) would be blocked.

- [ ] **Step 4: Revert the edit**

```bash
git restore --staged --worktree crates/rimap-server/src/lib.rs
```

Verify:

```bash
git status --short crates/rimap-server/src/lib.rs
```

Expected: empty (file is back to the committed state).

- [ ] **Step 5: No commit.**

---

## Task 4: Manual verification — stale-lockfile rejection

**Files:** none (live verification — uses a temporary local edit, never committed)

**Context:** Pin that the `--locked` flag catches `Cargo.lock` drift. This is the gate the old `just test` arguably had (nextest also uses `--locked`); we want to make sure we didn't lose it.

- [ ] **Step 1: Hand-edit `Cargo.lock` to introduce a fake mismatch**

The simplest reproducible drift: find a `version = "x.y.z"` line for a dep that's not used in this workspace and bump its patch number. Pick any third-party crate that appears in `Cargo.lock`. For example:

```bash
# Find the current line
grep -n -m 1 "^version = " Cargo.lock | head -1
```

Then edit `Cargo.lock` by hand (the file is normally generated, so just bump a digit in any non-workspace `version = "..."` field — e.g., change `version = "1.0.0"` to `version = "1.0.999"`). Save.

- [ ] **Step 2: Run the hook**

```bash
prek run cargo-check --hook-stage pre-push --all-files
```

Expected: the hook fails. The error message includes "the lock file ... needs to be updated but --locked was passed to prevent this" (exact wording varies by cargo version).

- [ ] **Step 3: Restore Cargo.lock from the repo**

```bash
git restore Cargo.lock
```

Verify:

```bash
git diff Cargo.lock
```

Expected: empty (no diff). Cargo.lock matches HEAD.

- [ ] **Step 4: No commit.**

---

## Task 5: Manual verification — dependency-only push still triggers the hook

**Files:** none (live verification — pins the `always_run: true` regression Codex caught)

**Context:** This is the regression case from adversarial review. With `types: [rust]`, a push containing only `Cargo.toml` / `Cargo.lock` changes (e.g. a dep bump) would bypass the hook entirely. With `always_run: true`, the hook fires regardless. Task 5 proves the new behavior live.

- [ ] **Step 1: Create a throwaway branch with a Cargo.toml-only change**

```bash
git checkout -b verify/pre-push-dep-only
```

Pick a non-essential dep that already appears in a workspace `Cargo.toml`. For example, find a workspace member's `Cargo.toml` and add a harmless comment to bump it without changing semantics. Easiest: add a trailing newline.

```bash
# Find any workspace Cargo.toml and append a comment line
echo "# verify/pre-push-dep-only probe" >> crates/rimap-server/Cargo.toml
```

This touches a `Cargo.toml` without touching any `.rs` file — exactly the scenario where the old `types: [rust]` filter would skip the hook.

- [ ] **Step 2: Commit the change**

```bash
git add crates/rimap-server/Cargo.toml
git commit -m "test: pre-push always_run verification probe (will be deleted)"
```

- [ ] **Step 3: Push without the keepalive workaround**

```bash
git push -u origin verify/pre-push-dep-only
```

Expected: the pre-push hook output INCLUDES the `cargo-check` line (Passed). If `cargo-check` is missing or shown as `Skipped`, the `always_run: true` change did not take effect — halt and re-check the Task 1 edit.

The push itself should succeed; verify with:

```bash
git ls-remote --heads origin verify/pre-push-dep-only
```

Expected: one line with the probe commit's SHA.

- [ ] **Step 4: Clean up the probe branch and revert the local Cargo.toml change**

```bash
git checkout feature/issue-266-mcp-fuzzing
git branch -D verify/pre-push-dep-only
git push origin --delete verify/pre-push-dep-only
```

Verify the local Cargo.toml is back to its committed state:

```bash
git diff crates/rimap-server/Cargo.toml
```

Expected: empty.

---

## Task 6: Manual verification — cargo-deny still gates the push

**Files:** none (live verification — pins that the YAML edit didn't accidentally disturb the cargo-deny hook)

**Context:** Cargo-deny is the other half of the pre-push stage. Task 6 confirms it still runs and still rejects on the kind of violation it's meant to catch.

- [ ] **Step 1: Introduce a deny rule that flags an existing dep**

The simplest reproducible failure: temporarily add an explicit `[bans]` entry to `deny.toml` for a crate that's already in the dependency tree. Pick any indirect crate from `Cargo.lock` (e.g. `serde` would be excessive — use something like `cfg-if` if present).

```bash
# Find a likely candidate
grep -m1 "^name = \"cfg-if\"" Cargo.lock || echo "cfg-if not in tree; pick another"
```

If `cfg-if` is in tree, edit `deny.toml` to add (under whichever `[bans]` section exists, or create one):

```toml
[bans]
deny = [
    { name = "cfg-if" },
]
```

(Adjust the exact TOML structure to match the existing `deny.toml` schema — see the existing file before editing.)

- [ ] **Step 2: Run the hook**

```bash
prek run cargo-deny --hook-stage pre-push --all-files
```

Expected: the hook fails; output includes `cfg-if` (or whichever crate you chose) being explicitly banned.

- [ ] **Step 3: Revert deny.toml**

```bash
git restore deny.toml
```

Verify:

```bash
git diff deny.toml
```

Expected: empty.

- [ ] **Step 4: No commit.**

---

## Task 7: Update session memory and final verification

**Files:** none (memory update + final sanity check)

**Context:** The `project-push-ssh-keepalive` auto-memory becomes outdated once Task 1 lands. Update it to reference the fix so future Claude sessions know the `GIT_SSH_COMMAND` workaround is no longer the default path.

- [ ] **Step 1: Update the auto-memory file**

Edit `/Users/dave/.claude/projects/-Users-dave-src-rusty-imap-mcp/memory/project_push_ssh_keepalive.md` and add a stanza at the end:

```markdown
**Resolved by:** Commit landing this plan's Task 1 change to `.pre-commit-config.yaml` (see `docs/superpowers/specs/2026-05-15-pre-push-hook-trim-design.md` and the corresponding plan). Pre-push hook runtime now ≤10s on a warm cache; SSH keepalive no longer required for the everyday case. The `GIT_SSH_COMMAND` workaround stays documented for cold-cache edge cases (fresh clone, post-`cargo clean`, major dep bump) where worst-case cargo-check timing can still exceed the SSH idle window.
```

This is a local-only edit (auto-memory lives under `~/.claude/`, not in the repo). No git commit.

- [ ] **Step 2: Sanity-check the full pre-push flow one more time**

Create one more throwaway probe to confirm Tasks 1+2 stick:

```bash
git checkout -b verify/pre-push-final
echo "" >> README.md
git add README.md
git commit -m "test: final pre-push sanity probe (will be deleted)"
git push -u origin verify/pre-push-final
```

Expected:
- pre-push hook output shows `cargo-check ... Passed` and `cargo-deny ... Passed`
- the push prints a real ref-transfer summary
- `git ls-remote --heads origin verify/pre-push-final` returns one line

- [ ] **Step 3: Clean up**

```bash
git checkout feature/issue-266-mcp-fuzzing
git branch -D verify/pre-push-final
git push origin --delete verify/pre-push-final
git restore README.md
```

Verify clean state:

```bash
git status --short
git log --oneline -3
```

Expected:
- empty `git status` (no working-tree drift from the verification tasks)
- the Task 1 commit is on the latest line; the two preceding lines are whatever was on this branch before

---

## Spec coverage check

Mapping each spec section to a task:

- **Problem statement & SSH timeout** (spec lines 9-30) → addressed by Task 1, verified by Tasks 2 and 5
- **Root cause** (spec lines 32-49) → addressed by Task 1 (replacing the slow step)
- **Desired behavior** (spec lines 51-63) — `git push` works without keepalive (Tasks 2, 5, 7), compile/type-error gate (Task 3), cargo-deny still gates (Task 6), test-failure detection moves to CI (acceptance, not a task)
- **Approach: hook config change** (spec lines 65-85) → Task 1
- **Why `always_run`** (spec lines 87-99) → Task 1 explicit note + Task 5 live verification
- **Why `cargo check`, not nothing / clippy / all-features** (spec rationale sections) → captured in Task 1's commit message
- **`--locked` rationale** (spec section) → Task 4 verification
- **File layout** (spec — single config file) → matches plan's File Structure
- **Memory update** (spec section) → Task 7
- **Testing plan** (spec section) → Tasks 2-6
- **Risks: cold cache** (spec risk section) → not addressed by code; the spec acknowledges the workaround stays valid. Task 7's memory note captures this.

No spec gaps.
