# Issue #289: Mutation baselines for `rimap-server` + `rimap-imap` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Tracking issue:** [#289](https://github.com/randomparity/rusty-imap-mcp/issues/289). Unblocks [#287](https://github.com/randomparity/rusty-imap-mcp/issues/287) (Phase 2 close) and [#288](https://github.com/randomparity/rusty-imap-mcp/issues/288) (Phase 3 — OSS-Fuzz upstream submission). Closes [#245](https://github.com/randomparity/rusty-imap-mcp/issues/245) once landed.

**Goal:** Run `cargo mutants` against current `main` for both `rimap-server` and `rimap-imap`, kill or annotate every survivor in the security-critical paths still present on `main`, and extend `docs/superpowers/specs/test-strategy/mutation-baseline.md` with new sections for both crates following the `rimap-audit` / `rimap-authz` format.

**Architecture:** Issue #289's premise — that this work is blocked on cargo-mutants PR #613 reaching a tagged release — is **already satisfied** for this host: the local dev box runs Fedora Linux (not macOS), so the upstream `dirhelper` reap behavior that motivated `--in-place` is not present. We can therefore run `cargo mutants` directly with `--jobs N` (no `--in-place`) for ~5×–10× wall-clock savings vs. the macOS-safe path. The actual work is the same shape as Sprint B2 (#244) was for `rimap-audit` and `rimap-authz`: per-crate baseline → survivor classification → kill-with-test or annotate-as-known-equivalent → doc-table row → re-run to confirm zero unannotated misses in the named paths.

**File-scope correction (versus the issue body):** Issue #289 inherited its path lists from #245, which was written against `archive/daemon-experiment`. The current `main` no longer has `crates/rimap-server/src/daemon/`, `shim.rs`, or `mcp/posture_context.rs` — those paths were rolled back when the daemon experiment was reverted. The current security-critical surface in `rimap-server` is `mcp/{dispatch,audit_envelope,tool_catalog,tool_name,wire_validator,preinit,server,response,content,error,fuzz_oracle}.rs` plus `boot/*`; `tools/*` is best-effort (large handler surface, mostly thin wrappers over `rimap-imap`). `rimap-imap` paths from #289 are unchanged on `main`. This plan operates on the corrected surface and the executor notes the substitution in the final close-out comment on #289.

**Tech Stack:** `cargo-mutants` 27.0.0 (already installed via `just setup`), `cargo nextest` for the test suite, `serde_json`, `tracing`, Rust 1.88 (workspace MSRV). No new dependencies. No source code refactors expected beyond test-only additions and inline annotation comments.

**Spec reference:** [`docs/superpowers/specs/2026-04-30-test-strategy-improvements-design.md`](../specs/2026-04-30-test-strategy-improvements-design.md), Sprint B3 — Section 6. Done criteria mirror those of B2 (#244) per the existing `rimap-audit` / `rimap-authz` sections of `mutation-baseline.md`.

**Branch:** `feat/issue-289-mutation-baselines-server-imap` (cut from current `main` at the start of execution).

**Phase split (default = one PR):** Mutation cleanup PRs bundle cleanly when most survivors are stub-return, comparator-boundary, or match-guard kinds (per `feedback_mutation_cleanup_complexity_not_count`). The split decision happens **after** both baselines run and the survivor *kinds* are known, not on raw count. The default expectation is one PR; the explicit out-of-band split criteria are at the end of this plan.

**Per-PR convention reminder:** `cargo-mutants` does not parse inline `// cargo-mutants: known-equivalent — <reason>` annotations (per `feedback_cargo_mutants_annotations_are_doc_only`). After cleanup, `mutants.out/missed.txt` still lists annotated survivors. The source of truth is the row in `mutation-baseline.md`; the inline comment is for human readers. Verification language throughout this plan uses **"zero unannotated survivors"** — not "zero missed survivors."

---

## Pre-flight

Confirm the host, branch, and tooling are ready before consuming any of the multi-hour baseline runs.

- [ ] **Step 0: Verify branch and clean tree**

Run:
```bash
git branch --show-current
git status --short
```

Expected:
- Branch is `feat/issue-289-mutation-baselines-server-imap` (NOT `main`). If on `main`, run `git checkout -b feat/issue-289-mutation-baselines-server-imap`.
- `git status --short` is empty.

- [ ] **Step 1: Verify host is Linux (or otherwise free of the cargo-mutants `dirhelper` issue)**

Run:
```bash
uname -s
```

Expected: `Linux`. If `Darwin`, stop and either (a) install cargo-mutants 27.0.1+ once it ships containing [PR #613](https://github.com/sourcefrog/cargo-mutants/pull/613), or (b) run this plan on a Linux box. Do not proceed on macOS with cargo-mutants 27.0.0 and `--in-place` — the runbook predicts ~3.5h workspace runs and the dev-host RAM issue documented in `feedback_cargo_mutants_jobs_cap.md`.

- [ ] **Step 2: Verify cargo-mutants is installed and on PATH**

Run:
```bash
cargo mutants --version
```

Expected: `cargo-mutants 27.0.0` (or higher). If missing, run `cargo install --locked cargo-mutants`.

- [ ] **Step 3: Verify the named security-critical paths still exist**

Run:
```bash
for f in \
  crates/rimap-server/src/mcp/dispatch.rs \
  crates/rimap-server/src/mcp/audit_envelope.rs \
  crates/rimap-server/src/mcp/tool_catalog.rs \
  crates/rimap-server/src/mcp/tool_name.rs \
  crates/rimap-server/src/mcp/wire_validator.rs \
  crates/rimap-server/src/mcp/preinit.rs \
  crates/rimap-server/src/mcp/server.rs \
  crates/rimap-server/src/mcp/response.rs \
  crates/rimap-server/src/mcp/content.rs \
  crates/rimap-server/src/mcp/error.rs \
  crates/rimap-server/src/mcp/fuzz_oracle.rs \
  crates/rimap-imap/src/tls.rs \
  crates/rimap-imap/src/auth.rs \
  crates/rimap-imap/src/connection.rs \
  crates/rimap-imap/src/preflight.rs ; do
  test -f "$f" && echo "ok    $f" || echo "MISSING $f"
done
ls crates/rimap-server/src/boot/ crates/rimap-imap/src/ops/
```

Expected: every file prints `ok`. `boot/` lists `audit_init.rs`, `discovery.rs`, `logging.rs`, `mod.rs`, `registry.rs`. `ops/` lists `append.rs`, `delete.rs`, `expunge.rs`, `fetch.rs`, `folder_management.rs`, `folders.rs`, `mod.rs`, `move_message.rs`, `search.rs`, `store.rs`. Any `MISSING` line means the file scope drifted again — stop and re-grep `git log` for the rename before continuing.

Then verify `mcp/fuzz_oracle.rs` is feature-gated as expected (the default-features baseline run does not exercise it; a dedicated `--features fuzzing` pass in Task 2 Step 2.5 covers it):

```bash
grep -n 'cfg(feature = "fuzzing")' crates/rimap-server/src/mcp/mod.rs
```

Expected: prints the `#[cfg(feature = "fuzzing")] pub mod fuzz_oracle;` line. If absent, the gating has been removed and the dedicated `--features fuzzing` pass (Task 2 Step 2.5 below) can be folded back into the default run.

- [ ] **Step 4: Verify the workspace builds clean before any mutation runs**

Run:
```bash
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo nextest run --workspace --all-features --locked
```

Expected: both clean. A pre-existing failure here will be misread as a mutation kill in Task 1.

---

## Task 1: Run `cargo mutants` baseline on `rimap-server`

**Why:** No prior baseline exists for `rimap-server` in `mutation-baseline.md`. The footer reads "The other two trust-boundary crates (rimap-server, rimap-imap) get their own sections here when Sprint B3 lands." This task produces the raw survivor data that drives Tasks 2–4.

**Files:**
- No source files modified. Output goes to `mutants.out/` (gitignored) and `/tmp/`.

- [ ] **Step 1: Run the targeted mutation suite**

Run **directly** (not through `just mutants`) so we get `--jobs N` parallelism on Linux. The `just mutants` recipe forces `--in-place` which locks `--jobs 1` — that's the macOS workaround per `docs/security/cargo-mutants-runbook.md` and is unnecessary here:

```bash
cargo mutants --package rimap-server --no-shuffle --jobs 8 --timeout 60 \
  2>&1 | tee /tmp/mutants-rimap-server.log
```

Expected runtime: 30–90 minutes depending on disk + CPU contention. If the box has fewer than 8 physical cores or low memory headroom, dial `--jobs` down (rule of thumb: `--jobs ≤ physical_cores / 2`, because each worker spawns a full `cargo` invocation with its own compile + test). On the 48-core / 250 GiB reference host, `--jobs 8` is conservative and leaves headroom for IDE / rust-analyzer.

If the run aborts mid-way (e.g. SIGINT), no source files need restoration — without `--in-place` cargo-mutants works in `target/mutants/` temp trees, not the live source. Verify with `git status` (should be empty).

- [ ] **Step 2: Snapshot survivors by path bucket**

```bash
# fuzz_oracle.rs is feature-gated; its baseline runs separately in Task 2 Step 2.5.
HOT_PATHS='^crates/rimap-server/src/(mcp/(dispatch|audit_envelope|tool_catalog|tool_name|wire_validator|preinit|server|response|content|error)\.rs|boot/)'
COLD_PATHS='^crates/rimap-server/src/(cli/|tools/|main\.rs|lib\.rs)'

TOTAL=$(grep -cE "^crates/rimap-server/src/" mutants.out/missed.txt 2>/dev/null || echo 0)
HOT=$(grep -cE "$HOT_PATHS" mutants.out/missed.txt 2>/dev/null || echo 0)
COLD=$(grep -cE "$COLD_PATHS" mutants.out/missed.txt 2>/dev/null || echo 0)

echo "rimap-server total survivors: $TOTAL"
echo "rimap-server hot-path survivors (mcp/ named files + boot/): $HOT"
echo "rimap-server cold/best-effort survivors (cli/, tools/, main.rs, lib.rs): $COLD"

grep -E "$HOT_PATHS"  mutants.out/missed.txt > /tmp/rimap-server-hot-survivors.txt  || true
grep -E "$COLD_PATHS" mutants.out/missed.txt > /tmp/rimap-server-cold-survivors.txt || true
wc -l /tmp/rimap-server-hot-survivors.txt /tmp/rimap-server-cold-survivors.txt
echo "(rimap-server fuzz_oracle.rs survivors land in /tmp/rimap-server-fuzz-oracle-survivors.txt via Task 2 Step 2.5)"
```

- [ ] **Step 3: Classify by mutant *kind* (drives the split decision)**

Per `feedback_mutation_cleanup_complexity_not_count`, the bundle/split decision is mutant-kind-based, not count-based. Run:

```bash
echo "--- Stub-return mutants (cheap kills: 1-3 line tests) ---"
grep -cE "replace .* -> .* with (\(\)|0|1|false|true|String::new\(\)|\"xyzzy\"\.into\(\)|Default::default\(\)|Vec::new\(\))" /tmp/rimap-server-hot-survivors.txt
echo "--- Comparator-boundary mutants (cheap: boundary-value test or known-equivalent) ---"
grep -cE "replace [<>=!]+ with [<>=!]+" /tmp/rimap-server-hot-survivors.txt
echo "--- Match-guard / negation mutants (cheap: inverse-arm test) ---"
grep -cE "(delete ! in|replace match guard)" /tmp/rimap-server-hot-survivors.txt
echo "--- Arithmetic / logic mutants in algorithm semantics (potentially expensive) ---"
grep -cE "replace (\+|-|\*|/|&&|\|\|) with " /tmp/rimap-server-hot-survivors.txt
echo "--- Other ---"
wc -l /tmp/rimap-server-hot-survivors.txt
```

Record the four counts in a scratch note `/tmp/issue-289-classify.txt` (you'll use them again in Task 6 Step 3 for the rimap-imap classification and in the final split decision).

- [ ] **Step 4: No commit — `mutants.out/` is gitignored**

The two `/tmp/` files drive Tasks 2–4. Verify with `git status --short` — should print nothing.

---

## Task 2: Mutation cleanup — `rimap-server` `mcp/` hot-path survivors

**Why:** `mcp/` is the JSON-RPC dispatch boundary. Every mutation that changes observable behavior at this layer is a potential MCP-protocol compliance bug; mutations that produce indistinguishable output under the protocol contract are documentable equivalents. Spec §6 names this entire surface security-critical.

**Files:** iterative — driven by `/tmp/rimap-server-hot-survivors.txt` entries that match `mcp/*.rs`. Tests land in either:
- `crates/rimap-server/src/mcp/<file>.rs` `#[cfg(test)]` blocks (preferred for unit-level mutations — every file already has one; verify with `grep -l "^#\[cfg(test)\]" crates/rimap-server/src/mcp/*.rs`), or
- `crates/rimap-server/tests/*.rs` integration tests (use sparingly; only when the mutation requires a fully-wired dispatch pipeline).

Annotations land inline immediately above the mutated line. The doc-table row is added in Task 7.

- [ ] **Step 1: Walk the `mcp/` slice of the hot-survivor list**

```bash
grep -E "^crates/rimap-server/src/mcp/" /tmp/rimap-server-hot-survivors.txt > /tmp/rimap-server-mcp-survivors.txt
wc -l /tmp/rimap-server-mcp-survivors.txt
```

For each line in `/tmp/rimap-server-mcp-survivors.txt`:

  1. **Read the mutation.** Open the named file at the named line. Read enough surrounding code (typically the enclosing function and its callers via `rg`) to understand what changes under the mutation.

  2. **Decide: real gap, or equivalent mutant?** Most mutations expose real test gaps. Equivalent mutants are mathematically indistinguishable from the original under the function's contract — examples in `crates/rimap-content/src/html/mismatch.rs` and `crates/rimap-audit/src/writer/rotation.rs:188` model the bar.

  3. **If real gap, write a failing test in the file's `#[cfg(test)]` block.** Test must:
     - Assert the precise behavior the mutation breaks (not just "the function returns something").
     - Pass under unmutated code: `cargo nextest run --package rimap-server --all-features -- <test_name>`.
     - Fail under the mutation: hand-apply the mutation locally (`git stash` first for safety), confirm the new test fails, then `git stash pop`. If it passes under both, tighten the assertion.

  4. **If equivalent mutant, annotate.** Comment immediately above the mutated line:
     ```rust
     // cargo-mutants: known-equivalent — <one-line rationale>
     ```
     Rationale must explain *why* the mutation is observably indistinguishable. "It doesn't matter" is not a rationale; "the predicate flips only at `x == y`, where both arms set `min = x` to the same value" is.

  5. **Track the row for Task 7.** Append to `/tmp/rimap-server-baseline-rows.md` (create if absent), one markdown table row per annotated mutant in this format:
     ```
     | mcp/<file>.rs:LINE | <verbatim mutation description from missed.txt> | <rationale> | mcp/<file>.rs:ANNOTATION_LINE |
     ```

- [ ] **Step 2: Re-run mutation tests on `mcp/` only and verify**

```bash
cargo mutants --package rimap-server --no-shuffle --jobs 8 --timeout 60 \
  -F 'mcp/' 2>&1 | tee /tmp/mutants-rimap-server-mcp-reverify.log
grep -E "^crates/rimap-server/src/mcp/" mutants.out/missed.txt | tee /tmp/rimap-server-mcp-reverify-missed.txt
```

Expected: every formerly-missed mutation in `mcp/` is now either `caught` (test killed it) **or** has an inline `// cargo-mutants: known-equivalent` annotation. Annotated survivors still appear in `missed.txt` — that's expected per `feedback_cargo_mutants_annotations_are_doc_only`. Cross-check each line in the reverify output against `/tmp/rimap-server-baseline-rows.md`; any line not represented in the rows file is an unannotated survivor → return to Step 1 for that mutation.

Then run a second reverify with `--features fuzzing` filtered to `fuzz_oracle.rs` so the feature-gated module is exercised at the same gate:

```bash
cargo mutants --package rimap-server --features fuzzing \
  --no-shuffle --jobs 8 --timeout 60 -F 'fuzz_oracle\.rs' \
  2>&1 | tee /tmp/mutants-rimap-server-fuzz-oracle-reverify.log
grep -E "^crates/rimap-server/src/mcp/fuzz_oracle\.rs" mutants.out/missed.txt \
  | tee /tmp/rimap-server-fuzz-oracle-reverify-missed.txt
```

Its `missed.txt` slice must be empty or fully represented in `/tmp/rimap-server-baseline-rows.md` (the `(fuzzing)`-tagged rows from Step 2.5). Any line not in the rows file is an unannotated survivor → return to Step 2.5 for that mutation.

- [ ] **Step 2.5: Mutate the feature-gated `mcp/fuzz_oracle.rs`**

The file at `crates/rimap-server/src/mcp/fuzz_oracle.rs` is behind `#[cfg(feature = "fuzzing")]` in `crates/rimap-server/src/mcp/mod.rs:21`, so default-features `cargo mutants` runs never see it. Run a dedicated pass with the feature enabled:

```bash
cargo mutants --package rimap-server --features fuzzing \
  --no-shuffle --jobs 8 --timeout 60 \
  -F 'mcp/fuzz_oracle\.rs' \
  2>&1 | tee /tmp/mutants-rimap-server-fuzz-oracle.log

grep -E '^crates/rimap-server/src/mcp/fuzz_oracle\.rs' mutants.out/missed.txt \
  > /tmp/rimap-server-fuzz-oracle-survivors.txt || true
wc -l /tmp/rimap-server-fuzz-oracle-survivors.txt
```

For each survivor in `/tmp/rimap-server-fuzz-oracle-survivors.txt`, follow the same read → decide → kill-or-annotate → track-row procedure as Task 2 Step 1, but:

  - Tests must live in the `#[cfg(all(test, feature = "fuzzing"))]` block at the bottom of `fuzz_oracle.rs` (create the block if it doesn't exist; existing `mcp/*` files model the `#[cfg(test)]` pattern, just add the `feature = "fuzzing"` predicate so the tests compile only when the module does).
  - The cleanup commit must run the feature-gated test suite to verify: `cargo nextest run --package rimap-server --features fuzzing -- fuzz_oracle::`.
  - The doc-table row in `/tmp/rimap-server-baseline-rows.md` should be tagged with a leading `(fuzzing)` marker so Task 9 places it in the dedicated subsection rather than the main `mcp/` table:
    ```
    | (fuzzing) mcp/fuzz_oracle.rs:LINE | <mutation> | <rationale> | mcp/fuzz_oracle.rs:LINE |
    ```

- [ ] **Step 3: Verify workspace builds clean**

```bash
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo nextest run --package rimap-server --all-features --locked
```

Expected: both clean.

- [ ] **Step 4: Commit (one commit per file group, file-alphabetical)**

Group commits by mutated file so the history reads `audit_envelope`, `content`, `dispatch`, etc.:

```bash
# Example (audit_envelope; repeat for each file with survivors)
git add crates/rimap-server/src/mcp/audit_envelope.rs
git commit -m "$(cat <<'EOF'
test(rimap-server): close mutation gaps in mcp/audit_envelope.rs

Adds <N> tests covering specific cargo-mutants survivors uncovered by
the 2026-05-18 baseline (issue #289). <M> known-equivalent mutants
annotated inline with rationale; doc-table rows added in the
mutation-baseline.md update commit.

Refs: #289, #245, #287
EOF
)"
```

Skip any mcp/ file with zero hot survivors. Pure-annotation-only files (no new tests) still need a commit so the inline annotation lands.

---

## Task 3: Mutation cleanup — `rimap-server` `boot/` hot-path survivors

**Why:** `boot/` is where startup wires the IMAP connection registry, audit subsystem, logging, and discovery flow. Mutations that flip control-flow at startup are silent footguns: the daemon comes up "successfully" but in a degraded state. Spec §6 includes `boot/` in the named security-critical surface.

**Files:** iterative — driven by `/tmp/rimap-server-hot-survivors.txt` entries matching `boot/`. Tests land in either:
- `crates/rimap-server/src/boot/<file>.rs` `#[cfg(test)]` blocks, or
- `crates/rimap-server/tests/boot_*.rs` (search for the existing pattern with `find crates/rimap-server/tests -name 'boot*'`).

- [ ] **Step 1: Walk the `boot/` slice of the hot-survivor list**

```bash
grep -E "^crates/rimap-server/src/boot/" /tmp/rimap-server-hot-survivors.txt > /tmp/rimap-server-boot-survivors.txt
wc -l /tmp/rimap-server-boot-survivors.txt
```

For each line, follow the same procedure as Task 2 Step 1 (read → decide → kill or annotate → track row). One additional note specific to `boot/`:

  - **Async-init mutations** (`boot/audit_init.rs`, `boot/registry.rs`) often need a small `#[tokio::test(flavor = "current_thread")]` driver. Pattern from existing tests: build a `tempfile::tempdir()`-rooted minimal config, call the function under test, assert on the returned handle / state. Avoid spawning a real daemon — use the smallest scope that observes the mutation.

  - **`tracing` event mutations** in `boot/logging.rs` (level swaps, message format changes) follow the same "diagnostic-only" annotation pattern as `rimap-audit`'s `backup_exclude.rs` rows in `mutation-baseline.md:111-114`. Test only when a downstream consumer asserts on the event content.

- [ ] **Step 2: Re-run mutation tests on `boot/` only**

```bash
cargo mutants --package rimap-server --no-shuffle --jobs 8 --timeout 60 \
  -F 'boot/' 2>&1 | tee /tmp/mutants-rimap-server-boot-reverify.log
grep -E "^crates/rimap-server/src/boot/" mutants.out/missed.txt | tee /tmp/rimap-server-boot-reverify-missed.txt
```

Cross-check every line against `/tmp/rimap-server-baseline-rows.md` (now extended with `boot/` rows). Any line not in the rows file is an unannotated survivor → return to Step 1.

- [ ] **Step 3: Verify workspace builds clean**

```bash
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo nextest run --package rimap-server --all-features --locked
```

- [ ] **Step 4: Commit (one commit per boot/ file with survivors)**

```bash
# Example
git add crates/rimap-server/src/boot/audit_init.rs
git commit -m "$(cat <<'EOF'
test(rimap-server): close mutation gaps in boot/audit_init.rs

Adds <N> tests covering specific cargo-mutants survivors uncovered by
the 2026-05-18 baseline (issue #289). <M> known-equivalent mutants
annotated inline with rationale.

Refs: #289, #245, #287
EOF
)"
```

---

## Task 4: Mutation cleanup — `rimap-server` cold/best-effort paths

**Why:** `tools/`, `cli/`, `main.rs`, and `lib.rs` are best-effort per spec §6 — they're either thin wrappers over `rimap-imap` (handler crate) or CLI plumbing whose failure modes surface as visible exit codes (already tested via `cli/` integration tests). Per the spec's done criteria they must still produce zero unannotated survivors *in the document* — but the bar for "kill vs. annotate" is lower: "diagnostic-only stdout phrasing" is a sufficient rationale.

**Files:** iterative — driven by `/tmp/rimap-server-cold-survivors.txt`.

- [ ] **Step 1: Walk the cold-survivor list**

For each line:

  - **Changes observable output / API contract / exit code** → kill with a test (Task 2 Step 1.3 procedure).
  - **Equivalent under documented round-trip** → annotate inline + add doc-table row.
  - **Pure cosmetic** (tracing format, internal counter never asserted on, CLI stdout layout) → annotate inline + add doc-table row with rationale "diagnostic-only" or "cosmetic stdout, JSON schema unaffected." Model on `crates/rimap-content/src/bin/epvme_runner.rs` rows in `mutation-baseline.md:82-86`.

  - **`tools/<file>.rs` mutations that bottom out in `rimap-imap` calls** are particularly likely to be equivalent — if the `rimap-imap` call's return value is forwarded verbatim and the mutation only changes how `rimap-server` shapes the forward, an upstream `rimap-imap` test (added in Task 9) often suffices. Note the cross-crate coverage in the rationale: "test in rimap-imap covers semantic; this wrapper is forwarding-only."

- [ ] **Step 2: Re-run mutation tests on cold paths**

```bash
cargo mutants --package rimap-server --no-shuffle --jobs 8 --timeout 60 \
  -F '(cli/|tools/|main\.rs|lib\.rs)' 2>&1 | tee /tmp/mutants-rimap-server-cold-reverify.log
grep -E "^crates/rimap-server/src/(cli/|tools/|main\.rs|lib\.rs)" mutants.out/missed.txt \
  | tee /tmp/rimap-server-cold-reverify-missed.txt
```

Cross-check against `/tmp/rimap-server-baseline-rows.md`. Unannotated cold-path survivors do **not** fail the done criteria (the spec's "kill all unannotated" applies to hot paths only), but they should be either covered or documented — leaving an unannotated survivor with no rationale is an information gap, not a correctness issue.

- [ ] **Step 3: Verify workspace builds clean**

```bash
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo nextest run --package rimap-server --all-features --locked
```

- [ ] **Step 4: Commit (one commit covering cold paths)**

Single commit for the cold-path batch — the file count is too high to make per-file commits useful:

```bash
git add crates/rimap-server/src/cli/ crates/rimap-server/src/tools/ \
        crates/rimap-server/src/main.rs crates/rimap-server/src/lib.rs
git commit -m "$(cat <<'EOF'
test(rimap-server): close mutation gaps in cold-path modules (best-effort)

Adds <N> tests and <M> known-equivalent annotations across cli/, tools/,
main.rs, and lib.rs per spec §6 best-effort tier. Hot-path coverage
landed in prior commits this PR.

Refs: #289, #245, #287
EOF
)"
```

If no changes land in this task (i.e. cold paths were already clean), skip the commit and proceed.

---

## Task 5: Run `cargo mutants` baseline on `rimap-imap`

**Why:** Same reason as Task 1 — no prior `rimap-imap` section exists in `mutation-baseline.md`. Spec §6 names `tls.rs`, `auth.rs`, `connection.rs`, `ops/`, `preflight.rs` as security-critical (TLS handshake, authentication, connection lifetime, mailbox operations, pre-auth STARTTLS probe).

**Files:** none modified. Output to `mutants.out/` + `/tmp/`.

- [ ] **Step 1: Run the targeted mutation suite**

```bash
cargo mutants --package rimap-imap --no-shuffle --jobs 8 --timeout 60 \
  2>&1 | tee /tmp/mutants-rimap-imap.log
```

Expected runtime: 15–45 minutes (`rimap-imap` is smaller than `rimap-server` — roughly the size of `rimap-audit`, which took ~4 minutes at `--jobs 1` for 231 mutants; expect more at `--jobs 8` because of the test-suite overhead per mutant).

- [ ] **Step 2: Snapshot survivors by path bucket**

```bash
HOT_PATHS='^crates/rimap-imap/src/(tls\.rs|auth\.rs|connection\.rs|preflight\.rs|ops/)'
COLD_PATHS='^crates/rimap-imap/src/(error\.rs|types\.rs|time\.rs|special_use\.rs|lib\.rs)'

TOTAL=$(grep -cE "^crates/rimap-imap/src/" mutants.out/missed.txt 2>/dev/null || echo 0)
HOT=$(grep -cE "$HOT_PATHS" mutants.out/missed.txt 2>/dev/null || echo 0)
COLD=$(grep -cE "$COLD_PATHS" mutants.out/missed.txt 2>/dev/null || echo 0)

echo "rimap-imap total survivors: $TOTAL"
echo "rimap-imap hot-path survivors (tls/auth/connection/preflight/ops): $HOT"
echo "rimap-imap cold/plumbing survivors (error/types/time/special_use/lib): $COLD"

grep -E "$HOT_PATHS"  mutants.out/missed.txt > /tmp/rimap-imap-hot-survivors.txt  || true
grep -E "$COLD_PATHS" mutants.out/missed.txt > /tmp/rimap-imap-cold-survivors.txt || true
wc -l /tmp/rimap-imap-hot-survivors.txt /tmp/rimap-imap-cold-survivors.txt
```

- [ ] **Step 3: Classify by mutant kind**

Append to `/tmp/issue-289-classify.txt`:

```bash
echo "" >> /tmp/issue-289-classify.txt
echo "=== rimap-imap ===" >> /tmp/issue-289-classify.txt
echo "stub-return:    $(grep -cE 'replace .* -> .* with (\(\)|0|1|false|true|String::new|\"xyzzy\"|Default::default|Vec::new|Ok\(\(\)\))' /tmp/rimap-imap-hot-survivors.txt)" >> /tmp/issue-289-classify.txt
echo "boundary:       $(grep -cE 'replace [<>=!]+ with [<>=!]+' /tmp/rimap-imap-hot-survivors.txt)" >> /tmp/issue-289-classify.txt
echo "match-guard:    $(grep -cE '(delete ! in|replace match guard)' /tmp/rimap-imap-hot-survivors.txt)" >> /tmp/issue-289-classify.txt
echo "arith/logic:    $(grep -cE 'replace (\+|-|\*|/|&&|\|\|) with ' /tmp/rimap-imap-hot-survivors.txt)" >> /tmp/issue-289-classify.txt
cat /tmp/issue-289-classify.txt
```

This is the data point that drives the "bundle vs split" decision at the end of the plan.

- [ ] **Step 4: Inspect git tree — no commits in this task**

```bash
git status --short
```

Expected: empty.

---

## Task 6: Mutation cleanup — `rimap-imap` `tls.rs`, `auth.rs`, `connection.rs`, `preflight.rs`

**Why:** These are the highest-impact files in `rimap-imap`: TLS handshake / pinning verifier (`tls.rs`), authentication audit event construction (`auth.rs`), connection establishment + IDLE lifecycle (`connection.rs`), pre-auth STARTTLS / capability probe (`preflight.rs`). A surviving mutant here can mean a silent TLS downgrade, an undetected auth-failure log, or a connection leak — exactly the failure modes the security spec was written to prevent.

**Files:** iterative. Tests land in each file's existing `#[cfg(test)]` block (verify with `grep -l "^#\[cfg(test)\]" crates/rimap-imap/src/*.rs`) or in `crates/rimap-imap/tests/*.rs` for integration-level scenarios.

- [ ] **Step 1: Walk the top-level (non-`ops/`) hot survivors**

```bash
grep -E "^crates/rimap-imap/src/(tls|auth|connection|preflight)\.rs" \
  /tmp/rimap-imap-hot-survivors.txt > /tmp/rimap-imap-toplevel-survivors.txt
wc -l /tmp/rimap-imap-toplevel-survivors.txt
```

For each line, follow Task 2 Step 1 procedure (read → decide → kill or annotate → track row). File-specific notes:

  - **`tls.rs` mutations on `PinningVerifier` / `CapturingVerifier`** require the rustls `ServerCertVerifier` trait to be exercised end-to-end. Use the existing `CaptureOnlyVerifier`-based pattern in the file's `#[cfg(test)]` block as a template; do not stub `rustls` — assertions on captured-cert state are what catch the verifier mutations.

  - **`auth.rs` mutations on `auth_success` / `auth_failure`** produce `AuthEvent` structs that flow into the audit pipeline. Test by constructing an `AuthContext`, calling the function, and asserting on the returned event fields. The event is `pub(crate)` so tests must live in the same crate.

  - **`connection.rs` `IDLE`-lifetime mutations** — bias toward annotating equivalent ones rather than spinning up a fake IMAP server. Real IDLE coverage lives in `crates/rimap-imap/tests/` integration tests against `dovecot` fixtures; the spec considers that the canonical coverage layer.

  - **`preflight.rs` STARTTLS-detection mutations** drive `probe_preflight`'s return shape. Use the existing fixture pattern in the file's `#[cfg(test)]` block.

- [ ] **Step 2: Track rows for Task 7**

Append annotated mutants to `/tmp/rimap-imap-baseline-rows.md` (create if absent), same row format as Task 2 Step 1.5.

- [ ] **Step 3: Re-run mutation tests on top-level files**

```bash
cargo mutants --package rimap-imap --no-shuffle --jobs 8 --timeout 60 \
  -F '(tls|auth|connection|preflight)\.rs' \
  2>&1 | tee /tmp/mutants-rimap-imap-toplevel-reverify.log
grep -E "^crates/rimap-imap/src/(tls|auth|connection|preflight)\.rs" \
  mutants.out/missed.txt | tee /tmp/rimap-imap-toplevel-reverify-missed.txt
```

Cross-check every line against `/tmp/rimap-imap-baseline-rows.md`. Any line not represented is an unannotated survivor → return to Step 1.

- [ ] **Step 4: Verify clean build + tests**

```bash
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo nextest run --package rimap-imap --all-features --locked
```

- [ ] **Step 5: Commit (one commit per file)**

```bash
# Example
git add crates/rimap-imap/src/tls.rs
git commit -m "$(cat <<'EOF'
test(rimap-imap): close mutation gaps in tls.rs

Adds <N> tests covering specific cargo-mutants survivors uncovered by
the 2026-05-18 baseline (issue #289). <M> known-equivalent mutants
annotated inline with rationale.

Refs: #289, #245, #287
EOF
)"
```

Repeat for `auth.rs`, `connection.rs`, `preflight.rs`. Skip files with zero hot survivors.

---

## Task 7: Mutation cleanup — `rimap-imap` `ops/` directory

**Why:** `ops/` is the per-IMAP-verb implementation layer (`fetch`, `search`, `append`, `move`, `expunge`, `store`, `delete`, `folders`, `folder_management`). Each module is small and security-relevant — `fetch.rs` and `search.rs` in particular shape arguments sent to the upstream server and the response shape returned to MCP tool handlers. Spec §6 includes the whole directory as hot.

**Files:** iterative — `/tmp/rimap-imap-hot-survivors.txt` entries matching `ops/`. Tests land in each file's `#[cfg(test)]` block or `crates/rimap-imap/tests/*.rs`.

- [ ] **Step 1: Walk the `ops/` slice**

```bash
grep -E "^crates/rimap-imap/src/ops/" /tmp/rimap-imap-hot-survivors.txt > /tmp/rimap-imap-ops-survivors.txt
wc -l /tmp/rimap-imap-ops-survivors.txt
```

For each line, Task 2 Step 1 procedure. Per-file notes:

  - **`ops/fetch.rs`, `ops/search.rs`** — argument shaping in these files affects the bytes sent on the wire to the IMAP server. Test by constructing the query value, calling the formatter, and asserting on the produced IMAP command string. Wire-level integration tests against dovecot live under `crates/rimap-imap/tests/`.

  - **`ops/append.rs`** mutations on size / flag handling need the `Vec<u8>` payload assertion. Empty-payload and size-zero edge cases are likely candidates for boundary-mutant kills.

  - **`ops/move_message.rs`, `ops/delete.rs`, `ops/expunge.rs`** — UID-set construction mutations. Boundary mutants here often kill cleanly with a single test exercising both the single-UID and ranged-UID paths.

- [ ] **Step 2: Track rows**

Append annotated mutants to `/tmp/rimap-imap-baseline-rows.md`.

- [ ] **Step 3: Re-run mutation tests on `ops/`**

```bash
cargo mutants --package rimap-imap --no-shuffle --jobs 8 --timeout 60 \
  -F 'ops/' 2>&1 | tee /tmp/mutants-rimap-imap-ops-reverify.log
grep -E "^crates/rimap-imap/src/ops/" mutants.out/missed.txt \
  | tee /tmp/rimap-imap-ops-reverify-missed.txt
```

Cross-check against `/tmp/rimap-imap-baseline-rows.md`. Any unannotated → Step 1.

- [ ] **Step 4: Verify clean build + tests**

```bash
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo nextest run --package rimap-imap --all-features --locked
```

- [ ] **Step 5: Commit (one commit per ops/ file)**

```bash
# Example
git add crates/rimap-imap/src/ops/fetch.rs
git commit -m "$(cat <<'EOF'
test(rimap-imap): close mutation gaps in ops/fetch.rs

Adds <N> tests covering specific cargo-mutants survivors uncovered by
the 2026-05-18 baseline (issue #289). <M> known-equivalent mutants
annotated inline with rationale.

Refs: #289, #245, #287
EOF
)"
```

Repeat for each `ops/*.rs` file with survivors.

---

## Task 8: Mutation cleanup — `rimap-imap` cold-path / plumbing

**Why:** `error.rs`, `types.rs`, `time.rs`, `special_use.rs`, `lib.rs` are spec-named "plumbing, best-effort." Same lower bar as Task 4 — kill survivors that change observable output, annotate equivalent / diagnostic-only mutants.

**Files:** iterative — `/tmp/rimap-imap-cold-survivors.txt`.

- [ ] **Step 1: Walk the cold-survivor list**

Same triage rules as Task 4 Step 1:
- Observable output change → kill.
- Equivalent under contract → annotate + doc row.
- Diagnostic-only → annotate + doc row with "diagnostic-only" rationale.

- [ ] **Step 2: Re-run on cold paths**

```bash
cargo mutants --package rimap-imap --no-shuffle --jobs 8 --timeout 60 \
  -F '(error|types|time|special_use|lib)\.rs' \
  2>&1 | tee /tmp/mutants-rimap-imap-cold-reverify.log
grep -E "^crates/rimap-imap/src/(error|types|time|special_use|lib)\.rs" \
  mutants.out/missed.txt | tee /tmp/rimap-imap-cold-reverify-missed.txt
```

Cross-check against `/tmp/rimap-imap-baseline-rows.md`.

- [ ] **Step 3: Verify clean build + tests**

```bash
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo nextest run --package rimap-imap --all-features --locked
```

- [ ] **Step 4: Commit (one commit for cold-path batch)**

```bash
git add crates/rimap-imap/src/error.rs crates/rimap-imap/src/types.rs \
        crates/rimap-imap/src/time.rs crates/rimap-imap/src/special_use.rs \
        crates/rimap-imap/src/lib.rs
git commit -m "$(cat <<'EOF'
test(rimap-imap): close mutation gaps in cold-path modules (best-effort)

Adds <N> tests and <M> known-equivalent annotations across error/types/
time/special_use/lib per spec §6 best-effort tier. Hot-path coverage
landed in prior commits this PR.

Refs: #289, #245, #287
EOF
)"
```

Skip if no changes land.

---

## Task 9: Update `mutation-baseline.md` with `rimap-server` + `rimap-imap` sections

**Why:** Spec §6 done-criterion: "`mutation-baseline.md` updated; the document now covers all four trust-boundary crates plus B1." The current footer reads "The other two trust-boundary crates (rimap-server, rimap-imap) get their own sections here when Sprint B3 lands." This task replaces that footer with two populated sections following the `rimap-audit` / `rimap-authz` format.

**Files:**
- Modify: `docs/superpowers/specs/test-strategy/mutation-baseline.md`

- [ ] **Step 1: Confirm current state**

```bash
sed -n '/^## `rimap-authz`/,$p' docs/superpowers/specs/test-strategy/mutation-baseline.md
```

Expected: prints the `## \`rimap-authz\`` section followed by the "The other two trust-boundary crates..." footer paragraph. If sections for `rimap-server` or `rimap-imap` already exist (scaffolds), they get replaced; if not, append new sections after `## \`rimap-authz\``.

- [ ] **Step 2: Replace the footer with the `rimap-server` section**

Edit `docs/superpowers/specs/test-strategy/mutation-baseline.md`. Delete the trailing paragraph:

```
The other two trust-boundary crates (`rimap-server`, `rimap-imap`)
get their own sections here when Sprint B3 lands.
```

Replace with the populated `## \`rimap-server\`` section. Template (fill in the actual numbers and rows from `/tmp/rimap-server-baseline-rows.md`):

```markdown
## `rimap-server`

**Last refresh:** 2026-05-18.
**Surviving mutants in hot paths (`mcp/{dispatch,audit_envelope,tool_catalog,tool_name,wire_validator,preinit,server,response,content,error}.rs`, `boot/`; `fuzz_oracle.rs` covered separately below):** <N> (all annotated as known-equivalent).
**Surviving mutants in best-effort paths (`cli/`, `tools/`, `main.rs`, `lib.rs`):** <M> (<K> annotated as known-equivalent, <M-K> unannotated diagnostic-only — see rationales below).

Run summary (<TOTAL> mutants total, 2026-05-18 baseline via `cargo
mutants --package rimap-server --jobs 8 --timeout 60`): <CAUGHT>
caught, <MISSED> missed (<HOT_ANNOT> annotated below, <COLD_ANNOT>
annotated in best-effort tier), <TIMEOUT> timeout, <UNVIABLE>
unviable in <WALL_CLOCK> wall clock. This run unblocked when the host
moved off macOS — cargo-mutants 27.0.0 + `--in-place` runs were
non-functional on the maintainer's macOS box per upstream
[#611](https://github.com/sourcefrog/cargo-mutants/issues/611);
running on Linux without `--in-place` sidestepped the issue entirely.
Issue #289 captured the deferral and this run closes it.

File-scope note: the issue body inherited path lists from
`archive/daemon-experiment` and referenced `daemon/transport*.rs`,
`daemon/audit_sink.rs`, `daemon/run.rs`, `shim.rs`, and
`mcp/posture_context.rs`, none of which exist on current `main`. The
hot-path list above is the current security-critical surface as of
2026-05-18.

| File:line | Mutation | Reason kept | Annotation site |
|---|---|---|---|
<rows from /tmp/rimap-server-baseline-rows.md>

### `mcp/fuzz_oracle.rs` (behind `--features fuzzing`)

**Last refresh:** 2026-05-18.
**Surviving mutants:** <N> (all annotated as `known-equivalent`).

The file is gated by `#[cfg(feature = "fuzzing")]` in `crates/rimap-server/src/mcp/mod.rs`, so the main `rimap-server` table above (default features) does not exercise it. The numbers below come from a dedicated `cargo mutants --package rimap-server --features fuzzing -F 'mcp/fuzz_oracle\.rs'` pass. Tests covering this file live in a `#[cfg(all(test, feature = "fuzzing"))]` block at the bottom of the source file.

| File:line | Mutation | Reason kept | Annotation site |
|---|---|---|---|
<rows from /tmp/rimap-server-baseline-rows.md with the "(fuzzing)" tag>
```

If `<N>` is zero (no survivors), keep the section but write the table as "No surviving mutants in `mcp/fuzz_oracle.rs` after Task 2 Step 2.5 cleanup." — the section's purpose is to document that the file was covered, not just to list survivors. This matches the `## \`rimap-authz\`` section's "no known-equivalent annotations were needed; every surviving mutant was a real test gap" pattern.

- [ ] **Step 3: Append the `rimap-imap` section**

After the `rimap-server` section, append:

```markdown
## `rimap-imap`

**Last refresh:** 2026-05-18.
**Surviving mutants in hot paths (`tls.rs`, `auth.rs`, `connection.rs`, `preflight.rs`, `ops/`):** <N> (all annotated as known-equivalent).
**Surviving mutants in plumbing (`error.rs`, `types.rs`, `time.rs`, `special_use.rs`, `lib.rs`):** <M> (<K> annotated as known-equivalent, <M-K> unannotated diagnostic-only — see rationales below).

Run summary (<TOTAL> mutants total, 2026-05-18 baseline via `cargo
mutants --package rimap-imap --jobs 8 --timeout 60`): <CAUGHT>
caught, <MISSED> missed (<HOT_ANNOT> annotated below, <COLD_ANNOT>
annotated in plumbing tier), <TIMEOUT> timeout, <UNVIABLE> unviable
in <WALL_CLOCK> wall clock. Wire-level coverage of `connection.rs`
and `ops/` IDLE lifetime lives in the dovecot integration suite under
`crates/rimap-imap/tests/`; this baseline focuses on per-module unit
semantics.

| File:line | Mutation | Reason kept | Annotation site |
|---|---|---|---|
<rows from /tmp/rimap-imap-baseline-rows.md>
```

- [ ] **Step 4: Verify the document renders and the new rows match the inline annotations**

```bash
# Sanity-check the markdown renders (no broken tables)
grep -n "^|" docs/superpowers/specs/test-strategy/mutation-baseline.md | wc -l

# Each row's annotation site should point to a real line with the inline comment
for row in $(grep -oE "(mcp|boot|tls|auth|connection|preflight|ops)[^ ]+:[0-9]+" /tmp/rimap-server-baseline-rows.md /tmp/rimap-imap-baseline-rows.md 2>/dev/null); do
  file=$(echo "$row" | cut -d: -f1)
  line=$(echo "$row" | cut -d: -f2)
  full_path=$(find crates/rimap-server/src crates/rimap-imap/src -path "*/$file" 2>/dev/null | head -1)
  if [ -n "$full_path" ] && [ -f "$full_path" ]; then
    grep -q "cargo-mutants: known-equivalent" "$full_path" || echo "MISSING annotation: $full_path"
  fi
done
```

Any `MISSING annotation:` line means the doc claims an annotation site that doesn't have the inline comment — fix by adding the comment or correcting the doc row.

- [ ] **Step 5: Commit**

```bash
git add docs/superpowers/specs/test-strategy/mutation-baseline.md
git commit -m "$(cat <<'EOF'
docs(test-strategy): add rimap-server + rimap-imap mutation baselines

Replaces the placeholder footer in mutation-baseline.md with populated
sections for both crates, generated by the 2026-05-18 cargo-mutants
27.0.0 baseline runs on Linux. Closes the B3 documentation gap and
unblocks the spec §6 done-criterion 5.

The host-side blocker captured in issue #289 (cargo-mutants PR #613
not yet in a tagged release) was sidestepped by running on Linux
where the upstream dirhelper issue does not apply. The cargo-mutants
runbook is updated in a follow-up commit to reflect this.

Refs: #289, #245, #287
EOF
)"
```

---

## Task 10: Update `docs/security/cargo-mutants-runbook.md` to note the Linux fast path

**Why:** The runbook currently describes only `just mutants --in-place` (the macOS workaround) and says workspace surveys take ~3.5h at `--jobs 1`. This plan's actual run used `cargo mutants --jobs 8` directly on Linux and finished in a small fraction of that time. Document the trade-off so the next contributor doesn't re-pay the wall-clock cost.

**Files:**
- Modify: `docs/security/cargo-mutants-runbook.md`

- [ ] **Step 1: Add a "Linux fast path" section after "Blessed invocations"**

Insert after the "Blessed invocations" table, before the "What `--in-place` costs you" section:

```markdown
## Linux fast path (bypass `--in-place`)

The `--in-place` flag exists to dodge a macOS-specific cargo-mutants
bug ([#611](https://github.com/sourcefrog/cargo-mutants/issues/611)).
On Linux, the temp-tree path the bug affects is not exercised — you
can drop `--in-place` and run cargo-mutants directly with `--jobs N`
for proportional wall-clock speedup. The 2026-05-18 issue #289
baselines used:

```bash
cargo mutants --package rimap-server --no-shuffle --jobs 8 --timeout 60
cargo mutants --package rimap-imap  --no-shuffle --jobs 8 --timeout 60
```

Trade-offs:

- **No `just mutants` wrapper.** Drop down to plain `cargo mutants`
  since the recipe forces `--in-place`. A future justfile change
  could pick the right invocation per `uname -s`, but is not done
  today.
- **Tune `--jobs` to physical cores.** Each worker spawns a full
  `cargo` invocation; rule of thumb `--jobs ≤ physical_cores / 2`,
  more aggressive if the box has tens of GiB of RAM headroom per
  worker.
- **No source-tree contention.** Workers operate on `target/mutants/`
  temp trees, so concurrent IDE / rust-analyzer work is fine.
- **Ctrl-C is safe.** The source tree is never mutated.

On macOS, do not use this path until cargo-mutants 27.0.1+ ships
containing [PR #613](https://github.com/sourcefrog/cargo-mutants/pull/613).
```

- [ ] **Step 2: Update the "Why not just downgrade to 25.x?" section's "If wall-clock time on macOS..." closing paragraph**

Edit the trailing paragraph of the "Why not just downgrade to 25.x?" section. Change:

```
If wall-clock time on macOS becomes the binding constraint before
[#611](https://github.com/sourcefrog/cargo-mutants/issues/611) is
fixed, revisit this.
```

To:

```
If wall-clock time on macOS becomes the binding constraint before
[#611](https://github.com/sourcefrog/cargo-mutants/issues/611) is
fixed (i.e. a tagged release containing
[PR #613](https://github.com/sourcefrog/cargo-mutants/pull/613)),
revisit this. Linux contributors can use the "Linux fast path"
section above today without changes.
```

- [ ] **Step 3: Verify the markdown still renders cleanly**

```bash
# No raw HTML, no broken code fences
grep -cE "^```" docs/security/cargo-mutants-runbook.md
# Must be even (open + close pairs)
```

Expected: an even number of fence markers.

- [ ] **Step 4: Commit**

```bash
git add docs/security/cargo-mutants-runbook.md
git commit -m "$(cat <<'EOF'
docs(security): document Linux fast path for cargo-mutants

Adds a "Linux fast path" section to the cargo-mutants runbook
documenting the `cargo mutants --jobs N` invocation used to run the
issue #289 baselines without --in-place. The macOS workaround
remains the documented default; the new section is the Linux escape
hatch that's been latent in the tooling since 25.x.

Refs: #289
EOF
)"
```

---

## Task 11: Final verification + PR

**Why:** Belt-and-braces: re-run both baselines on a clean tree to confirm zero unannotated survivors after all commits land, then open the PR.

- [ ] **Step 1: Re-run both baselines top-to-bottom**

```bash
cargo mutants --package rimap-server --no-shuffle --jobs 8 --timeout 60 \
  2>&1 | tee /tmp/mutants-rimap-server-final.log

# Verify zero unannotated hot-path survivors (default features, excluding fuzz_oracle)
HOT_PATHS='^crates/rimap-server/src/(mcp/(dispatch|audit_envelope|tool_catalog|tool_name|wire_validator|preinit|server|response|content|error)\.rs|boot/)'
FINAL_HOT=$(grep -cE "$HOT_PATHS" mutants.out/missed.txt 2>/dev/null || echo 0)
echo "rimap-server final hot survivors (must equal doc-table row count): $FINAL_HOT"
grep -E "$HOT_PATHS" mutants.out/missed.txt | tee /tmp/rimap-server-final-missed.txt
DOCSTR_HOT=$(grep -cE "^\| (mcp/|boot/)" docs/superpowers/specs/test-strategy/mutation-baseline.md)
echo "rimap-server doc-table rows in hot section: $DOCSTR_HOT"
test "$FINAL_HOT" = "$DOCSTR_HOT" || echo "MISMATCH — investigate before opening PR"
```

Then re-run the feature-gated `fuzz_oracle.rs` pass and verify its rows match the dedicated subsection:

```bash
cargo mutants --package rimap-server --features fuzzing \
  --no-shuffle --jobs 8 --timeout 60 -F 'mcp/fuzz_oracle\.rs' \
  2>&1 | tee /tmp/mutants-rimap-server-fuzz-oracle-final.log

FINAL_FUZZ=$(grep -cE '^crates/rimap-server/src/mcp/fuzz_oracle\.rs' \
  mutants.out/missed.txt 2>/dev/null || echo 0)
DOCSTR_FUZZ=$(grep -cE '^\| \(fuzzing\) mcp/fuzz_oracle\.rs' \
  docs/superpowers/specs/test-strategy/mutation-baseline.md)
echo "rimap-server final fuzz_oracle survivors: $FINAL_FUZZ"
echo "rimap-server doc-table rows in fuzz_oracle subsection: $DOCSTR_FUZZ"
test "$FINAL_FUZZ" = "$DOCSTR_FUZZ" || echo "MISMATCH — investigate before opening PR"
```

```bash
cargo mutants --package rimap-imap --no-shuffle --jobs 8 --timeout 60 \
  2>&1 | tee /tmp/mutants-rimap-imap-final.log

HOT_PATHS='^crates/rimap-imap/src/(tls\.rs|auth\.rs|connection\.rs|preflight\.rs|ops/)'
FINAL_HOT=$(grep -cE "$HOT_PATHS" mutants.out/missed.txt 2>/dev/null || echo 0)
echo "rimap-imap final hot survivors (must equal doc-table row count): $FINAL_HOT"
grep -E "$HOT_PATHS" mutants.out/missed.txt | tee /tmp/rimap-imap-final-missed.txt
DOCSTR_HOT=$(grep -cE "^\| (tls|auth|connection|preflight|ops/)" docs/superpowers/specs/test-strategy/mutation-baseline.md)
echo "rimap-imap doc-table rows in hot section: $DOCSTR_HOT"
test "$FINAL_HOT" = "$DOCSTR_HOT" || echo "MISMATCH — investigate before opening PR"
```

Both `MISMATCH` checks must print nothing (test passed). If either prints, an annotation was missed or a doc row is stale — fix and re-run.

- [ ] **Step 2: Run `just ci` — the repo's documented pre-push gate**

```bash
just ci
```

This recipe is the documented "if `just ci` passes locally, CI will pass" contract for this repo (`justfile:3`), and includes `fmt-check`, `lint`, `test`, `test-msrv` (workspace at MSRV 1.88.0), `deny`, and `mcp-conformance-node`. The per-task interim `clippy + nextest` gates throughout Tasks 2–8 stay as fast-feedback only — the heavyweight gate runs once here before push.

If `just ci` fails on `test-msrv`, the most likely cause is a new test using a `let...else` arm or a 1.89+ stable feature; check the failing diagnostic and rewrite to MSRV-safe syntax. The `deny` step can fail if any new dependency was pulled (no new deps are expected in this plan; if it fails, that's a signal to investigate the unexpected pull-in).

- [ ] **Step 3: Push branch**

```bash
git push -u origin feat/issue-289-mutation-baselines-server-imap
```

- [ ] **Step 4: Open the PR**

```bash
gh pr create --title "test(rimap-server,rimap-imap): mutation baselines + cleanup (issue #289)" \
  --body "$(cat <<'EOF'
## Summary

- Adds the `rimap-server` and `rimap-imap` baselines to `mutation-baseline.md` — closes the documentation gap that was the last open thread on issue #245 and unblocks issue #287 (Phase 2 close) and #288 (OSS-Fuzz upstream submission, Phase 3).
- Adds `<N_server>` tests and `<M_server>` known-equivalent annotations across `rimap-server` hot paths (`mcp/*`, `boot/`); `<N_imap>` tests and `<M_imap>` annotations across `rimap-imap` hot paths (`tls.rs`, `auth.rs`, `connection.rs`, `preflight.rs`, `ops/`).
- Documents the Linux fast path for cargo-mutants (drops `--in-place`, uses `--jobs 8`) in the existing runbook — the macOS-specific workaround stays the default.

## Why now

Issue #289 was deferred because the maintainer's macOS box hits cargo-mutants upstream issue [#611](https://github.com/sourcefrog/cargo-mutants/issues/611) even with `--in-place`, and the fix ([PR #613](https://github.com/sourcefrog/cargo-mutants/pull/613)) is merged upstream but not yet in a tagged release (latest is 27.0.0 from 2026-03-07). Running on Linux sidesteps the bug entirely.

## File-scope note

Issue #289 inherited file paths from #245's archive-era scope; `daemon/`, `shim.rs`, and `mcp/posture_context.rs` no longer exist on `main`. The current hot-path surface is documented in the new `## \`rimap-server\`` and `## \`rimap-imap\`` sections of `mutation-baseline.md`.

## Test plan

- [ ] `cargo mutants --package rimap-server --jobs 8` produces zero unannotated survivors in the named hot paths.
- [ ] `cargo mutants --package rimap-imap --jobs 8` produces zero unannotated survivors in the named hot paths.
- [ ] `cargo mutants --package rimap-server --features fuzzing -F 'mcp/fuzz_oracle\.rs'` produces zero unannotated survivors.
- [ ] `just ci` passes locally (fmt-check, lint, test, test-msrv@1.88, deny, mcp-conformance-node).
- [ ] Every doc-table row in `mutation-baseline.md` matches an inline `// cargo-mutants: known-equivalent` annotation at the cited line.

Closes #245.
Refs #287, #288, #289.
EOF
)"
```

- [ ] **Step 5: Comment on #289 and #287**

After the PR is open (capture URL in `$PR_URL`):

```bash
gh issue comment 289 --body "Implementation PR: $PR_URL — baselines run on Linux to bypass cargo-mutants upstream #611 without waiting for 27.0.1. File-scope correction (daemon/, shim.rs, posture_context.rs no longer on main) is documented in the PR body and in mutation-baseline.md."

gh issue comment 287 --body "Sprint B3 mutation-cleanup half landing via $PR_URL (issue #289). After merge, the only remaining thread on Phase 2 is the issue close itself."
```

Do not auto-close #289 or #245 — let the PR's `Closes #245` and the post-merge state speak. #287 stays open until the maintainer confirms Phase 2 is done.

---

## Out-of-band split: when to defer cleanup to a follow-up PR

Default expectation is one PR (this plan). Split only when the post-baseline classification (Task 1 Step 3 + Task 5 Step 3 combined) shows:

- **More than 30 total hot-path arithmetic-or-logic survivors across both crates.** These are the expensive kind per `feedback_mutation_cleanup_complexity_not_count` — each typically 30+ minutes of test design. 30+ arithmetic/logic survivors implies ≥15h of focused work; that's bigger than a normal PR review window.

- **OR more than 5 survivors require new shared test infrastructure** (e.g., a stub IMAP server crate, a new audit-event capture helper). Those infrastructure changes should land first in their own commit and ideally their own PR so the cleanup-PR diff stays focused on test-and-annotate.

When splitting:

1. Open `test(rimap-server): finish mutation cleanup deferred from issue #289` (or `rimap-imap`) as a new issue, with the survivor list pasted in.
2. Land this PR with the baselines run, the cheap kills (stub-return / boundary / match-guard), and the doc-table covering only the killed/annotated half. Mark unfinished hot-path lines explicitly in the doc.
3. The follow-up PR closes the new issue and updates the doc to reflect a fully-zero hot-path count.

Per the feedback memory, the kind-based threshold above replaces the "raw count > 25" heuristic from earlier B-sprint plans (which would have wasted Sprint B2's cleanup into two PRs unnecessarily).

---

## Done criteria

- [ ] `cargo mutants --package rimap-server --jobs 8` reports zero unannotated survivors in `mcp/{dispatch,audit_envelope,tool_catalog,tool_name,wire_validator,preinit,server,response,content,error}.rs` and `boot/`.
- [ ] `cargo mutants --package rimap-imap --jobs 8` reports zero unannotated survivors in `tls.rs`, `auth.rs`, `connection.rs`, `preflight.rs`, `ops/`.
- [ ] `cargo mutants --package rimap-server --features fuzzing -F 'mcp/fuzz_oracle\.rs'` reports zero unannotated survivors.
- [ ] `docs/superpowers/specs/test-strategy/mutation-baseline.md` has new sections for both crates following the format used for `rimap-audit` / `rimap-authz`.
- [ ] Footer note "The other two trust-boundary crates..." is removed.
- [ ] `docs/security/cargo-mutants-runbook.md` documents the Linux fast path.
- [ ] PR open, linked from #289 and #287, with `Closes #245` in the body.
- [ ] `just ci` passes locally.
