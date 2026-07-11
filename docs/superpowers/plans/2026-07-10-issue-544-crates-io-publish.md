# crates.io Publish (Issue #544) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development or superpowers:executing-plans to
> implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Make the 8 `rimap-*` workspace crates publishable to crates.io via a
new tag-driven `publish-crates` job, an ordered/idempotent/rate-limit-aware
publish script, `cargo-semver-checks` gating, complete per-crate metadata, and a
`rimap-content` relicense to cover its vendored Unicode data.

**Architecture:** No product-code behavior changes. Manifest metadata + a Bash
publish script + a `release.yml` job + docs. Publishing is ordered by the
intra-workspace DAG (`core → config → audit → content → authz → imap → smtp →
server`) and is **irreversible**, so idempotent skip-by-version and new-crate
rate-limit handling are load-bearing.

**Tech Stack:** Rust workspace, Bash (`shellcheck`/`shfmt`), `cargo publish`,
`cargo-semver-checks`, GitHub Actions, `cargo-deny`.

**Spec:** [2026-07-10-issue-544-crates-io-publish-design.md](../specs/2026-07-10-issue-544-crates-io-publish-design.md)
· **ADR:** [0004](../../ADR/0004-crates-io-publish-topology.md)

## Global Constraints

- **Branch:** `feat/crates-io-publish-544` (already created off `origin/main`).
  Never commit on `main`.
- **Base:** `main`. **Guardrail umbrella:** `just ci`. Per-commit, run the
  guardrails relevant to what changed:
  - Rust manifests: `just check`, `just deny`, and `cargo test -p <touched>`.
  - Shell: `shellcheck <script>` and `shfmt -d -i 4 <script>` — the repo's prek
    hooks pin shfmt to `-i 4 -d` (`.pre-commit-config.yaml`) and every sibling
    `scripts/*.sh` is 4-space indented. Shell quality is enforced at **commit
    time via prek** (shellcheck + shfmt hooks), not in `ci.yml`; run
    `prek run --files <new scripts>` before committing.
  - Workflow: `actionlint` and `zizmor` on **every** workflow file you edit —
    `release.yml` (Task 5) and `ci.yml` (Task 2/3, see below).
- **How PR CI actually gates (critical):** `ci.yml` does **not** run `just ci`.
  Each gate is a dedicated `ci.yml` job (e.g. `tool-schema-drift`,
  `tools-doc-drift`) or an inlined step (the openssl guard is a step in the
  `clippy` job "Mirrors `just check-no-openssl`"). Adding a check to the `just
  ci` recipe gives **local** coverage only. To gate PRs, a check must be
  **mirrored into `ci.yml`** as a job/step. The `just` targets below are for
  local/prek convenience; their PR-gating comes from the `ci.yml` job in Task 2.
  (Note: a *new* `ci.yml` job is not a *required* status check until the
  operator adds it to branch protection — that promotion is optional operator
  config, called out where relevant.)
- CI runs `--locked`. Manifest edits that change resolution must regenerate and
  commit `Cargo.lock` (and `html-oracle/Cargo.lock` if `rimap-core`/
  `rimap-content` deps change — they do not here). Removing a `version =` from a
  self dev-dep does not change the lock; run `just check` to confirm a clean
  tree afterward.
- Line length ≤ 100; absolute imports only; no `#[allow]`; `Unicode-3.0` is
  **already** allowed in `deny.toml` (do **not** add a new allow entry).
- **Do not publish anything** during implementation. Name reservation is a
  separate operator action (spec Decision 7), out of this PR's diff.
- Pin any new tool version to the **current stable** looked up at implementation
  time (e.g. `cargo-semver-checks`); do not guess from memory.

---

### Task 1: Complete per-crate publish metadata, relicense `rimap-content`, make self dev-deps path-only

**Files:**
- Modify: `crates/rimap-core/Cargo.toml`, `crates/rimap-config/Cargo.toml`,
  `crates/rimap-audit/Cargo.toml`, `crates/rimap-content/Cargo.toml`,
  `crates/rimap-authz/Cargo.toml`, `crates/rimap-imap/Cargo.toml`,
  `crates/rimap-server/Cargo.toml` (metadata; `rimap-smtp` already has
  keywords/categories — leave its metadata unchanged).
- Modify: `crates/rimap-content/data/NOTICE` (fix license naming).

**Where this fits:** Prerequisite for every later task — the dry-run (Task 3)
and the real publish require complete metadata, a correct license, and
publishable manifests.

**Steps:**

- [ ] **Metadata.** Add to each crate's `[package]` the `keywords` and
  `categories` from the spec's metadata table (verbatim). Keep the ordering /
  formatting consistent with `rimap-smtp`'s existing lines. Do **not** add a
  `documentation` field (crates.io auto-links docs.rs).
- [ ] **Relicense `rimap-content`.** Replace `license.workspace = true` with
  `license = "(MIT OR Apache-2.0) AND Unicode-3.0"` and delete the multi-line
  `# TODO: data/confusables.txt ...` comment above it. Leave every other
  workspace-inherited field (`repository`, `authors`, `readme`, `version`,
  `edition`, `rust-version`) inherited.
- [ ] **Fix the NOTICE.** In `crates/rimap-content/data/NOTICE`, change
  "Licensed under the Unicode License v3 (Unicode-DFS-2016)." to name only the
  correct identifier: "Licensed under the Unicode License v3 (SPDX:
  Unicode-3.0)." Keep the copyright line and the `license.txt` URL.
- [ ] **Self dev-deps → path-only.** Remove the `version = "..."` key from the
  three self-referential dev-dependencies, leaving `path` (+ `features`):
  - `crates/rimap-content/Cargo.toml` — the `[dev-dependencies.rimap-content]`
    table (drop its `version`).
  - `crates/rimap-smtp/Cargo.toml` — the inline `rimap-smtp = { path = ".", ... }`
    dev-dep (drop `version`, keep `features = ["test-support"]`).
  - `crates/rimap-server/Cargo.toml` — the inline `rimap-server = { path = ".", ... }`
    dev-dep (drop `version`, keep `features = ["test-support"]`).
  Leave all **cross-crate** dev-deps (e.g. `rimap-server`'s dev-deps on
  `rimap-imap`/`rimap-config`/…) untouched — they carry versions and publish
  earlier in the order, so they resolve.

**Acceptance criteria (reviewer-checkable):**
- `just deny` is green (licenses/bans/advisories/sources) with no new
  `deny.toml` entry.
- `cargo test -p rimap-content -p rimap-smtp -p rimap-server` still compiles and
  runs (the `test-support`/`test-injection` features still resolve via the
  path-only self dev-dep). Run at least `cargo test -p rimap-smtp` to prove the
  self-feature still activates.
- `cargo package --list -p rimap-content` includes both `data/NOTICE` and
  `data/confusables.txt`.
- `just check` clean; working tree has no unexpected `Cargo.lock` churn.

**Rollback:** revert the manifest/NOTICE edits; no external state touched.

---

### Task 2: Metadata guardrail script — validate categories/description

**Files:**
- Add: `scripts/check-publishable-metadata.sh`
- Modify: `justfile` (add a `check-metadata` target — local convenience).
- Modify: `.github/workflows/ci.yml` (add a **dedicated job** that runs the
  check — this is what actually gates PRs; mirror the `tools-doc-drift` job
  shape: SHA-pinned checkout + Rust toolchain, then the `just` target).

**Where this fits:** Realizes spec SC #2a. `cargo publish --dry-run` is offline
and cannot validate crates.io category slugs; a dedicated `ci.yml` job catches a
typo'd or retired slug on every PR instead of it being silently dropped at
publish. (Adding to the `just ci` recipe alone would **not** gate PRs — see
Global Constraints.)

**Steps:**

- [ ] Write `scripts/check-publishable-metadata.sh` (`set -euo pipefail`,
  `shellcheck`/`shfmt`-clean, matching sibling scripts' indent). For each of the
  8 crates it asserts:
  - a non-empty `description` is present (inherited fields are fine — only
    `description` is per-crate and required by crates.io);
  - every `categories` entry is a member of a **pinned** valid-slug set defined
    at the top of the script — the slugs this workspace uses: `email`, `config`,
    `parser-implementations`, `text-processing`, `authentication`,
    `network-programming`, `command-line-utilities`. Include a comment linking
    to `https://crates.io/category_slugs` as the source of truth;
  - `keywords` count ≤ 5 and each ≤ 20 chars (crates.io limits).
  Prefer parsing via `cargo metadata --no-deps --format-version 1` piped to a
  small filter, or a simple per-file scan — whichever stays `shellcheck`-clean.
- [ ] Add a `just check-metadata` target running the script (local/prek
  convenience).
- [ ] Add a dedicated `ci.yml` job (name e.g. `publish-checks`) that runs
  `just check-metadata` (Task 3 appends `just test-publish-script` to the same
  job). Mirror the `tools-doc-drift` job: `permissions: { contents: read }`,
  SHA-pinned `actions/checkout` + `dtolnay/rust-toolchain` (reuse the exact SHAs
  already in `ci.yml`), no `libdbus` needed (the check only reads manifests via
  `cargo metadata --no-deps`). Do **not** add it to the `just ci` recipe as the
  gating mechanism — the job is the gate.

**Acceptance criteria:**
- `shellcheck` and `shfmt -i 4 -d` clean on the script (via `prek run`).
- `just check-metadata` exits 0 on the current tree.
- The new `ci.yml` job runs `just check-metadata`; `actionlint` + `zizmor` clean
  on `ci.yml`.
- Mutating a category to a bogus slug locally makes it exit non-zero (prove the
  check bites), then revert.

**Rollback:** delete the script, justfile lines, and the `ci.yml` job.

---

### Task 3: `scripts/publish-crates.sh` — ordered, idempotent, rate-limit-aware

**Files:**
- Add: `scripts/publish-crates.sh`
- Add: `scripts/publish-crates.test.sh` (plain-bash function tests; no new deps)
- Modify: `justfile` (add `publish-dry-run` and `test-publish-script` targets;
  wire `test-publish-script` into `ci`).

**Where this fits:** The core of the publish pipeline (spec Decision 3 / Detailed
design). Invoked by the `release.yml` job (Task 5) and by the operator for the
first paced local reservation (spec Decision 7).

**Steps:**

- [ ] Implement `scripts/publish-crates.sh` (`set -euo pipefail`,
  `shellcheck`/`shfmt`-clean):
  - Constant ordered list: `rimap-core rimap-config rimap-audit rimap-content
    rimap-authz rimap-imap rimap-smtp rimap-server`.
  - Read the workspace version once (`cargo metadata --no-deps --format-version 1`
    → any member's `version`, or parse the workspace `Cargo.toml`).
  - Modes: default = real publish; `--dry-run` = validation only.
  - `already_published <crate> <version>`: `curl` the web API
    `https://crates.io/api/v1/crates/<crate>/<version>` with a descriptive
    `User-Agent` (crates.io requires one); HTTP 200 ⇒ already present (skip),
    404 ⇒ needs publish. Treat other/transient codes as "unknown" and let
    `cargo publish` be the source of truth.
  - `parse_retry_after <stderr-text>`: crates.io's new-crate 429 message embeds
    an **absolute timestamp** ("...try again after `<timestamp>`..."), not a
    Retry-After seconds value — so this function must extract that timestamp and
    compute `max(0, timestamp - now)` seconds. Keep it a pure function (input
    string → integer seconds) so the test can exercise it. **Safe fallback:** if
    the timestamp cannot be parsed (message format changed), return a sentinel
    that makes the caller do a documented bounded fixed sleep *or* exit with a
    clear "resume later" message — never a wrong/huge sleep and never a silent
    abort. This path fires at the burst boundary (crate #6) during the
    irreversible first reservation, so degrade predictably.
  - `index_has_version <crate> <version>`: GET
    `https://index.crates.io/ri/ma/<crate>` (4+-char names use the
    `<first2>/<next2>/<name>` layout) and check for the exact version line.
  - **Real mode per crate:** if `already_published` → log skip. Else
    `cargo publish -p <crate> --locked`; on 429, `parse_retry_after` → if within
    `MAX_RATE_WAIT` sleep+retry, else exit non-zero with a "resume later"
    message. After a successful publish, poll `index_has_version` until true or
    a bounded timeout, then continue.
  - **Real mode guard:** before the loop, assert the version contains no `-dev`
    (fail fast). **Skip this assertion under `--dry-run`** so it runs on a normal
    `-dev` branch.
  - **Dry-run mode per crate:** `cargo publish --dry-run --locked -p rimap-core`
    (full verify on the leaf) and
    `cargo publish --dry-run --no-verify --locked -p <crate>` for the other
    seven (metadata/packaging only — a registry-resolved verify build is
    impossible pre-publish for unpublished deps).
- [ ] Implement `scripts/publish-crates.test.sh`: source the script's functions
  (guard the script's `main` behind a `${BASH_SOURCE[0]} == ${0}` check so
  sourcing does not execute it) and assert:
  - `parse_retry_after` on a **realistic cargo 429 fixture** (use the documented
    crates.io message form with an absolute timestamp — cite the format in a
    comment; do not invent a seconds-based format) returns a positive delta; on
    a past timestamp returns 0; on an unparseable string returns the fallback
    sentinel; on a non-429 string returns empty/zero.
  - the `-dev` guard is skipped under `--dry-run` and enforced otherwise
    (call the guard function with a `-dev` version in each mode).
  - the ordered crate list is exactly the 8 crates in DAG order.
- [ ] Add `just publish-dry-run` (`scripts/publish-crates.sh --dry-run`) and
  `just test-publish-script` (`bash scripts/publish-crates.test.sh`) targets.
  Add `just test-publish-script` as a step to the `publish-checks` `ci.yml` job
  created in Task 2 (this is its PR gate; the `just ci` recipe is not).

**Acceptance criteria:**
- `shellcheck` + `shfmt -i 4 -d` clean on both scripts (via `prek run`).
- `just test-publish-script` exits 0, and the `publish-checks` `ci.yml` job runs
  it; `actionlint` + `zizmor` clean on `ci.yml`.
- `just publish-dry-run` exits 0 **on the current `-dev` branch** (all 8 package
  with complete metadata; no missing `description`/`license`; no version-less
  regular deps).
- The script never calls the real `cargo publish` (no `--dry-run`) unless invoked
  without `--dry-run` **and** given a clean version — verify by reading, and by
  the function test.

**Rollback:** delete both scripts + justfile lines.

---

### Task 4: `cargo-semver-checks` local target

**Files:**
- Modify: `justfile` (add a `semver-checks` target).

**Where this fits:** Spec Decision 4. The CI gate lives in the workflow (Task 5);
this is the local parity target. It no-ops until a crates.io baseline exists.

**Steps:**
- [ ] Look up the current stable `cargo-semver-checks` version. Add a
  `semver-checks` justfile target that runs
  `cargo semver-checks check-release --workspace` (documented to require a
  network baseline and to no-op before the first publish). Do **not** add it to
  `ci` (it needs registry baselines and is release-path only).

**Acceptance criteria:** `just --list` shows `semver-checks`; running it before
any publish either passes (no baseline) or is documented as network-dependent.
Do not block `just ci` on it.

**Rollback:** delete the justfile lines.

---

### Task 5: `publish-crates` job in `release.yml`

**Files:**
- Modify: `.github/workflows/release.yml`

**Where this fits:** Spec Decision 1/2. Wires the script into the tag-driven
release as a downstream leaf of `release`.

**Steps:**
- [ ] Add a `publish-crates` job:
  - `needs: release` (runs after the GitHub Release + artifacts publish).
  - `if: ${{ github.event_name == 'push' && !contains(github.ref_name, '-') }}`
    (stable tags only; never `workflow_dispatch`, never `-dev`).
  - `runs-on: ubuntu-24.04`, `environment: crates-io`,
    `permissions: { contents: read }`.
  - Steps: `actions/checkout` (reuse the **same pinned SHA + version comment**
    as other jobs, `persist-credentials: false`); install `libdbus-1-dev
    pkg-config` (the publish verify build compiles `rimap-config`→`keyring`);
    `dtolnay/rust-toolchain` stable (same pinned SHA as sibling jobs); install
    `cargo-semver-checks` at the pinned version from Task 4; run
    `cargo semver-checks check-release --workspace`; run
    `scripts/publish-crates.sh` with
    `env: { CARGO_REGISTRY_TOKEN: ${{ secrets.CARGO_REGISTRY_TOKEN }} }`.
  - Every `uses:` is a 40-char SHA with a version comment (repo/zizmor rule).
- [ ] Confirm the job does not widen any existing job's permissions and that the
  `release` job is unchanged.

**Acceptance criteria:**
- `actionlint .github/workflows/release.yml` clean.
- `zizmor .github/workflows/release.yml` clean (no new findings; SHA pins with
  version comments; minimal `permissions`).
- The job's `if:` provably excludes `workflow_dispatch` and `-dev` tags (read
  the expression; matches the `homebrew`/`post-release-bump` gating idiom).

**Rollback:** remove the `publish-crates` job block.

---

### Task 6: Docs — RELEASING.md, CHANGELOG

**Files:**
- Modify: `RELEASING.md`, `CHANGELOG.md`

**Where this fits:** Operator-facing record; spec "Docs" section.

**Steps:**
- [ ] `RELEASING.md` "One-time setup": add crates.io — reserve the 8 names by
  running `scripts/publish-crates.sh` locally at the release version (paced
  through the new-crate burst-5 / 1-per-10-min limit; a local run sleeps for
  free), and add `CARGO_REGISTRY_TOKEN` to the `crates-io` deployment
  environment (optional required reviewer). Note that the **first** release's 8
  new names exceed the burst and must be reserved locally beforehand;
  subsequent releases publish new *versions* (burst 30) in one CI run.
- [ ] `RELEASING.md` "What automation does": add `publish-crates` (needs
  release; stable-only; ordered/idempotent/rate-limit-aware; semver-checks
  gate). Update the "Watch the pipeline" order line to include it.
- [ ] `RELEASING.md` "Planned (later phases)": remove the crates.io bullet
  (#544 is now implemented); keep the #545 deb/rpm bullet.
- [ ] `CHANGELOG.md` `[Unreleased]`: add an entry under the appropriate heading
  (match the file's existing style) recording the crates.io publish pipeline,
  the `rimap-content` license correction, and the new metadata.

**Acceptance criteria:** `just ci` green (note: the local-only `typos` step is
pre-existing red on `main` and is non-gating — do not block on it; the 8 gating
checks must pass). Links resolve; the "Planned" section no longer lists #544.

**Rollback:** revert the doc edits.

---

## Execution order & prerequisites

1. **Task 1** first (metadata/license/self-dep) — everything else depends on
   publishable manifests.
2. **Task 2** and **Task 3** next (guardrail script + publish script); Task 3's
   dry-run depends on Task 1.
3. **Task 4** (semver target), then **Task 5** (workflow) which depends on
   Tasks 3–4 existing.
4. **Task 6** (docs) last.

Commit one task per commit (or finer), guardrails green each time. After all
tasks, run the full `just ci` and confirm the 8 gating checks are green.

## Out of scope (do not do here)

- The actual `cargo publish` / name reservation (operator action, separate).
- deb/rpm/manpages/installers (#545).
- Any product-code change or `deny.toml` allow-list addition.
