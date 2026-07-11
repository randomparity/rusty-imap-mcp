# crates.io Publish of the 8 Workspace Crates (Issue #544)

- **Issue:** [#544](https://github.com/randomparity/rusty-imap-mcp/issues/544)
  — "Phase 2B: Publish workspace crates to crates.io"
- **ADR:** [ADR-0004](../../ADR/0004-crates-io-publish-topology.md)
- **Depends on:** [ADR-0003](../../ADR/0003-manifest-dev-version-model.md) /
  the `-dev` version model
  ([spec](2026-07-10-dev-version-model-design.md)) — settles the clean-version
  invariant this work consumes.
- **Sequencing context:** [ADR-0002](../../ADR/0002-phased-bzr-release-parity-and-direct-publish.md).
  Note a numbering drift: ADR-0002 calls crates.io "Phase 3"; the issue labels
  it "Phase 2B". Same work; the issue number (#544) is the tracking id.

## Goal

Make the eight `rimap-*` workspace crates installable via `cargo add` /
`cargo install` by publishing them to crates.io as part of the existing tag-
driven release pipeline. Non-goal: deb/rpm/manpages/installers (issue #545).

## Background & current state (verified 2026-07-10)

- **crates.io name availability:** all eight `rimap-*` names return 404
  (available). The ADR-0002 "open risk" of name unavailability is retired for
  the pipeline itself; first publish *reserves* the names (crates.io has no
  pure-reservation primitive — claiming a name means publishing a version).
- **Per-crate metadata:** every crate already declares a `description`.
  `license`/`repository`/`readme`/`authors`/`version`/`edition`/`rust-version`
  are workspace-inherited. Only `rimap-smtp` currently carries
  `keywords`/`categories`.
- **License blocker (`rimap-content`):** the crate vendors
  `data/confusables.txt` (Unicode TR39). Its header is `© 2024 Unicode, Inc.`,
  dated `2024-08-14`, Unicode 16.0 — i.e. released under the **Unicode License
  v3**, SPDX identifier **`Unicode-3.0`** (*not* the older `Unicode-DFS-2016`;
  the crate's stale `TODO` and `data/NOTICE` both misname it, conflating the two
  — this spec corrects that). `build.rs` reads the file at build time and emits
  a `phf::Map` to `OUT_DIR`, so the data file **must** ship inside the published
  package — it cannot be excluded. The crate currently inherits the workspace
  `MIT OR Apache-2.0`, which does not cover the vendored data. Crucially,
  `deny.toml` **already allows `Unicode-3.0`** (line 27), so the correct fix
  needs **no** `deny.toml` change.
- **Version invariant (from ADR-0003):** `main` lives at `X.Y.Z-dev`; a
  release-prep PR strips `-dev` via `cargo set-version --workspace X.Y.Z`,
  which also rewrites the 24 intra-workspace path-dep `version =` fields to the
  clean version. At the tagged commit the workspace version is clean and every
  path dep's `version =` matches it. **crates.io publish depends on this
  invariant** and must never run for a `-dev` tag.
- **Intra-workspace dependency DAG** (path deps, all carrying `version =`):
  ```
  rimap-core     → (none)
  rimap-config   → core
  rimap-audit    → core
  rimap-content  → core
  rimap-authz    → core, config
  rimap-imap     → core, config, audit
  rimap-smtp     → core, config
  rimap-server   → all seven
  ```
  A valid linear topological publish order:
  **core → config → audit → content → authz → imap → smtp → server.**
- **Self-referential dev-dependencies (three crates):** `rimap-content`
  (`[dev-dependencies.rimap-content]` table-header form), `rimap-smtp`, and
  `rimap-server` each dev-depend on themselves (`path = "."`, with `version =`)
  to enable their own `test-support`/`test-injection` features in tests. This is
  a supported cargo pattern but is a known friction point at `cargo publish`
  verify time (the `version =` is stripped-to-registry in the published manifest,
  referencing a version not yet on the registry). This PR **proactively removes
  the `version =`** from all three self dev-deps, making them path-only — cargo
  drops path-only dev-deps from the published manifest entirely, eliminating the
  risk while keeping local `cargo test` working (see Risks).
- **crates.io publish rate limits** (verified against `crates.io/docs/rate-limits`
  and rust-lang/crates.io PR #6875): **publishing a brand-new crate name** is
  limited to a **burst of 5, then 1 every 10 minutes**; **publishing a new
  version of an existing crate** is a separate, far higher bucket (**burst 30,
  1/min**). This is load-bearing for the first publish: publishing all **8 new
  names** in one run deterministically 429s at crate #6 (`rimap-imap`). The
  design consequence: the **first** publish (name reservation) is a deliberate,
  paced action — see Decision 3 and the operational note — while every
  **subsequent** release publishes new *versions* of now-existing crates (burst
  30) and completes in one CI run.
- **Release trigger:** `release.yml` runs on `push` of a `v*` tag. Jobs:
  `verify-tag → build ×5 → release → homebrew → bottles → bottles-merge`, plus
  `post-release-bump`. `homebrew`/`bottles*` are stable-only
  (`!contains(ref_name, '-')`) and use `environment:`-gated tap tokens.

## Decisions

These are recorded with alternatives in ADR-0004; summarized here.

1. **Publish topology.** A new `publish-crates` job in `release.yml`,
   `needs: release` (runs only after the GitHub Release + artifacts are
   published — the issue's "after artifacts publish"). Gated to stable tags on
   `push` (`github.event_name == 'push' && !contains(github.ref_name, '-')`),
   mirroring `homebrew`. Failure of `publish-crates` does not un-publish the
   GitHub Release (it is a downstream leaf, like `homebrew`).

2. **Publish gate = fully automatic once configured.** The job runs behind an
   `environment: crates-io` that holds the `CARGO_REGISTRY_TOKEN` secret, with
   **no required reviewer** (operator's decision). Until the environment +
   secret exist, the job runs but `cargo publish` fails for lack of a token —
   which is acceptable (downstream leaf; does not affect the release). Tag
   protection (already required by RELEASING.md) is the human control on what
   gets published.

3. **Ordered, idempotent, rate-limit-aware publish script.**
   `scripts/publish-crates.sh` walks the topological order above. For each crate
   it checks whether the exact current version is already on crates.io; if so it
   **skips** (idempotent / resumable — re-running the same tag after a mid-run
   failure continues where it stopped). Otherwise it runs
   `cargo publish -p <crate> --locked`. On an HTTP 429 (rate limit) it parses the
   "try again after" time from cargo's error, sleeps until then (bounded by a
   `MAX_RATE_WAIT` cap), and retries the same crate — so even a fresh 8-new-crate
   run eventually completes rather than aborting under `set -euo pipefail`. After
   each publish it polls the **sparse index** (`index.crates.io`) for the exact
   just-published version before proceeding to the next crate (cargo's own
   publish-wait only *warns* on timeout, so this is the authoritative
   readiness guard for the next dependent's verify build). The script supports a
   `--dry-run` mode for local verification.

4. **`cargo-semver-checks` gate.** The publish job runs
   `cargo semver-checks check-release --workspace` before the publish loop. On
   the first publish there is no crates.io baseline, so it reports the crates as
   new and passes; from the second release onward it fails the publish if a
   crate's public API changed incompatibly without an appropriate version bump.
   Pinned install in CI. A `just semver-checks` local target is added for parity
   (no-ops until a baseline exists).

5. **`rimap-content` relicense.** Override the workspace license on the crate:
   `license = "(MIT OR Apache-2.0) AND Unicode-3.0"`, and remove the `TODO`.
   **No `deny.toml` change** — `Unicode-3.0` is already on the allow list. Fix
   `crates/rimap-content/data/NOTICE`, which currently misnames the license as
   "Unicode License v3 (Unicode-DFS-2016)"; it should read Unicode License v3
   (`Unicode-3.0`). The `data/NOTICE` file is git-tracked and ships with the
   package (the whole `data/` dir is packaged because `build.rs` reads
   `confusables.txt`), carrying the attribution.

6. **Metadata completeness.** Add `keywords` (≤ 5, ≤ 20 chars each) and
   `categories` (valid crates.io slugs only) to the seven crates that lack them;
   keep `rimap-smtp`'s. Leave `documentation` implicit — crates.io auto-links
   `docs.rs/<crate>` when the field is unset, so an explicit field is redundant.

7. **Name reservation is out of scope for this PR's diff, and is the deliberate
   first publish.** Reserving the eight names is an irreversible external write,
   handled as a discrete operational step (with the maintainer's token), not
   committed code. It is best done **locally** by running
   `scripts/publish-crates.sh` from a checkout at the release version: the
   new-crate burst limit (5) is crossed on this first run, and a local run can
   sleep through the ~10-min refill for crates #6–8 without burning CI minutes
   (the same script's 429 handling applies in CI too, but a CI run would idle-
   bill through the waits). After the eight names exist, every subsequent tagged
   release publishes new *versions* (burst 30) and completes in one CI run.
   RELEASING.md documents this; the code changes make publishing *possible*.

## Detailed design

### Metadata (per-crate `[package]`)

| crate | keywords | categories |
|-------|----------|-----------|
| rimap-core | `imap, email, mcp, types` | `email` |
| rimap-config | `imap, config, credentials, mcp` | `config, email` |
| rimap-audit | `audit, logging, jsonl, mcp` | `email` |
| rimap-content | `mime, email, sanitization, unicode` | `email, parser-implementations, text-processing` |
| rimap-authz | `authorization, rate-limiting, email, mcp` | `email, authentication` |
| rimap-imap | `imap, email, tls, mcp` | `email, network-programming` |
| rimap-smtp | *(unchanged)* `smtp, email, mcp` | `email, network-programming` |
| rimap-server | `imap, email, mcp, security` | `email, command-line-utilities` |

Category slugs are chosen from the published crates.io category list
(`email`, `config`, `parser-implementations`, `text-processing`,
`authentication`, `network-programming`, `command-line-utilities` are all
valid). **`cargo publish --dry-run` does not validate slugs** — it never
contacts the registry; crates.io enforces the list server-side at upload and
silently *warns-and-ignores* an unknown slug (a bad slug is non-fatal but means
the category simply is not applied). A small unit test asserts the chosen slugs
against a pinned copy of the category list so a typo is caught in CI rather than
silently dropped at publish.

### `scripts/publish-crates.sh`

- Bash, `set -euo pipefail`, `shellcheck`/`shfmt`-clean (repo guardrail).
- Constant, ordered crate list (topological order above).
- `already_published <crate> <version>`: `GET
  https://crates.io/api/v1/crates/<crate>/<version>` → HTTP 200 means present
  (skip), 404 means publish. A descriptive `User-Agent` is sent (crates.io
  requires one).
- Reads the version once from the workspace (`cargo metadata` or the workspace
  `Cargo.toml`) and uses it for every crate (workspace-uniform version). In
  **real-publish mode only** it asserts the version contains no `-dev` (defense
  in depth beside `verify-tag`); the assertion is **skipped under `--dry-run`**
  so the dry-run runs on a normal `-dev` working branch (`main` lives at
  `X.Y.Z-dev`) — see Success Criterion #1.
- `--dry-run`: a **single workspace-wide** invocation
  `cargo publish --dry-run --no-verify --locked --allow-dirty --workspace`
  (empirically verified in-repo on cargo 1.94.0 to package all 8 crates). A
  *per-crate* `--dry-run --no-verify -p <dependent>` does **not** work: cargo
  resolves the dependent's unpublished siblings from the registry and fails
  (`no matching package named 'rimap-config'`) — `--no-verify` skips the verify
  build, not sibling resolution. The `--workspace` form resolves siblings
  locally. `--allow-dirty` lets it run on a `-dev` working branch; `--no-verify`
  keeps it fast (the full build is covered by `just check`/`just test`). This
  validates packaging + manifest completeness + that no self-referential
  dev-dep with a `version =` remains (it fails on one until the self-deps are
  path-only). It does **not** validate category slugs (dry-run is offline — the
  metadata guardrail script does that).
- Real mode: `cargo publish -p <crate> --locked`, honoring
  `CARGO_REGISTRY_TOKEN` from the environment.
  - **Rate-limit handling.** A new-crate 429 (burst 5 exhausted) is caught: the
    script parses the retry time from cargo's stderr. If it is within
    `MAX_RATE_WAIT` (the per-wait cap, sized to cover the ~10-min refill), the
    script sleeps until then and retries the same crate; if a single required
    wait exceeds the cap, it exits non-zero with a clear "resume later" message
    (the run is idempotently resumable — already-published crates are skipped).
    This keeps the script from aborting *silently* mid-chain and never leaves a
    half-reserved namespace without an actionable next step.
  - **Index-readiness poll.** After each successful publish, poll the sparse
    index for the exact version — `https://index.crates.io/<p>/<q>/<crate>`
    (path derived per cargo's index layout; for the 4+-char `rimap-*` names,
    `ri/ma/<crate>`) — until the version line appears or a bounded timeout
    elapses, *then* proceed to the next crate. This is the authoritative guard;
    cargo's built-in publish-wait only warns on timeout.
  - The web-API `GET .../crates/<crate>/<version>` is used **only** for the
    `already_published` skip decision, not as an index-readiness signal (the web
    API and `index.crates.io` propagate independently).

### `release.yml` — `publish-crates` job

```yaml
publish-crates:
  name: Publish to crates.io
  needs: release
  if: ${{ github.event_name == 'push' && !contains(github.ref_name, '-') }}
  runs-on: ubuntu-24.04
  environment: crates-io          # holds CARGO_REGISTRY_TOKEN; no reviewer
  permissions:
    contents: read
  steps:
    - checkout (persist-credentials: false, SHA-pinned)
    - install libdbus-1-dev pkg-config   # rimap-config→keyring verify build
    - dtolnay/rust-toolchain stable (same pinned SHA as existing jobs)
    - install cargo-semver-checks (pinned --version)
    - cargo semver-checks check-release --workspace   # gate
    - scripts/publish-crates.sh
      env: { CARGO_REGISTRY_TOKEN: ${{ secrets.CARGO_REGISTRY_TOKEN }} }
```

- Every `uses:` is a 40-char SHA with a version comment (repo/zizmor rule).
- `needs: release` guarantees the "after artifacts publish" ordering; it also
  transitively inherits `verify-tag`'s clean-version guard.
- `libdbus-1-dev` is required because the publish **verify build** of
  `rimap-config` compiles its `keyring` dependency (Linux → libdbus), matching
  the existing `build-linux-x86_64` job.

### Docs

- **RELEASING.md:** add crates.io to one-time setup — reserve names by running
  `scripts/publish-crates.sh` locally at the release version (paced through the
  new-crate burst limit), add `CARGO_REGISTRY_TOKEN` to the `crates-io`
  environment (optional reviewer) — add `publish-crates` to "What automation
  does" with a note that the *first* release's 8 new names exceed the burst
  limit and should be reserved locally beforehand, and move crates.io out of
  "Planned (later phases)".
- **CHANGELOG.md `[Unreleased]`:** record the pipeline addition.
- **`justfile`:** `publish-dry-run` (runs the script's `--dry-run`) and
  `semver-checks` targets.

## Success criteria (falsifiable)

1. `just publish-dry-run` (a single
   `cargo publish --dry-run --no-verify --locked --allow-dirty --workspace`)
   exits 0 locally **on a normal `-dev` branch** and prints "Packaged" for all 8
   crates; the `-dev` guard is skipped under `--dry-run`. (Passes only after the
   self dev-deps are path-only — verified in-repo.)
2. `cargo deny check licenses` (`just deny`) is green with `rimap-content`
   declaring `(MIT OR Apache-2.0) AND Unicode-3.0` and **no** new `deny.toml`
   allow-list entry (`Unicode-3.0` is already allowed).
2a. A unit test asserts every crate's `categories` are members of a pinned
   crates.io category-slug list (`cargo publish --dry-run` cannot, being offline).
2b. `cargo package --list -p rimap-content` includes `data/NOTICE` and
   `data/confusables.txt` (attribution + data actually ship).
2c. No crate's *published* manifest carries a self-referential dev-dependency
   with a `version =` (all three are path-only), verified by inspecting the
   packaged manifest or the `[dev-dependencies]` sections.
3. `scripts/publish-crates.sh --dry-run` and the script itself are
   `shellcheck`- and `shfmt`-clean.
4. `actionlint` and `zizmor` pass on the edited `release.yml`; every `uses:` is
   a SHA pin with a version comment.
5. Re-running the script when a version is already published skips that crate
   (unit-tested via the `already_published` predicate against a mocked/real
   crates.io response) rather than erroring. The first 8-new-name publish is
   understood to span more than one burst (burst 5, then 1/10 min) and is run
   locally/paced — it is *not* expected to complete in a single CI burst.
5a. The script's 429 path parses a retry time and sleeps (bounded by
   `MAX_RATE_WAIT`) instead of aborting — unit-tested against a synthesized
   cargo 429 stderr sample (parse + bounded-sleep decision, with the actual
   sleep stubbed).
6. `just ci` is green on the branch.
7. The `publish-crates` job is stable-only and `push`-only: a `-dev` or
   `workflow_dispatch` invocation never reaches `cargo publish` (asserted by the
   job `if:` and the script's in-band `-dev` assertion).

## Risks & mitigations

- **Self-referential dev-dependency at publish verify (3 crates).**
  `rimap-content`, `rimap-smtp`, and `rimap-server` dev-depend on themselves.
  Rather than defer to an empirical check at the first (irreversible) publish,
  this PR **removes the risk at the source**: drop `version =` from all three
  self dev-deps, making them path-only. cargo drops path-only dev-deps from the
  published manifest, so publish verify never tries to resolve a
  not-yet-published self version; local `cargo test` still resolves them via
  `path = "."`. A plan task confirms all three are converted and that a normal
  `cargo test -p <crate>` still enables the intended `test-*` feature.
- **Partial publish (irreversibility).** If crate *k* fails after 1..k-1
  succeeded, those versions are permanently public. Mitigations: topological
  order minimizes cross-dependency failures; idempotent skip-by-version makes a
  same-tag re-run resume; a bug fix requires a new patch tag (normal crates.io
  practice). Documented in RELEASING.md.
- **Index propagation lag between dependent publishes.** Authoritative
  mitigation is the script's **sparse-index poll** (Decision 3 / Detailed
  design): after each publish it blocks until the exact version appears at
  `index.crates.io/ri/ma/<crate>` before the next crate. cargo's built-in
  publish-wait is a secondary guard only (it warns rather than fails on
  timeout). The web-API GET is used only for the skip decision, never as an
  index-readiness signal.
- **`cargo-semver-checks` false gate on first release.** No baseline ⇒ treated
  as new crates ⇒ passes. The gate only bites from release #2. (Not verifiable
  by the offline dry-run; asserted by reasoning about semver-checks' documented
  no-baseline behavior.)
- **Unknown category slug.** Non-fatal — crates.io warns-and-ignores at upload,
  so the category is silently not applied (it does **not** fail the publish).
  `cargo publish --dry-run` is offline and cannot catch it; a unit test against
  a pinned slug list catches typos in CI.
