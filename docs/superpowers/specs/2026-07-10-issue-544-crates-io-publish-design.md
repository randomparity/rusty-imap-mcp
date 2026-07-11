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
  `data/confusables.txt` (Unicode TR39), licensed **Unicode-DFS-2016**.
  `build.rs` reads the file at build time and emits a `phf::Map` to `OUT_DIR`,
  so the data file **must** ship inside the published package — it cannot be
  excluded. The crate currently inherits the workspace `MIT OR Apache-2.0`,
  which does not cover the vendored data. A `TODO` in
  `crates/rimap-content/Cargo.toml` already prescribes the fix.
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
- **Self-referential dev-dependencies:** `rimap-smtp` and `rimap-server` each
  dev-depend on themselves (`path = "."`, with `version =`) to enable their own
  `test-support`/`test-injection` features in tests. This is a supported cargo
  pattern but is a known friction point at `cargo publish` verify time and must
  be validated empirically (see Risks).
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

3. **Ordered, idempotent publish script.** `scripts/publish-crates.sh` walks
   the topological order above. For each crate it checks whether the exact
   current version is already on crates.io; if so it **skips** (idempotent /
   resumable — re-running the same tag after a mid-run failure continues where
   it stopped). Otherwise it runs `cargo publish -p <crate> --locked`. It relies
   on cargo's built-in publish-wait (cargo ≥ 1.66 blocks until the crate is
   available in the index before returning) so each dependent resolves its
   just-published dependencies; a bounded index-availability poll is added as
   defense in depth. The script supports a `--dry-run` mode for local
   verification.

4. **`cargo-semver-checks` gate.** The publish job runs
   `cargo semver-checks check-release --workspace` before the publish loop. On
   the first publish there is no crates.io baseline, so it reports the crates as
   new and passes; from the second release onward it fails the publish if a
   crate's public API changed incompatibly without an appropriate version bump.
   Pinned install in CI. A `just semver-checks` local target is added for parity
   (no-ops until a baseline exists).

5. **`rimap-content` relicense.** Override the workspace license on the crate:
   `license = "(MIT OR Apache-2.0) AND Unicode-DFS-2016"`, remove the `TODO`,
   and add `"Unicode-DFS-2016"` to `deny.toml`'s `[licenses] allow` list. The
   existing `crates/rimap-content/NOTICE` (git-tracked, ships with the package)
   carries the attribution.

6. **Metadata completeness.** Add `keywords` (≤ 5, ≤ 20 chars each) and
   `categories` (valid crates.io slugs only) to the seven crates that lack them;
   keep `rimap-smtp`'s. Leave `documentation` implicit — crates.io auto-links
   `docs.rs/<crate>` when the field is unset, so an explicit field is redundant.

7. **Name reservation is out of scope for this PR's diff.** Reserving the eight
   names is an irreversible external write and is handled as a discrete
   operational step (with the maintainer's token), not committed code. This spec
   and RELEASING.md document the step; the code changes make publishing
   *possible*, and the first stable tag (or the deliberate reservation step)
   performs it.

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

Category slugs are validated against the crates.io category list;
unknown slugs are dropped with a warning by `cargo publish`, so the
`--dry-run` guardrail surfaces any typo.

### `scripts/publish-crates.sh`

- Bash, `set -euo pipefail`, `shellcheck`/`shfmt`-clean (repo guardrail).
- Constant, ordered crate list (topological order above).
- `already_published <crate> <version>`: `GET
  https://crates.io/api/v1/crates/<crate>/<version>` → HTTP 200 means present
  (skip), 404 means publish. A descriptive `User-Agent` is sent (crates.io
  requires one).
- Reads the version once from the workspace (`cargo metadata` or the workspace
  `Cargo.toml`), asserts it contains no `-dev` (defense in depth beside
  `verify-tag`), and uses it for every crate (workspace-uniform version).
- `--dry-run`: runs `cargo publish --dry-run --locked -p <crate>` for the leaf
  (`rimap-core`, fully build-verifiable) and
  `cargo publish --dry-run --no-verify --locked -p <crate>` for dependents
  (metadata/packaging validation without a registry-resolved build, which is
  impossible pre-publish for unpublished deps). This catches missing
  `description`/`license`, version-less deps, and bad category slugs.
- Real mode: `cargo publish -p <crate> --locked`, honoring
  `CARGO_REGISTRY_TOKEN` from the environment. After each publish, a bounded
  poll (e.g. up to ~120 s) on the crates.io API confirms index availability
  before the next crate, augmenting cargo's own wait.

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

- **RELEASING.md:** add crates.io to one-time setup (reserve names, add
  `CARGO_REGISTRY_TOKEN` to the `crates-io` environment, optional reviewer),
  add `publish-crates` to "What automation does", move crates.io out of
  "Planned (later phases)".
- **CHANGELOG.md `[Unreleased]`:** record the pipeline addition.
- **`justfile`:** `publish-dry-run` (runs the script's `--dry-run`) and
  `semver-checks` targets.

## Success criteria (falsifiable)

1. `just publish-dry-run` exits 0 locally: all 8 crates package with complete
   metadata and version-carrying deps; no missing `description`/`license`.
2. `cargo deny check licenses` (`just deny`) is green with `rimap-content`
   declaring `(MIT OR Apache-2.0) AND Unicode-DFS-2016`.
3. `scripts/publish-crates.sh --dry-run` and the script itself are
   `shellcheck`- and `shfmt`-clean.
4. `actionlint` and `zizmor` pass on the edited `release.yml`; every `uses:` is
   a SHA pin with a version comment.
5. Re-running the script when a version is already published skips that crate
   (unit-tested via the `already_published` predicate against a mocked/real
   crates.io response) rather than erroring.
6. `just ci` is green on the branch.
7. The `publish-crates` job is stable-only and `push`-only: a `-dev` or
   `workflow_dispatch` invocation never reaches `cargo publish` (asserted by the
   job `if:` and the script's in-band `-dev` assertion).

## Risks & mitigations

- **Self-referential dev-dependency at publish verify.** `rimap-smtp` /
  `rimap-server` dev-depend on themselves. If `cargo publish` verify rejects
  this, the mitigation is to make the self dev-dep **path-only** (drop
  `version =`); cargo strips path-only dev-deps from the published manifest.
  This must be **verified empirically during build** (a full local
  registry-backed publish, or accepted-and-checked at first real publish). The
  plan carries an explicit investigation task with this decision point.
- **Partial publish (irreversibility).** If crate *k* fails after 1..k-1
  succeeded, those versions are permanently public. Mitigations: topological
  order minimizes cross-dependency failures; idempotent skip-by-version makes a
  same-tag re-run resume; a bug fix requires a new patch tag (normal crates.io
  practice). Documented in RELEASING.md.
- **Index propagation lag between dependent publishes.** Mitigated by cargo's
  built-in publish-wait plus the script's bounded availability poll.
- **`cargo-semver-checks` false gate on first release.** No baseline ⇒ treated
  as new crates ⇒ passes. Verified by the dry-run path; the gate only bites from
  release #2.
- **Unknown category slug.** Silently dropped by cargo (warning). Surfaced by
  the `--dry-run` guardrail; slugs chosen from the published category list.
