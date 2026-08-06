# ADR-0016: Dependabot fuzz-lock realignment runs in CI on `pull_request_target`

**Status:** Accepted · 2026-08-06 · issue [#698](https://github.com/randomparity/rusty-imap-mcp/issues/698)

**Relates to:** [ADR-0011](0011-fuzz-lockfile-workspace-parity.md) — this
records how the cost ADR-0011 accepted is paid. ADR-0011's decision is
unchanged and is not superseded.

## Context

ADR-0011 gates the two tracked fuzz lockfiles for parity with the workspace
`Cargo.lock` and accepted a named cost:

> **Every workspace dependency bump that touches a shared package now fails
> this gate until the fuzz lockfile is realigned.** In practice that means
> Dependabot PRs on the `/` cargo ecosystem will frequently need one extra
> commit from `just realign-fuzz-locks`.

"Frequently" turned out to be "every time". Nothing updates a fuzz lockfile:
the root `Cargo.toml` excludes `fuzz`, `crates/rimap-server/fuzz` declares its
own `[workspace]`, and `.github/dependabot.yml` has cargo entries for `/` and
`/html-oracle` only. So Dependabot moves the workspace lock, the fuzz locks
stay put, and the **required** `cargo-deny` check goes red before a human looks
at the PR. Commit `749d97e1` on `main` is that manual realign, done by hand.

The failure is not a dependency problem — `advisories`, `bans`, `licenses` and
`sources` all report `ok` on the same run. It is the parity step alone. Rebasing
does not clear it, because `main`'s fuzz locks are in parity at the *old*
versions; the realign has to land on the PR branch.

The cost is not the two minutes of `just realign-fuzz-locks`. It is that red CI
becomes the normal state of the dependency queue, which is how a required check
stops being read.

## Decision

`.github/workflows/dependabot-fuzz-lock.yml` runs `just realign-fuzz-locks` on
Dependabot PRs that move the workspace `Cargo.lock`, and pushes the result to
the PR branch.

The workflow triggers on `pull_request_target`, because a `pull_request` run on
a Dependabot-authored PR receives a read-only `GITHUB_TOKEN` and cannot push.

**Pushing uses a PAT (`FUZZ_LOCK_REALIGN_TOKEN`), not `GITHUB_TOKEN`.** This is
not a preference. Pushes authenticated with `GITHUB_TOKEN` do not trigger
workflows, so a realigned head would carry no CI runs at all and the required
checks would sit permanently "expected" — strictly worse than the red check it
replaced. The secret is a fine-grained PAT scoped to this repository with
`Contents: read and write`. **Without it the workflow fails on its first step
with that instruction**; a silent skip was rejected, because a warning nobody
reads reinstates exactly the manual step this removes.

`pull_request_target` combined with a write credential and PR-head content is
the most exploited pattern in GitHub Actions, so the safety argument is the
substance of this decision, not a footnote. Four independent properties hold,
and no single one is load-bearing alone:

1. **Fork PRs cannot reach the job.** The job condition requires
   `github.event.pull_request.user.login == 'dependabot[bot]'` — the PR
   *author*, fixed at open time and unmovable by a third party — **and**
   `head.repo.full_name == github.repository`, so the head branch must live in
   this repository. Pushing a branch here already requires write access, which
   excludes the entire untrusted-contributor population.

2. **`GITHUB_TOKEN` cannot push and the PAT is not in scope during the work.**
   Workflow-level `permissions` is `{}`; the job asks for `contents: read`,
   which is the minimum `actions/checkout` needs. The checkout runs with
   `persist-credentials: false`, so no credential is in `.git/config` while PR
   content is on disk. `FUZZ_LOCK_REALIGN_TOKEN` enters the environment in the
   final step only, after every read of PR content has completed.

3. **The diff must be cargo manifests and lockfiles, and nothing else.** Before
   any tool interprets PR content, the job lists the PR's files from the API
   and fails unless every path matches `Cargo.toml` or `Cargo.lock`. This is
   what excludes `.cargo/config.toml` — whose `build.rustc` and
   `build.rustc-wrapper` settings are arbitrary-command hooks that `cargo`
   honours — along with any added `build.rs`, and any edit to the `justfile` or
   `scripts/` the job then runs. Passing this gate is what proves those files
   are byte-identical to the base branch's.

4. **`cargo metadata` does not compile.** The realign copies the workspace
   lockfile over each fuzz lockfile and runs `cargo metadata`, which resolves
   the graph and downloads `.crate` files to read their manifests. It runs no
   build script and builds no proc-macro. This was verified empirically against
   a crate whose `build.rs` writes a sentinel file — after `cargo metadata` the
   sentinel does not exist — rather than taken from documentation.

The workflow file is read from the base branch on `pull_request_target`, so
every inline `run:` block in it is trusted code by construction.

**Loop containment.** The push is authenticated as the PAT's owner, so the
`synchronize` it fires carries a human actor and the third job condition,
`github.actor == 'dependabot[bot]'`, stops the workflow re-entering itself. The
realign is idempotent besides — a second run finds parity already restored and
pushes nothing — so termination does not depend on the actor check. A per-PR
`concurrency` group with `cancel-in-progress` bounds overlap.

zizmor reports `bot-conditions` on that actor check, and is right in general,
which is why it carries none of the security weight here: spoofing it can only
cause the job to *run*, and running still requires properties (1). The ignore
is scoped to that single expression, and zizmor's recommended replacement,
`github.event.pull_request.user.login`, is already the first condition.

## Alternatives considered

- **Dependabot entries for `/fuzz` and `/crates/rimap-server/fuzz`.** Rejected
  for the same reason ADR-0011 rejected it, now with a second one: Dependabot
  would open *separate* PRs on its own schedule, which race the workspace PR and
  drift the lockfiles the other way until both merge. It converts one red check
  into two PRs that are each red until the other lands.

- **Document the manual step in the merge runbook and accept it.** Rejected as
  the end state, though it is what `main` does today. It leaves the required
  check red by default on an automated-by-design queue.

- **Advisory-only gate** — downgrade the parity check to a warning on
  Dependabot PRs. Rejected: it removes the signal ADR-0011 exists to create,
  and the drift it detects is silent by nature.

- **Push with `GITHUB_TOKEN`.** Rejected on mechanism, above: the realigned
  head would carry no CI runs.

- **Split into two jobs**, one that runs `cargo metadata` with no access to the
  secret and one that downloads the result as an artifact and pushes it.
  Rejected: the artifact would then be the trust boundary, and validating it in
  the pushing job reproduces the same path checks against more moving parts.
  Step-scoped `env` already keeps the credential out of the environment that
  processes PR content, which is the property the split would buy.

- **A GitHub App token** (`actions/create-github-app-token`) instead of a PAT.
  Better in principle — installation tokens are short-lived and
  repository-scoped by construction — and rejected only on setup cost: it needs
  an App plus two secrets where the PAT needs one. It is the upgrade path if the
  PAT ever needs to be rotated or widened.

## Consequences

- A Dependabot cargo PR that moves shared packages reaches green required
  checks without a human, one extra commit later. `cargo-deny` and every other
  required check re-run on the realigned head, because the push is not
  `GITHUB_TOKEN`-authenticated.

- **The repository must carry a `FUZZ_LOCK_REALIGN_TOKEN` secret.** Until it
  exists, every Dependabot cargo PR gains one failing non-required check whose
  message says how to create it. This is a deployment prerequisite, not a
  degraded mode.

- **Dependabot stops auto-rebasing a PR once this workflow pushes to it** — it
  treats a branch a third party has touched as no longer solely its own.
  `@dependabot rebase` hands it back, and the force-push that follows fires
  `synchronize`, so the next run realigns the new head. Recorded in
  `crates/rimap-server/fuzz/README.md`, next to the manual command it replaces.

- The workflow refuses any Dependabot PR whose diff reaches beyond cargo
  manifests and lockfiles. That is a deliberate false-negative: such a PR gets
  the pre-existing manual `just realign-fuzz-locks` treatment, with a log line
  saying so.

- The push is a plain fast-forward, never a force-push. If Dependabot moved the
  branch mid-run the push fails and the resulting `synchronize` starts a fresh
  run against the new head.

- The realign re-resolves the fuzz-only packages (`libfuzzer-sys`, `arbitrary`,
  `jobserver`) from the index each time, because seeding from the workspace
  lockfile discards their previous pins. A fuzz-only release landing between two
  runs on the same PR therefore produces one additional commit. It cannot
  produce more: the run after it resolves to the same versions and pushes
  nothing.

- Nothing here is exercised until a real Dependabot PR triggers it. A
  `pull_request_target` workflow does not run from a feature branch, so the
  mechanism (`just realign-fuzz-locks` against live drift), the linters
  (`actionlint`, `zizmor`) and the `cargo metadata` non-execution property were
  verified directly, and the trigger, actor gate and push were not.
