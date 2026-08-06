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
`Contents: read and write`, held on a `fuzz-lock-realign` **environment** rather
than at repository scope, so it is readable by this job alone and each use lands
in the deployment log. The environment must carry no required reviewers: an
approval gate would reinstate the manual step. **Without the secret the workflow
fails on its first step with that instruction**; a silent skip was rejected,
because a warning nobody reads reinstates that step just as surely.

The PAT should be issued from an account holding *write*, not admin. `main`'s
protection has `enforce_admins` disabled, so an admin-owned PAT would, if ever
disclosed, be equivalent to unrestricted push to `main`. Tracked separately.

`pull_request_target` combined with a write credential and PR-head content is
the most exploited pattern in GitHub Actions, so the safety argument is the
substance of this decision, not a footnote. One property carries it:

> **No file from the PR head is ever executed.**

The job checks out the *base* commit and runs the base branch's `justfile` and
`scripts/` in that tree. From the head it copies in exactly the files named
`Cargo.toml` and `Cargo.lock` — data that cargo reads, never code it runs —
and then reads them with `cargo metadata`, which resolves and downloads but
never compiles, so no `build.rs` and no proc-macro executes either. That was
verified empirically against a crate whose `build.rs` writes a sentinel file:
after `cargo metadata` the sentinel does not exist. Everything the head could
otherwise use to obtain execution — `.cargo/config.toml` and its `build.rustc`
hook, a build script, the `justfile`, `scripts/` — stays at the base branch's
version, because the overlay never copies it. To push, the job restores the
pristine head tree and writes back only the two realigned lockfiles, so it
still executes nothing from the head.

**A path allowlist alone does not establish this, and an earlier draft of this
ADR wrongly claimed it did.** A file's *name* says nothing about its *mode*. A
manifest committed as a symlink (mode `120000`) still matches
`^(.*/)?Cargo\.(toml|lock)$`; `git checkout` materializes it as a real link,
and the realign's `shutil.copyfile` opens the destination for writing and
follows it. That is an arbitrary out-of-tree write of head-controlled content —
enough to overwrite `~/.gitconfig`, whose `core.fsmonitor` and `core.pager` are
command hooks that the very next `git` invocation would run, inside the job that
holds the push credential. It was reproduced against this repo before it was
fixed: the path gate passed, and a file outside the checkout was overwritten
with the workspace lockfile's contents.

Two controls close it, either sufficient alone:

- the gate rejects any manifest whose blob mode is not a regular file
  (`120000` symlink, `160000` gitlink), which a path regex structurally cannot
  see; and
- the overlay checks out with `core.symlinks=false`, so git writes a symlink
  blob as an ordinary file holding its target text rather than as a link.

The lesson is worth keeping with the decision: "only these paths" is not the
same statement as "only these bytes, as data".

Every commit the job touches is pinned to `github.event.pull_request.head.sha`
from the event payload: the diff that is inspected, the manifests that are
copied in, and the tree that is committed are one tree. An earlier draft
checked out that pinned SHA but read the file list from
`GET /pulls/{n}/files`, which describes the *current* head — validating one
tree and executing another, with a window an attacker holding push access
could widen. Deriving both from the same pinned SHA closes it structurally.

Three supporting controls narrow the attacker population and limit blast
radius. None of them is load-bearing, and none would stop code execution on its
own — that is the property above:

- **Fork PRs cannot reach the job.** The condition requires
  `github.event.pull_request.user.login == 'dependabot[bot]'` — the PR
  *author*, fixed at open time and unmovable by a third party, and
  unimpersonable because `[` and `]` are not legal in a GitHub login — **and**
  `head.repo.full_name == github.repository`, so the head branch must live in
  this repository. Pushing a branch here already requires write access.

- **`GITHUB_TOKEN` cannot push.** Workflow-level `permissions` is `{}`; the job
  asks for `contents: read`, the minimum `actions/checkout` needs. The checkout
  runs with `persist-credentials: false`. `FUZZ_LOCK_REALIGN_TOKEN` lives on a
  `fuzz-lock-realign` environment rather than at repository scope, enters the
  environment in the final step only, is passed in the push URL rather than
  written to `.git/config`, and that step disables git hooks. Note what this is
  and is not: steps share one VM and one uid, so step-scoped `env` bounds which
  step's environment holds the secret — it is not an isolation boundary.

- **The diff must be cargo manifests and lockfiles, and nothing else.** This is
  a *scope* guard, not the security control: it stops the workflow pushing an
  automated commit to a PR that is not an ordinary Dependabot bump. It compares
  against the merge base rather than the base tip, because a two-dot diff also
  reports every commit that landed on main after the PR branched — which, with
  `strict` branch protection here, is most PRs. An empty file list fails rather
  than passes, the same rule `scripts/check-fuzz-lock-parity.sh` applies to
  itself.

The workflow file is read from the base branch on `pull_request_target`, so
every inline `run:` block in it is trusted code by construction — and, with the
restructure above, those blocks no longer shell out to head-provided files.

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
  secret and one that downloads the result as an artifact and pushes it. This
  is genuinely stronger than step-scoped `env`, and for an honest reason: two
  jobs are two VMs, so the credential is out of reach of anything the first job
  left running, which no arrangement of steps within one job can achieve.
  Declined on complexity, not on security — and only because the property it
  defends against, code execution from the head, is already excluded by
  construction. It is the right next move if that ever stops being true.

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

- **A `fuzz-lock-realign` environment must carry a `FUZZ_LOCK_REALIGN_TOKEN`
  secret.** Until it
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

- `required_status_checks.strict` is on, and this workflow's push is what stops
  Dependabot auto-rebasing. So a PR that falls behind now costs an
  `@dependabot rebase` (which drops the realign commit), a re-realign and a
  re-push — two extra CI rounds. It converges; it is not free.

- Nothing here is exercised as a *workflow* until a real Dependabot PR triggers
  it, because `pull_request_target` does not run from a feature branch. What
  was verified directly: the whole job body, replayed step by step against
  PR #713's live 11-package drift in a scratch clone — base checkout, merge-base
  gate, manifest overlay, realign, parity re-check, lockfile save/restore onto
  the pristine head tree, and the resulting commit, which passes
  `just check-fuzz-lock-parity` on its own tree; the gate's rejection arm,
  against a PR that is not a cargo bump; the symlink-overlay attack above, which
  overwrites an out-of-tree file without the two controls and leaves it
  untouched with them; the `cargo metadata` non-execution property; and
  `actionlint` plus `zizmor`. What was not: the trigger, the actor gate, the
  environment secret, and the push.
