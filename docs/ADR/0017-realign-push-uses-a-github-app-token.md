# ADR-0017: The fuzz-lock realign pushes with a GitHub App installation token, not a PAT

**Status:** Accepted · 2026-08-06 · issue [#742](https://github.com/randomparity/rusty-imap-mcp/issues/742)

- **Supersedes:** the credential decision of
  [ADR-0016](0016-dependabot-fuzz-lock-auto-realign.md) — its
  "Pushing uses a PAT (`FUZZ_LOCK_REALIGN_TOKEN`), not `GITHUB_TOKEN`"
  paragraph and the `FUZZ_LOCK_REALIGN_TOKEN` deployment prerequisite. Every
  other decision in ADR-0016 — the trigger, the no-execution property, the
  overlay, the two symlink defences, the diff gate, the pinned-SHA discipline —
  is unchanged and is **not** superseded. ADR-0016 named this as "the upgrade
  path"; this is that path being taken.
- **Back-pointer and index row pending.** ADR-0016 does not yet carry the
  matching `Superseded-by` marker this repo's house style asks for, and
  `docs/ADR/README.md` has no row for this ADR — both are deliberately left to
  a separate change to avoid a conflict zone with concurrent branches, tracked
  in [#756](https://github.com/randomparity/rusty-imap-mcp/issues/756). Until
  they land, ADR-0016 still reads as instructing an operator to create
  `FUZZ_LOCK_REALIGN_TOKEN`, which nothing reads after this change. Do not
  create it.

## Context

ADR-0016 chose a fine-grained PAT because a `GITHUB_TOKEN`-authenticated push
starts no workflow runs, which would leave a realigned Dependabot head with its
required checks permanently "expected" — worse than the red check the workflow
exists to clear.

It also wrote down the condition it could not satisfy:

> The PAT should be issued from an account holding *write*, not admin. `main`'s
> protection has `enforce_admins` disabled, so an admin-owned PAT would, if ever
> disclosed, be equivalent to unrestricted push to `main`. Tracked separately.

That tracking is #742, and the intent turns out to be unreachable as stated.
`randomparity/rusty-imap-mcp` is a personal repository with exactly one owner.
Every human account with push access to it is the admin account, so "issue the
PAT from a write-not-admin account" has no account to name. The PAT is
admin-owned or it does not exist, and with `enforce_admins: false` on `main`
that makes the secret equivalent to unrestricted push to the default branch —
bypassing all 13 required checks — on any disclosure: a log-masking miss, a
secret-scanning gap, a future bug in this workflow.

The residual risk is therefore structural, not a matter of being careful with
the PAT, and no amount of scoping a *user* token fixes it: a fine-grained PAT's
permissions bound what it can call, but branch protection that exempts admins
exempts the admin's tokens too.

## Decision

`.github/workflows/dependabot-fuzz-lock.yml` pushes with a **GitHub App
installation access token**, minted per run by
`actions/create-github-app-token` (pinned to
`bcd2ba49218906704ab6c1aa796996da409d3eb1`, v3.2.0) from two secrets on the
existing `fuzz-lock-realign` environment: `REALIGN_APP_ID` and
`REALIGN_APP_KEY`. `FUZZ_LOCK_REALIGN_TOKEN` is removed; there is no fallback
path and no dual-credential mode.

Three properties are the reason, and only the first is about convenience:

- **An installation token still triggers workflow runs.** This is the load-
  bearing claim — if it were false the change would silently reintroduce the
  exact defect ADR-0016 exists to avoid, and a realigned PR would sit on stale
  checks forever. GitHub documents it directly. Under "Triggering a workflow
  from a workflow": *"If you do want to trigger a workflow from within a
  workflow run, you can use a GitHub App installation access token or a
  personal access token instead of `GITHUB_TOKEN` to trigger events that
  require a token."*
  ([Trigger a workflow](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow)),
  and under "When `GITHUB_TOKEN` triggers workflow runs": *"When you use the
  repository's `GITHUB_TOKEN` to perform tasks, events triggered by the
  `GITHUB_TOKEN` will not create a new workflow run"*
  ([GITHUB_TOKEN](https://docs.github.com/en/actions/concepts/security/github_token)).
  The suppression is scoped to `GITHUB_TOKEN`; an App installation token is
  named as one of the two documented ways out of it.

- **It is a separate identity that branch protection applies to, with its own
  ceiling.** An App installation is not the repository owner. `enforce_admins:
  false` exempts admins; it does not exempt an App. So a disclosed installation
  token is bounded by `main`'s protection in a way a disclosed admin PAT is
  not.

  The sharper version of the argument is about *where the ceiling comes from*.
  A PAT can never exceed the privileges of the human who issued it, but on a
  single-owner repository that human is the admin, so the ceiling is admin. An
  App's ceiling is the App's own grant, independent of any human account. The
  App registered for this is **`Contents: Read and write` and nothing else**,
  installed on `rusty-imap-mcp` alone, with its webhook inactive. That is the
  whole ceiling: it cannot administer the repository, cannot change protection,
  cannot read or write secrets, cannot touch Actions or workflows, and cannot
  reach another repository. This is what closes #742's core risk structurally,
  rather than by a policy nobody can enforce with one human account.

- **It is short-lived and minted per run.** An installation token expires in
  about an hour, and `actions/create-github-app-token` revokes it in its
  post-step when the job ends. A PAT is valid until it is manually rotated. The
  disclosure window shrinks from "until someone notices" to "the rest of this
  job".

`permission-contents: write` narrows the minted token to the one scope the push
needs, so widening the installation's grants later does not silently widen this
token. `owner` and `repositories` are left unset, which the action documents as
scoping the token to the current repository.

The mint step is the **last two steps** of the job, gated on
`steps.apply.outputs.changed == 'true'`, so no credential is created at all on
a run that finds parity already restored. ADR-0016's ordering property — the
push credential enters the environment only after every byte of PR content has
been read — is preserved: the mint is a separate step because
`actions/create-github-app-token` is a `uses:` action and cannot live inside
the push's `run:`, but it sits after the diff gate, the overlay, the realign,
the parity re-check and the apply step.

**Fail-loud is preserved and retargeted.** The job's first step still runs
before anything is checked out and still exits 1 with an actionable message
when the credential is missing; it now checks both `REALIGN_APP_ID` and
`REALIGN_APP_KEY`, and the message names the App registration, the
`Contents: read and write` permission, the single-repository installation, and
both secret names. A silent skip was rejected in ADR-0016 for the same reason
it is rejected here.

**Loop containment, re-reasoned.** ADR-0016's argument was that the PAT's push
carries a *human* actor, so the `github.actor == 'dependabot[bot]'` condition
stops re-entry. That argument no longer holds as written, because the push is
now the App. It holds on the same mechanism with a different identity: the
`synchronize` fired by the App's push carries the App's bot login as
`github.actor` — a distinct account from `dependabot[bot]`, which is
unimpersonable because `[` and `]` are not legal in a GitHub login — so the
condition is still false and the job still does not re-enter. Note the change
in what carries the argument: an App push *does* start runs (that is the whole
point), so the platform's own recursion suppression is not available here and
this gate is doing the work.

**The `paths: ['Cargo.lock']` filter is not a loop bound**, and an earlier draft
of this ADR wrongly listed it as one. For `pull_request_target`, GitHub
evaluates `paths` against a three-dot diff of the *whole pull request* — "a
comparison between the most recent version of the topic branch and the commit
where the topic branch was last synced with the base branch"
([workflow syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#onpushpull_requestpull_request_targetpathspaths-ignore))
— not against the incremental push. Dependabot's root `Cargo.lock` change is
still in that diff after the realign, so the filter matches on every
`synchronize`, including the one the App's own push fires. It is an *entry*
filter: it keeps non-cargo Dependabot PRs out of the workflow entirely. It
bounds nothing about recursion. (The realign commit itself touches only
`fuzz/Cargo.lock` and `*/fuzz/Cargo.lock`, which match `paths: ['Cargo.lock']`
under no reading — but that is irrelevant, because the filter never sees the
push in isolation.)

So termination rests on two legs, not three: the actor gate, and idempotency as
its one independent backstop. The realign is idempotent — a second run finds
parity restored, sets `changed=false`, mints no token and pushes nothing — so
even with the actor gate hypothetically defeated the sequence terminates after
one additional run. Anyone relaxing the actor gate must therefore be relying on
idempotency alone, deliberately. The per-PR `concurrency` group with
`cancel-in-progress` bounds overlap; note that the `synchronize` the App's push
fires enters that same group and can cancel the run that pushed, which is one
command wide but can skip the post-step revoke and leave a token valid for its
remaining hour. Still bounded, and still strictly better than a PAT valid until
someone rotates it.

**`app-id` over `client-id`.** Upstream marks `app-id` deprecated in favour of
`client-id`, and still supports it. `app-id` is used because the operator's
secret holds an App ID; switching to `client-id` requires a *different value*
from the App's settings, not a rename, so it is a credential change and not a
code change. It will produce a deprecation annotation on each run until then.

## Alternatives considered

- **Enable `enforce_admins` on `main` and keep the PAT** (#742's option 1).
  Independently worth doing and not excluded by this ADR, but it does not
  replace it: it constrains the admin account, whereas the App removes the
  admin account from the push path entirely. It is also the operator's to run —
  a repository-settings change, not a diff — and turning it on affects every
  human push, not just this workflow's.

- **Keep the PAT and issue it from a machine account holding write**
  (#742's option 2, and ADR-0016's stated intent). Rejected as unreachable: a
  personal repository has one owner, so there is no second human account to
  issue it from, and a machine account would need to be invited as a
  collaborator — a standing second admin-adjacent identity with a
  never-expiring credential, which is more surface than the App, not less.

- **Do nothing and accept the admin-owned PAT.** Rejected. The whole risk is
  that a credential equivalent to unrestricted `main` push sits in a workflow
  that, by design, runs against attacker-influenceable PR content. ADR-0016's
  safety argument is strong but it is an argument; this removes the thing the
  argument is protecting.

- **Split into two jobs**, one without the credential and one that only pushes.
  Unchanged from ADR-0016: genuinely stronger isolation, declined on
  complexity, and the right next move if the no-execution property ever stops
  holding. The App token makes it less urgent, not unnecessary.

## Consequences

- **A GitHub App must exist, be installed on this repository only, and hold
  `Contents: read and write`; its App ID and a private key must be stored as
  `REALIGN_APP_ID` and `REALIGN_APP_KEY` on the `fuzz-lock-realign`
  environment.** This was done on 2026-08-06: the App is registered with that
  single permission and no webhook, installed on `rusty-imap-mcp` only, and
  both secrets exist on the environment, which carries zero protection rules.
  Had they not, every Dependabot cargo PR would gain one failing non-required
  check whose message says how to create them — a deployment prerequisite, not
  a degraded mode, the same posture ADR-0016 took toward its own secret. Two
  secrets where the PAT needed one; that setup cost is the price ADR-0016
  declined to pay and this ADR accepts.

  **The installation itself is operator-confirmed, not machine-verified, and
  cannot be made otherwise from here.** `GET /repos/{owner}/{repo}/installation`
  requires a JWT signed by the App's private key, which nobody outside a run
  holding `REALIGN_APP_KEY` has — deliberately — and `GET /user/installations`
  rejects a classic PAT. So the App ID, the key, and the environment were
  verified; the grant and the installation target were not. The first real
  Dependabot cargo PR is what proves them, and it proves them by working.

- **`FUZZ_LOCK_REALIGN_TOKEN` should be deleted from the `fuzz-lock-realign`
  environment and revoked.** The App is in place, so nothing reads it after
  this change, and leaving an admin-owned push credential in the environment
  the workflow already has access to would keep the exact risk this ADR closes.
  Deleting it is also the cheapest confirmation that the App path works: if the
  realign still succeeds with the PAT gone, it was never the credential in use.

- The commits the workflow pushes are attributed to `github-actions[bot]` as
  before (the `user.name` / `user.email` git config is unchanged), while the
  *push* is authenticated as the App. Author identity and push identity differ;
  only the latter determines `github.actor` on the resulting event, which is
  what loop containment reads.

- **Third-party action code now handles the App private key, and the key
  outlives any token it mints.** This is the one place the App is worse than
  the PAT, and it runs the opposite way round from the usual worry. The action
  is unreachable from PR content — it is SHA-pinned and runs after every byte
  of the head has been read — but it is *handed* `REALIGN_APP_KEY` as an input.
  With the PAT, no third-party code ever saw the credential: it went from
  `secrets.` straight into a `git push` argv inside a base-branch-authored
  `run:`. A future compromised release of `actions/create-github-app-token`
  would exfiltrate not one hour-long token but the key that mints them
  indefinitely. Dependabot proposes that bump as routine, which is exactly how
  it would arrive. Mitigations: the action is `actions/`-owned, pinned to a
  40-char commit SHA, and covered by the `github-actions` Dependabot ecosystem
  with a cooldown. The escape hatch, if that ever stops being enough, is to
  build the JWT with `openssl` and `curl` in a base-branch `run:` and drop the
  third-party step entirely — about fifteen lines, declined here on
  readability.

- **The key's blast radius follows the App's installations, not a fixed
  repository list.** A fine-grained PAT's repository scope is fixed at
  issuance. `owner`/`repositories` being unset bounds the *token this workflow
  mints* to this repository; it does not bound the key. Installing the App on a
  second repository later silently gives the same `REALIGN_APP_KEY` write
  access there. The key also has no expiry. So: install the App on this
  repository only, and rotate the key if it is ever installed elsewhere.

- Two residuals were found reviewing this change and deliberately left out of
  it, because neither is introduced by the credential swap.
  [#754](https://github.com/randomparity/rusty-imap-mcp/issues/754): the
  SonarQube job in `ci.yml` is gated on `github.actor`, so the realign push
  un-skips it on a Dependabot PR and exposes `SONAR_TOKEN` to a job that
  compiles the freshly bumped dependency graph — true of the PAT too, and
  named in neither ADR until now. It should land before the first real realign.
  [#755](https://github.com/randomparity/rusty-imap-mcp/issues/755): no
  environment here carries a deployment branch policy, so environment secrets
  are readable from any branch; that is a free hardening and, unlike a
  reviewer gate, is compatible with this workflow.

- Nothing here is exercised as a *workflow* until a real Dependabot PR triggers
  it, because `pull_request_target` does not run from a feature branch and an
  App token cannot be minted outside a run holding the secrets. What was
  verified for this change: `actionlint` and `zizmor` on the revised file, the
  pinned action SHA resolved against `actions/create-github-app-token`'s
  `v3.2.0` tag, its token-scoping and log-masking behaviour read from the
  action's source at that SHA rather than its README, the documented
  trigger-on-push behaviour cited above, and a `ci-cd-security-reviewer` pass.
  What was not: the mint, the push, the resulting `synchronize`, and the
  `github.actor` value on it — which is the one the loop-containment argument
  turns on. Dependabot PR #713 is open and red on exactly this parity check, so
  it is the live test case as soon as it is re-synchronized. ADR-0016's own
  unverified list is unchanged by this ADR.
