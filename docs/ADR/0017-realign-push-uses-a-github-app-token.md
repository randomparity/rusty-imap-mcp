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

- **It is a separate identity that branch protection applies to.** An App
  installation is not the repository owner. `enforce_admins: false` exempts
  admins; it does not exempt an App. So a disclosed installation token is
  bounded by `main`'s protection in a way a disclosed admin PAT is not. This is
  what closes #742's core risk structurally rather than by a policy nobody can
  enforce with one human account.

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

Two further bounds, unchanged, make termination independent of that gate: the
`paths: ['Cargo.lock']` filter means only a push that moves the workspace
lockfile can re-trigger at all, and the realign is idempotent — a second run
finds parity restored, sets `changed=false`, mints no token and pushes nothing.
So even with the actor gate hypothetically defeated, the sequence terminates
after one additional run. The per-PR `concurrency` group with
`cancel-in-progress` bounds overlap.

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
  environment.** Until they exist, every Dependabot cargo PR gains one failing
  non-required check whose message says how to create them. This is a
  deployment prerequisite, not a degraded mode — the same posture ADR-0016 took
  toward its own secret. Two secrets where the PAT needed one; that setup cost
  is the price ADR-0016 declined to pay and this ADR accepts.

- **`FUZZ_LOCK_REALIGN_TOKEN` should be deleted from the `fuzz-lock-realign`
  environment and revoked** once the App is in place. Nothing reads it after
  this change, and leaving an admin-owned push credential in the environment
  the workflow already has access to would keep the exact risk this ADR closes.

- The commits the workflow pushes are attributed to `github-actions[bot]` as
  before (the `user.name` / `user.email` git config is unchanged), while the
  *push* is authenticated as the App. Author identity and push identity differ;
  only the latter determines `github.actor` on the resulting event, which is
  what loop containment reads.

- One more moving part in the supply chain: `actions/create-github-app-token`
  now runs in a job that holds a write credential. It is pinned to a 40-char
  commit SHA like every other action here, and it runs *after* all PR content
  has been read, so it cannot be reached by anything the head supplied.

- Nothing here is exercised as a *workflow* until a real Dependabot PR triggers
  it with the App installed, because `pull_request_target` does not run from a
  feature branch and an App token cannot be minted outside a run holding the
  secrets. What was verified for this change: `actionlint` and `zizmor` on the
  revised file, the pinned action SHA resolved against
  `actions/create-github-app-token`'s `v3.2.0` tag, the documented
  trigger-on-push behaviour cited above, and a `ci-cd-security-reviewer` pass.
  What was not: the mint, the push, the resulting `synchronize`, and the actor
  value on it. ADR-0016's own unverified list is unchanged by this ADR.
