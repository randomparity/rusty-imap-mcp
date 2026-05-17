# Pre-push Hook Trim — Replace `just test` With `cargo check`

**Date:** 2026-05-15
**Status:** Design approved; implementation pending
**Scope:** Developer tooling only. No runtime code changes.
**Related memory:** `[[project-push-ssh-keepalive]]`

## Problem

`git push` to `origin` on this repo regularly drops the ref transfer
silently. The `pre-push` stage of `.pre-commit-config.yaml` runs

- `just test` — `prune-containers` + `cargo nextest run --workspace --locked --no-tests=pass` (~25–60 s)
- `cargo deny check advisories bans` (~5 s)

github.com's SSH server has an idle timeout (~30 s) on the
connection. While the hook runs, the SSH session sits idle; the
server severs the connection mid-hook, but the hook itself succeeds.
`git push` then exits 0 with no refs transferred. Symptom and
diagnosis are pinned in this session's `project-push-ssh-keepalive`
auto-memory; the workaround is

```sh
GIT_SSH_COMMAND='ssh -o ServerAliveInterval=15 -o ServerAliveCountMax=20' git push ...
```

which has to be prefixed on every push. That's the everyday friction
this spec eliminates.

## Root cause

The slow step is `just test`. Its runtime exceeds the SSH idle window
for any push large enough that the hook can't finish in ≤30 s. The
nextest run is a full workspace test sweep — useful as a CI gate, but
unnecessary as a *pre-push* gate when:

1. `pre-commit` already runs `cargo clippy --workspace --all-targets --locked -- -D warnings`
   on every commit. Clippy is a superset of `cargo check`, so any
   commit that reaches `pre-push` has already passed compile + type
   + lint checks.
2. CI runs the full `just ci` (cargo-deny + nextest + workspace build
   + mcp-conformance + typos) on every push and PR.
3. Per project convention, contributors run `just ci` locally before
   substantive pushes.

Pre-push as currently configured duplicates work already covered
elsewhere, AND breaks the very network transfer it's supposed to
gate. Net value: negative.

## Desired behavior

After the fix:

1. `git push` to `origin` completes the ref transfer without
   `GIT_SSH_COMMAND` keepalive flags, for any push the developer
   would normally make.
2. Pre-push still surfaces a fast, meaningful local signal:
   compile/type errors before the network round-trip.
3. Cargo-deny advisory/ban gating remains pre-push — it is fast (~5 s)
   and catches new advisories before they hit CI.
4. Test-failure detection moves entirely to CI (already there).

## Approach

Replace the `cargo-nextest` hook in the `pre-push` stage with a
`cargo check` invocation. Single-file edit to
`.pre-commit-config.yaml`:

```yaml
# Before
- id: cargo-nextest
  name: just test (prune stale containers + cargo nextest)
  entry: just test
  language: system
  types: [rust]
  pass_filenames: false
  stages: [pre-push]

# After
- id: cargo-check
  name: cargo check --workspace --all-targets --locked
  entry: cargo check --workspace --all-targets --locked
  language: system
  always_run: true
  pass_filenames: false
  stages: [pre-push]
```

`cargo-deny check advisories bans` stays unchanged. Total pre-push
time drops from ~30-65 s to ~10 s (compile-check ~5 s + deny ~5 s)
on a warm `target/`, comfortably under github's SSH idle window. Cold-
cache pushes are not bounded by this fix; see "Risks and mitigations."

### Why `always_run: true` and not `types: [rust]`

prek's `rust` type matches `.rs` files only. A push that touches only
`Cargo.toml` or `Cargo.lock` — e.g. a dependency bump or
Dependabot-style update — would skip a `types: [rust]` hook entirely,
which is the exact failure mode `--locked` is meant to catch. The
hook is workspace-wide (no per-file behavior) and we always want it
to run on `git push`, so `always_run: true` is correct here.

The existing `cargo-fmt` and `cargo-clippy` pre-commit hooks use
`types: [rust]` and have the same gap on Cargo.toml-only commits.
That's out of scope for this spec but flagged for a future cleanup:
swap those `types: [rust]` clauses for `files: '\.(rs|toml|lock)$'`
or `always_run: true`.

### Why `cargo check` and not nothing

A push could in theory contain a commit that bypassed `pre-commit`
(`--no-verify`, an amended-without-rerun, or a force-pushed branch).
`cargo check` is a 5-second insurance step against those paths. It
costs nothing meaningful relative to the cargo-deny step that's also
running. Honesty bullet: most pushes flow through clippy-at-commit
and don't need this, but the 5 s premium is cheap.

### Why not `cargo clippy` at pre-push

Clippy is already run at pre-commit. Re-running it at pre-push is
the same belt-and-suspenders argument as `cargo check` but slower
(~15 s vs ~5 s). The `cargo check` step covers the same "compile
sanity" failure mode at a third of the runtime; the lint failure mode
is covered at commit time.

### Why not `--all-features`

`cargo check --workspace --all-targets --locked` checks default
features. `--all-features` is slower and CI handles the all-features
variant separately. Pre-push is about speed and a meaningful gate,
not exhaustiveness.

### Why keep `--locked`

`--locked` fails if `Cargo.lock` would be modified — i.e. a stale
or out-of-sync lockfile. Catching this at pre-push is *exactly* the
right time: better than CI's "your branch needs a lockfile update"
failure that requires another round-trip.

## File layout

- **Modified:** `.pre-commit-config.yaml` — single hook entry change.
- **No new files.** No new `just` targets needed; the hook entry is
  the canonical command. Developers running `just check` interactively
  get a similar but `--locked`-free invocation, which is fine for
  inner-loop iteration.

## Memory update

The session-local `project-push-ssh-keepalive` auto-memory becomes
outdated once this ships. As an implementation follow-up, add a
"Resolved by" stanza pointing to the resulting commit so future
sessions know the workaround is no longer required. The
`GIT_SSH_COMMAND` workaround stays documented as historical context
— useful if a future change to the pre-push hooks reintroduces a
slow step. Auto-memory updates happen locally; nothing to check into
git for this step.

## Testing

This is a configuration change in `.pre-commit-config.yaml`; the hook
itself is the test. Manual verification:

1. **Clean push smoke.** Make a trivial commit, push without
   `GIT_SSH_COMMAND` keepalive, observe ref transfer succeeds. The
   memory's repro condition — push exits 0 with no ref transfer —
   should not occur.
2. **Compile-fail rejection.** Introduce a deliberate compile error
   on a feature branch, attempt push, observe the hook fails the
   push with the `cargo check` diagnostic.
3. **Stale-lockfile rejection.** Hand-edit `Cargo.lock` to introduce
   a mismatch with `Cargo.toml`, attempt push, observe `cargo check`
   fails on the `--locked` constraint.
4. **Dep-only push still triggers the hook.** Commit a change that
   touches *only* `Cargo.toml` (e.g. bump a patch version) and push;
   observe `cargo check` runs (proving `always_run: true` works) and
   the push succeeds when the lockfile is in sync, fails when it
   isn't. Pins the `types: [rust]` regression Codex caught in review.
5. **Cargo-deny still gates.** Briefly add a deny rule that flags an
   existing dep (e.g. a known-CVE entry in `deny.toml`), attempt
   push, observe cargo-deny fails the hook. Revert.

No automated regression suite for this change — `prek run --all-files`
exercises the hook in CI's mcp-conformance / lint paths but doesn't
simulate the network timing.

## Risks and mitigations

- **Test regression slips past pre-push** → CI catches it; PR fails
  before merge. Acceptable. The pre-push test gate was already
  unreliable (silent push failures); a reliable lighter gate beats
  an unreliable heavy one.
- **`cargo check` is too lax to catch a real regression** → CI runs
  the full nextest, deny, build, and conformance sweep. Pre-push is
  a smoke gate, not the final word.
- **Developer assumes pre-push runs the tests and is surprised when
  CI catches a failure they could've caught locally** → mitigate
  with a one-liner in the project's CONTRIBUTING / setup notes:
  "Pre-push runs `cargo check` + `cargo deny` only. Run `just ci`
  before pushing if you want the full local sweep." A small docs
  follow-up; out of scope for this spec but flagged here.
- **Pre-commit `cargo clippy` is itself bypassed** (`--no-verify`,
  exotic git workflow). `cargo check` at pre-push catches the
  resulting compile-fail; clippy failures slip through to CI. Same
  net behavior as today, just with the test step removed.
- **Cold `target/` blows the SSH idle window.** `cargo check
  --workspace --all-targets --locked` from a fresh clone or post-
  `cargo clean` state can take several minutes — far beyond
  github's ~30 s idle timeout. Same for a major dependency bump that
  triggers a wide recompile, or a stale advisory DB that cargo-deny
  refreshes on first run. The ~10 s estimate is the *warm-cache*
  case, which is the norm in practice because developers compile
  during inner-loop iteration before pushing. Mitigation when cold:
  fall back to the documented `GIT_SSH_COMMAND='ssh -o ServerAliveInterval=15
  -o ServerAliveCountMax=20' git push ...` workaround from the
  `project-push-ssh-keepalive` memory. A permanent transport-layer
  fix would require `~/.ssh/config` (user's call) or a per-repo
  `git config --local core.sshCommand 'ssh -o ServerAliveInterval=15'`
  documented in CONTRIBUTING — both out of scope for this spec.

## Out of scope

- **`~/.ssh/config` keepalive.** Adding `ServerAliveInterval 15`
  globally for github.com is the user's call — not a repo-level
  concern. The memory mentions it as an alternative permanent fix;
  this spec doesn't preclude or require it.
- **Restructuring `just ci` or the CI workflow.** Untouched.
- **Other pre-commit/pre-push hooks.** `cargo-deny check advisories
  bans` stays in pre-push; pre-commit (fmt, clippy, typos,
  branch-name, forbidden-macros, ts-typecheck) is unchanged.
- **Making `just check` use `--locked` to match the hook.** `just check`
  is the inner-loop developer command and `--locked` would friction
  developers mid-Cargo.toml-edit. The hook owns the `--locked`
  invariant; `just check` stays liberal.
