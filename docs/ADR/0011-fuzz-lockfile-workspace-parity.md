# ADR-0011: Fuzz lockfiles are gated for parity with the workspace, not kept fresh by Dependabot

**Status:** Accepted · 2026-07-30 · issue [#608](https://github.com/randomparity/rusty-imap-mcp/issues/608)

## Context

The repo tracks three lockfiles: the workspace `Cargo.lock`,
`html-oracle/Cargo.lock`, and `crates/rimap-server/fuzz/Cargo.lock`.

`.github/dependabot.yml` has cargo entries for `/` and `/html-oracle`. The
third is uncovered, and not by oversight: `crates/rimap-server/fuzz/Cargo.toml`
declares its own `[workspace] members = ["."]`, because the root manifest's
`exclude = ["fuzz", "html-oracle"]` is a bare path that only matches `./fuzz/`
and never reaches the nested directory. Being its own workspace is what keeps
nightly-only `libfuzzer-sys` and the `fuzzing` feature off the root stable
build. It is also why the root `/` Dependabot entry never resolves it.

So nothing — not Dependabot, not CI — detected when that lockfile fell out of
step with the workspace. By the time #608 was filed the two had diverged on 94
shared packages, including `rmcp` 2.2.0 vs 2.1.0, `jsonschema` 0.48.5 vs
0.46.10, `ulid` 3.0.0 vs 1.2.1, `cfb` 0.14.0 vs 0.7.3, and `syn` 3.0.3 vs
2.0.118 — and, in the other direction, `bitflags` 2.13.0 in the fuzz lockfile
against 2.11.1 in the workspace.

This matters because the fuzz target is differential, not panic-only: it builds
`rimap-server` with `features = ["fuzzing"]` and re-checks every `Forward`
decision against rmcp's own deserializer. When the two lockfiles resolve
different versions of that parser stack, the fuzzer is no longer differential
against the code that ships, and it stops proving what it claims to. Divergence
of exactly this kind produced #512.

## Decision

- **The invariant is parity, not freshness.** The fuzz lockfile is required to
  agree with the workspace lockfile on shared dependencies; it is not required
  to be current in its own right.

- **Enforced by a CI gate**, `scripts/check-fuzz-lock-parity.sh`, run as
  `just check-fuzz-lock-parity` and as part of `just ci`.
  `.github/workflows/ci.yml` has no `paths:` filter, so the gate runs on every
  PR — including any PR that touches either lockfile.

- **The gate runs in the `cargo-deny` job, not `publish-checks`, because
  `cargo-deny` is a required status check on main and `publish checks` is
  not.** This is the non-obvious part. A gate wired into a non-required job
  runs but does not *enforce*: it goes red and the PR merges regardless. That
  failure mode is worst precisely where this gate matters most — a Dependabot
  bump that drifts the lockfile is exactly the PR that would sail through a
  non-blocking red check, landing the drift #608 exists to prevent. Placing it
  in an already-required job makes it enforcing with no branch-protection
  change and no new required job, and `cargo-deny` is its thematic home anyway:
  both are dependency-resolution gates. Moving these steps back into
  `publish-checks` on tidiness grounds would silently disarm the gate.

- **The comparison is containment, not equality.** The fuzz dependency graph is
  a *subgraph* of the workspace's, so it legitimately resolves fewer versions
  of a package the workspace holds several times (`base64` at 0.13/0.22/0.23,
  `hashbrown` at four versions, `thiserror` at 1.x and 2.x). Requiring equal
  version sets would false-positive on every one of those. The rule that
  actually holds: every version a fuzz lockfile resolves for a package name the
  workspace also has must appear in the workspace lockfile. Drift in either
  direction violates it — a stale fuzz pin is absent from the workspace, and so
  is one that has run ahead.

- **Failure names the crate and both versions**, choosing the workspace
  counterpart by semver-compatibility bucket so that drift in the 2.x line of a
  package that also has a 1.x line is reported against 2.x.

- **Containment is necessary but not sufficient, so each fuzz lockfile must
  also still contain `libfuzzer-sys`.** A fuzz lockfile that is a verbatim copy
  of the workspace lockfile satisfies containment trivially — an identical
  version set is a subset of itself — and that copy is exactly the wreckage a
  half-finished realign leaves behind. Without this requirement the gate would
  bless it.

- **The build honours the lockfile.** `cargo fuzz build` (0.13.1) has no
  `--locked` flag and rejects one, so `.clusterfuzzlite/build.sh` asserts the
  same property with `cargo metadata --locked` before building, in any fuzz
  directory that has a lockfile. Otherwise cargo would silently re-resolve and
  rewrite at build time, letting drift return with both the gate and the build
  green.

- **The gate discovers its inputs** with `git ls-files '*fuzz/Cargo.lock'`
  rather than hard-coding the one path, so a fuzz workspace whose lockfile is
  committed later is covered without editing the script. `html-oracle` does not
  match and stays free to float.

- **Remediation is one command**, `just realign-fuzz-locks`: copy the workspace
  lockfile over the fuzz one, then let `cargo metadata` prune the unreachable
  packages and add the fuzz-only ones. This preserves every shared pin
  verbatim. Regenerating from scratch would re-resolve to latest and reintroduce
  the drift. The copy has to land at the lockfile's real path for cargo to
  resolve against it, so the original bytes are held and written back if cargo
  fails — cargo must reach the registry index to add the fuzz-only packages, so
  a realign attempted offline fails, and without the restore it would fail with
  the real lockfile already destroyed.

## Alternatives considered

- **A Dependabot `cargo` entry for `/crates/rimap-server/fuzz`.** Rejected as
  the primary fix. It keeps the lockfile moving, but on its own schedule, which
  can push it *ahead* of the workspace — the same defect in the opposite
  direction, and one that already exists today in the `bitflags` entry. It
  could be layered on top of the gate later, but only because the gate would
  then catch the resulting skew; on its own it does not establish the
  invariant.

- **Deleting the tracked fuzz lockfile** so the build always resolves fresh.
  Rejected: it converts a detectable divergence into an undetectable one. The
  ClusterFuzzLite build would silently instrument a different dependency set on
  every run, with nothing to compare against. This was the shape the root
  `fuzz/` directory was in when this was decided (its lockfile was gitignored)
  and is the weaker of the two conventions, not the one to standardize on. It
  no longer describes any directory in the repo — see the Amendment below.

- **Comparing the two lockfiles for exact equality.** Rejected on the data: the
  fuzz graph is a strict subgraph, so equality is not the invariant and the
  check would be permanently red on packages that are correctly resolved.

## Consequences

- The 94-package drift is closed in the same change that adds the gate;
  `cargo +nightly fuzz build -O` was run against the realigned lockfile to
  confirm the target still builds.

- **Every workspace dependency bump that touches a shared package now fails
  this gate until the fuzz lockfile is realigned.** In practice that means
  Dependabot PRs on the `/` cargo ecosystem will frequently need one extra
  commit from `just realign-fuzz-locks`. This is the intended cost: the gate
  converts silent drift into a visible, one-command chore. It joins `cargo-deny`
  as a check that can block a Dependabot PR.

- The gate is pure lockfile text analysis — no cargo resolution, no network —
  so it adds negligible CI time and runs offline. It parses `[[package]]`
  blocks directly rather than via `tomllib`, which is Python 3.11+, because
  `just ci` must also run on developer machines with an older system `python3`.

- Realignment does not touch the workspace `Cargo.lock`, so `cargo deny`'s
  `multiple-versions = deny` ban is unaffected: the fuzz workspace is outside
  its scope.

- That same scoping is why parity also improves advisory posture. `cargo deny
  check advisories` only scans the root workspace, so whatever the fuzz
  lockfile resolved was never checked against RUSTSEC at all. After
  realignment every shared package inherits the workspace's audited
  resolution, leaving only `libfuzzer-sys`, `arbitrary`, and `jobserver`
  unscanned. Note this moves a few packages *backward* where the fuzz
  lockfile had run ahead (`zeroize` 1.9.0 → 1.8.2, `bytes` 1.12.1 → 1.11.1,
  `cc` 1.2.66 → 1.2.60) — to the versions the workspace ships and cargo-deny
  has cleared, which is the point of parity.

- The root `fuzz/` directory's own lockfile remains untracked, so the two fuzz
  directories still follow different conventions. Normalizing that is tracked
  separately; the gate already covers it automatically if the lockfile is ever
  committed. **Discharged — see the Amendment below.**

## Amendment · 2026-08-03 · issue [#611](https://github.com/randomparity/rusty-imap-mcp/issues/611)

The last consequence above is now discharged. `fuzz/Cargo.lock` is tracked:
the `Cargo.lock` line is gone from `fuzz/.gitignore`, and the lockfile was
realigned with `just realign-fuzz-locks` before its first commit (445 workspace
packages pruned to the 194 the fuzz graph reaches, plus `libfuzzer-sys`,
`arbitrary`, and `jobserver`). All five root targets — `content_mime`,
`content_html`, `content_rfc2047`, `content_charset`, `audit_jsonl` — build
against it with `cargo +nightly fuzz build -O`.

Nothing was edited to make this happen. Both mechanisms the decision above
describes picked the new lockfile up on their own, which is the property they
were built for:

- `check-fuzz-lock-parity.sh` discovers its inputs with `git ls-files`, so
  committing the lockfile took it from reporting one lockfile in parity to
  two. No script change.
- `.clusterfuzzlite/build.sh` guards with `cargo metadata --locked` in any
  fuzz directory that *has* a lockfile, so the root fuzz build is now pinned
  too. No workflow change.

The two fuzz directories now follow one convention, and the weaker of the two
— the untracked lockfile rejected under *Alternatives considered* as converting
detectable divergence into undetectable — is no longer in use anywhere in the
repo. The cost noted under Consequences doubles in the obvious way: a workspace
bump touching a shared package now needs both fuzz lockfiles realigned, which
is still the same single `just realign-fuzz-locks` invocation because it too
discovers its inputs from git.
