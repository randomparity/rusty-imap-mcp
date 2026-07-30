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
  `just check-fuzz-lock-parity` in the `publish-checks` job and as part of
  `just ci`. `.github/workflows/ci.yml` has no `paths:` filter, so the gate
  runs on every PR — including any PR that touches either lockfile.

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

- **The gate discovers its inputs** with `git ls-files '*fuzz/Cargo.lock'`
  rather than hard-coding the one path, so a fuzz workspace whose lockfile is
  committed later is covered without editing the script. `html-oracle` does not
  match and stays free to float.

- **Remediation is one command**, `just realign-fuzz-locks`: copy the workspace
  lockfile over the fuzz one, then let `cargo metadata` prune the unreachable
  packages and add the fuzz-only ones. This preserves every shared pin
  verbatim. Regenerating from scratch would re-resolve to latest and reintroduce
  the drift.

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
  every run, with nothing to compare against. This is the shape the root
  `fuzz/` directory is in today (its lockfile is gitignored) and is the weaker
  of the two conventions, not the one to standardize on.

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

- The root `fuzz/` directory's own lockfile remains untracked, so the two fuzz
  directories still follow different conventions. Normalizing that is tracked
  separately; the gate already covers it automatically if the lockfile is ever
  committed.
