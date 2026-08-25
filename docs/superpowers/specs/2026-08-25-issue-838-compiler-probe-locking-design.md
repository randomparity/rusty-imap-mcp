# Locked nested Cargo probes — design

Issue: [#838](https://github.com/randomparity/rusty-imap-mcp/issues/838).
Decision: [ADR-0027](../../ADR/0027-locked-downstream-compiler-probes.md).

## Frozen scope

- **Scope identity:** issue #838, token `q838-fbdfc578`, design cycle 2.
- **Outcome:** direct nested Cargo compiler probes in tracked Rust test code use
  committed dependency graphs pinned to the reviewed workspace graph and run
  locked and offline.
- **Completion criteria:** preserve both exact-E0639 positive and negative
  controls; install fixture locks and pass `--locked --offline`; reject a
  direct nested Cargo Rust test missing its fixture lock or either flag;
  maintain fixture locks during dependency and release bumps; pass focused
  tests and `just ci`.
- **Provenance:** issue #838; issue #835 and merged PR #839 for the second
  harness and deferral; repository contributor guide; operator scope correction
  recorded at issue comment `5411371166`.
- **Exclusions:** direct `rustc`, `rustdoc`, and `rustup run`; unrelated builds,
  installs, packaging, documentation, fuzz, and CI Cargo commands; wrappers
  that do not create temporary downstream Cargo projects; third-party
  compiler-harness policy; production behavior and public contracts;
  dependency upgrades beyond lock alignment.
- **Surface:** both exact-E0639 harnesses and fixture workspaces; a focused
  tracked-Rust-test nested-Cargo guard and regression suite; direct lock
  parity, realignment, post-release-bump, `just`, required-CI, ADR, plan, and
  changelog integration.
- **Ambiguities:** none. The operator selected the focused nested-Cargo boundary
  and committed fixture-lock approach.
- **Interaction:** interactive.

## Problem

`crates/rimap-audit/tests/non_exhaustive_e0639.rs` and
`crates/rimap-imap/tests/non_exhaustive_e0639.rs` generate temporary Cargo
packages without lockfiles and execute `cargo check` without lock or network
constraints. The nested roots can therefore choose a compatible registry
release absent from the reviewed root `Cargo.lock`.

`--locked` alone cannot repair a fresh root: Cargo 1.94.0 rejects a package with
no lockfile. `--offline` alone still permits selection of a different compatible
version already present in the local cache. Each probe needs a reviewed fixture
lock plus both execution flags.

The tests must remain downstream crates. Compiling the snippets inside the
published crate would stop exercising E0639, and stable rustdoc verifies only
that compilation fails, not the exact compiler error code.

## Fixture workspaces

Each harness gains:

```text
crates/<crate>/tests/fixtures/e0639-probe/
├── Cargo.toml
├── Cargo.lock
└── src/main.rs
```

The package names are unique (`rimap-audit-e0639-probe` and
`rimap-imap-e0639-probe`), versions are `0.0.0`, editions are 2024, and each
manifest contains an empty `[workspace]` table. The audit fixture depends on
`rimap-audit` and `rimap-core`; the IMAP fixture depends on `rimap-imap` and
`rimap-authz`. Dependencies are relative local paths and declare no registry
package directly.

The fixture source is an empty valid program used only for lock generation and
maintenance. At runtime the harness reads the committed fixture manifest and
rewrites only its relative local dependency paths to absolute paths. Package
name, version, edition, workspace boundary, dependency names, features, and
default-feature policy therefore have one source. Cargo lock identity depends
on package identity, not the spelling of a path dependency.

## Probe execution

Each existing `check_probe` keeps one fresh `TempDir` per source snippet. It:

1. reads the fixture manifest and writes its absolute-path equivalent plus the
   probe source;
2. copies `tests/fixtures/e0639-probe/Cargo.lock` into the temporary root;
3. runs `cargo check --locked --offline --message-format=short`; and
4. returns success plus stderr exactly as today.

Both harnesses declare this literal registration beside `check_probe`:

```rust
const COMPILER_PROBE_FIXTURE: &str = "tests/fixtures/e0639-probe";
```

The audit harness also sets `CARGO_TARGET_DIR` inside the temporary root,
matching the IMAP harness and preventing nested artifacts from touching a
shared target directory. Missing fixture reads or copies fail with operation
and path context. Cargo failure remains output for the E0639 assertions; there
is no online retry or lock regeneration.

## Focused recurrence and parity guard

`scripts/check-compiler-probe-locks.sh` scans every
`std::process::Command::new` invocation in tracked Rust files under `crates/`.
It resolves ordinary Cargo expressions independently per invocation:

- direct literals and `PathBuf::from(\"cargo\")`;
- `std::env::var(\"CARGO\")`, `std::env::var_os(\"CARGO\")`, or
  `env!(\"CARGO\")`;
- simple local aliases assigned from those expressions; and
- zero-argument local helpers that return one of those expressions, including
  the current `cargo_bin()` shape.

A resolved Cargo invocation is an in-scope nested downstream probe only when
its enclosing helper writes a temporary `Cargo.toml` and sets that invocation's
current directory to the same manifest root. A direct Cargo command without
that structure, such as a repository metadata check, is explicitly ignored.
For every in-scope invocation—not merely every containing file—the guard
requires:

- one literal `COMPILER_PROBE_FIXTURE` registration used by that invocation's
  enclosing probe helper;
- source evidence that the registered `Cargo.toml` is read and only dependency
  paths are rewritten;
- source evidence that the registered `Cargo.lock` is copied into the same
  temporary root;
- `--locked` and `--offline` in that invocation's argument builder;
- a registered fixture path inside the owning crate with tracked `Cargo.toml`,
  `Cargo.lock`, and `src/main.rs`;
- exactly one fixture package identity in the fixture lock matching the
  fixture manifest; and
- every fixture registry package identity—name, version, source, checksum—to
  occur in the root lock.

The script fails on unreadable Git state, a partially recognized Cargo helper
that cannot be resolved, malformed lock/package blocks, an empty in-scope probe
set, duplicate registration, or an unrecognized registered path. It never
interprets documentation, workflows, Just recipes, shell, Python, JavaScript,
direct compiler processes, unrelated Cargo commands without a temporary
downstream manifest, or third-party compiler APIs. Those are explicit
exclusions rather than silent blind spots.

`scripts/check-compiler-probe-locks.test.sh` builds synthetic tracked trees and
covers:

- the complete good case;
- two in-scope Cargo builders in one file where only one is compliant;
- direct, `PathBuf`, environment, compile-time environment, simple alias, and
  zero-argument helper-return Cargo expressions;
- a direct Cargo command without a temporary downstream manifest, which stays
  excluded;
- an unresolved Cargo helper, missing `--locked`, and missing `--offline`
  independently;
- missing, duplicate, absolute, escaping, and untracked fixture registration;
- fixture/generated-manifest drift or a second raw manifest authority;
- missing manifest, lock, or source;
- malformed and empty lock package blocks;
- missing or duplicate fixture package identity and a verbatim root-lock seed;
- fixture registry identity absent or different in the root lock;
- a root package absent from a smaller fixture lock, which remains valid; and
- empty in-scope probe discovery.

The test also runs the guard against the real repository so a source scanner
that no longer recognizes the two current probes fails instead of greening.

## Lock realignment and release maintenance

`--fix` on the guard realigns every discovered fixture atomically:

1. create a temporary workspace outside the repository;
2. write an absolute-path equivalent of the fixture manifest and copy its
   source;
3. seed the temporary lock from the root lock;
4. run `cargo metadata --manifest-path <temporary>/Cargo.toml --format-version
   1` so Cargo prunes unreachable packages and adds the fixture identity;
5. verify fixture identity and full root-lock parity in the temporary result;
   and
6. atomically replace the tracked fixture lock only after every prior step
   succeeds.

Failure or interruption before replacement leaves the original fixture lock
unchanged. A verbatim root-lock seed cannot pass because it lacks the fixture
package identity.

`just realign-compiler-probe-locks` invokes `--fix`; `just
check-compiler-probe-locks` checks parity; and `just
test-compiler-probe-locks` runs the contract suite. `just ci` runs the test and
check recipes. The required `cargo-deny` CI job runs both before `cargo deny`,
matching the existing fuzz-lock gate without adding a new status context.

`scripts/post-release-bump.sh` adds both fixture locks to its known extra-lock
inventory, invokes the realignment recipe after workspace versions move,
verifies `cargo metadata --locked --offline` for each fixture, and includes the
resulting lock paths in its derived change set. Its unit test expands the real
bump set and unknown-lock cases.

## Threat model

### Boundaries and actors

- **Added boundary:** reviewed fixture lock copied into a temporary downstream
  Cargo root. Repository contributors control fixture bytes; the local test
  process controls the destination.
- **Narrowed boundary:** nested Cargo to the crates.io index and cache. Registry
  content is external; the fixture lock selects reviewed identities and offline
  mode removes network access during the probe.
- **Existing boundary:** pull-request code to a CI runner capable of executing
  build scripts and proc macros. Required review and CI control admission.

### Controls

- A missing lock copy is a hard harness failure.
- `--locked` rejects manifest/lock disagreement; `--offline` prevents registry
  network access; no fallback exists.
- The focused source guard classifies temporary downstream Cargo probes, then
  validates each invocation independently, including local aliases and
  zero-argument helper returns. It rejects missing registration,
  derived-manifest evidence, lock operation, or flags without capturing
  unrelated Cargo commands.
- Fixture identity plus full package identity parity restricts fixture registry
  artifacts to the root lock and rejects an unpruned root copy.
- The required `cargo-deny` job runs the focused and parity checks.

### Explicitly out of scope

This change does not defend against a compromised Cargo binary, runner, cache,
or registry artifact whose checksum already matches the reviewed root lock. It
does not attempt to discover intentionally obfuscated Cargo launches, direct
compiler processes, non-Rust harnesses, or third-party compiler-test libraries.
Repository review and the no-new-dependency rule own those paths.

## Verification

1. Add focused script tests first and observe them fail against the current
   harnesses because registration, fixture locks, derived manifests, and flags
   are absent.
2. Add fixture manifests, sources, and generated locks; verify fixture identity
   and full root-lock parity.
3. Update both harnesses and run their exact integration binaries. Positive
   probes must still emit E0639; unrelated-failure probes must still omit it.
4. Exercise atomic realignment failure and confirm the original lock remains
   byte-identical.
5. Run `just test-compiler-probe-locks`, `just
   check-compiler-probe-locks`, and focused post-release-bump tests.
6. Run `actionlint` and `zizmor .github/workflows/` after editing CI.
7. Run `just ci` in the background to completion.

## Acceptance criteria

- Both E0639 binaries retain every current positive and negative assertion.
- Each direct nested Cargo Rust invocation independently registers a tracked
  fixture, derives its manifest from that fixture, installs its lock, and
  passes `--locked --offline`.
- Missing controls, mixed builders, helper-return resolution, manifest drift,
  an unpruned root seed, and fixture/root lock drift fail focused regression
  tests; unrelated direct Cargo commands remain excluded.
- Dependency and release bumps atomically realign and commit both fixture locks.
- The required `cargo-deny` CI context and local `just ci` run the guard.
- No production behavior, public contract, or dependency version changes.
- `just ci` passes.

## Durable execution context

- Branch: `feat/lock-compiler-probes-838`.
- Base branch: `main`.
- Guardrails: focused E0639 binaries; `just test-compiler-probe-locks`; `just
  check-compiler-probe-locks`; focused post-release-bump tests; `actionlint`;
  `zizmor .github/workflows/`; final `just ci`.
- Open findings: none under cycle-2 charter.
- Review deferrals: none. Prior overbroad compiler-inventory findings are
  invalidated by the operator's explicit scope correction, not deferred.
