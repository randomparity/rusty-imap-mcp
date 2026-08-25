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
  at issue comment `5411371166`; frozen cycle-2 `WORK:SCOPE` record at issue
  comment `5411379589`.
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
maintenance. At runtime each harness creates a unique temporary directory
beside `e0639-probe/`, at the same path depth, and copies the committed fixture
manifest byte-for-byte. Its relative dependency paths remain valid without a
semantic or textual rewrite. Package identity, version, edition, workspace
boundary, dependency names, features, path spelling, and default-feature
policy therefore have one source, and unusual repository path characters
never enter TOML serialization.

## Probe execution

Each existing `check_probe` keeps one fresh `TempDir` per source snippet. It:

1. creates the temporary root in `tests/fixtures/` beside the registered
   fixture;
2. copies the fixture `Cargo.toml` and `Cargo.lock` byte-for-byte;
3. writes the probe source over the copied empty `src/main.rs`;
4. runs `cargo check --locked --offline --message-format=short`; and
5. returns success plus stderr exactly as today.

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

`scripts/check-compiler-probe-locks.sh` scans process-command constructors in
tracked integration-test Rust files under `crates/*/tests/`. Tracked crate
`src/`, `build.rs`, examples, and benchmarks are outside this focused source
set.

The guard recognizes the canonical direct-probe shape used by both harnesses:

- one `check_probe` function owns a local `dir` temporary root;
- that body calls the fixed `copy_fixture_file` helper for `Cargo.toml` and
  `Cargo.lock` with source fixture and destination `dir.path()`;
- one or more fluent process builders run Cargo `check` with `current_dir` set
  to `dir.path()`; and
- every builder carries `--locked` and `--offline`.

It resolves `std::process::Command` and `tokio::process::Command` across
qualified paths, ordinary imports, and import aliases. The Cargo executable may
be a direct literal, `PathBuf::from(\"cargo\")`, or the exact repository
`cargo_bin()` helper shape: a zero-argument function returning a `CARGO`
environment lookup with a `cargo` fallback. It does not accept arbitrary
executable aliases or helper graphs.

For every canonical invocation—not merely every containing file—the guard
requires:

- one literal `COMPILER_PROBE_FIXTURE` registration referenced in that body;
- exact source and destination root agreement for both fixture copies and the
  process `current_dir`;
- `--locked` and `--offline` in that invocation's fluent argument builder;
- a registered fixture path inside the owning crate with tracked `Cargo.toml`,
  `Cargo.lock`, and `src/main.rs`;
- exactly one fixture package identity in the fixture lock matching the
  fixture manifest;
- every dependency edge in the fixture lock to resolve unambiguously;
- every fixture lock package block to be reachable from its fixture package;
  and
- every reachable registry package identity—name, version, source,
  checksum—to occur in the root lock.

A recognized Cargo `check` in a body that creates a temporary `Cargo.toml` but
uses a split builder, setup helper, parameter substitution, or another
noncanonical shape fails closed with a diagnostic directing the contributor to
the canonical form. A direct Cargo command without temporary downstream setup,
such as a repository metadata check, is explicitly ignored.

The script also fails on unreadable Git state, malformed lock/package blocks,
an empty in-scope probe set, duplicate registration, or an unrecognized
registered path. It never interprets documentation, workflows, Just recipes,
shell, Python, JavaScript, direct compiler processes, crate `src/`, `build.rs`,
examples, benchmarks, unrelated Cargo commands without a temporary downstream
manifest, or third-party compiler APIs. Those are explicit exclusions rather
than silent blind spots.

`scripts/check-compiler-probe-locks.test.sh` builds synthetic tracked trees and
covers:

- the canonical good case and two canonical builders where one is
  noncompliant;
- qualified, imported, and aliased standard and Tokio constructors;
- a Cargo literal, `PathBuf::from(\"cargo\")`, and the current `cargo_bin()`
  helper;
- noncanonical split builder and split setup rejection;
- two temporary roots where copies and `current_dir` disagree;
- excluded nested-Cargo-shaped files under crate `src/` and at `build.rs`;
- a direct Cargo command without a temporary downstream manifest;
- missing `--locked` and missing `--offline` independently;
- missing, duplicate, absolute, escaping, and untracked fixture registration;
- missing or non-byte-exact fixture manifest/lock copies;
- missing manifest, lock, or source;
- malformed and empty lock package blocks;
- missing or duplicate fixture package identity;
- unresolved dependency edges and unreachable package blocks;
- a root-lock seed with a valid fixture block, which remains invalid;
- fixture registry identity absent or different in the root lock;
- a root package absent from a smaller reachable fixture lock, which remains
  valid; and
- empty in-scope probe discovery.

The test also runs the guard against the real repository so discovery must
recognize exactly the two current canonical probes.

## Lock realignment and release maintenance

`--fix` on the guard realigns every discovered fixture without risking a
partial tracked lock:

1. create a unique untracked workspace beside the fixture, preserving the
   fixture's path depth and filesystem;
2. copy the fixture manifest and source byte-for-byte;
3. seed the temporary lock from the root lock;
4. run `cargo metadata --manifest-path <temporary>/Cargo.toml --format-version
   1` so Cargo prunes unreachable packages and adds the fixture identity;
5. verify fixture identity, dependency reachability, and full root-lock parity
   in the temporary result;
6. copy the candidate to an exclusively created temporary file beside the
   tracked `Cargo.lock`; and
7. atomically rename the fully written adjacent file over the destination.

Failure or interruption before replacement leaves the original fixture lock
unchanged. Interrupted staging may leave a disposable temporary file but never
a partial tracked lock. A root-lock seed plus a valid fixture block fails until
Cargo prunes all unreachable packages.

`just realign-compiler-probe-locks` invokes `--fix`; `just
check-compiler-probe-locks` checks parity; and `just
test-compiler-probe-locks` runs the contract suite. `just ci` runs the test and
check recipes. The required `cargo-deny` CI job runs both before `cargo deny`,
matching the existing fuzz-lock gate without adding a new status context.

`scripts/post-release-bump.sh` adds both fixture locks to its known extra-lock
inventory, invokes the realignment recipe after workspace versions move,
verifies `cargo metadata --locked --offline` for each fixture, and includes the
resulting lock paths in its derived change set. Its existing pure-function
cases expand the known and expected sets. A hermetic main-path case runs in a
minimal temporary repository with fake `cargo`, `just`, and `git` executables;
it asserts realignment follows the workspace update, both fixture metadata
checks carry both flags, and both lock paths reach the emitted change set.

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

- A missing or non-byte-exact manifest/lock copy is a hard harness failure.
- `--locked` rejects manifest/lock disagreement; `--offline` prevents registry
  network access; no fallback exists.
- The focused source guard recognizes the canonical direct temporary-probe
  shape and validates each invocation independently. It rejects missing
  registration, mismatched copy/current-directory roots, exact manifest/lock
  copy, or flags. Recognized noncanonical temporary probes fail with a rewrite
  diagnostic; non-test sources and unrelated Cargo commands remain excluded.
- Fixture identity, dependency reachability, and full package identity parity
  restrict fixture registry artifacts to the root lock and reject an unpruned
  root graph.
- The required `cargo-deny` job runs the focused and parity checks.

### Explicitly out of scope

This change does not defend against a compromised Cargo binary, runner, cache,
or registry artifact whose checksum already matches the reviewed root lock. It
does not attempt to discover intentionally obfuscated Cargo launches, direct
compiler processes, non-integration-test Rust sources, non-Rust harnesses, or
third-party compiler-test libraries. Repository review and the
no-new-dependency rule own those paths.

## Verification

1. Add focused script tests first and observe them fail against the current
   harnesses because registration, fixture manifest/lock copies, and flags are
   absent.
2. Add fixture manifests, sources, and generated locks; verify fixture identity,
   full reachability, and root-lock parity.
3. Update both harnesses and run their exact integration binaries. Positive
   probes must still emit E0639; unrelated-failure probes must still omit it.
4. Exercise realignment staging failure and confirm the original lock remains
   byte-identical; exercise a root lock plus valid fixture block and confirm
   reachability rejects it.
5. Run `just test-compiler-probe-locks`, `just
   check-compiler-probe-locks`, and the hermetic post-release-bump tests.
6. Run `actionlint` and `zizmor .github/workflows/` after editing CI.
7. Run `just ci` in the background to completion.

## Acceptance criteria

- Both E0639 binaries retain every current positive and negative assertion.
- Each direct nested Cargo integration-test invocation independently registers
  a tracked fixture, copies its manifest and lock byte-for-byte, and passes
  `--locked --offline`.
- Missing controls, mixed canonical builders, noncanonical direct-probe shapes,
  mismatched temporary roots, unreachable package blocks, an unpruned root seed
  with fixture identity, and fixture/root lock drift fail focused regression
  tests; non-test sources and unrelated direct Cargo commands remain excluded.
- Dependency and release bumps safely realign and commit both fixture locks.
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
