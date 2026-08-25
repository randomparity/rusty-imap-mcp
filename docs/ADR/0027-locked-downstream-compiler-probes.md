# ADR-0027: Nested Cargo probes use fixture lockfiles

**Status:** Accepted · 2026-08-25 · issue [#838](https://github.com/randomparity/rusty-imap-mcp/issues/838)

## Context

The `rimap-audit` and `rimap-imap` exact-E0639 integration tests each create a
temporary downstream crate and run `cargo check`. Those roots have no
`Cargo.lock`, `--locked`, or `--offline`, so the reviewed workspace lock does
not constrain the registry releases whose build scripts and proc macros nested
Cargo may execute.

The probes must remain downstream crates because E0639 is the public-crate
boundary under test. The recurrence requirement is limited to direct nested
Cargo launches in tracked integration-test sources under `crates/*/tests/`.
It does not govern crate `src/`, `build.rs`, direct `rustc`, normal repository
builds and installs, Cargo wrappers that do not create temporary downstream
projects, or third-party compiler-harness policy.

## Decision

Each exact-E0639 harness owns a minimal fixture workspace at
`tests/fixtures/e0639-probe/`, containing `Cargo.toml`, `Cargo.lock`, and a
valid empty `src/main.rs`. For each probe it creates a unique temporary
directory beside the fixture, where the fixture's relative dependency paths
remain valid, and copies the committed manifest byte-for-byte. Package
identity, edition, workspace boundary, dependency names, features, path
spelling, and default-feature policy therefore have one source; no TOML
rewriting or path escaping exists in the harness.

Before each check, the harness also copies its fixture lock into that temporary
crate and invokes:

```text
cargo check --locked --offline --message-format=short
```

A focused repository guard scans every `std::process::Command::new` invocation
in tracked `crates/*/tests/**/*.rs` integration-test sources and resolves
`\"cargo\"`, `PathBuf::from(\"cargo\")`, `CARGO` environment lookups, simple
local aliases assigned from those forms, and zero-argument local helpers that
return one of those forms. It builds a local helper-call graph and propagates
temporary-project roots to a fixed point, so setup may create and return the
root from a helper separate from the Cargo launch. A Cargo invocation is an
in-scope nested downstream probe when it runs `check` with `current_dir` or
`--manifest-path` rooted in a local temporary project whose setup writes
`Cargo.toml`. Other direct Cargo commands, such as repository metadata checks,
remain outside this decision.

Each in-scope invocation is validated independently; file-level evidence cannot
satisfy a second builder. Every such invocation must use one literal
`COMPILER_PROBE_FIXTURE`, copy its manifest byte-for-byte, copy its
`Cargo.lock`, and pass both `--locked` and `--offline`. The fixture path must
resolve inside the owning crate and contain tracked manifest, lock, and source
files.

The guard compares each fixture lock against the root lock using complete
registry package identity: name, version, source, and checksum. It requires
exactly one fixture package identity from the fixture manifest, resolves every
lock dependency edge, and rejects any package block unreachable from that
fixture root. A root lock plus an injected fixture block therefore cannot pass
as a pruned fixture graph.

Its regression suite covers mixed compliant and noncompliant builders in one
file, every supported direct, aliased, and helper-return Cargo expression,
temporary-project setup split into a separate local helper, excluded `src/`,
`build.rs`, and Cargo commands without a temporary downstream manifest, exact
manifest copying, each missing flag, missing registration, missing or untracked
fixture files, malformed or unreachable lock blocks, root/fixture drift, an
unpruned root copy with a fixture block, and empty discovery. This is a focused
recurrence gate for nested Cargo in integration tests, not a universal
executable or compiler inventory.

Realignment creates a unique untracked workspace beside each fixture, copies
the fixture manifest and source byte-for-byte, seeds its lock from the root,
runs Cargo metadata to prune unreachable packages, and verifies fixture
identity, reachability, and parity. It then copies the verified candidate to an
exclusive temporary file beside the tracked `Cargo.lock` and atomically renames
that file over the destination. Failure or interruption before the rename
leaves the original untouched; an interrupted staging copy leaves only a
disposable temporary file.

The post-release-bump script recognizes both fixture locks, realigns them after
workspace versions move, verifies them locked and offline, and includes them in
its derived commit set. A hermetic main-path test uses fake `cargo`, `just`, and
`git` executables to assert those calls, flags, order, and paths. The guard runs
in `just ci` and the required `cargo-deny` CI job.

## Consequences

- Nested E0639 checks cannot select a registry artifact absent from the reviewed
  root dependency graph.
- Missing cached packages fail loudly under `--offline`; probes never retry
  online or regenerate their lock.
- Two fixture locks follow the existing crate ownership boundary and keep each
  dependency graph minimal.
- Dependency and release-version updates must realign both fixture locks; the
  gate names the repair recipe.
- The two harnesses retain small duplicated setup code. At two call sites this
  follows the repository's no-utility-before-third-repetition rule; the guard
  prevents the security-sensitive flags from drifting.
- Production behavior and public contracts do not change.

## Considered & rejected

- **Retain unlocked temporary roots.** verified: issue #838 records that they
  can resolve compatible releases absent from the reviewed lock and reach the
  registry. This preserves the defect.
- **Invoke rustc directly against outer artifacts.** judgment: allowed by the
  issue, but locating Cargo's hash-named library artifacts is more brittle than
  retaining Cargo with an explicit fixture lock.
- **Create a private shared helper crate.** judgment: two small call sites do
  not justify another workspace member. A focused guard enforces the shared
  invariant without introducing a new API.
- **Use one union fixture lock.** judgment: it couples independently owned test
  graphs and their update failures; two discovered locks are simpler.
- **Build a repository-wide Cargo/compiler inventory.** verified: the operator
  rejected that design as scope creep at the cycle-2 scope checkpoint. The
  frozen charter limits recurrence prevention to direct nested Cargo launches
  in tracked Rust tests.
