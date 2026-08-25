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
Cargo launches in tracked Rust tests. It does not govern direct `rustc`, normal
repository builds and installs, Cargo wrappers that do not create temporary
downstream projects, or third-party compiler-harness policy.

## Decision

Each exact-E0639 harness owns a minimal fixture workspace at
`tests/fixtures/e0639-probe/`, containing `Cargo.toml`, `Cargo.lock`, and a
valid empty `src/main.rs`. The harness reads that committed manifest and
rewrites only its relative local dependency paths to absolute paths for the
temporary root. Package identity, edition, workspace boundary, dependency
names, features, and default-feature policy therefore have one source.

Before each check, the harness copies its fixture lock into the fresh temporary
crate and invokes:

```text
cargo check --locked --offline --message-format=short
```

A focused repository guard scans every `std::process::Command::new` invocation
in tracked Rust tests and resolves ordinary Cargo expressions: literal
`\"cargo\"`, `PathBuf::from(\"cargo\")`, `CARGO` environment lookups, and simple
local aliases assigned from those forms. Each discovered Cargo invocation is
validated independently; file-level evidence cannot satisfy a second builder.
Every invocation must use one literal `COMPILER_PROBE_FIXTURE`, derive its
manifest from the registered fixture, copy its `Cargo.lock`, and pass both
`--locked` and `--offline`. The fixture path must resolve inside the owning
crate and contain tracked manifest, lock, and source files.

The guard compares each fixture lock against the root lock using complete
registry package identity: name, version, source, and checksum. It also
requires exactly one fixture package identity from the fixture manifest, which
a verbatim root-lock seed lacks. Its regression suite covers mixed compliant
and noncompliant builders in one file, every supported direct and aliased Cargo
expression, fixture/generated-manifest drift, each missing flag, missing
registration, missing or untracked fixture files, malformed locks,
root/fixture drift, an unpruned root copy, and empty discovery. This is a
focused recurrence gate for nested Cargo in Rust tests, not a universal
executable or compiler inventory.

Realignment occurs in a temporary workspace outside the repository. The recipe
writes an absolute-path equivalent of the fixture manifest there, seeds its
lock from the root, runs Cargo metadata to prune unreachable packages, verifies
fixture identity and parity, then atomically replaces the tracked fixture lock.
Failure or interruption before replacement leaves the original untouched.

The post-release-bump script recognizes both fixture locks, realigns them after
workspace versions move, verifies them locked and offline, and includes them in
its derived commit set. The guard runs in `just ci` and the required
`cargo-deny` CI job.

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
