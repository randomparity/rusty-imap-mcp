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

A focused repository guard scans process-command constructors in tracked
`crates/*/tests/**/*.rs` integration-test sources. It recognizes the canonical
direct-probe shape used by both harnesses: a fixed `fixture_root()` helper joins
the crate root with `COMPILER_PROBE_FIXTURE`; one `check_probe` function binds
that result as `fixture` and owns a local `dir` temporary root; it calls the
fixed `copy_fixture_file` helper for `Cargo.toml` and `Cargo.lock` with
destination `dir.path()`; and it uses a fluent Cargo `check` builder whose
`current_dir` is `dir.path()`. The executable may be a Cargo literal,
`PathBuf::from(\"cargo\")`, or the repository's current `cargo_bin()` helper.
Standard and Tokio `Command` constructors may be qualified, imported, or
import-aliased; Tokio terminal futures may use `.await`.

Each canonical invocation is validated independently; file-level evidence
cannot satisfy a second builder. Its ordered literal Cargo arguments must
contain `check`, `--locked`, and `--offline`, with both flags before any `--`
argument separator. It must copy the registered manifest and `Cargo.lock`
byte-for-byte. The fixture path must resolve inside the owning crate and contain
tracked manifest, lock, and source files.

Classification is constructor- and function-body-local: temporary setup or a
subcommand in another body cannot capture an unrelated invocation. A recognized
Cargo invocation whose own body creates a temporary `Cargo.toml` enters the
focused policy before subcommand validation. `check` may use the canonical
form; other compiler-driving subcommands (`build`, `test`, `bench`, `run`,
`rustc`, `clippy`, or `fix`) fail closed with a diagnostic requiring an
explicit focused-guard extension. Split builders, setup helpers, parameter
substitution, and arbitrary helper call graphs likewise fail closed. Direct
noncompiling Cargo commands, such as repository metadata checks, remain outside
this decision.

The guard compares each fixture lock against the root lock using complete
registry package identity: name, version, source, and checksum. It requires
exactly one fixture package identity from the fixture manifest, resolves every
lock dependency edge, and rejects any package block unreachable from that
fixture root. A root lock plus an injected fixture block therefore cannot pass
as a pruned fixture graph.

Its regression suite covers mixed compliant and noncompliant canonical builders
in one file; qualified, imported, and aliased standard and asynchronously
awaited Tokio constructors; the Cargo literal and current `cargo_bin()` helper;
flags after `--`; noncanonical split builder/setup rejection; non-`check`
compiler-driving subcommand rejection; excluded `src/` and `build.rs`;
noncompiling Cargo metadata with temporary setup in its own body and in another
body; exact same-root manifest and lock copying; each missing flag; missing
registration; missing or untracked fixture files;
malformed or unreachable lock blocks;
root/fixture drift; an unpruned root copy with a fixture block; and empty
discovery. This is a focused canonical-shape gate for direct nested Cargo
probes, not a general Rust analyzer or universal executable inventory.

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
