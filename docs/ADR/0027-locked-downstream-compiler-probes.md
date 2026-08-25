# ADR-0027: Downstream compiler probes use fixture lockfiles

**Status:** Accepted · 2026-08-25 · issue [#838](https://github.com/randomparity/rusty-imap-mcp/issues/838)

## Context

The `rimap-audit` and `rimap-imap` exact-E0639 integration tests each create a
temporary downstream crate and invoke Cargo. Those temporary roots have no
`Cargo.lock`, and their `cargo check` commands have no lock or offline constraint.
The reviewed workspace lockfile therefore does not constrain the registry versions
whose build scripts and proc macros the nested Cargo process may execute.

The probes must remain downstream crates because E0639 is the public-crate boundary
being tested. They must also preserve one fresh source root per probe so a failure in
one source snippet cannot satisfy another assertion accidentally.

## Decision

Each exact-E0639 harness owns a minimal fixture workspace under its
`tests/fixtures/e0639-probe/` directory. The fixture commits `Cargo.toml`,
`Cargo.lock`, and a valid empty `src/main.rs`. Its manifest fixes the package
name, version, edition, workspace boundary, dependency names, enabled features,
and relative local dependency paths for that harness.

A private workspace crate, `rimap-compiler-probe`, is the only supported
invocation boundary for downstream Rust compiler probes. It creates the fresh
temporary crate, preserves the fixture manifest's package name, version,
edition, workspace boundary, dependency names, and enabled features, rewrites
only local dependency paths to absolute paths, copies the fixture lock, and
invokes:

```text
cargo check --locked --offline --message-format=short
```

The audit and IMAP harnesses supply fixture identity, local dependency paths,
and probe source through this API; they do not resolve or spawn Cargo directly.
Their existing positive and negative tests exercise the copied lock under both
the development and MSRV test suites. A manifest/lock mismatch therefore fails
the same focused contract before an E0639 assertion can pass.

A repository guard enforces the boundary over every tracked test/support source:
files below a `tests/` directory and `scripts/*.test.{sh,py,js,ts}`. It rejects
direct Cargo `check` or `rustc` process construction in Rust `Command`, shell
command position, Python `subprocess`, and JavaScript/TypeScript process APIs.
Only `rimap-compiler-probe` may resolve and spawn Cargo; every exact-E0639
harness must depend on that crate and own a tracked fixture manifest and lock.

Synthetic negative tests cover each supported language form, environment-based
and literal Cargo resolution, a second wrapper, missing helper use, and missing
locked/offline semantics in the helper. This covers the repository's ordinary
test and support harness shapes. Deliberate source obfuscation remains subject
to review like any other attempt to evade a repository guard.

The same guard verifies that every registry package identity in each fixture
lock—name, version, source, and checksum—occurs in the root `Cargo.lock`. Its
test suite covers drift in both directions, malformed or missing lockfiles,
manifest-identity drift, and discovery failures. The guard runs in `just ci`
and as steps in the required `cargo-deny` CI job.

The post-release bump script recognizes both fixture locks, re-resolves them after
workspace package versions move, checks them with `--locked --offline`, and includes
them in its derived commit set. A local `just realign-compiler-probe-locks` recipe
performs the same root-seed, Cargo-prune, and parity-check sequence after an ordinary
dependency update.

## Consequences

- Nested checks cannot select a compatible registry release absent from the reviewed
  root dependency graph.
- Offline mode turns a missing local crate cache entry into a loud test failure rather
  than a network fallback. Normal workspace tests build the path dependency graphs
  before executing the integration probes.
- Two fixture locks are committed because the audit and IMAP dependency graphs
  have separate owners and update independently. Each lock is the minimal graph
  for its harness.
- Dependency and release-version updates must realign the fixture locks. The parity
  and post-release guards name the repair command when they fail.
- Production crates, published APIs, wire schemas, and runtime behavior do not change.

## Considered & rejected

- **Retain the current unlocked, online probes.** verified: issue #838 records
  that both fresh roots can resolve compatible releases absent from the
  reviewed workspace lock and can reach the registry. Keeping them would avoid
  fixture maintenance by preserving the exact authority gap this decision must
  close.
- **Invoke rustc directly against outer-workspace artifacts.** judgment:
  a downstream rustc invocation would make the harness locate hash-named
  library artifacts and reproduce Cargo's `--extern`, dependency-search, and
  feature selection. Keeping Cargo as the graph authority is smaller and uses
  its supported lock validation directly.
- **Use one shared fixture workspace and lock for both harnesses.** judgment:
  selecting one workspace member avoids unrelated compilation, but every
  temporary probe root and every lock update would still depend on both fixture
  packages. Separate locks preserve crate ownership and failure isolation; the
  shared helper and parity gate already remove duplicated behavior.
- **Keep generated temporary locks but pass `--locked`.** verified: Cargo rejects
  `--locked` when the temporary root has no lockfile, so this does not provide a
  reviewed graph.
- **Keep committed locks but allow online Cargo access.** judgment: a lock constrains
  versions but does not satisfy issue #838's explicit no-registry-resolution and
  offline/frozen requirement. Failing on an unprepared cache is safer than silently
  reaching the registry from a compiler probe.
- **Rely on reviewer attention instead of a recurrence guard.** judgment: issue #835
  repeated the existing unlocked pattern because nothing encoded the rule. A focused
  structural and parity gate is the smallest durable prevention mechanism.
