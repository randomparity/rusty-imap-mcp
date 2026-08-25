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

At runtime, the harness copies its fixture `Cargo.lock` into each fresh temporary
crate before invoking:

```text
cargo check --locked --offline --message-format=short
```

The generated temporary manifest preserves every fixture manifest field except
that local dependency paths become absolute so the isolated root can live
anywhere. The recurrence guard compares those fields. A fixture proof under
Cargo 1.94.0 on macOS arm64 copied a lock generated with relative local paths
beside the equivalent absolute-path manifest; `cargo check --locked --offline`
completed without changing the lock.

A repository guard discovers downstream Rust compiler probes, requires each one to
have a matching tracked fixture lock, and requires locked plus offline Cargo
semantics. The same guard verifies that every registry package identity in each
fixture lock—name, version, source, and checksum—occurs in the root
`Cargo.lock`. Its test suite covers drift in both directions, malformed or
missing lockfiles, manifest-identity drift, missing flags, and discovery
failures.
The guard runs in `just ci` and as steps in the required `cargo-deny` CI job.

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
- Two fixture locks are committed because the audit and IMAP probes have different
  dependency graphs. Each remains a minimal subgraph instead of compiling unrelated
  crates.
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
- **Use one shared fixture lock for both harnesses.** judgment: the union graph would
  make each probe compile unrelated crates and couple otherwise independent test
  packages. Two discovered locks keep isolation without duplicating guard logic.
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
