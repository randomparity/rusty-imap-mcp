# ADR-0008: Shared fake-IMAP test-support crate for cross-crate wire tests

**Status:** Accepted · 2026-07-11 · issue [#561](https://github.com/randomparity/rusty-imap-mcp/issues/561)

## Context

The scriptable adversarial IMAP fake (`FakeImapServer`, `Step`,
`login_preamble`) lives in `crates/rimap-imap/tests/support/fake_imap.rs` and is
included per-test-binary via `mod support;`. It binds a real `127.0.0.1:0` IMAPS
socket, terminates TLS with a self-signed `rcgen` leaf, exposes `.port()` and
`.pin()` (leaf fingerprint), and can emit arbitrary/malformed server bytes via
`Step::Send`.

Issue #561 (follow-up to #535 / PR #560) needs that fake reachable from
**`rimap-server`'s** test tree so a `rimap-server` `e2e_wire` test can point the
production binary at the fake and assert `SearchMeta.fetch_skipped > 0` over the
JSON-RPC wire on a scripted short-page FETCH. Today the fake is only reachable
from `rimap-imap`; #535's spec deferred the full-wire assertion for exactly this
packaging reason.

There are two ways to share test code across crate boundaries in Cargo:

1. A cross-crate `#[path = "../../rimap-imap/tests/support/fake_imap.rs"]`
   include from `rimap-server`'s test tree.
2. A shared `publish = false` crate taken as a `dev-dependency` by both crates.

Issue #561's acceptance criteria explicitly require the fake be reachable
"without a relative cross-crate `#[path]` hack," ruling out option 1 for the
end state.

## Decision

Extract the fake into a new workspace member crate
**`crates/rimap-fake-imap`** (`publish = false`), containing the `fake_imap` and
`certs` modules verbatim, and depend on it as a `dev-dependency` from both
`rimap-imap` and `rimap-server`.

The crate's `fake_imap` module constructs `rimap_imap::Connection` values (for
`rimap-imap`'s existing adversarial tests), so the crate has a **normal**
dependency on `rimap-imap`. `rimap-imap` in turn takes the crate as a
`dev-dependency`. This forms a dependency cycle:

```
rimap-imap  --[dev-dependency]-->  rimap-fake-imap  --[dependency]-->  rimap-imap (lib)
```

Cargo permits this because dev-dependencies are excluded from the normal build
graph: building `rimap-imap`'s **library** does not pull in its dev-deps, so
`rimap-fake-imap` (and its normal dep back on the already-built `rimap-imap`
lib) only enters the graph when `rimap-imap`'s **tests** are built. There is no
cycle among library targets.

`tracing_capture` (used only by one `rimap-imap` adversarial test) stays a
per-binary `mod support;` module in `rimap-imap` — it is not needed
cross-crate, and moving it would widen the crate's surface for no consumer.

## Consequences

- The fake is a single source of truth reachable from any workspace crate's
  tests; new cross-crate adversarial wire tests need no packaging work.
- The per-binary `#![allow(dead_code)]` on the old `support/mod.rs` is dropped:
  `pub` items in a library crate are never dead-code-warned, so consumers that
  use only a subset of the API compile clean without a blanket allow.
- The `certs` unit test (`pin_matches_leaf_der_and_is_fresh_each_call`) moves
  into the crate and runs as a normal crate unit test.
- `rimap-imap`'s fake-based tests change their import path from
  `support::fake_imap::…` to `rimap_fake_imap::…`.
- A new workspace member appears in `cargo metadata`, cargo-deny's graph, and
  MSRV/CI matrices. It adds no new external dependency: `rcgen`,
  `tokio-rustls`, and `rustls` were already `rimap-imap` dev-deps.
- The dev-dependency cycle is unusual; this ADR is the durable record of why it
  is present and why it is sound, so a future reader does not try to "fix" it.

## Considered & rejected

- **Cross-crate `#[path]` include** (option 1): forbidden by the issue AC.
  Independently worse: a brittle `../../` relative path, each consumer binary
  recompiles the module and re-triggers the per-binary dead-code allows, and
  the fake has no crate identity (no shared unit tests, no single lint surface).
- **Move the fake into `rimap-imap`'s `src/` behind a `test-support` feature**
  (mirroring the existing `PreflightInfo::new` seam): this would place a
  TLS-terminating socket server plus `rcgen` key generation into the shipped
  library's feature graph and pull test-only deps into a non-`cfg(test)`
  configuration. Heavier and muddier than a dedicated `publish = false` test
  crate that is never in a production build graph. Rejected.
- **Duplicate the fake in `rimap-server`'s test tree**: violates single-source,
  guarantees drift between the two copies. Rejected.
