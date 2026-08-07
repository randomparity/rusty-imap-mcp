# Architecture Decision Records

Short records of architectural decisions with lasting consequences: the
context, the decision, its consequences, and the alternatives that were
considered and rejected. Most day-to-day design decisions are recorded inline
in the specs under [`docs/superpowers/specs/`](../superpowers/specs/); an ADR
is warranted when a decision changes a public contract, a trust boundary, or a
cross-crate invariant and a future reader would otherwise re-litigate it.

Each ADR is immutable once accepted: to revise a decision, add a new ADR that
supersedes the old one (update both `Status` fields and the `Supersedes` /
`Superseded-by` links) rather than editing history.

[ADR-0018](0018-runnable-artifacts-live-in-the-tree.md) bounds what that
covers. Immutability binds the whole accepted document, with exactly two
permitted edits: replacing an embedded **runnable artifact** with a pointer to
its committed location in the tree, and appending a dated entry to an
`## Errata` section at the end of the file, which every such replacement must
record. ADRs do not embed runnable artifacts in the first place — a harness a
reader is told to execute is committed where the workspace's build gates
compile it.

## Index

| ADR | Title | Status |
|-----|-------|--------|
| [0001](0001-smtp-real-socket-e2e-and-auth-taxonomy.md) | Real-socket SMTP e2e, `SmtpError::Auth`, and negative-reply classification | Accepted |
| [0002](0002-phased-bzr-release-parity-and-direct-publish.md) | Phased bzr-parity release process and direct-publish releases | Accepted |
| [0003](0003-manifest-dev-version-model.md) | Manifest `-dev` version model with automated post-release bump | Accepted |
| [0004](0004-crates-io-publish-topology.md) | crates.io publish topology for the 8-crate workspace | Accepted |
| [0005](0005-wave2-corpus-sourcing.md) | Wave-2 corpus sourcing — download-at-build pinned-by-hash + text-node scrub | Accepted |
| [0006](0006-native-packaging-build-topology.md) | Native packaging build topology — xtask manpages, host-side deb/rpm, amd64+arm64 only | Accepted |
| [0007](0007-inband-fetch-truncation-signal.md) | In-band partial-result signal for skipped FETCH items | Accepted |
| [0008](0008-shared-fake-imap-test-support-crate.md) | Shared fake-IMAP test-support crate for cross-crate wire tests | Accepted |
| [0009](0009-golden-agent-transcript-snapshots.md) | Golden agent-transcript snapshots on the fake, not Dovecot | Accepted |
| [0010](0010-secret-leak-canary-sweep.md) | Fixed sentinel for Dovecot, per-run canary elsewhere, swept in teardown | Accepted |
| [0011](0011-fuzz-lockfile-workspace-parity.md) | Fuzz lockfiles gated for parity with the workspace, not kept fresh by Dependabot | Accepted |
| [0012](0012-tool-call-ceiling.md) | One explicit configurable ceiling per tool call; `command_timeout` stays the per-stage budget | Accepted |
| [0013](0013-per-field-defaults-merge.md) | `[defaults]` merges into an account field by field, through all-`Option` override structs | Accepted |
| [0014](0014-synchronous-auth-audit-emission.md) | Every `auth` audit record is written synchronously, on the thread that produced it | Accepted |
| [0015](0015-terminal-process-end-via-bounded-dispatch-drain.md) | `process_end` is terminal, enforced by a bounded dispatch drain | Accepted |
| [0016](0016-dependabot-fuzz-lock-auto-realign.md) | Dependabot fuzz-lock realignment runs in CI on `pull_request_target` | Accepted |
| [0017](0017-realign-push-uses-a-github-app-token.md) | The fuzz-lock realign pushes with a GitHub App installation token, not a PAT | Accepted |
