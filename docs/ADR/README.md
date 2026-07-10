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

## Index

| ADR | Title | Status |
|-----|-------|--------|
| [0001](0001-smtp-real-socket-e2e-and-auth-taxonomy.md) | Real-socket SMTP e2e, `SmtpError::Auth`, and negative-reply classification | Accepted |
| [0002](0002-phased-bzr-release-parity-and-direct-publish.md) | Phased bzr-parity release process and direct-publish releases | Accepted |
