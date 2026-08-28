# ADR-0028: Advisory CODEOWNERS covers the CI control plane

**Status:** Accepted · 2026-08-27 · issue [#768](https://github.com/randomparity/rusty-imap-mcp/issues/768)

## Context

The advisory CODEOWNERS policy owns `.github/`, `scripts/`, and `deny.toml`, but
not four configuration surfaces that decide what CI and local guardrails run:
`justfile`, `.pre-commit-config.yaml`, `.config/nextest.toml`, and
`.clusterfuzzlite/`. A small edit to one of those files can remove a check,
exclude inputs, alter test execution, or change the fuzz build without requesting
the repository owner as a reviewer.

The file remains advisory because the solo-maintainer constraint recorded by
issue #744 and PR #764 has not changed. This decision selects reviewer-assignment
coverage; it does not change branch protection.

## Decision

CODEOWNERS owns the repository's CI control plane: files that select, configure,
or implement required checks and automated fuzz builds. In addition to the
existing entries, that set includes:

- `/justfile`;
- `/.pre-commit-config.yaml`;
- `/.config/nextest.toml`; and
- `/.clusterfuzzlite/`.

The header records both this inclusion rule and its boundary. General Rust build
inputs (`Cargo.toml`, `Cargo.lock`, and `rust-toolchain.toml`) remain outside the
owned set: they affect what is built, but do not define which review and CI gates
run. Generated artifacts and ordinary source remain outside for the same reason.

## Consequences

- Pull requests touching the four added surfaces request `@randomparity` and
  show owner attribution.
- The policy remains advisory and does not block self-authored pull requests.
- A future binding-policy decision can evaluate one explicit control-plane set
  rather than inheriting an undocumented collection of paths.
- Dependency updates and ordinary source changes do not gain owner-assignment
  noise from this decision.

## Considered & rejected

- **Keep the current three entries.** verified: issue #768 identifies four
  unowned files or directories that configure checks or fuzz execution, so the
  existing set does not satisfy the stated control-plane rationale.
- **Own every root build input.** judgment: `Cargo.toml`, `Cargo.lock`, and the
  toolchain pin are build inputs rather than gate-selection policy; including
  them would broaden reviewer assignment beyond the problem being settled.
- **Make code-owner review binding now.** verified: PR #764 records that GitHub
  does not let the solo maintainer approve their own pull request, so binding
  review needs a second reviewer or documented bypass that issue #768 excludes.
