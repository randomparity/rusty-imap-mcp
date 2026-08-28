# ADR-0028: Advisory CODEOWNERS covers the CI control plane

**Status:** Accepted · 2026-08-27 · issue [#768](https://github.com/randomparity/rusty-imap-mcp/issues/768)

## Context

The advisory CODEOWNERS policy owns `.github/`, `scripts/`, and `deny.toml`, but
not the four configuration surfaces issue #768 identified: `justfile`,
`.pre-commit-config.yaml`, `.config/nextest.toml`, and `.clusterfuzzlite/`. A
bounded repository audit applying the same rationale found five more dedicated
control-plane surfaces: `.dockerignore`, `clippy.toml`, `rustfmt.toml`,
`typos.toml`, and `sonar-project.properties`. The audit also found the nested
`html-oracle/deny.toml` supply-chain policy, which the root `/deny.toml` pattern
does not match. Together these ten paths decide what checks run or what they
inspect. A small edit can remove a check, exclude inputs, alter test execution,
or change the fuzz build without requesting the repository owner as a reviewer.

The file remains advisory because the solo-maintainer constraint recorded by
issue #744 and PR #764 has not changed. This decision selects reviewer-assignment
coverage; it does not change branch protection.

## Decision

CODEOWNERS owns the repository's dedicated CI control-plane files: repository-
level standalone files and external-automation directories whose primary
purpose is to select, configure, or implement required checks and automated
fuzz builds, plus supply-chain policy files wherever they live. In addition to
the existing entries, that set includes:

- `/justfile`;
- `/.pre-commit-config.yaml`;
- `/.config/nextest.toml`; and
- `/.clusterfuzzlite/`;
- `/.dockerignore`;
- `/clippy.toml`;
- `/rustfmt.toml`;
- `/typos.toml`; and
- `/sonar-project.properties`; and
- `/html-oracle/deny.toml`.

The header records both this inclusion rule and its boundary. Multipurpose Rust
build inputs (`Cargo.toml`, `Cargo.lock`, and `rust-toolchain.toml`) remain
outside the owned set: they affect compilation and may contain lint settings,
but gate configuration is not their primary purpose. Generated artifacts and
ordinary source, including component-local harness configuration and fixtures,
remain outside for the same reason. `.cargo/mutants.toml` also remains outside
because mutation testing is not a required CI check.

## Consequences

- Pull requests touching the ten added surfaces request `@randomparity` and
  show owner attribution.
- The policy remains advisory and does not block self-authored pull requests.
- A future binding-policy decision can evaluate one explicit control-plane set
  rather than inheriting an undocumented collection of paths.
- Dependency updates and ordinary source changes do not gain owner-assignment
  noise from this decision.

## Considered & rejected

- **Keep the current three entries.** verified: issue #768 identifies four
  unowned files or directories, and the bounded repository audit recorded in
  Context identifies five more matching the same dedicated-control-plane rule;
  the existing set therefore does not satisfy its stated rationale.
- **Own every file that can influence a build or lint.** judgment: multipurpose
  manifests, lockfiles, toolchain pins, and source can all influence results,
  but including them would erase the dedicated-control-plane boundary and
  broaden reviewer assignment beyond the problem being settled.
- **Make code-owner review binding now.** verified: PR #764 records that GitHub
  does not let the solo maintainer approve their own pull request, so binding
  review needs a second reviewer or documented bypass that issue #768 excludes.
