# AGENTS.md

Guidance for programming agents (Claude Code, Codex, Copilot, etc.) working in
this repository. The global development standards in the developer's personal
`~/.claude/CLAUDE.md` (or equivalent) apply first; this file adds repo-specific
context and overrides where needed.

## What this project is

`rusty-imap-mcp` is a security-first [Model Context Protocol](https://modelcontextprotocol.io/)
server for IMAP email, written in Rust. The primary target is Proton Mail via
Proton Bridge (localhost IMAPS with self-signed TLS), with broad compatibility
for standard IMAP servers (Dovecot, Cyrus, Gmail via app password, etc.).

The threat model treats every byte of email content as untrusted adversarial
input. Prompt injection via crafted email bodies, headers, and attachment
metadata is the #1 concern. Defenses are layered: aggressive sanitization,
structural tagging (`meta` / `untrusted` / `security_warnings`), Unicode
normalization, look-alike detection, content provenance tracking in the audit
log, posture-based authorization, and rate limiting.

**Source of truth:** the design specifications live at
[`docs/superpowers/specs/`](docs/superpowers/specs/): the v1 spec
(`2026-04-07-rusty-imap-mcp-design.md`), v2 spec
(`2026-04-12-v2-design.md`), and sprint 3 spec
(`2026-04-13-sprint-3-design.md`). Read them before making non-trivial
changes. Sprint-by-sprint implementation plans live in
[`docs/superpowers/plans/`](docs/superpowers/plans/). The Phase 2 MCP Node
strict-client conformance spec (`2026-05-12-mcp-conformance-node-design.md`)
extends the Phase 1 wire-conformance work
(`2026-05-12-mcp-wire-conformance-design.md`) with a Node + TypeScript harness
that drives `rusty-imap-mcp` through the official `@modelcontextprotocol/sdk`.
The Phase 3 behavioral-conformance spec
(`docs/superpowers/specs/2026-05-12-mcp-behavioral-conformance-design.md`) covers
the wire-driven Dovecot e2e harness for tool dispatch + audit-log attribution.

## Repository status

v1.0.0 is feature-complete. The eight member crates under `crates/` implement
22 posture-gated MCP tools + 2 infrastructure tools (24 `ToolName` variants),
multi-account support, SMTP sending, an audit log, and a content pipeline with
look-alike detection. Five platform targets are built via the release workflow.

## Development commands

All commands are wrapped in `just` so local dev and CI stay in lockstep. **If
`just ci` passes locally, CI will pass.**

```bash
just setup           # one-time: install tooling, MSRV toolchain, prek hooks
just check           # fast compile-check (inner loop)
just fmt             # format the workspace in place
just fmt-check       # verify formatting without modifying
just lint            # cargo clippy with -D warnings
just test            # cargo nextest run --workspace
just test-msrv       # same as `test` but on the MSRV toolchain (1.88.0)
just deny            # cargo deny check (advisories, licenses, bans, sources)
just ci              # full local-CI equivalent — run this before pushing
just hooks           # re-run prek on all files
just test-injection  # adversarial email corpus (content pipeline, future)
just test-integration  # Proton Bridge integration tests (gated, future)
```

`just` targets are defined in the `justfile` at the repo root. Add new targets
there, not in ad-hoc scripts.

### Container runtime for integration tests

The Dovecot integration harness autodetects `docker` first, then falls
back to `podman` (via `podman compose` / `podman-compose`). Both
runtimes work on macOS (Apple Silicon and Intel), Ubuntu CI, and Fedora.
Override with `RIMAP_CONTAINER_TOOL=docker` or
`RIMAP_CONTAINER_TOOL=podman` if you need to force a specific one. Set
`RIMAP_REQUIRE_DOCKER=1` to fail loudly instead of silently skipping
when no runtime is installed.

The fixture image is `docker.io/dovecot/dovecot:2.4.4-root` (rootful
flavor, multi-arch `linux/amd64` + `linux/arm64`). It listens on
container ports 143 (IMAP+STARTTLS) and 993 (IMAPS); the Rust harness
maps host ports dynamically. There is no arch gate — every supported
developer host can run the suite.

### Wire-driven Dovecot e2e (Phase 3, #265)

`crates/rimap-server/tests/e2e_wire.rs` drives the production binary
over its stdio JSON-RPC wire against the same Dovecot fixture
`e2e_full_session` uses. It exercises every draft-safe and read-only
posture tool, validates every response against the vendored MCP spec
schemas + per-tool schemas under
`crates/rimap-server/tests/fixtures/rimap-tool-schemas/`, and asserts
audit-log pairing + namespace attribution.

- Wall time: silent-skip path is sub-second when no container runtime
  is available; with Docker on either linux/amd64 or macOS arm64,
  expect ~10–60s on a warm machine (Dovecot bring-up dominates).
- Gating: silent-skip ONLY when the host genuinely cannot run the
  fixture — missing docker/podman. `RIMAP_REQUIRE_DOCKER=1` flips
  every failure mode (compose-up, readiness timeout, port reservation,
  fingerprint read) to a panic with diagnostic context. Same
  convention as the legacy in-process `e2e_full_session`.
- Schema regen: when changing any `<Tool>Meta` or `<Tool>Untrusted`
  struct in `crates/rimap-server/src/tools/`, run
  `just regen-tool-schemas` and commit the diff. CI fails on a
  non-empty diff under `tests/fixtures/rimap-tool-schemas/`.
- Specs: see `docs/superpowers/specs/2026-05-12-mcp-behavioral-conformance-design.md`.

## Toolchain and MSRV

- **Dev toolchain:** Rust 1.94.0, pinned in `rust-toolchain.toml`. Rustup
  auto-installs on `cd`.
- **MSRV:** Rust 1.88.0, pinned in `[workspace.package] rust-version`. Verified
  independently in CI and locally via `just test-msrv`. Never introduce syntax
  or dependencies that break the MSRV build.
- **Edition:** 2024 (workspace-level).
- **Dependencies:** declared once in the workspace root's
  `[workspace.dependencies]`, inherited by member crates via
  `foo = { workspace = true }`. Member crates MUST NOT declare versions
  directly.

## Workspace layout

```
crates/
├── rimap-core/      # shared types (Message, Folder, Posture, audit records)
├── rimap-config/    # config loading, validation, credential resolution
├── rimap-imap/      # async-imap wrapper with TLS fingerprint pinning
├── rimap-content/   # MIME parse, Unicode, HTML→text, look-alike, sanitization
├── rimap-audit/     # append-only JSONL audit log with exclusive file locking
├── rimap-authz/     # posture matrix, rate limiter, circuit breaker
├── rimap-smtp/      # lettre wrapper, SMTP connection, TLS
└── rimap-server/    # rmcp server (bin), tool dispatch, main.rs
```

Each library crate has one clear responsibility and communicates through typed
interfaces. `rimap-content` has zero network dependencies; `rimap-authz` has
zero IMAP dependencies; `rimap-imap` is a pure transport crate that depends
only on `rimap-core` (`AuthEventSink` + `CredentialResolver` trait seams) —
the audit log and credential keyring sit on the other side of those traits
and are wired by `rimap-server` at boot. This isolation is load-bearing for
testability — do not introduce cross-crate coupling that breaks it.

## Coding standards

Most of this is enforced by `cargo clippy` and `prek` hooks. The points below
are the ones that trip people up or aren't obvious from the lint set.

- **Zero warnings.** `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
  must be clean. This is the baseline, not the goal.
- **No `println!` / `eprintln!` / `dbg!` / `todo!` in non-test source.**
  `print_stdout` and `print_stderr` are denied workspace-wide because stdout is
  reserved for MCP transport (stderr is held in reserve for a future `tracing`
  subscriber). In tests, debug output via these macros is allowed. In `main.rs`
  and library code, use `tracing` (coming in Sprint 1) or `writeln!` on a
  captured handle.
- **No `#[allow(...)]` attributes.** `allow_attributes = "deny"`. Use
  `#[expect(...)]` with a comment explaining why if you must suppress a lint.
- **No `unwrap()` in non-test code.** `unwrap_used` is denied. Prefer `?`,
  `match`, `let ... else`, or explicit error handling. Tests may
  `#[expect(clippy::unwrap_used)]` the whole `mod tests`.
- **No panics in `Result` functions.** `panic_in_result_fn` is denied. If you
  need to bail, return an error.
- **`thiserror` for library crates, `anyhow` for `rimap-server`** (when those
  dependencies land in Sprint 1).
- **100-char line length.** See `rustfmt.toml`.
- **Absolute imports only.** No relative `..` paths.
- **Google-style docstrings** on non-trivial public APIs. Every public crate
  has `#![deny(missing_docs)]`.
- **`for` loops with mutable accumulators** are preferred over iterator chains
  when the loop is non-trivial. Shadowing through transformations is fine; no
  `raw_x` / `parsed_x` prefix patterns.
- **No wildcard matches.** No `matches!` macro — explicit destructuring
  catches future field additions.
- **Newtypes over primitives.** `MessageUid(u32)`, not `u32`. Enums for state
  machines, not boolean flags.

## Testing expectations (starting Sprint 1)

- **TDD for feature code.** Write the failing test first, run it to see it
  fail, write the minimal implementation, re-run, commit.
- **Test behavior, not implementation.** A refactor that breaks tests but not
  behavior means the tests were wrong.
- **Test edges and errors.** Every error path the code handles must have a
  test that triggers it. Empty inputs, boundaries, malformed data, network
  failures.
- **Mock boundaries, not logic.** Mock network, filesystem, time — never mock
  your own domain types.
- **Property tests** (`proptest`) for parsers, serializers, and the Unicode /
  HTML → text pipeline (`rimap-content`).
- **Snapshot tests** (`insta`) for sanitizer output so changes are visible in
  diffs.
- **Adversarial corpus** (`tests/injection-corpus/`) for the content pipeline.
  Each fixture is an `.eml` file plus an `.expected.json` declaring required
  security warnings and forbidden content. The corpus only grows.

## Git, commits, and PR workflow

- **Never commit on `main` or `master`.** Feature branches only. Enforced by
  the `branch-name` pre-commit hook.
- **One logical change per commit.** Commit messages in imperative mood, ≤72
  char subject. Use conventional-commit prefixes where natural: `feat:`,
  `fix:`, `chore:`, `docs:`, `ci:`, `test:`, `refactor:`.
- **`prek` hooks run on every commit and push.** If a hook fails, fix the
  underlying issue — do not `--no-verify`. Do not `--amend` commits that have
  been pushed.
- **PR workflow:** feature branch -> push -> PR against `main`. CI runs all seven
  status checks (`rustfmt`, `clippy`, `check (macOS)`, `test (stable)`,
  `test (MSRV 1.88.0)`, `cargo-deny`, `zizmor self-check`), plus `SonarQube` for
  code quality. `main` has branch protection requiring the status checks strict
  (branch must be up to date). A separate release workflow triggers on `v*` tags
  and builds binaries for five platform targets.
- **Never force-push to `main`.** Never amend commits that have been pushed.
  Never skip hooks.

## Security-sensitive work

Some changes deserve extra scrutiny. When touching:

- **`rimap-content` sanitization pipeline:** every change must keep the
  adversarial corpus green. Add a new fixture for any new attack class.
- **`rimap-audit` writer:** the audit log is append-only with an exclusive OS
  advisory lock. Never hold the lock across awaits. Never silently swallow
  write errors — audit failures must surface as `ERR_INTERNAL` tool errors by
  default. New `AuditWriter::log_*` methods take a single argument: pass the
  record struct directly (`Auth`, `ProcessEnd`) when no derivation is needed,
  or introduce a `<Kind>Inputs` shim with `From<Inputs> for record::<Kind>`
  when the on-disk record carries derived fields. Never positional. The rule
  is documented on `AuditWriter::log_auth`.
- **`rimap-authz` posture matrix:** the matrix has 22 tools x 4 postures
  (readonly, draft-safe, full, destructive) plus 2 infrastructure tools
  (use_account, list_accounts) that bypass posture checks. Additions to the
  tool set must update the matrix in `rimap-core` first, then the
  matrix-driven tool advertisement in `rimap-server`. Tools denied by the
  active posture must not be advertised via `list_tools`.
- **TLS fingerprint verifier** (`rimap-imap`): the custom `ServerCertVerifier`
  must reject on fingerprint mismatch *before* any application data flows.
  Never fall back to system trust on pinning failure.
- **Any change to `.github/workflows/`:** `actionlint` and `zizmor` must pass.
  Every `uses:` line must be a full 40-character SHA with a version comment.
  Never pin to a tag or branch.

## Tasks, plans, and "finish the job"

- Work on feature code is plan-driven: a spec in `docs/superpowers/specs/`
  produces a plan in `docs/superpowers/plans/`, which an implementer executes
  task by task. Plans are bite-sized, TDD-shaped, and reviewed.
- Each sprint is an independently releasable artifact. See the design spec's
  Section 12 for the full roadmap.
- "Finish the job" means: handle the edge cases you can see, clean up what you
  touched, flag adjacent brokenness. It does **not** mean: expand scope, add
  speculative features, or refactor code you didn't need to change.
- **Deferrals become GitHub issues.** When a plan, review, or implementation
  consciously defers work that needs follow-up beyond the current scope —
  punted features, partial implementations, cross-platform parity gaps,
  config fields whose behavior isn't wired yet, etc. — open a GitHub issue
  for each item before the plan/PR is considered done. Do not rely on prose
  in a plan document or a TODO comment to track follow-up work; both rot.
  Each issue should name the deferral, link the plan/PR that introduced it,
  cite the relevant spec section, and state acceptance criteria. Work that
  is *already covered* by an upcoming sprint's spec scope does not need a
  separate issue; work that falls between sprints does.

## What not to do

- Do not add runtime dependencies without explicit scope approval.
- Do not add features, flags, or config fields that nothing uses.
- Do not deprecate in place when replacing — delete the old code.
- Do not leave commented-out code. Delete it; git remembers.
- Do not add doc comments explaining WHAT the code does. Refactor until the
  code is self-documenting, then comment WHY if it's non-obvious.
- Do not restructure unrelated code "while you're there."
- Do not claim a task is complete before `just ci` is green locally.

## Operator notes

### Operator notes — `audit merge`

`audit merge` re-emits records to stdout. When the output is redirected to a
file, the new file is created with the shell's current umask, which on most
systems is `0022` and produces a world-readable `0644` dump. Operators may
assume "audit log = `0600`" and not realize the merged dump isn't.

Recommended patterns:

**Important:** `umask` only affects subsequent file creations in the SAME
shell invocation. If you run `umask 077` on one line and the `rusty-imap-mcp
audit merge` command on the next line, that works in an interactive shell
session — but in a script that spawns a new subshell per command, the umask
will not apply to the redirect. The `&&` form below chains the umask and
the redirect into a single invocation and is safe in both interactive shells
and scripts. The `install` form below is safer still because it sets the
mode atomically on the destination without depending on the shell's umask.

```bash
# 1. Set a tight umask and run the redirect in the same shell command.
#    The && is load-bearing: it ensures both actions share a umask scope.
umask 077 && rusty-imap-mcp audit merge … > dump.jsonl

# 2. Preferred in scripts: pipe through `install` for an atomic mode-set.
#    This does not depend on umask at all.
rusty-imap-mcp audit merge … | install -m 0600 /dev/stdin /target/dump.jsonl
```
