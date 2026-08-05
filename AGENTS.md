# AGENTS.md

Guidance for programming agents (Claude Code, Codex, Copilot, etc.) working in
this repository. The global development standards in the developer's personal
`~/.claude/CLAUDE.md` (or equivalent) apply first; this file adds repo-specific
context and overrides where needed.

> **Scope:** this is a contributor guide for developing *this codebase*. If you
> are configuring or operating an email agent and want the surface the server
> exposes — the tools, their parameters, response fields, and required
> postures — see the generated reference at [docs/tools.md](docs/tools.md).

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

The workspace is feature-complete for its 0.1.x line. The eight member crates under `crates/` implement
24 advertised MCP tools (22 posture-gated + 2 infrastructure), backed by 27 `ToolName`
capability variants (three are full-posture sub-capabilities of `search`, `fetch_message`,
and `create_draft`), multi-account support, SMTP sending, an audit log, and a content
pipeline with look-alike detection. Five platform targets are built via the release workflow.

## Development commands

All commands are wrapped in `just` so local dev and CI stay in lockstep. **If
`just ci` passes locally, CI will pass.**

```bash
just setup           # one-time: install tooling, MSRV toolchain, prek hooks
just check           # fast compile-check (inner loop)
just fmt             # format the workspace in place
just fmt-check       # verify formatting without modifying
just lint            # cargo clippy with -D warnings
just test-fast       # inner-loop unit tests (~4 s; skips heavy integration/proptest)
just test            # full nextest workspace — run before pushing
just test-msrv       # same as `test` but on the MSRV toolchain (1.88.0)
just deny            # cargo deny check (advisories, licenses, bans, sources)
just semver-checks   # public API vs the last vX.Y.Z tag (see RELEASING.md)
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

Autodetect picks the first runtime that *works*, not the first one
installed: each candidate is probed in turn and the first whose daemon
answers is selected, so a stopped Docker Desktop falls through to a
working podman instead of skipping the suite. Set
`RIMAP_CONTAINER_TOOL=docker` or `RIMAP_CONTAINER_TOOL=podman` to force a
choice — an explicit override probes only the runtime it names and never
falls through, so a typo'd or unusable override fails on its own terms.

The gate probes the runtime, not just the binary: it runs
`<runtime> info`, the first call that actually contacts the daemon. A
missing binary *and* a binary whose daemon cannot be reached (stopped,
restarting, socket gone) are both silent skips — they are the two ways a
host genuinely cannot run the fixture. Selection and its verdict share
one cache, so the probe runs once per test process (twice only when the
first candidate is unusable) and gives up after 10s per candidate. Set
`RIMAP_REQUIRE_DOCKER=1` to turn either into a loud failure; CI does.

Everything else is loud, deliberately. The probe only reports "cannot
run containers" when the runtime's own stderr says it could not reach
its engine; any other non-zero exit — and a probe that overruns its
budget — is treated as usable, so the run proceeds to `compose up` and
fails there. That is what keeps a *live* daemon refusing work visible:
an unpullable image, a readiness timeout, or
`all predefined address pools have been fully subnetted` (which is what
several agents running `just ci` at once actually hit) is a hard failure
at every posture, never a skip.

The fixture image is `docker.io/dovecot/dovecot:2.4.4-root` (rootful
flavor, multi-arch `linux/amd64` + `linux/arm64`). It listens on
container ports 143 (IMAP+STARTTLS) and 993 (IMAPS); the Rust harness
maps host ports dynamically. There is no arch gate — every supported
developer host can run the suite.

### Local Test Troubleshooting: Address Pool Exhaustion

If running integration tests locally triggers the error:
`Error response from daemon: all predefined address pools have been fully subnetted`

This happens when transient Docker Compose networks accumulate. The test runner now automatically runs network pruning via `just test`, but if you encounter this manually, run:
`docker network prune -f` (or `podman network prune -f`).


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
  fixture — missing docker/podman, or a runtime whose daemon does not
  answer the pre-flight probe. `RIMAP_REQUIRE_DOCKER=1` flips every
  failure mode (unusable runtime, compose-up, readiness timeout, port
  reservation, fingerprint read) to a panic with diagnostic context.
  Same convention as the legacy in-process `e2e_full_session`.
- Schema regen: when changing any `<Tool>Meta` or `<Tool>Untrusted`
  struct in `crates/rimap-server/src/tools/`, run
  `just regen-tool-schemas` and commit the diff. CI fails on a
  non-empty diff under `tests/fixtures/rimap-tool-schemas/`.
- Specs: see `docs/superpowers/specs/2026-05-12-mcp-behavioral-conformance-design.md`.

### Network chaos e2e (nightly, #522)

`crates/rimap-server/tests/e2e_wire_chaos.rs` interposes a Toxiproxy container
between the server binary and the same Dovecot fixture to exercise
degraded-but-alive networks: delayed greeting, mid-FETCH stall, RST during
STARTTLS, and byte-trickle. Each scenario asserts the typed `ERR_*` wire code,
the audit record, and post-fault recovery.

- **Nightly-only.** Gated behind `RIMAP_CHAOS=1` (checked before the runtime
  probe), so the suite silent-skips on PR CI even under `RIMAP_REQUIRE_DOCKER=1`.
- **Run locally:**
  `RIMAP_CHAOS=1 RIMAP_REQUIRE_DOCKER=1 cargo nextest run -p rimap-server -E 'binary(e2e_wire_chaos)' --no-capture`
- **Multi-arch, no arch gate.** Toxiproxy `ghcr.io/shopify/toxiproxy:2.12.0` and
  Dovecot `2.4.4-root` both ship `linux/amd64` + `linux/arm64`.
- Runs serially (nextest `chaos-backed` group) — two containers per test with
  tight timeout budgets. CI: `.github/workflows/nightly-chaos.yml`. Spec:
  `docs/superpowers/specs/2026-07-09-issue-522-wire-chaos-design.md`.

### Differential HTML oracle (nightly, #529)

`html-oracle/` is a crate **excluded** from the workspace (like `fuzz/`, own
`Cargo.lock`) that diffs the production HTML→text sanitizer against an
independent `lol_html` tokenizer over the fuzz + injection HTML corpus. It
red-flags text the sanitizer drops with no explaining `SecurityWarning` (a
silent-drop bug). Run locally:

```bash
cargo run --manifest-path html-oracle/Cargo.toml -- --repo-root .
```

Exits non-zero only on a HARD (silent-drop) divergence; writes
`html-oracle/report.json`. Warning-explained (SOFT) drops stay green and land in
the report for triage. Being excluded, it never touches the PR gates
(`clippy --all-features`, `test-msrv`, `cargo-deny`); the nightly workflow
(`.github/workflows/nightly-html-oracle.yml`) runs it and a scoped `cargo deny`
on its own graph. Spec:
`docs/superpowers/specs/2026-07-10-issue-529-differential-html-oracle-design.md`.

The nightly also checks out the private `rusty-imap-mcp-corpus` repo at a pinned
SHA into `corpus/` and runs with `--repo-root . --corpus-root corpus` (issue
#550, spec `docs/superpowers/specs/2026-07-10-oracle-corpus-expansion-design.md`).
Locally, `--corpus-root <dir>` (or `CORPUS_ROOT`) loads an external `.eml` tree
under `corpus/…` ids alongside `--repo-root`; `--corpus-min-compared <N>` fails
the run when fewer than `N` `corpus/` inputs compare nonempty. Waves 1 (#551,
454 html5lib/template/synthetic inputs) and 2 (#554, +200 SpamAssassin/Nazario
real-mail inputs) are ingested, so the nightly pins the wave-2 corpus SHA and
sets `--corpus-min-compared 517` (`floor(0.9 × 575)`); recompute `N` in the same
reviewed PR whenever a SHA bump materially shifts the comparison count. The
restated keep/kill baseline is `docs/security/html-oracle-corpus-wave2-baseline.md`. Because the corpus repo is private, the checkout uses
the `CORPUS_READ_TOKEN` secret — an expired/revoked token or an unresolvable
pinned SHA reddens the *whole* oracle nightly by design (fail-loud, not a silent
degrade), so first triage on a red nightly is the corpus-checkout step, then the
token, then the pin.

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
  reserved for MCP transport; diagnostics go to stderr through the `tracing`
  subscriber that ships today (`boot/logging.rs`, wired in `main.rs`; filter
  controlled by `RIMAP_LOG` / `RUST_LOG`, default `info`). In tests, debug
  output via these macros is allowed. In `main.rs` and library code, use
  `tracing` or `writeln!` on a captured handle.
- **No `#[allow(...)]` attributes.** `allow_attributes = "deny"`. Use
  `#[expect(...)]` with a comment explaining why if you must suppress a lint.
- **No `unwrap()` in non-test code.** `unwrap_used` is denied. Prefer `?`,
  `match`, `let ... else`, or explicit error handling. Tests may
  `#[expect(clippy::unwrap_used)]` the whole `mod tests`.
- **No panics in `Result` functions.** `panic_in_result_fn` is denied. If you
  need to bail, return an error.
- **`thiserror` for library crates, `anyhow` for `rimap-server`.**
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

## Testing expectations

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
- **Golden agent transcripts** (`insta`, issue #524).
  `crates/rimap-server/tests/e2e_wire_transcript_*.rs` snapshot the full JSON-RPC
  transcript an agent sees across a scripted session (initialize instructions, the
  advertised tool catalog, and each tool response's `meta`/`untrusted`/
  `security_warnings`), driven against the in-process fake (no container,
  PR-blocking). A `.snap` diff means the agent-facing surface changed:
  - **Intended change** (reworded warning, new `meta` field, protocol bump):
    review the diff, then `cargo insta review` (or `cargo insta accept`) and
    commit the updated `.snap`.
  - An **unintended diff is a drift bug** — investigate, do not accept.
  - **Never blind-accept** a triage-transcript `security_warnings`/sanitized-body
    diff: the hostile fixture is transcript-owned
    (`tests/fixtures/transcript/`), so such a diff is a sanitizer change, not
    fixture churn — attribute it before accepting.
- **Adversarial corpus** (`tests/injection-corpus/`) for the content pipeline.
  Each fixture is an `.eml` file plus an `.expected.json` declaring required
  security warnings and forbidden content. The corpus only grows.
- **Fake vs Dovecot.** Use the in-process scriptable fake
  (`crates/rimap-imap/tests/support/fake_imap.rs`) to test client behavior
  against a *misbehaving* server — missing capabilities (no MOVE/UIDPLUS,
  `LOGINDISABLED`), malformed or zero UIDs, truncated literals, mid-command
  disconnects. It terminates TLS with a pinned self-signed cert, is
  host-runnable (no container), and is PR-blocking. Use the Dovecot container
  harness (`tests/integration/`) for *conformant* end-to-end behavior; it is
  container-gated and silent-skips without a usable runtime (see "Container
  runtime for integration tests").

## Git, commits, and PR workflow

- **Never commit on `main` or `master`.** Feature branches only. Enforced by
  the `branch-name` pre-commit hook.
- **One logical change per commit.** Commit messages in imperative mood, ≤72
  char subject. Use conventional-commit prefixes where natural: `feat:`,
  `fix:`, `chore:`, `docs:`, `ci:`, `test:`, `refactor:`.
- **`prek` hooks run on every commit and push.** If a hook fails, fix the
  underlying issue — do not `--no-verify`. Do not `--amend` commits that have
  been pushed.
- **PR workflow:** feature branch -> push -> PR against `main`. `main` requires
  twelve status checks, strict (the branch must be up to date before merging):
  `rustfmt`, `clippy`, `check (macOS)`, `test (stable)`, `test (MSRV 1.88.0)`,
  `cargo-deny`, `zizmor self-check`, `SonarQube`, `mcp-conformance (Node)`,
  `publish checks`, `tool-schema drift`, `tools-doc drift`. A separate release
  workflow triggers on `v*` tags and builds binaries for five platform targets.
- **A CI job outside that list runs without enforcing.** It goes red and the PR
  merges anyway, so adding a gate to an unrequired job silently disarms it
  (issue #613). Before wiring a new check into a job, confirm the job's
  status-check name is required, and add it if not:
  `gh api repos/randomparity/rusty-imap-mcp/branches/main/protection --jq '.required_status_checks.contexts'`
- **`semver-checks` is a thirteenth check that is *not* yet required** (issue
  #633). It runs on every PR and reports, but until `semver-checks` is added to
  the contexts list above it cannot block a merge — treat a red one as blocking
  by hand. It fails when a PR breaks the public API of a publishable crate
  without bumping the planned version; the fix is
  `cargo set-version --workspace 0.2.0-dev` (from `cargo-edit`), not an
  override. See
  [RELEASING.md](RELEASING.md), "Breaking a public API".
- **`release.yml` runs the same `just semver-checks` before publishing** (issue
  #650), so a red one is not only a PR problem — it is what stands between a
  break and an unpublishable-back crates.io version. Do not paper over it in the
  recipe; the fix belongs in the manifest version.
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
- **`rimap-authz` posture matrix:** the matrix has 25 capabilities x 4 postures
  (readonly, draft-safe, full, destructive) — 22 posture-gated tools plus 3
  full-posture sub-capabilities (`search.advanced_query`,
  `fetch_message.include_html`, `create_draft.include_html`) — plus 2
  infrastructure tools (use_account, list_accounts) that bypass posture checks.
  Additions to the tool set must update the matrix in `rimap-core` first, then the
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
