# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Boot now reports each account's effective tool matrix, marking every explicit
  per-tool verdict as account-written or inherited from
  `[defaults.security.tools]`. An inherited `allow` on an account tightened to
  `posture = "readonly"` is visible without running anything: it appears in a
  `tracing::info!` line at startup, in a new `tool_matrix` field on the
  `process_start` audit record (present for single- and multi-account configs
  alike), and in a new `Explicit tool overrides:` section of
  `rusty-imap-mcp --dry-run`. All three render the same rows from one producer.
  `process_start` records written before this field parse unchanged. See #632
  and `docs/audit-log.md`.
- crates.io publishing of all 8 workspace crates on stable `v*` tags, via a
  new `publish-crates` release job. Publishes in dependency order with an
  idempotent, rate-limit-aware `scripts/publish-crates.sh`, gated by
  `cargo-semver-checks` and the `crates-io` deployment environment. See #544 /
  ADR-0004 and RELEASING.md.

### Fixed

- `process_end` is now the terminal audit record of its process. The server
  cancels and drains in-flight tool dispatches before writing it, so a connect
  the shutdown cuts records its `auth` entry (`ERR_CANCELLED`) *before*
  `process_end` instead of appending after it — or losing it, or tearing the
  JSONL tail. The same drain also stops an in-flight dispatch from holding the
  process exit for its own command timeout. See #645 and `docs/audit-log.md`.
- Multi-account configs now merge `[defaults.security]`, `[defaults.limits]`,
  and `[defaults.credentials]` into each account **key by key**. Previously an
  account that wrote the corresponding table at all discarded the whole
  `[defaults]` block, and every key it left unset silently reverted to the
  built-in default rather than the operator's configured one. See #624 /
  ADR-0013.

### Changed

- **API break: every `pub` struct in `rimap_config::model` is now
  `#[non_exhaustive]` (#665).** All 16 of them — `Config`, `ImapConfig`,
  `SmtpConfig`, `SecurityConfig`, `LookalikeConfig`, `LimitsConfig`,
  `AuditConfig`, `AttachmentsConfig`, `CredentialsConfig`,
  `MultiAccountConfig`, `DefaultsConfig`, `RawAccountConfig`, and the four
  `Account*Overrides` types. Adding a config field is no longer a breaking
  change, which is the failure #648 hit when one new `LimitsConfig` field
  forced the workspace to `0.2.0`. This aligns `rimap-config` with
  `rimap_content::output`, which has carried the same policy since Sprint 4b.

  Downstream impact: the struct literal is no longer available outside the
  crate, and **that includes functional-update syntax** — `..Default::default()`
  is still a struct expression, so rustc rejects it too (E0639). Construct
  these types as `let mut c = T::default(); c.field = …;`, or via the new
  constructors below. Pattern matches need a trailing `..`.

  `ImapConfig`, `SmtpConfig`, and `AuditConfig` have no `Default` and gain
  `ImapConfig::new(host, port, username)`,
  `SmtpConfig::new(host, port, encryption, username)`, and
  `AuditConfig::new(path)`. Each takes exactly the fields the TOML schema
  requires and fills the rest with the value the loader applies for an omitted
  key. `Config`, `MultiAccountConfig`, and `RawAccountConfig` deliberately gain
  neither a `Default` nor a constructor: they are file-load roots from
  `load_and_validate` / `load_from_path`, and a `Default` for them would mint a
  config with an empty `host` and `username` — the invalid state validation
  exists to reject.
- **API break: `rimap_config::validate::ValidatedAccountConfig` and
  `ValidatedMultiConfig` are now `#[non_exhaustive]` (#707).** These are the
  two `pub` structs the validation pipeline outputs, and both are still
  growing: #632 broke them one field ago by adding `account_written_tools`.
  Marking them makes a future field additive. Sibling of #665, which applied
  the same policy to `rimap_config::model`.

  Downstream impact: the struct literal is no longer available outside the
  crate, and **that includes functional-update syntax** — `..Default::default()`
  is still a struct expression, so rustc rejects it too (E0639). Neither type
  gains a `Default`: in production a validated config is obtainable only from
  `validate_multi` / `validate_legacy_as_multi` / `load_and_validate`, which is
  what makes "validated" mean something, and a `Default` would mint the
  unvalidated state those entry points exist to reject. Adjust a value from
  one of those entry points by field assignment; pattern matches need a
  trailing `..`.

  For test code, the `test-support` feature adds
  `ValidatedAccountConfig::new_for_tests(id, imap)` and
  `ValidatedMultiConfig::new_for_tests(audit, attachments)` — each takes the
  fields with no meaningful default and fills the rest with the value the
  validator resolves for an omitted key, leaving the remainder to field
  assignment. They sit behind the same gate as `validate_multi_allowing_empty`
  so the production surface keeps offering exactly one way in.
- **Behaviour break for multi-account configs (#624).** Because the fix above
  makes accounts inherit keys they previously reverted, an account carrying a
  partial `[accounts.security]` block can come out *more* permissive after
  upgrading:
  - it now inherits `[defaults.security.tools]` verdicts, including `allow`
    entries — and an explicit `allow` permits a tool regardless of posture, so
    an account marked `posture = "readonly"` can acquire `delete_message`,
    `export_messages`, or `send_email`;
  - it now inherits `[defaults.security] expunge_folders` in place of the
    built-in empty list, which is the one way a folder can become expungeable
    that was not before;
  - it now inherits `[defaults.security] protected_folders`, which narrows
    protection whenever that list is shorter than the built-in
    `INBOX`/`Sent`/`Drafts`/`Trash`.

  Some configs that previously started will now fail validation instead, all
  fail-closed: an inherited `send_email = "allow"` requires `[accounts.smtp]`,
  an inherited `export_messages = "allow"` requires a server-private
  `[attachments].download_dir`, and an inherited `protected_folders` may now
  overlap an account's own `expunge_folders`.

  Run `rusty-imap-mcp --dry-run` before and after upgrading and diff the
  per-account effective matrix it prints. **That covers the tool-verdict
  widening only.** `--dry-run` prints posture, per-tool verdicts,
  infrastructure tools, IMAP capabilities, and the TLS fingerprint — it does
  **not** print `protected_folders`, `expunge_folders`, or any `[limits]`
  field, so the folder-list widenings above are invisible in its output.
  Review those two lists by hand against your `[defaults.security]` for every
  account carrying a partial `[accounts.security]` block. #632 added a
  boot-time record of the resolved *tool verdicts* with their provenance; the
  resolved folder lists are still recorded nowhere.
- `rimap-config`: `RawAccountConfig::{security, limits, credentials}` change
  type to the new `AccountSecurityOverrides` / `AccountLimitsOverrides` /
  `AccountCredentialsOverrides` mirror structs. Breaking for direct consumers
  of the crate's model types.
- Version model: `Cargo.toml` now carries the next planned version with a
  `-dev` suffix (e.g. `0.1.1-dev`); release-prep strips it and a
  `post-release-bump` job re-bumps after each release. See ADR-0003.
- **Next planned release is `0.2.0`, not `0.1.1`** — the manifest moved from
  `0.1.1-dev` to `0.2.0-dev`. `rimap-config`'s `LimitsConfig` gained a `pub`
  field (`tool_call_timeout_seconds`, #594 / ADR-0012) after `v0.1.0`, and it
  is a `pub` struct with all-`pub` fields and no `#[non_exhaustive]`, so an
  external struct literal written against `v0.1.0` no longer compiles. Under
  SemVer at `0.x` the minor field carries breaking changes, so a patch release
  could not have shipped it honestly. **No action is needed by anyone today** —
  crates.io holds only `0.0.0` placeholder reservations, so no real `v0.1.0`
  was ever published and nothing downstream can have built against it; the
  bump is what keeps that true at the first genuine publish. Caught by the
  per-PR `cargo-semver-checks` gate added for #633 (PR #651). The same bump
  also covers the `RawAccountConfig` break noted above and any further break
  landing in this release cycle — they all diff against the same `v0.1.0` tag.
  See #648.
- `rimap-content` now declares `license = "(MIT OR Apache-2.0) AND
  Unicode-3.0"` to cover its vendored Unicode 16.0 TR39 `confusables.txt` data
  (correcting a stale note that misnamed the license `Unicode-DFS-2016`). Every
  crate now carries `keywords`/`categories` for crates.io discoverability.

## [0.1.0] - 2026-07-10

### Fixed

- A read tool call resumed after an idle gap now recovers transparently
  instead of returning `ERR_CONNECTION_LOST` on the first try. When the IMAP
  server has closed a cached session during inactivity, `with_session` now
  reconnects and retries the command **once** — but only for idempotent
  read-only ops (`list_folders`, `status`, `select`, `search`,
  `thread_related`, `fetch`, `fetch_body`). Mutating ops (`store`, `move`,
  `append`, `delete_message`, `expunge`, folder create/rename/delete) are
  never auto-retried, since a re-sent write could double-apply after a
  mid-command disconnect; they still invalidate the dead session and surface
  the error to the caller. The retry is bounded to a single attempt. Issue
  #450 (audit finding M-13); builds on #449.

### Added

- Generated tool reference at [`docs/tools.md`](docs/tools.md): one section
  per advertised MCP tool with its title, description, minimum posture,
  parameter table, and response fields, rendered from the live catalog. A
  hidden `dump-tool-doc` subcommand emits the per-tool data (including the
  minimum posture from `rimap-core`'s matrix); `just gen-tools-doc` renders
  it and a `tools-doc drift` CI job (plus `just ci`) fails if the committed
  doc falls out of sync — the same guarantee as the tool-schema drift check.
  `AGENTS.md` now states it is a contributor guide and points operators at
  `docs/tools.md`; `docs/INDEX.md` links the reference. Issue #413.
- `search` gains an opt-in `thread_of_uid` parameter: given a UID, returns
  the whole conversation (the target message, every ancestor named in its
  own `References`/`In-Reply-To` chain, and every descendant whose
  `References`/`In-Reply-To` names the target's `Message-ID`) instead of a
  filtered search. Built as a Message-ID chain-walk over a single `SEARCH`
  command with nested `OR` clauses — `async-imap` has no client support
  for the IMAP THREAD extension (RFC 5256), so that path is out of scope.
  Available at every posture: the header values compared are drawn from
  the target message itself, not caller-supplied text, so `thread_of_uid`
  cannot probe arbitrary header/value pairs across the mailbox the way
  `headers`/`body`/`text` can — it stays at the low-posture `Search` seat
  rather than promoting to `SearchAdvanced`. Mutually exclusive with
  `advanced_query`. Issue #435 (deferred option (c) from #410).
- `tools/list` now honors MCP cursor pagination. Large multi-account
  catalogs are served one page at a time (25 tools/page) instead of a single
  response; the cursor is an opaque catalog offset and a client walks
  `nextCursor` to completion. Single- and few-account deployments fit in one
  page and are unchanged. For a 3-account full-posture config the initial
  response drops from ~616 KB (59 entries) to ~267 KB (25 entries). A
  non-numeric cursor is rejected with `-32602`. Issue #411.
- Two static MCP resources, `rimap://docs/postures` and
  `rimap://docs/workflows`, advertised by `resources/list` regardless of
  account count. `rimap://docs/postures` is `docs/postures.md` verbatim;
  `rimap://docs/workflows` is a new `docs/mcp-workflows.md` covering the
  search→fetch→act pattern, UIDVALIDITY pinning, attachment retrieval, the
  draft lifecycle, and the `export_messages` opt-in, with a numeric-limits
  table pinned by a test against the Rust constants that enforce each
  limit. Both `ServerInfo.instructions` constants now point agents at these
  URIs. Issue #407.
- `search` gains an opt-in `body_preview_bytes` parameter: when set, each
  result carries a sanitized plain-text `body_preview` (first N bytes, capped
  at 1024) plus a `body_preview_truncated` flag, for the first 50 results of a
  page. Collapses "summarize my inbox" from one `search` + K `fetch_message`
  calls to a single call. Previews reuse the `fetch_message` body pipeline
  (same Unicode sanitization); per-message fetch/parse failures are isolated,
  and the parameter adds no posture gate (a truncated body of an
  already-matched message, like `fetch_message`, not a content filter).
  Rationale in `docs/superpowers/specs/2026-07-03-issue-410-body-preview-design.md`.
  Issue #410.
- `fetch_message` gains an opt-in `include_headers` parameter: an allowlist
  of header names (≤ 16 per call) whose sanitized values are returned under
  `untrusted.headers` (name → array of values). Unblocks unsubscribe,
  mailing-list triage, and delivery/spam-header workflows without raising
  posture. Not gated as a sub-capability (rationale in
  `docs/superpowers/specs/2026-07-03-issue-409-include-headers-design.md`).
  Extraction runs on the same scrubbed message as body parsing, so
  CRLF-smuggled headers cannot reappear. Issue #409.
- Annotated `config.example.toml` (single-account) and
  `config.multi-account.example.toml` at the repo root — copyable,
  secrets-free starting points documenting the full config surface. A
  `rimap-config` integration test loads both through the real loader so
  the examples cannot drift from the schema. Issue #418.
- Per-protocol password env-var fallbacks
  `RUSTY_IMAP_MCP_IMAP_PASSWORD` / `RUSTY_IMAP_MCP_SMTP_PASSWORD`, consulted
  before the legacy shared `RUSTY_IMAP_MCP_PASSWORD` when
  `fallback = "keyring-then-env"`. Lets IMAP and SMTP resolve different
  credentials via the env-var fallback; a `tracing::warn!` fires when the
  legacy shared var supplies a credential while the protocol-scoped var is
  unset. `keyring-only` mode still consults no env var. Issue #260.
- MCP wire-shape conformance test
  (`crates/rimap-server/tests/mcp_wire_conformance.rs`) — spawns the
  binary, drives JSON-RPC over stdio, and validates every response
  against the vendored MCP spec schema. Permanent regression net for
  #261 (empty capabilities) and `fix/tool-input-schema-object-type`
  (empty inputSchema). Issue #263.
- `scripts/refresh-mcp-spec.sh` to refresh or drift-check the vendored
  MCP spec schema.
- `.github/workflows/mcp-spec-drift.yml` — weekly check that opens a
  tracking issue when the vendored MCP schema differs from upstream.
- `[defaults.credentials]` / `[[accounts.credentials]]` TOML section with a
  `fallback` knob (`keyring-only` vs `keyring-then-env`, default
  `keyring-then-env`). Setting `keyring-only` disables the
  `RUSTY_IMAP_MCP_PASSWORD` env-var fallback for multi-account deployments
  where a shared fallback would cross account boundaries (#78).
- Audit records of kind `auth` now include a `credential_source` field
  (`keyring` / `legacy_keyring` / `env_var`) for post-incident analysis.
- `rusty-imap-mcp migrate-keyring` CLI subcommand to migrate credentials
  from the legacy keyring key format to the new namespaced format.

#### Multi-account support

- Multiple IMAP/SMTP accounts in a single server process via `[[accounts]]`
  config array with per-account posture, rate limits, and SMTP settings.
- `use_account` tool to set the session-scoped default account.
- `list_accounts` tool to enumerate configured accounts with posture and
  SMTP status.
- MCP resource discovery: `rimap://accounts/<name>` exposes account
  metadata (host, posture, available tools) without credentials.
- Account resolution: explicit `account` parameter > session default >
  auto-select (single account) > error.
- Full backward compatibility: existing single-account `[imap]` configs
  work unchanged as a synthetic `"default"` account.

#### MCP tools

**Read operations (all postures):**

- `list_folders` -- IMAP folder listing with message counts
- `search` -- structured query builder (from, to, subject, date range)
- `fetch_message` -- message fetch with text body extraction
- `list_attachments` -- attachment metadata for a message
- `download_attachment` -- download attachment by part index
- `list_labels` -- list custom IMAP keyword flags on a message

`export_messages` (bulk raw mbox export of multiple UIDs to the download
sandbox) is denied in every posture by default and enabled only via an
`export_messages = "allow"` override in `[security.tools]`.

**Mutation operations (draft-safe and above):**

- `mark_read` / `mark_unread` -- set or clear `\Seen` flag
- `flag` / `unflag` -- set or clear `\Flagged` flag
- `add_label` / `remove_label` -- add or remove custom IMAP keyword flags
- `move_message` -- move message between folders
- `create_draft` -- append to Drafts with `$PendingReview` keyword

**Full posture operations:**

- `send_email` -- SMTP send with Sent folder copy
- `forward` -- re-send an existing message as a `message/rfc822` wrapper
- `delete_message` -- flag `\Deleted` and move to Trash
- `create_folder` / `rename_folder` -- IMAP folder management

Advanced IMAP `SEARCH` passthrough and sanitized HTML bodies are exposed
as full-posture sub-capabilities of `search`, `fetch_message`, and
`create_draft` (`advanced_query` / `include_html` / `body_html`), not as
standalone tools.

**Destructive posture operations:**

- `expunge` -- permanently remove `\Deleted` messages (folder allowlist)
- `delete_folder` -- permanently remove folder (folder allowlist +
  protected folder check)

**Infrastructure tools (always available):**

- `use_account` -- switch active account context
- `list_accounts` -- list configured accounts

#### Security postures

Four authorization tiers with per-tool overrides:

| Posture | Scope |
|---------|-------|
| `readonly` | Read-only: list, search, fetch, download |
| `draft-safe` | Read + safe mutations: flags, moves, drafts (default) |
| `full` | All above + send, delete, folder management, HTML, advanced search |
| `destructive` | All above + expunge, delete_folder |

Tools denied by the active posture are not advertised via `list_tools`.
Per-tool `"allow"` / `"deny"` overrides merge on top of the posture.

#### Content pipeline

- RFC 5322 / MIME parsing via `mail-parser`
- Charset decoding via `encoding_rs`
- NFKC Unicode normalization
- Invisible/ambiguous codepoint stripping (zero-width chars, bidi
  overrides, C0/C1 controls)
- HTML-to-text conversion with hidden-content stripping (CSS
  `display:none`, `visibility:hidden`, `opacity:0`, white-on-white)
- Sanitized HTML output via `ammonia` (conservative allowlist)
- Link text/href domain mismatch detection
- Look-alike detection: mixed-script, confusable skeleton matching,
  display-name spoofing, reply-to domain mismatch, filename bidi tricks
- Attachment filename sanitization (path separators, leading dots,
  Windows reserved names, length truncation)
- Structured response envelope: `meta` (trusted), `untrusted`
  (sanitized), `security_warnings` (server assessment)

#### SMTP sending

- `rimap-smtp` crate wrapping `lettre` with rustls TLS
- STARTTLS (port 587), implicit TLS (port 465), and plaintext modes
- Per-send connection lifecycle (no pooling)
- Automatic Sent folder copy via IMAP APPEND after send
- `sends_per_minute` rate limit (default 3)

#### Audit log

- Append-only JSONL audit log with exclusive OS advisory file lock
- Every tool call produces `tool_start` + `tool_end` records linked by
  sequence number
- Content provenance ring buffer: recently-read message IDs snapshotted
  into every `tool_end` record
- Account name tagged on every record in multi-account configs
- Size-based rotation with configurable count and time-based retention
- `audit merge` subcommand with `--account` filter and `--since` /
  `--until` time range
- `fail_open = false` default: audit write failures fail the tool call

#### Folder safety

- `protected_folders` list (default: INBOX, Sent, Drafts, Trash) --
  blocks rename and delete on protected folders
- `expunge_folders` allowlist (default empty = deny all) -- required for
  `expunge` and `delete_folder`
- `create_folder` rejects names colliding with protected folders

#### Rate limiting and circuit breaker

- Token-bucket rate limiter: `commands_per_second` (default 10) with
  burst of 20
- Separate `drafts_per_minute` (default 5) and `sends_per_minute`
  (default 3) limits
- Sliding-window circuit breaker: closed > open > half-open state
  machine
- Auth failures trip immediately (single failure opens for 60s)
- Exponential backoff cooldown (doubled per re-trip, capped at 5 min)

#### TLS fingerprint pinning

- SHA-256 certificate fingerprint pinning for self-signed certs (e.g.
  Proton Bridge)
- Verified before any application data flows
- Hard failure on mismatch -- no fallback to system trust store when
  pinning is configured

#### Labels

- IMAP keyword-based labels via `STORE +FLAGS` / `-FLAGS`
- `add_label`, `remove_label`, `list_labels` tools
- Label validation: max 256 bytes, IMAP atom charset, no system flag
  namespace (`\` prefix rejected)

#### Platform support

Pre-built binaries for five targets:

- `x86_64-unknown-linux-gnu` (native)
- `aarch64-unknown-linux-gnu` (QEMU emulation)
- `aarch64-apple-darwin` (native macOS)
- `powerpc64le-unknown-linux-gnu` (QEMU emulation)
- `s390x-unknown-linux-gnu` (QEMU emulation)

#### Development toolchain

- Cargo workspace with 8 member crates
- MSRV 1.88.0 (edition 2024), dev toolchain 1.94.0
- SHA-pinned GitHub Actions CI (fmt, clippy, test, MSRV, cargo-deny,
  zizmor, SonarQube)
- Release workflow triggered on `v*` tags with SHA256 checksums
- `prek` pre-commit hooks (fmt, clippy, shellcheck, actionlint, zizmor,
  typos)
- `cargo-deny` supply-chain audit (advisories, licenses, bans, sources)
- `cargo-nextest` test runner
- Property-based tests via `proptest`, snapshot tests via `insta`
- Adversarial email injection corpus
- `justfile` with `just ci` as the local-CI equivalent
- Dual MIT / Apache-2.0 license

### Changed

- Launching the server when no config file exists at the resolved path now
  prints actionable first-run guidance to stderr — naming the missing path
  and pointing at `config.example.toml`, the Gmail and Proton Bridge
  quickstarts, and the `--config` / `RUSTY_IMAP_MCP_CONFIG` overrides —
  instead of a raw `tracing::error!` "No such file or directory" line that
  GUI/stdio MCP clients discard. A new `ConfigError::NotFound` variant
  distinguishes an absent file from other read failures. stdout (the MCP
  transport) is untouched. Issue #469 (audit finding M-11).
- Added static remediation guidance for folder-policy and posture
  denials to the `expunge`, `create_folder`, `rename_folder`,
  `delete_folder`, and `send_email` descriptions. Runtime denial errors
  are deliberately scrubbed (`ProtectedFolder`/`ExpungeDenied` become
  "operation denied for this folder"), leaving an agent no way to act;
  the descriptions now name the stable `error_code` it will see
  (`ERR_PROTECTED_FOLDER`, `ERR_EXPUNGE_DENIED`, `ERR_POSTURE_DENIED`),
  the governing config key (`[security].protected_folders`,
  `[security].expunge_folders`), that the policy cannot be overridden
  through MCP, and the `rimap://docs/postures` resource. No runtime
  behavior or error message changed. Issue #417.
- Expanded the MCP tool descriptions from terse one-liners to 1-3
  sentences of workflow and constraint guidance an agent can act on:
  when to use each tool, the discovery tool that feeds it (`search` for
  UIDs, `list_attachments` for `part_id`), the batch limit (single `uid`
  or up to 100 `uids`), the two-step delete/expunge model, and plain-word
  posture/config gating. `create_draft` now documents the `$PendingReview`
  dead-end (the draft cannot be sent through the server; do not follow up
  with `send_email`). Issue #404.
- Stripped rustdoc artifacts from every published tool schema:
  unresolvable Rust doc-link syntax (`` [`...`] ``), internal
  function/constant names (`build_query`, `escape_wire_name`,
  `MAX_BATCH_UIDS`), the generic-parameter (`M`/`U`) implementation
  note on every tool's response envelope, `# Shape` design-rationale
  essays aimed at reviewers rather than callers, and boilerplate
  "Input for the `X` tool." schema roots that added nothing. Batch and
  export size limits now appear as literal numbers (100 UIDs, 100 MiB)
  where referenced. The `search` tool's posture-gated field
  descriptions use plain language instead of the internal
  "Content-oracle" / `SearchAdvanced` terms, pointing agents at
  `rimap://accounts/<name>` instead — this piece was originally slated
  for #406 but landed here. A new `dump-tool-catalog`-scanning test
  guards against regressions. Issue #405.
- The `rimap://accounts/<name>` resource now reports the account's
  `posture`, making the server instructions' claim true and giving an
  agent a self-service answer to a posture denial. The instructions now
  also name the four postures (`readonly` / `draft-safe` / `full` /
  `destructive`) and what each enables. `imap_host` stays in the
  resource but remains omitted from the leaner `list_accounts` summary
  (documented tiering). Issue #406.
- Tool-execution failures are now returned as a `CallToolResult` with
  `isError: true` instead of a JSON-RPC protocol error. Per the MCP
  spec, a tool that ran but failed should report the failure inside the
  result so the agent reliably sees the message and can self-correct.
  This covers `NotFound`, `UidValidityChanged`, `RateLimited`,
  `CircuitOpen`, `AttachmentTooLarge`, IMAP/SMTP/TLS/auth/connection/
  timeout failures, and posture / folder-policy denials. The stable
  `error_code` string and typed recovery `data` (`retry_after_ms`,
  expected/actual UIDVALIDITY, `kind`/`limit`) now ride
  `result.structuredContent` instead of `error.data`; the human-readable
  message is the result's text content. Genuine protocol errors (unknown
  tool, malformed params shape, account resolution, unsupported protocol
  version) are unchanged and still returned as JSON-RPC errors. This is
  an observable behavior change for existing clients that keyed on the
  JSON-RPC `error` envelope for tool failures. Issue #402.
- `rimap-config` now accepts configs with `accounts = []`. The server
  boots in infrastructure-only mode (only `list_accounts` /
  `use_account` are functionally useful). Unblocks the wire-conformance
  harness. Removes `ConfigError::NoAccounts`.
- `rimap_audit::reader::parse_line` now returns
  `AuditError::Parse(serde_json::Error)` instead of `AuditError::Read`
  with an empty path and a synthesized `io::Error`. The previous
  Display rendered with empty backticks (``failed to read audit file
  `` `` ``); the new variant renders as `failed to parse audit
  record: ...`. The `Read` variant remains in use for `stream_records`,
  which still has the real path and line number. `AuditError` is
  `#[non_exhaustive]` so adding the variant is source-compatible for
  downstream wildcard matches. Issue #255.
- Bumped workspace `rand` from `0.9` to `0.10`. `rand 0.10` renames
  the core trait `RngCore` → `Rng`; the only direct caller is
  `rimap-audit`'s `RedactionSalt::new_random` (`crates/rimap-audit/src/redact/mod.rs:18`).
  `governor 0.10`, `ulid 1.2`, and `proptest 1.11` still pin
  `rand = "0.9"` at their latest releases, so `deny.toml` carries a
  time-boxed `bans.skip` entry for `rand 0.9` / `rand_core 0.9` until
  those upstreams publish `rand 0.10`–compatible versions. Issue #256.
- **Breaking (keyring):** Credential keyring entries are now namespaced by
  account id (`<account-id>/<username>@<host>`) to prevent collisions in
  multi-account deployments (#77). Existing entries under the legacy
  `<username>@<host>` key continue to resolve via a transparent fallback
  that emits a `tracing::warn!` — run
  `rusty-imap-mcp migrate-keyring --account <id> --host <h> --username <u>`
  once per account to migrate.
- `rusty-imap-mcp login` gains a `--account <id>` argument (default
  `default`), so multi-account deployments can store credentials under
  the correct namespaced key. Single-account invocations remain
  unchanged.
- `ConfigError::NoCredential` and `ConfigError::Keychain` Display strings no
  longer include the username; they now show the host and a short
  `account_tag` hash for log correlation (#76).

### Fixed

- `list_folders` and `list_accounts` now advertise a proper
  `"type": "object"` `inputSchema` instead of a bare `{}`. Spec-strict
  MCP clients (e.g. `bobshell`'s Zod validator) reject any tool whose
  `inputSchema.type` is not the string `"object"` and surface
  `invalid_value` errors at tool-discovery time. `{}` is a valid JSON
  Schema (matches anything) but the wrong shape for MCP. New
  `every_tool_input_schema_declares_object_type` regression test
  guards every entry in `TOOL_DEFS`.
- `initialize` response now advertises the `tools` and `resources`
  capabilities. Previously `get_info()` returned
  `ServerCapabilities::default()` (all-`None` fields), so the wire
  payload was `"capabilities": {}` and spec-strict MCP clients (e.g.
  `bobshell`) refused to call `tools/list` with "No prompts or tools
  found on the server." Permissive clients (Claude Desktop, IBM Bob
  desktop) called `tools/list` anyway and were unaffected.

### Security

- Namespace MCP tool names per account (`<account>.<tool>`) in multi-account
  configs to prevent cross-account posture bypass. Single-account configs
  with the synthetic `"default"` account keep bare tool names.
- Emit `tool_start` and `tool_end` audit records for every dispatch with
  account attribution, redacted arguments, and duration metadata.
- Populate `account` field on `Auth` audit records for multi-account
  attribution of login events.
- Wrap resolved credentials in `secrecy::SecretString` to limit in-memory
  exposure of IMAP and SMTP passwords.
- Redact IMAP/SMTP usernames from `anyhow` error contexts so they no longer
  leak into tracing output.
- Reject IMAP/SMTP usernames containing CR, LF, or NUL bytes at config load.
- Rate-limit infrastructure tools (`use_account`, `list_accounts`) to
  prevent session-state flip-flap attacks.
- Validate account names via `AccountId::new` before echoing them in
  MCP error messages to prevent reflected-content amplification.
- Drop `posture` from `read_resource` body and `imap_host` from
  `list_accounts` response to reduce attack-surface fingerprinting.
- Require labels to be ASCII (RFC 3501 atom syntax) and reject `[`
  consistently at both validator layers to prevent homograph/bidi spoofing.
- Digest-pin the Rust Docker base image used for aarch64/ppc64le/s390x
  release builds to resist tag-repointing supply-chain attacks.
- Embed SBOMs in native release binaries via `cargo-auditable`.
- Add SLSA build provenance attestation to release artifacts and
  `SHA256SUMS.txt` via `actions/attest-build-provenance`.
- Extract per-tag release notes from `CHANGELOG.md` rather than attaching
  the entire changelog to every release.
- Document GitHub tag protection and release environment setup.
- Create per-process attachment tempdir with `0700` permissions on Unix
  to close a symlink/TOCTOU race on shared `/tmp`.
- Replace `Mutex<Option<AccountId>>` in the account registry with
  `ArcSwapOption` to eliminate async-refactor footguns and mutex poisoning.

[0.1.0]: https://github.com/randomparity/rusty-imap-mcp/releases/tag/v0.1.0
