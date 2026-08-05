# Audit Log

rusty-imap-mcp maintains an append-only JSONL audit log at the path
configured in `[audit].path`. Every tool invocation, authentication
attempt, and process lifecycle event is recorded.

## Format

One JSON object per line (JSONL). Every record shares a common header:

```json
{
  "seq": 42,
  "ts": "2026-04-07T14:22:01.234Z",
  "process_id": "01JX...",
  "kind": "tool_start"
}
```

| Field | Description |
|---|---|
| `seq` | Per-process monotonic sequence number, starting at 1 |
| `ts` | RFC 3339 timestamp, millisecond precision, UTC |
| `process_id` | ULID generated at process start, stable for the process lifetime |
| `kind` | Record type discriminator |

## Compatibility contract

This is the normative statement of what a reader of an audit file may assume,
and of what "additive" means for a record. It exists because the record types
are `#[non_exhaustive]` (#706): adding a field to one is no longer a breaking
change *to the Rust API*, and that must not be mistaken for a licence to change
the file.

**What a reader may assume.**

- Every line is one complete JSON object, and `seq`, `ts`, `process_id`, and
  `kind` are present on all of them.
- A field it does not recognize is a field added after it was written. Ignore
  it; do not treat the line as corrupt.
- A `kind` it does not recognize is a record type added after it was written.
  It should skip the line rather than treat the file as corrupt.

  **The bundled reader does not yet do this.** `stream_records` — and so
  `rimap audit merge` — aborts with a read error on any non-trailing line it
  cannot parse, and an unrecognized `kind` is a parse failure, because the
  record enum has no catch-all variant. So a `v0.2` binary reading a file that
  a later version wrote stops at the first unknown record instead of skipping
  it. Only a malformed *trailing* line is tolerated, which covers a torn write
  at the tail, not forward compatibility. Tracked in #717. Until it lands,
  treat "skip unknown kinds" as the contract third-party readers should
  implement and as a known gap in this one, and do not merge files written by
  a newer version than the binary doing the merging.
- A field it expects and does not find was added after *that line* was written.
  Every such field has a documented read-as value in the tables below --
  `records_lost` reads as `0`, `undrained_dispatches` as `0`, `tool_matrix` as
  empty -- so the line parses into the same struct a current writer produces.

  **That is a parse rule, not a measurement.** For the two counters it means
  *not measured*, not *measured as zero*: a binary predating `records_lost`
  could lose records, and one predating `undrained_dispatches` could leave
  dispatches running past `process_end`, and either wrote the fact to stderr
  and no field. An alerting rule keyed on `> 0` must therefore treat a line
  that omits the field as **unknown**, not as clean -- which is the ordinary
  state of a log spanning an upgrade, and of any merged or rotated set that
  reaches back across one.
- Fields it does find keep their spelling, their type, and their position on
  the line. Records already on disk are never rewritten in place.

**What counts as an additive change.** A field addition is additive only if
*both* halves hold, and a change that satisfies one without the other is a
format break wearing an additive label:

1. **The Rust half.** The struct is `#[non_exhaustive]`, so no downstream crate
   named the full field set in a struct expression and none has to be
   recompiled against a wider one. This is what #706 bought.
2. **The on-disk half.** The new field carries `#[serde(default)]`, so lines
   written before it parse unchanged; and it carries
   `#[serde(skip_serializing_if = ...)]` unless it is genuinely present on
   every record from now on, so lines that do not populate it keep the bytes
   they had. A reader of the old shape must stay correct without being taught
   about the field.

Anything else -- renaming a field, changing its type or its serialized
spelling, reordering fields, removing a field, or repurposing an existing
`kind` -- is a **format break**. It requires a new `kind` or an explicitly
versioned file, not a field edit, because the files it invalidates are already
written and are append-only by design.

`crates/rimap-audit/tests/non_exhaustive_record.rs` holds this contract as
byte-exact golden lines. A diff there means the format moved.

**One known asymmetry.** A record whose `ts` lands exactly on a second boundary
is rewritten as `12:00:00Z` rather than `12:00:00.000Z` when it passes through
[`audit merge`](#audit-merge-subcommand): the RFC 3339 formatter elides a zero
subsecond. Both forms parse to the same instant, and the value is stable under
further rewrites. No other field is altered by a merge.

## Record types

### `process_start`

First record of every process invocation.

| Field | Description |
|---|---|
| `version` | Semver of the running binary |
| `git_commit` | Build-time git SHA (empty until wired) |
| `posture` | Effective base posture at startup (single-account mode only) |
| `accounts` | Per-account name/posture/IMAP host (multi-account mode only) |
| `tool_matrix` | Per-account posture and explicit per-tool verdicts with provenance (absent on records written before this field existed; read as an empty list) |
| `config_path` | Absolute path of the loaded config file |
| `config_hash_sha256` | SHA-256 hex of the config file contents at load time |
| `previous_last_seq` | Last `seq` found in the file at startup (null if empty) |
| `previous_process_id` | Process ID of the previous run (null if empty) |
| `previous_file_inode` | Inode of the audit file as observed at open time |
| `audit_file_inode_changed` | True if the inode differs from the prior `process_start`'s inode (tamper signal) |

#### `tool_matrix`

One entry per account, in both single- and multi-account mode -- unlike
`posture` / `accounts`, which are mutually exclusive, so nothing reading
`tool_matrix` has to branch on account count.

```json
"tool_matrix": [
  {
    "account": "work",
    "posture": "readonly",
    "tools": [
      {"tool": "delete_message", "allow": true,  "source": "inherited"},
      {"tool": "search",         "allow": false, "source": "account"}
    ]
  }
]
```

| Field | Description |
|---|---|
| `account` | Account name from config (`default` for a flat config) |
| `posture` | Effective base posture for this account |
| `tools[].tool` | The tool the verdict names |
| `tools[].allow` | `true` for an explicit `allow`, `false` for an explicit `deny` |
| `tools[].source` | `account` if the account's own `[accounts.security.tools]` wrote it, `inherited` if it came from `[defaults.security.tools]` |

`tools` lists **explicit verdicts only**. A tool with no override follows
`posture` through the posture table, which the record's `version` and
`git_commit` already identify.

**`"allow": true` with `"source": "inherited"` is the line to look for.** An
account tightened to `posture = "readonly"` still holds every `allow` it
inherited from `[defaults.security.tools]` -- that is the documented merge
semantics (ADR-0014), and this is where it becomes visible. The same rows are
printed by `rusty-imap-mcp --dry-run` and logged at `info` level at boot under
the message `effective tool matrix`.

### `process_end`

Best-effort record on SIGINT, SIGTERM, or stdin EOF. A hard crash
leaves no `process_end` -- the last record will be whatever was most
recently flushed.

| Field | Description |
|---|---|
| `reason` | One of `signal_int`, `signal_term`, `eof`, `error` |
| `total_tool_calls` | Number of tool calls dispatched in this process |
| `records_lost` | Number of records this process failed to persist and told no caller about (absent on records written before this field existed; read as `0`) |
| `undrained_dispatches` | Tool dispatches -- or audit writes one of them offloaded -- still registered when the shutdown drain's budget expired (absent on records written before this field existed, where it means *not measured* rather than zero) |

**A non-zero `records_lost` means this file has a hole in it.** Some event
happened and left no record — most often a disk that filled mid-run. The count
merges its two sources on purpose, because no operator decision turns on which
one it was:

- a write, flush, or fsync failure that `fail_open = true` swallowed and
  continued past;
- a record whose caller had nowhere to return the failure to — `rimap-imap`'s
  cut-connect `Drop` guard and its auth-failure branch, which keeps the
  connect's own error. These reach the counter only under the default
  `fail_open = false`, where the write error went back to a caller who could
  not surface it.

Either way the cause is on stderr at `error` level; the count is what survives
in the file. Treat a run reporting a non-zero count as one whose record stream
is incomplete, and alert on it.

The reverse does not hold: a run that lost records to a hard crash writes no
`process_end` at all. A non-zero count is evidence of loss; a missing record is
not evidence of none.

**`process_end` is terminal for its `process_id`, subject to the one exception
below.** When a `process_end` record is present, no other record carrying the
same `process_id` follows it anywhere in the file. A reader may treat it as
closing that process, and may attribute every subsequent record to a later run.

The rule is enforced, not incidental. Before writing `process_end` the server
cancels every in-flight tool dispatch and waits, bounded, for each to unwind --
so a connect the shutdown cuts writes its `auth` record (`ERR_CANCELLED`, see
below) *before* the `process_end`, rather than racing it. The wait covers the
`tool_start` / `tool_end` writes a dispatch hands to the blocking pool as well
as the dispatch itself: those writes are not cancellable, so each takes its own
registration and the drain waits for the write, not for the dispatch that
submitted it (`auth` writes are synchronous, ADR-0014, and need nothing extra).
The two states this rules out are a trailing record that a naive reader would
attribute to the *next* process in the same file, and a half-written final line
that makes the JSONL tail unparseable.

Read the exception before building on the rule.

- **A dispatch that outlived the drain budget.** If a dispatch cannot be
  unwound in time -- it is inside an uncancelable blocking call, say -- the
  server logs `tool dispatches outlived the shutdown drain` with the count and
  proceeds. Anything those dispatches write afterwards keeps the old behaviour:
  sequenced after `process_end`, or lost to process exit. This one is
  **announced in the file**, as `process_end.undrained_dispatches`: a non-zero
  count is the record saying that terminality was not met for its own run, so a
  reader holding nothing but the audit log can tell. Treat such a run as
  suspect and alert on it. An audit write still queued on the blocking pool
  when the budget expires holds a registration of its own, so it is counted
  there too rather than silently absorbed. The same count is still logged to
  stderr, which is now the redundant copy rather than the only one.

  Two things the field does not cover, so a zero is narrower than "this run was
  clean":

  - A run that never reaches `process_end` at all -- a hard crash, a `SIGKILL`
    -- reports nothing, neither a count nor a zero. A non-zero count is
    evidence that terminality was broken; a missing `process_end` is not
    evidence that it held.
  - **The cancellation drainer's own join budget is a second, still
    stderr-only hole.** The residue is measured before that join, and a cut
    dispatch releases its registration as soon as it hands its `tool_end` to
    the drainer's queue -- so the drain honestly reports zero while records sit
    unwritten. If the join then expires, the server aborts the drainer: those
    queued records are lost, and a write already handed to the blocking pool
    lands after `process_end`. `records_lost` does not see it either, because
    nothing was ever written to fail. The warning
    `cancellation drainer did not finish within the join budget` on stderr is
    the only signal. Tracked in #725.

Separately, and not an exception to *ordering*: a record may be missing
entirely. Loss on shutdown is expected and documented (best-effort). Terminality
says nothing about completeness -- only that what *is* present is correctly
ordered.

### `auth`

IMAP authentication attempt. One record per attempt, on every termination path,
including attempts cut off before they concluded — subject to `audit.fail_open`
(see below). "Attempt" starts just before the TCP connect, so a cut in that
narrow window records an attempt that never reached the server; the log errs
towards recording one too many rather than one too few.

| Field | Description |
|---|---|
| `result` | `success` or `failure` |
| `host` | IMAP host attempted |
| `port` | IMAP port attempted |
| `username` | Login identity (never contains credentials) |
| `tls_fingerprint_sha256` | Observed TLS certificate fingerprint (null if handshake did not complete) |
| `fingerprint_match` | Whether observed fingerprint matched config (null if no pin configured) |
| `error_code` | Stable error code on failure (e.g. `ERR_TLS`, `ERR_AUTH`, `ERR_CANCELLED`); null on success |
| `credential_source` | Which store the credential came from; null if the attempt ended before resolution |

**`ERR_CANCELLED` is not an authentication failure.** It means the connect was
cut before it reached a verdict of its own — read it as *cut*, not specifically
*cancelled*. Any of: the per-tool-call ceiling fired
(`limits.tool_call_timeout_seconds`), the client cancelled the call, the
process shut down mid-connect, or a panic unwound through it. The attempt is recorded so the log does not
silently omit a connection that was opened, but a monitor counting failed
logins, or alerting on credential-stuffing, must **exclude** these. The reason
for the cut is on the paired `tool_end` record. See ADR-0012.

### `tool_start`

Recorded before dispatch begins. If the process crashes mid-call, this
record survives as a breadcrumb.

| Field | Description |
|---|---|
| `tool` | Tool name (e.g. `fetch_message`) |
| `posture_effective` | Effective posture at dispatch time |
| `arguments_redacted` | Redacted arguments (untrusted content replaced with `"<redacted:length>"`, recipient addresses hashed, passwords never logged) |
| `arguments_hash_sha256` | SHA-256 hex of the unredacted arguments for integrity |

### `tool_end`

Recorded after dispatch completes.

| Field | Description |
|---|---|
| `start_seq` | `seq` of the paired `tool_start` record |
| `tool` | Tool name (duplicated for self-contained log lines) |
| `status` | `ok` or `error` |
| `error_code` | Stable error code on failure; null on success |
| `duration_ms` | Wall-clock duration in milliseconds |
| `result_summary.message_ids_returned` | Message-ID values returned to the caller |
| `result_summary.bytes_returned` | Approximate bytes returned (post-truncation) |
| `result_summary.truncated` | Whether the result was truncated |
| `result_summary.security_warnings_emitted` | Warning codes emitted (e.g. `LOOKALIKE_SENDER_MIXED_SCRIPT`) |
| `provenance.window_seconds` | Configured provenance window |
| `provenance.message_ids_recently_read` | Message IDs read by this process within the window |

The audit record shape is independent of how the failure is delivered to
the MCP client. Since #402 a tool-execution failure is returned as a
`CallToolResult` with `isError: true` rather than a JSON-RPC error, but
the `tool_end` record still carries `status = "error"` and the same
`error_code`.

### `config`

Config-related event. Declared for future use.

| Field | Description |
|---|---|
| `path` | Config file path |
| `hash_sha256` | SHA-256 hex of the config file contents |

## File handling

- **Permissions:** audit file is created with mode `0600`. Parent
  directory is created with mode `0700` if missing.
- **Exclusive lock:** the process acquires a non-blocking exclusive
  advisory lock (`flock(LOCK_EX | LOCK_NB)`) on the audit file at
  startup. A second process against the same path fails immediately
  with `ERR_CONFIG`. The lock is held for the full process lifetime
  and released on exit.
- **Write discipline:** each record is one `write_all` + buffer flush.
  `fsync` is called after `process_start`, `process_end`, `auth`, and
  `config` records. `tool_start` and `tool_end` are flushed but not
  fsync'd (a crash may lose a few trailing entries).
- **Write failure:** fails the tool call with `ERR_INTERNAL` by
  default. Set `audit.fail_open = true` to suppress write failures
  and continue (not recommended -- audit records will be lost).

  Two `auth` paths are exceptions, because they have no caller to fail:
  the record for a connect that was cut (written from a drop guard), and
  the one for a connect that failed on its own terms (where replacing the
  connect's error with an audit error would hide the reason the connect
  failed). Both log the failure and continue. Neither goes unaccounted --
  they increment the same lost-record counter as a `fail_open`
  suppression.
- **`audit.path` must be on local storage.** This is not limited to the
  two exceptional paths above. *Every* connect writes its `auth` record
  synchronously on a runtime worker thread, with the account's session
  lock held, and nothing bounds that write -- no timeout covers it
  (ADR-0014). Pointed at a network mount that stops responding (NFS,
  SMB), the write never returns: the worker stays pinned for the life of
  the process, the session lock is never released, and any peer queued on
  that account waits forever rather than spending its
  `imap.command_timeout_seconds`.

  How many workers one stall can pin is bounded by `min(accounts,
  worker_threads)` -- and the second term can be 1. The runtime sizes its
  worker pool from `available_parallelism()`, so under a one-vCPU quota
  (a container CPU limit, a small VM) a *single* account's connect pins
  the only worker. With every worker pinned the timer stops advancing, so
  no deadline fires anywhere in the process -- including the per-tool-call
  ceiling -- and the server stops answering its MCP client at all.

  Nothing checks the path's locality at startup; it is an operator
  requirement. Local disk has no such failure mode.

## Running multiple MCP clients

`rusty-imap-mcp` holds an exclusive lock on its configured `[audit].path`
for the lifetime of the process. A second process against the same path
fails immediately with `ERR_CONFIG`. The lock guards append atomicity,
the per-process `seq` allocator, the inode tamper chain, and the
in-memory provenance ring — all forensic invariants that depend on a
single writer.

To run multiple MCP clients on the same machine — for example, two
Claude Code windows on different projects, or Claude Code alongside
Codex — give each MCP client its own `rusty-imap-mcp` config file with
a distinct `[audit].path`.

### Supported scenarios

#### Single MCP client

The default. Nothing to configure beyond the standard setup. One
`[audit].path`, one `rusty-imap-mcp` PID, one audit file.

#### Cross-application: Claude Code + Codex

Each host application has its own MCP config; point each at a
different `rusty-imap-mcp` config file with its own audit path.

`~/.claude.json` (Claude Code, user-scope):

```json
{
  "mcpServers": {
    "rusty-imap": {
      "command": "/usr/local/bin/rusty-imap-mcp",
      "args": ["--config", "/home/dave/.config/rusty-imap-mcp/claude.toml"]
    }
  }
}
```

`~/.codex/config.toml` (Codex):

```toml
[mcp_servers.rusty-imap]
command = "/usr/local/bin/rusty-imap-mcp"
args = ["--config", "/home/dave/.config/rusty-imap-mcp/codex.toml"]
```

`~/.config/rusty-imap-mcp/claude.toml` (Linux example — the TOML
parser does not expand `~`, so `audit.path` must be absolute):

```toml
[audit]
path = "/home/dave/.local/share/rusty-imap-mcp/audit-claude.jsonl"
# ... rest of config identical between the two
```

`~/.config/rusty-imap-mcp/codex.toml`:

```toml
[audit]
path = "/home/dave/.local/share/rusty-imap-mcp/audit-codex.jsonl"
# ...
```

Both parent directories must already exist before startup — create
them with `mkdir -p /home/dave/.local/share/rusty-imap-mcp` (Linux)
or the equivalent under `~/Library/Application Support/rusty-imap-mcp/`
on macOS. The audit path must also live under the platform-default
`allowed_base_dir` (or set `audit.allowed_base_dir` explicitly).

#### Cross-project: per-project `.mcp.json`

For users whose MCP usage is tied to a specific repository, register
`rusty-imap-mcp` at project scope rather than user scope. Each project
gets its own `.mcp.json` and its own audit path.

```bash
cd /home/dave/src/work-project
claude mcp add --scope project rusty-imap /usr/local/bin/rusty-imap-mcp \
  -- --config /home/dave/.config/rusty-imap-mcp/work.toml
```

This writes `/home/dave/src/work-project/.mcp.json`:

```json
{
  "mcpServers": {
    "rusty-imap": {
      "command": "/usr/local/bin/rusty-imap-mcp",
      "args": ["--config", "/home/dave/.config/rusty-imap-mcp/work.toml"]
    }
  }
}
```

A second project gets the same treatment with its own paths. Each
Claude Code window opened in a project loads that project's
`.mcp.json` and spawns its own `rusty-imap-mcp` child against that
project's audit file.

### Unsupported: same MCP-client config across multiple windows

If you have one `rusty-imap-mcp` entry in `~/.claude.json` (user
scope) and open two Claude Code windows, both windows spawn their own
child against the same audit path. The second child fails to acquire
the lock and exits with `ERR_CONFIG`.

Two options:

1. Move the entry to project scope (`.mcp.json`) so each project gets
   its own audit path, as in the cross-project example above.
2. Accept that one window will lose its `rusty-imap-mcp` MCP server.
   The other features of that Claude Code window are unaffected; only
   the rusty-imap-mcp tools are unavailable in the losing window
   until the holding window exits.

A future database-backed audit store will remove this constraint by
sharing the audit log across processes; until then, distinct
`[audit].path` values per concurrent MCP client are the supported
pattern.

### Per-account rate limits and circuit breakers

Each `rusty-imap-mcp` process maintains its own per-account
`Governor` (rate limiter) and `CircuitBreaker`. With multiple
concurrent MCP clients on the same IMAP account, each client's
budget is independent. Operators who need a single per-account
ceiling enforced across all local clients should track the future
database-backed audit store, which will share this state by
construction.

## Rotation

When the active file exceeds `audit.rotate_bytes` (default 10 MiB),
rotation occurs under the exclusive lock:

1. The active file is renamed (e.g. `audit.jsonl.1`)
2. A new active file is created and locked
3. Excess rotated files beyond `audit.rotate_keep` (default 5) are
   deleted

`rotate_keep` is a count-based cap. Under low write volumes a single
rotated file may span a long time period. Operators needing time-based
retention should configure external log rotation as well.

Set `rotate_bytes = 0` to disable rotation entirely.

## `audit merge` subcommand

```
rusty-imap-mcp audit merge [options] <path>
```

Reads the audit file with a shared lock and streams JSONL to stdout.
Output is canonical JSON (re-serialized via `serde_json`) and can be
piped to `jq`.

### Filters

| Flag | Description |
|---|---|
| `--since <RFC3339>` | Only records at or after this timestamp |
| `--until <RFC3339>` | Only records at or before this timestamp |
| `--tool <name>` | Only `tool_start`/`tool_end` records for this tool |
| `--kind <kind>` | Only records of this kind (e.g. `auth`, `tool_end`) |
| `--process <ulid>` | Only records from this process ID |

Trailing malformed lines (from a mid-record crash) produce a stderr
warning and are skipped.

### Example

```bash
rusty-imap-mcp audit merge \
  --since 2026-04-07T00:00:00Z \
  --tool fetch_message \
  ~/.local/share/rusty-imap-mcp/audit.jsonl \
  | jq '.result_summary'
```

(The CLI path here is a shell argument, so `~` is expanded by the
shell — only `audit.path` inside the TOML config file is taken
literally.)

### File permissions for merged output

`audit merge` writes to stdout. When redirected to a file, the output
inherits the shell's umask, which is typically `0022` (producing
world-readable `0644`). The source audit file is `0600`, so the merged
output may have weaker permissions than expected.

Recommended patterns:

```bash
# Set a tight umask in the same shell invocation (the && is required)
umask 077 && rusty-imap-mcp audit merge ... > dump.jsonl

# Preferred in scripts: atomic mode-set via install, no umask dependency
rusty-imap-mcp audit merge ... \
  | install -m 0600 /dev/stdin /target/dump.jsonl
```

## Startup self-check

Before writing the first `process_start` record, the server:

1. Verifies the audit file is writable (creates it if missing)
2. Reads the last line of the existing file and extracts `seq` and
   `process_id`, recording them as `previous_last_seq` and
   `previous_process_id` in the new `process_start` (chains history
   across restarts)
3. Records the file's current inode. If the file was deleted and
   recreated between runs, the inode differs and
   `audit_file_inode_changed` is set to `true` as a tamper signal

## What is not logged

- Full message bodies or HTML
- Passwords, tokens, keychain internals
- Config file contents (only path + hash)
- IMAP wire-level traffic (use `tracing` stderr logs for debugging)
