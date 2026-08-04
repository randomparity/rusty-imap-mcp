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

## Record types

### `process_start`

First record of every process invocation.

| Field | Description |
|---|---|
| `version` | Semver of the running binary |
| `git_commit` | Build-time git SHA (empty until wired) |
| `posture` | Effective base posture at startup |
| `config_path` | Absolute path of the loaded config file |
| `config_hash_sha256` | SHA-256 hex of the config file contents at load time |
| `previous_last_seq` | Last `seq` found in the file at startup (null if empty) |
| `previous_process_id` | Process ID of the previous run (null if empty) |
| `previous_file_inode` | Inode of the audit file as observed at open time |
| `audit_file_inode_changed` | True if the inode differs from the prior `process_start`'s inode (tamper signal) |

### `process_end`

Best-effort record on SIGINT, SIGTERM, or stdin EOF. A hard crash
leaves no `process_end` -- the last record will be whatever was most
recently flushed.

| Field | Description |
|---|---|
| `reason` | One of `signal_int`, `signal_term`, `eof`, `error` |
| `total_tool_calls` | Number of tool calls dispatched in this process |

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
- **`audit.path` must be on local storage.** The drop-guard write above
  runs on a runtime worker thread with the account's connection lock
  held, and nothing bounds it. Pointed at a network mount that stops
  responding (NFS, SMB), that write never returns: the account wedges,
  and enough concurrent occurrences stall the server as a whole. Local
  disk has no such failure mode.

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
