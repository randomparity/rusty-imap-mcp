# Configuration

rusty-imap-mcp uses a single TOML config file. Two formats are supported:

- **Single-account (legacy):** flat `[imap]` / `[security]` / `[limits]`
  sections. Works unchanged from pre-1.0.
- **Multi-account:** `[[accounts]]` array with optional `[defaults]`.
  Each account has its own IMAP, SMTP, security, and limits settings.

Mixing both formats in one file is a startup error.

## Config file location

Resolution order:

1. `--config <path>` CLI argument
2. `RUSTY_IMAP_MCP_CONFIG` environment variable
3. Platform default:
   - Linux: `$XDG_CONFIG_HOME/rusty-imap-mcp/config.toml`
     (falls back to `~/.config/rusty-imap-mcp/config.toml`)
   - macOS: `~/Library/Application Support/rusty-imap-mcp/config.toml`

## Single-account example (legacy)

```toml
[imap]
host = "127.0.0.1"
port = 1143
username = "alice@proton.me"
tls_fingerprint_sha256 = "ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89"

[smtp]
host = "127.0.0.1"
port = 1025
encryption = "starttls"
username = "alice@proton.me"

[security]
posture = "draft-safe"

[limits]
commands_per_second = 10

[audit]
path = "/home/alice/.local/share/rusty-imap-mcp/audit.jsonl"

[attachments]
download_dir = ""
```

## Multi-account example

```toml
[defaults.security]
posture = "draft-safe"
protected_folders = ["INBOX", "Sent", "Drafts", "Trash"]

[defaults.limits]
commands_per_second = 10

[[accounts]]
name = "work"

[accounts.imap]
host = "127.0.0.1"
port = 1143
username = "user@proton.me"
tls_fingerprint_sha256 = "ab:cd:..."

[accounts.smtp]
host = "127.0.0.1"
port = 1025
encryption = "starttls"
username = "user@proton.me"

[[accounts]]
name = "personal"

[accounts.imap]
host = "imap.fastmail.com"
port = 993
username = "me@fastmail.com"

[accounts.security]
posture = "readonly"

[audit]
path = "/home/user/.local/share/rusty-imap-mcp/audit.jsonl"
```

See [multi-account.md](multi-account.md) for account discovery and
selection details.

## `[imap]` section

IMAP connection settings. Required per account (or at the top level in
single-account format).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `host` | string | (required) | IMAP server hostname or IP |
| `port` | u16 | (required) | IMAP server port (993 for implicit TLS, 143 or 1143 for STARTTLS) |
| `encryption` | string | `"tls"` | `"tls"` (implicit TLS/IMAPS) or `"starttls"` (STARTTLS upgrade). See below. |
| `username` | string | (required) | IMAP login identity |
| `tls_fingerprint_sha256` | string | (none) | Pinned TLS certificate SHA-256 fingerprint. Hex, colons optional. Required for self-signed certs (e.g. Proton Bridge). Omit to use the system trust store. Run `--dry-run` to print the observed fingerprint for copy-paste pinning. |
| `command_timeout_seconds` | u32 | 30 | Per-command timeout for IMAP operations |
| `connect_timeout_seconds` | u32 | 10 | TCP + TLS handshake + greeting + CAPABILITY probe deadline |

The two budgets are independent, and either ordering is valid. They bound
one *stage* each, not a tool call. One IMAP operation spends, worst case:

1. up to `command_timeout_seconds` waiting for the account's connection
   (another call holds it), then
2. up to `connect_timeout_seconds` on the connect, if the session needs
   opening — this runs outside the command deadline by design, so that a
   stalled connect still writes its `auth` audit record, then
3. up to `command_timeout_seconds` on the command itself, and
4. **all of the above a second time** when a read-only operation fails
   with `ERR_CONNECTION_LOST` and is transparently reconnected and
   retried once.

That is `2 x (2 x command_timeout_seconds + connect_timeout_seconds)` —
**140 seconds at the defaults** — for a single operation, and a tool that
issues several operations multiplies it again. Those are the stages with
deadlines; a few awaits on the same path have none of their own (the
session-lock release after a failed command, and the `auth` audit write
inside a connect), so the wall clock can exceed even that. No `[imap]`
field predicts the number, which is why the whole call is bounded
separately by [`limits.tool_call_timeout_seconds`](#limits-section). Setting
`command_timeout_seconds` below `connect_timeout_seconds` is supported —
it means "fail commands fast, tolerate a slow handshake" and does not
shorten the connect.

Raising `command_timeout_seconds` much past 70s at the default
`connect_timeout_seconds` pushes that worst case above the default
ceiling, and startup then fails until `tool_call_timeout_seconds` is
raised to match. The error states the computed minimum.

Each account holds a single IMAP connection, and concurrent tool calls
against that account serialize on it: a slow command (a large `FETCH`
or a `SEARCH` over a big mailbox) can head-of-line-block other queued
calls on the same account for up to `command_timeout_seconds` before
that command is cut off. Calls to different accounts are unaffected —
each account has its own connection. See
[architecture/audit-locking.md](architecture/audit-locking.md#operator-impact-concurrent-calls-to-one-account-serialize)
for the mechanism.

### `imap.encryption`

Transport encryption mode. Two values:

- `"tls"` (default) — implicit TLS (IMAPS). Typical port 993. Used by Gmail,
  most commercial providers, and Dovecot's default config.
- `"starttls"` — plaintext connection upgraded via STARTTLS before LOGIN.
  Typical port 143 (Dovecot default) or 1143 (Proton Bridge default).

The field defaults to `"tls"` if omitted, preserving single-account configs
written before STARTTLS support.

Selecting `"starttls"` requires the server to advertise `STARTTLS` in its
CAPABILITY response; there is no silent downgrade to plaintext. A STARTTLS
failure surfaces as `ERR_TLS`.

See also: `smtp.encryption` (symmetric field for the SMTP transport).

## `[smtp]` section

SMTP connection settings. Optional -- required only when `send_email` is
effectively enabled: either by the active posture (`full` or `destructive`)
or by an explicit `[security.tools] send_email = "allow"` override on a
posture that does not enable it (`readonly` or `draft-safe`).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `host` | string | (required) | SMTP server hostname or IP |
| `port` | u16 | (required) | SMTP server port (587 for STARTTLS, 465 for implicit TLS) |
| `encryption` | string | (required) | `"starttls"`, `"tls"`, or `"none"` |
| `username` | string | (required) | SMTP login identity |
| `command_timeout_seconds` | u32 | 30 | Per-command timeout for SMTP operations |

## `[security]` section

Controls which tools are available.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `posture` | string | `"draft-safe"` | Base posture: `"readonly"`, `"draft-safe"`, `"full"`, or `"destructive"`. See [security-model.md](security-model.md). |
| `tools` | table | (empty) | Per-tool overrides. Keys are tool names, values are `"allow"` or `"deny"`. |
| `protected_folders` | list | `["INBOX", "Sent", "Drafts", "Trash"]` | Folders that cannot be renamed or deleted |
| `expunge_folders` | list | `[]` | Folders where `expunge` and `delete_folder` are permitted (default empty = deny all) |

### Special-use folder discovery

At account boot, the server runs `LIST "" "*"` once and records any
RFC 6154 special-use markers (`\Drafts`, `\Sent`, `\Trash`, `\Junk`,
`\Archive`, `\All`, `\Flagged`) reported by the server. These names
are then:

1. Used as the target folder for `create_draft` (`\Drafts`),
   `send_email`'s Sent copy (`\Sent`), and `delete_message`'s move
   destination (`\Trash`), falling back to the literal strings
   `"Drafts"`, `"Sent"`, and `"Trash"` if the server does not advertise
   special-use attributes.
2. Merged (case-insensitively) into the `protected_folders` list, so
   Gmail's `[Gmail]/Sent Mail` is protected by the default config even
   though the literal list contains `"Sent"`. The merge only adds
   names; user-configured entries are preserved.

No config is required to opt in. The expansion is additive — there is
no way to disable it short of setting `protected_folders` to a list
that already covers the server-native names.

### `[security.lookalike]` subsection

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | true | Enable look-alike detection on addresses, domains, links, and filenames |
| `known_domains` | list | `[]` | User-curated watchlist of protected domains (e.g. `["paypal.com"]`) |
| `warn_on_any_non_ascii_domain` | bool | false | Warn on any non-ASCII domain, even if not in the watchlist |

### Per-tool overrides

Override the posture's default for individual tools:

```toml
[security]
posture = "draft-safe"

[security.tools]
mark_read = "deny"                # deny even though draft-safe allows it
"search.advanced_query" = "allow" # allow even though draft-safe denies it
```

#### Valid tool names

All 25 valid tool names for `[security.tools]`:

| Tool name | Description | Default posture |
|-----------|-------------|-----------------|
| `list_folders` | List IMAP folders | readonly+ |
| `search` | Structured search (subject, from, to, dates, flags) | readonly+ |
| `search.advanced_query` | Advanced search (body, text, bcc, headers) | full+ |
| `fetch_message` | Fetch message (text parts only) | readonly+ |
| `fetch_message.include_html` | Fetch message with HTML parts | full+ |
| `list_attachments` | List message attachments | readonly+ |
| `download_attachment` | Download attachment to sandbox | readonly+ |
| `export_messages` | Export raw messages to a `git am`-able mbox | disabled by default² |
| `mark_read` | Mark message as read | draft-safe+ |
| `mark_unread` | Mark message as unread | draft-safe+ |
| `flag` | Add star/flag | draft-safe+ |
| `unflag` | Remove star/flag | draft-safe+ |
| `add_label` | Add label/tag | draft-safe+ |
| `remove_label` | Remove label/tag | draft-safe+ |
| `list_labels` | List available labels | readonly+ |
| `move_message` | Move message to folder | draft-safe+ |
| `create_draft` | Create draft with $PendingReview | draft-safe+ |
| `send_email` | Send email via SMTP | full+ |
| `delete_message` | Mark message as deleted | full+ |
| `create_folder` | Create new folder | full+ |
| `rename_folder` | Rename existing folder | full+ |
| `expunge` | Permanently delete marked messages | destructive |
| `delete_folder` | Permanently delete folder | destructive |
| `use_account` | Switch active account (multi-account only) | always available (not gateable¹) |
| `list_accounts` | List configured accounts (multi-account only) | always available (not gateable¹) |

**Note:** "readonly+" means allowed in readonly and all higher postures.
"draft-safe+" means allowed in draft-safe and all higher postures.

¹ `use_account` and `list_accounts` are infrastructure tools, not
posture-gated capabilities. They are always advertised and dispatchable,
and `[security.tools]` cannot disable them. An `"allow"` or `"deny"`
override targeting either name is accepted by config validation but has
**no effect** at runtime — they remain available regardless.

² `export_messages` is **denied in every posture** and is only available
when explicitly enabled via `[security.tools]` with
`export_messages = "allow"`. See
[The `export_messages` tool](#the-export_messages-tool) below.

Sub-capabilities (`.advanced_query`, `.include_html`) are separate
authorization gates within their parent tool. The parent tool name
(`search`, `fetch_message`) controls the base capability; the
sub-capability controls the escape hatch.

`fetch_message`'s `include_headers` parameter is **not** a gated
sub-capability. It takes an allowlist of header names (≤ 16 per call,
e.g. `["List-Unsubscribe", "List-Id"]`) and returns their sanitized
values under `untrusted.headers`. It is available at every posture
`fetch_message` is, because reading named header values off a single
already-fetched message is a weaker capability than the header *filtering*
that `search.advanced_query` already gates at `full`. See
`docs/superpowers/specs/2026-07-03-issue-409-include-headers-design.md`
for the threat-model rationale.

#### Override semantics

- `"allow"` grants the tool regardless of posture
- `"deny"` blocks the tool regardless of posture
- An override matching the posture's default is a no-op (not an error)
- Unknown tool names are rejected at config validation with `ERR_CONFIG`
- Infrastructure tools (`use_account`, `list_accounts`) are not gated by
  `[security.tools]`; overrides targeting them are accepted but have no
  effect (see the note above)

If you see `unknown tool name 'mark_as_read'`, check the spelling
against the table above. The correct name is `mark_read`.

### The `export_messages` tool

`export_messages` exports one or more raw messages from a folder into a
single mbox file in the download sandbox. The mbox uses `mboxrd` framing
and is consumable directly by `git am`, which makes it the bridge for
turning emailed patches into local commits.

#### Workflow

```
search → read uid_validity → export_messages → git am <path>
```

1. `search` for the messages to export and note the `uid_validity`
   reported alongside the matching UIDs.
2. Call `export_messages` with those UIDs and pass the observed
   `uid_validity` as `expected_uidvalidity`. The server re-checks the
   folder's UIDVALIDITY before fetching; if it changed (mailbox renumbered),
   the call fails rather than exporting the wrong messages.
3. Apply the resulting mbox with `git am <path>`.

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `folder` | string | yes | IMAP folder containing the messages. |
| `uids` | list of int | yes | UIDs to export, in mbox/patch order. Non-empty, max 100, de-duplicated. |
| `expected_uidvalidity` | int | yes | UIDVALIDITY observed when the UIDs were discovered. Pins mailbox identity across `search`→`export_messages`; a mismatch fails the call. |
| `dest_dir` | string | no | Destination directory. Must resolve inside the download root. Defaults to the download root. |
| `filename` | string | no | Advisory basename prefix; sanitized before use. |
| `max_total_bytes` | int | no | Aggregate byte cap for the export. Clamped to the hard ceiling of 100 MiB regardless of the value supplied. |
| `allow_partial` | bool | no | Default `false` = all-or-nothing: if any requested UID is missing or oversize the whole call fails and no `.mbox` is written. `true` = best-effort: successes are written to a `.partial.mbox` artifact and the failures are reported in the response. |

#### Default-disabled and how to enable

`export_messages` is denied in **every** posture. It is enabled only by an
explicit override:

```toml
[security.tools]
export_messages = "allow"
```

#### Required: a server-private download root

`export_messages` writes a **raw, unsanitized** copy of message bytes to
the download sandbox. Because that export is an unredacted raw-message
oracle, the download root must be writable only by the server — the write
authority must be separated from the agent that consumes the file.

On Unix, this is enforced as a set of **fail-closed config preconditions**:
when `export_messages` is enabled and `[attachments].download_dir` is set,
config validation rejects startup if the download root

- is group- or world-writable (any of mode bits `0o022` set) — use a
  private directory (e.g. mode `0o700`);
- is a **symlink** — the resolved path must not be redirectable by whoever
  controls the link target; use a real directory;
- has an **immediate parent that is group/world-writable without the sticky
  bit** — otherwise another user could rename the root and substitute their
  own directory. A sticky parent (the `/tmp` model, mode `0o1777`) is
  accepted because it restricts rename/delete to each entry's owner.

An empty `download_dir` (the default per-session temporary directory) is
created privately by the server and is not subject to these checks. Only
the **immediate** parent is validated; a writable, non-sticky *grand*parent
is not walked — the runtime held-fd writer (below) is the backstop for
deeper path components.

These startup checks are gated on `export_messages` being enabled, because
the raw-export oracle is the high-value asset they protect. `download_attachment`
writes *decoded* attachments to the same root but does not, on its own,
trigger them; it relies on the same runtime writer protections and on the
operator keeping the download root server-private.

At runtime, writes (for both `download_attachment` and `export_messages`)
are anchored to a held directory descriptor and placed atomically (write to
a `.rimap-tmp-*` temp, then hard-link to the final name), so a partially
written file never appears at the final path and a rename of a path
component cannot redirect the write. A process killed mid-write may leave a
`0600` `.rimap-tmp-*` orphan in the download root; operators can safely
delete stale `.rimap-tmp-*` files.

## `[limits]` section

Numeric limits for rate limiting, search, and size caps.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_search_results` | u32 | 200 | Default search result limit |
| `max_search_results_cap` | u32 | 1000 | Hard ceiling on search results |
| `max_fetch_body_bytes` | u64 | 5,242,880 (5 MiB) | Max fetched body bytes per message |
| `max_attachment_bytes` | u64 | 26,214,400 (25 MiB) | Max attachment download size |
| `max_append_bytes` | u64 | 10,485,760 (10 MiB) | Max APPEND message size (drafts, sent copy) |
| `commands_per_second` | u32 | 10 | Rate limiter: tool calls per second |
| `drafts_per_minute` | u32 | 5 | Separate rate limit for `create_draft` |
| `sends_per_minute` | u32 | 3 | Separate rate limit for `send_email` |
| `circuit_breaker_error_threshold` | u32 | 5 | Error count within the window to trip the circuit breaker |
| `circuit_breaker_window_seconds` | u32 | 30 | Sliding window for the circuit breaker error counter |
| `tool_call_timeout_seconds` | u32 | 300 | Wall-clock ceiling on one account-scoped tool call |

The global rate limiter is a token bucket: it allows a **burst** of
`2 x commands_per_second` calls before throttling down to a sustained
rate of `commands_per_second` calls/sec. With the default
`commands_per_second = 10`, that's a burst of 20.

This matters for batch loops. An agent that lists 30 messages and then
fetches each one individually spends its entire burst (20 calls) almost
instantly, then the 21st call onward is admitted only once every
`1 / commands_per_second` seconds (100ms at the default) until the
bucket refills. Calls issued faster than that fail closed with
`ERR_RATE_LIMITED` and a `retry_after_ms` hint (see
[security-model.md](security-model.md#9-rate-limiting)) rather than
queuing silently.

Tuning guidance:

- Raise `commands_per_second` if a workflow legitimately needs a higher
  sustained throughput (the burst scales with it, `2x`).
- An agent doing large batch operations should either pace calls to
  stay under the sustained rate or back off on `ERR_RATE_LIMITED` using
  the returned `retry_after_ms` instead of retrying immediately.
- `drafts_per_minute` and `sends_per_minute` are separate, stricter
  buckets that gate `create_draft` and `send_email` independently of
  the global limiter. Each has a burst equal to its own rate (e.g.
  `sends_per_minute = 3` allows a burst of 3), not the global bucket's
  `2x` multiplier.

### `tool_call_timeout_seconds`

The single upper bound on one tool call, covering everything the
[`[imap]` budgets](#imap-section) bound only stage by stage: the wait for
the account's connection, the lazy connect, the command, and the one
transparent retry. When it fires the call returns `ERR_TIMEOUT`, the
`tool_end` audit record carries that code, and the account's IMAP
connection is dropped so the next call reconnects rather than reusing a
session with a half-read response on it.

The default is deliberately generous — it is a backstop against a call
nobody bounded, not a latency target, and it has to stay above the 140s
worst case a single operation can reach at the `[imap]` defaults.
Interactive clients usually give up long before it. Lower it if you want
tool calls to fail faster than your MCP client's own request timeout;
raise it if a legitimate long-running call (a large `export_messages`)
gets cut off.

Startup rejects a ceiling below
`2 x (2 x imap.command_timeout_seconds + imap.connect_timeout_seconds)`,
since that would cut off operations still inside their own budgets. When
`[smtp]` is configured, `smtp.command_timeout_seconds` is added to that
minimum: `send_email` sends and *then* appends the message to Sent, and a
ceiling that fits only the append could fire after delivery — reporting
`ERR_TIMEOUT` for a message that went out. The check is per account, so
an account that raises its own budgets may need an `[accounts.limits]`
override rather than the inherited `[defaults.limits]` value.

That minimum is a floor, not a promise that the ceiling outlasts every
call. It models one IMAP operation, and the compose tools can carry more:
`forward` fetches the source message before sending, and `send_email`
with `in_reply_to_uid` fetches it to build threading headers. At the
defaults a forward can reach 140s (fetch) + 30s (send) + 70s (Sent
append) — above the 170s the validator enforces.

**If you send mail and want the ceiling never to fire after delivery,
size it yourself rather than relying on the minimum.** A ceiling of
`3 x (2 x command_timeout + connect_timeout) + smtp.command_timeout` —
310s at the defaults, so slightly above the 300s default — covers a
forward. The default is deliberately not raised to that: it would trade a
tighter bound on every read-only call for a case that only affects
sending. The failure mode if it does fire mid-send is `ERR_TIMEOUT` on a
message that was delivered, which an agent may retry into a duplicate.

## `[audit]` section

Audit log settings. `path` is required. Global (shared across all
accounts in multi-account configs).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `path` | string | (required) | Path to the audit log file (JSONL). Must be an absolute path — the TOML parser does not expand `~`. The parent directory must exist before startup. |
| `rotate_bytes` | u64 | 10,485,760 (10 MiB) | Rotate when the file reaches this size. `0` disables rotation. |
| `rotate_keep` | u32 | 5 | Number of rotated files to keep after rotation |
| `retention_seconds` | u64 | (none) | Time-based retention for rotated files. Omit to disable. |
| `provenance_window_seconds` | u32 | 60 | Provenance ring buffer window |
| `fail_open` | bool | false | If true, continue on audit write failure (insecure). Default: audit write failure fails the tool call. |
| `allowed_base_dir` | string | (platform default) | Containment base for `audit.path`. Default is `directories::ProjectDirs::data_local_dir()` — `~/Library/Application Support/rusty-imap-mcp/` on macOS, `$XDG_DATA_HOME/rusty-imap-mcp/` (typically `~/.local/share/rusty-imap-mcp/`) on Linux. Set to `"/"` to disable (not recommended). |

See [audit-log.md](audit-log.md) for the log format and record types.

## `[attachments]` section

Global (shared across all accounts).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `download_dir` | string | `""` | Directory for downloaded attachments and `export_messages` output. Empty string means a per-session temporary directory. |

When `export_messages` is enabled, `download_dir` must be server-private
on Unix: config validation rejects a group- or world-writable directory
at startup. See
[The `export_messages` tool](#the-export_messages-tool).

## `[defaults]` section (multi-account only)

Default security and limits settings inherited by all accounts unless
overridden per-account. Only valid in multi-account configs.

```toml
[defaults.security]
posture = "draft-safe"
protected_folders = ["INBOX", "Sent", "Drafts", "Trash"]

[defaults.limits]
commands_per_second = 10
drafts_per_minute = 5
```

Per-account `[accounts.security]` and `[accounts.limits]` sections
override the corresponding `[defaults.*]` sections. Fields not specified
in the per-account section inherit from defaults.

## Credential resolution

Passwords are never stored in the config file. Resolution order:

1. **OS keychain** -- service `rusty-imap-mcp`, account
   `<account-id>/<username>@<host>` (the legacy `<username>@<host>` form
   is still read for back-compat). Store credentials with:
   ```
   rusty-imap-mcp login --host <host> --username <username>
   ```
   Add `--account <name>` to target a non-default account. The command
   prompts on `/dev/tty`; the password is never read from stdin or the
   environment.
2. **Environment variable** `RUSTY_IMAP_MCP_PASSWORD` -- fallback for
   headless, container, or CI environments. Read by the server at
   credential-resolution time, not by `login`.
3. **Error** -- if neither source has a value, the server exits with a
   message directing the user to run `rusty-imap-mcp login` or set the
   environment variable.

The server never prompts interactively on stdio (stdio is the MCP
transport). The `login` subcommand is the only interactive mode.

## Validation

The config is validated at startup. Validation errors are fatal:

- Posture name is one of `readonly`, `draft-safe`, `full`, `destructive`
- Every tool override name exists in the tool set
- TLS fingerprint (if set) parses as 32 hex bytes
- Numeric limits are positive
- Unknown fields in any section are rejected (`deny_unknown_fields`)
- Account names: non-empty, ASCII alphanumeric + hyphens, max 64 chars,
  unique across all accounts
- At least one account (flat `[imap]` or `[[accounts]]`) must exist
- Flat `[imap]` and `[[accounts]]` cannot coexist (`MixedConfigFormat`)
- SMTP required when `send_email` is enabled for an account
- `protected_folders` and `expunge_folders` must not overlap
