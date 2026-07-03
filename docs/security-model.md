# Security Model

## Threat model

The primary adversary is a crafted email that, when read by an agent
through this MCP server, attempts to induce the agent to take a harmful
action: exfiltrate data, send mail on the attacker's behalf, modify
mailbox state, or pivot to other tools.

Secondary adversaries include a hostile IMAP server (MITM, malformed
responses) and local malware with the user's file-system privileges.

Multi-account introduces a cross-account exfiltration vector: a
compromised agent could read from one account and send via another.
Per-account posture gates, rate limits, and audit logging mitigate this.

**Account-name exposure in errors.** `ERR_NO_ACCOUNT` and
`ERR_UNKNOWN_ACCOUNT` include the full list of configured account
names in their user-facing message (see
`RimapError::NoAccount` / `UnknownAccount`). This is deliberate: an
agent that hits one of these errors can learn the available accounts
and recover on its next call without operator intervention.

For v1.0 (stdio-only, single trusted client) this is the right
trade-off. Operators who run the server over stdio own both sides of
the pipe, and the enumeration value is zero.

**When this must be revisited:** if and when an HTTP/SSE/WebSocket
transport ships, authenticated clients may have different trust
levels, and one bad call would reveal every configured account name
to any client that can reach the endpoint. Before that transport
lands, one of the following changes is required:

1. Narrow the disclosure — include only `count: N` in the user
   message; move the full list to a debug-log-only path.
2. Gate the disclosure on a config flag
   (`expose_account_names_in_errors = true`, default off for
   non-stdio transports).

Issue #81 tracks this commitment.

**Scope extension — credential-unavailable errors.**
`RimapError::Auth::CredentialUnavailable` carries the reason
produced by `rimap-config::credential::resolve_credential`, which
embeds `<account-id>/<username>@<host>` (the keyring lookup key) so
operators can correlate the error with the exact entry to create.
The same stdio-only / single-trusted-client trade-off justifies the
disclosure under v1.0. The transport revisit above must also narrow
this string — either to the 16-hex `account_tag` already computed in
`ConfigError::NoCredential`, or behind the same
`expose_account_names_in_errors` flag.

**The server does not trust:** email bodies, headers, sender addresses,
display names, attachment filenames, link targets, or any
server-provided content. All of these are treated as untrusted input
that must be parsed, sanitized, tagged, and structurally separated from
server-controlled metadata before being returned to an MCP client.

**The server does trust:** its own configuration file, its own keychain
entries, its own audit log, and (within limits defined by fingerprint
pinning) the TLS identity of its configured IMAP server.

## Defense layers

### 1. Content pipeline

Every byte from IMAP flows through the content pipeline
(`rimap-content`) before reaching any tool response. The pipeline has
zero IMAP dependencies -- it takes `&[u8]` in and emits typed `Content`
structures out.

**Pipeline stages:**

1. **Parse** -- `mail-parser` decodes RFC 5322 into headers + body
   parts. Malformed messages produce a structured error, not a panic.
2. **Header extraction** -- Header names are ASCII-validated (control
   chars in names indicate header smuggling and are rejected). Values
   are decoded from RFC 2047 encoded-words, then processed through the
   Unicode pipeline. CR/LF inside decoded header values is rejected
   (header smuggling defense).
3. **Mailing list detection** -- `List-Id` and `List-*` headers are
   extracted before sanitization so the raw values survive for agent
   filtering.
4. **Body part selection** -- MIME tree walk preferring `text/plain`;
   falls back to `text/html` through the HTML-to-text converter.
5. **HTML to text conversion** -- Strips `<script>`, `<style>`,
   `<iframe>`, `<form>`, and other dangerous elements. Strips elements
   with hidden visibility (CSS `display:none`, `visibility:hidden`,
   `opacity:0`, `font-size:0`, white-on-white color). Strips zero-width
   and bidirectional override characters. Link handling detects
   text/href domain mismatches and emits `link_warnings`.
6. **Sanitized HTML** (only with `include_html=true` in `full` posture)
   -- `ammonia` with a conservative allowlist: no scripts, no event
   handlers, no external resources, no `data:` URIs except images
   under 1 MiB.
7. **Attachment metadata extraction** -- Filenames sanitized (path
   separators stripped, leading dots stripped, Windows reserved names
   prefixed, length truncated). No bytes are read at this stage.
8. **Content tagging** -- The final output is wrapped in the `untrusted`
   field, separate from `meta`.

### 2. Unicode policy

Every string leaving the content pipeline is:

- Valid UTF-8
- In NFKC form (collapses visually-equivalent forms for security)
- Free of invisible/ambiguous codepoints (zero-width chars,
  bidirectional overrides, C0/C1 controls except `\t` and `\n`,
  unassigned/private-use codepoints)
- Preserves legitimate scripts (CJK, Hebrew, Arabic, European
  accents, emoji including ZWJ sequences)

### 3. Response envelope

Every tool response structurally separates three fields:

- **`meta`** -- server-controlled metadata (folder names, UIDs, flags,
  sizes). Trusted.
- **`untrusted`** -- sanitized content derived from email data. Agents
  and host LLMs should treat this as untrusted input.
- **`security_warnings`** -- structured observations emitted by the
  server's look-alike and sanitization layers. Trusted metadata (the
  server's assessment, not email content).

This structural separation means agents can apply different trust
policies to different parts of the response without parsing conventions
out of a flat string.

### 4. Look-alike detection

Detects and flags (never rejects) visual spoofing attempts on:

- Sender addresses (mixed-script, confusable skeleton matching)
- Display name vs. address mismatches
  (`From: "support@paypal.com" <eve@evil.example>`)
- Reply-To vs. From domain mismatches
- Link href domain vs. link text mismatches
- Attachment filename bidirectional tricks

Body text prose is not scanned (false-positive rate on multilingual
content is too high). All detection is local, deterministic, and
rules-based -- no network lookups, no ML.

### 5. `$PendingReview` human-in-the-loop gate

`create_draft` appends messages to the Drafts folder with `\Draft` and
`$PendingReview` keywords. A human must review and send from their mail
client. This provides a safe drafting workflow in `draft-safe` posture
without granting autonomous send capability.

### 6. Posture-based authorization

Four postures control which tools are available. Tools denied by the
active posture are not advertised via `list_tools` and are rejected at
dispatch. A denial is returned to the client as a `CallToolResult` with
`isError: true` carrying the `ERR_POSTURE_DENIED` code and an opaque
message (`operation denied for this folder` for folder-policy denials —
the folder name and policy field names are never reflected). See
[Error delivery](#12-error-delivery).

### 7. Folder safety

- `protected_folders` (default: INBOX, Sent, Drafts, Trash) prevents
  `rename_folder` and `delete_folder` on critical folders.
- `expunge_folders` (default empty = deny all) is an allowlist for
  `expunge` and `delete_folder`. Folders not in this list cannot be
  expunged or deleted.
- `create_folder` rejects names that collide with protected folders
  (case-insensitive).

### 8. Audit log

Every tool invocation produces exactly two audit records (`tool_start`
+ `tool_end`), linked by a monotonic sequence number. The audit log
tracks content provenance: a ring buffer of recently-read message IDs
is snapshotted into every `tool_end` record, enabling post-hoc
detection of suspicious read-then-send sequences.

The audit file is exclusively locked for the process lifetime. Write
failures fail the tool call by default (`fail_open = false`). See
[audit-log.md](audit-log.md).

### 9. Rate limiting

- Global rate limiter: `commands_per_second` (default 10/sec) with a
  burst of 20.
- Separate stricter limit for `create_draft`: `drafts_per_minute`
  (default 5/min).
- Separate stricter limit for `send_email`: `sends_per_minute`
  (default 3/min).
- On exceed: waits up to 250ms, then fails with `ERR_RATE_LIMITED` and
  a `retry_after_ms` hint.

### 10. Circuit breaker

Sliding-window count-based breaker protects against cascading failures:

- **Closed** (normal): counts errors in the configured window (default
  30s). At threshold (default 5 errors), transitions to Open.
- **Open**: immediately fails with `ERR_CIRCUIT_OPEN` for a cooldown
  period.
- **Half-open**: allows one probe call. Success returns to Closed;
  failure re-opens with a doubled cooldown (capped at 5 min).
- Auth failures trip immediately (single failure opens for 60s).

Errors that trip the breaker: `ConnectionLost`, `AuthFailure`,
`Timeout`, `ProtocolError`, `TlsError`. User/policy errors
(`NotFound`, `InvalidInput`, `PostureDenied`, `RateLimited`) do not
trip it.

### 11. TLS fingerprint pinning

When `imap.tls_fingerprint_sha256` is set, the server verifies the
IMAP server's TLS certificate fingerprint before any application data
flows. A mismatch is a hard failure -- the server does not fall back
to the system trust store when pinning is configured.

### 12. Error delivery

The server distinguishes two failure channels, following the MCP spec:

- **Tool-execution failures** — the request was validly routed and the
  tool ran but failed (missing UID, stale UIDVALIDITY, rate limit,
  circuit open, size cap, IMAP/SMTP/TLS/timeout, posture / folder-policy
  denial). These are returned as a `CallToolResult` with `isError:
  true`: the human-readable message is the result's text content and the
  stable `error_code` plus any typed recovery `data` (`retry_after_ms`,
  expected/actual UIDVALIDITY, `kind`/`limit`) are in
  `structuredContent`. The agent reliably sees the message and can
  self-correct.
- **Protocol / routing failures** — unknown tool, malformed params
  shape, account resolution, unsupported protocol version. These are
  returned as JSON-RPC errors.

Folder-policy denials (`protected_folders` / `expunge_folders`) and
posture denials use an opaque message (`operation denied for this
folder`) that never reflects the folder name or the policy field names,
so the error surface does not leak configuration. The machine-readable
`error_code` (`ERR_POSTURE_DENIED`, `ERR_PROTECTED_FOLDER`,
`ERR_EXPUNGE_DENIED`) is still provided for programmatic handling.

## Posture matrix

22 posture-gated tools across 4 postures. `use_account` and
`list_accounts` are infrastructure tools that bypass the posture matrix.

| Tool | `readonly` | `draft-safe` | `full` | `destructive` |
|------|:----------:|:------------:|:------:|:-------------:|
| `list_folders` | yes | yes | yes | yes |
| `search` | yes | yes | yes | yes |
| `search_advanced` | - | - | yes | yes |
| `fetch_message` | yes | yes | yes | yes |
| `fetch_message_html` | - | - | yes | yes |
| `list_attachments` | yes | yes | yes | yes |
| `download_attachment` | yes | yes | yes | yes |
| `mark_read` | - | yes | yes | yes |
| `mark_unread` | - | yes | yes | yes |
| `flag` | - | yes | yes | yes |
| `unflag` | - | yes | yes | yes |
| `add_label` | - | yes | yes | yes |
| `remove_label` | - | yes | yes | yes |
| `list_labels` | yes | yes | yes | yes |
| `move_message` | - | yes | yes | yes |
| `create_draft` | - | yes | yes | yes |
| `send_email` | - | - | yes | yes |
| `delete_message` | - | - | yes | yes |
| `create_folder` | - | - | yes | yes |
| `rename_folder` | - | - | yes | yes |
| `expunge` | - | - | - | yes |
| `delete_folder` | - | - | - | yes |
| `export_messages` | - | - | - | - |

Per-tool overrides (`"allow"` / `"deny"`) merge on top of the base
posture. An override that matches the posture's default is a no-op.

`export_messages` is denied in every posture; it is enabled only by an
explicit `export_messages = "allow"` override. It writes a raw,
unsanitized mbox to the download sandbox (an unredacted raw-message
oracle), so when enabled it requires a server-private download root:
config validation rejects a group/world-writable `attachments.download_dir`
on Unix. See
[configuration.md](configuration.md#the-export_messages-tool).

## Dispatch chain

Every tool call passes through all layers in order:

```
ToolCall -> input validation -> posture authorization -> circuit breaker
         -> rate limiter -> audit start -> tool execution -> audit end
         -> response
```

Any stage failing short-circuits to a structured error response and
records an audit end entry. Failures before tool execution never reach
the network.
