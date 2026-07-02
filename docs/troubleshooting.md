# Troubleshooting

Diagnosing startup failures and runtime issues with `rusty-imap-mcp`.

## "No prompts or tools found" / `tools/list` returns nothing

If an MCP client reports that the server is reachable but exposes
no tools, drive the stdio transport directly to see what the server
actually returns:

```bash
./scripts/mcp-probe-tools.sh
```

The script auto-generates `/tmp/rimap-probe.toml` from your main
config (rewriting `[audit].path` to a distinct file so it doesn't
fight a running MCP client's audit lock), sends `initialize` +
`notifications/initialized` + `tools/list`, and reports the tool
count and names plus full stderr.

- **Tool count matches the posture matrix (16 on draft-safe)** —
  the gap is client-side. Capture the client's `initialize` request
  via the stderr-capture shim below and inspect its
  `clientCapabilities` plus the actual `tools/list` response in the
  client's own logs. Spec-strict clients (e.g. `bobshell`) verify
  the server's advertised capabilities first; the server must
  declare `tools` in its `initialize` response or these clients
  refuse to call `tools/list` at all.
- **Tool count is 0 or the probe shows a server error** — the gap
  is server-side; check the stderr output the script printed.

## "Connection closed" / "MCP error -32000" from your MCP client

A generic transport error from the client (Claude Desktop, Claude Code,
IBM Bob, Cursor, etc.) almost always means the server **exited before
completing the MCP handshake**. The real error went to stderr. See
[Where logs go](#where-logs-go) below.

### First move: run the server from a terminal

Reproduce the failure outside the MCP client with stderr visible:

```bash
RIMAP_LOG=debug rusty-imap-mcp --dry-run
```

`--dry-run` loads and validates the config, resolves credentials from
the OS keychain, opens an IMAP/TLS connection, prints the posture
matrix and capability list, and exits. It does **not** start the MCP
transport, so any startup-stage failure surfaces as a normal stderr
error instead of being hidden behind "connection closed."

If `--dry-run` succeeds but the MCP client still fails, run the server
without `--dry-run` and redirect stderr to a file:

```bash
RIMAP_LOG=debug rusty-imap-mcp 2>/tmp/rimap.log
# press Ctrl-D to send EOF, then inspect the log
```

### Common root causes

| Symptom in stderr | Cause | Fix |
|-------------------|-------|-----|
| `no config path (pass --config or set RUSTY_IMAP_MCP_CONFIG)` | Server could not locate a config file | Set `RUSTY_IMAP_MCP_CONFIG` in the client's MCP `env` block, pass `--config <path>`, or place the file at the platform default (see [configuration.md](configuration.md)) |
| `audit file ... is already locked` | Another `rusty-imap-mcp` process holds the audit lock | Each MCP client must use a distinct `[audit].path`; see [Running multiple MCP clients](audit-log.md#running-multiple-mcp-clients) |
| `path ... is not writable: directory does not exist` | Audit log parent directory missing | Create it; `audit.path` must be absolute (no `~` — the TOML parser does not expand `~`) |
| `audit path ... is not contained in allowed base ...` | `audit.path` is outside the platform-default base | Move the audit file under the default base, or set `audit.allowed_base_dir` explicitly |
| `ERR_TLS` | TLS handshake failure | Verify network reachability to the IMAP host on port 993 |
| `ERR_TLS: ... UnknownIssuer` | Server cert chains to a CA not in the compiled `webpki-roots` bundle (corporate internal CA, self-signed cert, or a TLS-inspection proxy presenting an internal CA) | Pin the leaf cert: capture via `--dry-run` and add `tls_fingerprint_sha256` to `[imap]`. See [Optional: pin the TLS certificate](quickstart-gmail.md#optional-pin-the-tls-certificate) for the procedure; pinning skips chain validation entirely |
| `Capabilities ...: unavailable (...)` | Preflight could not complete | Inspect the parenthesised cause — typically DNS, connectivity, or TLS |
| `ERR_CONFIG` | TOML parse or validation error | Check syntax and field names against [configuration.md](configuration.md) |
| No credential found in keyring | `rusty-imap-mcp login` was never run for this account | Run `rusty-imap-mcp login --host <h> --username <u>` |

### GUI MCP clients and PATH

GUI applications launched from the macOS Dock or Spotlight (and the
Linux equivalents) do **not** inherit your shell environment. `$PATH`
is usually limited to `/usr/bin:/bin:/usr/sbin:/sbin`, and any env vars
exported from `~/.zshrc` or `~/.bashrc` are invisible.

For GUI MCP clients, use the absolute path to the binary and set
`RUSTY_IMAP_MCP_CONFIG` explicitly in the client's MCP `env` block:

```jsonc
{
  "mcpServers": {
    "email": {
      "command": "/Users/you/.cargo/bin/rusty-imap-mcp",
      "env": {
        "RUSTY_IMAP_MCP_CONFIG": "/Users/you/Library/Application Support/rusty-imap-mcp/config.toml"
      }
    }
  }
}
```

## Verifying and managing stored credentials

`rusty-imap-mcp login` stores the IMAP/SMTP password in the OS-native
secret store: macOS Keychain via the Security framework, Linux Secret
Service (libsecret) via D-Bus. The MCP server never reads passwords
from `config.toml`. If startup fails with `ERR_AUTH: credential
unavailable`, the credential is either not stored, stored under a
different key (typo in `--host` or `--username`), or stored but
inaccessible from the launching process's context.

The expected key is `<account>/<username>@<host>`, where `<account>`
is `default` for a legacy single-account config (no `[[accounts]]`
block) and the account ID otherwise. Service is always
`rusty-imap-mcp`.

### macOS

The CLI is `security` (built in, no install). Keychain Access.app is
the GUI equivalent.

```bash
# Existence check (no password retrieval)
security find-generic-password \
  -s rusty-imap-mcp \
  -a "default/you@example.com@imap.example.com"
# Exit 0 = found; exit 44 = not found.

# Retrieve the password (exercises ACL — same path the server walks)
security find-generic-password \
  -s rusty-imap-mcp \
  -a "default/you@example.com@imap.example.com" -w

# List everything stored under the service (useful when the username
# or host is uncertain or has a typo)
security dump-keychain | rg -A 2 '"svce".*"rusty-imap-mcp"'

# Delete a wrong entry
security delete-generic-password \
  -s rusty-imap-mcp \
  -a "default/wrong-username@imap.example.com"
```

GUI: open **Keychain Access.app** → login keychain → search
`rusty-imap-mcp`. Double-click an item → **Access Control** tab to
view or widen the allow-list. Most GUI MCP clients launch the same
binary path that `login` used, so the existing ACL applies — but
macOS may prompt "Always Allow / Allow Once / Deny" on first
GUI-context access. Pick **Always Allow** or you'll have to revisit
the ACL panel each time.

### Linux

The CLI is `secret-tool` from the `libsecret-tools` package
(`apt install libsecret-tools` on Debian/Ubuntu, `dnf install
libsecret` on Fedora). The keyring crate stores items with these
attributes:

| Attribute | Value |
|-----------|-------|
| `service` | `rusty-imap-mcp` |
| `username` | `<account>/<username>@<host>` |
| `target` | `default` |
| `application` | `rust-keyring` |

```bash
# Discover everything this binary has stored (shows all attributes,
# useful when key strings are uncertain)
secret-tool search service rusty-imap-mcp

# Retrieve a specific password (prints it to stdout)
secret-tool lookup \
  service rusty-imap-mcp \
  username "default/you@example.com@imap.example.com"

# Delete an entry by matching attributes
secret-tool clear \
  service rusty-imap-mcp \
  username "default/wrong-username@imap.example.com"
```

GUI: **Seahorse** ("Passwords and Keys") on GNOME, **KWalletManager**
on KDE. Look under "Login" or the equivalent default keyring.

The Secret Service requires a running `dbus-daemon` and a Secret
Service provider (`gnome-keyring-daemon`, `kwallet`, or a headless
alternative like `pass-secret-service`). On headless servers without
a desktop session, neither `secret-tool` nor `rusty-imap-mcp login`
will work — fall back to the `RUSTY_IMAP_MCP_PASSWORD` environment
variable (see [Fallback: environment variable](#fallback-environment-variable)
below).

### Windows

Pre-built binaries are not currently published for Windows targets
(see [README.md](../README.md#pre-built-binaries) for the release
matrix). Windows support would use Credential Manager via the same
keyring crate, but is untested and unsupported. Build from source at
your own risk.

### Fallback: environment variable

If the keyring path is blocked (headless host, no Secret Service
provider, ACL denied, debugging) the server reads
`RUSTY_IMAP_MCP_PASSWORD` from the environment as a last resort:

```jsonc
"env": {
  "RUSTY_IMAP_MCP_PASSWORD": "...",
  "RUSTY_IMAP_MCP_CONFIG": "..."
}
```

Environment variables leak through process listings, crash dumps, and
shell history. Use this only for diagnosis or in environments where
the OS keyring genuinely isn't available. Move back to the keyring as
soon as the underlying problem is fixed.

**Per-protocol env vars.** Three password variables are consulted, in
order, and only when `fallback = "keyring-then-env"` (the default):

1. The protocol-scoped var — `RUSTY_IMAP_MCP_IMAP_PASSWORD` for IMAP
   lookups, `RUSTY_IMAP_MCP_SMTP_PASSWORD` for SMTP lookups.
2. The legacy shared var `RUSTY_IMAP_MCP_PASSWORD` (back-compat).

If your IMAP and SMTP passwords are identical (Gmail App Passwords,
Proton Bridge passwords), `RUSTY_IMAP_MCP_PASSWORD` alone still works.
If they differ, set the two protocol-scoped vars so each protocol gets
its own credential — the shared var would otherwise feed the same
password to both. When a credential resolves from the legacy
`RUSTY_IMAP_MCP_PASSWORD` while the protocol-scoped var is unset, the
server logs a `warn` naming the scoped var to set.

```jsonc
"env": {
  "RUSTY_IMAP_MCP_IMAP_PASSWORD": "...",
  "RUSTY_IMAP_MCP_SMTP_PASSWORD": "...",
  "RUSTY_IMAP_MCP_CONFIG": "..."
}
```

For split-credential setups that want the strongest guarantee — a
keyring miss fails loud instead of consulting *any* env var — keep
using the keyring (each protocol uses its own key —
`<account>/<imap_username>@<imap_host>` vs
`<account>/<smtp_username>@<smtp_host>`) with keyring-only:

```toml
[defaults.credentials]
fallback = "keyring-only"
```

The `fallback` field lives under `[defaults.credentials]` (applies
to all accounts) or per-account under `[accounts.credentials]`. It
is **not available in legacy single-account configs** (flat `[imap]`
with no `[[accounts]]`) — `deny_unknown_fields` rejects a
`[credentials]` block at the top level. To use keyring-only with a
single account, migrate to the multi-account form:

```toml
[defaults.credentials]
fallback = "keyring-only"

[[accounts]]
name = "default"
imap = { host = "imap.example.com", port = 993, username = "you@example.com" }
```

See `crates/rimap-config/src/model.rs` (`FallbackMode` doc-comment)
for the design rationale: the same hazard motivated the keyring-only
mode for multi-account deployments and applies here within a single
account.

### `--dry-run` does not verify credentials

A successful `--dry-run` proves your config parses, your network
reaches the IMAP server, and your TLS configuration is correct. It
does **not** prove your credentials authenticate — the preflight
probe deliberately stops before `LOGIN` (see
`crates/rimap-imap/src/preflight.rs`), and SMTP isn't touched at all.

The verify-the-credential-stored commands above prove the keyring
entry exists, but not that the stored password is accepted by the
server. To exercise authentication directly:

- **IMAP:** see "Optional: verify the credential authenticates" in
  [quickstart-gmail.md](quickstart-gmail.md#optional-verify-the-credential-authenticates)
  or [quickstart-proton-bridge.md](quickstart-proton-bridge.md#optional-verify-the-credential-authenticates)
  — uses `openssl s_client` to send `LOGIN` / `LOGOUT` directly.
- **SMTP:** see the "Verify the SMTP credential" step in the
  "Optional: enable sending" section of either quickstart — uses
  `swaks --quit-after AUTH` to exercise AUTH without transacting a
  message.

Built-in support for both is tracked in
[issue #259](https://github.com/randomparity/rusty-imap-mcp/issues/259).

## Where logs go

`rusty-imap-mcp` writes diagnostic logs (from the `tracing` framework)
to **stderr only**. There is no log file, no rotation, no
`RIMAP_LOG_FILE` setting.

This is by design: stdout is reserved for the MCP JSON-RPC transport,
so the server can never write logs there. The project does not own a
debug log file — routing stderr is the operator's choice.

The separate `[audit]` block in `config.toml` controls the **audit
event log** (structured JSONL: tool calls, auth events, process
lifecycle). It is not a debug log and contains nothing from before
audit initialization.

### Log level

The level filter is read from the `RIMAP_LOG` env var first, then
`RUST_LOG`, then defaults to `info`. Both use the standard
`tracing-subscriber` `EnvFilter` syntax:

```bash
RIMAP_LOG=debug rusty-imap-mcp
RIMAP_LOG=rimap_imap=trace,info rusty-imap-mcp   # per-module override
```

### Capturing stderr from GUI MCP clients

GUI MCP clients typically launch the server with stdin/stdout wired to
the protocol and stderr inherited or discarded. To capture stderr,
wrap the binary in a shim script:

```sh
#!/bin/sh
# ~/bin/rusty-imap-mcp-debug
exec /Users/you/.cargo/bin/rusty-imap-mcp "$@" 2>>/tmp/rusty-imap-mcp.stderr.log
```

```bash
chmod +x ~/bin/rusty-imap-mcp-debug
```

Point the MCP client's `command` at the shim instead of the binary,
add `RIMAP_LOG=debug` to its `env` block, and tail
`/tmp/rusty-imap-mcp.stderr.log` while the client reconnects. Remove
the shim once the cause is identified — appending to a long-lived log
file leaks diagnostic data over time.
