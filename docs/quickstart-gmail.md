# Quick start: Gmail

Set up rusty-imap-mcp with a Gmail account in about 10 minutes.

## Prerequisites

- A Gmail account with [2-Step Verification](https://myaccount.google.com/signinoptions/two-step-verification) enabled
- An [App Password](https://myaccount.google.com/apppasswords) generated for "Mail" (16-character code, spaces don't matter)

## Step 1: Install

Download a pre-built binary from the
[releases page](https://github.com/randomparity/rusty-imap-mcp/releases)
and put it on your `$PATH`, or build from source and install:

```bash
git clone https://github.com/randomparity/rusty-imap-mcp.git
cd rusty-imap-mcp
cargo install --path crates/rimap-server   # installs into ~/.cargo/bin
```

If `~/.cargo/bin` isn't already on your `$PATH`, add it (e.g.
`export PATH="$HOME/.cargo/bin:$PATH"` in `~/.zshrc` or `~/.bashrc`),
then verify:

```bash
rusty-imap-mcp --version
```

All subsequent commands assume `rusty-imap-mcp` resolves on `$PATH`.

## Step 2: Create the config and audit directories

The config file lives at:

- **Linux:** `~/.config/rusty-imap-mcp/config.toml`
- **macOS:** `~/Library/Application Support/rusty-imap-mcp/config.toml`

The audit log directory must exist before startup; `rusty-imap-mcp`
never creates it for you. The audit path must also live under the
platform-default `allowed_base_dir`
(`~/Library/Application Support/rusty-imap-mcp/` on macOS,
`~/.local/share/rusty-imap-mcp/` on Linux) unless you set
`audit.allowed_base_dir` explicitly.

Create both directories:

```bash
# macOS
mkdir -p ~/Library/Application\ Support/rusty-imap-mcp

# Linux
mkdir -p ~/.config/rusty-imap-mcp ~/.local/share/rusty-imap-mcp
```

Then write the config file. **The TOML parser does not expand `~`** —
`audit.path` must be an absolute path. Pick the block for your platform:

**macOS** (`~/Library/Application Support/rusty-imap-mcp/config.toml`):

```toml
[imap]
host = "imap.gmail.com"
port = 993
username = "you@gmail.com"

[audit]
path = "/Users/you/Library/Application Support/rusty-imap-mcp/audit.jsonl"
```

**Linux** (`~/.config/rusty-imap-mcp/config.toml`):

```toml
[imap]
host = "imap.gmail.com"
port = 993
username = "you@gmail.com"

[audit]
path = "/home/you/.local/share/rusty-imap-mcp/audit.jsonl"
```

Replace `you@gmail.com` with your Gmail address and `/Users/you` or
`/home/you` with your actual home directory (run `echo $HOME` if
unsure).

> **No `[smtp]` yet.** The default posture (`draft-safe`) does not
> permit `send_email`, so SMTP is not needed for this quickstart.
> Adding an `[smtp]` block while the credential is missing causes the
> server to fail at startup. To enable sending later, switch posture to
> `full` and follow [Optional: enable sending](#optional-enable-sending)
> below.

If you plan to run multiple MCP clients against this account (e.g.
two Claude Code windows on different projects, or Claude Code
alongside Codex), see
[Running multiple MCP clients](audit-log.md#running-multiple-mcp-clients)
for the per-client configuration pattern.


### Optional: Customize tool availability

The default `draft-safe` posture allows most operations except sending,
deleting, and advanced search. You can fine-tune this with per-tool
overrides:

```toml
[security]
posture = "draft-safe"

[security.tools]
mark_read = "deny"                # preserve unread state
"search.advanced_query" = "allow" # enable body/text search
```

Valid tool names and their default availability are listed in the
[security postures](postures.md) documentation. Common patterns:

- **Preserve unread state:** `mark_read = "deny"` in draft-safe
- **Enable advanced search:** `"search.advanced_query" = "allow"` in draft-safe
- **Block downloads:** `download_attachment = "deny"` in readonly

See [configuration.md](configuration.md#per-tool-overrides) for the
complete reference.


## Step 3: Store your credentials

Store the App Password in your OS keychain. The `login` subcommand
prompts on `/dev/tty`; `--host` and `--username` are required:

```bash
rusty-imap-mcp login --host imap.gmail.com --username you@gmail.com
```

When prompted, paste your 16-character App Password (not your Google
account password). Spaces in the displayed App Password don't matter.
The password is stored in the OS keychain under service
`rusty-imap-mcp`, account `default/you@gmail.com@imap.gmail.com`.

## Step 4: Test the connection

Validate the config and test the IMAP connection without starting the
MCP server:

```bash
rusty-imap-mcp --dry-run
```

A successful run prints the posture matrix, the active tool allowlist,
and the IMAP server's capability list (after a TLS handshake), then
exits. It does not authenticate.

**If it fails:**

| Error | Cause | Fix |
|-------|-------|-----|
| `path ... is not writable: directory does not exist` | Audit log parent directory missing | Create it (see Step 2). Confirm `audit.path` is an absolute path, not `~/...` — the TOML parser does not expand `~`. |
| `audit path ... is not contained in allowed base ...` | `audit.path` is outside the platform-default base | Move the audit file under the platform-default base (Step 2) or set `audit.allowed_base_dir` explicitly in the `[audit]` block. |
| `ERR_TLS` | TLS handshake failure | Verify your network allows connections to imap.gmail.com:993 |
| `Capabilities ...: unavailable (...)` | Preflight could not complete | Inspect the parenthesised cause — typically connectivity, DNS, or TLS. `--dry-run` does not authenticate, so an auth error cannot surface here |
| `ERR_CONFIG` | Config parse error | Check TOML syntax and field names against the [configuration reference](configuration.md) |
| Config not found | Wrong file location | Verify the path matches your platform (see Step 2) or use `--config <path>` |

### Optional: pin the TLS certificate

The dry-run output ends with the observed certificate's SHA-256
fingerprint and a copy-pasteable line:

```
TLS fingerprint (sha256):
  ab:cd:ef:...:ef
  (add `tls_fingerprint_sha256 = "ab:cd:ef:...:ef"` under [imap] in config.toml to pin)
```

Gmail's certificate chains to a public root, so pinning is **not
required** for a successful connection. Pin anyway if you want
defense-in-depth against:

- Corporate TLS-inspection proxies presenting an internal CA
- Local MITM (compromised network, malicious profile)
- Any environment where the cert chain `rusty-imap-mcp` sees should
  match what you observed at setup time

Paste the printed line into your `[imap]` block:

```toml
[imap]
host = "imap.gmail.com"
port = 993
username = "you@gmail.com"
tls_fingerprint_sha256 = "ab:cd:ef:...:ef"
```

Re-run `rusty-imap-mcp --dry-run`; the fingerprint section now reads
`(matches configured pin)`. From this point, a fingerprint mismatch
aborts the connection — when Gmail rotates its certificate (rare, but
it happens), re-run `--dry-run` and update the pinned value.

> **Trust note:** the pin records whatever cert the network presents
> the first time. Capture it from a network you trust.

### Optional: verify the credential authenticates

`--dry-run` deliberately stops before `LOGIN`, so it cannot tell you
whether your stored password is accepted. The first auth attempt
happens inside the MCP client at server startup, which is the worst
place to discover a wrong password. To verify the credential before
integration, speak IMAP to Gmail directly:

```bash
openssl s_client -connect imap.gmail.com:993 -crlf -quiet
```

After the `* OK ...` greeting, type these (the `a1`/`a2` tags are
arbitrary identifiers you make up):

```
a1 LOGIN you@gmail.com YourAppPasswordHere
a2 LOGOUT
```

Interpreting the response:

| Response to `a1` | Meaning | Next step |
|------------------|---------|-----------|
| `a1 OK ...` | Credential accepted | Continue to Step 5 |
| `a1 NO ...` | Server rejected the credential | Re-check the App Password (16 chars, spaces optional); regenerate if needed and re-run `rusty-imap-mcp login` |
| `a1 BAD ...` | Server rejected the `LOGIN` command itself | Server may require `AUTHENTICATE` with a specific SASL mechanism; send `a3 CAPABILITY` and look at what's advertised |

> **Shell-history caveat.** The command line above places your App
> Password in your shell history. Prefix the entire shell command
> with a space (most shells with `HISTCONTROL=ignorespace` skip it),
> or run `LOGIN you@gmail.com "PaSt3 H3rE"` after the connection
> opens so the password only lives in the openssl session.

Confirm the stored password matches what just worked:

```bash
security find-generic-password \
  -s rusty-imap-mcp \
  -a "default/you@gmail.com@imap.gmail.com" -w
```

The printed value should match byte-for-byte what you typed at the
`LOGIN` prompt. If they differ, re-run `rusty-imap-mcp login`. For
Linux equivalents and broader credential management, see
[docs/troubleshooting.md](troubleshooting.md#verifying-and-managing-stored-credentials).

## Step 5: Add to your MCP client

### Claude Desktop

Edit your Claude Desktop config
(`~/Library/Application Support/Claude/claude_desktop_config.json` on
macOS, `%APPDATA%\Claude\claude_desktop_config.json` on Windows):

```json
{
  "mcpServers": {
    "email": {
      "command": "rusty-imap-mcp"
    }
  }
}
```

### Claude Code

```bash
claude mcp add email rusty-imap-mcp
```

Restart your MCP client after adding the server.

## Step 6: Verify with your agent

Test the full integration by asking your agent to perform these actions:

**Test 1 — List folders:**
> "List my email folders."

Expected: a list including INBOX, [Gmail]/Sent Mail, [Gmail]/Drafts,
[Gmail]/Trash, and any labels you have.

**Test 2 — Search for a known email:**
> "Search for a recent email from [someone you know]."

Expected: results with sanitized content. Each message has a structured
envelope with `meta` (trusted server data), `untrusted` (sanitized
email content), and `security_warnings` (any detected issues).

**Test 3 — Search for something that doesn't exist:**
> "Search for emails from nonexistent-sender-abc123@example.com."

Expected: an empty result set, not an error.

## Optional: enable sending

The default `draft-safe` posture cannot send mail. To enable
`send_email`, you need both the SMTP block in the config and a separate
keyring entry for the SMTP host (Gmail uses different hosts for IMAP
and SMTP, so the IMAP keyring entry does not cover SMTP):

1. Add an `[smtp]` block and switch posture:

   ```toml
   [smtp]
   host = "smtp.gmail.com"
   port = 465
   encryption = "tls"
   username = "you@gmail.com"

   [security]
   posture = "full"
   ```

2. Store the App Password under the SMTP host as well:

   ```bash
   rusty-imap-mcp login --host smtp.gmail.com --username you@gmail.com
   ```

   Reuse the same 16-character App Password — Gmail accepts it for both
   IMAP and SMTP.

3. (Optional) Verify the SMTP credential authenticates. `--dry-run`
   exercises IMAP only, so a wrong SMTP password surfaces inside the
   MCP client at first `send_email` attempt. Test it ahead of time
   with [`swaks`](https://github.com/jetmore/swaks)
   (`brew install swaks` on macOS, `apt install swaks` /
   `dnf install swaks` on Linux):

   ```bash
   swaks --server smtp.gmail.com:465 --tls-on-connect \
         --auth LOGIN \
         --auth-user you@gmail.com \
         --auth-password 'YOUR-APP-PASSWORD' \
         --quit-after AUTH
   ```

   `--quit-after AUTH` sends `EHLO` → AUTH negotiation → `QUIT`. No
   message is transacted. Look for `235 2.7.0 Accepted` on the AUTH
   response — that's the credential confirmed. `535 5.7.8 ...` means
   the App Password was rejected; regenerate it and re-run
   `rusty-imap-mcp login --host smtp.gmail.com --username you@gmail.com`.

   > **Shell-history caveat.** The command above places your App
   > Password on the command line. Prefix the entire command with a
   > space if your shell has `HISTCONTROL=ignorespace`, or omit
   > `--auth-password` and let swaks prompt for it on stderr.

4. Re-run `rusty-imap-mcp --dry-run` to confirm the matrix now shows
   `send_email` as `[ok ]`.

## What's next

- [Security postures](postures.md) — change what the agent can do
  (default is `draft-safe`: read + flags/labels/moves/drafts, no send)
- [Configuration reference](configuration.md) — all config options
- [Multi-account support](multi-account.md) — add more email accounts
- [Full documentation index](INDEX.md)
