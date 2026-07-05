# Quick start: Proton Bridge

Set up rusty-imap-mcp with Proton Mail via Proton Bridge in about
15 minutes.

## Prerequisites

- [Proton Bridge](https://proton.me/mail/bridge) installed and signed in
- IMAP enabled in Bridge settings
- The bridge password noted (displayed in Bridge settings — this is not
  your Proton account password)

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

Then write the initial config. Proton Bridge's default IMAP mode is
STARTTLS on port 1143; the implicit-TLS alternative (port 1993)
requires enabling "SSL" in Bridge's Advanced Settings. This config
uses the default.

**The TOML parser does not expand `~`** — `audit.path` must be an
absolute path. Leave `tls_fingerprint_sha256` empty for now; you fill
it in after Step 3:

**macOS** (`~/Library/Application Support/rusty-imap-mcp/config.toml`):

```toml
[imap]
host = "127.0.0.1"
port = 1143
encryption = "starttls"
username = "you@proton.me"
# tls_fingerprint_sha256 = "fill-in-after-step-3"

[security]
posture = "draft-safe"

[audit]
path = "/Users/you/Library/Application Support/rusty-imap-mcp/audit.jsonl"
```

**Linux** (`~/.config/rusty-imap-mcp/config.toml`):

```toml
[imap]
host = "127.0.0.1"
port = 1143
encryption = "starttls"
username = "you@proton.me"
# tls_fingerprint_sha256 = "fill-in-after-step-3"

[security]
posture = "draft-safe"

[audit]
path = "/home/you/.local/share/rusty-imap-mcp/audit.jsonl"
```

Replace `you@proton.me` with your Proton email address and `/Users/you`
or `/home/you` with your actual home directory (run `echo $HOME` if
unsure).

> **No `[smtp]` yet.** The default posture (`draft-safe`) does not
> permit `send_email`, so SMTP is not needed for this quickstart.
> Adding an `[smtp]` block before storing the credential causes the
> server to fail at startup. To enable sending later, see
> [Optional: enable sending](#optional-enable-sending) below.

If you plan to run multiple MCP clients against this account (e.g.
two Claude Code windows on different projects, or Claude Code
alongside Codex), see
[Running multiple MCP clients](audit-log.md#running-multiple-mcp-clients)
for the per-client configuration pattern.

## Step 3: Capture and pin the TLS fingerprint

Proton Bridge uses a self-signed TLS certificate that is not in your
system trust store. Pin the certificate fingerprint so the server can
verify it.

### Recommended: capture via `--dry-run`

With the config from Step 2 saved (and the audit directory created),
run:

```bash
rusty-imap-mcp --dry-run
```

The output includes a `TLS fingerprint (sha256):` line followed by the
observed cert hash and a copy-pasteable line:

```
TLS fingerprint (sha256):
  ab:cd:ef:...:ef
  (add `tls_fingerprint_sha256 = "ab:cd:ef:...:ef"` under [imap] in config.toml to pin)
```

Uncomment `tls_fingerprint_sha256` in `[imap]` and paste the hex value,
then re-run `--dry-run`; the fingerprint section now reads
`(matches configured pin)`.

> **Trust note**: `--dry-run` records whatever cert the network presents.
> Run it from a network you trust at the time of fingerprint extraction —
> same caveat as the `openssl s_client` recipe below.

### Alternative: extract the fingerprint with openssl

If you prefer to extract the fingerprint without invoking
`rusty-imap-mcp` at all:

```bash
openssl s_client -connect 127.0.0.1:1143 -starttls imap < /dev/null 2>/dev/null \
  | openssl x509 -outform DER \
  | openssl dgst -sha256 -hex \
  | awk '{print $2}'
```

This prints a 64-character hex string. Paste it as the value of
`tls_fingerprint_sha256` in `[imap]`.

Bridge's IMAP port uses STARTTLS rather than implicit TLS, so `-starttls imap`
is required — without it, `openssl` returns no certificate and the pipeline
silently hashes empty bytes to the well-known constant
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
If you see that value, you forgot the flag.

The fingerprint changes when Proton Bridge regenerates its certificate
(after a Bridge update or reinstall). If the server later fails with
`ERR_TLS`, re-run this step and update the config.

## Step 4: Store your credentials

Store the Bridge password in your OS keychain. The `login` subcommand
prompts on `/dev/tty`; `--host` and `--username` are required:

```bash
rusty-imap-mcp login --host 127.0.0.1 --username you@proton.me
```

When prompted, paste the bridge password from Proton Bridge settings
(not your Proton account password). The password is stored in the OS
keychain under service `rusty-imap-mcp`, account
`default/you@proton.me@127.0.0.1`.

Because Proton Bridge serves IMAP and SMTP on the same host
(`127.0.0.1`), this single keyring entry covers both protocols — no
separate SMTP login is needed when you later enable sending.

## Step 5: Test the connection

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
| `ERR_TLS` | Fingerprint mismatch or Bridge not running | Verify Bridge is running, then re-capture the fingerprint (Step 3) |
| `Capabilities ...: unavailable (...)` | Preflight could not complete | Inspect the parenthesised cause — typically connectivity or TLS. `--dry-run` does not authenticate, so an auth error cannot surface here |
| `ERR_CONFIG` | Config parse error | Check TOML syntax and field names against the [configuration reference](configuration.md) |
| Connection refused | Bridge not running or wrong port | Start Proton Bridge and verify the IMAP port in Bridge settings |

### Optional: verify the credential authenticates

`--dry-run` deliberately stops before `LOGIN`, so it cannot tell you
whether your stored password is accepted. The first auth attempt
happens inside the MCP client at server startup, which is the worst
place to discover a wrong password. To verify the credential before
integration, speak IMAP to Bridge directly (note `-starttls imap` —
Bridge uses STARTTLS on port 1143, not implicit TLS):

```bash
openssl s_client -connect 127.0.0.1:1143 -starttls imap -crlf -quiet
```

After the `* OK ...` greeting, type these (the `a1`/`a2` tags are
arbitrary identifiers you make up):

```
a1 LOGIN you@proton.me YourBridgePasswordHere
a2 LOGOUT
```

Interpreting the response:

| Response to `a1` | Meaning | Next step |
|------------------|---------|-----------|
| `a1 OK ...` | Credential accepted | Continue to Step 6 |
| `a1 NO ...` | Server rejected the credential | Re-copy the bridge password from Proton Bridge settings (not your Proton account password); re-run `rusty-imap-mcp login` if you mistyped it earlier |
| `a1 BAD ...` | Server rejected the `LOGIN` command itself | Unexpected against Bridge; send `a3 CAPABILITY` and inspect what's advertised |

> **Shell-history caveat.** The command line above places your bridge
> password in your shell history. Prefix the entire shell command
> with a space (most shells with `HISTCONTROL=ignorespace` skip it),
> or run `LOGIN you@proton.me "PaSt3 H3rE"` after the connection
> opens so the password only lives in the openssl session.

Confirm the stored password matches what just worked:

```bash
security find-generic-password \
  -s rusty-imap-mcp \
  -a "default/you@proton.me@127.0.0.1" -w
```

The printed value should match byte-for-byte what you typed at the
`LOGIN` prompt. If they differ, re-run `rusty-imap-mcp login`. For
Linux equivalents and broader credential management, see
[docs/troubleshooting.md](troubleshooting.md#verifying-and-managing-stored-credentials).

## Step 6: Add to your MCP client

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

## Step 7: Verify with your agent

Test the full integration by asking your agent to perform these actions:

**Test 1 — List folders:**
> "List my email folders."

Expected: a list including INBOX, Drafts, Sent, Trash, Archive, Spam,
and any custom labels (under `Labels/`) or folders (under `Folders/`).

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
`send_email`, add an `[smtp]` block and switch posture to `full`:

```toml
[smtp]
host = "127.0.0.1"
port = 1025
encryption = "starttls"
username = "you@proton.me"

[security]
posture = "full"
```

The keyring entry stored in Step 4 already covers SMTP — Bridge uses
the same host (`127.0.0.1`) and the same bridge password for both
protocols, so no second `login` invocation is needed.

The SMTP port shown above (1025) is the Proton Bridge default; the
exact port appears in Bridge settings.

### Optional: verify the SMTP credential authenticates

`--dry-run` exercises IMAP only, so a wrong SMTP password surfaces
inside the MCP client at first `send_email` attempt. Test it ahead of
time with [`swaks`](https://github.com/jetmore/swaks)
(`brew install swaks` on macOS, `apt install swaks` /
`dnf install swaks` on Linux):

```bash
swaks --server 127.0.0.1:1025 --tls \
      --auth LOGIN \
      --auth-user you@proton.me \
      --auth-password 'YOUR-BRIDGE-PASSWORD' \
      --quit-after AUTH
```

`--quit-after AUTH` sends `EHLO` → STARTTLS → AUTH negotiation →
`QUIT`. No message is transacted. Look for `235 ... Authentication
succeeded` on the AUTH response — that's the credential confirmed.
`535 ...` means Bridge rejected the password; re-copy it from
Bridge settings (it's the bridge-specific password, not your Proton
account password) and re-run `rusty-imap-mcp login`.

> **Shell-history caveat.** The command above places your bridge
> password on the command line. Prefix the entire command with a
> space if your shell has `HISTCONTROL=ignorespace`, or omit
> `--auth-password` and let swaks prompt for it on stderr.

### Confirm the posture matrix

Re-run `rusty-imap-mcp --dry-run` to confirm the matrix now shows
`send_email` as `[ok ]`.

## Known quirks

### Bridge password vs. account password

The IMAP/SMTP password is the bridge-specific password displayed in
Proton Bridge settings, not your Proton account password. Using the
wrong password results in `ERR_AUTH`.

### Self-signed certificate

Without `tls_fingerprint_sha256`, the server rejects the connection
because the certificate is not in the system trust store. Fingerprint
pinning is required for Proton Bridge.

### Folder naming

Proton Bridge maps Proton's label system to IMAP folders. Use
`list_folders` to discover the actual IMAP names. Common mappings:

- `INBOX`, `Drafts`, `Sent`, `Trash`, `Archive`, `Spam`
- Labels appear under `Labels/`
- Subfolders appear under `Folders/`

### MOVE support

Proton Bridge supports the IMAP MOVE extension. `move_message` uses
MOVE directly rather than the COPY+STORE+EXPUNGE fallback.

### SMTP port

Proton Bridge uses port 1025 for SMTP with STARTTLS. The exact port
is shown in Bridge settings.

### Timeouts

The defaults (`connect_timeout_seconds` of 10,
`command_timeout_seconds` of 30) work well with Proton Bridge. If
Bridge is slow to start or your mailbox is large, increase
`command_timeout_seconds` in the config.

### TLS fingerprint changes

The fingerprint changes when Bridge regenerates its certificate (after
updates or reinstalls). If you get `ERR_TLS` after a Bridge update,
re-run the fingerprint capture from Step 3 and update the config.

### Running headless or over SSH

Proton Bridge and `rusty-imap-mcp` both resolve credentials through the
Linux Secret Service API (`libsecret` / gnome-keyring or KWallet). In a
graphical session, PAM unlocks the login keyring automatically at sign-in;
in a TTY or SSH session it does not, and Bridge fails to start with:

```text
Proton Mail Bridge is not able to detect a supported password manager
(secret-service or pass). Please install and set up a supported password
manager and restart the application.
```

Pick one of the following.

**A. Log in graphically at least once.** Sign in via your display manager
so `pam_gnome_keyring` unlocks the login keyring, then launch Bridge from a
terminal inside that graphical session. SSH sessions spawned afterward also
need `DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$(id -u)/bus` exported so
they can reach the running daemon.

**B. Use `pass` as Bridge's backend (recommended for headless hosts).**
Bridge tries `pass` after Secret Service fails, so a working `pass` store
is sufficient on its own:

```bash
# 1. If you don't already have one, generate a local-use GPG key
chmod 700 ~/.gnupg
gpg --batch --quick-gen-key "bridge-local <you@localhost>" default default never

# 2. Get the key fingerprint
gpg --list-secret-keys --keyid-format=long

# 3. Initialize the password store with that fingerprint
pass init <KEY_FINGERPRINT>

# 4. Re-launch Bridge
protonmail-bridge -c
```

Bridge will store its own credentials under `pass` automatically. You can
then store the Bridge password for `rusty-imap-mcp` the usual way
(Step 4 above) — `rusty-imap-mcp` itself does not require `pass`, only
Bridge does.

**C. Capture the fingerprint from a TTY.** The `openssl` pipeline in
Step 3 works over SSH as long as you can reach `127.0.0.1:1143` from
the shell where Bridge is running. The `-starttls imap` flag is
required regardless of session type.
