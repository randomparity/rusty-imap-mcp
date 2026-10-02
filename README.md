<p align="center">
  <img src="docs/assets/rusty-imap-mcp-logo.svg" width="320" alt="rusty-imap-mcp">
</p>

# rusty-imap-mcp

<p align="center">
  A security-first MCP server that gives coding agents controlled access to IMAP email.
</p>

<p align="center">
  <a href="https://github.com/randomparity/rusty-imap-mcp/actions/workflows/ci.yml"><img src="https://github.com/randomparity/rusty-imap-mcp/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/randomparity/rusty-imap-mcp/releases"><img src="https://img.shields.io/github/v/release/randomparity/rusty-imap-mcp" alt="Latest release"></a>
  <a href="https://github.com/randomparity/rusty-imap-mcp/blob/main/LICENSE-MIT"><img src="https://img.shields.io/badge/license-MIT%20%2F%20Apache--2.0-blue" alt="MIT or Apache-2.0 license"></a>
  <a href="https://github.com/randomparity/rusty-imap-mcp/blob/main/rust-toolchain.toml"><img src="https://img.shields.io/badge/MSRV-1.88.0-orange" alt="MSRV 1.88.0"></a>
</p>

## Email is untrusted input

An email-connected agent can search a mailbox, summarize a thread, prepare a reply, or organize
messages without leaving the coding workflow. It can also encounter a crafted message that tries
to redirect the agent, exfiltrate data, or trigger a more powerful tool.

`rusty-imap-mcp` treats every byte of email content as adversarial. It parses, sanitizes,
normalizes, and labels content before an agent sees it. Trusted metadata stays structurally
separate from untrusted message text and explicit security warnings. Authorization postures then
limit what the agent can do with that content.

It is written in Rust and ships as one binary. Proton Mail through Proton Bridge is the primary
target, with support for standard IMAP servers such as Gmail, Fastmail, Dovecot, and Cyrus.

## Features

- **Layered content defense** — strips hidden HTML, invisible Unicode controls, bidi tricks, and
  look-alike identifiers; normalizes text; and reports what it found in `security_warnings`.
- **Four authorization postures** — `readonly`, `draft-safe` (default), `full`, and `destructive`,
  plus per-tool overrides. Denied tools are not advertised to the agent.
- **24 MCP tools** — search and fetch mail, manage flags and folders, download attachments, create
  drafts, and—with an explicit posture—send, forward, move, or delete messages.
- **Human-reviewed drafts** — new drafts receive the `$PendingReview` flag so an agent can prepare
  mail without silently bypassing review.
- **Multi-account isolation** — each account has its own posture, limits, circuit breaker, and
  credential lookup.
- **Audit and containment** — append-only JSONL audit records, rate limiting, a circuit breaker,
  TLS certificate pinning, bounded attachment paths, and OS-keychain credential storage.
- **Portable deployment** — Homebrew, `.deb` and `.rpm` packages, a verified installer path, and
  release binaries for five Linux and macOS targets.

See the [security model](docs/security-model.md), [posture matrix](docs/postures.md), and
[complete tool reference](docs/tools.md) for the exact guarantees and capabilities.

## Quick start

### 1. Install the binary

Homebrew is the shortest path on macOS and supported Linux hosts:

```bash
brew install randomparity/tap/rusty-imap-mcp
rusty-imap-mcp --version
```

Packages, release tarballs, checksums, and provenance attestations are available on the
[releases page](https://github.com/randomparity/rusty-imap-mcp/releases). To build from source:

```bash
cargo install rimap-server --locked --bin rusty-imap-mcp
```

Rust 1.88.0 or newer is required for a source build. Linux source builds also need the system
D-Bus development package. See [Installation options](#installation-options) for package and
verification details.

### 2. Connect an email account

Choose the provider guide that matches your mailbox:

- [Gmail quick start](docs/quickstart-gmail.md) — about 10 minutes with a Google App Password.
- [Proton Bridge quick start](docs/quickstart-proton-bridge.md) — about 15 minutes, including the
  self-signed TLS certificate pin.

For Fastmail or another standards-compliant server, start with the Gmail guide and substitute the
provider's IMAP host, port, encryption mode, and app-password instructions. The server reads its
configuration from the platform config directory and resolves passwords from the OS keychain;
credentials do not belong in the TOML file.

Before connecting an agent, verify configuration and TLS without starting the MCP transport:

```bash
rusty-imap-mcp --dry-run
```

### 3. Connect your coding agent

Choose one client below. Each example registers the installed binary as a local stdio MCP server;
`rusty-imap-mcp` continues to read the account configuration created in step 2.

#### Claude Code

```bash
claude mcp add --scope user rusty-imap-mcp -- rusty-imap-mcp
claude mcp get rusty-imap-mcp
```

See [Claude Code MCP configuration](https://docs.anthropic.com/en/docs/claude-code/mcp).

#### Codex

```bash
codex mcp add rusty-imap-mcp -- rusty-imap-mcp
codex mcp list
```

The Codex CLI and IDE extension share `~/.codex/config.toml`. See the
[official OpenAI MCP documentation](https://developers.openai.com/codex/mcp/).

#### Cursor

Add this server to the `mcpServers` object in `~/.cursor/mcp.json`, or use
`.cursor/mcp.json` in one project:

```json
{
  "mcpServers": {
    "rusty-imap-mcp": {
      "command": "rusty-imap-mcp"
    }
  }
}
```

See [Cursor MCP configuration](https://docs.cursor.com/context/model-context-protocol).

#### VS Code with GitHub Copilot

Create `.vscode/mcp.json` in a project, or run **MCP: Open User Configuration** for a user-level
server:

```json
{
  "servers": {
    "rusty-imap-mcp": {
      "type": "stdio",
      "command": "rusty-imap-mcp"
    }
  }
}
```

Start the server from the editor and approve its tools when prompted. See
[MCP servers in VS Code](https://code.visualstudio.com/docs/agent-customization/mcp-servers).

#### IBM Bob

Create `.bob/mcp.json` in the project, or edit the global MCP file from Bob's MCP settings:

```json
{
  "mcpServers": {
    "rusty-imap-mcp": {
      "command": "rusty-imap-mcp",
      "alwaysAllow": [],
      "disabled": false
    }
  }
}
```

Keep `alwaysAllow` empty until you have reviewed the advertised tools, then restart the server in
Bob. See [Using MCP in IBM Bob](https://bob.ibm.com/docs/ide/configuration/mcp/mcp-in-bob).

> **Running more than one client:** each client starts a separate server process, and the audit
> log permits one writer. Give concurrent clients separate `--config` files with distinct audit
> paths; see [Running multiple MCP clients](docs/audit-log.md#running-multiple-mcp-clients).

Try a read-only first prompt after the tools appear: “List my inbox folders, then show the five
newest message subjects.” Keep the default `draft-safe` posture until you intentionally need
sending or destructive operations.

## How the security boundary works

Every tool response separates three kinds of information:

- `meta` contains server-derived identifiers and operation facts.
- `untrusted` contains sanitized mailbox content that an email sender could influence.
- `security_warnings` names suspicious transformations or identity signals.

The active posture controls both tool advertisement and dispatch. `draft-safe` permits reading,
organization, and draft creation but denies sending and destructive operations. Content-search
queries, raw sanitized HTML, and HTML draft bodies are independently gated at `full` posture.
`export_messages` is denied in every posture until explicitly allowed.

The server supports MCP protocol version `2025-11-25`. An older client fails the handshake instead
of connecting with reduced behavior. See [protocol troubleshooting](docs/troubleshooting.md#unsupported-protocol-version-during-initialize)
if initialization reports an unsupported version.

## Installation options

### Homebrew

```bash
brew install randomparity/tap/rusty-imap-mcp
```

Prebuilt bottles support Apple Silicon macOS and x86_64/aarch64 Linux. Intel Macs build from
source. See the [Homebrew notes](homebrew/README.md).

### Debian and RPM packages

Download the matching `.deb` or `.rpm` from the
[latest release](https://github.com/randomparity/rusty-imap-mcp/releases), then install it with
the platform package manager:

```bash
sudo apt install ./rusty-imap-mcp_X.Y.Z-1_amd64.deb
# or
sudo dnf install ./rusty-imap-mcp-X.Y.Z-1.x86_64.rpm
```

Packages are available for amd64 and arm64 and include manpages. They target glibc 2.36 or newer.

### Release tarballs and installer

Releases include five target tarballs, `SHA256SUMS.txt`, and build provenance attestations. The
convenience installer downloads the latest stable binary:

```bash
curl -fsSL https://raw.githubusercontent.com/randomparity/rusty-imap-mcp/main/install.sh | sh
```

The piped script trusts GitHub over TLS; it is not independently authenticated. For a verifiable
path, download a pinned release's `install.sh` and `SHA256SUMS.txt`, verify the script before
running it, and verify the selected artifact with
[`gh attestation verify`](https://cli.github.com/manual/gh_attestation_verify).

### Build from a checkout

```bash
git clone https://github.com/randomparity/rusty-imap-mcp.git
cd rusty-imap-mcp
cargo build --release
```

The binary is written to `target/release/rusty-imap-mcp`.

## Documentation

- [Gmail quick start](docs/quickstart-gmail.md)
- [Proton Bridge quick start](docs/quickstart-proton-bridge.md)
- [Configuration reference](docs/configuration.md)
- [Security model](docs/security-model.md) and [posture matrix](docs/postures.md)
- [Multi-account setup](docs/multi-account.md)
- [Audit log](docs/audit-log.md)
- [Tool reference](docs/tools.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Full documentation index](docs/INDEX.md)

## Development

The workspace uses Rust 1.94.0 for development and verifies Rust 1.88.0 as its MSRV. Repository
checks are wrapped in `just` so local and CI commands stay aligned:

```bash
just setup
just check
just test-fast
just ci
```

See [AGENTS.md](AGENTS.md) for contributor guardrails and the design specifications under
[`docs/superpowers/specs/`](docs/superpowers/specs/).

## Troubleshooting

- **`Connection closed` or `MCP error -32000` at startup:** run `rusty-imap-mcp --dry-run`, then
  inspect the client's MCP stderr log. See the [startup workflow](docs/troubleshooting.md).
- **`audit file ... is already locked`:** another server process owns that audit file. Use a
  distinct configuration and audit path for each concurrent client.
- **Unsupported protocol version:** update the MCP client to one that negotiates `2025-11-25`.

## License and security

Dual-licensed under MIT or Apache-2.0. See [LICENSE-MIT](LICENSE-MIT) and
[LICENSE-APACHE](LICENSE-APACHE).

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).
