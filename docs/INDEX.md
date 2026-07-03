# Documentation

## Getting started

| Guide | Provider | Time |
|-------|----------|------|
| [Quick start: Gmail](quickstart-gmail.md) | Gmail (app password) | ~10 min |
| [Quick start: Proton Bridge](quickstart-proton-bridge.md) | Proton Mail via Bridge | ~15 min |

Copyable annotated configs: [`config.example.toml`](../config.example.toml)
(single account) and
[`config.multi-account.example.toml`](../config.multi-account.example.toml)
(several mailboxes).

## Configuration and operations

| Document | Description |
|----------|-------------|
| [Configuration reference](configuration.md) | All config fields, types, defaults, and validation rules |
| [Security postures](postures.md) | 4-tier tool matrix, per-tool overrides, folder safety. Also published as the MCP resource `rimap://docs/postures` |
| [Agent workflows](mcp-workflows.md) | search→fetch→act, UIDVALIDITY pinning, attachment retrieval, draft lifecycle, numeric limits. Also published as the MCP resource `rimap://docs/workflows` |
| [Multi-account support](multi-account.md) | Account discovery, selection, per-account isolation |
| [Audit log](audit-log.md) | JSONL format, rotation, merge subcommand, tamper detection |
| [Troubleshooting](troubleshooting.md) | Diagnosing startup failures, where logs go, capturing stderr from GUI MCP clients |

## Security

| Document | Description |
|----------|-------------|
| [Security model](security-model.md) | Threat model, content pipeline, defense layers |
| [SECURITY.md](../SECURITY.md) | Vulnerability disclosure policy, supported versions |
| [Supply-chain watchlist](security/supply-chain-watchlist.md) | Dependency risk tracking |
| [cargo-mutants runbook](security/cargo-mutants-runbook.md) | macOS workaround for sourcefrog/cargo-mutants#611 |

## Architecture (for contributors)

| Document | Description |
|----------|-------------|
| [AGENTS.md](../AGENTS.md) | Developer guide: workspace layout, coding standards, testing |
| [Audit locking](architecture/audit-locking.md) | Mutex discipline for async and audit writer |
| [CHANGELOG.md](../CHANGELOG.md) | Release history |
