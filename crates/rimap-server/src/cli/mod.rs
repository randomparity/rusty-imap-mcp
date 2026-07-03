//! CLI definitions for `rusty-imap-mcp`.
//!
//! Top-level flags:
//!   - `--config <path>` — explicit config path (else env var, else XDG default).
//!   - `--dry-run` — load config, print effective matrix, exit.
//!
//! Subcommand:
//!   - `login` — interactively store a credential in the keychain.
//!   - `audit <action>` — audit log inspection utilities (see `AuditAction`).

pub(crate) mod audit_merge;
pub(crate) mod dry_run;
#[cfg(feature = "test-support")]
pub(crate) mod dump_tool_catalog;
#[cfg(feature = "test-support")]
pub(crate) mod dump_tool_doc;
#[cfg(feature = "test-support")]
pub(crate) mod dump_tool_schemas;
pub(crate) mod migrate_keyring;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use rimap_core::account::DEFAULT_ACCOUNT_NAME;

/// Top-level CLI.
#[derive(Debug, Parser)]
#[command(
    name = "rusty-imap-mcp",
    about = "Security-first MCP server for IMAP email access"
)]
pub struct Cli {
    /// Path to the config file. Overrides `RUSTY_IMAP_MCP_CONFIG` and the
    /// platform default.
    #[arg(long, value_name = "PATH", env = "RUSTY_IMAP_MCP_CONFIG")]
    pub config: Option<PathBuf>,

    /// Load the config, print the effective tool matrix, and exit.
    /// Mutually exclusive with subcommands.
    #[arg(long)]
    pub dry_run: bool,

    /// Skip the empty-accounts rejection in `rimap_config::validate_multi`.
    /// Used by the wire-conformance harness (#263) so the binary can
    /// boot with `accounts = []`. Hidden from `--help` because it is a
    /// test-only knob; compiled out entirely when the `test-support`
    /// feature is off.
    #[cfg(feature = "test-support")]
    #[arg(long, hide = true)]
    pub allow_empty_accounts: bool,

    /// Subcommand (optional; default is the MCP server loop — not yet implemented).
    #[command(subcommand)]
    pub command: Option<Command>,
}

/// Supported subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Interactively store IMAP credentials in the OS keychain.
    Login {
        /// Account name from config. Defaults to `default`, matching the
        /// synthetic account used for legacy single-account configs.
        #[arg(long, default_value_t = String::from(DEFAULT_ACCOUNT_NAME))]
        account: String,
        /// IMAP host (e.g. `127.0.0.1` for Proton Bridge).
        #[arg(long)]
        host: String,
        /// IMAP username (e.g. `alice@example.com`).
        #[arg(long)]
        username: String,
    },
    /// Migrate a credential from the legacy keyring key format
    /// (`<username>@<host>`) to the new namespaced format
    /// (`<account-id>/<username>@<host>`). Run once per account after
    /// upgrading across #77.
    MigrateKeyring {
        /// Account name from config.
        #[arg(long)]
        account: String,
        /// IMAP host.
        #[arg(long)]
        host: String,
        /// IMAP username.
        #[arg(long)]
        username: String,
    },
    /// Audit log inspection utilities.
    Audit {
        /// Audit subcommand.
        #[command(subcommand)]
        action: AuditAction,
    },
    /// Print the static MCP tool catalog as line-delimited JSON to
    /// stdout. Used by the Phase 2 Node conformance harness (#264) to
    /// validate every tool's `inputSchema` through the SDK's Zod Tool
    /// definition without standing up a configured account or live
    /// IMAP server. Hidden from `--help` because it is a test-only
    /// utility; compiled out entirely when the `test-support` feature
    /// is off.
    #[cfg(feature = "test-support")]
    #[command(name = "dump-tool-catalog", hide = true)]
    DumpToolCatalog,
    /// Emit per-tool JSON Schemas (one entry per in-scope tool,
    /// composing `<Tool>Meta` and `<Tool>Untrusted` into a single
    /// `{meta, untrusted}` envelope) as pretty JSON on stdout. Used
    /// by the Phase 3 wire-conformance harness (#265) and the
    /// `just regen-tool-schemas` recipe. Hidden from `--help` because
    /// it is a test-only utility.
    #[cfg(feature = "test-support")]
    #[command(name = "dump-tool-schemas", hide = true)]
    DumpToolSchemas,
    /// Emit per-tool documentation records (title, description, min
    /// posture, and input/output schemas) as line-delimited JSON on
    /// stdout. Consumed by `scripts/gen-tools-doc.py` via
    /// `just gen-tools-doc` to render `docs/tools.md` (#413). Hidden from
    /// `--help` because it is a test-only utility.
    #[cfg(feature = "test-support")]
    #[command(name = "dump-tool-doc", hide = true)]
    DumpToolDoc,
}

/// Actions under `rusty-imap-mcp audit <action>`.
#[derive(Debug, Subcommand)]
pub enum AuditAction {
    /// Stream the active (or rotated) audit file as filtered JSONL on stdout.
    Merge {
        /// Path to an audit file.
        #[arg(value_name = "PATH")]
        path: std::path::PathBuf,
        /// Only include records at or after this RFC 3339 timestamp.
        #[arg(long)]
        since: Option<String>,
        /// Only include records at or before this RFC 3339 timestamp.
        #[arg(long)]
        until: Option<String>,
        /// Only include records whose `tool` field matches this string.
        #[arg(long)]
        tool: Option<String>,
        /// Only include records whose `kind` field matches this string.
        #[arg(long)]
        kind: Option<String>,
        /// Only include records whose `process_id` matches this ULID.
        #[arg(long)]
        process: Option<String>,
        /// Only include records whose `account` field matches this name.
        #[arg(long)]
        account: Option<String>,
    },
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
#[expect(clippy::panic, reason = "tests")]
mod tests {
    use clap::Parser;
    use rimap_core::account::DEFAULT_ACCOUNT_NAME;

    use crate::cli::{Cli, Command};

    #[test]
    fn parses_dry_run_with_config() {
        let cli = Cli::try_parse_from(["rusty-imap-mcp", "--config", "/tmp/x.toml", "--dry-run"])
            .unwrap();
        assert_eq!(
            cli.config.as_deref(),
            Some(std::path::Path::new("/tmp/x.toml"))
        );
        assert!(cli.dry_run);
        assert!(cli.command.is_none());
    }

    #[test]
    fn parses_login_subcommand() {
        let cli = Cli::try_parse_from([
            "rusty-imap-mcp",
            "login",
            "--host",
            "127.0.0.1",
            "--username",
            "alice",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Login {
                account,
                host,
                username,
            }) => {
                assert_eq!(account, DEFAULT_ACCOUNT_NAME);
                assert_eq!(host, "127.0.0.1");
                assert_eq!(username, "alice");
            }
            other => panic!("expected Login, got {other:?}"),
        }
    }

    #[test]
    fn parses_login_subcommand_with_explicit_account() {
        let cli = Cli::try_parse_from([
            "rusty-imap-mcp",
            "login",
            "--account",
            "work",
            "--host",
            "127.0.0.1",
            "--username",
            "alice",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Login {
                account,
                host,
                username,
            }) => {
                assert_eq!(account, "work");
                assert_eq!(host, "127.0.0.1");
                assert_eq!(username, "alice");
            }
            other => panic!("expected Login, got {other:?}"),
        }
    }

    #[test]
    fn no_args_is_valid_and_defaults() {
        let cli = Cli::try_parse_from(["rusty-imap-mcp"]).unwrap();
        assert!(!cli.dry_run);
        assert!(cli.command.is_none());
    }

    #[test]
    fn parses_audit_merge_with_all_filters() {
        let cli = Cli::try_parse_from([
            "rusty-imap-mcp",
            "audit",
            "merge",
            "/tmp/audit.jsonl",
            "--since",
            "2026-04-07T00:00:00Z",
            "--until",
            "2026-04-08T00:00:00Z",
            "--tool",
            "search",
            "--kind",
            "tool_end",
            "--process",
            "01JXAAAAAAAAAAAAAAAAAAAAAA",
            "--account",
            "work",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Audit {
                action:
                    crate::cli::AuditAction::Merge {
                        path,
                        since,
                        until,
                        tool,
                        kind,
                        process,
                        account,
                    },
            }) => {
                assert_eq!(path, std::path::PathBuf::from("/tmp/audit.jsonl"));
                assert_eq!(since.as_deref(), Some("2026-04-07T00:00:00Z"));
                assert_eq!(until.as_deref(), Some("2026-04-08T00:00:00Z"));
                assert_eq!(tool.as_deref(), Some("search"));
                assert_eq!(kind.as_deref(), Some("tool_end"));
                assert_eq!(process.as_deref(), Some("01JXAAAAAAAAAAAAAAAAAAAAAA"));
                assert_eq!(account.as_deref(), Some("work"));
            }
            other => panic!("expected Audit::Merge, got {other:?}"),
        }
    }
}
