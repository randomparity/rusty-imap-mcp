//! CLI definitions for `rusty-imap-mcp`.
//!
//! Top-level flags:
//!   - `--config <path>` — explicit config path (else env var, else XDG default).
//!   - `--dry-run` — load config, print effective matrix, exit.
//!
//! Subcommand:
//!   - `login` — interactively store a credential in the keychain.
//!   - `audit <action>` — audit log inspection utilities (see `AuditAction`).

pub mod audit_merge;
pub mod dry_run;
#[cfg(feature = "test-support")]
pub mod dump_tool_catalog;
#[cfg(feature = "test-support")]
pub mod dump_tool_doc;
#[cfg(feature = "test-support")]
pub mod dump_tool_schemas;
pub mod migrate_keyring;

use std::path::PathBuf;

use clap::{CommandFactory, Parser, Subcommand};
use rimap_core::account::DEFAULT_ACCOUNT_NAME;

/// Top-level CLI.
#[derive(Debug, Parser)]
#[command(
    name = "rusty-imap-mcp",
    about = "Security-first MCP server for IMAP email access",
    long_about = "rusty-imap-mcp is a security-first Model Context Protocol (MCP) server that \
exposes an IMAP mailbox (Proton Mail via Proton Bridge, or any standard IMAP server such as \
Dovecot, Cyrus, or Gmail with an app password) to an MCP client over stdio.\n\n\
It treats every byte of email as untrusted adversarial input: message bodies, headers, and \
attachment metadata are aggressively sanitized and structurally tagged, Unicode is normalized, \
look-alike characters are flagged, and each tool is gated by a configurable authorization \
posture (readonly, draft-safe, full, or destructive). Every action is recorded in an \
append-only, exclusively-locked audit log.\n\n\
Run with no subcommand to start the server loop, which speaks JSON-RPC over stdin and stdout; \
all diagnostics go to stderr (stdout is reserved for the MCP transport). Configuration is \
resolved from --config, then the RUSTY_IMAP_MCP_CONFIG environment variable, then the platform \
default (~/.config/rusty-imap-mcp/config.toml on Linux). Log verbosity is controlled by \
RIMAP_LOG or RUST_LOG (default: info). Store credentials with the 'login' subcommand before \
first use.",
    after_long_help = "EXAMPLES:\n  \
Store an IMAP credential in the OS keychain (run once per account):\n    \
rusty-imap-mcp login --host 127.0.0.1 --username alice@example.com\n\n  \
Validate configuration and print the effective tool matrix, then exit:\n    \
rusty-imap-mcp --dry-run\n\n  \
Start the server against an explicit config with debug logging (as an MCP client\n  \
would spawn it):\n    \
RIMAP_LOG=debug rusty-imap-mcp --config ~/.config/rusty-imap-mcp/config.toml\n\n  \
Inspect the audit log, filtering to one tool since a timestamp:\n    \
rusty-imap-mcp audit merge ~/.local/state/rusty-imap-mcp/audit.jsonl --tool search \\\n      \
--since 2026-01-01T00:00:00Z"
)]
pub struct Cli {
    /// Path to the config file. Overrides the `RUSTY_IMAP_MCP_CONFIG`
    /// environment variable and the platform default.
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

    /// Subcommand (optional; with none, the default is the MCP server loop).
    #[command(subcommand)]
    pub command: Option<Command>,
}

/// The fully-configured top-level [`clap::Command`], carrying the runtime
/// version string.
///
/// Shared by the binary's argument parser (`main.rs`) and the `xtask` manpage
/// generator so generated pages match the CLI users actually run.
#[must_use]
pub fn command() -> clap::Command {
    <Cli as CommandFactory>::command().version(rimap_core::version::version())
}

/// Supported subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Interactively store IMAP credentials in the OS keychain.
    #[command(
        long_about = "Prompt for an IMAP password and store it in the operating system's keychain \
(Keychain on macOS, Secret Service / libsecret on Linux) so the server can authenticate without \
the secret ever being written to the config file or process arguments.\n\n\
Run this once per account before starting the server. The credential is keyed by \
account/username@host, so re-running it for the same triple overwrites the stored password.",
        after_long_help = "EXAMPLES:\n  \
Store the password for the default account against a local Proton Bridge:\n    \
rusty-imap-mcp login --host 127.0.0.1 --username alice@example.com\n\n  \
Store a credential for a named account from the config:\n    \
rusty-imap-mcp login --account work --host imap.example.com --username alice"
    )]
    Login {
        /// Account name from config. Defaults to "default", matching the
        /// synthetic account used for legacy single-account configs.
        #[arg(long, default_value_t = String::from(DEFAULT_ACCOUNT_NAME))]
        account: String,
        /// IMAP host (for example 127.0.0.1 for Proton Bridge).
        #[arg(long)]
        host: String,
        /// IMAP username (for example alice@example.com).
        #[arg(long)]
        username: String,
    },
    /// Migrate a stored credential to the namespaced keyring key format.
    #[command(
        long_about = "Move a stored credential from the legacy keyring key format \
(username@host) to the account-scoped format (account-id/username@host).\n\n\
Multi-account support made the account id part of the keyring key, so a credential stored by an \
older single-account build is not found under the new scheme. Run this once per account after \
upgrading to re-key the existing secret; it is a no-op if the credential is already namespaced.",
        after_long_help = "EXAMPLES:\n  \
Re-key the 'work' account's stored credential:\n    \
rusty-imap-mcp migrate-keyring --account work --host imap.example.com --username alice"
    )]
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
    #[command(
        long_about = "Inspect the append-only audit log the server writes for every action. \
See the 'merge' subcommand to stream and filter records."
    )]
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
    #[command(
        long_about = "Read an append-only audit file and write its records as line-delimited \
JSON to stdout, applying the given filters. Filters combine with AND; omitting all of them \
streams the whole file.\n\n\
Output is intended for piping into jq or another JSONL tool. Note that redirecting stdout to a \
file uses the shell's umask, which is typically world-readable — set 'umask 077' in the same \
command, or pipe through 'install -m 0600', to keep the dump private.",
        after_long_help = "EXAMPLES:\n  \
Show every record for the 'search' tool since a timestamp:\n    \
rusty-imap-mcp audit merge audit.jsonl --tool search --since 2026-01-01T00:00:00Z\n\n  \
Write a private dump of one account's records:\n    \
umask 077 && rusty-imap-mcp audit merge audit.jsonl --account work > dump.jsonl"
    )]
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
        /// Only include records whose tool field matches this string.
        #[arg(long)]
        tool: Option<String>,
        /// Only include records whose kind field matches this string.
        #[arg(long)]
        kind: Option<String>,
        /// Only include records whose `process_id` matches this ULID.
        #[arg(long)]
        process: Option<String>,
        /// Only include records whose account field matches this name.
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
    fn command_builder_exposes_production_subcommands() {
        let cmd = crate::cli::command();
        assert_eq!(cmd.get_name(), "rusty-imap-mcp");
        assert!(cmd.get_version().is_some(), "version must be wired");
        let subs: Vec<&str> = cmd.get_subcommands().map(clap::Command::get_name).collect();
        for expected in ["login", "audit", "migrate-keyring"] {
            assert!(
                subs.contains(&expected),
                "missing subcommand {expected}; got {subs:?}"
            );
        }
    }

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
