//! Build helpers for the `rusty-imap-mcp` workspace.
//!
//! Exposes a `man` subcommand that generates roff manpages for `rusty-imap-mcp`
//! and all of its subcommands by introspecting the clap CLI tree at
//! `rimap_server::cli::command()`.
//!
//! Run via `cargo run -p xtask --no-default-features -- man [--out DIR]`.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "xtask", about = "Internal build helpers for rusty-imap-mcp")]
struct Xtask {
    #[command(subcommand)]
    cmd: XtaskCmd,
}

#[derive(Subcommand)]
enum XtaskCmd {
    /// Generate roff manpages for `rusty-imap-mcp` and all subcommands.
    Man {
        /// Output directory; created if missing. Defaults to `man/man1` at the
        /// workspace root so packagers can consume a stable path.
        #[arg(long, default_value = "man/man1")]
        out: PathBuf,
    },
}

fn main() -> Result<()> {
    let xtask = Xtask::parse();
    match xtask.cmd {
        XtaskCmd::Man { out } => generate_man(&out),
    }
}

/// Render `rusty-imap-mcp.1` and one page per subcommand into `out`.
fn generate_man(out: &Path) -> Result<()> {
    fs::create_dir_all(out)
        .with_context(|| format!("creating manpage output directory {}", out.display()))?;
    clap_mangen::generate_to(rimap_server::cli::command(), out)
        .with_context(|| format!("writing manpages to {}", out.display()))?;
    Ok(())
}

#[cfg(test)]
// The workspace denies `clippy::unwrap_used`; tests opt out with an #[expect]
// (matches crates/rimap-server/src/cli/mod.rs). Without this, `just lint`
// (`--all-targets -D warnings`) fails on the test's .unwrap()s.
#[expect(clippy::unwrap_used, reason = "tests")]
#[path = "main_tests.rs"]
mod tests;
