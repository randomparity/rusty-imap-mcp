//! End-to-end CLI test: invoke the compiled binary with `--dry-run` against a
//! temp-file config and assert exit code + stdout contents.

#![expect(clippy::unwrap_used, reason = "tests")]

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

fn write_config(dir: &TempDir) -> std::path::PathBuf {
    let audit = dir.path().join("audit.jsonl");
    let path = dir.path().join("config.toml");
    let body = format!(
        r#"
[imap]
host = "127.0.0.1"
port = 1143
username = "alice@example.test"

[security]
posture = "readonly"

[audit]
path = "{}"
allowed_base_dir = "{}"
"#,
        audit.display(),
        dir.path().display()
    );
    std::fs::write(&path, body).unwrap();
    path
}

#[test]
fn dry_run_exits_zero_and_prints_matrix() {
    let dir = TempDir::new().unwrap();
    let config = write_config(&dir);
    Command::cargo_bin("rusty-imap-mcp")
        .unwrap()
        .arg("--config")
        .arg(&config)
        .arg("--dry-run")
        .assert()
        .success()
        .stdout(predicate::str::contains("readonly"))
        .stdout(predicate::str::contains("[ok ] list_folders"))
        .stdout(predicate::str::contains("[deny] create_draft"))
        .stdout(predicate::str::contains("Capabilities"));
}

#[test]
fn missing_config_prints_actionable_first_run_guidance() {
    let dir = TempDir::new().unwrap();
    let missing = dir.path().join("absent.toml");
    Command::cargo_bin("rusty-imap-mcp")
        .unwrap()
        .arg("--config")
        .arg(&missing)
        .arg("--dry-run")
        .assert()
        .failure()
        // stdout is reserved for the MCP transport and must stay clean.
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("No configuration file was found"))
        .stderr(predicate::str::contains("absent.toml"))
        .stderr(predicate::str::contains("config.example.toml"))
        .stderr(predicate::str::contains("docs/quickstart-gmail.md"))
        .stderr(predicate::str::contains("docs/quickstart-proton-bridge.md"));
}

#[test]
fn unknown_tool_override_exits_non_zero() {
    let dir = TempDir::new().unwrap();
    let audit = dir.path().join("audit.jsonl");
    let config = dir.path().join("config.toml");
    let body = format!(
        r#"
[imap]
host = "127.0.0.1"
port = 1143
username = "alice@example.test"

[security.tools]
nuke_inbox = "deny"

[audit]
path = "{}"
allowed_base_dir = "{}"
"#,
        audit.display(),
        dir.path().display()
    );
    std::fs::write(&config, body).unwrap();
    Command::cargo_bin("rusty-imap-mcp")
        .unwrap()
        .arg("--config")
        .arg(&config)
        .arg("--dry-run")
        .assert()
        .failure()
        .stderr(predicate::str::contains("nuke_inbox"));
}
