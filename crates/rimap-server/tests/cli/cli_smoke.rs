//! Smoke tests for the user-visible `--version` output.

use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn version_flag_prints_expected_shape() {
    #[expect(
        clippy::expect_used,
        reason = "test scaffold: panic on missing binary is intentional"
    )]
    Command::cargo_bin("rusty-imap-mcp")
        .expect("binary exists")
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::starts_with("rusty-imap-mcp "))
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));
}
