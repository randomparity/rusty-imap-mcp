//! Exact compiler-error guard for downstream construction of non-exhaustive records.
//!
//! Stable rustdoc only verifies that `compile_fail` snippets fail, not that they
//! fail with E0639. These probes compile downstream crates against the local
//! `rimap-imap` and `rimap-authz` sources and inspect Cargo's stderr.

#![expect(clippy::expect_used, reason = "integration test setup")]

use std::path::{Path, PathBuf};
use std::process::Command;

use tempfile::TempDir;

fn imap_crate_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

fn authz_crate_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates directory exists")
        .join("rimap-authz")
}

fn cargo_bin() -> PathBuf {
    std::env::var("CARGO").map_or_else(|_| PathBuf::from("cargo"), PathBuf::from)
}

fn check_probe(probe_src: &str) -> (bool, String) {
    let dir = TempDir::new().expect("create probe tempdir");
    let cargo_toml = format!(
        r#"[package]
name = "probe"
version = "0.1.0"
edition = "2024"

[dependencies]
rimap-imap = {{ path = "{imap}" }}
rimap-authz = {{ path = "{authz}" }}
"#,
        imap = imap_crate_root().display(),
        authz = authz_crate_root().display(),
    );

    std::fs::write(dir.path().join("Cargo.toml"), cargo_toml).expect("write probe Cargo.toml");
    std::fs::create_dir_all(dir.path().join("src")).expect("create probe src directory");
    std::fs::write(dir.path().join("src/main.rs"), probe_src).expect("write probe source");

    let output = Command::new(cargo_bin())
        .args(["check", "--message-format=short"])
        .env("CARGO_TARGET_DIR", dir.path().join("target"))
        .current_dir(dir.path())
        .output()
        .expect("run cargo check");

    (
        output.status.success(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

const PROBE_HEADER_SEARCH_LITERAL: &str = r#"
fn main() {
    let _ = rimap_imap::types::HeaderSearch {
        name: "List-Id".to_owned(),
        value: "example.test".to_owned(),
    };
}
"#;

const PROBE_BREAKER_CONFIG_FUNCTIONAL_UPDATE: &str = r"
fn main() {
    let _ = rimap_authz::BreakerConfig {
        error_threshold: 1,
        ..rimap_authz::BreakerConfig::default_spec()
    };
}
";

const PROBE_UNRELATED_FAILURE: &str = r"
fn main() {
    missing_function();
}
";

#[test]
fn non_exhaustive_plain_literal_yields_e0639() {
    let (success, stderr) = check_probe(PROBE_HEADER_SEARCH_LITERAL);
    assert!(!success, "probe must not compile; stderr:\n{stderr}");
    assert!(
        stderr.contains("error[E0639]"),
        "expected error[E0639] in stderr; got:\n{stderr}",
    );
}

#[test]
fn non_exhaustive_functional_update_yields_e0639() {
    let (success, stderr) = check_probe(PROBE_BREAKER_CONFIG_FUNCTIONAL_UPDATE);
    assert!(!success, "probe must not compile; stderr:\n{stderr}");
    assert!(
        stderr.contains("error[E0639]"),
        "expected error[E0639] in stderr; got:\n{stderr}",
    );
}

#[test]
fn non_exhaustive_unrelated_failure_is_not_e0639() {
    let (success, stderr) = check_probe(PROBE_UNRELATED_FAILURE);
    assert!(
        !success,
        "probe with a missing function must not compile; stderr:\n{stderr}",
    );
    assert!(
        !stderr.contains("error[E0639]"),
        "unrelated compile failure must not produce E0639; got:\n{stderr}",
    );
}
