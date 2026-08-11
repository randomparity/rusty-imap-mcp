//! Gate for the E0639 error code on `#[non_exhaustive]` record types (#777).
//!
//! rustdoc on stable verifies only that a `compile_fail` snippet fails to
//! compile, not which error code it fails with. So the six
//! `compile_fail,E0639` doctests in `record/mod.rs` would pass even if the
//! `#[non_exhaustive]` attribute were dropped and the snippet failed for some
//! other reason. This test closes that gap by shelling out to `cargo check`
//! on probe snippets that import the real crate and trying to construct two
//! of its `#[non_exhaustive]` types with struct expressions. The output is
//! checked for `error[E0639]` — not merely for a non-zero exit status.
//!
//! Two types are covered: `FolderPolicy` and `ProcessEnd`. Together they
//! exercise the three representative doctest shapes: plain struct literal
//! (`FolderPolicy` first probe), and functional-update spread (`ProcessEnd`
//! second probe as in the `record/mod.rs` doctest).
//!
//! An additional "unrelated failure" probe confirms that checking for
//! `error[E0639]` specifically matters: it defines a plain local struct
//! (not `#[non_exhaustive]`) with a wrong field, which produces `error[E0560]`
//! (unknown field) but not `error[E0639]`. That probe must *not* yield
//! `error[E0639]`, which proves the gate would reject a false positive from
//! an unrelated compile failure.
//!
//! The probes are compiled against the built `rimap-audit` artifact via a
//! minimal temp workspace so no flags or `--extern` paths need to be
//! hand-assembled.

#![expect(clippy::expect_used, reason = "integration test")]

use std::path::{Path, PathBuf};
use std::process::Command;

use tempfile::TempDir;

/// Absolute path to the `rimap-audit` crate root, resolved at compile time.
fn audit_crate_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

/// Absolute path to the `rimap-core` crate root (sibling of rimap-audit).
fn core_crate_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/ dir exists")
        .join("rimap-core")
}

/// The `cargo` binary to use — cargo sets `CARGO` when running tests.
fn cargo_bin() -> PathBuf {
    std::env::var("CARGO").map_or_else(|_| PathBuf::from("cargo"), PathBuf::from)
}

/// Create a minimal two-file temp workspace (`Cargo.toml` + `src/main.rs`)
/// that depends on the local `rimap-audit` and `rimap-core` via path, then
/// run `cargo check` on it and return the full stderr output.
fn check_probe(probe_src: &str) -> (bool, String) {
    let dir = TempDir::new().expect("tempdir");

    let cargo_toml = format!(
        r#"[package]
name = "probe"
version = "0.1.0"
edition = "2024"

[dependencies]
rimap-audit = {{ path = "{audit}" }}
rimap-core = {{ path = "{core}" }}
"#,
        audit = audit_crate_root().display(),
        core = core_crate_root().display(),
    );

    std::fs::write(dir.path().join("Cargo.toml"), cargo_toml).expect("write probe Cargo.toml");
    std::fs::create_dir_all(dir.path().join("src")).expect("create src/");
    std::fs::write(dir.path().join("src").join("main.rs"), probe_src)
        .expect("write probe src/main.rs");

    let output = Command::new(cargo_bin())
        .args(["check", "--message-format=short"])
        .current_dir(dir.path())
        .output()
        .expect("spawn cargo check");

    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    (output.status.success(), stderr)
}

// ---------------------------------------------------------------------------
// Probe sources
// ---------------------------------------------------------------------------

/// Struct literal on `FolderPolicy` — the plain form that E0639 should reject.
const PROBE_FOLDER_POLICY_STRUCT_LITERAL: &str = r#"
fn main() {
    let _ = rimap_audit::record::FolderPolicy {
        account: "work".to_owned(),
        protected_folders: Vec::new(),
        special_use_discovery: rimap_audit::record::SpecialUseDiscovery::Ran,
        expunge_folders: Vec::new(),
    };
}
"#;

/// Functional-update spread on `ProcessEnd` — the `..` form that E0639 should
/// reject (mirrors the second doctest shape in `record/mod.rs`).
const PROBE_PROCESS_END_FUNCTIONAL_UPDATE: &str = r"
fn main() {
    let base = rimap_audit::record::ProcessEnd::new(
        rimap_audit::record::ProcessEndReason::Eof,
        0, 0, 0, 0,
    );
    let _ = rimap_audit::record::ProcessEnd {
        total_tool_calls: 1,
        ..base
    };
}
";

/// Wrong field name on a plain (exhaustive) local struct — this breaks with
/// E0560 ("unknown field"), not E0639. Used to confirm the gate checks the
/// right error code: this probe must NOT yield `error[E0639]`.
///
/// The struct is defined locally in the probe rather than being one of the
/// `#[non_exhaustive]` types from `rimap-audit`. A non-exhaustive type with
/// a wrong field name may produce both E0639 *and* E0560, making the check
/// ambiguous. A plain local struct produces only E0560, which is the
/// unambiguous "not E0639" case the test needs.
const PROBE_UNRELATED_FAILURE: &str = r"
struct Plain {
    x: i32,
}

fn main() {
    let _ = Plain {
        no_such_field: 42,
    };
}
";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Removing `#[non_exhaustive]` from `FolderPolicy` would make this probe
/// compile. Confirm the E0639 gate fires for a struct literal.
#[test]
fn folder_policy_struct_literal_yields_e0639() {
    let (success, stderr) = check_probe(PROBE_FOLDER_POLICY_STRUCT_LITERAL);
    assert!(!success, "probe must not compile; stderr:\n{stderr}");
    assert!(
        stderr.contains("error[E0639]"),
        "expected error[E0639] in stderr; got:\n{stderr}",
    );
}

/// Removing `#[non_exhaustive]` from `ProcessEnd` would make this probe
/// compile. Confirm the E0639 gate fires for a functional-update spread.
#[test]
fn process_end_functional_update_yields_e0639() {
    let (success, stderr) = check_probe(PROBE_PROCESS_END_FUNCTIONAL_UPDATE);
    assert!(!success, "probe must not compile; stderr:\n{stderr}");
    assert!(
        stderr.contains("error[E0639]"),
        "expected error[E0639] in stderr; got:\n{stderr}",
    );
}

/// A probe that fails with an unrelated compile error (unknown field on a
/// plain exhaustive struct) must NOT produce `error[E0639]`, confirming that
/// "fails to compile" and "fails with E0639" are distinct assertions and this
/// test enforces the latter.
#[test]
fn unrelated_compile_failure_does_not_yield_e0639() {
    let (success, stderr) = check_probe(PROBE_UNRELATED_FAILURE);
    assert!(
        !success,
        "probe with unknown field must not compile; stderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("error[E0639]"),
        "an unrelated compile failure must not produce E0639; got:\n{stderr}",
    );
}
