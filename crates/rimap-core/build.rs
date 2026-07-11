//! Compile-time version composer for rusty-imap-mcp.
//!
//! Emits three `cargo:rustc-env` variables consumed by `src/version.rs`:
//!
//! - `RIMAP_VERSION` — the user-facing version string. Bare `CARGO_PKG_VERSION`
//!   when HEAD is exactly the tag `v<CARGO_PKG_VERSION>` (a clean base);
//!   otherwise `<CARGO_PKG_VERSION>+g<short-sha>[.dirty]`. The `-dev`
//!   pre-release now lives in `Cargo.toml` (the next planned version), so this
//!   script only appends git provenance — it never synthesizes `-dev`.
//! - `RIMAP_COMMIT` — the short SHA (or `unknown` outside a git checkout).
//! - `RIMAP_RELEASE` — `"true"` or `"false"` depending on the release/dev path.
//!
//! Every git failure path falls back to `RIMAP_VERSION =
//! <CARGO_PKG_VERSION>+gunknown`, so vendored or `cargo package` builds
//! still compile without surprise breakage.

use std::process::Command;

fn main() {
    let base = std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".to_string());
    let expected_tag = format!("v{base}");

    let exact_tag = run_git(&["describe", "--tags", "--exact-match", "HEAD"]);
    let short_sha =
        run_git(&["rev-parse", "--short=7", "HEAD"]).unwrap_or_else(|| "unknown".to_string());
    let dirty = run_git(&["status", "--porcelain"]).is_some_and(|s| !s.is_empty());

    let is_release = exact_tag.as_deref() == Some(expected_tag.as_str());
    let (version, commit) = if is_release {
        (base.clone(), short_sha.clone())
    } else {
        let suffix = if dirty {
            format!("+g{short_sha}.dirty")
        } else {
            format!("+g{short_sha}")
        };
        let commit = if dirty {
            format!("{short_sha}-dirty")
        } else {
            short_sha.clone()
        };
        (format!("{base}{suffix}"), commit)
    };

    println!("cargo:rustc-env=RIMAP_VERSION={version}");
    println!("cargo:rustc-env=RIMAP_COMMIT={commit}");
    println!(
        "cargo:rustc-env=RIMAP_RELEASE={}",
        if is_release { "true" } else { "false" }
    );
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/tags");
    println!("cargo:rerun-if-changed=.git/packed-refs");
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
}

fn run_git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let s = String::from_utf8(output.stdout).ok()?.trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}
