//! Smoke tests for the build-injected version metadata.

use rimap_core::version::{commit, is_release, version};

#[test]
fn version_is_non_empty() {
    let v = version();
    assert!(!v.is_empty(), "version() must not be empty");
}

#[test]
fn version_starts_with_workspace_base() {
    let v = version();
    assert!(
        v.starts_with(env!("CARGO_PKG_VERSION")),
        "version() = {v:?} should start with CARGO_PKG_VERSION = {:?}",
        env!("CARGO_PKG_VERSION")
    );
}

#[test]
fn commit_matches_expected_shape() {
    let c = commit();
    // Either the sentinel `unknown` or a 7-hex SHA with an optional `-dirty` suffix.
    let body = c.strip_suffix("-dirty").unwrap_or(c);
    let valid =
        body == "unknown" || (body.len() == 7 && body.chars().all(|ch| ch.is_ascii_hexdigit()));
    assert!(
        valid,
        "commit() = {c:?} should be `unknown`, `<7hex>`, or `<7hex>-dirty`"
    );
}

#[test]
fn build_script_does_not_synthesize_dev_suffix() {
    // Any `-dev` must come from the manifest base (CARGO_PKG_VERSION), never
    // from build.rs. Inspect only the part build.rs appended to the base.
    let v = version();
    let base = env!("CARGO_PKG_VERSION");
    let appended = v.strip_prefix(base).unwrap_or(v);
    assert!(
        !appended.contains("-dev"),
        "build.rs must not synthesize -dev; version() = {v:?}, base = {base:?}"
    );
}

#[test]
fn release_flag_agrees_with_version_shape() {
    let v = version();
    // A release build is exactly one with no `+g…` build-metadata suffix:
    // release = clean base; dev / release-prep / no-git all carry `+g…`.
    let has_build_metadata = v.contains("+g");
    assert_eq!(
        is_release(),
        !has_build_metadata,
        "is_release() must be true exactly when version() lacks a +g build-metadata suffix"
    );
}
