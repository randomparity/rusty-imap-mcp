//! Build-injected version metadata.
//!
//! Values are produced by `build.rs` and embedded via `env!`. They are
//! string slices with `'static` lifetime, suitable for direct use in
//! `clap`'s `version = ...` attribute and any other place that wants a
//! `&'static str`.

/// The user-facing version string.
///
/// `X.Y.Z` for release builds (HEAD is exactly the tag `v<X.Y.Z>`);
/// `X.Y.Z[-dev]+g<short-sha>[.dirty]` otherwise, where the `-dev` (if any)
/// comes from the workspace `Cargo.toml` version, not from `build.rs`.
/// Outside a git checkout the suffix is `+gunknown`.
#[must_use]
pub fn version() -> &'static str {
    env!("RIMAP_VERSION")
}

/// Short git SHA of the build (`abc1234`), `abc1234-dirty` for dirty
/// worktrees, or `unknown` when no git information is available.
#[must_use]
pub fn commit() -> &'static str {
    env!("RIMAP_COMMIT")
}

/// `true` when this build was produced from a `vX.Y.Z` git tag whose
/// version matches the workspace `Cargo.toml`.
#[must_use]
pub fn is_release() -> bool {
    matches!(env!("RIMAP_RELEASE"), "true")
}
