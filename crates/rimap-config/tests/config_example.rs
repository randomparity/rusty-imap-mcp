//! Drift guard for the repo-root example configs.
//!
//! `config.example.toml` (single-account, flat) and
//! `config.multi-account.example.toml` (`[[accounts]]`) ship as the canonical,
//! copyable configuration examples. If a field is renamed, removed, or retyped
//! in `rimap-config`, deserialization here fails and CI goes red — the example
//! can never silently drift from the schema.
//!
//! The examples carry illustrative filesystem paths (audit log, download
//! directory) that will not exist on a CI runner, so path-shaped validation is
//! retargeted at a fresh tempdir. Everything else — schema (`deny_unknown_fields`),
//! tool-name resolution, limit invariants, folder safety, SMTP encryption —
//! runs against the real values from the file.

#![expect(clippy::expect_used, reason = "integration test")]

use std::path::{Path, PathBuf};

use rimap_config::{
    AttachmentsConfig, AuditConfig, Config, MultiAccountConfig, load_from_path,
    validate_legacy_as_multi, validate_multi,
};
use tempfile::TempDir;

/// Repo root, derived from this crate's manifest dir (`<root>/crates/rimap-config`).
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("resolve repo root")
}

/// Point audit + attachment paths at `dir` so filesystem-shaped validation
/// (writable-dir probe, audit-path containment, export-root permissions)
/// passes on any host, while the schema and every non-path semantic rule
/// still validate the file's real values.
fn retarget_paths(audit: &mut AuditConfig, attachments: &mut AttachmentsConfig, dir: &Path) {
    audit.path = dir.join("audit.jsonl");
    audit.allowed_base_dir = Some(dir.to_path_buf());
    if !attachments.download_dir.is_empty() {
        attachments.download_dir = dir.to_string_lossy().into_owned();
    }
}

#[test]
fn flat_example_parses_and_validates() {
    let path = repo_root().join("config.example.toml");
    let mut config: Config = load_from_path(&path).expect("deserialize config.example.toml");
    let tmp = TempDir::new().expect("tempdir");
    retarget_paths(&mut config.audit, &mut config.attachments, tmp.path());
    validate_legacy_as_multi(config).expect("validate config.example.toml");
}

#[test]
fn multi_account_example_parses_and_validates() {
    let path = repo_root().join("config.multi-account.example.toml");
    let contents = std::fs::read_to_string(&path).expect("read config.multi-account.example.toml");
    let mut config: MultiAccountConfig =
        toml::from_str(&contents).expect("deserialize config.multi-account.example.toml");
    let tmp = TempDir::new().expect("tempdir");
    retarget_paths(&mut config.audit, &mut config.attachments, tmp.path());
    validate_multi(config).expect("validate config.multi-account.example.toml");
}
