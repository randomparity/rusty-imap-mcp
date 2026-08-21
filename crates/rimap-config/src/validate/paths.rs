//! Path-shaped checks: writable-directory probes, audit retention sanity,
//! and audit-path containment within the configured (or platform-default)
//! base.

use std::path::{Path, PathBuf};

use crate::error::ConfigError;
use crate::model::{AttachmentsConfig, AuditConfig};

pub(super) fn validate_audit_config(audit: &AuditConfig) -> Result<(), ConfigError> {
    if audit.retention_seconds == Some(0) {
        return Err(ConfigError::InvalidLimit {
            field: "audit.retention_seconds",
            reason: "must be > 0 (use None / omit the field to disable \
                     time-based retention)"
                .to_string(),
        });
    }
    Ok(())
}

pub(super) fn validate_paths_multi(
    audit: &AuditConfig,
    attachments: &AttachmentsConfig,
) -> Result<(), ConfigError> {
    let audit_parent = audit
        .path
        .parent()
        .ok_or_else(|| ConfigError::PathNotWritable {
            path: audit.path.clone(),
            reason: "audit path has no parent directory".to_string(),
        })?;
    require_writable_dir(audit_parent)?;
    enforce_audit_containment(audit)?;
    if !attachments.download_dir.is_empty() {
        require_writable_dir(Path::new(&attachments.download_dir))?;
    }
    Ok(())
}

/// Fail-closed precondition for `export_messages`: when the tool is
/// enabled, the configured download root must be server-private (not
/// group- or world-writable).
///
/// `export_messages` writes a raw, unsanitized mbox into the download
/// sandbox. Because the export is an unredacted raw-message oracle, the
/// design requires the download root be writable only by the server
/// (write authority separated from the consuming agent). This turns that
/// requirement into a hard startup check: enabling the tool with a
/// group/world-writable download root rejects the config.
///
/// The check fires only when `export_enabled` is true and a download root
/// is configured (a non-empty `attachments.download_dir`). An empty
/// `download_dir` means per-session tempdir, which the server creates with
/// private permissions and is out of operator control. On non-Unix
/// platforms the permission concept does not apply and the check is a
/// no-op.
pub(super) fn validate_export_download_root(
    attachments: &AttachmentsConfig,
    export_enabled: bool,
) -> Result<(), ConfigError> {
    if !export_enabled || attachments.download_dir.is_empty() {
        return Ok(());
    }
    check_export_download_root_private(Path::new(&attachments.download_dir))
}

#[cfg(unix)]
fn check_export_download_root_private(download_root: &Path) -> Result<(), ConfigError> {
    use std::os::unix::fs::PermissionsExt as _;

    // A symlinked root means the operator-named path and the path the writer
    // resolves differ; whoever controls the link target controls the export
    // destination. Reject before any metadata call (which follows the link).
    let link_meta =
        std::fs::symlink_metadata(download_root).map_err(|e| ConfigError::PathNotWritable {
            path: download_root.to_path_buf(),
            reason: format!("cannot stat download root: {e}"),
        })?;
    if link_meta.file_type().is_symlink() {
        return Err(ConfigError::PathNotWritable {
            path: download_root.to_path_buf(),
            reason: "export_messages download root is a symlink; it must be a real \
                     directory so its resolved path cannot be redirected to an \
                     attacker-writable target"
                .to_string(),
        });
    }

    // Not a symlink, so `link_meta` already describes the directory itself —
    // no second (link-following) stat needed. The root must not be
    // group/world-writable. 0o022 = group-write (0o020) | other-write (0o002).
    let mode = link_meta.permissions().mode();
    if mode & 0o022 != 0 {
        return Err(ConfigError::PathNotWritable {
            path: download_root.to_path_buf(),
            reason: format!(
                "export_messages is enabled but the download root is \
                 group/world-writable (mode {:o}); export_messages requires \
                 a server-private download root",
                mode & 0o777,
            ),
        });
    }

    check_export_download_root_parent(download_root)
}

/// Reject a download root whose immediate parent lets another user swap the
/// root inode out from under the resolver.
///
/// Renaming/replacing a directory entry requires write+execute on its parent,
/// so a group/world-writable parent permits the swap — *unless* the sticky bit
/// is set, which restricts rename/delete to each entry's owner (the `/tmp`
/// model). Only the immediate parent is checked; deeper ancestors are out of
/// scope (the runtime held-fd writer is the backstop).
#[cfg(unix)]
fn check_export_download_root_parent(download_root: &Path) -> Result<(), ConfigError> {
    use std::os::unix::fs::PermissionsExt as _;

    let canonical =
        std::fs::canonicalize(download_root).map_err(|e| ConfigError::PathNotWritable {
            path: download_root.to_path_buf(),
            reason: format!("canonicalize download root: {e}"),
        })?;
    let Some(parent) = canonical.parent() else {
        // The root is the filesystem root `/`: no parent can swap it.
        return Ok(());
    };
    let mode = std::fs::metadata(parent)
        .map_err(|e| ConfigError::PathNotWritable {
            path: parent.to_path_buf(),
            reason: format!("cannot stat download-root parent: {e}"),
        })?
        .permissions()
        .mode();
    let group_or_world_writable = mode & 0o022 != 0;
    let sticky = mode & 0o1000 != 0;
    if group_or_world_writable && !sticky {
        return Err(ConfigError::PathNotWritable {
            path: parent.to_path_buf(),
            reason: format!(
                "export_messages download root's parent {} is group/world-writable \
                 without the sticky bit (mode {:o}); another user could swap the \
                 download root. Use a server-private parent or set the sticky bit",
                parent.display(),
                mode & 0o7777,
            ),
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_export_download_root_private(_download_root: &Path) -> Result<(), ConfigError> {
    Ok(())
}

/// Compute the default audit base when `audit.allowed_base_dir` is unset.
/// Returns `$XDG_STATE_HOME/rusty-imap-mcp/` on platforms where
/// `directories::ProjectDirs` resolves; returns `None` otherwise (which
/// causes the containment check to fail with a clear error).
///
/// ## macOS Time Machine caveat (LOCAL-PRI-06)
///
/// On macOS, `ProjectDirs::data_local_dir()` resolves to
/// `~/Library/Application Support/rusty-imap-mcp/`, which is covered by
/// Time Machine backups by default. The audit log appears in every
/// backup snapshot and is readable from any restore. A stolen laptop or
/// stolen Time Machine disk gives cold-attacker access to the full audit
/// history even if the live process was never touched.
///
/// The backup-exclude xattr fix (setting
/// `com.apple.metadata:com_apple_backup_excludeItem` on the audit path)
/// is tracked in issue #45. Until that lands, operators on macOS should
/// either (a) set `audit.allowed_base_dir` explicitly to a path that
/// Time Machine does not back up (e.g., under `~/Library/Caches/`), or
/// (b) manually exclude `~/Library/Application Support/rusty-imap-mcp/`
/// via `tmutil addexclusion`.
fn default_audit_base() -> Option<PathBuf> {
    let dirs = directories::ProjectDirs::from("", "", "rusty-imap-mcp")?;
    Some(dirs.data_local_dir().to_path_buf())
}

/// Canonicalize the audit path and verify it is contained in the allowed
/// base. Called after `require_writable_dir` so the parent dir is known to
/// exist. The parent is canonicalized first (not the path itself, which
/// may not exist yet), then joined with the file name to produce the
/// canonical audit path.
fn enforce_audit_containment(audit: &AuditConfig) -> Result<(), ConfigError> {
    let audit_path = &audit.path;
    let parent = audit_path
        .parent()
        .ok_or_else(|| ConfigError::PathNotWritable {
            path: audit_path.clone(),
            reason: "audit path has no parent directory".to_string(),
        })?;
    let canon_parent = std::fs::canonicalize(parent).map_err(|e| ConfigError::PathNotWritable {
        path: parent.to_path_buf(),
        reason: format!("canonicalize parent: {e}"),
    })?;
    let file_name = audit_path
        .file_name()
        .ok_or_else(|| ConfigError::PathNotWritable {
            path: audit_path.clone(),
            reason: "audit path has no file name".to_string(),
        })?;
    let canon_path = canon_parent.join(file_name);

    let base = audit
        .allowed_base_dir
        .clone()
        .or_else(default_audit_base)
        .ok_or_else(|| ConfigError::PathNotWritable {
            path: audit_path.clone(),
            reason: "no allowed_base_dir configured and platform default unavailable".to_string(),
        })?;
    let canon_base = std::fs::canonicalize(&base).map_err(|e| ConfigError::PathNotWritable {
        path: base.clone(),
        reason: format!("canonicalize allowed_base_dir: {e}"),
    })?;

    if !canon_path.starts_with(&canon_base) {
        return Err(ConfigError::AuditPathOutsideBase {
            path: canon_path,
            base: canon_base,
        });
    }
    Ok(())
}

fn require_writable_dir(dir: &Path) -> Result<(), ConfigError> {
    if !dir.exists() {
        return Err(ConfigError::PathNotWritable {
            path: dir.to_path_buf(),
            reason: "directory does not exist".to_string(),
        });
    }
    let meta = std::fs::metadata(dir).map_err(|e| ConfigError::PathNotWritable {
        path: dir.to_path_buf(),
        reason: format!("stat failed: {e}"),
    })?;
    if !meta.is_dir() {
        return Err(ConfigError::PathNotWritable {
            path: dir.to_path_buf(),
            reason: "not a directory".to_string(),
        });
    }
    if meta.permissions().readonly() {
        return Err(ConfigError::PathNotWritable {
            path: dir.to_path_buf(),
            reason: "directory is read-only".to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
#[expect(clippy::panic, reason = "test failure paths")]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn audit_with(path: PathBuf, base: Option<PathBuf>) -> AuditConfig {
        AuditConfig {
            path,
            rotate_bytes: 10_485_760,
            rotate_keep: 5,
            retention_seconds: None,
            provenance_window_seconds: 60,
            write_deadline_seconds: 15,
            fail_open: false,
            allowed_base_dir: base,
        }
    }

    fn audit_with_retention(retention: Option<u64>) -> AuditConfig {
        let mut audit = audit_with(PathBuf::from("/tmp/audit.jsonl"), None);
        audit.retention_seconds = retention;
        audit
    }

    #[test]
    fn audit_retention_seconds_zero_rejected() {
        let audit = audit_with_retention(Some(0));
        let err = validate_audit_config(&audit).unwrap_err();
        assert!(
            matches!(&err, ConfigError::InvalidLimit { field, .. } if *field == "audit.retention_seconds")
        );
    }

    #[test]
    fn audit_retention_seconds_positive_accepted() {
        let audit = audit_with_retention(Some(3600));
        assert!(validate_audit_config(&audit).is_ok());
    }

    #[test]
    fn audit_retention_seconds_none_accepted() {
        let audit = audit_with(PathBuf::from("/tmp/audit.jsonl"), None);
        assert!(validate_audit_config(&audit).is_ok());
    }

    #[test]
    fn require_writable_dir_rejects_missing_path() {
        let err = require_writable_dir(Path::new("/this/path/should/never/exist/xyz")).unwrap_err();
        let ConfigError::PathNotWritable { reason, .. } = &err else {
            panic!("expected PathNotWritable, got {err:?}");
        };
        assert!(reason.contains("does not exist"));
    }

    #[test]
    fn require_writable_dir_rejects_non_directory_path() {
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join("a_file");
        std::fs::write(&file, b"").unwrap();
        let err = require_writable_dir(&file).unwrap_err();
        let ConfigError::PathNotWritable { reason, .. } = &err else {
            panic!("expected PathNotWritable, got {err:?}");
        };
        assert!(reason.contains("not a directory"));
    }

    #[test]
    fn require_writable_dir_accepts_writable_dir() {
        let tmp = TempDir::new().unwrap();
        assert!(require_writable_dir(tmp.path()).is_ok());
    }

    #[test]
    fn enforce_audit_containment_rejects_path_outside_base() {
        let base_tmp = TempDir::new().unwrap();
        let other_tmp = TempDir::new().unwrap();
        let audit = audit_with(
            other_tmp.path().join("audit.jsonl"),
            Some(base_tmp.path().to_path_buf()),
        );
        let err = enforce_audit_containment(&audit).unwrap_err();
        assert!(matches!(err, ConfigError::AuditPathOutsideBase { .. }));
    }

    #[test]
    fn enforce_audit_containment_accepts_path_inside_base() {
        let base_tmp = TempDir::new().unwrap();
        let audit = audit_with(
            base_tmp.path().join("audit.jsonl"),
            Some(base_tmp.path().to_path_buf()),
        );
        assert!(enforce_audit_containment(&audit).is_ok());
    }

    /// Regression guard for the example configs shipping an audit path
    /// outside the platform default containment base (#465).
    ///
    /// `tests/config_example.rs` deserializes and validates the repo-root
    /// example configs, but it retargets `audit.path` at a fresh tempdir
    /// before validating — so a literal `audit.path` that disagrees with
    /// `default_audit_base()` (e.g. `.local/state` vs. the real default of
    /// `.local/share`) never gets exercised there. This test reads the
    /// examples' literal `audit.path`, substitutes the example's
    /// `/home/alice` placeholder for the real `$HOME`, and checks the
    /// result against the actual `default_audit_base()` — the same check
    /// `enforce_audit_containment` performs when `allowed_base_dir` is
    /// unset (the shipped default; it's commented out in both examples).
    #[cfg(target_os = "linux")]
    #[test]
    fn example_audit_paths_are_contained_in_default_base_verbatim() {
        let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let home = std::env::var("HOME")
            .unwrap_or_else(|_| panic!("HOME must be set on Linux test runners"));
        let base = default_audit_base().unwrap_or_else(|| panic!("resolve default audit base"));

        for example in ["config.example.toml", "config.multi-account.example.toml"] {
            let contents = std::fs::read_to_string(repo_root.join(example))
                .unwrap_or_else(|e| panic!("read {example}: {e}"));
            let parsed: toml::Value = toml::from_str(&contents)
                .unwrap_or_else(|e| panic!("{example}: parse as TOML: {e}"));
            let literal_path = parsed["audit"]["path"]
                .as_str()
                .unwrap_or_else(|| panic!("{example}: audit.path is not a string"));
            let real_path = PathBuf::from(literal_path.replacen("/home/alice", &home, 1));
            assert!(
                real_path.starts_with(&base),
                "{example}: audit.path {literal_path:?} resolves to {real_path:?} \
                 under the caller's real $HOME, which is not contained in the \
                 platform default audit base {base:?}; a verbatim copy of this \
                 example would fail startup containment on Linux with \
                 `allowed_base_dir` left unset",
            );
        }
    }

    #[cfg(unix)]
    fn attachments_with(download_dir: &Path) -> AttachmentsConfig {
        AttachmentsConfig {
            download_dir: download_dir.to_string_lossy().into_owned(),
        }
    }

    #[cfg(unix)]
    fn set_mode(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn export_root_world_writable_rejected_when_enabled() {
        let tmp = TempDir::new().unwrap();
        set_mode(tmp.path(), 0o777);
        let attachments = attachments_with(tmp.path());
        let err = validate_export_download_root(&attachments, true).unwrap_err();
        let ConfigError::PathNotWritable { reason, .. } = &err else {
            panic!("expected PathNotWritable, got {err:?}");
        };
        assert!(reason.contains("group/world-writable"), "reason: {reason}");
    }

    #[cfg(unix)]
    #[test]
    fn export_root_private_accepted_when_enabled() {
        let tmp = TempDir::new().unwrap();
        set_mode(tmp.path(), 0o700);
        let attachments = attachments_with(tmp.path());
        assert!(validate_export_download_root(&attachments, true).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn export_root_world_writable_ignored_when_disabled() {
        let tmp = TempDir::new().unwrap();
        set_mode(tmp.path(), 0o777);
        let attachments = attachments_with(tmp.path());
        assert!(validate_export_download_root(&attachments, false).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn export_root_empty_download_dir_skips_check() {
        let attachments = AttachmentsConfig {
            download_dir: String::new(),
        };
        assert!(validate_export_download_root(&attachments, true).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn export_root_symlink_rejected_when_enabled() {
        // A symlinked root must be rejected even when its target is private:
        // the resolved path can be redirected by whoever controls the link.
        let tmp = TempDir::new().unwrap();
        let real = tmp.path().join("real");
        std::fs::create_dir(&real).unwrap();
        set_mode(&real, 0o700);
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let attachments = attachments_with(&link);
        let err = validate_export_download_root(&attachments, true).unwrap_err();
        let ConfigError::PathNotWritable { reason, .. } = &err else {
            panic!("expected PathNotWritable, got {err:?}");
        };
        assert!(reason.contains("symlink"), "reason: {reason}");
    }

    #[cfg(unix)]
    #[test]
    fn export_root_parent_world_writable_rejected_when_enabled() {
        // A private root under a world-writable, non-sticky parent is
        // rejected: another user could rename the root and substitute their
        // own directory.
        let tmp = TempDir::new().unwrap();
        let parent = tmp.path().join("parent");
        std::fs::create_dir(&parent).unwrap();
        let root = parent.join("root");
        std::fs::create_dir(&root).unwrap();
        set_mode(&root, 0o700);
        set_mode(&parent, 0o777); // world-writable, no sticky bit

        let attachments = attachments_with(&root);
        let err = validate_export_download_root(&attachments, true).unwrap_err();
        let ConfigError::PathNotWritable { reason, .. } = &err else {
            panic!("expected PathNotWritable, got {err:?}");
        };
        assert!(reason.contains("swap the"), "reason: {reason}");
    }

    #[cfg(unix)]
    #[test]
    fn export_root_sticky_parent_accepted_when_enabled() {
        // A world-writable parent WITH the sticky bit (the `/tmp` model) does
        // not permit swapping another user's entry, so a private root under it
        // is accepted.
        let tmp = TempDir::new().unwrap();
        let parent = tmp.path().join("parent");
        std::fs::create_dir(&parent).unwrap();
        let root = parent.join("root");
        std::fs::create_dir(&root).unwrap();
        set_mode(&root, 0o700);
        set_mode(&parent, 0o1777); // sticky + world-writable

        let attachments = attachments_with(&root);
        assert!(validate_export_download_root(&attachments, true).is_ok());
    }
}
