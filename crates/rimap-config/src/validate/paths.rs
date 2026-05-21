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
}
