//! Attachment download sandboxing.
//!
//! Validates download destinations against an allowed root directory,
//! writes attachment data with collision-safe filenames, and provides
//! MIME sniffing and SHA-256 hashing utilities.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rimap_core::RimapError;

/// Resolve and validate the download destination.
///
/// If `dest_dir` is provided, canonicalize it and verify it starts
/// with `allowed_root`. If absent, use `fallback_dir`.
///
/// # Errors
///
/// Returns `RimapError::Authz { code: InvalidInput, ... }` when the
/// user-supplied `dest_dir` cannot be canonicalized (missing path,
/// permission denied) or when the canonical form falls outside
/// `allowed_root`.
pub(crate) fn resolve_dest_dir(
    dest_dir: Option<&str>,
    allowed_root: &Path,
    fallback_dir: &Path,
) -> Result<PathBuf, RimapError> {
    let dir = match dest_dir {
        Some(d) => {
            let p = PathBuf::from(d);
            let canonical = p
                .canonicalize()
                .map_err(|e| RimapError::invalid_input(format!("cannot resolve dest_dir: {e}")))?;
            if !canonical.starts_with(allowed_root) {
                return Err(RimapError::invalid_input(
                    "dest_dir is outside allowed download directory",
                ));
            }
            canonical
        }
        None => fallback_dir.to_path_buf(),
    };
    Ok(dir)
}

/// Write `data` to `dir/filename`, de-duplicating on collision.
/// Returns the final path.
///
/// Each candidate is created with `O_CREAT | O_EXCL | O_NOFOLLOW` and mode
/// `0600` (via [`create_new_private`]): the create is atomic and exclusive, so
/// it never overwrites or follows a symlink at the final path component, and
/// the resulting file is owner-only. A pre-existing name (regular file *or*
/// symlink) yields `AlreadyExists`, and the de-dup counter advances — the
/// reason `export_messages` (a raw-email export oracle) and
/// `download_attachment` can share this primitive safely.
///
/// Containment of `dir` itself is enforced upstream by [`resolve_dest_dir`]
/// (canonicalize + `starts_with(allowed_root)`) and by the config-time private
/// download-root check. This writer does not hold a directory fd / create
/// fd-relative (`openat`), because that requires `unsafe` FFI, which the
/// workspace forbids (`unsafe_code = "forbid"`); the residual directory-swap
/// window is bounded by that upstream canonicalization and the enforced
/// non-group/world-writable root.
///
/// # Errors
///
/// Returns `RimapError::Internal` if writing fails or if more than
/// 1000 filename collisions occur. On non-Unix platforms the no-follow /
/// private-mode semantics are unavailable, so the writer fails closed with
/// `RimapError::Internal` rather than writing without those guarantees.
#[cfg(unix)]
pub(crate) fn write_attachment(
    dir: &Path,
    filename: &str,
    data: &[u8],
) -> Result<PathBuf, RimapError> {
    // Strip path components to prevent directory traversal.
    let safe_name = Path::new(filename)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("attachment");

    let base = Path::new(safe_name);
    let stem = base
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("attachment");
    let ext = base.extension().and_then(|s| s.to_str());

    let mut counter = 0u32;
    loop {
        let name = if counter == 0 {
            safe_name.to_string()
        } else {
            match ext {
                Some(e) => format!("{stem}_{counter}.{e}"),
                None => format!("{stem}_{counter}"),
            }
        };
        let path = dir.join(&name);
        match create_new_private(&path) {
            Ok(file) => return finish_write(file, path, data),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                counter += 1;
                if counter > 1000 {
                    return Err(RimapError::Internal("too many filename collisions".into()));
                }
            }
            Err(e) => {
                return Err(RimapError::InternalSourced {
                    message: "failed to create attachment file".into(),
                    source: Box::new(e),
                });
            }
        }
    }
}

/// Atomically create `path` for writing with `O_CREAT | O_EXCL | O_NOFOLLOW`
/// and mode `0600`. Fails with [`std::io::ErrorKind::AlreadyExists`] if the
/// path already exists (including as a symlink), which the caller treats as a
/// de-dup collision. Uses only the safe [`std::os::unix::fs::OpenOptionsExt`]
/// surface — no `unsafe`.
#[cfg(unix)]
fn create_new_private(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o600)
        .open(path)
}

/// Write `data` to the exclusively-created `file`, then return its `path`. If
/// the write fails partway (short write, disk-full, I/O error), the file is
/// removed so a failed download/export never leaves a partial artifact at the
/// final path. The original write error is reported regardless of whether the
/// cleanup unlink succeeds.
#[cfg(unix)]
fn finish_write(
    mut file: std::fs::File,
    path: PathBuf,
    data: &[u8],
) -> Result<PathBuf, RimapError> {
    use std::io::Write as _;
    if let Err(e) = file.write_all(data) {
        drop(file);
        let _ = std::fs::remove_file(&path);
        return Err(RimapError::InternalSourced {
            message: "failed to write attachment".into(),
            source: Box::new(e),
        });
    }
    Ok(path)
}

/// Fail-closed stub for non-Unix platforms.
///
/// The hardened writer relies on `O_NOFOLLOW` and POSIX file modes, which are
/// unavailable here. Rather than write raw message bytes without those
/// guarantees, the sandbox refuses to write.
///
/// # Errors
///
/// Always returns `RimapError::Internal`.
#[cfg(not(unix))]
pub(crate) fn write_attachment(
    _dir: &Path,
    _filename: &str,
    _data: &[u8],
) -> Result<PathBuf, RimapError> {
    Err(RimapError::Internal(
        "sandboxed attachment writes require a Unix platform (O_NOFOLLOW / file-mode support)"
            .into(),
    ))
}

/// Async wrapper around [`resolve_dest_dir`] that runs on a
/// blocking thread.
///
/// # Errors
///
/// Propagates whatever [`resolve_dest_dir`] returns (typically
/// `RimapError::Authz` with `InvalidInput` when the path cannot be
/// canonicalized or escapes `allowed_root`). Returns
/// `RimapError::Internal` if the blocking task panics.
pub async fn resolve_dest_dir_async(
    dest_dir: Option<String>,
    root: Arc<Path>,
) -> Result<PathBuf, RimapError> {
    tokio::task::spawn_blocking(move || resolve_dest_dir(dest_dir.as_deref(), &root, &root))
        .await
        .unwrap_or_else(|e| Err(crate::mcp::spawn_blocking_panic_error(e)))
}

/// Async wrapper around [`write_attachment`] that runs on a
/// blocking thread.
///
/// # Errors
///
/// Propagates whatever [`write_attachment`] returns
/// (`RimapError::Internal` on I/O failure or after >1000 filename
/// collisions). Also returns `RimapError::Internal` if the blocking
/// task panics.
pub async fn write_attachment_async(
    dir: PathBuf,
    filename: String,
    data: Vec<u8>,
) -> Result<PathBuf, RimapError> {
    tokio::task::spawn_blocking(move || write_attachment(&dir, &filename, &data))
        .await
        .unwrap_or_else(|e| Err(crate::mcp::spawn_blocking_panic_error(e)))
}

/// MIME-sniff `data` using magic bytes.
#[must_use]
pub fn sniff_mime(data: &[u8]) -> Option<String> {
    infer::get(data).map(|t| t.mime_type().to_string())
}

/// SHA-256 hex digest.
#[must_use]
pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(data);
    hex::encode(hash)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn resolve_dest_dir_uses_fallback_when_none() {
        let fallback = PathBuf::from("/tmp/fallback");
        let allowed = Path::new("/tmp");
        let result = resolve_dest_dir(None, allowed, &fallback).unwrap();
        assert_eq!(result, fallback);
    }

    #[test]
    fn resolve_dest_dir_accepts_valid_path() {
        let tmp = tempfile::tempdir().unwrap();
        // Canonicalize once so the assertion below sees the same prefix
        // form `resolve_dest_dir` produces internally. On macOS,
        // `tempfile::tempdir()` returns `/var/folders/.../T/...` which
        // canonicalize()s to `/private/var/folders/.../T/...`; without
        // this, `result.starts_with(allowed)` compares the two forms
        // and fails despite the path being legitimately inside.
        let allowed = tmp.path().canonicalize().unwrap();
        let sub = allowed.join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        let fallback = allowed.clone();
        let result = resolve_dest_dir(Some(sub.to_str().unwrap()), &allowed, &fallback).unwrap();
        assert!(result.starts_with(&allowed));
    }

    #[test]
    fn resolve_dest_dir_rejects_traversal() {
        let tmp = tempfile::tempdir().unwrap();
        let allowed = tmp.path().join("sandbox");
        std::fs::create_dir_all(&allowed).unwrap();
        // Try to escape to the parent.
        let err =
            resolve_dest_dir(Some(tmp.path().to_str().unwrap()), &allowed, &allowed).unwrap_err();
        assert_eq!(err.code(), rimap_core::ErrorCode::InvalidInput);
        assert!(err.to_string().contains("outside allowed"));
    }

    #[test]
    fn resolve_dest_dir_invalid_path_returns_invalid_input() {
        let tmp = tempfile::tempdir().unwrap();
        let allowed = tmp.path().join("sandbox");
        std::fs::create_dir_all(&allowed).unwrap();
        // Non-existent dest_dir cannot be canonicalized.
        let bogus = tmp.path().join("does/not/exist");
        let err = resolve_dest_dir(Some(bogus.to_str().unwrap()), &allowed, &allowed).unwrap_err();
        assert_eq!(err.code(), rimap_core::ErrorCode::InvalidInput);
    }

    #[cfg(unix)]
    #[test]
    fn write_attachment_normal() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_attachment(tmp.path(), "doc.pdf", b"data").unwrap();
        assert_eq!(path, tmp.path().join("doc.pdf"));
        assert_eq!(std::fs::read(&path).unwrap(), b"data");
    }

    #[cfg(unix)]
    #[test]
    fn write_attachment_collision() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("doc.pdf"), b"old").unwrap();
        let path = write_attachment(tmp.path(), "doc.pdf", b"new").unwrap();
        assert_eq!(path, tmp.path().join("doc_1.pdf"));
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
    }

    #[cfg(unix)]
    #[test]
    fn write_attachment_no_extension() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("readme"), b"old").unwrap();
        let path = write_attachment(tmp.path(), "readme", b"new").unwrap();
        assert_eq!(path, tmp.path().join("readme_1"));
    }

    #[cfg(unix)]
    #[test]
    fn write_attachment_rejects_relative_traversal() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_attachment(tmp.path(), "../escape.txt", b"data").unwrap();
        // Must land inside tmp, not escape.
        assert!(path.starts_with(tmp.path()));
        assert_eq!(path.file_name().unwrap(), "escape.txt");
        assert_eq!(std::fs::read(&path).unwrap(), b"data");
    }

    #[cfg(unix)]
    #[test]
    fn write_attachment_rejects_absolute_path() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_attachment(tmp.path(), "/etc/passwd", b"data").unwrap();
        assert!(path.starts_with(tmp.path()));
        assert_eq!(path.file_name().unwrap(), "passwd");
        assert_eq!(std::fs::read(&path).unwrap(), b"data");
    }

    #[cfg(unix)]
    #[test]
    fn write_attachment_handles_deep_traversal() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_attachment(tmp.path(), "../../.ssh/authorized_keys", b"data").unwrap();
        assert!(path.starts_with(tmp.path()));
        assert_eq!(path.file_name().unwrap(), "authorized_keys");
    }

    #[cfg(unix)]
    #[test]
    fn write_attachment_sets_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().unwrap();
        let path = write_attachment(tmp.path(), "secret.mbox", b"raw email").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        // The export oracle writes raw message bytes; the file must be
        // owner-only regardless of the process umask.
        assert_eq!(mode & 0o777, 0o600, "expected 0600, got {:o}", mode & 0o777);
    }

    #[cfg(unix)]
    #[test]
    fn finish_write_removes_partial_file_on_write_error() {
        // Reopen the just-created target read-only so write_all fails (EBADF),
        // then assert the file is unlinked rather than left as a partial
        // raw-email artifact at its final path.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("partial.mbox");
        std::fs::write(&path, b"placeholder").unwrap();
        let read_only = std::fs::OpenOptions::new().read(true).open(&path).unwrap();
        let err = finish_write(read_only, path.clone(), b"raw email bytes").unwrap_err();
        assert_eq!(err.code(), rimap_core::ErrorCode::Internal);
        assert!(
            !path.exists(),
            "partial file must be removed on write error"
        );
    }

    #[cfg(unix)]
    #[test]
    fn write_attachment_does_not_follow_symlink_at_final_path() {
        // A symlink pre-planted inside the sandbox must not be followed: the
        // exclusive create yields AlreadyExists, so the writer de-dups to a
        // fresh name and the symlink target outside the sandbox is never
        // created or written. Guards the raw-export escape vector.
        let tmp = tempfile::tempdir().unwrap();
        let sandbox = tmp.path().join("sandbox");
        std::fs::create_dir_all(&sandbox).unwrap();
        let outside = tmp.path().join("outside-target.txt");
        std::os::unix::fs::symlink(&outside, sandbox.join("evil.mbox")).unwrap();

        let path = write_attachment(&sandbox, "evil.mbox", b"payload").unwrap();

        // Wrote a de-duped sibling, not through the symlink.
        assert_eq!(path, sandbox.join("evil_1.mbox"));
        assert!(path.starts_with(&sandbox));
        // The symlink target outside the sandbox was never created.
        assert!(
            !outside.exists(),
            "symlink was followed: target was written"
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"payload");
    }

    #[test]
    fn sha256_hex_known_value() {
        // SHA-256 of empty input.
        let digest = sha256_hex(b"");
        assert_eq!(
            digest,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934\
             ca495991b7852b855"
        );
    }

    #[test]
    fn sniff_mime_detects_png() {
        // Minimal PNG header.
        let png_header = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        let result = sniff_mime(&png_header);
        assert_eq!(result.as_deref(), Some("image/png"));
    }

    #[test]
    fn sniff_mime_returns_none_for_unknown() {
        assert!(sniff_mime(b"hello world").is_none());
    }
}
