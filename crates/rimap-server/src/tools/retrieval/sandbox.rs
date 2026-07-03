//! Attachment download sandboxing.
//!
//! Validates download destinations against an allowed root directory,
//! holds the destination open as a capability directory, writes attachment
//! data fd-relative with collision-safe filenames, and provides MIME sniffing
//! and SHA-256 hashing utilities.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use cap_std::ambient_authority;
use cap_std::fs::Dir;

use rimap_core::RimapError;

/// A resolved, validated download destination held open as a capability.
///
/// `canonical` is retained only to render the human-readable result path; all
/// writes go through `dir`, an open directory descriptor. Anchoring writes to
/// a held fd closes the resolve→write directory-swap window: once the `Dir` is
/// open, no rename/replace of a path component can redirect the write, because
/// `cap-std` creates files fd-relative (`openat`-family) and refuses `..`,
/// absolute paths, and symlinks that escape the directory.
#[derive(Debug)]
pub struct DestDir {
    canonical: PathBuf,
    dir: Dir,
}

impl DestDir {
    /// The canonical directory path, for building the reported result path.
    #[must_use]
    pub(crate) fn canonical(&self) -> &Path {
        &self.canonical
    }
}

/// Resolve and validate the download destination, returning it held open as a
/// capability [`DestDir`].
///
/// If `dest_dir` is provided, canonicalize it and verify it starts with
/// `allowed_root`. If absent, use `fallback_dir`. The resolved directory is
/// then opened once via the host's ambient authority; every subsequent write
/// is fd-relative to that held descriptor.
///
/// # Errors
///
/// Returns `RimapError::Authz { code: InvalidInput, ... }` when the
/// user-supplied `dest_dir` cannot be canonicalized (missing path, permission
/// denied) or when the canonical form falls outside `allowed_root`. Returns
/// `RimapError::InternalSourced` if the resolved directory cannot be opened.
pub(crate) fn resolve_dest_dir(
    dest_dir: Option<&str>,
    allowed_root: &Path,
    fallback_dir: &Path,
) -> Result<DestDir, RimapError> {
    let dir_path = match dest_dir {
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
    // The single ambient (path-following) step. Everything after is
    // fd-relative to this held directory descriptor.
    let dir = Dir::open_ambient_dir(&dir_path, ambient_authority()).map_err(|e| {
        RimapError::InternalSourced {
            message: "failed to open download directory".into(),
            source: Box::new(e),
        }
    })?;
    Ok(DestDir {
        canonical: dir_path,
        dir,
    })
}

/// Write `data` into `dest`, de-duplicating on collision. Returns the final
/// path.
///
/// The bytes are first written to a process-unique temp file created
/// fd-relative with `create_new` (`O_EXCL`, which refuses to follow a symlink
/// at the final component) and mode `0600` (owner-only). The temp is then
/// atomically placed at the first free candidate name via [`Dir::hard_link`]
/// — `EEXIST` (a pre-existing regular file *or* symlink) advances the de-dup
/// counter, so the writer never overwrites or follows an existing name. The
/// final name therefore only ever appears fully-written: a crash between the
/// write and the link leaves a recognizable `.rimap-tmp-*` orphan, never a
/// truncated raw-email artifact at the final path. Every handled error path
/// unlinks the temp.
///
/// Containment of the directory is enforced upstream by [`resolve_dest_dir`]
/// (canonicalize + `starts_with(allowed_root)`) and by the config-time private
/// download-root check; the held `Dir` fd closes the resolve→write swap window
/// for both `download_attachment` and `export_messages`, which share this
/// primitive.
///
/// # Errors
///
/// Returns `RimapError::Internal` if writing fails or if more than 1000
/// filename collisions occur. On non-Unix platforms the no-follow / private-
/// mode semantics are unavailable, so the writer fails closed with
/// `RimapError::Internal` rather than writing without those guarantees.
#[cfg(unix)]
pub(crate) fn write_attachment(
    dest: &DestDir,
    filename: &str,
    data: &[u8],
) -> Result<PathBuf, RimapError> {
    use cap_std::fs::{OpenOptions, OpenOptionsExt as _};
    use std::io::Write as _;

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

    // 1. Create the temp fd-relative: exclusive, owner-only, no-follow.
    let tmp_name = unique_temp_name();
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file =
        dest.dir
            .open_with(&tmp_name, &options)
            .map_err(|e| RimapError::InternalSourced {
                message: "failed to create temporary download file".into(),
                source: Box::new(e),
            })?;

    // 2. Write the bytes; unlink the temp on any error.
    if let Err(e) = file.write_all(data) {
        drop(file);
        let _ = dest.dir.remove_file(&tmp_name);
        return Err(RimapError::InternalSourced {
            message: "failed to write download file".into(),
            source: Box::new(e),
        });
    }
    drop(file);

    // 3. Atomically place the temp at the first free candidate name.
    let mut counter = 0u32;
    loop {
        let name = candidate_name(safe_name, stem, ext, counter);
        match dest.dir.hard_link(&tmp_name, &dest.dir, &name) {
            Ok(()) => {
                let _ = dest.dir.remove_file(&tmp_name);
                return Ok(dest.canonical().join(&name));
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                counter += 1;
                if counter > 1000 {
                    let _ = dest.dir.remove_file(&tmp_name);
                    return Err(RimapError::Internal("too many filename collisions".into()));
                }
            }
            Err(e) => {
                let _ = dest.dir.remove_file(&tmp_name);
                return Err(RimapError::InternalSourced {
                    message: "failed to place download file".into(),
                    source: Box::new(e),
                });
            }
        }
    }
}

/// The candidate final name for de-dup `counter`: the original name for the
/// first attempt, then `stem_N` / `stem_N.ext` siblings.
#[cfg(unix)]
fn candidate_name(safe_name: &str, stem: &str, ext: Option<&str>, counter: u32) -> String {
    if counter == 0 {
        safe_name.to_string()
    } else {
        match ext {
            Some(e) => format!("{stem}_{counter}.{e}"),
            None => format!("{stem}_{counter}"),
        }
    }
}

/// A process-unique temp filename. The PID, a process-local atomic counter,
/// and wall-clock nanos make it distinct across concurrent writers (download +
/// export, or two exports) so the exclusive temp create never collides between
/// them. The `.rimap-tmp-` prefix is recognizable for operator cleanup of any
/// crash-orphaned temp.
#[cfg(unix)]
fn unique_temp_name() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let pid = std::process::id();
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!(".rimap-tmp-{pid}-{seq}-{nanos:x}")
}

/// Fail-closed stub for non-Unix platforms.
///
/// The hardened writer relies on `O_EXCL` semantics and POSIX file modes for
/// its no-follow / owner-only guarantees. Rather than write raw message bytes
/// without those guarantees, the sandbox refuses to write.
///
/// # Errors
///
/// Always returns `RimapError::Internal`.
#[cfg(not(unix))]
pub(crate) fn write_attachment(
    _dest: &DestDir,
    _filename: &str,
    _data: &[u8],
) -> Result<PathBuf, RimapError> {
    Err(RimapError::Internal(
        "sandboxed attachment writes require a Unix platform (O_EXCL / file-mode support)".into(),
    ))
}

/// Read a file from inside the download sandbox, enforcing containment and a
/// size cap.
///
/// Mirrors [`resolve_dest_dir`]'s containment for the read direction: the
/// requested path is canonicalized and checked with `starts_with(root)`, the
/// parent is opened once via ambient authority as a held [`Dir`], and the final
/// component is read fd-relative. The final component is rejected if it is a
/// symlink (no-follow), if it is not a regular file, or if its size exceeds
/// `max_bytes` — the size is checked from `symlink_metadata` **before** any
/// bytes are read, and the read itself is hard-capped at `max_bytes` so a file
/// swapped larger between the stat and the read still cannot exhaust memory.
///
/// The accepted trust boundary is the shared download root: any file the server
/// downloaded/exported, or the operator placed, under `root` is readable. This
/// primitive does not widen that boundary — a path resolving outside `root`
/// (including via a symlink whose target escapes) is refused.
///
/// # Errors
///
/// Returns `RimapError::invalid_input` when the path cannot be canonicalized,
/// escapes `root`, is a symlink or non-regular file, or exceeds `max_bytes`.
/// Returns `RimapError::InternalSourced` if the held directory or file cannot be
/// opened. On non-Unix platforms the no-follow guarantee is unavailable, so the
/// reader fails closed with `RimapError::Internal`.
#[cfg(unix)]
pub(crate) fn read_sandboxed_file(
    root: &Path,
    requested: &str,
    max_bytes: usize,
) -> Result<Vec<u8>, RimapError> {
    use std::io::Read as _;

    let requested_path = PathBuf::from(requested);
    // Canonicalize the PARENT only, never the full path: canonicalizing the
    // full path would resolve a final-component symlink and defeat the leaf
    // no-follow guarantee. The final component is opened by its original name so
    // `symlink_metadata` below can reject a symlink leaf even when its target is
    // itself inside the root.
    let parent = requested_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty());
    let (parent, name) = match (parent, requested_path.file_name()) {
        (Some(parent), Some(name)) => (parent, name.to_owned()),
        _ => {
            return Err(RimapError::invalid_input(
                "attachment path must be an absolute file path inside the download sandbox",
            ));
        }
    };
    let canonical_parent = parent.canonicalize().map_err(|e| {
        RimapError::invalid_input(format!("cannot resolve attachment directory: {e}"))
    })?;
    // Canonicalize the root too: the configured download root may itself
    // contain a symlink component (e.g. macOS `/var` → `/private/var`, or an
    // operator-symlinked staging dir), so comparing the canonical parent
    // against a raw root would spuriously reject in-sandbox files.
    let canonical_root = root.canonicalize().map_err(|e| {
        RimapError::invalid_input(format!("cannot resolve download sandbox root: {e}"))
    })?;
    if !canonical_parent.starts_with(&canonical_root) {
        return Err(RimapError::invalid_input(
            "attachment path is outside the download sandbox",
        ));
    }

    // The single ambient (path-following) step. Everything after is fd-relative
    // to this held directory descriptor, closing the resolve→read swap window.
    let dir = Dir::open_ambient_dir(&canonical_parent, ambient_authority()).map_err(|e| {
        RimapError::InternalSourced {
            message: "failed to open attachment directory".into(),
            source: Box::new(e),
        }
    })?;

    let meta = dir
        .symlink_metadata(&name)
        .map_err(|e| RimapError::invalid_input(format!("cannot stat attachment: {e}")))?;
    if meta.is_symlink() {
        return Err(RimapError::invalid_input(
            "attachment path is a symlink; refusing to follow",
        ));
    }
    if !meta.is_file() {
        return Err(RimapError::invalid_input(
            "attachment path is not a regular file",
        ));
    }
    if meta.len() > max_bytes as u64 {
        return Err(RimapError::invalid_input(format!(
            "attachment too large ({} bytes); max is {max_bytes}",
            meta.len()
        )));
    }

    let file = dir.open(&name).map_err(|e| RimapError::InternalSourced {
        message: "failed to open attachment file".into(),
        source: Box::new(e),
    })?;
    let mut buf = Vec::new();
    // Hard-cap the read at max_bytes + 1 so a file grown after the stat is
    // detected (buf > max_bytes) rather than read unbounded.
    file.take(max_bytes as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|e| RimapError::InternalSourced {
            message: "failed to read attachment file".into(),
            source: Box::new(e),
        })?;
    if buf.len() > max_bytes {
        return Err(RimapError::invalid_input(format!(
            "attachment too large (>{max_bytes} bytes)"
        )));
    }
    Ok(buf)
}

/// Fail-closed stub for non-Unix platforms.
///
/// The no-follow / containment guarantees rely on the same POSIX semantics the
/// writer uses. Rather than read a file without them, the sandbox refuses.
///
/// # Errors
///
/// Always returns `RimapError::Internal`.
#[cfg(not(unix))]
pub(crate) fn read_sandboxed_file(
    _root: &Path,
    _requested: &str,
    _max_bytes: usize,
) -> Result<Vec<u8>, RimapError> {
    Err(RimapError::Internal(
        "sandboxed attachment reads require a Unix platform (no-follow support)".into(),
    ))
}

/// Async wrapper around [`read_sandboxed_file`] that runs on a blocking thread.
///
/// # Errors
///
/// Propagates whatever [`read_sandboxed_file`] returns. Also returns
/// `RimapError::Internal` if the blocking task panics.
pub async fn read_sandboxed_file_async(
    root: Arc<Path>,
    requested: String,
    max_bytes: usize,
) -> Result<Vec<u8>, RimapError> {
    tokio::task::spawn_blocking(move || read_sandboxed_file(&root, &requested, max_bytes))
        .await
        .unwrap_or_else(|e| Err(crate::mcp::spawn_blocking_panic_error(e)))
}

/// Async wrapper around [`resolve_dest_dir`] that runs on a blocking thread.
///
/// # Errors
///
/// Propagates whatever [`resolve_dest_dir`] returns (typically
/// `RimapError::Authz` with `InvalidInput` when the path cannot be
/// canonicalized or escapes `allowed_root`, or `RimapError::InternalSourced`
/// if the directory cannot be opened). Returns `RimapError::Internal` if the
/// blocking task panics.
pub async fn resolve_dest_dir_async(
    dest_dir: Option<String>,
    root: Arc<Path>,
) -> Result<DestDir, RimapError> {
    tokio::task::spawn_blocking(move || resolve_dest_dir(dest_dir.as_deref(), &root, &root))
        .await
        .unwrap_or_else(|e| Err(crate::mcp::spawn_blocking_panic_error(e)))
}

/// Async wrapper around [`write_attachment`] that runs on a blocking thread.
///
/// # Errors
///
/// Propagates whatever [`write_attachment`] returns (`RimapError::Internal` on
/// I/O failure or after >1000 filename collisions). Also returns
/// `RimapError::Internal` if the blocking task panics.
pub async fn write_attachment_async(
    dest: DestDir,
    filename: String,
    data: Vec<u8>,
) -> Result<PathBuf, RimapError> {
    tokio::task::spawn_blocking(move || write_attachment(&dest, &filename, &data))
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

    /// Open `dir` as a held [`DestDir`] for the write tests (allowed-root ==
    /// the dir itself, no user-supplied `dest_dir`).
    #[cfg(unix)]
    fn dest_for(dir: &Path) -> DestDir {
        resolve_dest_dir(None, dir, dir).unwrap()
    }

    #[test]
    fn resolve_dest_dir_uses_fallback_when_none() {
        let tmp = tempfile::tempdir().unwrap();
        let fallback = tmp.path();
        let result = resolve_dest_dir(None, fallback, fallback).unwrap();
        assert_eq!(result.canonical(), fallback);
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
        let result = resolve_dest_dir(Some(sub.to_str().unwrap()), &allowed, &allowed).unwrap();
        assert!(result.canonical().starts_with(&allowed));
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
        let dest = dest_for(tmp.path());
        let path = write_attachment(&dest, "doc.pdf", b"data").unwrap();
        assert_eq!(path, dest.canonical().join("doc.pdf"));
        assert_eq!(std::fs::read(&path).unwrap(), b"data");
    }

    #[cfg(unix)]
    #[test]
    fn write_attachment_leaves_no_temp_orphan() {
        // A successful write removes its temp; only the final file remains.
        let tmp = tempfile::tempdir().unwrap();
        let dest = dest_for(tmp.path());
        write_attachment(&dest, "doc.pdf", b"data").unwrap();
        let leftover: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with(".rimap-tmp-"))
            .collect();
        assert!(leftover.is_empty(), "temp orphan left behind: {leftover:?}");
    }

    #[cfg(unix)]
    #[test]
    fn write_attachment_collision() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("doc.pdf"), b"old").unwrap();
        let dest = dest_for(tmp.path());
        let path = write_attachment(&dest, "doc.pdf", b"new").unwrap();
        assert_eq!(path, dest.canonical().join("doc_1.pdf"));
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
    }

    #[cfg(unix)]
    #[test]
    fn write_attachment_no_extension() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("readme"), b"old").unwrap();
        let dest = dest_for(tmp.path());
        let path = write_attachment(&dest, "readme", b"new").unwrap();
        assert_eq!(path, dest.canonical().join("readme_1"));
    }

    #[cfg(unix)]
    #[test]
    fn write_attachment_rejects_relative_traversal() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = dest_for(tmp.path());
        let path = write_attachment(&dest, "../escape.txt", b"data").unwrap();
        // Must land inside the dir, not escape.
        assert_eq!(path, dest.canonical().join("escape.txt"));
        assert_eq!(std::fs::read(&path).unwrap(), b"data");
    }

    #[cfg(unix)]
    #[test]
    fn write_attachment_rejects_absolute_path() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = dest_for(tmp.path());
        let path = write_attachment(&dest, "/etc/passwd", b"data").unwrap();
        assert_eq!(path, dest.canonical().join("passwd"));
        assert_eq!(std::fs::read(&path).unwrap(), b"data");
    }

    #[cfg(unix)]
    #[test]
    fn write_attachment_handles_deep_traversal() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = dest_for(tmp.path());
        let path = write_attachment(&dest, "../../.ssh/authorized_keys", b"data").unwrap();
        assert_eq!(path, dest.canonical().join("authorized_keys"));
    }

    #[cfg(unix)]
    #[test]
    fn write_attachment_sets_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().unwrap();
        let dest = dest_for(tmp.path());
        let path = write_attachment(&dest, "secret.mbox", b"raw email").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        // The export oracle writes raw message bytes; the file must be
        // owner-only regardless of the process umask.
        assert_eq!(mode & 0o777, 0o600, "expected 0600, got {:o}", mode & 0o777);
    }

    #[cfg(unix)]
    #[test]
    fn write_attachment_does_not_follow_symlink_at_final_path() {
        // A symlink pre-planted at the final name must not be followed: the
        // atomic hard_link placement yields AlreadyExists, so the writer
        // de-dups to a fresh name and the symlink target outside the sandbox
        // is never created or written. Guards the raw-export escape vector.
        let tmp = tempfile::tempdir().unwrap();
        let sandbox = tmp.path().join("sandbox");
        std::fs::create_dir_all(&sandbox).unwrap();
        let outside = tmp.path().join("outside-target.txt");
        std::os::unix::fs::symlink(&outside, sandbox.join("evil.mbox")).unwrap();

        let dest = dest_for(&sandbox);
        let path = write_attachment(&dest, "evil.mbox", b"payload").unwrap();

        // Wrote a de-duped sibling, not through the symlink.
        assert_eq!(path, dest.canonical().join("evil_1.mbox"));
        // The symlink target outside the sandbox was never created.
        assert!(
            !outside.exists(),
            "symlink was followed: target was written"
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"payload");
    }

    #[cfg(unix)]
    #[test]
    fn write_lands_via_held_fd_after_dir_swap() {
        // Open the destination as a held capability, then swap the directory
        // out from under its path: the original inode is moved aside (kept
        // linked at `real_moved`) and an attacker dir is planted at the
        // original path. The write must follow the held fd to the ORIGINAL
        // inode, not the attacker's dir now sitting at the path. This is the
        // directory-component race #317 targets; it would land in the
        // attacker's dir under the old path-based writer.
        let tmp = tempfile::tempdir().unwrap();
        let allowed = tmp.path().canonicalize().unwrap();
        let real = allowed.join("real");
        std::fs::create_dir_all(&real).unwrap();
        let dest = resolve_dest_dir(Some(real.to_str().unwrap()), &allowed, &real).unwrap();

        // Move the original inode aside (still linked) and plant an attacker
        // directory at the original path.
        let real_moved = allowed.join("real_moved");
        std::fs::rename(&real, &real_moved).unwrap();
        std::fs::create_dir_all(&real).unwrap();

        write_attachment(&dest, "x.mbox", b"data").unwrap();

        // The held fd wrote to the original inode (now at `real_moved`)...
        assert_eq!(std::fs::read(real_moved.join("x.mbox")).unwrap(), b"data");
        // ...and never to the attacker's directory at the swapped-in path.
        assert!(
            !real.join("x.mbox").exists(),
            "write followed the swapped-in path instead of the held fd"
        );
    }

    #[cfg(unix)]
    #[test]
    fn write_attachment_cleans_temp_on_collision_exhaustion() {
        // Force the de-dup loop to exhaust by pre-filling the original name and
        // all 1000 siblings, then assert the error path unlinks the temp (no
        // `.rimap-tmp-*` residue) rather than leaking a raw-email temp.
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("f"), b"x").unwrap();
        for i in 1..=1000 {
            std::fs::write(tmp.path().join(format!("f_{i}")), b"x").unwrap();
        }
        let dest = dest_for(tmp.path());
        let err = write_attachment(&dest, "f", b"payload").unwrap_err();
        assert_eq!(err.code(), rimap_core::ErrorCode::Internal);
        let temps: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with(".rimap-tmp-"))
            .collect();
        assert!(
            temps.is_empty(),
            "temp not cleaned on exhaustion: {temps:?}"
        );
    }

    // --- read_sandboxed_file (#408 attachments) ---

    #[cfg(unix)]
    #[test]
    fn read_sandboxed_file_reads_inside_root() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        std::fs::write(root.join("doc.pdf"), b"hello").unwrap();
        let data =
            read_sandboxed_file(&root, root.join("doc.pdf").to_str().unwrap(), 1024).unwrap();
        assert_eq!(data, b"hello");
    }

    #[cfg(unix)]
    #[test]
    fn read_sandboxed_file_rejects_path_outside_root() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap().join("sandbox");
        std::fs::create_dir_all(&root).unwrap();
        // A real file that exists but lives outside the sandbox root.
        let outside = tmp.path().canonicalize().unwrap().join("secret.txt");
        std::fs::write(&outside, b"top secret").unwrap();
        let err = read_sandboxed_file(&root, outside.to_str().unwrap(), 1024).unwrap_err();
        assert_eq!(err.code(), rimap_core::ErrorCode::InvalidInput);
        assert!(err.to_string().contains("outside the download sandbox"));
    }

    #[cfg(unix)]
    #[test]
    fn read_sandboxed_file_rejects_symlink_escaping_root() {
        // A symlink INSIDE the sandbox pointing OUTSIDE must not be followed:
        // canonicalize resolves it to the outside target, and starts_with(root)
        // then rejects it. Guards the exfiltration vector.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap().join("sandbox");
        std::fs::create_dir_all(&root).unwrap();
        let outside = tmp.path().canonicalize().unwrap().join("passwd");
        std::fs::write(&outside, b"root:x:0:0").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
        let err =
            read_sandboxed_file(&root, root.join("link").to_str().unwrap(), 1024).unwrap_err();
        assert_eq!(err.code(), rimap_core::ErrorCode::InvalidInput);
        // The outside file's bytes must never be returned.
        assert!(!err.to_string().contains("root:x"));
    }

    #[cfg(unix)]
    #[test]
    fn read_sandboxed_file_rejects_oversized_before_read() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        std::fs::write(root.join("big.bin"), vec![0u8; 2048]).unwrap();
        let err =
            read_sandboxed_file(&root, root.join("big.bin").to_str().unwrap(), 1024).unwrap_err();
        assert_eq!(err.code(), rimap_core::ErrorCode::InvalidInput);
        assert!(err.to_string().contains("too large"));
    }

    #[cfg(unix)]
    #[test]
    fn read_sandboxed_file_accepts_at_size_cap() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        std::fs::write(root.join("exact.bin"), vec![7u8; 1024]).unwrap();
        let data =
            read_sandboxed_file(&root, root.join("exact.bin").to_str().unwrap(), 1024).unwrap();
        assert_eq!(data.len(), 1024);
    }

    #[cfg(unix)]
    #[test]
    fn read_sandboxed_file_rejects_missing_file() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        let err =
            read_sandboxed_file(&root, root.join("nope.txt").to_str().unwrap(), 1024).unwrap_err();
        assert_eq!(err.code(), rimap_core::ErrorCode::InvalidInput);
    }

    #[cfg(unix)]
    #[test]
    fn read_sandboxed_file_rejects_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        std::fs::create_dir(root.join("subdir")).unwrap();
        let err =
            read_sandboxed_file(&root, root.join("subdir").to_str().unwrap(), 1024).unwrap_err();
        assert_eq!(err.code(), rimap_core::ErrorCode::InvalidInput);
        assert!(err.to_string().contains("not a regular file"));
    }

    #[cfg(unix)]
    #[test]
    fn read_sandboxed_file_reads_from_nested_subdir() {
        // A file the operator/exporter placed in a nested subdir of the shared
        // root is readable — confirms containment allows legitimate depth, not
        // only the root's immediate children.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        let nested = root.join("a/b");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join("f.bin"), b"deep").unwrap();
        let data =
            read_sandboxed_file(&root, nested.join("f.bin").to_str().unwrap(), 1024).unwrap();
        assert_eq!(data, b"deep");
    }

    #[cfg(unix)]
    #[test]
    fn read_sandboxed_file_accepts_symlinked_non_canonical_root() {
        // The configured download root may itself be reached through a symlink
        // (macOS `/var`→`/private/var`, or an operator-symlinked staging dir).
        // Passing that non-canonical root must still admit an in-sandbox file:
        // the containment check canonicalizes BOTH sides. Regression guard for
        // the bug the e2e_wire attachment round-trip surfaced.
        let tmp = tempfile::tempdir().unwrap();
        let real_root = tmp.path().canonicalize().unwrap().join("real_root");
        std::fs::create_dir_all(&real_root).unwrap();
        std::fs::write(real_root.join("doc.pdf"), b"payload").unwrap();

        // A symlink that points at the real root; use it as the configured root.
        let link_root = tmp.path().canonicalize().unwrap().join("link_root");
        std::os::unix::fs::symlink(&real_root, &link_root).unwrap();

        // Reference the file through the symlinked root path (as a caller who
        // was handed a path under the configured, non-canonical root would).
        let requested = link_root.join("doc.pdf");
        let data = read_sandboxed_file(&link_root, requested.to_str().unwrap(), 1024).unwrap();
        assert_eq!(data, b"payload");
    }

    #[cfg(not(unix))]
    #[test]
    fn read_sandboxed_file_fails_closed_on_non_unix() {
        let err = read_sandboxed_file(Path::new("/"), "/x", 1024).unwrap_err();
        assert_eq!(err.code(), rimap_core::ErrorCode::Internal);
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
