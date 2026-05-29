//! `AuditWriter` struct, `AuditOptions`, `Inner` state, the `open` /
//! lifecycle methods, and the platform-gated file/dir mode setters.
//! The per-kind `log_*` family lives in `super::log`, record emission
//! in `super::emit`, rotation in `super::rotation`, and self-check in
//! `super::self_check`. Tests for `open` / `write_record` / rotation /
//! `log_*` live at the bottom of this file.

use std::fs::File;
use std::io::BufWriter;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use fs4::{FileExt, TryLockError};

use crate::AuditError;

/// Options for opening an audit writer.
#[derive(Debug, Clone)]
pub struct AuditOptions {
    /// Path to the active audit file.
    pub path: PathBuf,
    /// Rotate when the file exceeds this many bytes. `0` disables rotation.
    pub rotate_bytes: u64,
    /// Number of rotated sibling files to keep on disk after a rotation.
    /// `0` means "keep none — delete every rotated sibling immediately
    /// after rotation". The default at the config layer is 5.
    pub rotate_keep: u32,
    /// Optional time-based retention in seconds. When set, rotated siblings
    /// older than `now - retention_seconds` are pruned during rotation,
    /// in addition to the count-based `rotate_keep` cap.
    pub retention_seconds: Option<u64>,
    /// If `true`, write/flush/fsync failures inside `write_record` are
    /// logged via `tracing::error!` and converted to `Ok(())` so the
    /// surrounding tool call still succeeds. The default is `false`
    /// (a write failure fails the tool call). Operators who explicitly
    /// accept losing audit records on storage failures opt in via this
    /// flag — see the audit security model docs for the trade-off.
    pub fail_open: bool,
    /// First `Seq` value this writer will allocate. Callers compute this from
    /// `read_trailing_state(path).last_seq.map(Seq::next).unwrap_or(Seq::FIRST)`
    /// before calling `open`.
    pub initial_seq: crate::record::ids::Seq,
}

/// Test-only failure injection hook. When `fail_next` is set, the next
/// call to `write_record_inner` returns an injected `AuditError::Write`
/// without touching the file, then clears the flag.
#[cfg(any(test, feature = "test-injection"))]
#[derive(Debug, Default)]
pub(super) struct FailureInjection {
    /// When `true`, the next `write_record_inner` call returns
    /// `AuditError::Write` without touching the file.
    pub(super) fail_next: std::sync::atomic::AtomicBool,
}

/// Append-only JSONL writer. Construct via [`AuditWriter::open`]. Cheaply
/// cloneable — the underlying `File` and `BufWriter` live behind an
/// `Arc<Mutex<_>>`, so all clones write through the same lock.
#[derive(Debug, Clone)]
pub struct AuditWriter {
    pub(super) path: PathBuf,
    pub(super) rotate_bytes: u64,
    pub(super) rotate_keep: u32,
    pub(super) retention_seconds: Option<u64>,
    pub(super) fail_open: bool,
    pub(super) process_id: crate::record::ids::ProcessId,
    pub(super) suppressed_failures: Arc<AtomicU64>,
    pub(super) tool_calls: Arc<AtomicU64>,
    pub(super) inner: Arc<Mutex<Inner>>,
    #[cfg(any(test, feature = "test-injection"))]
    pub(super) failure_injection: Arc<FailureInjection>,
}

#[derive(Debug)]
pub(crate) struct Inner {
    pub(crate) buf: BufWriter<File>,
    /// Total bytes written to the active file (used by rotation).
    pub(crate) bytes_written: u64,
    /// Next `Seq` value to hand out via `allocate_seq`.
    pub(crate) next_seq: crate::record::ids::Seq,
}

impl AuditWriter {
    /// Open or create the audit file at `opts.path`, acquire an exclusive
    /// non-blocking lock, and return the writer.
    ///
    /// # Errors
    /// - [`AuditError::ParentDir`] if the parent directory cannot be created.
    /// - [`AuditError::Open`] on I/O failure during `OpenOptions::open`.
    /// - [`AuditError::Locked`] if another process already holds the lock.
    pub fn open(opts: &AuditOptions) -> Result<Self, AuditError> {
        if let Some(parent) = opts.path.parent()
            && !parent.as_os_str().is_empty()
            && !parent.exists()
        {
            std::fs::create_dir_all(parent).map_err(|source| AuditError::ParentDir {
                path: opts.path.clone(),
                source,
            })?;
            set_parent_mode_0700(parent);
        }
        let file = crate::fs::writer_open_options()
            .open(&opts.path)
            .map_err(|source| AuditError::Open {
                path: opts.path.clone(),
                source,
            })?;
        // Defense in depth: re-assert mode in case the file existed pre-open
        // with wider perms. When the file is newly created, `writer_open_options`
        // already sets 0600 atomically; this is a no-op in that case.
        set_file_mode_0600(&file);

        match FileExt::try_lock(&file) {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(AuditError::Locked {
                    path: opts.path.clone(),
                });
            }
            Err(TryLockError::Error(source)) => {
                return Err(AuditError::Open {
                    path: opts.path.clone(),
                    source,
                });
            }
        }

        let bytes_written = file
            .metadata()
            .map_err(|source| AuditError::Open {
                path: opts.path.clone(),
                source,
            })?
            .len();

        Ok(Self {
            path: opts.path.clone(),
            rotate_bytes: opts.rotate_bytes,
            rotate_keep: opts.rotate_keep,
            retention_seconds: opts.retention_seconds,
            fail_open: opts.fail_open,
            process_id: crate::record::ids::ProcessId::new_now(),
            suppressed_failures: Arc::new(AtomicU64::new(0)),
            tool_calls: Arc::new(AtomicU64::new(0)),
            inner: Arc::new(Mutex::new(Inner {
                buf: BufWriter::new(file),
                bytes_written,
                next_seq: opts.initial_seq,
            })),
            #[cfg(any(test, feature = "test-injection"))]
            failure_injection: Arc::new(FailureInjection::default()),
        })
    }

    /// The active audit file path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Rotation threshold in bytes. `0` disables rotation.
    #[must_use]
    pub fn rotate_bytes(&self) -> u64 {
        self.rotate_bytes
    }

    /// The process ID this writer was opened with. Stable for the lifetime
    /// of the writer.
    #[must_use]
    pub fn process_id(&self) -> crate::record::ids::ProcessId {
        self.process_id
    }

    /// Number of write/flush/fsync failures suppressed by `fail_open = true`
    /// since this writer was opened. Accumulated via `Relaxed` atomic
    /// increments inside `write_record`.
    ///
    /// ## Not yet wired into `process_end`
    ///
    /// The intent is for the shutdown `process_end` record to read this
    /// counter and persist it as `audit_write_failures_suppressed` so
    /// operators running `fail_open = true` can see how many records
    /// were dropped in the process's lifetime. That wiring depends on
    /// the audit lifecycle glue (`process_start`/`process_end` emission)
    /// tracked in issue #8 and is not yet in place. Today this accessor
    /// is available for ad-hoc inspection and tests; the persistent
    /// audit trail will follow when #8 lands.
    #[must_use]
    pub fn suppressed_failures(&self) -> u64 {
        self.suppressed_failures.load(Ordering::Relaxed)
    }

    /// Number of tool calls dispatched in this process — incremented once
    /// per successful [`AuditWriter::log_tool_start`]. Counts every call
    /// whose `tool_start` was accepted, including those whose write was
    /// later suppressed under `fail_open = true`; a `fail_open = false`
    /// write failure aborts the call and is not counted. Read at shutdown
    /// to populate `ProcessEnd::total_tool_calls`.
    #[must_use]
    pub fn total_tool_calls(&self) -> u64 {
        self.tool_calls.load(Ordering::Relaxed)
    }

    /// Test-only: cause the next `write_record_inner` call to fail with
    /// `AuditError::Write`. Used to exercise `fail_open = true`
    /// suppression paths without filesystem tricks (#72).
    #[cfg(any(test, feature = "test-injection"))]
    pub fn force_next_write_failure(&self) {
        self.failure_injection
            .fail_next
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// Total bytes written through this writer since `open` (including bytes
    /// already present at open time). Used by rotation logic.
    ///
    /// # Errors
    /// Returns `AuditError::Write` if the internal mutex is poisoned.
    pub fn bytes_written(&self) -> Result<u64, AuditError> {
        let guard = self.lock_inner()?;
        Ok(guard.bytes_written)
    }

    /// Returns the current on-disk length of the active file. Used by tests.
    ///
    /// # Errors
    /// I/O error from `metadata()`.
    pub fn on_disk_len(&self) -> Result<u64, AuditError> {
        let guard = self.lock_inner()?;
        let meta = guard
            .buf
            .get_ref()
            .metadata()
            .map_err(|source| AuditError::Write {
                path: self.path.clone(),
                source,
            })?;
        Ok(meta.len())
    }
}

#[cfg(unix)]
pub(crate) fn set_file_mode_0600(file: &File) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = file.metadata() {
        let mut perms = meta.permissions();
        perms.set_mode(0o600);
        if let Err(err) = file.set_permissions(perms) {
            tracing::warn!(error = %err, "failed to set audit file mode 0600");
        }
    }
}

#[cfg(not(unix))]
pub(crate) fn set_file_mode_0600(_file: &File) {}

#[cfg(unix)]
fn set_parent_mode_0700(parent: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(parent) {
        let mut perms = meta.permissions();
        perms.set_mode(0o700);
        if let Err(err) = std::fs::set_permissions(parent, perms) {
            tracing::warn!(error = %err, "failed to set audit parent dir mode 0700");
        }
    }
}

#[cfg(not(unix))]
fn set_parent_mode_0700(_parent: &Path) {}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
#[expect(clippy::expect_used, reason = "tests")]
#[expect(clippy::panic, reason = "tests")]
mod tests {
    use tempfile::TempDir;

    use crate::AuditError;
    use crate::writer::{AuditOptions, AuditWriter};

    #[test]
    fn open_creates_file_and_acquires_lock() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = AuditWriter::open(&AuditOptions {
            path: path.clone(),
            rotate_bytes: 0,
            rotate_keep: 0,
            retention_seconds: None,
            fail_open: false,
            initial_seq: crate::record::ids::Seq::FIRST,
        })
        .unwrap();
        assert_eq!(writer.path(), path);
        assert!(path.exists());
    }

    #[test]
    fn second_open_against_same_path_fails_with_locked() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let _first = AuditWriter::open(&AuditOptions {
            path: path.clone(),
            rotate_bytes: 0,
            rotate_keep: 0,
            retention_seconds: None,
            fail_open: false,
            initial_seq: crate::record::ids::Seq::FIRST,
        })
        .unwrap();
        let err = AuditWriter::open(&AuditOptions {
            path: path.clone(),
            rotate_bytes: 0,
            rotate_keep: 0,
            retention_seconds: None,
            fail_open: false,
            initial_seq: crate::record::ids::Seq::FIRST,
        })
        .unwrap_err();
        match err {
            AuditError::Locked { path: p } => assert_eq!(p, path),
            other => panic!("expected Locked, got {other:?}"),
        }
    }

    #[test]
    fn drop_releases_the_lock() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        {
            let _first = AuditWriter::open(&AuditOptions {
                path: path.clone(),
                rotate_bytes: 0,
                rotate_keep: 0,
                retention_seconds: None,
                fail_open: false,
                initial_seq: crate::record::ids::Seq::FIRST,
            })
            .unwrap();
        }
        // After drop, a second open succeeds.
        let _second = AuditWriter::open(&AuditOptions {
            path: path.clone(),
            rotate_bytes: 0,
            rotate_keep: 0,
            retention_seconds: None,
            fail_open: false,
            initial_seq: crate::record::ids::Seq::FIRST,
        })
        .unwrap();
    }

    #[test]
    fn open_creates_missing_parent_directory() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nested").join("audit.jsonl");
        let _writer = AuditWriter::open(&AuditOptions {
            path: path.clone(),
            rotate_bytes: 0,
            rotate_keep: 0,
            retention_seconds: None,
            fail_open: false,
            initial_seq: crate::record::ids::Seq::FIRST,
        })
        .unwrap();
        assert!(path.exists());
        assert!(path.parent().unwrap().is_dir());
    }

    #[test]
    fn write_record_appends_one_jsonl_line() {
        use crate::record::ids::{ProcessId, Seq, Timestamp};
        use crate::record::{AuditRecord, Payload, ProcessEnd, ProcessEndReason};

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = AuditWriter::open(&AuditOptions {
            path: path.clone(),
            rotate_bytes: 0,
            rotate_keep: 0,
            retention_seconds: None,
            fail_open: false,
            initial_seq: crate::record::ids::Seq::FIRST,
        })
        .unwrap();

        let rec = AuditRecord {
            seq: Seq::FIRST,
            ts: Timestamp::now(),
            process_id: ProcessId::new_now(),
            payload: Payload::ProcessEnd(ProcessEnd {
                reason: ProcessEndReason::Eof,
                total_tool_calls: 0,
            }),
        };
        writer.write_record(&rec).unwrap();
        drop(writer);

        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents.lines().count(), 1);
        let line = contents.lines().next().unwrap();
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(v["kind"], "process_end");
        assert!(contents.ends_with('\n'));
    }

    #[test]
    fn write_record_tracks_bytes_written() {
        use crate::record::ids::{ProcessId, Seq, Timestamp};
        use crate::record::{AuditRecord, Payload, ProcessEnd, ProcessEndReason};

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = AuditWriter::open(&AuditOptions {
            path: path.clone(),
            rotate_bytes: 0,
            rotate_keep: 0,
            retention_seconds: None,
            fail_open: false,
            initial_seq: crate::record::ids::Seq::FIRST,
        })
        .unwrap();

        for seq in 1_u64..=5 {
            let rec = AuditRecord {
                seq: Seq(seq),
                ts: Timestamp::now(),
                process_id: ProcessId::new_now(),
                payload: Payload::ProcessEnd(ProcessEnd {
                    reason: ProcessEndReason::Eof,
                    total_tool_calls: seq,
                }),
            };
            writer.write_record(&rec).unwrap();
        }
        assert_eq!(
            writer.bytes_written().unwrap(),
            writer.on_disk_len().unwrap()
        );
    }

    #[test]
    fn rotation_creates_new_file_and_preserves_contents() {
        use crate::record::ids::{ProcessId, Seq, Timestamp};
        use crate::record::{AuditRecord, Payload, ProcessEnd, ProcessEndReason};

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = AuditWriter::open(&AuditOptions {
            path: path.clone(),
            rotate_bytes: 200,
            rotate_keep: 5,
            retention_seconds: None,
            fail_open: false,
            initial_seq: crate::record::ids::Seq::FIRST,
        })
        .unwrap();

        for seq in 1_u64..=5 {
            let rec = AuditRecord {
                seq: Seq(seq),
                ts: Timestamp::now(),
                process_id: ProcessId::new_now(),
                payload: Payload::ProcessEnd(ProcessEnd {
                    reason: ProcessEndReason::Eof,
                    total_tool_calls: seq,
                }),
            };
            writer.write_record(&rec).unwrap();
        }

        let mut rotated = 0;
        for entry in std::fs::read_dir(dir.path()).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with("audit.jsonl.") {
                rotated += 1;
            }
        }
        assert!(
            rotated >= 1,
            "expected at least one rotated file, got {rotated}"
        );

        let mut all = String::new();
        for entry in std::fs::read_dir(dir.path()).unwrap() {
            let entry = entry.unwrap();
            let p = entry.path();
            if p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("audit.jsonl")
            {
                all.push_str(&std::fs::read_to_string(&p).unwrap());
            }
        }
        let seqs: std::collections::BTreeSet<u64> = all
            .lines()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .filter_map(|v| v.get("seq").and_then(serde_json::Value::as_u64))
            .collect();
        assert_eq!(seqs, (1_u64..=5).collect::<std::collections::BTreeSet<_>>(),);
        assert_eq!(
            seqs.len(),
            5,
            "expected exactly 5 distinct seqs across all files"
        );
        assert!(path.exists(), "active file still exists after rotation");
    }

    #[test]
    fn after_rotation_the_lock_still_blocks_new_writers() {
        use crate::record::ids::{ProcessId, Seq, Timestamp};
        use crate::record::{AuditRecord, Payload, ProcessEnd, ProcessEndReason};

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = AuditWriter::open(&AuditOptions {
            path: path.clone(),
            rotate_bytes: 200,
            rotate_keep: 0,
            retention_seconds: None,
            fail_open: false,
            initial_seq: crate::record::ids::Seq::FIRST,
        })
        .unwrap();

        for seq in 1_u64..=5 {
            let rec = AuditRecord {
                seq: Seq(seq),
                ts: Timestamp::now(),
                process_id: ProcessId::new_now(),
                payload: Payload::ProcessEnd(ProcessEnd {
                    reason: ProcessEndReason::Eof,
                    total_tool_calls: seq,
                }),
            };
            writer.write_record(&rec).unwrap();
        }

        let err = AuditWriter::open(&AuditOptions {
            path: path.clone(),
            rotate_bytes: 0,
            rotate_keep: 0,
            retention_seconds: None,
            fail_open: false,
            initial_seq: crate::record::ids::Seq::FIRST,
        })
        .unwrap_err();
        match err {
            AuditError::Locked { .. } => {}
            other => panic!("expected Locked after rotation, got {other:?}"),
        }
    }

    #[test]
    fn writer_holds_a_stable_process_id() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = AuditWriter::open(&AuditOptions {
            path,
            rotate_bytes: 0,
            rotate_keep: 0,
            retention_seconds: None,
            fail_open: false,
            initial_seq: crate::record::ids::Seq::FIRST,
        })
        .unwrap();
        let pid_a = writer.process_id();
        let pid_b = writer.process_id();
        assert_eq!(pid_a, pid_b);
    }

    #[test]
    fn writer_allocates_sequential_seqs() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = AuditWriter::open(&AuditOptions {
            path,
            rotate_bytes: 0,
            rotate_keep: 0,
            retention_seconds: None,
            fail_open: false,
            initial_seq: crate::record::ids::Seq::FIRST,
        })
        .unwrap();
        let s1 = writer.allocate_seq().unwrap();
        let s2 = writer.allocate_seq().unwrap();
        let s3 = writer.allocate_seq().unwrap();
        assert_eq!(s1, crate::record::ids::Seq::FIRST);
        assert_eq!(s2, crate::record::ids::Seq(2));
        assert_eq!(s3, crate::record::ids::Seq(3));
    }

    #[test]
    fn writer_resumes_seq_from_initial_seq_option() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = AuditWriter::open(&AuditOptions {
            path,
            rotate_bytes: 0,
            rotate_keep: 0,
            retention_seconds: None,
            fail_open: false,
            initial_seq: crate::record::ids::Seq(42),
        })
        .unwrap();
        assert_eq!(writer.allocate_seq().unwrap(), crate::record::ids::Seq(42));
        assert_eq!(writer.allocate_seq().unwrap(), crate::record::ids::Seq(43));
    }

    #[test]
    fn log_auth_writes_one_record_with_allocated_seq() {
        use crate::record::{AuthEvent, AuthResult};

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = AuditWriter::open(&AuditOptions {
            path: path.clone(),
            rotate_bytes: 0,
            rotate_keep: 0,
            retention_seconds: None,
            fail_open: false,
            initial_seq: crate::record::ids::Seq::FIRST,
        })
        .unwrap();

        let seq = writer
            .log_auth(AuthEvent {
                account: None,
                result: AuthResult::Success,
                host: "127.0.0.1".to_string(),
                port: 993,
                username: "alice@example.test".to_string(),
                tls_fingerprint_sha256: Some("ab".repeat(32)),
                fingerprint_match: Some(true),
                error_code: None,
                credential_source: None,
            })
            .unwrap();

        assert_eq!(seq, crate::record::ids::Seq::FIRST);
        drop(writer);

        let contents = std::fs::read_to_string(&path).unwrap();
        let line = contents.lines().next().unwrap();
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(v["kind"], "auth");
        assert_eq!(v["seq"], 1);
        assert_eq!(v["result"], "success");
        assert_eq!(v["host"], "127.0.0.1");
        assert_eq!(v["fingerprint_match"], true);
    }

    #[test]
    fn log_auth_uses_writer_process_id_for_every_record() {
        use crate::record::{AuthEvent, AuthResult};

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = AuditWriter::open(&AuditOptions {
            path: path.clone(),
            rotate_bytes: 0,
            rotate_keep: 0,
            retention_seconds: None,
            fail_open: false,
            initial_seq: crate::record::ids::Seq::FIRST,
        })
        .unwrap();
        let pid = writer.process_id();

        let make = || AuthEvent {
            account: None,
            result: AuthResult::Failure,
            host: "h".into(),
            port: 1,
            username: "u".into(),
            tls_fingerprint_sha256: None,
            fingerprint_match: None,
            error_code: Some(rimap_core::ErrorCode::Tls),
            credential_source: None,
        };
        writer.log_auth(make()).unwrap();
        writer.log_auth(make()).unwrap();
        drop(writer);

        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<serde_json::Value> = contents
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0]["process_id"], pid.to_string());
        assert_eq!(lines[1]["process_id"], pid.to_string());
        assert_eq!(lines[0]["seq"], 1);
        assert_eq!(lines[1]["seq"], 2);
    }

    #[test]
    fn log_process_start_populates_chain_of_history_fields() {
        use crate::writer::ProcessStartInputs;
        use crate::writer::self_check::TrailingState;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = AuditWriter::open(&AuditOptions {
            path: path.clone(),
            rotate_bytes: 0,
            rotate_keep: 0,
            retention_seconds: None,
            fail_open: false,
            initial_seq: crate::record::ids::Seq::FIRST,
        })
        .unwrap();

        let prior_pid = crate::record::ids::ProcessId::new_now();
        let inputs = ProcessStartInputs {
            version: "0.0.0".to_string(),
            git_commit: String::new(),
            posture: Some(rimap_core::Posture::DraftSafe),
            accounts: None,
            config_path: std::path::PathBuf::from("/tmp/config.toml"),
            config_hash_sha256: "ab".repeat(32),
            trailing: TrailingState {
                last_seq: Some(crate::record::ids::Seq(99)),
                last_process_id: Some(prior_pid),
                last_recorded_inode: Some(7777),
            },
            current_inode: 8888,
        };
        let seq = writer.log_process_start(inputs).unwrap();
        assert_eq!(seq, crate::record::ids::Seq::FIRST);
        drop(writer);

        let contents = std::fs::read_to_string(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(contents.lines().next().unwrap()).unwrap();
        assert_eq!(v["kind"], "process_start");
        assert_eq!(v["previous_last_seq"], 99);
        assert_eq!(v["previous_process_id"], prior_pid.to_string());
        assert_eq!(v["previous_file_inode"], 8888);
        assert_eq!(v["audit_file_inode_changed"], true);
    }

    #[test]
    fn log_process_end_writes_valid_record() {
        use crate::record::{ProcessEnd, ProcessEndReason};

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = AuditWriter::open(&AuditOptions {
            path: path.clone(),
            rotate_bytes: 0,
            rotate_keep: 0,
            retention_seconds: None,
            fail_open: false,
            initial_seq: crate::record::ids::Seq::FIRST,
        })
        .unwrap();

        let seq = writer
            .log_process_end(ProcessEnd {
                reason: ProcessEndReason::Eof,
                total_tool_calls: 42,
            })
            .unwrap();
        assert_eq!(seq, crate::record::ids::Seq::FIRST);
        drop(writer);

        let contents = std::fs::read_to_string(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(contents.lines().next().unwrap()).unwrap();
        assert_eq!(v["kind"], "process_end");
        assert_eq!(v["reason"], "eof");
        assert_eq!(v["total_tool_calls"], 42);
    }

    #[test]
    fn total_tool_calls_counts_each_tool_start() {
        use crate::writer::ToolStartInputs;

        let dir = TempDir::new().unwrap();
        let writer = AuditWriter::open(&AuditOptions {
            path: dir.path().join("audit.jsonl"),
            rotate_bytes: 0,
            rotate_keep: 0,
            retention_seconds: None,
            fail_open: false,
            initial_seq: crate::record::ids::Seq::FIRST,
        })
        .unwrap();

        assert_eq!(writer.total_tool_calls(), 0);

        let inputs = || ToolStartInputs {
            tool: rimap_core::tool::ToolName::Search,
            account: Some("a".to_string()),
            posture_effective: Some(rimap_core::Posture::DraftSafe),
            arguments_redacted: serde_json::Value::Object(serde_json::Map::new()),
            arguments_hash_sha256: "0".repeat(64),
        };
        writer.log_tool_start(inputs()).unwrap();
        writer.log_tool_start(inputs()).unwrap();
        assert_eq!(writer.total_tool_calls(), 2);

        // A non-tool_start record must not bump the counter.
        writer
            .log_process_end(crate::record::ProcessEnd {
                reason: crate::record::ProcessEndReason::Eof,
                total_tool_calls: writer.total_tool_calls(),
            })
            .unwrap();
        assert_eq!(writer.total_tool_calls(), 2);

        // Clones share the counter.
        assert_eq!(writer.clone().total_tool_calls(), 2);
    }

    #[test]
    fn log_process_end_uses_writer_process_id() {
        use crate::record::{ProcessEnd, ProcessEndReason};

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = AuditWriter::open(&AuditOptions {
            path: path.clone(),
            rotate_bytes: 0,
            rotate_keep: 0,
            retention_seconds: None,
            fail_open: false,
            initial_seq: crate::record::ids::Seq::FIRST,
        })
        .unwrap();
        let pid = writer.process_id();

        writer
            .log_process_end(ProcessEnd {
                reason: ProcessEndReason::SignalTerm,
                total_tool_calls: 7,
            })
            .unwrap();
        drop(writer);

        let contents = std::fs::read_to_string(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(contents.lines().next().unwrap()).unwrap();
        assert_eq!(v["process_id"], pid.to_string());
        assert_eq!(v["reason"], "signal_term");
    }

    #[test]
    fn log_process_start_marks_inode_unchanged_when_matching() {
        use crate::writer::ProcessStartInputs;
        use crate::writer::self_check::TrailingState;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = AuditWriter::open(&AuditOptions {
            path: path.clone(),
            rotate_bytes: 0,
            rotate_keep: 0,
            retention_seconds: None,
            fail_open: false,
            initial_seq: crate::record::ids::Seq::FIRST,
        })
        .unwrap();

        let inputs = ProcessStartInputs {
            version: "0.0.0".to_string(),
            git_commit: String::new(),
            posture: Some(rimap_core::Posture::DraftSafe),
            accounts: None,
            config_path: std::path::PathBuf::from("/tmp/c.toml"),
            config_hash_sha256: "00".repeat(32),
            trailing: TrailingState {
                last_seq: None,
                last_process_id: None,
                last_recorded_inode: Some(4242),
            },
            current_inode: 4242,
        };
        writer.log_process_start(inputs).unwrap();
        drop(writer);

        let contents = std::fs::read_to_string(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(contents.lines().next().unwrap()).unwrap();
        assert_eq!(v["audit_file_inode_changed"], false);
    }

    #[test]
    fn rotate_bytes_accessor_returns_configured_threshold() {
        // Pin `rotate_bytes()` so the `-> u64 with 0` and `with 1` mutations
        // are observable. Pick a non-zero, non-one value the trivial stubs
        // cannot return.
        let dir = TempDir::new().unwrap();
        let writer = AuditWriter::open(&AuditOptions {
            path: dir.path().join("audit.jsonl"),
            rotate_bytes: 4242,
            rotate_keep: 0,
            retention_seconds: None,
            fail_open: false,
            initial_seq: crate::record::ids::Seq::FIRST,
        })
        .unwrap();
        assert_eq!(writer.rotate_bytes(), 4242);
    }

    #[test]
    fn force_next_write_failure_makes_next_write_record_fail() {
        // Pins the test-injection helper: setting the flag must cause the
        // *next* `write_record` to return `AuditError::Write`. The
        // `with ()` mutation would skip the store and the write would
        // succeed.
        use crate::record::ids::{ProcessId, Seq, Timestamp};
        use crate::record::{AuditRecord, Payload, ProcessEnd, ProcessEndReason};

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = AuditWriter::open(&AuditOptions {
            path,
            rotate_bytes: 0,
            rotate_keep: 0,
            retention_seconds: None,
            fail_open: false,
            initial_seq: Seq::FIRST,
        })
        .unwrap();

        let rec = AuditRecord {
            seq: Seq::FIRST,
            ts: Timestamp::now(),
            process_id: ProcessId::new_now(),
            payload: Payload::ProcessEnd(ProcessEnd {
                reason: ProcessEndReason::Eof,
                total_tool_calls: 0,
            }),
        };

        writer.force_next_write_failure();
        let err = writer
            .write_record(&rec)
            .expect_err("injected failure must surface as Err");
        match err {
            AuditError::Write { .. } => {}
            other => panic!("expected AuditError::Write, got {other:?}"),
        }

        // The flag is single-shot: the *next* write should succeed.
        writer.write_record(&rec).unwrap();
    }

    #[test]
    fn force_next_write_failure_is_observed_by_fail_open_counter() {
        // Confirms the injection helper is wired through the same path as
        // real write failures: with `fail_open = true`, an injected failure
        // must increment `suppressed_failures`. The `with ()` mutation
        // would leave the flag unset and the counter at 0.
        use crate::record::ids::{ProcessId, Seq, Timestamp};
        use crate::record::{AuditRecord, Payload, ProcessEnd, ProcessEndReason};

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = AuditWriter::open(&AuditOptions {
            path,
            rotate_bytes: 0,
            rotate_keep: 0,
            retention_seconds: None,
            fail_open: true,
            initial_seq: Seq::FIRST,
        })
        .unwrap();

        let rec = AuditRecord {
            seq: Seq::FIRST,
            ts: Timestamp::now(),
            process_id: ProcessId::new_now(),
            payload: Payload::ProcessEnd(ProcessEnd {
                reason: ProcessEndReason::Eof,
                total_tool_calls: 0,
            }),
        };

        writer.force_next_write_failure();
        // fail_open suppresses the error; the call returns Ok but the counter
        // increments.
        writer.write_record(&rec).unwrap();
        assert_eq!(writer.suppressed_failures(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn open_sets_file_mode_to_0600() {
        // Pin `set_file_mode_0600 with ()` mutation: a freshly-opened audit
        // file must have permission bits 0o600. Pre-create the file with a
        // wider mode so the defense-in-depth re-assertion in `open` is also
        // exercised.
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        std::fs::File::create(&path).unwrap();
        let mut wide = std::fs::metadata(&path).unwrap().permissions();
        wide.set_mode(0o644);
        std::fs::set_permissions(&path, wide).unwrap();

        let _writer = AuditWriter::open(&AuditOptions {
            path: path.clone(),
            rotate_bytes: 0,
            rotate_keep: 0,
            retention_seconds: None,
            fail_open: false,
            initial_seq: crate::record::ids::Seq::FIRST,
        })
        .unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "audit file must be 0600 after open");
    }

    #[cfg(unix)]
    #[test]
    fn open_creates_parent_dir_with_mode_0700() {
        // Pin `set_parent_mode_0700 with ()` mutation: when `open` creates a
        // missing parent, that directory must end up at 0o700.
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let parent = dir.path().join("audit-dir");
        let path = parent.join("audit.jsonl");
        let _writer = AuditWriter::open(&AuditOptions {
            path: path.clone(),
            rotate_bytes: 0,
            rotate_keep: 0,
            retention_seconds: None,
            fail_open: false,
            initial_seq: crate::record::ids::Seq::FIRST,
        })
        .unwrap();

        let mode = std::fs::metadata(&parent).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "audit parent dir must be 0700");
    }
}
