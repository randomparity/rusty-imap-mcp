//! The "build a record and put bytes on the disk" core of the writer.
//!
//! Holds the seq allocator, the rotation-aware write path, the optional
//! fail-open suppression policy, and the small synchronous I/O helpers.
//! Lives separately from the per-kind `log_*` family so the kind-specific
//! glue can stay narrow.

use std::path::Path;
use std::sync::atomic::Ordering;

use crate::AuditError;

use super::{AuditWriter, Inner};

impl AuditWriter {
    /// Allocate the next monotonic `Seq` value. Locks the inner mutex
    /// briefly; never crosses an `.await`.
    ///
    /// ## Ordering contract
    ///
    /// `allocate_seq` and `write_record` each acquire the inner lock
    /// independently. Two concurrent `log_auth` / `log_process_start`
    /// callers can therefore produce a file where physical line order
    /// disagrees with `seq` order (allocation races with the write).
    ///
    /// Readers of the audit log MUST sort by the `seq` field rather than
    /// relying on line order. No outer lock serializes the writers into
    /// one, so this is a live hazard rather than a hypothetical one:
    /// `rimap_server::boot::audit_init` writes `process_start` before
    /// serving begins, but from then on `Connection::emit_auth` (an `auth`
    /// record per connect, inline on a runtime worker, serialized per
    /// account by the session lock but not across accounts) and
    /// `rimap_server::mcp::audit_envelope` (`tool_start` / `tool_end` on
    /// the blocking pool) can be inside this pair concurrently.
    ///
    /// # Errors
    /// Returns `AuditError::Write` if the internal mutex is poisoned.
    #[must_use = "the seq value should be stored in the audit record"]
    pub fn allocate_seq(&self) -> Result<crate::record::ids::Seq, AuditError> {
        let mut guard = self.lock_inner()?;
        let seq = guard.next_seq;
        guard.next_seq = seq.next();
        Ok(seq)
    }

    /// Acquire the inner mutex, translating poisoning into a typed
    /// `AuditError::Write`. The poisoned-path message is deliberately
    /// generic — the mutex guards both the sequence counter and the
    /// write buffer, so "poisoned" is the only meaningful signal.
    pub(super) fn lock_inner(&self) -> Result<std::sync::MutexGuard<'_, Inner>, AuditError> {
        self.inner.lock().map_err(|_| AuditError::Write {
            path: self.path.clone(),
            source: std::io::Error::other("audit mutex poisoned"),
        })
    }

    /// Allocate a seq, build an `AuditRecord` wrapping `payload`, stamp it
    /// with the writer's `process_id` and `Timestamp::now()`, and write it
    /// as a single JSONL line. All `log_*` methods route through this helper
    /// so the allocate-build-write skeleton lives in one place.
    pub(super) fn emit(
        &self,
        payload: crate::record::Payload,
    ) -> Result<crate::record::ids::Seq, AuditError> {
        let seq = self.allocate_seq()?;
        let record = crate::record::AuditRecord {
            seq,
            ts: crate::record::ids::Timestamp::now(),
            process_id: self.process_id,
            payload,
        };
        self.write_record(&record)?;
        Ok(seq)
    }

    /// Serialize `record` as one JSONL line, append it to the active file,
    /// flush the buffer, and fsync on `process_*` / `auth` / `config` kinds.
    ///
    /// If `fail_open` is `true`, write/flush/fsync failures are logged via
    /// `tracing::error!` and converted to `Ok(())`. Serialization errors are
    /// programmer errors and never suppressed regardless of `fail_open`.
    /// Suppressed failures are counted via [`Self::suppressed_failures`].
    ///
    /// # Blocking
    ///
    /// This function performs synchronous filesystem I/O: at minimum a
    /// `write_all` + `flush` + (conditionally) `fsync`, and on rotation
    /// additionally `rename`, `open`, `try_lock`, `read_dir`,
    /// `symlink_metadata`, and `remove_file`. An async caller should move it
    /// onto the blocking pool rather than stall a runtime worker on it — in
    /// this workspace through `DispatchDrain::spawn_blocking_tracked`, which
    /// also registers the write with the shutdown drain (#672), rather than a
    /// bare `tokio::task::spawn_blocking`. The `tool_start` / `tool_end`
    /// emitters in `rimap_server::mcp::audit_envelope` are the pattern;
    /// `docs/architecture/audit-locking.md` has the rule and its exceptions.
    ///
    /// `Connection::emit_auth` deliberately does not, and ADR-0014 records
    /// why: the hop loses the record when the runtime is shutting down, and
    /// the `Drop` caller has nobody to await it. The cost it accepts in
    /// exchange is exactly the stall described above — see that function's
    /// docs for the bound on how many workers it can pin, and
    /// `docs/audit-log.md` for why it makes `audit.path` a local-storage
    /// requirement.
    ///
    /// # Errors
    /// - [`AuditError::Serialize`] on JSON failure (never suppressed).
    /// - [`AuditError::Write`] / [`AuditError::Fsync`] / [`AuditError::Rotate`]
    ///   when `fail_open == false`.
    pub fn write_record(&self, record: &crate::record::AuditRecord) -> Result<(), AuditError> {
        match self.write_record_inner(record) {
            Ok(()) => Ok(()),
            Err(AuditError::Serialize(e)) => {
                // Serialization failures are programmer errors, not storage
                // failures. Never suppressed regardless of fail_open.
                Err(AuditError::Serialize(e))
            }
            Err(err) if self.fail_open => {
                // Emit only the stable error code, not the full Display
                // chain which would duplicate the audit path (already in
                // the explicit `path` field below) and any filesystem
                // layout contained in an underlying io::Error. Operators
                // who want the full Display can enable TRACE-level
                // logging where `write_record_inner` records it.
                // (LOCAL-ERR-05)
                tracing::error!(
                    path = %self.path.display(),
                    error_code = %err.code(),
                    "audit write failed; fail_open=true so suppressing and continuing",
                );
                self.count_suppressed_failure();
                Ok(())
            }
            Err(err) => Err(err),
        }
    }

    /// Count one record that is not on disk and that no caller was told
    /// about. See [`super::AuditWriter::suppressed_failures`] for the two
    /// sources.
    pub(super) fn count_suppressed_failure(&self) {
        self.suppressed_failures.fetch_add(1, Ordering::Relaxed);
    }

    fn write_record_inner(&self, record: &crate::record::AuditRecord) -> Result<(), AuditError> {
        #[cfg(any(test, feature = "test-injection"))]
        if self
            .failure_injection
            .fail_next
            .swap(false, std::sync::atomic::Ordering::Relaxed)
        {
            return Err(AuditError::Write {
                path: self.path.clone(),
                source: std::io::Error::other("injected failure (test)"),
            });
        }

        let mut bytes = serde_json::to_vec(record).map_err(AuditError::Serialize)?;
        bytes.push(b'\n');

        let mut guard = self.lock_inner()?;

        // Rotation check happens inside the same critical section as the write.
        // This prevents two clones of AuditWriter from both observing "needs
        // rotation" and racing on the rename.
        if self.rotate_bytes > 0 && guard.bytes_written >= self.rotate_bytes {
            let (new_buf, new_len) =
                super::rotation::rotate_file(&self.path, self.rotate_keep, self.retention_seconds)?;
            guard.buf = new_buf;
            guard.bytes_written = new_len;
            tracing::info!(path = %self.path.display(), "audit file rotated");
        }

        write_under_lock(&mut guard, &bytes, &self.path)?;

        if needs_fsync(&record.payload) {
            guard
                .buf
                .get_ref()
                .sync_data()
                .map_err(|source| AuditError::Fsync {
                    path: self.path.clone(),
                    source,
                })?;
        }

        Ok(())
    }
}

/// Write `bytes` to `guard.buf`, flush, and update `bytes_written`.
fn write_under_lock(guard: &mut Inner, bytes: &[u8], path: &Path) -> Result<(), AuditError> {
    use std::io::Write;

    guard
        .buf
        .write_all(bytes)
        .map_err(|source| AuditError::Write {
            path: path.to_path_buf(),
            source,
        })?;
    guard.buf.flush().map_err(|source| AuditError::Write {
        path: path.to_path_buf(),
        source,
    })?;
    // bytes.len() is usize; on 64-bit targets this always fits in u64.
    // On hypothetical 128-bit targets, saturate rather than panic.
    let written = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    guard.bytes_written = guard.bytes_written.saturating_add(written);
    Ok(())
}

fn needs_fsync(payload: &crate::record::Payload) -> bool {
    use crate::record::Payload;
    match payload {
        Payload::ProcessStart(_)
        | Payload::ProcessEnd(_)
        | Payload::Auth(_)
        | Payload::Config(_) => true,
        Payload::ToolStart(_) | Payload::ToolEnd(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use rimap_core::auth_event::{AuthEvent, AuthResult};

    use crate::record::{Payload, ProcessEnd, ProcessEndReason, ProcessStart, ToolEnd, ToolStart};

    fn auth_payload() -> Payload {
        Payload::Auth(AuthEvent {
            account: None,
            result: AuthResult::Success,
            host: "h".to_string(),
            port: 1,
            username: "u".to_string(),
            tls_fingerprint_sha256: None,
            fingerprint_match: None,
            error_code: None,
            credential_source: None,
        })
    }

    fn process_start_payload() -> Payload {
        Payload::ProcessStart(ProcessStart {
            version: "0.0.0".to_string(),
            git_commit: String::new(),
            posture: None,
            accounts: None,
            tool_matrix: Vec::new(),
            config_path: std::path::PathBuf::from("/tmp/c"),
            config_hash_sha256: "00".repeat(32),
            previous_last_seq: None,
            previous_process_id: None,
            previous_file_inode: 0,
            audit_file_inode_changed: false,
        })
    }

    fn process_end_payload() -> Payload {
        Payload::ProcessEnd(ProcessEnd {
            reason: ProcessEndReason::Eof,
            total_tool_calls: 0,
            records_lost: 0,
        })
    }

    fn tool_start_payload() -> Payload {
        Payload::ToolStart(ToolStart {
            account: None,
            tool: rimap_core::tool::ToolName::FetchMessage,
            posture_effective: crate::record::PostureEffective::Account(
                rimap_core::Posture::DraftSafe,
            ),
            arguments_redacted: serde_json::json!({}),
            arguments_hash_sha256: "0".repeat(64),
        })
    }

    fn tool_end_payload() -> Payload {
        Payload::ToolEnd(ToolEnd {
            account: None,
            start_seq: crate::record::ids::Seq::FIRST,
            tool: rimap_core::tool::ToolName::FetchMessage,
            status: crate::record::ToolStatus::Ok,
            error_code: None,
            duration_ms: 0,
            result_summary: crate::record::ResultSummary::default(),
            provenance: crate::record::Provenance {
                window_seconds: 60,
                message_ids_recently_read: Vec::new(),
            },
        })
    }

    #[test]
    fn auth_process_and_config_records_are_fsynced() {
        // Pins `needs_fsync -> true` mutation: durability-critical kinds
        // must trigger an fsync after write. The `with false` mutation would
        // skip fsync for these, breaking the durability contract.
        assert!(super::needs_fsync(&auth_payload()));
        assert!(super::needs_fsync(&process_start_payload()));
        assert!(super::needs_fsync(&process_end_payload()));
    }

    #[test]
    fn tool_start_and_tool_end_records_are_not_fsynced() {
        // Pins `needs_fsync -> false` mutation: high-frequency tool records
        // must skip fsync to keep the audit path off the I/O hot loop. The
        // `with true` mutation would fsync every tool call.
        assert!(!super::needs_fsync(&tool_start_payload()));
        assert!(!super::needs_fsync(&tool_end_payload()));
    }
}
