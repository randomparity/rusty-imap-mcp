//! The "build a record and put bytes on the disk" core of the writer.
//!
//! Holds the seq allocator, the rotation-aware write path, the optional
//! fail-open suppression policy, and the small synchronous I/O helpers.
//! Lives separately from the per-kind `log_*` family so the kind-specific
//! glue can stay narrow.

use std::sync::atomic::Ordering;

use crate::AuditError;

use super::AuditWriter;
use super::deadline::Request;

impl AuditWriter {
    /// Allocate the next monotonic `Seq` value. An atomic fetch-add; never
    /// crosses an `.await` and never blocks on file I/O.
    ///
    /// ## Ordering contract
    ///
    /// `allocate_seq` and `write_record` are independent: two concurrent
    /// `log_auth` / `log_process_start` callers can therefore produce a file
    /// where physical line order disagrees with `seq` order (allocation
    /// races with the write).
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
    /// Infallible in practice; the `Result` preserves the historical
    /// signature.
    pub fn allocate_seq(&self) -> Result<crate::record::ids::Seq, AuditError> {
        let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
        Ok(crate::record::ids::Seq(seq))
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
    /// This function performs synchronous filesystem I/O: at minimum a
    /// `write_all` + `flush` + (conditionally) `fsync`, and on rotation
    /// additionally `rename`, `open`, `try_lock`, `read_dir`,
    /// `symlink_metadata`, and `remove_file`. The I/O itself runs on the
    /// writer's dedicated worker thread; the caller waits for the
    /// completion reply, bounded by `write_deadline_seconds` (unbounded
    /// when the deadline is 0) — see `super::deadline`. An async caller
    /// should still move it onto the blocking pool rather than stall a
    /// runtime worker for up to the deadline — in this workspace through
    /// `DispatchDrain::spawn_blocking_tracked`, which also registers the
    /// write with the shutdown drain (#672), rather than a bare
    /// `tokio::task::spawn_blocking`. The `tool_start` / `tool_end`
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
    /// - [`AuditError::Write`] / [`AuditError::WriteDeadline`] /
    ///   [`AuditError::Fsync`] / [`AuditError::Rotate`] when
    ///   `fail_open == false`.
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

        self.io.request(|reply| Request::Write {
            bytes,
            fsync: needs_fsync(&record.payload),
            reply,
        })
    }
}

fn needs_fsync(payload: &crate::record::Payload) -> bool {
    use crate::record::Payload;
    match payload {
        // `folder_policy` sits with the lifecycle kinds rather than the
        // per-call ones: it is written once per account at boot, so the fsync
        // cost is bounded by account count, and it is a record you want
        // durable before the process it describes can fail.
        Payload::ProcessStart(_)
        | Payload::ProcessEnd(_)
        | Payload::Auth(_)
        | Payload::Config(_)
        | Payload::FolderPolicy(_) => true,
        Payload::ToolStart(_) | Payload::ToolEnd(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use rimap_core::auth_event::{AuthEvent, AuthResult, Host, Username};

    use crate::record::{Payload, ProcessEnd, ProcessEndReason, ProcessStart, ToolEnd, ToolStart};

    fn auth_payload() -> Payload {
        Payload::Auth(AuthEvent::new(
            AuthResult::Success,
            Host("h".to_string()),
            1,
            Username("u".to_string()),
            None,
            None,
            None,
            None,
        ))
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
            undrained_dispatches: 0,
            drainer_aborted_records: 0,
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
