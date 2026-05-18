//! Audit envelope wrapping every tool dispatch.
//!
//! [`ImapMcpServer::run_with_audit_envelope`] redacts+hashes arguments,
//! emits a `tool_start` record, runs the provided body future, then
//! emits a `tool_end` record with the resulting status and error code.
//! The helpers [`ImapMcpServer::emit_tool_start`] and
//! [`ImapMcpServer::emit_tool_end`] offload the blocking writer calls
//! onto `spawn_blocking` and surface panics/join errors as
//! `RimapError::Internal`.
//!
//! [`AuditEnvelopeGuard`] is a drop-guard that synthesizes a cancellation
//! `tool_end` if the enclosing future is dropped between `tool_start`
//! emission and the normal `emit_tool_end` call (#71, #99).

use rimap_audit::record::{Provenance, ResultSummary, ToolStatus};
use rimap_audit::redact::{Redactor, ToolRedactionSchema, hash_arguments};
use rimap_audit::{CancelledToolEndSender, ToolEndInputs, ToolStartInputs};
use rimap_core::tool::ToolName;
use rmcp::model::{CallToolResult, ErrorData};

use crate::mcp::dispatch::{DispatchTicket, PostureContext};
use crate::mcp::server::ImapMcpServer;

impl ImapMcpServer {
    /// Wrap an inner dispatch `body` in the full audit envelope:
    /// redact+hash args, emit `tool_start`, time the body, emit
    /// `tool_end` with the status/error code derived from the body's
    /// result. Returns the MCP-shaped `CallToolResult` or `ErrorData`.
    pub(super) async fn run_with_audit_envelope<F, Fut>(
        &self,
        tool: ToolName,
        audit_account: Option<String>,
        posture: PostureContext,
        args: &serde_json::Map<String, serde_json::Value>,
        body: F,
    ) -> Result<CallToolResult, ErrorData>
    where
        F: FnOnce(DispatchTicket) -> Fut,
        Fut: std::future::Future<Output = Result<serde_json::Value, rimap_core::RimapError>>,
    {
        let args_value = serde_json::Value::Object(args.clone());
        let redacted = self.redact_tool_args(tool, &args_value);
        let hash = hash_arguments(&args_value);

        let start_seq = self
            .emit_tool_start(tool, audit_account.clone(), posture, redacted, hash)
            .await?;
        let start_time = std::time::Instant::now();

        let mut guard = AuditEnvelopeGuard::new(
            start_seq,
            tool,
            audit_account.clone(),
            start_time,
            self.cancellation_sender.clone(),
        );

        // Mint a `DispatchTicket` only now that the envelope is open.
        // Consuming it by value inside `dispatch_tool` makes "forgot
        // the envelope" a compile error.
        let ticket = DispatchTicket::new();
        let result = body(ticket).await;

        // Body completed normally. Disarm before any further await points so
        // a drop of THIS future between here and emit_tool_end does not cause
        // double emission.
        guard.disarm();

        let duration_ms = start_time
            .elapsed()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX);
        let (status, error_code) = match &result {
            Ok(_) => (ToolStatus::Ok, None),
            Err(e) => (ToolStatus::Error, Some(e.code())),
        };
        self.emit_tool_end(
            start_seq,
            tool,
            audit_account,
            status,
            error_code,
            duration_ms,
        )
        .await;

        match result {
            Ok(value) => Ok(CallToolResult::structured(value)),
            Err(e) => Err(crate::mcp::error::to_mcp_error(&e)),
        }
    }

    /// Apply the [`RedactionSchema`][rimap_audit::RedactionSchema] dispatched
    /// from [`ToolRedactionSchema::redaction_schema`] to `tool`'s arguments.
    /// The dispatch is exhaustive, so a missing schema is a compile error
    /// rather than a runtime warn-and-drop.
    fn redact_tool_args(&self, tool: ToolName, args: &serde_json::Value) -> serde_json::Value {
        Redactor::new(&tool.redaction_schema(), self.redaction_salt.as_ref()).apply(args)
    }

    /// Emit a `tool_start` audit record via `spawn_blocking`. Returns the
    /// allocated `seq` on success; on audit failure emits a `warn!` and
    /// returns a synthetic `Seq::FIRST` so the call can proceed.
    ///
    /// Errors bubble up only when `fail_open = false` AND the write fails:
    /// in that case the tool call MUST fail because the audit trail is
    /// broken. `fail_open = true` deployments swallow the error inside
    /// the writer and return `Ok`.
    async fn emit_tool_start(
        &self,
        tool: ToolName,
        account: Option<String>,
        posture: PostureContext,
        redacted: serde_json::Value,
        hash: String,
    ) -> Result<rimap_audit::Seq, ErrorData> {
        let audit = self.audit.clone();
        let posture_effective = posture.posture();
        let join = tokio::task::spawn_blocking(move || {
            audit.log_tool_start(ToolStartInputs {
                tool,
                account,
                posture_effective,
                arguments_redacted: redacted,
                arguments_hash_sha256: hash,
            })
        })
        .await;
        match join {
            Ok(Ok(seq)) => Ok(seq),
            Ok(Err(audit_err)) => {
                tracing::error!(error = %audit_err, "tool_start audit write failed");
                Err(ErrorData::internal_error(
                    format!("audit write failed: {audit_err}"),
                    None,
                ))
            }
            Err(join_err) => {
                tracing::error!(error = %join_err, "tool_start join error");
                let rimap_err = crate::mcp::spawn_blocking_panic_error(join_err);
                Err(crate::mcp::error::to_mcp_error(&rimap_err))
            }
        }
    }

    /// Emit a `tool_end` audit record via `spawn_blocking`. Failures are
    /// logged but not propagated — at end-of-call the tool has already
    /// finished and the caller sees its original result.
    async fn emit_tool_end(
        &self,
        start_seq: rimap_audit::Seq,
        tool: ToolName,
        account: Option<String>,
        status: ToolStatus,
        error_code: Option<rimap_core::ErrorCode>,
        duration_ms: u64,
    ) {
        let audit = self.audit.clone();
        // The provenance ring buffer is not yet wired for multi-account.
        // Record an empty snapshot with the window placeholder until a
        // per-account buffer lands.
        let provenance = Provenance {
            window_seconds: 60,
            message_ids_recently_read: Vec::new(),
        };
        let summary = ResultSummary::default();
        let inputs = rimap_audit::ToolEndInputs {
            start_seq,
            tool,
            account,
            status,
            error_code,
            duration_ms,
            result_summary: summary,
            provenance,
        };
        let join = tokio::task::spawn_blocking(move || audit.log_tool_end(inputs)).await;
        match join {
            Ok(Ok(_)) => {}
            Ok(Err(audit_err)) => {
                tracing::error!(error = %audit_err, "tool_end audit write failed");
            }
            Err(join_err) => {
                let rimap_err = crate::mcp::spawn_blocking_panic_error(join_err);
                tracing::error!(error = %rimap_err, "tool_end join error");
            }
        }
    }
}

/// RAII guard that emits a cancellation `tool_end` record if dropped
/// undisarmed. Used inside `run_with_audit_envelope` to pair every
/// `tool_start` with a `tool_end` even when the outer MCP dispatch
/// future is dropped mid-call (#71, #99).
struct AuditEnvelopeGuard {
    inner: Option<GuardInner>,
}

struct GuardInner {
    start_seq: rimap_audit::Seq,
    tool: ToolName,
    account: Option<String>,
    start_time: std::time::Instant,
    sender: CancelledToolEndSender,
}

impl AuditEnvelopeGuard {
    fn new(
        start_seq: rimap_audit::Seq,
        tool: ToolName,
        account: Option<String>,
        start_time: std::time::Instant,
        sender: CancelledToolEndSender,
    ) -> Self {
        Self {
            inner: Some(GuardInner {
                start_seq,
                tool,
                account,
                start_time,
                sender,
            }),
        }
    }

    /// Mark the guard as completed normally. `Drop` becomes a no-op.
    fn disarm(&mut self) {
        self.inner = None;
    }
}

impl Drop for AuditEnvelopeGuard {
    fn drop(&mut self) {
        let Some(inner) = self.inner.take() else {
            return;
        };
        let duration_ms = inner
            .start_time
            .elapsed()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX);
        // ToolName is Copy; capture it for the warning log before try_send
        // consumes the payload.
        let tool = inner.tool;
        let cancellation = ToolEndInputs {
            start_seq: inner.start_seq,
            tool,
            account: inner.account,
            status: rimap_audit::record::ToolStatus::Cancelled,
            error_code: Some(rimap_core::ErrorCode::Cancelled),
            duration_ms,
            result_summary: rimap_audit::record::ResultSummary::default(),
            provenance: Provenance {
                window_seconds: 60,
                message_ids_recently_read: Vec::new(),
            },
        };
        if let Err(e) = inner.sender.try_send(cancellation) {
            tracing::warn!(
                error = %e,
                tool = tool.as_str(),
                "cancellation tool_end drop: failed to enqueue (channel full or closed)",
            );
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use rimap_audit::writer::AuditOptions;
    use rimap_audit::{AuditWriter, Seq, ToolStartInputs, cancellation_channel, spawn_drainer};
    use rimap_core::tool::ToolName;
    use tempfile::tempdir;

    use super::AuditEnvelopeGuard;

    fn test_writer(path: std::path::PathBuf) -> AuditWriter {
        AuditWriter::open(&AuditOptions {
            path,
            rotate_bytes: 10 * 1024 * 1024,
            rotate_keep: 5,
            retention_seconds: None,
            fail_open: false,
            initial_seq: Seq::FIRST,
        })
        .unwrap()
    }

    /// Dropping an `AuditEnvelopeGuard` without disarming enqueues a
    /// cancellation record with `status = cancelled` and
    /// `error_code = ERR_CANCELLED`. The drainer writes it to the audit file.
    /// This is the core invariant for #71 and #99.
    #[tokio::test]
    async fn dropped_guard_enqueues_cancellation_record() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = test_writer(path.clone());

        // Prime a tool_start so the resulting tool_end references a real seq.
        let start_seq = writer
            .log_tool_start(ToolStartInputs {
                tool: ToolName::Search,
                account: Some("test".to_string()),
                posture_effective: Some(rimap_core::Posture::Readonly),
                arguments_redacted: serde_json::Value::Object(serde_json::Map::new()),
                arguments_hash_sha256: "0".repeat(64),
            })
            .unwrap();

        let (tx, rx) = cancellation_channel();
        let drainer = spawn_drainer(rx, writer.clone());

        {
            let _guard = AuditEnvelopeGuard::new(
                start_seq,
                ToolName::Search,
                Some("test".to_string()),
                std::time::Instant::now(),
                tx.clone(),
            );
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            // Implicit drop of `_guard` here — undisarmed, so cancellation fires.
        }

        drop(tx); // Close the channel so the drainer can exit.
        drainer.await.unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<_> = contents.lines().collect();
        assert_eq!(
            lines.len(),
            2,
            "expected exactly 2 records (tool_start + cancellation tool_end), got {} records:\n{contents}",
            lines.len(),
        );
        let last = lines.last().unwrap();
        assert!(
            last.contains(r#""status":"cancelled""#),
            "last record should be cancellation tool_end: {last}",
        );
        assert!(
            last.contains(r#""error_code":"ERR_CANCELLED""#),
            "last record should carry ERR_CANCELLED: {last}",
        );
        assert!(
            last.contains(&format!(r#""start_seq":{start_seq}"#)),
            "last record should reference primed tool_start seq {start_seq}: {last}",
        );
    }

    /// Wrapper-level test: drive `run_with_audit_envelope` end-to-end with a
    /// body future that never completes, then abort the outer task. The
    /// abort drops the wrapper future between `emit_tool_start` and the
    /// normal `emit_tool_end`, so the only `tool_end` written must come
    /// from `AuditEnvelopeGuard::drop`. Expectation: exactly two records
    /// — one `tool_start` and one `tool_end {status: cancelled}` — in
    /// order. This catches regressions where guard construction is
    /// reordered relative to `tool_start` emission or where the disarm
    /// call is moved/removed on the normal path. The guard-level tests
    /// above would not catch those (they construct `AuditEnvelopeGuard`
    /// directly). Codex review finding #4.
    ///
    /// `spawn` + `abort` is used (rather than `pin!` + `timeout` + drop)
    /// to match the proven cancellation pattern from
    /// `tests/dispatch_ticket.rs::drop_during_body_enqueues_cancellation_tool_end`.
    /// The multi-thread flavor lets the aborted task and the drainer
    /// task make progress concurrently with the test driver.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropped_run_with_audit_envelope_emits_exactly_one_cancellation() {
        use std::sync::Arc;
        use std::time::Duration;

        use rimap_core::tool::ToolName;

        use crate::mcp::dispatch::PostureContext;
        use crate::mcp::server::ImapMcpServer;

        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = test_writer(path.clone());

        let (tx, rx) = cancellation_channel();
        let drainer = spawn_drainer(rx, writer.clone());

        let server = Arc::new(ImapMcpServer::new_for_tests(writer, tx.clone()));

        // Spawn `run_with_audit_envelope` with a body that pends forever.
        // After `emit_tool_start` has had time to fire, `abort()` the
        // task; the wrapper future is dropped between `tool_start` and
        // `emit_tool_end`, exercising the guard's `Drop` path.
        let server_clone = Arc::clone(&server);
        let task = tokio::spawn(async move {
            let args = serde_json::Map::new();
            server_clone
                .run_with_audit_envelope(
                    ToolName::ListAccounts,
                    None,
                    PostureContext::Infrastructure,
                    &args,
                    |_ticket| {
                        std::future::pending::<Result<serde_json::Value, rimap_core::RimapError>>()
                    },
                )
                .await
        });

        // Give the envelope time to emit `tool_start` and enter the
        // body's pending await before aborting. 50ms matches the
        // headroom used by `dispatch_ticket::drop_during_body_*`.
        tokio::time::sleep(Duration::from_millis(50)).await;
        task.abort();
        let _ = task.await; // wait for the abort to settle

        // Give the drainer time to flush the queued cancellation record.
        tokio::time::sleep(Duration::from_millis(100)).await;
        // Drop the last sender so the drainer task can exit.
        drop(tx);
        drop(server);
        drainer.await.unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<_> = contents.lines().collect();
        assert_eq!(
            lines.len(),
            2,
            "expected exactly 2 records (tool_start + cancellation tool_end), got {} records:\n{contents}",
            lines.len(),
        );
        assert!(
            lines[0].contains(r#""tool_start""#),
            "first record must be tool_start: {}",
            lines[0],
        );
        assert!(
            lines[1].contains(r#""status":"cancelled""#),
            "second record must be cancellation tool_end: {}",
            lines[1],
        );
        assert!(
            lines[1].contains(r#""error_code":"ERR_CANCELLED""#),
            "second record must carry ERR_CANCELLED: {}",
            lines[1],
        );
    }

    /// A disarmed guard's drop is a no-op: no cancellation record is written.
    #[tokio::test]
    async fn disarmed_guard_does_not_enqueue() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = test_writer(path.clone());

        let (tx, rx) = cancellation_channel();
        let drainer = spawn_drainer(rx, writer.clone());

        {
            let mut guard = AuditEnvelopeGuard::new(
                Seq::FIRST,
                ToolName::Search,
                Some("test".to_string()),
                std::time::Instant::now(),
                tx.clone(),
            );
            guard.disarm();
            // Drop here — disarmed, so no cancellation is enqueued.
        }

        drop(tx);
        drainer.await.unwrap();

        let contents = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(
            !contents.contains(r#""status":"cancelled""#),
            "disarmed guard must not write a cancellation record: {contents}",
        );
    }
}
