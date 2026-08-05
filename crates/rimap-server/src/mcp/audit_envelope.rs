//! Audit envelope wrapping every tool dispatch.
//!
//! [`ImapMcpServer::run_with_audit_envelope`] redacts+hashes arguments,
//! emits a `tool_start` record, runs the provided body future, then
//! emits a `tool_end` record with the resulting status and error code.
//! The helpers [`ImapMcpServer::emit_tool_start`] and
//! [`ImapMcpServer::emit_tool_end`] offload the blocking writer calls
//! onto the blocking pool and surface panics/join errors as
//! `RimapError::Internal`. Both offload through
//! `DispatchDrain::spawn_blocking_tracked` rather than `spawn_blocking`
//! directly, so a write the shutdown detaches still cannot append after
//! `process_end` (#672).
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

/// The terminal outcome of a tool call, bundled so `emit_tool_end` stays
/// within the positional-parameter limit: the status, the error code (on
/// failure), and the derived durable [`ResultSummary`] (#316).
struct ToolOutcome {
    status: ToolStatus,
    error_code: Option<rimap_core::ErrorCode>,
    result_summary: ResultSummary,
}

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
        // Derive the durable result provenance from the successful result so
        // the actual on-disk scope (artifact path/sha/bytes, exported/failed
        // UIDs) is reconstructable post-incident; a failed call wrote no
        // artifact, so it records the default summary (#316).
        let outcome = match &result {
            Ok(value) => ToolOutcome {
                status: ToolStatus::Ok,
                error_code: None,
                result_summary: crate::mcp::result_provenance::result_provenance(tool, value),
            },
            Err(e) => ToolOutcome {
                status: ToolStatus::Error,
                error_code: Some(e.code()),
                result_summary: ResultSummary::default(),
            },
        };
        self.emit_tool_end(start_seq, tool, audit_account, duration_ms, outcome)
            .await;

        // A tool that ran but failed returns a normal `CallToolResult`
        // with `is_error: true` so the agent reliably sees the message
        // and typed recovery data and can self-correct (#402). Genuine
        // protocol / routing / infrastructure failures stay JSON-RPC
        // errors. The audit outcome above was already derived from the
        // `RimapError`, so `tool_end` shape is unchanged either way.
        match result {
            Ok(value) => Ok(CallToolResult::structured(value)),
            Err(e) if crate::mcp::error::is_tool_execution_error(&e) => {
                Ok(crate::mcp::error::to_error_call_result(&e))
            }
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

    /// Emit a `tool_start` audit record on the blocking pool, registered with
    /// the server's `DispatchDrain` for the write's own lifetime (#672) — a
    /// shutdown that cuts this dispatch detaches the closure rather than
    /// stopping it, so the drain has to wait on the write, not on the await.
    /// Returns the allocated `seq` on success; on audit failure emits a `warn!`
    /// and returns a synthetic `Seq::FIRST` so the call can proceed.
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
        let join = self
            .drain
            .spawn_blocking_tracked(move || {
                let inputs = ToolStartInputs::new(tool, account, posture_effective, redacted, hash);
                audit.log_tool_start(inputs)
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

    /// Emit a `tool_end` audit record on the blocking pool, registered with the
    /// server's `DispatchDrain` for the write's own lifetime (#672), for the
    /// same reason as `emit_tool_start`. Failures are logged but not propagated
    /// — at end-of-call the tool has already finished and the caller sees its
    /// original result.
    async fn emit_tool_end(
        &self,
        start_seq: rimap_audit::Seq,
        tool: ToolName,
        account: Option<String>,
        duration_ms: u64,
        outcome: ToolOutcome,
    ) {
        let audit = self.audit.clone();
        // The provenance ring buffer is not yet wired for multi-account.
        // Record an empty snapshot with the window placeholder until a
        // per-account buffer lands.
        let provenance = Provenance::new(60, Vec::new());
        let mut inputs = rimap_audit::ToolEndInputs::new(
            start_seq,
            tool,
            outcome.status,
            outcome.error_code,
            duration_ms,
            provenance,
        );
        inputs.account = account;
        inputs.result_summary = outcome.result_summary;
        let join = self
            .drain
            .spawn_blocking_tracked(move || audit.log_tool_end(inputs))
            .await;
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
        let mut cancellation = ToolEndInputs::new(
            inner.start_seq,
            tool,
            rimap_audit::record::ToolStatus::Cancelled,
            Some(rimap_core::ErrorCode::Cancelled),
            duration_ms,
            Provenance::new(60, Vec::new()),
        );
        cancellation.account = inner.account;
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
#[expect(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
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

    /// A never-completing tool body that signals `entered` on its first poll.
    ///
    /// This is the barrier for "the envelope is ready to be cancelled".
    /// [`super::ImapMcpServer::run_with_audit_envelope`] awaits
    /// `emit_tool_start`, constructs the [`AuditEnvelopeGuard`], and only
    /// *then* polls the body — so observing the first poll proves the
    /// `tool_start` write finished and the guard is armed. Nothing else polls
    /// this future, so the signal cannot arrive early, which makes it an exact
    /// ordering barrier rather than a timing window.
    fn body_signalling_first_poll(
        entered: tokio::sync::oneshot::Sender<()>,
    ) -> impl std::future::Future<Output = Result<serde_json::Value, rimap_core::RimapError>> {
        let mut entered = Some(entered);
        std::future::poll_fn(move |_cx| {
            if let Some(entered) = entered.take() {
                // A dropped receiver means the test already gave up; the
                // assertions report that, so the send result is not actionable.
                let _ = entered.send(());
            }
            // Never resolve: the abort must land while the body is suspended.
            std::task::Poll::Pending
        })
    }

    fn test_writer_fail_open(path: std::path::PathBuf, fail_open: bool) -> AuditWriter {
        AuditWriter::open(&AuditOptions {
            path,
            rotate_bytes: 10 * 1024 * 1024,
            rotate_keep: 5,
            retention_seconds: None,
            fail_open,
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
        let inputs = ToolStartInputs::new(
            ToolName::Search,
            Some("test".to_string()),
            Some(rimap_core::Posture::Readonly),
            serde_json::Value::Object(serde_json::Map::new()),
            "0".repeat(64),
        );
        let start_seq = writer.log_tool_start(inputs).unwrap();

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
        // Once the body has been polled — which proves `tool_start` is
        // written and the guard is armed — `abort()` the task; the wrapper
        // future is dropped between `tool_start` and `emit_tool_end`,
        // exercising the guard's `Drop` path.
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let server_clone = Arc::clone(&server);
        let task = tokio::spawn(async move {
            let args = serde_json::Map::new();
            server_clone
                .run_with_audit_envelope(
                    ToolName::ListAccounts,
                    None,
                    PostureContext::Infrastructure,
                    &args,
                    |_ticket| body_signalling_first_poll(entered_tx),
                )
                .await
        });

        // Wait for the body's first poll rather than for a clock: the abort
        // is then strictly ordered after the guard is armed, whatever the
        // host load (#684 — the previous 50ms sleep was a race window).
        entered_rx.await.unwrap();
        task.abort();
        let _ = task.await; // wait for the abort to settle

        // No sleep before the drain: closing every cancellation sender makes
        // `drainer.await` itself the flush barrier.
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
        // Join the two records, so a cancellation synthesized against some
        // other dispatch's `seq` cannot satisfy the assertions above.
        let start: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        let end: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(
            end["start_seq"], start["seq"],
            "tool_end.start_seq must reference this dispatch's tool_start.seq: {contents}",
        );
    }

    /// The per-tool-call ceiling (#594) fires inside the envelope's body,
    /// so the envelope disarms normally and the durable `tool_end` record
    /// carries `status: "error"` + `ERR_TIMEOUT`.
    ///
    /// The negative half is the point: `AuditEnvelopeGuard` synthesizes an
    /// `ERR_CANCELLED` `tool_end` whenever the envelope future is dropped,
    /// so a ceiling applied *around* `run_with_audit_envelope` would
    /// mis-record an operator-configured timeout as a client cancellation.
    /// This asserts on the record written to disk, not on the returned
    /// error, because only the record distinguishes the two.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fired_ceiling_records_err_timeout_not_cancellation() {
        use std::sync::Arc;
        use std::time::Duration;

        use rimap_core::tool::ToolName;

        use crate::mcp::dispatch::{PostureContext, with_tool_call_ceiling};
        use crate::mcp::server::ImapMcpServer;

        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = test_writer(path.clone());

        let (tx, rx) = cancellation_channel();
        let drainer = spawn_drainer(rx, writer.clone());
        let server = Arc::new(ImapMcpServer::new_for_tests(writer, tx.clone()));

        let args = serde_json::Map::new();
        let result = server
            .run_with_audit_envelope(
                ToolName::ListFolders,
                Some("work".to_string()),
                PostureContext::Account(rimap_core::Posture::Readonly),
                &args,
                |_ticket| {
                    with_tool_call_ceiling(
                        Duration::from_millis(50),
                        std::future::pending::<Result<serde_json::Value, rimap_core::RimapError>>(),
                        || {},
                    )
                },
            )
            .await;

        // A tool-execution failure surfaces as Ok(CallToolResult{is_error}) (#402).
        let call = result.expect("a fired ceiling is a tool-execution failure, not a protocol one");
        assert_eq!(call.is_error, Some(true));

        drop(tx);
        drop(server);
        drainer.await.unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<_> = contents.lines().collect();
        assert_eq!(
            lines.len(),
            2,
            "expected exactly 2 records (tool_start + tool_end), got:\n{contents}",
        );
        assert!(
            lines[1].contains(r#""status":"error""#),
            "tool_end must record an error status: {}",
            lines[1],
        );
        assert!(
            lines[1].contains(r#""error_code":"ERR_TIMEOUT""#),
            "the audit record must attribute a fired ceiling to ERR_TIMEOUT: {}",
            lines[1],
        );
        assert!(
            !contents.contains("ERR_CANCELLED") && !contents.contains(r#""cancelled""#),
            "a fired ceiling must not be recorded as a cancellation:\n{contents}",
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

    /// End-to-end wiring (#316): a successful export-shaped result drives
    /// `run_with_audit_envelope` → `result_provenance` → `emit_tool_end`, and
    /// the durable `tool_end` record carries the artifact path/sha/bytes and
    /// the exported/failed UID partition.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tool_end_records_export_provenance_from_result() {
        use std::sync::Arc;

        use rimap_core::tool::ToolName;

        use crate::mcp::dispatch::PostureContext;
        use crate::mcp::server::ImapMcpServer;

        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = test_writer(path.clone());
        let (tx, _rx) = cancellation_channel();
        let server = Arc::new(ImapMcpServer::new_for_tests(writer, tx));

        let args = serde_json::Map::new();
        let result = server
            .run_with_audit_envelope(
                ToolName::ExportMessages,
                None,
                PostureContext::Infrastructure,
                &args,
                |_ticket| async {
                    Ok(serde_json::json!({
                        "meta": {
                            "path": "/srv/dl/messages-xyz.mbox",
                            "sha256": "ab",
                            "total_bytes": 4096,
                            "succeeded": [{ "uid": 7 }, { "uid": 9 }],
                            "failed": [{ "uid": 8 }]
                        }
                    }))
                },
            )
            .await;
        assert!(result.is_ok(), "envelope should surface the Ok result");

        let contents = std::fs::read_to_string(&path).unwrap();
        let tool_end = contents
            .lines()
            .find(|l| l.contains(r#""kind":"tool_end""#))
            .unwrap();
        let v: serde_json::Value = serde_json::from_str(tool_end).unwrap();
        assert_eq!(v["status"], "ok");
        assert_eq!(
            v["result_summary"]["artifact_path"],
            "/srv/dl/messages-xyz.mbox"
        );
        assert_eq!(v["result_summary"]["artifact_bytes"], 4096);
        assert_eq!(
            v["result_summary"]["uids_exported"],
            serde_json::json!([7, 9])
        );
        assert_eq!(v["result_summary"]["uids_failed"], serde_json::json!([8]));
    }

    /// A tool-execution failure (`NotFound`) surfaces as
    /// `Ok(CallToolResult { is_error: true })` carrying the structured
    /// error code, and the `tool_end` record still records
    /// `status = "error"` + the error code (#402). The isError mapping
    /// does not change the audit shape.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn execution_error_returns_iserror_result_and_records_error() {
        use std::sync::Arc;

        use rimap_core::tool::ToolName;

        use crate::mcp::dispatch::PostureContext;
        use crate::mcp::server::ImapMcpServer;

        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = test_writer(path.clone());
        let (tx, _rx) = cancellation_channel();
        let server = Arc::new(ImapMcpServer::new_for_tests(writer, tx));

        let args = serde_json::Map::new();
        let result = server
            .run_with_audit_envelope(
                ToolName::FetchMessage,
                None,
                PostureContext::Infrastructure,
                &args,
                |_ticket| async {
                    Err(rimap_core::RimapError::Imap {
                        code: rimap_core::ErrorCode::NotFound,
                        message: "no such UID".into(),
                        source: None,
                    })
                },
            )
            .await;

        let call = result.expect("execution error must surface as Ok(CallToolResult), not Err");
        assert_eq!(call.is_error, Some(true));
        let sc = call
            .structured_content
            .as_ref()
            .expect("execution error result must carry structured content");
        assert_eq!(sc["error_code"], "ERR_NOT_FOUND");

        let contents = std::fs::read_to_string(&path).unwrap();
        let tool_end = contents
            .lines()
            .find(|l| l.contains(r#""kind":"tool_end""#))
            .expect("tool_end record");
        let v: serde_json::Value = serde_json::from_str(tool_end).unwrap();
        assert_eq!(v["status"], "error", "tool_end status must be unchanged");
        assert_eq!(v["error_code"], "ERR_NOT_FOUND");
    }

    /// A protocol-class failure (`InvalidInput`) still surfaces as
    /// `Err(ErrorData)`; the isError mapping applies only to
    /// tool-execution errors (#402).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn protocol_error_still_returns_err_error_data() {
        use std::sync::Arc;

        use rimap_core::tool::ToolName;

        use crate::mcp::dispatch::PostureContext;
        use crate::mcp::server::ImapMcpServer;

        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = test_writer(path.clone());
        let (tx, _rx) = cancellation_channel();
        let server = Arc::new(ImapMcpServer::new_for_tests(writer, tx));

        let args = serde_json::Map::new();
        let result = server
            .run_with_audit_envelope(
                ToolName::FetchMessage,
                None,
                PostureContext::Infrastructure,
                &args,
                |_ticket| async { Err(rimap_core::RimapError::invalid_input("bad uid")) },
            )
            .await;

        let err = result.expect_err("protocol error must surface as Err(ErrorData)");
        assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
    }

    /// `fail_open` = false: an injected `tool_start` write failure must abort
    /// the call with an "audit write failed" error, never run the body, and
    /// leave ZERO records on disk (no orphan `tool_start`).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tool_start_failure_fail_closed_aborts_with_no_orphan() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        use rimap_core::tool::ToolName;

        use crate::mcp::dispatch::PostureContext;
        use crate::mcp::server::ImapMcpServer;

        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = test_writer_fail_open(path.clone(), false);
        writer.force_next_write_failure();

        let (tx, _rx) = cancellation_channel();
        let server = Arc::new(ImapMcpServer::new_for_tests(writer, tx));

        let body_ran = Arc::new(AtomicBool::new(false));
        let body_ran_clone = Arc::clone(&body_ran);
        let args = serde_json::Map::new();
        let result = server
            .run_with_audit_envelope(
                ToolName::ListAccounts,
                None,
                PostureContext::Infrastructure,
                &args,
                |_ticket| async move {
                    body_ran_clone.store(true, Ordering::SeqCst);
                    Ok(serde_json::Value::Null)
                },
            )
            .await;

        let err = result.expect_err("fail-closed audit failure must abort the call");
        assert_eq!(
            err.code,
            rmcp::model::ErrorCode::INTERNAL_ERROR,
            "fail-closed audit failure must surface as an MCP internal error",
        );
        assert!(
            err.message.contains("audit write failed"),
            "expected audit-write-failed error, got: {}",
            err.message,
        );
        assert!(
            !body_ran.load(Ordering::SeqCst),
            "body must not run when tool_start fails fail-closed",
        );

        let contents = std::fs::read_to_string(&path).unwrap_or_default();
        assert_eq!(
            contents.lines().count(),
            0,
            "a failed tool_start must leave zero records on disk (no orphan):\n{contents}",
        );
    }

    /// `fail_open` = true: the injected `tool_start` write failure is
    /// suppressed (counted), the body runs, and the call succeeds.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tool_start_failure_fail_open_proceeds_and_counts() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        use rimap_core::tool::ToolName;

        use crate::mcp::dispatch::PostureContext;
        use crate::mcp::server::ImapMcpServer;

        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = test_writer_fail_open(path.clone(), true);
        writer.force_next_write_failure();
        // Hold a clone so we can read the suppressed-failure counter after.
        let writer_probe = writer.clone();

        let (tx, _rx) = cancellation_channel();
        let server = Arc::new(ImapMcpServer::new_for_tests(writer, tx));

        let body_ran = Arc::new(AtomicBool::new(false));
        let body_ran_clone = Arc::clone(&body_ran);
        let args = serde_json::Map::new();
        let result = server
            .run_with_audit_envelope(
                ToolName::ListAccounts,
                None,
                PostureContext::Infrastructure,
                &args,
                |_ticket| async move {
                    body_ran_clone.store(true, Ordering::SeqCst);
                    Ok(serde_json::Value::Null)
                },
            )
            .await;

        assert!(result.is_ok(), "fail-open must let the call succeed");
        assert!(
            body_ran.load(Ordering::SeqCst),
            "body must run when the tool_start failure is suppressed",
        );
        assert_eq!(
            writer_probe.suppressed_failures(),
            1,
            "fail-open must increment the suppressed-failure counter exactly once",
        );
    }
}
