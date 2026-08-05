//! Cancellation drop-guard plumbing: a bounded channel of `ToolEndInputs`
//! submitted from `Drop` (sync) and consumed by a dedicated tokio task that
//! routes each record through the existing `AuditWriter::log_tool_end` path.
//!
//! Used by `rimap-server/src/mcp/audit_envelope.rs::AuditEnvelopeGuard` to
//! close out the `tool_start` / `tool_end` pair when the MCP dispatch future
//! is dropped mid-call (#71, #99).
//!
//! [`spawn_drainer`] writes each record through a bare
//! `tokio::task::spawn_blocking`, not `DispatchDrain::spawn_blocking_tracked`.
//! That is a sanctioned exception, not the general pattern: `spawn_blocking_tracked`
//! lives on `DispatchDrain` in `rimap-server`, which depends on `rimap-audit`
//! and not the reverse, so it is unreachable from this crate. The drainer's
//! `JoinHandle` is bounded a different way instead — a join-budget timeout
//! and an `abort()` on overrun in `rimap-server`'s shutdown path. See
//! `docs/architecture/audit-locking.md` for the full argument. Do not copy
//! this shape for a new audit-write path elsewhere in the workspace; use
//! `spawn_blocking_tracked`.

use crate::ToolEndInputs;
use crate::writer::AuditWriter;

/// Channel capacity. 1024 outstanding cancellations is a lot — drops here
/// only happen on client disconnect / shutdown, not steady-state.
const CHANNEL_CAPACITY: usize = 1024;

/// Clone-cheap handle used by `Drop` implementations to enqueue a
/// cancellation `ToolEnd`. `try_send` is non-blocking; on `Full` or `Closed`
/// the caller logs a warning and discards the record.
#[derive(Clone, Debug)]
pub struct CancelledToolEndSender {
    inner: async_channel::Sender<ToolEndInputs>,
}

impl CancelledToolEndSender {
    /// Try to enqueue a cancellation record without blocking. Returns an
    /// error if the channel is full or all receivers have dropped.
    ///
    /// # Errors
    /// Returns `async_channel::TrySendError` on `Full` or `Closed`.
    pub fn try_send(
        &self,
        inputs: ToolEndInputs,
    ) -> Result<(), Box<async_channel::TrySendError<ToolEndInputs>>> {
        self.inner.try_send(inputs).map_err(Box::new)
    }
}

/// Receiver half. Created once at startup; moved into the drainer task.
pub struct CancelledToolEndReceiver {
    inner: async_channel::Receiver<ToolEndInputs>,
}

/// Build a paired `(sender, receiver)` for cancellation records.
#[must_use]
pub fn cancellation_channel() -> (CancelledToolEndSender, CancelledToolEndReceiver) {
    let (tx, rx) = async_channel::bounded(CHANNEL_CAPACITY);
    (
        CancelledToolEndSender { inner: tx },
        CancelledToolEndReceiver { inner: rx },
    )
}

/// Spawn a dedicated tokio task that drains `receiver` and writes each
/// record via `AuditWriter::log_tool_end` on a bare `spawn_blocking` thread
/// — the sanctioned exception documented at the top of this module, not a
/// pattern to copy. The task exits when all senders are dropped and the
/// channel drains.
///
/// The returned `JoinHandle` should be `await`ed on shutdown so the drainer
/// finishes any remaining queued records before the runtime exits. Callers
/// (`rimap-server/src/main.rs`) bound that wait with a timeout and `abort()`
/// the task on overrun, since this function has no way to bound itself from
/// inside `rimap-audit` — see `docs/architecture/audit-locking.md`.
#[must_use]
pub fn spawn_drainer(
    receiver: CancelledToolEndReceiver,
    writer: AuditWriter,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Ok(inputs) = receiver.inner.recv().await {
            let writer = writer.clone();
            let join = tokio::task::spawn_blocking(move || writer.log_tool_end(inputs)).await;
            match join {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    tracing::error!(
                        error = %e,
                        "cancellation tool_end write failed",
                    );
                }
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "cancellation drainer spawn_blocking panic",
                    );
                }
            }
        }
        tracing::debug!("cancellation drainer exiting — all senders dropped");
    })
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::cancellation_channel;
    use crate::record::{Provenance, ResultSummary, ToolStatus};
    use crate::writer::AuditOptions;
    use crate::{AuditWriter, Seq, ToolEndInputs, ToolStartInputs};
    use rimap_core::ErrorCode;
    use rimap_core::tool::ToolName;
    use tempfile::tempdir;

    fn dummy_inputs(account: &str) -> ToolEndInputs {
        ToolEndInputs {
            start_seq: Seq::FIRST,
            tool: ToolName::Search,
            account: Some(account.to_string()),
            status: ToolStatus::Cancelled,
            error_code: Some(ErrorCode::Cancelled),
            duration_ms: 42,
            result_summary: ResultSummary::default(),
            provenance: Provenance {
                window_seconds: 60,
                message_ids_recently_read: Vec::new(),
            },
        }
    }

    #[test]
    fn try_send_and_receive_round_trip() {
        let (tx, rx) = cancellation_channel();
        tx.try_send(dummy_inputs("a")).unwrap();
        tx.try_send(dummy_inputs("b")).unwrap();
        drop(tx);
        let received: Vec<_> = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let mut out = Vec::new();
                while let Ok(inputs) = rx.inner.recv().await {
                    out.push(inputs);
                }
                out
            });
        assert_eq!(received.len(), 2);
        assert_eq!(received[0].account.as_deref(), Some("a"));
        assert_eq!(received[1].account.as_deref(), Some("b"));
    }

    #[tokio::test]
    async fn drainer_writes_records_to_audit_writer() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = AuditWriter::open(&AuditOptions {
            path: path.clone(),
            rotate_bytes: 10 * 1024 * 1024,
            rotate_keep: 5,
            retention_seconds: None,
            fail_open: false,
            initial_seq: Seq::FIRST,
        })
        .unwrap();

        // Prime an earlier tool_start so the tool_end has a plausible start_seq.
        let start_seq = writer
            .log_tool_start(ToolStartInputs {
                tool: ToolName::Search,
                account: Some("a".to_string()),
                posture_effective: Some(rimap_core::Posture::DraftSafe),
                arguments_redacted: serde_json::Value::Object(serde_json::Map::new()),
                arguments_hash_sha256: "0".repeat(64),
            })
            .unwrap();

        let (tx, rx) = cancellation_channel();
        let handle = super::spawn_drainer(rx, writer.clone());

        let mut inputs = dummy_inputs("a");
        inputs.start_seq = start_seq;
        tx.try_send(inputs).unwrap();
        drop(tx); // Signals drainer to exit once drained.
        handle.await.unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<_> = contents.lines().collect();
        assert_eq!(lines.len(), 2, "expected 2 records, got: {contents}");
        assert!(
            lines[1].contains(r#""status":"cancelled""#),
            "last line should be cancellation tool_end: {}",
            lines[1]
        );
    }
}
