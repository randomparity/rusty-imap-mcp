//! Write-deadline watchdog: bounds audit writes per ADR-0022.
//!
//! All file I/O for an [`AuditWriter`](super::AuditWriter) runs on one
//! dedicated worker thread that owns the file handle exclusively. Callers
//! submit requests over a channel and wait on the reply with
//! `Receiver::recv_timeout`; when the wait exceeds the configured deadline
//! the caller receives [`AuditError::WriteDeadline`] and is unblocked while
//! the worker stays parked inside the hung syscall. This is the mechanism
//! ADR-0022 names — a timeout enforced from a dedicated thread — and it
//! never holds a lock across a park (the worker owns its state outright) and
//! never crosses an `.await`.
//!
//! On deadline fire the caller follows the existing audit error propagation
//! rules: under the default `fail_open = false` the error surfaces (as
//! `ERR_INTERNAL` at the tool boundary); under `fail_open = true` it is
//! logged and suppressed like any other write failure. A timed-out record
//! may still reach disk later if the stalled I/O eventually completes;
//! ordering survives because the worker serves requests FIFO, so a later
//! record can never overtake an earlier one.
//!
//! # Shutdown
//!
//! Dropping the last writer clone sends [`Request::Shutdown`]; the worker
//! drops the file handle *before* acknowledging, so the advisory flock is
//! released by the time `Drop` returns on any run whose I/O kept up. A
//! worker wedged inside a syscall cannot acknowledge; `Drop` waits out the
//! shutdown grace and abandons the thread rather than hanging process exit.
//! The OS reclaims both at exit.

use std::io::Write as _;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, SyncSender};
use std::time::Duration;

#[cfg(any(test, feature = "test-injection"))]
use std::sync::Arc;
#[cfg(any(test, feature = "test-injection"))]
use std::sync::atomic::AtomicU64;

use crate::AuditError;

use super::core::Inner;

/// Grace period `Drop` waits for the worker to acknowledge shutdown when
/// `write_deadline_seconds` is 0 (deadline disabled). Only a worker wedged
/// inside a syscall can miss it: every submitted write already waited for
/// its own completion reply, so a healthy worker is idle at `recv` and
/// acknowledges in microseconds. When a deadline is configured, the deadline
/// itself is the grace instead.
const SHUTDOWN_GRACE_SECS_WHEN_UNBOUNDED: u64 = 30;

/// One unit of work for the writer thread.
#[derive(Debug)]
pub(crate) enum Request {
    /// Append one serialized JSONL line, flushing (and fsyncing when
    /// `fsync`) before replying.
    Write {
        bytes: Vec<u8>,
        fsync: bool,
        reply: SyncSender<Result<(), AuditError>>,
    },
    /// Total bytes written through the active file counter.
    BytesWritten {
        reply: SyncSender<Result<u64, AuditError>>,
    },
    /// On-disk length of the active file.
    OnDiskLen {
        reply: SyncSender<Result<u64, AuditError>>,
    },
    /// Release the file (and with it the advisory flock) before
    /// acknowledging, so a reopening process never races the exiting one.
    Shutdown { reply: SyncSender<()> },
}

/// Everything the worker needs besides the file handle itself.
#[derive(Debug)]
pub(crate) struct WorkerConfig {
    pub(crate) path: PathBuf,
    pub(crate) rotate_bytes: u64,
    pub(crate) rotate_keep: u32,
    pub(crate) retention_seconds: Option<u64>,
}

/// Caller-side half: the channel to the worker plus the deadline policy.
///
/// The `Mutex` serializes submitters (as the file mutex previously did) and
/// keeps `shutdown`'s takeover of the sender race-free against an in-flight
/// request.
#[derive(Debug)]
pub(crate) struct IoHandle {
    path: PathBuf,
    write_deadline_seconds: u64,
    tx: Mutex<Option<Sender<Request>>>,
    /// Test-only: when nonzero, the worker sleeps this many milliseconds
    /// before performing exactly one write, simulating a slow mount.
    #[cfg(any(test, feature = "test-injection"))]
    pub(crate) stall_next_write_ms: Arc<std::sync::atomic::AtomicU64>,
}

impl IoHandle {
    pub(crate) fn new(
        path: PathBuf,
        write_deadline_seconds: u64,
        tx: Sender<Request>,
        #[cfg(any(test, feature = "test-injection"))] stall_next_write_ms: Arc<
            std::sync::atomic::AtomicU64,
        >,
    ) -> Self {
        Self {
            path,
            write_deadline_seconds,
            tx: Mutex::new(Some(tx)),
            #[cfg(any(test, feature = "test-injection"))]
            stall_next_write_ms,
        }
    }

    fn worker_gone(&self) -> AuditError {
        AuditError::Write {
            path: self.path.clone(),
            source: std::io::Error::other("audit writer worker thread unavailable"),
        }
    }

    /// Submit `build(reply)`'s request and wait for the worker's answer.
    ///
    /// With `write_deadline_seconds > 0` the wait is bounded and a timeout
    /// becomes [`AuditError::WriteDeadline`]; with 0 the wait is unbounded,
    /// preserving the pre-watchdog behavior for operators who disable the
    /// deadline.
    ///
    /// # Errors
    /// The worker's own result, [`AuditError::WriteDeadline`] on timeout, or
    /// [`AuditError::Write`] if the worker thread is gone.
    pub(crate) fn request<R>(
        &self,
        build: impl FnOnce(SyncSender<Result<R, AuditError>>) -> Request,
    ) -> Result<R, AuditError> {
        let guard = self.tx.lock().map_err(|_| self.worker_gone())?;
        let Some(tx) = guard.as_ref() else {
            return Err(self.worker_gone());
        };
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        tx.send(build(reply_tx)).map_err(|_| self.worker_gone())?;

        if self.write_deadline_seconds > 0 {
            match reply_rx.recv_timeout(Duration::from_secs(self.write_deadline_seconds)) {
                Ok(result) => result,
                Err(RecvTimeoutError::Timeout) => Err(AuditError::WriteDeadline {
                    path: self.path.clone(),
                    deadline_seconds: self.write_deadline_seconds,
                }),
                Err(RecvTimeoutError::Disconnected) => Err(self.worker_gone()),
            }
        } else {
            reply_rx.recv().map_err(|_| self.worker_gone())?
        }
    }

    /// Take the sender out and handshake the worker shut. Called from
    /// `Drop`; idempotent (a second call finds `None` and returns).
    pub(crate) fn shutdown(&self) {
        let Ok(mut guard) = self.tx.lock() else {
            return;
        };
        let Some(tx) = guard.take() else {
            return;
        };
        let (reply_tx, reply_rx) = mpsc::sync_channel::<()>(1);
        if tx.send(Request::Shutdown { reply: reply_tx }).is_err() {
            return;
        }
        let grace = if self.write_deadline_seconds > 0 {
            Duration::from_secs(self.write_deadline_seconds)
        } else {
            Duration::from_secs(SHUTDOWN_GRACE_SECS_WHEN_UNBOUNDED)
        };
        // Bounded on purpose: an abandoned (wedged) worker must not hang
        // process exit. The flock stays held until exit either way.
        let _ = reply_rx.recv_timeout(grace);
    }
}

impl Drop for IoHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Spawn the worker thread owning `inner` and return its request channel.
pub(crate) fn spawn_worker(
    cfg: WorkerConfig,
    inner: Inner,
    #[cfg(any(test, feature = "test-injection"))] stall_next_write_ms: Arc<AtomicU64>,
) -> Sender<Request> {
    let (tx, rx) = mpsc::channel();
    let builder = std::thread::Builder::new().name("audit-writer".to_string());
    // If the OS refuses the thread, the closure (and with it `rx`) is
    // dropped and every future send fails: callers see the worker-gone
    // error instead of a silent hang.
    #[cfg(any(test, feature = "test-injection"))]
    let _ = builder.spawn(move || worker_loop(&rx, &cfg, inner, &stall_next_write_ms));
    #[cfg(not(any(test, feature = "test-injection")))]
    let _ = builder.spawn(move || worker_loop(&rx, &cfg, inner));
    tx
}

fn worker_loop(
    rx: &Receiver<Request>,
    cfg: &WorkerConfig,
    inner: Inner,
    #[cfg(any(test, feature = "test-injection"))] stall_next_write_ms: &Arc<AtomicU64>,
) {
    let mut inner = Some(inner);

    loop {
        match rx.recv() {
            // All writer clones are gone: dropping `inner` closes the file
            // and releases the advisory flock.
            Err(_) => return,
            Ok(Request::Shutdown { reply }) => {
                if let Some(inner) = inner.take() {
                    drop(inner);
                }
                let _ = reply.send(());
                return;
            }
            Ok(Request::Write {
                bytes,
                fsync,
                reply,
            }) => {
                #[cfg(any(test, feature = "test-injection"))]
                stall_once(stall_next_write_ms);
                let _ = reply.send(perform_write(inner.as_mut(), cfg, &bytes, fsync));
            }
            Ok(Request::BytesWritten { reply }) => {
                let result = match inner.as_mut() {
                    Some(inner) => Ok(inner.bytes_written),
                    None => Err(worker_gone(&cfg.path)),
                };
                let _ = reply.send(result);
            }
            Ok(Request::OnDiskLen { reply }) => {
                let result = match inner.as_mut() {
                    Some(inner) => inner
                        .buf
                        .get_ref()
                        .metadata()
                        .map(|meta| meta.len())
                        .map_err(|source| AuditError::Write {
                            path: cfg.path.clone(),
                            source,
                        }),
                    None => Err(worker_gone(&cfg.path)),
                };
                let _ = reply.send(result);
            }
        }
    }
}

fn worker_gone(path: &std::path::Path) -> AuditError {
    AuditError::Write {
        path: path.to_path_buf(),
        source: std::io::Error::other("audit writer already shut down"),
    }
}

#[cfg(any(test, feature = "test-injection"))]
fn stall_once(stall_next_write_ms: &std::sync::atomic::AtomicU64) {
    use std::sync::atomic::Ordering;
    let millis = stall_next_write_ms.swap(0, Ordering::Relaxed);
    if millis > 0 {
        std::thread::sleep(Duration::from_millis(millis));
    }
}

/// Rotation-aware append of one line; the caller's deadline is enforced by
/// its bounded wait on `reply`, not here — the worker runs to completion.
fn perform_write(
    inner: Option<&mut Inner>,
    cfg: &WorkerConfig,
    bytes: &[u8],
    fsync: bool,
) -> Result<(), AuditError> {
    let Some(inner) = inner else {
        return Err(worker_gone(&cfg.path));
    };

    // Rotation check happens before the write so two requests cannot race
    // on "needs rotation": the single worker observes the threshold in
    // request order.
    if cfg.rotate_bytes > 0 && inner.bytes_written >= cfg.rotate_bytes {
        let (new_buf, new_len) =
            super::rotation::rotate_file(&cfg.path, cfg.rotate_keep, cfg.retention_seconds)?;
        inner.buf = new_buf;
        inner.bytes_written = new_len;
        tracing::info!(path = %cfg.path.display(), "audit file rotated");
    }

    inner
        .buf
        .write_all(bytes)
        .map_err(|source| AuditError::Write {
            path: cfg.path.clone(),
            source,
        })?;
    inner.buf.flush().map_err(|source| AuditError::Write {
        path: cfg.path.clone(),
        source,
    })?;
    // bytes.len() is usize; on 64-bit targets this always fits in u64.
    // On hypothetical 128-bit targets, saturate rather than panic.
    let written = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    inner.bytes_written = inner.bytes_written.saturating_add(written);

    if fsync {
        inner
            .buf
            .get_ref()
            .sync_data()
            .map_err(|source| AuditError::Fsync {
                path: cfg.path.clone(),
                source,
            })?;
    }
    Ok(())
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
#[expect(clippy::panic, reason = "tests")]
mod tests {
    use std::time::{Duration, Instant};

    use tempfile::TempDir;

    use super::SHUTDOWN_GRACE_SECS_WHEN_UNBOUNDED;
    use crate::AuditError;
    use crate::record::ids::{ProcessId, Seq, Timestamp};
    use crate::record::{AuditRecord, Payload, ProcessEnd, ProcessEndReason};
    use crate::writer::AuditOptions;
    use crate::writer::AuditWriter;

    fn process_end_record(seq: Seq) -> AuditRecord {
        AuditRecord {
            seq,
            ts: Timestamp::now(),
            process_id: ProcessId::new_now(),
            payload: Payload::ProcessEnd(ProcessEnd {
                reason: ProcessEndReason::Eof,
                total_tool_calls: 0,
                records_lost: 0,
                undrained_dispatches: 0,
                drainer_aborted_records: 0,
            }),
        }
    }

    fn open(path: &std::path::Path, deadline_seconds: u64, fail_open: bool) -> AuditWriter {
        AuditWriter::open(&AuditOptions {
            path: path.to_path_buf(),
            rotate_bytes: 0,
            rotate_keep: 0,
            retention_seconds: None,
            fail_open,
            write_deadline_seconds: deadline_seconds,
            initial_seq: Seq::FIRST,
        })
        .unwrap()
    }

    /// The deadline fires while the worker is stalled and the caller is
    /// unbounded well before the stall ends — the property ADR-0022 exists
    /// for.
    #[test]
    fn write_deadline_fires_when_io_stalls() {
        let dir = TempDir::new().unwrap();
        let writer = open(&dir.path().join("audit.jsonl"), 1, false);
        writer.stall_next_write_ms(10_000);

        let start = Instant::now();
        let err = writer
            .write_record(&process_end_record(Seq::FIRST))
            .unwrap_err();
        let waited = start.elapsed();

        match err {
            AuditError::WriteDeadline {
                deadline_seconds: 1,
                ..
            } => {}
            other => panic!("expected WriteDeadline(1), got {other:?}"),
        }
        // Bounded by the 1s deadline plus scheduling slack, not by the 10s
        // stall. No lower bound: firing early is not a defect.
        assert!(
            waited < Duration::from_millis(5_000),
            "caller waited {waited:?}; the deadline did not bound the write"
        );
    }

    /// `write_deadline_seconds = 0` restores the unbounded wait: a slow but
    /// completing write still succeeds and reaches disk.
    #[test]
    fn zero_deadline_waits_for_a_slow_write_to_complete() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = open(&path, 0, false);
        writer.stall_next_write_ms(300);

        writer
            .write_record(&process_end_record(Seq::FIRST))
            .unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents.lines().count(), 1);
    }

    /// A timed-out record may land later; when it does it must not break
    /// sequence ordering or line integrity for records written afterwards.
    #[test]
    fn seq_order_survives_a_timed_out_stall() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = open(&path, 1, false);
        writer.stall_next_write_ms(3_000);

        let err = writer
            .write_record(&process_end_record(Seq::FIRST))
            .unwrap_err();
        assert!(matches!(err, AuditError::WriteDeadline { .. }));

        // Wait out the stall so the abandoned record lands, then confirm
        // the file holds exactly that record before writing the next one.
        let deadline = Instant::now() + Duration::from_secs(SHUTDOWN_GRACE_SECS_WHEN_UNBOUNDED);
        while std::fs::read_to_string(&path).map_or(true, |c| c.lines().count() < 1) {
            assert!(Instant::now() < deadline, "stalled record never landed");
            std::thread::sleep(Duration::from_millis(25));
        }

        writer.write_record(&process_end_record(Seq(2))).unwrap();
        drop(writer);

        let contents = std::fs::read_to_string(&path).unwrap();
        let seqs: Vec<u64> = contents
            .lines()
            .map(|line| {
                serde_json::from_str::<serde_json::Value>(line).unwrap()["seq"]
                    .as_u64()
                    .unwrap()
            })
            .collect();
        assert_eq!(seqs, vec![1, 2]);
    }

    /// Under `fail_open = true` a deadline fire is suppressed and counted
    /// exactly like any other write failure.
    #[test]
    fn fail_open_counts_a_timed_out_write() {
        let dir = TempDir::new().unwrap();
        let writer = open(&dir.path().join("audit.jsonl"), 1, true);
        writer.stall_next_write_ms(2_000);

        writer
            .write_record(&process_end_record(Seq::FIRST))
            .unwrap();
        assert_eq!(writer.suppressed_failures(), 1);
    }

    /// The shutdown handshake releases the flock before `Drop` returns on a
    /// healthy run, so an immediate reopen succeeds deterministically.
    #[test]
    fn reopen_after_drop_succeeds_while_worker_idle() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = open(&path, 5, false);
        writer
            .write_record(&process_end_record(Seq::FIRST))
            .unwrap();
        drop(writer);
        let _reopened = open(&path, 5, false);
    }
}
