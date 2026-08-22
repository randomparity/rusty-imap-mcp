//! Bounded shutdown drain for in-flight `call_tool` dispatches.
//!
//! Extracted from `mcp::server` so the server hub file carries only the
//! `ServerHandler` surface; the drain is a self-contained lifecycle
//! concern with its own tests.
use std::sync::Arc;
use std::time::Duration;

use rmcp::model::{CallToolResponse, CallToolResult, ErrorData};
use tokio::sync::watch;

/// Message returned to the (already-departed) client for a dispatch the
/// shutdown cut. Nothing reads it over the wire — rmcp's transport is gone by
/// the time [`DispatchDrain::shutdown`] runs — but the dispatch pipeline needs
/// an error value to unwind through so its audit envelope closes.
const SHUTDOWN_CUT_MESSAGE: &str = "server is shutting down";

/// Bounded shutdown drain for in-flight `call_tool` dispatches.
///
/// rmcp spawns every request handler as a **detached** `tokio::spawn` (rmcp
/// 2.2.0, `service.rs:1184`): no `JoinSet` owns them, and dropping the service
/// future releases only the transport, not the handlers. So the server tracks
/// them itself. Each dispatch registers here for its lifetime and races its
/// body against a cancel flag; [`DispatchDrain::shutdown`] sets that flag and
/// waits, bounded, for the registration count to reach zero.
///
/// Before this existed, the only thing that ever dropped a stuck dispatch was
/// `Runtime::shutdown_background` in `run_server` — which runs *after*
/// `process_end` is written. A connect cut that way emits its `auth` record
/// from `AuthEmitGuard::drop`, so the record landed with a higher `seq` than
/// the `process_end` of its own process, or was lost to process exit, or tore
/// the JSONL tail mid-line (#645). Draining first makes `process_end`
/// terminal; see `docs/audit-log.md`.
///
/// Audit writes the dispatch offloads to the blocking pool register separately,
/// through `DispatchDrain::spawn_blocking_tracked`, because a detached
/// blocking closure outlives the dispatch that submitted it (#672).
///
/// Both halves are cheap clones of one shared cell, so the server can hand a
/// clone to `serve_mcp` without any take-once ceremony.
#[derive(Clone)]
pub struct DispatchDrain {
    inner: Arc<DrainCell>,
}

/// Shared state behind [`DispatchDrain`]. `watch` channels rather than atomics
/// so both waits are event-driven: no polling interval to tune, and no
/// wake-lost window between checking a counter and parking on a `Notify`.
struct DrainCell {
    /// Dispatches currently registered.
    inflight: watch::Sender<usize>,
    /// Set once, by [`DispatchDrain::shutdown`]. Never reset — a shutdown that
    /// has begun does not un-begin.
    cancel: watch::Sender<bool>,
}

impl DispatchDrain {
    /// A drain with nothing registered and no shutdown requested.
    #[must_use]
    pub(super) fn new() -> Self {
        Self {
            inner: Arc::new(DrainCell {
                inflight: watch::Sender::new(0),
                cancel: watch::Sender::new(false),
            }),
        }
    }

    /// Run `body` as a tracked dispatch: registered for its whole lifetime, and
    /// cut short if [`DispatchDrain::shutdown`] fires first.
    ///
    /// The drop ordering is load-bearing, and holds whether the returned future
    /// completes or is itself dropped: `body` lives in the inner block, so it is
    /// dropped before the registration is released either way. Any audit record
    /// its guards write on drop (`AuthEmitGuard`, `AuditEnvelopeGuard`) is
    /// therefore already on disk, or already queued to the cancellation drainer,
    /// by the time `shutdown` observes the count reach zero.
    /// `drop_ordering_holds_when_the_track_future_is_aborted` pins it.
    ///
    /// The `tool_start` / `tool_end` writes `mcp::audit_envelope` hands to the
    /// blocking pool are not covered by that argument — a detached closure
    /// outlives the future that awaited it — so they take a registration of
    /// their own via [`DispatchDrain::spawn_blocking_tracked`] (#672).
    /// `auth` writes are synchronous (ADR-0014) and need nothing extra.
    pub(super) async fn track<F>(&self, body: F) -> Result<CallToolResponse, ErrorData>
    where
        F: Future<Output = Result<CallToolResult, ErrorData>>,
    {
        let registration = Registration::open(self);
        let mut cancel = self.inner.cancel.subscribe();
        let outcome = {
            let mut body = std::pin::pin!(body);
            tokio::select! {
                biased;
                // `wait_for` resolves immediately on an already-set flag, so a
                // dispatch rmcp spawned but had not yet polled when `shutdown`
                // ran never polls `body` at all — it cannot reach a connect,
                // so it has no record to misorder.
                _ = cancel.wait_for(|c| *c) =>
                    Err(ErrorData::internal_error(SHUTDOWN_CUT_MESSAGE.to_string(), None)),
                result = &mut body => result,
            }
        };
        drop(registration);
        outcome.map(CallToolResponse::Complete)
    }

    /// Run `f` on the blocking pool, registered with this drain for the
    /// closure's whole lifetime rather than for the awaiting future's.
    ///
    /// `spawn_blocking` is not cancellable. Dropping its `JoinHandle` — which
    /// is what dropping the future that awaits it does, and therefore what
    /// cutting a dispatch does — *detaches* the closure; it does not stop it.
    /// So an audit write already handed to the pool used to run after
    /// `process_end`, and to do it silently, because the dispatch's own
    /// registration had been released and [`DispatchDrain::shutdown`] reported
    /// a clean drain (#672).
    ///
    /// The registration is opened here, on the async side, *before* the closure
    /// is submitted, and moved into it — so it spans the queue wait as well as
    /// the write itself, and is released only when the closure returns or is
    /// dropped unrun. `shutdown` therefore either waits for the write to land
    /// or counts it in the residue it reports.
    pub(crate) fn spawn_blocking_tracked<F, R>(&self, f: F) -> tokio::task::JoinHandle<R>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        let registration = Registration::open(self);
        tokio::task::spawn_blocking(move || {
            let _registration = registration;
            f()
        })
    }

    /// Cancel every registered dispatch and wait up to `budget` for them to
    /// finish unwinding. Returns the number of registrations still outstanding
    /// when the budget expired — `0` on a clean drain.
    ///
    /// A registration is a dispatch or an audit write one of them offloaded, so
    /// a non-zero return bounds the number of dispatches involved from above
    /// rather than counting them exactly.
    ///
    /// A non-zero return is not recoverable here: the caller logs it and
    /// proceeds, because the alternative is an unbounded shutdown. Those
    /// dispatches keep the pre-#645 behaviour — whatever they write lands after
    /// `process_end` or not at all. The count is the announced residue, so
    /// discarding it silently absorbs exactly what the caller promised to
    /// report; hence `#[must_use]`.
    ///
    /// `budget` is honoured only while at least one runtime worker can still
    /// park to drive the timer. The cut path performs a synchronous, fsync-ing
    /// audit write on a worker, so on a runtime with very few workers and a slow
    /// `audit.path` the wait can outlast the budget. It stays correct — the
    /// order is what matters, not the latency — but it stops being bounded.
    #[must_use]
    pub async fn shutdown(&self, budget: Duration) -> usize {
        self.inner.cancel.send_replace(true);
        let mut inflight = self.inner.inflight.subscribe();
        let drained = tokio::time::timeout(budget, inflight.wait_for(|n| *n == 0))
            .await
            .is_ok_and(|result| result.is_ok());
        if drained {
            0
        } else {
            *self.inner.inflight.borrow()
        }
    }

    /// Registrations currently outstanding. Test-only: the drain's own tests
    /// use it as a barrier, so they synchronise on the registration actually
    /// having been taken rather than on a wall-clock sleep.
    #[cfg(test)]
    fn inflight(&self) -> usize {
        *self.inner.inflight.borrow()
    }
}

/// RAII registration in a [`DispatchDrain`]: counts up on open, down on drop.
struct Registration {
    drain: DispatchDrain,
}

impl Registration {
    fn open(drain: &DispatchDrain) -> Self {
        drain.inner.inflight.send_modify(|n| *n += 1);
        Self {
            drain: drain.clone(),
        }
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        self.drain
            .inner
            .inflight
            .send_modify(|n| *n = n.saturating_sub(1));
    }
}

#[cfg(test)]
mod dispatch_drain_tests {
    #![expect(clippy::expect_used, reason = "unit tests")]
    #![expect(clippy::panic, reason = "a test body that panics on purpose")]

    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use rimap_audit::AuditOptions;
    use rimap_audit::{AuditWriter, Seq, cancellation_channel, spawn_drainer};
    use rimap_core::tool::ToolName;
    use rmcp::model::{CallToolResult, ErrorData};

    use super::{DispatchDrain, SHUTDOWN_CUT_MESSAGE};
    use crate::mcp::dispatch::PostureContext;
    use crate::mcp::server::ImapMcpServer;

    /// What a `run_with_audit_envelope` body resolves to. Named so the
    /// `pending::<_>()` turbofish below stays readable.
    type BodyResult = Result<serde_json::Value, rimap_core::RimapError>;

    /// Records on drop that it was dropped. Stands in for `AuthEmitGuard`,
    /// whose drop performs the synchronous audit write whose ordering against
    /// `process_end` is the whole point of the drain.
    struct DropWitness(Arc<AtomicBool>);

    impl Drop for DropWitness {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    /// Spin until `flag` is set. Used instead of a fixed sleep so the tests
    /// synchronise on the dispatch actually having been polled.
    async fn await_flag(flag: &AtomicBool) {
        while !flag.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    #[tokio::test]
    async fn an_idle_drain_returns_without_spending_its_budget() {
        let drain = DispatchDrain::new();
        let started = Instant::now();
        assert_eq!(drain.shutdown(Duration::from_secs(30)).await, 0);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "an idle drain must not wait out its budget; took {:?}",
            started.elapsed(),
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_cut_dispatch_finishes_dropping_before_shutdown_reports_idle() {
        let drain = DispatchDrain::new();
        let dropped = Arc::new(AtomicBool::new(false));
        let entered = Arc::new(AtomicBool::new(false));

        let dispatch = tokio::spawn({
            let drain = drain.clone();
            let dropped = Arc::clone(&dropped);
            let entered = Arc::clone(&entered);
            async move {
                drain
                    .track(async move {
                        let _witness = DropWitness(dropped);
                        entered.store(true, Ordering::SeqCst);
                        std::future::pending::<Result<CallToolResult, ErrorData>>().await
                    })
                    .await
            }
        });
        await_flag(&entered).await;

        assert_eq!(drain.shutdown(Duration::from_secs(30)).await, 0);
        assert!(
            dropped.load(Ordering::SeqCst),
            "a dispatch's guards must have run before the drain reports idle — \
             otherwise their audit writes land after process_end",
        );

        let outcome = dispatch.await.expect("dispatch task joins");
        assert_eq!(
            outcome.err().map(|e| e.message.to_string()),
            Some(SHUTDOWN_CUT_MESSAGE.to_string()),
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_dispatch_that_cannot_be_polled_is_reported_undrained() {
        let drain = DispatchDrain::new();
        let entered = Arc::new(AtomicBool::new(false));

        // The blocking window is closed by the test, not by a clock: a wall-clock
        // sleep raced against the drain budget would flip to `0` on a starved
        // runner.
        let (release, blocked) = std::sync::mpsc::channel::<()>();
        let dispatch = tokio::spawn({
            let drain = drain.clone();
            let entered = Arc::clone(&entered);
            async move {
                drain
                    .track(async move {
                        entered.store(true, Ordering::SeqCst);
                        // Stands in for an uncancelable blocking call: the task
                        // cannot observe the cancel flag until this returns, so
                        // the drain has to give up on it.
                        let _ = blocked.recv();
                        Err(ErrorData::internal_error("finished".to_string(), None))
                    })
                    .await
            }
        });
        await_flag(&entered).await;

        assert_eq!(drain.shutdown(Duration::from_millis(50)).await, 1);

        // It then ran to completion on its own terms rather than being cut —
        // which is exactly why the drain could not account for it.
        drop(release);
        let outcome = dispatch.await.expect("dispatch task joins");
        assert_eq!(
            outcome.err().map(|e| e.message.to_string()),
            Some("finished".to_string()),
        );
    }

    /// The residue the drain reports must reach the durable audit trail as
    /// `process_end.undrained_dispatches`, or a reader holding only the file
    /// cannot tell that terminality went unbacked for that run (#680).
    ///
    /// The whole path is real: a real `DispatchDrain` producing a real non-zero
    /// count, a real `AuditWriter` writing a real line to a real file, and the
    /// same `ProcessEnd::new` shape `main.rs::emit_process_end` uses. The one
    /// thing standing in for production is the uncancelable block — an
    /// `mpsc::recv` the *test* closes rather than a clock, so the count cannot
    /// flip to zero on a fast or an overloaded runner.
    ///
    /// The wire suite `e2e_wire_shutdown_audit_ordering` covers the threading
    /// out of `serve_mcp` that this test stops short of; it cannot cover a
    /// non-zero deterministically, because every dispatch reachable from the
    /// wire is cancellable and can unwind before the drain reads its count.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_undrained_count_reaches_process_end_on_disk() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let mut options = AuditOptions::new(path.clone(), Seq::FIRST);
        options.rotate_bytes = 10 * 1024 * 1024;
        options.rotate_keep = 5;
        let writer = AuditWriter::open(&options).expect("audit writer opens");

        let drain = DispatchDrain::new();
        let entered = Arc::new(AtomicBool::new(false));
        let (release, blocked) = mpsc::channel::<()>();
        let dispatch = tokio::spawn({
            let drain = drain.clone();
            let entered = Arc::clone(&entered);
            async move {
                drain
                    .track(async move {
                        entered.store(true, Ordering::SeqCst);
                        let _ = blocked.recv();
                        Err(ErrorData::internal_error("finished".to_string(), None))
                    })
                    .await
            }
        });
        await_flag(&entered).await;

        let undrained = drain.shutdown(Duration::from_millis(50)).await;
        assert_eq!(undrained, 1, "the blocked dispatch must be reported");

        // Exactly what `run_server` does with the drain's return.
        let end = rimap_audit::record::ProcessEnd::new(
            rimap_audit::record::ProcessEndReason::Eof,
            1,
            writer.suppressed_failures(),
            u64::try_from(undrained).expect("count fits u64"),
            0,
        );
        writer.log_process_end(end).expect("process_end write");

        drop(release);
        let _ = dispatch.await;

        // Read the raw line, not through `reader`, which defaults a missing
        // field back to zero and would pass on a record that never carried it.
        let contents = std::fs::read_to_string(&path).expect("audit file readable");
        let line = contents
            .lines()
            .find(|l| l.contains(r#""kind":"process_end""#))
            .expect("a process_end line is on disk");
        assert!(
            line.contains(r#""undrained_dispatches":1"#),
            "the drain's residue must reach the record; got: {line}",
        );
    }

    /// The correctness argument for the whole drain is that a dispatch's guards
    /// finish running before its registration is released. That holds for the
    /// cancel path (covered above) and equally when the `track` future is
    /// dropped outright, which is what `Runtime::shutdown_background` still does
    /// to anything the drain could not account for. Nothing but this test stops
    /// a refactor — hoisting the `pin!`, reordering the bindings — from
    /// silently inverting it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn drop_ordering_holds_when_the_track_future_is_aborted() {
        let drain = DispatchDrain::new();
        let dropped = Arc::new(AtomicBool::new(false));
        let entered = Arc::new(AtomicBool::new(false));

        let dispatch = tokio::spawn({
            let drain = drain.clone();
            let dropped = Arc::clone(&dropped);
            let entered = Arc::clone(&entered);
            async move {
                drain
                    .track(async move {
                        let _witness = DropWitness(dropped);
                        entered.store(true, Ordering::SeqCst);
                        std::future::pending::<Result<CallToolResult, ErrorData>>().await
                    })
                    .await
            }
        });
        await_flag(&entered).await;

        dispatch.abort();
        let _ = dispatch.await;
        assert!(
            dropped.load(Ordering::SeqCst),
            "the body's guards must run when the tracked future is dropped",
        );
        assert_eq!(
            drain.shutdown(Duration::from_secs(30)).await,
            0,
            "an aborted dispatch must not leak its registration",
        );
    }

    /// A panicking dispatch must not leak its registration — otherwise every
    /// later shutdown burns its whole budget and reports a phantom residue.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_panicking_dispatch_does_not_leak_its_registration() {
        let drain = DispatchDrain::new();
        let dispatch = tokio::spawn({
            let drain = drain.clone();
            async move {
                drain
                    .track(async {
                        panic!("dispatch body panics");
                    })
                    .await
            }
        });
        assert!(
            dispatch.await.is_err(),
            "the dispatch task must have panicked",
        );

        let started = Instant::now();
        assert_eq!(drain.shutdown(Duration::from_secs(30)).await, 0);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "a leaked registration would make this wait out the budget; took {:?}",
            started.elapsed(),
        );
    }

    #[tokio::test]
    async fn a_dispatch_starting_after_shutdown_never_polls_its_body() {
        let drain = DispatchDrain::new();
        assert_eq!(drain.shutdown(Duration::from_secs(30)).await, 0);

        let polled = Arc::new(AtomicBool::new(false));
        let outcome = drain
            .track({
                let polled = Arc::clone(&polled);
                async move {
                    polled.store(true, Ordering::SeqCst);
                    Err(ErrorData::internal_error("unreachable".to_string(), None))
                }
            })
            .await;

        assert_eq!(
            outcome.err().map(|e| e.message.to_string()),
            Some(SHUTDOWN_CUT_MESSAGE.to_string()),
        );
        assert!(
            !polled.load(Ordering::SeqCst),
            "the cancel arm is biased first, so a dispatch rmcp had not yet \
             polled when the drain ran must never reach a connect",
        );
    }

    // --- #672: audit writes offloaded to the blocking pool ------------------
    //
    // `spawn_blocking` is not cancellable. Dropping its `JoinHandle` — which is
    // what dropping the future that awaits it does, and therefore what cutting a
    // dispatch does — *detaches* the closure rather than stopping it. Before the
    // fix such a write still ran, after `process_end`, and silently: the drain
    // saw the dispatch's own registration released and reported a clean drain.
    //
    // Both tests below hold that window open with the test, not with a clock.
    // The fixture runtime's blocking pool has exactly one usable thread; an
    // occupant holds it, so the audit write is *queued* rather than running when
    // the drain cuts the dispatch. A plain thread releases the occupant on a
    // delay, giving the fixed drain something to wait for and the unfixed one
    // time to write `process_end` first.

    /// Blocking-pool queue time the drain is given something to wait on. Long
    /// enough that an untracked run gets `process_end` — a local append — down
    /// first, so the ordering assertion fails rather than flickering.
    const RELEASE_DELAY: Duration = Duration::from_millis(150);

    /// Ceiling on the two barriers below. Reached in milliseconds on any host
    /// that is not pathologically loaded; burned in full only when the offload
    /// is untracked, which is the regression these tests name. Generous on
    /// purpose — expiry does not fail a barrier, it just lets the run continue
    /// to an assertion, so a slow runner costs seconds rather than a red build.
    const REGISTRATION_BARRIER: Duration = Duration::from_secs(5);

    /// How long a late write is given to land before the tail is read. Only a
    /// regression produces one, so this is spent on making the *failure*
    /// legible: too short and a broken build fails on the "record is present"
    /// assertion instead of on the ordering one.
    const SETTLE: Duration = Duration::from_secs(1);

    /// A runtime whose blocking pool has exactly one usable thread, plus a real
    /// `AuditWriter` over a temp dir. tokio sizes the pool at
    /// `max_blocking_threads + worker_threads` and the workers hold their own
    /// slots, so a single occupant leaves zero spare.
    fn offload_fixture() -> (tokio::runtime::Runtime, tempfile::TempDir, AuditWriter) {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .max_blocking_threads(1)
            .enable_all()
            .build()
            .expect("runtime builds");
        let dir = tempfile::tempdir().expect("tempdir");
        let mut options = AuditOptions::new(dir.path().join("audit.jsonl"), Seq::FIRST);
        options.rotate_bytes = 10 * 1024 * 1024;
        options.rotate_keep = 5;
        let writer = AuditWriter::open(&options).expect("audit writer opens");
        (rt, dir, writer)
    }

    /// Fill the fixture's one blocking slot. Returns once the closure is
    /// genuinely running, so nothing submitted afterwards can jump the queue,
    /// along with the sender whose drop releases it.
    fn occupy_blocking_slot() -> (mpsc::Sender<()>, tokio::task::JoinHandle<()>) {
        let (occupied_tx, occupied_rx) = mpsc::channel::<()>();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let occupant = tokio::task::spawn_blocking(move || {
            occupied_tx.send(()).expect("occupant reports in");
            let _ = release_rx.recv();
        });
        occupied_rx.recv().expect("blocking slot is occupied");
        (release_tx, occupant)
    }

    /// Release the blocking slot after [`RELEASE_DELAY`], from a plain thread:
    /// the pool is full, so the release cannot itself be a pool task.
    fn release_slot_after_delay(release_tx: mpsc::Sender<()>) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            std::thread::sleep(RELEASE_DELAY);
            drop(release_tx);
        })
    }

    /// Wait until `drain` holds `n` registrations, or until the barrier
    /// expires. Expiry is not an error: on an untracked build the second
    /// registration never appears, and the caller must go on to fail on the
    /// ordering rather than hang.
    async fn await_registrations(drain: &DispatchDrain, n: usize) {
        let deadline = Instant::now() + REGISTRATION_BARRIER;
        while drain.inflight() < n && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// Assert the raw JSONL: every line parses, the offloaded `expected_kind`
    /// record is present, and `process_end` is both the last line and the
    /// highest `seq`.
    ///
    /// Deliberately strict, and deliberately not routed through a record
    /// reader. `tests/support/chaos/audit.rs` and the production reader both
    /// skip lines they cannot parse (ADR-0015), which is exactly how a
    /// misordered or torn tail hides. The `expected_kind` check is what stops a
    /// run whose barrier fired before the write was submitted from passing
    /// vacuously — no record at all trivially satisfies an ordering assertion.
    fn assert_process_end_is_terminal(path: &std::path::Path, expected_kind: &str) {
        let contents = std::fs::read_to_string(path).expect("audit file is readable");
        let records: Vec<serde_json::Value> = contents
            .lines()
            .map(|line| {
                serde_json::from_str(line)
                    .unwrap_or_else(|e| panic!("every audit line must parse; {e} on {line:?}"))
            })
            .collect();

        assert!(
            records.iter().any(|r| r["kind"] == expected_kind),
            "the offloaded {expected_kind} must have been written at all, or this \
             test is not exercising the window it names:\n{contents}",
        );
        let last = records.last().expect("at least one record");
        assert_eq!(
            last["kind"], "process_end",
            "process_end must be the last line in the file:\n{contents}",
        );
        let max_seq = records
            .iter()
            .map(|r| r["seq"].as_u64().expect("every record carries a seq"))
            .max()
            .expect("at least one record");
        assert_eq!(
            last["seq"].as_u64().expect("process_end carries a seq"),
            max_seq,
            "process_end must carry the highest seq in the file:\n{contents}",
        );
    }

    /// Exactly what `run_server` writes, immediately after the drain returns.
    /// `undrained` is the drain's own return, as `main.rs` threads it (#680).
    fn log_process_end(writer: &AuditWriter, undrained: usize) {
        let end = rimap_audit::record::ProcessEnd::new(
            rimap_audit::record::ProcessEndReason::Eof,
            1,
            writer.suppressed_failures(),
            u64::try_from(undrained).unwrap_or(u64::MAX),
            0,
        );
        writer
            .log_process_end(end)
            .expect("process_end write succeeds");
    }

    /// A `tool_start` write already queued on the blocking pool when the drain
    /// cuts its dispatch must not append after `process_end`. The dispatch never
    /// reaches its body: it is parked on `emit_tool_start`'s offload.
    #[test]
    fn an_offloaded_tool_start_cannot_append_after_process_end() {
        let (rt, dir, writer) = offload_fixture();
        let path = dir.path().join("audit.jsonl");

        rt.block_on(async {
            let (tx, rx) = cancellation_channel();
            let drainer = spawn_drainer(rx, writer.clone());
            let server = Arc::new(ImapMcpServer::new_for_tests(writer.clone(), tx.clone()));
            let drain = server.dispatch_drain();

            let (release_tx, occupant) = occupy_blocking_slot();

            let dispatch = tokio::spawn({
                let drain = drain.clone();
                let server = Arc::clone(&server);
                async move {
                    drain
                        .track(async move {
                            server
                                .run_with_audit_envelope(
                                    ToolName::ListAccounts,
                                    None,
                                    PostureContext::Infrastructure,
                                    &serde_json::Map::new(),
                                    |_ticket| std::future::pending::<BodyResult>(),
                                )
                                .await
                        })
                        .await
                }
            });

            // The dispatch's own registration plus the offloaded write's.
            // Nothing between `track` and the `spawn_blocking` submit awaits, so
            // reaching two means the write is in the pool's queue.
            await_registrations(&drain, 2).await;

            let releaser = release_slot_after_delay(release_tx);
            let undrained = drain.shutdown(Duration::from_secs(30)).await;
            log_process_end(&writer, undrained);

            releaser.join().expect("releaser thread joins");
            occupant.await.expect("occupant joins");
            let _ = dispatch.await;
            settle(tx, server, drainer).await;

            assert_eq!(undrained, 0, "the drain must account for the queued write");
            assert_process_end_is_terminal(&path, "tool_start");
        });
    }

    /// The same for `emit_tool_end`, whose window is a different one: the body
    /// has completed and the envelope guard is already disarmed, so the only
    /// thing left to misorder is the offloaded write itself.
    #[test]
    fn an_offloaded_tool_end_cannot_append_after_process_end() {
        let (rt, dir, writer) = offload_fixture();
        let path = dir.path().join("audit.jsonl");

        rt.block_on(async {
            let (tx, rx) = cancellation_channel();
            let drainer = spawn_drainer(rx, writer.clone());
            let server = Arc::new(ImapMcpServer::new_for_tests(writer.clone(), tx.clone()));
            let drain = server.dispatch_drain();

            // The body parks here until the slot is occupied, so `tool_start`
            // gets a free pool and only `tool_end` is left queued.
            let (open_gate, gate) = tokio::sync::oneshot::channel::<()>();
            let dispatch = tokio::spawn({
                let drain = drain.clone();
                let server = Arc::clone(&server);
                async move {
                    drain
                        .track(async move {
                            server
                                .run_with_audit_envelope(
                                    ToolName::ListAccounts,
                                    None,
                                    PostureContext::Infrastructure,
                                    &serde_json::Map::new(),
                                    |_ticket| async move {
                                        let _ = gate.await;
                                        Ok(serde_json::Value::Null)
                                    },
                                )
                                .await
                        })
                        .await
                }
            });

            // Barrier on the artifact itself: `tool_start` is on disk, so the
            // pool is idle again and the occupant below is first in line.
            await_records(&path, 1).await;
            let (release_tx, occupant) = occupy_blocking_slot();
            open_gate
                .send(())
                .expect("body is still parked on the gate");

            // The dispatch's registration plus `emit_tool_end`'s. The body
            // completed, so this is the last offload the envelope makes.
            await_registrations(&drain, 2).await;

            let releaser = release_slot_after_delay(release_tx);
            let undrained = drain.shutdown(Duration::from_secs(30)).await;
            log_process_end(&writer, undrained);

            releaser.join().expect("releaser thread joins");
            occupant.await.expect("occupant joins");
            let _ = dispatch.await;
            settle(tx, server, drainer).await;

            assert_eq!(undrained, 0, "the drain must account for the queued write");
            assert_process_end_is_terminal(&path, "tool_end");
        });
    }

    /// Wait until the audit file holds `n` lines. Used as a barrier on the real
    /// artifact rather than on a sleep.
    async fn await_records(path: &std::path::Path, n: usize) {
        let deadline = Instant::now() + REGISTRATION_BARRIER;
        while Instant::now() < deadline {
            let count = std::fs::read_to_string(path)
                .map(|c| c.lines().count())
                .unwrap_or(0);
            if count >= n {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("audit file never reached {n} records");
    }

    /// Give anything the drain failed to account for time to land — so the
    /// assertions see the real tail rather than a not-yet-written one — then
    /// close the cancellation channel and join its drainer.
    async fn settle(
        tx: rimap_audit::CancelledToolEndSender,
        server: Arc<ImapMcpServer>,
        drainer: tokio::task::JoinHandle<()>,
    ) {
        tokio::time::sleep(SETTLE).await;
        drop(tx);
        drop(server);
        drainer.await.expect("drainer joins");
    }
}
