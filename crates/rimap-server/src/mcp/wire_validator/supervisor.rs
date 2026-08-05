//! Bridge-task supervisor. Owns the lifecycle of the inbound and
//! outbound bridges via their `JoinHandle`s and exposes the three
//! lifecycle methods (`watch_for_error`, `drain`,
//! `shutdown_after_failure`) consumed by `main.rs::run`.

use tokio::task::JoinHandle;

use super::ValidatorSupervisor;

impl ValidatorSupervisor {
    /// Polls each bridge `JoinHandle` in turn. Resolves with the
    /// first bridge-task error encountered, OR `Ok(())` once both
    /// bridges exit `Ok` cleanly (exotic mid-service condition —
    /// usually one side stays alive until the service ends). Used for
    /// fail-fast during the `service.waiting()` / `serve_server` race
    /// in `main.rs::run`.
    ///
    /// **Side effect.** When an arm fires, the corresponding
    /// `JoinHandle` has been polled to completion and its value
    /// consumed; the `*_consumed` flag is set so the success-path
    /// `drain` and failure-path `shutdown_after_failure` skip the
    /// already-polled handle (tokio panics on re-poll of a completed
    /// `JoinHandle`). The skipped result is treated as `Ok(())` per
    /// the invariant that this method only returns `Ok` when both
    /// bridges exited `Ok` (the `Err` arms return early and `drain`
    /// is not called on the error path).
    pub async fn watch_for_error(&mut self) -> std::io::Result<()> {
        loop {
            tokio::select! {
                biased;
                r = &mut self.inbound, if !self.inbound_consumed => {
                    self.inbound_consumed = true;
                    match Self::flatten(r) {
                        Ok(()) if self.outbound_consumed => return Ok(()),
                        Ok(()) => {}
                        Err(e) => return Err(e),
                    }
                }
                r = &mut self.outbound, if !self.outbound_consumed => {
                    self.outbound_consumed = true;
                    match Self::flatten(r) {
                        Ok(()) if self.inbound_consumed => return Ok(()),
                        Ok(()) => {}
                        Err(e) => return Err(e),
                    }
                }
                else => return Ok(()),
            }
        }
    }

    /// Success-path shutdown. Awaits both bridge tasks; returns the
    /// first error encountered, else `Ok(())`. Use when
    /// `service.waiting()` resolved `Ok` (which implies rmcp saw EOF
    /// on its read, which implies inbound already exited — drain is
    /// then essentially instant on inbound and bounded on outbound).
    ///
    /// **Do not call on failure paths** — the inbound bridge only
    /// exits on real stdin EOF, but a client may legitimately keep
    /// stdin open while waiting for the error response, causing this
    /// to hang. Use `shutdown_after_failure` instead.
    ///
    /// **Already-consumed handles are skipped.** If `watch_for_error`
    /// previously polled a `JoinHandle` to completion, its `_consumed`
    /// flag is set and the await is skipped (re-polling panics).
    /// The invariant guarantees the skipped result was `Ok`.
    pub async fn drain(mut self) -> std::io::Result<()> {
        let in_r = Self::take_or_await(&mut self.inbound, &mut self.inbound_consumed).await;
        let out_r = Self::take_or_await(&mut self.outbound, &mut self.outbound_consumed).await;
        in_r.and(out_r)
    }

    /// Failure-path shutdown. Aborts the inbound bridge (the client
    /// may keep stdin open while waiting for an error response;
    /// without abort, we'd block forever in `read_until` on real
    /// stdin), then awaits the outbound bridge to drain rmcp's
    /// queued error envelope plus any validator-synthesized
    /// rejections. Returns the first error from the outbound path;
    /// inbound cancellation is expected and ignored.
    ///
    /// Called from every failure path — pre-init
    /// `ExpectedInitializeRequest`, `InitializeFailed`, post-init bridge
    /// race error, and post-init `service.waiting()` error — but do not
    /// read that as "always runs". The pre-init arm reaches the call
    /// only when the envelope write succeeds; a write failure there
    /// propagates first and detaches both bridge `JoinHandle`s.
    /// `main.rs::handle_init_failure` documents why that is inert (#722).
    ///
    /// **Already-consumed handles are skipped.** Same contract as
    /// `drain` — re-polling a completed `JoinHandle` panics, so the
    /// `_consumed` flags gate the awaits.
    pub async fn shutdown_after_failure(mut self) -> std::io::Result<()> {
        // `abort` is always safe (no-op on a finished task); it does
        // not poll the `JoinHandle` so the consumed flag is irrelevant.
        self.inbound.abort();
        // Either it raced to EOF (Ok), got aborted (JoinError), or
        // was already consumed by `watch_for_error`. We don't care
        // about the inbound result on this path — the outbound may
        // still have queued frames to flush.
        let _ = Self::take_or_await(&mut self.inbound, &mut self.inbound_consumed).await;
        Self::take_or_await(&mut self.outbound, &mut self.outbound_consumed).await
    }

    /// Await `handle` if its `consumed` flag is `false`, then mark it
    /// consumed. Returns `Ok(())` if already consumed — guarded by
    /// the invariant documented on `drain` and `shutdown_after_failure`.
    async fn take_or_await(
        handle: &mut JoinHandle<std::io::Result<()>>,
        consumed: &mut bool,
    ) -> std::io::Result<()> {
        if *consumed {
            return Ok(());
        }
        *consumed = true;
        Self::flatten(handle.await)
    }

    fn flatten(r: Result<std::io::Result<()>, tokio::task::JoinError>) -> std::io::Result<()> {
        match r {
            Ok(inner) => inner,
            Err(je) if je.is_cancelled() => Ok(()),
            Err(je) => Err(std::io::Error::other(format!("bridge task panic: {je}"))),
        }
    }
}
