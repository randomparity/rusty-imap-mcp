# ADR-0015: `process_end` is terminal, enforced by a bounded dispatch drain

**Status:** Accepted · 2026-08-04 · issue [#645](https://github.com/randomparity/rusty-imap-mcp/issues/645)

## Context

`docs/audit-log.md` described `process_end` as the record written on shutdown.
It never said whether anything *follows* it, and nothing enforced that anything
did not. Readers — human and tooling — treat it as terminal anyway, because
that is the only reading a per-process `seq` counter and a per-process
`process_id` invite.

Three facts together made that reading unsafe.

**rmcp does not own its handlers.** In rmcp 2.2.0, each request handler is
started with a detached `tokio::spawn` (`service.rs:1184`), not into a
`JoinSet`. Shutdown drains outstanding *responses* on a bounded budget
(`service.rs:1274-1305`) and then returns; a handler still running past that
budget survives both `drop(service_fut)` and `service.waiting()`. Nothing in
the server held a handle to it.

**A cut connect writes from `Drop`.** Since #623 / ADR-0012, `AuthEmitGuard`
emits its `auth` record synchronously from `Drop`, so that a connect cut before
it reached a verdict is recorded rather than silently omitted. That write is
therefore triggered by *whoever drops the dispatch future*.

**Nothing dropped it until after `process_end`.** `run_server` wrote
`process_end` at `main.rs:196` and only then called `rt.shutdown_background()`.
Dropping the runtime is what dropped the detached handler, so the `auth` record
the drop produced was appended with a **higher `seq` than the `process_end` of
its own `process_id`**. This is not merely an unspecified order — it is an
inverted one, because the drop cannot happen before the runtime is dropped.

Two further states followed from the same window. That write raced `main`
returning to `exit`, so the record could instead be lost outright, or land
half-written and leave the JSONL tail unparseable. And a dispatch still holding
a cancellation-channel sender kept `serve_mcp`'s drainer join waiting for that
command's full timeout, so the process did not exit promptly either.

No test caught any of it. `tests/support/chaos/audit.rs::parse_lines` skipped
unparseable lines and `crates/rimap-audit/tests/partial_line.rs` shows the
production reader skipping a truncated final line by design — so both readers
render a torn tail indistinguishable from a record that was never written.
Nothing asserted that `process_end` was last.

## Decision

**`process_end` is terminal for its `process_id`,** subject to two named
exceptions recorded below. When the record is present, no other record carrying
the same `process_id` appears after it. This is now a stated rule in
`docs/audit-log.md`, not an implication a reader has to infer.

It is enforced by the server tracking its own in-flight dispatches, in
`ImapMcpServer`:

- A `DispatchDrain` — a shared cell holding an in-flight count and a cancel
  flag, both `tokio::sync::watch` channels so each wait is event-driven.
- `ServerHandler::call_tool` is reduced to registering with the drain and
  deferring to `ImapMcpServer::dispatch_call_tool`. There is exactly one place
  a dispatch can start, and it cannot be entered untracked.
- `serve_mcp` sets the cancel flag and waits, bounded, for the count to reach
  zero — **before** it returns, therefore before `emit_process_end`.
  `rt.shutdown_background()` stays last and unchanged.

Cancellation is by `tokio::select!` with `biased`, cancel arm first, and the
dispatch body is dropped at the end of that select — before the registration is
released. So a guard's audit write is already on disk (or already queued to the
cancellation drainer) by the time the drain observes the count reach zero. The
bias also covers the dispatch rmcp spawned but had not yet polled: it sees the
flag already set and never polls its body, so it never reaches a connect and
has no record to misorder.

The budget is **2 seconds**, and it buys only unwinding, not completion — the
dispatches are cancelled, not awaited. What has to fit inside it is a
synchronous `AuthEmitGuard` write plus its `fsync`, and any blocking call that
has to return before its task can be polled again. On expiry the server logs
`tool dispatches outlived the shutdown drain` with the count and proceeds.

The budget is honoured only while at least one runtime worker can still park to
drive the timer. `Runtime::block_on` on the multi-thread scheduler does not
advance the time driver itself, and the cut path performs a synchronous,
fsync-ing audit write *on a worker*. So on a runtime with very few workers and a
slow `audit.path`, the wait can outlast its nominal bound. It stays correct —
what the drain guarantees is the ordering, not the latency — but it stops being
bounded. `audit.path` on local storage is the precondition.

The cancellation-drainer join is bounded at **1 second** for the same reason: on
the clean path every sender is already gone and it returns at once, but an
undrained dispatch still holds a sender clone and an unbounded join would hold
process exit for that command's own timeout. On expiry the handle is
**aborted**, not merely dropped: dropping a `JoinHandle` detaches the task, and
a detached drainer would keep appending `tool_end` records past `process_end`.

`tests/support/chaos/audit.rs::parse_lines` now panics on an unparseable line
rather than skipping it. A corrupt log must not read as a log missing a record.

## Consequences

- A reader may treat `process_end` as closing its process, and may attribute
  every later record to a later run. Tooling that merges rotated audit files
  can rely on this.
- A dispatch cut by the shutdown is now recorded deterministically rather than
  best-effort — within the drain budget. This **narrows** the residual that
  ADR-0012 records for the shutdown path ("best-effort on a runtime shutdown,
  where the process may exit before the dropping worker reaches the write").
  ADR-0012's decision is unchanged and stands; only that window closes. This
  ADR does not supersede it.
- Shutdown gains a bounded cost it did not have: up to 2 s of drain plus up to
  1 s of drainer join, in addition to rmcp's own fixed response-drain budget.
  On the ordinary path — no dispatch in flight — both waits return immediately,
  because a `watch` receiver checks the current value before parking.
- The rule has two holes, and `docs/audit-log.md` names both rather than burying
  them.
  - **A dispatch that outlives the budget** keeps the pre-#645 behaviour. This
    one is announced on stderr with a count, so an operator can alert on it, and
    the doc tells a reader to treat such a run as suspect. #647 will carry the
    same fact into the audit trail as a counter on `process_end`.
  - **A `tool_start` or `tool_end` write already handed to `spawn_blocking`**
    (`mcp/audit_envelope.rs`). Dropping the task awaiting that `JoinHandle`
    *detaches* the closure rather than cancelling it, so the write still lands,
    after `process_end`. This one is silent: the drain sees the registration
    released and reports a clean drain. `auth` writes are not affected —
    ADR-0014 made every one of them synchronous. Closing it means making the two
    offloaded writes countable, with an RAII ticket taken on the async side
    before the offload and moved into the closure; tracked as
    [#672](https://github.com/randomparity/rusty-imap-mcp/issues/672).
- `ImapMcpServer::new`'s signature is unchanged; the drain is constructed
  internally and handed out by a new `dispatch_drain()` accessor. The public
  API change is additive, so `cargo-semver-checks` sees a minor bump.

## Alternatives considered

**`Runtime::shutdown_timeout` instead of `shutdown_background`** — the fix the
issue itself suggested. Rejected on inspection: `shutdown_timeout(0)` is
literally `shutdown_background`, so it changes nothing, and any non-zero timeout
makes the runtime drop wait on blocking tasks. The #277 envelope validator holds
a `tokio::io::stdin()` whose blocking read is uncancelable, so a client that
legitimately keeps stdin open after the server decides to shut down would hang
the exit for the whole timeout. That regression is exactly what the comment
above `shutdown_background` exists to prevent. It also would not fix the
ordering, because it still runs *after* `emit_process_end`.

**Move `emit_process_end` after `shutdown_background`** — makes `process_end`
last by construction, and nothing else. The cut dispatch's write would still
race process exit, and `process_end` would be written after the runtime that
owns the audit machinery had been torn down.

**`tokio_util::task::TaskTracker` + `CancellationToken`** — the off-the-shelf
version of this cell, and the closer fit in the abstract. Rejected for the size
of the change it demands rather than for its behaviour: `tokio-util` is present
only transitively, so adopting it means a new direct workspace dependency, a
lockfile change, and the fuzz-lockfile parity realignment that follows
(ADR-0011). Two `watch` channels on the `tokio` dependency already declared cost
about forty lines and no manifest churn. Worth revisiting if a second call site
ever needs the same primitive.

**Track at the `AuthEmitGuard` level instead** — i.e. have the guard itself
register somewhere the shutdown can wait on. Rejected: it puts shutdown
knowledge in `rimap-imap`, and it would still leave every *other* in-flight
dispatch orphaned, including the one whose `AuditEnvelopeGuard` holds the
cancellation sender that stalls the drainer join. The dispatch is the right
unit of ownership because it is the unit rmcp actually spawns.
