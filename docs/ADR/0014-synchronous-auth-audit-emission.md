# ADR-0014: Every `auth` audit record is written synchronously, on the thread that produced it

**Status:** Accepted · 2026-08-04 · issue [#643](https://github.com/randomparity/rusty-imap-mcp/issues/643)

## Context

`rimap-audit::AuditWriter` is a synchronous, fsyncing, `std::sync::Mutex`-guarded
writer. `docs/architecture/audit-locking.md` has, since Sprint 3, required async
callers to route into it through `tokio::task::spawn_blocking`, so the std mutex
is never held across an `.await`. `Connection::emit_auth` obeyed that:

```rust
tokio::task::spawn_blocking(move || sink.emit_auth(event)).await
```

[ADR-0012](0012-tool-call-ceiling.md) records the one exception introduced by
[#623](https://github.com/randomparity/rusty-imap-mcp/issues/623):
`AuthEmitGuard::drop` writes the record for a *cut* connect inline, because a
`Drop` cannot await, and because tokio's blocking pool refuses work once the
runtime begins shutting down.

That left the two halves of one function disagreeing. `connect_inner` disarms
the guard and then awaits `emit_auth`, so a connect that **completed** still
deferred its record to the blocking pool. Tokio drops queued blocking tasks once
shutdown starts — not merely refusing new submissions — and `rimap-server` shuts
down with `Runtime::shutdown_background`, which waits for nothing. A shutdown
landing between the queue and the run therefore drops the `auth` record for a
connect that reached the server and authenticated, with the guard already
disarmed and no other path covering it. ADR-0012's consequences call this window
knowingly open and track it as #643.

The window is small — microseconds on a healthy host — but it is a hole in an
append-only security log, on the record that says a credential was used against
a remote server.

## Decision

- **Collapse `Connection::emit_auth` to a synchronous call and delete the
  `spawn_blocking` hop.** It becomes `fn emit_auth(&self, event) -> Result<(),
  ImapError>`, invoked without `.await` from both of `connect_inner`'s emit
  arms.

- **Route `emit_auth_blocking` through it.** The guard's emitter now differs
  from the ordinary one only in failure handling — `note_auth_write_lost` plus a
  `tracing::error!`, because a `Drop` has nowhere to propagate to. There is one
  call into `AuthEventSink::emit_auth` in the crate, not two.

- **This closes the window rather than shrinking it.** With the write
  synchronous there is no `.await` between `emit_guard.disarm()` and the write,
  so no cut of any kind — ceiling, client cancellation, runtime shutdown — can
  land in the handover. The guard/`connect_inner` split stops being a race and
  becomes a plain branch.

- **The `spawn_blocking` requirement in `docs/architecture/audit-locking.md` no
  longer describes the `auth` path.** The document is updated to say what is now
  true: the std mutex is still never held across an `.await` — it is taken and
  released inline — and the `auth` emitters are the exception to the
  `spawn_blocking` recipe, not an application of it. The rule that survives is
  the one clippy enforces (`await_holding_lock`), which this shape satisfies
  trivially.

- **Cost accepted on the evidence below, not on the assertion that it is
  small.**

## What the change costs

The decisive framing: `connect_inner` **already awaited** the write to
completion before returning, so the connect's end-to-end latency is unchanged.
What moved is which thread spends that time — a tokio runtime worker instead of
a blocking-pool thread. The cost is therefore worker occupancy, not latency.

Measured with `AuthEventSink::emit_auth` driven against a real `AuditWriter`
(rotation disabled, so this is the steady-state per-record cost), 2000 records
after a 50-record warmup, on the development host — Apple M5 Max, macOS, APFS on
the internal NVMe:

| | ms |
|---|---|
| mean | 4.70 |
| p50 | 4.09 |
| p95 | 6.91 |
| p99 | 11.72 |
| max | 16.92 |

Read that as the pessimistic end. Rust's `File::sync_data` maps to
`F_FULLFSYNC` on macOS, a full barrier to the device; on Linux it is
`fdatasync`, which is materially cheaper on the same class of hardware. Only the
one host was measured, and no figure for CI's Linux runners is claimed here.
The rotation path is excluded deliberately — it adds a rename, an open, and with
retention a `read_dir` plus a `remove_file` per pruned file, and it is an
outlier the `emit_auth` rustdoc states separately rather than an amortized cost.

Bounding the worker occupancy that buys:

- **Once per connect, not once per tool call.** Connects are lazy; a session is
  reused until it is poisoned or the transport fails.
- **At most one concurrent emit per account.** `dispatch::attempt` serializes
  connects for an account behind the session lock, so the number of runtime
  workers blocked in an `auth` emit at any instant is bounded by the number of
  configured accounts.
- **Against a worker pool sized to the host.** `rimap-server` builds its runtime
  with `Runtime::new()`, so worker count is `available_parallelism`. Starving the
  scheduler requires as many accounts connecting simultaneously as the host has
  cores, each paying single-digit milliseconds.

The one unbounded case is unchanged from #623 and is now reachable on every
connect rather than only on a cut one: an `audit.path` that stops responding — a
hung NFS or SMB mount — pins the worker for the life of the process, with the
account's session lock still held. `audit.path` on local storage is a
requirement, not a preference; `docs/audit-log.md` states this to operators and
`emit_auth`'s rustdoc states it to contributors.

## Alternatives considered

- **Bound the shutdown instead: `Runtime::shutdown_timeout` before
  `emit_process_end` in `rimap-server`.** Rejected. It shrinks the window rather
  than closing it — a write still queued when the timeout expires is still
  dropped — and it makes the durability of an `auth` record depend on a value
  configured in a different crate from the one that writes it. It also leaves
  the two halves of `connect_inner` on different mechanisms, which is the
  condition that produced this bug.

- **Disarm `AuthEmitGuard` *after* the emit rather than before.** Rejected in
  #643's own analysis and still wrong: with a deferred write it trades a rare
  gap for a rare duplicate at the same `.await`, and a duplicate in an
  append-only audit log is no better than a gap. With the write synchronous the
  question dissolves — there is no await between the two points, so either order
  is correct.

- **Make `AuditWriter` async.** Rejected when the writer was designed and still
  rejected: audit records are small and append-only, tokio's async file I/O is
  itself `spawn_blocking` underneath, and it would not change the shutdown
  behaviour that causes the loss.

- **Accept the window as documented.** This was the status quo, and ADR-0012
  documented it. Rejected now that the fix is a strict simplification: the
  deferred path cost the same wall time, ran the same code, and only added a way
  to lose the record.

## Consequences

- Every `auth` record in the process is written by the thread that produced the
  event, inline, before that thread proceeds. The audit log gains a property it
  did not have: an `auth` record's existence does not depend on the runtime
  outliving the connect.

- A runtime worker is blocked for one fsync per connect, bounded as above. On a
  non-local `audit.path` that bound does not hold, and the failure mode is a
  pinned worker rather than a lost record.

- **ADR-0012's consequence bullet stating that "the completed-connect path keeps
  its own residual shutdown window ... Tracked in #643" is superseded by this
  ADR.** ADR-0012 is immutable and its own decision — the tool-call ceiling — is
  untouched, so it is not edited and not marked superseded; only that one
  forward-looking consequence has been overtaken. `docs/architecture/audit-locking.md`
  is the live description of the locking discipline and has been corrected in
  the same change.

- `Connection::emit_auth` no longer returns a join error, so
  `ImapError::Audit { op: "emit_auth", .. }` now only ever carries a sink
  failure. The variant and its wire mapping are unchanged.

- The unit test `emit_auth_completes_despite_caller_cancellation` was deleted
  rather than adapted: it pinned `spawn_blocking`'s handle-drop semantics, which
  the emit no longer relies on. The property that replaces it —
  `a_completed_connect_records_its_auth_event_without_the_blocking_pool` in
  `crates/rimap-imap/tests/connect_auth_record.rs` — asserts the stronger and
  now-true statement: a completed connect leaves its record even when the
  blocking pool will never run another task and the runtime is shutting down.

- The `spawn_blocking` recipe still governs every *other* blocking call from
  async code in this workspace. This ADR is about the `auth` emitters
  specifically, and the reason is specific to them: they must survive the
  runtime that would otherwise defer them.
