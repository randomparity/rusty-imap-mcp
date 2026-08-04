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
deferred its record to the blocking pool. ADR-0012's consequences call the
resulting window knowingly open and track it as #643.

### What tokio actually does, since the earlier prose got it wrong

The rustdoc #623 left behind said the blocking pool "refuses new work once the
runtime begins shutting down — the returned handle never resolves, and even an
already-queued closure is discarded rather than run." Read against
`tokio-1.53.1/src/runtime/blocking/pool.rs`, that is two-thirds right and the
wrong third is load-bearing enough to state properly. There are three cases:

1. **Submitted after the shutdown flag is set.** `Spawner::spawn_task` sees
   `shared.shutdown`, calls `task.task.shutdown()`, and returns
   `SpawnError::ShuttingDown`. `spawn_blocking` maps that to
   `Err(SpawnError::ShuttingDown) => join_handle` — so the handle *does*
   resolve, immediately, with a cancelled `JoinError`. The closure never runs.
   The old `emit_auth` had a join-error arm, so this case turned a successful
   connect into `ImapError::Audit { message: "tokio join error during audit
   write" }` — the record lost *and* the caller handed a spurious failure.

2. **Already queued, every pool worker idle.** This is the ordinary case: the
   pool has nothing else to do. The worker wakes on the shutdown notify, enters
   the shutdown drain, and empties the queue through
   `Task::shutdown_or_run_if_mandatory`, which for `Mandatory::NonMandatory`
   calls `task.shutdown()` — dropped, not run. `spawn_blocking` produces
   non-mandatory tasks. This is the case that loses the record silently.

3. **Already queued behind a worker that is busy at that instant.** The `BUSY`
   loop drains with `task.run()` and never rechecks the flag, so this closure
   *does* run — if the process lives long enough. `rimap-server`'s `main`
   returns immediately after `shutdown_background`, which waits for nothing, so
   usually it does not.

So the loss is real, via cases 1 and 2, and it is case 2 that is silent. The
window is small — microseconds on a healthy host — but it is a hole in an
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
- **At most one concurrent emit per account.** `Connection` is one-per-account,
  built once at boot; `connect_inner`'s only caller is `dispatch::attempt`,
  which holds the per-account `SessionGuard` across it; and a fired ceiling
  drops the `connect_inner` frame — running `AuthEmitGuard`'s write — *before*
  the enclosing guard releases the lock. So neither a hostile server nor a
  client driving concurrent calls can open a second simultaneous connect for one
  account. A hostile server makes each connect slower, not more numerous.
- **Blocked workers are bounded by `min(accounts, worker_threads)` — and the
  second term can be 1.** `rimap-server` builds its runtime with
  `Runtime::new()`, so worker count is `available_parallelism()`. Under a
  one-vCPU quota (a `--cpus=1` container, a 1-vCPU VM) that is one worker, and
  the bound is reached by the *default single-account deployment* rather than an
  exotic one. That is the shape to size the risk against, not a many-core host.
- **The wait is one fsync plus contention, not one fsync.** The audit mutex is
  process-wide and `tool_start`/`tool_end` also take it, from up to 512
  blocking-pool threads. `std::sync::Mutex` is not fair, so a worker parked in
  `emit_auth` waits for its own fsync plus whatever is queued ahead of it; with
  N accounts emitting at once the N-th pays roughly N times the per-record cost.

The one unbounded case is unchanged from #623 and is now reachable on every
connect rather than only on a cut one: an `audit.path` that stops responding — a
hung NFS or SMB mount — pins the worker for the life of the process, with the
account's session lock still held. `audit.path` on local storage is a
requirement, not a preference; `emit_auth`'s rustdoc states this to
contributors, and widening `docs/audit-log.md`'s statement of it — today still
scoped to the cut path — is tracked in
[#667](https://github.com/randomparity/rusty-imap-mcp/issues/667).

### The measurement harness

Not committed to the tree, so it is reproduced here in full. Drop it into a
scratch crate depending on `rimap-audit` and `rimap-core` by path, build
`--release`, and pass a directory:

```rust
use std::time::Instant;
use rimap_audit::writer::{AuditOptions, AuditWriter};
use rimap_core::auth_event::{AuthEvent, AuthResult};
use rimap_core::auth_sink::AuthEventSink;

fn event() -> AuthEvent {
    AuthEvent {
        account: Some("alice".to_string()),
        result: AuthResult::Success,
        host: "imap.example.test".to_string(),
        port: 993,
        username: "alice@example.test".to_string(),
        tls_fingerprint_sha256: Some("ab".repeat(32)),
        fingerprint_match: Some(true),
        error_code: None,
        credential_source: None,
    }
}

fn main() {
    let dir = std::env::args().nth(1).expect("usage: emitcost <dir> [n]");
    let n: usize = std::env::args().nth(2).map_or(2000, |s| s.parse().unwrap());
    let writer = AuditWriter::open(&AuditOptions {
        path: std::path::Path::new(&dir).join("audit.jsonl"),
        rotate_bytes: 0,          // steady state, not the rotation outlier
        rotate_keep: 0,
        retention_seconds: None,
        fail_open: false,
        initial_seq: rimap_audit::record::ids::Seq::FIRST,
    })
    .expect("open audit writer");

    for _ in 0..50 {
        AuthEventSink::emit_auth(&writer, event()).expect("warmup");
    }
    let mut samples = Vec::with_capacity(n);
    for _ in 0..n {
        let ev = event();
        let start = Instant::now();
        AuthEventSink::emit_auth(&writer, ev).expect("emit");
        samples.push(start.elapsed().as_secs_f64() * 1000.0);
    }
    samples.sort_by(f64::total_cmp);
    let pct = |p: f64| samples[((samples.len() as f64 - 1.0) * p) as usize];
    println!("mean {:.3}", samples.iter().sum::<f64>() / samples.len() as f64);
    println!("p50 {:.3}  p95 {:.3}  p99 {:.3}  max {:.3}",
             pct(0.50), pct(0.95), pct(0.99), pct(1.0));
}
```

## Alternatives considered

- **Bound the shutdown instead: `Runtime::shutdown_timeout` before
  `emit_process_end` in `rimap-server`.** Rejected, and note it is weaker than
  it first appears. A timeout waits for blocking tasks that are already
  *running*; a task still *queued* is drained by the same
  `shutdown_or_run_if_mandatory` path as case 2 above and dropped regardless of
  how long the timeout is. So it would help only when the write had already
  started — which is the case that was never at risk. It also makes the
  durability of an `auth` record depend on a value configured in a different
  crate from the one that writes it, and leaves the two halves of
  `connect_inner` on different mechanisms, which is the condition that produced
  this bug in the first place.

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
  documented it. Rejected: the deferred path cost the same wall time and ran the
  same code, and bought only a way to lose the record. It is *nearly* a strict
  simplification — the one thing it did buy is named under Consequences below.

## Consequences

- The **completed-connect** record no longer depends on the blocking pool being
  drained: it is written by the thread that produced the event, inline, before
  that thread proceeds. This does **not** extend to the cut path. `AuthEmitGuard`
  writes from a `Drop`, and `shutdown_background` can let the process exit before
  the dropping worker reaches the write, so that record stays best-effort on a
  runtime shutdown — as the guard's own rustdoc says. Do not read this ADR as
  claiming every `auth` record now survives a shutdown.

- A runtime worker is blocked for one fsync per connect, bounded as above. On a
  non-local `audit.path` that bound does not hold, and the failure mode is a
  pinned worker rather than a lost record. Because tokio's time driver only
  advances when a worker parks, workers pinned that way also stop `tokio::time`
  deadlines from firing — `command_timeout` and the ADR-0012 ceiling included.
  Immaterial at single-digit milliseconds; it is the mechanism by which the hung
  mount wedges the scheduler.

- **One property was given up: `spawn_blocking`'s panic containment.** A panic
  inside a sink used to come back as a `JoinError` and become
  `ImapError::Audit`, leaving the process and the writer usable. It now unwinds
  through `connect_inner` and poisons the `AuditWriter`'s mutex, which
  `lock_inner` maps to a permanent `AuditError` — one transient panic becomes a
  process-wide audit outage. Latent, not live: the `AuthEventSink` contract
  forbids panicking and the shipped writer has no panicking construct on its
  write path. [#646](https://github.com/randomparity/rusty-imap-mcp/issues/646)
  closes it structurally.

- **The window this ADR closes is the queue-discard one, and not every way a
  completed connect can go unrecorded.** The rest, all pre-existing: a
  `fail_open = true` write failure is suppressed and counted in
  `suppressed_failures`; a `fail_open = false` write failure on the *success*
  branch propagates as an error to the caller and is deliberately **not** counted
  by `note_auth_write_lost` (the caller was told), so the credential was used and
  the log has no evidence beyond the writer's own `tracing::error!`; a
  `build_tls_config` failure exits before the guard is armed; and a process abort
  before fsync returns is unavoidable.

- **[#645](https://github.com/randomparity/rusty-imap-mcp/issues/645) now has two
  producers, not one.** It is scoped to the cut path appending an `auth` record
  after its own `process_end`. Because the completed path's write is no longer
  discarded, a worker still finishing a connect when `serve_mcp` returns can
  land its record after `process_end` too, and that write races process exit the
  same way. Ordering *within* a tool call is unaffected: `connect_inner` already
  awaited the deferred write, so the record still falls in the
  `[tool_start.seq, tool_end.seq]` window.

- **ADR-0012's consequence bullet stating that "the completed-connect path keeps
  its own residual shutdown window ... Tracked in #643" is superseded by this
  ADR.** ADR-0012 is immutable and its own decision — the tool-call ceiling — is
  untouched, so it is not edited and not marked superseded; only that one
  forward-looking consequence has been overtaken. `docs/architecture/audit-locking.md`
  is the live description of the locking discipline and has been corrected in
  the same change.

- `Connection::emit_auth` no longer returns a join error, so
  `ImapError::Audit { op: "emit_auth", .. }` now only ever carries a sink
  failure. The variant and its wire mapping are unchanged. Its `tracing::error!`
  was dropped as redundant rather than as a regression: the production
  `AuditWriter` already logs at `error` with the code and the path before
  returning, and every caller of `emit_auth` either propagates the error or logs
  it. `message` is still the sink's pre-sanitized `AuthSinkError::message()`, and
  `ImapError::Audit`'s `Display` does not walk the `source` chain, so nothing new
  reaches a log or the wire.

- The unit test `emit_auth_completes_despite_caller_cancellation` was deleted
  rather than adapted: it pinned `spawn_blocking`'s handle-drop semantics, which
  the emit no longer relies on. Nothing replaces it directly, because the
  invariant is now structural — `emit_auth` is `fn`, not `async fn`, so no
  cancellation point exists between the disarm and the write, and the type system
  enforces that more strongly than a runtime test could. What was added instead
  is `a_completed_connect_records_its_auth_event_without_the_blocking_pool` in
  `crates/rimap-imap/tests/connect_auth_record.rs`, which asserts the outcome: a
  completed connect leaves its record even when the blocking pool will never run
  another task. It reads the sink while the pool's only thread is still occupied,
  so it is deterministic in both directions rather than resting on shutdown
  timing — verified at 40/40 green against this change and 0/40 against the
  deferred emit.

- **Several documents outside this change still describe the abolished
  contract** — `crates/rimap-core/src/auth_sink.rs` (the trait doc a sink
  implementer reads), `crates/rimap-audit/src/writer/emit.rs`,
  `docs/audit-log.md`, and `crates/rimap-config/src/validate/limits.rs`. They sit
  outside this change's file scope and are collected in
  [#667](https://github.com/randomparity/rusty-imap-mcp/issues/667).

- The `spawn_blocking` recipe still governs every *other* blocking call from
  async code in this workspace. This ADR is about the `auth` emitters
  specifically, and the reason is specific to them: they must survive the
  runtime that would otherwise defer them.
