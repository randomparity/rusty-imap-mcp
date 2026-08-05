# Audit locking discipline

rusty-imap-mcp uses two distinct mutexes around shared state, with
opposite rules about whether they may be held across an `.await`. Both
rules apply concurrently — getting either wrong is a deadlock or a
data-loss bug.

## The audit writer lock (`std::sync::Mutex`)

`rimap_audit::AuditWriter` wraps its buffered file writer in a
`std::sync::Mutex` (via `Arc<Mutex<Inner>>`). Every call to
`write_record`, `log_auth`, `log_process_start`, or `allocate_seq`
locks this mutex, performs synchronous I/O, and unlocks before
returning.

**Rule: this lock must NEVER be held across an `.await` point.**

Why:

- The lock is `std::sync::Mutex`, not `tokio::sync::Mutex`. Holding a
  std mutex across an `.await` blocks the runtime worker if the future
  is poll-yielded while the lock is held.
- The clippy lint `await_holding_lock = "deny"` enforces this at the
  workspace level for `std::sync::MutexGuard`.
- Sprint 2's design committed to synchronous, fsync-on-critical-record
  audit emission. Making the audit writer async would require either
  spawning blocking tasks per write (the path Sprint 3 takes for
  emission from async code) or rewriting it as fully async (rejected:
  audit logs are append-only and small; tokio's async I/O adds latency
  without throughput benefit).

### How async code calls into the audit writer

From any async function that needs to emit an audit record, use
`tokio::task::spawn_blocking`:

```rust
let audit = self.audit.clone();   // AuditWriter is cheaply cloneable
tokio::task::spawn_blocking(move || audit.log_tool_end(record))
    .await??;
```

**`auth` records are the exception, and they are the exception on
purpose.** Every `auth` record — `connect_inner`'s own on a completed
connect, and the one `AuthEmitGuard`'s `Drop` writes for a cut one —
goes through `rimap_imap::Connection::emit_auth`, which takes and
releases the audit lock *inline, on the calling thread*. That still
satisfies the rule above (the lock is not held across an `.await`; there
is no `.await`).

For the completed connect that is what makes the record no longer depend
on the blocking pool being drained — a deferred write is refused
outright when it is submitted after the shutdown flag, and merely racing
process exit when it was already queued, and `rimap-server` shuts down
with `Runtime::shutdown_background`, which waits for nothing. It is
**not** an unconditional survival guarantee, for either emitter: a
thread still inside the write when the process exits loses the record
whichever emitter it is, and the guard writes from a `Drop` that can
lose that race outright, so that path stays best-effort exactly as
`AuthEmitGuard`'s own rustdoc says. See
[ADR-0014](../ADR/0014-synchronous-auth-audit-emission.md) for the
decision, the tokio shutdown semantics it actually rests on, the
measured cost, and the bound on how many runtime workers this can
occupy at once.

Note that this reverses what an earlier version of this document said,
and what [ADR-0012](../ADR/0012-tool-call-ceiling.md)'s consequences
describe: ADR-0012 records the completed-connect path as still deferring,
with a residual shutdown window tracked as
[#643](https://github.com/randomparity/rusty-imap-mcp/issues/643). That
window is closed. ADR-0012 is immutable and its own decision stands; this
document is the live description.

## The connection session lock (`tokio::sync::Mutex`)

`rimap_imap::Connection` wraps its `Option<async_imap::Session>` in a
`tokio::sync::Mutex`. Every public method on `Connection` acquires the
lock, runs an `.await`-heavy IMAP command sequence, and releases.

**Rule: this lock IS held across `.await` points. It HAS to be —
async-imap commands are themselves `.await`.**

Why this is fine:

- `tokio::sync::Mutex::lock()` is itself `.await`-able and yields
  cooperatively rather than blocking the runtime worker.
- The lock serializes IMAP commands per-connection, which is what we
  want: a single IMAP session can only have one in-flight tagged
  command at a time per RFC 3501.
- The audit lock is a leaf: nothing that holds it reaches for a session
  lock, so no ordering between the two can deadlock.
- Audit writes other than `auth` run on a `spawn_blocking` thread, so
  the session lock is never held while a runtime worker is parked on
  disk I/O for those.
- **The `auth` emitters are deliberately different**, both of them
  (#623, #643). `AuthEmitGuard` writes the record for a connect that was
  cut, from a `Drop` that cannot await; `connect_inner` writes the record
  for one that completed, inline for the same durability reason. Both run
  with `dispatch::attempt`'s session lock still held, so a peer queued on
  that account waits out one fsync — single-digit milliseconds on local
  storage, measured in [ADR-0014](../ADR/0014-synchronous-auth-audit-emission.md) —
  *plus* any contention on the audit mutex itself, which `tool_start` and
  `tool_end` also take from the blocking pool.
  These are the only places a blocking audit write happens under the
  session lock, and it must stay that way: it is the `auth` record's
  durability that buys the exception, and nothing else has that claim.
  The write is unbounded on a non-local `audit.path`; making
  `docs/audit-log.md`'s local-storage requirement cover every connect
  rather than only cut ones is tracked in
  [#667](https://github.com/randomparity/rusty-imap-mcp/issues/667).

### Operator impact: concurrent calls to one account serialize

Because the session lock is held for the full duration of an IMAP
command, **concurrent tool calls against the same account do not run in
parallel** — they queue and execute one at a time, in the order they
acquire the lock. This is a direct, intentional consequence of RFC 3501
(one in-flight tagged command per session), not a bug.

The practical effect: a slow command (e.g. a large `FETCH` or a
`SEARCH` against a big mailbox) head-of-line-blocks every other queued
call on that account until it completes or the server's
`command_timeout_seconds` fires (default 30s — see
[configuration.md](../configuration.md)). A caller waiting on a queued
command can therefore see latency up to the full timeout even though
its own command would otherwise be fast.

This only affects calls scoped to the *same* account. Different
accounts each have their own `Connection` and session lock, so they
never block one another — see
[multi-account.md](../multi-account.md#per-account-isolation). An
operator who needs true parallelism for one account's workload has no
in-process workaround today; running multiple server instances against
separate credentials for that account is the only way to get
concurrent sessions (subject to the IMAP server's own per-account
connection limits).

## Quick reference

| Lock | Type | Held across `.await`? | Why |
|---|---|---|---|
| Audit writer (`Inner`) | `std::sync::Mutex` | **NO** | Synchronous I/O; clippy enforces |
| Connection session | `tokio::sync::Mutex` | **YES** | async-imap commands are async |

Future contributors who add new audit emission paths from async code:
follow the `spawn_blocking` pattern above.

The exception is the `auth` pair in
`crates/rimap-imap/src/connection/login.rs` — `Connection::emit_auth`
and `Connection::emit_auth_blocking`, which delegates to it — both of
which write synchronously. Do not copy them without reading the
trade-off argument on `emit_auth` and
[ADR-0014](../ADR/0014-synchronous-auth-audit-emission.md): it is
justified only for a record that must survive the runtime that would
otherwise defer it, and it makes `audit.path` a local-storage
requirement.
