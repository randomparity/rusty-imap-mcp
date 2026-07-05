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
tokio::task::spawn_blocking(move || audit.log_auth(record))
    .await??;
```

`rimap_imap::Connection::ensure_connected` is the canonical example.
Every `Auth` audit record passes through this pattern.

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
- We never hold the connection lock and the audit lock simultaneously.
  When a connect attempt finishes (success or failure), we drop the
  session lock guard before calling `spawn_blocking` to log the audit
  record. The two locks are taken in opposite orders by different code
  paths, so even acquiring both would not deadlock — but in practice
  nothing in Sprint 3 holds both at once.

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
follow the `spawn_blocking` pattern in
`crates/rimap-imap/src/connection.rs::Connection::emit_auth`.
