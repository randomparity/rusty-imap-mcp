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
Every `Auth` audit record written from an async context passes through
this pattern. One is not written from an async context — see the
deliberate exception under the session lock below.

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
- On every ordinary path the audit write also runs on a `spawn_blocking`
  thread, so the session lock is never held while a runtime worker is
  parked on disk I/O.
- **One path is deliberately different.** `AuthEmitGuard` (#623) writes
  the `auth` record for a connect that was cut before it finished, and
  it writes it from a `Drop`, which cannot await. That write is
  synchronous, and it runs with `dispatch::attempt`'s session lock still
  held — so a peer queued on that account waits out one fsync. The
  alternative loses the record entirely when the cut is a runtime
  shutdown; `Connection::emit_auth_blocking` documents the full
  trade-off. This is the only place a blocking audit write happens under
  the session lock, and it must stay that way.

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
`crates/rimap-imap/src/connection/login.rs::Connection::emit_auth`.

The single exception is `Connection::emit_auth_blocking` in the same
file, which writes synchronously because its caller is a `Drop` and
cannot await. Do not copy it without reading the trade-off argument on
it: it is justified only where there is no async context to defer from,
and it makes `audit.path` a local-storage requirement.
