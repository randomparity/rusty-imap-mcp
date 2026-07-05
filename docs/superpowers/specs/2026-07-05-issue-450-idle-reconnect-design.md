# Transparently recover from an idle-disconnect on the first resumed tool call

Issue: #450 (epic #446, FABLE_AUDIT finding M-13, Medium). Depends on #449
(correct `ConnectionLost` classification), merged to `main`.

## Problem

`Connection::with_session` (in `crates/rimap-imap/src/connection/dispatch.rs`)
is *invalidate-only*. When a cached session has gone stale — the IMAP server
closed it during an idle gap — the first resumed command fails, async-imap
surfaces `ConnectionLost`, and `with_session` drops the session and **returns
the error**. Only the *second* tool call lazy-reconnects. So every resumed
session burns one user-visible `ERR_CONNECTION_LOST` before recovering.

There is no NOOP/IDLE keepalive scheduler either, so any idle gap longer than
the server's inactivity timeout triggers this.

## Decision: bounded reconnect-and-retry, gated on op idempotency

The issue offers (a) one transparent reconnect-and-retry for idempotent read
ops on `ConnectionLost`, or (b) a NOOP staleness probe. **Chosen: (a).**

Rationale:
- (a) fixes the headline symptom directly — the *first* resumed read recovers,
  with no extra round trip on the healthy path (a probe costs a NOOP on every
  op or a clock read + branch on every op).
- A probe still races: the server can drop the session in the window between
  the NOOP reply and the real command. Retry-on-failure closes that window.

### Safety: only idempotent (read-only) ops auto-retry

Re-sending a *mutating* command after a mid-command disconnect risks
double-application: the server may have applied the first send before the
stream dropped (e.g. an `APPEND` that landed, a `MOVE`/`EXPUNGE` that
committed, a `STORE` that toggled a flag). A blind retry would double-send.

So retry is gated on a per-op **idempotency tag** passed into `with_session`:

- `Idempotency::ReadOnly` — `list_folders`, `list_folders_with_status`,
  `status`, `select`, `search`, `thread_related`, `fetch`, `fetch_body`
  (`fetch_body` uses `BODY.PEEK`, so it does not even mutate `\Seen`). These
  auto-retry once.
- `Idempotency::Mutating` — `store_flags`, `move_messages`, `append_message`,
  `delete_message`, `expunge`, `create_folder`, `rename_folder`,
  `delete_folder`. These **never** auto-retry; on `ConnectionLost` the session
  is still invalidated and the error is returned to the caller unchanged
  (pre-existing behavior).

### Bounds and trigger

- Retry fires **only** on `ImapError::ConnectionLost`, never on `Timeout`
  (the command may still be executing server-side) or `SizeLimit` (a
  deterministic rejection, not a transient disconnect).
- **Exactly one** retry. `with_session` attempts the body at most twice; a
  second `ConnectionLost` propagates to the caller. No storm.
- The session is invalidated after every transport-level failure
  (`ConnectionLost | SizeLimit | Timeout`) on both attempts, so a dead session
  is never reused — unchanged from today.

## Shape

`with_session` gains an `idempotency: Idempotency` parameter and its body
bound relaxes from `AsyncFnOnce` to `AsyncFn` (so the closure can run twice).
The retry orchestration is factored into a free async fn `with_reconnect`
driven by two pure predicates — `should_reconnect(idempotency, &result)` and
`is_transport_failure(&result)` — which are unit-tested directly (the double-
send safety gate), plus a `with_reconnect` test that drives fake attempt /
invalidate closures to prove: read+`ConnectionLost` retries once, mutating+
`ConnectionLost` does not, read+`Timeout`/`SizeLimit` does not, and the loop
is bounded to two attempts. No public API changes; `with_session` is
`pub(super)`.

## Out of scope

A NOOP/IDLE keepalive scheduler (option (b) as an *addition*) — deferred; the
retry alone satisfies the acceptance criteria without a background task.
