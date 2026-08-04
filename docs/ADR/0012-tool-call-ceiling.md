# ADR-0012: A tool call carries one explicit configurable ceiling; `command_timeout` stays the per-stage budget

**Status:** Accepted · 2026-08-03 · issue [#594](https://github.com/randomparity/rusty-imap-mcp/issues/594)

## Context

#592 split the IMAP timeout budgets so a lazy connect is bounded by
`imap.connect_timeout_seconds` and a command by `imap.command_timeout_seconds`,
instead of nesting the connect inside the command deadline. That split was
necessary: the nested form let the command deadline — which starts earlier, at
lock acquisition — cancel a stalled connect before `connect_inner` could emit
its `auth` audit record.

The consequence is that no single configured value bounds one tool call.
`rimap_imap::connection::dispatch::attempt` spends, worst case:

- up to `command_timeout` acquiring the session lock (a peer call on the same
  account holds it), plus
- up to `connect_timeout` on the lazy connect, which runs *outside* the command
  deadline by design, plus
- up to `command_timeout` on the command body.

`with_session` then runs `attempt` a **second** time for a read-only op that
fails with `ConnectionLost`, so the real worst case for one IMAP operation is

```
2 x (2 x command_timeout + connect_timeout)
```

which is 140s at the shipped defaults (30s / 10s), not the ~70s #594's body
estimates — the issue counts one attempt. That figure covers the
*deadline-bounded* stages; a few awaits on the same path carry no deadline of
their own (`with_session`'s `invalidate()` parks on the session lock,
`connect_inner`'s `emit_auth` runs an audit write outside the connect
deadline), so the wall clock can exceed it. Nothing above the IMAP layer imposed
a deadline: `rimap_server::mcp::dispatch` had no timeout at all, so a tool that
issues several IMAP operations (`list_folders_with_status`, `export_messages`)
multiplied that figure by its operation count with no bound in sight.

Nothing wedges — every stage has a deadline — but an operator reading
`command_timeout_seconds = 30` has no field that predicts the real ceiling, and
an MCP client's own request timeout fires long before the server gives up.

## Decision

- **Enforce a ceiling rather than document the additive behaviour.** #594
  option 2. Documentation alone leaves the operator computing a four-term
  product by hand, and leaves the server working on a call whose client has
  already abandoned it.

- **The ceiling is an explicit config key, `limits.tool_call_timeout_seconds`,
  not a value derived from the existing knobs.** A derived ceiling
  (`2 x (2 x command + connect)`, say) would be exactly as unpredictable as the
  sum it replaces — the operator still cannot read one field and know the
  answer, and any change to the retry policy would silently move a number
  nobody configured. An explicit key is the one field #594 asks for. It also
  admits the case a derived value cannot express: a ceiling deliberately larger
  than one IMAP operation, because a tool legitimately issues many.

- **Default 300 seconds.** It must exceed the validated minimum (140s at the
  `[imap]` defaults, 170s once a default `[smtp]` block is present) or a stock
  config would self-reject, and it should leave room for the multi-operation
  tools above. 300s is also comfortably
  beyond any interactive client's own request timeout, which is the point: the
  ceiling is a backstop against an unbounded server-side call, not a latency
  target. Operators who want a tighter bound lower it.

- **`command_timeout` keeps its current meaning — the per-stage budget.**
  Redefining it as the whole-call total was rejected: it is load-bearing for
  the stage separation #592 established, the chaos scenarios distinguish a
  connect-stage stall from a command-stage stall by setting the two budgets to
  different values, and silently changing what a shipped key means breaks every
  existing config file without a parse error.

- **Validate the relationship between the knobs at startup.** A ceiling below
  `2 x (2 x command_timeout + connect_timeout)` would preempt an IMAP
  operation that every per-stage deadline still considers healthy, converting a
  working call into `ERR_TIMEOUT`, so it is a config error naming both sides
  and the arithmetic. This is a per-account check: `[imap]`, `[smtp]` and
  `[limits]` all resolve per account, so `[defaults.limits]` inheritance is
  validated against each account's own budgets.

- **`smtp.command_timeout_seconds` is part of that minimum when `[smtp]` is
  configured.** `send_email` sends over SMTP and *then* appends the message to
  the Sent folder — a full IMAP operation. A ceiling that fits the append but
  not the send ahead of it could fire *after* delivery, returning `ERR_TIMEOUT`
  for a message that went out; an agent that retries on `ERR_TIMEOUT` would
  double-send. Requiring the ceiling to cover
  `smtp.command_timeout_seconds + 2 x (2 x command_timeout + connect_timeout)`
  puts that outcome out of reach for a send inside its own budgets. Excluding
  `send_email` from the ceiling instead was rejected: it would leave the two
  tools with irreversible side effects as the only unbounded ones.

- **The wire error is the existing `ERR_TIMEOUT`, not a new code.** #594 raises
  the question. A new code would be a new stable public contract for a
  condition an agent cannot act on differently: in both cases the operation
  exceeded its time budget and retrying is the same decision. The audit
  `tool_end` record carries `status: "error"` with `error_code: "ERR_TIMEOUT"`,
  and `rimap_error_to_breaker_reason` maps it to `FailureReason::Timeout`, so a
  ceiling that keeps firing opens the per-account circuit breaker like any
  other timeout.

- **The ceiling wraps the account-scoped dispatch body, inside the audit
  envelope, in `ImapMcpServer::dispatch_account_scoped`.** Two properties
  decide the placement:

  - It has to be *inside* `run_with_audit_envelope`'s body future, not around
    the envelope. `AuditEnvelopeGuard` synthesizes a cancellation `tool_end`
    (`ERR_CANCELLED`) when the envelope future is dropped. A `timeout` around
    the whole envelope would drop that future and mis-record an operator-set
    ceiling as a client cancellation. Timing out the body instead leaves the
    guard's own frame alive: the elapsed timeout becomes an ordinary
    `Err(RimapError::Timeout)` that the envelope disarms on and records as
    `ERR_TIMEOUT`, on the existing code path. There is a test asserting the
    audit record, not just the returned error.

  - It needs the `AccountState`, both for the configured value and for the
    poisoning below. `dispatch_account_scoped` is the layer that owns the
    whole account-scoped call — envelope, `DispatchTicket`, posture, breaker.

- **A fired ceiling poisons the account's IMAP connection.** Cutting the
  dispatch future mid-command drops the `MutexGuard` over
  `Mutex<Option<ImapSession>>` while the cached session still holds an unread
  server response. Reusing it would parse that reply as the *next* command's,
  desynchronizing the protocol with no error that `with_session`'s
  `is_transport_failure` would recognize — so it would never self-heal.

  `Connection::poison` sets an `AtomicBool` that `dispatch::attempt` consumes
  *under* the session lock, rather than calling `invalidate().await`. Awaiting
  the invalidate would be wrong twice over: it would push this call past the
  ceiling that just fired, and — the decisive one — `tokio::sync::Mutex` is
  FIFO-fair, so a peer command that queued on the lock while the cut command
  held it sits **ahead** of anything that starts waiting now and would take the
  poisoned session first. A flag is ordered ahead of every queued waiter
  because the waiter itself checks it. It is also synchronous, which is what
  makes the cancellation path in #620 fixable from a `Drop` impl.

- **Infrastructure tools (`list_accounts`, `use_account`) are not covered.**
  They resolve against in-memory state with no I/O and no account, so they have
  no configured ceiling and nothing for one to bound.

## Alternatives considered

- **Document only (#594 option 1).** Rejected by the issue owner. It is also
  the status quo: `docs/configuration.md` already described the additive sum,
  and had been wrong about it since #592 — it omitted the retry doubling
  entirely. That omission is fixed in the same change, but a document that
  states the worst case does not bound it.

- **Derive the ceiling from the existing knobs and log it at startup (#594
  option 3).** Rejected: it surfaces the number without enforcing it, so the
  MCP client's timeout still fires first, and it hard-codes the retry policy
  into a user-visible value.

- **A new error code (`ERR_DEADLINE_EXCEEDED`).** Rejected: see above. The
  distinction between "one stage overran" and "the whole call overran" is
  visible in the audit `duration_ms` and the server logs, where an operator
  looks, rather than in a code an agent would have to branch on.

- **Enforcing the ceiling inside `rimap-imap`.** Rejected: `with_session` sees
  one IMAP operation, not one tool call. A per-operation ceiling there is what
  `command_timeout` and `connect_timeout` already are.

- **A process-global key rather than a per-account one.** Rejected: the
  quantities it has to dominate (`command_timeout`, `connect_timeout`) are
  per-account, so a global key could not be validated against them without
  taking the maximum across accounts and rejecting configs no individual
  account would violate.

## Consequences

- One tool call against an account is bounded by `tool_call_timeout_seconds`,
  up to the untimed awaits noted in the context above. At the defaults that is
  300s against a previous worst case with no upper bound at all.

- **Raising `imap.command_timeout_seconds` past ~72s (at the default
  `connect_timeout_seconds = 10`) now requires raising
  `limits.tool_call_timeout_seconds` too.** The startup error states the
  computed minimum. This is the intended cost of making the relationship
  explicit: previously that config silently produced a call nobody had bounded.

- The chaos scenarios in `crates/rimap-server/tests/e2e_wire_chaos.rs` are
  unaffected and unchanged. They set `connect`/`command` to 1s–10s, so their
  worst case (6s and 24s) is far below the default ceiling, which therefore
  cannot preempt the stage each scenario is exercising — the property #594's
  third acceptance criterion asks for.

- A ceiling firing is breaker-visible (`FailureReason::Timeout`), so repeated
  ceiling hits on one account open its circuit breaker rather than each call
  paying the full 300s.

- The ceiling does not cover a client-initiated cancellation, which continues
  to drop the envelope future and record `ERR_CANCELLED` through
  `AuditEnvelopeGuard`. That path has the same mid-command session-poisoning
  hazard the poison flag closes for the ceiling; it predates this change and is
  tracked in [#620](https://github.com/randomparity/rusty-imap-mcp/issues/620).

- **A ceiling that fires during a lazy connect drops that connect's `auth`
  audit record.** `connect_inner` emits it after `connect_with_bundle`
  returns, and warns that a caller wrapping it in a shorter deadline than
  `connect_timeout` loses the record — which is what the ceiling can do. This is
  the loss #592 fixed for the `command_timeout`/`connect_timeout` nesting,
  reappearing one layer up with a far larger budget, so reaching it means the
  connect was already pathological. The `tool_end` record still lands with
  `ERR_TIMEOUT`; only the connection attempt goes unrecorded. Tracked in
  [#623](https://github.com/randomparity/rusty-imap-mcp/issues/623).

- A ceiling that fires during `download_attachment` or `export_messages` can
  leave an artifact on disk that no audit record accounts for: the sandbox
  write runs in `spawn_blocking`, and dropping the awaiting future does not
  cancel the blocking closure, while the failed call records the default
  `ResultSummary`. The window is narrow — the fetch dominates, not the write —
  but it is a new cut point on the #316 provenance guarantee.
