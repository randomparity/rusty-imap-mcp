# ADR-0022: Write-deadline watchdog is the primary control for a slow or non-local `audit.path`

**Status:** Accepted · 2026-08-07 · issue [#720](https://github.com/randomparity/rusty-imap-mcp/issues/720)

## Context

[ADR-0014](0014-synchronous-auth-audit-emission.md) records the decision to write every
`auth` audit record synchronously, on the runtime worker that produced it, with no
`spawn_blocking` hop. The decision was correct for reliability — deferring to the
blocking pool lost records on shutdown — but it carries one cost that the same ADR names
explicitly:

> An `audit.path` that stops responding — a hung NFS or SMB mount — pins the worker for
> the life of the process, and `dispatch::attempt` still holds the account's session lock,
> so a peer queued on that account waits forever. With every worker so pinned the time
> driver stops advancing too, so no `tokio::time` deadline fires — `command_timeout` and
> the ADR-0012 ceiling included — and the server stops answering its MCP client at all.

The affected write path is in `crates/rimap-audit/src/writer/emit.rs`:
`write_record_inner` takes the `std::sync::Mutex` guard, serialises the record, calls
`write_all`, `flush`, and (for `auth` records) `sync_data` — all inside a single
critical section. No `Duration` or deadline exists anywhere on that path today.

The write reaches async code via `crates/rimap-imap/src/connection/login.rs:emit_auth`,
called directly (without `.await`) from `connect_inner` and from the `Drop` of
`AuthEmitGuard`. It also reaches async code through
`crates/rimap-imap/src/connection/mod.rs:463` (the cut-connect `Drop`).

`audit.path` validation at startup (`crates/rimap-config/src/validate/paths.rs`) checks
existence, directory membership, and writability. It performs no filesystem-type
inspection; `rg 'statfs|getmntinfo|f_type|fstypename|nfs|smbfs|cifs'` over `crates/` hits
no config-layer code.

Two candidate controls were evaluated.

## Decision

**Choose Option A: write-deadline watchdog.** Reject Option B (filesystem-type detection)
as the primary control.

**Option A** detects the actual symptom — an audit write exceeding a caller-configured
deadline — rather than a proxy for it. `crates/rimap-audit` owns the guard: a helper
(e.g. `src/writer/deadline.rs`) that wraps `write_record_inner` with a
`std::time::Instant`-based timeout on a dedicated thread, or an equivalent mechanism
that does not require holding the audit mutex across an `.await`. The helper returns an
`AuditError` variant when the deadline fires, and the caller propagates that error up
through the existing `AuditError` return type — consistent with what
`write_record_inner` already returns on all other failures.

On failure the caller follows the existing rule in `AGENTS.md` and the audit security
model: audit failures surface as `ERR_INTERNAL` tool errors by default (`fail_open =
false`). When the operator has explicitly set `fail_open = true`, the failure is logged
via `tracing::error!` and suppressed, exactly as any other write error is today.
**No new escape-hatch config key is introduced**: the existing `fail_open` knob covers
the degrade-vs-fail axis, and AGENTS.md forbids config fields that nothing uses.

Option A requires **no new direct dependency** in `crates/rimap-audit`. The relevant
primitives (`std::thread`, `std::sync`, `std::time::Instant`) are already available.

**Option B** is rejected as not sound for use as the primary control:

- **Bind mounts and FUSE defeat it.** A path exported via `mount --bind` (Linux) or
  `bindfs` presents as the bind's filesystem type, not the source's. An NFS subtree
  bind-mounted locally has no kernel-visible indicator that it is network-backed.
  FUSE filesystems report their own driver names, which have no universal convention
  for "local vs remote". Option B therefore false-negatives on the exact failure mode
  it is meant to prevent.
- **It can false-positive.** Exotic but legitimate local filesystems (e.g. `overlayfs`,
  `tmpfs`, some FUSE-backed configs) would be flagged as unsafe when they are not.
- **It requires a new direct dependency.** `libc` or `nix` is not a direct dependency of
  `crates/rimap-audit` today. AGENTS.md gates new runtime dependencies behind explicit
  scope approval, which is absent here.
- **It is a proxy, not the property.** What matters is whether the write returns in
  finite time. Filesystem type is correlated with that but does not determine it; a
  local filesystem under heavy I/O pressure can stall indefinitely, and a well-tuned
  network mount with aggressive timeout and retransmit settings may not.

**Option B may be added later as a defense-in-depth hint** — warn-only at startup when
the filesystem type is identifiably non-local on platforms where the check is cheap and
reliable (e.g. Linux `statfs(2)` with an explicit allowlist of `f_type` values). It
must not be the primary gate, and it must not refuse startup: it is an advisory whose
false-negative rate is non-trivial. That addition requires a separate ADR and explicit
scope approval for the dependency it introduces; it is not part of this decision.

## Consequences

- `crates/rimap-audit` adds a write-deadline mechanism. The timeout value is
  operator-configurable (a new field in `AuditOptions`, exposed through the existing
  `[audit]` config section) with a documented default. An unconfigured default of
  something in the range of 5–30 seconds catches a completely hung mount while not
  triggering on a momentarily slow but healthy local disk.
- On deadline fire, `write_record_inner` returns `AuditError` and the caller proceeds
  exactly as it does today for any write failure: `ERR_INTERNAL` under `fail_open =
  false`, suppressed under `fail_open = true`. The runtime worker is unblocked; the
  session lock is released; the server continues serving other requests.
- `docs/audit-log.md`'s statement "nothing checks the path's locality at startup; it is
  an operator requirement" remains accurate as a description of the *startup* check —
  this ADR replaces the runtime exposure, not the startup warning.
- The write-path call sites (`emit_auth`, `write_record`) already return `Result`; no
  public API signature changes.
- The mechanism that Option A uses must not hold the `std::sync::Mutex` across a park.
  ADR-0014's rule that the mutex is never held across an `.await` still applies; a
  timeout implementation that threads the deadline through without sleeping under the
  lock satisfies it.
- Implementation is tracked in [#668](https://github.com/randomparity/rusty-imap-mcp/issues/668).

## Alternatives considered

**Option B (filesystem-type detection at config validation)** — addressed in full under
Decision above. The short form: it is defeated by bind mounts and FUSE, so it
false-negatives on the exact scenario it targets; it adds a platform-conditional
dependency without explicit scope approval; and it is a proxy for the property we care
about rather than the property itself. It may be worth adding as a warn-only hint later,
but it is not a substitute for a write-deadline control.

**Accept the exposure with a docs-only operator warning** — the pre-#720 status quo.
`docs/audit-log.md` already states the requirement; this ADR establishes the point where
stating a requirement is not sufficient and a runtime guard is warranted. The failure mode
— a permanently hung runtime with no client-visible error — is severe enough that a doc
note to the operator is not an adequate sole control.

**`spawn_blocking` with a short timeout** — reverts the decision in ADR-0014. Rejected:
ADR-0014 removed `spawn_blocking` specifically because it lost records on shutdown;
re-introducing it re-opens that window. A deadline wrapper inside
`crates/rimap-audit` achieves the same liveness goal without re-introducing the
durability loss.
