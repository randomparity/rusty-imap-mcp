# ADR-0021: The enforced folder policy is its own record kind, written after the registry is built

**Status:** Accepted · 2026-08-06 · issue [#761](https://github.com/randomparity/rusty-imap-mcp/issues/761)

## Context

`protected_folders` is not the list the operator configured. At boot each
account runs `LIST "" "*"`, and any RFC 6154 special-use folder the server
declares — `[Gmail]/Sent Mail` and friends — is appended to the configured
list by `boot::discovery::merge_protected_folders`. The union is what
`FolderGuard::new` is handed, and so it, not the configured list, is what
`check_protected` enforces on every `delete_folder`, `rename_folder`, and
`expunge`.

#696 put each account's resolved folder lists on the `process_start` record,
tagged `account` / `inherited` / `discovered`. Four of its five acceptance
criteria were met. The fifth — "the recorded value should be the one the
`FolderGuard` was actually built from" — could not be, and the reason is
structural rather than an oversight.

`process_start` is written by `boot::audit_init::init_audit_writer_multi`,
called from `run_server` before the tokio runtime exists. Special-use
discovery cannot run there: it needs a live IMAP session, and the first one is
opened by `build_registry`, several steps later. So the record carries the
*configured* policy and states `special_use_discovery: not_run` to say so
honestly. **No `process_start` record can ever contain a `discovered` entry.**

#696 considered moving `process_start` after IMAP boot and rejected it. That
rejection stands and this ADR does not revisit it: an account that fails to
connect would then leave no `process_start` at all, losing the property #632
added specifically so a failed account still leaves its effective matrix on
the record. That is the wrong trade on precisely the boots most worth
auditing.

The complete union therefore surfaced in exactly one place — the
`effective folder policy` `tracing::info!` line emitted after the guard is
built. Greppable, and gone when the process is. An operator reconstructing
what a past process enforced could not, and the audit log is the artifact that
question is supposed to be asked of.

## Decision

Add a **new audit record kind, `folder_policy`**, emitted once per account
immediately after that account's `FolderGuard` is constructed, carrying the
folder lists the guard was built from.

```json
{"seq":4,"ts":"...","process_id":"...","kind":"folder_policy",
 "account":"work",
 "protected_folders":[{"folder":"INBOX","source":"inherited"},
                      {"folder":"[Gmail]/Sent Mail","source":"discovered"}],
 "special_use_discovery":"ran",
 "expunge_folders":[{"folder":"Trash","source":"inherited"}]}
```

Five decisions are bundled here, each of which a future reader would otherwise
have to re-derive.

**1. A new kind, not a field on `process_start`.** The two records answer
different questions at different times and cannot be merged without losing
one: `process_start` is "what this process was configured with, for every
account, including the ones that never came up", and `folder_policy` is "what
this account's guard actually enforces". Their timings are what make them
different, so collapsing them means choosing which property to drop.

**2. One record per account, not one covering all accounts.** The boot loop is
already per-account, `Filter::account` already indexes on `account`, and it
makes the partial-failure question below fall out of the code rather than
needing a rule of its own.

**3. It is emitted on partial boot failure, for every account that got that
far.** `build_registry` iterates accounts and `?`-propagates a `list_folders`
failure, so an account whose guard was built has its record and the failing
account — and every account after it — has none. This is not a special case
added for the failure path; it is what per-account emission at the point of
guard construction means. The asymmetry with `process_start` is deliberate and
is the whole point of keeping both: `process_start` covers every configured
account whether or not it connected, `folder_policy` covers exactly the
accounts something is being enforced for. A reader that finds a `process_start`
naming three accounts and only two `folder_policy` records has learned which
account failed to boot.

**4. `--dry-run` gains nothing, and gets nothing.** This confirms #761's own
view rather than overturning it. A dry run opens no IMAP session, so the only
thing it could print is the configured list a second time, under a heading
implying it is the enforced one. That is precisely the misread `special_use_
discovery: not_run` was introduced to prevent, and adding a surface that
invites it would undo #696's work. `--dry-run` keeps its two #696 sections,
which say what they are.

**5. The payload keeps `special_use_discovery` even though it can only say
`ran`.** This is the arguable one. A field with one possible value looks like
redundancy, and "no speculative features" argues for dropping it.

It stays because it is not a constant of the *type*, it is a constant of
*correct wiring*, and that makes it the on-disk detector for the single defect
this record exists to prevent. The lists are derived from
`boot::tool_matrix::account_tool_matrix(acfg, resolved_protected)`, whose
`Option` argument is what distinguishes "discovery ran, this is the guard's
list" from "discovery has not run, this is the configured list". A producer
that passed `None` — the mistake `process_start` is *required* to make —
would write a `folder_policy` record carrying the configured list while
looking exactly like one carrying the enforced union. With the field, that
same miswiring writes `"special_use_discovery":"not_run"` on a `folder_policy`
line, which is visibly wrong, greppable, and assertable in a test. Without it,
it is invisible. A field that cannot be miswired without saying so is worth
its 30 bytes per account per boot.

It also keeps the payload shape-compatible with a `process_start`
`tool_matrix` entry's folder half, so the two are directly diffable — which is
the comparison an operator asking "did discovery widen my protection?" wants
to make.

`posture` and `tools` are **not** carried. They are unchanged between the two
emission points and `process_start` already has them; repeating them per
account per boot would be bulk, not evidence.

## Consequences

**On disk, this is additive, and it leans on unknown-`kind` tolerance rather
than unknown-*field* tolerance.** These are different mechanisms and the
distinction matters: #696 was additive because `#[serde(default)]` lets an old
reader parse a line carrying a field it does not know. That does nothing here —
an old reader meeting `"kind":"folder_policy"` has no variant to deserialize
into. What saves it is #717's skip: `stream_records` drops a line whose `kind`
is absent from `KNOWN_KINDS`, warns on stderr, and counts it in
`StreamSummary::skipped_unknown_kind`.

**That tolerance has not shipped yet, and the distinction is load-bearing.**
#717 is unreleased — `v0.1.0` is the only tag, and its
`crates/rimap-audit/src/reader/mod.rs` has no `unknown_kind`, no
`KNOWN_KINDS`, and no `skipped_unknown_kind`. So a `v0.1.0` binary reading a
file this change wrote **aborts with a parse error naming the line**, which is
exactly the corruption behavior the tolerance exists to avoid. The guarantee
is therefore: readers at or after the release carrying #717 skip these records;
`v0.1.0` does not. Both #717 and this change land in the same unreleased
`0.2.0` cycle, so no released reader ever has to skip a kind it does not know —
but a mixed deployment against a `v0.1.0` binary is a real and unhandled case
until that release exists.

The cost, once the tolerance has shipped, is the one `docs/audit-log.md`
documents for that path: **`rimap audit merge` run by an older binary silently
omits these records from its output**, and the count on stderr is the only
trace. That is worse than the field case, where the data survives the merge. It
is the price of a new kind and it is why a new kind is reserved for things that
genuinely cannot be a field.

**The audit write here is a blocking, fsynced write issued from an `async fn`,
which is a third exception to the rule in
`docs/architecture/audit-locking.md`.** That document says async callers reach
the writer through `DispatchDrain::spawn_blocking_tracked` and names exactly
two exceptions (`Connection::emit_auth` under ADR-0014, and the cancellation
drainer). This is the third, and it is justified by *when* it runs rather than
by what it does: `resolve_folder_policy` is awaited from `build_registry`,
which completes before `spawn_drainer` and before `rmcp::serve_server`, so the
drain it would register with does not exist yet and a bare `spawn_blocking`
is what that document itself calls a bug. Boot is single-task at this point, so
the write stalls nothing. **This justification is about boot's serial
structure, not about the write being cheap** — a change that parallelizes
account boot (`join_all` over accounts is the obvious one) invalidates it and
must revisit this call site. The exception list in `audit-locking.md` carries
the same note.

**Nothing about `process_start` changes** — not its timing, not its fields, not
its `special_use_discovery: not_run`. An account that fails to connect still
leaves its full matrix on the record. #632's property is untouched.

**The "only place this appears" claim in `docs/audit-log.md` and in
`boot::tool_matrix::log_account_folder_policy`'s docs stops being true**, and
both are corrected in the same change. The log line stays: it is the live
operator's view, and a `tracing` line and an audit record are read by different
people at different times.

**The emission point moves into the library.** `build_registry` lives in
`main.rs`, a binary target no integration test can link against, so the
LIST → merge → `FolderGuard::new` → emit sequence is factored into
`boot::discovery::resolve_folder_policy`. `main.rs` keeps a single call. This
is what lets a test drive a fake server advertising a special-use folder and
assert the emitted record carries it as `discovered` — the acceptance criterion
that could not be tested while the wiring lived in a binary.

**`KNOWN_KINDS` grows to 7**, `kind_of` gains an arm, `needs_fsync` treats
`folder_policy` as a boot/lifecycle kind (fsynced, like `process_start` —
it is written once per account at boot, not per tool call, so the cost is
bounded and the record is one you want on disk before the process can fail),
and `Filter`'s `account` arm returns the record's account so
`audit merge --account work` includes it.

## Alternatives considered

**Add `discovered` entries to `process_start` by moving it later.** Rejected by
#696 and re-rejected here; see Context. It trades a complete audit trail for
one field.

**Emit a second `process_start`.** Two records of one kind per process breaks
"first record of every process invocation", which the startup self-check and
every reader rely on, and would make `previous_process_id` chaining ambiguous.

**Widen the `effective folder policy` log line and call it sufficient.** It is
already as wide as it can be. The gap is that `tracing` output is not the audit
trail: it is not append-only, not fsynced, not covered by the compatibility
contract, and not what `rimap audit merge` reads.

**Put the folder lists on the `auth` record**, which is per-account and already
post-session. Rejected: `auth` is emitted per *connect*, including reconnects,
so the policy would be repeated on every reconnection while being a property of
boot; and it would couple an authentication record to an authorization concern.

**Put them on `process_end`** — the only *existing* kind written after the
guards are built, and therefore the only option that would have been
field-additive rather than kind-additive. That matters, because the consequence
above sets a bar this decision has to clear: a field parses on an old reader
and survives a merge, a new kind does neither. Rejected anyway, and decisively:
`process_end` is best-effort. A hard crash leaves none, which means the runs
that most need an enforcement record are exactly the runs that would have no
enforcement record. Hanging a durable authorization statement off a
best-effort one inverts its reliability. It would also arrive at shutdown,
hours after the policy took effect, and would have to carry an array over
accounts — reintroducing the "which account failed to boot" ambiguity that
per-account emission resolves for free.
