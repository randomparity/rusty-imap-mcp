# Pin export_messages peak memory with a read-level streaming limit (#318)

## Context

`export_messages` worst-case heap today is ~`2·max_total_bytes +
max_fetch_body_bytes`:

- `fetch_bodies` collects every successful body into `outcomes`
  (`Vec<FetchOutcome>`), then `plan_outcome` moves them into `bodies`
  (`Vec<Vec<u8>>`) — one `max_total_bytes` (S) worth of raw bodies;
- `build_mbox(&bodies)` allocates a **separate** framed copy `mbox` (≈ S)
  while `bodies` is still alive (it stays in scope through the
  `write_attachment_async` call) — the second S;
- during the fetch loop, one in-flight body up to `max_fetch_body_bytes` (B)
  accumulates before the running-byte check trips.

The gate accepted this as bounded (`max_total_bytes` is hard-clamped to the
100 MiB ceiling; the running-sum check counts *actual* transferred bytes; the
framed-size re-check is authoritative before any write) but filed this to pin
the peak to ≈ `max_total_bytes`.

## Goal / acceptance (from #318)

- Pin peak heap to approximately `max_total_bytes`.
- Preserve the existing fail-closed running-byte and framed-size checks.

## Design

Two reinforcing changes, each small and behavior-preserving on the happy path:

### A. `build_mbox` consumes its input (removes the second S)

Change `build_mbox(messages: &[Vec<u8>]) -> Vec<u8>` to
`build_mbox(messages: Vec<Vec<u8>>) -> Vec<u8>`, draining each body as it is
framed (`for msg in messages { ...frame...; drop(msg) }`). At the call site
`let mbox = build_mbox(bodies);` moves `bodies` in, so the raw bodies are
freed as the framed buffer grows — peak during framing ≈ S (bytes transfer
from `bodies` to `mbox`), and `bodies` no longer lingers (holding a second S)
through the write. Output bytes are identical, so all `build_mbox` assertions
stand; only the call form changes.

### B. Per-body read limit = `min(per_msg_cap, budget − running)`

`fetch_bodies` currently fetches each body up to `per_msg_cap`
(`max_fetch_body_bytes`) and only afterwards checks `running > budget`. Pass a
per-call read limit of `min(per_msg_cap, budget.saturating_sub(running))` so
the in-flight body cannot exceed the remaining budget. Then
`outcomes (≈ running raw) + in-flight (≤ budget − running) ≤ budget`, pinning
the fetch-phase peak to ≈ S.

Plumbing (additive, no existing caller touched):

- `Imap::fetch_body_with_limit(folder, uid, expected, limit)` — the current
  `fetch_body` body, parameterized on `limit`; `fetch_body` becomes a
  one-line delegate passing `self.inner.cfg.max_fetch_body_bytes` (so
  `fetch_message` / `download_attachment` / `message_builder` are unchanged).
- `ExportSource::fetch_one_body` gains a `body_limit: u64` parameter; the
  `AccountState` impl forwards it to `fetch_body_with_limit`.
- `fetch_bodies` computes `body_limit` per UID from the live `running` total.

### Interaction with the existing checks (preserved)

- **Preflight `eligible_sum`** (sum of *reported* sizes) still rejects a
  legitimately over-budget request with `InvalidInput "export exceeds
  max_total_bytes"` **before any body fetch** — so a user who simply set a
  small `max_total_bytes` is rejected cleanly at preflight, not via the read
  limit.
- **Running-byte check** (`running > budget`) is kept verbatim. Be honest:
  with the read limit in place it is **unreachable by construction** — every
  accepted body satisfies `body.len() ≤ budget − running`, so `running` can
  never exceed `budget` (and when `running == budget` the limit is `0`, so a
  non-empty body trips `SizeLimit` first). It is retained only as a cheap
  fail-closed backstop guarding future changes to the limit computation, not
  as a live guard. (It is *already* untested today — every test uses the
  100 MiB max budget — so change B removes no existing coverage.) A surviving
  mutation that deletes it is expected and acceptable.
- **Framed-size re-check** (`total_bytes > budget`) on the assembled mbox is
  unchanged and remains authoritative before the write. Note the peak buffer
  is this *framed* mbox: ≈ raw `budget` plus bounded framing overhead
  (separators + `From `-escaping, ≤ ~5 KB for 100 messages), not exactly
  `max_total_bytes`.

### Behavior change (adversarial path only)

When a hostile server under-reports/omits `RFC822.SIZE` (the STRIDE-D threat
this issue targets), a body that would push past the remaining budget now
aborts mid-read with `ImapError::SizeLimit` (fatal; the dispatch layer drops
the half-consumed session) instead of being fully buffered and then rejected
by the running-byte check. This bounds memory for the exact attack and only
affects the adversarial case — the legitimate over-budget request is already
caught at preflight. Documented, not hidden.

## Execution tasks (TDD)

1. `build_mbox` → by-value `Vec<Vec<u8>>`, drain while framing; update its
   unit tests' call form (assertions unchanged). Update the `run_export` call
   site so `bodies` is moved (freed before the write).
2. `fetch_body_with_limit` in `rimap-imap` dispatch; `fetch_body` delegates.
   No new behavior for existing callers (same limit value).
3. `ExportSource::fetch_one_body` + `body_limit`; thread `min(per_msg_cap,
   budget − running)` from `fetch_bodies`; update the 3 fake sources.
4. Test: a fake source whose body exceeds the remaining budget makes the
   in-flight read abort (peak bounded) — assert the call fails closed and no
   artifact is written; keep the happy-path tests green (large budget ⇒ limit
   == per_msg_cap, unchanged).
5. Verify: `clippy -D warnings`, `fmt`, targeted `rimap-server` +
   `rimap-imap` tests, `cargo deny`.

## Out of scope

- Framing each body directly into the mbox *during* the fetch loop (removing
  the `outcomes`/`bodies` intermediate entirely) would also work but discards
  the pure, unit-tested `fetch_bodies` / `plan_outcome` / `build_mbox`
  separation for a marginal gain; the read limit already caps the
  intermediate to ≤ budget.
