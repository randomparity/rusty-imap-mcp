# Network chaos e2e layer — latency, resets, byte-trickle — design

**Status:** Draft 2026-07-09 · issue #522
**Scope:** Add a nightly-only e2e suite that interposes Toxiproxy between the
`rusty-imap-mcp` binary and the Dovecot fixture to exercise *degraded-but-alive*
network conditions (slow greeting, mid-FETCH stall, RST during STARTTLS,
byte-trickle of a large body) through the real MCP tool-dispatch wire. Asserts
the typed `ERR_*` code on the wire, the audit record, and that a subsequent call
recovers with no wedged session or circuit breaker.

## Problem

Fault injection today is binary. `e2e_wire_fault_injection.rs` proves three
*protocol/dead-server* faults — oversize fetch (`ERR_ATTACHMENT_TOO_LARGE`),
stale UIDVALIDITY (`ERR_UID_VALIDITY_CHANGED`), and a fully stopped container
(`ERR_CONNECTION_LOST`). Nothing exercises a network that is *alive but
degraded*: a server that accepts the TCP connection but stalls the greeting,
latency that spikes mid-FETCH, a reset landing during the STARTTLS handshake, or
a large body delivered a byte at a time.

These are exactly the conditions that determine whether the timeout taxonomy
(`connect_timeout` vs `command_timeout` → `ERR_TIMEOUT`), the idle-reconnect
retry (`211f629f`, #450), the session-invalidation-then-lazy-reconnect contract,
and the circuit-breaker accounting behave correctly or wedge — and none are
covered. The gap is a test-harness dimension, not a production-code gap: the
grounding survey (below) confirms the machinery each scenario asserts already
exists.

## Acceptance criteria (from the issue)

- [ ] Greeting delayed past `connect_timeout` → typed timeout (`ERR_TIMEOUT`).
- [ ] Mid-FETCH latency spike → operation timeout (`ERR_TIMEOUT`), session
  invalidated, next call recovers.
- [ ] Connection reset during STARTTLS → typed TLS/connection error, exactly one
  `AuthEvent`.
- [ ] Byte-trickle a large body → time bound honored, no unbounded buffering.
- [ ] Each scenario asserts the typed error code **on the wire**, the **audit
  record**, and that a **subsequent call succeeds** (no wedged session/breaker).
- [ ] Nightly job, not PR CI (wall-time).

## Grounding survey — reality the assertions bind to

Established by reading the current tree; every assertion below cites live
behavior, not wished behavior.

- **Timeout taxonomy.** `connect_timeout` (default 10s) spans TCP+TLS+greeting+
  login as one budget (`connection/handshake.rs`); `command_timeout` (default
  30s) wraps every op (`connection/dispatch.rs`, `time.rs`). Elapsing either →
  `ImapError::Timeout { op }` → `ErrorCode::Timeout` → **`ERR_TIMEOUT`**. The
  suite lowers both budgets in config to keep wall-time bounded.
- **Session invalidation + recovery.** A mid-op timeout is a *transport failure*
  (`is_transport_failure` includes `Timeout`) → `invalidate()` drops the cached
  session (`connection/mod.rs`). The session is a lazy `Mutex<Option<..>>`; the
  *next* call reconnects via `connect_inner()`. A `Timeout` is **not** in-call
  retried (`should_reconnect` excludes it) — recovery is on the subsequent call,
  exactly what the issue asks to assert.
- **STARTTLS reset is a code *set*, not a single code.** A RST during the
  plaintext greeting → `ERR_CONNECTION_LOST`; a RST once TLS bytes flow →
  `ERR_TLS`. Toxiproxy operates at TCP and cannot pin the plaintext→TLS boundary,
  so the scenario asserts `code ∈ {ERR_TLS, ERR_CONNECTION_LOST}` plus
  **exactly one `AuthEvent`** (`connect_inner` emits exactly one auth event per
  attempt, success or failure). This matches the issue's own wording, "typed
  TLS/connection error."
- **Byte-trickle: two distinct bounds, two falsifiable sub-cases.** The AC pairs
  *"no unbounded buffering"* (a **size/memory** bound) with *"time bound
  honored"* — different properties needing different observables. `fetch_body`
  pre-checks `RFC822.SIZE` and rejects over-cap bodies *before* reading a body
  byte (honest Dovecot reports true size), which is the actual no-unbounded-
  buffering guard. Scenario 4 therefore has two sub-cases (see §Component 4):
  - **4a — buffering bound.** Seed a body **over** `max_fetch_body_bytes`, apply
    a slow `bandwidth` toxic, fetch → assert **`ERR_ATTACHMENT_TOO_LARGE`**
    returns *promptly* (well inside `command_timeout`). This is falsifiable
    against a buffering regression: if `fetch_body` regressed to read the body
    before checking size, the bandwidth toxic would make it stall to
    `command_timeout` and surface `ERR_TIMEOUT` instead — the sub-case would
    fail. The prompt `ERR_ATTACHMENT_TOO_LARGE` *under an active trickle* is
    exactly the evidence that no body bytes were buffered.
  - **4b — time bound.** Raise `max_fetch_body_bytes` above the body, seed a body
    the `bandwidth` toxic cannot deliver inside `command_timeout`, fetch →
    assert **`ERR_TIMEOUT`**, session invalidated, next call (toxic removed)
    recovers. This is falsifiable against an unbounded-wait regression.
- **Breaker neutrality.** `ERR_ATTACHMENT_TOO_LARGE` is breaker-neutral; a single
  `Timeout` counts toward the breaker but the trip threshold is 5 within 30s, so
  one timeout per scenario never trips it. The "subsequent call succeeds"
  assertion therefore is not masked by `ERR_CIRCUIT_OPEN`. Each test uses a fresh
  server process (fresh breaker) so cross-test accumulation is impossible.

## Non-goals

- No production-code changes. This is test coverage. If a scenario surfaces a
  genuine defect (a wedge the survey says should not happen), the fix is scoped
  to a follow-up issue per the `AGENTS.md` deferral convention — unless the fix
  is a one-liner clearly within this branch's blast radius, in which case it
  lands here with its own commit and a regression test.
- No new runtime or dev dependency. The control plane reuses `ureq` (already a
  workspace dev-dep, used by `e2e_smtp_real.rs`).
- No change to the PR-blocking compose fixture (`docker-compose.yml`) or the
  existing `DovecotHarness`. The chaos layer is additive.
- No Toxiproxy on the PR path. Wall-time is the reason the issue mandates nightly.
- Not a general chaos framework. Four scenarios, one binary; the corpus grows by
  adding scenarios, not by building a DSL.

## Design

### Component 1 — chaos compose fixture

A new `crates/rimap-imap/tests/integration/dovecot/docker-compose.chaos.yml`
defines **two** services on one compose network:

- `dovecot` — identical to the existing service (same image pin, same
  `dovecot.conf` / `entrypoint.sh` / `users` / `fixtures` mounts, same `shared`
  volume for the fingerprint hand-off). Its 993/143 are **not** host-published;
  Toxiproxy reaches it in-network as `dovecot:993` / `dovecot:143`.
- `toxiproxy` — pinned `ghcr.io/shopify/toxiproxy:<sha>` (exact tag+digest
  resolved at build time). Starts with a seed config mounting two proxies on
  *fixed container-internal* ports so Docker can publish them:
  - `imaps`   : listen `0.0.0.0:21993` → upstream `dovecot:993`
  - `starttls`: listen `0.0.0.0:21143` → upstream `dovecot:143`
  - control API: `0.0.0.0:8474`
  Published to three harness-reserved host ports
  (`RIMAP_TOXI_IMAPS_PORT`, `RIMAP_TOXI_STARTTLS_PORT`, `RIMAP_TOXI_CTRL_PORT`).

Toxiproxy is pure TCP passthrough, so the TLS session is end-to-end
server↔Dovecot and the **pinned Dovecot fingerprint still matches** — the suite
exercises pinning, it does not disable it.

Keeping this in a separate compose file (not a second service in the shared
`docker-compose.yml`, not a compose `profile`) means the PR-blocking e2e path
never starts Toxiproxy and its startup/teardown code never runs on PR CI.

### Component 2 — `ChaosHarness` (rimap-server test support)

New `crates/rimap-server/tests/support/chaos/mod.rs` + `harness.rs`, sibling to
`support/dovecot/`. Reuses the existing patterns (raw `docker/podman compose`
CLI, `ReservedPort`, `uuid_like` project name, fingerprint read from
`/shared/fingerprint.hex`, `RIMAP_CONTAINER_TOOL` autodetect, Drop → `compose
down -v`). Additions over `DovecotHarness`:

- Reserves **three** host ports and injects them into compose env.
- Brings up with `-f docker-compose.chaos.yml`; readiness = Dovecot fingerprint
  present **and** a `GET /version` on the Toxiproxy control API returns 200.
- `imaps_port()` / `starttls_port()` → host ports the server config points at.
- A small `ToxiproxyControl` client over `ureq`: `add_toxic(proxy, spec)`,
  `remove_toxic(proxy, name)`, `reset()` (clears all toxics). Toxic specs are
  built with `serde_json::json!` and POSTed to
  `/proxies/<name>/toxics`; removal is `DELETE /proxies/<name>/toxics/<toxic>`.
  **Every call checks the HTTP status and panics on non-2xx with a diagnostic
  that names the *control plane* as the cause** (e.g. `"toxiproxy control:
  add_toxic latency on 'imaps' failed: HTTP 500 …"`). This keeps a control-plane
  flake from masquerading as a product recovery-wedge: a failed `remove_toxic`/
  `reset()` aborts the test *before* the recovery assertion runs, attributed to
  the harness, not to `rusty-imap-mcp`.

### Component 3 — two-tier gate `RIMAP_CHAOS`

`ChaosHarness::try_start` gate order:

1. `RIMAP_CHAOS` unset → `Err(ChaosSkip::Disabled)` → test `return`s. **This is
   checked first**, so the suite skips even when Docker is present and even under
   `RIMAP_REQUIRE_DOCKER=1`. That is what keeps it off PR CI: the existing
   `binary(/e2e/)` nextest filter selects `e2e_wire_chaos`, but every test
   early-returns because PR CI never sets `RIMAP_CHAOS`.
2. `RIMAP_CHAOS=1` and no container runtime:
   - `RIMAP_REQUIRE_DOCKER=1` → panic (loud, nightly).
   - else → `Err(ChaosSkip::DockerUnavailable)` → `return` (local dev without
     Docker).
3. `RIMAP_CHAOS=1` and runtime present → bring the stack up.

The nightly workflow sets `RIMAP_CHAOS=1` **and** `RIMAP_REQUIRE_DOCKER=1`.

### Component 4 — `e2e_wire_chaos.rs` scenarios

One binary, `#[tokio::test(flavor = "multi_thread")]` per scenario. All start the
chaos stack, **seed while no toxic is active**, and spawn the server with a chaos
config (low `connect_timeout`/`command_timeout`, e.g. 2s each). Then the ordering
depends on *what stage the fault must hit* — the server's IMAP session is lazy and
its connect runs **inside** the command-timeout guard on the first tool call, so
*when* the toxic is added decides whether it hits connect or an operation:

- **Connect-targeting scenarios (1, 3).** The fault *is* a connect-handshake
  fault. Add the toxic **before** the first server tool call, so the lazy connect
  traverses it. Assert the `ERR_*` and the failing `auth` record.
- **Operation-targeting scenarios (2, 4).** The fault must hit an operation on an
  *already-established* session. Drive **one successful tool call first with no
  toxic** (`use_account` + a `search`/`list_folders`) to force the lazy connect
  and cache the session; assert that warm-up's `tool_end` is success. **Only then**
  add the toxic and drive the operation that must stall. This is load-bearing: if
  the toxic were added before the session exists, the connect would time out, the
  subsequent `invalidate()` would be a no-op on an already-`None` session, and
  "recovery" would be a first-ever connect — AC#2's *established-session
  invalidation → lazy reconnect* contract would pass vacuously. The audit
  assertion for scenario 2/4 therefore requires **a preceding successful
  `tool_end` then a failing `tool_end`**, so a connect-time timeout cannot
  masquerade as the mid-operation case.

Assumption to confirm in the first nightly run: Toxiproxy applies a
newly-added `latency`/`timeout`/`bandwidth` toxic to the *already-open*
warm-up connection's live stream (not only to connections opened after the
toxic). If a toxic proves to apply only to new connections, scenario 2/4 add the
toxic and then force a reconnect (e.g. via an intervening invalidating op) before
the stalling call; this contingency is noted so a green-but-wrong result is
impossible.

After the assertions, remove the toxic and prove recovery. Shared wire-assert
helper mirrors `e2e_wire_fault_injection.rs::assert_error_code`.

**Toxic parameters and the connect-survival invariant.** Magnitudes are
load-bearing. The invariant: for operation-targeting scenarios the toxic is added
*after* the warm-up, so connect + `SELECT` + `RFC822.SIZE` preflight already
completed and only the target operation is starved. Concrete starting values
(tuned in the first run): `command_timeout = connect_timeout = 2s`; scenario 2
uses a `timeout` toxic (stops all data, guaranteeing the in-flight FETCH exceeds
2s); scenario 4 uses a `bandwidth` toxic at ~64 KB/s with a ~2 MiB seed body for
4b (≈32s to deliver ≫ 2s) and a >`max_fetch_body_bytes` seed body for 4a.
Scenario 1's toxic is *intended* to kill the connect, so no survival margin
applies there.

**Seed path (single supported route).** The test is a host process; Dovecot's
993/143 are **not** host-published, so the *only* reachable path is through a
published Toxiproxy proxy port. Seeding therefore opens a pinned IMAP connection
**through the relevant proxy while no toxic is active**, `APPEND`s the fixture,
then the scenario adds its toxic. There is no direct-to-Dovecot path. Scenario 4
seeds a body under the account's `max_append_bytes`; the chaos config raises
`max_append_bytes` to `26_214_400` (25 MiB) so a >10 MiB seed body fits the
`APPEND` even though it exceeds the `fetch` cap in sub-case 4a.

**Audit-drain assertion helper.** Every audit line is a JSON record with a
top-level `seq` and a `kind` discriminator (`auth`, `tool_start`, `tool_end`,
`process_start`, `process_end`); `tool_end` carries `start_seq` back to its
`tool_start`. The helper reads the JSONL, then:
- for the failing tool call, locates its `tool_start` (seq `S₀`) and matching
  `tool_end` (whose `start_seq == S₀`, seq `S₁`), and asserts the `tool_end`
  `error_code`;
- for scenario 3's "exactly one AuthEvent", counts `kind == "auth"` records with
  `S₀ < seq < S₁` and asserts the count is 1.
This rests on a **load-bearing invariant stated here so a future change breaks
loudly**: IMAP connect is *lazy* — no `auth` record is emitted at `initialize`,
so the first tool call's connect is the first-ever `auth` record. If connect ever
becomes eager (a preflight that emits auth, an eager pool warm-up), the
scenario-3 count must be re-derived; the Seq-bracketing above already scopes the
count to the single call window, which contains the mis-count if it happens.

| # | Scenario | Proxy | Toxic | Wire assertion | Audit assertion | Recovery |
|---|----------|-------|-------|----------------|-----------------|----------|
| 1 | Delayed **greeting** | `starttls` (143) | `timeout` (block data after TCP connect, > connect budget) — plaintext greeting is read before TLS on the STARTTLS path, so this stalls the greeting specifically | `ERR_TIMEOUT` | `auth` result=Failure, error_code=Timeout | remove toxic → next `list_folders` ok |
| 2 | Mid-FETCH stall | `imaps` (993) | **warm-up call succeeds**, then `timeout` toxic added, then FETCH | `ERR_TIMEOUT` | preceding `tool_end` success **then** failing `tool_end` error_code=`ERR_TIMEOUT` | remove toxic → next `search`/`fetch` ok (session was invalidated → reconnect) |
| 3 | RST during STARTTLS | `starttls` (143) | `reset_peer` (`timeout: 0`) | `ERR_TLS` **or** `ERR_CONNECTION_LOST` | **exactly one** `auth` result=Failure in the call window | remove toxic → next call over STARTTLS ok |
| 4a | Over-cap body under trickle (buffering bound) | `imaps` (993) | warm-up ok, then `bandwidth` (slow); body **>** `max_fetch_body_bytes` | `ERR_ATTACHMENT_TOO_LARGE` **promptly** (≪ command budget) | success `tool_end` then `tool_end` error_code=`ERR_ATTACHMENT_TOO_LARGE` | remove toxic → next fetch ok |
| 4b | Under-cap body trickled (time bound) | `imaps` (993) | warm-up ok, then `bandwidth` so body can't arrive in command budget; `max_fetch_body_bytes` raised above body | `ERR_TIMEOUT` | success `tool_end` then `tool_end` error_code=`ERR_TIMEOUT` | remove toxic → next fetch ok |

Scenario 1 and 3 use the `starttls` proxy (`encryption = "starttls"`, port 143) —
the first e2e_wire coverage of the STARTTLS path; scenario 1 there genuinely
delays the *plaintext greeting* (on the `imaps`/993 path a data-blocking toxic
stalls the TLS handshake first, never reaching the greeting). Scenarios 2/4 use
the `imaps` proxy (`encryption = "tls"`, port 993). **Scenarios 4a and 4b are two
separate `#[tokio::test]`s (two server processes).** They cannot share one process
because `max_fetch_body_bytes` is fixed at process spawn (4a needs the body *over*
the cap; 4b needs it *under* a raised cap), and a single process cannot present
two caps. Both do the operation-targeting warm-up before adding the `bandwidth`
toxic.

### Component 5 — nightly workflow

New `.github/workflows/nightly-chaos.yml`, modeled on `mcp-fuzz-nightly.yml`:
`schedule` cron + `workflow_dispatch`; single job on `ubuntu-latest`; installs
`cargo-nextest`; runs
`cargo nextest run -p rimap-server -E 'binary(e2e_wire_chaos)' --no-tests=fail`
with `RIMAP_CHAOS: "1"` and `RIMAP_REQUIRE_DOCKER: "1"`. All `uses:` pinned to
40-char SHA + version comment (zizmor/actionlint gates apply). Non-blocking (not
in branch-protection required set). The job sets `timeout-minutes: 15` so a
runaway suite (a container that never comes ready, a proxy that wedges) fails
loudly instead of silently drifting past the wall-time rationale for nightly-only.

## Failure modes & edge cases

- **Toxic outlives the test.** Each test calls `ToxiproxyControl::reset()` before
  the recovery assertion; the container is discarded per-test via Drop, so a
  leaked toxic cannot cross tests. Recovery uses a *removed*-toxic state, not a
  hope that the toxic expired.
- **Breaker accidentally trips.** Only if a scenario provokes ≥5 timeouts in 30s.
  Each scenario provokes exactly one fault before removing the toxic; the
  survey confirms `ERR_ATTACHMENT_TOO_LARGE` is breaker-neutral. Fresh process
  per test ⇒ fresh breaker.
- **Idle-reconnect double AuthEvent.** A recovering *ReadOnly* call after a
  `ConnectionLost` does two connects → two `AuthEvent`s. Scenario 3 asserts
  exactly one AuthEvent, but scenario 3's fault is a handshake reset (single
  `connect_inner`, no in-call ReadOnly retry — retry needs an already-established
  session that then drops), so one AuthEvent holds. The assertion counts events
  in the audit JSONL for that single tool call window, not the whole session.
- **STARTTLS reset races to a timeout.** `reset_peer` sends a real RST promptly,
  so the outcome is a prompt io error, not a stall to the connect budget — the
  `{ERR_TLS, ERR_CONNECTION_LOST}` set holds and `ERR_TIMEOUT` is not expected
  here. If flake appears, the fallback is to widen the asserted set with a
  logged rationale rather than to silently accept any code.
- **Toxiproxy image unavailable / control API slow to bind.** Readiness gate
  polls `GET /version` with the same 60s budget as Dovecot readiness; under
  `RIMAP_REQUIRE_DOCKER=1` a timeout panics with diagnostic context (compose
  logs), matching `DovecotHarness`.
- **Port publish vs runtime proxy config.** Proxies listen on *fixed* internal
  ports (21993/21143) seeded at container start, so Docker's publish mapping is
  stable; toxics are added at runtime but the listen ports never change.
- **Control-plane failure mid-test.** A non-2xx from any Toxiproxy control call
  panics with a control-plane-attributed diagnostic (§Component 2), so a
  `remove_toxic`/`reset()` hiccup aborts before the recovery assertion and never
  reads as a product wedge.
- **Wall-time.** Low timeout budgets (2s) bound each timeout scenario; container
  bring-up dominates and is bounded by the 60s readiness gate per fixture plus
  the workflow's `timeout-minutes: 15` job cap — the "~90s on a warm runner"
  figure is informational, the 15-minute cap is the enforced bound.

## Testing

- The suite **is** the test. Its own correctness is checked by: (a) running it
  locally with `RIMAP_CHAOS=1 RIMAP_REQUIRE_DOCKER=1` and observing each scenario
  fail-then-pass when the toxic is toggled; (b) confirming it silent-skips with
  `RIMAP_CHAOS` unset even under `RIMAP_REQUIRE_DOCKER=1` (the PR-CI invariant);
  (c) `just ci` staying green (the new binary must not run on the PR path).
- No unit tests for the harness plumbing beyond what the scenarios exercise;
  the `ToxiproxyControl` client is validated end-to-end by every scenario adding
  and removing a toxic.

## Considered & rejected

- **Toxiproxy as a second service in the shared `docker-compose.yml` (behind a
  compose `profile`).** Rejected: even with a profile, it couples the chaos
  fixture's lifecycle and env to the PR-blocking harness, and a mis-set profile
  would start Toxiproxy on every e2e_wire run. A separate compose file is
  strictly additive and cannot regress the PR path.
- **Excluding the chaos binary from PR CI via a nextest `-E` filter
  (`binary(/e2e/) - binary(e2e_wire_chaos)`).** Rejected as the *primary* gate:
  it is fragile (a second chaos binary silently re-enters), and the workspace
  `cargo nextest run --workspace` step would still run it when Docker is present.
  The `RIMAP_CHAOS` env gate is robust at the source level; the nextest filter is
  not needed.
- **Terminating TLS at Toxiproxy to inject at the TLS layer.** Rejected: breaks
  fingerprint pinning, forcing the test to disable the very control it exercises.
  TCP passthrough keeps pinning honest.
- **`iptables`/`tc netem` for latency/loss instead of Toxiproxy.** Rejected:
  requires host privileges/capabilities that CI runners and dev laptops don't
  uniformly grant; Toxiproxy's HTTP control API is portable and deterministic.
- **A dedicated `toxiproxy` Rust client crate.** Rejected: a new dependency for
  ~4 HTTP calls. `ureq` + `serde_json` (both present) cover it.
- **Reusing `DovecotHarness::stop()` / `restart()` (container-level faults).**
  Rejected: those model dead/recreated servers (already covered). The issue is
  specifically about *alive-but-degraded*, which only an in-path proxy provides.
- **Making scenario 3 assert a single code.** Rejected: the plaintext→TLS
  boundary is invisible at TCP; asserting a set + one-AuthEvent is faithful to
  the issue's "TLS/connection" wording and avoids a timing-dependent flake.

## Rollout / rollback

- Additive: new compose file, new support module, new test binary, new nightly
  workflow. No existing file changes except adding the workflow and (if needed) a
  one-line note in `AGENTS.md` "Container runtime for integration tests".
- Rollback: delete the four new artifacts; nothing else depends on them.
- Follow-up: if scenario 3 proves flaky in the first nightly cycles, widen the
  asserted code set with a rationale comment (tracked inline, not deferred).
