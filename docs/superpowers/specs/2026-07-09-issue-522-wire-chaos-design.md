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
- **Byte-trickle / no unbounded buffering.** `fetch_body` pre-checks
  `RFC822.SIZE` and rejects over-cap bodies *before* reading (honest Dovecot
  reports true size), so a 10 MiB body under a 5 MiB cap → `ERR_ATTACHMENT_TOO_
  LARGE` **instantly**, trickle irrelevant — that path is already covered. To
  exercise the *time* bound and prove no unbounded wait, the scenario raises
  `max_fetch_body_bytes` above the body size, seeds a body large enough that a
  bandwidth toxic cannot deliver it inside `command_timeout`, and asserts
  **`ERR_TIMEOUT`** with the session invalidated and the next call recovering.
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

One binary, `#[tokio::test(flavor = "multi_thread")]` per scenario. Each: start
the chaos stack, seed via a direct pinned IMAP connection through Toxiproxy (or
directly to Dovecot's in-network port via a seed helper), spawn the server with a
chaos config (low `connect_timeout`/`command_timeout`, e.g. 2s each), drive tools
over the wire, assert the `ERR_*` code, drain and assert the audit JSONL, then
prove recovery. Shared assert helper mirrors
`e2e_wire_fault_injection.rs::assert_error_code`.

| # | Scenario | Toxic | Wire assertion | Audit assertion | Recovery |
|---|----------|-------|----------------|-----------------|----------|
| 1 | Delayed greeting | `timeout` on `imaps` downstream (stall > connect budget) | `ERR_TIMEOUT` | `AuthEvent` result=Failure, code=Timeout | remove toxic → next `list_folders` ok |
| 2 | Mid-FETCH stall | success first, then `latency`/`timeout` on `imaps` > command budget | `ERR_TIMEOUT` | tool_end `ERR_TIMEOUT` | remove toxic → next `search`/`fetch` ok (session was invalidated → reconnect) |
| 3 | RST during STARTTLS | `reset_peer` (`timeout: 0`) on `starttls` | `ERR_TLS` **or** `ERR_CONNECTION_LOST` | **exactly one** `AuthEvent` result=Failure | remove toxic → next call over STARTTLS ok |
| 4 | Byte-trickle large body | `max_fetch_body_bytes` raised above body; `bandwidth` toxic so body can't arrive in command budget | `ERR_TIMEOUT` (time bound, not size) | tool_end `ERR_TIMEOUT` | remove toxic → next fetch ok |

Scenarios 1/2/4 use the `imaps` proxy (`encryption = "tls"`, port 993);
scenario 3 uses the `starttls` proxy (`encryption = "starttls"`, port 143),
which also adds the first e2e_wire coverage of the STARTTLS path.

### Component 5 — nightly workflow

New `.github/workflows/nightly-chaos.yml`, modeled on `mcp-fuzz-nightly.yml`:
`schedule` cron + `workflow_dispatch`; single job on `ubuntu-latest`; installs
`cargo-nextest`; runs
`cargo nextest run -p rimap-server -E 'binary(e2e_wire_chaos)' --no-tests=fail`
with `RIMAP_CHAOS: "1"` and `RIMAP_REQUIRE_DOCKER: "1"`. All `uses:` pinned to
40-char SHA + version comment (zizmor/actionlint gates apply). Non-blocking (not
in branch-protection required set).

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
- **Wall-time.** Low timeout budgets (2s) bound each timeout scenario; total
  suite target < ~90s on a warm runner (Dovecot + Toxiproxy bring-up dominates).

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
