# Network Chaos e2e Layer (#522) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a nightly-only e2e suite that interposes Toxiproxy between the `rusty-imap-mcp` binary and the Dovecot fixture to exercise degraded-but-alive network conditions (delayed greeting, mid-FETCH stall, RST during STARTTLS, byte-trickle), asserting the typed `ERR_*` wire code, the audit record, and post-fault recovery with no wedged session/breaker.

**Architecture:** A dedicated `docker-compose.chaos.yml` runs Dovecot + Toxiproxy on one compose network; Toxiproxy is a TCP passthrough (pinned Dovecot cert still matches). A `ChaosHarness` (rimap-server test support) brings the stack up, drives Toxiproxy's HTTP control API over `ureq`, and gates the whole suite behind `RIMAP_CHAOS=1` so it never runs on PR CI. Five test functions (scenarios 1, 2, 3, 4a, 4b) drive the production binary over its stdio JSON-RPC wire.

**Tech Stack:** Rust (edition 2024, MSRV 1.88), `tokio` multi-thread tests, `assert_cmd` (binary spawn), `ureq` (Toxiproxy control), `serde_json`, `tempfile`, raw `docker`/`podman compose` CLI, Toxiproxy 2.12.0, Dovecot 2.4.4.

**Source spec:** `docs/superpowers/specs/2026-07-09-issue-522-wire-chaos-design.md` — read it before starting; it carries every design decision and the failure-mode rationale.

## Global Constraints

- **MSRV 1.88.0, edition 2024.** No syntax/deps that break the MSRV build.
- **No new runtime or dev dependency.** The control plane reuses `ureq` (v3, already a workspace dev-dep, used in `crates/rimap-server/tests/support/mailpit/harness.rs`) and `serde_json`. Do not add a toxiproxy client crate or `reqwest`. Note: the in-repo `ureq` example shows only `GET`/`.call()`/`.body_mut().read_json()`; the `POST .send_json()` (add_toxic) and `POST /reset` shapes must be confirmed against ureq 3.x docs (use context7) before writing — no in-repo POST example exists.
- **No production-code changes.** This is test coverage. If a scenario surfaces a genuine defect, open a follow-up issue per `AGENTS.md` (do not expand scope) unless the fix is a clearly-scoped one-liner with its own regression test.
- **Workspace lints are law.** `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` must be clean. No `#[allow]` (use `#[expect(..., reason = "...")]`). Integration-test binaries may `#![expect(clippy::expect_used, reason = "integration tests")]` and `#![expect(clippy::panic, reason = "test diagnostics")]` at the top, mirroring `e2e_wire_fault_injection.rs`. `eprintln!`/`println!` are allowed **in tests only**.
- **Multi-arch, no arch gate.** Toxiproxy image `ghcr.io/shopify/toxiproxy:2.12.0` is multi-arch (`linux/amd64` + `linux/arm64`); Dovecot is `docker.io/dovecot/dovecot:2.4.4-root` (multi-arch). Do **not** add any `std::env::consts::ARCH` guard — every supported dev host (Apple Silicon macOS, Ubuntu CI, Fedora) runs the suite natively.
- **Compose images are tag-pinned** (matching the existing `docker-compose.yml`); GitHub Actions `uses:` lines are 40-char-SHA-pinned with a version comment (zizmor/actionlint gate `.github/workflows/`).
- **Container gating (three-tier).** `RIMAP_CHAOS` unset → silent-skip (even under `RIMAP_REQUIRE_DOCKER=1`, so PR CI's `binary(/e2e/)` sweep stays green). `RIMAP_CHAOS=1` + no runtime → `RIMAP_REQUIRE_DOCKER=1` panics, else silent-skip. `RIMAP_CHAOS=1` + runtime → run.
- **Guardrail commands:** `just check` (fast compile), `just fmt`, `just lint`, `just test-fast` (inner loop), `cargo nextest run -p rimap-server -E 'binary(e2e_wire_chaos)'` with `RIMAP_CHAOS=1 RIMAP_REQUIRE_DOCKER=1` (chaos suite), `just ci` (full local CI — must stay green, i.e. the chaos binary must NOT run on the non-chaos path). `actionlint` + `zizmor .github/workflows/` for the workflow task.
- **Commits:** conventional-commit prefixes (`test:`, `ci:`, `docs:`), imperative ≤72-char subject, one logical change each. Never `git add -A`; stage explicit paths. Branch: `feat/wire-chaos-522` (already created).

---

## File Structure

- **Create** `crates/rimap-imap/tests/integration/dovecot/docker-compose.chaos.yml` — Dovecot + Toxiproxy on one network; only Toxiproxy ports published.
- **Create** `crates/rimap-imap/tests/integration/dovecot/toxiproxy.json` — Toxiproxy seed config (two proxies on fixed internal ports).
- **Create** `crates/rimap-server/tests/support/chaos/mod.rs` — module re-exports.
- **Create** `crates/rimap-server/tests/support/chaos/harness.rs` — `ChaosHarness`, `ChaosSkip`, `ToxiproxyControl`, gate logic.
- **Create** `crates/rimap-server/tests/support/chaos/audit.rs` — audit-drain/Seq-bracket assertion helper (pure, unit-tested).
- **Create** `crates/rimap-server/tests/e2e_wire_chaos.rs` — the five scenario tests.
- **Modify** `crates/rimap-server/tests/support/wire/harness.rs` — add a slow-tolerant `request_within(method, params, deadline)` (Task 3B); the existing `request()` caps reads at a shared 2s `REQUEST_TIMEOUT`, which both the ≥2s chaos **faults** and the reconnect-bearing **recovery** calls (scenarios 1/2/3/4b) would trip.
- **Create** `.github/workflows/nightly-chaos.yml` — scheduled nightly job + vacuous-green guard + SIGKILL cleanup.
- **Modify** `AGENTS.md` — add a "Network chaos e2e (nightly, #522)" note under the container-runtime section.

Reference files to adapt/mirror (read before writing):
- `crates/rimap-server/tests/support/dovecot/harness.rs` — the harness to adapt (runtime autodetect, `ReservedPort`, `uuid_like`, compose up/down, fingerprint read, Drop).
- `crates/rimap-server/tests/support/dovecot/mod.rs`, `.../wire/mod.rs`, `.../wire/harness.rs`, `.../wire/config.rs` — module wiring, `Harness::spawn_with_config`, TOML config builders.
- `crates/rimap-server/tests/e2e_wire_fault_injection.rs` — scenario shape, `assert_error_code`, `build_fault_config`, `seed_multipart_message`, `StaticCreds`.
- `crates/rimap-imap/tests/integration/dovecot/docker-compose.yml`, `entrypoint.sh` — the fixture the chaos compose reuses.
- `.github/workflows/mcp-fuzz-nightly.yml` — nightly workflow template (schedule, SHA-pinned actions).

---

## Task 1: Chaos compose fixture + Toxiproxy seed config

**Files:**
- Create: `crates/rimap-imap/tests/integration/dovecot/docker-compose.chaos.yml`
- Create: `crates/rimap-imap/tests/integration/dovecot/toxiproxy.json`

**Interfaces:**
- Produces (consumed by Task 2's `ChaosHarness`): a compose stack that, given env `RIMAP_DOVECOT_HOST_PORT` (unused here but harmless), `RIMAP_TOXI_IMAPS_PORT`, `RIMAP_TOXI_STARTTLS_PORT`, `RIMAP_TOXI_CTRL_PORT`, publishes on `127.0.0.1`: `<imaps_port>:21993`, `<starttls_port>:21143`, `<ctrl_port>:8474`. Dovecot's 993/143 are NOT published. Toxiproxy seeds proxies `imaps` (→`dovecot:993`) and `starttls` (→`dovecot:143`). The Dovecot service writes `/shared/fingerprint.hex` and `touch /shared/ready` exactly as today.

- [ ] **Step 1: Write the seed config**

`crates/rimap-imap/tests/integration/dovecot/toxiproxy.json`:

```json
[
  {
    "name": "imaps",
    "listen": "0.0.0.0:21993",
    "upstream": "dovecot:993",
    "enabled": true
  },
  {
    "name": "starttls",
    "listen": "0.0.0.0:21143",
    "upstream": "dovecot:143",
    "enabled": true
  }
]
```

- [ ] **Step 2: Write the chaos compose file**

`crates/rimap-imap/tests/integration/dovecot/docker-compose.chaos.yml`. The `dovecot` service is copied from `docker-compose.yml` **minus the published `ports:`** (Toxiproxy reaches it in-network). Toxiproxy publishes its three ports and mounts the seed config.

```yaml
services:
  dovecot:
    image: docker.io/dovecot/dovecot:2.4.4-root
    container_name: ${COMPOSE_PROJECT_NAME:-rimap-chaos}-dovecot
    # No published ports: Toxiproxy reaches dovecot:993 / dovecot:143 on the
    # compose network. Keeping 993/143 unpublished forces all client traffic
    # through the proxy, which is the whole point of the chaos layer.
    volumes:
      - ./dovecot.conf:/etc/dovecot/dovecot.conf:ro,z
      - ./users:/etc/dovecot/users:ro,z
      - ./fixtures:/fixtures:ro,z
      - ./entrypoint.sh:/entrypoint.sh:ro,z
      - shared:/shared
    entrypoint: ["/bin/sh", "/entrypoint.sh"]
    healthcheck:
      test: ["CMD", "test", "-f", "/shared/ready"]
      interval: 1s
      timeout: 1s
      retries: 30

  toxiproxy:
    # Multi-arch (linux/amd64 + linux/arm64): no arch gate needed.
    image: ghcr.io/shopify/toxiproxy:2.12.0
    container_name: ${COMPOSE_PROJECT_NAME:-rimap-chaos}-toxiproxy
    depends_on:
      - dovecot
    command: ["-host=0.0.0.0", "-config=/toxiproxy.json"]
    volumes:
      - ./toxiproxy.json:/toxiproxy.json:ro,z
    ports:
      - "127.0.0.1:${RIMAP_TOXI_IMAPS_PORT}:21993"
      - "127.0.0.1:${RIMAP_TOXI_STARTTLS_PORT}:21143"
      - "127.0.0.1:${RIMAP_TOXI_CTRL_PORT}:8474"

volumes:
  shared:
```

- [ ] **Step 3: Manually validate the stack comes up (smoke, not committed as a test)**

Run (requires Docker/Podman):

```bash
cd crates/rimap-imap/tests/integration/dovecot
RIMAP_TOXI_IMAPS_PORT=21993 RIMAP_TOXI_STARTTLS_PORT=21143 RIMAP_TOXI_CTRL_PORT=28474 \
  docker compose -f docker-compose.chaos.yml -p rimap-chaos-smoke up -d
sleep 8
curl -fsS localhost:28474/version && echo
curl -fsS localhost:28474/proxies | head -c 400 && echo
docker compose -f docker-compose.chaos.yml -p rimap-chaos-smoke down -v --remove-orphans
```

Expected: `/version` prints a version string; `/proxies` shows `imaps` and `starttls` with `upstream` `dovecot:993`/`dovecot:143` and `enabled: true`. (If your host uses podman, substitute `podman compose`.)

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-imap/tests/integration/dovecot/docker-compose.chaos.yml \
        crates/rimap-imap/tests/integration/dovecot/toxiproxy.json
git commit -m "test(chaos): add Toxiproxy+Dovecot compose fixture for #522"
```

---

## Task 2: `ChaosHarness` + `ToxiproxyControl` + gate

**Files:**
- Create: `crates/rimap-server/tests/support/chaos/mod.rs`
- Create: `crates/rimap-server/tests/support/chaos/harness.rs`

**Interfaces:**
- Consumes: Task 1's compose stack; the sibling `support/dovecot/harness.rs` scaffolding (copy `runtime()`, `binary_present()`, `ReservedPort`, `uuid_like()`, `compose_down()`, `read_fingerprint()` verbatim or via a shared path — simplest is to copy into `harness.rs`, matching how the two existing `DovecotHarness` copies already duplicate this).
- Produces (consumed by Tasks 4–7):
  - `enum ChaosSkip { Disabled, DockerUnavailable }`
  - `ChaosHarness::try_start() -> Result<ChaosHarness, ChaosSkip>` — applies the three-tier gate, brings up the stack, waits for readiness.
  - `ChaosHarness::imaps_port(&self) -> u16`, `starttls_port(&self) -> u16` — host ports for the two proxies.
  - `ChaosHarness::fingerprint(&self) -> &TlsFingerprint` (type `rimap_core::TlsFingerprint`; confirm the exact path used by `DovecotHarness`).
  - `ChaosHarness::project(&self) -> &str` — the `rimap-chaos-<uuid>` project name (for diagnostics).
  - `ChaosHarness::toxics(&self) -> &ToxiproxyControl`.
  - `ToxiproxyControl::add_toxic(&self, proxy: &str, spec: serde_json::Value)`, `reset(&self)` — each panics on non-2xx with a control-plane-attributed message. (No `remove_toxic`: every scenario clears via `reset()`; adding an uncalled `pub fn` would trip `dead_code` under `-D warnings` — `pub` does not exempt items in a test binary. If a future scenario needs per-toxic removal, add it *with* its caller, or link it via a `force_use_for_dead_code_link` helper mirroring `e2e_wire_fault_injection.rs:60`.)
  - Drop → `compose down -v --remove-orphans`.

> **Ordering is critical.** `tests/support/*` files compile **only** when a test
> binary pulls them in via `#[path = "..."] mod ...;` — there is no lib/support
> target. So the chaos modules do not compile (and `just lint` / `--no-run` give a
> **false green**) until an `e2e_wire_chaos.rs` binary includes them. Therefore
> **create the binary shell in Step 1**, before the harness code, so every
> subsequent `just lint` actually compiles `support/chaos/*` and Task 3's audit
> unit tests can run. **No chaos-module commit is valid until
> `cargo nextest run -p rimap-server -E 'binary(e2e_wire_chaos)' --no-run`
> compiles cleanly.**

- [ ] **Step 1: Write the module file AND a compiling binary shell**

`crates/rimap-server/tests/support/chaos/mod.rs`:

```rust
//! Network-chaos e2e support: a Toxiproxy-in-path Dovecot harness (#522).
pub mod harness;

pub use harness::{ChaosHarness, ChaosSkip, ToxiproxyControl};
```

(`pub mod audit;` + its re-export are added in Task 3 when `audit.rs` lands.)

`crates/rimap-server/tests/e2e_wire_chaos.rs` — minimal shell so the module
compiles under `just lint` from now on (Task 4 fleshes it out):

```rust
#![expect(clippy::expect_used, reason = "integration tests")]
#![expect(clippy::panic, reason = "test diagnostics")]

#[path = "support/chaos/mod.rs"]
mod chaos;

// Reference the public surface so it is not dead code before scenarios land.
#[expect(dead_code, reason = "shell; scenarios in Task 4+ exercise this")]
fn _force_use() {
    let _ = chaos::ChaosHarness::try_start;
}
```

- [ ] **Step 2: Write the gate + `ToxiproxyControl` (the genuinely new code)**

`crates/rimap-server/tests/support/chaos/harness.rs`. Copy the scaffolding from `support/dovecot/harness.rs` (runtime autodetect, `ReservedPort`, `uuid_like`, `compose_down`, `read_fingerprint`), then add the chaos-specific pieces below. Gate logic:

```rust
/// Three-tier gate. `RIMAP_CHAOS` is checked FIRST so the suite skips even
/// under `RIMAP_REQUIRE_DOCKER=1` — that is what keeps it off PR CI, whose
/// `binary(/e2e/)` filter otherwise selects this binary.
fn check_gate() -> Result<(), ChaosSkip> {
    if std::env::var("RIMAP_CHAOS").is_err() {
        return Err(ChaosSkip::Disabled);
    }
    if !runtime_available() {
        if std::env::var("RIMAP_REQUIRE_DOCKER").is_ok() {
            panic!("RIMAP_CHAOS=1 but no docker/podman found and RIMAP_REQUIRE_DOCKER=1");
        }
        return Err(ChaosSkip::DockerUnavailable);
    }
    Ok(())
}
```

`ToxiproxyControl` (uses `ureq`; base URL `http://127.0.0.1:<ctrl_port>`):

```rust
pub struct ToxiproxyControl {
    base: String, // e.g. "http://127.0.0.1:28474"
}

impl ToxiproxyControl {
    pub fn new(ctrl_port: u16) -> Self {
        Self { base: format!("http://127.0.0.1:{ctrl_port}") }
    }

    /// POST a toxic spec to a proxy. Panics (control-plane-attributed) on non-2xx.
    pub fn add_toxic(&self, proxy: &str, spec: serde_json::Value) {
        let url = format!("{}/proxies/{proxy}/toxics", self.base);
        match ureq::post(&url).send_json(spec.clone()) {
            Ok(_) => {}
            Err(e) => panic!("toxiproxy control: add_toxic on '{proxy}' failed: {e}; spec={spec}"),
        }
    }

    /// Clear all toxics on all proxies. Panics (control-plane-attributed) on error.
    pub fn reset(&self) {
        let url = format!("{}/reset", self.base);
        match ureq::post(&url).call() {
            Ok(_) => {}
            Err(e) => panic!("toxiproxy control: reset failed: {e}"),
        }
    }

    /// Readiness helpers used by the harness.
    fn version_ok(&self) -> bool {
        ureq::get(&format!("{}/version", self.base)).call().is_ok()
    }

    /// Assert both seed proxies exist, enabled, with the expected upstreams.
    fn proxies_ok(&self) -> bool {
        let Ok(mut resp) = ureq::get(&format!("{}/proxies", self.base)).call() else {
            return false;
        };
        let Ok(body) = resp.body_mut().read_json::<serde_json::Value>() else {
            return false;
        };
        let check = |name: &str, upstream: &str| {
            body[name]["upstream"].as_str() == Some(upstream)
                && body[name]["enabled"].as_bool() == Some(true)
        };
        check("imaps", "dovecot:993") && check("starttls", "dovecot:143")
    }
}
```

> Note: mirror the `ureq` 3.x call style from `crates/rimap-server/tests/support/mailpit/harness.rs` (`ureq::get(url).call()?.body_mut().read_json()`). That file demonstrates **GET only** — `version_ok`/`proxies_ok` above match it. The `POST .send_json()` (add_toxic) and `POST /reset` shapes have **no in-repo example**; confirm them against ureq 3.x docs via context7 before writing, and check whether a non-2xx status returns `Err` in ureq 3.x (it does by default) so the panic arms fire correctly.

- [ ] **Step 3: Write `try_start` (reserve 3 ports, compose up, wait for readiness)**

Model on `DovecotHarness::try_start`, with these deltas:
1. `check_gate()?` first.
2. Reserve **three** `ReservedPort`s → `imaps_port`, `starttls_port`, `ctrl_port`.
3. Project name `rimap-chaos-{uuid_like()}`.
4. `compose_dir` = same `rimap-imap/tests/integration/dovecot` directory (reached via `CARGO_MANIFEST_DIR`→parent, exactly as the sibling does).
5. `up` command: `<runtime> compose -p <project> -f docker-compose.chaos.yml up -d` with env `RIMAP_TOXI_IMAPS_PORT`, `RIMAP_TOXI_STARTTLS_PORT`, `RIMAP_TOXI_CTRL_PORT` (release the port leases just before `up`, mirroring the sibling's `RIMAP_DOVECOT_HOST_PORT` handling).
6. Readiness (60s budget, poll ~1s): `read_fingerprint(project)` succeeds **and** `ToxiproxyControl::version_ok()` **and** `ToxiproxyControl::proxies_ok()`.
7. On `RIMAP_REQUIRE_DOCKER=1`, every readiness/compose failure panics with diagnostic context (dump `<runtime> compose -p <project> logs`); else return the appropriate `ChaosSkip`. Mirror the sibling's require-docker branch.
8. Store `imaps_port`, `starttls_port`, `ctrl_port`, `project`, `fingerprint`, `ToxiproxyControl`, and the tempdir/compose handle for Drop.

- [ ] **Step 4: Write Drop**

```rust
impl Drop for ChaosHarness {
    fn drop(&mut self) {
        compose_down(&self.project, "docker-compose.chaos.yml");
    }
}
```

(Adapt `compose_down` to take the compose filename; the sibling hardcodes `docker-compose.yml`.)

- [ ] **Step 5: Wire the module into a throwaway harness self-test binary and run it**

Create a temporary test at the bottom of `harness.rs` (remove before commit if it slows CI, or keep as an ignored-by-default marker):

```rust
#[cfg(test)]
mod harness_selftest {
    use super::*;
    #[test]
    fn chaos_stack_starts_and_control_api_responds() {
        let h = match ChaosHarness::try_start() {
            Ok(h) => h,
            Err(_) => return, // gated off without RIMAP_CHAOS or Docker
        };
        // Adding then removing a no-op-ish toxic exercises the control plane.
        h.toxics().add_toxic("imaps", serde_json::json!({
            "type": "latency", "attributes": { "latency": 1 }
        }));
        h.toxics().reset();
        assert!(h.imaps_port() != 0 && h.starttls_port() != 0);
    }
}
```

- [ ] **Step 6: Compile the modules, then run the self-test under the gate**

First prove the modules compile (this is the check `just lint` alone would have
missed before the Step-1 shell existed):
```bash
cargo nextest run -p rimap-server -E 'binary(e2e_wire_chaos)' --no-run
```
Expected: compiles cleanly (the shell binary pulls in `support/chaos/*`).

Then run the harness self-test:
```bash
RIMAP_CHAOS=1 RIMAP_REQUIRE_DOCKER=1 \
  cargo nextest run -p rimap-server -E 'binary(e2e_wire_chaos)' --no-capture 2>&1 | tail -20
```
Expected with `RIMAP_CHAOS=1` and Docker: the stack comes up, the toxic add/reset
succeeds, teardown runs clean. Without the gate env: the self-test returns early
(skip).

- [ ] **Step 7: Guardrails + commit**

```bash
just fmt && just lint
git add crates/rimap-server/tests/support/chaos/mod.rs \
        crates/rimap-server/tests/support/chaos/harness.rs \
        crates/rimap-server/tests/e2e_wire_chaos.rs
git commit -m "test(chaos): add ChaosHarness and Toxiproxy control client"
```

---

## Task 3: Audit-drain / Seq-bracket assertion helper (pure, unit-tested)

**Files:**
- Create: `crates/rimap-server/tests/support/chaos/audit.rs`
- Modify: `crates/rimap-server/tests/support/chaos/mod.rs` (add `pub mod audit;`)
- Test: inline `#[cfg(test)]` in `audit.rs` (pure — no Docker).

> Because the Task-2 shell binary already `#[path]`-includes `support/chaos/mod.rs`,
> adding `pub mod audit;` makes these `#[cfg(test)]` tests compile and run under
> `cargo nextest run -p rimap-server -E 'binary(e2e_wire_chaos)'` — the red→green
> loop below is genuinely runnable in this task (no Docker needed; the helper is pure).

**Interfaces:**
- Consumes: audit JSONL lines (each a flat object with top-level `seq`, `kind`, and kind-specific fields; `tool_end` carries `start_seq` and `error_code`; `auth` carries `result` and `error_code`). Confirm field names against `crates/rimap-audit/src/record/mod.rs`.
- Produces (consumed by Tasks 4–7):
  - `fn read_records(path: &Path) -> Vec<serde_json::Value>` — parse each non-empty line.
  - `fn last_tool_call(records: &[Value]) -> (u64, u64)` — return `(start_seq, end_seq)` of the **last** `tool_start`/matching `tool_end` pair (matched by `tool_end.start_seq == tool_start.seq`).
  - `fn tool_end_error_code(records: &[Value], start_seq: u64) -> Option<String>` — the `error_code` of the `tool_end` whose `start_seq == start_seq`.
  - `fn count_auth_failures_between(records: &[Value], start_seq: u64, end_seq: u64) -> usize` — `kind == "auth"` && `result == "failure"` && `start_seq < seq < end_seq`.

This encodes the spec's lazy-connect invariant: because connect is lazy (no `auth` before the first tool call), a scenario-3 connect emits its single `auth` inside the failing call's `[start_seq, end_seq]` window.

- [ ] **Step 1: Write the failing test (synthetic JSONL)**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn line(v: serde_json::Value) -> String { v.to_string() }

    #[test]
    fn counts_one_auth_failure_in_the_failing_call_window() {
        // process_start(0), tool_start(1), auth failure(2), tool_end(3, start_seq=1)
        let jsonl = [
            line(json!({"seq":0,"kind":"process_start"})),
            line(json!({"seq":1,"kind":"tool_start"})),
            line(json!({"seq":2,"kind":"auth","result":"failure","error_code":"ERR_CONNECTION_LOST"})),
            line(json!({"seq":3,"kind":"tool_end","start_seq":1,"error_code":"ERR_CONNECTION_LOST"})),
        ].join("\n");
        let recs = parse_lines(&jsonl);
        let (s0, s1) = last_tool_call(&recs).expect("a tool call");
        assert_eq!(tool_end_error_code(&recs, s0).as_deref(), Some("ERR_CONNECTION_LOST"));
        assert_eq!(count_auth_failures_between(&recs, s0, s1), 1);
    }

    #[test]
    fn ignores_auth_records_outside_the_window() {
        let jsonl = [
            line(json!({"seq":0,"kind":"tool_start"})),
            line(json!({"seq":1,"kind":"auth","result":"failure","error_code":"ERR_TLS"})),
            line(json!({"seq":2,"kind":"tool_end","start_seq":0,"error_code":"ERR_TLS"})),
            line(json!({"seq":3,"kind":"tool_start"})),   // later successful call
            line(json!({"seq":4,"kind":"tool_end","start_seq":3,"error_code":null})),
        ].join("\n");
        let recs = parse_lines(&jsonl);
        let (s0, s1) = last_tool_call(&recs).expect("a tool call");
        assert_eq!((s0, s1), (3, 4));
        assert_eq!(count_auth_failures_between(&recs, s0, s1), 0);
    }
}
```

(Use a `parse_lines(&str)` helper in tests to avoid touching the filesystem; `read_records(path)` wraps it with a file read.)

- [ ] **Step 2: Run to verify it fails**

Run: `cargo nextest run -p rimap-server -E 'binary(e2e_wire_chaos)' -E 'test(/audit/)'` (the Task-2 shell binary includes the module). Expected: FAIL to compile / test not found (functions not defined).

- [ ] **Step 3: Implement the helper**

```rust
use std::path::Path;
use serde_json::Value;

pub fn parse_lines(s: &str) -> Vec<Value> {
    let mut out = Vec::new();
    for l in s.lines() {
        let l = l.trim();
        if l.is_empty() { continue; }
        if let Ok(v) = serde_json::from_str::<Value>(l) { out.push(v); }
    }
    out
}

pub fn read_records(path: &Path) -> Vec<Value> {
    let s = std::fs::read_to_string(path).unwrap_or_default();
    parse_lines(&s)
}

fn seq(v: &Value) -> Option<u64> { v["seq"].as_u64() }

pub fn last_tool_call(records: &[Value]) -> Option<(u64, u64)> {
    let mut best: Option<(u64, u64)> = None;
    for r in records {
        if r["kind"] == "tool_end" {
            let end = seq(r)?;
            let start = r["start_seq"].as_u64()?;
            if best.map(|(_, e)| end > e).unwrap_or(true) {
                best = Some((start, end));
            }
        }
    }
    best
}

pub fn tool_end_error_code(records: &[Value], start_seq: u64) -> Option<String> {
    for r in records {
        if r["kind"] == "tool_end" && r["start_seq"].as_u64() == Some(start_seq) {
            return r["error_code"].as_str().map(str::to_owned);
        }
    }
    None
}

pub fn count_auth_failures_between(records: &[Value], start_seq: u64, end_seq: u64) -> usize {
    let mut n = 0;
    for r in records {
        let Some(s) = seq(r) else { continue };
        if r["kind"] == "auth"
            && r["result"] == "failure"
            && s > start_seq
            && s < end_seq
        {
            n += 1;
        }
    }
    n
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cargo nextest run -p rimap-server -E 'binary(e2e_wire_chaos)' -E 'test(/audit/)'`. Expected: PASS (both helper tests). No Docker needed — these are pure.

- [ ] **Step 5: Guardrails + commit**

```bash
just fmt && just lint
git add crates/rimap-server/tests/support/chaos/audit.rs \
        crates/rimap-server/tests/support/chaos/mod.rs
git commit -m "test(chaos): add audit-drain Seq-bracket assertion helper"
```

---

## Task 3B: Wire `Harness` slow-tolerant request path (prerequisite for Tasks 4–7)

**Files:**
- Modify: `crates/rimap-server/tests/support/wire/harness.rs`

**Why:** `Harness::request()` reads each response under a shared
`pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(2)`
(`support/wire/harness.rs:35`), enforced in `read_one_envelope`
(`:347-360`, panics "response … did not arrive within 2s"). Chaos scenarios 1
(connect budget 4s), 2 and 4b (command budget 2s + connect/dispatch overhead)
deliberately make the server emit its typed `ERR_TIMEOUT` **after** 2s, so
`request()` would panic before the asserted response arrives. Do **not** raise
the shared const — it is deliberately tight so ordinary wire tests fail fast on
hangs. Add an **additive** per-call slow path instead.

**Interfaces:**
- Produces (consumed by Tasks 4–7): `Harness::request_within(&mut self, method: &str, params: Value, deadline: Duration) -> Value` — identical to `request()` (assign id, write line, read + parse + schema-validate the response envelope, assert id match) but bounds the stdout read by `deadline` instead of `REQUEST_TIMEOUT`. Used for BOTH the ≥2s fault calls AND the reconnect-bearing recovery calls (scenarios 1/2/3/4b) — a recovery reconnect (TCP+TLS+LOGIN through docker-networked Toxiproxy, +command) routinely exceeds 2s under the roomy connect budget, so it must not use the 2s-capped `request()`. Only scenario 4a's live-session recovery stays on `request()`.

- [ ] **Step 1: Read `request()` and `read_one_envelope()` and factor a per-call timeout**

Refactor `read_one_envelope(&mut self, caller: &str)` to
`read_one_envelope_within(&mut self, caller: &str, read_timeout: Duration)`, and
have the existing `read_one_envelope` call it with `REQUEST_TIMEOUT` so **every
current caller keeps identical 2s behavior**. Confirm all in-file callers
(`request`, `recv_until_id`, `initialize_handshake`, …) still pass through the
2s default.

- [ ] **Step 2: Add `request_within`**

Mirror `request()` exactly (id assignment, `send_line`, envelope read, schema
validation, id-match assertion) but call `read_one_envelope_within(caller,
deadline)`:

```rust
/// Like `request`, but bounds the response read by `deadline` instead of the
/// shared 2s `REQUEST_TIMEOUT`. For chaos scenarios whose server-side timeout
/// budget (connect/command) is >= 2s and would otherwise trip the fast-fail cap.
pub async fn request_within(&mut self, method: &str, params: Value, deadline: Duration) -> Value {
    // ... same body as `request`, but `read_one_envelope_within(method, deadline)`
}
```

- [ ] **Step 3: Compile the whole test crate (no behavior change to existing tests)**

Run: `cargo nextest run -p rimap-server --no-run` and then a fast existing wire test:
`cargo nextest run -p rimap-server -E 'binary(e2e_wire) & test(/full_session/)' 2>&1 | tail` (or, if Docker-gated, at least `--no-run`).
Expected: compiles; existing wire tests unchanged (they still use the 2s default).

- [ ] **Step 4: Guardrails + commit**

```bash
just fmt && just lint
git add crates/rimap-server/tests/support/wire/harness.rs
git commit -m "test(wire): add request_within for slow-response chaos scenarios"
```

> Dead-code note: `request_within` is `pub` on the shared wire `Harness`, which
> other e2e binaries also compile. If a binary that does not call it emits
> `dead_code`, that mirrors how the repo already handles cross-binary support
> items — reference it from the existing `force_use_for_dead_code_link` helpers
> (`e2e_wire_fault_injection.rs:60`, `e2e_wire_destructive.rs`) as those files do
> for other shared `Harness` methods. Add the reference if lint flags it.

---

## Task 4: Scenario 1 — delayed greeting (STARTTLS) → `ERR_TIMEOUT`

**Files:**
- Modify: `crates/rimap-server/tests/e2e_wire_chaos.rs` (the Task-2 shell — flesh it out; delete the `_force_use` shim once a real scenario references `ChaosHarness`).
- Consumes: `support/chaos` (Tasks 2–3), `support/wire` (`Harness`, `assert_valid`), `support/dovecot::fixtures`.

**Interfaces:**
- Produces: the binary all later scenarios extend. Establishes `build_chaos_config(..)`/`ChaosConfigParams`, `spawn_ready(..)`, `assert_error_code(..)`, and the per-scenario `RIMAP_CHAOS_RAN <name>` marker. (`seed_through_proxy`/`search_seed_uid` are authored in **Task 5**, their first caller — scenario 1 does not seed, so authoring them here would leave an unused private fn that fails the `-D warnings` `dead_code` gate.)

- [ ] **Step 1: Expand the shell — add module imports, config builder, seed + assert helpers**

The Task-2 shell already has the `#![expect]` preamble and `#[path] mod chaos;`.
Add the remaining `#[path]` includes and helpers (mirror `e2e_wire_fault_injection.rs`
for `StaticCreds`, `DOVECOT_PASSWORD`, `assert_error_code`, `seed`-style helpers):

```rust
#[path = "support/dovecot/mod.rs"]
mod dovecot;
#[path = "support/wire/mod.rs"]
mod wire;

use chaos::{ChaosHarness, ChaosSkip, audit};
use dovecot::fixtures;
use wire::{Harness, assert_valid};
// ... serde_json::json, tempfile::TempDir, PASSWORD_ENV_VAR, etc. (see fault_injection)

const DOVECOT_PASSWORD: &str = "testpass";

/// Chaos account TOML params. A struct (not 10 positional args) — clippy's
/// `too_many_arguments` default threshold is 7 and `clippy.toml` does not raise
/// it, so a 10-arg fn would fail the `-D warnings` gate; the repo also caps
/// positional params at 5.
struct ChaosConfigParams<'a> {
    fingerprint_hex: &'a str,
    port: u16,
    /// "tls" (993 proxy) or "starttls" (143 proxy).
    encryption: &'a str,
    /// Per-scenario budgets — see the spec's "Toxic parameters and per-scenario
    /// budgets".
    connect_timeout_seconds: u32,
    command_timeout_seconds: u32,
    max_fetch_body_bytes: u64,
    max_append_bytes: u64,
    audit_path: &'a std::path::Path,
    allowed_base: &'a std::path::Path,
    download_dir: &'a std::path::Path,
}

fn build_chaos_config(p: &ChaosConfigParams<'_>) -> String {
    let ChaosConfigParams {
        fingerprint_hex, port, encryption,
        connect_timeout_seconds, command_timeout_seconds,
        max_fetch_body_bytes, max_append_bytes,
        audit_path, allowed_base, download_dir,
    } = *p;
    format!(
        r#"
[audit]
path = "{audit_path}"
allowed_base_dir = "{allowed_base}"

[attachments]
download_dir = "{download_dir}"

[defaults.credentials]
fallback = "keyring-then-env"

[[accounts]]
name = "chaos"

[accounts.imap]
host = "127.0.0.1"
port = {port}
username = "rimap-test"
encryption = "{encryption}"
tls_fingerprint_sha256 = "{fingerprint_hex}"
connect_timeout_seconds = {connect_timeout_seconds}
command_timeout_seconds = {command_timeout_seconds}

[accounts.security]
posture = "draft-safe"

[accounts.limits]
max_fetch_body_bytes = {max_fetch_body_bytes}
max_append_bytes = {max_append_bytes}
"#,
        audit_path = audit_path.display(),
        allowed_base = allowed_base.display(),
        download_dir = download_dir.display(),
    )
}
```

> Confirm `[accounts.imap]` accepts `connect_timeout_seconds` / `command_timeout_seconds` and `[accounts.limits]` accepts `max_append_bytes` (fields exist in `rimap-config/src/model.rs`; `deny_unknown_fields` is on, so names must be exact).

Add `assert_error_code` copied from `e2e_wire_fault_injection.rs` (it reads
`resp["result"]["structuredContent"]["error_code"]` and also `assert_valid`s the
`CallToolResult`). Add a marker helper. (Do **not** author `seed_through_proxy`/`search_seed_uid` here — scenario 1 does not seed, so an unused private fn would fail `dead_code` under `-D warnings`; they land in Task 5. The set-aware `assert_error_code_in` used by scenario 3 lands in Task 6, its first caller, for the same dead-code reason.)

```rust
fn mark_ran(scenario: &str) {
    eprintln!("RIMAP_CHAOS_RAN {scenario}");
}
```

- [ ] **Step 2: Write the scenario-1 test**

```rust
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn chaos_delayed_greeting_times_out() {
    let chaos = match ChaosHarness::try_start() {
        Ok(c) => c,
        Err(ChaosSkip::Disabled) | Err(ChaosSkip::DockerUnavailable) => return,
    };
    mark_ran("scenario1");

    // STARTTLS path (143 proxy). The `timeout` toxic below blocks the greeting
    // FOREVER, so the fault trips at whatever connect_timeout is — the toxic, not
    // a tight budget, makes it deterministic. Keep connect_timeout moderate (4s)
    // so the *same* budget also gates the post-reset RECOVERY connect roomily
    // (spec principle: a must-succeed recovery connect should not run under a
    // tight fault budget). First-run tuning: if the recovery connect flakes on a
    // cold runner, raise BOTH connect_timeout AND the recovery request_within
    // deadline — raising connect_timeout alone is useless if the wire deadline is
    // the tighter bound. The block-forever toxic keeps the fault deterministic at
    // any budget; only wall-time grows.
    let mut h = spawn_ready(
        &chaos, chaos.starttls_port(), "starttls",
        /*connect*/ 4, /*command*/ 30, ROOMY_FETCH, ROOMY_APPEND,
    ).await;

    // Block all data after TCP connect: the plaintext greeting never arrives
    // within connect_timeout. `timeout` toxic with a large `timeout` (ms) or
    // 0 (block forever) on the downstream.
    chaos.toxics().add_toxic("starttls", serde_json::json!({
        "type": "timeout",
        "stream": "downstream",
        "attributes": { "timeout": 0 }
    }));

    // Slow path: the fault emits ERR_TIMEOUT at ~connect_timeout (4s), which
    // exceeds the wire Harness's 2s REQUEST_TIMEOUT — use request_within (Task 3B).
    let resp = h.request_within("tools/call", serde_json::json!({
        "name": "chaos.list_folders", "arguments": {}
    }), std::time::Duration::from_secs(15)).await;
    assert_error_code(&resp, "ERR_TIMEOUT");

    // Audit: exactly the failing tool_end carries ERR_TIMEOUT; the connect
    // auth Failure (error_code Timeout) sits in the call window. (See spec:
    // connect emits one auth record even on a per-step timeout.)
    // Drain after shutdown for a flushed file.
    chaos.toxics().reset();

    // Recovery forces a FULL reconnect (fault destroyed the session) under the
    // roomy connect budget — but that budget (4s) exceeds the wire 2s cap, so
    // recovery must ALSO use request_within, else request() panics at 2s before
    // the reconnect+response completes.
    let ok = h.request_within("tools/call", serde_json::json!({
        "name": "chaos.list_folders", "arguments": {}
    }), std::time::Duration::from_secs(15)).await;
    assert!(ok["error"].is_null() && ok["result"]["isError"] == serde_json::json!(false),
        "recovery call must succeed: {ok}");

    let audit_path = h.audit_path();          // expose from spawn_ready's tempdir
    let (status, _guard) = h.shutdown_and_wait().await;
    assert!(status.success());
    let recs = audit::read_records(&audit_path);
    // At least one auth failure with Timeout occurred during the run.
    assert!(recs.iter().any(|r| r["kind"] == "auth"
        && r["result"] == "failure"
        && r["error_code"] == "ERR_TIMEOUT"),
        "expected an auth Failure with ERR_TIMEOUT; got {recs:?}");
}
```

> `spawn_ready(&chaos, port, encryption, connect_s, command_s, fetch_cap, append_cap)` (7 params — at the clippy threshold, not over) mirrors `e2e_wire_fault_injection.rs::spawn_ready`: it assembles a `ChaosConfigParams` from its args + the tempdir paths, calls `build_chaos_config`, spawns via `Harness::spawn_with_config`, completes the MCP handshake, and returns a `Harness`. Expose the audit path via `Harness::audit_path()` (confirm it exists on the wire `Harness`; if not, return `(Harness, PathBuf)`). Define `ROOMY_FETCH = 26_214_400`, `ROOMY_APPEND = 26_214_400`.

- [ ] **Step 3: Run under the gate**

Run:
```bash
RIMAP_CHAOS=1 RIMAP_REQUIRE_DOCKER=1 \
  cargo nextest run -p rimap-server -E 'binary(e2e_wire_chaos)' --no-capture 2>&1 | tail -30
```
Expected: `chaos_delayed_greeting_times_out` PASS; log contains `RIMAP_CHAOS_RAN scenario1`.

**First-run confirmation (spec-mandated):** confirm the drained audit contains exactly one `auth` Failure with `ERR_TIMEOUT` for the connect. If it emits zero (a future refactor), apply the spec's fallback: relax the audit half to the failing `tool_end` (`ERR_TIMEOUT`) and record the fallback inline with a comment citing the spec.

- [ ] **Step 4: Verify the skip path (PR-CI invariant)**

Run (no `RIMAP_CHAOS`):
```bash
RIMAP_REQUIRE_DOCKER=1 cargo nextest run -p rimap-server -E 'binary(e2e_wire_chaos)' 2>&1 | tail
```
Expected: the test is selected but returns early (counts as pass); NO `RIMAP_CHAOS_RAN` marker. This is the invariant that keeps the suite off PR CI.

- [ ] **Step 5: Guardrails + commit**

```bash
just fmt && just lint
git add crates/rimap-server/tests/e2e_wire_chaos.rs
git commit -m "test(chaos): scenario 1 — delayed STARTTLS greeting → ERR_TIMEOUT"
```

---

## Task 5: Scenario 2 — mid-FETCH stall (established session) → `ERR_TIMEOUT` + recovery

**Files:**
- Modify: `crates/rimap-server/tests/e2e_wire_chaos.rs` (add one test).

**Interfaces:** consumes everything from Task 4; **authors** `seed_through_proxy` and `search_seed_uid` (first used here).

- [ ] **Step 1: Author `seed_through_proxy` and `search_seed_uid`**

`seed_through_proxy(chaos, port, encryption)` appends the fixture **through the
proxy while no toxic is active** (adapt `e2e_wire_fault_injection.rs::seed_multipart_message`,
pointing the `ConnectionConfig` at the proxy `port` + given `encryption`).
**Critical (independent cap):** the seed path uses its **own**
`ConnectionConfig`, whose `max_append_bytes` is separate from the server's TOML
cap. `seed_multipart_message` hardcodes `max_append_bytes: 10_485_760` (10 MiB);
scenario 4a seeds a >10 MiB body, so set the seed `ConnectionConfig`'s
`max_append_bytes` to **`26_214_400` (25 MiB)** — otherwise the seed `APPEND`
fails with `SizeLimit` before the scenario runs. Also add a
`seed_body_through_proxy(chaos, port, encryption, raw: &[u8])` variant for the
sized bodies in Task 7, sharing the same `max_append_bytes`. `search_seed_uid`
is copied from `e2e_wire_fault_injection.rs` (drives `chaos.search` for the smoke
subject, returns the max UID).

- [ ] **Step 2: Write the test (warm-up ordering is load-bearing)**

```rust
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn chaos_mid_fetch_stall_times_out_then_recovers() {
    let chaos = match ChaosHarness::try_start() {
        Ok(c) => c,
        Err(_) => return,
    };
    mark_ran("scenario2");
    seed_through_proxy(&chaos, chaos.imaps_port(), "tls").await;

    // imaps (993): connect_timeout GENEROUS (10s) so warm-up + recovery
    // connects aren't gated; command_timeout LOW (2s) so the stalled FETCH
    // trips fast.
    let mut h = spawn_ready(
        &chaos, chaos.imaps_port(), "tls",
        /*connect*/ 10, /*command*/ 2, ROOMY_FETCH, ROOMY_APPEND,
    ).await;

    // WARM-UP: establish + cache the session (no toxic yet). Success is
    // asserted; without it AC#2 passes vacuously on a connect-time timeout.
    let uid = search_seed_uid(&mut h).await; // adapt from fault_injection

    // Now stall all data → the in-flight FETCH exceeds command_timeout.
    chaos.toxics().add_toxic("imaps", serde_json::json!({
        "type": "timeout", "stream": "downstream", "attributes": { "timeout": 0 }
    }));
    // command budget 2s + overhead > wire 2s cap → request_within (Task 3B).
    let resp = h.request_within("tools/call", serde_json::json!({
        "name": "chaos.fetch_message",
        "arguments": { "folder": "INBOX", "uid": uid }
    }), std::time::Duration::from_secs(15)).await;
    assert_error_code(&resp, "ERR_TIMEOUT");

    // Recovery: session was invalidated → this call forces a reconnect under the
    // roomy 10s connect budget → request_within (not the 2s-capped request()).
    chaos.toxics().reset();
    let ok = h.request_within("tools/call", serde_json::json!({
        "name": "chaos.search",
        "arguments": { "folder": "INBOX", "subject": "e2e-wire-test-smoke" }
    }), std::time::Duration::from_secs(15)).await;
    assert!(ok["error"].is_null() && ok["result"]["isError"] == serde_json::json!(false),
        "recovery search must succeed: {ok}");

    let audit_path = h.audit_path();
    let (status, _g) = h.shutdown_and_wait().await;
    assert!(status.success());
    // A preceding success then a failing ERR_TIMEOUT tool_end — a connect-time
    // timeout cannot masquerade as the mid-op case.
    let recs = audit::read_records(&audit_path);
    let (s0, s1) = audit::last_tool_call_matching_error(&recs, "ERR_TIMEOUT")
        .expect("a failing tool_end with ERR_TIMEOUT");
    assert!(recs.iter().any(|r| r["kind"] == "tool_end"
        && r["error_code"].is_null()
        && r["seq"].as_u64().map(|s| s < s0).unwrap_or(false)),
        "a successful warm-up tool_end must precede the failing FETCH; got {recs:?}");
    let _ = s1;
}
```

> Add `last_tool_call_matching_error(records, code) -> Option<(u64,u64)>` to `audit.rs` (variant of `last_tool_call` filtered to `tool_end.error_code == code`), plus a unit test for it in Task 3's style. Confirm `chaos.fetch_message` is the correct draft-safe tool name that fetches a body (check `docs/tools.md` / the tool catalog); if the body-fetch tool differs, use it.

- [ ] **Step 3: Run under the gate**

Run: `RIMAP_CHAOS=1 RIMAP_REQUIRE_DOCKER=1 cargo nextest run -p rimap-server -E 'binary(e2e_wire_chaos)' --no-capture 2>&1 | tail -30`
Expected: PASS; log has `RIMAP_CHAOS_RAN scenario2`.

**First-run confirmation:** verify Toxiproxy applies the newly-added `timeout` toxic to the already-open warm-up connection (spec's stated assumption). If the toxic only affects new connections, the FETCH would succeed — in that case add an intervening step that forces the FETCH onto a stream the toxic governs (or reconnect), per the spec's contingency, and record it inline.

- [ ] **Step 4: Guardrails + commit**

```bash
just fmt && just lint
git add crates/rimap-server/tests/e2e_wire_chaos.rs \
        crates/rimap-server/tests/support/chaos/audit.rs
git commit -m "test(chaos): scenario 2 — mid-FETCH stall → ERR_TIMEOUT + recovery"
```

---

## Task 6: Scenario 3 — RST during STARTTLS → `{ERR_TLS, ERR_CONNECTION_LOST}` + exactly one AuthEvent

**Files:**
- Modify: `crates/rimap-server/tests/e2e_wire_chaos.rs` (add one test).

- [ ] **Step 1: Author `assert_error_code_in`, then write the test**

First add the set-aware assert helper (same accessor/validation as
`assert_error_code`, so scenario 3 never diverges onto a hand-rolled JSON path):

```rust
/// Like `assert_error_code`, but the wire code must be one of `expected`.
fn assert_error_code_in(resp: &serde_json::Value, expected: &[&str]) {
    assert!(resp["error"].is_null(), "unexpected JSON-RPC error: {resp}");
    assert_valid(&resp["result"], "CallToolResult");
    assert_eq!(resp["result"]["isError"], serde_json::json!(true), "{resp}");
    let code = resp["result"]["structuredContent"]["error_code"].as_str().unwrap_or("");
    assert!(expected.contains(&code), "expected one of {expected:?}; got {code:?} in {resp}");
}
```

Then the test:

```rust
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn chaos_starttls_reset_typed_error_one_auth() {
    let chaos = match ChaosHarness::try_start() {
        Ok(c) => c,
        Err(_) => return,
    };
    mark_ran("scenario3");

    // STARTTLS path; budgets default (a prompt RST needs no low budget).
    let mut h = spawn_ready(
        &chaos, chaos.starttls_port(), "starttls",
        /*connect*/ 10, /*command*/ 30, ROOMY_FETCH, ROOMY_APPEND,
    ).await;

    // reset_peer: RST at/near connection open (timeout: 0 → on first bytes).
    chaos.toxics().add_toxic("starttls", serde_json::json!({
        "type": "reset_peer", "stream": "downstream", "attributes": { "timeout": 0 }
    }));

    // reset_peer is prompt (<2s), but use request_within for uniformity/margin.
    let resp = h.request_within("tools/call", serde_json::json!({
        "name": "chaos.list_folders", "arguments": {}
    }), std::time::Duration::from_secs(15)).await;
    // Typed TLS/connection error — assert on the set (see spec: TCP-layer reset
    // is not deterministic between plaintext-greeting and TLS-handshake phases).
    // Use the set-aware helper (same accessor as assert_error_code — no hand-rolled path).
    assert_error_code_in(&resp, &["ERR_TLS", "ERR_CONNECTION_LOST"]);

    // Recovery forces a fresh STARTTLS connect (RST left no session) → the
    // reconnect can exceed 2s → request_within, not the 2s-capped request().
    chaos.toxics().reset();
    let ok = h.request_within("tools/call", serde_json::json!({
        "name": "chaos.list_folders", "arguments": {}
    }), std::time::Duration::from_secs(15)).await;
    assert!(ok["error"].is_null() && ok["result"]["isError"] == serde_json::json!(false),
        "recovery over STARTTLS must succeed: {ok}");

    let audit_path = h.audit_path();
    let (status, _g) = h.shutdown_and_wait().await;
    assert!(status.success());
    // Exactly one auth Failure within the failing call's Seq window.
    let recs = audit::read_records(&audit_path);
    let (s0, s1) = audit::last_tool_call_matching_error_in(
        &recs, &["ERR_TLS", "ERR_CONNECTION_LOST"]).expect("a failing tool_end");
    assert_eq!(audit::count_auth_failures_between(&recs, s0, s1), 1,
        "exactly one auth Failure in the failing call window; got {recs:?}");
}
```

> Add `last_tool_call_matching_error_in(records, &[codes]) -> Option<(u64,u64)>` to `audit.rs` (same shape, membership test), with a unit test.

- [ ] **Step 2: Run under the gate**

Run: `RIMAP_CHAOS=1 RIMAP_REQUIRE_DOCKER=1 cargo nextest run -p rimap-server -E 'binary(e2e_wire_chaos)' --no-capture 2>&1 | tail -30`
Expected: PASS; `RIMAP_CHAOS_RAN scenario3`.

**First-run confirmation (spec-mandated):** confirm a pre-login RST still emits exactly one `auth` Failure (grounding survey verified `connect_inner` emits on every termination path). If it emits zero, the "exactly one AuthEvent" must be re-derived — record findings inline.

- [ ] **Step 3: Guardrails + commit**

```bash
just fmt && just lint
git add crates/rimap-server/tests/e2e_wire_chaos.rs \
        crates/rimap-server/tests/support/chaos/audit.rs
git commit -m "test(chaos): scenario 3 — STARTTLS reset typed error + one AuthEvent"
```

---

## Task 7: Scenario 4a/4b — byte-trickle (buffering bound + time bound)

**Files:**
- Modify: `crates/rimap-server/tests/e2e_wire_chaos.rs` (add two tests, two server processes).

**Interfaces:** consumes Task 4 helpers and the Task-5 `seed_body_through_proxy`/`search_seed_uid`. Needs a large-body builder: add `fixtures::message_of_size(n: usize) -> Vec<u8>` in `support/dovecot/fixtures.rs` that builds a valid `.eml` of ~`n` bytes (headers + a repeated-filler body). Seed via `seed_body_through_proxy`, whose seed `ConnectionConfig` sets `max_append_bytes = 26_214_400` (Task 5 Step 1) — note this is the **seed** connection's own cap, independent of the server TOML `max_append_bytes`; the 10 MiB 4a body fits the 25 MiB seed cap but exceeds the server's small **fetch** cap.

- [ ] **Step 1: Scenario 4a — over-cap body, prompt `ERR_ATTACHMENT_TOO_LARGE` under trickle**

```rust
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn chaos_trickle_over_cap_rejects_promptly() {
    let chaos = match ChaosHarness::try_start() { Ok(c) => c, Err(_) => return };
    mark_ran("scenario4a");

    // Seed a body > cap. Cap small (e.g. 1 MiB); body ~10 MiB.
    let big = fixtures::message_of_size(10 * 1024 * 1024); // add this builder
    seed_body_through_proxy(&chaos, chaos.imaps_port(), "tls", &big).await;

    let mut h = spawn_ready(
        &chaos, chaos.imaps_port(), "tls",
        /*connect*/ 10, /*command*/ 30, /*fetch cap*/ 1_048_576, ROOMY_APPEND,
    ).await;
    let uid = search_seed_uid(&mut h).await; // warm-up (does NOT fetch the body's RFC822.SIZE)

    // Slow trickle: ~64 KB/s. RFC822.SIZE preflight is tiny → returns fast →
    // size-check rejects promptly, proving the body was never buffered.
    chaos.toxics().add_toxic("imaps", serde_json::json!({
        "type": "bandwidth", "stream": "downstream", "attributes": { "rate": 64 }
    }));
    let t0 = std::time::Instant::now();
    // Preflight rejection is prompt but travels through the bandwidth toxic;
    // give generous headroom (30s) — request_within (Task 3B), not the 2s cap.
    let resp = h.request_within("tools/call", serde_json::json!({
        "name": "chaos.download_attachment",
        "arguments": { "folder": "INBOX", "uid": uid, "part_id": "1" }
    }), std::time::Duration::from_secs(30)).await;
    assert_error_code(&resp, "ERR_ATTACHMENT_TOO_LARGE");
    assert!(t0.elapsed() < std::time::Duration::from_secs(20),
        "rejection must be prompt (preflight, not a body-read stall); took {:?}", t0.elapsed());

    // 4a is the ONE scenario whose recovery stays on plain request(): ERR_ATTACHMENT_TOO_LARGE
    // is transport-neutral, the session stays LIVE (no invalidate), so this
    // metadata call reuses the open session with no reconnect and returns < 2s.
    // (Re-fetching the over-cap body would still be ERR_ATTACHMENT_TOO_LARGE, so
    // recovery uses a different call to prove session liveness.)
    chaos.toxics().reset();
    let ok = h.request("tools/call", serde_json::json!({
        "name": "chaos.list_folders", "arguments": {}
    })).await;
    assert!(ok["error"].is_null() && ok["result"]["isError"] == serde_json::json!(false),
        "recovery metadata call must succeed: {ok}");

    let (status, _g) = h.shutdown_and_wait().await;
    assert!(status.success());
}
```

> `rate` is in KB/s for the `bandwidth` toxic — confirm units against Toxiproxy docs; adjust so `command_timeout` is comfortably not exceeded by the tiny preflight but a full-body read would be. Confirm `download_attachment` / `part_id` against the fault-injection test (it uses `part_id: "2"` for the multipart fixture). Choose a `part_id` valid for `message_of_size`, or use the body-fetch tool that trips the cap on `fetch_body` before part-walking (fault-injection notes the cap trips before MIME walking, so `part_id` only needs to be non-empty).

- [ ] **Step 2: Scenario 4b — under-cap body trickled, `ERR_TIMEOUT` (time bound)**

```rust
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn chaos_trickle_under_cap_times_out_then_recovers() {
    let chaos = match ChaosHarness::try_start() { Ok(c) => c, Err(_) => return };
    mark_ran("scenario4b");

    let body = fixtures::message_of_size(2 * 1024 * 1024); // 2 MiB, UNDER the raised cap
    seed_body_through_proxy(&chaos, chaos.imaps_port(), "tls", &body).await;

    // Cap raised above the body; command_timeout LOW (2s) so a ~2 MiB body at
    // 64 KB/s (~32s) cannot arrive in time → ERR_TIMEOUT.
    let mut h = spawn_ready(
        &chaos, chaos.imaps_port(), "tls",
        /*connect*/ 10, /*command*/ 2, /*fetch cap*/ ROOMY_FETCH, ROOMY_APPEND,
    ).await;
    let uid = search_seed_uid(&mut h).await; // warm-up

    chaos.toxics().add_toxic("imaps", serde_json::json!({
        "type": "bandwidth", "stream": "downstream", "attributes": { "rate": 64 }
    }));
    // ~2 MiB at 64 KB/s ≫ command budget 2s → ERR_TIMEOUT; slow path (Task 3B).
    let resp = h.request_within("tools/call", serde_json::json!({
        "name": "chaos.fetch_message",
        "arguments": { "folder": "INBOX", "uid": uid }
    }), std::time::Duration::from_secs(15)).await;
    assert_error_code(&resp, "ERR_TIMEOUT");

    // Recovery reconnects AND fetches a 2 MiB body — both must fit the wire
    // deadline, so request_within with generous headroom (the 2s request() cap
    // would trip here even on a fast runner).
    chaos.toxics().reset();
    let ok = h.request_within("tools/call", serde_json::json!({
        "name": "chaos.fetch_message",
        "arguments": { "folder": "INBOX", "uid": uid }
    }), std::time::Duration::from_secs(15)).await;
    assert!(ok["error"].is_null() && ok["result"]["isError"] == serde_json::json!(false),
        "recovery fetch must succeed after toxic removed: {ok}");

    let (status, _g) = h.shutdown_and_wait().await;
    assert!(status.success());
}
```

- [ ] **Step 3: Run under the gate**

Run: `RIMAP_CHAOS=1 RIMAP_REQUIRE_DOCKER=1 cargo nextest run -p rimap-server -E 'binary(e2e_wire_chaos)' --no-capture 2>&1 | tail -40`
Expected: both PASS; markers `RIMAP_CHAOS_RAN scenario4a` and `scenario4b` present. Tune `rate`/body sizes so 4a rejects < ~20s and 4b reliably exceeds 2s.

- [ ] **Step 4: Guardrails + commit**

```bash
just fmt && just lint
git add crates/rimap-server/tests/e2e_wire_chaos.rs \
        crates/rimap-server/tests/support/dovecot/fixtures.rs
git commit -m "test(chaos): scenario 4a/4b — byte-trickle buffering + time bounds"
```

---

## Task 8: Nightly workflow + vacuous-green guard + SIGKILL cleanup

**Files:**
- Create: `.github/workflows/nightly-chaos.yml`

**Interfaces:** consumes the five markers (`RIMAP_CHAOS_RAN scenario1|2|3|4a|4b`).

- [ ] **Step 1: Write the workflow**

Model on `.github/workflows/mcp-fuzz-nightly.yml`. Resolve current 40-char SHAs for `actions/checkout`, `dtolnay/rust-toolchain` (or the repo's toolchain action), and `taiki-e/install-action` (cargo-nextest) — copy the exact pinned SHAs already used in `ci.yml`/`mcp-fuzz-nightly.yml` so pins stay consistent. Skeleton:

```yaml
name: nightly-chaos
on:
  schedule:
    - cron: "0 5 * * *"   # daily; adjust to match other nightlies
  workflow_dispatch:
permissions:
  contents: read
jobs:
  chaos:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@<40-char-sha>  # vX.Y.Z
      - uses: dtolnay/rust-toolchain@<40-char-sha>  # stable (match ci.yml)
        with:
          toolchain: stable
      - uses: taiki-e/install-action@<40-char-sha>  # vX.Y.Z
        with:
          tool: cargo-nextest
      - name: chaos suite
        env:
          RIMAP_CHAOS: "1"
          RIMAP_REQUIRE_DOCKER: "1"
        run: |
          set -o pipefail
          cargo nextest run -p rimap-server -E 'binary(e2e_wire_chaos)' \
            --no-tests=fail --no-capture 2>&1 | tee chaos.log
      - name: vacuous-green guard (per-scenario presence)
        run: |
          for s in scenario1 scenario2 scenario3 scenario4a scenario4b; do
            grep -q "RIMAP_CHAOS_RAN $s" chaos.log \
              || { echo "chaos scenario $s did not run"; exit 1; }
          done
      - name: reap chaos stack (SIGKILL-safe)
        if: always()
        run: |
          docker ps -aq --filter name=rimap-chaos | xargs -r docker rm -f || true
          docker network prune -f || true
```

- [ ] **Step 2: Lint the workflow**

Run: `actionlint .github/workflows/nightly-chaos.yml && zizmor .github/workflows/nightly-chaos.yml`
Expected: no errors. Fix any unpinned `uses:` (must be 40-char SHA + version comment) or missing `permissions`.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/nightly-chaos.yml
git commit -m "ci(chaos): nightly wire-chaos suite with vacuous-green guard"
```

---

## Task 9: Docs — AGENTS.md note

**Files:**
- Modify: `AGENTS.md` (add under "Container runtime for integration tests" / near the "Wire-driven Dovecot e2e" section).

- [ ] **Step 1: Add the note**

Add a short subsection describing the nightly chaos suite: what it does (Toxiproxy in path), how to run it locally (`RIMAP_CHAOS=1 RIMAP_REQUIRE_DOCKER=1 cargo nextest run -p rimap-server -E 'binary(e2e_wire_chaos)' --no-capture`), that it is nightly-only (off PR CI via the `RIMAP_CHAOS` gate), multi-arch (no arch gate), and points at the spec. Keep it factual, ≤15 lines.

- [ ] **Step 2: Commit**

```bash
git add AGENTS.md
git commit -m "docs(chaos): document nightly wire-chaos suite in AGENTS.md"
```

---

## Task 10: Full-suite guardrail + PR-CI-invariant verification

**Files:** none (verification only).

- [ ] **Step 1: Confirm the chaos binary does NOT run on the non-chaos path**

Run: `cargo nextest run -p rimap-server -E 'binary(e2e_wire_chaos)' 2>&1 | tail` (no `RIMAP_CHAOS`, no `RIMAP_REQUIRE_DOCKER`).
Expected: tests selected, all early-return (pass), NO `RIMAP_CHAOS_RAN` markers.

- [ ] **Step 2: Confirm PR-CI e2e step stays green**

Run: `RIMAP_REQUIRE_DOCKER=1 cargo nextest run -p rimap-server -E 'binary(/e2e/)' 2>&1 | tail` (mirrors ci.yml's e2e step; `RIMAP_CHAOS` unset).
Expected: green — the chaos tests silent-skip even under `RIMAP_REQUIRE_DOCKER=1`; the other e2e binaries run against Docker (or fail loudly only if a runtime is genuinely missing, matching existing behavior).

- [ ] **Step 3: Full local CI**

Run: `just ci`
Expected: green (note `typos`/`pr-smoke` are known non-gating; the eight gating checks must pass). The chaos binary must compile and its skip path run clean here.

- [ ] **Step 4: Full chaos suite once more**

Run: `RIMAP_CHAOS=1 RIMAP_REQUIRE_DOCKER=1 cargo nextest run -p rimap-server -E 'binary(e2e_wire_chaos)' --no-capture 2>&1 | tail -40`
Expected: all five PASS; five distinct markers present.

- [ ] **Step 5: No commit** (verification task). Proceed to `/review-loop`.

---

## Self-Review notes (author)

- **Spec coverage:** AC#1 → Task 4; AC#2 → Task 5; AC#3 → Task 6; AC#4 (buffering + time) → Task 7 (4a/4b); "typed code on wire + audit + recovery, every scenario" → each scenario task asserts all three; "nightly not PR CI" → Task 8 + the `RIMAP_CHAOS` gate (Task 2) + Task 10 invariant checks. Readiness gate (proxies+upstreams) → Task 2 Step 2. SIGKILL cleanup → Task 8 Step 1. Vacuous-green guard → Task 8 Step 1 + markers seeded in Tasks 4–7.
- **Open items the implementer MUST confirm at the source (flagged inline):** exact `ureq` 3.x response API (mirror GET from `support/mailpit/harness.rs`; verify POST `send_json`/`/reset` via context7 — no in-repo POST example); `[accounts.imap]` timeout field names + `[accounts.limits] max_append_bytes` (`rimap-config/src/model.rs`, `deny_unknown_fields`); audit record field names (`rimap-audit/src/record/mod.rs`); the correct draft-safe body-fetch tool name (`chaos.fetch_message` / `chaos.download_attachment` — check the tool catalog); Toxiproxy `bandwidth` `rate` units and `timeout`/`reset_peer` attribute names (Toxiproxy README); whether a mid-connection toxic applies to the already-open scenario-2/4 connection (first-run confirmation).
- **Fallbacks are pre-authorized by the spec** for: scenario-1 connect auth-emission (relax to `tool_end`), scenario-2/4 toxic-on-open-connection, scenario-3 pre-login auth count — each recorded inline if triggered.
