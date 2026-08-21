# Issue #811 — Guard against arch-mismatched container fixture pins; fix `test-fast` filter

Date: 2026-08-20
Issue: https://github.com/randomparity/rusty-imap-mcp/issues/811
ADR: [ADR-0023](../../ADR/0023-fixture-image-arch-must-match-host.md)
Branch: `feat/guard-arch-mismatched-container-pin-811`

## Problem

When a Dovecot compose pin resolves to a single-architecture image (the
pre-#803 pin `sha256:34c8425…` is linux/amd64-only), Docker Desktop on Apple
Silicon runs it under Rosetta/QEMU emulation and the fixture breaks in ways
that look like code bugs: `doveadm` user lookups die with
`auth-userdb … Unexpectedly disconnected from auth service`, and IMAPS
handshakes fail with `tls handshake eof`. #803 fixed the pin incidentally
(multi-arch manifest list), but nothing guards against regressing, and
`just test-fast`'s binary filter is missing eight container-backed binaries,
so the inner loop compiles and runs every container suite and surfaces
fixture failures as unit failures.

Verified on this host (Apple M5 Max, Docker 29.7.2):

- `docker manifest inspect` on the multi-arch pins returns a manifest list /
  OCI index covering `amd64` + `arm64` (dovecot, toxiproxy, mailpit) — the
  current pins cannot false-fail the new check on CI.
- `docker manifest inspect` on the old amd64-only child digest fails outright
  (`manifest verification failed for digest …`) — registry-side manifest
  inspection is unusable for exactly the bad-pin shape we need to diagnose.
- `docker image inspect --format '{{.Architecture}}'
  docker.io/dovecot/dovecot:2.4.4-root@sha256:d6b2f80…` on this arm64 host
  prints `arm64` — the local inspect reports the arch of the image compose
  actually runs.

## Goals

1. An arch-mismatched fixture pin fails fast with a named diagnostic: the
   image reference, the image's architecture, the host's architecture, and a
   pointer to the emulation symptom.
2. `just test-fast` runs only non-container tests: every container-backed
   test binary is excluded, and the exclusion list cannot silently drift from
   the binaries that link container harnesses.
3. The gate's documented philosophy is preserved: only a host that genuinely
   cannot run containers silent-skips; everything else stays loud.

## Non-goals

- No production (`src/`) code changes; test infrastructure only.
- No compose pin bumps (Dependabot owns pins).
- No `.github/workflows/` changes; no new runtime dependencies.
- No change to runtime selection (`RIMAP_CONTAINER_TOOL` autodetect, daemon
  probe, `RIMAP_REQUIRE_DOCKER` semantics).
- Chaos nightly `RIMAP_CHAOS` gating and the Proton Bridge suite
  (`PROTON_BRIDGE_TEST=1`) are untouched.

## Design

### 1. Architecture check lives in `rimap-container-gate`

The gate crate is the single home for container prerequisites (AGENTS.md).
It gains four small public items (`crates/rimap-container-gate/src/lib.rs`):

```rust
/// Host architecture in OCI image naming ("arm64", "amd64"), or `None`
/// when the compile-time arch is not one the check can judge.
pub fn host_arch() -> Option<&'static str>

/// The pinned image reference for `service` in a compose file, parsed by
/// line scan (no YAML dependency). `None` when the service or its
/// `image:` key cannot be found.
pub fn pinned_image(compose: &std::path::Path, service: &str) -> Option<String>

/// The architecture of a *local* image as `<tool> image inspect` reports
/// it. `None` when the inspect fails for any reason — the check then
/// stands down and compose up owns the failure.
pub fn image_arch(tool: &str, image_ref: &str) -> Option<String>

/// Pure: the loud-failure reason when `image_arch` differs from
/// `host_arch`, else `None`.
pub fn arch_mismatch_reason(image_ref: &str, image_arch: &str, host_arch: &str) -> Option<String>
```

Decisions inside the API:

- **Host arch is `std::env::consts::ARCH`** mapped `aarch64 → arm64`,
  `x86_64 → amd64`. Test binaries are never cross-compiled in this repo
  (CI builds each platform natively), so the compile-time arch is the host
  arch. Any other value returns `None` and the check stands down — it never
  guesses.
- **The image reference is parsed from the compose file at runtime**, not
  duplicated as a Rust const. Dependabot bumps digests in the YAML only; a
  const would silently go stale and make the check validate a ref nobody
  runs. The parser is a ~20-line line scan (track the two-space-indented
  service key, capture the `image:` value inside it), unit-tested against
  the real fixture files' shape. No `serde_yaml` dependency for a two-field
  need.
- **The check runs after `compose up -d` succeeds**, before readiness
  polling. The image is local by then, so one `image inspect` answers
  without any new network path. On mismatch the harness tears the compose
  project down and returns the loud error. The cost on the failure path is
  one emulated bring-up (seconds) — acceptable against the alternative of
  giving the gate pull/budget/network semantics.
- **Any indeterminate answer stands down** (`None` → no verdict → proceed).
  Compose up already owns "image cannot run" failures loudly; the check
  only adds the *named arch diagnosis* when it can determine one. This
  keeps the documented asymmetry: the gate never turns a maybe into a skip
  or a false failure.

### 2. Harness wiring (four call sites)

Each container harness (`rimap-imap`
`tests/integration/support/container.rs`, `rimap-server`
`tests/support/{dovecot,mailpit,chaos}/harness.rs`) gains, immediately
after its compose up succeeds:

```rust
if let Some(image) = rimap_container_gate::pinned_image(&compose_dir.join(COMPOSE_FILE), "dovecot") {
    if let (Some(arch), Some(host)) = (
        rimap_container_gate::image_arch(runtime(), &image),
        rimap_container_gate::host_arch(),
    ) {
        if let Some(reason) = rimap_container_gate::arch_mismatch_reason(&image, &arch, &host) {
            compose_down(&project, &compose_dir);
            return Err(HarnessError::ArchMismatch(reason));
        }
    }
}
```

- `HarnessError` gains `ArchMismatch(String)` in each harness. It maps to a
  **hard failure at every posture** — it is never `DockerUnavailable` and
  never silent-skips, not even without `RIMAP_REQUIRE_DOCKER`. An
  arch-mismatched pin is a fixture defect, not an absent host capability;
  the documented contract already makes "an unpullable image" a hard
  failure at every posture, and this is the same class. (The harnesses'
  skip path is deliberately quiet — a test matches
  `Err(DockerUnavailable) => return` and prints nothing — so a skip could
  not carry the diagnosis to the operator.)
- The chaos harness checks both images (dovecot, toxiproxy); the mailpit
  harness checks mailpit; the two Dovecot harnesses check dovecot.
- `DockerUnavailable`'s doc comment already promises "wrong arch" lands in
  the loud path — this change makes the promise true; the comment is
  updated to name `ArchMismatch`.

### 3. `test-fast` filter from a shared source

- New file `scripts/container-test-binaries.txt`: one binary name per line,
  the complete container-backed set (verified by scanning the tree for
  `DovecotHarness|MailpitHarness|ChaosHarness|ConnectedHarness` in test
  binaries): `dovecot`, `e2e`, `e2e_smtp`, `e2e_smtp_real`, `e2e_wire`,
  `e2e_wire_cancellation`, `e2e_wire_chaos`, `e2e_wire_destructive`,
  `e2e_wire_fault_injection`, `e2e_wire_folder_management`,
  `e2e_wire_multi_account_advertisement`, `e2e_wire_tool_advertisement`.
- The `test-fast` recipe becomes a shebang recipe that builds the `-E`
  filter from the file (`binary(&name)` joined with `|` inside `not (…)`),
  keeping `binary(proptest_html_lookalike)` as an explicit, commented
  second exclusion (slow, not container-backed).
- **Drift guard**: a test in `rimap-container-gate` (the shared home; it is
  a dev-dependency of both harness-owning crates and can reach the
  workspace root via `CARGO_MANIFEST_DIR`) scans `crates/*/tests/**/*.rs`
  (excluding any `support/` path segment), maps file stem → binary name,
  and fails when (a) a test binary references a container harness type but
  is missing from the list, or (b) a list entry matches no such file. This
  runs in every `just test` / CI test job — a gate that runs where the
  drift would happen, not in a script only `just ci` reaches.
- The `test-fast` doc comment and the AGENTS.md description stop saying
  "five heaviest binaries" and say "every container-backed binary plus the
  slow HTML-lookalike proptest".

### 4. `scripts/prune-containers.sh` — documented exemption

Pruning removes stale `rimap-it-*` resources; it never pulls or runs the
fixture image, so image architecture cannot affect it. A header comment
records the exemption explicitly (the issue allows "the same treatment or
a documented exemption") so a future reader does not re-derive it.

### 5. AGENTS.md

- Troubleshooting note: an amd64-only digest pin on Apple Silicon manifests
  as `doveadm … Unexpectedly disconnected from auth service` / TLS
  handshake EOF, not as an arch error; the gate now names it.
- The gate-contract paragraph gains one sentence: fixture image
  architecture is checked against the host after compose up, mismatch is a
  loud failure at every posture, and `prune-containers.sh` is exempt
  because it never runs the fixture image.

## Threat model note

Not security-relevant: the new parsing reads repo-owned, in-tree fixture
YAML; no untrusted input, no new network path, no widened entry point, no
dependency change. The `image inspect` output is parsed as a bare string
comparison against a mapped constant.

## Testing

- **Gate unit tests** (no container runtime needed, mirroring the existing
  `select_runtime` test style): `pinned_image` against inline YAML fixtures
  shaped like the real files (dovecot single-service, chaos two-service,
  missing service, missing image key, comment lines); `host_arch` mapping
  (aarch64/x86_64 → Some, exotic → None); `arch_mismatch_reason` match /
  mismatch / message content (names ref, both arches).
- **`image_arch`**: thin wrapper over `Command`; covered indirectly by the
  container-gated integration path and by the drift-guard test's static
  checks. Its failure contract (None on any error) is one match arm.
- **Drift-guard test**: positive case (the real tree passes), and mutation
  cases via tempdirs? No — it reads the real tree. Its bite is proven by
  the TDD red step: adding a fake harness-referencing test file turns it
  red, removing it turns it green.
- **Harness mapping tests**: each harness's existing pure `gate()`
  mapping test style extends to `ArchMismatch` (always loud, message
  carried).
- **Manual verification on this host**: temporarily pin the old amd64-only
  digest `sha256:34c8425…` in a scratch copy of the compose file, run one
  e2e test, observe the named `ArchMismatch` failure (not auth/TLS
  garbage), restore. Also `docker image inspect` on the current pin
  reports `arm64` here — the suite stays green.

## Acceptance criteria

| # | Criterion (source) | Where |
|---|---|---|
| 1 | Arch-mismatched pin fails fast, naming both arches and the pin (issue Expected ¶1) | gate `arch_mismatch_reason` + `ArchMismatch` wiring |
| 2 | `just test-fast` excludes every container-backed binary (issue Expected ¶2) | shared list + recipe + drift guard |
| 3 | Only genuine can't-run hosts silent-skip (issue Context, AGENTS.md) | `ArchMismatch` never maps to `DockerUnavailable` |
| 4 | `prune-containers.sh` same treatment or documented exemption (issue Proposed 1) | header comment |
| 5 | AGENTS.md troubleshooting note (issue Proposed 3) | AGENTS.md |
| 6 | No new dependencies, no workflow changes, philosophy preserved (charter exclusions) | whole diff |
