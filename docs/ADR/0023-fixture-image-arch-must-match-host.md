# ADR-0023: Fixture image architecture must match the host; mismatch is a loud gate failure

## Status

Accepted (2026-08-20)

## Context

The container fixtures are digest-pinned in compose files. A pin that
resolves to a single-architecture image — the pre-#803 Dovecot pin
`sha256:34c8425…` is linux/amd64-only — runs under Rosetta/QEMU emulation on
Apple Silicon and breaks the fixture with errors that look like code bugs:
`doveadm` auth-userdb disconnects and TLS handshake EOFs across every
container-backed e2e binary (issue #811). Nothing in the container gate
(`rimap-container-gate`) inspects what was pinned; the gate's contract stops
at "can a runtime daemon be reached". The per-bump multi-arch verification
that would have caught the bad pin exists only as prose —
[ADR-0001](0001-smtp-real-socket-e2e-and-auth-taxonomy.md) prescribes
re-verifying `amd64+arm64` with `docker manifest inspect` on every bump —
and nothing enforced it.

## Decision

Every container-backed test harness verifies, immediately after
`compose up -d` succeeds, that the architecture of each image in its compose
project matches the host architecture. The parse, inspect, and compare logic
lives once, in `rimap-container-gate`, returning a mismatch verdict; each
harness maps the verdict onto its own error type exactly as it already does
for the runtime probe — the single-home rule that killed the four-copies
hazard (#675) holds for this check too. The image reference is parsed from
the compose file at runtime (the chaos project's Toxiproxy image is
tag-pinned, its Dovecot digest-pinned; the parse handles both forms), so a
Dependabot bump cannot leave the check validating a reference nobody runs.
The host arch is the compile-time target arch (`std::env::consts::ARCH`,
mapped `aarch64 → arm64`, `x86_64 → amd64`); the check stands down when that
arch is outside the known map. This assumes test binaries are never
cross-compiled or built under emulation — true of every supported developer
and CI flow today; a Rosetta-built test binary would see its emulation arch
as the host arch, a residual accepted as out of scope. On mismatch the
harness tears the project down and fails loudly at every posture — a new
`ArchMismatch` error that never maps to the silent-skip `DockerUnavailable`.
When the check cannot determine an answer (unparseable pin, unmapped host
arch, inspect failure), it stands down and compose up keeps owning the
failure. `scripts/prune-containers.sh` is exempt: it never pulls or runs the
fixture image.

## Consequences

- An arch-mismatched pin produces one named diagnostic — image reference,
  image arch, host arch, emulation symptom — instead of auth/TLS garbage.
  The failure path costs one emulated bring-up plus teardown (seconds) per
  harness start — every test in a container-backed binary pays it until the
  pin is fixed.
- Dependabot digest bumps need no Rust changes: the checked reference is
  parsed from the compose YAML at runtime, so the check cannot go stale
  against a bumped pin.
- The gate gains no network path and no pull logic; the local image after
  compose up is the image that runs, so one inspect is authoritative.
- The decision falsifies documented statements, amended in the same change:
  AGENTS.md's gate-contract paragraph gains the arch-check sentences;
  AGENTS.md's "There is no arch gate" (fixture section) and "Multi-arch, no
  arch gate" (chaos section) bullets; the chaos compose file's "no arch
  gate" comment; and each harness's `DockerUnavailable` doc comment stops
  listing "wrong arch" among the silent-skip causes (it moves to the loud
  `ArchMismatch`).

## Considered & rejected

- **Do nothing.** The failure mode recurs on every future amd64-only pin
  and costs a debugging session each time; #811's evidence shows it already
  masqueraded as test failures during a dependabot restock run. ADR-0001's
  re-verify-on-every-bump procedure is exactly the discipline whose absence
  let the bad pin land.
- **Mechanize ADR-0001's verification as a CI check on compose pins.**
  Detection-only, and only at PR time: it would not have protected the
  local runs of pre-bump commits, and #811's damage was done by exactly
  such local runs. The runtime check is needed regardless, which makes a
  parallel CI gate redundant surface for the same guarantee.
- **Registry manifest inspection before compose up.** Two grounds. First,
  an image manifest's body does not carry `architecture` — that field lives
  in the config blob, and only manifest-list *entries* name a platform — so
  a child-digest inspect cannot answer the question without a second,
  config-blob fetch. Second, with the `tag@digest` form the repo's compose
  pins use, `docker manifest inspect
  docker.io/dovecot/dovecot:2.4.4-root@sha256:34c8425…` exits 1 with
  `manifest verification failed for digest sha256:34c8425…` on Docker
  29.7.2 (reproduced 2026-08-20); the bare `image@digest` form succeeds but
  returns the arch-less image manifest, so the tool answer is incomplete
  for child digests either way. Either way the gate also gains a registry
  network dependency it does not have today.
- **Pull-then-inspect in the gate.** Gives the same answer but adds pull
  budget/timeout semantics and a network path to a gate that today spawns
  two bounded commands; an offline host with a cached image would regress.
  Post-up inspect gets the authoritative answer with one command.
- **Skip with a greppable reason.** The harnesses' skip path is
  deliberately quiet — a test matches `Err(DockerUnavailable) => return`
  and prints nothing — so a skip could not carry the diagnosis to the
  operator; a fixture defect would hide behind the same silence the gate
  philosophy forbids.
- **Emulation opt-out env var.** An acknowledged-once override would
  recreate exactly the silent foreign-arch execution the diagnostic exists
  to prevent, and no supported host currently needs it; if deliberate
  emulation ever becomes a real workflow, that is a new decision.
- **Duplicate the pin as a Rust const.** Dependabot updates only the YAML;
  the const would go stale and the check would validate a reference nobody
  runs — the same missed-copy class #675 recorded for the gate itself.
