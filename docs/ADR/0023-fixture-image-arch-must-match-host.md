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
at "can a runtime daemon be reached".

## Decision

Every container-backed test harness verifies, immediately after
`compose up -d` succeeds, that the architecture of the pinned fixture image
(read with `<tool> image inspect` on the local image, reference parsed from
the compose file at runtime) matches the host architecture
(`std::env::consts::ARCH` mapped to OCI naming). On mismatch the harness
tears the project down and fails loudly at every posture — a new
`ArchMismatch` error that never maps to the silent-skip `DockerUnavailable`.
When the check cannot determine an answer (unparseable pin, unmapped host
arch, inspect failure), it stands down and compose up keeps owning the
failure. `scripts/prune-containers.sh` is exempt: it never pulls or runs the
fixture image.

## Consequences

- An arch-mismatched pin produces one named diagnostic — image reference,
  image arch, host arch, emulation symptom — instead of auth/TLS garbage.
  The failure path costs one emulated bring-up plus teardown (seconds).
- Dependabot digest bumps need no Rust changes: the checked reference is
  parsed from the compose YAML at runtime, so the check cannot go stale
  against a bumped pin.
- The gate gains no network path and no pull logic; the local image after
  compose up is the image that runs, so one inspect is authoritative.
- A silent-skip variant was rejected partly because test source denies
  `print_stderr` — a skip could not carry the diagnosis to the operator.

## Considered & rejected

- **Do nothing.** The failure mode recurs on every future amd64-only pin
  and costs a debugging session each time; #811's evidence shows it already
  masqueraded as test failures during a dependabot restock run.
- **Registry manifest inspection before compose up.** `docker manifest
  inspect` fails outright on child (non-index) digests — verified:
  `manifest verification failed` on `sha256:34c8425…` — which is exactly
  the bad-pin shape the check must diagnose. Also adds a registry network
  dependency to the gate.
- **Pull-then-inspect in the gate.** Gives the same answer but adds pull
  budget/timeout semantics and a network path to a gate that today spawns
  two bounded commands; an offline host with a cached image would regress.
  Post-up inspect gets the authoritative answer with one command.
- **Skip with a greppable reason.** Silent skips cannot print
  (`print_stderr` is denied workspace-wide in non-test source, and the
  harnesses' skip path is deliberately quiet); a fixture defect would hide
  behind the same silence the gate philosophy forbids.
- **Duplicate the pin as a Rust const.** Dependabot updates only the YAML;
  the const would go stale and the check would validate a reference nobody
  runs — the same missed-copy class #675 recorded for the gate itself.
