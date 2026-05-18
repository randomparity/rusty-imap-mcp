# Dovecot 2.4 Multi-Arch Test Fixture

**Date:** 2026-05-13
**Status:** Spec (pending implementation plan)
**Tracking:** GitHub issue #273

## Problem

The integration-test Dovecot fixture is pinned to `docker.io/dovecot/dovecot:2.3.21`, which is published only for `linux/amd64`. Two test harnesses (`crates/rimap-server/tests/support/dovecot/harness.rs` and `crates/rimap-imap/tests/integration/support/container.rs`) silently skip on `std::env::consts::ARCH != "x86_64"` because the 2.3.21 image crashes under Rosetta on arm64 macOS (`rosetta error: unable to mmap ExecutableHeap: 12` — `ENOMEM` in dovecot worker processes). Consequence: every integration test for `rimap-imap` and `rimap-server` silently skips for any developer working on Apple Silicon, and only CI exercises that surface.

## Goal

Run the Dovecot-backed integration suites on both `linux/amd64` (CI) and `arm64 macOS` (local Apple-Silicon dev hosts) using the same fixture, same harness, same assertions. Close issue #273.

## Non-Goals

- Deduplicating the two harnesses that both call into the same compose tree.
- Switching from `docker compose` to a Rust container library.
- Supporting a non-container fallback.
- Pinning the Docker image by SHA digest (separate Dependabot/supply-chain decision).

## Approach

Single-step replacement: bump the fixture to `dovecot/dovecot:2.4.4-root`, rewrite `dovecot.conf` to 2.4 syntax, and delete the arch gate from both harnesses. No 2.3 fallback, no runtime config translation, no dual-image branching — consistent with the project's "replace, don't deprecate" rule.

The `-root` flavor (not the default `2.4.4`) is the intentional choice: upstream's default 2.4 images are rootless, run as `vmail` UID 1000, listen on non-privileged ports (`31143`/`31993`), and expect config drop-ins under `/etc/dovecot/conf.d` plus mail data under `/srv/vmail`. Our existing entrypoint writes under `/etc/dovecot`, `/var/run/dovecot`, and `/var/mail`, binds 143/993 directly, and runs as root. Adopting rootless would require simultaneously rewriting the entrypoint, ports, paths, and volume layout — a wider change than this work needs. The `-root` flavor preserves the existing fixture contract; migrating to rootless is a separate, optional follow-up.

## Components Touched

### 1. Image bump
- File: `crates/rimap-imap/tests/integration/dovecot/docker-compose.yml`
- Change: `image: docker.io/dovecot/dovecot:2.3.21` → `image: docker.io/dovecot/dovecot:2.4.4-root`
- Drop the multi-line comment that explained the amd64-only constraint.

Both `2.4.4` (rootless) and `2.4.4-root` (rootful) ship `linux/amd64` and `linux/arm64` manifests on Docker Hub (verified 2026-05-13). The plan stage confirms the tag is still the latest stable at implementation time and that the `-root` variant carries an arm64 manifest before pinning.

### 2. Config rewrite

File: `crates/rimap-imap/tests/integration/dovecot/dovecot.conf`. Rewritten from scratch in 2.4 syntax against the upstream upgrade guide (`https://doc.dovecot.org/2.4.3/installation/upgrade/2.3-to-2.4.html`) and verified at implementation time by capturing `doveconf -n` output from the running 2.4.4-root container and treating that as the source of truth. The table records the renames the upgrade guide names explicitly; anything ambiguous is resolved by `doveconf -n`, not by guessing.

| 2.3 (current) | 2.4 target | Notes |
|---|---|---|
| (none) | `dovecot_config_version = 2.4.4` | new required first line in 2.4 |
| (none) | `dovecot_storage_version = 2.4.4` | new required setting in 2.4 |
| `protocols = imap` | unchanged | |
| `ssl = required` | unchanged | tightened semantics: login_trusted_networks also requires TLS; our list is empty so test path is unaffected |
| `ssl_cert = </etc/dovecot/cert.pem` | `ssl_server_cert_file = /etc/dovecot/cert.pem` | renamed; `<file` literal-load syntax replaced with a plain path |
| `ssl_key = </etc/dovecot/key.pem` | `ssl_server_key_file = /etc/dovecot/key.pem` | same rename pattern |
| `ssl_min_protocol = TLSv1.2` | unchanged | `SSLv3` removed in 2.4; we don't use it |
| `disable_plaintext_auth = yes` | `auth_allow_cleartext = no` | renamed (and inverted polarity) |
| `login_trusted_networks =` | unchanged | empty list preserved |
| `mail_location = maildir:~/Maildir` | `mail_path = ~/Maildir` + `mail_driver = maildir` | per 2.4 rename; verify exact split via `doveconf -n` |
| `passdb { driver = passwd-file; args = scheme=PLAIN /etc/dovecot/users }` | `passdb passwd-file { passwd_file_path = /etc/dovecot/users; default_password_scheme = PLAIN }` | sections require names in 2.4; `args =` removed in favour of named settings |
| `userdb { driver = static; args = uid=1000 gid=1000 home=/var/mail/%u }` | `userdb static { fields { uid = 1000; gid = 1000; home = /var/mail/%{user} } }` | named section; static-userdb fields are a nested block in 2.4 (not `fields = ...`); `%u` removed, use `%{user}` |
| `namespace inbox { … mailbox Drafts/Junk/Sent/Trash { special_use=…; auto=subscribe } }` | structurally unchanged | already named `inbox`; mailbox blocks already named |
| `service imap-login { inet_listener imap { port=143 } inet_listener imaps { port=993; ssl=yes } }` | structurally unchanged | already-named sections satisfy 2.4 rule; we still bind 143/993 inside the container because we run the `-root` flavor |
| `log_path = /dev/stderr` / `info_log_path = /dev/stderr` / `debug_log_path = /dev/stderr` | unchanged | `auth_debug`/`mail_debug` removed but we don't use them |

**Variable syntax:** anywhere the existing config or entrypoint emits a one-letter `%`-variable (only `%u` in `userdb static.fields.home` here), it must become the new `%{...}` form (e.g., `%{user}`). All one-letter variables were removed in 2.4.

**Implementation-time follow-up:** the `-root` image still ships baked-in defaults under `/etc/dovecot/conf.d/`. Our compose mounts a single `dovecot.conf` over `/etc/dovecot/dovecot.conf`, so confirm during bring-up that the mounted file does not `!include conf.d/*.conf`. If it does, drop the include or mount an empty `conf.d/` over the inherited one to prevent upstream defaults from overriding our test config.

### 3. Harness arch gate removal

**`crates/rimap-server/tests/support/dovecot/harness.rs`** (lines 48–73). `check_prerequisites` collapses to:

```rust
fn check_prerequisites() -> Result<(), HarnessError> {
    let require_runtime = std::env::var("RIMAP_REQUIRE_DOCKER").is_ok();
    if !runtime_available() {
        return if require_runtime {
            Err(HarnessError::ComposeFailed(
                "neither docker nor podman found but RIMAP_REQUIRE_DOCKER=1".into(),
            ))
        } else {
            Err(HarnessError::DockerUnavailable)
        };
    }
    Ok(())
}
```

Module `//!` doc comment (lines 1–6) loses the "silently skips on non-x86_64" sentence.

**`crates/rimap-imap/tests/integration/support/container.rs`** — equivalent change at lines 259–276 plus rustdoc at lines 86–95.

### 4. Caller-side doc comment sweep

- `crates/rimap-server/tests/e2e.rs:5`
- `crates/rimap-server/tests/e2e_wire.rs:9`
- `crates/rimap-imap/tests/integration/dovecot.rs:2`

Each currently mentions the arch skip; each gets a one-line update reflecting the new "container runtime required on any arch" reality.

### 5. AGENTS.md

Lines 72–108 currently encode the Rosetta failure mode and arch-gate rationale. Replace with a shorter section: container runtime is required on any host; `RIMAP_REQUIRE_DOCKER=1` flips silent-skip to a hard error when the runtime is missing; no arch caveats.

### 6. Memory cleanup

Delete `/Users/dave/.claude/projects/-Users-dave-src-rusty-imap-mcp/memory/project_dovecot_rosetta_gate.md` and remove its line from `MEMORY.md`. The memo exists specifically to discourage removing the arch gate; once the gate is gone the memo is actively misleading.

## Out of Scope

- Deduplicating the two harnesses (`rimap-server` and `rimap-imap` both have a near-identical `runtime_available` + prerequisite-check stack).
- Replacing `docker compose` with a Rust container library.
- Image digest pinning.
- Adding a non-container fallback for environments without Docker/Podman.

## Verification

The migration is complete only when verification passes on **both** `linux/amd64` and `arm64 macOS`. Asymmetric verification is the known failure mode.

### Bring-up (manual, both arches)

1. `docker pull docker.io/dovecot/dovecot:2.4.4-root`; confirm host-native manifest with `docker image inspect docker.io/dovecot/dovecot:2.4.4-root | jq '.[].Architecture'` and that it reports `arm64` on Apple Silicon (and `amd64` on Linux CI).
2. `RIMAP_DOVECOT_HOST_PORT=9993 RIMAP_DOVECOT_HOST_PORT_STARTTLS=1143 docker compose -p smoke up -d`
3. `docker compose -p smoke exec dovecot id` reports `uid=0` (the `-root` flavor runs as root, satisfying our entrypoint's `/etc/dovecot` / `/var/mail` writes and 143/993 bind).
4. `docker compose -p smoke logs dovecot` — no `dovecot_config_version` upgrade-required error, no unknown-setting errors, `[entrypoint] ready` line emitted.
5. `docker compose -p smoke exec dovecot doveconf -n` returns a config file with no `Conflicting/unknown setting` warnings. Capture this output and diff it against the committed `dovecot.conf` for parity — any drift indicates an inherited `conf.d/` default sneaking through.
6. `openssl s_client -connect 127.0.0.1:9993 -servername localhost` returns the self-signed cert.
7. `docker exec <name> doveadm mailbox list -u rimap-test` returns INBOX and the seeded sub-folders without `Disconnected unexpectedly`.
8. `docker compose -p smoke down -v --remove-orphans` cleans up.

### Automated (CI on amd64, local on arm64 macOS)

9. `RIMAP_REQUIRE_DOCKER=1 cargo nextest run -p rimap-imap --test dovecot --locked`
10. `RIMAP_REQUIRE_DOCKER=1 cargo nextest run -p rimap-server --test e2e --locked`
11. `RIMAP_REQUIRE_DOCKER=1 cargo nextest run -p rimap-server --test e2e_wire --locked`

Each suite must pass on both arches. Silent-skip on arm64 = failure of this migration's central goal.

### Specific risks

- **`-root` image deprecation.** Upstream's strategic direction is rootless; the `-root` flavor exists to ease migration. If upstream stops publishing `-root` images for 2.5+, the next Dovecot version bump will force a rootless redesign of the entrypoint, ports, paths, and volumes. That's a known, accepted follow-up — not blocker for #273.
- **`case_11` force-recreate flow** (rimap-imap). Relies on the shared volume persisting `cert.pem` / `key.pem` across `docker compose up --force-recreate` so the pinned TLS fingerprint stays stable. 2.4 doesn't touch volume semantics, but this test exercises a real TCP/TLS race and is the most likely regression site.
- **`doveadm -u rimap-test`**. 2.4 tightened `doveadm` USER-env-var semantics, but our calls already pass `-u`, so should be unaffected.
- **Entrypoint wait-for-LISTEN ordering**. The current `entrypoint.sh` parses `/proc/net/tcp{,6}` to wait for port 993 before publishing readiness markers; 2.4's child-process startup order may differ. Bring-up step 4 + automated step 11 jointly cover this.
- **Inherited `/etc/dovecot/conf.d/` defaults.** The upstream image bakes in default drop-ins; bring-up step 5 (`doveconf -n` diff) is the explicit guard.

### No-silent-skip regression guard

Run `cargo nextest run -p rimap-server --test e2e_wire wire_e2e_full_session_draft_safe` *without* `RIMAP_REQUIRE_DOCKER=1` on a host with Docker available; the test must execute and pass, not return "0 tests executed". If silent-skip re-appears, the harness has regressed.

## Implementation Order

The plan derived from this spec should sequence work so that intermediate states are testable:

1. Bring up the new image with an exploratory config on arm64 macOS (offline, not committed).
2. Extract `doveconf -n` output as the source of truth for the rewritten `dovecot.conf`.
3. Commit the new compose tree (image bump + config) on a branch.
4. Remove the arch gates from both harnesses on the same branch — there's no env-var bypass today, so a local patch and a gate removal are the same edit. Run the suites on arm64 macOS at this point.
5. Update AGENTS.md and caller-side doc comments to reflect the new "container runtime required on any arch" rule.
6. Verify on CI (linux/amd64) before merging.
7. Delete the obsolete memory note (`project_dovecot_rosetta_gate.md`) and its `MEMORY.md` index line.

## Open Questions for the Plan Stage

1. **Exact image tag.** Plan-time check: is `2.4.4-root` still latest stable in the `-root` line, or has `2.4.5-root+` shipped? Pin to whatever is current and confirm the tag carries an arm64 manifest.
2. **`mail_location` replacement form.** `mail_path` + `mail_driver` is the rename per the 2.4 docs; `doveconf -n` from the running image is authoritative.
3. **Static `userdb` field block.** This spec writes `userdb static { fields { uid = 1000; ... } }` per the upstream 2.4 static-userdb docs. Confirm against `doveconf -n` — if upstream emits a flat form instead of a nested block, match what `doveconf -n` produces.
4. **Inherited `/etc/dovecot/conf.d/*.conf` defaults.** The upstream image ships drop-ins. Bring-up step 5 catches any conflict; if a drop-in does override one of our settings, either mount an empty `conf.d/` over the inherited one or drop the offending include line.
5. **Are there other `%`-variables hiding outside `dovecot.conf`?** Sweep `entrypoint.sh`, fixture `.eml` files, and any test harness arguments for one-letter `%` variables before declaring the migration complete.
