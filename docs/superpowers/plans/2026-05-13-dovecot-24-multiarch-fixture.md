# Dovecot 2.4 Multi-Arch Test Fixture Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the amd64-only `dovecot/dovecot:2.3.21` test fixture with multi-arch `dovecot/dovecot:2.4.4-root`, drop the `std::env::consts::ARCH != "x86_64"` silent-skip gates, and make the integration suites run on both `linux/amd64` (CI) and `arm64 macOS` (local Apple Silicon). Closes GitHub issue #273.

**Architecture:** Single-step replacement. Bump the compose image, rewrite `dovecot.conf` from 2.3 to 2.4 syntax (named `passdb`/`userdb` sections, renamed SSL/auth settings, nested `fields { }` block, `%{user}` variables), delete arch gates from both harnesses, refresh AGENTS.md and caller-side doc comments, remove the obsolete memory note. The `-root` flavor preserves the existing rootful entrypoint contract (ports 143/993, `/etc/dovecot`, `/var/mail`). Rootless migration is an explicit non-goal.

**Tech Stack:** Dovecot 2.4.4 (Docker image, `-root` flavor, multi-arch amd64+arm64), Docker / Podman, `docker compose`, Rust integration test harness (`crates/rimap-server/tests/support/dovecot/harness.rs` and `crates/rimap-imap/tests/integration/support/container.rs`).

**Spec:** `docs/superpowers/specs/2026-05-13-dovecot-24-multiarch-fixture-design.md`

**Branch:** continues `spec/dovecot-24-multiarch-fixture` (already has spec commit). Each task below is one logical commit on this branch.

---

## File Structure

Files modified by this plan (no new files created):

- `crates/rimap-imap/tests/integration/dovecot/docker-compose.yml` — image tag bump
- `crates/rimap-imap/tests/integration/dovecot/dovecot.conf` — rewrite to 2.4 syntax
- `crates/rimap-server/tests/support/dovecot/harness.rs` — drop arch gate (lines 48–73, rustdoc lines 1–6)
- `crates/rimap-imap/tests/integration/support/container.rs` — drop arch gate (lines 258–283, rustdoc lines 84–96)
- `crates/rimap-server/tests/e2e.rs` — rustdoc line 5 (skip caveat)
- `crates/rimap-server/tests/e2e_wire.rs` — rustdoc lines 8–9 (skip caveat)
- `crates/rimap-imap/tests/integration/dovecot.rs` — rustdoc line 3 (skip caveat)
- `AGENTS.md` — replace lines 67–116 ("Container runtime …" + "Wire-driven Dovecot e2e" arch caveat) with arch-agnostic wording
- `/Users/dave/.claude/projects/-Users-dave-src-rusty-imap-mcp/memory/project_dovecot_rosetta_gate.md` — delete
- `/Users/dave/.claude/projects/-Users-dave-src-rusty-imap-mcp/memory/MEMORY.md` — drop the matching index line

Files NOT modified (deliberate):
- `crates/rimap-imap/tests/integration/dovecot/entrypoint.sh` — works against `-root` flavor unchanged
- `crates/rimap-imap/tests/integration/dovecot/users` — passwd-file format unchanged in 2.4
- `crates/rimap-imap/tests/integration/dovecot/fixtures/*.eml` — sample emails are content, not config

---

### Task 1: Verify image availability and arm64 manifest

**Files:** none (verification only).

- [ ] **Step 1: Pull the target image**

Run:
```bash
docker pull docker.io/dovecot/dovecot:2.4.4-root
```
Expected: `Pull complete` for the host-native variant. If `2.4.4-root` no longer exists, list available `-root` tags with `docker run --rm anchore/skopeo:latest list-tags docker://docker.io/dovecot/dovecot | grep -E '^\s+"2\.4\.[0-9]+-root"'` and pick the highest 2.4.x. Record the chosen tag and use it consistently from this point on. Anywhere the plan says `2.4.4-root`, substitute the chosen tag.

- [ ] **Step 2: Confirm the manifest has both amd64 and arm64 variants**

Run:
```bash
docker manifest inspect docker.io/dovecot/dovecot:2.4.4-root | jq '.manifests[].platform | "\(.os)/\(.architecture)"'
```
Expected: output contains both `linux/amd64` and `linux/arm64`. If either is missing, stop — the spec's central premise (multi-arch availability) does not hold for the chosen tag.

- [ ] **Step 3: Confirm host-native image is the right architecture**

Run:
```bash
docker image inspect docker.io/dovecot/dovecot:2.4.4-root | jq -r '.[].Architecture'
```
Expected on Apple Silicon: `arm64`. Expected on Linux CI runners: `amd64`. Mismatch means Docker pulled the wrong variant (rare with manifest lists, but worth confirming).

- [ ] **Step 4: No commit for this task** — verification only.

---

### Task 2: Capture upstream image's `doveconf -n` baseline

**Files:** scratch directory under `/tmp`, none committed.

Purpose: produce a `doveconf -n` reference output from a minimally-valid 2.4 config running inside the `2.4.4-root` image. This output is the source of truth for the rewritten `dovecot.conf` in Task 3 — anything we write must round-trip through `doveconf -n` without producing `Unknown setting` or `Conflicting setting` warnings.

- [ ] **Step 1: Create a scratch config**

Run:
```bash
mkdir -p /tmp/dovecot-2.4-probe
cat > /tmp/dovecot-2.4-probe/dovecot.conf <<'EOF'
dovecot_config_version = 2.4.4
dovecot_storage_version = 2.4.4

protocols = imap

ssl = required
ssl_server_cert_file = /etc/dovecot/cert.pem
ssl_server_key_file = /etc/dovecot/key.pem
ssl_min_protocol = TLSv1.2

auth_allow_cleartext = no
login_trusted_networks =

mail_driver = maildir
mail_path = ~/Maildir

passdb passwd-file {
  passwd_file_path = /etc/dovecot/users
  default_password_scheme = PLAIN
}

userdb static {
  fields {
    uid = 1000
    gid = 1000
    home = /var/mail/%{user}
  }
}

namespace inbox {
  inbox = yes
  separator = /

  mailbox Drafts {
    special_use = \Drafts
    auto = subscribe
  }
  mailbox Junk {
    special_use = \Junk
    auto = subscribe
  }
  mailbox Sent {
    special_use = \Sent
    auto = subscribe
  }
  mailbox Trash {
    special_use = \Trash
    auto = subscribe
  }
}

service imap-login {
  inet_listener imap {
    port = 143
  }
  inet_listener imaps {
    port = 993
    ssl = yes
  }
}

log_path = /dev/stderr
info_log_path = /dev/stderr
debug_log_path = /dev/stderr
EOF
```

- [ ] **Step 2: Run `doveconf -n` against the scratch config**

Run:
```bash
docker run --rm \
  -v /tmp/dovecot-2.4-probe/dovecot.conf:/etc/dovecot/dovecot.conf:ro \
  docker.io/dovecot/dovecot:2.4.4-root \
  doveconf -n 2>/tmp/dovecot-2.4-probe/stderr.log > /tmp/dovecot-2.4-probe/canonical.conf
echo "--- stderr ---"
cat /tmp/dovecot-2.4-probe/stderr.log
echo "--- canonical.conf head ---"
head -40 /tmp/dovecot-2.4-probe/canonical.conf
```
Expected: `stderr.log` contains no lines matching `Unknown setting`, `Conflicting setting`, or `Error`. `canonical.conf` starts with `# 2.4.4 ...` and lists the settings in canonical 2.4 form.

- [ ] **Step 3: Triage any warnings**

If `stderr.log` reports `Unknown setting <foo>`, that setting is misnamed or has been renamed again — consult `https://doc.dovecot.org/2.4.4/installation/upgrade/2.3-to-2.4.html` or run `docker run --rm docker.io/dovecot/dovecot:2.4.4-root doveconf -a | grep -i <foo>` to find the canonical name. Update `/tmp/dovecot-2.4-probe/dovecot.conf` and rerun Step 2 until warnings are clean.

If `stderr.log` reports `Conflicting setting`, the upstream image's baked-in `/etc/dovecot/conf.d/*.conf` is overriding our value. Confirm with:
```bash
docker run --rm docker.io/dovecot/dovecot:2.4.4-root ls /etc/dovecot/conf.d/
```
If non-empty, plan to mount an empty directory over `/etc/dovecot/conf.d/` in Task 4. (The committed compose file uses a single `dovecot.conf` mount; the override is needed only if the upstream `dovecot.conf` `!include`s `conf.d/`.)

- [ ] **Step 4: No commit for this task** — `/tmp/dovecot-2.4-probe/dovecot.conf` is the input to Task 3. Keep it on disk.

---

### Task 3: Rewrite `dovecot.conf` to 2.4 syntax

**Files:**
- Modify: `crates/rimap-imap/tests/integration/dovecot/dovecot.conf` (full rewrite)

- [ ] **Step 1: Copy the validated scratch config into the repo**

Run:
```bash
cp /tmp/dovecot-2.4-probe/dovecot.conf \
  crates/rimap-imap/tests/integration/dovecot/dovecot.conf
```

- [ ] **Step 2: Diff against the previous version to confirm intent**

Run:
```bash
git --no-pager diff crates/rimap-imap/tests/integration/dovecot/dovecot.conf
```
Expected: diff matches the rename table in the spec (Section 2). Every removed line maps to a renamed/restructured replacement; no settings are silently dropped.

- [ ] **Step 3: Stage and commit**

Run:
```bash
git add crates/rimap-imap/tests/integration/dovecot/dovecot.conf
git commit -m "$(cat <<'EOF'
test(fixture): rewrite dovecot.conf to 2.4 syntax (#273)

Named passdb/userdb sections, dovecot_config_version preamble,
ssl_server_{cert,key}_file rename, auth_allow_cleartext = no,
nested userdb static.fields block, %{user} variable.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: Bump compose image tag

**Files:**
- Modify: `crates/rimap-imap/tests/integration/dovecot/docker-compose.yml`

- [ ] **Step 1: Edit the compose file**

Replace lines 2–10 (the multi-line amd64-only comment plus the `image:` line) with:

```yaml
services:
  dovecot:
    # Pinned to the multi-arch `-root` flavor (2.4.x default images are
    # rootless on non-privileged ports; the `-root` variant preserves the
    # rootful contract this fixture's entrypoint relies on: writes to
    # /etc/dovecot, /var/mail, /var/run/dovecot and binds 143/993).
    image: docker.io/dovecot/dovecot:2.4.4-root
```

Keep everything from `container_name:` onwards unchanged.

- [ ] **Step 2: If Task 2 Step 3 found inherited `conf.d/` defaults, also override the directory**

Only if needed (skip this step otherwise). A bare path under `volumes:` does **not** mask the image contents — it creates an anonymous volume that Docker initializes from the image's directory at first run, so the upstream defaults would still leak through. Use a real empty tmpfs instead. Add a top-level `tmpfs:` service key (sibling of `volumes:`, `image:`, etc.) to the `dovecot` service:

```yaml
    tmpfs:
      # Empty tmpfs mounted over /etc/dovecot/conf.d so upstream image
      # defaults cannot override the settings in our dovecot.conf. A
      # bare-path entry under `volumes:` would NOT do this — Docker
      # populates anonymous volumes from the image's directory contents
      # at first run.
      - /etc/dovecot/conf.d
```

If the long form is preferred (e.g., because tmpfs sizing matters), the equivalent under `volumes:` is:
```yaml
      - type: tmpfs
        target: /etc/dovecot/conf.d
```

- [ ] **Step 3: Manual bring-up to validate**

Run:
```bash
RIMAP_DOVECOT_HOST_PORT=9993 \
RIMAP_DOVECOT_HOST_PORT_STARTTLS=1143 \
docker compose \
  -p smoke \
  -f crates/rimap-imap/tests/integration/dovecot/docker-compose.yml \
  up -d
sleep 3
docker compose -p smoke -f crates/rimap-imap/tests/integration/dovecot/docker-compose.yml logs dovecot | tail -30
```
Expected: log output includes `[entrypoint] start` ... `[entrypoint] ready`. No `dovecot_config_version` upgrade-required errors, no `Unknown setting`, no `Disconnected unexpectedly`.

- [ ] **Step 4: Confirm container UID and ports**

Run:
```bash
docker compose -p smoke -f crates/rimap-imap/tests/integration/dovecot/docker-compose.yml exec dovecot id
docker compose -p smoke -f crates/rimap-imap/tests/integration/dovecot/docker-compose.yml exec dovecot doveconf -n > /tmp/dovecot-2.4-probe/runtime.conf 2>&1
diff -u /tmp/dovecot-2.4-probe/canonical.conf /tmp/dovecot-2.4-probe/runtime.conf
```
Expected: `id` reports `uid=0(root)`. `diff` exits 0 with empty output — runtime `doveconf -n` matches the Task-2 baseline exactly.

**This check fails closed.** If `diff` exits non-zero, do not proceed. A non-empty diff means an inherited `conf.d/` default or a settings-format mismatch is silently changing the runtime config; this is the exact failure mode Task 2 Step 3 and this step were designed to catch. Triage:
- If the diff is purely whitespace/comment lines, normalize with `diff -u -w` and re-evaluate.
- If real settings differ (e.g., upstream `conf.d/` set `ssl_min_protocol = TLSv1.3`), apply the conditional `tmpfs:` override from Step 2 and re-run the bring-up loop (Steps 3 → 4) until `diff` reports clean.
- If `doveconf -n` reorders entries deterministically but values match, treat that as parity and document the canonical form by re-capturing `/tmp/dovecot-2.4-probe/canonical.conf` from the running container (`cp runtime.conf canonical.conf`) — the runtime output is authoritative.

- [ ] **Step 5: TLS handshake smoke test**

Run:
```bash
echo "QUIT" | openssl s_client -connect 127.0.0.1:9993 -servername localhost -verify_return_error 2>&1 | head -10
```
Expected: handshake succeeds (a `subject=CN = rimap-test-dovecot` line appears); `verify error:num=18:self-signed certificate` is expected and acceptable.

- [ ] **Step 6: doveadm mailbox sanity check**

Run:
```bash
docker compose -p smoke -f crates/rimap-imap/tests/integration/dovecot/docker-compose.yml \
  exec dovecot doveadm mailbox list -u rimap-test
```
Expected: lists `INBOX` and the seeded sub-mailboxes (`INBOX/Drafts`, `INBOX/Sent`, etc.) without `Disconnected unexpectedly` errors.

- [ ] **Step 7: Tear down**

Run:
```bash
docker compose -p smoke -f crates/rimap-imap/tests/integration/dovecot/docker-compose.yml down -v --remove-orphans
```

- [ ] **Step 8: Stage and commit**

Run:
```bash
git add crates/rimap-imap/tests/integration/dovecot/docker-compose.yml
git commit -m "$(cat <<'EOF'
test(fixture): bump dovecot image to 2.4.4-root multi-arch (#273)

Replaces amd64-only 2.3.21 with the multi-arch -root flavor. Manifest
verified for both linux/amd64 and linux/arm64. The -root variant
preserves the existing rootful entrypoint contract (ports 143/993,
/etc/dovecot, /var/mail).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 5: Drop arch gate from `rimap-server` harness

**Files:**
- Modify: `crates/rimap-server/tests/support/dovecot/harness.rs` (lines 1–6 rustdoc, lines 48–73 `check_prerequisites`)

- [ ] **Step 1: Update the module rustdoc**

Replace lines 1–6:

```rust
//! Dovecot container harness lifted from the original
//! `crates/rimap-server/tests/e2e.rs`. Honors the same env vars
//! (`RIMAP_CONTAINER_TOOL`, `RIMAP_REQUIRE_DOCKER`) and silently skips
//! on non-x86_64 hosts or when no container runtime is available.
//! See `AGENTS.md` "Container runtime for integration tests".
```

with:

```rust
//! Dovecot container harness lifted from the original
//! `crates/rimap-server/tests/e2e.rs`. Honors the same env vars
//! (`RIMAP_CONTAINER_TOOL`, `RIMAP_REQUIRE_DOCKER`) and silently skips
//! when no container runtime is available.
//! See `AGENTS.md` "Container runtime for integration tests".
```

- [ ] **Step 2: Collapse `check_prerequisites`**

Replace the existing function (currently lines 48–73) with:

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

- [ ] **Step 3: Compile-check the crate**

Run:
```bash
cargo check -p rimap-server --tests --locked
```
Expected: clean compile. Warnings about unused `std::env::consts::ARCH` should not appear (the symbol was inline-used, not imported).

- [ ] **Step 4: Run the wire e2e suite on this host (arm64 macOS)**

Run:
```bash
RIMAP_REQUIRE_DOCKER=1 cargo nextest run -p rimap-server --test e2e_wire --locked
```
Expected: the suite executes (not silent-skipped) and passes. Wall-clock target: 30s–120s on a warm machine; bring-up dominates. If a test fails:
- Inspect `docker compose -p <project> logs dovecot` while the harness still has the container alive (the harness tears down on drop, so add a `sleep 60` breakpoint locally if needed). Common failure modes: `Unknown setting` (config drift not caught in Task 2), `doveadm Disconnected unexpectedly` (userdb mismatch), TLS handshake EOF (entrypoint readiness ordering).
- Do not silence the failure. Fix the config or harness and re-run.

- [ ] **Step 5: Run the in-process e2e suite**

Run:
```bash
RIMAP_REQUIRE_DOCKER=1 cargo nextest run -p rimap-server --test e2e --locked
```
Expected: passes.

- [ ] **Step 6: No-silent-skip regression guard**

Run:
```bash
unset RIMAP_REQUIRE_DOCKER
cargo nextest run -p rimap-server --test e2e_wire wire_e2e_full_session_draft_safe --locked --no-fail-fast 2>&1 | tail -20
```
Expected: the test executes and passes. If output says `0 tests run` or `(skipped)`, the harness has regressed into a new silent-skip path — investigate before continuing.

- [ ] **Step 7: Stage and commit**

Run:
```bash
git add crates/rimap-server/tests/support/dovecot/harness.rs
git commit -m "$(cat <<'EOF'
test(rimap-server): drop arch gate from dovecot harness (#273)

The 2.4.4-root image is multi-arch, so the arm64-skip gate no longer
serves a purpose. Removing it allows the e2e and wire-conformance
suites to run on Apple Silicon.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 6: Drop arch gate from `rimap-imap` harness

**Files:**
- Modify: `crates/rimap-imap/tests/integration/support/container.rs` (rustdoc lines 84–96, `check_prerequisites` lines 258–283)

- [ ] **Step 1: Update the rustdoc on `DovecotHarness::try_start`**

Replace lines 84–96 (the `/// Start a fresh Dovecot container...` block down through the closing `///` line before `pub fn try_start`):

```rust
    /// Start a fresh Dovecot container. Returns `Err(DockerUnavailable)`
    /// and skips the test silently when neither `docker` nor `podman`
    /// is installed (unless `RIMAP_REQUIRE_DOCKER=1` is set, in which
    /// case the absence becomes a hard error). Pick a specific runtime
    /// with `RIMAP_CONTAINER_TOOL={docker,podman}`.
```

- [ ] **Step 2: Collapse `check_prerequisites`**

Replace lines 258–283 (the existing function body):

```rust
fn check_prerequisites() -> Result<(), HarnessError> {
    let require_runtime = std::env::var("RIMAP_REQUIRE_DOCKER").is_ok();

    if !runtime_available() {
        return if require_runtime {
            Err(HarnessError::DockerCommandFailed(
                "neither docker nor podman found but RIMAP_REQUIRE_DOCKER=1".into(),
            ))
        } else {
            Err(HarnessError::DockerUnavailable)
        };
    }

    Ok(())
}
```

Note the error variant is `DockerCommandFailed` here (not `ComposeFailed` as in `rimap-server`); the two harnesses use different error enums. Use whatever variant the surrounding code already used for the prior runtime-missing case.

- [ ] **Step 3: Compile-check**

Run:
```bash
cargo check -p rimap-imap --tests --locked
```
Expected: clean.

- [ ] **Step 4: Run the rimap-imap dovecot integration suite**

Run:
```bash
RIMAP_REQUIRE_DOCKER=1 cargo nextest run -p rimap-imap --test dovecot --locked
```
Expected: full suite executes and passes on arm64 macOS. Wall-clock target: 60–180s (this suite has more cases than rimap-server's e2e; `case_11` does a force-recreate which costs an extra ~10s).

If `case_11` fails specifically (look for `--force-recreate` in the test name or `pinned fingerprint` in the assertion message), inspect the entrypoint's cert-persistence path:
- `cert.pem`/`key.pem` must live on the named `shared` volume (they do — see `entrypoint.sh:30-46`).
- The fingerprint published to `/shared/fingerprint.hex` must match across recreate. 2.4 doesn't touch openssl, so the cert generation should produce the same fingerprint deterministically.

- [ ] **Step 5: Stage and commit**

Run:
```bash
git add crates/rimap-imap/tests/integration/support/container.rs
git commit -m "$(cat <<'EOF'
test(rimap-imap): drop arch gate from dovecot harness (#273)

Mirror of the rimap-server change. The 2.4.4-root image is multi-arch,
so the arm64-skip gate is removed; the rimap-imap dovecot integration
suite now runs on Apple Silicon too.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 7: Refresh caller-side rustdoc comments

**Files:**
- Modify: `crates/rimap-server/tests/e2e.rs` (line 5 region)
- Modify: `crates/rimap-server/tests/e2e_wire.rs` (lines 8–9 region)
- Modify: `crates/rimap-imap/tests/integration/dovecot.rs` (line 3 region)

- [ ] **Step 1: Update `crates/rimap-server/tests/e2e.rs`**

Replace the current line 4–5 block:
```rust
//! Skips silently when no container runtime is available or the host
//! architecture is not `x86_64` (dovecot image is amd64-only).
```
with:
```rust
//! Skips silently when no container runtime is available. Set
//! `RIMAP_REQUIRE_DOCKER=1` to fail loudly instead.
```

- [ ] **Step 2: Update `crates/rimap-server/tests/e2e_wire.rs`**

Replace the current lines 8–9 block:
```rust
//! Silent-skip when no container runtime is available or the host
//! arch is not `x86_64`; `RIMAP_REQUIRE_DOCKER=1` flips to loud failure.
```
with:
```rust
//! Silent-skip when no container runtime is available;
//! `RIMAP_REQUIRE_DOCKER=1` flips to loud failure.
```

- [ ] **Step 3: Update `crates/rimap-imap/tests/integration/dovecot.rs`**

Replace the current lines 1–3 block:
```rust
//! Dovecot-in-container integration suite for rimap-imap. Runs against
//! docker or podman (autodetected, override with `RIMAP_CONTAINER_TOOL`).
//! Local devs without either runtime get the skip path automatically.
```
with (just confirm — this version already does not mention arch; leave as-is if it doesn't):
```rust
//! Dovecot-in-container integration suite for rimap-imap. Runs against
//! docker or podman (autodetected, override with `RIMAP_CONTAINER_TOOL`).
//! Local devs without either runtime get the skip path automatically.
```

(If the current text in this file already matches the target, skip this sub-step. The Task 6 rustdoc edit on `try_start` already cleaned up the arch caveat in the same crate.)

- [ ] **Step 4: Compile-check**

Run:
```bash
cargo check -p rimap-server -p rimap-imap --tests --locked
```
Expected: clean.

- [ ] **Step 5: Stage and commit**

Run:
```bash
git add crates/rimap-server/tests/e2e.rs \
        crates/rimap-server/tests/e2e_wire.rs \
        crates/rimap-imap/tests/integration/dovecot.rs
git commit -m "$(cat <<'EOF'
test: drop arch caveat from integration-test rustdoc (#273)

Mirrors the harness change.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 8: Update AGENTS.md

**Files:**
- Modify: `AGENTS.md` (lines 67–116 — both the "Container runtime for integration tests" section and the arch caveat embedded in "Wire-driven Dovecot e2e (Phase 3, #265)")

- [ ] **Step 1: Replace the "Container runtime for integration tests" section**

Lines 67–89 currently read as one section ending just before "### Wire-driven Dovecot e2e (Phase 3, #265)". Replace the entire section (the heading line through line 89) with:

```markdown
### Container runtime for integration tests

The Dovecot integration harness autodetects `docker` first, then falls
back to `podman` (via `podman compose` / `podman-compose`). Both
runtimes work on macOS (Apple Silicon and Intel), Ubuntu CI, and Fedora.
Override with `RIMAP_CONTAINER_TOOL=docker` or
`RIMAP_CONTAINER_TOOL=podman` if you need to force a specific one. Set
`RIMAP_REQUIRE_DOCKER=1` to fail loudly instead of silently skipping
when no runtime is installed.

The fixture image is `docker.io/dovecot/dovecot:2.4.4-root` (rootful
flavor, multi-arch `linux/amd64` + `linux/arm64`). It listens on
container ports 143 (IMAP+STARTTLS) and 993 (IMAPS); the Rust harness
maps host ports dynamically. There is no arch gate — every supported
developer host can run the suite.
```

- [ ] **Step 2: Update the "Wire-driven Dovecot e2e" subsection**

Within the section that begins `### Wire-driven Dovecot e2e (Phase 3, #265)`, replace the "Gating" bullet (lines 105–111 in the pre-edit file, which mentions Rosetta and the arch gate) with:

```markdown
- Gating: silent-skip ONLY when the host genuinely cannot run the
  fixture — missing docker/podman. `RIMAP_REQUIRE_DOCKER=1` flips
  every failure mode (compose-up, readiness timeout, port reservation,
  fingerprint read) to a panic with diagnostic context. Same
  convention as the legacy in-process `e2e_full_session`.
```

Also update the immediately-preceding "Wall time" bullet (lines 101–104) to drop the "without Docker" caveat that's no longer arch-conditioned:

```markdown
- Wall time: silent-skip path is sub-second when no container runtime
  is available; with Docker on either linux/amd64 or macOS arm64,
  expect ~10–60s on a warm machine (Dovecot bring-up dominates).
```

- [ ] **Step 3: Compile-check (sanity, even though it's a doc file)**

Run:
```bash
just fmt-check && just lint
```
Expected: no formatting or lint regressions (the change is markdown only).

- [ ] **Step 4: Stage and commit**

Run:
```bash
git add AGENTS.md
git commit -m "$(cat <<'EOF'
docs(AGENTS): drop arm64 Rosetta caveat from integration-test docs (#273)

The 2.4.4-root fixture is multi-arch; the arch gate is gone; the
arch-specific Rosetta narrative is now obsolete.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 9: Local CI parity check

**Files:** none (verification only).

- [ ] **Step 1: Run the full local-CI gate**

Run:
```bash
just ci
```
Expected: all targets green — `fmt-check`, `lint`, `test`, `test-msrv`, `deny`. This is the same gate CI runs; if it passes locally, CI should pass on Linux amd64. Wall-clock: ~10–25 minutes depending on cache state.

- [ ] **Step 2: Spot-check that the integration suites are actually executing**

Run:
```bash
RIMAP_REQUIRE_DOCKER=1 cargo nextest run -p rimap-server --test e2e_wire --locked 2>&1 | grep -E '(test|passed|failed|skipped)'
RIMAP_REQUIRE_DOCKER=1 cargo nextest run -p rimap-imap --test dovecot --locked 2>&1 | grep -E '(test|passed|failed|skipped)'
```
Expected: non-zero test counts, all passed.

- [ ] **Step 3: No commit for this task** — verification only.

---

### Task 10: Push branch and verify CI on linux/amd64

**Files:** none (CI verification).

- [ ] **Step 1: Push the branch**

Run:
```bash
git push -u origin spec/dovecot-24-multiarch-fixture
```
Expected: branch published to origin.

- [ ] **Step 2: Open the pull request**

Run:
```bash
gh pr create --title "Migrate Dovecot test fixture to multi-arch 2.4.4-root (#273)" --body "$(cat <<'EOF'
## Summary
- Replaces amd64-only `dovecot/dovecot:2.3.21` with multi-arch `dovecot/dovecot:2.4.4-root` so integration tests run on Apple Silicon.
- Rewrites `dovecot.conf` to 2.4 syntax (named `passdb`/`userdb` sections, renamed SSL/auth settings, nested `fields { }` block, `%{user}` variables).
- Drops the `std::env::consts::ARCH != "x86_64"` silent-skip gates from both `rimap-server` and `rimap-imap` harnesses.
- Refreshes `AGENTS.md` and the integration-test rustdoc to remove the Rosetta caveat.

Closes #273.

## Test plan
- [ ] `just ci` passes locally on arm64 macOS.
- [ ] `RIMAP_REQUIRE_DOCKER=1 cargo nextest run -p rimap-server --test e2e_wire --locked` passes on arm64 macOS.
- [ ] `RIMAP_REQUIRE_DOCKER=1 cargo nextest run -p rimap-server --test e2e --locked` passes on arm64 macOS.
- [ ] `RIMAP_REQUIRE_DOCKER=1 cargo nextest run -p rimap-imap --test dovecot --locked` passes on arm64 macOS.
- [ ] Same three suites pass on CI (linux/amd64).
- [ ] No-silent-skip guard: `cargo nextest run -p rimap-server --test e2e_wire wire_e2e_full_session_draft_safe --locked` (without `RIMAP_REQUIRE_DOCKER`) executes the test, does not return "0 tests".

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 3: Watch CI**

Run:
```bash
gh pr checks --watch
```
Expected: every required check (`rustfmt`, `clippy`, `check (macOS)`, `test (stable)`, `test (MSRV 1.88.0)`, `cargo-deny`, `zizmor self-check`) goes green. If any fails, do not merge — investigate, push fix-up commits, repeat.

The `test (stable)` and `check (macOS)` checks are where the Dovecot fixture work most likely breaks first. Inspect the job log for `Unknown setting` (config drift), `RIMAP_REQUIRE_DOCKER` failures, or fingerprint mismatches.

- [ ] **Step 4: No local commit for this task** — verification only.

---

### Task 11: Delete obsolete memory note (post-merge)

**Files:**
- Delete: `/Users/dave/.claude/projects/-Users-dave-src-rusty-imap-mcp/memory/project_dovecot_rosetta_gate.md`
- Modify: `/Users/dave/.claude/projects/-Users-dave-src-rusty-imap-mcp/memory/MEMORY.md` (drop the Rosetta-gate entry line)

This task runs **after** the PR merges. The memory note specifically says "do not propose dropping the arch gate without first switching the fixture image"; that condition is now satisfied, so the note is actively misleading rather than useful.

- [ ] **Step 1: Delete the memory file**

Run:
```bash
trash /Users/dave/.claude/projects/-Users-dave-src-rusty-imap-mcp/memory/project_dovecot_rosetta_gate.md
```

- [ ] **Step 2: Remove the index line from `MEMORY.md`**

Open `/Users/dave/.claude/projects/-Users-dave-src-rusty-imap-mcp/memory/MEMORY.md` and delete the line:
```
- [Dovecot arm64 gate is load-bearing](project_dovecot_rosetta_gate.md) — silent-skip on arm64 macOS is because dovecot:2.3.21 amd64 crashes under Rosetta (mmap ExecutableHeap ENOMEM), not a Docker-emulation misconception. Do not propose removing without migrating the fixture image first.
```

- [ ] **Step 3: No git commit for this task** — the memory directory is outside the repo. No tracking needed.

---

## Self-Review Checklist

(Maintainer: tick before declaring the plan complete.)

- Spec section 1 (Image bump) → Task 1 + Task 4. ✓
- Spec section 2 (Config rewrite) → Task 2 (capture baseline) + Task 3 (commit). ✓
- Spec section 3 (Harness arch gate removal) → Task 5 (rimap-server) + Task 6 (rimap-imap). ✓
- Spec section 4 (Caller-side doc sweep) → Task 7. ✓
- Spec section 5 (AGENTS.md) → Task 8. ✓
- Spec section 6 (Memory cleanup) → Task 11. ✓
- Verification: bring-up steps → Task 4 (steps 3–6). ✓
- Verification: automated suites on both arches → Task 5 (steps 4–6) + Task 6 (step 4) on arm64; Task 10 (step 3) on amd64 CI. ✓
- Verification: no-silent-skip guard → Task 5 step 6. ✓
- Open Question 1 (latest 2.4.x tag) → Task 1 Step 1 explicitly checks. ✓
- Open Question 2 (mail_path/mail_driver split) → Task 2 Step 2 (`doveconf -n` is the source of truth). ✓
- Open Question 3 (static userdb fields block) → Task 2 Step 2 same. ✓
- Open Question 4 (inherited conf.d defaults) → Task 2 Step 3 + Task 4 Step 2 (conditional override). ✓
- Open Question 5 (`%`-variable sweep outside dovecot.conf) → no `%`-variables found outside `dovecot.conf` (verified during plan drafting via `rg '%[a-z]\\b' crates/rimap-imap/tests/integration/dovecot/`). If a future change introduces one, the `doveconf -n` step in Task 4 will catch it.
