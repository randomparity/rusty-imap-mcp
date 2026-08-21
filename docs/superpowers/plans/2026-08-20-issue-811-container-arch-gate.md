# Plan — Issue #811: container arch gate + `test-fast` filter

**Goal:** an arch-mismatched fixture pin fails fast with a named diagnostic, and
`just test-fast` excludes every container-backed test binary via a drift-guarded
shared list.

**Architecture:** the check lives in `rimap-container-gate` (the single home for
container prerequisites). Each of the four container harnesses parses its pinned
image reference out of its compose file at runtime, inspects the local image's
architecture after `compose up -d` succeeds, and fails loudly on mismatch.
`test-fast`'s nextest filter is built from `scripts/container-test-binaries.txt`,
guarded against drift by a test in the gate crate.

**Tech stack:** Rust 2024 edition, `std::process::Command`, no new dependencies.

**Spec:** `docs/superpowers/specs/2026-08-20-issue-811-container-arch-gate-design.md`
**ADR:** `docs/ADR/0023-fixture-image-arch-must-match-host.md`

## Global Constraints

- MSRV 1.88.0 (`[workspace.package] rust-version`); dev toolchain 1.94.0.
- Zero warnings: `just lint` (`cargo clippy --workspace --all-targets
  --all-features --locked -- -D warnings`) must stay clean.
- No `unwrap()`/`#[allow]`/`println!` in non-test source; `#[expect(...,
  reason = "...")]` where suppression is needed. Tests may
  `#![expect(clippy::expect_used, ...)]`.
- 100-char lines, absolute imports, Google-style doc comments on public items
  (`#![deny(missing_docs)]` in the gate crate).
- No new runtime or dev dependencies.
- Dependencies are declared in `[workspace.dependencies]` and inherited; the
  gate crate gains none.
- Guardrail commands: `just check`, `just fmt`, `just lint`, `just test-fast`,
  `just test` (full, before push), `just ci` (everything, before done).
- Branch: `feat/guard-arch-mismatched-container-pin-811` off `main`.

## File map

| File | Change |
|---|---|
| `crates/rimap-container-gate/src/lib.rs` | Add `host_arch`, `pinned_image`, `image_arch`, `arch_mismatch_reason` + unit tests + drift-guard test |
| `crates/rimap-imap/tests/integration/support/container.rs` | `ArchMismatch` variant + post-up check in `DovecotHarness::try_start` |
| `crates/rimap-server/tests/support/dovecot/harness.rs` | same, for the server Dovecot harness |
| `crates/rimap-server/tests/support/mailpit/harness.rs` | same, for Mailpit |
| `crates/rimap-server/tests/support/chaos/harness.rs` | same, for Dovecot + Toxiproxy (panic-based loud path) |
| `scripts/container-test-binaries.txt` | new: shared exclusion list |
| `justfile` | `test-fast` builds the filter from the list |
| `scripts/prune-containers.sh` | exemption comment |
| `AGENTS.md` | arch-gate sentences, troubleshooting note, two falsified-statement rewrites |
| `crates/rimap-imap/tests/integration/dovecot/docker-compose.chaos.yml` | comment-only "no arch gate" update |

## Task 1 — Gate: pure arch predicates (TDD)

**Files:** `crates/rimap-container-gate/src/lib.rs`
**Interfaces consumed:** nothing new. **Provides:** `host_arch()`,
`arch_mismatch_reason()`, `pinned_image()` — used by Tasks 2 and 3.

1. Write the failing tests first, appended to `mod tests` in
   `crates/rimap-container-gate/src/lib.rs`:

```rust
    // ── arch gate (#811) ─────────────────────────────────────────────

    #[test]
    fn host_arch_maps_rust_names_to_oci_names() {
        // Compile-time arch on this host is whatever built the tests; the
        // mapping itself is what the check depends on. Both known values
        // must map; the function must never guess at anything else.
        let mapped = ["aarch64", "x86_64"]
            .into_iter()
            .filter_map(oci_arch_name)
            .collect::<Vec<_>>();
        assert_eq!(mapped, ["arm64", "amd64"]);
    }

    #[test]
    fn arch_mismatch_reason_names_both_arches_and_the_pin() {
        let reason = arch_mismatch_reason(
            "docker.io/dovecot/dovecot:2.4.4-root@sha256:34c8425",
            "amd64",
            "arm64",
        )
        .expect("a mismatch is a reason");
        assert!(reason.contains("34c8425"), "{reason:?}");
        assert!(reason.contains("amd64"), "{reason:?}");
        assert!(reason.contains("arm64"), "{reason:?}");
        assert!(
            reason.contains("emulation"),
            "the symptom hint must be there: {reason:?}"
        );
    }

    #[test]
    fn arch_mismatch_reason_is_none_on_a_match() {
        assert_eq!(arch_mismatch_reason("some@sha256:1", "arm64", "arm64"), None);
    }

    const COMPOSE_ONE_SERVICE: &str = "\
services:
  dovecot:
    image: docker.io/dovecot/dovecot:2.4.4-root@sha256:d6b2f80
    container_name: rimap-it-dovecot
    ports: []
";

    const COMPOSE_TWO_SERVICES: &str = "\
services:
  dovecot:
    image: docker.io/dovecot/dovecot:2.4.4-root@sha256:d6b2f80
  toxiproxy:
    image: ghcr.io/shopify/toxiproxy:2.12.0
";

    /// Unique per-process scratch dir under std::env::temp_dir — no
    /// `tempfile` dependency: the gate crate's manifest says "No
    /// dependencies, by design" and a dev-dep would amend that contract
    /// for no gain. The pid+counter name cannot collide across parallel
    /// test threads; tests only ever read files they just wrote.
    fn scratch_compose(name: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "rimap-gate-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("create scratch dir");
        dir.join(name)
    }

    #[test]
    fn pinned_image_reads_the_named_service() {
        let path = scratch_compose("compose.yml");
        std::fs::write(&path, COMPOSE_ONE_SERVICE).expect("write");
        assert_eq!(
            pinned_image(&path, "dovecot").as_deref(),
            Some("docker.io/dovecot/dovecot:2.4.4-root@sha256:d6b2f80")
        );
        std::fs::write(&path, COMPOSE_TWO_SERVICES).expect("write");
        assert_eq!(
            pinned_image(&path, "toxiproxy").as_deref(),
            Some("ghcr.io/shopify/toxiproxy:2.12.0"),
            "the second service must not inherit the first"
        );
    }

    #[test]
    fn pinned_image_is_none_for_a_missing_service_or_file() {
        let path = scratch_compose("compose.yml");
        std::fs::write(&path, COMPOSE_TWO_SERVICES).expect("write");
        assert_eq!(pinned_image(&path, "mailpit"), None);
        let dir = path.parent().expect("scratch dir");
        assert_eq!(pinned_image(&dir.join("absent.yml"), "dovecot"), None);
    }
```

2. Run `cargo nextest run -p rimap-container-gate` — the new tests must FAIL
   to compile (functions do not exist). That is the red step.
3. Implement in `crates/rimap-container-gate/src/lib.rs`, after
   `names_unreachable_engine`:

```rust
/// The host architecture in OCI image naming, or `None` when this build's
/// target architecture is not one the check can judge. Test binaries are
/// never cross-compiled here (CI builds every platform natively), so the
/// compile-time arch is the host arch.
#[must_use]
pub fn host_arch() -> Option<&'static str> {
    oci_arch_name(std::env::consts::ARCH)
}

fn oci_arch_name(arch: &str) -> Option<&'static str> {
    match arch {
        "aarch64" => Some("arm64"),
        "x86_64" => Some("amd64"),
        _ => None,
    }
}

/// The loud-failure reason when the fixture image's architecture differs
/// from the host's, naming the pin, both arches, and the symptom the
/// mismatch produces downstream. `None` when they match.
#[must_use]
pub fn arch_mismatch_reason(
    image_ref: &str,
    image_arch: &str,
    host_arch: &str,
) -> Option<String> {
    if image_arch == host_arch {
        return None;
    }
    Some(format!(
        "fixture image {image_ref} is linux/{image_arch} but this host is \
         {host_arch}: the container would run under emulation, which breaks \
         the fixture (doveadm auth-userdb disconnects, TLS handshake EOFs). \
         Re-pin the compose image to a manifest whose architecture list \
         covers {host_arch}."
    ))
}

/// The pinned image reference for `service` in a compose file, parsed by
/// line scan — no YAML dependency for a two-field need. The reference is
/// read at runtime, never duplicated as a constant, so a Dependabot digest
/// bump cannot leave the arch check validating a ref nobody runs. `None`
/// when the file, the service, or its `image:` key cannot be found.
#[must_use]
pub fn pinned_image(compose: &std::path::Path, service: &str) -> Option<String> {
    let text = std::fs::read_to_string(compose).ok()?;
    let service_key = format!("{service}:");
    let mut in_service = false;
    for line in text.lines() {
        if !line.starts_with(' ') {
            in_service = false;
        } else if line.starts_with("  ") && !line.starts_with("   ") {
            in_service = line.trim_end() == service_key;
        } else if in_service {
            if let Some(value) = line.trim_start().strip_prefix("image:") {
                let value = value.trim();
                if !value.is_empty() {
                    return Some(value.to_owned());
                }
            }
            // Any other property line inside the service is skipped — a
            // `?` here would abort the whole scan on the first
            // non-`image:` key (e.g. `container_name:`) and return `None`
            // for every real compose file.
        }
    }
    None
}
```

   Update the `use super::{...}` list in `mod tests` to include the new
   items. Run `cargo nextest run -p rimap-container-gate` — all green.

4. `just fmt && just lint` — clean. Commit: `feat(gate): arch predicates for fixture image checks (#811)`.

## Task 2 — Gate: `image_arch` wrapper

**Files:** `crates/rimap-container-gate/src/lib.rs`
**Interfaces consumed:** nothing. **Provides:** `image_arch()` for Task 3.

1. Implement after `pinned_image` (thin wrapper; its failure contract —
   `None` on any error — is one match arm, covered by the container-gated
   path and Task 3's wiring):

```rust
/// The architecture of a *local* image as `<tool> image inspect` reports
/// it. The harnesses call this only after `compose up -d` succeeded, so
/// the image is local by construction and one inspect is authoritative.
/// `None` on any inspect failure — the check then stands down and compose
/// keeps owning the failure, per the gate's documented asymmetry.
#[must_use]
pub fn image_arch(tool: &str, image_ref: &str) -> Option<String> {
    let output = Command::new(tool)
        .args(["image", "inspect", "--format", "{{.Architecture}}", image_ref])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let arch = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if arch.is_empty() { None } else { Some(arch) }
}
```

   (`Command` is already imported at the top of the file.)

   Probe verification boundary (spec §1): the exact probe is verified on
   Docker 29.7.2 (returns `arm64` for the current pin on this arm64 host).
   Podman is not installed on this host, so that arm is unverified here;
   its failure contract is fail-safe — any surprise yields `None` and the
   accepted silent stand-down, never a false failure.

2. `just check && just lint` — clean. Commit: `feat(gate): local image arch inspection (#811)`.

## Task 3 — Harness wiring (four call sites)

**Files:** the four harness files.
**Interfaces consumed:** `host_arch`, `image_arch`, `arch_mismatch_reason`,
`pinned_image` from Tasks 1–2. **Provides:** loud `ArchMismatch` behavior.

For **three** of the four harnesses (`rimap-imap` `container.rs`,
`rimap-server` `dovecot/harness.rs`, `rimap-server` `mailpit/harness.rs` —
all of which have a `HarnessError`):

1. Add the variant to that harness's `HarnessError` (always loud — it is
   constructed only on a determined mismatch or an unparseable pin, and no
   caller may map it to `DockerUnavailable`):

```rust
    /// The pinned fixture image's architecture does not match this host,
    /// or the pinned reference could not be parsed. Always a hard failure
    /// at every posture: an arch-mismatched pin is a fixture defect, not
    /// an absent host capability (ADR-0023).
    ArchMismatch(String),
```

   and its `Display` arm: `Self::ArchMismatch(s) => f.write_str(s),`

2. Add a private helper next to the existing `gate()` mapping function,
   parameterized over the service name (each harness passes its own —
   `dovecot`, `smtp`, or the chaos loop's current service — and the error
   message interpolates it):

```rust
/// Verify the pinned fixture image's architecture matches this host.
/// Runs after `compose up -d` succeeded, so the image is local and one
/// inspect answers without a network path. Tears the project down before
/// returning the loud error. An unparseable reference is loud — compose
/// accepted the file, so `None` means parser drift, and a silent
/// stand-down would disarm the guard on its own target class (ADR-0023).
/// A failed inspect after a parsed reference stands down: genuinely
/// indeterminate, compose keeps owning it.
fn check_image_arch(
    project: &str,
    compose_dir: &Path,
    service: &str,
) -> Result<(), HarnessError> {
    let Some(image) =
        rimap_container_gate::pinned_image(&compose_dir.join(COMPOSE_FILE), service)
    else {
        compose_down(project, compose_dir);
        return Err(HarnessError::ArchMismatch(format!(
            "could not determine the pinned image for service '{service}' from \
             {COMPOSE_FILE}; the compose parser in rimap-container-gate needs \
             updating",
        )));
    };
    let (Some(arch), Some(host)) = (
        rimap_container_gate::image_arch(runtime(), &image),
        rimap_container_gate::host_arch(),
    ) else {
        return Ok(());
    };
    if let Some(reason) = rimap_container_gate::arch_mismatch_reason(&image, &arch, &host) {
        compose_down(project, compose_dir);
        return Err(HarnessError::ArchMismatch(reason));
    }
    Ok(())
}
```

**The chaos harness is the exception** (`crates/rimap-server/tests/support/chaos/harness.rs`):
`ChaosHarness::try_start` returns `Result<Self, ChaosSkip>`, and
`ChaosSkip` is documented as a silent-skip enum — do not add an
`ArchMismatch` variant to it. Instead, in the chaos harness's own
`check_image_arch` helper (same shape as above, parameterized over the
service and looping over `["dovecot", "toxiproxy"]`), return the failure
via the file's established loud path: `compose_down` then
`panic!("chaos: {reason}")` — the file already carries
`#![expect(clippy::panic, reason = "control-plane failures abort the test
loudly")]`. That is loud at every posture, as ADR-0023 requires; the
three-tier `RIMAP_CHAOS`/skip/loud policy is unchanged.

3. Call it in `try_start` where compose up succeeded, before readiness
   polling — e.g. in the server Dovecot harness:

```rust
            if output.status.success() {
                check_image_arch(&project, &compose_dir, "dovecot")?;
                return wait_for_ready(&project, host_port.port(), &compose_dir);
            }
```

Per-harness specifics:

- `crates/rimap-imap/tests/integration/support/container.rs`
  (`DovecotHarness`): compose dir is the dovecot integration dir, compose
  file `docker-compose.yml`, service `dovecot`. The gate items are already
  imported by name there — extend the `use rimap_container_gate::{...}`
  list. Insert the call between `compose_up_with_retry(...)?` and
  `let result = wait_for_ready(...)`:

```rust
        check_image_arch(&project, &compose_dir, "dovecot")?;
```

  Its `compose_down` takes `(&project, &compose_dir)` — the helper matches.
- `crates/rimap-server/tests/support/dovecot/harness.rs`: compose file
  `docker-compose.yml` (const may not exist yet — add
  `const COMPOSE_FILE: &str = "docker-compose.yml";`), service `dovecot`.
- `crates/rimap-server/tests/support/mailpit/harness.rs`: compose dir
  `.../integration/smtp`, compose file `docker-compose.yml`, service
  `smtp` (verified: the YAML names the service `smtp`, not `mailpit`).
- `crates/rimap-server/tests/support/chaos/harness.rs`: compose file
  `docker-compose.chaos.yml`, **two** services — run the check for
  `dovecot` and for `toxiproxy` (loop over `["dovecot", "toxiproxy"]`).

4. Update the `DockerUnavailable` doc comment in
   `crates/rimap-server/tests/support/dovecot/harness.rs` — the only
   harness whose doc comment lists "wrong arch" among silent-skip causes:
   arch mismatch now lands in the loud `ArchMismatch` variant, not here.
   The other three harnesses' `DockerUnavailable` docs make no arch claim
   and need no edit.

5. Verification: `just lint` alone — clippy `--all-targets` compiles every
   test binary, which is all this task needs (the harness changes are
   compile-checked; the runtime path is container-gated and is exercised
   by Task 5's manual proof). Do NOT run `just test-fast` here: until
   Task 4 lands, its filter still lets the eight not-yet-excluded container
   binaries compile and run against live fixtures. Commit:
   `feat(tests): fail loudly on arch-mismatched fixture pins (#811)`.

## Task 4 — Shared binary list + `test-fast` recipe + drift guard

**Files:** `scripts/container-test-binaries.txt` (new), `justfile`,
`crates/rimap-container-gate/src/lib.rs` (drift-guard test).
**Interfaces consumed:** nothing from Tasks 1–3 (the guard is static
analysis). **Provides:** the drift-guarded filter; completes criterion 2.

1. Create `scripts/container-test-binaries.txt` (one name per line, no
   blanks, no comments — the recipe and the guard both read it raw). The
   `proton` binary is deliberately absent: it is `PROTON_BRIDGE_TEST=1`-
   gated and self-skips instantly without the env var, so excluding it
   adds nothing.

```
dovecot
e2e
e2e_smtp
e2e_smtp_real
e2e_wire
e2e_wire_cancellation
e2e_wire_chaos
e2e_wire_destructive
e2e_wire_fault_injection
e2e_wire_folder_management
e2e_wire_multi_account_advertisement
e2e_wire_tool_advertisement
```

2. Write the drift-guard test (green on arrival against the list from
   step 1 — its red proof is the mutation check below), in `mod tests` of
   the gate crate:

```rust
    /// The `test-fast` exclusion list must cover exactly the test binaries
    /// that link a container harness — the drift #811 records: eight
    /// container-backed binaries were missing from the justfile filter and
    /// ran (and failed on fixture breakage) in the ~4 s inner loop.
    ///
    /// HARNESS_TYPES is the registry of container-harness public types: a
    /// future container harness MUST add its type here in the same change.
    /// `proton` (Proton Bridge, env-gated) is deliberately absent from the
    /// list: without PROTON_BRIDGE_TEST=1 it self-skips instantly.
    #[test]
    fn container_backed_test_binaries_match_the_shared_list() {
        // Two parents: CARGO_MANIFEST_DIR is
        // <root>/crates/rimap-container-gate, so one parent is still
        // <root>/crates.
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(std::path::Path::parent)
            .expect("gate crate sits at <workspace>/crates/<crate>");
        let list_path = root.join("scripts/container-test-binaries.txt");
        let list: Vec<String> = std::fs::read_to_string(&list_path)
            .expect("shared list exists")
            .lines()
            .map(str::to_owned)
            .collect();
        assert!(!list.is_empty(), "the shared list must not be empty");

        const HARNESS_TYPES: [&str; 4] =
            ["DovecotHarness", "MailpitHarness", "ChaosHarness", "ConnectedHarness"];

        let mut container_backed: Vec<String> = Vec::new();
        // Scan only crates/*/tests — the test binaries. A whole-tree scan
        // would match this crate's own source, whose HARNESS_TYPES literal
        // names every harness type, and the guard would detect itself.
        for crate_dir in std::fs::read_dir(root.join("crates")).expect("crates dir").flatten()
        {
            let tests_dir = crate_dir.path().join("tests");
            if !tests_dir.is_dir() {
                continue;
            }
            for entry in walkdir_like(tests_dir) {
                let path = std::path::Path::new(&entry);
                if path.components().any(|c| c.as_os_str() == "support") {
                    continue;
                }
                let Ok(source) = std::fs::read_to_string(path) else {
                    continue;
                };
                if HARNESS_TYPES.iter().any(|t| source.contains(t)) {
                    container_backed.push(binary_name_for(root, path));
                }
            }
        }
        container_backed.sort();

        let mut listed = list;
        listed.sort();
        assert_eq!(
            container_backed, listed,
            "container-backed test binaries and scripts/container-test-binaries.txt disagree"
        );
    }

    /// Map a test source file to its binary name. A `[[test]]` block in the
    /// owning crate's Cargo.toml whose `path` names this file wins with its
    /// `name`; any other file takes its stem (Cargo's autodiscovery
    /// convention). Stem-equals-name is NOT assumed: rimap-imap declares
    /// `name = "dovecot"`, `path = "tests/integration/dovecot.rs"`.
    fn binary_name_for(root: &std::path::Path, file: &std::path::Path) -> String {
        let crate_dir = file
            .ancestors()
            .find(|a| a.join("Cargo.toml").is_file())
            .expect("test file lives in a crate");
        let manifest = std::fs::read_to_string(crate_dir.join("Cargo.toml"))
            .expect("readable manifest");
        let rel = file.strip_prefix(crate_dir).expect("file inside crate");
        let mut current_name: Option<String> = None;
        let mut current_path: Option<String> = None;
        for line in manifest.lines() {
            let trimmed = line.trim();
            if trimmed == "[[test]]" {
                if let (Some(name), Some(p)) = (&current_name, &current_path) {
                    if std::path::Path::new(p) == rel {
                        return name.clone();
                    }
                }
                current_name = None;
                current_path = None;
            } else if let Some(rest) = trimmed.strip_prefix("name = ") {
                current_name = Some(rest.trim_matches('"').to_owned());
            } else if let Some(rest) = trimmed.strip_prefix("path = ") {
                current_path = Some(rest.trim_matches('"').to_owned());
            }
        }
        if let (Some(name), Some(p)) = (&current_name, &current_path) {
            if std::path::Path::new(p) == rel {
                return name.clone();
            }
        }
        file.file_stem().expect("file stem").to_string_lossy().into_owned()
    }

    /// Collect every `.rs` file under `dir`, recursively, as strings, in
    /// read order (the caller sorts the derived names).
    fn walkdir_like(dir: std::path::PathBuf) -> Vec<String> {
        let mut found = Vec::new();
        let entries = std::fs::read_dir(&dir).expect("readable dir");
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                found.extend(walkdir_like(path));
            } else if path.extension().is_some_and(|e| e == "rs") {
                found.push(path.to_string_lossy().into_owned());
            }
        }
        found
    }
```

   (Keep both helpers inside `mod tests`.) Run it — it must PASS against
   the list from step 1 (the list was derived from the same scan; the red
   proof for this guard is the mutation check below). Then prove it bites:
   temporarily append a bogus name to the list → red; remove a real name
   (`e2e_wire_chaos`) → red; restore → green.

3. Replace the `test-fast` recipe in `justfile`:

```just
# Inner-loop unit tests. Skips every container-backed test binary — the
# list lives in scripts/container-test-binaries.txt and a test in
# rimap-container-gate fails when it drifts from the binaries that link
# container harnesses (#811) — plus the slow HTML lookalike proptest. Use
# this between `cargo check` cycles during inner-loop iteration. Before
# pushing, run `just test` (or `just ci`) for the full sweep. See
# docs/superpowers/specs/2026-05-20-local-test-runtime-trim-design.md and
# docs/superpowers/specs/2026-08-20-issue-811-container-arch-gate-design.md.
#
# Intentionally keeps nextest's built-in fail-fast=true (not --profile ci):
# this target is for iterating on one failure at a time, so stopping at the
# first one is the wanted behavior, not the bug #625 fixes.
test-fast:
    #!/usr/bin/env bash
    set -euo pipefail
    containers=$(sed -e '/^[[:space:]]*$/d' -e 's/.*/binary(&)/' \
        scripts/container-test-binaries.txt | paste -sd '|' -)
    exec cargo nextest run --workspace --locked --no-tests=pass \
        -E "not (${containers} | binary(proptest_html_lookalike))"
```

   (`proptest_html_lookalike` stays an explicit, commented exclusion here:
   slow, not container-backed — the shared list is container-backed only.)

4. Verify: `just test-fast` runs and its filter excludes all twelve
   binaries (`cargo nextest list` count drops accordingly); the run is
   green and fast. `shellcheck` runs on the justfile's embedded script via
   prek — keep it clean. Commit:
   `test: build test-fast filter from a drift-guarded shared list (#811)`.

## Task 5 — Docs: prune exemption, AGENTS.md amendments, manual proof

**Files:** `scripts/prune-containers.sh`, `AGENTS.md`,
`crates/rimap-imap/tests/integration/dovecot/docker-compose.chaos.yml`
(comment-only); manual verification.

1. In `scripts/prune-containers.sh`, extend the header comment block:

```bash
# Arch exemption (#811 / ADR-0023): pruning never pulls or runs the fixture
# image — it only removes stale rimap-it-* resources — so the fixture-image
# architecture check the Rust harnesses run does not apply here. The runtime
# *selection* contract above is still mirrored exactly.
```

2. AGENTS.md, "Container runtime for integration tests" section: after the
   paragraph on the loud/skip asymmetry, add the arch-gate paragraph and
   troubleshooting note (block below). Then amend the two statements the
   decision falsifies (spec §6 items 2–3):

   - Line ~122 ("There is no arch gate — every supported developer host
     can run the suite."): rewrite to state the arch gate now exists — the
     harnesses fail loudly when the fixture image's architecture does not
     match the host (ADR-0023); what remains true is that no *CI* arch
     gate blocks a pin bump before merge.
   - Line ~178 (chaos section bullet "**Multi-arch, no arch gate.**"):
     rewrite the lead to "**Multi-arch.**" and note the harness-level arch
     gate (ADR-0023) covers both images on any host that runs the suite.

```markdown
The gate also checks fixture-image architecture (ADR-0023): after
`compose up -d` succeeds, each harness inspects the pinned image's
architecture against the host's and fails loudly — at every posture, never
a silent skip — when they differ. The image reference is parsed from the
compose file at runtime, so a Dependabot digest bump needs no Rust change.
`scripts/prune-containers.sh` is exempt: it never pulls or runs the fixture
image.

**Troubleshooting:** an amd64-only digest pin on Apple Silicon does not
fail with an arch error — it manifests as `doveadm … Unexpectedly
disconnected from auth service` during user lookups and `tls handshake eof`
on IMAPS handshakes across every container-backed e2e binary (#811). The
arch gate now names the pin, the image arch, and the host arch instead.
```

   Also (spec §6 item 5): in
   `crates/rimap-imap/tests/integration/dovecot/docker-compose.chaos.yml`,
   update the Toxiproxy image's comment "Multi-arch (linux/amd64 +
   linux/arm64): no arch gate …" to say the arch gate now exists in the
   harnesses (ADR-0023); comment-only, no pin change. The ADR-0001 Errata
   append (spec §6 item 4) is already committed on this branch.

3. Manual proof on this host (the criterion-1 red/green). The fixture file
   is tracked, so the restore is guarded, not assumed:

   - Red: edit the real
     `crates/rimap-imap/tests/integration/dovecot/docker-compose.yml` in
     place — the only file the harness reads — replacing the multi-arch
     pin `sha256:d6b2f80…` with the old amd64-only
     `sha256:34c8425a6811a80df614353dd2b0bad779b64c76c88b6a5ab3fa2e3d99b981fb`.
     Run exactly
     `cargo nextest run -p rimap-imap --test dovecot -E 'test(case_01)'`
     (a real case: `case_01_connect_with_correct_pin_succeeds`) and observe
     the named `ArchMismatch` failure — not `auth-userdb` garbage. Record
     the observation.
   - Restore immediately: `git checkout -- crates/rimap-imap/tests/integration/dovecot/docker-compose.yml`,
     then verify with `git diff --stat` that the tree is clean again
     BEFORE any commit.
   - Green: run the same test on the restored pin and observe it pass
     (this host resolves the multi-arch pin to native `arm64`). Record
     the observation.
   - Loud-path arms for the other call sites (cheap one-line temp edits,
     each reverted with `git checkout --` and a `git diff --stat` check):
     (a) in `crates/rimap-server/tests/support/dovecot/harness.rs`,
     temporarily pass service `"nonexistent"` to `check_image_arch`, run
     `cargo nextest run -p rimap-server --test e2e_smtp -E 'test(e2e_send_email_and_forward_through_dispatch)'`,
     and observe the "could not determine the pinned image" `ArchMismatch`
     — the unparseable-pin loud path on a `HarnessError` harness; (b) in
     `crates/rimap-server/tests/support/chaos/harness.rs`, temporarily use
     service `"nonexistent"` and run one chaos scenario with
     `RIMAP_CHAOS=1 cargo nextest run -p rimap-server --test e2e_wire_chaos -E 'test(chaos_delayed_greeting_times_out)'`
     — observe the `panic!("chaos: …")` loud path. Revert both.

4. `just fmt && just lint && just test-fast`. Commit:
   `docs: arch-gate contract and troubleshooting note (#811)`.

## Acceptance criteria (from the spec)

1. Arch-mismatched pin → named loud failure (Task 3 + Task 5 manual proof).
2. `test-fast` excludes every container-backed binary (Task 4, drift guard).
3. Only genuine can't-run hosts silent-skip (Task 3: `ArchMismatch` never
   maps to `DockerUnavailable`).
4. Prune exemption documented (Task 5).
5. AGENTS.md note + both falsified-statement rewrites (Task 5).
6. No new deps, no workflow changes (whole diff).

## Rollback

Single PR; `git revert` of the merge restores the prior behavior. No data,
schema, or external state.
