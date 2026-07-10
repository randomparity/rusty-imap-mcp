# Supply-chain watchlist

This file tracks supply-chain concerns from the Sprint 2 review (#17) that
do not block merge but need periodic re-evaluation. Each entry has a
trigger condition for promotion to a full-fledged issue or follow-up.

## 1. fs4 single-maintainer status

- **Crate:** `fs4 = "0.13"` (https://github.com/al8n/fs4-rs)
- **Concern:** Single-publisher (Al Liu) in a load-bearing role (audit log
  advisory locking). Bus factor 1.
- **Trigger:** No upstream release in the past 12 months, OR a CVE
  filed against fs4, OR the maintainer announces deprecation.
- **Action on trigger:** Evaluate forking or switching to a maintained
  alternative (`rustix`, `sysinfo` + native APIs, etc.). The lock primitive
  is small enough to vendor.
- **Reference:** supply-chain-reviewer `[SC-DEP-09]` (info)

## 2. ulid = "=1.1.4" exact pin

- **Crate:** `ulid = "=1.1.4"` (in `Cargo.toml`)
- **Concern:** Exact pin blocks any 1.1.x patch release including a
  hypothetical security fix. The pin exists because ulid 1.2+ depends on
  rand 0.9 which conflicts with governor's rand 0.8 transitively.
- **Trigger:** governor releases a version on rand 0.9, OR a CVE is
  filed against ulid 1.1.4.
- **Action on trigger:** Drop the exact pin and unify on rand 0.9
  workspace-wide. The change touches `Cargo.toml`, `deny.toml`, and any
  call site that pinned `rand = "0.8"` for the same reason.
- **Reference:** supply-chain-reviewer `[SC-DEP-01]` (info)

## 3. Internal-crate `version = "0.0.0"` pattern

- **Pattern:** Internal path deps use
  `{ path = "../foo", version = "0.0.0" }` rather than
  `{ workspace = true }`. Documented in commit `27c37dd`.
- **Concern:** At first `cargo publish`, every consumer must be updated
  in lockstep with the workspace version bump. Easy to forget.
- **Trigger:** A pre-publish dry-run (`cargo publish --dry-run`) for any
  workspace member.
- **Action on trigger:** Either (a) move internal crates back into
  `[workspace.dependencies]` and add explicit `bans.skip` entries to
  `deny.toml`, or (b) write a `scripts/release.sh` that grep-replaces
  `version = "0.0.0"` to the new workspace version across every member's
  `Cargo.toml`.
- **Reference:** supply-chain-reviewer (Sprint 2 review)

## 4. SBOM generation at release time

- **Concern:** No SBOM is generated at release time. CycloneDX or SPDX
  via `cargo sbom` or `cargo auditable`, attached as a release asset, is
  the industry expectation for a security-sensitive tool.
- **Trigger:** First binary release (post-v1).
- **Action on trigger:** Add an `sbom` job to the release workflow that
  runs `cargo auditable build --release`, then `cargo sbom` to produce
  CycloneDX JSON, and uploads it as a release asset alongside the binary.
- **Reference:** supply-chain-reviewer (Sprint 2 review). Cross-references
  the deferred `release-integrity-reviewer` (#19).

## 5. Bundled libdbus C source (vendored-keyring)

- **Crate:** `libdbus-sys 0.2.7` under the `vendored-keyring` feature.
- **Concern:** With `vendored-keyring` (release Linux legs; also any
  `--all-features` build), `libdbus-sys` statically compiles a **bundled
  libdbus 1.14.4** (2022) C source via `cc`. C-level libdbus CVEs are invisible
  to `cargo audit`/RUSTSEC, so the release binary could carry a vulnerable
  libdbus while every Rust gate stays green. 1.14.4 predates the 1.14.8 security
  series. The build script itself was audited clean (no network; writes only
  `$OUT_DIR`; safe env reads).
- **Trigger:** A libdbus CVE in the 1.14.x line, OR `libdbus-sys` bumping its
  bundled libdbus version.
- **Action on trigger:** Bump `libdbus-sys`, re-check `DBUS_VERSION` in its
  `build_vendored.rs`, and record the bundled libdbus version in the release
  notes/SBOM (advisory tooling will not).
- **Reference:** supply-chain-reviewer `[SC-BUILD-05/06]` (low, accepted).

## 6. OpenSSL pinned-but-never-built (rustls-only invariant)

- **Crates:** `openssl`, `openssl-sys`, `openssl-src`, `vcpkg` in `Cargo.lock`.
- **Concern:** `dbus-secret-service`'s `vendored = ["dbus/vendored",
  "openssl?/vendored"]` makes the OpenSSL stack reachable, so it is pinned in
  `Cargo.lock`. It is **never compiled** (weak `openssl?` edge; no
  `crypto-openssl` backend). Risk: a future change silently pulls OpenSSL into
  the build graph, breaking the rustls-only invariant; and a future OpenSSL
  RUSTSEC advisory could red `cargo audit` for a crate shipping no OpenSSL.
- **Trigger:** `just check-no-openssl` fails (openssl-sys enters the build
  graph), OR an OpenSSL advisory flags the lockfile entry.
- **Action on trigger:** Find what enabled `crypto-openssl`/`dep:openssl` and
  disable it; if the advisory is lock-only (never built), document and ignore.
- **Enforcement:** `just check-no-openssl` (part of `just ci`) asserts
  `cargo tree -i openssl-sys --all-features --target all` is empty.
- **Reference:** supply-chain-reviewer `[SC-FEAT-03/SC-DEP-01]` (medium).

## Review cadence

This file is reviewed as part of every minor-version bump. Add the entry to
the `CHANGELOG.md` of the bump if any trigger condition has fired.
