# Release v0.1.0 + Homebrew Tap (Phase 1) Design

Date: 2026-07-10
Status: Approved (adversarial spec review passed, 3 iterations)
ADR: [ADR-0002](../../ADR/0002-phased-bzr-release-parity-and-direct-publish.md) — phased bzr-parity, direct-publish releases

## Summary

Ship the first real release of `rusty-imap-mcp` (`v0.1.0`) through GitHub
Releases and a Homebrew tap. Release artifacts become `.tar.gz` tarballs
(one per target triple); a `homebrew` job renders and pushes a formula to
[`randomparity/homebrew-tap`](https://github.com/randomparity/homebrew-tap),
and `bottles` / `bottles-merge` jobs build native Homebrew bottles and fold a
`bottle do` block into that formula. A new `RELEASING.md` at the repo root
documents the end-to-end procedure, including one-time tap setup.

This is **Phase 1** of a larger effort to mirror the release process used by
[`randomparity/bzr`](https://github.com/randomparity/bzr). It deliberately
keeps the project's **current** version model (clean `Cargo.toml`,
`build.rs`-computed dev suffix, existing `verify-tag` guard) and defers the
remaining bzr-parity subsystems to their own specs.

## Goals

- Publish `v0.1.0` binaries as verifiable `.tar.gz` artifacts with
  `SHA256SUMS.txt` and a build-provenance attestation (the latter already
  exists).
- Auto-publish a Homebrew formula on every stable `v*` tag so users can run
  `brew install randomparity/tap/rusty-imap-mcp`.
- Build native Homebrew bottles so `brew install` pours a prebuilt binary
  instead of running the formula's `install` under Homebrew's build sandbox.
- Document the release procedure and one-time tap setup in `RELEASING.md`.

## Non-goals (deferred to later phases)

- **`-dev` version model** — reworking `build.rs` + `verify-tag` so
  `Cargo.toml` carries a `-dev` suffix between releases, plus release-prep and
  post-release-bump jobs. Phase 1 keeps the current tag-and-push model.
- **crates.io publish** — reserving and publishing all 8 workspace crates in
  dependency order (`publish-crates.yml`, `CARGO_REGISTRY_TOKEN`).
- **deb/rpm packaging** — Cargo package metadata, `cargo-deb` /
  `cargo-generate-rpm`, lintian/rpmlint, container install smoke.
- **Manpages + `install.sh` / `install.ps1` + `installer-smoke`** — none exist
  today; Phase 1 ships no manpages, so the formula omits `man` handling.

## Current state (baseline)

- No git tags exist; this is the first release. `Cargo.toml`
  `[workspace.package].version = "0.1.0"`.
- `CHANGELOG.md` already has a dated `## [0.1.0] - 2026-07-05` section.
- `.github/workflows/release.yml` triggers on `v*` tags and a
  `workflow_dispatch` dry-run. It runs `verify-tag` (via
  `scripts/check-release-version.sh`), builds 5 targets
  (`x86_64`/`aarch64`/`powerpc64le`/`s390x` Linux + `aarch64-apple-darwin`),
  uploads **bare binaries**, generates `SHA256SUMS.txt`, attaches a
  provenance attestation, extracts release notes from `CHANGELOG.md`, and
  creates a **draft** GitHub Release.
- `randomparity/homebrew-tap` exists with an empty `Formula/` directory and
  one neighbor formula (`bzr.rb`) as a house-style reference.
- The binary `rusty-imap-mcp` is produced by the `rimap-server` crate.

## Architecture

### 1. Tarball packaging

Each of the 5 build jobs currently ends by uploading a bare
`rusty-imap-mcp-<triple>`. It instead packages a tarball named
`rusty-imap-mcp-v<VERSION>-<triple>.tar.gz` whose contents are:

```
rusty-imap-mcp          # the binary, unsuffixed, so bin.install "rusty-imap-mcp" works
LICENSE-MIT
LICENSE-APACHE
NOTICE
README.md
```

Bare binaries are **replaced** by tarballs (not shipped alongside), matching
bzr. The `release` job's `SHA256SUMS.txt` step covers `rusty-imap-mcp-v*.tar.gz`
and the build-provenance attestation subject-path updates to the tarballs.

### 1b. Linux libdbus vendoring (tarball + bottle correctness)

The keyring backend (`keyring = { features = ["linux-native-sync-persistent"] }`)
pulls `dbus-secret-service` -> `libdbus-sys` on Linux, so the Linux binary
**dynamically links C libdbus** (why `release.yml` installs `libdbus-1-dev` on
every Linux build). A tarball or poured Homebrew bottle cannot declare a system
`libdbus-1-3` dependency, so a distributed Linux binary would fail to load
(`--version` errors before `main`) on any host without libdbus — a class of
minimal Homebrew-on-Linux and container hosts. `brew test` on a CI runner that
has libdbus installed would pass while real users break.

Fix (mirrors bzr): the **x86_64 and aarch64 Linux** binaries — the targets that
feed both tarballs and Homebrew bottles — are built with a new
`vendored-keyring` cargo feature that **static-links libdbus** into the binary,
so it carries no runtime `libdbus-1.so` dependency. Mechanism:

- `crates/rimap-config/Cargo.toml` declares an optional, **Linux-target-gated**
  direct dependency and a **weak** feature reference (mirroring bzr exactly —
  the strong `dep:` form is a cross-platform sharp edge, see below):

  ```toml
  [target.'cfg(target_os = "linux")'.dependencies]
  dbus-secret-service = { version = "4.1", optional = true, default-features = false }

  [features]
  vendored-keyring = ["dbus-secret-service?/vendored"]
  ```

  The `4.1` pin satisfies cargo-deny's wildcard ban and unifies with keyring
  3.6.3's transitive `dbus-secret-service 4.1.0`. The weak `?/vendored` means
  "if `dbus-secret-service` is otherwise in the graph, turn on its `vendored`
  feature." On Linux keyring pulls it in (non-optionally, via
  `linux-native-sync-persistent`), so `vendored` applies:
  `dbus-secret-service/vendored` -> `dbus/vendored` -> `libdbus-sys/vendored`
  compiles libdbus from source via `cc` (`rustc-link-lib=static=dbus`;
  libdbus-sys gates its pkg-config probe off under `vendored`). On macOS/Windows
  the dep is absent, so `?/vendored` is a **clean no-op** — no feature-resolution
  error even under `--all-features`. (The strong
  `["dep:dbus-secret-service", "dbus-secret-service/vendored"]` form would
  force-activate a target-gated dep on non-Linux targets and can error during
  resolution; the weak form is why bzr uses `?/`.)
- `crates/rimap-server/Cargo.toml` re-exports it:
  `vendored-keyring = ["rimap-config/vendored-keyring"]`.
- The feature is **off by default** for local dev and the release build's
  x86_64/aarch64 Linux legs pass `--features vendored-keyring` explicitly.
  **However** — this is a cargo feature, so any `--all-features` invocation
  activates it, and several Linux guardrails run `--all-features`:
  `cargo clippy/check/llvm-cov` (ci.yml), the MSRV check and `cargo deny`
  (justfile). Those Linux jobs will therefore compile libdbus from source too.
  This is **accepted**: the C compile is bounded (ubuntu runners ship the
  toolchain; `cc` is already ubiquitous in the graph), non-Linux `--all-features`
  is a no-op per the weak form, and cutting vendoring off the feature axis is not
  possible (a cargo feature is inherently `--all-features`-reachable). The
  supply-chain review confirms the cargo-deny graph delta (notably `cc` as a
  build-dep of `libdbus-sys` under `vendored`) stays within `deny.toml` rules.

The **ppc64le and s390x** tarballs are **not** vendored (they have no Homebrew
bottle path and are niche): they retain the dynamic libdbus link and the README
notes those two tarballs require a system `libdbus-1-3`. macOS is unaffected
(`apple-native` uses the Security framework, no libdbus). Adding
`--features vendored-keyring` is a supply-chain-relevant change (new direct dep,
feature unification) and is called out for the supply-chain review in the
implementation plan.

### 2. Release job: draft -> published

The `release` job drops `--draft` from `gh release create` so the release
publishes immediately on tag push. This is required: the `homebrew` and
`bottles` jobs download assets from the public
`https://github.com/.../releases/download/<tag>/` CDN, which only serves
assets from a **published** release. Publishing directly (rather than gating
on a manual draft-review step) is the approved tradeoff for Phase 1; a
review gate returns with the release-prep PR when the `-dev` model lands.

The `release` job declares `environment: release`. As of this design that
environment is **referenced but not configured** (the repo's only configured
environment is `sonarcloud`), so it carries **no required-reviewer or wait-timer
protection** — publishing is genuinely immediate on tag push, and the
homebrew/bottles jobs do not stall. This is deliberate for Phase 1: a future
maintainer who adds required-reviewer protection to the `release` environment
would silently gate the tap/bottle pipeline behind manual approval, so any such
change must be paired with revisiting this section.

### 3. Homebrew formula template + `homebrew` job

A new `homebrew/rusty-imap-mcp.rb.template` mirrors bzr's template:

```ruby
class RustyImapMcp < Formula
  desc "Security-first MCP server for IMAP email access"
  homepage "https://github.com/randomparity/rusty-imap-mcp"
  license any_of: ["MIT", "Apache-2.0"]
  version "{{VERSION}}"

  on_macos do
    on_arm do
      url ".../releases/download/v{{VERSION}}/rusty-imap-mcp-v{{VERSION}}-aarch64-apple-darwin.tar.gz"
      sha256 "{{MAC_ARM_SHA}}"
    end
    on_intel do
      # No prebuilt Intel macOS binary — fall back to a source build.
      url ".../archive/refs/tags/v{{VERSION}}.tar.gz"
      sha256 "{{SRC_SHA}}"
      depends_on "rust" => :build
    end
  end

  on_linux do
    on_arm do
      url ".../rusty-imap-mcp-v{{VERSION}}-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "{{LINUX_ARM_SHA}}"
    end
    on_intel do
      url ".../rusty-imap-mcp-v{{VERSION}}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "{{LINUX_INTEL_SHA}}"
    end
  end

  def install
    if OS.mac? && Hardware::CPU.intel?
      ENV["CARGO_TARGET_DIR"] = buildpath/"target"
      system "cargo", "install", "--locked", "--root", prefix, "--path", "crates/rimap-server"
    else
      bin.install "rusty-imap-mcp"
    end
  end

  test do
    assert_match "rusty-imap-mcp", shell_output("#{bin}/rusty-imap-mcp --version")
  end
end
```

License uses `any_of: ["MIT", "Apache-2.0"]` (SPDX), matching the workspace
`MIT OR Apache-2.0`. No manpage handling in Phase 1.

The `homebrew` job (`needs: release`, `if: !contains(github.ref_name, '-')`):

1. Checks out this repo (for the template) and the tap
   (`repository: randomparity/homebrew-tap`, `token: HOMEBREW_TAP_TOKEN`,
   `path: tap`).
2. `curl --fail --silent --location --retry 5 --retry-all-errors --retry-delay 5 <asset> | sha256sum`
   for each prebuilt tarball (mac arm64, Linux x86_64, Linux aarch64) and the
   GitHub source tarball (`archive/refs/tags/<tag>.tar.gz`) for the Intel-mac
   source branch. The `--retry` flags absorb releases/download CDN propagation
   lag: with `--draft` dropped, this job runs seconds after publish and the CDN
   can briefly 404/5xx an asset that exists. The bottle build's asset pulls get
   the same retry treatment.
3. `sed` the placeholders into `tap/Formula/rusty-imap-mcp.rb`.
4. Commit + push (no-op guard when the formula is already current).

### 4. Bottles + bottles-merge jobs

Mirror bzr's two-stage bottle build:

- **`bottles`** (`needs: homebrew`, stable tags only) — matrix over
  `macos-14` (arm64 macOS; oldest arm runner so the `arm64_sonoma` bottle
  pours on newer macOS too), `ubuntu-latest` (x86_64 Linux), and
  `ubuntu-24.04-arm` (arm64 Linux). Each leg:
  - On Linux, ensures Homebrew is on PATH. **No `libdbus-1-3` install is
    needed**: the x86_64/aarch64 Linux tarball binaries the formula pours are
    built with `vendored-keyring` (static libdbus, §1b), so neither the bottle
    runner nor the end user needs a system libdbus. (This is the payoff of §1b —
    the bottle would otherwise pass `brew test` on a libdbus-equipped runner and
    break for users without it.)
  - `brew tap randomparity/tap`; `brew install --build-bottle randomparity/tap/rusty-imap-mcp`.
  - `brew bottle --json --no-rebuild --root-url <release-base>`.
  - Renames the double-dash local bottle file to the single-dash form
    Homebrew requests from `root_url`, `gh release upload --clobber` it, and
    uploads the bottle JSON as a workflow artifact.
- **`bottles-merge`** (`needs: bottles`, stable tags only) — downloads the
  JSONs, `brew tap`, `brew trust --formula randomparity/tap/rusty-imap-mcp`
  (Homebrew 6 requires trusting a non-official formula that `--merge` loads
  by tap context), `brew bottle --merge --write --no-commit`, `ruby -c`
  parse-gate on the formula, then a second tap commit pushing the
  `bottle do` block.

If any bottle leg fails, `bottles-merge` is skipped and the formula stays
bottle-less — degrading to the binary-download `install` path.

### 5. `RELEASING.md` (new, repo root)

Adapted from bzr's `RELEASING.md`, written for the **current** version model:

- **Pre-release checklist**: confirm `Cargo.toml` version matches the intended
  tag; ensure a dated `## [X.Y.Z] - YYYY-MM-DD` CHANGELOG section exists (the
  `release.yml` awk extractor produces an empty body otherwise); run local
  checks (`just ci` or fmt/clippy/test + `cargo build --release`);
  `scripts/check-release-version.sh vX.Y.Z`.
- **Tag-and-push**: tag the merge commit on `main`
  (`git tag -a vX.Y.Z -m "rusty-imap-mcp vX.Y.Z"`; `git push origin vX.Y.Z`).
  No `Cargo.toml` edit at release time — `build.rs` supplies the dev suffix on
  non-tag builds; a release build reports the clean semver.
- **What automation does**: `verify-tag` guard, 5-target build, tarball
  packaging, `SHA256SUMS.txt`, provenance attestation, published GitHub
  Release, Homebrew tap bump, bottle build + merge.
- **One-time tap setup**: create/confirm the tap repo, render the first
  formula, and create the `HOMEBREW_TAP_TOKEN` fine-grained PAT
  (`Contents: Write` on `randomparity/homebrew-tap`). A companion
  `homebrew/README.md` (mirroring bzr's) carries the same setup detail plus
  end-user install instructions and the homebrew-core future goal.
- **Planned (later phases)**: `-dev` version model, crates.io publish
  (8-crate workspace), deb/rpm + manpages + installers.

### 6. README update

- Add a **Homebrew** subsection to the install section:
  `brew install randomparity/tap/rusty-imap-mcp` (with `brew tap` shown as
  the two-step alternative). Note the supported prebuilt platforms
  (macOS arm64, Linux x86_64, Linux aarch64) and the Intel-mac source-build
  fallback.
- Rewrite the "Installing a prebuilt binary" section for **tarballs**:
  download `rusty-imap-mcp-vX.Y.Z-<triple>.tar.gz` + `SHA256SUMS.txt`,
  `sha256sum --ignore-missing -c SHA256SUMS.txt`, `tar xzf`, then
  `chmod`/place `rusty-imap-mcp` on `$PATH`. Keep the macOS Gatekeeper
  quarantine note.
- Note that the **ppc64le and s390x** Linux tarballs are not libdbus-vendored
  (§1b) and require a system `libdbus-1-3` at runtime; the x86_64/aarch64 Linux
  and macOS tarballs are self-contained.

## Data flow

```
git tag vX.Y.Z (on main merge commit) ──> push
        │
        ▼
release.yml
  verify-tag ──> build (×5 triples; x86_64+aarch64 Linux use --features vendored-keyring)
             ──> package rusty-imap-mcp-vX.Y.Z-<triple>.tar.gz
        │
        ▼
  release (publish): SHA256SUMS.txt + provenance + gh release create (no --draft)
        │
        ▼
  homebrew: curl|sha256sum each tarball ──> sed template ──> push Formula/rusty-imap-mcp.rb
        │
        ▼
  bottles (×3 OS): brew install --build-bottle ──> brew bottle ──> upload bottle + JSON
        │
        ▼
  bottles-merge: brew bottle --merge --write ──> ruby -c ──> push bottle do block
```

## Error handling

| Path                                             | Outcome                                             |
|--------------------------------------------------|-----------------------------------------------------|
| Tag pushed but `Cargo.toml` not matching          | `verify-tag` hard-fails before any build            |
| No dated CHANGELOG section for the tag            | Release-notes step errors (existing behavior)       |
| Prerelease tag (`vX.Y.Z-rc1`)                     | `verify-tag` hard-fails (see prerelease note below) — nothing builds |
| Transient CDN 404/5xx right after publish          | `curl --retry` absorbs propagation lag; only a persistent miss fails the job |
| A tarball asset genuinely missing (404 after retries) | `curl --fail` errors the job; formula not pushed |
| A bottle leg fails                                | `bottles-merge` skipped; formula stays bottle-less  |
| Rendered formula is invalid Ruby                  | `ruby -c` gate blocks the bottle-merge push         |
| `HOMEBREW_TAP_TOKEN` missing/expired              | tap checkout/push fails; release + tarballs unaffected |
| Intel-mac `{{SRC_SHA}}` mismatch (GitHub regenerated the auto source tarball) | `brew install` hard-fails on Intel mac only, post-release; recover by re-fetching `SRC_SHA` and pushing a formula fixup commit |

**Prerelease tags are not supported in Phase 1.**
`scripts/check-release-version.sh` (run by `verify-tag`) enforces
`^v[0-9]+\.[0-9]+\.[0-9]+$` and rejects any `-`, so a tag like `v0.1.0-rc1`
fails before any build job runs — no release, no brew jobs. The
`if: !contains(github.ref_name, '-')` guards on the homebrew/bottles/bottles-merge
jobs are therefore **unreachable in Phase 1**; they are retained deliberately as
forward-compatible defense for Phase 2 (the `-dev`/prerelease model), so that
phase does not have to re-add them. Loosening `verify-tag` to accept prerelease
suffixes (and adding `--prerelease` to `gh release create`) is Phase 2 work, not
Phase 1.

## Testing strategy

- **`verify-tag` dry run**: `workflow_dispatch` with `dry_run: true` exercises
  the guard against the current `Cargo.toml` (unchanged from today).
- **Tarball layout**: a local packaging check confirms the tarball contains
  `rusty-imap-mcp` (unsuffixed) plus the license/NOTICE/README files, so
  `bin.install "rusty-imap-mcp"` resolves.
- **Formula parse**: `ruby -c Formula/rusty-imap-mcp.rb` gate in
  `bottles-merge`; `brew test` (`--version` substring assertion) runs inside
  each bottle build.
- **Linux vendoring (libdbus)**: prove §1b for **both** Linux triples with an
  arch-independent linkage check — `readelf -d <bin> | grep NEEDED` (or
  `objdump -p`) must show **no `libdbus-1.so`** entry. `ldd` is unusable for the
  aarch64 binary (cross-built via `cross`; `ldd` on a foreign-arch ELF from the
  x86_64 runner does not resolve NEEDED). Then run the binary with `--version`:
  the x86_64 binary in a **clean container without `libdbus-1-3`**, and the
  aarch64 binary under `qemu-user`. `brew test` on a libdbus-equipped CI runner
  cannot catch a missing-libdbus regression, so these are the checks that
  actually prove §1b. The plan must also confirm the `cross` aarch64 image ships
  the target C toolchain the vendored `cc` build needs.
- **End-to-end**: the `v0.1.0` tag push is the acceptance test — release
  published, formula pushed to the tap, bottles built and merged, and
  `brew install randomparity/tap/rusty-imap-mcp` succeeding on a supported
  platform.

## Rollout / ordering

1. Land the Phase 1 changes (release.yml jobs, `homebrew/` template + README,
   `RELEASING.md`, README) on `release/v0.1.0-phase1` -> PR -> merge to `main`.
2. Perform the one-time tap setup and add the `HOMEBREW_TAP_TOKEN` secret.
3. Tag `v0.1.0` on the `main` merge commit and push. Confirm the pipeline:
   `verify-tag` -> build -> release -> homebrew -> bottles -> bottles-merge.
4. Verify `brew install randomparity/tap/rusty-imap-mcp` on a supported
   platform.

## Open questions

None blocking. Carried risks (not blockers for Phase 1):

- The `vendored-keyring` feature adds a direct optional `dbus-secret-service`
  dependency and relies on cargo feature unification applying `vendored` to the
  instance keyring already pulls. The implementation plan routes this through
  the supply-chain review (cargo-deny, `deny.toml` wildcard rules) and verifies
  the resulting binary via `ldd` (no `libdbus-1.so`).
- Phase 2+ specs will address the `-dev` version model, crates.io publishing
  (8-crate workspace, name availability), and deb/rpm + manpages + installers.
