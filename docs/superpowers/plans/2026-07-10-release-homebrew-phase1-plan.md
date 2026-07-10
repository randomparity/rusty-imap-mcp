# Release v0.1.0 + Homebrew Tap (Phase 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `rusty-imap-mcp v0.1.0` as `.tar.gz` GitHub Release artifacts and auto-publish a bottled Homebrew formula to `randomparity/homebrew-tap`, mirroring bzr's release pipeline.

**Architecture:** Extend `.github/workflows/release.yml` (tag-triggered) to package tarballs, static-link libdbus into the Linux binaries that feed Homebrew, publish (not draft) the release, render + push a formula, and build + merge native bottles. Add the `vendored-keyring` cargo feature, the formula template, and release documentation. Keep the current `build.rs`-computed version model (no `Cargo.toml` edit at release time).

**Tech Stack:** GitHub Actions, Rust/Cargo (workspace), `cargo-auditable`, `cross`, Homebrew (formula + bottles), bash, `sed`, `curl`.

**Spec:** `docs/superpowers/specs/2026-07-10-release-homebrew-phase1-design.md`
**ADR:** `docs/ADR/0002-phased-bzr-release-parity-and-direct-publish.md`

## Global Constraints

- **Branch:** `release/v0.1.0-phase1` (already exists, holds spec + ADR). BASE_BRANCH = `main`. Never commit on `main`.
- **Guardrails (run before each commit that touches the relevant surface):**
  - Rust: `just fmt-check`, `just lint`, `cargo check --workspace`, `just deny` (cargo-deny), `just ci` for the full suite.
  - Workflows: `actionlint .github/workflows/release.yml` and `zizmor .github/workflows/release.yml` — both must be clean.
  - Formula/docs: `ruby -c` on any rendered formula; `typos` clean on changed files.
- **Action pinning:** every `uses:` is a 40-char commit SHA with a `# vX.Y.Z` comment; every `actions/checkout` sets `persist-credentials: false` (except where a push token is deliberately used). Reuse the SHAs already pinned in `release.yml`.
- **Naming:** binary = `rusty-imap-mcp` (from `rimap-server`). Tarball = `rusty-imap-mcp-vX.Y.Z-<triple>.tar.gz` with a single top-level dir `rusty-imap-mcp-vX.Y.Z-<triple>/` containing the binary + `LICENSE-MIT` + `LICENSE-APACHE` + `NOTICE` + `README.md`. Formula class = `RustyImapMcp`, file `Formula/rusty-imap-mcp.rb`, `license any_of: ["MIT", "Apache-2.0"]`.
- **Vendoring targets:** only `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu` build with `--features vendored-keyring`. `powerpc64le`/`s390x`/macOS do not.
- **Tap:** `randomparity/homebrew-tap`, pushed via `HOMEBREW_TAP_TOKEN` secret (fine-grained PAT, `Contents: Write`). One-time setup + tag push are out-of-band manual steps (Task 6 checklist), not part of any workflow run.
- **Commit trailer:** end every commit message with `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.

---

## Task 1: `vendored-keyring` cargo feature (static libdbus for Linux)

**Files:**
- Modify: `Cargo.toml` (root — add `dbus-secret-service` to `[workspace.dependencies]`)
- Modify: `crates/rimap-config/Cargo.toml`
- Modify: `crates/rimap-server/Cargo.toml`
- Modify: `deny.toml` (only if cargo-deny flags the new dep/`cc`)

**Interfaces:**
- Produces: a workspace feature `vendored-keyring` (enable via `cargo build -p rimap-server --features vendored-keyring`) that static-links libdbus on Linux; a no-op on macOS/Windows.

**Host prerequisite for the local verification steps (5–7):** the machine needs a C toolchain plus libdbus headers — `sudo apt-get install -y libdbus-1-dev pkg-config build-essential` (this mirrors the release.yml x86_64 job env). Without them the default build (Step 6) fails at pkg-config and the vendored build (Step 5) fails at the `cc` compile.

- [ ] **Step 1: Add `dbus-secret-service` to `[workspace.dependencies]`**

The root `Cargo.toml` documents "No member crate may declare a version directly." Follow the existing target-gated precedent (`libc = "0.2"` in `[workspace.dependencies]`, referenced as `libc = { workspace = true }` in `rimap-audit`). Add to the root `Cargo.toml` `[workspace.dependencies]`:

```toml
# Declared here so rimap-config's `vendored-keyring` feature can enable its
# `vendored` (static libdbus) feature. `4.1` unifies with keyring 3.6.3's
# transitive dbus-secret-service 4.1.0. default-features stay off — keyring's
# own transitive pull supplies the crypto backend; feature unification is
# additive.
dbus-secret-service = { version = "4.1", default-features = false }
```

- [ ] **Step 2: Reference it (optional, Linux-gated) + add the weak feature in `rimap-config`**

In `crates/rimap-config/Cargo.toml`, add a Linux-target-gated optional dependency (via `workspace = true`) and a `[features]` table:

```toml
[target.'cfg(target_os = "linux")'.dependencies]
# Linux-only, declared solely so `vendored-keyring` can turn on its `vendored`
# feature (static libdbus). keyring already pulls this crate in non-optionally
# on Linux via `linux-native-sync-persistent`; the weak `?/` reference below
# applies `vendored` to that same instance.
dbus-secret-service = { workspace = true, optional = true }

[features]
# Static-link libdbus so release Linux binaries carry no runtime libdbus-1.so.
# STRONG dep: form is required — keyring pulls dbus-secret-service through its
# own edge, not this optional dep, so the weak `?/vendored` never fires. The
# optional dep is Linux-cfg-gated, so dep: is a clean no-op on macOS/Windows
# (verified via cargo metadata --filter-platform).
vendored-keyring = ["dep:dbus-secret-service", "dbus-secret-service/vendored"]
```

- [ ] **Step 3: Re-export the feature from `rimap-server`**

In `crates/rimap-server/Cargo.toml`, add (or extend) a `[features]` table:

```toml
[features]
vendored-keyring = ["rimap-config/vendored-keyring"]
```

- [ ] **Step 4: Verify the feature resolves and reaches libdbus-sys on Linux**

Run:
```bash
cargo tree -p rimap-config --features vendored-keyring -i libdbus-sys -e features 2>/dev/null | rg -i 'libdbus-sys|vendored'
```
Expected: `libdbus-sys` appears with the `vendored` feature active (the chain `dbus-secret-service vendored -> dbus vendored -> libdbus-sys vendored`).

- [ ] **Step 5: Verify non-Linux resolution is a clean no-op**

Run (resolution only, no build — catches the target-gated-feature sharp edge):
```bash
cargo metadata --all-features --filter-platform x86_64-apple-darwin --format-version 1 >/dev/null && echo "macOS resolves OK"
cargo metadata --all-features --filter-platform x86_64-pc-windows-msvc --format-version 1 >/dev/null && echo "windows resolves OK"
```
Expected: both print OK, no error. (Proves `--all-features` on non-Linux does not error on the weak feature.)

- [ ] **Step 6: Build the release binary with the feature and assert no dynamic libdbus**

Run:
```bash
cargo build --release -p rimap-server --features vendored-keyring
readelf -d target/release/rusty-imap-mcp | rg -i 'NEEDED' | rg -i 'dbus' || echo "OK: no libdbus NEEDED entry"
```
Expected: `OK: no libdbus NEEDED entry` (the vendored static libdbus leaves no `libdbus-1.so.3` NEEDED entry).

- [ ] **Step 7: Confirm default build still links libdbus dynamically (feature is off by default)**

Run:
```bash
cargo build --release -p rimap-server
readelf -d target/release/rusty-imap-mcp | rg -i 'NEEDED' | rg -i 'dbus' && echo "OK: default build still dynamic-links libdbus"
```
Expected: a `libdbus-1.so.3` NEEDED entry is present (default/dev builds keep using system libdbus).

- [ ] **Step 8: Run cargo-deny and fmt/lint; adjust `deny.toml` only if needed**

Run:
```bash
just deny
just fmt-check && just lint
```
Expected: green. If cargo-deny flags a new advisory/license/duplicate for `dbus-secret-service`/`cc`/`libdbus-sys`, add a narrowly-scoped, commented exception to `deny.toml` (do not broaden global rules). Re-run until green.

- [ ] **Step 9: Commit**

```bash
git add Cargo.toml crates/rimap-config/Cargo.toml crates/rimap-server/Cargo.toml Cargo.lock
# add deny.toml only if you changed it
git commit -m "feat(release): add vendored-keyring feature to static-link libdbus

Off by default; release Linux legs build with it so tarball/bottle binaries
carry no runtime libdbus-1.so dependency. Weak dbus-secret-service?/vendored
is a clean no-op on macOS/Windows.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: Tarball packaging, vendored Linux legs, publish (not draft)

**Files:**
- Modify: `.github/workflows/release.yml`

**Interfaces:**
- Consumes: the `vendored-keyring` feature from Task 1.
- Produces: release assets `rusty-imap-mcp-vX.Y.Z-<triple>.tar.gz` (×5) + `SHA256SUMS.txt`, on a **published** (non-draft) release. Task 3's `homebrew` job consumes these asset URLs.

- [ ] **Step 1: Build the two Linux bottle-feeding legs with the vendored feature**

In `release.yml`, for `build-linux-x86_64` change the build step from
`cargo auditable build --release --locked` to:
```yaml
      - run: cargo auditable build --release --locked -p rimap-server --features vendored-keyring
```
Do the same for `build-linux-aarch64`, changing the `cross` invocation to:
```yaml
      - run: cross auditable build --release --locked --target aarch64-unknown-linux-gnu -p rimap-server --features vendored-keyring
```
Leave `build-macos-aarch64`, `build-linux-ppc64le`, and `build-linux-s390x` build commands unchanged (no feature).

- [ ] **Step 2: Replace each "Rename binary" + upload with tarball packaging**

For every one of the 5 build jobs, replace the `Rename binary` step and the `upload-artifact` step with a packaging step + upload. Template (substitute `<TRIPLE>` and the correct binary source path per job):

```yaml
      - name: Package tarball
        env:
          TAG: ${{ github.ref_name }}
        run: |
          set -euo pipefail
          triple="<TRIPLE>"
          stage="${BINARY_NAME}-${TAG}-${triple}"   # e.g. rusty-imap-mcp-v0.1.0-x86_64-unknown-linux-gnu
          mkdir "$stage"
          cp "<BINARY_SRC_PATH>" "$stage/${BINARY_NAME}"
          cp LICENSE-MIT LICENSE-APACHE NOTICE README.md "$stage/"
          tar czf "${stage}.tar.gz" "$stage"
      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a  # v7.0.1
        with:
          name: ${{ env.BINARY_NAME }}-${{ github.ref_name }}-<TRIPLE>
          path: ${{ env.BINARY_NAME }}-${{ github.ref_name }}-<TRIPLE>.tar.gz
```

`<BINARY_SRC_PATH>` per job:
- x86_64 linux / macos: `target/release/${BINARY_NAME}`
- aarch64 linux: `target/aarch64-unknown-linux-gnu/release/${BINARY_NAME}`
- ppc64le/s390x: `target/release/${BINARY_NAME}` (docker builds into the mounted workspace `target/`)

Note `${BINARY_NAME}` is available in the shell via `env.BINARY_NAME` (already set at workflow level); reference it as `$BINARY_NAME` inside `run:` by adding `BINARY_NAME: ${{ env.BINARY_NAME }}` to that step's `env:` alongside `TAG`, or inline `${{ env.BINARY_NAME }}`. Use one consistent style.

- [ ] **Step 3: Point SHA256SUMS + attestation at the tarballs**

In the `release` job, the download-artifact `merge-multiple: true` already collects all uploaded files into `artifacts/`. Update the checksum step glob and the attestation subject-path to the tarballs:
```yaml
      - name: Generate SHA256 checksums
        run: |
          cd artifacts
          sha256sum ${{ env.BINARY_NAME }}-*.tar.gz > SHA256SUMS.txt
          cat SHA256SUMS.txt
      - uses: actions/attest-build-provenance@0f67c3f4856b2e3261c31976d6725780e5e4c373  # v4.1.1
        with:
          subject-path: |
            artifacts/rusty-imap-mcp-*.tar.gz
            artifacts/SHA256SUMS.txt
```

- [ ] **Step 4: Publish the release (drop `--draft`) and attach the tarballs**

In the `release` job's `gh release create` step, remove `--draft` and update the asset glob:
```yaml
      - name: Create release
        env:
          GH_TOKEN: ${{ github.token }}
          TAG_NAME: ${{ github.ref_name }}
        run: |
          gh release create "$TAG_NAME" \
            --title "$TAG_NAME" \
            --notes-file RELEASE_NOTES.md \
            artifacts/${{ env.BINARY_NAME }}-*.tar.gz \
            artifacts/SHA256SUMS.txt
```

- [ ] **Step 5: Lint the workflow**

Run:
```bash
actionlint .github/workflows/release.yml && echo "actionlint OK"
zizmor .github/workflows/release.yml && echo "zizmor OK"
```
Expected: both clean. Fix any finding (e.g. add missing `env:`, quote expansions) before committing.

- [ ] **Step 6: Dry-run the tag guard**

Run:
```bash
scripts/check-release-version.sh v0.1.0 && echo "verify-tag guard OK"
```
Expected: `ok: tag 'v0.1.0' matches Cargo.toml workspace version '0.1.0'`. (Confirms the retained guard still passes for the tag we will push.)

- [ ] **Step 7: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "feat(release): package tarballs, vendor Linux libdbus, publish directly

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: Homebrew formula template + `homebrew` job

**Files:**
- Create: `homebrew/rusty-imap-mcp.rb.template`
- Modify: `.github/workflows/release.yml` (add `homebrew` job)

**Interfaces:**
- Consumes: the published tarball assets from Task 2.
- Produces: `Formula/rusty-imap-mcp.rb` pushed to `randomparity/homebrew-tap`. Task 4's `bottles` job consumes the tapped formula.

- [ ] **Step 1: Write the formula template**

Create `homebrew/rusty-imap-mcp.rb.template`:
```ruby
class RustyImapMcp < Formula
  desc "Security-first MCP server for IMAP email access"
  homepage "https://github.com/randomparity/rusty-imap-mcp"
  license any_of: ["MIT", "Apache-2.0"]
  version "{{VERSION}}"

  on_macos do
    on_arm do
      url "https://github.com/randomparity/rusty-imap-mcp/releases/download/v{{VERSION}}/rusty-imap-mcp-v{{VERSION}}-aarch64-apple-darwin.tar.gz"
      sha256 "{{MAC_ARM_SHA}}"
    end
    on_intel do
      # No prebuilt Intel macOS binary — fall back to a source build.
      url "https://github.com/randomparity/rusty-imap-mcp/archive/refs/tags/v{{VERSION}}.tar.gz"
      sha256 "{{SRC_SHA}}"
      depends_on "rust" => :build
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/randomparity/rusty-imap-mcp/releases/download/v{{VERSION}}/rusty-imap-mcp-v{{VERSION}}-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "{{LINUX_ARM_SHA}}"
    end
    on_intel do
      url "https://github.com/randomparity/rusty-imap-mcp/releases/download/v{{VERSION}}/rusty-imap-mcp-v{{VERSION}}-x86_64-unknown-linux-gnu.tar.gz"
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

- [ ] **Step 2: Verify the template renders to valid Ruby**

Run (dummy values):
```bash
sed -e 's|{{VERSION}}|0.1.0|g' -e 's|{{MAC_ARM_SHA}}|0|g' -e 's|{{LINUX_ARM_SHA}}|0|g' \
    -e 's|{{LINUX_INTEL_SHA}}|0|g' -e 's|{{SRC_SHA}}|0|g' \
    homebrew/rusty-imap-mcp.rb.template | ruby -c
```
Expected: `Syntax OK`.

- [ ] **Step 3: Add the `homebrew` job to `release.yml`**

Append after the `release` job:
```yaml
  homebrew:
    name: Bump randomparity/homebrew-tap
    needs: release
    if: ${{ !contains(github.ref_name, '-') }}
    runs-on: ubuntu-24.04
    permissions:
      contents: read
    steps:
      - name: Checkout rusty-imap-mcp (for template)
        uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0  # v7.0.0
        with:
          persist-credentials: false
      - name: Checkout tap
        uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0  # v7.0.0
        with:
          repository: randomparity/homebrew-tap
          token: ${{ secrets.HOMEBREW_TAP_TOKEN }}
          path: tap
      - name: Render formula
        env:
          TAG: ${{ github.ref_name }}
        run: |
          set -euo pipefail
          VERSION="${TAG#v}"
          BASE="https://github.com/randomparity/rusty-imap-mcp/releases/download/${TAG}"
          fetch_sha() {
            curl --fail --silent --show-error --location \
              --retry 5 --retry-all-errors --retry-delay 5 "$1" | sha256sum | awk '{print $1}'
          }
          MAC_ARM_SHA=$(fetch_sha   "${BASE}/rusty-imap-mcp-${TAG}-aarch64-apple-darwin.tar.gz")
          LINUX_ARM_SHA=$(fetch_sha "${BASE}/rusty-imap-mcp-${TAG}-aarch64-unknown-linux-gnu.tar.gz")
          LINUX_INTEL_SHA=$(fetch_sha "${BASE}/rusty-imap-mcp-${TAG}-x86_64-unknown-linux-gnu.tar.gz")
          SRC_SHA=$(fetch_sha "https://github.com/randomparity/rusty-imap-mcp/archive/refs/tags/${TAG}.tar.gz")
          mkdir -p tap/Formula
          sed \
            -e "s|{{VERSION}}|${VERSION}|g" \
            -e "s|{{MAC_ARM_SHA}}|${MAC_ARM_SHA}|g" \
            -e "s|{{LINUX_ARM_SHA}}|${LINUX_ARM_SHA}|g" \
            -e "s|{{LINUX_INTEL_SHA}}|${LINUX_INTEL_SHA}|g" \
            -e "s|{{SRC_SHA}}|${SRC_SHA}|g" \
            homebrew/rusty-imap-mcp.rb.template > tap/Formula/rusty-imap-mcp.rb
      - name: Commit and push
        working-directory: tap
        env:
          TAG: ${{ github.ref_name }}
        run: |
          set -euo pipefail
          git config user.name "github-actions[bot]"
          git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
          git add Formula/rusty-imap-mcp.rb
          if git diff --staged --quiet; then
            echo "Formula already up-to-date for ${TAG}; nothing to commit."
            exit 0
          fi
          git commit -m "rusty-imap-mcp ${TAG#v}"
          git push
```

- [ ] **Step 4: Lint the workflow**

Run:
```bash
actionlint .github/workflows/release.yml && zizmor .github/workflows/release.yml && echo "lint OK"
```
Expected: clean. (zizmor may warn on the tap checkout using a token — the `token:` on a non-default-repo checkout is intentional; if zizmor flags it, add a scoped `# zizmor: ignore[...]` with a justification comment matching the repo's existing style.)

- [ ] **Step 5: Commit**

```bash
git add homebrew/rusty-imap-mcp.rb.template .github/workflows/release.yml
git commit -m "feat(release): render + push Homebrew formula on stable tags

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: Bottles + bottles-merge jobs

**Files:**
- Modify: `.github/workflows/release.yml` (add `bottles` and `bottles-merge` jobs)

**Interfaces:**
- Consumes: the tapped formula from Task 3.
- Produces: bottle tarballs uploaded to the release + a `bottle do` block committed to the tap formula.

- [ ] **Step 1: Add the `bottles` job**

Append after `homebrew`:
```yaml
  bottles:
    name: Build bottle (${{ matrix.label }})
    needs: homebrew
    if: ${{ !contains(github.ref_name, '-') }}
    runs-on: ${{ matrix.os }}
    permissions:
      contents: write   # upload bottle tarballs to the GitHub release
    strategy:
      fail-fast: false
      matrix:
        include:
          - os: macos-14
            label: arm64 macOS
          - os: ubuntu-latest
            label: x86_64 Linux
          - os: ubuntu-24.04-arm
            label: arm64 Linux
    steps:
      - name: Set up Homebrew on PATH (Linux)
        if: runner.os == 'Linux'
        run: |
          set -euo pipefail
          if [ ! -x /home/linuxbrew/.linuxbrew/bin/brew ]; then
            NONINTERACTIVE=1 /bin/bash -c \
              "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
          fi
          echo "/home/linuxbrew/.linuxbrew/bin" >> "$GITHUB_PATH"
      - name: Build, bottle, and upload
        env:
          TAG: ${{ github.ref_name }}
          GH_TOKEN: ${{ github.token }}
        run: |
          set -euo pipefail
          VERSION="${TAG#v}"
          BASE="https://github.com/randomparity/rusty-imap-mcp/releases/download/${TAG}"
          brew tap randomparity/tap
          brew install --build-bottle randomparity/tap/rusty-imap-mcp
          workdir="$(mktemp -d)"; cd "$workdir"
          brew bottle --json --no-rebuild --root-url "$BASE" randomparity/tap/rusty-imap-mcp
          dd_file="$(ls rusty-imap-mcp--"${VERSION}".*.bottle.tar.gz)"
          sd_file="${dd_file/--/-}"
          mv "$dd_file" "$sd_file"
          gh release upload "$TAG" "$sd_file" --repo randomparity/rusty-imap-mcp --clobber
          mkdir -p "$GITHUB_WORKSPACE/bottle-json"
          cp ./*.json "$GITHUB_WORKSPACE/bottle-json/"
      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a  # v7.0.1
        with:
          name: bottle-json-${{ matrix.os }}
          path: bottle-json/*.json
          if-no-files-found: error
```

Note: **no `libdbus-1-3` apt install** on the Linux legs — the poured x86_64/aarch64 binary is vendored (Task 1), so no system libdbus is needed on the runner or for end users.

- [ ] **Step 2: Add the `bottles-merge` job**

Append after `bottles`:
```yaml
  bottles-merge:
    name: Add bottle block to formula
    needs: bottles
    if: ${{ !contains(github.ref_name, '-') }}
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - name: Set up Homebrew on PATH
        run: echo "/home/linuxbrew/.linuxbrew/bin" >> "$GITHUB_PATH"
      - name: Download bottle JSONs
        uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c  # v8.0.1
        with:
          pattern: bottle-json-*
          path: bottle-json
          merge-multiple: true
      - name: Merge bottle block and push to tap
        env:
          TAG: ${{ github.ref_name }}
          HOMEBREW_TAP_TOKEN: ${{ secrets.HOMEBREW_TAP_TOKEN }}
        run: |
          set -euo pipefail
          brew tap randomparity/tap
          brew trust --formula randomparity/tap/rusty-imap-mcp
          brew bottle --merge --write --no-commit bottle-json/*.json
          tap_dir="$(brew --repository randomparity/tap)"
          cd "$tap_dir"
          ruby -c Formula/rusty-imap-mcp.rb
          git config user.name "github-actions[bot]"
          git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
          git remote set-url origin \
            "https://x-access-token:${HOMEBREW_TAP_TOKEN}@github.com/randomparity/homebrew-tap.git"
          git add Formula/rusty-imap-mcp.rb
          if git diff --staged --quiet; then
            echo "Formula already carries the bottle block for ${TAG}; nothing to commit."
            exit 0
          fi
          git commit -m "rusty-imap-mcp ${TAG#v}: add bottles"
          git push origin HEAD:main
```

- [ ] **Step 3: Lint the workflow**

Run:
```bash
actionlint .github/workflows/release.yml && zizmor .github/workflows/release.yml && echo "lint OK"
```
Expected: clean. Address findings (SHA pins, `persist-credentials`, quoted vars) with scoped ignores + justification only where a rule is a false positive matching the repo's existing pattern.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "feat(release): build and merge Homebrew bottles on stable tags

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: Documentation — `homebrew/README.md`, `RELEASING.md`, README

**Files:**
- Create: `homebrew/README.md`
- Create: `RELEASING.md`
- Modify: `README.md`

**Interfaces:** none (docs).

- [ ] **Step 1: Write `homebrew/README.md`**

Cover: what the template is and which job renders it; end-user install (`brew install randomparity/tap/rusty-imap-mcp` and the two-step `brew tap` + `brew install`); supported prebuilt platforms (macOS arm64, Linux x86_64, Linux aarch64) + Intel-mac source fallback; one-time tap setup and the `HOMEBREW_TAP_TOKEN` PAT (`Contents: Write` on `randomparity/homebrew-tap`); the homebrew-core future goal. Adapt from bzr's `homebrew/README.md`, substituting names.

- [ ] **Step 2: Write `RELEASING.md`** (repo root)

Sections (written for the **current** tag-and-push model):
- **Pre-release checklist:** `Cargo.toml` `[workspace.package].version` equals the intended tag (no `-`); a dated `## [X.Y.Z] - YYYY-MM-DD` section exists in `CHANGELOG.md` (the `release.yml` awk extractor needs it); run `just ci`; run `scripts/check-release-version.sh vX.Y.Z`.
- **Tag and push:** `git checkout main && git pull --ff-only`; `git tag -a vX.Y.Z -m "rusty-imap-mcp vX.Y.Z"`; `git push origin vX.Y.Z`. No `Cargo.toml` edit — `build.rs` supplies the dev suffix on non-tag builds.
- **What automation does:** `verify-tag` guard → 5-target build (x86_64/aarch64 Linux vendored) → tarball packaging → `SHA256SUMS.txt` + provenance attestation → **published** GitHub Release → `homebrew` formula bump → `bottles` + `bottles-merge`.
- **One-time tap setup:** create/confirm `randomparity/homebrew-tap`; create the `HOMEBREW_TAP_TOKEN` fine-grained PAT (`Contents: Write`) and add it as a repo secret; point to `homebrew/README.md`.
- **Prerelease tags are unsupported** in Phase 1 (verify-tag rejects any `-`).
- **Planned (later phases):** `-dev` version model, crates.io (8-crate workspace), deb/rpm + manpages + installers.

- [ ] **Step 3: Update `README.md` install section**

- Add a **Homebrew** subsection: `brew install randomparity/tap/rusty-imap-mcp` (+ two-step `brew tap` alternative); supported prebuilt platforms + Intel-mac source fallback.
- Rewrite "Installing a prebuilt binary" for tarballs: download `rusty-imap-mcp-vX.Y.Z-<triple>.tar.gz` + `SHA256SUMS.txt`; `sha256sum --ignore-missing -c SHA256SUMS.txt`; `tar xzf ...`; place `rusty-imap-mcp` on `$PATH`; keep the macOS Gatekeeper note.
- Add a note: the **ppc64le and s390x** tarballs are not libdbus-vendored and need a system `libdbus-1-3`; x86_64/aarch64 Linux and macOS tarballs are self-contained.

- [ ] **Step 4: Typos + link sanity**

Run:
```bash
typos RELEASING.md homebrew/README.md README.md && echo "typos OK"
```
Expected: clean (fix or add to `typos.toml` only genuine false positives).

- [ ] **Step 5: Commit**

```bash
git add RELEASING.md homebrew/README.md README.md
git commit -m "docs(release): add RELEASING.md, homebrew tap README, Homebrew install docs

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: Full guardrail sweep + out-of-band release steps

**Files:** none (verification + operator runbook).

- [ ] **Step 1: Run the full guardrail suite**

Run:
```bash
just ci
actionlint .github/workflows/release.yml
zizmor .github/workflows/release.yml
```
Expected: green. Note (from project memory) that `just ci`'s local-only `typos` step may show pre-existing false positives unrelated to this change; the 8 gating CI checks are rustfmt/clippy/check(macOS)/test/test-MSRV/cargo-deny/zizmor/SonarQube — those must pass.

- [ ] **Step 2: Confirm the workflow-level dry-run path**

Confirm `release.yml` still has the `workflow_dispatch` `dry_run` input and that `verify-tag` is the only job that runs when `dry_run: true`. This is exercised via the GitHub UI after merge (out-of-band); note it in the PR description as the guard smoke test.

- [ ] **Step 3: Pre-tag gate — verify the aarch64 vendored cross-build (spec §Testing strategy)**

The spec requires proving §1b for **both** Linux triples and confirming the `cross` aarch64 image ships the C toolchain the vendored `cc` build needs. The aarch64 binary is cross-built, so this cannot be checked by Task 1's native steps — it must be verified before the production tag push (a failed aarch64 build would otherwise first surface on the tag). Run locally (requires Docker; `cross` is installed on demand):

```bash
cargo install cross --locked --version 0.2.5   # if not already present
cross build --release --target aarch64-unknown-linux-gnu -p rimap-server --features vendored-keyring
readelf -d target/aarch64-unknown-linux-gnu/release/rusty-imap-mcp | rg -i 'NEEDED' | rg -i 'dbus' \
  || echo "OK: aarch64 vendored build has no libdbus NEEDED entry"
```
Expected: the `cross` build succeeds (proving the aarch64 image's C toolchain compiles the bundled libdbus source) and `OK: aarch64 vendored build has no libdbus NEEDED entry`. If `cross` cannot run in this environment, treat the first CI `build-linux-aarch64` run on the tag as the gate and be ready to delete the tag on failure (the `release` job `needs` all 5 builds, so a failed aarch64 build skips publish rather than shipping a broken release).

- [ ] **Step 4: Record the out-of-band manual steps (do NOT run during implementation)**

These happen after the PR merges to `main`, in order:
1. Create the `HOMEBREW_TAP_TOKEN` fine-grained PAT (`Contents: Write` on `randomparity/homebrew-tap`) and add it as a repo secret on `randomparity/rusty-imap-mcp`.
2. Ensure `randomparity/homebrew-tap` exists with a `Formula/` dir (it does).
3. `git checkout main && git pull --ff-only origin main`.
4. `git tag -a v0.1.0 -m "rusty-imap-mcp v0.1.0" && git push origin v0.1.0`.
5. Watch the pipeline: `verify-tag → build ×5 → release → homebrew → bottles → bottles-merge`.
6. Verify `brew install randomparity/tap/rusty-imap-mcp` on a supported platform and, in a clean container without `libdbus-1-3`, that `rusty-imap-mcp --version` runs.

- [ ] **Step 5: No commit** (this task is verification + runbook only).

---

## Self-Review Notes

- **Spec coverage:** §1b → Task 1; §1 tarballs + §2 publish → Task 2; §3 formula + homebrew job → Task 3; §4 bottles → Task 4; §5 RELEASING + §6 README + tap README → Task 5; §8 testing + rollout → Tasks 1/2/6.
- **Vendored verification** uses `readelf` (arch-independent) per spec: x86_64 native in Task 1 (Steps 6–7), aarch64 cross-build as a pre-tag gate in Task 6 Step 3 (confirms the cross image's aarch64 C toolchain), and clean-container runtime proof in Task 6 Step 4.6.
- **Dependency governance:** `dbus-secret-service` version lives in `[workspace.dependencies]` (Task 1 Step 1), referenced via `{ workspace = true }` — matches the repo's single-version-source rule and the `libc` target-gated precedent.
- **Out-of-band** `HOMEBREW_TAP_TOKEN` and tag push are explicitly not workflow-run steps.
