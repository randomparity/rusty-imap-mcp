# Release v0.1.0 + Homebrew Tap (Phase 1) Design

Date: 2026-07-10
Status: Draft (pending user review)

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

### 2. Release job: draft -> published

The `release` job drops `--draft` from `gh release create` so the release
publishes immediately on tag push. This is required: the `homebrew` and
`bottles` jobs download assets from the public
`https://github.com/.../releases/download/<tag>/` CDN, which only serves
assets from a **published** release. Publishing directly (rather than gating
on a manual draft-review step) is the approved tradeoff for Phase 1; a
review gate returns with the release-prep PR when the `-dev` model lands.

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
2. `curl --fail --silent --location <asset> | sha256sum` for each prebuilt
   tarball (mac arm64, Linux x86_64, Linux aarch64) and the GitHub
   source tarball (`archive/refs/tags/<tag>.tar.gz`) for the Intel-mac
   source branch.
3. `sed` the placeholders into `tap/Formula/rusty-imap-mcp.rb`.
4. Commit + push (no-op guard when the formula is already current).

### 4. Bottles + bottles-merge jobs

Mirror bzr's two-stage bottle build:

- **`bottles`** (`needs: homebrew`, stable tags only) — matrix over
  `macos-14` (arm64 macOS; oldest arm runner so the `arm64_sonoma` bottle
  pours on newer macOS too), `ubuntu-latest` (x86_64 Linux), and
  `ubuntu-24.04-arm` (arm64 Linux). Each leg:
  - On Linux, ensures Homebrew is on PATH and installs `libdbus-1-3` (the
    keyring default feature links libdbus at runtime; `brew test` runs
    `--version`, so the loader needs it).
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

## Data flow

```
git tag vX.Y.Z (on main merge commit) ──> push
        │
        ▼
release.yml
  verify-tag ──> build (×5 triples) ──> package rusty-imap-mcp-vX.Y.Z-<triple>.tar.gz
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
| Prerelease tag (`vX.Y.Z-rc1`)                     | `homebrew`/`bottles`/`bottles-merge` skipped (`if`) |
| A tarball asset 404s during `homebrew` sha fetch  | `curl --fail` errors the job; formula not pushed    |
| A bottle leg fails                                | `bottles-merge` skipped; formula stays bottle-less  |
| Rendered formula is invalid Ruby                  | `ruby -c` gate blocks the bottle-merge push         |
| `HOMEBREW_TAP_TOKEN` missing/expired              | tap checkout/push fails; release + tarballs unaffected |

## Testing strategy

- **`verify-tag` dry run**: `workflow_dispatch` with `dry_run: true` exercises
  the guard against the current `Cargo.toml` (unchanged from today).
- **Tarball layout**: a local packaging check confirms the tarball contains
  `rusty-imap-mcp` (unsuffixed) plus the license/NOTICE/README files, so
  `bin.install "rusty-imap-mcp"` resolves.
- **Formula parse**: `ruby -c Formula/rusty-imap-mcp.rb` gate in
  `bottles-merge`; `brew test` (`--version` substring assertion) runs inside
  each bottle build.
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

None at design time. Phase 2+ specs will address the `-dev` version model,
crates.io publishing, and deb/rpm + manpages + installers.
