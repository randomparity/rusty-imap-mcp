# Releasing `rusty-imap-mcp`

This project ships release binaries as GitHub Release `.tar.gz` artifacts and a
Homebrew formula (with native bottles) in
[`randomparity/homebrew-tap`](https://github.com/randomparity/homebrew-tap). A
release is cut by pushing a `vX.Y.Z` git tag; the rest is automated by
[`.github/workflows/release.yml`](.github/workflows/release.yml).

This is **Phase 1** of the release process. See
[ADR-0002](docs/ADR/0002-phased-bzr-release-parity-and-direct-publish.md) and
[the Phase 1 design](docs/superpowers/specs/2026-07-10-release-homebrew-phase1-design.md)
for scope and the planned later phases.

## Version-number convention

`Cargo.toml` always carries a clean semver (`version = "0.1.0"`) — there is **no
`-dev` suffix in the manifest**. `crates/rimap-core/build.rs` computes the
runtime version at build time: a build from a `vX.Y.Z` tag reports the bare
`X.Y.Z`; every other build reports `X.Y.Z-dev+g<sha>` (with `.dirty` when the
worktree is dirty). Cutting a release is therefore "tag and push" — no manifest
edit at release time.

The `verify-tag` job (mirrored locally by
[`scripts/check-release-version.sh`](scripts/check-release-version.sh)) hard-fails
if the tag does not match `Cargo.toml` or is not exactly `^v[0-9]+\.[0-9]+\.[0-9]+$`.

**Prerelease tags are not supported in Phase 1** — `verify-tag` rejects any tag
containing `-`.

## One-time setup (before the first release)

1. Confirm `randomparity/homebrew-tap` exists with a `Formula/` directory.
2. Create a **fine-grained** PAT scoped to `randomparity/homebrew-tap` only,
   with **`Contents: Write`** (no other repos, no other scopes — this bounds the
   blast radius), and add it to this repo's secrets as `HOMEBREW_TAP_TOKEN`. See
   [`homebrew/README.md`](homebrew/README.md).
3. **Protect the `v*` tags.** Because the release publishes directly (no draft
   — ADR-0002), the tag push *is* the release: it publishes the GitHub Release
   and pushes to the public Homebrew tap with no further human gate. Tag
   protection is the control that replaces the draft. Restrict who can create
   `v*` tags per [`scripts/setup-tag-protection.md`](scripts/setup-tag-protection.md).
4. **Optional:** configure the `homebrew-tap` deployment environment with
   required reviewers to add an approval gate before the tap is pushed. Leaving
   it unconfigured (the default) means the tap bump runs unattended.

## Release checklist

1. Ensure `Cargo.toml` `[workspace.package].version` equals the intended tag
   version (no `-` suffix).
2. Ensure `CHANGELOG.md` has a dated section for the version using the exact
   heading `## [X.Y.Z] - YYYY-MM-DD` — the release job extracts the release
   notes by matching that heading, and a different format produces an empty
   release body.
3. Run the local checks:

   ```bash
   just ci
   scripts/check-release-version.sh vX.Y.Z
   ```

4. Land any release-prep changes via a normal PR to `main` (direct pushes to
   `main` are blocked). The merge commit on `main` is what you tag.
5. Tag the merge commit and push:

   ```bash
   git checkout main
   git pull --ff-only origin main
   git tag -a vX.Y.Z -m "rusty-imap-mcp vX.Y.Z"
   git push origin vX.Y.Z
   ```

## What automation does

Pushing a `v*` tag triggers `release.yml`, which:

- **`verify-tag`** — fails fast on tag/`Cargo.toml` drift or a malformed tag.
- **build (×5 triples)** — `x86_64`/`aarch64`/`powerpc64le`/`s390x` Linux and
  `aarch64-apple-darwin`. The `x86_64`/`aarch64` Linux legs build
  `--features vendored-keyring` so their binaries static-link libdbus and carry
  no runtime `libdbus-1.so` dependency (self-contained tarballs and bottles).
  `powerpc64le`/`s390x` are not vendored and their tarballs need a system
  `libdbus-1-3`.
- **package** — each binary is wrapped into
  `rusty-imap-mcp-vX.Y.Z-<triple>.tar.gz` with `LICENSE-MIT`, `LICENSE-APACHE`,
  `NOTICE`, and `README.md`.
- **`release`** — generates `SHA256SUMS.txt`, attaches a build-provenance
  attestation over the tarballs, and **publishes** the GitHub Release directly
  (no draft; see ADR-0002).
- **`homebrew`** — fetches the published tarball checksums, renders
  `homebrew/rusty-imap-mcp.rb.template`, and pushes `Formula/rusty-imap-mcp.rb`
  to the tap. Stable tags only.
- **`bottles` / `bottles-merge`** — build native bottles for arm64 macOS and
  x86_64/arm64 Linux, upload them to the release, and commit the `bottle do`
  block to the tap formula. If any bottle leg fails, the formula stays
  bottle-less and installs fall back to the binary-download path.

## After tagging

Watch the pipeline succeed in order:
`verify-tag → build ×5 → release → homebrew → bottles → bottles-merge`.

Then verify the install on a supported platform:

```bash
brew install randomparity/tap/rusty-imap-mcp
rusty-imap-mcp --version
```

For a Linux bottle, also confirm it runs in a clean container **without**
`libdbus-1-3` installed (proves the vendored static libdbus).

## Planned (later phases)

- The `-dev`-in-`Cargo.toml` version model (release-prep + post-release-bump).
- crates.io publishing (all 8 workspace crates, in dependency order).
- deb/rpm packaging, manpages, and `install.sh` / `install.ps1` installers.
