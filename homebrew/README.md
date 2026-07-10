# Homebrew tap

This directory holds the formula template that the `homebrew` job in
[`.github/workflows/release.yml`](../.github/workflows/release.yml) renders into
`Formula/rusty-imap-mcp.rb` in the
[`randomparity/homebrew-tap`](https://github.com/randomparity/homebrew-tap)
repository on each stable (non-prerelease) `v*` release. The `bottles` and
`bottles-merge` jobs then build native bottles and fold a `bottle do` block into
that formula.

## End-user install

```bash
brew install randomparity/tap/rusty-imap-mcp
```

or, as two steps:

```bash
brew tap randomparity/tap
brew install rusty-imap-mcp
```

Supported prebuilt platforms:

- macOS arm64 (Apple Silicon)
- Linux x86_64 (glibc)
- Linux aarch64 (glibc)

The Linux binaries static-link libdbus (via the `vendored-keyring` build
feature), so a poured bottle needs no system `libdbus-1-3`.

Intel Mac (`x86_64-apple-darwin`) builds from source via `cargo` and a
build-time `rust` dependency — no prebuilt Intel-macOS binary is published.

## One-time tap setup

The `homebrew` job assumes the tap repo already exists (it does) and pushes with
a token. Before the first release:

1. Confirm the tap repo exists with a `Formula/` directory:

   ```bash
   gh repo view randomparity/homebrew-tap
   ```

2. Create a fine-grained PAT with **`Contents: Write`** on
   `randomparity/homebrew-tap`, and add it to the `rusty-imap-mcp` repo as a
   secret named `HOMEBREW_TAP_TOKEN`. The `homebrew` and `bottles-merge` jobs
   use it (both run in the `homebrew-tap` deployment environment; a repo-level
   secret is visible to them).

After that, every stable release auto-bumps the formula and its bottles.

## Editing the formula

Update `rusty-imap-mcp.rb.template` in this directory; the workflow re-renders
it into the tap on the next release. Keep the placeholders (`{{VERSION}}`,
`{{MAC_ARM_SHA}}`, `{{LINUX_ARM_SHA}}`, `{{LINUX_INTEL_SHA}}`, `{{SRC_SHA}}`)
intact — the workflow's `sed` pass replaces them.

## Future: homebrew-core

A long-term goal is to publish `rusty-imap-mcp` to homebrew-core so users do not
need a custom tap. homebrew-core requires a stable, in-use project with a
verifiable maintainer and no conflicts, submitted via PR. Defer until the
project has a track record across multiple stable releases.
