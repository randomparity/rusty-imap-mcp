# Releasing `rusty-imap-mcp`

This project ships release binaries as GitHub Release `.tar.gz` artifacts and a
Homebrew formula (with native bottles) in
[`randomparity/homebrew-tap`](https://github.com/randomparity/homebrew-tap). A
release is cut by pushing a `vX.Y.Z` git tag; the rest is automated by
[`.github/workflows/release.yml`](.github/workflows/release.yml).

See [ADR-0002](docs/ADR/0002-phased-bzr-release-parity-and-direct-publish.md)
for the phased bzr-parity plan. Phase 1 (tarballs + Homebrew tap + bottles),
Phase 2A (the manifest `-dev` version model,
[ADR-0003](docs/ADR/0003-manifest-dev-version-model.md)), and native packaging
(deb/rpm + manpages + `install.sh`,
[ADR-0006](docs/ADR/0006-native-packaging-build-topology.md)) are implemented.
crates.io publish is the last remaining phase.

## Version-number convention

Between releases, `[workspace.package].version` carries the **next planned
version with a `-dev` suffix** (e.g. after `v0.1.0` ships, `main` lives at
`0.1.1-dev`). The suffix is a placeholder — the actual release version is
chosen at release-prep per SemVer based on what landed; patch is the default,
minor when features accumulated. `crates/rimap-core/build.rs` appends git
provenance: a build from the `vX.Y.Z` tag (a clean, stripped base) reports the
bare `X.Y.Z`; every other build reports `<base>+g<sha>` (with `.dirty`), so a
dev build reports `0.1.1-dev+g<sha>`. SemVer orders `0.1.1-dev` after `0.1.0`
and before `0.1.1` — see [ADR-0003](docs/ADR/0003-manifest-dev-version-model.md).

Because the 8 workspace crates pin each other with explicit `version`
requirements (needed for crates.io), a version change must move the workspace
version **and** all intra-workspace requirements together. Always use
`cargo set-version --workspace <version>` (from `cargo-edit`:
`cargo install cargo-edit --locked`) — never hand-edit the version.

The `verify-tag` job (mirrored locally by
[`scripts/check-release-version.sh`](scripts/check-release-version.sh)) hard-fails
if the tag does not match `Cargo.toml` or is not exactly `^v[0-9]+\.[0-9]+\.[0-9]+$`.
It runs against the **stripped** manifest at tag time, so it also catches a
forgotten `-dev` strip (tagging `v0.1.1` while the manifest still says
`0.1.1-dev` fails the clean-version check).

**Prerelease tags are not supported** — `verify-tag` rejects any tag
containing `-`.

### Breaking a public API

Under SemVer at `0.x`, the **minor** field is the breaking-change field: a break
between `0.1.z` and the next release requires `0.2.0`, not `0.1.z+1`. So a PR
that breaks the public API of a publishable workspace crate must move the
planned version with it:

```bash
cargo set-version --workspace 0.2.0-dev   # from 0.1.1-dev
```

This is the PR author's job, not release-prep's. Release-prep chooses between
patch and minor for *accumulated features*; it cannot retroactively discover
that some merged PR removed a `pub fn`.

The `semver-checks` CI job enforces this. It diffs the branch's public API
against the last `vX.Y.Z` tag and fails when a break is not covered by the
manifest version, so a breaking PR is red until the version bump lands in the
same PR. Once the planned version is already `0.2.0-dev`, further breaks in the
same cycle are free — they all diff against the same tag, and one bump covers
them all. Run it locally with `just semver-checks` (`just ci` includes it).

"Public API" here means the API of the 8 publishable crates. `rimap-fake-imap`
and `xtask` are `publish = false` and are skipped.

**Adding a new publishable crate.** A tag baseline errors on a crate that does
not exist at the baseline tag — `package <name> not found`, which reads as a
tooling failure rather than a SemVer verdict. The PR that introduces the crate
must skip it for that one PR:

```bash
cargo semver-checks check-release --workspace --baseline-rev v0.1.0 --exclude <new-crate>
```

From the next tag onward it has a baseline and needs no exclusion.

**The release runs the same gate.** `release.yml`'s `publish-crates` job runs
`just semver-checks` too, immediately before uploading to crates.io — one
baseline definition, two callers (issue #650). It is not redundant with the PR
job: the release triggers on a tag push and `verify-tag` only checks the tag
against `Cargo.toml`, so a tag cut off a branch would otherwise publish a tree
the PR gate never saw. And a crates.io version cannot be unpublished, only
yanked, so this is the one gate in the repo standing in front of something
irreversible.

At release time HEAD *is* the tag being released, so the baseline has to be the
tag before it. `scripts/semver-baseline.sh` resolves that — the most recent
reachable `vX.Y.Z` tag that is not on HEAD — and fails loudly rather than
returning nothing, because a self-comparison is green whatever it is handed.
`scripts/semver-baseline.test.sh` (`just test-semver-baseline`, mirrored in the
`publish checks` CI job) covers that case and the tag shapes around it.

One limit worth knowing before you trust a green result: the gate is only as
good as `cargo-semver-checks`' lint set. It catches removed and re-typed public
items well; it does not model behavioral compatibility, and it cannot see
through a re-export from a private module it declines to traverse.

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
5. **crates.io publishing (issue #544).**
   1. **Reserve the 8 crate names first, locally.** crates.io throttles *new*
      crate names to a burst of 5 then 1 every 10 minutes, so publishing all 8
      names cannot finish in one CI run. Reserve them by running the publish
      script locally at the release version, where it can sleep through the
      refill for free:

      ```bash
      # On the tagged (or release-prep) commit, at the clean release version:
      CARGO_REGISTRY_TOKEN=<your-token> ./scripts/publish-crates.sh
      ```

      The script publishes `rimap-core → … → rimap-server` in order, skips any
      version already up (so it is resumable), and on a `429` parses the "try
      again after" time and sleeps. Expect the first run to span ~30+ minutes as
      it paces past the burst limit. After the names exist, every subsequent
      tagged release publishes new *versions* (burst 30) in one CI run.
   2. Add `CARGO_REGISTRY_TOKEN` (a crates.io API token scoped to publish) to
      the **`crates-io`** deployment environment's secrets. The `publish-crates`
      job runs unattended once this is set (no required reviewer — ADR-0004);
      add a required reviewer to the environment if you want a manual gate.

## Release checklist

1. On a `release/vX.Y.Z-prep` branch, **strip `-dev`** across the workspace:

   ```bash
   cargo set-version --workspace X.Y.Z   # choose patch/minor per what landed
   cargo build                            # refresh Cargo.lock
   ```

2. Rename the `CHANGELOG.md` `## [Unreleased]` heading to
   `## [X.Y.Z] - YYYY-MM-DD` (exact format — the release job extracts notes by
   matching `## [X.Y.Z]`, and a different format produces an empty release body).
3. Run the local checks:

   ```bash
   just ci
   scripts/check-release-version.sh vX.Y.Z
   ```

4. Open the prep PR to `main` (direct pushes are blocked) and merge it. The
   merge commit on `main` is what you tag.
5. Tag the merge commit and push:

   ```bash
   git checkout main
   git pull --ff-only origin main
   git tag -a vX.Y.Z -m "rusty-imap-mcp vX.Y.Z"
   git push origin vX.Y.Z
   ```

6. After the release publishes, the **`post-release-bump`** job opens a
   `chore/post-release-bump-vX.Y.(Z+1)-dev` PR automatically (stable tags
   only). **Merge prerequisite:** because it is opened by `GITHUB_TOKEN`, it
   does **not** trigger `pull_request` CI — push an empty commit to its branch
   (or run `just ci` locally) to get a green signal before merging. Edit the
   version on the PR first if the next release is a minor/major bump.

   **If no PR appears,** the job refused to open a broken one rather than
   failing quietly — read its log. `scripts/post-release-bump.sh` deliberately
   fails, before the PR step, when: the version on `main` is not behind the
   one it computed (a re-run of an older release's workflow, or a `main`
   somebody bumped by hand); a cargo workspace exists that it does not know
   how to re-resolve; `cargo metadata --locked` or `just check-fuzz-lock-parity`
   disagrees with what it produced; or the bump dirtied something that is not
   a manifest, a lockfile, or the changelog. Each names the cause. Reproduce
   any of them locally with `./scripts/post-release-bump.sh vX.Y.Z` on a clean
   checkout of `main`, fix the cause, and re-run the job.

## What automation does

Pushing a `v*` tag triggers `release.yml`, which:

- **`verify-tag`** — fails fast on tag/`Cargo.toml` drift or a malformed tag.
- **`manpages`** — runs `cargo run -p xtask -- man` to generate roff manpages
  from the clap CLI, guards that no test-support subcommand pages were emitted,
  and shares them to every build leg via an artifact.
- **build (×5 triples)** — `x86_64`/`aarch64`/`powerpc64le`/`s390x` Linux and
  `aarch64-apple-darwin`. The `x86_64`/`aarch64` Linux legs build
  `--features vendored-keyring` so their binaries static-link libdbus and carry
  no runtime `libdbus-1.so` dependency (self-contained tarballs and bottles).
  `powerpc64le`/`s390x` are not vendored and their tarballs need a system
  `libdbus-1-3`.
- **package** — each binary is wrapped into
  `rusty-imap-mcp-vX.Y.Z-<triple>.tar.gz` with `LICENSE-MIT`, `LICENSE-APACHE`,
  `NOTICE`, `README.md`, and `share/man/man1/*.1`. Additionally, the vendored
  `x86_64`/`aarch64` legs build `.deb` (`cargo-deb`) and `.rpm`
  (`cargo-generate-rpm`) packages — amd64/arm64 only, with **no** libdbus
  dependency (static-linked). A content assertion fails the job unless each
  package carries the man pages, a `LICENSE`, and the README; the x86_64 leg
  also install-tests the `.deb`/`.rpm` in minimal Debian/Fedora containers
  (no `libdbus-1-3`/`dbus-libs` present) to prove the self-contained contract.
  See [ADR-0006](docs/ADR/0006-native-packaging-build-topology.md).
- **`release`** — stages `install.sh` with the release tag baked in, generates
  `SHA256SUMS.txt` over **every** artifact (tarballs, `.deb`, `.rpm`,
  `install.sh`), attaches a build-provenance attestation over the tarballs and
  packages, attaches all of the above, and **publishes** the GitHub Release
  directly (no draft; see ADR-0002).
- **`homebrew`** — fetches the published tarball checksums, renders
  `homebrew/rusty-imap-mcp.rb.template`, and pushes `Formula/rusty-imap-mcp.rb`
  to the tap. Stable tags only.
- **`bottles` / `bottles-merge`** — build native bottles for arm64 macOS and
  x86_64/arm64 Linux, upload them to the release, and commit the `bottle do`
  block to the tap formula. If any bottle leg fails, the formula stays
  bottle-less and installs fall back to the binary-download path.
- **`publish-crates`** — publishes the 8 workspace crates to crates.io in
  dependency order (`rimap-core → … → rimap-server`) after the GitHub Release is
  up. Stable tags only; gated behind the `crates-io` environment and
  `cargo-semver-checks`. Idempotent (skips versions already published) and
  rate-limit-aware. **The first release's 8 new names exceed the burst limit —
  reserve them locally first (one-time setup step 5).** A failure here does not
  un-publish the GitHub Release.
- **`post-release-bump`** — on a stable release, opens a PR bumping the
  workspace to the next `-dev` (`cargo set-version --workspace`) and prepending
  `## [Unreleased]` to the CHANGELOG. See checklist step 6 for the CI-kickoff
  merge prerequisite.
- **`installer-smoke`** — a downstream leaf (its failure does **not** un-publish
  the release): downloads and runs the published `install.sh` pinned to the
  release tag, then verifies `rusty-imap-mcp --version` matches `Cargo.toml`
  independently of the installer's advisory exit code. Stable tags only.

## After tagging

Watch the pipeline succeed in order:
`verify-tag → manpages → build ×5 → release → {publish-crates, installer-smoke, homebrew → bottles → bottles-merge}`
(`publish-crates`, `installer-smoke`, and `homebrew` all fan out from `release`).

Then verify the install on a supported platform:

```bash
brew install randomparity/tap/rusty-imap-mcp
rusty-imap-mcp --version
man rusty-imap-mcp   # after a .deb/.rpm or Homebrew install
```

For a Linux bottle (or the `.deb`/`.rpm`), also confirm it runs in a clean
container **without** `libdbus-1-3`/`dbus-libs` installed (proves the vendored
static libdbus).

## Planned (later phases)

- crates.io publish of the 8 workspace crates —
  [#544](https://github.com/randomparity/rusty-imap-mcp/issues/544) (see the
  one-time setup above).
