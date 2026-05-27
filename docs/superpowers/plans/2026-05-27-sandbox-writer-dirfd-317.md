# Harden shared sandbox writer with dir-fd anchoring (#317)

## Context

`d16986a5` landed the dependency-free half of #317: the shared
`write_attachment` (`crates/rimap-server/src/tools/retrieval/sandbox.rs`) now
creates each candidate with `O_CREAT | O_EXCL | O_NOFOLLOW` and mode `0600`,
and cleans up a partial file on write error. This closes the
`path.exists()`-then-write race and the final-component symlink swap.

The **directory-component** race remains: between `resolve_dest_dir`
(canonicalize + `starts_with(allowed_root)`) and the `open` of the final file,
a same-UID local writer can rename/replace the resolved destination directory
and redirect the write. Closing it requires creating the file *fd-relative* to
a held directory descriptor (`openat`-family), which needs either `unsafe` FFI
(forbidden: `unsafe_code = "forbid"`) or a capability-style wrapper. Per the
owner's decision on the issue, adopt [`cap-std`] (Bytecode Alliance; its
`unsafe` is encapsulated).

Two adjacent gaps the runtime writer cannot close on its own, called out in the
issue, are addressed at config-validation time:

- a download **root that is itself a symlink** to an attacker-writable target;
- a `0o700` root whose **immediate parent** is group/world-writable (lets an
  attacker swap the root inode out from under the resolver).

[`cap-std`]: https://crates.io/crates/cap-std

## Scope

Shared by `download_attachment` and `export_messages` — one code path, no
fork. Two crates change:

- `rimap-server` — the writer + its resolve/write seam (`sandbox.rs` and the
  two callers).
- `rimap-config` — the export-gated private-root check (`validate/paths.rs`).

Non-Unix stays fail-closed (the `0600` / no-follow guarantees are Unix-only);
unchanged from today.

## Dependency

`cap-std = "4"` (4.0.2 latest; license `Apache-2.0 WITH LLVM-exception OR
Apache-2.0 OR MIT`, all on the deny.toml allow-list). Builds on `rustix`,
already in the tree. Added to `rimap-server` only.

API confirmed against cap-std 4.0.2 docs (the load-bearing surface):
`Dir::open_ambient_dir(path, ambient_authority())`, `Dir::open_with(path,
&OpenOptions)`, `OpenOptions{create_new, mode}` (`mode` via
`cap_std::fs::OpenOptionsExt`), `Dir::hard_link(src, &dst_dir, dst)` (mirrors
`std::fs::hard_link` → `EEXIST` on an existing destination, which is the de-dup
signal), `Dir::remove_file`, `Dir::symlink_metadata`. `Dir` is `Send + Sync`
(owns an fd), so it crosses `spawn_blocking` and `.await` points.

## Design

### Layer A — runtime dir-fd anchoring (`rimap-server`)

Replace the `(resolve → PathBuf) … (write PathBuf)` split, which re-resolves
the directory by path at write time, with a **held capability** carried from
resolve through write:

```rust
/// A resolved, validated download destination held open as a capability.
/// `canonical` is kept only to render the human-readable result path; `dir`
/// is the held cap-std directory fd that anchors every write fd-relative,
/// closing the resolve→write directory-swap window.
pub struct DestDir {
    canonical: PathBuf,
    dir: cap_std::fs::Dir,
}
```

- `resolve_dest_dir(dest_dir, allowed_root, fallback) -> Result<DestDir>`:
  1. target = canonicalize(`dest_dir`) checked `starts_with(allowed_root)`, or
     `fallback` when `dest_dir` is `None` (unchanged containment logic).
  2. `cap_std::fs::Dir::open_ambient_dir(&target, ambient_authority())` — the
     one ambient (path-following) step; everything after is fd-relative.
  3. return `DestDir { canonical: target, dir }`.

- `write_attachment(dest: &DestDir, filename, data) -> Result<PathBuf>`
  (temp-file + atomic placement, so the final name only ever appears
  fully-written — a crash mid-write leaves a `.tmp` orphan, never a truncated
  raw-email artifact at the final path):
  1. create a temp fd-relative with a **process-unique** name
     `.rimap-tmp-<token>` where `<token>` = `pid` + a process-local atomic
     counter + wall-clock nanos (same recipe as the existing `export_token()`,
     lifted into a shared `unique_temp_name()` helper so two concurrent
     writers — download + export, or two exports — never derive the same temp):
     `dest.dir.open_with(tmp, create_new(true).write(true).mode(0o600))`
     (cap-std `create_new` ⇒ `O_EXCL`, which refuses to follow a symlink at the
     final component; `OpenOptionsExt::mode` sets `0600`).
  2. `write_all`; on error `dest.dir.remove_file(tmp)` and return. (No
     `sync_all`: atomic *appearance* comes from link-after-full-write, not from
     fsync; power-loss durability is not a requirement and the prior writer
     never fsynced — adding it would be a silent latency cost on up-to-100 MiB
     exports.)
  3. de-dup loop over candidate final names (`name`, `name_1`, …): atomically
     place via `dest.dir.hard_link(tmp, &dest.dir, final_name)` — `EEXIST`
     ⇒ collision, advance the counter (cap at 1000); other error ⇒ remove temp,
     return.
  4. on success remove the temp; return `dest.canonical.join(final_name)`.

  The de-dup, traversal-stripping (`file_name()` only), and 1000-collision cap
  carry over unchanged. The `.rimap-tmp-` prefix is recognizable and `0600`;
  the only way one survives is a `SIGKILL`/power loss between create and link
  (every handled error path unlinks it). Sweeping stale `.rimap-tmp-*` orphans
  is left to the operator and noted in the tool docs — bounded because the
  window is a single un-acked syscall gap, not the whole write.

- async wrappers: `resolve_dest_dir_async` now returns `DestDir`;
  `write_attachment_async(dest: DestDir, filename, data)` takes it by value
  (`cap_std::fs::Dir` is `Send`). Both callers thread `DestDir` from resolve to
  write — the held fd lives across the intervening body fetch.

### Layer B — config-time root hardening (`rimap-config`)

Extend `check_export_download_root_private` (fires only when `export_enabled`
and `download_dir` is non-empty; Unix-only) beyond the existing
group/world-writable mode check:

1. **Symlinked root** — `symlink_metadata(root)`; if the root itself is a
   symlink, reject (the canonicalized path the resolver trusts would differ
   from the operator-named root).
2. **Parent writability** — canonicalize the root, stat its immediate parent;
   if the parent is group/world-writable (`mode & 0o022 != 0`), reject (an
   attacker who can write the parent can swap the root inode).

Both reuse the existing `ConfigError::PathNotWritable` shape with actionable
reasons.

## Why this is the right cut

- The held `Dir` fd closes the resolve→write directory-swap window (#1): once
  opened, fd-relative create/link cannot be redirected by renaming a path
  component. This is the only *runtime* guarantee and the heart of the fix.
- The config checks (Layer B) are **necessary-but-not-sufficient capability
  reduction**, not a runtime guarantee: they read mode bits / symlink status
  once at startup and remove the attacker's *ability* to swap the root under
  the documented trust model (write authority to the root separated from the
  consuming agent). They do not re-check per request, and they walk only the
  immediate parent.
- One shared writer keeps `download_attachment` and `export_messages` on the
  identical primitive (no export-only fork).

### Residual windows (named, not hidden)

- Inside Layer A, a window remains between `canonicalize(dest_dir)` and
  `open_ambient_dir(canonical)` — far smaller than today's resolve→fetch→write
  span, and only exploitable by an actor who can write a path component, which
  the trust model and Layer B's parent check deny.
- Layer B is a startup snapshot; a writable *grand*parent could let the parent
  be swapped later. Closing that fully means holding the root `Dir` for the
  process lifetime (see Out of scope).

## Out of scope (residual, documented)

- Holding the download **root** Dir for the whole process lifetime and deriving
  per-request dirs fd-relative from it would also close the per-request
  re-resolution window, but reshapes `AccountState.download_dir`
  (`Arc<Path>` → a held `Dir`) across `registry`/`main`/`test_support`. The
  per-operation open + parent-writable check is the bounded cut here.
- Deep-ancestor writability (beyond the immediate parent) is not walked; the
  immediate parent is the case named in the issue.

## Execution tasks (TDD; test first, watch it fail, then implement)

1. **Add `cap-std`** to `rimap-server`; `cargo build -p rimap-server`; run
   `cargo deny check` to confirm licenses/advisories pass.
2. **`DestDir` + dir-fd writer** in `sandbox.rs`. Port existing writer tests to
   the new signature; add tests:
   - directory-swap: open `DestDir`, rename the underlying dir, confirm the
     write lands via the held fd (not the swapped path) or fails closed — never
     escapes.
   - crash-safety: a write error leaves no file at the final name (temp only).
   - keep: collision de-dup, traversal/absolute stripping, `0600`, symlink at
     final name not followed.
3. **Thread `DestDir`** through `download_attachment` and `export_messages`
   call sites; `cargo build` + existing integration tests green.
4. **Config checks** in `validate/paths.rs` with tests: symlinked root
   rejected; parent group/world-writable rejected; private root + private
   parent accepted; non-export / empty-root no-op.
5. **Verify**: `cargo clippy --all-targets --all-features -- -D warnings`,
   `cargo fmt --check`, targeted `cargo test` for `rimap-server` sandbox +
   retrieval and `rimap-config` paths, `cargo deny check`.

## Acceptance criteria (from #317)

- Race-proof create (dir-fd-anchored, no-follow, exclusive) for **both**
  `download_attachment` and `export_messages`. ✔ Layer A.
- Handle symlinked-root and parent-dir-writable. ✔ Layer B.
