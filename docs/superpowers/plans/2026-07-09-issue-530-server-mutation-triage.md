# Issue #530: Triage the rimap-server cold-path mutation survivors

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development for
> each kill. Steps use checkbox (`- [ ]`) syntax for tracking.

**Tracking issue:** [#530](https://github.com/randomparity/rusty-imap-mcp/issues/530)
(Theme C of the FABLE test-coverage epic [#532](https://github.com/randomparity/rusty-imap-mcp/issues/532)).

**Goal:** Bucket every unannotated cold-path mutation survivor in `rimap-server`
(`tools/`, `cli/`, `main.rs`, `lib.rs`) into **kill** / **known-equivalent** /
**best-effort-cold-path**, so `mutation-baseline.md` shows **zero unannotated
survivors** — closing the AGENTS.md "deferrals become GitHub issues" gap the
`rimap-server` section's 54-survivor prose left open.

**Design note (why a plan, not a spec+ADR):** this follows the documented
mutation-wave playbook (#192/#225/#289) — no architecture, interface, data-model,
or public-contract change. The only code changes are test-only additions and
inline `// cargo-mutants:` annotation comments. Per repo precedent every prior
wave used a plan doc; there is no `docs/adr/`. Classification is the design, and
it is complete (below).

**Baseline refresh vs the issue body:** the issue cites 54 survivors from the
2026-07-09 #515 baseline (PR #516, merged 11:07 UTC). #517 (SMTP `message_builder`
e2e, the "A1" overlap) landed *after* that refresh (15:09 UTC). A scoped rerun on
current `main` therefore shows **43 missed + 2 timeout = 45** survivors — the issue
explicitly advised "re-run the baseline before hand-writing kills," and this is
that rerun. The "A4" overlap, #520 (export_messages over the wire), is still open,
so the real `ExportSource` IMAP impl survivors are bucketed best-effort with a
`#520` attribution rather than hand-written kills.

**Survey invocation** (runbook "Docker-capable hosts" path, scoped to cold paths):
```
cargo mutants --package rimap-server --no-shuffle --jobs 10 --timeout 120 \
  -f 'crates/rimap-server/src/tools/**/*.rs' -f 'crates/rimap-server/src/cli/**/*.rs' \
  -f 'crates/rimap-server/src/main.rs' -f 'crates/rimap-server/src/lib.rs' \
  --test-tool nextest -- -E 'not (binary(=e2e) | binary(=e2e_smtp))' --test-threads 4
```
614 mutants: 414 caught, 43 missed, 155 unviable, 2 timeout, 39 min.

**Per-PR convention reminder:** `cargo-mutants` does not parse inline annotations
(per `feedback_cargo_mutants_annotations_are_doc_only`). After cleanup,
`missed.txt` still lists annotated survivors. Source of truth is the row in
`mutation-baseline.md`; the inline comment is for human readers. Verification
language throughout is **"zero unannotated survivors"** — not "zero missed."

---

## Bucket 1 — KILL (add unit test), 17 mutants / 13 sites

Pure functions with observably-wrong mutants. Each kill is a targeted `#[test]`
in the file's existing `#[cfg(test)]` module.

- [ ] `admin/list_folders.rs:27` `escape_wire_name` `< with <=` — assert `0x7f`
      (DEL) escapes to `\u{7f}` (mutant emits raw DEL into "display-safe" output).
- [ ] `admin/list_folders.rs:61` `sanitize_folder_entry` cap `* with +` / `* with /`
      — a long folder name requiring sanitization keeps >1028 graphemes in `name_wire`.
- [ ] `compose/message_builder.rs:133/134` `validate_compose_input` body_html
      (`delete !`, `> with <`, `> with >=`) — oversized body_html rejected;
      at-`MAX_BODY_BYTES` accepted (mirror the existing body_text tests).
- [ ] `compose/message_builder.rs:183` `validate_recipient_set` `> with >=` —
      exactly `MAX_RECIPIENTS` accepted on the forward path.
- [ ] `compose/message_builder.rs:224` `forwarded_subject` `-= with /=` — a
      multibyte subject exceeding `MAX_SUBJECT_LEN` at a non-char-boundary
      (exercises the boundary-walk loop; mutant hangs → timeout-kill).
- [ ] `compose/message_builder.rs:354` `validate_header_text` `|| with &&` — each
      of `<`, `>`, `\0` individually rejected.
- [ ] `retrieval/mbox.rs:85` `line_is_from` `< with <=` — an all-`>` line does not
      index out of bounds (mutant panics).
- [ ] `retrieval/sandbox.rs:204` `unique_temp_name -> "xyzzy"` — asserts
      `.rimap-tmp-` prefix and that two calls differ.
- [ ] `retrieval/search.rs:646` `build_query` `|| with &&` ×2 — `advanced_query`
      containing `\r`, `\n`, or `\0` is rejected.
- [ ] `retrieval/search.rs:811` `format_flag -> ""` / `"xyzzy"` — assert flag→wire
      mappings (`Seen`→`\Seen`, `Keyword`→raw).
- [ ] `retrieval/export_messages.rs:581` `export_token -> String::new()` — non-empty
      and two calls differ.
- [ ] `retrieval/part_walker.rs:29` `walk_inner` `> with >=` on `MAX_PART_DEPTH`(64) —
      a leaf nested exactly 64 `Multipart` layers is reached at `depth == 64` and IS
      visited under `>`; `>=` drops it. `walk_inner` is pure over an arbitrary
      `BodyStructure`, so this is a constructible-input difference, not an
      equivalence (the `rimap-content` `raw_parts.rs`/`bodies.rs` analog kills the
      same mutant). Reclassified from known-equivalent during review iteration 1.

## Bucket 2 — KNOWN-EQUIVALENT (inline annotation + baseline row), 3 mutants / 2 sites

- [ ] `retrieval/mbox.rs:68` `escape_from_lines_into` `< with <=` — at
      `line_start == msg.len()` the trailing push sees an empty slice;
      `write_mbox_line` emits nothing either way (= `mime_scrub.rs:187`).
- [ ] `retrieval/sandbox.rs:365` `read_sandboxed_file -> Ok(vec![0/1])` ×2 —
      `#[cfg(not(unix))]` fail-closed stub, not compiled on Linux CI (= `self_check.rs:189`).

## Bucket 3 — BEST-EFFORT-COLD-PATH (inline annotation + baseline row), 23 mutants / 15 sites

Thin wrappers over `rimap-imap`, non-portable filesystem error/TOCTOU paths, and
diagnostic CLI wiring — spec §6 best-effort tier. Killing these means an
integration harness, not a unit test (mocking `AccountState.imap` would mock our
own domain types, which AGENTS.md forbids).

- [ ] `retrieval/sandbox.rs:167` `write_attachment` `> with ==` on the 1000-collision
      cap — off-by-one, not strict equivalence: `== 1000` fires one iteration earlier
      than `> 1000` (1000 vs 1001 collisions). Distinguishing them needs 1000
      pre-existing colliding filenames, so annotated rather than killed.
      Reclassified from known-equivalent during review iteration 1.

- [ ] `retrieval/export_messages.rs:220` `fetch_sizes` ×4, `:243` `fetch_one_body` —
      the real `impl ExportSource for AccountState`; the export *logic* is unit-tested
      behind the `ExportSource` trait seam, the IMAP round-trip is **#520**'s harness.
- [ ] `retrieval/fetch_message.rs:177` `> with </>=/==` ×3 — `max_body_bytes`
      truncation; needs a fetched body straddling the cap.
- [ ] `compose/message_builder.rs:450` `apply_threading_headers` stub — IMAP
      `fetch_body` for reply threading.
- [ ] `compose/message_builder.rs:49` `MAX_FORWARD_ORIGINAL_BYTES` `* with +`
      + `compose/forward.rs:87` `> with >=` — forward handler (IMAP fetch + SMTP);
      the exact-25 MiB boundary is impractical to exercise.
- [ ] `retrieval/download_attachment.rs:136` delete `bodystructure` field — IMAP
      fetch for MIME cross-validation (best-effort security warning).
- [ ] `retrieval/search.rs:342` `handle_thread` delete `!`, `:381` `fetch_thread_headers`
      ×2, `:394` delete `Message-ID` arm — IMAP thread-fetch wrappers.
- [ ] `retrieval/search.rs:472/474` delete `envelope`/`size` FetchSpec fields — the
      search page fetch.
- [ ] `retrieval/sandbox.rs:165` guard `AlreadyExists -> true` — a persistent
      non-`AlreadyExists` `hard_link` error is not portably inducible.
- [ ] `retrieval/sandbox.rs:337` `read_sandboxed_file` `+ with *` on `take(max+1)` —
      the post-stat file-growth (TOCTOU) guard; not deterministically testable.
- [ ] `main.rs:641` delete `DumpToolSchemas` arm — test-support schema-dump CLI
      wiring; CI exercises it via `just regen-tool-schemas`, no rust test asserts it.
- [ ] `main.rs:670` `run_migrate_keyring -> Ok(())` — keyring CLI wiring (needs an OS keyring).

## Already caught by TIMEOUT (document only, no code change), 2 mutants

- `retrieval/mbox.rs:86` `line_is_from` `+= with *=` — `j *= 1` never advances → hang.
- `retrieval/sandbox.rs:166` `write_attachment` `+= with *=` — `counter *= 1` never
      advances → hang.

## Done criteria

- [ ] All 17 kills added; each verified with a single-mutant rerun
      (`cargo mutants -p rimap-server -F '<regex>'` → CAUGHT).
- [ ] All 26 annotated survivors (3 equivalent + 23 best-effort) carry an inline
      `// cargo-mutants:` comment and a `mutation-baseline.md` table row.
- [ ] `mutation-baseline.md` `rimap-server` best-effort count updated: 54 → 0
      unannotated; the refreshed run figures replace the stale ones.
- [ ] `just ci` green.
