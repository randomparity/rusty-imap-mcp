# Mutation-baseline — Targeted-trust-boundary survivor inventory

**Updated:** 2026-07-09
**Tool:** `cargo-mutants` (run via `just mutants --package <name>`)
**Scope:** Five trust-boundary crates — `rimap-content`, `rimap-authz`,
`rimap-audit`, `rimap-server`, `rimap-imap`. Other workspace crates are
out of scope per spec
[`archive: 2026-04-30-test-strategy-improvements-design.md`](https://github.com/randomparity/rusty-imap-mcp/blob/archive/daemon-experiment/docs/superpowers/specs/2026-04-30-test-strategy-improvements-design.md).

A survivor is recorded here when it is *not* a true bug in the test suite —
either because the mutation is mathematically equivalent to the original
code, or because it falls in a code path the spec explicitly classifies as
"plumbing, best-effort." Survivors that *are* test-suite gaps are killed by
adding a test, not annotated.

---

## `rimap-content`

**Last refresh:** 2026-05-04.
**Surviving mutants in non-`bin/` code:** 14.

Run summary (652 mutants total, 2026-05-04 full run via `just mutants
--package rimap-content`): 563 caught, 19 missed, 6 timeout, 64
unviable in 44 minutes wall clock. The deterministic survivor floor
is 14 outside `src/bin/` and 5 inside; both numbers match this run's
output exactly after the
[#239](https://github.com/randomparity/rusty-imap-mcp/issues/239)
flaky-tracing-test fix landed. Every non-`bin/` survivor is a
mathematically equivalent mutation documented in the table below;
the 5 `src/bin/epvme_runner.rs` survivors are documented in the
`### bin/epvme_runner.rs` subsection below (issue #193 took the
original 16 to 5 by killing 11 with tests and annotating the rest).
Issue #236 killed three post-archive survivors in `testutil.rs` and
`parse/mime_scrub.rs` and added two new known-equivalent rows for
the `> with >=` mutations on the `MAX_ANCHOR_TEXT_SCAN` truncation
guards in `html/mismatch.rs`.

The follow-up plan
[`archive: 2026-04-30-rimap-content-mutation-cleanup-followup.md`](https://github.com/randomparity/rusty-imap-mcp/blob/archive/daemon-experiment/docs/superpowers/plans/2026-04-30-rimap-content-mutation-cleanup-followup.md)
drove the non-`bin/` list to zero. The table below records every
survivor whose mutation is mathematically equivalent to the original
code — those are kept behind a `// cargo-mutants: known-equivalent —
<rationale>` comment at the annotation site. Survivors that are real
test-suite gaps are killed by adding a test, not annotated, and so do
not appear here.

| File:line | Mutation | Reason kept | Annotation site |
|---|---|---|---|
| `parse/mime_scrub.rs:130` | `replace < with <= in locate_encoded_word_end` (`if start_offset < first.len()`) | At `start_offset == first.len()`, the empty `&first[start_offset..]` produces no `windows(2)` element, so the `let Some(rel)` guard short-circuits and the function falls through to the outer scan — identical to the `<` branch. | `parse/mime_scrub.rs:124` |
| `parse/mime_scrub.rs:187` | `replace < with > in split_header_lines` (`if line_start < headers.len()`) | The inner loop's only exit invariant is `line_start == headers.len()` — the `None` branch of the `\n` search sets `line_end = headers.len()` and the subsequent push sets `line_start = line_end`. On exit, the predicate is false under both `<` and `>`; the trailing push is defensive dead code in current usage. | `parse/mime_scrub.rs:180` |
| `html/style_parse.rs:74` | `replace < with <= in parse_translate_px` (`if px_val < current`) | The `<` and `<=` predicates differ only when `px_val == current`; in that case both arms set `min = Some(px_val)` to a value already equal to `current`, leaving the running minimum unchanged. Distinct values pick the same minimum under either operator. | `html/style_parse.rs:68` |
| `html/mismatch.rs:51` | `replace || with && in extract_registrable_domain` (`if host.is_empty() || !host.contains('.')`) | The `||` and `&&` predicates differ only when `host.is_empty()=false && !host.contains('.')=true` — a non-empty single-label host. Both branches then route control through the idna+addr lookup, which returns `None` for any single-label host (no registrable domain exists above a TLD). The opposite case (`is_empty=true && !contains('.')=false`) is unreachable: an empty string contains no `.`. | `html/mismatch.rs:43` |
| `html/mismatch.rs:107` | `replace > with >= in detect_mismatches` (unparsable-href branch `if text.len() > MAX_ANCHOR_TEXT_SCAN`) | `>` and `>=` differ only at `text.len() == MAX_ANCHOR_TEXT_SCAN`. In that case, `String::truncate(MAX_ANCHOR_TEXT_SCAN)` is a documented no-op (does nothing when `new_len >= len`), so the predicate flip produces no observable change in `text` or in the downstream linkify scan. | `html/mismatch.rs:101` |
| `html/mismatch.rs:123` | `replace > with >= in detect_mismatches` (parsable-href branch `if text.len() > MAX_ANCHOR_TEXT_SCAN`) | Same reasoning as the unparsable-branch row above: `truncate(MAX_ANCHOR_TEXT_SCAN)` is a no-op at the boundary value, so the operator flip is observably equivalent. | `html/mismatch.rs:119` |
| `lookalike.rs:110` | `replace || with && in label_mixes_scripts` (the first `||` between `is_ascii_digit()` and `c == '-'`) | Each char that the original `continue`s past — ASCII digits, `-`, `_` — has `Script::Common`, which the match below treats as a no-op. Whether the loop short-circuits via `continue` or runs through to the match, the `scripts` set membership is unchanged. | `lookalike.rs:103` |
| `lookalike.rs:110` | `replace || with && in label_mixes_scripts` (the second `||` between `c == '-'` and `c == '_'`) | Same reasoning as the first `||` mutation: the chars that the guard short-circuits on all classify as `Script::Common`, ignored by the match arm. | `lookalike.rs:103` |
| `lookalike.rs:220` | `replace < with <= in extract_domain_from_address` (`lt < gt`) | `lt == gt` is unreachable when both `rfind` results are `Some`: a single byte cannot be both `<` and `>`. Distinct positions exercise the same arm under either operator. | `lookalike.rs:214` |
| `lookalike.rs:228` | `replace + with * in extract_domain_from_address` (`&trimmed[lt + 1..gt]`) | `lt * 1 == lt` shifts the slice start by one byte to include the `<` delimiter; `rsplit_once('@')` then yields the same `(local, domain)` split because the leading `<` lands in the discarded local part, not the domain on the right of `@`. | `lookalike.rs:222` |
| `lookalike.rs:268` | `replace || with && in extract_domain_from_url` (`if host.is_empty() || !host.contains('.')`) | Same equivalence as `html/mismatch.rs:51`: the only difference between `||` and `&&` is on non-empty single-label hosts, which `classify_domain` filters out anyway because no registrable PSL match exists above a TLD. | `lookalike.rs:260` |
| `raw_parts.rs:71` | `replace > with == in walk` (`if depth > MAX_MIME_DEPTH`) | `parse_message` already rejects messages whose MIME depth exceeds 8 (`MAX_MIME_DEPTH`) before any caller of `walk_attachment_parts` sees them. The 64-level defensive cap here therefore can never fire in production; `==` only differs from `>` at exactly `depth == 64`, which is unreachable. | `raw_parts.rs:62` |
| `raw_parts.rs:71` | `replace > with >= in walk` (same site) | Same reasoning as the `==` mutation: `>=` differs from `>` only on the unreachable range `depth in [64, max-tree-depth]`, which is gated out upstream by `parse_message`'s 8-level depth limit. | `raw_parts.rs:62` |
| `raw_parts.rs:96` | `replace + with * in walk` (`walk(msg, child_idx, &child_id, out, depth + 1)?`) | `depth * 1 == depth` keeps the recursion depth at 0 forever, but mail_parser-reachable trees are bounded by `parse_message`'s 8-level depth limit, so both `+ 1` and `* 1` walk to the same set of leaves before recursion bottoms out on `sub_parts() == None`. | `raw_parts.rs:89` |

### `bin/epvme_runner.rs`

**Last refresh:** 2026-05-01.
**Surviving mutants:** 5 (all annotated as `known-equivalent`; 11 of
the 16 mutations recorded in the 2026-04-30 baseline were killed by
tests added under issue #193).

Issue [#193](https://github.com/randomparity/rusty-imap-mcp/issues/193)
drove this list to its current state. Triage bar: a mutation that
affects the dataset's pass/fail signal (counts in `RunSummary`,
`is_success`, the process exit code) or the JSON summary schema was
killed by adding a test; everything else (stdout phrasing, log-style
summary lines, diagnostic-only counter ordering) is annotated as
`known-equivalent` with a one-line rationale.

| File:line | Mutation | Reason kept | Annotation site |
|---|---|---|---|
| `bin/epvme_runner.rs:189` | `replace usage -> String with String::new()` | usage() output is consumed only as stderr text; no test or production caller asserts its content. Mutation leaves exit codes and JSON schema unchanged. | `bin/epvme_runner.rs:185` |
| `bin/epvme_runner.rs:189` | `replace usage -> String with "xyzzy".into()` | Same rationale as the String::new mutation — stderr-only diagnostic text. | `bin/epvme_runner.rs:185` |
| `bin/epvme_runner.rs:381` | `delete ! in print_summary` (`if !summary.parse_error_counts.is_empty()` guard) | Guard inversion would print "Parse error kinds:" header with zero rows; stdout phrasing only, JSON schema unaffected. | `bin/epvme_runner.rs:377` |
| `bin/epvme_runner.rs:392` | `delete ! in print_summary` (`if !summary.warning_counts.is_empty()` guard) | Guard inversion would print "Warning counts:" header with zero rows; stdout phrasing only, JSON schema unaffected. | `bin/epvme_runner.rs:388` |
| `bin/epvme_runner.rs:403` | `delete ! in print_summary` (`if !summary.recorded_failures.is_empty()` guard) | Guard inversion would print "Recorded failures (showing up to 50):" header with zero rows; stdout phrasing only, JSON schema unaffected. | `bin/epvme_runner.rs:399` |

## `rimap-audit`

**Last refresh:** 2026-05-05.
**Surviving mutants in hot paths (`writer/`, `redact/`, `reader/`):** 9 (all annotated as known-equivalent).
**Surviving mutants in plumbing (`cancellation.rs`, `fs.rs`, `record/`):** 0.

Run summary (231 mutants total, 2026-05-05 full run via `just mutants
--package rimap-audit`): 143 caught, 9 missed (all annotated below),
1 timeout, 78 unviable in ~4 minutes wall clock. The Task 6 cleanup
in Sprint B2 added 29 tests across `reader/`, `writer/`, `fs.rs`, and
`record/error.rs` to drive the missed count from 41 hot-path survivors
down to the 9 known-equivalent rows below; one production-side
visibility bump (`needs_fsync` → `pub(super)`) was the only non-test
change. `redact/` had zero survivors (its only consumer is the
existing `Redactor::apply` test surface). The 1 timeout mutant
(`writer/rotation.rs:50`, `delete ! in unique_rotated_path`) is
covered by the existing `unique_rotated_path_appends_counter_when_base_exists`
test — under the mutation the test loops until the kernel kills it
at the 60s test timeout, surfacing the regression as TIMEOUT rather
than as a clean test failure.

| File:line | Mutation | Reason kept | Annotation site |
|---|---|---|---|
| `reader/backup_exclude.rs:11` | `replace exclude_from_backup with ()` | Best-effort tmutil shellout, returns `()` and never propagates errors. The only side effect is an external subprocess on macOS that the harness has no portable way to inspect; on non-macOS the body is already a `let _ = path;` no-op. | `reader/backup_exclude.rs:10` |
| `reader/backup_exclude.rs:20` | `replace exclude_macos with ()` | Same shellout — only outcome is the `tracing` event level (debug vs warn), not asserted by any test. | `reader/backup_exclude.rs:23` |
| `reader/backup_exclude.rs:25` | `replace match guard output.status.success() with true in exclude_macos` | Same shellout — only outcome is the `tracing` event level (debug vs warn), not asserted by any test. | `reader/backup_exclude.rs:23` |
| `reader/backup_exclude.rs:25` | `replace match guard output.status.success() with false in exclude_macos` | Same shellout — only outcome is the `tracing` event level (debug vs warn), not asserted by any test. | `reader/backup_exclude.rs:23` |
| `writer/rotation.rs:123` | `replace match guard !p.as_os_str().is_empty() with true in prune_rotated_siblings` | Both branches end in zero filesystem mutation. With the original guard, an empty parent returns immediately; with the mutated guard, control reaches `read_dir("")` which returns ENOENT, the warn arm logs, and the function still returns without pruning anything. The only difference is a single `tracing` event. | `writer/rotation.rs:122` |
| `writer/rotation.rs:188` | `replace < with <= in mtime < cutoff` | The cutoff is computed via `SystemTime::now() - retention`; matching `mtime == cutoff` to nanosecond precision requires controlling the kernel's mtime stamp at the moment of `now()`, which the test harness has no portable way to do. | `writer/rotation.rs:196` |
| `writer/self_check.rs:189` | `replace inode_of -> u64 with 0` (Windows variant) | Platform-gated via `#[cfg(windows)]`; not compiled on this Linux CI. The existing fallback already returns 0 for filesystems without stable file indices (ReFS, FAT32). | `writer/self_check.rs:187` |
| `writer/self_check.rs:189` | `replace inode_of -> u64 with 1` (Windows variant) | Platform-gated via `#[cfg(windows)]`; not compiled on this Linux CI. Only matters if a test could observe NTFS file reference numbers on Windows-CI; none today does. | `writer/self_check.rs:187` |
| `writer/self_check.rs:200` | `replace inode_of -> u64 with 1` (other-platforms variant) | Platform-gated via `#[cfg(not(any(unix, windows)))]`; not compiled on Linux/Windows. Only matters on hypothetical platforms with no `MetadataExt`, where no test exists. | `writer/self_check.rs:205` |

## `rimap-authz`

**Last refresh:** 2026-05-05.
**Surviving mutants in hot paths (`matrix.rs`, `breaker.rs`, `rate_limit.rs`, `folder_guard.rs`, `folder_name.rs`):** 0.
**Surviving mutants in plumbing (`error.rs`, `guard.rs`, `lib.rs`):** 0.

Run summary (54 mutants total, 2026-05-05 full run via `just mutants
--package rimap-authz`): 37 caught, 0 missed, 0 timeout, 17 unviable
in ~32 seconds wall clock. The Task 8 cleanup in Sprint B2 added two
tests — `breaker::tests::system_clock_now_advances_with_wall_time`
(asserts `SystemClock::now()` advances across a 2 ms sleep, killing
the `Default::default()` mutation) and
`rate_limit::tests::rate_limited_retry_after_ms_is_meaningful_lower_bound`
(drains the draft-bucket quota and asserts `retry_after_ms >= 2`,
killing both the `-> 0` and `-> 1` constant-return mutations). No
known-equivalent annotations were needed; every surviving mutant was
a real test gap.

## `rimap-server`

**Last refresh:** 2026-07-09 (issue #530 — cold-path triage over the #515 hot-path refresh).
**Surviving mutants in hot paths (`mcp/{dispatch,audit_envelope,tool_catalog,tool_name,preinit,server,response,error,result_provenance}.rs`, `mcp/wire_validator/`, `boot/`; `fuzz_oracle.rs` covered separately below):** 13 in this run (all annotated as known-equivalent), plus 7 hot-path mutants caught by timeout (documented in the timeout table below).
**Surviving mutants in cold paths (`cli/`, `tools/`, `main.rs`, `lib.rs`):** **0 unannotated.** Issue #530 triaged the cold-path survivors (45 total = 43 missed + 2 caught-by-timeout; down from the pre-#517 #515 figure of 54): the 43 missed split into 17 killed (new unit tests), 3 known-equivalent, and 23 best-effort — every remaining survivor carries an inline `// cargo-mutants:` annotation and a row in the cold-path table below, and the 2 timeout kills sit in the timeout table.

Run summary (917 mutants total, 2026-07-09 refresh via `cargo mutants
--package rimap-server --no-shuffle --jobs 10 --jobserver-tasks 40
--timeout 120 --test-tool nextest -- -E 'not (binary(=e2e) |
binary(=e2e_smtp))' --test-threads 4` on Linux with the `mold` linker):
658 caught, 67 missed (13 hot-path known-equivalent + 54 best-effort),
183 unviable, 9 timeouts (7 hot-path kill-by-timeout + 2 best-effort) in
39 minutes wall clock. Mutant total is up from 529 on 2026-05-18 (rmcp 2.1
migration, multi-account reveal-on-select #439, compose attachments +
sanitized HTML #408, `thread_of_uid` #410, folder-wide EXPUNGE, and the
`wire_validator` module split).

Issue #530 cold-path rerun (2026-07-09), scoped to the cold-path files via
`cargo mutants --package rimap-server --no-shuffle --jobs 10 --timeout 120 -f
'.../tools/**/*.rs' -f '.../cli/**/*.rs' -f '.../main.rs' -f '.../lib.rs'
--test-tool nextest -- -E 'not (binary(=e2e) | binary(=e2e_smtp))'
--test-threads 4`: 614 mutants, 414 caught, **43 missed + 2 timeout**, 155
unviable, 39 min. The missed count is down from the #515 figure of 54 because
#517 (real SMTP `message_builder` e2e) landed *after* the #515 refresh
(PR #516 merged 11:07 UTC; #517 closed 15:09 UTC) and kills several compose
survivors. The 43 missed split 17 kill / 3 known-equivalent / 23 best-effort;
the 2 timeouts are new kill-by-timeout survivors (below).

Methodology change vs 2026-05-18: this refresh **runs the container
integration harnesses** as part of the survey. The wire-driven dovecot
suite (`e2e_wire*`) is included via the `--test-tool nextest` selection
above; only the in-process `e2e` binary and `e2e_smtp` are excluded (the
former is redundant with `e2e_wire` for dispatch coverage, the latter is
SMTP-only), because on a Docker-capable host their per-mutant container
bring-up otherwise blows the test timeout. The 2026-05-18 baseline instead
treated every container harness as skipped (its dev host had no Docker) and
documented container-only mutations as test-infrastructure gaps. Counting
the harness CI actually runs as coverage catches those mutations directly:
the `list_resources -> Ok(Default::default())` stub is now caught by
`e2e_wire`, so its former known-equivalent annotation was removed.
`call_tool`'s notify-suppression gate (`server.rs:702`) still survives even
under `e2e_wire` — asserting the *absence* of a
`notifications/tools/list_changed` for non-`use_account` calls needs a
`RequestContext<RoleServer>`, for which rmcp exposes no public test
constructor — so it stays annotated.

The exact hot-survivor count is run-varying: `mcp_wire_proptest` generates
fresh random JSON each run and catches a different subset of the
observably-equivalent `wire_validator` visitor-method mutants, so the
count drifts by a few (this run 13; a 2026-07-08 pre-cleanup run saw 15).
Every member of that equivalence class is covered by the group annotations
at `envelope.rs:103` and `:193`, so there are **0 unannotated hot
survivors** in every run. The table below documents the equivalence
classes, not a single-run per-line snapshot.

File-scope corrections vs the 2026-05-18 section:
- `mcp/content.rs` moved to `tools/content_parse.rs` (now best-effort tier).
- `mcp/result_provenance.rs` is new (#316) and hot; it has 0 survivors.
- `mcp/wire_validator.rs` became the `mcp/wire_validator/` module dir
  (`envelope.rs`, `inbound.rs`, `outbound.rs`, `supervisor.rs`, `mod.rs`);
  the visitor/CRLF known-equivalent rows below moved with it.

Cold-path triage (issue #530): the cold-path survivors are no longer deferred.
Seventeen were pure-function gaps and are now killed by unit tests (`escape_wire_name`
DEL escaping, the `sanitize_folder_entry` raw-input cap, `validate_compose_input`
body_html size, `validate_recipient_set` boundary, `forwarded_subject` multibyte
truncation, `validate_header_text` injection chars, `line_is_from` all-`>` bound,
`unique_temp_name`/`export_token` uniqueness, `build_query` control-byte rejection,
`format_flag` mappings, and the `part_walker` leaf-at-exactly-`MAX_PART_DEPTH`
boundary). The remaining 26 carry inline `// cargo-mutants:` annotations and the
cold-path table rows below: 3 known-equivalent and 23 best-effort (thin wrappers
over `rimap-imap` whose argument shaping needs an
integration harness, non-portable filesystem error/TOCTOU paths, and diagnostic
CLI wiring — spec §6 best-effort tier). The retrieval `ExportSource` and
`fetch_message` truncation rows are attributed to issue #520 (export/retrieval
over the wire), which will kill them via the harness. The "zero unannotated
survivors" gate now holds for cold paths too.

| Equivalence class / File:line | Mutation(s) | Reason kept | Annotation site |
|---|---|---|---|
| `mcp/wire_validator/mod.rs:34` | `replace * with + in BUF_SIZE` | Buffer-size constant; no test asserts the value and both `64 * 1024` and `64 + 1024` hold one envelope per write. | `mcp/wire_validator/mod.rs:31` |
| `mcp/wire_validator/inbound.rs:66,70` | `delete match arm Some(&b'\n')` / `Some(&b'\r')`, and `replace - with /` on the two `len() - 1` strips | `serde_json::from_str` (and the dup-check `Deserializer::from_str`) tolerate trailing whitespace, and `len() / 1 == len()`, so the trimmed validation view is unchanged either way. The companion `replace - with +` at the `\r` site IS a real gap (slices past the buffer and panics on `\r\n`) and is killed by `validate_inbound_strips_crlf_line_ending`. | `mcp/wire_validator/inbound.rs:54` |
| `mcp/wire_validator/envelope.rs` — `OneLevelDupCheck` non-`visit_map` methods (`expecting`, `visit_seq`, `visit_str`/`visit_string`, `visit_unit`/`visit_none`) | stub / constant-return | `expecting` only formats serde diagnostics; `visit_string`/`visit_none` are unreachable from `serde_json::Deserializer::from_str` (strings route through `visit_str`, JSON null through `visit_unit`); a non-draining `visit_seq` leaves the parser mid-array and the outer `deserialize_any(...).unwrap_or(false)` swallows the error to the same "no duplicates" verdict. `visit_map` (the load-bearing method) is killed by the dup-check tests. Which members survive vs. are caught by `mcp_wire_proptest` varies per run. | `mcp/wire_validator/envelope.rs:103` |
| `mcp/wire_validator/envelope.rs` — `TopAndErrorDupCheck` non-`visit_map` methods (`expecting`, `visit_seq`, `visit_<primitive>`, `visit_unit`/`visit_none`) | stub / constant-return | The dup-check runs before `validate()` parses the line; a non-object top-level then fails `parsed.as_object()` and is rejected with `invalid_request(Value::Null)` — the same id as the dup-check rejection path — so any `visit_<primitive>` verdict yields the same `Reject`. `expecting`/`visit_seq` as above. `visit_map` is killed by `duplicate_top_level_keys_reject` / `duplicate_keys_inside_error_body_reject`. Run-varying subset. | `mcp/wire_validator/envelope.rs:193` |
| `mcp/server.rs:702` | `replace && with ||` and `replace == with !=` in `<impl ServerHandler>::call_tool` | Test-infrastructure gap: the `use_account` notify gate. Asserting that non-`use_account` calls suppress `notifications/tools/list_changed` needs a `RequestContext<RoleServer>` (no rmcp public test constructor); `e2e_wire` asserts the notification's presence, not its absence. | `mcp/server.rs:692` |

### Cold-path survivors (issue #530)

Line numbers are a 2026-07-09 post-annotation snapshot; the grouping and
mutation kind are the durable identifiers. Known-equivalent first, then
best-effort tier.

| File:line | Mutation(s) | Reason kept | Annotation site |
|---|---|---|---|
| `tools/retrieval/mbox.rs:73` | `< with <=` on the `escape_from_lines_into` trailing push | At `line_start == msg.len()` the mutated guard passes the empty tail slice to `write_mbox_line`, and `line_is_from(b"")` is false, so nothing is appended — identical to the `<` branch skipping the push. Same shape as `rimap-content` `mime_scrub.rs:187`. | `tools/retrieval/mbox.rs:68` |
| `tools/retrieval/sandbox.rs` — `#[cfg(not(unix))]` `read_sandboxed_file` | `-> Ok(vec![0])` / `Ok(vec![1])` (2 mutants) | Platform-gated fail-closed stub, not compiled on Linux CI, so it cannot change behavior in this run; on non-Unix the stub failing closed is the security property. Same shape as `rimap-audit` `self_check.rs:189`. | the `#[cfg(not(unix))]` fn body |
| `tools/retrieval/export_messages.rs:219,241` | `fetch_sizes` stub-returns (4) + `fetch_one_body -> Ok(vec![1])` | The real IMAP-backed `impl ExportSource for AccountState`. The export logic is unit-tested against a fake `ExportSource` (trait seam); this impl's `self.imap.fetch*` round trip is best-effort, covered by **#520** (export over the wire). | `impl ExportSource for AccountState` |
| `tools/retrieval/fetch_message.rs:181` | `> with </>=/==` (3) on the `max_body_bytes` truncation | `body_text` comes from an IMAP fetch + content parse inside `handle`; exercising the boundary needs a fetched body straddling `max` (harness; **#520**-adjacent). | `tools/retrieval/fetch_message.rs:177` |
| `tools/retrieval/search.rs:346` | `delete !` in `handle_thread` (`!related.contains(target)`) | `related` is the result of an IMAP `thread_related` round trip; the branch is only distinguishable through the thread integration harness. | `tools/retrieval/search.rs:342` |
| `tools/retrieval/search.rs:385,403` | `fetch_thread_headers` stub-returns (2) + `delete "Message-ID"` match arm | The function fetches the target's body over IMAP and parses headers; the token parsing it delegates to is unit-tested, this fetch+dispatch shell is harness-covered. | `tools/retrieval/search.rs:381` |
| `tools/retrieval/search.rs:485` | delete `envelope` / `size` FetchSpec fields in `fetch_and_format_page` | Changes what the page fetch requests; observable only through a real IMAP fetch. `format_search_result`, the consumer, is unit-tested. | `tools/retrieval/search.rs:481` |
| `tools/retrieval/download_attachment.rs:140` | delete `bodystructure` field from the cross-validation FetchSpec | The MIME cross-validation warning is only observable through an IMAP fetch returning a BODYSTRUCTURE (harness). | `tools/retrieval/download_attachment.rs:132` |
| `tools/retrieval/sandbox.rs:179` | `> with ==` on the 1000-collision cap in `write_attachment` | Off-by-one, not strict equivalence: `counter` increments by one from 0, so `== 1000` fires one iteration earlier than `> 1000` (tolerating 1000 vs 1001 collisions); both terminate the loop at ~1000. Distinguishing them needs 1000 pre-existing colliding filenames, so it is annotated rather than killed. | `tools/retrieval/sandbox.rs:172` |
| `tools/retrieval/sandbox.rs:171` | `match guard e.kind() == AlreadyExists` forced to `true` | Routing a non-`AlreadyExists` `hard_link` error through the retry path only changes the surfaced error after ~1000 iterations, and a persistent non-`AlreadyExists` `hard_link` failure is not portable across CI filesystems. | `tools/retrieval/sandbox.rs:165` |
| `tools/retrieval/sandbox.rs:352` | `+ with *` on `take(max_bytes + 1)` in `read_sandboxed_file` | Disables only the post-stat file-growth (TOCTOU) tripwire; observing it requires the file to grow between the `metadata()` stat and the read, which the harness cannot induce deterministically. | `tools/retrieval/sandbox.rs:346` |
| `tools/compose/message_builder.rs:52` | `* with +` on `MAX_FORWARD_ORIGINAL_BYTES` | No unit test pins the byte value; it is only observable through the `forward` handler's size gate, which needs an IMAP+SMTP round trip. | `tools/compose/message_builder.rs:50` |
| `tools/compose/message_builder.rs:451` | `apply_threading_headers -> Ok(Default::default())` | Body fetches the referenced message over IMAP; killing it needs a harness that replies to a real message. | `tools/compose/message_builder.rs:443` |
| `tools/compose/forward.rs:91` | `> with >=` on the forward-size cap | Handler needs an IMAP fetch plus SMTP send, and the boundary differs only at an original of exactly 25 MiB — impractical to stage in an e2e run. | `tools/compose/forward.rs:84` |
| `main.rs:645` | `delete match arm Some(Command::DumpToolSchemas)` | `#[cfg(feature = "test-support")]` diagnostic dispatch; CI exercises it via `just regen-tool-schemas`, not by an in-process Rust test. | `main.rs:641` |
| `main.rs:677` | `run_migrate_keyring -> Ok(())` | CLI wiring over the OS keyring; `migrate_keyring::migrate_one` is unit-tested, but the handler needs a live keyring the unit suite cannot access. | `main.rs:669` |

Mutants caught by timeout (kill-by-timeout — the mutation induces a
non-terminating loop that the test timeout kills, surfacing as TIMEOUT
rather than a clean failure; same pattern as `rimap-audit`'s
`writer/rotation.rs:50` and `rimap-imap`'s `ops/fetch.rs:51`):

| File:line | Mutation | Kill mechanism |
|---|---|---|
| `mcp/server.rs:474` | `tool_page_window -> (usize, usize, Option<usize>)` constant-return variants that leave `next = Some(_)` (4 mutants) | Forces the `list_tools` cursor to always advertise a next page, so a client walking `next_cursor` to completion loops forever → TIMEOUT. |
| `mcp/server.rs:476` | `replace < with <= in tool_page_window` | `end < len` becomes `end <= len`, so `next` stays `Some` on the final page → non-terminating page walk → TIMEOUT. |
| `mcp/wire_validator/mod.rs:34` | `replace * with / in BUF_SIZE` | `64 / 1024 == 0` → a zero-capacity duplex buffer whose read loop makes no progress → TIMEOUT. |
| `mcp/wire_validator/outbound.rs:37` | `replace == with != in passthrough_outbound` | EOF (`n == 0`) no longer returns, so the outbound pump spins on zero-byte reads → TIMEOUT (`passthrough_outbound_drops_on_eof`). |
| `tools/retrieval/mbox.rs:86` | `replace += with *= in line_is_from` | `j *= 1` never advances past a leading `>`, so the quote-run scan on any `>`-prefixed line spins forever → TIMEOUT (cold-path, issue #530). |
| `tools/retrieval/sandbox.rs:174` | `replace += with *= in write_attachment` | `counter *= 1` never advances, so a filename collision retries forever without reaching the 1000-cap → TIMEOUT (cold-path, issue #530). |

### `mcp/fuzz_oracle.rs` (behind `--features fuzzing`)

**Last refresh:** 2026-07-09.
**Surviving mutants:** 0 (all caught or unviable under the feature-gated build).

The file is gated by `#[cfg(feature = "fuzzing")]` in
`crates/rimap-server/src/mcp/mod.rs`, so the main `rimap-server` survey
(default features) does not exercise it. A dedicated `cargo mutants
--package rimap-server --features fuzzing -f
'crates/rimap-server/src/mcp/fuzz_oracle.rs'` pass (2026-07-09) enumerated
4 mutants: 2 caught, 2 unviable, 0 missed. `fuzz_validate ->
FuzzOutcome` and `error_envelope_validator -> &'static Validator` remain
**unviable** (`FuzzOutcome` and `jsonschema::Validator` have no `Default`
impl). `check_rmcp_accepts -> Ok(())` and `check_error_envelope_valid ->
Ok(())` are **caught** by the feature-gated test suite at the bottom of
`fuzz_oracle.rs`. No known-equivalent annotations needed.

## `rimap-imap`

**Last refresh:** 2026-07-09 (issue #515 — refresh of the 2026-05-18 #289 baseline).
**Surviving mutants in hot paths (`tls.rs`, `auth.rs`, `connection/`, `preflight.rs`, `ops/`):** 0 (all killed by tests; no annotations needed).
**Surviving mutants in plumbing (`error.rs`, `types.rs`, `time.rs`, `special_use.rs`, `lib.rs`):** 0.

Run summary (381 mutants total, 2026-07-09 refresh via `cargo mutants
--package rimap-imap --no-shuffle --jobs 10 --jobserver-tasks 40 --timeout
200 --test-tool nextest -- -E 'not binary(/proton/)' --test-threads 4` on
Linux with the `mold` linker): 267 caught, 0 missed, 114 unviable, 0
timeouts in 10 minutes wall clock. Mutant total is up from 313 on
2026-05-18. As with `rimap-server`, this refresh runs the container
harness: the dovecot integration suite (`tests/integration/dovecot`) is
included; only the `proton` binary is excluded (it requires a live Proton
Bridge and always silent-skips). The dovecot harness is the coverage for
the network-facing `Connection::*` / `ops::*` functions — without it, ~100
stub-return mutants on those functions survive purely because nothing
exercises the round trip.

File-scope correction vs the 2026-05-18 section: `connection.rs` became the
`connection/` module dir (`handshake.rs`, `login.rs`, `dispatch.rs`,
`mod.rs`).

The survey surfaced two hot-path gaps, both killed by adding tests:
- `connection/mod.rs:180` — `Connection::username() -> ""`: the config
  accessors (`host`, `username`, `max_fetch_body_bytes`) had no test
  pinning them to the config they read. `username()` feeds the compose
  `From:` address, so a stub returning `""` would forge sender identity.
  Killed by `connection::tests::config_accessors_return_the_configured_values`.
- `ops/move_message.rs:95` — the UIDVALIDITY guard forced always-true: the
  mismatch path (abort on stale validity) was tested, but the success path
  (matching validity → move proceeds) was not, so a guard that always
  aborted would go unnoticed. Killed by the dovecot integration test
  `case_25_move_message_uidvalidity_guard`, which moves with a matching
  validity (must succeed) and a stale one (must abort with
  `UidValidityChanged`).

| File:line | Mutation | Reason kept | Annotation site |
|---|---|---|---|

(No annotated survivors — every hot-path mutant was either killed by a test
or caught by the dovecot harness.)
