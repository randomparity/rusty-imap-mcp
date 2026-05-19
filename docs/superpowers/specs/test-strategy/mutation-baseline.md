# Mutation-baseline — Targeted-trust-boundary survivor inventory

**Updated:** 2026-05-05
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

**Last refresh:** 2026-05-18.
**Surviving mutants in hot paths (`mcp/{dispatch,audit_envelope,tool_catalog,tool_name,wire_validator,preinit,server,response,content,error}.rs`, `boot/`; `fuzz_oracle.rs` covered separately below):** 25 (all annotated as known-equivalent).
**Surviving mutants in best-effort paths (`cli/`, `tools/`, `main.rs`):** 55 (unannotated; documented as best-effort tier per spec §6 — see "best-effort paths" note below).

Run summary (529 mutants total, 2026-05-18 baseline via `cargo
mutants --package rimap-server --no-shuffle --jobs 8 --timeout 60`
on Linux): 281 caught, 107 missed (52 annotated below as hot-path
known-equivalent across the main table and `### \`mcp/fuzz_oracle.rs\``
subsection — 25 in hot paths and the rest documented under
`fuzz_oracle` or as best-effort tier), 3 timeouts, 138 unviable in
22 minutes wall clock. The dev-host blocker captured in issue #289
(cargo-mutants 27.0.0 + macOS-specific [#611](https://github.com/sourcefrog/cargo-mutants/issues/611))
was sidestepped by running on Linux without `--in-place`; see
`docs/security/cargo-mutants-runbook.md` ("Linux fast path") for the
invocation contract.

File-scope correction: issue #289 inherited path lists from #245's
`archive/daemon-experiment` scope and referenced `daemon/transport*.rs`,
`daemon/audit_sink.rs`, `daemon/run.rs`, `shim.rs`, and
`mcp/posture_context.rs`, none of which exist on current `main`
(the daemon experiment was reverted). The hot-path surface above is
the current security-critical surface as of 2026-05-18.

Best-effort paths note: 55 cold-path survivors in `tools/retrieval/`
(36), `tools/compose/message_builder.rs` (7), `main.rs` (7),
`cli/dump_tool_schemas.rs` (3), `tools/admin/list_folders.rs` (2),
and `tools/retrieval/download_attachment.rs` (1) are not annotated
inline. Per spec §6 these are best-effort tier (mostly thin
wrappers over `rimap-imap` whose argument shaping needs an
integration harness, plus diagnostic-only CLI output). Per-mutant
triage is deferred to a follow-up issue; the spec's
"zero unannotated survivors" gate applies to hot paths only.

| File:line | Mutation | Reason kept | Annotation site |
|---|---|---|---|
| `mcp/wire_validator.rs:21` | `replace * with + in BUF_SIZE` | Buffer-size constant; no test asserts the value and both `64 * 1024` and `64 + 1024` hold one envelope per write. | `mcp/wire_validator.rs:21` |
| `mcp/wire_validator.rs:174` | `replace <impl Visitor for OneLevelDupCheck>::expecting -> std::fmt::Result with Ok(Default::default())` | Formatter only feeds serde's error-message machinery; no test or production caller observes the diagnostic text. | `mcp/wire_validator.rs:173` |
| `mcp/wire_validator.rs:190` | `replace <impl Visitor for OneLevelDupCheck>::visit_seq with Ok(true)` | Without the drain loop, the underlying `serde_json::Deserializer` leaves trailing state mid-array; the outer `de.deserialize_any(...).unwrap_or(false)` in `has_duplicate_keys_in_rmcp_strict_positions` swallows the resulting error back to `false`, same outcome as drained-then-`Ok(false)`. | `mcp/wire_validator.rs:173` |
| `mcp/wire_validator.rs:190` | `replace <impl Visitor for OneLevelDupCheck>::visit_seq with Ok(false)` | Same reasoning — skipping the drain leaves the deserializer mid-array, `unwrap_or(false)` rescues, dup-check returns `false` either way. | `mcp/wire_validator.rs:173` |
| `mcp/wire_validator.rs:210` | `replace <impl Visitor for OneLevelDupCheck>::visit_string with Ok(true)` | Unreachable from `serde_json::Deserializer::from_str` (used by `has_duplicate_keys_in_rmcp_strict_positions`): the streaming deserializer routes JSON strings through `visit_str`, never the owned-`String` path. | `mcp/wire_validator.rs:173` |
| `mcp/wire_validator.rs:216` | `replace <impl Visitor for OneLevelDupCheck>::visit_none with Ok(true)` | Unreachable from `serde_json::Deserializer`: JSON `null` invokes `visit_unit`, not `visit_none` (which is for `Option`-style deserialization). | `mcp/wire_validator.rs:173` |
| `mcp/wire_validator.rs:245` | `replace <impl Visitor for TopAndErrorDupCheck>::expecting -> std::fmt::Result with Ok(Default::default())` | Same diagnostic-only formatter as `OneLevelDupCheck::expecting` above. | `mcp/wire_validator.rs:263` |
| `mcp/wire_validator.rs:275` | `replace <impl Visitor for TopAndErrorDupCheck>::visit_seq with Ok(true)` | `validate()` parses the line into a `Value` AFTER the dup-check; a non-object top-level (array) fails `parsed.as_object()` and rejects with `invalid_request(Value::Null)` regardless of whether the dup-check returned true or false. Same final outcome. | `mcp/wire_validator.rs:263` |
| `mcp/wire_validator.rs:275` | `replace <impl Visitor for TopAndErrorDupCheck>::visit_seq with Ok(false)` | Same equivalence — non-object top-level rejects with `Value::Null` id regardless of dup-check verdict. | `mcp/wire_validator.rs:263` |
| `mcp/wire_validator.rs:280` | `replace <impl Visitor for TopAndErrorDupCheck>::visit_bool with Ok(true)` | Top-level boolean fails `parsed.as_object()` → rejects with `Value::Null` id (same as the dup-check rejection path). | `mcp/wire_validator.rs:263` |
| `mcp/wire_validator.rs:283` | `replace <impl Visitor for TopAndErrorDupCheck>::visit_i64 with Ok(true)` | Top-level number fails `parsed.as_object()` → rejects with `Value::Null` id (same outcome). | `mcp/wire_validator.rs:263` |
| `mcp/wire_validator.rs:286` | `replace <impl Visitor for TopAndErrorDupCheck>::visit_u64 with Ok(true)` | Same as `visit_i64`. | `mcp/wire_validator.rs:263` |
| `mcp/wire_validator.rs:289` | `replace <impl Visitor for TopAndErrorDupCheck>::visit_f64 with Ok(true)` | Same as `visit_i64`. | `mcp/wire_validator.rs:263` |
| `mcp/wire_validator.rs:292` | `replace <impl Visitor for TopAndErrorDupCheck>::visit_str with Ok(true)` | Top-level string fails `parsed.as_object()` → rejects with `Value::Null` id (same outcome). | `mcp/wire_validator.rs:263` |
| `mcp/wire_validator.rs:295` | `replace <impl Visitor for TopAndErrorDupCheck>::visit_string with Ok(true)` | Unreachable from `serde_json::Deserializer::from_str` — owned-String path is not used by the streaming deserializer. | `mcp/wire_validator.rs:263` |
| `mcp/wire_validator.rs:298` | `replace <impl Visitor for TopAndErrorDupCheck>::visit_unit with Ok(true)` | Top-level `null` fails `parsed.as_object()` → rejects with `Value::Null` id (same outcome). | `mcp/wire_validator.rs:263` |
| `mcp/wire_validator.rs:301` | `replace <impl Visitor for TopAndErrorDupCheck>::visit_none with Ok(true)` | Unreachable — `serde_json` routes JSON `null` through `visit_unit`, not `visit_none`. | `mcp/wire_validator.rs:263` |
| `mcp/wire_validator.rs:482` | `delete match arm Some(&b'\n') in validate_inbound` | The trimmed view feeds `serde_json::from_str` (and the dup-check `Deserializer::from_str`), both of which tolerate trailing whitespace. Retaining `\n` in the validation view does not change parse outcomes. | `mcp/wire_validator.rs:518` |
| `mcp/wire_validator.rs:482` | `replace - with / in validate_inbound` (at `buf.len() - 1`) | `len() / 1 == len()` produces the same slice as deleting the match arm — `\n` is not stripped. serde_json tolerates trailing whitespace; same parse outcome. | `mcp/wire_validator.rs:518` |
| `mcp/wire_validator.rs:486` | `delete match arm Some(&b'\r') in validate_inbound` | Same reasoning as the `\n` arm above — serde_json tolerates trailing whitespace. | `mcp/wire_validator.rs:518` |
| `mcp/wire_validator.rs:486` | `replace - with / in validate_inbound` (at `trimmed.len() - 1`) | `len() / 1 == len()` — same effect as deleting the match arm. The companion `replace - with +` mutant at the same site IS a real gap (it panics on `\r\n` input) and is killed by `validate_inbound_strips_crlf_line_ending`. | `mcp/wire_validator.rs:518` |
| `mcp/content.rs:27` | `delete match arm ContentError::Malformed{..} in classify_content_error` | The `Malformed` arm and the `_` fallback both call `RimapError::invalid_input(err.to_string())` — the `#[expect(clippy::match_same_arms)]` above the match documents this intent. Deleting the explicit arm routes to the identical fallback. The companion `delete match arm ContentError::LimitExceeded{..}` IS a real gap and is killed by `limit_exceeded_classifies_as_attachment_too_large`. | `mcp/content.rs:22` |
| `mcp/server.rs:353` | `replace <impl ServerHandler>::list_resources -> Result<ListResourcesResult, ErrorData> with Ok(Default::default())` | Test-infrastructure gap: rmcp `RequestContext<RoleServer>` has no public test constructor in this version, so the trait method cannot be invoked from a unit test. End-to-end coverage via the dovecot harness in `tests/e2e.rs`. | `mcp/server.rs:348` |
| `mcp/server.rs:489` | `replace == with != in <impl ServerHandler>::call_tool` (`tool_name == ToolName::UseAccount` post-dispatch notify gate) | Test-infrastructure gap: verifying the suppression of `notifications/tools/list_changed` for non-`use_account` calls requires a `RequestContext<RoleServer>` (to drive `context.peer.notify_tool_list_changed()`); rmcp does not expose a public test constructor. End-to-end coverage via the dovecot harness. | `mcp/server.rs:510` |
| `boot/discovery.rs:27` | `replace resolve_special_use -> Result<SpecialUseMap, RimapError> with Ok(Default::default())` | Test-infrastructure gap: the function calls `connection.list_folders("*")` which requires a live IMAP server. The dovecot harness in `tests/e2e.rs` does not exercise this code path either (it constructs `AccountState` with `SpecialUseMap::default()` directly, bypassing the function). Annotated as a known coverage gap pending future test infrastructure. | `boot/discovery.rs:26` |

### `mcp/fuzz_oracle.rs` (behind `--features fuzzing`)

**Last refresh:** 2026-05-18.
**Surviving mutants:** 0 (all caught or unviable under the feature-gated build).

The file is gated by `#[cfg(feature = "fuzzing")]` in
`crates/rimap-server/src/mcp/mod.rs`, so the main `rimap-server`
table above (default features) does not exercise it. The numbers
here come from a dedicated `cargo mutants --package rimap-server
--features fuzzing -F 'fuzz_oracle.rs'` pass. Of the 4 mutants
cargo-mutants enumerated for this file:

- `fuzz_validate -> FuzzOutcome with Default::default()` and
  `error_envelope_validator -> &'static Validator with
  Box::leak(Box::new(Default::default()))` are **unviable**
  (`FuzzOutcome` and `jsonschema::Validator` have no `Default`
  impl, so the mutation does not compile).
- `check_rmcp_accepts -> Result<(), String> with Ok(())` is
  **caught** by `rmcp_rejects_missing_jsonrpc_version` and
  `rmcp_rejects_envelope_with_no_method_result_or_error` (both
  assert `Err`, which would fail under the stub `Ok(())`).
- `check_error_envelope_valid -> Result<(), String> with Ok(())` is
  **caught** by `error_envelope_schema_rejects_missing_error_field`
  and `error_envelope_schema_rejects_array_id`.

No known-equivalent annotations were needed; every mutant is killed
or unviable under the feature-gated test suite at the bottom of
`fuzz_oracle.rs`.

## `rimap-imap`

**Last refresh:** 2026-05-18.
**Surviving mutants in hot paths (`tls.rs`, `auth.rs`, `connection.rs`, `preflight.rs`, `ops/`):** 0 (all killed by tests; no annotations needed).
**Surviving mutants in plumbing (`error.rs`, `types.rs`, `time.rs`, `special_use.rs`, `lib.rs`):** 0.

Run summary (313 mutants total, 2026-05-18 baseline via `cargo
mutants --package rimap-imap --no-shuffle --jobs 8 --timeout 60` on
Linux): 212 caught, 1 missed, 99 unviable, 1 timeout in 6 minutes
wall clock. The single missed mutant
(`connection.rs:127`, `replace <impl Debug for Connection>::fmt
-> std::fmt::Result with Ok(Default::default())`) was killed by
adding `debug_format_includes_connection_fields`. The 1 timeout
mutant (`ops/fetch.rs:51`, `replace != with == in compress_uid_set`)
is covered by the existing test suite — under the mutation
`compress_uid_set` enters an infinite loop and the test runs until
the kernel kills it at the 60s timeout, surfacing the regression as
TIMEOUT rather than as a clean test failure. Same pattern as
`rimap-audit`'s `writer/rotation.rs:50` documented above.

The pre-existing `rimap-imap` test suite (including the dovecot
integration harness under `tests/integration/dovecot/` and the
proton-bridge harness under `tests/integration/proton/`) was already
strong enough to catch all hot-path mutations without any new
known-equivalent annotations. No annotation rows below — every
surviving mutant was either a real test gap (killed in commit
`feb3a3d` of the issue #289 PR) or a timeout-caught mutation.

| File:line | Mutation | Reason kept | Annotation site |
|---|---|---|---|

(No annotated survivors — every hot-path mutant was a real test gap killed by adding tests.)
