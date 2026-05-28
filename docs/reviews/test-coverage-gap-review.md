# Test Coverage Gap Review

## 1. Executive summary

> **Correction (2026-05-28).** An earlier draft of this summary claimed the Docker-gated
> integration suites are unreachable on this host because "macOS cannot run Docker." That
> is wrong for local development. With Docker Desktop and the ARM64 image
> `docker.io/dovecot/dovecot:2.4.4-root`, all of them **run and pass on this host**:
> `rimap-imap` `dovecot` (43 passed), `rimap-server` `e2e` (1), `e2e_wire` (7),
> `e2e_wire_cancellation` (7), all with `RIMAP_REQUIRE_DOCKER=1`. The macOS-Docker
> limitation applies only to GitHub's *hosted* Apple-Silicon runners, not to this machine
> or to Linux CI runners. The analysis below has been revised accordingly.

This sweep covered 11 areas of the rusty-imap-mcp workspace. The integration suites are
runnable, so connection lifecycle, MCP dispatch, and the server boot path do have working
coverage — but it is **happy-path coverage**. `e2e_full_session` walks list → search →
fetch → mark_read → create_draft → export → move; the Dovecot connection cases cover
TLS-pin mismatch (`case_02`, `case_22`, `starttls_with_wrong_pin`), login rejection
(`case_04`), connection drop/recovery (`case_10`, `case_11`), and folder/store/move/expunge
operations. Pure helpers below the orchestration layers are also well tested.

The real gaps that survive are of two kinds, **neither of which is closed by the suites
being runnable**:

1. **Fault-injection branches the e2e suites never trigger even though they execute.** The
   e2e server wires a `CircuitBreaker` but never trips it, so the service-vs-user tripping
   decision in `dispatch_account_scoped` is unasserted. It opens the audit writer with
   `fail_open: false` but never induces a write failure, so the fail-closed abort and the
   no-orphan-`tool_start` property are unasserted. The non-UIDPLUS plain-`EXPUNGE`
   data-loss fallback is unreachable against Dovecot (which always advertises UIDPLUS), so
   it needs a mock IMAP server, not a container.
2. **Pure-unit gaps independent of any server.** FolderGuard Modified-UTF-7 normalization
   (all current tests are ASCII-only — a fail-open protected-folder bypass), rimap-content
   body accounting / secondary-HTML drop, the SMTP error taxonomy, and AccountId/FolderName
   validation owe nothing to Docker.

The most common defect class is a fail-open that is "safe today only by accident": a
dead defensive branch, a mirror function that can drift from production, or a side effect
committed before a later stage can reject it. Several confirmed bugs (SMTP error
taxonomy, AccountId deserialize, breaker probe waste) are of this kind.

The single biggest change from the earlier draft: the recommended **in-process rustls/rcgen
TLS mock is redundant** — TLS-pin mismatch with a typed error and a single AuthEvent is
already tested against real Dovecot here (`case_02`/`case_22`/`starttls_with_wrong_pin`).
Any missing auth-provenance variant (e.g. `LOGINDISABLED`) should be added by extending
`dovecot.rs`, not by building a mock.

## 2. Confirmed, untested bugs

Counts: 14 confirmed bugs across the sweep. Severity below reflects the verified
verdicts, not the original reporter estimates.

| Severity | Area | Location | Defect | Suggested test |
|----------|------|----------|--------|----------------|
| high | rimap-authz | folder_guard.rs:17-45 | Modified-UTF-7 normalization is exercised only with ASCII; the decode + decode-failure-fallback paths for protected-folder matching are unverified (potential fail-open bypass) | Build FolderGuard from a raw mUTF-7 protected name, assert `check_protected` rejects both the encoded and decoded request forms, plus a malformed-encoding fallback case |
| high | server-mcp | server.rs:125-139 | breaker `on_success`/`on_failure` and posture/rate gating in `dispatch_account_scoped` are only covered behind Docker e2e | Drive a `DispatchGuard<ManualClock>` fed by `rimap_error_to_breaker_reason`: assert Timeout/Auth trip, InvalidInput does not, Ok resets |
| high | server-mcp | audit_envelope.rs:124-159 | fail-closed tool_start audit failure and the no-orphan-tool_start property are untested at the envelope level | `run_with_audit_envelope` + `force_next_write_failure`: assert Err on fail_open=false with zero records on disk; Ok + suppressed counter on fail_open=true |
| medium | rimap-core | account.rs:15 | `AccountId` derives `Deserialize`, bypassing `AccountId::new` validation and lowercasing (verdict: real, low blast radius today) | Assert `from_str::<AccountId>("\"WORK\"") == AccountId::new("work")` and that empty/space/oversized strings are rejected |
| medium | server-mcp | server.rs:546-549 | A non-string `account` arg (`123`/`null`) silently falls through to auto-select/session-default instead of erroring | Multi-account harness with a session default: send `{"account":123}`/`{"account":null}`, assert invalid_input rather than success against the default |
| medium | server-tools | part_walker.rs:43-47 | `BodyStructure::Message` arm reuses the wrapper part_id and re-descends with it, producing a part-ID collision / RFC-incorrect numbering for embedded messages | Walk `Message{ body: single }`, assert ids are `["1","1.1"]` not `["1","1"]` |
| low | rimap-core | folder_name.rs:107 | Doc promises C0/C1 rejection but C1 controls (U+0080–U+009F) are never rejected; proptest reference shares the omission | Assert `FolderName::new("bad\u{0080}name")` and `\u{009f}` are rejected; update the proptest reference predicate |
| low | rimap-config | credential.rs:83-86 | `split_account_for_error` splits on the first `@`, wrongly attributing username/host for namespaced (`id/user@host`) and multi-`@` keys, breaking log-tag correlation | Drive a Keychain error and assert `account_tag == hash_account_tag("alice", host)` (not `hash_account_tag("work/alice", host)`) |
| low | rimap-imap | fetch.rs:158-163 | FETCH silently `continue`s on UID-absent or UID-0 messages with no warning (only reachable on a non-conformant server) | Extract a pure UID helper; assert None/Some(0) produce a warn/skip signal, not a silent drop |
| medium | rimap-content | bodies.rs:64-70 | Secondary text/html parts are silently dropped (no warning, not counted, anchors escape lookalike audit) | Two-HTML-part multipart/mixed with a homograph anchor in part 2; assert the second part surfaces OR a warning fires, and the homograph is audited |
| low | rimap-content | bodies.rs:76-85 | Aggregate body cap is checked only after a part is appended, so one part can straddle MAX_TOTAL_BODY_BYTES by up to ~1MiB | Parts that cross the 4MiB boundary mid-part; assert retained total exceeds the cap (pins the overshoot) |
| low | rimap-content | bodies.rs:159 vs 132 | `body_html` bytes are never counted toward `total_bytes`, so serialized Content can exceed the transport cap | Small text + large-body_html primary part; assert serialized total (incl. body_html) > MAX_TOTAL_BODY_BYTES while body_truncated is false |
| medium | rimap-authz | guard.rs:40-45 | `breaker.pre_call` transitions Open→HalfOpen before `governor.check`; a rate-limit rejection wastes the probe slot and can wedge the breaker | Trip Open, advance past cooldown, drain the global bucket, assert pre_dispatch returns RateLimited AND breaker is wedged HalfOpen with retry_after_ms=0 |
| low | rimap-authz | rate_limit.rs:100-108 | A rejected create_draft/send_email still debits a global token (consumed before the specific bucket rejects) | Control vs experiment run with small global burst; assert rejected drafts reduce admitted Search calls |
| medium | rimap-smtp | client.rs:160-168 | Timeouts misclassify as Transport→ErrorCode::Internal; `SmtpError::Timeout`/`ErrorCode::Timeout` are never produced by send paths | Refactor classifier to take (is_response, is_client, is_timeout); assert is_timeout=true → Timeout/ErrorCode::Timeout |
| medium | rimap-smtp | client.rs:148-157 | Auth and TLS failures collapse into Connection/Transport; `SmtpError::Auth`/`Tls` are never produced | Extend `SmtpErrorShape` to consult `is_tls()`/auth predicate; assert TLS/auth lettre errors map to Tls/Auth and ErrorCode::Tls/Auth |
| low | rimap-smtp | client.rs:170-181 | `shape_to_variant_name` is a `#[cfg(test)]` duplicate of `classify_smtp_error` that can silently drift | Extract a single shared `shape→variant` function used by both production and tests |
| low | server-mcp | audit_envelope.rs:272-278 | Cancellation tool_end is silently dropped when the cancellation channel is full (documented tradeoff; breaks tool_start/tool_end pairing at >1024 backlog) | Saturate the channel without a drainer, drive 1025 guard drops, assert orphaned tool_start |
| low | server-boot | migrate_keyring.rs:36-42 | migrate-keyring is non-atomic: a failure after writing the new key leaves the secret in BOTH keys with no rollback | Add a fail-on-second-set MockStore knob; assert Err leaves both keys populated |

### HIGH-severity bugs

**FolderGuard mUTF-7 normalization (folder_guard.rs:17-45).** Every folder_guard test
uses plain ASCII, so the Modified-UTF-7 decode branch and the documented "fall back to
ASCII-lowercased input on decode failure" behavior are unexercised. If a protected folder
is stored in its raw wire form and the runtime passes the decoded form (or vice versa),
the equality at line 45 must still match after normalization on both sides. A
non-idempotent decode, a one-sided encoding, or a dropped fallback would let a protected
folder be deleted/renamed/expunged — a fail-open on the core authz boundary. This is the
top fix because it is a security gate with zero coverage of its non-trivial path.

**Breaker `dispatch_account_scoped` wiring (server.rs:125-139).** The decision of whether
a service failure trips the circuit and whether an agent is denied is exercised only
behind Docker e2e. No host-runnable test asserts that a Timeout/Auth error calls
`on_failure` while an InvalidInput does not, nor that a successful call calls
`on_success`. A regression that swapped the Ok/Err arms or dropped `on_failure` would pass
all non-Docker CI. `rimap_error_to_breaker_reason` is host-runnable, so a mapping table
plus a `DispatchGuard<ManualClock>` driver fully closes this without a live server.

**Envelope-level fail-closed audit (audit_envelope.rs:124-159).** `audit_fail_open.rs`
only drives `AuditWriter::log_tool_start` directly; it never drives
`run_with_audit_envelope`. The fail-closed contract (the tool call MUST fail when audit is
broken) and the no-orphan property (the guard is constructed AFTER `emit_tool_start`, so a
failed start must not leave a dangling tool_start) are untested. `force_next_write_failure`
makes this host-runnable today.

## 3. Coverage gaps by area

### rimap-core
- Serde wire-format paths untested for the on-disk audit types: `AuthEvent` (skip/default/None handling), `AuthResult` snake_case, `Posture` kebab-case round-trip and its agreement with `as_str()`/`from_str()`, `ErrorCode` full deserialize/unknown-code rejection.
- `AccountId` deserialize bypasses validation/normalization (confirmed bug).
- `ImapEncryption` serde (lowercase) and `Default=Tls` completely untested — a casing or default flip would silently alter encryption negotiation.
- `CredentialResolverError` source-chain / `reason`/`into_reason` sanitization contract untested.
- `TlsFingerprint::from_hex` defensive fallbacks (hex/length map_err) and empty-string input are dead-untested; `BoundedUids::TryFrom` 100/101 boundary tested only via serde, not the direct API.
- `FolderName` C1 control range never rejected despite the doc (confirmed bug).

### rimap-config
- `classify_format` for a non-array `accounts` key routes to the legacy parse path (but the refuted claim shows it surfaces a clear "unknown field accounts" error, not a misleading missing-`[imap]` error).
- Credential migration-hint and keyring-failure `tracing::warn!` branches are never asserted; the skip-legacy-on-new-key-transport-error policy is untested.
- `split_account_for_error` namespaced/multi-`@` key handling (confirmed bug); `KeyringStore::get/set_password` NoEntry-vs-error discrimination untested.
- `KeyringCredentialResolver::resolve` adapter error mapping (username redaction preservation) untested.
- `validate_paths_multi` non-export writable-dir branch, audit-containment fail-closed branches (base missing / `default_audit_base()` None), and UTF-7-encoded protected-folder collision untested.
- `run_login` store-write failure path uncovered.

### rimap-imap
- The plain-EXPUNGE data-loss fallback in move/delete (has_uidplus=false) is unreachable against Dovecot and has no unit/mock test; `delete.rs` has no `#[cfg(test)]` at all.
- FETCH silent UID drop and the preflight UID-omission fail-open (confirmed/related bugs), plus the untested preflight→project_size defense-in-depth chain.
- `with_session` does NOT invalidate on `Protocol` mid-stream — a half-consumed session is reused with no test proving safety.
- Post-login CAPABILITY probe failure silently downgrades to the non-atomic fallback (the broader data-loss framing was refuted, but the transient-probe-error fail-open remains untested at the unit level).
- `probe_preflight` greeting/capability path and `is_dead_tcp_kind` wildcard arm are reachable only against a live server (the wildcard claim itself was refuted — `#[non_exhaustive]` forces the arm).

### rimap-content
- `alternate_parts` is never populated by any test or snapshot (all 26 snaps empty); the secondary-HTML drop, post-hoc aggregate cap, and body_html exclusion are confirmed bugs.
- `convert_datetime` invalid/out-of-range Date, `audit_domain_bidi_prestrip` idna-failure fallback, `sniff` Rar/opendocument branches, and `raw_parts` depth-cap/index-out-of-bounds arms are dead-untested defensive paths.
- `extract_message_id` raw passthrough vs `sanitize_msg_id` divergence (claim refuted as already-covered indirectly, but the divergence is worth a direct pin).

### rimap-audit
- fail_open rotation-then-write-fails seq gap (the "permanent gap" framing was refuted against the monotonic-only contract, but the suppression-at-rotation path and post-write fsync failure are still untested).
- Mutex-poisoned degradation, drainer Ok(Err)/join-panic survival, `try_send` Full/Closed boundaries.
- `unique_rotated_path` exhaustion-overwrite, mixed-mtime `retention_seconds` pruning, reader mid-stream I/O error / non-UTF-8 line, self_check interior-corruption tolerance vs reader fail-fast, Some(0)-inode sentinel.

### rimap-authz
- Breaker probe waste under same-pre_dispatch rate-limit (confirmed bug); global-token leak on rejected draft/send (confirmed bug).
- Mixed auth/non-auth cooldown ceiling, post-recovery doubling sequence, `on_success`-in-Open, Closed-state mixed-reason accumulation (several refuted as design-consistent or dead state, but cooldown-class interactions remain thinly tested).
- FolderGuard mUTF-7 (confirmed bug); `matrix.check` on an infrastructure tool and `rate_limit` burst saturation boundary untested.

### rimap-smtp
- Real `classify_smtp_error`, the Tls/Starttls construction branches, `format_response` shape, zero-timeout behavior, and four of six `From<SmtpError>` arms are untested (confirmed bugs around taxonomy collapse).

### server-mcp
- `dispatch_account_scoped` breaker wiring and envelope fail-closed (confirmed high bugs); `read_resource` no-reflection invariant, namespaced-infrastructure-tool rejection, TOOL_DEFS-before-refine ordering, `run_on_blocking_pool` closed-semaphore/panic arms, and `extract_json_from_call_tool_result` fallbacks untested outside Docker.

### server-tools
- `search` pagination arithmetic (the truncated-on-out-of-range claim was refuted as mathematically wrong), `list_folders` status-projection (Noselect→None), `send_email` copy-to-Sent fail-open wiring, `fetch_message` truncation, `download_attachment` MIME cross-validation skip, and `part_walker` Message arm (confirmed bug) are handler-orchestration paths covered only by skipped e2e.

### server-boot
- The entire `run()` two-phase `tokio::select!` lifecycle, `handle_init_failure` dispatch, `emit_process_end` reason mapping, `build_registry` protected-folder merge/special-use expansion, download-dir lockdown of pre-existing loose-perm dirs, `compute_config_hash` fail-open, multi-account `process_start` summary, and `logging::init` env-precedence chain are untested (several lifecycle sub-claims refuted as unreachable, but the happy/error reason mapping and registry merge remain uncovered).

## 4. Complex functional test sequences to add

### Theme: ingest pipeline (rimap-content)

**Two-HTML-part multipart/mixed: secondary HTML dropped, anchors escape audit**
- Steps: build multipart/mixed with text/plain primary, a second text/plain, a clean text/html, and a second text/html carrying `<a href="https://p\u{0430}ypal.com/login">`; call `parse_message`; assert `alternate_parts` is non-empty (first time exercised); assert body_html is the first HTML only; assert NO LookalikeMixedScript warning for the homograph host; add a single-HTML-part positive control that DOES fire the warning.
- Components: parse/bodies.rs, parse/pipeline.rs, html/sanitize.rs, lookalike.rs.
- Oracle: alternate_parts populated; the homograph host appears in neither body_html nor a warning (pins the silent drop and the audit blind spot in both directions).
- Harness: inline `#[cfg(test)]` in bodies.rs or tests/ using public `parse_message`.

**Adversarial smuggling + zero-width subject + bidi From domain: warning aggregation**
- Steps: one raw message that triggers CRLF-smuggled Bcc, a U+200B subject, and an RLO bidi-override From domain; assert Bcc was scrubbed before parse (no bcc recipient + ParseHeaderSmugglingBlocked), the zero-width was stripped (UnicodeZeroWidthStripped), a LookalikeHomographDomain at header:from with `reason=bidi_pre_strip`, and that all three coexist with the smuggling warning preceding the lookalike warning.
- Components: mime_scrub.rs, safe_parser.rs, headers.rs, meta.rs, unicode.rs, lookalike.rs.
- Oracle: all three codes present, ordering preserved, Bcc absent, subject free of U+200B.
- Harness: inline test in pipeline.rs.

**mailto: anchor feeds homograph host into lookalike (scheme-rejection divergence)**
- Steps: HTML-only body with one `mailto:user@p\u{0430}ypal.com` anchor; assert lookalike audits it (extract_domain_from_url has no mailto rejection); contrast against `extract_registrable_domain("mailto:...")==None` in the mismatch pass; pin the divergence.
- Components: lookalike.rs, html/mismatch.rs, html/sanitize.rs, parse/pipeline.rs.
- Oracle: LookalikeMixedScript at html:anchor_href present for the mailto case; mismatch still returns None.
- Harness: inline test in lookalike.rs + one parse-level assertion.

**Aggregate cap straddle + body_html exclusion**
- Steps: three near-1MiB text parts (total ~3MiB) then a large-body_html/small-text HTML primary; compute serialized = body_text + alternates + body_html; assert text+alternates ≤ cap but serialized > cap with body_truncated false.
- Components: parse/bodies.rs, html/sanitize.rs, parse/pipeline.rs.
- Oracle: serialized total exceeds MAX_TOTAL_BODY_BYTES while no truncation fired.
- Harness: inline test in bodies.rs/pipeline.rs.

**FETCH UID-less/zero-UID drop + preflight bypass + defense-in-depth + dispatch classification**
- Steps: (A) feed UID=None and UID=Some(0) through the fetch loop guards, assert both excluded with no error; (B) drive preflight_fetch_size with a UID-omitting response so size stays None, feed None to preflight_size_check (Ok), then project_size over-limit returns SizeLimit; cross-reference dispatch classifying SizeLimit as should_invalidate=true.
- Components: ops/fetch.rs, connection/dispatch.rs, types Uid.
- Oracle: dropped messages excluded; preflight passes but project_size errors; dispatch invalidates only on SizeLimit.
- Harness: inline tests in fetch.rs (helpers exist; a thin UID-guard helper may be needed since no mock session exists).

**Outbound Message-ID round-trip divergence**
- Steps: hostile Message-ID (angle brackets + control char); compare `extract_message_id` vs `extract_threading_headers().message_id`; assert they differ and the former retains `<`/`>`/control char; show the would-be outbound header is malformed; verify the threading path round-trips cleanly.
- Components: lib.rs, threading.rs, unicode.rs.
- Oracle: extract_message_id output != sanitized form and contains the hostile chars.
- Harness: inline test in lib.rs.

### Theme: authz posture gating (rimap-authz)

**Wasted half-open probe under same-pre_dispatch rate-limit**
- Steps: build `DispatchGuard<ManualClock>` at DraftSafe with error_threshold=2 and a tiny `Governor::new(1,5,3)`; trip Open; advance past cooldown; drain the global bucket; call pre_dispatch once so breaker flips Open→HalfOpen then governor rejects; assert RateLimited; assert breaker is HalfOpen with no callback; assert the next call returns CircuitOpen{retry_after_ms:0}; assert recovery only after an explicit on_success/on_failure.
- Components: guard.rs, breaker.rs, rate_limit.rs, rimap-core tool/posture.
- Oracle: RateLimited returned, breaker wedged HalfOpen, retry_after_ms=0; reorder/rollback fix flips it.
- Harness: inline test in guard.rs.

**Mixed auth/non-auth cooldown ceiling**
- Steps: breaker with distinct auth vs non-auth bounds; auth-first trip then a non-auth half-open failure (and the reverse); read cooldown via the CircuitOpen retry hint; assert the cap selected matches the current reason's ceiling and pin the carried-over current_cooldown behavior.
- Components: breaker.rs.
- Oracle: retry_after_ms equals (carried current_cooldown × 2) capped by the current reason's cap.
- Harness: inline test in breaker.rs (ManualClock).

**Stray on_success while Open**
- Steps: trip Open; without advancing the clock or calling pre_call, call on_success directly; assert state→Closed and pre_call→Ok (early cooldown clear); repeat for a non-auth trip.
- Components: breaker.rs.
- Oracle: pins current fail-open behavior so a future guard is a deliberate change.
- Harness: inline test in breaker.rs.

**Rejected create_draft erodes the global bucket**
- Steps: `Governor::new(2,1,3)`; control run counts Search admits; experiment run drains the draft bucket (including rejected attempts that still debit global) then counts remaining Search admits.
- Components: rate_limit.rs, rimap-core is_draft_quota_gated.
- Oracle: experiment Search admits < control by the count of rejected drafts.
- Harness: inline test in rate_limit.rs.

**FolderGuard mUTF-7 bypass attempts + malformed fallback**
- Steps: encode a non-ASCII protected name; build guards from the raw and decoded forms; assert all four (config-form × request-form) combinations reject; test a malformed (dangling `&`) name's fallback; cross-check byte-identity with rimap-config's normalization.
- Components: folder_guard.rs, folder_name.rs, utf7_imap, rimap-config validate/rules.rs.
- Oracle: all combinations return ProtectedFolder; malformed name still blocked.
- Harness: inline test in folder_guard.rs.

**Service vs user error breaker feeding + exhaustive reason mapping**
- Steps: assert `rimap_error_to_breaker_reason` over every ErrorCode (Some for ConnectionLost/Auth/Timeout/ImapProtocol/SmtpProtocol/Tls, None for the rest); then via a `DispatchGuard<ManualClock>` driver feed 3× Timeout (Open), N× InvalidInput (still Closed), 2× Timeout + Ok (reset), 1× Auth (immediate Open).
- Components: mcp/dispatch.rs, mcp/server.rs reason-feeding, rimap-authz breaker, rimap-core error.
- Oracle: per-code Some/None plus the four breaker-state outcomes; swapped Ok/Err arm or misclassified service error flips one.
- Harness: mapping table inline in dispatch.rs; breaker sequence in guard.rs via `DispatchGuard<ManualClock>`.

### Theme: audit lifecycle (rimap-audit)

**Seq gap survives crash-resume across rotation under fail_open**
- Steps: open with rotate_bytes just above one line, fail_open=true; write seq=1; force the threshold-crossing write to fail (read-only parent); assert suppressed_failures==1 and Ok; next write reports seq=3; drop and run read_trailing_state across siblings asserting no seq==2 anywhere.
- Components: rimap-audit.
- Oracle: gap at seq 2, suppression counted, resume reflects highest durable seq.
- Harness: tests/ (Unix-gated; extends fail_open.rs + rotation.rs).

**Reader vs self-check tolerance divergence on interior corruption after rotation**
- Steps: write+rotate to produce a sibling; corrupt the active file into good/garbage/good lines; assert read_trailing_state skips the garbage (last_seq=N+2) while stream_records returns Err(Read) at "line 2".
- Components: rimap-audit.
- Oracle: self-check tolerant, reader fail-fast on the same file.
- Harness: tests/ (combines self_check + reader paths).

**Rotation-changed inode not wrongly flagged as tamper**
- Steps: process_start with inode_A; rotate (active gets inode_B); resume and log_process_start with current_inode=inode_B; assert audit_file_inode_changed=true; contrast a no-rotation control asserting false.
- Components: rimap-audit.
- Oracle: legitimate rotation inode change vs missed real tamper, both pinned.
- Harness: tests/ (Unix-gated; extends inode_change.rs with a real rotation).

**Cancellation drainer survives a failing record**
- Steps: fail_open=false writer; spawn drainer; enqueue valid #1, force the next write to fail then enqueue #2, enqueue valid #3; drop tx, await drainer Ok; assert #1 and #3 on disk, #2 absent.
- Components: rimap-audit.
- Oracle: drainer does not die on the Ok(Err) arm; subsequent records still written.
- Harness: inline `#[tokio::test]` (multi_thread) in cancellation.rs.

**Fail-closed tool_start audit abort with no orphan; fail-open proceeds**
- Steps: ImapMcpServer::new_for_tests with fail_open=false; force the tool_start write to fail; call run_with_audit_envelope; assert Err with "audit write failed" and ZERO records on disk; repeat fail_open=true asserting Ok + suppressed_failures>=1.
- Components: rimap-server, rimap-audit.
- Oracle: no orphan tool_start on fail-closed; body proceeds on fail-open.
- Harness: inline `#[tokio::test]` in audit_envelope.rs.

**Interleaved tool_start/tool_end across rotation preserve contiguous seq**
- Steps: small rotate_bytes, fail_open=false; interleave log_tool_start/log_tool_end/log_auth from two writer clones across several rotations; drop; collect seq across all siblings; assert the set equals 1..=N with no gaps/dupes and tool_start count == tool_end count.
- Components: rimap-audit.
- Oracle: contiguous seq + paired envelopes survive rotation with interleaved writers.
- Harness: tests/ (extends rotation.rs with clones).

### Theme: MCP wire protocol (server-mcp)

**Split frame reassembly + unterminated final frame at EOF**
- Steps: spawn the binary (zero-account); handshake; write one tools/list line in three mid-token chunks; assert reassembled result; send a second request with no trailing newline then close stdin; assert clean close or a valid trailing response, never hang/crash.
- Components: wire_validator::inbound, mcp::server, main::run, rmcp.
- Oracle: reassembled frame returns a valid result; EOF outcome is clean.
- Harness: tests/ mcp_wire_negative.rs.

**Mixed batch: parse-error + invalid-request-with-id + valid request under stdout-mutex contention**
- Steps: handshake; send `not json`, `{method:42,id:7}`, valid tools/list id 8 in a burst; drain until id 8; assert three standalone schema-valid envelopes; parse-error has no id, invalid-request echoes id 7, valid returns a result.
- Components: wire_validator inbound/envelope/outbound, rmcp.
- Oracle: exactly 3 well-framed envelopes; no torn/concatenated lines.
- Harness: tests/ mcp_wire_negative.rs.

**Oversized/fractional request ids round-tripped through the synthesized error envelope**
- Steps: send a rejected request with id `9223372036854775808`, then `2.5`, then a string id; assert numeric out-of-range/fractional ids are suppressed to absent while the string id is echoed; every envelope passes the MCP schema; a trailing tools/list confirms responsiveness.
- Components: envelope is_forwardable_id/extract_id/synthesize_error_line, rmcp, MCP schema validator.
- Oracle: synthesized lines schema-valid; no oversized/fractional id echoed.
- Harness: tests/ mcp_wire_negative.rs.

**Cancellation tool_end dropped when channel saturated**
- Steps: saturate the cancellation channel (no drainer); new_for_tests server with fail_open=false; spawn a pending-body tool via run_envelope_with_body_for_test, sleep, abort; assert exactly one record (tool_start) and no cancelled tool_end; control run with a drained channel + drainer asserts the tool_end lands.
- Components: audit_envelope guard drop, rimap-audit try_send Full path.
- Oracle: saturated run orphans the tool_start; control run pairs it.
- Harness: inline / tests (extends dispatch_ticket.rs).

**notifications/cancelled for in-flight, unknown, and completed ids (host-runnable)**
- Steps: handshake; tools/call nonexistent_tool (fast RESOURCE_NOT_FOUND) then cancel its id; assert exactly one envelope; cancel a never-issued id and assert no response within 200ms; a final tools/list confirms responsiveness.
- Components: mcp::server call_tool + notifications/cancelled, wire_validator passthrough, rmcp.
- Oracle: one envelope per issued id; unknown-id cancel is a no-op; server stays responsive.
- Harness: tests/ mcp_wire_negative.rs (host-runnable variant of the Docker-gated suite).

**Duplicate top-level id key caught before parse**
- Steps: send the #266 duplicate-top-level-key line; assert -32600 with no id; send a params-only dup (forwards, valid result); send an error-body dup (rejected -32600); confirm responsiveness.
- Components: envelope has_duplicate_keys_in_rmcp_strict_positions, dup-check visitors, inbound, rmcp, serde_json.
- Oracle: strict-position dups rejected, lenient params dup forwards.
- Harness: tests/ mcp_wire_negative.rs.

### Theme: connection lifecycle (rimap-imap)

> **Revised.** Most of this theme is already covered against real Dovecot on this host and
> does **not** need the proposed TLS mock: pin mismatch + typed `Tls` error + AuthEvent
> (`case_02`, `case_22`, `starttls_with_wrong_pin`), login rejection (`case_04`), and
> connection drop/recovery (`case_10`, `case_11`). What remains genuinely open: the
> **non-UIDPLUS plain-`EXPUNGE` fallback** (unreachable against Dovecot — needs a mock) and
> any **auth-provenance variant not yet in `dovecot.rs`** (`LOGINDISABLED`,
> resolver-error → `CredentialUnavailable`), which should be added to the existing harness.

**TLS pin mismatch → typed Tls error + exactly one AuthEvent; matching pin → Success once**
*(already covered by `case_02`/`case_22`/`starttls_with_wrong_pin` — listed for completeness, not as new work)*
- Steps: stand up an in-process rustls/rcgen TLS server; compute the leaf fingerprint; mismatch run asserts ImapError::Tls{observed,expected} and exactly one AuthEvent (Failure, error_code=Tls, fingerprint_match=false, credential_source=None); matching run asserts success and exactly one AuthEvent (Success, fingerprint_match=true, source=EnvVar).
- Components: connection/mod.rs connect_inner + enrich_tls_handshake_error, handshake.rs, login.rs, auth.rs, rimap-core types.
- Oracle: typed Tls error with correct fingerprints; single AuthEvent per termination.
- Harness: tests/ TLS mock (host-runnable, not Docker).

**Auth-failure provenance: missing credential vs LOGIN rejection vs LOGINDISABLED**
- Steps: over the TLS mock, drive (A) resolver Err → CredentialUnavailable, source=None; (B) LOGIN NO → LoginRejected, source=Some(Keyring); (C) LOGINDISABLED → CapabilityMissing, source=None and resolver never called.
- Components: login.rs imap_login/drain_for_logindisabled, connect_inner, rimap-core credential types.
- Oracle: each AuthFailure variant + error_code=Auth; source threading and resolver-not-called ordering.
- Harness: tests/ same TLS mock.

**Protocol mid-stream reuses session; ConnectionLost reconnects; fetch_body SizeLimit invalidates**
- Steps: cache a session; (A) Protocol error then a second op on the same Connection asserting reuse (one TCP accept); (B) ConnectionLost then a reconnect (second accept + second AuthEvent); (C) fetch_body_with_limit SizeLimit then reconnect.
- Components: connection/dispatch.rs with_session/fetch_body_with_limit, connection/mod.rs, ops/fetch.rs.
- Oracle: accept-count / session-state assertions per error class.
- Harness: tests/ TLS mock with multi-connection accept loop.

**Per-account FallbackMode + env-var: no cross-account credential bleed**
- Steps: multi-account TOML (A keyring-only, B keyring-then-env) over a shared MockStore + temp_env; assert A never consults env (NoCredential), B resolves to its own Keyring key; remove B's key and assert B→EnvVar while A still fails.
- Components: validate/compose.rs, credential.rs resolve/adapter, test_support MockStore, rimap-core.
- Oracle: A never returns the env secret; B's source flips correctly.
- Harness: tests/ in rimap-config (host-runnable).

**Adapter preserves ConfigError on source chain while keeping reason username-free**
- Steps: KeyringCredentialResolver over MockStore::failing in KeyringOnly; assert reason omits the username, source() downcasts to ConfigError::Keychain, into_reason()==reason(); thread into a Connection and assert ImapError::Auth{CredentialUnavailable} still omits the username; KeyringThenEnv leg succeeds with EnvVar.
- Components: credential.rs resolver/split/KeyringStore, rimap-core CredentialResolverError, login.rs map_err.
- Oracle: username never in reason() through the full chain; source preserved.
- Harness: tests/ spanning rimap-config + rimap-core + the TLS mock.

**probe_preflight greeting-budget starvation**
- Steps: TLS mock delays the greeting after handshake; size connect_timeout so TLS + delay approach it; assert the deterministic outcome (Timeout{op:"imap_greeting"} vs Ok) and pin it; contrast a generous-timeout run asserting Ok with capabilities and fingerprint populated.
- Components: preflight.rs greeting_budget, handshake.rs tls_handshake, tls.rs capture-only config.
- Oracle: starvation outcome pinned; contrast run returns PreflightInfo with the mock fingerprint.
- Harness: tests/ TLS mock with a pre-greeting delay knob.

## 5. Refuted / already-covered claims

Reviewers do not need to re-investigate these:

- **posture_matrix base_allows fallthrough** — already covered cross-crate in rimap-authz matrix.rs.
- **AuthEvent error_code Some-on-Failure/None-on-Success invariant** — already asserted in rimap-imap auth.rs producers.
- **rimap-config port-vs-encryption consistency validation** — refuted; no such validation is advertised (model docstrings are descriptive hints).
- **Non-array `accounts` misclassified with a misleading error** — refuted; `deny_unknown_fields` yields a clear "unknown field `accounts`" error.
- **KeyringThenEnv cross-account env bleed** — already covered/documented; KeyringOnly is the documented multi-account mitigation with tests.
- **SMTP plaintext localhost allowlist missing spellings** — refuted; the deny outcome for non-listed spellings is the safe intended path.
- **Post-login CAPABILITY failure enabling plain-EXPUNGE fallback** — refuted as framed (a dead stream fails the COPY step first).
- **move_messages empty-input skipping the UIDVALIDITY guard** — refuted; the path is unreachable (BoundedUids rejects empty) and an empty move is a no-op.
- **probe_preflight zero greeting budget** — refuted; design intent, only reachable with a near-exhausted connect budget.
- **is_dead_tcp_kind wildcard arm** — refuted; `#[non_exhaustive]` requires the arm and the cited future kinds are not stable; current kinds are tested.
- **extract_message_id leaks brackets** — already covered indirectly (parse strips them; value only echoed to response meta) — but a direct pin is still recommended.
- **collect_anchor_hrefs mailto survives into lookalike** — already covered (pure-ASCII anchors emit no warning).
- **fail_open suppression leaves a permanent seq gap** — refuted against the monotonic-only (not contiguous) contract.
- **previous_file_inode stores current inode** — already covered; field is documented and round-trip tested.
- **Reader positional trailing tolerance** — refuted; the actual crash-recovery path (read_trailing_state) is newline-aware.
- **Rotation threshold >= against pre-open bytes** — refuted; intentional and tested (content preserved, seq resumes).
- **Mixed auth/non-auth wrong cooldown ceiling** — refuted; last_trip_was_auth is dead state and the single-accumulator doubling is the documented design.
- **on_success-in-Open clears cooldown** — refuted as a defect (production caller only calls on_success after a genuine Ok dispatch); still worth a behavior-pin test.
- **FolderGuard mUTF-7 fail-open** — the decode non-idempotency variant was refuted; the untested-ASCII-only variant remains a confirmed high bug.
- **SMTP send() clones the whole Message** — refuted; forced by lettre's API and not on the production path (send_raw is used).
- **tools/list_changed notify gate** — refuted; advertised tool list does not vary with the session default.
- **Forward path retains trailing \r** — already covered; rmcp's codec strips \r identically.
- **search out-of-range offset reports truncated=true** — refuted; the predicate is mathematically false for offset >= total_matched.
- **send_email sent:true without rollback** — already covered; documented fail-open with mapping tests.
- **fetch_message tiny-max grapheme truncation** — already covered in unicode.rs truncation tests.
- **main.rs lifecycle sub-claims (both-bridges-exit, Bridge clean-exit distinction, configured download_dir loose perms)** — refuted as unreachable or guarded elsewhere (export download-root privacy checks, EOF→Rmcp routing).
- **registry resolve stale-active fallthrough** — refuted; set_active validates membership and no removal API exists.

## 6. Recommended priority order

Revised after confirming the Dovecot/e2e suites run on this host. The TLS-mock harness
(previously #2) is **dropped** — it duplicates `case_02`/`case_22`/`starttls_with_wrong_pin`.
The surviving high items are fault-injection and pure-unit gaps the runnable suites do not
exercise.

1. **FolderGuard mUTF-7 normalization** (authz fail-open, high) — pure unit, Docker-independent. Close the protected-folder bypass with encoded/decoded/malformed cases.
2. **Envelope fail-closed audit + no-orphan tool_start** (server-mcp, high) — `e2e` runs with `fail_open: false` but never induces a write failure; assert via `force_next_write_failure` at the `run_with_audit_envelope` level.
3. **Breaker service-vs-user tripping via DispatchGuard<ManualClock>** (server-mcp, high) — `e2e` wires a `SystemClock` breaker but never trips it; a `ManualClock` unit test + reason-mapping table is the right tool, not e2e.
4. **Non-UIDPLUS plain-`EXPUNGE` data-loss fallback** (rimap-imap, high) — unreachable against Dovecot (always UIDPLUS); needs a mock IMAP server. Data-loss severity.
5. **SMTP error taxonomy** (timeout/auth/tls misclassification + shared shape→variant function) (rimap-smtp, medium) — fixes three confirmed bugs and removes the drift-prone test mirror.
6. **Breaker wasted-probe wedge + global-token leak** (rimap-authz, medium) — deterministic with ManualClock and a small Governor.
7. **rimap-content secondary-HTML drop + cap/body_html accounting** (medium/low) — first tests to populate alternate_parts.
8. **AccountId validating Deserialize + FolderName C1 rejection** (rimap-core, low) — small, high-clarity invariant pins.
9. **Audit lifecycle sequences** (drainer survival, interleaved-rotation seq, channel-full cancellation drop) (medium/low).
10. **part_walker Message arm, split_account_for_error, fetch UID-drop, migrate-keyring atomicity** (low) — targeted regression nets.
11. **Extend `dovecot.rs` with missing auth-provenance variants** (e.g. `LOGINDISABLED` → `CapabilityMissing`, resolver-error → `CredentialUnavailable`) — the harness already exists; no mock needed.
