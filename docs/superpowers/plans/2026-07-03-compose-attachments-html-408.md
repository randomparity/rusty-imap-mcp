# Plan: attachments + HTML body for compose (#408)

Spec: `docs/superpowers/specs/2026-07-03-issue-408-compose-forward-attachments-design.md`
(see "Scope update (2026-07-03)"). `forward` already shipped in PR #430; this
plan covers the two remaining items. TDD throughout: failing test → minimal
impl → green → commit.

## Task 1 — `read_sandboxed_file` primitive (rimap-server sandbox.rs)

Add a read counterpart to `write_attachment`, mirroring its containment.

- `read_sandboxed_file(root: &Path, rel_or_abs_path: &str, max_bytes: usize) -> Result<Vec<u8>, RimapError>`
  (Unix): canonicalize the requested path, verify `starts_with(root)`, open the
  **parent** dir once via ambient authority as a held `cap_std::fs::Dir`, then
  open the final component fd-relative **without following a symlink**
  (`OpenOptions` + `nofollow`/`O_NOFOLLOW`-equivalent via cap-std, which refuses
  symlink escape), stat the size and reject `> max_bytes` **before** reading,
  then read. Non-Unix: fail closed (`RimapError::Internal`), like
  `write_attachment`.
- Async wrapper `read_sandboxed_file_async(root, path, max_bytes)` via
  `spawn_blocking`, matching `resolve_dest_dir_async`.
- Tests (mirror the write-path tests):
  - reads a file inside the root; bytes exact.
  - path outside root → `InvalidInput`, no read.
  - symlink inside root → target outside → not followed → rejected.
  - dir-swap between resolve and read lands on the held fd (mirror
    `write_lands_via_held_fd_after_dir_swap`).
  - oversized file → `InvalidInput`/limit error, rejected before full read.
  - missing file → `InvalidInput`.
  - non-Unix stub returns error (cfg-gated test).

Commit: `feat(server): add read_sandboxed_file sandbox primitive (#408)`.

## Task 2 — `AttachmentInput` + caps + validation (message_builder.rs)

- `AttachmentInput { path: String, filename: Option<String>, content_type: Option<String> }`
  (`Deserialize, JsonSchema, non_exhaustive`).
- `ComposeInput` gains `attachments: Option<Vec<AttachmentInput>>` (default None).
- Caps: `MAX_ATTACHMENTS = 20`, `MAX_ATTACHMENT_BYTES = 10 * 1_048_576`,
  `MAX_TOTAL_MESSAGE_BYTES = 25 * 1_048_576`.
- `validate_attachments(&[AttachmentInput])`: count ≤ MAX_ATTACHMENTS;
  each `filename`/`content_type` injection-guarded via `validate_header_text`;
  `path` non-empty. (Size + containment enforced at read time in Task 3.)
- Extend `validate_compose_input` to call `validate_attachments`.
- Tests: count over cap rejected; filename/content_type with `\r\n\0<>` rejected;
  at-cap accepted; empty attachments accepted.

Commit: `feat(compose): add AttachmentInput fields and validation (#408)`.

## Task 3 — build attachments into the message (message_builder.rs + handlers)

- New async `build_message` reads attachments from the sandbox: for each
  `AttachmentInput`, `read_sandboxed_file_async(download_dir, path, MAX_ATTACHMENT_BYTES)`,
  accumulate total bytes (reject when running total + body_text exceeds
  `MAX_TOTAL_MESSAGE_BYTES`), reduce `filename` to basename (default = file
  basename), resolve `content_type` (declared → else `sniff_mime` → else
  `application/octet-stream`), add via `MessageBuilder::attachment(ct, name, bytes)`.
- Thread `download_dir: &Path` into `build_message`; update
  `create_draft::handle` and `send_email::handle` to pass `account.download_dir`.
- Tests: attachments produce `multipart/mixed`; body_text still present;
  total-cap boundary (at-cap accepted, over-cap rejected); sniffed vs declared
  content type; basename reduction (a filename with path separators lands as
  basename only); attachment path outside sandbox → error surfaced.

Commit: `feat(compose): send/draft attachments sourced from the sandbox (#408)`.

## Task 4 — outbound HTML sanitizer public API (rimap-content)

- Add `pub fn sanitize_outbound_html(raw: &str) -> Result<OutboundHtml, ContentError>`
  to `rimap-content` (new small module or in `lib.rs`), delegating to
  `html::sanitize(raw.as_bytes(), Some("utf-8"))` and returning
  `OutboundHtml { body_html: String, warnings: Vec<SecurityWarning> }`
  (drop `body_text`/`anchor_hrefs`, which are inbound-only concerns). This is
  the FIRST production (non-test) consumer of `html::sanitize`; expose only the
  narrow outbound entry point, not the whole inbound type.
- Tests: script stripped + warning; `javascript:` URL dropped; remote `img src`
  stripped; safe tags preserved; oversize → `LimitExceeded`.

Commit: `feat(content): add sanitize_outbound_html entry point (#408)`.

## Task 5 — `body_html` field + `multipart/alternative` (message_builder.rs)

- `ComposeInput` gains `body_html: Option<String>`.
- `validate_compose_input`: when `body_html` is `Some(non-empty)`, size-cap at
  `MAX_BODY_BYTES`.
- `build_message_headers` (or a follow-on step): when `body_html` present and
  non-empty, `sanitize_outbound_html` it, `.html_body(sanitized)` alongside
  `.text_body(body_text)` → `multipart/alternative`. Return the stripped-content
  warnings so handlers can surface them.
- Tests: text+html → multipart/alternative, text/plain always present; script in
  body_html stripped from emitted message; oversize body_html rejected; empty
  body_html behaves as no HTML (plain text/plain only).

Commit: `feat(compose): optional sanitized HTML body with text/plain alt (#408)`.

## Task 6 — `create_draft.include_html` capability + posture gate (rimap-core + server)

- `ToolName::CreateDraftHtml` = `"create_draft.include_html"`; add to every
  exhaustive match in `tool.rs` (as_str, is_infrastructure=false, quota
  classification = draft-quota like CreateDraft, annotation_hints group matching
  CreateDraft), `POSTURE_MATRIX` row `(CreateDraftHtml, [false,false,true,true])`.
  Capability count 26 → 27.
- `refine_tool_name`: `CreateDraft` with non-empty `body_html` → `CreateDraftHtml`.
- `dispatch.rs`: `CreateDraft | CreateDraftHtml => create_draft::handle`.
- `dispatch_infrastructure` non-infra list, `result_provenance`, `tool_catalog`
  advertisement (CreateDraftHtml advertised only at full+), redaction schema
  (`CreateDraftHtml => create_draft_schema`).
- `send_email` needs NO sub-capability (already full).
- Tests: refine elevates on body_html; authz matrix denies CreateDraftHtml below
  full; catalog advertises it only at full+; exhaustive-match / count tests pass.

Commit: `feat(authz): gate create_draft HTML body at full posture (#408)`.

## Task 7 — attachments redaction + response warnings surfacing

- Add `attachments` handling to `create_draft_schema` + `send_email_schema` in
  `rimap-audit/redact.rs`: `path`, `filename` → `RedactString` (the array/object
  policy per the redactor's array handling). `body_html` already present in
  create_draft_schema; add to send_email_schema.
- `CreateDraftMeta` / `SendEmailMeta` gain `security_warnings: Vec<SecurityWarning>`
  (empty when no HTML or nothing stripped), populated from Task 5's warnings.
- Tests: redaction leaves no raw path/filename; meta carries warnings when HTML
  stripped, empty otherwise.

Commit: `feat(audit): redact attachment paths; surface HTML strip warnings (#408)`.

## Task 8 — schema regen, docs, conformance, tool descriptions

- `just regen-tool-schemas`; commit the fixture diff.
- Bump hardcoded capability counts: `dump_tool_schemas`, `dump_tool_catalog.rs`,
  `tests/mcp-conformance/src/wire.test.ts`.
- `docs/postures.md`: add `create_draft.include_html` row; document the
  shared-sandbox attachment trust model and the new attachment/HTML capability.
- `create_draft` / `send_email` tool descriptions: document `attachments`
  (sandbox-only, shared-root caveat, caps) and `body_html` (sanitized, full-only,
  text/plain always sent).
- `README.md`: note the new compose capabilities in the tool inventory.
- Regenerate `docs/tools.md` if it is generated (per AGENTS.md).

Commit: `docs: schemas, postures, tool descriptions for compose attachments+HTML (#408)`.

## Guardrails

Run `just ci` before pushing. Individually gated: rustfmt, clippy -D warnings,
check (macOS), test (stable), test (MSRV 1.88.0), cargo-deny, zizmor. Schema
fixtures must match (`just regen-tool-schemas` clean). Adversarial corpus stays
green (Task 4/5 touch content pipeline surface).
