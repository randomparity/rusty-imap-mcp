# Compose: `forward` tool and sandbox-sourced attachments (#408)

## Context

`ComposeInput` (`crates/rimap-server/src/tools/compose/message_builder.rs:31-53`)
supports `to/cc/bcc/subject/body_text/in_reply_to_uid/in_reply_to_folder`
only. There is no attachment field, no HTML body, and no forward tool. Two
of the most common email-agent requests are impossible today: sending a
file the server already downloaded, and forwarding an existing message
(`export_messages` writes an mbox to local disk, not a forwardable
message). FABLE_AUDIT finding F11 (Medium). Verified on `main` @ `9fd8dc24`.

The existing compose invariants must be preserved: `MAX_RECIPIENTS=100`,
`MAX_SUBJECT_LEN=1000`, `MAX_BODY_BYTES=1 MiB`, and the RFC 5322
header-injection guards (`validate_header_text` rejects `\r \n \0 < >`).

## Goal

Implement the issue's recommended scope in priority order, preserving the
no-arbitrary-payload trust model:

1. **`forward` tool** — server-side re-send of an existing message.
2. **Attachments** on `create_draft` / `send_email`, sourced **only** from
   the per-account download sandbox.

HTML body (issue item 3) and a draft-safe `forward` variant are **deferred**
(see "Deferred, with rationale").

## Security review outcome (2026-07-03) — scope change

Two security-review agents (mcp-security-reviewer, email-imap-security-reviewer)
reviewed this spec. One **critical, blocking** finding reshapes the scope:

- **Attachments are BLOCKED pending a maintainer decision.** The spec's
  premise of a *per-account* download sandbox is false: `download_dir` is a
  single process-global `Arc<Path>` cloned into every `AccountState`
  (`crates/rimap-server/src/main.rs:479`,
  `crates/rimap-server/src/boot/registry.rs:65-67`). It is today effectively
  write-only (`download_attachment` / `export_messages` write; nothing reads
  a sandbox file back into outbound mail). Adding sandbox-sourced attachments
  turns it into a **cross-account exfiltration channel**: an agent resolving
  account B could attach a file account A exported into the shared root and
  send it to an attacker — breaking account isolation. Path containment is
  correct *within* a root; the problem is that all accounts share one root.
  Resolving it requires either (a) partitioning the sandbox per account
  (`<root>/<account_id>/`), which changes where existing downloads land and
  touches `download_attachment` / `export_messages` — a compat/behavior
  change to shipped tools that needs maintainer sign-off — or (b) an explicit
  product decision to accept and gate the shared-sandbox trust model. Neither
  is answered by the issue, which assumed a per-account sandbox. Per the
  dispatch instruction ("if attachment-source sandbox model is ambiguous,
  mark blocked pending maintainer"), **attachments are deferred to a
  follow-up** and are not implemented here.

- **`forward` proceeds** — it re-sends the *resolved* account's own IMAP mail
  (same-account; no cross-account widening) — with the following mandatory
  hardening from the review:
  1. The forwarded **Subject is derived from fetched (untrusted) bytes**;
     `mail_builder` does **not** neutralize a bare CR/LF in a `Subject`
     value. Extract the original subject via a `rimap-content` helper built
     on the panic-catching, size-bounded `safe_parse` path (mirroring
     `extract_threading_headers`), RFC-2047-decode it, then run it through
     the CR/LF/NUL injection guard **before** prefixing `Fwd: ` and handing
     it to the builder.
  2. The `message/rfc822` wrapper **must be base64-encoded**. Build it with
     `MessageBuilder::attachment("message/rfc822", name, bytes)` (mail_builder
     forces base64 for non-`text/*` parts); never set a manual `7bit`/`8bit`
     transfer-encoding or a raw part — that would re-open outer-frame
     injection from attacker-crafted original bytes. "Verbatim" means
     byte-exact after base64 decode.
  3. **Do not double-fetch.** Extract threading headers from the
     already-fetched wrapper bytes (`extract_threading_headers(&raw)`), not by
     re-invoking `apply_threading_headers` (which fetches the UID again and
     could see a different message after an interleaved EXPUNGE/UIDVALIDITY
     change). The original `Message-ID` is echoed into In-Reply-To/References
     only through `extract_threading_headers` → `sanitize_msg_id` (strips
     `\r \n \0 < >`).
  4. **`Bcc` must not appear in the sent DATA.** Build the forward message
     without a `Bcc` header (Bcc addresses go only into the SMTP envelope
     RCPT TO); otherwise the Bcc header is disclosed to every recipient.
     (This is a pre-existing bug in `send_email`, reported separately; the
     `forward` implementation must not reproduce it.)
  5. Forward audit uses a **dedicated `forward_schema`** recording the source
     `folder` + `uid` **verbatim** (not aliased to `send_email_schema`), so
     an incident responder can identify which stored message was re-sent.
  6. Cap the forwarded original: reject before send when the fetched original
     + comment would exceed the total-message cap; note base64 inflates the
     wrapper ~33%.

## Trust model

The server already trusts two byte sources: messages it fetches from the
account's own IMAP server, and files under the per-account download
sandbox root (`AccountState.download_dir`, the same root
`download_attachment` / `export_messages` write to). Both features stay
inside that boundary and do not widen it:

- **`forward`** re-sends bytes the server fetched from IMAP (`fetch_body`).
  No caller-supplied payload, so the "no arbitrary outbound payload"
  posture holds.
- **Attachments** are read **only** from the download sandbox, validated
  with the same containment logic as `download_attachment.dest_dir`
  (canonicalize + `starts_with(root)`, then open through a held directory
  fd so the resolve→read window cannot be swapped, and refuse to follow a
  symlink at the final component). An agent can therefore only attach a
  file the server itself downloaded or the operator deliberately placed in
  the sandbox — never `/etc/passwd`, never an arbitrary path.

Caller-supplied text (the forward `comment`, attachment `filename` and
`content_type`) is header/parameter data and runs through the existing
`validate_header_text` injection guard.

## Posture gating

| tool | readonly | draft_safe | full | destructive |
|------|----------|-----------|------|-------------|
| `forward` | deny | deny | allow | allow |

`forward` sends via SMTP, so it is gated identically to `send_email`
(`POSTURE_MATRIX` row `[false, false, true, true]`) and is `destructive`
+ non-`read_only` + `open_world` + `is_send_quota_gated` in
`ToolName::annotation_hints` / quota classification.

Attachments add **no new tool** — they are optional fields on the existing
`create_draft` (draft_safe+) and `send_email` (full+) inputs, so they
inherit each tool's existing posture gate. Reading a sandbox file is not a
new capability surface (`download_attachment` already reads/writes the same
root under the same postures).

## MIME construction

### `forward`

Strategy: **`message/rfc822` wrapper** (RFC 2822 §forwarding), not inline
re-attachment of parts. Rationale: the original bytes are attached
verbatim, so the recipient's client renders the complete original
(headers, structure, its own attachments) without the server
re-serializing untrusted MIME — smaller attack surface than parsing and
rebuilding the tree, and it preserves the original message faithfully.

Construction (`mail_builder::MessageBuilder`):
- `From` = account username; `To/Cc/Bcc` = forward recipients.
- `Subject` = `Fwd: <original subject>` (original subject fetched from the
  message; sanitized through the subject guard; capped at `MAX_SUBJECT_LEN`).
- Fresh `Message-ID` (own domain), as for any new outbound message.
- Optional `comment` becomes the `text/plain` body (injection-guarded,
  capped at `MAX_BODY_BYTES`). Absent comment → a minimal body.
- The original raw message (from `fetch_body(folder, uid, None)`) is
  attached as a single `message/rfc822` part.
- **Threading headers preserved**: the original's `Message-ID` is set as
  `In-Reply-To` and appended to `References` (reusing
  `apply_threading_headers` / `cap_references`), so the forward threads
  with the source and the original's identity is preserved both in the
  wrapper part (verbatim) and the outer headers.

Delivery mirrors `send_email`: SMTP `send_raw` with an envelope unioning
To/Cc/Bcc, then best-effort APPEND to the resolved Sent folder
(`sent_copy` semantics unchanged).

### Attachments

`ComposeInput` gains `attachments: Option<Vec<AttachmentInput>>` where:

```
AttachmentInput {
    path: String,                 // file within the download sandbox root
    filename: Option<String>,     // override name; default = file's basename
    content_type: Option<String>, // default = magic-byte sniff, else application/octet-stream
}
```

Each attachment is read via a new `sandbox::read_sandboxed_file` primitive
(mirrors `resolve_dest_dir`'s containment: canonicalize the parent,
`starts_with(download_dir)`, open the parent as a held `cap_std::fs::Dir`,
open the file fd-relative without following a symlink, read with the size
cap). Bytes are added with `MessageBuilder::binary_attachment(content_type,
filename, data)`. When attachments are present the builder emits a
`multipart/mixed` with the `text/plain` body plus each attachment part.

`filename` and `content_type` are injection-guarded. `filename` is reduced
to its basename (defense in depth; the MIME `name`/`filename` parameter is
quoted, but we never emit caller path separators).

## Caps (new)

- `MAX_ATTACHMENTS = 20` — attachment count per message.
- `MAX_ATTACHMENT_BYTES = 10 MiB` — per-file read cap; a sandbox file larger
  than this is rejected (`InvalidInput`) without being fully read.
- `MAX_TOTAL_MESSAGE_BYTES = 25 MiB` — `body_text` + sum of attachment
  sizes; keeps a single message within common MTA limits and bounds memory.
- Existing `MAX_RECIPIENTS`, `MAX_SUBJECT_LEN`, `MAX_BODY_BYTES` unchanged
  and still enforced.

For `forward`, the `message/rfc822` wrapper counts toward
`MAX_TOTAL_MESSAGE_BYTES`; an oversized original is rejected before send.

## Scope update (2026-07-03) — attachments + HTML accepted by maintainer

`forward` shipped in PR #430. Two follow-on decisions the maintainer took on
2026-07-03 lift the deferrals below and put attachments and HTML body **in
scope** for the remainder of #408:

### Decision 1 — attachments use the shared sandbox root, risk documented

The blocking finding was that `download_dir` is one process-global root shared
by every account, so a sandbox read-back is a cross-account exfiltration
channel. Of the two resolutions (partition per-account vs. accept-and-document
the shared root), the maintainer chose **accept-and-document**: attachments are
readable from anywhere under the single shared root; no change to where
`download_attachment` / `export_messages` write; the shared-sandbox trust model
is stated explicitly in `docs/postures.md` and the `create_draft` / `send_email`
tool descriptions.

Consequence for the trust model: an operator running multiple accounts under
one server accepts that those accounts **share a file staging area** — a file
one account downloads or exports can be attached to outbound mail by any
account. This is an accepted product posture, not a defect. It does not widen
the boundary beyond "files the server itself wrote, or the operator placed, in
the download root"; it does not permit reading arbitrary host paths. The
containment primitive (`read_sandboxed_file`) still enforces
canonicalize + `starts_with(root)` + held-fd no-follow read, exactly as
`resolve_dest_dir` does for writes.

`AttachmentInput`, the caps (`MAX_ATTACHMENTS`, `MAX_ATTACHMENT_BYTES`,
`MAX_TOTAL_MESSAGE_BYTES`), the MIME construction (`multipart/mixed`), and the
security invariants specified above are unchanged and now implemented.

### Decision 2 — HTML body accepted, gated at `full`, text/plain mandatory

Agent-authored HTML body is **in scope**. Design:

- `ComposeInput` gains `body_html: Option<String>`. `body_text` **remains
  required**, so a `text/plain` alternative is *always* present — the message
  is emitted as `multipart/alternative` (text first, sanitized HTML second),
  wrapped in `multipart/mixed` when attachments are also present.
- **Sanitization reuses the inbound ammonia pipeline.** A new public
  `rimap_content` entry point (`sanitize_outbound_html`) runs the agent's HTML
  through the same tag-allowlist / script-strip / remote-content-strip /
  `javascript:`-drop sanitizer used for inbound mail (`html::sanitize`), so the
  server never emits agent-supplied `<script>`, event handlers, remote images,
  or `javascript:` URLs. Anything stripped is surfaced to the caller as
  `security_warnings` in the tool response `meta`, so an operator can see the
  HTML was altered. Size-capped at `MAX_BODY_BYTES` (1 MiB), same as `body_text`.
- **Posture gate = `full`, via a new sub-capability.** The posture matrix
  already promises HTML bodies at `full` (`docs/postures.md`), and there is a
  precedent (`fetch_message.include_html`). A new `ToolName::CreateDraftHtml`
  (`"create_draft.include_html"`, matrix row `[false, false, true, true]`) is
  resolved at the `refine_tool_name` seam when a `create_draft` call carries a
  non-empty `body_html`, so a draft-safe agent can still create plain-text
  drafts but HTML requires `full`. `send_email` is already `full`, so
  `send_email` + `body_html` needs **no** separate capability (the same gate
  already applies); adding one would be a redundant no-op, so it is omitted.
- Capability count 26 → 27; `POSTURE_MATRIX` len +1; exhaustive matches,
  dispatch route (`CreateDraftHtml` → `create_draft::handle`), catalog
  advertisement, redaction schema (`create_draft.include_html` →
  `create_draft_schema`), `dump-tool-*` counts, conformance `wire.test.ts`
  counts, README inventory, and `docs/postures.md` all updated.

### Attachment wiring (no new tool)

`create_draft` and `send_email` inputs gain `attachments`. `build_message` reads
each entry from the shared sandbox via `read_sandboxed_file(download_dir, …)`,
enforces the per-file and total caps, injection-guards `filename` /
`content_type`, reduces `filename` to its basename, sniffs `content_type` when
absent, and adds each part with `MessageBuilder::attachment`. The `attachments`
array is added to the `create_draft` / `send_email` redaction schemas with
`path` and `filename` as `RedactString` (local paths, not secrets, but redacted
to avoid leaking sandbox layout). Schema fixtures regenerate via
`just regen-tool-schemas`.

## Deferred, with rationale

- **~~HTML body~~** — **now in scope** (see Decision 2 above). This bullet is
  retained for history; the deferral no longer applies.
- **Per-account sandbox partitioning** — not done; the maintainer accepted the
  shared-root model (Decision 1). If a future deployment needs hard
  cross-account file isolation, partitioning `<root>/<account_id>/` is the
  follow-up (tracked separately if that need arises).
- **Draft-safe `forward` variant** (a `$PendingReview` forward draft):
  deferred. The codebase models "send" and "save draft" as *separate tools*
  (`send_email` vs `create_draft`), not as one tool that changes behavior by
  posture. A behavior-switch inside `forward` would be the first tool to
  branch on the account's own posture, inconsistent with the matrix's
  binary allow/deny model. A future `forward_draft` tool (or attaching the
  fetched original to `create_draft`) can add draft-safe forwarding without
  overloading posture semantics. `forward` here is send-only, gated like
  `send_email`.

## Security invariants (must have tests)

- Attachment `path` outside the sandbox root → `InvalidInput`, no read.
- Symlink inside the sandbox pointing outside → not followed; rejected.
- Directory-swap between resolve and read lands on the held fd, never a
  swapped-in path (mirrors `write_lands_via_held_fd_after_dir_swap`).
- Oversized attachment / too many attachments / oversized total → rejected.
- `comment`, `filename`, `content_type` with `\r \n \0 < >` → rejected.
- `forward` comment injection-guarded; original attached verbatim.
- Non-Unix: sandbox read fails closed (as `write_attachment` does).

## Wiring checklist (new tool `forward`)

`ToolName::Forward` added to the enum and every exhaustive match
(`as_str`, `is_infrastructure`=false, `is_draft_quota_gated`=false,
`is_send_quota_gated`=true, `annotation_hints`=destructive group); variant
count 25→26. `POSTURE_MATRIX` row added (len 23→24) and authz coverage
tests updated. `tool_def_parts` + dispatch + `dispatch_infrastructure`
non-infra list + redaction schema (`forward_schema`, reusing the
send_email redaction shape) + `dump-tool-schemas` insert + new
`forward.schema.json` fixture. Hardcoded counts bumped: `dump_tool_schemas`
(23→24), `dump_tool_catalog.rs` (23→24), `tests/mcp-conformance/src/wire.test.ts`
(23→24, 25→26), `README.md` tool count/inventory, `docs/postures.md` row.
Attachment redaction: `AttachmentInput.path` is a local filesystem path
(not a secret) but is `RedactString`-classified to avoid leaking sandbox
layout; `filename` likewise.

## Test plan

- `message_builder`: forward builds a `message/rfc822` wrapper that
  round-trips (original recoverable, verbatim); `Fwd:` subject; comment as
  body; threading headers preserved; comment injection rejected; oversized
  original rejected.
- `message_builder`: attachments produce `multipart/mixed`; count/size/total
  caps enforced at the boundaries (at-cap accepted, over-cap rejected);
  filename/content_type injection rejected; sniffed vs declared content type.
- `sandbox`: `read_sandboxed_file` containment, symlink-escape, dir-swap,
  size-cap, non-Unix fail-closed (mirrors the write-path tests).
- Catalog/schema/conformance: `forward` advertised with an object
  inputSchema; fixture matches; counts consistent.
- Security-review agents (mcp-security-reviewer, email-imap-security-reviewer)
  review this spec and the sandbox-read implementation.
