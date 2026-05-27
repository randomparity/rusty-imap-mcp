# `export_messages`: bulk raw export to a `git am`-able mbox

**Date:** 2026-05-26
**Status:** Design — pending review
**Branch:** `feature/export-messages-mbox`

## Problem

Reading a multi-message set (e.g. a 27-patch DPDK series) through `fetch_message`
means 27 separate tool calls, each returning a sanitized, parsed JSON body. For an
agent whose goal is to **apply the patches**, that path is wrong on every axis:

- 27 round-trips and 27 bodies in context is expensive, so agents route around the
  tool and try to script raw IMAP/`curl` access instead.
- Sanitized `body_text` is the wrong artifact for `git am`: the content pipeline runs
  NFKC normalization and disallowed-codepoint filtering that can corrupt a diff, and
  the parsed JSON shape drops the raw `From`/`Subject`/`Date` headers `git am` turns
  into commit metadata.

The agent's actual need is a single artifact it can hand to `git am`.

## Goal

One tool call that fetches a caller-specified set of messages and writes them as a
single `git am`-able **mbox** file into the existing download sandbox — written the same
way `download_attachment` writes attachments — returning the path plus a trusted
manifest. No per-message body content is surfaced inline.

## Non-goals

- **Server-side threading.** Selection is an explicit `uids[]` list; the caller
  discovers the series with `search` (including its `List-Id` header filter) and
  controls ordering. A `Message-ID`/`References` thread mode is a possible future
  follow-up, not part of this work.
- **Inline body content.** Bodies never enter the response. The artifact is the file.
- **Modifying `fetch_message`.** Its deliberately-scalar `uid` contract
  (`fetch_message.rs:11-21`) stays intact. This is a new, separate tool.
- **Crash durability / atomic-artifact transactions.** The mbox is a **best-effort,
  ephemeral sandbox file** written exactly like an attachment download — no `fsync`,
  no write-ahead journal, no crash-recovery sweep, no lease. The agent consumes it in
  the same session (`git am <path>`); a process crash may leave a stale file in the
  sandbox, cleaned up like any other sandbox download. See *Durability scope* for why.

## Approach (chosen over alternatives)

A **new dedicated tool**, `export_messages`, rather than extending `fetch_message`
with a batch/export mode (which would overload one schema with two output channels and
contradict the documented scalar-shape rationale) or a prompt-only fix (which solves
neither context bloat nor `git am` fidelity).

The tool is a generic raw-export primitive that happens to be ideal for patch series.
It **reuses `download_attachment`'s machinery** — `resolve_dest_dir` for path-validated,
traversal-safe sandbox containment and `write_attachment` for collision-safe writes —
and the same `Posture::Readonly` seat (same trust channel: raw bytes to a contained
file, never into the agent's trusted context). It deliberately holds itself to the
*same* durability and containment posture as `download_attachment`, no higher.

## Durability scope

An earlier draft of this spec specified a full write-ahead journal, liveness lease,
crash/cancellation recovery, inode-ownership proofs, and directory-fd atomic finalize.
That was trimmed: `export_messages` is a **default-disabled, opt-in convenience tool**,
not a high-assurance durable store, and `download_attachment` — which writes comparable
raw bytes to the same sandbox — ships with none of that machinery. Holding the new tool
to a stricter durability bar than its sibling is inconsistent and over-engineered for
the use case (fetch a series, `git am` it, done, in one session).

The artifact therefore inherits `download_attachment`'s exact posture: a best-effort
file in the sandbox, no durability guarantee across crashes. If the sandbox-durability
or containment bar should rise, it should rise for `download_attachment` and
`export_messages` **together**, as separate hardening work — not be gold-plated onto
this tool alone.

The existing sandbox writer (`resolve_dest_dir` canonicalize + `write_attachment`
check-then-write) is **path-based, not directory-fd-based**, so it shares
`download_attachment`'s theoretical TOCTOU/symlink-swap window: a *separate local process
or agent with write access to the download root* could swap the directory or final path
between resolution and write. The trimmed design does not add `openat`/no-follow/held-fd
machinery for this one tool (that is the cross-cutting hardening above). Instead the
mitigation is **operational and required**: the **download root must be a server-private,
non-agent-writable directory** — a path only the MCP server process can write, not shared
with the agent's general filesystem access. With no concurrent writer in the sandbox, the
swap race has no actor. The **trust-model requirement** is that the download root's write
authority is *separated from the consuming agent* — ideally a directory owned by a
dedicated OS user / restricted by ownership or ACL, so neither the agent nor another
same-UID-as-the-agent process can write it. As a fail-closed **backstop**, config
validation refuses to start when `export_messages` is enabled and the resolved download
root is group- or world-writable (`mode & 0o022 != 0` on Unix). The mode-bit check alone
does **not** prove same-UID separation, so the deployment-model requirement above is the
real control and is a blocking item for the threat-model gate.

A fully race-proof `openat`/`O_NOFOLLOW`/exclusive-create writer for the shared sandbox
remains the alternative the gate may require; it is cross-cutting (it must cover
`download_attachment` too) and is deliberately out of this tool's scope per the trim.

## Input schema

```jsonc
{
  "folder": "string",            // required; validate_folder_input
  "uids": [101, 102, 103],       // required; non-empty, max 100, de-duped, ORDER PRESERVED
  "expected_uidvalidity": 12345, // REQUIRED; pins mailbox identity across search→export
  "dest_dir": "string?",         // optional; canonicalized, must stay inside download root
  "filename": "string?",         // optional; advisory basename PREFIX only (sanitized)
  "max_total_bytes": 52428800,   // optional aggregate cap; clamped to MAX_EXPORT_TOTAL_BYTES
  "allow_partial": false         // optional; default false. See partial-failure semantics
}
```

`uids` is a plain ordered `Vec<NonZeroU32>`, **not** the `uid` XOR `uids`
`UidSelector` — the caller's order is the mbox order, which is the patch order for
`git am`. Integer fields use the existing `lenient_int` deserializers. The `max 100`
batch cap is shared with the mutation tools.

`expected_uidvalidity` is **required** (unlike the optional guard on the flag tools).
UIDs are meaningful only relative to a UIDVALIDITY, and the documented discovery flow
selects the UID list with `search` *before* the export runs. If the mailbox is recreated
between those two steps, the same UIDs can be reused by different messages and the export
would write the wrong ones. Requiring the caller to pass the UIDVALIDITY it saw at
discovery closes that window: `search` surfaces `uid_validity` (from the same
EXAMINE/UID SEARCH operation — see *Wiring*), the caller threads it in, and the export's
preflight aborts if the mailbox no longer matches.

`filename` is an **advisory basename prefix**, sanitized before use (see below);
`max_total_bytes` is clamped to a compile-time `MAX_EXPORT_TOTAL_BYTES` ceiling so the
aggregate budget cannot be inflated by an oversized request.

## Data flow

1. `validate_folder_input("folder", …)` and `resolve_dest_dir_async` — the same sandbox
   containment `download_attachment` uses.
2. **One** `fetch(folder, uids, FetchSpec { size: true, .. }, expected_uidvalidity)`
   preflight: validates UIDVALIDITY against the required input (abort on mismatch **or**
   an absent observed value — the tool cannot run unguarded), identifies which UIDs
   exist, and sums `RFC822.SIZE` for an advisory aggregate-budget pre-check.
3. For each UID in **caller order**, fetch the raw body with `fetch_body`, passing
   `expected_uidvalidity` so the guard is re-checked **fail-closed** on **every** body
   fetch (both EXAMINE commands in the fetch path) — the batch loop issues a fresh select per
   call, so a mailbox recreation (with reused UIDs) between fetches would otherwise write
   the wrong messages. The guard is fail-closed: a *mismatched* or *omitted* UIDVALIDITY
   is fatal, never a per-UID failure. (Its per-message `max_fetch_body_bytes` cap,
   preflight size check, and connection safety still apply.) **No MIME parse** — raw
   bytes only, so this path never acquires the parse semaphore. A running raw-byte count
   early-aborts against `max_total_bytes`.
4. Frame each message into **mboxrd** (see below), then **re-check the budget against the
   framed artifact size** (framing adds separators, escape bytes, and padding beyond the
   raw bodies); on overflow, abort without writing. Otherwise write the assembled mbox
   via `write_attachment` (collision-safe) and SHA-256 the file.

Fetches are sequential (a single IMAP session serializes commands anyway). Peak memory is
bounded by the successful bodies plus the framed mbox — i.e. by the clamped
`max_total_bytes` (≤ `MAX_EXPORT_TOTAL_BYTES`), not literally one body at a time, since
the bodies are buffered to decide complete-vs-partial before writing. The UIDVALIDITY
guard covers both the preflight and every body fetch (this is correctness, distinct from
the trimmed streaming-read-limit / durability machinery).

## Filename sanitization

`resolve_dest_dir` validates only the *directory*; the artifact name is built separately,
so the advisory `filename` prefix is sanitized first:

- Reject the request (`InvalidInput`) if `filename` is absolute, contains any path
  separator (`/` or `\`), a parent component (`..`), control characters or NUL, is empty
  after trimming, or is a platform-reserved name.
- Reduce the accepted value to a single basename and use it only as the leading text of
  `<prefix>-<token>.mbox` (or `.partial.mbox`), where `<token>` is a short random value
  so two concurrent exports do not contend for the same name. `write_attachment`'s
  collision handling is the backstop.

## Resource bounds

`max_total_bytes` is clamped to `MAX_EXPORT_TOTAL_BYTES` at input validation. Per-message
size is bounded by the existing `fetch_body` cap (`max_fetch_body_bytes`, with its
preflight `RFC822.SIZE` check and post-parse defense-in-depth) — the same protection
`download_attachment` relies on. The aggregate budget is enforced in three places: an
advisory pre-check summing the reported sizes of *eligible* UIDs only (present and within
the per-message cap — so a skipped `NotFound`/`Oversize` UID cannot block an
`allow_partial` export); a running sum of *actual* body bytes during the fetch loop that
aborts the moment it exceeds the budget (this is the real guard against a server that
omits or under-reports `RFC822.SIZE`); and an **authoritative re-check against the framed
artifact size** before writing — mboxrd separators, `From`-line escaping, and terminal
padding add bytes the raw sum does not see. Exceeding the budget aborts the whole run
without writing (a byte budget is a batch-level limit, so it is fatal regardless of
`allow_partial`).

**Worst-case memory** (documented rather than engineered away with a streaming writer,
per the trim): the running check fires within one body of the budget, and a single
under-reported or size-unknown body is still bounded by the per-message
`max_fetch_body_bytes` cap (async-imap buffers a body before the post-parse size check),
so peak heap is roughly `clamped max_total_bytes` (buffered successful bodies) + the
framed mbox copy + **at most one `max_fetch_body_bytes` of over-budget transfer** before
the running check trips. Note `max_fetch_body_bytes` is **operator-configurable**, so the
true memory ceiling is `max_total_bytes + max_fetch_body_bytes`, not exactly
`max_total_bytes` — the same single-body bound the existing `fetch_message` /
`download_attachment` paths already have. Pinning the ceiling exactly to `max_total_bytes`
would require a read-level literal limit (the `body_limit_bytes` streaming variant that
was trimmed). With both caps finite, peak is bounded and finite — acceptable for a
default-disabled, opt-in tool; tightening it is a threat-model-gate decision (it
re-introduces the trimmed streaming read path).

Failure classification is **entirely preflight-driven**: the size preflight identifies
UIDs **not present** in the folder (→ `NotFound`) and UIDs whose reported size exceeds the
per-message cap (→ `Oversize`), both without attempting a body fetch. These are the only
two per-UID reasons, and they feed `allow_partial`.

A UID that reaches the body fetch is therefore known-present and in-bounds, so **any error
from the body fetch is fatal** — never downgraded to a per-UID failure, even under
`allow_partial`. That covers UIDVALIDITY mismatch or omission, a mid-stream `SizeLimit` (a
server lying about size), a `Timeout` (leaves the BODY stream half-consumed; the body
fetch invalidates the session on timeout), connection loss, and any BODY-stream protocol
error (where the session or returned bytes are untrustworthy). The fatal cases abort with
no artifact, so a corrupt or stale body can never land in a `.partial.mbox`.

## mbox format: mboxrd

`build_mbox` operates on raw RFC822 bytes, so framing is specified at the **byte level** —
sloppy framing makes `git am`/`mailsplit` merge or drop messages and corrupt the series:

- Each message is preceded by a synthesized separator line at column 0 with a **pinned
  exact form**: `From mboxrd@rusty-imap-mcp <asctime>\n` (the classic mboxrd postmark;
  `<asctime>` is a fixed-width UTC `ctime` string). `git am` uses it only as a delimiter
  and takes real authorship from each message's own `From:` header.
- The separator **must start at column 0**: before emitting any separator after the
  first, if the previous message did not end with a line feed, insert one. That padding
  byte is part of the persisted output and is counted in `total_bytes` / `sha256`.
- **Every** raw line matching `^>*From ` is escaped with one extra leading `>` — body,
  malformed, and header-position lines alike, since the splitter keys purely on column-0
  `From `. `git am` un-escapes mboxrd on read.
- CRLF endings are preserved verbatim; the column-0 and terminal-LF checks operate on
  `\n` boundaries regardless of a preceding `\r`.

The logic lives in a pure `build_mbox` function, unit- and property-testable without a
live IMAP connection, with fixtures for no-terminal-newline, CRLF, and
malformed/header-position `From ` lines.

## Response (trusted metadata only)

No body or subject is surfaced inline, so the response carries **only trusted metadata** —
no untrusted payload, no sanitization step. The content stays in the sandbox file.

Complete export:

```jsonc
{
  "folder": "INBOX",
  "complete": true,
  "path": "<sandbox>/messages-a1b2c3.mbox",   // git am-ready
  "partial_path": null,
  "sha256": "…",
  "message_count": 27,
  "total_bytes": 1234567,
  "uid_validity": 12345,
  "succeeded": [{ "uid": 101, "size_bytes": 4096 }],
  "failed":    []
}
```

When some UIDs fail **and `allow_partial=true`**, `complete` is `false`, `path` is
`null`, and the bytes are surfaced only as `partial_path` (`…-a1b2c3.partial.mbox`).
When some UIDs fail and `allow_partial=false` (the default), **no artifact is written and
the tool returns an error** listing the failed UIDs. `reason` ∈
`not_found | oversize` (both preflight-determined). Exactly one of `path` / `partial_path` is non-null,
keyed off `complete`.

## Partial-failure semantics: safe by default, best-effort on request

The default is **all-or-nothing**: if any requested UID is missing, oversize, or fails
to fetch, the export returns an error naming the failed UIDs and writes no artifact. The
documented `export_messages(uids) → git am <path>` flow therefore can never receive a
partial series that would half-apply and leave a repository partially mutated.

Best-effort export — the behavior chosen during brainstorming — is preserved as an
explicit opt-in via **`allow_partial: true`**. Only then does the tool write the
successes to a distinct `.partial.mbox` artifact, set `complete: false` / `path: null`,
and surface the bytes as `partial_path`. The caller has consciously asked for a
possibly-incomplete result and must resolve the gaps before applying anything.

> Reconciliation: brainstorming chose best-effort; adversarial review flagged that any
> returned incomplete artifact is reachable by `git am` regardless of which field carries
> it. Making best-effort an explicit `allow_partial` opt-in keeps the capability while
> making the safe behavior the default. This default is called out for the user's review.

## Security posture

`Posture::Readonly`, parity with `download_attachment`: identical trust channel (raw
bytes to a contained, path-validated file — not the agent's trusted context). Two guards
address that this is a broader oracle than a single attachment (`fetch_message` at
`Readonly` returns *sanitized* content; this returns *unsanitized full RFC822*):

- **Default-deny, not Readonly-by-default.** Because absent `[security.tools]` entries
  fall back to `base_allows`, listing the tool at `Readonly` in the base matrix would
  make it callable in a default deployment. Instead, `export_messages` is **denied in the
  base matrix at every posture** and becomes callable *only* via an explicit
  `[security.tools].export_messages = "allow"` operator override. An empty/default config
  denies it and `list_tools` omits it.
- **`threat-model-reviewer` sign-off is a blocking acceptance gate** — the tool does not
  merge until that review approves the gating model versus requiring a higher posture.

Note: `export_messages` guarantees faithful mboxrd framing (column-0 `From ` escaping is
tested against real `git am`), but it does NOT sanitize message content. Running
`git am <path>` applies attacker-influenceable `From:`/`Subject:`/diff content as commit
metadata and working-tree files — that consumption step is a trust boundary the calling
agent/operator owns, not one this tool mediates.

**The authz seat is distinct from the MCP annotation hints.** `Readonly` is the authz
seat (no *mailbox* mutation), but the tool *writes a new file*, so — exactly like
`download_attachment` (`read_only_hint=false`) — its `ToolName::annotation_hints` are
`read_only=false`, `idempotent=false` (each call writes a new artifact),
`destructive=false` (it never overwrites — `write_attachment` de-dups), `open_world=true`
(it contacts an external IMAP server). These mirror `download_attachment`'s annotation
tests so a client cannot auto-approve a raw export as read-only.

## Audit contract

`export_messages` uses the **same audit envelope as every other tool**, no more and no
less: a `tool_start`/`tool_end` pair recording status, error code, and duration, plus the
redacted arguments and an `arguments_hash_sha256`. This is parity, not a downgrade — the
shared `tool_end` `ResultSummary` is currently recorded empty for *all* tools
(`download_attachment` included), and its fields (`message_ids_returned`,
`bytes_returned`, `truncated`, `security_warnings_emitted`) have no path/sha256/UID-list
slots.

- **Argument redaction** is the export-specific audit work: the tool adds a redaction
  schema (compile-forced, since the dispatch is exhaustive) that keeps `folder`,
  `expected_uidvalidity`, and the requested `uids` (verbatim `U64Array`) recoverable,
  redacts the path-ish `dest_dir` / `filename`, and forbids `password` / `token`. **No
  message content** ever enters the audit log.
- **Rich result provenance** — the ordered succeeded-UID list with sizes, the failed
  `{uid, reason}` list, `total_bytes`, artifact path, and `sha256` — is returned in the
  tool **response** (trusted metadata), which is where an operating agent and any
  response-logging consumer can see it.

Recording that rich provenance *durably* in the audit log would require extending the
shared `ResultSummary` record format and plumbing handler results through the envelope
for every tool. That is deliberately **out of scope** here (cross-cutting audit work),
for the same reason the durability tier was trimmed: this tool should not carry bespoke
infrastructure that none of its siblings have.

**Accepted risk (recorded for the threat-model gate).** Adversarial review flagged that
a default-disabled but high-impact raw export should have durable provenance an operator
can reconstruct after the fact. The durable trail that *is* recorded: the per-call
`tool_start`/`tool_end` records (tool name, account, posture, timing, status), the
`arguments_hash_sha256`, and the redacted arguments — which record `folder`,
`expected_uidvalidity`, and the **exact requested `uids` verbatim** (`Verbatim(U64Array)`,
the same policy `expunge` uses for UID arrays). So the *requested scope* of every export
is durably auditable. What is **not** durable (only in the tool response) is the
succeeded-vs-failed partition and the artifact path/`sha256`/byte count. We accept that
narrower gap rather than build cross-cutting audit plumbing for one tool; if the
`threat-model-reviewer` (the blocking gate) judges it insufficient for raw export, the
prerequisite is the shared `ResultSummary` extension across all tools — done as separate
work before this tool ships, not bolted onto it.

## Wiring (files touched)

- `rimap-core`: add `ToolName::ExportMessages` with canonical name + `FromStr`/`Display`;
  add `MAX_EXPORT_TOTAL_BYTES`; add its `annotation_hints` (`read_only=false`,
  `idempotent=false`, `destructive=false`, `open_world=true`).
- `rimap-imap` search op + `rimap-server/src/tools/retrieval/search.rs`: return
  `(uids, uid_validity)` from the **same** EXAMINE/UID SEARCH operation and surface that
  exact `uid_validity` in the `search` response, so the discovery flow can thread it into
  `expected_uidvalidity`. (The current path returns only UIDs; the UIDVALIDITY in the
  handler comes from a later fetch — unsafe to pair with the searched UID set.)
- `rimap-authz/src/matrix.rs`: **deny `ExportMessages` at every posture** in the base
  matrix; reachable only via an explicit `[security.tools].export_messages = "allow"`.
- `rimap-server/src/tools/retrieval/export_messages.rs`: handler + pure `build_mbox`;
  reuses `fetch_body`, `resolve_dest_dir`, and `write_attachment` (no new IMAP fetch
  variant, no atomic-writer machinery).
- `rimap-server/src/tools/retrieval/mod.rs`: `pub mod export_messages;`.
- `rimap-server/src/mcp/tool_name.rs`: exhaustive `refine_tool_name` arm (no refinement).
- `rimap-server/src/mcp/tool_catalog.rs`: input + response envelope schema registration.
- `rimap-server/src/mcp/dispatch.rs`: dispatch arm.
- `rimap-audit/src/redact.rs`: add the export_messages argument redaction schema
  (compile-forced — the dispatch is exhaustive). No `audit_envelope.rs` change: the tool
  uses the standard envelope, same as every other tool.
- `rimap-server/src/cli/dump_tool_schemas.rs`: schema-dump entry.
- Docs: tool reference + the per-tool enable/disable section.

The tool's MCP description states its intended use ("fetch many messages at once as a
`git am`-able mbox"). The intended end-to-end flow is: `search` (e.g. `List-Id` +
`[PATCH` subject) → read its `uid_validity` → `export_messages(uids,
expected_uidvalidity)` → `git am <path>`.

## Testing

- **`build_mbox` unit tests:** escaping of every `^>*From ` line (body, malformed,
  header-position), column-0 separator framing with terminal-LF padding counted in
  `total_bytes`/`sha256`, CRLF preservation, caller-order preservation, empty/single-
  message edges. Fixtures: no-terminal-newline, CRLF, malformed/header-position `From `.
- **Property test:** N raw messages → `build_mbox` → split back → equals inputs.
- **Real-`git` acceptance test:** run `git mailsplit` / `git am` in a throwaway fixture
  repo against generated mboxes (CRLF, no-terminal-newline, `From `-line, multi-patch)
  and assert the commits apply with the expected count and metadata.
- **Partial semantics (default vs opt-in):** `allow_partial=false` + a failing UID →
  error, no artifact, no `path`. `allow_partial=true` → `complete:false`, `path:null`,
  populated `partial_path` (`.partial.mbox`), `failed[]` entry. Full success →
  `complete:true`, non-null `path`, `partial_path:null`. An e2e assertion proves the
  `git am <path>` flow never receives a path for an incomplete series.
- **Filename sanitization:** `../escape`, `/abs/path`, `a/b`, `a\\b`, empty,
  whitespace-only, control-char, platform-reserved names are rejected.
- **Concurrency:** two concurrent exports with the same `filename` prefix get distinct
  paths (random token + `write_attachment` de-dup), and each `sha256` matches the bytes
  at its path.
- **Aggregate budget:** caller `max_total_bytes` above `MAX_EXPORT_TOTAL_BYTES` is
  clamped; a run whose written bytes exceed the clamped cap aborts.
- **Sandbox containment:** reuse the `resolve_dest_dir` traversal/escape test pattern
  (same containment model as `download_attachment`).
- **UIDVALIDITY guard:** preflight aborts on mismatch and on an absent observed value
  (distinct errors); the `search` API returns `(uids, uid_validity)` from one operation,
  with a race test recreating the mailbox between UID SEARCH and the response so the
  reported `uid_validity` matches the mailbox the UIDs came from.
- **Fatal vs per-UID failures:** a mid-loop `UidValidityChanged`, an omitted UIDVALIDITY
  (`UidValidityUnavailable`, fail-closed), a mid-stream `SizeLimit`, a `Timeout`, or
  connection loss aborts the whole export with no artifact — **never** downgraded to a
  per-UID failure (even under `allow_partial`); a missing UID is `NotFound` and a
  preflight-oversize UID is `Oversize`, both per-UID.
- **Argument redaction:** the export_messages redaction schema keeps `folder` /
  `expected_uidvalidity` / the requested `uids` (verbatim) recoverable, redacts
  `dest_dir` / `filename`, and forbids `password` / `token`; no message content reaches
  the audit log. (The succeeded/failed partition + artifact path/sha256 are in the tool
  response, not the durable audit summary — see *Audit contract*.)
- **MCP annotation hints:** `read_only=false`, `idempotent=false`, `destructive=false`,
  `open_world=true`, mirroring the `download_attachment` annotation test.
- **Schema envelope:** validates under Draft-07 (all-scalar trusted meta, no date tuples).
