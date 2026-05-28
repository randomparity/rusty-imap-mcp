# export_messages (bulk mbox export) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an `export_messages` MCP tool that fetches a caller-specified set of UIDs and writes them as one `git am`-able mbox file into the download sandbox, returning a path + trusted manifest.

**Architecture:** A new retrieval tool mirroring `download_attachment`: reuses `resolve_dest_dir`/`write_attachment` for sandbox writes, `fetch`/`fetch_body` for IMAP, and the `Posture`/annotation/audit wiring. Output fidelity (raw RFC822 for `git am`) lives in a pure `build_mbox` function; all genuinely-testable logic is pure and unit-tested, while IMAP orchestration is thin and exercised by the dovecot e2e harness — matching how the existing retrieval handlers are tested. The tool is **default-deny** in the posture matrix (enabled only via `[security.tools].export_messages = "allow"`).

**Tech Stack:** Rust (workspace crates `rimap-core`, `rimap-authz`, `rimap-imap`, `rimap-server`), `serde`/`schemars`, `tokio`, `cargo nextest`.

**Reference spec:** `docs/superpowers/specs/2026-05-26-export-messages-mbox-design.md`

**Conventions:**
- Tests run with `cargo nextest run -p <crate> --locked` (workspace runner is `just test`).
- Lints: `cargo clippy --all-targets --all-features -- -D warnings`. Wildcard match arms are banned; test modules carry `#[expect(clippy::unwrap_used, reason = "tests")]` etc.
- Tool-schema fixtures live in `crates/rimap-server/tests/fixtures/rimap-tool-schemas/`; regenerate with `just regen-tool-schemas` (runs `./scripts/regen-tool-schemas.sh`).
- Commit after each task. Imperative mood, ≤72-char subject.

---

## File Structure

**Created:**
- `crates/rimap-server/src/tools/retrieval/export_messages.rs` — input/meta types, pure helpers (`build_mbox`, `sanitize_filename_prefix`, `clamp_total_bytes`, `validate_uids`, `plan_outcome`), the `handle` orchestrator, and all unit tests (including the in-module real-`git` acceptance test).
- `crates/rimap-server/tests/fixtures/rimap-tool-schemas/export_messages.schema.json` — generated schema fixture.

**Modified:**
- `crates/rimap-core/src/tool.rs` — `ToolName::ExportMessages` variant, `as_str`, three classification matches, `annotation_hints`, count test.
- `crates/rimap-core/src/posture_matrix.rs` — default-deny matrix row, length bump.
- `crates/rimap-authz/src/matrix.rs` — update four base-posture row tests to treat `ExportMessages` as the always-base-denied exception; add a gate test.
- `crates/rimap-imap/src/ops/search.rs` + `crates/rimap-imap/src/connection/dispatch.rs` — `search` returns `(Vec<Uid>, Option<u32>)`.
- `crates/rimap-imap/src/ops/fetch.rs` (`preflight_fetch_size`) + `crates/rimap-imap/src/connection/dispatch.rs` (`fetch_body`) — thread `expected_uidvalidity` so body fetches are UIDVALIDITY-guarded; `crates/rimap-server/src/tools/retrieval/download_attachment.rs` passes `None`.
- `crates/rimap-server/src/tools/retrieval/search.rs` — surface `uid_validity` in `SearchMeta`.
- `crates/rimap-server/src/tools/retrieval/mod.rs` — `pub mod export_messages;`.
- `crates/rimap-server/src/mcp/dispatch.rs`, `tool_catalog.rs`, `tool_name.rs`, `cli/dump_tool_schemas.rs` — register/dispatch the tool.
- `crates/rimap-server/src/mcp/audit_envelope.rs` — export-specific `tool_end` result summary (Task 8).
- Docs (Task 10).

---

## Task 1: Register `ExportMessages` (inert) so the workspace compiles

Adding the enum variant breaks every exhaustive `match` over `ToolName` (the codebase bans wildcard arms). This task adds the variant, the type definitions the schema registration needs, and an inert handler, then fixes every exhaustive site so the workspace compiles with the tool advertised (only when allowed) and returning a "not implemented" error when called.

**Files:**
- Modify: `crates/rimap-core/src/tool.rs`
- Modify: `crates/rimap-core/src/posture_matrix.rs`
- Modify: `crates/rimap-authz/src/matrix.rs`
- Modify: `crates/rimap-audit/src/redact.rs` (redaction schema — compile-forced)
- Create: `crates/rimap-server/src/tools/retrieval/export_messages.rs`
- Modify: `crates/rimap-server/src/tools/retrieval/mod.rs`
- Modify: `crates/rimap-server/src/mcp/dispatch.rs`
- Modify: `crates/rimap-server/src/mcp/tool_catalog.rs`
- Modify: `crates/rimap-server/src/mcp/tool_name.rs`
- Modify: `crates/rimap-server/src/cli/dump_tool_schemas.rs`

- [ ] **Step 1: Add the enum variant.** In `crates/rimap-core/src/tool.rs`, after the `DownloadAttachment` variant (line 30), add:

```rust
    /// `export_messages` — bulk raw export of multiple UIDs to a
    /// `git am`-able mbox in the download sandbox. Default-denied in the
    /// base posture matrix; enabled only via `[security.tools]`.
    ExportMessages,
```

- [ ] **Step 2: Add the `as_str` mapping.** In `tool.rs` `as_str`, after the `DownloadAttachment` arm (line 82):

```rust
            Self::ExportMessages => "export_messages",
```

- [ ] **Step 3: Add to the three classification matches.** In `tool.rs`, add `| Self::ExportMessages` to the `false`-returning arm of each of `is_infrastructure` (after line 129), `is_draft_quota_gated` (after line 162), and `is_send_quota_gated` (after line 196). Example for `is_infrastructure`:

```rust
            | Self::DownloadAttachment
            | Self::ExportMessages
```

- [ ] **Step 4: Add the annotation hints.** In `tool.rs` `annotation_hints`, add a dedicated arm (it is *not* idempotent, unlike the `DownloadAttachment` group — each call writes a new artifact):

```rust
            // Writes a new sandbox file per call (not idempotent), never
            // overwrites (write_attachment de-dups), reads from IMAP.
            Self::ExportMessages => (false, false, false, true),
```

- [ ] **Step 5: Update the variant-count test.** In `tool.rs` tests, change both `24` to `25`:

```rust
    #[test]
    fn all_has_exactly_twenty_four_variants() {
        assert_eq!(ToolName::all().len(), 25);
        assert_eq!(ToolName::iter().count(), 25);
    }
```

(Rename the fn to `all_has_exactly_twenty_five_variants` for accuracy.)

- [ ] **Step 6: Add the default-deny posture row.** In `crates/rimap-core/src/posture_matrix.rs`, bump the array length `; 22]` → `; 23]` (line 14) and add after the `DownloadAttachment` row (line 21):

```rust
    // export_messages: default-DENY at every posture. Reachable only via
    // an explicit [security.tools].export_messages = "allow" override.
    (ToolName::ExportMessages, [false, false, false, false]),
```

- [ ] **Step 7: Update the four base-posture row tests.** In `crates/rimap-authz/src/matrix.rs`:
  - `base_readonly_row_matches_spec`: add `ToolName::ExportMessages,` to the *denied* list (the second array, after line 139).
  - `base_draft_safe_row_matches_spec`: add `ToolName::ExportMessages,` to the `denied` array (after line 155).
  - `base_full_allows_except_destructive`: change `let denied = [ToolName::Expunge, ToolName::DeleteFolder];` (line 170) to `let denied = [ToolName::Expunge, ToolName::DeleteFolder, ToolName::ExportMessages];`.
  - `base_destructive_allows_all_non_infrastructure`: this asserts every non-infra tool is allowed at Destructive; add an exception. Replace the `else` branch body (lines 199-204) so `ExportMessages` is asserted denied:

```rust
            } else if t == ToolName::ExportMessages {
                assert!(
                    !base_allows(Posture::Destructive, t),
                    "export_messages is default-deny at every base posture"
                );
            } else {
                assert!(
                    base_allows(Posture::Destructive, t),
                    "destructive should allow {t}"
                );
            }
```

- [ ] **Step 8: Add the default-deny gate test.** Append to `crates/rimap-authz/src/matrix.rs` tests:

```rust
    #[test]
    fn export_messages_denied_by_default_enabled_only_by_override() {
        // No override: denied at every posture.
        for p in Posture::all() {
            let m = EffectiveMatrix::build(p, &BTreeMap::new());
            assert!(
                m.is_allowed(ToolName::ExportMessages).is_err(),
                "export_messages must be default-denied at {p:?}"
            );
        }
        // Explicit allow override enables it.
        let mut overrides = BTreeMap::new();
        overrides.insert(ToolName::ExportMessages, Verdict::Allow);
        let m = EffectiveMatrix::build(Posture::Readonly, &overrides);
        assert!(m.is_allowed(ToolName::ExportMessages).is_ok());
    }
```

(If the accessor is named differently than `is_allowed`, match the method used by neighbouring tests in this file — e.g. the one returning `Result<(), AuthzError::PostureDenied>`.)

- [ ] **Step 8b: Add the redaction schema (compile-forced).** `ToolName::redaction_schema()` in `crates/rimap-audit/src/redact.rs` is an exhaustive match — the workspace will not compile without an arm for the new variant. After the `DownloadAttachment` arm (line 323) add:

```rust
            Self::ExportMessages => export_messages_schema(self),
```

and add the helper next to `download_attachment_schema` (after line 474):

```rust
fn export_messages_schema(tool: ToolName) -> RedactionSchema {
    use FieldPolicy::{Forbidden, RedactString, Verbatim};
    use VerbatimType::{Bool, String as VtString, U64, U64Array};
    RedactionSchema::new(
        tool,
        &[
            ("folder", Verbatim(VtString)),
            ("uids", Verbatim(U64Array)),
            ("expected_uidvalidity", Verbatim(U64)),
            ("max_total_bytes", Verbatim(U64)),
            ("allow_partial", Verbatim(Bool)),
            ("dest_dir", RedactString),
            ("filename", RedactString),
            ("password", Forbidden),
            ("token", Forbidden),
        ],
    )
}
```

(`uids` uses `Verbatim(U64Array)` — the same policy `expunge`/`flag` use for UID arrays — so the **exact requested UID set is durably recorded** in the redacted audit args, not just the response. `dest_dir`/`filename` are path-ish and redacted.)

> Known limitation (consistent with existing tools, not export-specific): `Verbatim`
> preserves only JSON-number forms, so a client that sends a *string-form* lenient integer
> (`"expected_uidvalidity": "12345"`) has that value redacted to `<redacted:N>` in the
> audit args rather than recorded verbatim — the redactor runs on raw args before serde
> canonicalizes them. This affects every lenient-int field across the codebase (`flag`'s
> `uid`, `search`'s `limit`, …), so canonicalizing lenient numeric strings in the audit
> layer is a **cross-cutting** improvement, deferred out of this tool. The
> `arguments_hash_sha256` still covers the raw value, and the `uid_validity` is echoed in
> the response.

- [ ] **Step 9: Create the handler module with types + inert handler.** Create `crates/rimap-server/src/tools/retrieval/export_messages.rs`:

```rust
//! `export_messages` tool handler: bulk raw export of multiple UIDs to a
//! single `git am`-able mbox file in the download sandbox.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::boot::registry::AccountState;
use crate::mcp::response::ToolResponse;

/// Hard ceiling on the aggregate export size, regardless of the
/// caller-supplied `max_total_bytes`.
pub const MAX_EXPORT_TOTAL_BYTES: u64 = 100 * 1024 * 1024;

/// Input for the `export_messages` tool.
#[derive(Debug, Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct ExportMessagesInput {
    /// IMAP folder containing the messages.
    pub folder: String,
    /// UIDs to export, in mbox (patch) order. Non-empty, max 100, de-duped.
    pub uids: Vec<core::num::NonZeroU32>,
    /// UIDVALIDITY observed when the UID list was discovered (e.g. from
    /// `search`). Required: pins mailbox identity across search→export.
    #[serde(deserialize_with = "crate::tools::lenient_int::deserialize_nonzero_u32")]
    #[schemars(schema_with = "crate::tools::lenient_int::schema_nonzero_u32")]
    pub expected_uidvalidity: core::num::NonZeroU32,
    /// Optional destination directory. Must be within the download root.
    pub dest_dir: Option<String>,
    /// Optional advisory basename prefix (sanitized).
    pub filename: Option<String>,
    /// Aggregate byte cap; clamped to `MAX_EXPORT_TOTAL_BYTES`.
    #[serde(
        default,
        deserialize_with = "crate::tools::lenient_int::deserialize_opt_u64"
    )]
    #[schemars(schema_with = "crate::tools::lenient_int::schema_opt_u64")]
    pub max_total_bytes: Option<u64>,
    /// When true, write the successes to a `.partial.mbox` artifact instead
    /// of failing the whole call. Default false (all-or-nothing).
    pub allow_partial: Option<bool>,
}

/// One successfully exported message.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct ExportedUid {
    pub uid: u32,
    pub size_bytes: usize,
}

/// Reason a requested UID was not exported. Both are determined at the size
/// preflight, before any body fetch — a UID that reaches the body fetch is
/// known-present and in-bounds, and any error there is fatal (never per-UID),
/// so there is no `FetchError` variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExportFailReason {
    NotFound,
    Oversize,
}

/// One requested UID that failed.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct FailedUid {
    pub uid: u32,
    pub reason: ExportFailReason,
}

/// Trusted metadata for an `export_messages` response.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct ExportMessagesMeta {
    /// Folder the messages were exported from.
    pub folder: String,
    /// True iff every requested UID was exported.
    pub complete: bool,
    /// `git am`-ready mbox path; `null` when `complete` is false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Path of a `.partial.mbox` artifact; non-null only on a partial export.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partial_path: Option<String>,
    /// SHA-256 of the written mbox, hex-encoded.
    pub sha256: String,
    /// Number of messages written to the artifact.
    pub message_count: usize,
    /// Total bytes written.
    pub total_bytes: u64,
    /// UIDVALIDITY the export was pinned to.
    pub uid_validity: u32,
    /// Exported UIDs, in mbox order, with sizes.
    pub succeeded: Vec<ExportedUid>,
    /// Requested UIDs that failed, with reasons.
    pub failed: Vec<FailedUid>,
}

/// Execute the `export_messages` tool.
///
/// # Errors
///
/// Returns `RimapError::Internal` — not yet implemented (filled in Task 7).
pub async fn handle(
    _account: &AccountState,
    _input: ExportMessagesInput,
) -> Result<ToolResponse<ExportMessagesMeta>, rimap_core::RimapError> {
    Err(rimap_core::RimapError::Internal(
        "export_messages not yet implemented".into(),
    ))
}
```

- [ ] **Step 10: Declare the module.** In `crates/rimap-server/src/tools/retrieval/mod.rs`, add `pub mod export_messages;` (alphabetical order near `download_attachment`).

- [ ] **Step 11: Wire dispatch.** In `crates/rimap-server/src/mcp/dispatch.rs`, after the `DownloadAttachment` dispatch arm (lines 161-163), add:

```rust
            ToolName::ExportMessages => {
                ser(Box::pin(export_messages::handle(account, parse_args(args)?)).await?)?
            }
```

Add `export_messages` to the `use crate::tools::retrieval::{... }` import (alongside `download_attachment`), and add `| ToolName::ExportMessages` to the not-infrastructure catch-all (after `| ToolName::DownloadAttachment` in the lines 241-262 block).

- [ ] **Step 12: Wire the catalog.** In `crates/rimap-server/src/mcp/tool_catalog.rs`:
  - Import: add `export_messages::ExportMessagesMeta,` to the `use crate::tools::retrieval::{...}` block (near line 99-105).
  - `output_schema`: after the `DownloadAttachment` arm (lines 123-125), add:

```rust
        ToolName::ExportMessages => {
            envelope_schema::<ToolResponse<ExportMessagesMeta, ()>>()
        }
```

  - `tool_spec`: after the `DownloadAttachment` arm (lines 190-194), add:

```rust
        ToolName::ExportMessages => (
            "Export Messages",
            "Export multiple messages by UID as a single git am-able mbox \
             file in the download sandbox. Discover UIDs with `search` and \
             pass its uid_validity. Disabled unless enabled in [security.tools].",
            envelope_schema::<ExportMessagesInput>(),
        ),
```

  Add `ExportMessagesInput` to the `use ... export_messages::ExportMessagesInput` import used by `tool_spec` (mirror how `DownloadAttachmentInput` is imported).

- [ ] **Step 13: Wire tool-name refinement.** In `crates/rimap-server/src/mcp/tool_name.rs`, add `| ToolName::ExportMessages` to the catch-all base arm (lines 52-75, near `| ToolName::DownloadAttachment`).

- [ ] **Step 14: Wire the schema dump.** In `crates/rimap-server/src/cli/dump_tool_schemas.rs`, add `export_messages::ExportMessagesMeta,` to the import (near line 45) and add an insert (near the `download_attachment` insert, lines 84-87):

```rust
    out.insert(
        "export_messages",
        tool_envelope::<ExportMessagesMeta, ()>(),
    );
```

- [ ] **Step 15: Generate the schema fixture.** Run:

```bash
just regen-tool-schemas
```

Expected: creates `crates/rimap-server/tests/fixtures/rimap-tool-schemas/export_messages.schema.json`.

- [ ] **Step 16: Build + test the workspace.** Run:

```bash
cargo build --workspace --locked
cargo nextest run -p rimap-core -p rimap-authz -p rimap-audit --locked
```

Expected: PASS — `all_has_exactly_twenty_five_variants`, the updated base-posture row tests, `export_messages_denied_by_default_enabled_only_by_override`, and the `rimap-audit` redaction-schema coverage tests all pass.

- [ ] **Step 17: Lint.** Run:

```bash
cargo clippy --all-targets --all-features -- -D warnings
```

Expected: no warnings.

- [ ] **Step 18: Commit.**

```bash
git add -A
git commit -m "feat(export_messages): register tool (inert) with default-deny gate"
```

---

## Task 2: `build_mbox` byte-level mboxrd framing (pure)

The heart of `git am` fidelity. Pure function over raw RFC822 bytes.

**Files:**
- Modify: `crates/rimap-server/src/tools/retrieval/export_messages.rs`
- Test: same file (`#[cfg(test)] mod tests`)

- [ ] **Step 1: Write the failing tests.** Add to `export_messages.rs`:

```rust
#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod build_mbox_tests {
    use super::build_mbox;

    const SEP: &[u8] = b"From mboxrd@rusty-imap-mcp Thu Jan  1 00:00:00 1970\n";

    #[test]
    fn single_message_gets_separator_and_trailing_newline() {
        let out = build_mbox(&[b"Subject: hi\r\n\r\nbody".to_vec()]);
        assert!(out.starts_with(SEP), "missing leading separator");
        assert!(out.ends_with(b"\n"), "must end with newline");
        assert!(out.windows(4).any(|w| w == b"body"));
    }

    #[test]
    fn missing_terminal_newline_padded_before_next_separator() {
        // First message has no trailing newline; the second separator must
        // still start at column 0.
        let out = build_mbox(&[b"a: 1\r\n\r\nno-newline".to_vec(), b"b: 2\r\n\r\nx\n".to_vec()]);
        let text = String::from_utf8(out).unwrap();
        // Exactly two separators, each at the start of a line.
        let seps: Vec<_> = text.match_indices("From mboxrd@").collect();
        assert_eq!(seps.len(), 2);
        for (idx, _) in &seps {
            assert!(*idx == 0 || text.as_bytes()[idx - 1] == b'\n', "separator not at col 0");
        }
    }

    #[test]
    fn escapes_every_from_line_including_nested_and_header_position() {
        let msg = b"From the desk of X\r\n>From already escaped\r\nFrom \r\nnormal\n".to_vec();
        let out = build_mbox(&[msg]);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains(">From the desk of X"));
        assert!(text.contains(">>From already escaped"));
        assert!(text.contains(">From \r\n"));
        assert!(text.contains("\nnormal"));
    }

    #[test]
    fn preserves_crlf_verbatim_in_body() {
        let out = build_mbox(&[b"H: 1\r\n\r\nline1\r\nline2\r\n".to_vec()]);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("line1\r\nline2\r\n"));
    }

    #[test]
    fn split_back_round_trips_messages() {
        // Build, then split on separator lines and un-escape; must equal inputs.
        let inputs = vec![
            b"A: 1\r\n\r\nFrom space\r\nbody1\r\n".to_vec(),
            b"B: 2\r\n\r\nbody2\n".to_vec(),
        ];
        let mbox = build_mbox(&inputs);
        let recovered = split_and_unescape(&mbox);
        assert_eq!(recovered.len(), inputs.len());
        // Compare ignoring a single trailing newline build_mbox may add.
        for (got, want) in recovered.iter().zip(inputs.iter()) {
            assert_eq!(trim_one_trailing_nl(got), trim_one_trailing_nl(want));
        }
    }

    fn trim_one_trailing_nl(b: &[u8]) -> &[u8] {
        b.strip_suffix(b"\n").unwrap_or(b)
    }

    // Test-only inverse of build_mbox's framing: split on separator lines,
    // strip one leading '>' from each `^>+From ` line.
    fn split_and_unescape(mbox: &[u8]) -> Vec<Vec<u8>> {
        let text = mbox;
        let sep = SEP;
        let mut parts: Vec<Vec<u8>> = Vec::new();
        let mut cur: Option<Vec<u8>> = None;
        for line in split_keep_newlines(text) {
            if line == sep {
                if let Some(c) = cur.take() {
                    parts.push(c);
                }
                cur = Some(Vec::new());
            } else if let Some(c) = cur.as_mut() {
                c.extend_from_slice(&unescape_line(line));
            }
        }
        if let Some(c) = cur.take() {
            parts.push(c);
        }
        parts
    }

    fn unescape_line(line: &[u8]) -> Vec<u8> {
        // If line is `>+From `, drop one leading '>'.
        let mut j = 0;
        while j < line.len() && line[j] == b'>' {
            j += 1;
        }
        if j >= 1 && line[j..].starts_with(b"From ") {
            line[1..].to_vec()
        } else {
            line.to_vec()
        }
    }

    fn split_keep_newlines(b: &[u8]) -> Vec<&[u8]> {
        let mut out = Vec::new();
        let mut start = 0;
        for i in 0..b.len() {
            if b[i] == b'\n' {
                out.push(&b[start..=i]);
                start = i + 1;
            }
        }
        if start < b.len() {
            out.push(&b[start..]);
        }
        out
    }
}
```

- [ ] **Step 2: Run to verify failure.**

```bash
cargo nextest run -p rimap-server build_mbox_tests --locked
```

Expected: FAIL — `build_mbox` not found.

- [ ] **Step 3: Implement `build_mbox`.** Add to `export_messages.rs` (module scope):

```rust
/// Pinned mboxrd separator. `git am`/`mailsplit` use it only as a delimiter
/// and take real authorship from each message's own `From:` header.
const MBOX_SEPARATOR: &[u8] = b"From mboxrd@rusty-imap-mcp Thu Jan  1 00:00:00 1970\n";

/// Assemble raw RFC822 messages into a single mboxrd byte buffer suitable
/// for `git am`. Each message is preceded by [`MBOX_SEPARATOR`] at column 0;
/// every line matching `^>*From ` is escaped with one extra leading `>`;
/// CRLF is preserved verbatim.
fn build_mbox(messages: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for msg in messages {
        // Ensure the previous message ended with a line feed so this
        // separator starts at column 0.
        if let Some(&last) = out.last()
            && last != b'\n'
        {
            out.push(b'\n');
        }
        out.extend_from_slice(MBOX_SEPARATOR);
        escape_from_lines_into(&mut out, msg);
    }
    // Trailing newline for a well-formed final message.
    if let Some(&last) = out.last()
        && last != b'\n'
    {
        out.push(b'\n');
    }
    out
}

/// Append `msg` to `out`, escaping each `^>*From ` line with one extra `>`.
fn escape_from_lines_into(out: &mut Vec<u8>, msg: &[u8]) {
    let mut line_start = 0;
    for i in 0..msg.len() {
        if msg[i] == b'\n' {
            write_mbox_line(out, &msg[line_start..=i]);
            line_start = i + 1;
        }
    }
    if line_start < msg.len() {
        write_mbox_line(out, &msg[line_start..]);
    }
}

fn write_mbox_line(out: &mut Vec<u8>, line: &[u8]) {
    if line_is_from(line) {
        out.push(b'>');
    }
    out.extend_from_slice(line);
}

/// Whether `line` (from column 0) matches `^>*From ` — any run of `>` then
/// the literal `From `.
fn line_is_from(line: &[u8]) -> bool {
    let mut j = 0;
    while j < line.len() && line[j] == b'>' {
        j += 1;
    }
    line[j..].starts_with(b"From ")
}
```

- [ ] **Step 4: Run to verify pass.**

```bash
cargo nextest run -p rimap-server build_mbox_tests --locked
```

Expected: PASS (all 5 tests).

- [ ] **Step 5: Commit.**

```bash
git add crates/rimap-server/src/tools/retrieval/export_messages.rs
git commit -m "feat(export_messages): add build_mbox mboxrd framing"
```

---

## Task 3: `sanitize_filename_prefix` (pure)

**Files:**
- Modify: `crates/rimap-server/src/tools/retrieval/export_messages.rs`

- [ ] **Step 1: Write the failing tests.** Add a `mod sanitize_tests`:

```rust
#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod sanitize_tests {
    use super::sanitize_filename_prefix;

    #[test]
    fn default_when_absent() {
        assert_eq!(sanitize_filename_prefix(None).unwrap(), "messages");
    }

    #[test]
    fn accepts_plain_basename() {
        assert_eq!(sanitize_filename_prefix(Some("dpdk-series")).unwrap(), "dpdk-series");
    }

    #[test]
    fn rejects_everything_outside_the_allowlist() {
        for bad in [
            "../escape", "/abs/path", "a/b", "a\\b", "", "  ", "a\u{0}b", "a\nb", // separators/control
            "a;b", "a b", "a'b", "a\"b", "a$b", "a|b", "a&b", "a`b",            // shell metachars/spaces/quotes
            "-lead", ".hidden",                                                  // leading dash/dot
            "a\u{202E}b", "a\u{200B}b", "a\u{E0001}b",                           // bidi / zero-width / tag
        ] {
            assert!(sanitize_filename_prefix(Some(bad)).is_err(), "should reject {bad:?}");
        }
        // Overlong (> 64 chars) is rejected.
        let long = "a".repeat(65);
        assert!(sanitize_filename_prefix(Some(&long)).is_err());
    }

    #[test]
    fn accepts_conservative_ascii_basenames() {
        for ok in ["messages", "dpdk-series", "patch_set.v2", "AB12"] {
            assert!(sanitize_filename_prefix(Some(ok)).is_ok(), "should accept {ok:?}");
        }
    }
}
```

- [ ] **Step 2: Run to verify failure.**

```bash
cargo nextest run -p rimap-server sanitize_tests --locked
```

Expected: FAIL — function not found.

- [ ] **Step 3: Implement.** Add to `export_messages.rs`:

```rust
/// Sanitize the advisory `filename` prefix to a safe single basename, or
/// return the default `"messages"` when absent.
///
/// Uses a conservative **allowlist** grammar — `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`
/// — because the prefix ends up in the `path` returned to the agent and the
/// documented flow is `git am <path>`. The allowlist rejects path separators,
/// `..` traversal, shell metacharacters, whitespace, quotes, and all non-ASCII
/// (so bidi / zero-width / tag display-spoofing codepoints cannot appear), and
/// the alphanumeric-first rule rejects leading `.`/`-`.
///
/// # Errors
///
/// `RimapError::Authz { code: InvalidInput }` if the prefix is empty after
/// trimming, longer than 64 bytes, or contains any character outside the
/// grammar.
fn sanitize_filename_prefix(prefix: Option<&str>) -> Result<String, rimap_core::RimapError> {
    let Some(raw) = prefix else {
        return Ok("messages".to_string());
    };
    let trimmed = raw.trim();
    let valid = !trimmed.is_empty()
        && trimmed.len() <= 64
        && trimmed.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric())
        && trimmed
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if !valid {
        return Err(rimap_core::RimapError::invalid_input(
            "filename prefix must match [A-Za-z0-9][A-Za-z0-9._-]{0,63} \
             (conservative ASCII basename)",
        ));
    }
    Ok(trimmed.to_string())
}
```

- [ ] **Step 4: Run to verify pass.**

```bash
cargo nextest run -p rimap-server sanitize_tests --locked
```

Expected: PASS.

- [ ] **Step 5: Commit.**

```bash
git add crates/rimap-server/src/tools/retrieval/export_messages.rs
git commit -m "feat(export_messages): add filename prefix sanitization"
```

---

## Task 4: `validate_uids` + `clamp_total_bytes` (pure)

**Files:**
- Modify: `crates/rimap-server/src/tools/retrieval/export_messages.rs`

- [ ] **Step 1: Write the failing tests.** Add `mod input_tests`:

```rust
#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod input_tests {
    use super::{clamp_total_bytes, validate_uids, MAX_EXPORT_TOTAL_BYTES};
    use core::num::NonZeroU32;

    fn nz(n: u32) -> NonZeroU32 {
        NonZeroU32::new(n).unwrap()
    }

    #[test]
    fn rejects_empty() {
        assert!(validate_uids(Vec::new()).is_err());
    }

    #[test]
    fn rejects_over_100() {
        let v: Vec<NonZeroU32> = (1..=101).map(nz).collect();
        assert!(validate_uids(v).is_err());
    }

    #[test]
    fn dedups_preserving_first_order() {
        let v = vec![nz(3), nz(1), nz(3), nz(2), nz(1)];
        let out = validate_uids(v).unwrap();
        let got: Vec<u32> = out.iter().map(|u| u.get()).collect();
        assert_eq!(got, vec![3, 1, 2]);
    }

    #[test]
    fn clamp_none_is_ceiling() {
        assert_eq!(clamp_total_bytes(None), MAX_EXPORT_TOTAL_BYTES);
    }

    #[test]
    fn clamp_caps_oversized_request() {
        assert_eq!(clamp_total_bytes(Some(u64::MAX)), MAX_EXPORT_TOTAL_BYTES);
        assert_eq!(clamp_total_bytes(Some(1024)), 1024);
    }
}
```

- [ ] **Step 2: Run to verify failure.**

```bash
cargo nextest run -p rimap-server input_tests --locked
```

Expected: FAIL — functions not found.

- [ ] **Step 3: Implement.** Add to `export_messages.rs` (with `use rimap_imap::types::Uid;` at the top of the file):

```rust
/// Max UIDs per export, shared with the mutation-tool batch cap.
const MAX_EXPORT_UIDS: usize = 100;

/// Validate and normalize the requested UID list: reject empty / over-cap,
/// de-dup preserving first-seen order, and convert to `Uid`.
///
/// # Errors
///
/// `RimapError::Authz { code: InvalidInput }` for an empty list or one
/// exceeding [`MAX_EXPORT_UIDS`].
fn validate_uids(
    uids: Vec<core::num::NonZeroU32>,
) -> Result<Vec<Uid>, rimap_core::RimapError> {
    if uids.is_empty() {
        return Err(rimap_core::RimapError::invalid_input("uids must not be empty"));
    }
    if uids.len() > MAX_EXPORT_UIDS {
        return Err(rimap_core::RimapError::invalid_input(
            "uids exceeds the maximum of 100 per export",
        ));
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::with_capacity(uids.len());
    for u in uids {
        if seen.insert(u.get()) {
            out.push(Uid::from(u));
        }
    }
    Ok(out)
}

/// Clamp the caller-supplied aggregate byte budget to the hard ceiling.
fn clamp_total_bytes(requested: Option<u64>) -> u64 {
    requested.map_or(MAX_EXPORT_TOTAL_BYTES, |n| n.min(MAX_EXPORT_TOTAL_BYTES))
}
```

- [ ] **Step 4: Run to verify pass.**

```bash
cargo nextest run -p rimap-server input_tests --locked
```

Expected: PASS.

- [ ] **Step 5: Commit.**

```bash
git add crates/rimap-server/src/tools/retrieval/export_messages.rs
git commit -m "feat(export_messages): add uid validation and byte-budget clamp"
```

---

## Task 5: `plan_outcome` — partial/complete decision (pure)

Decides, given per-UID fetch outcomes and `allow_partial`, whether to abort (default, with failures) or proceed (complete or partial).

**Files:**
- Modify: `crates/rimap-server/src/tools/retrieval/export_messages.rs`

- [ ] **Step 1: Write the failing tests.** Add `mod outcome_tests`:

```rust
#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod outcome_tests {
    use super::{plan_outcome, ExportFailReason, FetchOutcome, Outcome};

    fn ok(uid: u32, body: &[u8]) -> FetchOutcome {
        FetchOutcome { uid, result: Ok(body.to_vec()) }
    }
    fn err(uid: u32, reason: ExportFailReason) -> FetchOutcome {
        FetchOutcome { uid, result: Err(reason) }
    }

    #[test]
    fn all_success_is_complete() {
        let out = plan_outcome(vec![ok(1, b"a"), ok(2, b"b")], false);
        match out {
            Outcome::Proceed { complete, bodies, succeeded, failed } => {
                assert!(complete);
                assert_eq!(bodies.len(), 2);
                assert_eq!(succeeded.len(), 2);
                assert!(failed.is_empty());
            }
            Outcome::Abort { .. } => panic!("expected Proceed"),
        }
    }

    #[test]
    fn failure_without_allow_partial_aborts() {
        let out = plan_outcome(vec![ok(1, b"a"), err(2, ExportFailReason::NotFound)], false);
        match out {
            Outcome::Abort { failed } => {
                assert_eq!(failed.len(), 1);
                assert_eq!(failed[0].uid, 2);
            }
            Outcome::Proceed { .. } => panic!("expected Abort"),
        }
    }

    #[test]
    fn failure_with_allow_partial_proceeds_incomplete() {
        let out = plan_outcome(vec![ok(1, b"a"), err(2, ExportFailReason::Oversize)], true);
        match out {
            Outcome::Proceed { complete, bodies, succeeded, failed } => {
                assert!(!complete);
                assert_eq!(bodies.len(), 1);
                assert_eq!(succeeded.len(), 1);
                assert_eq!(failed.len(), 1);
            }
            Outcome::Abort { .. } => panic!("expected Proceed"),
        }
    }
}
```

- [ ] **Step 2: Run to verify failure.**

```bash
cargo nextest run -p rimap-server outcome_tests --locked
```

Expected: FAIL — types/functions not found.

- [ ] **Step 3: Implement.** Add to `export_messages.rs`:

```rust
/// Per-UID fetch result fed into [`plan_outcome`].
pub(crate) struct FetchOutcome {
    pub uid: u32,
    pub result: Result<Vec<u8>, ExportFailReason>,
}

/// Decision produced by [`plan_outcome`].
pub(crate) enum Outcome {
    /// Default all-or-nothing path with failures: write nothing, error out.
    Abort { failed: Vec<FailedUid> },
    /// Write the bodies (in order) and report the manifest.
    Proceed {
        complete: bool,
        bodies: Vec<Vec<u8>>,
        succeeded: Vec<ExportedUid>,
        failed: Vec<FailedUid>,
    },
}

/// Partition per-UID outcomes into an export decision. With failures and
/// `allow_partial == false`, returns [`Outcome::Abort`]; otherwise
/// [`Outcome::Proceed`] with `complete == failed.is_empty()`.
fn plan_outcome(outcomes: Vec<FetchOutcome>, allow_partial: bool) -> Outcome {
    let mut bodies = Vec::new();
    let mut succeeded = Vec::new();
    let mut failed = Vec::new();
    for o in outcomes {
        match o.result {
            Ok(body) => {
                succeeded.push(ExportedUid { uid: o.uid, size_bytes: body.len() });
                bodies.push(body);
            }
            Err(reason) => failed.push(FailedUid { uid: o.uid, reason }),
        }
    }
    if !failed.is_empty() && !allow_partial {
        return Outcome::Abort { failed };
    }
    Outcome::Proceed {
        complete: failed.is_empty(),
        bodies,
        succeeded,
        failed,
    }
}

/// What to do with one requested UID, decided from its preflight size entry.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum UidPlan {
    /// Resolved at preflight without a body fetch (`NotFound` / `Oversize`).
    Skip(ExportFailReason),
    /// Present and in-bounds: fetch the body.
    Fetch,
}

/// Classify a UID from its preflight size entry (`None` = absent from the
/// folder; `Some(None)` = present, size unknown; `Some(Some(n))` = present,
/// reported size `n`). Pure, so the security-critical NotFound/Oversize
/// decision is unit-testable without a live IMAP server.
fn classify_uid(reported: Option<Option<u32>>, per_msg_cap: u64) -> UidPlan {
    match reported {
        None => UidPlan::Skip(ExportFailReason::NotFound),
        Some(Some(sz)) if u64::from(sz) > per_msg_cap => UidPlan::Skip(ExportFailReason::Oversize),
        _ => UidPlan::Fetch,
    }
}
```

- [ ] **Step 4: Add `classify_uid` tests.** Append to `outcome_tests`:

```rust
    #[test]
    fn classify_uid_cases() {
        use super::{classify_uid, ExportFailReason, UidPlan};
        assert_eq!(classify_uid(None, 100), UidPlan::Skip(ExportFailReason::NotFound));
        assert_eq!(classify_uid(Some(Some(200)), 100), UidPlan::Skip(ExportFailReason::Oversize));
        assert_eq!(classify_uid(Some(Some(50)), 100), UidPlan::Fetch);
        assert_eq!(classify_uid(Some(None), 100), UidPlan::Fetch); // present, size unknown
    }
```

- [ ] **Step 5: Run to verify pass.**

```bash
cargo nextest run -p rimap-server outcome_tests --locked
```

Expected: PASS (both `plan_outcome` and `classify_uid` cases).

- [ ] **Step 6: Commit.**

```bash
git add crates/rimap-server/src/tools/retrieval/export_messages.rs
git commit -m "feat(export_messages): add outcome planning and uid classification"
```

---

## Task 6: IMAP layer — `search` returns `uid_validity`, and a UIDVALIDITY-guarded body fetch

Two IMAP-layer changes: (a) `search` returns `(uids, uid_validity)` so the discovery
flow can thread `uid_validity` into `export_messages`; (b) `fetch_body` gains an
`expected_uidvalidity` guard so the export loop cannot write the wrong messages if the
mailbox is recreated (and the same UIDs reused) *between* body fetches. This guard is
correctness (which messages get exported), distinct from the streaming read-limit /
durability machinery deliberately left out of scope.

**Files:**
- Modify: `crates/rimap-imap/src/ops/search.rs:9-31`
- Modify: `crates/rimap-imap/src/connection/dispatch.rs:124-133` (search) and `:182-228` (fetch_body)
- Modify: `crates/rimap-imap/src/ops/fetch.rs:255-278` (`preflight_fetch_size`)
- Modify: `crates/rimap-server/src/tools/retrieval/download_attachment.rs:108` (pass `None`)
- Modify: `crates/rimap-server/src/tools/retrieval/search.rs`

- [ ] **Step 1: Change the IMAP search op.** In `crates/rimap-imap/src/ops/search.rs`, replace the function body (lines 9-31) so it selects read-only (capturing UIDVALIDITY from the same operation) and returns the pair:

```rust
pub(crate) async fn search(
    session: &mut ImapSession,
    folder: &str,
    query: SearchQuery,
) -> Result<(Vec<Uid>, Option<u32>), ImapError> {
    // Read-only SELECT (EXAMINE) so the UID set and its UIDVALIDITY come
    // from the same selected-mailbox operation.
    let selected = super::folders::select(session, folder, true).await?;
    let uid_validity = selected.uid_validity;

    let key = match query {
        SearchQuery::Structured(s) => structured_to_key(&s)?,
        SearchQuery::Raw(r) => r,
    };

    let uids = session
        .uid_search(&key)
        .await
        .map_err(super::folders::map_err)?;
    Ok((uids.into_iter().filter_map(Uid::new).collect(), uid_validity))
}
```

(If `Uid::new` here takes the raw `u32` from `uid_search`, keep it exactly as the original line used it — only the return type and the select change.)

- [ ] **Step 2: Change the connection wrapper.** In `crates/rimap-imap/src/connection/dispatch.rs`, update the `search` method signature (lines 128-133) return type:

```rust
    pub async fn search(
        &self,
        folder: &str,
        query: crate::types::SearchQuery,
    ) -> Result<(Vec<crate::types::Uid>, Option<u32>), ImapError> {
        self.with_session("search", async |session| {
            crate::ops::search::search(session, folder, query).await
        })
        .await
    }
```

- [ ] **Step 3: Add `uid_validity` to `SearchMeta` + write a serialization test.** In `crates/rimap-server/src/tools/retrieval/search.rs`, add the field to `SearchMeta` (after `truncated`, line 167):

```rust
    /// UIDVALIDITY observed for the searched folder, from the same
    /// EXAMINE/UID SEARCH operation. Thread into `export_messages`'
    /// `expected_uidvalidity`. `None` if the server omitted it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid_validity: Option<u32>,
```

Add a test at the bottom of `search.rs` tests:

```rust
    #[test]
    fn search_meta_serializes_uid_validity() {
        let meta = SearchMeta {
            folder: "INBOX".to_string(),
            total_matched: 0,
            returned: 0,
            truncated: false,
            uid_validity: Some(12345),
        };
        let v = serde_json::to_value(meta).unwrap();
        assert_eq!(v["uid_validity"], serde_json::json!(12345));
    }
```

- [ ] **Step 4: Update the `search` handler to thread the value.** In `search.rs` `handle`, change the search call and the meta construction:

```rust
    let (uids, uid_validity) = Box::pin(account.imap.search(&input.folder, query)).await?;
```

and add `uid_validity,` to the `SearchMeta { ... }` literal (line 225-230 block).

- [ ] **Step 5: Build + test.**

```bash
cargo build --workspace --locked
cargo nextest run -p rimap-imap -p rimap-server search --locked
```

Expected: PASS, including `search_meta_serializes_uid_validity`. Fix any other in-crate callers of `account.imap.search(...)` flagged by the compiler (destructure the tuple).

- [ ] **Step 6a: Add a fail-closed UIDVALIDITY error + strict check.** The shared `check_uidvalidity` (fetch.rs:79-104) *warns and proceeds* when `expected=Some` but the server omits UIDVALIDITY. For a raw export that is unsafe — a recreated mailbox whose EXAMINE omits UIDVALIDITY would export unguarded. Add a dedicated error and a strict helper. In `crates/rimap-imap/src/error.rs`, add a variant to `ImapError`:

```rust
    /// A guarded fetch required UIDVALIDITY but the server omitted it.
    /// Distinct from `UidValidityChanged` (which carries a concrete
    /// mismatch); here the guard simply could not be verified.
    #[error("server omitted UIDVALIDITY for folder {folder} on a guarded fetch")]
    UidValidityUnavailable { folder: String },
```

Wire the variant through every exhaustive `ImapError` match the compiler flags — at minimum: `ImapError::code()` (error.rs:~195) → `ErrorCode::UidValidityChanged`; the `From<ImapError> for RimapError` mapping in `crates/rimap-core/src/error.rs` (route through the generic `Imap` arm like other variants, so `code()` surfaces `ERR_UID_VALIDITY_CHANGED`); and the `should_invalidate` match in dispatch `fetch_body` (Step 6c) as **non-invalidating** (the session is healthy; only the mailbox identity is unverifiable). Then add the strict helper in `crates/rimap-imap/src/ops/fetch.rs`:

```rust
/// Like [`check_uidvalidity`] but **fail-closed**: when `expected` is set,
/// an absent observed UIDVALIDITY is an error, not a warning.
pub(crate) fn require_uidvalidity(
    folder: &str,
    expected: Option<u32>,
    observed: Option<u32>,
) -> Result<(), ImapError> {
    let Some(expected) = expected else {
        return Ok(());
    };
    match observed {
        Some(actual) if actual == expected => Ok(()),
        Some(actual) => Err(ImapError::UidValidityChanged {
            folder: folder.to_owned(),
            expected,
            actual,
        }),
        None => Err(ImapError::UidValidityUnavailable { folder: folder.to_owned() }),
    }
}
```

- [ ] **Step 6b: Guard BOTH EXAMINEs in the body-fetch path.** The dispatch `fetch_body` runs two EXAMINEs: one in `preflight_fetch_size` (RFC822.SIZE) and one in `ops::fetch::fetch_body` (the EXAMINE immediately before `BODY.PEEK[]`, fetch.rs:194-197). The second determines *which bytes are returned*, so it must be guarded too. In `crates/rimap-imap/src/ops/fetch.rs`, change both to take `expected_uidvalidity` and verify via `folders::select(..., true)` (which returns `uid_validity`) + the strict `require_uidvalidity`:

```rust
pub(crate) async fn preflight_fetch_size(
    session: &mut ImapSession,
    folder: &str,
    uid: Uid,
    expected_uidvalidity: Option<u32>,
) -> Result<Option<u32>, ImapError> {
    let selected = super::folders::select(session, folder, true).await?;
    require_uidvalidity(folder, expected_uidvalidity, selected.uid_validity)?;

    let mut stream = session
        .uid_fetch(uid.get().to_string(), "RFC822.SIZE")
        .await
        .map_err(super::folders::map_err)?;

    let mut size: Option<u32> = None;
    while let Some(msg) = stream.next().await {
        let msg = msg.map_err(super::folders::map_err)?;
        if msg.uid == Some(uid.get()) {
            size = msg.size;
        }
    }
    Ok(size)
}

pub(crate) async fn fetch_body(
    session: &mut ImapSession,
    folder: &str,
    uid: Uid,
    limit: u64,
    expected_uidvalidity: Option<u32>,
) -> Result<Vec<u8>, ImapError> {
    let selected = super::folders::select(session, folder, true).await?;
    require_uidvalidity(folder, expected_uidvalidity, selected.uid_validity)?;

    let mut stream = session
        .uid_fetch(uid.get().to_string(), "BODY.PEEK[]")
        .await
        .map_err(super::folders::map_err)?;
    // ... rest of the existing body-accumulation loop unchanged ...
```

(Only the leading `session.examine(folder)` block of `ops::fetch::fetch_body` changes; the `uid_fetch`/accumulation/`found` logic below is untouched. `require_uidvalidity` with `expected=None` is a no-op, so `download_attachment`'s `None` caller is unaffected.)

- [ ] **Step 6c: Invalidate the session on timeout in `fetch_body`.** A timed-out `BODY.PEEK[]` leaves the response stream half-consumed, so reusing the session corrupts later fetches. In `crates/rimap-imap/src/connection/dispatch.rs`, move `ImapError::Timeout { .. }` from the non-invalidating arm into the `true` arm of the `should_invalidate` match (dispatch.rs:207-223), alongside `ConnectionLost | SizeLimit`. Add `ImapError::UidValidityUnavailable { .. }` to the non-invalidating arm.

- [ ] **Step 7: Thread `expected_uidvalidity` through dispatch `fetch_body`.** In `crates/rimap-imap/src/connection/dispatch.rs`, add the parameter to `fetch_body` (lines 182-228) and pass it into **both** internal calls:

```rust
    pub async fn fetch_body(
        &self,
        folder: &str,
        uid: crate::types::Uid,
        expected_uidvalidity: Option<u32>,
    ) -> Result<Vec<u8>, ImapError> {
```

Update the preflight call to `preflight_fetch_size(session, folder, uid, expected_uidvalidity)` and the body call to `crate::ops::fetch::fetch_body(session, folder, uid, limit, expected_uidvalidity)`. A UIDVALIDITY mismatch returns `ImapError::UidValidityChanged`; add it to the `should_invalidate` match's non-invalidating (false) arm if the compiler's exhaustiveness check flags it (it is already listed there per dispatch.rs:217-219 — leave as-is).

- [ ] **Step 8: Add a per-message cap accessor + update the single-message caller.** In `crates/rimap-imap/src/connection/mod.rs`, alongside the existing `host()`/`username()` accessors, add:

```rust
    /// Maximum bytes a single `fetch_body` will accept (config cap).
    #[must_use]
    pub fn max_fetch_body_bytes(&self) -> u64 {
        self.inner.cfg.max_fetch_body_bytes
    }
```

Then in `crates/rimap-server/src/tools/retrieval/download_attachment.rs:108`, change `account.imap.fetch_body(&input.folder, uid)` to `account.imap.fetch_body(&input.folder, uid, None)`.

- [ ] **Step 9: Build + test.**

```bash
cargo build --workspace --locked
cargo nextest run -p rimap-imap -p rimap-server --locked
```

Expected: PASS. Fix any other `fetch_body(...)` call sites flagged by the compiler to pass `None`.

- [ ] **Step 10: Regenerate the search schema fixture** (SearchMeta changed):

```bash
just regen-tool-schemas
```

- [ ] **Step 11: Unit-test the fail-closed guard.** Add to `crates/rimap-imap/src/ops/fetch.rs` tests (this is the deterministic coverage for the omitted-UIDVALIDITY and mid-loop-recreation cases the Dovecot harness cannot reliably inject):

```rust
    #[test]
    fn require_uidvalidity_strict() {
        use super::require_uidvalidity;
        // expected=None: no-op (download_attachment path).
        assert!(require_uidvalidity("INBOX", None, None).is_ok());
        assert!(require_uidvalidity("INBOX", None, Some(7)).is_ok());
        // expected=Some: match ok, mismatch and ABSENT both error.
        assert!(require_uidvalidity("INBOX", Some(7), Some(7)).is_ok());
        assert!(matches!(
            require_uidvalidity("INBOX", Some(7), Some(8)),
            Err(crate::error::ImapError::UidValidityChanged { .. })
        ));
        assert!(matches!(
            require_uidvalidity("INBOX", Some(7), None),
            Err(crate::error::ImapError::UidValidityUnavailable { .. })
        ));
    }
```

Run: `cargo nextest run -p rimap-imap require_uidvalidity_strict --locked` → PASS.

- [ ] **Step 12: Commit.**

```bash
git add -A
git commit -m "feat(imap): search returns uid_validity; fetch_body gains UIDVALIDITY guard"
```

---

## Task 7: Implement `export_messages::handle`

Wire the pure helpers together with IMAP fetch + sandbox write.

**Files:**
- Modify: `crates/rimap-server/src/tools/retrieval/export_messages.rs`

- [ ] **Step 1: Add imports** at the top of `export_messages.rs`:

```rust
use std::sync::Arc;

use rimap_imap::types::{FetchSpec, Uid};

use crate::tools::retrieval::sandbox;
```

(Keep the existing `use rimap_imap::types::Uid;` consolidated into the line above. No
`ImapError` import is needed — the handler converts any body-fetch error with `e.into()`
without naming the type.)

- [ ] **Step 2: Replace the inert `handle`** with the orchestration:

```rust
/// Execute the `export_messages` tool.
///
/// # Errors
///
/// - `RimapError::Authz { code: InvalidInput }` for an empty/over-cap UID
///   list or an unsafe `filename`.
/// - `RimapError::UidValidityChanged` if the folder's UIDVALIDITY no longer
///   matches `expected_uidvalidity`.
/// - `RimapError::Authz { code: InvalidInput }` (all-or-nothing default)
///   listing failed UIDs when `allow_partial` is false and any UID fails.
/// - `RimapError::Imap { ... }` for connection-dropping fetch failures.
/// - `RimapError::Internal` for filesystem/hashing failures.
pub async fn handle(
    account: &AccountState,
    input: ExportMessagesInput,
) -> Result<ToolResponse<ExportMessagesMeta>, rimap_core::RimapError> {
    crate::tools::validation::validate_folder_input("folder", &input.folder)?;

    let prefix = sanitize_filename_prefix(input.filename.as_deref())?;
    let uids = validate_uids(input.uids)?;
    let budget = clamp_total_bytes(input.max_total_bytes);
    let allow_partial = input.allow_partial.unwrap_or(false);
    let expected = input.expected_uidvalidity.get();
    let per_msg_cap = account.imap.max_fetch_body_bytes();

    let dest =
        sandbox::resolve_dest_dir_async(input.dest_dir, Arc::clone(&account.download_dir)).await?;

    // Preflight: validate UIDVALIDITY (required), learn which UIDs exist, and
    // collect reported sizes. A mismatch surfaces as UidValidityChanged here.
    let (pre_msgs, uid_validity_opt) = account
        .imap
        .fetch(
            &input.folder,
            &uids,
            FetchSpec { size: true, ..FetchSpec::default() },
            Some(expected),
        )
        .await?;
    // The shared guard only *warns* on an omitted UIDVALIDITY; export refuses
    // to run unguarded, so reject an absent value.
    let Some(uid_validity) = uid_validity_opt else {
        return Err(rimap_core::RimapError::invalid_input(
            "server omitted UIDVALIDITY; export_messages requires it to guard the mailbox",
        ));
    };

    // uid -> reported RFC822.SIZE (None if the server omitted it). Absence from
    // the map means the UID is not present in the folder.
    let mut size_by_uid: std::collections::BTreeMap<u32, Option<u32>> =
        std::collections::BTreeMap::new();
    for m in &pre_msgs {
        size_by_uid.insert(m.uid.get(), m.size);
    }

    // Advisory aggregate pre-check, summed over ONLY the UIDs that may be
    // written — present and within the per-message cap. Excluding NotFound and
    // known-Oversize UIDs means they cannot block an `allow_partial` export of
    // the writable messages. (A present-but-size-unknown UID counts 0 here; the
    // running actual-bytes check during fetch is its real guard.) The framed
    // size check below is the final authority.
    let eligible_sum: u64 = uids
        .iter()
        .filter_map(|u| match size_by_uid.get(&u.get()) {
            Some(Some(sz)) if u64::from(*sz) <= per_msg_cap => Some(u64::from(*sz)),
            _ => None,
        })
        .sum();
    if eligible_sum > budget {
        return Err(rimap_core::RimapError::invalid_input(
            "export exceeds max_total_bytes",
        ));
    }

    // Classify + fetch in caller order. Missing and known-oversize UIDs are
    // per-UID failures resolved at preflight (no body fetch). `running` is the
    // authoritative bound on *actual* transferred bytes — the reported-size
    // pre-check above can be defeated by a server that omits/under-reports
    // RFC822.SIZE, so we abort the moment real bytes exceed the budget.
    let mut outcomes = Vec::with_capacity(uids.len());
    let mut running: u64 = 0;
    for uid in &uids {
        let n = uid.get();
        // Preflight-driven per-UID decision (pure, unit-tested). Skips never
        // attempt a body fetch, so oversize never triggers SizeLimit.
        if let UidPlan::Skip(reason) = classify_uid(size_by_uid.get(&n).copied(), per_msg_cap) {
            outcomes.push(FetchOutcome { uid: n, result: Err(reason) });
            continue;
        }
        match account.imap.fetch_body(&input.folder, *uid, Some(expected)).await {
            Ok(body) => {
                running = running.saturating_add(body.len() as u64);
                if running > budget {
                    return Err(rimap_core::RimapError::invalid_input(
                        "export exceeds max_total_bytes",
                    ));
                }
                outcomes.push(FetchOutcome { uid: n, result: Ok(body) });
            }
            // ANY body-fetch error is fatal — never downgraded to a per-UID
            // failure. Per-UID absence/oversize is already resolved at preflight
            // (above), so a UID that reaches the body fetch is known-present and
            // in-bounds; an error here (UIDVALIDITY change/omission, SizeLimit,
            // Timeout, connection loss, or a BODY-stream protocol error) means
            // the session or the returned bytes are untrustworthy. Aborting
            // prevents a corrupt/stale body landing in a `.partial.mbox`.
            Err(e) => return Err(e.into()),
        }
    }

    let (complete, bodies, succeeded, failed) = match plan_outcome(outcomes, allow_partial) {
        Outcome::Abort { failed } => {
            let uids: Vec<String> = failed.iter().map(|f| f.uid.to_string()).collect();
            return Err(rimap_core::RimapError::invalid_input(format!(
                "export incomplete (set allow_partial=true to override); failed UIDs: {}",
                uids.join(", ")
            )));
        }
        Outcome::Proceed { complete, bodies, succeeded, failed } => {
            (complete, bodies, succeeded, failed)
        }
    };

    let mbox = build_mbox(&bodies);
    let total_bytes = mbox.len() as u64;
    // Authoritative budget check on the *framed* output: mboxrd separators,
    // From-line escaping, and terminal padding add bytes beyond the raw
    // bodies counted in the loop above. Reject before writing anything.
    if total_bytes > budget {
        return Err(rimap_core::RimapError::invalid_input(
            "framed mbox exceeds max_total_bytes",
        ));
    }
    let sha256 = sandbox::sha256_hex(&mbox);

    let suffix = if complete { "mbox" } else { "partial.mbox" };
    let token = export_token();
    let filename = format!("{prefix}-{token}.{suffix}");
    let written = sandbox::write_attachment_async(dest, filename, mbox).await?;
    let written = written.to_string_lossy().to_string();

    let (path, partial_path) = if complete {
        (Some(written), None)
    } else {
        (None, Some(written))
    };

    Ok(ToolResponse::meta_only(ExportMessagesMeta {
        folder: input.folder,
        complete,
        path,
        partial_path,
        sha256,
        message_count: succeeded.len(),
        total_bytes,
        uid_validity,
        succeeded,
        failed,
    }))
}

/// Short random token making concurrent exports' filenames distinct.
fn export_token() -> String {
    use rand::Rng as _;
    let n: u64 = rand::thread_rng().r#gen();
    format!("{n:016x}")
}
```

- [ ] **Step 3: Confirm the `rand` dependency.** Check `crates/rimap-server/Cargo.toml` for `rand`. If absent, add it (look up the current workspace version — `grep -r "rand" Cargo.lock | head` to match the already-vendored version) and run `cargo deny check` after. If `rand` is undesirable, replace `export_token` with a counter+timestamp using `std::time::SystemTime` nanos; the `write_attachment` collision de-dup is the correctness backstop either way.

- [ ] **Step 4: Build.**

```bash
cargo build --workspace --locked
```

Expected: compiles. Fix the `ImapError` import path / variant names if the compiler disagrees (confirm `SizeLimit`/`ConnectionLost` spelling against `crates/rimap-imap/src/error.rs`).

- [ ] **Step 5: Run the unit tests (pure helpers still pass through `handle`).**

```bash
cargo nextest run -p rimap-server export_messages --locked
```

Expected: PASS (the pure-helper tests from Tasks 2-5).

- [ ] **Step 6: Where each failure path is tested (read before writing tests).** The Dovecot e2e harness drives a *real* server and **cannot deterministically inject** protocol faults — lying/omitted `RFC822.SIZE`, omitted UIDVALIDITY on a specific EXAMINE, precise mid-loop interleaving, or `fetch_body` timeouts are not normal Dovecot behavior, so asserting them through Dovecot would be flaky sleeps or no real coverage. The security-critical *decisions* are therefore covered at the **deterministic pure-function seam**, and Dovecot covers only what it can do faithfully:
  - **Unit (deterministic), already specified:** `require_uidvalidity` — mismatch → `UidValidityChanged`, absent → `UidValidityUnavailable`, match → `Ok` (Task 6); `classify_uid` — NotFound / Oversize / Fetch (Task 5); `build_mbox` framing + exact byte counts feeding the framed-budget threshold (Task 2); `clamp_total_bytes` (Task 4); `plan_outcome` partial/complete (Task 5). These prove the wrong-message, oversize-skip, fail-closed-UIDVALIDITY, and budget-threshold logic without a live server.
  - **Handler is a thin driver over those pure pieces:** the only handler-level rules not pure are "any `fetch_body` error → fatal" (no branching) and the running/framed budget aborts (trivial comparisons). They are exercised by the happy-path e2e plus the pure tests above; deeper deterministic coverage would need a scriptable IMAP fake (a cross-cutting test seam — see the note in Step 7).

- [ ] **Step 7: Add Dovecot e2e for what it can do faithfully.** In `crates/rimap-server/tests/e2e.rs`, mirroring the existing `download_attachment` e2e (seed messages, build `AccountState`, dispatch a tool call; gate as the neighbours are):
  - **Happy path:** enable `export_messages` via `[security.tools]`, `search` a seeded folder for `(uids, uid_validity)`, call `export_messages`, assert the returned `path` exists, `sha256` matches the file bytes, `message_count` equals the requested count, and (separately) `git am` applies the file in a temp repo.
  - **UIDVALIDITY change via delete+recreate:** delete and recreate the seeded folder so its UIDVALIDITY changes, then call `export_messages` with the *stale* `expected_uidvalidity`; assert the preflight aborts with `UidValidityChanged` and writes no artifact (a real, deterministic Dovecot operation — distinct from the unreproducible mid-loop interleaving, which is covered by the `require_uidvalidity` unit test). Run with both `allow_partial` values.
  - **Partial success:** request a present UID plus a UID that does not exist in the folder with `allow_partial=true`; assert the present message is written to a `.partial.mbox`, the missing UID is in `failed[]` as `not_found`, and `allow_partial=false` instead returns an error with no artifact.
  - If the dovecot harness is feature/CI-only, gate these the same way; a **scriptable IMAP fake** for protocol-level fault injection is noted as optional follow-up test infrastructure, not built here.

Run (if the harness runs locally; else rely on CI):

```bash
just test-integration
```

Expected: the export e2e tests pass (or are collected to run in CI per the harness's gating).

- [ ] **Step 8: Deterministic handler-level fault tests via a source seam.** Pure helpers prove the *decisions*, but not that the *handler wiring* passes `expected_uidvalidity` into every body fetch and treats every body-fetch error as fatal-with-no-artifact. Close that with a minimal injection seam: define a small trait the handler depends on instead of calling `account.imap` directly —

```rust
#[cfg_attr(test, mockall::automock)] // or a hand-written fake under #[cfg(test)]
pub(crate) trait ExportSource {
    async fn fetch_sizes(
        &self, folder: &str, uids: &[Uid], expected_uidvalidity: u32,
    ) -> Result<Vec<(u32, Option<u32>)>, rimap_core::RimapError>; // (uid, RFC822.SIZE)
    async fn fetch_one_body(
        &self, folder: &str, uid: Uid, expected_uidvalidity: u32,
    ) -> Result<Vec<u8>, rimap_core::RimapError>;
}
```

Implement it for `AccountState` (delegating to `account.imap.fetch(..)` / `fetch_body(.., Some(expected))`), split `handle` into the thin public `handle(account, input)` and an inner `run_export(source: &impl ExportSource, dest, prefix, uids, expected, budget, allow_partial)`. Then add unit tests with a fake `ExportSource` that injects, per body fetch: a `UidValidityChanged`, a `UidValidityUnavailable`, a `Timeout`, and a `SizeLimit` — each asserting `run_export` returns `Err` and **wrote no artifact** (the temp dir is empty), under both `allow_partial` values. Also assert the happy fake yields the expected manifest and that `fetch_one_body` is always called with the same `expected`. (If `mockall` is not already a dev-dependency, a 30-line hand-written fake struct is fine and avoids a new dep — check `Cargo.lock` first.)

- [ ] **Step 9: Commit.**

```bash
git add -A
git commit -m "feat(export_messages): handler orchestration + injectable source seam"
```

---

## Task 8: Audit redaction test (result-summary parity)

**Scope correction (read first).** The audit `tool_end` envelope in
`crates/rimap-server/src/mcp/audit_envelope.rs` hardcodes `ResultSummary::default()`
(empty) and an empty `Provenance` for **every** tool — `emit_tool_end` takes only
`status`/`error_code`/`duration_ms`. No tool (including `download_attachment`) records
a path/sha256/UID result summary today, and `ResultSummary`'s fields are
`message_ids_returned` / `bytes_returned` / `truncated` / `security_warnings_emitted`
(no path/sha256/uid-list fields). Recording rich per-export provenance durably would
require extending the shared `ResultSummary` schema **and** plumbing handler results
through `run_with_audit_envelope` → `emit_tool_end` for all tools — cross-cutting audit
work, and exactly the kind of gold-plating the durability-tier trim rejected.

Therefore `export_messages` gets the **same audit treatment as every other tool**:
`tool_start`/`tool_end` with status/error/duration, redacted args (via the schema added
in Task 1, Step 8b), and the `arguments_hash_sha256`. The rich per-export detail
(ordered UID list, sizes, path, sha256) lives in the tool **response** returned to the
caller. Extending the durable audit `ResultSummary` is tracked as separate, cross-cutting
work (it must change the on-disk record format for all tools). This task only verifies
the redaction schema behaves correctly.

**Files:**
- Modify: `crates/rimap-audit/src/redact.rs` (test only)

- [ ] **Step 1: Write the failing redaction test.** In `crates/rimap-audit/src/redact.rs` tests (mirror the style of the existing per-tool schema tests), assert the `export_messages` schema redacts `dest_dir`/`filename` (path-ish, not verbatim), keeps `folder`/`expected_uidvalidity` recoverable, hashes `uids`, and forbids `password`/`token`:

```rust
    #[test]
    fn export_messages_schema_redacts_paths_keeps_identifiers() {
        let salt = RedactionSalt::for_test(); // use the same constructor neighbouring tests use
        let schema = ToolName::ExportMessages.redaction_schema();
        let args = serde_json::json!({
            "folder": "INBOX",
            "uids": [101, 102],
            "expected_uidvalidity": 12345,
            "dest_dir": "/home/user/secret-dir",
            "filename": "private-series",
            "password": "hunter2"
        });
        let out = Redactor::new(&schema, &salt).apply(&args);
        assert_eq!(out["folder"], serde_json::json!("INBOX"));
        assert_eq!(out["expected_uidvalidity"], serde_json::json!(12345));
        // Requested UID set is recorded verbatim (recoverable for audit).
        assert_eq!(out["uids"], serde_json::json!([101, 102]));
        // dest_dir / filename / password must not appear verbatim.
        let serialized = serde_json::to_string(&out).unwrap();
        assert!(!serialized.contains("/home/user/secret-dir"));
        assert!(!serialized.contains("private-series"));
        assert!(!serialized.contains("hunter2"));
    }
```

(Match `RedactionSalt`'s test constructor and the assertion idioms to the neighbouring schema tests already in this file — e.g. how `download_attachment`/`search` schema tests build a salt and call `Redactor`.)

- [ ] **Step 2: Run.**

```bash
cargo nextest run -p rimap-audit export_messages --locked
```

Expected: PASS.

- [ ] **Step 3: Commit.**

```bash
git add -A
git commit -m "test(export_messages): verify argument redaction schema"
```

---

## Task 9: Real-`git` mbox acceptance test (in-module unit test)

Guards against a custom splitter passing while real `git` rejects/wrongly-splits the mbox. Operates on `build_mbox` output — no IMAP. Lives as a unit test **inside** `export_messages.rs` so it calls the private `build_mbox` directly (no `pub` exposure, no feature gate). `git` is available in dev/CI; `tempfile` is already a `rimap-server` dev-dependency.

**Files:**
- Modify: `crates/rimap-server/src/tools/retrieval/export_messages.rs` (add a `#[cfg(test)]` module)

- [ ] **Step 1: Write the test.** Add to `export_messages.rs`:

```rust
#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod git_am_tests {
    use super::build_mbox;
    use std::process::Command;

    fn git(args: &[&str], cwd: &std::path::Path) -> std::process::Output {
        Command::new("git")
            .args(args)
            .current_dir(cwd)
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@t")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@t")
            .output()
            .expect("git runs")
    }

    fn patch(n: u32, body_extra: &str) -> Vec<u8> {
        // A minimal git-format-patch-style message: From/Subject/Date headers,
        // then a unified diff creating file_<n>.txt.
        format!(
            "From 0000000000000000000000000000000000000000 Mon Sep 17 00:00:00 2001\r\n\
             From: Dev <dev@example.com>\r\n\
             Date: Mon, 1 Jan 2024 0{n}:00:00 +0000\r\n\
             Subject: [PATCH {n}/2] add file {n}{body_extra}\r\n\
             \r\n\
             ---\r\n \
             file_{n}.txt | 1 +\r\n \
             1 file changed, 1 insertion(+)\r\n\
             \r\n\
             diff --git a/file_{n}.txt b/file_{n}.txt\r\n\
             new file mode 100644\r\n\
             index 0000000..0000001\r\n\
             --- /dev/null\r\n\
             +++ b/file_{n}.txt\r\n\
             @@ -0,0 +1 @@\r\n\
             +content {n}\r\n\
             -- \r\n\
             2.40.0\r\n"
        )
        .into_bytes()
    }

    #[test]
    fn git_am_applies_generated_mbox() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        assert!(git(&["init", "-q"], repo).status.success());

        // A From-line in the body content must survive escaping.
        let mbox = build_mbox(&[patch(1, "\r\nFrom the author: note"), patch(2, "")]);
        let mbox_path = repo.join("series.mbox");
        std::fs::write(&mbox_path, &mbox).unwrap();

        let out = git(&["am", mbox_path.to_str().unwrap()], repo);
        assert!(
            out.status.success(),
            "git am failed: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );

        let log = git(&["rev-list", "--count", "HEAD"], repo);
        let count = String::from_utf8_lossy(&log.stdout).trim().to_string();
        assert_eq!(count, "2", "expected 2 commits from a 2-patch series");
        assert!(repo.join("file_1.txt").exists());
        assert!(repo.join("file_2.txt").exists());
    }
}
```

(If `tempfile` is not yet a `rimap-server` dev-dependency, add it to `[dev-dependencies]` matching the workspace version.)

- [ ] **Step 2: Run.**

```bash
cargo nextest run -p rimap-server git_am_applies_generated_mbox --locked
```

Expected: PASS — `git am` applies both patches, 2 commits, both files present. (No feature flag needed — it is a plain unit test.)

- [ ] **Step 3: Commit.**

```bash
git add -A
git commit -m "test(export_messages): verify mbox applies with real git am"
```

---

## Task 10: Docs, final schema regen, full verification

**Files:**
- Modify: `docs/` tool reference + per-tool enable/disable section (find with `rg -l "download_attachment" docs/`).

- [ ] **Step 1: Enforce a private download root when the tool is enabled (config validation).** Convert the private-root requirement from documentation into a hard, fail-closed precondition. In the config validation flow (`crates/rimap-config/src/validate/` — mirror how existing path validations in `paths.rs`/`compose.rs` are wired), add: when `security.tools` resolves `export_messages` to `Allow`, verify the resolved download root is **not group- or world-writable** on Unix, else fail validation. Sketch:

```rust
#[cfg(unix)]
fn check_export_download_root_private(
    download_root: &std::path::Path,
) -> Result<(), ConfigError> {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = std::fs::metadata(download_root)
        .map_err(|e| ConfigError::invalid(format!(
            "cannot stat download root {}: {e}", download_root.display()
        )))?
        .permissions()
        .mode();
    if mode & 0o022 != 0 {
        return Err(ConfigError::invalid(format!(
            "export_messages is enabled but the download root {} is group/world-writable \
             (mode {:o}); export_messages requires a server-private download root",
            download_root.display(), mode & 0o777,
        )));
    }
    Ok(())
}
```

Call it from the validation entry point only when `export_messages` is allowed. (Match the actual `ConfigError` constructor and download-root field names in `model.rs`/`validate`.) Add a validation test: enabling `export_messages` with a `0o777` temp dir fails; with `0o700` passes; disabled tool skips the check. Then document the requirement + this enforcement in the tool docs (`docs/configuration.md` + tool reference) alongside the `search → read uid_validity → export_messages → git am <path>` flow, the required `expected_uidvalidity`, `allow_partial` semantics, and that it is **default-disabled** (`[security.tools]\nexport_messages = "allow"`). Do **not** build the dir-fd writer here (cross-cutting, out of scope per the spec's *Durability scope*).

- [ ] **Step 2: Regenerate all tool schemas** (catches any drift):

```bash
just regen-tool-schemas
git diff --stat crates/rimap-server/tests/fixtures/rimap-tool-schemas/
```

Expected: only `export_messages.schema.json` (new) and `search.schema.json` (uid_validity added) differ.

- [ ] **Step 3: Full workspace test + lint + deny.**

```bash
cargo nextest run --workspace --locked --no-tests=pass
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --check
cargo deny check
```

Expected: all green.

- [ ] **Step 4: Commit.**

```bash
git add -A
git commit -m "docs(export_messages): document tool, flow, and default-disable"
```

- [ ] **Step 5 (blocking gate):** Before merge, route the change past the `threat-model-reviewer`. The gate must explicitly rule on **four** recorded decisions, not rubber-stamp them (each is a deliberate scope call deferred here because it is cross-cutting / conflicts with the durability-tier trim, so the human gate is the right place to relitigate the risk tradeoff):
  1. The `Readonly` seat + default-deny `[security.tools]` gating for an unsanitized raw-export oracle.
  2. The **audit provenance gap** — durable audit records the *requested* UID set (verbatim) but the *actual* exported scope (succeeded/failed partition, artifact path, sha256, byte count) lives only in the tool response (spec *Audit contract* → "Accepted risk"). If not accepted, the prerequisite is the cross-cutting shared-`ResultSummary` extension across all tools, before this tool ships.
  3. The **sandbox-write containment posture** — the writer is path-based (shares `download_attachment`'s TOCTOU window). The controls are (a) the deployment trust-model requirement that the download root's write authority is *separated from the consuming agent* (dedicated OS user / ownership / ACL — a mode-bit check alone does not prove same-UID separation), and (b) the fail-closed group/world-writable config check (Step 1) as a backstop. If the reviewer judges that insufficient, the prerequisite is cross-cutting `openat`/`O_NOFOLLOW`/exclusive-create hardening of the shared sandbox writer for `download_attachment` + `export_messages` together.
  4. The **memory ceiling** — the effective bound is `max_total_bytes + max_fetch_body_bytes` (one buffered body before the running check trips), not exactly `max_total_bytes`, the same single-body bound the existing fetch paths have (spec *Resource bounds* → "Worst-case memory"). Pinning it exactly requires re-introducing the trimmed read-level `body_limit_bytes` literal limit. Accept the documented bound or require the streaming read path.
  Record the reviewer's decision on each in the PR.

---

## Self-Review notes (spec coverage)

- Required `expected_uidvalidity` + search same-op `uid_validity` → Tasks 1 (input), 6 (search + UIDVALIDITY-guarded `fetch_body`), 7 (preflight + per-body guard, race e2e).
- `allow_partial` safe-by-default, `complete`/`path`/`partial_path` → Tasks 1, 5, 7.
- byte-level mboxrd framing + real-`git` test → Tasks 2, 9.
- aggregate `max_total_bytes` clamp + **framed-size** budget enforcement → Tasks 4, 7 (raw early-abort + authoritative framed check; overflow e2e).
- default-deny gate + annotation hints → Task 1 (matrix + tests + hints).
- argument redaction (compile-forced) → Task 1 Step 8b (`uids` verbatim `U64Array`, so
  the requested scope is durably auditable); verified in Task 8.
- audit *result* provenance (succeeded/failed partition, path, sha256) lives in the tool
  **response**, not the durable audit summary: no tool records a non-empty
  `ResultSummary` today, so durable rich provenance is out of scope (cross-cutting audit
  work) — consistent with the durability-tier trim. The requested UID *set* IS durable
  (redacted args). Recorded as an explicit accepted risk for the threat-model gate.
- sandbox containment → Task 7 reuses `resolve_dest_dir`/`write_attachment` (parity with `download_attachment`), and Task 10 Step 1 adds a **fail-closed private-download-root config check** as the enforced control (group/world-writable root rejects enabling the tool). Per-tool dir-fd hardening is out of scope (cross-cutting).
- security-critical fault paths are covered at three levels because the Dovecot harness
  cannot reliably inject protocol faults: (a) **pure-function** unit tests of the decisions
  (`require_uidvalidity`, `classify_uid`, `build_mbox` sizes, `plan_outcome`) — Tasks
  2/4/5/6; (b) **handler-wiring** unit tests via an injectable `ExportSource` seam that
  feeds per-body `UidValidityChanged`/`UidValidityUnavailable`/`Timeout`/`SizeLimit` and
  asserts fatal-with-no-artifact (Task 7 Step 8); (c) **Dovecot** happy-path +
  delete/recreate UIDVALIDITY change + missing-UID partial (Task 7 Step 7).
- **Durability deliberately out of scope** (per spec's *Durability scope*): no WAL/lease/recovery/dir-fd tasks — matches the trimmed design.
- **Three scope decisions deferred to the threat-model gate** (Task 10 Step 5): posture/gating, durable audit provenance gap, sandbox-write containment posture. These are deliberate, recorded holds (cross-cutting or conflicting with the user's durability-tier trim), not oversights.
