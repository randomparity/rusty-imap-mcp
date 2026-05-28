# Extend shared ResultSummary for durable per-tool result provenance (#316)

## Context

`emit_tool_end` hardcodes `ResultSummary::default()` for every tool
(`crates/rimap-server/src/mcp/audit_envelope.rs`). The shared `ResultSummary`
(`crates/rimap-audit/src/record/mod.rs`) carries `message_ids_returned`,
`bytes_returned`, `truncated`, `security_warnings_emitted` — none of which
cover the *artifact* a write-producing tool emits. So for `export_messages`
the **requested** UID set is durably recorded (redacted args), but the
**actual exported scope** (succeeded/failed UID partition, artifact path,
sha256, byte count) lives only in the tool *response*, not the durable audit
record. `download_attachment` has the same gap.

## Threat

Repudiation / post-incident forensics (STRIDE-R). Under `allow_partial=true`
the actual exported scope is not durably reconstructable from the audit log.

## Acceptance (from #316)

- Durable audit records the succeeded/failed UID partition, artifact path,
  sha256, and byte count for `export_messages`.
- The shared `ResultSummary` extension + plumbing is applied consistently
  across tools (at minimum `download_attachment` and `export_messages`).

## Design

### 1. Extend `ResultSummary` (rimap-audit), backward-compatibly

Add five fields, each `#[serde(default, skip_serializing_if = ...)]` so a tool
that does not populate them serializes **byte-identically to today** — the
on-disk format changes *only* for records that actually carry provenance
(export / download), and existing tool_end assertions/round-trips are
unaffected:

```rust
/// Path of a durable artifact this tool wrote (download/export), if any.
#[serde(default, skip_serializing_if = "Option::is_none")]
pub artifact_path: Option<String>,
/// SHA-256 (hex) of the written artifact.
#[serde(default, skip_serializing_if = "Option::is_none")]
pub artifact_sha256: Option<String>,
/// Byte length of the written artifact.
#[serde(default, skip_serializing_if = "Option::is_none")]
pub artifact_bytes: Option<u64>,
/// UIDs actually exported (export_messages succeeded partition).
#[serde(default, skip_serializing_if = "Vec::is_empty")]
pub uids_exported: Vec<u32>,
/// Requested UIDs that were not exported (export_messages failed partition).
#[serde(default, skip_serializing_if = "Vec::is_empty")]
pub uids_failed: Vec<u32>,
```

Consistent with the existing pattern where not every tool populates every
field (`message_ids_returned` is search/fetch-specific).

### 2. Derive the summary from the result and plumb it to `emit_tool_end`

The body future already returns the tool's serialized `ToolResponse`
(`serde_json::Value` with a top-level `meta`). `run_with_audit_envelope`
computes the summary from that result and passes it to `emit_tool_end`
(replacing the hardcoded default):

- New `fn result_provenance(tool: ToolName, value: &serde_json::Value) ->
  ResultSummary` (a small dedicated module). It matches on `tool`:
  - `ExportMessages`: `artifact_path = meta.path ∨ meta.partial_path`,
    `artifact_sha256 = meta.sha256`, `artifact_bytes = meta.total_bytes`,
    `uids_exported = meta.succeeded[].uid`, `uids_failed = meta.failed[].uid`.
  - `DownloadAttachment`: `artifact_path = meta.path`,
    `artifact_sha256 = meta.sha256`, `artifact_bytes = meta.size_bytes`.
  - all other tools: `ResultSummary::default()` (unchanged behavior).
  Extraction is defensive (`get().and_then()`), so a missing field yields
  `None`/empty rather than a panic.
- `emit_tool_end` gains a `result_summary: ResultSummary` parameter.
  `run_with_audit_envelope` passes the derived summary on `Ok`, and
  `ResultSummary::default()` on `Err` (a failed call wrote no artifact).
- The cancellation drop-guard (`AuditEnvelopeGuard`) keeps `default()`: a call
  cancelled before completion produced no result.

### Why derive from the result `Value` (not thread a typed summary)

`dispatch_tool` returns a uniform `serde_json::Value`; threading a typed
`ResultSummary` out would touch all 24 dispatch arms and the envelope
signature. The result already flows through the envelope as a `Value`, so
deriving there is localized and is exactly "plumb handler results through
`run_with_audit_envelope` → `emit_tool_end`." The coupling to meta field
names is bounded: the per-tool output **schema fixtures** pin those names, and
the extraction unit tests build their input by serializing a real
`ExportMessagesMeta` / `DownloadAttachmentMeta`, so a field rename breaks the
test at compile time.

### Privacy / redaction

`ResultSummary` is, by design, the **un-redacted result-provenance sink** of
the audit record: arguments flow through `Redactor`, but `ResultSummary` is
serialized verbatim (it already stores raw RFC822 `message_ids_returned`). The
new fields record no data not already durable: the requested UIDs are already
in the redacted args (`Verbatim(U64Array)`), the artifact path lives under the
operator-controlled download root and embeds only the already-recorded
sanitized filename prefix, and the sha256 is non-sensitive. No redaction-schema
change is needed.

Because this struct bypasses redaction, **any future field added here must be
consciously reviewed for sensitivity** — a doc note on the struct will say so.

`artifact_path` is recorded **absolute** on purpose: it matches what the tool
returns to the caller and maximizes forensic value (which file, where). This
is a deliberate, minor directory-structure disclosure in the audit log, not an
accident; it is not switched to a download-root-relative path (which would
lose where-it-landed forensics).

`ResultSummary` derives `Serialize`/`Deserialize` but **not** `JsonSchema`, so
it is not part of any published tool schema and the schemars→fixture rule does
not apply to it. The round-trip and extraction unit tests (below) are the
guard for these fields, not schema fixtures.

## Execution tasks (TDD)

1. Extend `ResultSummary` with the five `skip_serializing_if` fields; update
   the one full-literal test in `record/mod.rs` (`..Default::default()`); add
   a test asserting empty new fields are omitted from JSON and populated ones
   round-trip.
2. Add `result_provenance(tool, &Value) -> ResultSummary` with unit tests that
   serialize real `ExportMessagesMeta` (complete, partial, zero-success) and
   `DownloadAttachmentMeta`, asserting the extracted fields; and that an
   unrelated tool yields `default()`.
3. Thread it through: `emit_tool_end` takes the summary;
   `run_with_audit_envelope` derives it on `Ok`, `default()` on `Err`;
   guard/cancellation path unchanged.
4. Verify: `clippy -D warnings`, `fmt`, `cargo deny`, targeted `rimap-audit` +
   `rimap-server` tests, and tool-schema regen (no tool *input/meta* doc
   changed, so no fixture drift expected — confirm).

## Out of scope

- Populating `message_ids_returned` / `bytes_returned` / `truncated` /
  `security_warnings_emitted` for tools that currently leave them default —
  this issue is specifically the artifact-provenance gap for the
  write-producing tools.
- Threading a typed summary through `dispatch_tool` (deferred; the JSON
  derivation is sufficient and far less invasive).
