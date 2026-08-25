# Published Non-Exhaustive Records Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make all 27 remaining public named-field data records in the six issue #835 library crates non-exhaustive before v0.3.0 without changing runtime values, serialization, schemas, or wire behavior.

**Architecture:** Apply `#[non_exhaustive]` crate family by crate family so each commit compiles independently. Preserve downstream construction through an existing constructor or `Default` plus explicit field assignment; add a narrow public constructor only for a compiler-proven caller with no valid existing route. Representative compile-fail doctests cover each crate family, and one downstream cargo-check harness asserts rustc E0639 for plain literals and functional-update syntax.

**Tech Stack:** Rust 1.94.0 development toolchain, Rust 1.88.0 MSRV, Cargo/rustdoc, cargo-nextest, ast-grep, just, cargo-semver-checks.

**Spec:** `docs/superpowers/specs/2026-08-24-issue-835-non-exhaustive-records-design.md`

## Global Constraints

- Govern the implementation by `docs/ADR/0026-published-data-records-non-exhaustive.md`.
- Change exactly the 27 records in the spec inventory; tuple newtypes, tuple error wrappers, `CircuitBreaker<C>`, and published `rimap-server` `*Meta`/`*Input` records remain exhaustive.
- Add no dependency, feature flag, wire field, schema field, serialization change, compatibility shim, builder, or blanket `Default` implementation.
- Existing construction routes come first. New constructors initialize only fields with a documented meaningful empty value and accept every field without one.
- Preserve every rewritten value field-for-field; tests compare constructor results with in-crate legacy literals.
- Accumulate E0639 fallout over repeated `cargo check --workspace --all-targets --all-features --locked` runs in `target/quest-835/e0639-fallout.tsv`. Each sorted unique row is `type<TAB>relative_path:line<TAB>plain-literal|functional-update|pattern`; merge a batch before migrating it.
- Reconcile every fallout row with a migrated site and every new constructor with a forcing row. Copy the sorted union and reconciliation into the pull request's `WORK:REVIEW` evidence.
- Regenerate tool schemas only through `just regen-tool-schemas`; an attribute-only schema diff is a defect to diagnose, not accept.
- The two hook-discovered EOF repairs are already isolated in commit `b903b2bd`; do not broaden them.
- Public constructors require rustdoc and `#[must_use]`. The nine-argument `ConnectionConfig::new` is the sole justified `clippy::too_many_arguments` expectation because invalid defaults would lose operator configuration.

---

### Task 1: Core, authorization, and configuration records

**Files:**

- Modify: `crates/rimap-core/src/folder_name.rs`
- Modify: `crates/rimap-core/src/tool.rs`
- Modify: `crates/rimap-authz/src/breaker.rs`
- Modify: `crates/rimap-config/src/credential.rs`
- Modify: `crates/rimap-server/src/main.rs`

**Interfaces:**

- Consumes: existing `BreakerConfig::default_spec()`, `FallbackMode`, and `Protocol`.
- Produces: `ResolutionPolicy::new(fallback_mode: FallbackMode, protocol: Protocol) -> ResolutionPolicy`; non-exhaustive `FolderNameError`, `ToolAnnotationHints`, `BreakerConfig`, and `ResolutionPolicy`.

- [ ] **Step 1: Add representative downstream compile-fail contracts**

Add `compile_fail,E0639` examples to the public docs for `ToolAnnotationHints`, `BreakerConfig`, and `ResolutionPolicy`. The examples must use the published paths and complete expressions:

```rust
let _ = rimap_core::tool::ToolAnnotationHints {
    read_only: true,
    destructive: false,
    idempotent: true,
    open_world: true,
};
```

```rust
let _ = rimap_authz::BreakerConfig {
    error_threshold: 1,
    ..rimap_authz::BreakerConfig::default_spec()
};
```

```rust
let _ = rimap_config::ResolutionPolicy {
    fallback_mode: rimap_config::FallbackMode::KeyringOnly,
    protocol: rimap_config::Protocol::Smtp,
};
```

- [ ] **Step 2: Run the doctests and observe the red contract**

Run:

```bash
cargo test --doc -p rimap-core -p rimap-authz -p rimap-config --locked
```

Expected: each new `compile_fail` example fails with “Test compiled successfully, but it's marked compile_fail” because the records are still exhaustive.

- [ ] **Step 3: Add the constructor-equivalence test before implementation**

In `crates/rimap-config/src/credential.rs`, add `resolution_policy_new_preserves_fields`. It calls `ResolutionPolicy::new(FallbackMode::KeyringOnly, Protocol::Smtp)` and asserts both fields equal those values, pinning the protocol used by the sole external SMTP caller.

Run:

```bash
cargo nextest run -p rimap-config -E 'test(resolution_policy_new_preserves_fields)'
```

Expected: compile failure E0599 because `ResolutionPolicy::new` does not exist.

- [ ] **Step 4: Apply attributes and the minimal constructor**

Add `#[non_exhaustive]` to exactly:

```text
rimap-core: FolderNameError, ToolAnnotationHints
rimap-authz: BreakerConfig
rimap-config: ResolutionPolicy
```

Add this API shape in `credential.rs`:

```rust
impl ResolutionPolicy {
    /// Construct a credential resolution policy.
    ///
    /// # Arguments
    ///
    /// * `fallback_mode` - Whether fallback credential sources are permitted.
    /// * `protocol` - The protocol whose credential is being resolved.
    #[must_use]
    pub const fn new(fallback_mode: crate::model::FallbackMode, protocol: Protocol) -> Self {
        Self {
            fallback_mode,
            protocol,
        }
    }
}
```

- [ ] **Step 5: Capture the first normalized E0639 batch**

Run the full command before migrating the external literals:

```bash
mkdir -p target/quest-835
cargo check --workspace --all-targets --all-features --locked
```

Expected: non-zero with E0639 at the external `ResolutionPolicy` and
`BreakerConfig` expressions. Before editing those sites, add each unique
`type<TAB>relative_path:line<TAB>construction-form` row to
`target/quest-835/e0639-fallout.tsv`, then normalize it:

```bash
sort -u target/quest-835/e0639-fallout.tsv -o target/quest-835/e0639-fallout.tsv
```

- [ ] **Step 6: Migrate the two external literals in `rimap-server`**

Replace the `ResolutionPolicy` literal in `build_smtp_client` with
`ResolutionPolicy::new(acfg.fallback_mode, Protocol::Smtp)`.

Replace the
`BreakerConfig { error_threshold, window, ..BreakerConfig::default_spec() }`
expression with:

```rust
let mut breaker_cfg = BreakerConfig::default_spec();
breaker_cfg.error_threshold = acfg.limits.circuit_breaker_error_threshold;
breaker_cfg.window =
    Duration::from_secs(u64::from(acfg.limits.circuit_breaker_window_seconds));
```

No field value changes. Literals and destructures inside the defining crates
remain valid and stay unchanged.

- [ ] **Step 7: Verify the task and close this crate-family batch**

Run:

```bash
cargo test --doc -p rimap-core -p rimap-authz -p rimap-config --locked
cargo nextest run -p rimap-config -E 'test(resolution_policy_new_preserves_fields)'
cargo check --workspace --all-targets --all-features --locked
```

If the full check exposes another E0639 for these four records, merge its row
before migration and repeat. Expected final result: all commands green, with
no unrecorded E0639.

- [ ] **Step 8: Commit**

```bash
just fmt
git add crates/rimap-core/src/folder_name.rs crates/rimap-core/src/tool.rs \
  crates/rimap-authz/src/breaker.rs crates/rimap-config/src/credential.rs \
  crates/rimap-server/src/main.rs
git commit -m "feat: protect core configuration records"
```

---

### Task 2: Content-pipeline records

**Files:**

- Modify: `crates/rimap-content/src/html/pipeline.rs`
- Modify: `crates/rimap-content/src/lib.rs`
- Modify: `crates/rimap-content/src/parse/raw_parts.rs`
- Modify: `crates/rimap-content/src/parse/threading.rs`
- Modify: `crates/rimap-content/src/unicode.rs`

**Interfaces:**

- Consumes: existing in-crate literals and parsing/sanitization tests.
- Produces: non-exhaustive `HtmlResult`, `OutboundHtml`, `RawPart`, `ThreadingHeaders`, and `FilterResult`; no new constructor.

- [ ] **Step 1: Add a downstream compile-fail contract**

Add this `compile_fail,E0639` example to `OutboundHtml`'s public docs:

```rust
let _ = rimap_content::OutboundHtml {
    body_html: String::new(),
    warnings: Vec::new(),
};
```

The expression must compile before the attribute and fail only because of E0639 afterward.

- [ ] **Step 2: Observe the red doctest**

Run:

```bash
cargo test --doc -p rimap-content --locked
```

Expected: the new example reports that code marked `compile_fail` compiled successfully.

- [ ] **Step 3: Apply the five attributes**

Add `#[non_exhaustive]` to `HtmlResult`, `OutboundHtml`, `RawPart`, `ThreadingHeaders`, and `FilterResult`. Add no constructor: all workspace literals are in `rimap-content`, and the defining crate remains allowed to construct non-exhaustive records directly.

- [ ] **Step 4: Verify behavior and the contract**

Run:

```bash
cargo test --doc -p rimap-content --locked
cargo nextest run -p rimap-content
cargo check --workspace --all-targets --all-features --locked
```

Expected: the doctest observes E0639, all parser/sanitizer/Unicode/HTML tests
pass unchanged, and the full check is green. If the full check exposes an
unexpected external content-record literal, merge its normalized TSV row
before migrating it and rerun.

- [ ] **Step 5: Commit**

```bash
just fmt
git add crates/rimap-content/src/html/pipeline.rs crates/rimap-content/src/lib.rs \
  crates/rimap-content/src/parse/raw_parts.rs \
  crates/rimap-content/src/parse/threading.rs crates/rimap-content/src/unicode.rs
git commit -m "feat: protect content pipeline records"
```

---

### Task 3: SMTP records and envelope callers

**Files:**

- Modify: `crates/rimap-smtp/src/client.rs`
- Modify: `crates/rimap-smtp/src/testing.rs`
- Modify: `crates/rimap-smtp/tests/real_socket.rs`
- Modify: `crates/rimap-server/src/boot/registry.rs`
- Modify: `crates/rimap-server/src/tools/compose/forward.rs`
- Modify: `crates/rimap-server/src/tools/compose/send_email.rs`

**Interfaces:**

- Consumes: existing `SmtpSender::send_raw` and Mailpit test behavior.
- Produces: `SendEnvelope::new(from: String, to: Vec<String>) -> SendEnvelope`; non-exhaustive `SendEnvelope` and feature-gated `CapturedSend`.

- [ ] **Step 1: Add red compile and constructor contracts**

Add a `compile_fail,E0639` example to `SendEnvelope`:

```rust
let _ = rimap_smtp::SendEnvelope {
    from: "sender@example.test".to_owned(),
    to: vec!["recipient@example.test".to_owned()],
};
```

Add `send_envelope_new_preserves_fields` beside the existing client tests. It compares both fields of `SendEnvelope::new(from.clone(), to.clone())` with `from` and `to`.

- [ ] **Step 2: Observe both failures**

Run:

```bash
cargo test --doc -p rimap-smtp --locked
cargo nextest run -p rimap-smtp -E 'test(send_envelope_new_preserves_fields)'
```

Expected: the doctest says the compile-fail example compiled; the unit test fails to compile with E0599.

- [ ] **Step 3: Apply attributes and add the exact constructor**

Add `#[non_exhaustive]` to `SendEnvelope` and `CapturedSend`. Add:

```rust
impl SendEnvelope {
    /// Construct an SMTP envelope.
    ///
    /// # Arguments
    ///
    /// * `from` - Envelope sender address.
    /// * `to` - Envelope recipient addresses.
    #[must_use]
    pub fn new(from: String, to: Vec<String>) -> Self {
        Self { from, to }
    }
}
```

Do not add a constructor for `CapturedSend`; the public test-support sender produces it and no external workspace literal exists.

- [ ] **Step 4: Capture SMTP E0639 before migration**

Run:

```bash
cargo check --workspace --all-targets --all-features --locked
```

Expected: E0639 at each external `SendEnvelope` literal. Merge every site into
`target/quest-835/e0639-fallout.tsv` and run the plan's `sort -u` command
before editing those files.

- [ ] **Step 5: Migrate external envelope literals**

Use `SendEnvelope::new(from, to)` in `real_socket.rs`, `boot/registry.rs`,
`compose/forward.rs`, and `compose/send_email.rs`. Preserve address order and
owned-string conversion exactly. Literals inside `rimap-smtp` remain legal and
need no migration.

- [ ] **Step 6: Verify the SMTP path and exposed targets**

Run:

```bash
cargo test --doc -p rimap-smtp --locked
cargo nextest run -p rimap-smtp -E 'test(send_envelope_new_preserves_fields)'
cargo check -p rimap-smtp --all-targets --features test-support --locked
cargo nextest run -p rimap-server -E 'test(build_envelope) | test(forward)'
cargo check --workspace --all-targets --all-features --locked
```

Merge and migrate any newly exposed `SendEnvelope` E0639 before repeating.
Expected: all commands green and every SMTP fallout site retained.

- [ ] **Step 7: Commit**

```bash
just fmt
git add crates/rimap-smtp/src/client.rs crates/rimap-smtp/src/testing.rs \
  crates/rimap-smtp/tests/real_socket.rs crates/rimap-server/src/boot/registry.rs \
  crates/rimap-server/src/tools/compose/forward.rs \
  crates/rimap-server/src/tools/compose/send_email.rs
git commit -m "feat: protect SMTP data records"
```

---

### Task 4: IMAP connection and operation-outcome records

**Files:**

- Modify: `crates/rimap-imap/src/connection/mod.rs`
- Modify: `crates/rimap-imap/src/ops/delete.rs`
- Modify: `crates/rimap-imap/src/ops/search.rs`
- Modify: `crates/rimap-imap/src/tls.rs`
- Modify: `crates/rimap-fake-imap/src/fake_imap.rs`
- Modify: `crates/rimap-imap/tests/integration/dovecot.rs`
- Modify: `crates/rimap-imap/tests/integration/proton.rs`
- Modify: `crates/rimap-imap/tests/integration/support/container.rs`
- Modify: `crates/rimap-server/src/boot/registry.rs`
- Modify: `crates/rimap-server/src/test_support.rs`
- Modify: `crates/rimap-server/tests/dispatch/server_capabilities.rs`
- Modify: `crates/rimap-server/tests/e2e/e2e.rs`
- Modify: `crates/rimap-server/tests/e2e/e2e_smtp.rs`
- Modify: `crates/rimap-server/tests/e2e/e2e_smtp_real.rs`
- Modify: `crates/rimap-server/tests/wire/e2e_wire.rs`
- Modify: `crates/rimap-server/tests/wire/e2e_wire_chaos.rs`
- Modify: `crates/rimap-server/tests/wire/e2e_wire_destructive.rs`
- Modify: `crates/rimap-server/tests/wire/e2e_wire_fault_injection.rs`

**Interfaces:**

- Consumes: exact validated account fields and existing TLS/operation behavior.
- Produces: `ConnectionConfig::new(account_id, host, port, encryption, username, connect_timeout, command_timeout, max_fetch_body_bytes, max_append_bytes)` with `account` derived from `account_id` and `pinned_fingerprint` initialized to `None`; non-exhaustive `ConnectionConfig`, `DeleteOutcome`, `SearchOutcome`, and `TlsConfigBundle`.

- [ ] **Step 1: Add red compile and equivalence contracts**

Add a `compile_fail,E0639` example to `SearchOutcome` using `uids: Vec::new()` and `uidvalidity: None`.

Add `connection_config_new_preserves_required_fields_and_defaults_optionals` in `connection/mod.rs`. Construct one default-account value through the proposed API, construct the legacy literal in the same module, and compare all eleven fields individually, including `account == None` and `pinned_fingerprint == None`. Add `connection_config_new_derives_named_account_attribution` to prove a named `AccountId` produces the matching audit-account label.

- [ ] **Step 2: Observe the failures**

Run:

```bash
cargo test --doc -p rimap-imap --locked
cargo nextest run -p rimap-imap -E 'test(connection_config_new_preserves_required_fields_and_defaults_optionals)'
```

Expected: the doctest compiles unexpectedly and the unit test fails with E0599.

- [ ] **Step 3: Apply attributes and add `ConnectionConfig::new`**

Add `#[non_exhaustive]` to `ConnectionConfig`, `DeleteOutcome`, `SearchOutcome`, and `TlsConfigBundle`.

Implement the constructor with these exact arguments and field assignments:

```rust
#[expect(
    clippy::too_many_arguments,
    reason = "all required connection values must remain explicit; invalid defaults would discard operator configuration"
)]
#[must_use]
pub fn new(
    account_id: rimap_core::account::AccountId,
    host: String,
    port: u16,
    encryption: ImapEncryption,
    username: String,
    connect_timeout: Duration,
    command_timeout: Duration,
    max_fetch_body_bytes: u64,
    max_append_bytes: u64,
) -> Self {
    let account = account_id
        .as_optional()
        .map(rimap_core::account::AccountId::as_str)
        .map(str::to_owned);
    Self {
        account,
        account_id,
        host,
        port,
        encryption,
        username,
        pinned_fingerprint: None,
        connect_timeout,
        command_timeout,
        max_fetch_body_bytes,
        max_append_bytes,
    }
}
```

Document every argument. Do not default a timeout, byte limit, host, username, port, encryption mode, or account identifier.

- [ ] **Step 4: Capture the first connection E0639 batch**

Run before changing any external literal:

```bash
cargo check --workspace --all-targets --all-features --locked
```

Merge each reported `ConnectionConfig` row into
`target/quest-835/e0639-fallout.tsv` and normalize the file before migration.
The first red target may hide dependent integration targets.

- [ ] **Step 5: Migrate each captured connection batch**

At every captured external `ConnectionConfig` literal:

1. Pass the nine required fields to `ConnectionConfig::new` in declaration
   order.
2. Let the constructor derive `account` from `account_id`. Retain an explicit
   assignment only if a legacy expression differs from that derivation.
3. Copy the exact prior `pinned_fingerprint` expression after construction
   unless it was literally `None`; this includes `acfg.tls_fingerprint` in
   `build_account_connection`.
4. Preserve cloned versus moved values, timeout values, byte limits, account
   labels, and certificate fingerprints exactly.

Rerun the full all-target/all-feature check. Before migrating any newly exposed
E0639, merge its normalized row. Repeat until no E0639 remains for these four
records; Task 5 may then expose its separate record family.

- [ ] **Step 6: Verify connection behavior**

Run:

```bash
cargo test --doc -p rimap-imap --locked
cargo nextest run -p rimap-imap -E 'test(connection_config_new)'
just check
```

Expected: the compile contract and equivalence test pass; all non-container
targets compile.

- [ ] **Step 7: Commit**

```bash
just fmt
git add crates/rimap-imap/src/connection/mod.rs crates/rimap-imap/src/ops/delete.rs \
  crates/rimap-imap/src/ops/search.rs crates/rimap-imap/src/tls.rs \
  crates/rimap-fake-imap/src/fake_imap.rs \
  crates/rimap-imap/tests/integration/dovecot.rs \
  crates/rimap-imap/tests/integration/proton.rs \
  crates/rimap-imap/tests/integration/support/container.rs \
  crates/rimap-server/src/boot/registry.rs crates/rimap-server/src/test_support.rs \
  crates/rimap-server/tests/dispatch/server_capabilities.rs \
  crates/rimap-server/tests/e2e/e2e.rs \
  crates/rimap-server/tests/e2e/e2e_smtp.rs \
  crates/rimap-server/tests/e2e/e2e_smtp_real.rs \
  crates/rimap-server/tests/wire/e2e_wire.rs \
  crates/rimap-server/tests/wire/e2e_wire_chaos.rs \
  crates/rimap-server/tests/wire/e2e_wire_destructive.rs \
  crates/rimap-server/tests/wire/e2e_wire_fault_injection.rs
git commit -m "feat: protect IMAP connection records"
```

---

### Task 5: IMAP data records and remaining fallout

**Files:**

- Modify: `crates/rimap-imap/src/types.rs`
- Modify: `crates/rimap-imap/src/ops/append.rs`
- Modify: `crates/rimap-imap/src/ops/fetch.rs`
- Modify: `crates/rimap-imap/src/ops/folders.rs`
- Modify: `crates/rimap-imap/src/ops/move_message.rs`
- Modify: `crates/rimap-imap/src/special_use.rs`
- Modify: `crates/rimap-imap/tests/adversarial_imap.rs`
- Modify: `crates/rimap-imap/tests/integration/dovecot.rs`
- Modify: `crates/rimap-imap/tests/integration/proton.rs`
- Modify: `crates/rimap-server/src/boot/discovery.rs`
- Modify: `crates/rimap-server/src/tools/compose/create_draft.rs`
- Modify: `crates/rimap-server/src/tools/admin/list_folders.rs`
- Modify: `crates/rimap-server/src/tools/mailbox/delete_message.rs`
- Modify: `crates/rimap-server/src/tools/mailbox/folder_management.rs`
- Modify: `crates/rimap-server/src/tools/mailbox/labels.rs`
- Modify: `crates/rimap-server/src/tools/retrieval/download_attachment.rs`
- Modify: `crates/rimap-server/src/tools/retrieval/export_messages.rs`
- Modify: `crates/rimap-server/src/tools/retrieval/list_attachments.rs`
- Modify: `crates/rimap-server/src/tools/retrieval/search.rs`
- Modify: `crates/rimap-server/src/tools/fetch_by_uid.rs`
- Modify: `crates/rimap-server/tests/e2e/e2e_smtp_real.rs`

**Interfaces:**

- Consumes: existing `StructuredQuery::default()`, `FetchSpec::default()`, and `StatusItems::all()`.
- Produces: `Folder::new(name)`, `Envelope::empty()`, `Address::empty()`, `HeaderSearch::new(name, value)`, and `FetchedMessage::new(uid)`; twelve non-exhaustive IMAP records.

- [ ] **Step 1: Add red compile and constructor contracts**

Add a `compile_fail,E0639` functional-update example to `FetchSpec`:

```rust
let _ = rimap_imap::types::FetchSpec {
    bodystructure: true,
    ..rimap_imap::types::FetchSpec::default()
};
```

Add in-crate equivalence tests for:

```text
Folder::new(name): empty attributes, no delimiter, no special use
Envelope::empty(): absent date/subject/addresses/message-id and empty reply_to/to/cc/bcc vectors
Address::empty(): all four optional fields absent
HeaderSearch::new(name, value): both fields preserved
FetchedMessage::new(uid): uid preserved and every optional field, including flags, absent
```

Each test creates the expected value with the legacy literal inside `rimap-imap` and compares every field. Do not add `Default` solely to make these tests shorter.

- [ ] **Step 2: Observe the red contracts**

Run:

```bash
cargo test --doc -p rimap-imap --locked
cargo nextest run -p rimap-imap -E 'test(record_constructor)'
```

Name each equivalence test with the common `record_constructor_` prefix. Expected: the doctest compiles unexpectedly and the constructor tests fail with E0599.

- [ ] **Step 3: Apply all twelve attributes**

Add `#[non_exhaustive]` to exactly:

```text
Folder, StatusItems, FolderStatus, SelectedFolder, MoveResult, AppendResult,
Envelope, Address, HeaderSearch, StructuredQuery, FetchSpec, FetchedMessage
```

The operation modules continue to use direct literals because they define these types in the same crate.

- [ ] **Step 4: Add only the five proven constructor routes**

Implement and document:

```rust
pub fn Folder::new(name: String) -> Self
pub fn Envelope::empty() -> Self
pub fn Address::empty() -> Self
pub fn HeaderSearch::new(name: String, value: String) -> Self
pub fn FetchedMessage::new(uid: Uid) -> Self
```

Use these exact defaults:

```text
Folder: attributes = [], delimiter = None, special_use = None
Envelope: scalar option fields = None, address vectors = []
Address: every option field = None
FetchedMessage: every option field, including flags, = None
```

Mark each constructor `#[must_use]`. Do not add constructors for records produced only by `rimap-imap`.

- [ ] **Step 5: Capture the initial IMAP data-record batch**

Before changing an external literal, run:

```bash
cargo check --workspace --all-targets --all-features --locked
```

Merge every reported IMAP data-record E0639 into
`target/quest-835/e0639-fallout.tsv`, normalize it with `sort -u`, and only then
start migration.

- [ ] **Step 6: Migrate existing-route callers**

For every captured external `StructuredQuery` and `FetchSpec` literal, start
with `Default::default()` and explicitly assign every field whose legacy value
was non-default.

For each captured external partial `StatusItems` literal, start with
`StatusItems::all()` and then assign all five flags (`messages`, `recent`,
`uid_next`, `uid_validity`, `unseen`) to the exact legacy values. This full
assignment is load-bearing: leaving an `all()` flag unchanged would silently
widen the IMAP STATUS selector.

Keep the existing in-crate empty-selector literal and its rejection test; do
not create `StatusItems::none()`.

- [ ] **Step 7: Migrate constructor-route callers**

Use `Folder::new`, `Envelope::empty`, `Address::empty`, `HeaderSearch::new`,
and `FetchedMessage::new` only at captured sites, then assign every legacy
non-default optional/vector field. Preserve:

```text
folder attributes, delimiter, and special-use classification
address ADL/name/mailbox/host bytes
envelope dates, raw subjects, all address lists, in-reply-to, and message-id
message flags, size, internal date, envelope, headers, and body payloads
header-search name/value case and ownership
```

- [ ] **Step 8: Accumulate fallout until the complete check is green**

Run the full command again. Merge each newly exposed E0639 batch before
migration, apply the same rules, and repeat until this succeeds:

```bash
cargo check --workspace --all-targets --all-features --locked
```

Then reconcile every TSV row with a migrated site and each of the five new
constructors with at least one forcing row. Remove any constructor without a
forcing row.

- [ ] **Step 9: Verify constructors, queries, and folder rendering**

Run:

```bash
cargo test --doc -p rimap-imap --locked
cargo nextest run -p rimap-imap -E 'test(record_constructor) | test(status_items)'
cargo nextest run -p rimap-server -E 'test(no_warnings_for_clean_folder_name) | test(non_empty_fetch_returns_first_message) | test(format_search_result_populates_cc_from_envelope)'
```

Expected: the IMAP filter runs non-zero constructor/status coverage and the
server filter reports exactly three tests run: one folder, one fetch, and one
search-format case. Compile contracts observe E0639, constructor equivalence
passes, STATUS strings are unchanged, and the three server behaviors pass.

- [ ] **Step 10: Commit**

```bash
just fmt
git add crates/rimap-imap/src/types.rs crates/rimap-imap/src/ops/append.rs \
  crates/rimap-imap/src/ops/fetch.rs crates/rimap-imap/src/ops/folders.rs \
  crates/rimap-imap/src/ops/move_message.rs crates/rimap-imap/src/special_use.rs \
  crates/rimap-imap/tests/adversarial_imap.rs \
  crates/rimap-imap/tests/integration/dovecot.rs \
  crates/rimap-imap/tests/integration/proton.rs \
  crates/rimap-server/src/boot/discovery.rs \
  crates/rimap-server/src/tools/compose/create_draft.rs \
  crates/rimap-server/src/tools/admin/list_folders.rs \
  crates/rimap-server/src/tools/mailbox/delete_message.rs \
  crates/rimap-server/src/tools/mailbox/folder_management.rs \
  crates/rimap-server/src/tools/mailbox/labels.rs \
  crates/rimap-server/src/tools/retrieval/download_attachment.rs \
  crates/rimap-server/src/tools/retrieval/export_messages.rs \
  crates/rimap-server/src/tools/retrieval/list_attachments.rs \
  crates/rimap-server/src/tools/retrieval/search.rs \
  crates/rimap-server/src/tools/fetch_by_uid.rs \
  crates/rimap-server/tests/e2e/e2e_smtp_real.rs
git commit -m "feat: protect IMAP data records"
```

---

### Task 6: Exact compiler guard, changelog, and generated artifacts

**Files:**

- Create: `crates/rimap-imap/tests/non_exhaustive_e0639.rs`
- Modify: `CHANGELOG.md`
- Modify only if generated by the recipe: `crates/rimap-server/tests/fixtures/rimap-tool-schemas/*.json`

**Interfaces:**

- Consumes: the approved 27-record surface and the final green all-target/all-feature check.
- Produces: a downstream exact-E0639 regression guard and the v0.3.0 migration note.

- [ ] **Step 1: Add the exact-E0639 harness**

Adapt the process and temp-crate structure from `crates/rimap-audit/tests/non_exhaustive_e0639.rs`. The temporary `Cargo.toml` path-depends on `rimap-imap` and `rimap-authz`. Give each probe a separate target directory.

Add exactly these three test functions:

```text
non_exhaustive_plain_literal_yields_e0639
non_exhaustive_functional_update_yields_e0639
non_exhaustive_unrelated_failure_is_not_e0639
```

The first compiles
`rimap_imap::types::HeaderSearch { name, value }`; the second compiles
`rimap_authz::BreakerConfig { error_threshold, ..default_spec() }`; the third
compiles a missing function and asserts stderr does not contain `error[E0639]`.
For the first two, assert `cargo check` fails and stderr contains
`error[E0639]`.

- [ ] **Step 2: Run the exact compiler guard**

Run:

```bash
cargo nextest run -p rimap-imap -E 'test(non_exhaustive)'
```

Expected: nextest reports exactly three tests run; both positive probes observe exact E0639 and the unrelated control proves specificity.

- [ ] **Step 3: Prove the new guard bites**

Temporarily remove `#[non_exhaustive]` from `HeaderSearch`, then run:

```bash
cargo nextest run -p rimap-imap -E 'test(non_exhaustive)'
```

Expected: failure because the plain literal compiles without E0639. Restore the
committed Task 5 source and rerun:

```bash
git restore --source=HEAD -- crates/rimap-imap/src/types.rs
cargo nextest run -p rimap-imap -E 'test(non_exhaustive)'
```

Expected: green.

- [ ] **Step 4: Add the Unreleased changelog note**

Under `## [Unreleased]`, add `### Changed` and one factual bullet:

```markdown
- Public named-field data records in `rimap-core`, `rimap-authz`, `rimap-config`,
  `rimap-content`, `rimap-imap`, and `rimap-smtp` are now non-exhaustive.
  Downstream code must construct them through the provided constructors or
  defaults plus field assignment and add `..` to record patterns.
```

Do not claim the excluded server tool records or tuple wrappers changed.

- [ ] **Step 5: Regenerate and inspect tool schemas**

Run:

```bash
just regen-tool-schemas
git diff -- crates/rimap-server/tests/fixtures/rimap-tool-schemas
```

Expected: no schema diff. If a diff appears, stop and diagnose which Rust change altered schema output; do not accept an attribute-only drift.

- [ ] **Step 6: Run focused release gates**

Run:

```bash
just fmt
git status --short
just lint
just test-fast
just semver-checks
```

Expected: `git status --short` names only the planned Task 6 guard and
changelog, and every gate is green. Any formatter-modified earlier path must
be staged with its owning task before proceeding; an unrelated path stops the
task. The semver gate is expected to permit the already-declared 0.3.0-dev
breaking-version transition; it is not proof that the source change is
compatible.

- [ ] **Step 7: Commit**

```bash
git add crates/rimap-imap/tests/non_exhaustive_e0639.rs CHANGELOG.md
git commit -m "test: guard non-exhaustive record contracts"
```

---

### Task 7: Full repository verification

**Files:**

- Verify only; no planned file changes.

**Interfaces:**

- Consumes: all six implementation commits and the reviewed design records.
- Produces: local-CI evidence suitable for adversarial review and pull-request delivery.

- [ ] **Step 1: Re-run and reconcile the complete compile inventory**

Run:

```bash
cargo check --workspace --all-targets --all-features --locked
sort -u target/quest-835/e0639-fallout.tsv -o target/quest-835/e0639-fallout.tsv
```

Expected: cargo exits 0 with no E0639. Reconcile every TSV row to one migrated
diff site, and every new constructor to at least one row. This closes the
working fallout inventory.

- [ ] **Step 2: Run full local CI in the background**

Run `just ci` as one background job with no foreground timeout. Ingest its
actual exit status and full summary.

Expected: exit 0. Do not claim completion from individual crate tests alone.

- [ ] **Step 3: Inspect the final diff against the frozen surface**

Confirm all 27 inventory records have `#[non_exhaustive]`, every external
literal in the reconciled TSV migrated, tuple/state-holder/server exclusions
remain untouched, only compiler-forced constructors were added, generated
schemas are unchanged, and the changelog names the source migration.

- [ ] **Step 4: Publish fallout evidence during PR review**

Copy the sorted TSV union plus the migrated-site and constructor reconciliation
into the pull request's required `WORK:REVIEW` payload. The issue-bound scope
token is `q835-d8f3faa3`.

- [ ] **Step 5: Hand the verified branch to quest delivery**

Run the quest's adversarial code review, security-trigger decision, simplification pass, push, pull-request creation, and green-plus-mergeable CI loop. Do not merge without the independent final review required by repository policy.
