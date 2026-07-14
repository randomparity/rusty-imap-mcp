# Golden agent transcripts — snapshot what the agent actually sees — design

**Status:** Draft 2026-07-13 · issue [#524](https://github.com/randomparity/rusty-imap-mcp/issues/524)
**ADR:** [ADR-0009](../../ADR/0009-golden-agent-transcript-snapshots.md)
**Builds on:** #561 (PR #562, ADR-0008 — shared `crates/rimap-fake-imap`),
the wire harness (`crates/rimap-server/tests/support/wire/`), and the injection
corpus (`crates/rimap-content/tests/injection-corpus/`).
**Extends:** `docs/superpowers/specs/2026-04-30-test-strategy-improvements-design.md` §8.1.
**Scope:** Test-only. Add `insta`-snapshotted "day in the life" JSON-RPC-wire
transcripts of multi-step agent sessions driven against the in-process
scriptable fake. **No production code changes.**

## Problem

Tool descriptions, `server_instructions`, `security_warnings` phrasing, and
response `meta`/`untrusted` shape are the server's *UI for agents* — the surface
prompt-injection defenses and agent usability both depend on. Drift is only
partially guarded today: `just check-tools-doc` and the schema-drift gate pin
individual struct shapes, but **nothing pins the actual transcript an agent sees
across a realistic multi-step session** — the composition of initialize
instructions, advertised tool catalog, and the sequence of tool responses
(warnings, sanitized content, meta) that an agent reads while working.

A single struct can pass its schema gate while the *rendered session* an agent
experiences changes: a reworded `security_warning`, a dropped `meta` field on
one tool, a sanitizer that starts stripping content silently. Those are exactly
the changes that should be **reviewed**, not shipped invisibly.

## Acceptance criteria (from the issue)

- [ ] ≥2 transcript snapshots run in PR CI (not nightly, not container-gated).
- [ ] A normalization helper so snapshots are stable across runs.
- [ ] A documented convention for intentional updates (`cargo insta review`).

## Decision

Settled in ADR-0009 and below.

1. **Drive all transcripts against `rimap-fake-imap`, not seeded Dovecot.** The
   fake is container-free (so the snapshots are **PR-blocking**, the property a
   drift-guard needs) and byte-deterministic (scripted UIDs, dates, sizes, body
   bytes), so normalization shrinks to ports + temp paths. The Dovecot harness
   is container-gated and *silent-skips* without a runtime, so a Dovecot-backed
   golden snapshot would not guard drift on a runner lacking Docker — defeating
   the purpose. Rationale + rejected alternatives: ADR-0009.
2. **Two headline snapshots — `triage` and `cleanup`** — matching the two flows
   the issue names. The triage flow fetches **one clean and one hostile** message
   (the hostile fixture is served by the fake, which can emit adversarial bytes a
   conformant server never would), so the sanitizer's `security_warnings` and
   `untrusted` shaping are pinned in the same snapshot.
3. **A `transcript` test-support module** with (a) a `Recorder` that captures the
   ordered request→response exchanges a session drives, and (b) an explicit,
   unit-tested `normalize` helper. Snapshots via `insta::assert_snapshot!` on the
   rendered, normalized transcript string.

## Design

### 1. What a transcript contains

A transcript is the ordered list of JSON-RPC exchanges an agent would see across
one session, rendered as labeled pretty-printed JSON blocks:

- The **`initialize` response** — `serverInfo`, `capabilities`, and the
  `instructions` / `server_instructions` string. This is the first thing an
  agent reads; drift here (reworded posture guidance, changed capabilities) is
  load-bearing.
- The **`tools/list` response** — the advertised tool catalog with descriptions
  and input schemas, filtered by the active posture. Drift here (a reworded tool
  description, a tool appearing/disappearing under a posture) is exactly the
  "UI for agents" the issue targets.
- Each **`tools/call` exchange** in the flow — the request (`name` + normalized
  `arguments`) and the response (`content`, `structuredContent` with `meta` /
  `untrusted` / `security_warnings`, `isError`).

Recording the request side too keeps the snapshot self-describing (a reviewer
sees which call produced which response) at negligible extra churn — the request
args are authored in the test, so they only change when the test does.

`notifications/initialized` carries no response and is not recorded. The audit
log is a **separate file**, out of scope for the transcript (it has its own
attribution tests); the transcript pins only the over-the-wire JSON-RPC an agent
consumes.

### 2. `crates/rimap-server/tests/support/wire/transcript.rs` (new)

A recorder that wraps `Harness` calls without touching `Harness` internals:

```rust
pub struct Recorder { exchanges: Vec<Value> }

impl Recorder {
    /// Drive one request through the harness, record request+response, return
    /// the response for optional in-test assertions.
    pub async fn call(&mut self, h: &mut Harness, method: &str, params: Value) -> Value;

    /// Render the recorded exchanges to a stable, normalized snapshot string.
    pub fn render(&self) -> String;
}

/// Replace run-varying substrings with stable placeholders. Pure, unit-tested.
pub fn normalize(raw: &str) -> String;
```

`Recorder::call` reconstructs the request envelope from `(method, params)` with a
**sequential display id** (1, 2, 3…) rather than the harness's internal id, so
the id column is stable by construction and needs no masking. It calls
`Harness::request` (which already schema-validates the response envelope), then
pushes `{ "request": {method, params}, "response": <result-or-error> }`.

`render` serializes the exchanges with `serde_json::to_string_pretty`, wrapped in
`>>> request N` / `<<< response N` header lines for diff readability, then applies
`normalize`.

The module lives under `support/wire/` (not the shared `rimap-fake-imap` crate) —
it is `rimap-server`-test-specific and depends on `Harness`. It follows the
existing `force_use_*` per-binary dead-code-link convention if any item is unused
in a sibling binary (see `harness.rs`).

### 3. The `normalize` helper — exactly what it masks, and why

Because the fake is byte-deterministic, the mask list is short and each entry has
a justification (an un-justified mask hides the very drift we want to catch):

| Masked → placeholder | Why it varies | Risk if unmasked |
|---|---|---|
| `127.0.0.1:<port>` and bare `:<port>` → `<HOST:PORT>` | fake binds `:0` (ephemeral) | flaky every run |
| tempdir path prefix → `<TMPDIR>` | `TempDir` randomizes | flaky every run |
| `serverInfo.version` value → `<VERSION>` | bumps every release | churns on version bump, not on drift |
| any generated `Date:`/RFC-2822 timestamp in a `create_draft` echo → `<DATE>` | server stamps "now" if it echoes a generated date | flaky every run — **confirmed during TDD**; masked only if the response actually carries one |

Everything else is deterministic and **left visible on purpose**: tool
descriptions, `server_instructions`, `security_warnings` text, `meta` fields,
sanitized body text, scripted UIDs/sizes/envelope dates. Those are the payload
the snapshot exists to guard.

`normalize` is applied as an ordered list of `(Regex, &str)` replacements and is
unit-tested directly (feed a string with a port + temp path, assert the
placeholders) so the helper itself is a checkable unit, not just an implicit part
of a big snapshot — satisfying AC 2 with its own falsifiable test.

### 4. Fixtures and flows

**Config.** Each flow writes a single-account TOML pointing the binary at the
fake (`host = 127.0.0.1`, `port = fake.port()`, `encryption = "tls"`,
`tls_fingerprint_sha256 = fake.pin().to_hex()`,
`[defaults.credentials] fallback = "keyring-then-env"`), modeled on
`e2e_wire_uidvalidity::fake_config`. Posture differs per flow:

- **Triage** needs `list_folders`, `search`, `fetch_message` (read) + `mark_read`,
  `create_draft` (draft mutations) → **`posture = "draft-safe"`**.
- **Cleanup** needs `move_message`, `delete_message`, `expunge` (destructive) →
  **`posture = "destructive"`**.

**Hostile fixture.** Reuse one existing injection-corpus `.eml` (e.g.
`html-only-hidden-instructions` or `prompt-injection-plaintext`) as the hostile
`fetch_message` body, so the pinned `security_warnings` correspond to a known,
already-covered attack class. The fake emits its raw bytes as the `UID FETCH
BODY[]` literal. The clean message is a small hand-authored RFC 822 body.

**Expected IMAP dialogs (TDD-calibrated).** The fake's `Step::Expect { verb }` is
strictly linear, so each tool's client command sequence must be scripted exactly.
The sequences below are *expected* from the ops layer; the exact bytes are
confirmed the way #561 did it — run the test, dump `server.recorded()` via a
`DumpOnPanic` drop guard, match the reply to the actual client commands. Boot
capability atoms are advertised as `IMAP4rev1 MOVE UIDPLUS` so `move_message`
takes the direct `UID MOVE` path and `expunge` the scoped `UID EXPUNGE` path.

Boot (both flows): `login_preamble("IMAP4rev1 MOVE UIDPLUS")` + `LIST "" *`
(reveal-on-select catalog boot, answered with a small folder set incl. `INBOX`
and `Drafts`/`Trash` as the flow needs).

Triage (one pooled connection, draft-safe):
1. `list_folders` → `LIST` (tool's own list).
2. `search` (unread) → `EXAMINE INBOX` + `UID SEARCH` (`* SEARCH …`) + page
   `UID FETCH` returning fully-parseable `ENVELOPE`/`FLAGS`/`RFC822.SIZE` lines.
3. `fetch_message` (clean) → `EXAMINE INBOX` + `UID FETCH` size preflight +
   `UID FETCH BODY[]` clean bytes.
4. `fetch_message` (hostile) → same shape, hostile `.eml` bytes.
5. `mark_read` → read-write `SELECT INBOX` (with `UIDVALIDITY`) +
   `UID STORE +FLAGS (\Seen)`.
6. `create_draft` → `APPEND Drafts` literal (+ any `SELECT`/`STATUS` the path
   emits — TDD-confirmed).

Cleanup (one pooled connection, destructive):
1. `search` → `EXAMINE` + `UID SEARCH` + page `UID FETCH`.
2. `move_message` → read-write `SELECT` src + `STATUS` dest (UIDVALIDITY probe) +
   `UID MOVE`.
3. `delete_message` → the configured delete path (`UID MOVE`/`UID COPY` to Trash
   or `UID STORE +FLAGS (\Deleted)`) — TDD-confirmed against the flow's config.
4. `expunge` → read-write `SELECT` + `UID EXPUNGE`.

### 5. Diagnosability and connection budget

Both risks the #561 spec documented apply verbatim and are handled the same way:

- **Mid-sequence divergence must be legible.** `Harness::request` *panics* (not
  returns `Err`) on the 2s `REQUEST_TIMEOUT` or a dropped connection, which is
  how the fake's in-task `assert!` (wrong verb) surfaces. Each flow test holds a
  `DumpOnPanic(&server)` drop guard that prints `server.recorded()` when
  `std::thread::panicking()`, so a miscalibrated step shows the client-command
  order instead of a bare timeout. (`eprintln!` under `#[expect(clippy::print_stderr,
  …)]`, as the sibling fake tests do.)
- **Connection budget.** A multi-tool session is expected to use **one** pooled
  connection, so the whole flow is one linear `Vec<Step>` served via
  `FakeImapServer::start`. `MAX_ACCEPTS = 4` leaves headroom for a transparent
  read-only reconnect. If calibration shows the pool opens a fresh connection per
  tool call (so the single replayed script desyncs on the second accept), the fix
  is `start_sequence` with a per-connection script vector — **not** papering over
  a reconnect storm by raising `MAX_ACCEPTS`. A 2s-timeout signature (vs a clean
  snapshot mismatch) is the tell that the budget, not the arithmetic, is wrong.

### 6. Documented update convention (AC 3)

Add a short "Updating golden transcripts" subsection to `AGENTS.md` (near the
existing schema-regen note) and a header doc-comment in each flow test:

- Intentional changes to tool output shape/warnings/sanitization will fail the
  snapshot. Review the diff, and if the change is intended, run
  `cargo insta review` (or `cargo insta accept`) and commit the updated `.snap`.
- A snapshot diff that is **not** an intended change is a drift bug — investigate,
  don't accept.
- `insta` is already a dev-dependency (`rimap-content`, `rimap-config`,
  `rimap-server`); no new dependency. `.snap` files live under
  `crates/rimap-server/tests/snapshots/` and are committed.

## Testing

- **Two flow snapshots** (headline AC): `e2e_wire_transcript_triage.rs` and
  `e2e_wire_transcript_cleanup.rs`, each producing one committed `.snap`. Both
  are host-runnable (no container) and run on every PR.
- **`normalize` unit test**: feeds a raw string containing a port, a temp path,
  and a version and asserts the placeholders — the normalization helper is
  falsifiable on its own (AC 2).
- **Non-vacuity**: the snapshots contain the real `security_warnings` and `meta`
  text; reverting a warning string or dropping a `meta` field changes the `.snap`
  and fails CI. A snapshot that renders empty/degenerate (e.g. all calls errored)
  is a calibration failure to escalate, not a pass.
- **`just ci` green**, including the schema-regen gate (no `*Meta`/`*Untrusted`
  struct change here → empty diff expected).

## Residual risk

- **Fake ≠ Dovecot.** The transcripts pin what the binary *renders* for a scripted
  server, not what any particular real server drives. That is the correct scope —
  a golden test guards the server's agent-facing output, and the fake is the only
  backend that is both deterministic and container-free. The realistic
  Dovecot/`e2e_wire` suite continues to guard conformance behavior separately.
- **Snapshot churn on intended changes.** Any deliberate reword of a warning or
  `meta` change updates two `.snap` files. That is the *feature* (the change is
  now reviewed), and the `cargo insta review` convention makes it a one-command
  update.
- **Script drift.** If a tool's IMAP command sequence changes, the hand-scripted
  fake must be updated (same maintenance property as every fake-backed wire test;
  the `recorded()` calibration workflow is documented above).

## Out of scope / non-goals

- Any production code change. Coverage only.
- Dovecot-backed transcripts (rejected in ADR-0009; container-gated silent-skip
  makes them a non-guard on PR CI).
- Snapshotting the audit log (separate file, separate attribution tests).
- A third "hostile-only" snapshot — the hostile fetch lives inside the triage
  snapshot per the issue's flow description; splitting it out is a later option if
  the triage snapshot grows unwieldy.

## Guardrails

`just ci` (rustfmt, clippy `--all-targets --all-features --locked -D warnings`,
check-macOS, test stable, test MSRV 1.88.0, cargo-deny, zizmor) plus the
schema-regen diff gate (expected empty). Branch:
`feat/golden-agent-transcripts-524`, base `main`.
