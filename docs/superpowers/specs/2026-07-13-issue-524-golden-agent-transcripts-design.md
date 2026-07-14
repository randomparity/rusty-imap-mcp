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
    /// the response so the flow's mandatory non-vacuity assertions can run on it
    /// (see Testing §Non-vacuity).
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
`>>> request N` / `<<< response N` header lines for diff readability, then
**strips `\r`** (so a CRLF-terminated MIME body line in a fetched message renders
LF-only — see "Cross-platform stability" below) and applies `normalize`.

**Serialization-order invariant.** The snapshot pins the *server binary's*
serialized output, so it is stable only if every collection the server renders
into the response serializes in a fixed order run-to-run. `serde_json` emits
struct fields in declaration order and its object `Map` is order-stable, but a
`HashMap`/`HashSet` anywhere in the response path (capabilities, the `tools/list`
catalog, a `meta` map, a `security_warnings` collection) would randomize key/element
order per process and flake the snapshot — the classic `insta` failure. This spec
requires: (a) confirming during TDD that those surfaces serialize from ordered
containers (`Vec` / `BTreeMap` / `IndexMap`), and (b) if any hash-ordered container
is found, adding a canonicalizing sort in `render` (parse to `serde_json::Value`,
which orders object keys, before rendering) rather than masking. Calibration runs
each flow test **5×** locally before committing the `.snap`, so hash-order flake
surfaces pre-commit, not on a later CI run.

The module lives under `support/wire/` (not the shared `rimap-fake-imap` crate) —
it is `rimap-server`-test-specific and depends on `Harness`. It follows the
existing `force_use_*` per-binary dead-code-link convention if any item is unused
in a sibling binary (see `harness.rs`).

### 3. The `normalize` helper — exactly what it masks, and why

Because the fake is byte-deterministic, the mask list is short and each entry has
a justification (an un-justified mask hides the very drift we want to catch). The
first calibration step is to **establish which of these values actually appear in
the MCP transcript at all** — the IMAP `host:port` and the tempdir are
server-internal config that may never surface in a happy-path tool response. A
mask for a value that never appears is dead weight and is dropped; a mask is added
only for a value TDD shows in the rendered transcript.

| Masked → placeholder | Why it varies | Anchoring / risk if unmasked |
|---|---|---|
| the full `127.0.0.1:<port>` token → `<HOST:PORT>` | fake binds `:0` (ephemeral) | **only if it appears** (e.g. connection-error meta). Anchor to the whole `host:port` string — **never** a bare `:<digits>` regex, which would rewrite envelope/body clock times like `10:30:00`. |
| tempdir path prefix → `<TMPDIR>` | `TempDir` randomizes | **only if it appears** (e.g. an attachment save path). Must match both macOS (`/var/folders/…`, `$TMPDIR`) and Linux (`/tmp/…`) forms. |
| `serverInfo.version` value → `<VERSION>` | bumps every release | churns on version bump, not on drift |
| every server-generated field in the `create_draft` / `APPEND` response — `Date:`, `Message-ID`, MIME `boundary`, any UUID/nonce, generated save-path | server stamps "now" / random per call | flaky every run. **The full set is enumerated during TDD, not assumed to be `Date` alone.** Prefer pinning at the source (a seeded clock/RNG if the config exposes one) over adding masks; mask only what genuinely cannot be pinned. Each mask erodes faithfulness. |

**Collision window.** The ephemeral port is random in the 32768–60999 range and
could, on some runs, equal a scripted `RFC822.SIZE` or `UID` — masking a
deterministic value on those runs only. Because every scripted numeric in the
fixtures is author-chosen, they are all kept **well below 32768** (small UIDs like
1–3, small sizes like 42/512), eliminating the window by construction. The
`host:port` mask (if needed at all) is additionally anchored to the full token, so
it cannot match a bare number.

Everything else is deterministic and **left visible on purpose**: tool
descriptions, `server_instructions`, `security_warnings` text, `meta` fields,
sanitized body text, scripted UIDs/sizes/envelope dates. Those are the payload
the snapshot exists to guard.

`normalize` is applied as an ordered list of `(Regex, &str)` replacements and is
unit-tested directly with **both a positive and a negative case for every mask**:
feed a string containing a `host:port`, a temp path, and a version and assert the
placeholders; **and** feed a string containing values that are same-shaped-but-
legitimate and assert they are left **untouched**. The negative case is not
limited to the safe masks — it must specifically cover the *greediest* entries,
the `create_draft`/`APPEND` generated-field masks (`Message-ID`, MIME `boundary`,
`any UUID/nonce`, generated `Date`), since an over-broad boundary/Message-ID regex
is far likelier to over-match than an anchored `host:port` token and could
silently rewrite a scripted envelope value, a `security_warnings` substring, or
sanitized body text — the cardinal faithfulness sin. Concretely: an envelope
clock time (`10:30:00`), a small scripted size/UID, a `security_warnings` string,
and a scripted value resembling a Message-ID/boundary fragment must all survive
`normalize` unchanged. **Every mask added during TDD ships with its own negative
assertion, not just a positive one.** This makes the helper a checkable unit whose
over-masking is falsifiable — satisfying AC 2 with its own tests.

**Cross-platform stability.** One committed `.snap` per flow is shared across the
`check (macOS)` lane and the Linux `test` lanes, so the golden must be identical on
both. Two hazards are handled: (1) `render` strips `\r` before snapshotting, so
CRLF-terminated MIME body lines never embed a `\r` in the `.snap`; and (2) a
`.gitattributes` entry pins `*.snap` to `text eol=lf` so `core.autocrlf` cannot
rewrite committed goldens. Any surviving path mask must cover both OS temp-dir
forms and is unit-tested for each.

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

**Hostile fixture — a dedicated, transcript-owned copy.** The hostile
`fetch_message` body is a **byte-frozen `.eml` committed under the transcript test
tree** (e.g. `crates/rimap-server/tests/fixtures/transcript/hostile.eml`),
seeded from a known attack class (modeled on an injection-corpus case such as
`html-only-hidden-instructions`). It is **not** read live from the
injection-corpus tree. Rationale: the injection corpus is an independently
maintained, actively evolving asset (wave-1/wave-2 ingestion, PII-scrub passes,
download-at-build regeneration); if the triage snapshot read a corpus file
directly, a corpus-side byte change would churn the triage `.snap` in a PR
unrelated to the agent surface, and a maintainer following the `cargo insta
review` convention could blind-accept that diff — swallowing a genuine
`security_warnings`/sanitizer regression riding alongside the corpus edit. Owning
a frozen copy makes the golden depend only on files the transcript tests control,
so any `.snap` diff is attributable to a sanitizer or output-shape change. The
fake emits the fixture's raw bytes as the `UID FETCH BODY[]` literal. The clean
message is likewise a small hand-authored RFC 822 body committed alongside it.

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
- `insta` is a **workspace dependency** already used by `rimap-content` and
  `rimap-config`; `rimap-server` picks it up with a one-line
  `insta = { workspace = true }` under `[dev-dependencies]` (no new external
  crate enters the graph). `normalize` uses **plain string operations, not a new
  `regex` dependency**. `.snap` files live under
  `crates/rimap-server/tests/snapshots/` and are committed, with a
  `.gitattributes` entry pinning `*.snap` to `text eol=lf`.

## Testing

- **Two flow snapshots** (headline AC): `e2e_wire_transcript_triage.rs` and
  `e2e_wire_transcript_cleanup.rs`, each producing one committed `.snap`. Both
  are host-runnable (no container) and run on every PR.
- **`normalize` unit test**: feeds a raw string containing a port, a temp path,
  and a version and asserts the placeholders — the normalization helper is
  falsifiable on its own (AC 2).
- **Non-vacuity is enforced in-test, not by review.** Before rendering the
  snapshot, each flow test asserts the transcript is non-degenerate, so a subtly
  empty golden fails *loudly at run time* rather than being silently accepted into
  a green-forever `.snap`. The hard assertions:
  - No `tools/call` in the flow returned `isError: true` **unless that error is
    the pinned subject of the call** (none of the triage/cleanup happy-path calls
    are). A tool that errored because its dialog was miscalibrated must fail the
    test, not be snapshotted as the "expected" output.
  - The **`initialize`** response's `instructions` / `server_instructions` string
    is present and non-empty — the spec's #1 drift target (§Problem, §Design 1).
    A regression that empties or strips that string produces no `isError`, never
    touches the hostile path, and leaves the catalog intact, so without this
    explicit check it would sail through the other assertions and be accepted as
    "the new golden." The assertion floors its length and requires it to still
    contain a stable posture-guidance substring, so a silent gutting of the
    primary defensive surface fails loudly.
  - The **hostile** `fetch_message` response carries a **non-empty
    `security_warnings`** and the `untrusted` marker — the whole reason the hostile
    fixture is in the flow. If the sanitizer path wasn't reached (e.g. the fixture
    bytes didn't parse), this fires before the snapshot is written.
  - The **`search`** response (triage step 2, cleanup step 1) returned a
    **non-empty result set whose UIDs match the ones later steps consume**. Later
    tools (`fetch_message`, `mark_read`, `move_message`) act on UIDs authored in
    the test, and the fake serves its scripted `UID FETCH` reply regardless of what
    the preceding `UID SEARCH` returned — so a desynced or empty SEARCH would still
    yield a full-looking snapshot narrating hits that never happened. This ties the
    snapshot's story to reality.
  - `tools/list` advertised a **non-empty** tool catalog for the flow's posture.

  `Recorder::call` returns the response precisely so these assertions can run on
  it; they are mandatory, not "optional." Only after they pass is `render()` +
  `assert_snapshot!` reached.
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
