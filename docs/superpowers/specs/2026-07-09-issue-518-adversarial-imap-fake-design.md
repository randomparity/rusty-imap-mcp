# Scriptable adversarial IMAP server (byzantine peer) harness — design

Issue: [#518](https://github.com/randomparity/rusty-imap-mcp/issues/518)
(P1, Effort L, Theme A: close verified full-stack gaps). Verified on `main`
@ `795fedf`. Extends the test-strategy spec
[`2026-04-30-test-strategy-improvements-design.md`](2026-04-30-test-strategy-improvements-design.md) §8.1.
No ADR: this is additive test infrastructure plus one two-line observability
add; it changes no public contract, trust boundary, or cross-crate invariant,
so per [`docs/ADR/README.md`](../../ADR/README.md) the decisions are recorded
inline here (see *Considered & rejected*).

## Problem

Every IMAP test in the workspace runs against conformant Dovecot, which always
advertises `UIDPLUS` and `MOVE`. Entire failure families are therefore
**structurally unreachable** — no test can script a *misbehaving* server:

- The folder-wide `EXPUNGE` data-loss fallback (plain RFC 3501 `EXPUNGE`,
  taken only when a server advertises neither `MOVE` nor `UIDPLUS`) is
  unverified at the wire level. It is tracked today by the `#[ignore]`d
  placeholder `crates/rimap-imap/tests/expunge_folder_wide_gap.rs`, whose
  ignore-reason names the missing harness. The pure pieces
  (`expunge_strategy`, `fallback_uses_folder_wide_expunge`) are unit-tested;
  the live path through `run_expunge` → `session.expunge()` is not.
- `LOGINDISABLED` capability, UID-less / UID-0 FETCH responses, truncated
  responses mid-literal, and mid-command disconnects cannot be exercised.

The threat model (`AGENTS.md`) treats the IMAP server itself as a potential
adversary (compromised or MITM'd past the TLS pin), yet no harness can feed
hostile responses to the real client state machine.

## Acceptance criteria (from the issue)

- [ ] Harness merged under `crates/rimap-imap/tests/support/`.
- [ ] These four scripts green:
  1. No-`UIDPLUS`/no-`MOVE` server → assert `MoveOutcome.folder_wide_expunge`
     (the `ServerFolderWideExpungeDataLoss` condition) **and**
     `used_fallback`, end-to-end; un-`#[ignore]` `expunge_folder_wide_gap.rs`.
  2. `LOGINDISABLED` → `AuthFailure::CapabilityMissing { needed: "LOGIN" }`
     auth provenance.
  3. FETCH responses with missing / zero UIDs → skip-with-warning.
  4. Truncated response mid-literal → typed error, no hang.
- [ ] `expunge_folder_wide_gap.rs` no longer `#[ignore]`d.
- [ ] CONTRIBUTING note: when to use the fake (misbehavior) vs Dovecot
  (conformant behavior).

## Non-goals

- **No general-purpose IMAP server.** The fake replays an ordered, per-scenario
  script; it does not maintain mailbox state or parse arbitrary client
  commands beyond dispatching on the command verb.
- **No new runtime dependency in shipped crates.** The harness is test-only and
  reuses `rcgen` + `tokio-rustls` + `rustls`, already in-tree (`rcgen` entered
  the workspace for #517's SMTP e2e). No `Cargo.toml` shipped-dependency change.
- **No container runtime.** The fake is a pure in-process tokio listener; it
  runs on every PR, including hosts where Docker is absent.
- **No change to any MCP tool contract or response shape.** The one shipped-code
  change (Component 2, scenario 3) is a single aggregated `warn!` after an
  already-existing silent skip loop — the returned message set is unchanged, and
  behavior for well-behaved servers (zero skips → no warn) is unchanged.

## Design

### Component 1 — the in-process fake (`crates/rimap-imap/tests/support/`)

A test-only tokio TCP listener that terminates TLS and replays a scripted
IMAP dialog against the **real** `Connection` client. Structure mirrors the
#517 SMTP responder (`crates/rimap-smtp/tests/support/`).

**Files.**

- `support/mod.rs` — `#![allow(dead_code)]` (module-level; the one place the
  repo permits a bare `#[allow]`, mirroring
  `tests/integration/support/container.rs:7`) followed by `pub mod certs;` and
  `pub mod fake_imap;`. The attribute is load-bearing: each `tests/*.rs`
  integration file is its own binary and recompiles this module, so any helper
  a given binary does not use would otherwise trip `dead_code` under CI's
  `RUSTFLAGS=-D warnings`.
- `support/certs.rs` — `self_signed() -> SelfSigned`, adapting
  `rimap-smtp`'s `certs::self_signed`. Returns the rustls cert chain + key
  **and** the leaf DER, so the harness can derive the pin via
  `rimap_core::TlsFingerprint::from_cert_der(leaf_der)`. The connecting
  `PinningVerifier` (`rimap-imap/src/tls.rs`) compares only the leaf SHA-256
  and ignores hostname/chain, so a self-signed `127.0.0.1` cert is accepted
  when the test pins its fingerprint.
- `support/fake_imap.rs` — the `FakeImapServer` type and its `Step` script
  vocabulary.

**Transport.** Implicit TLS (`ImapEncryption::Tls`, IMAPS-style): the client
does the TLS handshake immediately after TCP connect, so the fake wraps the
accepted `TcpStream` in a `tokio_rustls::TlsAcceptor` before speaking IMAP.
This avoids the plaintext STARTTLS dance and matches the primary production
posture (Proton Bridge: localhost IMAPS + pinned self-signed cert). rcgen's
default leaf is ECDSA-P256, which the ring provider's signature verification
(still enforced by `PinningVerifier`) accepts.

**Script vocabulary (`Step`).** An ordered `Vec<Step>` of expected-command →
canned-response pairs, plus adversarial knobs:

```rust
pub enum Step {
    /// Read one CRLF-terminated client command line; assert the verb
    /// (after the client tag) case-insensitively starts with `verb`, and
    /// capture the client tag for the next `Reply`. Does not write.
    Expect { verb: &'static str },
    /// Send these bytes verbatim over the TLS stream: untagged data
    /// (`* CAPABILITY …`, `* n FETCH (…)`), greetings, literals, or
    /// deliberately malformed/truncated bytes. Does not read.
    Send(Vec<u8>),
    /// Emit a tagged completion using the tag captured by the most recent
    /// `Expect`: writes `<captured-tag> <text>\r\n`. Does not read. E.g.
    /// `Reply { text: "OK LOGIN completed" }`.
    Reply { text: &'static str },
    /// Sleep, to exercise the client command timeout without closing.
    Delay(Duration),
    /// Drop the TLS session and TCP socket immediately (bare drop → prompt
    /// FIN, no `close_notify` wait) — a mid-command disconnect / truncation.
    Disconnect,
}
```

A real command reply is therefore three steps —
`Expect { verb }`, then zero-or-more `Send(untagged…)`, then
`Reply { text }` — so the untagged-data-then-tagged-completion shape every
scenario needs (post-login `* CAPABILITY …` + OK; `SELECT` response; each
`* n FETCH (…)` + OK) is expressible. Because `Reply` echoes the tag captured
by the preceding `Expect` **without reading another line**, the fake never
deadlocks waiting for a command the client already completed, and it is robust
to async-imap's tag format — unlike the existing plaintext `MockImap` in
`handshake.rs`, which hardcodes `A0001` and would desync if the tag scheme
changed. (`Expect` reads exactly one CRLF line and asserts the verb; a `+`
literal-continuation dialog is not modeled — see *Failure modes*.)

**Capability sets** are expressed as plain `Send` steps of the untagged
`* CAPABILITY …` line the scenario wants (e.g. `IMAP4rev1` with neither `MOVE`
nor `UIDPLUS` for scenario 1; `IMAP4rev1 LOGINDISABLED` for scenario 2). No
capability enum is introduced — the raw line is the knob, matching the issue's
"ordered expected-command → canned-response pairs" model.

**Lifecycle.** `FakeImapServer::start(script) -> FakeImapServer` binds
`127.0.0.1:0`, spawns a one-connection background task running the script over
the TLS stream, and exposes:

- `port() -> u16`,
- `pin() -> TlsFingerprint` (leaf fingerprint for the client's
  `pinned_fingerprint`),
- `connection(username) -> Connection` — a fully-wired `Connection` pointed at
  the fake with `encryption: Tls`, the pin set, a no-op `AuthEventSink`, and a
  static-password `CredentialResolver` (returns a fixed ASCII `SecretString` +
  `CredentialSource::Keyring`), with a short `command_timeout` (~1s) so a hang
  bug fails fast rather than stalling the suite,
- `connection_with(username, resolver, command_timeout) -> Connection` — same,
  but injects an arbitrary `Arc<dyn CredentialResolver>` and timeout;
  `connection()` delegates to it. Scenario 2 passes a `PanicResolver` (mirroring
  `handshake.rs`) to prove the resolver is never consulted; scenario 4 passes a
  longer timeout (see below). The injected username/password are constrained to
  ASCII with no quotes, backslashes, or 8-bit bytes, so async-imap 0.11 encodes
  `LOGIN` as quoted strings and never as an IMAP literal (which the `Step`
  vocabulary cannot answer — see *Failure modes*),
- `join() -> Result<Vec<String>, io::Error>` — await the server task; returns
  the client command lines it recorded (for ordering assertions).

The client `host` is `"127.0.0.1"`; `ServerName::try_from("127.0.0.1")` yields
an IP server name, and the pinned verifier ignores it — no DNS, no `/etc/hosts`.

### Component 2 — the four scenarios + un-ignore

Each scenario drives the real `Connection` against a scripted `FakeImapServer`
and asserts the typed outcome. The shared harness lives in `tests/support/`;
scenario binaries `mod support;` it.

**File layout (see *Considered & rejected* for why not one binary):**

- `tests/expunge_folder_wide_gap.rs` — **rewritten** from the `#[ignore]`
  placeholder into the real, un-ignored scenario 1 (`mod support;` +
  `#[tokio::test]`). Keeps the AC-named filename.
- `tests/adversarial_imap.rs` — scenarios 2, 3, 4 as three `#[tokio::test]`s +
  `mod support;`.

Both binaries include the same `support` module; the module-level
`#![allow(dead_code)]` absorbs the per-binary unused-helper warnings.

**Scenario 1 — folder-wide EXPUNGE data loss.** Script a server that logs in,
advertises (post-login CAPABILITY) neither `MOVE` nor `UIDPLUS`, and answers the
COPY+STORE+EXPUNGE fallback dialog that `Connection::move_messages`
(`dispatch.rs:406`) drives with `expected_source_uidvalidity: None`: greeting →
`CAPABILITY` → `LOGIN` → post-login `CAPABILITY` (no `MOVE`/`UIDPLUS`) →
`SELECT <src>` → `UID COPY` → `STATUS <dest> (UIDVALIDITY)` → `UID STORE
+FLAGS (\Deleted)` → plain `EXPUNGE`. Assert the returned
`MoveOutcome.used_fallback == true` **and** `folder_wide_expunge == true`, and
(via `join()`) that the client issued a plain `EXPUNGE`, not `UID EXPUNGE`.

**Scenario 2 — `LOGINDISABLED`.** Greeting → `CAPABILITY` → untagged
`* CAPABILITY IMAP4rev1 LOGINDISABLED` → tagged OK. The client's login flow
(`connection/login.rs`) drains for `LOGINDISABLED` and returns
`ImapError::Auth { reason: AuthFailure::CapabilityMissing { needed: "LOGIN" } }`
**before** the credential resolver is consulted. Assert that variant, and that
the resolver was not called (a panicking resolver proves it, mirroring
`handshake.rs`'s `PanicResolver`). Drive it via any read op (e.g.
`list_folders`).

**Scenario 3 — missing / zero UID FETCH, skip-with-warning.** Log in
(advertising `UIDPLUS`), `EXAMINE` (read-only open — `Connection::fetch` →
`ops::fetch` calls `folders::select(session, folder, true)`, which issues
`EXAMINE`, not `SELECT`; `fetch.rs:136`), then answer a `UID FETCH` with three
items: one lacking the `UID` data item, one with `UID 0`, and one well-formed
(`UID 5`). `ops::fetch` skips the first two at `fetch.rs:158-163` and returns
only `UID 5`. Assert the single returned message.

**Contingency (verified during TDD, mirroring scenario 4).** The `UID 0`
half is certain (`Uid::new(0)` returns `None`, `fetch.rs:161-163`). The
missing-UID half assumes async-imap 0.11 surfaces a `* n FETCH (…)` line that
omits the `UID` item as a value with `msg.uid == None` (the `else` at
`fetch.rs:158`) rather than dropping or rejecting it during parsing. The build
step MUST confirm how async-imap 0.11 surfaces a UID-less FETCH item and bind
the assertion to the observed skip count — if the parser drops the UID-less
item, only the `UID 0` item skips and the aggregated count is `1`, not `2`. The
robust form asserts the two skip mechanisms independently (a UID-0 item is
skipped; a UID-less item, however async-imap represents it, is skipped) and
asserts `skipped_uids` equals the empirically observed total, rather than
hardcoding `2` against an unverified parser assumption.

The skip is currently **silent**. To satisfy the AC's "skip-**with-warning**"
and give operators a signal that a server withheld/zeroed a UID (a hostile-input
indicator per the threat model), the fetch loop **counts** skipped items
(missing UID + zero UID) and emits a **single aggregated** `tracing::warn!`
after the loop when the count is non-zero, with a stable structured field
`skipped_uids = <count>` (and the folder), so the event is matchable by field
rather than by log-string parsing. A per-item `warn!` is rejected: the skip is attacker-controlled, so
one-warn-per-item lets a hostile server amplify log volume 1:1 with its
response stream — the exact threat the warn is meant to surface must not become
a log-flood lever. One aggregated warn per fetch call is inert for conformant
servers and bounded for hostile ones. This is the spec's only shipped-code
change; it is additive.

Assert the warning fires using the repo's parallel-safe capture wiring
(`tracing::dispatcher::with_default`, per the existing tracing-test
convention). The dispatcher is thread-local, so scenario 3 pins
`#[tokio::test(flavor = "current_thread")]` and `.await`s the `fetch` call
**inside** the `with_default` guard scope — a current-thread runtime polls the
future on the test thread, so the `warn!` fires on the thread the dispatcher
covers. Because that thread-local dispatcher also captures incidental warns from
async-imap, rustls, and the co-scheduled `FakeImapServer` task, the assertion
**filters** captured events to the fetch skip warn (by its target/message) and
asserts exactly one *matching* event whose `skipped_uids` equals the observed
skip count (see the scenario-3 contingency below) — not a raw total-event count,
which would break on any unrelated warn on the shared dispatcher.

**Scenario 4 — truncated response mid-literal, typed error no hang.** Log in,
`EXAMINE` (the fetch path's read-only open, as in scenario 3 — not `SELECT`),
then answer a `UID FETCH` with a `BODY[]` literal announcing `{100}`
but `Send` fewer than 100 bytes followed by `Disconnect`. `Disconnect` bare-drops
the TLS/TCP stream (prompt FIN, no `close_notify`), so async-imap's read sees
EOF mid-literal on the loopback socket essentially immediately (sub-millisecond)
and surfaces a truncation-class `ImapError` (`Protocol` or `ConnectionLost`).
Scenario 4 uses `connection_with(..)` with a **generous ~5s** `command_timeout`
so the near-instant loopback EOF unambiguously wins the race against the
backstop timeout on any plausibly-loaded CI runner. Assert the call returns
`Err(_)` and that it is **not** an `ImapError::Timeout` — proving the client
detects the truncation itself rather than merely timing out. The timeout remains
only as a no-hang backstop; making it large removes the flake surface the strict
variant-exclusion would otherwise create, while keeping the AC-required "typed
error, no hang" assertion meaningful.

**Contingency (verified during TDD, not assumed).** Whether async-imap 0.11
converts an EOF received after a `{100}` literal announcement but before 100
bytes into an `Err` on the next `stream.next()` — versus a graceful `None` that
would end `ops::fetch`'s `while let Some(msg)` loop and return `Ok(partial)` — is
an assumption about async-imap internals, **not** settled fact. The build step
MUST first capture the actual outcome of a mid-literal bare-drop against
async-imap 0.11 and pin the observed `ImapError` variant (rather than the
`Protocol | ConnectionLost` guess named here). **If** the mid-literal EOF is
delivered as a graceful stream end (`Ok`), the harness switches to a truncation
trigger that async-imap does surface as an error — e.g. truncating the *tagged
completion line* itself (EOF before the tagged `OK`, so the command never
completes) or announcing a malformed literal length — so the AC's "typed error"
is actually reachable. The scenario is not considered done until the assertion
observes a real `Err`.

### Component 3 — CONTRIBUTING note

Add a short subsection to `AGENTS.md` (the repo's contributor guide; there is
no separate `CONTRIBUTING.md`) under *Testing expectations*: **use the
in-process fake (`crates/rimap-imap/tests/support/fake_imap.rs`) to test
client behavior against a *misbehaving* server** (missing capabilities,
malformed/zero UIDs, truncated literals, mid-command disconnects); **use the
Dovecot container harness for *conformant* end-to-end behavior**. The fake is
host-runnable and PR-blocking; Dovecot is container-gated and silent-skips.

## Failure modes & edge cases

- **async-imap command count is deterministic but implementation-defined.** The
  post-login `Session::capabilities()` issues a second `CAPABILITY`; the exact
  command sequence (and whether `LOGIN` uses quoted strings vs literals) is
  fixed by async-imap 0.11 and pinned in `Cargo.lock`. The scripts are written
  against the observed sequence (captured during TDD via `join()`), and an
  async-imap bump that changes the dialog will fail these tests loudly — which
  is the intended tripwire, not a flake.
- **Server response tag mismatch would hang.** async-imap correlates the tagged
  completion by tag; a wrong tag would leave the client waiting. `Reply`
  echoes the tag captured by the preceding `Expect`, eliminating this class. Any
  residual hang is bounded by the `command_timeout` and surfaces as
  `ImapError::Timeout`.
- **One connection per server.** Each scenario gets a fresh `FakeImapServer`
  (fresh port, fresh cert/pin). The test awaits the *client* call, then
  `join()`s the server; the server task returns on script completion or client
  disconnect, so no listener leaks across scenarios.
- **rcgen key/signature-scheme compatibility.** The pinned verifier still runs
  `verify_tls13_signature`/`verify_tls12_signature` against the ring provider;
  rcgen's default ECDSA-P256 leaf is in the supported set. If a future rcgen
  default changed to an unsupported scheme, the handshake would fail with a
  `TlsHandshake` error — caught immediately by scenario 1's login.
- **Scenario 4 races truncation vs timeout.** Resolved by construction:
  `Disconnect` bare-drops the socket (prompt FIN, no `close_notify`), so the
  loopback EOF is observed sub-millisecond, while scenario 4's `command_timeout`
  is set to ~5s — a ~1000× margin. The assertion excludes `Timeout` so a
  regression to "only the timeout saved us" is caught, but the large margin
  keeps that exclusion from flaking on a loaded CI runner.
- **LOGIN literal encoding is a known cliff, not a silent hang.** The `Step`
  vocabulary models one CRLF line per client command and cannot answer an IMAP
  literal continuation (`{n}\r\n` → server `+ …\r\n` → remaining bytes). async-
  imap 0.11 (pinned in `Cargo.lock`) encodes `LOGIN` as quoted strings for the
  constrained ASCII credentials the harness injects, so no literal is emitted
  today. If a future async-imap bump switched `LOGIN` (or any argument) to
  literal encoding, the script would desync and the call would fail via the
  command-timeout backstop — a loud, bounded failure that flags the cliff, not
  a silent hang. Adding a `+` continuation step is deferred until a scenario
  needs it.
- **`folder_wide_expunge` vs `used_fallback`.** Scenario 1 asserts **both**:
  `used_fallback` (`!has_move`) is also true on the *safe* scoped-UID path, so
  only the conjunction with `folder_wide_expunge` (`!has_move && !has_uidplus`)
  proves the data-loss branch ran.

## Testing

- Fast, no Docker, PR-blocking: `expunge_folder_wide_gap.rs` (scenario 1) and
  `adversarial_imap.rs` (scenarios 2–4).
- `just ci` green locally (`fmt-check`, `lint`, `test`, `deny`, hooks). No
  `.github/workflows` change, so no `actionlint`/`zizmor` delta. No new
  dependency, so no `cargo-deny` delta.
- The added aggregated `warn!` (scenario 3) is asserted via
  `tracing::dispatcher::with_default` under a pinned `current_thread` runtime.

## Considered & rejected

- **One combined test binary (mirror #517 exactly).** #517 puts all scenarios
  in a single `real_socket.rs` so its `support` module has no unused-helper
  warnings without any `#[allow]`. Rejected here because the AC names
  `expunge_folder_wide_gap.rs` specifically ("no longer `#[ignore]`d"); keeping
  that file as a real test reads more honestly than deleting it and folding
  scenario 1 into a differently-named binary. The `dead_code` cost is paid once
  with the module-level `#![allow(dead_code)]` the repo already uses for shared
  test support.
- **Ship the harness as a `#[cfg(feature = "test-support")]` library module**
  (in `src/`, like the crate's existing `test-support` feature) so multiple
  test binaries share one compiled copy with no `dead_code` friction. Rejected:
  the AC explicitly requires the harness "under
  `crates/rimap-imap/tests/support/`", and a `tests/support/` module keeps the
  fake out of the shipped library surface entirely.
- **STARTTLS transport for the fake.** Rejected in favor of implicit TLS: the
  scenarios under test are post-login behaviors (or the LOGINDISABLED
  capability check), none of which are STARTTLS-specific; implicit TLS removes
  the plaintext-negotiation step and matches the Proton Bridge posture. The
  existing plaintext `MockImap` already covers the STARTTLS negotiation paths.
- **A capability-set enum / structured mailbox model.** Rejected as premature
  abstraction for four scripts. Raw `* CAPABILITY …` lines and ordered `Step`s
  are the issue's prescribed model and keep each script self-documenting.
- **Leave the FETCH skip silent (test-only, no `warn!`).** Rejected: the AC
  says "skip-with-warning", and a compromised server silently dropping messages
  by omitting/zeroing UIDs is exactly the kind of event the audit/observability
  story should surface.
- **Per-item FETCH `warn!`.** Rejected in favor of a single aggregated warn
  carrying the skipped count: a per-item warn is driven 1:1 by attacker-
  controlled response items, turning the observability signal into a log-flood
  amplifier under the very threat it targets.

## Rollout / rollback

Additive: a new `tests/support/` harness, a rewritten (previously-ignored) test
file, a new test binary, one aggregated `warn!` (plus a skipped-count
accumulator) in `ops/fetch.rs`, and an `AGENTS.md` note. No migration, no
shipped-dependency change, no public-contract change. Rollback is a straight
revert; the `ops/fetch.rs` `warn!` add is independently revertible from the test
scaffolding.
