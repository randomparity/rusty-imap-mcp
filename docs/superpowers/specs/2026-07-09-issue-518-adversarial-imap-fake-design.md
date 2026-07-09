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
  change (Component 2, scenario 3) is a `warn!` on an already-existing silent
  skip — behavior for well-behaved servers is unchanged.

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
    /// Send these bytes verbatim over the TLS stream (untagged data,
    /// tagged replies, greetings, or deliberately malformed bytes).
    Send(Vec<u8>),
    /// Read one CRLF-terminated client command line; assert the verb
    /// (after the client tag) case-insensitively starts with `verb`.
    /// The parsed tag is captured so `SendTagged` can echo it.
    Expect { verb: &'static str },
    /// Read one client command line (asserting `verb`) and reply with the
    /// client's own tag + this suffix, e.g. `SendTagged { verb: "LOGIN",
    /// reply: "OK LOGIN completed" }` emits `<tag> OK LOGIN completed\r\n`.
    SendTagged { verb: &'static str, reply: &'static str },
    /// Sleep, to exercise the client command timeout without closing.
    Delay(Duration),
    /// Drop the TLS session (and TCP) immediately — mid-command disconnect.
    Disconnect,
}
```

Tag echoing (`Expect`/`SendTagged` capture the client's tag and reply with it)
makes the fake robust to async-imap's tag format, unlike the existing plaintext
`MockImap` in `handshake.rs`, which hardcodes `A0001`.

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
  static-password `CredentialResolver` (returns a fixed `SecretString` +
  `CredentialSource::Keyring`), with a short `command_timeout` (~1s) so a hang
  bug fails fast rather than stalling the suite,
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
(advertising `UIDPLUS`), `SELECT`, then answer a `UID FETCH` with three items:
one lacking the `UID` data item, one with `UID 0`, and one well-formed
(`UID 5`). `Connection::fetch` → `ops::fetch` skips the first two at
`fetch.rs:158-163` and returns only `UID 5`. Assert the single returned message.

The skip is currently **silent**. To satisfy the AC's "skip-**with-warning**"
and give operators a signal that a server withheld/zeroed a UID (a hostile-input
indicator per the threat model), add a `tracing::warn!` on each of the two skip
arms. Assert the warnings fire using the repo's parallel-safe capture wiring
(`tracing::dispatcher::with_default`, per the existing tracing-test convention).
This is the spec's only shipped-code change; it is additive and inert for
conformant servers.

**Scenario 4 — truncated response mid-literal, typed error no hang.** Log in,
`SELECT`, then answer a `UID FETCH` with a `BODY[]` literal announcing `{100}`
but `Send` fewer than 100 bytes followed by `Disconnect`. async-imap sees EOF
mid-literal and surfaces a typed `ImapError` (`Protocol` or `ConnectionLost`)
promptly. Assert the call returns `Err(_)` within the ~1s command timeout and
that it is **not** an `ImapError::Timeout` — proving the client detects the
truncation rather than merely timing out. (The command timeout is the belt-and-
suspenders backstop; the EOF is the primary signal.)

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
  completion by tag; a wrong tag would leave the client waiting. `SendTagged`
  echoes the captured client tag, eliminating this class. Any residual hang is
  bounded by the ~1s `command_timeout` and surfaces as `ImapError::Timeout`.
- **One connection per server.** Each scenario gets a fresh `FakeImapServer`
  (fresh port, fresh cert/pin). The test awaits the *client* call, then
  `join()`s the server; the server task returns on script completion or client
  disconnect, so no listener leaks across scenarios.
- **rcgen key/signature-scheme compatibility.** The pinned verifier still runs
  `verify_tls13_signature`/`verify_tls12_signature` against the ring provider;
  rcgen's default ECDSA-P256 leaf is in the supported set. If a future rcgen
  default changed to an unsupported scheme, the handshake would fail with a
  `TlsHandshake` error — caught immediately by scenario 1's login.
- **Scenario 4 races truncation vs timeout.** Closing the connection (EOF)
  after a short partial literal makes the truncation the first observable event;
  the assertion explicitly excludes `Timeout` so a regression to "only the
  timeout saved us" is caught.
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
- The added `warn!`s (scenario 3) are asserted via `tracing::dispatcher::with_default`.

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
  story should surface. The `warn!` is two lines and inert for good servers.

## Rollout / rollback

Additive: a new `tests/support/` harness, a rewritten (previously-ignored) test
file, a new test binary, two `warn!` lines in `ops/fetch.rs`, and an `AGENTS.md`
note. No migration, no shipped-dependency change, no public-contract change.
Rollback is a straight revert; the `ops/fetch.rs` `warn!` add is independently
revertible from the test scaffolding.
