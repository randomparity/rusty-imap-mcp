# Real SMTP protocol e2e — send/forward over a real socket — design

Issue: [#517](https://github.com/randomparity/rusty-imap-mcp/issues/517)
(P1, Theme A: close verified full-stack gaps). Verified on `main` @ `f4e6730`.
ADR: [docs/ADR/0001-smtp-real-socket-e2e-and-auth-taxonomy.md](../../ADR/0001-smtp-real-socket-e2e-and-auth-taxonomy.md).
Extends the test-strategy spec
[`2026-04-30-test-strategy-improvements-design.md`](2026-04-30-test-strategy-improvements-design.md) §8.1.

## Problem

`send_email`/`forward` have never opened a real SMTP socket. The production
dialog in `crates/rimap-smtp/src/client.rs` — EHLO, STARTTLS, AUTH,
MAIL/RCPT/DATA, timeout handling, and the `classify_smtp_error` taxonomy — has
zero functional coverage. The only SMTP e2e today,
`crates/rimap-server/tests/e2e_smtp.rs`, injects `FakeSmtpSender`
(`crates/rimap-smtp/src/testing.rs`), an in-memory spy that returns a
preconfigured `SmtpError` **without** running `classify_smtp_error`.

Driving the real client exposes a latent bug: in lettre 0.11 a `4xx` reply is
`Kind::Transient(code)` and a `5xx` reply is `Kind::Permanent(code)`, but
`classify_smtp_error` only checks `is_response()` (which matches `Kind::Response`,
a response-*parse* error) and never `is_permanent()` / `is_transient()`. So a
`550` RCPT rejection or a `535` auth failure is misclassified as
`SmtpError::Transport` → `ErrorCode::Internal`, surfacing `ERR_INTERNAL` instead
of `ERR_SMTP_PROTOCOL`. The fake never caught this because it bypasses the
classifier.

## Acceptance criteria (from the issue)

- Real-socket e2e: successful submission; auth rejection → `SmtpError::Auth`;
  STARTTLS failure → `SmtpError::Tls`; connection timeout → `SmtpError::Timeout`;
  RCPT rejection surfaced to the tool result; Sent-copy fail-open with a live
  server.
- Delivered-bytes assertion for ≥1 multipart message with attachment.
- Bcc-excluded-from-DATA regression net (#432 / `f5e2d855`) verified against
  real delivery.

`SmtpError::Auth` does not exist today; this spec adds it (maps to the existing
`ErrorCode::Auth` / `ERR_AUTH`).

## Non-goals

- No changes to the `send_email`/`forward` tool contracts or response shapes.
- No general-purpose SMTP server; the in-process responder covers only the
  scripted scenarios below.
- No new runtime dependency in shipped crates. Test-only code may use existing
  dev-dependencies (`tokio`, `tokio-rustls`/`rcgen` if a test cert is needed).
- No promotion of container-gated tests into the PR-blocking check set.

## Design

### Component 1 — error taxonomy fix + `SmtpError::Auth` (`rimap-smtp`)

`crates/rimap-smtp/src/error.rs`: add

```rust
/// Server rejected authentication (e.g. 535 5.7.8).
#[error("SMTP authentication failed: {reason}")]
Auth { reason: String },
```

and map `SmtpError::Auth { .. } => ErrorCode::Auth` in `From<SmtpError> for
RimapError`.

`crates/rimap-smtp/src/client.rs`: rework classification so a server negative
reply is read via `err.status() -> Option<Code>` and dispatched by a pure,
unit-testable function:

```rust
fn classify_reply_code(code: Code) -> ReplyClass { Auth | Rejected }
```

Recognized auth codes (RFC 4954 / RFC 5321): permanent `530`, `534`, `535`,
`538`; transient `432`, `454`. All other negative replies → `Rejected`.
`is_timeout`/`is_tls`/`is_client` keep their current precedence and mappings;
only the previously-unhandled `Transient`/`Permanent` path changes. This is
unit-testable without fabricating a lettre `Error` because
`lettre::transport::smtp::response::Code` has public fields.

**Overall-operation deadline (shipped-code robustness fix).** lettre's async
transport applies the configured `.timeout()` only to the TCP *connect* future
(`async_net.rs`); the greeting read and every command read have no deadline. A
server that accepts the connection then stalls — including a hostile one —
hangs `send_email`/`forward` forever. `SmtpClient::send_raw` therefore wraps the
whole `transport.send_raw(..)` call in `tokio::time::timeout(deadline, ..)`,
where `deadline = command_timeout_seconds`; an elapsed deadline maps to
`SmtpError::Timeout` (`ERR_TIMEOUT`) before classification. This closes the
hang gap *and* makes the timeout scenario deterministically testable
in-process (Component 2 scenario 4). It is additive: the happy path completes
well within the deadline, and the connect-phase timeout lettre already applies
is left in place.

### Component 2 — in-process scripted SMTP responder (`rimap-smtp` tests)

A test-only tokio TCP listener under `crates/rimap-smtp/tests/` that:

- binds `127.0.0.1:0`, returns its port, and serves exactly one connection per
  scenario on a background task;
- speaks the minimal dialog (`220` banner, `EHLO` → capability lines,
  `MAIL`/`RCPT`/`DATA`/`.`/`QUIT`) with per-scenario scripted replies;
- supports four scenarios driving the **real `SmtpClient::send_raw`**:
  1. **auth reject** — advertise `AUTH PLAIN`, reply `535 5.7.8 …` to `AUTH` →
     expect `SmtpError::Auth`, `ERR_AUTH`.
  2. **RCPT reject** — reply `550 5.1.1 …` to `RCPT` → expect
     `SmtpError::Rejected`, `ERR_SMTP_PROTOCOL`.
  3. **STARTTLS failure** — configure the client for STARTTLS; advertise
     `STARTTLS`, complete the upgrade, and present a self-signed cert the
     client's default roots reject → expect `SmtpError::Tls`, `ERR_TLS`.
  4. **timeout** — accept the TCP connection and never send the `220` banner;
     `SmtpConfig.command_timeout_seconds` set low (~1s) → the `send_raw`
     overall-operation deadline (Component 1) elapses → expect
     `SmtpError::Timeout`, `ERR_TIMEOUT`.

Each scenario also asserts the `RimapError` code via `From<SmtpError>`.
Runs on every PR — no container runtime.

The STARTTLS-failure scenario is committed to the self-signed-cert mechanism:
the responder completes the `STARTTLS` upgrade and serves a cert generated
in-test with `rcgen` via `tokio-rustls`, which the client's default webpki
roots reject, yielding `Kind::Tls` → `is_tls()` → `SmtpError::Tls`. The
cert-free alternatives are rejected, not deferred: a `454` reply to `STARTTLS`
is `Kind::Transient(454)`, which the reworked classifier routes to `Auth` (454
is a recognized transient auth code), and a mid-STARTTLS connection drop yields
a client/network error — neither sets `is_tls()`. `rcgen` and `tokio-rustls`
are added as `rimap-smtp` dev-dependencies (no shipped-crate dependency
change).

### Component 3 — Mailpit harness + real-delivery e2e (`rimap-server` tests)

`crates/rimap-server/tests/support/mailpit/harness.rs`, mirroring
`DovecotHarness`:

- reuses the compose scaffold at
  `crates/rimap-imap/tests/integration/smtp/docker-compose.yml`, re-pinned to
  the multi-arch v1.29.5 index digest
  `sha256:c5a6d0ba4d08187f70f305471da5fd9ad424fdfc2f25a2308226a786335dfa9f`
  (covers linux/amd64 + linux/arm64) and adding
  `MP_SMTP_AUTH_ALLOW_INSECURE: "true"` (alongside the existing
  `MP_SMTP_AUTH_ACCEPT_ANY`) so lettre's plaintext AUTH succeeds. Multi-arch is
  verified — and re-verified on any future digest bump — with
  `docker manifest inspect docker.io/axllent/mailpit@<digest>` (or
  `docker buildx imagetools inspect`), which must list both `linux/amd64` and
  `linux/arm64`;
- honors `RIMAP_CONTAINER_TOOL` / `RIMAP_REQUIRE_DOCKER`; silent-skips when no
  runtime; reserves two host ports (SMTP 1025, API 8025) via the same
  `ReservedPort` pattern; waits on `GET /api/v1/info`;
- exposes `smtp_port()`, and a retrieval helper that reads
  `GET /api/v1/messages` + `GET /api/v1/message/{id}` (and `/raw`) to fetch
  delivered bytes.

`crates/rimap-server/tests/e2e_smtp_real.rs`: build the same `Full`-posture
in-process server as `e2e_smtp.rs`, but inject a **real** `SmtpClient`
(`SmtpConfig { host: 127.0.0.1, port: mailpit.smtp_port(), encryption: None, … }`)
into `AccountState.smtp` in place of the fake, backed by the existing Dovecot
fixture for the IMAP side. Assertions:

- **Successful submission** — `send_email` → `meta.sent == true`; the message
  is retrievable from Mailpit's API; envelope From = account, RCPT unions
  To+Cc+Bcc.
- **Delivered bytes, multipart+attachment** — send a multipart message with an
  attachment; fetch raw bytes from Mailpit; assert structure (a text part + an
  attachment part) survives real delivery.
- **Bcc excluded from DATA (#432)** — the Bcc recipient is in the Mailpit
  *envelope*/RCPT set but absent from the delivered `DATA` headers and body.
- **Sent-copy fail-open** — with a live SMTP server, `forward`/`send_email`
  succeeds and the Sent APPEND lands (read back over IMAP, as `e2e_smtp.rs`
  does); a fail-open variant (Sent folder absent) asserts `meta.sent == true`
  with `sent_copy.failed == true` — send success is independent of the copy.

Container-gated (both Dovecot and Mailpit); nightly, not PR-blocking.

## Failure modes & edge cases

- **Auth-code false positives.** `535` is unambiguously auth; `530`/`538` can
  appear in non-auth contexts but only ever after a failed/omitted AUTH in
  practice, and mapping them to `ERR_AUTH` (a subtype of protocol failure) is
  not harmful. Documented in the ADR.
- **Responder liveness.** The in-process server serves one connection then
  exits; the test must `await` the client call, not the server task, and must
  not leak the listener across scenarios (each scenario gets a fresh port).
- **Mailpit AUTH over plaintext.** lettre sends AUTH over an unencrypted
  connection whenever credentials are set (no client-side insecure-auth gate),
  so `MP_SMTP_AUTH_ALLOW_INSECURE` is load-bearing: without it the happy-path
  submission fails. The exact failure code is not pinned — Mailpit may reject
  the AUTH (a `5xx` → `ERR_SMTP_PROTOCOL`/`ERR_AUTH`) or simply not advertise a
  compatible mechanism (a lettre client error → `ERR_CONNECTION_LOST`). The
  successful-submission test guards the env var by failing loudly if it is
  missing; it asserts on *send success*, not on a specific failure code.
  `MP_SMTP_AUTH_ACCEPT_ANY` stays set alongside it.
- **arm64.** The single-arch scaffold digest would fail to pull on arm64 (silent
  test failure on Apple Silicon, or a confusing manifest error). The re-pin is
  verified multi-arch with a documented command (see Component 3) that every
  future digest bump — including a Dependabot one — must repeat.
- **Timeout determinism.** The timeout scenario relies on the `send_raw`
  overall-operation deadline (Component 1), not on lettre's connect-only
  timeout and not on wall-clock racing: with `command_timeout_seconds ≈ 1` and a
  responder that accepts but withholds the banner, the deadline fires
  deterministically in-process. A blackhole-address connect timeout is *not*
  used — it is environment-sensitive (an ICMP unreachable fast-fails as a
  connection error, not a timeout).

## Testing

- `rimap-smtp` unit tests: `classify_reply_code` over the auth-code set and a
  representative non-auth `550`/`450`; `SmtpError::Auth → ERR_AUTH` mapping and
  Display.
- `rimap-smtp` responder tests (fast, no Docker): the four scripted scenarios.
- `rimap-server` `e2e_smtp_real.rs` (container-gated): successful submission,
  multipart delivered-bytes, Bcc-excluded, Sent-copy fail-open.
- Guardrails: `just ci` green locally (`fmt-check`, `lint`, `test`, `deny`,
  hooks). New `.github/workflows` are not touched, so no `actionlint`/`zizmor`
  delta; the compose re-pin keeps a full digest + version comment.

## Rollout / rollback

Additive: a new error variant (`#[non_exhaustive]` enum, so downstream matches
are unaffected), new test binaries, a new harness, and a compose re-pin. No
migration. Rollback is a straight revert; the only shipped-code change is the
`rimap-smtp` classifier + variant, which is independently revertible from the
test scaffolding.
