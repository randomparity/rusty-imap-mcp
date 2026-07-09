# ADR-0001: Real-socket SMTP e2e, `SmtpError::Auth`, and negative-reply classification

- **Status:** Accepted
- **Date:** 2026-07-09
- **Issue:** [#517](https://github.com/randomparity/rusty-imap-mcp/issues/517)
- **Spec:** [docs/superpowers/specs/2026-07-09-issue-517-smtp-real-e2e-design.md](../superpowers/specs/2026-07-09-issue-517-smtp-real-e2e-design.md)
- **Supersedes:** none

## Context

`send_email`/`forward` have never opened a real SMTP socket in any test. The
production dialog in `crates/rimap-smtp/src/client.rs` (EHLO, STARTTLS, AUTH,
MAIL/RCPT/DATA, timeout handling) had zero functional coverage: the existing
`crates/rimap-server/tests/e2e_smtp.rs` injects `FakeSmtpSender`, an in-memory
spy that returns a preconfigured `SmtpError` **without** exercising
`classify_smtp_error`.

Driving the real client surfaced a latent classification bug and a taxonomy
gap:

1. **Every server negative reply is misclassified.** In lettre 0.11 a `4xx`
   reply is `Kind::Transient(code)` and a `5xx` reply is `Kind::Permanent(code)`.
   `classify_smtp_error` checks `is_response()` — which matches only
   `Kind::Response`, a *response-parse* failure — and never `is_permanent()` /
   `is_transient()`. So a `550` RCPT rejection or a `535` auth failure falls
   through every arm to `SmtpErrorShape::Other` → `SmtpError::Transport` →
   `ErrorCode::Internal`. The tool surfaces `ERR_INTERNAL` instead of
   `ERR_SMTP_PROTOCOL`. The fake-based test never caught this because it bypasses
   the classifier.

2. **No auth-specific error.** The issue's acceptance criteria name
   `SmtpError::Auth`, which does not exist. `rimap_core::ErrorCode::Auth`
   (`ERR_AUTH`) already exists, so the gap is only in `rimap-smtp`.

Constraints:

- The Dovecot fixture has **no arch gate** — every supported developer host
  (linux/amd64, macOS arm64) runs the suite. Any SMTP container must be
  multi-arch.
- Container-gated tests silent-skip without a runtime and honor
  `RIMAP_REQUIRE_DOCKER=1`; they must stay out of the fast PR-blocking set.
- lettre's `smtp::Error` has crate-private constructors — its variants cannot
  be fabricated in a unit test.

## Decision

### 1. Add `SmtpError::Auth`, classify by reply code

Add a `SmtpError::Auth { reason: String }` variant mapping to the existing
`ErrorCode::Auth` (`ERR_AUTH`). Classification reads `err.status() ->
Option<Code>`: recognized authentication reply codes map to `Auth`, all other
negative replies map to `Rejected`, and everything else keeps its current
mapping. Recognized auth codes (RFC 4954 / RFC 5321):

- Permanent: `530`, `534`, `535`, `538`
- Transient: `432`, `454`

`535` (credentials invalid) is the dominant case a wrong password produces and
is unambiguous. The classifier is refactored into a pure
`classify_reply_code(Code) -> …` function that is unit-testable because
`lettre::transport::smtp::response::Code` has public fields, even though the
enclosing `Error` does not.

Additionally, bound the whole SMTP operation: lettre's async transport applies
its `.timeout()` only to the TCP *connect* future, leaving greeting/command
reads unbounded, so a stalled (or hostile) server hangs `send_email`/`forward`
forever. `SmtpClient::send_raw` wraps the transport call in
`tokio::time::timeout(command_timeout_seconds, ..)`; an elapsed deadline maps to
`SmtpError::Timeout`. This is a shipped-code robustness fix, not test-only, and
it is what makes the timeout scenario deterministically testable with an
in-process responder that accepts then withholds the banner (a blackhole-address
connect timeout was rejected as environment-sensitive).

### 2. Two test homes, split by dependency

- **In-process scripted SMTP responder → `rimap-smtp` crate tests, no Docker,
  runs in the fast PR set.** A tokio TCP listener speaking just enough SMTP,
  with per-scenario scripted replies, drives the real `SmtpClient::send_raw` to
  prove the classifier end-to-end: wrong password → `Auth`/`ERR_AUTH`; `RCPT`
  `550` → `Rejected`/`ERR_SMTP_PROTOCOL`; self-signed STARTTLS cert →
  `Tls`/`ERR_TLS`; silent socket + low timeout → `Timeout`/`ERR_TIMEOUT`.
- **Mailpit + Dovecot through dispatch → `rimap-server`, container-gated.** A
  `MailpitHarness` (mirrors `DovecotHarness`) brings up a re-pinned multi-arch
  Mailpit; a real `SmtpClient` is injected into `AccountState.smtp` in place of
  the fake, and the Dovecot fixture backs the IMAP Sent-copy read-back. Asserts
  successful submission, delivered-bytes for a multipart-with-attachment
  message (fetched from Mailpit's HTTP API), Bcc-excluded-from-DATA (#432)
  against real delivery, and Sent-copy fail-open.

### 3. Re-pin Mailpit to a multi-arch manifest list

The scaffold's pinned digest
(`sha256:0d7b9c8e…`) is a **single-arch** manifest and would fail to pull on
arm64. Re-pin to the v1.29.5 **index** digest
`sha256:c5a6d0ba4d08187f70f305471da5fd9ad424fdfc2f25a2308226a786335dfa9f`,
verified to cover `linux/amd64` + `linux/arm64` via
`docker manifest inspect docker.io/axllent/mailpit@<digest>`; every future
digest bump (including Dependabot's) must re-run that check and confirm both
platforms. Add `MP_SMTP_AUTH_ALLOW_INSECURE` so lettre's plaintext AUTH
succeeds on the happy path.

## Consequences

- **Behavior change (correct):** callers that received `ERR_INTERNAL` for a
  4xx/5xx SMTP reply now receive `ERR_SMTP_PROTOCOL` (or `ERR_AUTH` for auth
  codes). No structured-error `data` shape changes.
- **Behavior change (bounded send):** `send_email`/`forward` now fail with
  `ERR_TIMEOUT` after `command_timeout_seconds` instead of hanging on a stalled
  server. A server slower than the deadline that previously (in the connect
  phase) would have completed is unaffected; only post-connect stalls are newly
  bounded.
- Error-taxonomy coverage runs on every PR (no Docker); only the real-delivery
  assertions are gated.
- `SmtpError` gains a variant. It is `#[non_exhaustive]`, so downstream matches
  need no change, but the crate's own exhaustive matches must add the arm.
- A new, small SMTP-protocol responder lives in test code only; it is not a
  general SMTP server and covers only the scripted scenarios.

## Considered & rejected

- **Fold auth rejection into `Rejected` (no `Auth` variant).** Simpler and the
  `535` reason string is still observable, but an agent caller cannot
  distinguish "fix your credentials" (config) from "fix the recipient"
  (per-message). The distinct `ERR_AUTH` already exists in core; not using it
  would leave the taxonomy poorer for no saving. Rejected by maintainer
  decision on #517.
- **Mailpit-only harness.** Mailpit delivers everything and cannot selectively
  reject a `RCPT`, and forcing STARTTLS/timeout failures against a happy sink is
  awkward; some acceptance criteria become unachievable, and all coverage would
  be Docker-gated.
- **In-process responder only (no container).** Full control and fast, but
  never exercises a real third-party SMTP implementation and diverges from the
  issue's "reuse the container harness / fetch via retrieval API" direction; the
  delivered-bytes assertion would read the responder's own capture rather than a
  real store.
- **Blackhole-address connect timeout (no `send_raw` deadline).** Testing the
  timeout purely at lettre's connect phase by pointing at an unrouted TEST-NET
  address avoids a shipped-code change, but is environment-sensitive: a network
  that answers with ICMP unreachable fast-fails as a connection error, not a
  timeout, making the test flaky. It also leaves the real post-connect hang gap
  unfixed.
- **454-to-STARTTLS or connection-drop for the TLS scenario.** A cert-free way
  to fail STARTTLS, but `454` collides with the recognized transient auth codes
  (routes to `Auth`) and a drop yields a client/network error — neither sets
  `is_tls()`. Only a real handshake against an untrusted self-signed cert
  produces `Kind::Tls`.
