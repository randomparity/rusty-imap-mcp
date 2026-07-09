# Real SMTP protocol e2e (#517) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Drive the real `SmtpClient` over a socket so `send_email`/`forward` have functional SMTP coverage, and fix the negative-reply classification bug the fake hid.

**Architecture:** Two test homes. (A) `rimap-smtp` unit + in-process scripted-responder tests — no Docker, runs in the fast PR set — cover the error taxonomy (auth/RCPT/STARTTLS/timeout) against the real `SmtpClient::send_raw`. (B) `rimap-server` container-gated e2e injects a real `SmtpClient` (pointed at Mailpit) into `AccountState.smtp` in place of `FakeSmtpSender`, backed by the Dovecot fixture, and asserts real delivery.

**Tech Stack:** Rust 2024, lettre 0.11, tokio, tokio-rustls + rcgen (test cert), ureq (Mailpit HTTP retrieval, dev-dep), Mailpit + Dovecot containers.

**Spec:** `docs/superpowers/specs/2026-07-09-issue-517-smtp-real-e2e-design.md`
**ADR:** `docs/ADR/0001-smtp-real-socket-e2e-and-auth-taxonomy.md`

## Global Constraints

- MSRV 1.88.0; dev toolchain 1.94.0. Never break the MSRV build.
- Workspace deps declared once in root `[workspace.dependencies]`; member crates use `foo = { workspace = true }`, never inline versions. Dev-deps added here (`rcgen`, `ureq`) follow the same rule.
- Zero warnings: `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` clean. No `unwrap()`/`panic!`/`println!` in non-test code; tests may `#[expect(clippy::unwrap_used, reason = "tests")]` the whole `mod`.
- No `#[allow(...)]`; use `#[expect(..., reason = "...")]`.
- `thiserror` for `rimap-smtp` (library). 100-char lines. Absolute imports only. `#![deny(missing_docs)]` on public crates.
- Container tests: silent-skip without a runtime, honor `RIMAP_CONTAINER_TOOL` / `RIMAP_REQUIRE_DOCKER`, stay out of the PR-blocking check set.
- Every `uses:` in workflows is a 40-char SHA + version comment (not touched here). Compose image pins are full digests + version comment.
- Guardrails (run before each commit that changes code): `just fmt-check`, `just lint`, `just test-fast` (or targeted `cargo test -p <crate>`), and `just ci` before the final push. New deps must pass `just deny`.
- Commit conventional-commit style, imperative ≤72-char subject, end with the `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>` trailer. Stage explicit paths only.

## File Structure

- `crates/rimap-smtp/src/error.rs` — add `SmtpError::Auth`; map to `ErrorCode::Auth`.
- `crates/rimap-smtp/src/client.rs` — reply-code classification + `send_raw` operation timeout; `SmtpClient` gains a `deadline` field.
- `crates/rimap-smtp/tests/support/smtp_responder.rs` (new) — scripted in-process SMTP responder.
- `crates/rimap-smtp/tests/real_socket.rs` (new) — the four taxonomy scenarios driving `SmtpClient`.
- `crates/rimap-smtp/tests/support/certs.rs` (new) — rcgen self-signed cert for the STARTTLS scenario.
- `crates/rimap-smtp/Cargo.toml` — add `tokio` to `[dependencies]` (Task 2); dev-deps: `tokio-rustls`, `rustls`, `rcgen` (+ extend `tokio` features).
- `Cargo.toml` (workspace) — add `rcgen` and `ureq` to `[workspace.dependencies]`.
- `crates/rimap-imap/tests/integration/smtp/docker-compose.yml` — re-pin Mailpit; add `MP_SMTP_AUTH_ALLOW_INSECURE`.
- `crates/rimap-server/tests/support/mailpit/mod.rs`, `harness.rs` (new) — Mailpit container harness + HTTP retrieval.
- `crates/rimap-server/tests/e2e_smtp_real.rs` (new) — real-delivery e2e through dispatch.
- `crates/rimap-server/Cargo.toml` — dev-dep: `ureq`.

---

### Task 1: `SmtpError::Auth` variant + reply-code classification

Fixes the core bug: 4xx/5xx server replies currently fall through to `Transport`/`Internal` because `classify_smtp_error` never inspects `err.status()`. Adds an auth-specific variant.

**Files:**
- Modify: `crates/rimap-smtp/src/error.rs`
- Modify: `crates/rimap-smtp/src/client.rs`
- Test: unit tests inline in both files.

**Interfaces:**
- Produces: `SmtpError::Auth { reason: String }`; `fn classify_reply_code(code: u16) -> ReplyClass` where `enum ReplyClass { Auth, Rejected }`; existing `classify_smtp_error(err) -> SmtpError` unchanged in signature.
- Consumes: `lettre::transport::smtp::Error::status() -> Option<Code>`, `u16::from(Code)`.

- [ ] **Step 1: Write the failing test (error.rs)** — add to `mod tests`:

```rust
#[test]
fn auth_maps_to_auth_code() {
    let err = SmtpError::Auth { reason: "535 5.7.8 bad creds".into() };
    let mapped: RimapError = err.into();
    assert_eq!(mapped.code(), ErrorCode::Auth);
    assert!(mapped.to_string().contains("535 5.7.8 bad creds"));
}

#[test]
fn auth_display_includes_reason() {
    let err = SmtpError::Auth { reason: "credentials rejected".into() };
    assert!(err.to_string().contains("credentials rejected"));
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p rimap-smtp --lib error:: 2>&1 | tail -20`
Expected: FAIL — `SmtpError::Auth` does not exist (compile error).

- [ ] **Step 3: Add the variant + mapping (error.rs)**

Add to `enum SmtpError` (after `Rejected`):

```rust
    /// Server rejected authentication (e.g. 535 5.7.8).
    #[error("SMTP authentication failed: {reason}")]
    Auth {
        /// Server response reason.
        reason: String,
    },
```

Add to the `match &err` in `From<SmtpError> for RimapError`:

```rust
            SmtpError::Auth { .. } => ErrorCode::Auth,
```

- [ ] **Step 4: Run to verify error.rs tests pass**

Run: `cargo test -p rimap-smtp --lib error:: 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 5: Write the failing test (client.rs)** — add to `mod tests`:

```rust
#[test]
fn reply_code_535_classifies_as_auth() {
    assert_eq!(super::classify_reply_code(535), super::ReplyClass::Auth);
}

#[test]
fn reply_code_454_classifies_as_auth() {
    assert_eq!(super::classify_reply_code(454), super::ReplyClass::Auth);
}

#[test]
fn reply_code_550_classifies_as_rejected() {
    assert_eq!(super::classify_reply_code(550), super::ReplyClass::Rejected);
}

#[test]
fn reply_code_450_classifies_as_rejected() {
    assert_eq!(super::classify_reply_code(450), super::ReplyClass::Rejected);
}

#[test]
fn shape_auth_maps_to_auth_variant() {
    assert_eq!(shape_to_variant_name(SmtpErrorShape::Auth), "Auth");
}
```

- [ ] **Step 6: Run to verify it fails**

Run: `cargo test -p rimap-smtp --lib client:: 2>&1 | tail -20`
Expected: FAIL — `classify_reply_code` / `ReplyClass` / `SmtpErrorShape::Auth` undefined.

- [ ] **Step 7: Implement classification (client.rs)**

Add the reply-code classifier above `SmtpErrorShape`:

```rust
/// Whether a server negative-reply code denotes an authentication failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReplyClass {
    Auth,
    Rejected,
}

/// Recognized SMTP authentication reply codes (RFC 4954 / RFC 5321):
/// permanent 530/534/535/538, transient 432/454.
fn classify_reply_code(code: u16) -> ReplyClass {
    const AUTH_CODES: [u16; 6] = [530, 534, 535, 538, 432, 454];
    if AUTH_CODES.contains(&code) {
        ReplyClass::Auth
    } else {
        ReplyClass::Rejected
    }
}
```

Add `Auth` and `Rejected` to `SmtpErrorShape` (replace the old `Response` arm usage), and rework `of`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SmtpErrorShape {
    /// Server sent a negative reply that is not an auth failure.
    Rejected,
    /// Server sent an authentication-failure reply code.
    Auth,
    /// The operation exceeded the configured timeout.
    Timeout,
    /// TLS handshake / certificate failure.
    Tls,
    /// Client-side / protocol-setup failure.
    Client,
    /// Anything else (network, connection, shutdown).
    Other,
}

impl SmtpErrorShape {
    fn of(err: &lettre::transport::smtp::Error) -> Self {
        // Timeout and TLS take precedence over the broader predicates.
        // A well-formed negative reply carries a status code; split it into
        // Auth vs Rejected. A response *parse* error (is_response) has no
        // status and is treated as a protocol rejection.
        if err.is_timeout() {
            Self::Timeout
        } else if err.is_tls() {
            Self::Tls
        } else if let Some(code) = err.status() {
            match classify_reply_code(u16::from(code)) {
                ReplyClass::Auth => Self::Auth,
                ReplyClass::Rejected => Self::Rejected,
            }
        } else if err.is_response() {
            Self::Rejected
        } else if err.is_client() {
            Self::Client
        } else {
            Self::Other
        }
    }
}
```

Rework `classify_smtp_error`:

```rust
fn classify_smtp_error(err: lettre::transport::smtp::Error) -> SmtpError {
    match SmtpErrorShape::of(&err) {
        SmtpErrorShape::Rejected => SmtpError::Rejected { reason: err.to_string() },
        SmtpErrorShape::Auth => SmtpError::Auth { reason: err.to_string() },
        SmtpErrorShape::Timeout => SmtpError::Timeout,
        SmtpErrorShape::Tls => SmtpError::Tls(err),
        SmtpErrorShape::Client => SmtpError::Connection(err),
        SmtpErrorShape::Other => SmtpError::Transport(err),
    }
}
```

Update `shape_to_variant_name` (the `#[cfg(test)]` mirror):

```rust
#[cfg(test)]
fn shape_to_variant_name(shape: SmtpErrorShape) -> &'static str {
    match shape {
        SmtpErrorShape::Rejected => "Rejected",
        SmtpErrorShape::Auth => "Auth",
        SmtpErrorShape::Timeout => "Timeout",
        SmtpErrorShape::Tls => "Tls",
        SmtpErrorShape::Client => "Connection",
        SmtpErrorShape::Other => "Transport",
    }
}
```

Update the existing `shape_response_maps_to_rejected_variant` test: rename to `shape_rejected_maps_to_rejected_variant` and use `SmtpErrorShape::Rejected`.

- [ ] **Step 8: Run to verify client.rs tests pass**

Run: `cargo test -p rimap-smtp --lib 2>&1 | tail -20`
Expected: PASS (all lib tests).

- [ ] **Step 9: Lint + commit**

Run: `just fmt-check && cargo clippy -p rimap-smtp --all-targets --all-features --locked -- -D warnings`
Expected: clean.

```bash
git add crates/rimap-smtp/src/error.rs crates/rimap-smtp/src/client.rs
git commit -m "fix(smtp): classify negative replies; add SmtpError::Auth"
```

---

### Task 2: Bound the whole SMTP operation with a timeout

lettre only times out TCP connect; a stalled server hangs `send_raw` forever. Wrap the transport call in `tokio::time::timeout`; an elapsed deadline → `SmtpError::Timeout`.

**Files:**
- Modify: `crates/rimap-smtp/src/client.rs`
- Modify: `crates/rimap-smtp/Cargo.toml` (add `tokio` to `[dependencies]` — the wrapper runs in **library** code, and `tokio` is currently only a dev-dep).
- Test: inline `#[tokio::test]` using a bare `TcpListener` that accepts then withholds the banner.

**Interfaces:**
- Consumes: `SmtpClient::new` already computes `timeout: Duration`.
- Produces: `SmtpClient` gains a private `deadline: Duration` field; `send_raw` behavior maps `Elapsed → SmtpError::Timeout`.

- [ ] **Step 1: Write the failing test** — add to `mod tests` (needs `std::net::TcpListener`, `std::thread`):

```rust
#[tokio::test]
async fn send_raw_times_out_when_server_withholds_banner() {
    // A listener that accepts the connection but never sends the 220
    // greeting. lettre's connect succeeds; the banner read would hang, so
    // the send_raw operation deadline must fire.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let _keep = listener.accept(); // hold the connection open, send nothing
        std::thread::sleep(std::time::Duration::from_secs(5));
    });

    let cfg = SmtpConfig {
        host: "127.0.0.1".into(),
        port,
        encryption: SmtpEncryption::None,
        username: "user@example.com".into(),
        command_timeout_seconds: 1,
    };
    let client = SmtpClient::new(&cfg, "pw").unwrap();
    let env = SendEnvelope { from: "a@example.com".into(), to: vec!["b@example.com".into()] };

    let err = client.send_raw(&env, b"From: a\r\n\r\nhi").await.unwrap_err();
    let SmtpError::Timeout = err else { panic!("expected Timeout, got {err:?}") };
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p rimap-smtp --lib send_raw_times_out -- --nocapture 2>&1 | tail -20`
Expected: FAIL — the call hangs until the test harness times out (no operation deadline yet). If it hangs, that itself confirms the gap; proceed to implement.

- [ ] **Step 3: Add the deadline field + timeout wrapper**

First add `tokio` to `crates/rimap-smtp/Cargo.toml` `[dependencies]` (the
workspace feature set already includes `time`):

```toml
tokio = { workspace = true }
```

In `SmtpClient`:

```rust
pub struct SmtpClient {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    deadline: Duration,
}
```

In `new`, store the deadline (reuse the `timeout` already computed):

```rust
        let transport = builder.credentials(creds).timeout(Some(timeout)).build();
        Ok(Self { transport, deadline: timeout })
```

Rewrite the body of `send_raw`:

```rust
    pub async fn send_raw(&self, envelope: &SendEnvelope, raw: &[u8]) -> Result<String, SmtpError> {
        let lettre_env = build_lettre_envelope(envelope)?;
        let send = self.transport.send_raw(&lettre_env, raw);
        let response = match tokio::time::timeout(self.deadline, send).await {
            Ok(Ok(response)) => response,
            Ok(Err(e)) => return Err(classify_smtp_error(e)),
            Err(_elapsed) => return Err(SmtpError::Timeout),
        };
        Ok(format_response(&response))
    }
```

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p rimap-smtp --lib send_raw_times_out 2>&1 | tail -20`
Expected: PASS within ~1-2s.

- [ ] **Step 5: Lint + commit**

Run: `just fmt-check && cargo clippy -p rimap-smtp --all-targets --all-features --locked -- -D warnings`

```bash
git add crates/rimap-smtp/src/client.rs crates/rimap-smtp/Cargo.toml
git commit -m "fix(smtp): bound whole send operation with a timeout"
```

---

### Task 3: In-process scripted SMTP responder + test cert

A reusable test harness serving one scripted SMTP dialog per scenario, for Task 4. Lives under `crates/rimap-smtp/tests/support/` so it compiles only for integration tests.

**Files:**
- Create: `crates/rimap-smtp/tests/support/mod.rs`
- Create: `crates/rimap-smtp/tests/support/smtp_responder.rs`
- Create: `crates/rimap-smtp/tests/support/certs.rs`
- Modify: `crates/rimap-smtp/Cargo.toml` (dev-deps `tokio-rustls`, `rustls`, `rcgen`; extend `tokio` features)
- Modify: `Cargo.toml` (workspace) — add `rcgen` to `[workspace.dependencies]`

**Interfaces:**
- Produces:
  - `enum Scenario { AuthReject, RcptReject, StarttlsBadCert, TimeoutNoBanner }`
  - `struct Responder { pub port: u16 }` with `async fn Responder::spawn(scenario: Scenario) -> Responder` — binds `127.0.0.1:0`, serves exactly one connection on a background task, returns once listening.
  - `fn certs::self_signed() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)`.

- [ ] **Step 1: Add dev-deps.** In workspace `Cargo.toml` `[workspace.dependencies]` (look up the current stable `rcgen` version first, e.g. `cargo search rcgen`):

```toml
rcgen = "0.13"
```

In `crates/rimap-smtp/Cargo.toml` `[dev-dependencies]` — add `rustls` and
`tokio-rustls` (the responder uses `rustls::ServerConfig` and
`rustls::pki_types` directly, so `rustls` must be a declared dev-dep, not
relied on transitively), and **extend** the existing `tokio` dev-dep features
so the responder's `tokio::net` + `tokio::io` use does not depend on lettre's
transitive feature unification:

```toml
tokio = { workspace = true, features = ["test-util", "macros", "net", "io-util", "rt"] }
tokio-rustls = { workspace = true }
rustls = { workspace = true }
rcgen = { workspace = true }
```

Run: `cargo fetch` and `just deny` to confirm the new deps pass advisories/licenses/bans.
Expected: `just deny` clean. If a license/ban trips, stop and report — do not add an exception without approval.

- [ ] **Step 2: Write `certs.rs`** (self-signed cert for 127.0.0.1):

```rust
//! Self-signed cert for the STARTTLS-failure scenario. rustls' default
//! roots reject it, which is exactly the handshake failure under test.
#![expect(clippy::unwrap_used, reason = "tests")]

use rustls::pki_types::{CertificateDer, PrivateKeyDer};

pub fn self_signed() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(cert.key_pair.serialize_der()).unwrap();
    (vec![cert_der], key_der)
}
```

(Verify the exact rcgen 0.13 API surface — `generate_simple_self_signed` returns a `CertifiedKey { cert, key_pair }`; adjust field/method names if the pinned version differs. The build fails fast if wrong.)

- [ ] **Step 3: Write `smtp_responder.rs`.** Full scripted dialog per scenario. Key behaviors (each scenario serves ONE connection then exits):

```rust
//! Minimal scripted SMTP responder driving the real SmtpClient.
#![expect(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

#[derive(Debug, Clone, Copy)]
pub enum Scenario {
    /// Advertise AUTH, reject it with 535 → SmtpError::Auth.
    AuthReject,
    /// Accept AUTH (235), reject RCPT with 550 → SmtpError::Rejected.
    RcptReject,
    /// Advertise + begin STARTTLS, present a self-signed cert → SmtpError::Tls.
    StarttlsBadCert,
}
```

> **Timeout is NOT a responder scenario.** It is covered deterministically at
> the lib level in Task 2 (a bare `std::net::TcpListener` that accepts and
> withholds the banner). Do **not** add a `TimeoutNoBanner` variant here: an
> enum variant never constructed in the `real_socket` test binary trips
> `dead_code` under the `-D warnings` guardrail and blocks the commit.

```rust

pub struct Responder {
    pub port: u16,
}

impl Responder {
    pub async fn spawn(scenario: Scenario) -> Responder {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                let _ = serve(stream, scenario).await;
            }
        });
        Responder { port }
    }
}

async fn serve(mut stream: TcpStream, scenario: Scenario) -> std::io::Result<()> {
    stream.write_all(b"220 rimap-test ESMTP\r\n").await?;
    // Read EHLO.
    let mut reader = BufReader::new(&mut stream);
    let mut line = String::new();
    reader.read_line(&mut line).await?; // EHLO ...
    match scenario {
        Scenario::AuthReject | Scenario::RcptReject => {
            reader.get_mut()
                .write_all(b"250-rimap-test\r\n250 AUTH PLAIN\r\n").await?;
            line.clear();
            reader.read_line(&mut line).await?; // AUTH PLAIN <b64>
            if let Scenario::AuthReject = scenario {
                reader.get_mut().write_all(b"535 5.7.8 authentication failed\r\n").await?;
                return Ok(());
            }
            reader.get_mut().write_all(b"235 2.7.0 accepted\r\n").await?;
            line.clear(); reader.read_line(&mut line).await?; // MAIL FROM
            reader.get_mut().write_all(b"250 2.1.0 ok\r\n").await?;
            line.clear(); reader.read_line(&mut line).await?; // RCPT TO
            reader.get_mut().write_all(b"550 5.1.1 no such user\r\n").await?;
            Ok(())
        }
        Scenario::StarttlsBadCert => {
            reader.get_mut().write_all(b"250-rimap-test\r\n250 STARTTLS\r\n").await?;
            line.clear();
            reader.read_line(&mut line).await?; // STARTTLS
            reader.get_mut().write_all(b"220 2.0.0 ready\r\n").await?;
            // Upgrade to TLS with a self-signed cert; the client rejects it.
            let (certs, key) = crate::support::certs::self_signed();
            let config = std::sync::Arc::new(
                rustls::ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(certs, key)
                    .unwrap(),
            );
            let acceptor = tokio_rustls::TlsAcceptor::from(config);
            let _ = acceptor.accept(stream).await; // handshake fails on the client
            Ok(())
        }
    }
}
```

`support/mod.rs`:

```rust
pub mod certs;
pub mod smtp_responder;
```

(Adjust `reader.get_mut()` borrow handling if clippy objects; the intent is: write capability lines, read the next client line. If borrow juggling is awkward, drop `BufReader` and read with a manual CRLF loop — behavior, not shape, is what matters.)

- [ ] **Step 4: Compile-check the support module** by referencing it from a throwaway empty test (added properly in Task 4). For now:

Run: `cargo test -p rimap-smtp --test real_socket 2>&1 | tail -20` will fail until Task 4 creates that file — skip running here; Task 3's deliverable is the support module compiling as part of Task 4's binary.

- [ ] **Step 5: Commit** (support module lands with its first consumer in Task 4; if committing separately, ensure it at least `cargo build`s via a minimal `real_socket.rs` stub with `mod support;` and one `#[test] fn placeholder() {}`).

```bash
git add crates/rimap-smtp/tests/support/ crates/rimap-smtp/Cargo.toml Cargo.toml
git commit -m "test(smtp): add scripted SMTP responder + test cert harness"
```

---

### Task 4: Real-socket taxonomy tests (auth / RCPT / STARTTLS / timeout note)

Drive the real `SmtpClient` against the responder and assert each `SmtpError` variant and its `RimapError` code. Timeout is already covered in Task 2; this file covers auth, RCPT, and STARTTLS, and asserts the `RimapError` mapping for all.

**Files:**
- Create: `crates/rimap-smtp/tests/real_socket.rs`

**Interfaces:**
- Consumes: `support::smtp_responder::{Responder, Scenario}`; `rimap_smtp::{SmtpClient, SmtpError, SendEnvelope}`; `rimap_config::model::{SmtpConfig, SmtpEncryption}`.

- [ ] **Step 1: Write the failing tests**

```rust
//! Real-socket SMTP taxonomy: drive SmtpClient against a scripted responder.
#![expect(clippy::unwrap_used, clippy::panic, reason = "tests")]

mod support;

use rimap_config::model::{SmtpConfig, SmtpEncryption};
use rimap_smtp::{SendEnvelope, SmtpClient, SmtpError};
use support::smtp_responder::{Responder, Scenario};

fn config(port: u16, encryption: SmtpEncryption) -> SmtpConfig {
    SmtpConfig {
        host: "127.0.0.1".into(),
        port,
        encryption,
        username: "user@example.com".into(),
        command_timeout_seconds: 5,
    }
}

fn envelope() -> SendEnvelope {
    SendEnvelope { from: "a@example.com".into(), to: vec!["b@example.com".into()] }
}

async fn send(port: u16, enc: SmtpEncryption) -> SmtpError {
    let client = SmtpClient::new(&config(port, enc), "pw").unwrap();
    client.send_raw(&envelope(), b"From: a\r\nTo: b\r\nSubject: t\r\n\r\nbody\r\n")
        .await
        .expect_err("scenario must fail")
}

#[tokio::test]
async fn auth_rejection_maps_to_auth() {
    let r = Responder::spawn(Scenario::AuthReject).await;
    let err = send(r.port, SmtpEncryption::None).await;
    let SmtpError::Auth { .. } = err else { panic!("expected Auth, got {err:?}") };
    let mapped: rimap_core::RimapError = err.into();
    assert_eq!(mapped.code(), rimap_core::ErrorCode::Auth);
}

#[tokio::test]
async fn rcpt_rejection_maps_to_rejected() {
    let r = Responder::spawn(Scenario::RcptReject).await;
    let err = send(r.port, SmtpEncryption::None).await;
    let SmtpError::Rejected { .. } = err else { panic!("expected Rejected, got {err:?}") };
    let mapped: rimap_core::RimapError = err.into();
    assert_eq!(mapped.code(), rimap_core::ErrorCode::SmtpProtocol);
}

#[tokio::test]
async fn starttls_bad_cert_maps_to_tls() {
    let r = Responder::spawn(Scenario::StarttlsBadCert).await;
    let err = send(r.port, SmtpEncryption::Starttls).await;
    let SmtpError::Tls(_) = err else { panic!("expected Tls, got {err:?}") };
    let mapped: rimap_core::RimapError = err.into();
    assert_eq!(mapped.code(), rimap_core::ErrorCode::Tls);
}
```

Add `rimap-core` to `crates/rimap-smtp/Cargo.toml` `[dev-dependencies]` if the mapping assertions need it directly (it is already a normal dependency, so `rimap_core::` is in scope for tests).

- [ ] **Step 2: Run to verify they fail (then pass)**

Run: `cargo test -p rimap-smtp --test real_socket 2>&1 | tail -30`
Expected: with Tasks 1-3 implemented, these PASS. If `StarttlsBadCert` yields `Connection`/`Transport` instead of `Tls`, the responder's TLS upgrade is not being reached — verify the client uses `SmtpEncryption::Starttls` and the responder advertises `STARTTLS` and calls the acceptor. Iterate on the responder until `is_tls()` fires.

- [ ] **Step 3: Lint + commit**

Run: `just fmt-check && cargo clippy -p rimap-smtp --all-targets --all-features --locked -- -D warnings`

```bash
git add crates/rimap-smtp/tests/real_socket.rs crates/rimap-smtp/Cargo.toml
git commit -m "test(smtp): real-socket auth/RCPT/STARTTLS taxonomy coverage"
```

---

### Task 5: Re-pin Mailpit to a multi-arch digest; allow insecure AUTH

The scaffold's pinned digest is single-arch (fails on arm64). Re-pin to the verified multi-arch v1.29.5 index digest and permit plaintext AUTH so lettre's happy path succeeds.

**Files:**
- Modify: `crates/rimap-imap/tests/integration/smtp/docker-compose.yml`

- [ ] **Step 1: Verify the digest is multi-arch** (repeat on any future bump):

Run: `docker manifest inspect docker.io/axllent/mailpit@sha256:c5a6d0ba4d08187f70f305471da5fd9ad424fdfc2f25a2308226a786335dfa9f | grep architecture`
Expected: lists `amd64` and `arm64`. (Verified 2026-07-09.)

- [ ] **Step 2: Apply the edit** — change the image line and comment, and add the env var:

```yaml
    # Mailpit: SMTP sink with HTTP API for test assertions.
    # Pinned by multi-arch index digest — update via Dependabot or manually,
    # re-verifying amd64+arm64 with `docker manifest inspect`.
    # v1.29.5
    image: docker.io/axllent/mailpit@sha256:c5a6d0ba4d08187f70f305471da5fd9ad424fdfc2f25a2308226a786335dfa9f
```

Add under `environment:` (keep the existing keys):

```yaml
      # Permit AUTH over the plaintext loopback connection so lettre's
      # credentialed happy path succeeds.
      MP_SMTP_AUTH_ALLOW_INSECURE: "true"
```

- [ ] **Step 3: Commit**

```bash
git add crates/rimap-imap/tests/integration/smtp/docker-compose.yml
git commit -m "test(smtp): re-pin Mailpit to multi-arch digest; allow insecure AUTH"
```

---

### Task 6: `MailpitHarness` — container lifecycle + HTTP retrieval

Mirror `DovecotHarness`: bring up the Mailpit compose, reserve two host ports, wait on the HTTP health endpoint, and expose `smtp_port()` + a delivered-message retrieval helper.

**Files:**
- Create: `crates/rimap-server/tests/support/mailpit/mod.rs`
- Create: `crates/rimap-server/tests/support/mailpit/harness.rs`
- Modify: `crates/rimap-server/Cargo.toml` (dev-dep `ureq`)
- Modify: `Cargo.toml` (workspace) — add `ureq` to `[workspace.dependencies]`

**Interfaces:**
- Produces:
  - `struct MailpitHarness` with `try_start() -> Result<Self, HarnessError>` (silent-skip via `HarnessError::DockerUnavailable`), `smtp_port() -> u16`, `api_base() -> String` (e.g. `http://127.0.0.1:<api_port>`), and `fetch_raw_by_subject(&self, subject: &str) -> Option<Vec<u8>>` returning the delivered raw RFC 5322 bytes of the newest message matching `subject`.
- Consumes: the same `RIMAP_CONTAINER_TOOL` / `RIMAP_REQUIRE_DOCKER` gating and `ReservedPort` pattern as `DovecotHarness`.

- [ ] **Step 1: Add `ureq` dev-dep.** Look up the current stable `ureq` (e.g. `2.x`), add to workspace `[workspace.dependencies]` with TLS disabled (loopback HTTP only):

```toml
ureq = { version = "2", default-features = false }
```

In `crates/rimap-server/Cargo.toml` `[dev-dependencies]`: `ureq = { workspace = true }`.

Run: `cargo fetch && just deny`
Expected: clean. If a transitive dep trips bans/licenses, stop and report before adding any exception.

- [ ] **Step 2: Write `harness.rs`.** Reuse the structure of `crates/rimap-server/tests/support/dovecot/harness.rs` (copy the `HarnessError` enum, `runtime()`, `binary_present`, `runtime_available`, `uuid_like`, `ReservedPort`, `compose_down`, retry loop). Differences:
  - `compose_dir` = `<manifest>/../rimap-imap/tests/integration/smtp`.
  - Reserve TWO ports; pass `RIMAP_SMTP_HOST_PORT` and `RIMAP_SMTP_API_PORT` env into `compose up` (matching the compose file's variables).
  - `wait_for_ready` polls `GET {api_base}/api/v1/info` for HTTP 200 instead of reading a fingerprint file.
  - Container name: `format!("{project}-smtp")` (matches the compose `container_name`).

Retrieval helper (exact Mailpit endpoints confirmed against the pinned version — the test fails fast if a path is wrong):

```rust
pub fn fetch_raw_by_subject(&self, subject: &str) -> Option<Vec<u8>> {
    // List messages, find the newest whose Subject matches, fetch its raw source.
    let list = ureq::get(&format!("{}/api/v1/messages", self.api_base()))
        .call().ok()?.into_string().ok()?;
    let json: serde_json::Value = serde_json::from_str(&list).ok()?;
    let id = json["messages"].as_array()?.iter()
        .find(|m| m["Subject"].as_str() == Some(subject))
        .and_then(|m| m["ID"].as_str())?
        .to_string();
    let raw = ureq::get(&format!("{}/api/v1/message/{}/raw", self.api_base(), id))
        .call().ok()?.into_string().ok()?;
    Some(raw.into_bytes())
}
```

`support/mailpit/mod.rs`: `pub mod harness; pub use harness::{MailpitHarness, HarnessError};`

- [ ] **Step 3: Smoke-test the harness** with a temporary test in `e2e_smtp_real.rs` (Task 7 replaces it): start the harness, assert `smtp_port() != 0`. Run with a runtime available:

Run: `RIMAP_REQUIRE_DOCKER=1 cargo test -p rimap-server --test e2e_smtp_real 2>&1 | tail -30`
Expected: harness starts, health check passes. Without a runtime: `cargo test` silent-skips.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-server/tests/support/mailpit/ crates/rimap-server/Cargo.toml Cargo.toml
git commit -m "test(smtp): add Mailpit container harness with HTTP retrieval"
```

---

### Task 7: Real-delivery e2e through dispatch

Inject a real `SmtpClient` (pointed at Mailpit) into `AccountState.smtp`, backed by Dovecot for the Sent-copy read-back. Assert successful submission, multipart delivered-bytes, Bcc-excluded, and Sent-copy fail-open.

**Files:**
- Modify/replace: `crates/rimap-server/tests/e2e_smtp_real.rs` (created with a smoke test in Task 6; replace the smoke test with the real assertions).

**Interfaces:**
- Consumes: `support/dovecot/mod.rs` (via `#[path]`), `support/mailpit/mod.rs`, `MailpitHarness::fetch_raw_by_subject`, and the `build_server`/`test_account_config`/`call_tool`/`search_folder`/`fetch_body` helpers — copy the needed helpers from `e2e_smtp.rs` (or extract a shared `support/smtp_dispatch.rs`; keep it simple — duplication across two e2e binaries is acceptable and matches the repo's per-binary `#[path]` pattern).
- Produces: `build_server_real(&DovecotHarness, &MailpitHarness) -> ServerScope`, where `ServerScope` keeps the download `TempDir` and exposes `download_dir(&self) -> &Path`.
- The one change from `e2e_smtp.rs`: build a real sender instead of a fake:

```rust
let smtp_cfg = rimap_config::model::SmtpConfig {
    host: "127.0.0.1".into(),
    port: mailpit.smtp_port(),
    encryption: rimap_config::model::SmtpEncryption::None,
    username: ACCOUNT_USERNAME.into(),
    command_timeout_seconds: 30,
};
let real = rimap_smtp::SmtpClient::new(&smtp_cfg, "testpass").expect("smtp client");
// AccountState { smtp: Some(Box::new(real)), .. }
```

- [ ] **Step 1: Write the failing test.** One `#[tokio::test]` that silent-skips when either harness is unavailable:

```rust
#[tokio::test]
async fn e2e_send_email_real_socket_delivers_and_copies() {
    let dovecot = match DovecotHarness::try_start() {
        Ok(h) => h, Err(HarnessError::DockerUnavailable) => return,
        Err(e) => panic!("dovecot: {e}"),
    };
    let mailpit = match MailpitHarness::try_start() {
        Ok(h) => h, Err(mailpit_support::HarnessError::DockerUnavailable) => return,
        Err(e) => panic!("mailpit: {e}"),
    };
    dovecot.create_mailbox("Sent");
    let scope = build_server_real(&dovecot, &mailpit);

    // Attachments are sourced from the account's download-sandbox root, not
    // passed inline. Stage a file there, then reference it by basename.
    // `AttachmentInput` (message_builder.rs) is { path, filename?, content_type? }.
    std::fs::write(scope.download_dir().join("note.txt"), b"hello attachment")
        .expect("stage attachment");

    // Multipart message with an attachment.
    let subject = "e2e-smtp-real-multipart";
    let result = call_tool(&scope.server, "send_email", serde_json::json!({
        "to": [{"address": "rcpt@example.com"}],
        "bcc": [{"address": "blind@secret.example"}],
        "subject": subject,
        "body_text": "hello over a real socket",
        "attachments": [{ "path": "note.txt", "content_type": "text/plain" }],
    })).await.expect("send_email");
    assert_eq!(result["meta"]["sent"], true);

    // Delivered bytes from Mailpit: multipart survived, Bcc excluded from DATA.
    let raw = mailpit.fetch_raw_by_subject(subject).expect("delivered message");
    let parsed = mail_parser::MessageParser::new().parse(&raw).expect("parse");
    assert!(parsed.attachment_count() >= 1 || parsed.parts.len() >= 2, "multipart delivered");
    assert!(parsed.bcc().is_none(), "Bcc header leaked into delivered DATA");
    assert!(!String::from_utf8_lossy(&raw).contains("blind@secret.example"),
        "blind recipient leaked into delivered DATA");

    // Sent-copy landed over IMAP (read-back), independent of self-report.
    let sent = search_folder(&scope.server, "Sent", subject).await;
    assert_eq!(match_count(&sent), 1, "Sent copy not appended");
}
```

The attachment shape is verified against `AttachmentInput` in
`crates/rimap-server/src/tools/compose/message_builder.rs` (`path` required,
`filename`/`content_type` optional; bytes read from the download sandbox via
`retrieval::sandbox::read_sandboxed_file`). `build_server_real` must therefore
expose the account's `download_dir` — return the `TempDir` (as `e2e_smtp.rs`'s
`ServerScope` keeps `_download_dir`) and add a `download_dir(&self) -> &Path`
accessor so the test can stage `note.txt` before the call.

- [ ] **Step 2: Add the Sent-copy fail-open assertion** — a **second, independent** `#[tokio::test]` that starts its **own** Dovecot + Mailpit harnesses and does NOT call `create_mailbox("Sent")`, so the handler's Sent APPEND fails and fail-open engages:

```rust
assert_eq!(result["meta"]["sent"], true);
assert_eq!(result["meta"]["sent_copy"]["failed"], true);
```

> **Isolation is load-bearing.** Each `#[tokio::test]` must own its Dovecot
> container (`DovecotHarness::try_start()` mints a unique compose project via
> `uuid_like`). Do NOT share one harness between the happy-path test (which
> creates `Sent`) and this fail-open test — a shared container would already
> have `Sent` and flip `failed` to `false`. This differs from `e2e_smtp.rs`,
> which uses one shared harness for all its assertions.

- [ ] **Step 3: Run (with runtimes) / verify silent-skip (without)**

Run: `RIMAP_REQUIRE_DOCKER=1 cargo test -p rimap-server --test e2e_smtp_real 2>&1 | tail -40`
Expected: PASS. Without a runtime, `cargo test -p rimap-server --test e2e_smtp_real` returns 0 tests run for the skipped cases (silent-skip).

- [ ] **Step 4: Lint + commit**

Run: `just fmt-check && cargo clippy -p rimap-server --all-targets --all-features --locked -- -D warnings`

```bash
git add crates/rimap-server/tests/e2e_smtp_real.rs
git commit -m "test(smtp): real-socket send_email e2e with Mailpit delivery"
```

---

### Task 8: Forward e2e + full guardrail pass

Add the `forward` real-delivery scenario (mirrors `e2e_smtp.rs`'s forward assertions but against Mailpit), then run the whole suite.

**Files:**
- Modify: `crates/rimap-server/tests/e2e_smtp_real.rs`

- [ ] **Step 1: Add a `forward` test** — its own `#[tokio::test]` with its own Dovecot + Mailpit harnesses (same per-test isolation as Task 7; it cannot reference the happy-path test's local harness values). Seed a source message into INBOX (reuse `seed_forward_source` from `e2e_smtp.rs`), call `forward`, assert `meta.sent == true`, fetch delivered bytes from Mailpit, and assert the `message/rfc822` base64 wrapper survived real delivery (reuse `assert_forward_wrapper`'s logic).

- [ ] **Step 2: Run the targeted suites**

Run: `cargo test -p rimap-smtp && RIMAP_REQUIRE_DOCKER=1 cargo test -p rimap-server --test e2e_smtp_real 2>&1 | tail -40`
Expected: all PASS.

- [ ] **Step 3: Full guardrail pass**

Run: `just ci`
Expected: green (fmt, clippy, test stable, MSRV, deny, hooks). If MSRV fails on a new dev-dep, pin that dep to an MSRV-compatible version and re-run.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-server/tests/e2e_smtp_real.rs
git commit -m "test(smtp): real-socket forward e2e against Mailpit delivery"
```

---

## Self-Review

**Spec coverage:**
- Auth rejection → `SmtpError::Auth` — Task 1 (variant/classifier) + Task 4 (real socket). ✓
- STARTTLS failure → `SmtpError::Tls` — Task 3/4. ✓
- Connection timeout → `SmtpError::Timeout` — Task 2. ✓
- RCPT rejection surfaced — Task 4 (`ERR_SMTP_PROTOCOL`) + Task 7 real delivery. ✓
- Successful submission + Sent-copy fail-open — Task 7. ✓
- Multipart delivered-bytes — Task 7. ✓
- Bcc-excluded (#432) against real delivery — Task 7. ✓
- Multi-arch re-pin + insecure-AUTH env — Task 5. ✓
- Whole-operation timeout semantics/idempotency — documented in spec/ADR; behavior in Task 2. ✓

**Placeholder scan:** the attachment shape (Task 7) is now concrete —
sandbox-file `path`/`content_type` verified against `AttachmentInput`. The only
remaining "verify during build" items are the exact Mailpit HTTP endpoint paths
(Task 6) and the rcgen 0.13 API surface (Task 3); both fail the TDD test loudly
if wrong. No silent TODOs.

**Type consistency:** `Scenario`, `Responder{port}`, `classify_reply_code(u16)->ReplyClass`, `SmtpError::Auth{reason}`, `MailpitHarness::{smtp_port,fetch_raw_by_subject}` are used consistently across tasks.
