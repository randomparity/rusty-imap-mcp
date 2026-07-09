# Scriptable Adversarial IMAP Fake — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a host-runnable, in-process TLS-terminating fake IMAP server that
replays scripted adversarial dialogs against the real `rimap-imap` client, and use
it to close four structurally-unreachable coverage gaps (folder-wide EXPUNGE data
loss, `LOGINDISABLED`, missing/zero-UID FETCH, truncated-literal).

**Architecture:** A test-only tokio TCP listener under
`crates/rimap-imap/tests/support/` terminates TLS with a self-signed `rcgen`
cert (pinned by fingerprint, so the real `PinningVerifier` accepts it) and
replays an ordered `Vec<Step>` per accepted connection (an accept-loop, so the
client's transparent ReadOnly reconnect re-observes the script). Four scenario
`#[tokio::test]`s drive the real `Connection` and assert the typed outcome. One
two-line shipped change adds an aggregated `warn!` to `ops::fetch`.

**Tech Stack:** Rust 2024, tokio, tokio-rustls (server side), rustls, rcgen
(all already in-tree), async-imap 0.11 (client under test).

**Source spec:** `docs/superpowers/specs/2026-07-09-issue-518-adversarial-imap-fake-design.md`

## Global Constraints

- **MSRV 1.88.0**; dev toolchain 1.94.0. No syntax/deps that break MSRV.
- **Zero warnings, per commit.** CI builds under `RUSTFLAGS="-D warnings"`, and
  `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
  must be clean **after every commit** (bisect-clean). Two consequences that
  bite this plan specifically:
  - `[lints] workspace = true` applies the workspace clippy config
    (`unwrap_used = "deny"`, `expect_used = "warn"`, `panic = "deny"`, …) to the
    package's **integration test crates** too. Test files must suppress the
    lints they trigger.
  - **`#![expect(...)]` must list exactly the lints the file body triggers.** An
    unfulfilled member fires `unfulfilled_lint_expectations`, which `-D warnings`
    turns into a hard error. So `#![expect(clippy::unwrap_used, clippy::expect_used)]`
    on a file with no `.expect()` call FAILS. When a task adds a construct
    (`.unwrap()`, `.expect()`, `panic!`) that a scenario file did not previously
    contain, that same task must update the file's `#![expect(...)]` list.
- **No new shipped dependency.** `rcgen`/`tokio-rustls`/`rustls`/`tracing-subscriber`
  are added only to `rimap-imap` **dev-dependencies** (all already
  `[workspace.dependencies]`).
- **No `#[allow(...)]`** except the module-level `#![allow(dead_code)]` on the
  shared test-support module (mirrors `tests/integration/support/container.rs:7`).
  Elsewhere use `#[expect(..., reason = "...")]`.
- **`#[cfg(test)]` IS set in integration-test crates** (they compile under
  rustc `--test`), so a `#[cfg(test)] mod tests` inside a `tests/support/*.rs`
  file DOES compile and run — but only once some top-level `tests/*.rs` binary
  does `mod support;`. Until then the support module is never compiled.
- **Absolute imports only** (no relative `..`). 100-char lines. Google-style
  docstrings on public items (`missing_docs = "warn"` applies to test targets).
- **Guardrail suite:** `just ci` (`fmt-check`, `lint`, `test`, `deny`, hooks).
  Fast inner loop: `cargo nextest run -p rimap-imap --locked`.
- **TDD:** failing test first, watch it fail, minimal implementation, watch it
  pass, commit. One logical change per commit; conventional-commit subjects
  ≤72 chars; end each commit body with the trailer
  `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.

## Public API reference (verified against the repo — use these exact forms)

- `rimap_imap::{Connection, ConnectionConfig, ImapEncryption}` (re-exported at
  crate root).
- `rimap_imap::error::{AuthFailure, ImapError}`.
- `rimap_imap::types::{FetchSpec, Uid, Folder}`.
- **UID construction from a test crate:** `Uid::new` is `pub(crate)` and
  **unreachable** from `tests/*.rs`. Use the public
  `rimap_imap::types::Uid::from(core::num::NonZeroU32::new(N).unwrap())`
  (exactly as `tests/integration/dovecot.rs:494` does).
- `Connection::move_messages(&self, source_folder, dest_folder, uids: &[Uid], expected_source_uidvalidity: Option<u32>) -> Result<MoveOutcome, ImapError>`
  where `MoveOutcome { used_fallback: bool, folder_wide_expunge: bool, .. }`.
- `Connection::fetch(&self, folder, uids: &[Uid], spec: FetchSpec, expected_uidvalidity: Option<u32>) -> Result<(Vec<FetchedMessage>, Option<u32>), ImapError>`
  where `FetchedMessage { uid: Uid, .. }`.
- `Connection::list_folders(&self, pattern) -> Result<Vec<Folder>, ImapError>`
  where `Folder { name: String, .. }`.
- `rimap_core::TlsFingerprint::from_cert_der(der: &[u8]) -> TlsFingerprint`.
- `secrecy::SecretString::from(String)`, `rimap_core::credential::CredentialSource::Keyring`.

---

## File Structure

- `crates/rimap-imap/Cargo.toml` — `[dev-dependencies]` add `rcgen`,
  `tokio-rustls`, `rustls` (Task 1), then `tracing`, `tracing-subscriber` (Task 5).
- `crates/rimap-imap/tests/support/mod.rs` — `#![allow(dead_code)]`, module decls.
- `crates/rimap-imap/tests/support/certs.rs` — self-signed cert + pin (Task 2).
- `crates/rimap-imap/tests/support/fake_imap.rs` — `Step`, `FakeImapServer` (Task 2).
- `crates/rimap-imap/tests/support/tracing_capture.rs` — scoped warn capture (Task 5).
- `crates/rimap-imap/tests/adversarial_imap.rs` — smoke (Task 2) + scenarios 2, 3, 4.
- `crates/rimap-imap/tests/expunge_folder_wide_gap.rs` — **rewritten** from the
  `#[ignore]` placeholder into scenario 1 (Task 3).
- `crates/rimap-imap/src/ops/fetch.rs` — aggregated skip `warn!` (Task 5).
- `AGENTS.md` — CONTRIBUTING note (Task 7).

**Cargo discovery:** every top-level `tests/*.rs` file is its own test binary;
`tests/support/` is not compiled as a binary — it is included per-scenario-binary
via `mod support;`. Both scenario binaries include it; the module-level
`#![allow(dead_code)]` absorbs per-binary unused-helper warnings.

---

### Task 1: Add dev-dependencies for the fake harness

**Files:**
- Modify: `crates/rimap-imap/Cargo.toml` (`[dev-dependencies]`)

**Rationale:** Kept as its own commit because it is independently verifiable
(the crate still builds, no new modules yet). The support module is NOT created
here — a `tests/support/*.rs` file is not compiled until a binary includes it
(Task 2), so creating it now would land unverified code.

- [ ] **Step 1: Add the dev-deps.** In `crates/rimap-imap/Cargo.toml`, under
  `[dev-dependencies]`, add:

```toml
# In-process fake IMAP server (tests/support): terminates TLS with a
# self-signed rcgen cert the client pins by fingerprint. Test-only; no
# shipped-dependency change (all three are already normal deps of this crate,
# repeated here so dev/test code may use them directly).
rcgen = { workspace = true }
tokio-rustls = { workspace = true }
rustls = { workspace = true }
```

- [ ] **Step 2: Verify the crate still builds.**

```bash
cargo check -p rimap-imap --tests --locked
```

Expected: PASS (no code change, only manifest). This genuinely compiles the
existing test binaries; the new harness arrives in Task 2.

- [ ] **Step 3: Commit.**

```bash
git add crates/rimap-imap/Cargo.toml
git commit -m "test(imap): add dev-deps for in-process fake IMAP server"
```

---

### Task 2: Support module + self-signed cert + `FakeImapServer` + smoke test

**This task is the calibration point.** The exact async-imap 0.11 command
sequence (does `Session::capabilities()` re-issue `CAPABILITY` post-login? are
`LOGIN` args quoted?) is implementation-defined. Task 2's smoke test drives a
real login through the fake and prints `recorded()`; **read that output and
adjust the scenario scripts in Tasks 3–6 to match the observed sequence.** This
is also the **first real compile** of the support module (the smoke binary
`mod support;`s it).

**Files:**
- Create: `crates/rimap-imap/tests/support/mod.rs`
- Create: `crates/rimap-imap/tests/support/certs.rs`
- Create: `crates/rimap-imap/tests/support/fake_imap.rs`
- Create: `crates/rimap-imap/tests/adversarial_imap.rs`

**Interfaces produced:**
- `support::certs::self_signed() -> SelfSigned { chain: Vec<CertificateDer<'static>>, key: PrivateKeyDer<'static>, pin: TlsFingerprint }`
- `enum support::fake_imap::Step { Expect { verb: &'static str }, Send(Vec<u8>), Reply { text: &'static str }, Delay(Duration), Disconnect }`
- `struct support::fake_imap::FakeImapServer` with `async fn start(Vec<Step>) -> Self`,
  `fn port(&self) -> u16`, `fn pin(&self) -> TlsFingerprint`,
  `fn connection(&self, &str) -> Connection`,
  `fn connection_timeout(&self, &str, Duration) -> Connection`,
  `fn connection_with(&self, &str, Arc<dyn CredentialResolver>, Duration) -> Connection`,
  `fn recorded(&self) -> Vec<String>`.
- `struct support::fake_imap::PanicResolver`.

- [ ] **Step 1: Create the support module root.**
  `crates/rimap-imap/tests/support/mod.rs`:

```rust
//! Test support: in-process scriptable adversarial IMAP fake.
//!
//! Included per-scenario-binary via `mod support;`. The module-level
//! `#![allow(dead_code)]` (the one place the repo permits a bare `#[allow]`,
//! mirroring `tests/integration/support/container.rs:7`) absorbs the
//! per-binary unused-helper warnings under CI's `-D warnings`.
#![allow(dead_code)]

pub mod certs;
pub mod fake_imap;
```

- [ ] **Step 2: Create the cert helper.**
  `crates/rimap-imap/tests/support/certs.rs`:

```rust
//! Self-signed leaf for the in-process fake. The client pins its
//! fingerprint, so the `PinningVerifier` (which ignores hostname/chain)
//! accepts it while a system-trust client would reject it.
#![expect(clippy::unwrap_used, reason = "tests")]

use rimap_core::TlsFingerprint;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// A generated self-signed cert bundle plus the leaf-cert pin the client
/// must configure to accept it.
pub struct SelfSigned {
    /// Leaf cert chain for the rustls server config.
    pub chain: Vec<CertificateDer<'static>>,
    /// PKCS#8 private key for the leaf.
    pub key: PrivateKeyDer<'static>,
    /// SHA-256 fingerprint of the leaf DER — the client's `pinned_fingerprint`.
    pub pin: TlsFingerprint,
}

/// Generate a fresh self-signed cert/key for `127.0.0.1` and its pin.
pub fn self_signed() -> SelfSigned {
    let generated = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
    let cert_der = generated.cert.der().clone();
    let pin = TlsFingerprint::from_cert_der(cert_der.as_ref());
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(
        generated.signing_key.serialize_der(),
    ));
    SelfSigned {
        chain: vec![cert_der],
        key,
        pin,
    }
}

#[cfg(test)]
mod tests {
    use super::self_signed;

    #[test]
    fn pin_matches_leaf_der_and_is_fresh_each_call() {
        let a = self_signed();
        assert_eq!(
            a.pin,
            rimap_core::TlsFingerprint::from_cert_der(a.chain[0].as_ref()),
        );
        let b = self_signed();
        assert_ne!(a.pin, b.pin);
    }
}
```

- [ ] **Step 3: Create the fake server.**
  `crates/rimap-imap/tests/support/fake_imap.rs`:

```rust
//! In-process TLS-terminating scriptable IMAP fake. Replays an ordered
//! `Vec<Step>` per accepted connection (accept-loop) so a client's transparent
//! ReadOnly reconnect re-observes the same dialog. Drives the real `Connection`.
#![expect(clippy::unwrap_used, reason = "tests")]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use rimap_core::TlsFingerprint;
use rimap_core::account::AccountId;
use rimap_core::auth_event::AuthEvent;
use rimap_core::auth_sink::{AuthEventSink, AuthSinkError};
use rimap_core::credential::{CredentialResolver, CredentialResolverError, CredentialSource};
use rimap_imap::{Connection, ConnectionConfig, ImapEncryption};
use secrecy::SecretString;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

use crate::support::certs::{self, SelfSigned};

/// Bounded number of connections the accept-loop serves — a ReadOnly retry
/// needs at most 2; the cap prevents a storming client.
const MAX_ACCEPTS: usize = 4;

/// Fixed password the static resolver returns.
const FAKE_PASSWORD: &str = "fake-password";

/// One scripted server step.
pub enum Step {
    /// Read one CRLF client command line; assert the verb (after the tag)
    /// case-insensitively starts with `verb`, and capture the tag for `Reply`.
    Expect { verb: &'static str },
    /// Send these bytes verbatim (untagged data, literals, or malformed bytes).
    Send(Vec<u8>),
    /// Emit `<captured-tag> <text>\r\n` using the most recent `Expect`'s tag.
    Reply { text: &'static str },
    /// Sleep without closing (exercise the command timeout).
    Delay(Duration),
    /// Drop the connection immediately (prompt FIN, no close_notify).
    Disconnect,
}

/// A running fake. Drop aborts the accept-loop and closes the listener.
pub struct FakeImapServer {
    port: u16,
    pin: TlsFingerprint,
    recorded: Arc<Mutex<Vec<String>>>,
    task: JoinHandle<()>,
}

impl Drop for FakeImapServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl FakeImapServer {
    /// Bind `127.0.0.1:0`, spawn the accept-loop, and return once listening.
    pub async fn start(script: Vec<Step>) -> FakeImapServer {
        let SelfSigned { chain, key, pin } = certs::self_signed();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let recorded = Arc::new(Mutex::new(Vec::new()));
        let script = Arc::new(script);
        let rec_task = Arc::clone(&recorded);

        let task = tokio::spawn(async move {
            for _ in 0..MAX_ACCEPTS {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let Ok(tls) = acceptor.accept(stream).await else {
                    continue;
                };
                let _ = serve(tls, &script, &rec_task).await;
            }
        });

        FakeImapServer {
            port,
            pin,
            recorded,
            task,
        }
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn pin(&self) -> TlsFingerprint {
        self.pin
    }

    /// Snapshot of client command lines read so far (for ordering assertions).
    pub fn recorded(&self) -> Vec<String> {
        self.recorded.lock().unwrap().clone()
    }

    /// Fully-wired `Connection` (static-password resolver, ~1s timeout).
    pub fn connection(&self, username: &str) -> Connection {
        self.connection_timeout(username, Duration::from_secs(1))
    }

    /// Static-resolver connection with a caller-chosen command timeout
    /// (scenario 4 uses a generous 5s backstop).
    pub fn connection_timeout(&self, username: &str, command_timeout: Duration) -> Connection {
        self.connection_with(username, Arc::new(StaticResolver), command_timeout)
    }

    /// Inject an arbitrary resolver and command timeout (scenario 2 uses a
    /// `PanicResolver` to prove resolve() is never consulted).
    pub fn connection_with(
        &self,
        username: &str,
        resolver: Arc<dyn CredentialResolver>,
        command_timeout: Duration,
    ) -> Connection {
        let cfg = ConnectionConfig {
            account: None,
            account_id: AccountId::default_account(),
            host: "127.0.0.1".to_string(),
            port: self.port,
            encryption: ImapEncryption::Tls,
            username: username.to_string(),
            pinned_fingerprint: Some(self.pin),
            connect_timeout: Duration::from_secs(5),
            command_timeout,
            max_fetch_body_bytes: 1024 * 1024,
            max_append_bytes: 1024 * 1024,
        };
        Connection::new(cfg, Arc::new(NoopAudit), resolver)
    }
}

async fn serve(
    tls: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    script: &[Step],
    recorded: &Arc<Mutex<Vec<String>>>,
) -> std::io::Result<()> {
    let (read, mut write) = tokio::io::split(tls);
    let mut reader = BufReader::new(read);
    let mut last_tag = String::new();
    for step in script {
        match step {
            Step::Expect { verb } => {
                let mut line = String::new();
                let n = reader.read_line(&mut line).await?;
                if n == 0 {
                    return Ok(()); // client closed
                }
                recorded.lock().unwrap().push(line.clone());
                let (tag, rest) = line.split_once(' ').unwrap_or((line.trim(), ""));
                last_tag = tag.to_string();
                assert!(
                    rest.trim_start().to_ascii_uppercase().starts_with(verb),
                    "fake: expected command `{verb}`, got `{}`",
                    line.trim(),
                );
            }
            Step::Send(bytes) => {
                write.write_all(bytes).await?;
                write.flush().await?;
            }
            Step::Reply { text } => {
                let line = format!("{last_tag} {text}\r\n");
                write.write_all(line.as_bytes()).await?;
                write.flush().await?;
            }
            Step::Delay(d) => tokio::time::sleep(*d).await,
            Step::Disconnect => return Ok(()), // drop halves → FIN
        }
    }
    Ok(())
}

/// Resolver returning a fixed password. Used by `connection()`.
#[derive(Debug)]
struct StaticResolver;

impl CredentialResolver for StaticResolver {
    fn resolve(
        &self,
        _account: &AccountId,
        _username: &str,
        _host: &str,
    ) -> Result<(SecretString, CredentialSource), CredentialResolverError> {
        Ok((
            SecretString::from(FAKE_PASSWORD.to_string()),
            CredentialSource::Keyring,
        ))
    }
}

/// Resolver that panics if consulted — proves the pre-resolve error paths
/// (e.g. LOGINDISABLED) never reach credential resolution.
#[derive(Debug)]
pub struct PanicResolver;

impl CredentialResolver for PanicResolver {
    #[expect(
        clippy::panic,
        clippy::panic_in_result_fn,
        reason = "deliberate: proves the resolver is never called"
    )]
    fn resolve(
        &self,
        _account: &AccountId,
        _username: &str,
        _host: &str,
    ) -> Result<(SecretString, CredentialSource), CredentialResolverError> {
        panic!("credential resolver must not be consulted on this path");
    }
}

/// No-op audit sink.
#[derive(Debug)]
struct NoopAudit;

impl AuthEventSink for NoopAudit {
    fn emit_auth(&self, _event: AuthEvent) -> Result<(), AuthSinkError> {
        Ok(())
    }
}
```

- [ ] **Step 4: Create the smoke test.**
  `crates/rimap-imap/tests/adversarial_imap.rs`:

```rust
//! Adversarial IMAP scenarios driven against the in-process fake
//! (`support::fake_imap`). Scenario 1 (folder-wide EXPUNGE) lives in
//! `expunge_folder_wide_gap.rs`; scenarios 2–4 live here.
//!
//! Fake, no container runtime — runs on every PR.
//!
//! The `#![expect(...)]` list below must match exactly the clippy lints this
//! file's body triggers; later tasks extend it as they add `.unwrap()` /
//! `panic!` constructs (see the plan's Global Constraints).
#![expect(clippy::expect_used, reason = "tests")]

mod support;

use support::fake_imap::{FakeImapServer, Step};

/// Smoke/calibration: a real login + LIST through the fake proves the TLS
/// handshake, pin, greeting, CAPABILITY drain, LOGIN, and post-login
/// CAPABILITY all work end-to-end. Print `recorded()` and use the observed
/// command order to write the scenario scripts in Tasks 3–6.
#[tokio::test]
async fn login_and_list_succeed_through_fake() {
    let server = FakeImapServer::start(vec![
        Step::Send(b"* OK fake ready\r\n".to_vec()),
        Step::Expect { verb: "CAPABILITY" },
        Step::Send(b"* CAPABILITY IMAP4rev1 UIDPLUS\r\n".to_vec()),
        Step::Reply { text: "OK CAPABILITY completed" },
        Step::Expect { verb: "LOGIN" },
        Step::Reply { text: "OK LOGIN completed" },
        // Post-login CAPABILITY probe (login.rs calls session.capabilities()).
        // If calibration shows async-imap does NOT re-issue CAPABILITY here,
        // delete these two steps and move the cap list into the LOGIN OK as
        // `OK [CAPABILITY IMAP4rev1 UIDPLUS] LOGIN completed`.
        Step::Expect { verb: "CAPABILITY" },
        Step::Send(b"* CAPABILITY IMAP4rev1 UIDPLUS\r\n".to_vec()),
        Step::Reply { text: "OK CAPABILITY completed" },
        Step::Expect { verb: "LIST" },
        Step::Send(b"* LIST (\\HasNoChildren) \"/\" \"INBOX\"\r\n".to_vec()),
        Step::Reply { text: "OK LIST completed" },
    ])
    .await;

    let conn = server.connection("user@example.com");
    let folders = conn.list_folders("*").await.expect("list should succeed");
    assert!(folders.iter().any(|f| f.name == "INBOX"));

    // Calibration aid: dump the exact client command order.
    eprintln!("recorded dialog: {:#?}", server.recorded());
}
```

- [ ] **Step 5: Run the smoke test and read the dialog.**

```bash
cargo nextest run -p rimap-imap --locked adversarial_imap --no-capture
```

Expected: PASS. **Read the `recorded dialog:` output** and confirm the command
order (pre-login CAPABILITY, LOGIN, post-login CAPABILITY?, LIST). If it fails on
a `fake: expected command` panic, the observed order differs — adjust the script
until PASS. **The confirmed order is the template for Tasks 3–6.**

- [ ] **Step 6: Confirm clippy is clean (per-commit gate).**

```bash
cargo clippy -p rimap-imap --tests --all-features --locked -- -D warnings
```

Expected: clean. (Confirms the `#![expect(...)]` lists match the triggered lints.)

- [ ] **Step 7: Commit.**

```bash
git add crates/rimap-imap/tests/support/mod.rs \
        crates/rimap-imap/tests/support/certs.rs \
        crates/rimap-imap/tests/support/fake_imap.rs \
        crates/rimap-imap/tests/adversarial_imap.rs
git commit -m "test(imap): add scriptable TLS fake and login smoke test"
```

---

### Task 3: Scenario 1 — folder-wide EXPUNGE data loss (un-ignore)

**Files:**
- Modify (rewrite): `crates/rimap-imap/tests/expunge_folder_wide_gap.rs`

- [ ] **Step 1: Replace the placeholder with the real test.** Overwrite
  `crates/rimap-imap/tests/expunge_folder_wide_gap.rs` entirely. **Adjust the
  CAPABILITY placement and untagged-response shapes to the sequence Task 2
  confirmed.**

```rust
//! Scenario 1: a server advertising neither MOVE nor UIDPLUS forces the
//! COPY + STORE \Deleted + folder-wide EXPUNGE fallback (the data-loss path).
//! Drives the real `Connection::move_messages` against the in-process fake and
//! asserts both `used_fallback` and `folder_wide_expunge`, plus that a plain
//! `EXPUNGE` (not `UID EXPUNGE`) reached the wire.
//!
//! Fake, no container runtime — runs on every PR. Replaces the former
//! `#[ignore]`d placeholder that marked this gap.
#![expect(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

mod support;

use core::num::NonZeroU32;

use rimap_imap::types::Uid;
use support::fake_imap::{FakeImapServer, Step};

#[tokio::test]
async fn no_move_no_uidplus_uses_folder_wide_expunge() {
    let server = FakeImapServer::start(vec![
        Step::Send(b"* OK fake ready\r\n".to_vec()),
        Step::Expect { verb: "CAPABILITY" },
        Step::Send(b"* CAPABILITY IMAP4rev1\r\n".to_vec()),
        Step::Reply { text: "OK CAPABILITY completed" },
        Step::Expect { verb: "LOGIN" },
        Step::Reply { text: "OK LOGIN completed" },
        Step::Expect { verb: "CAPABILITY" },
        Step::Send(b"* CAPABILITY IMAP4rev1\r\n".to_vec()),
        Step::Reply { text: "OK CAPABILITY completed" },
        // move_messages: SELECT source (read-write; select(...,false)).
        Step::Expect { verb: "SELECT" },
        Step::Send(b"* 3 EXISTS\r\n* OK [UIDVALIDITY 1] .\r\n".to_vec()),
        Step::Reply { text: "OK [READ-WRITE] SELECT completed" },
        // UID COPY 5 "Archive"
        Step::Expect { verb: "UID COPY" },
        Step::Reply { text: "OK COPY completed" },
        // STATUS "Archive" (UIDVALIDITY) — dest probe after COPY.
        Step::Expect { verb: "STATUS" },
        Step::Send(b"* STATUS \"Archive\" (UIDVALIDITY 7)\r\n".to_vec()),
        Step::Reply { text: "OK STATUS completed" },
        // UID STORE 5 +FLAGS (\Deleted)
        Step::Expect { verb: "UID STORE" },
        Step::Send(b"* 1 FETCH (FLAGS (\\Deleted))\r\n".to_vec()),
        Step::Reply { text: "OK STORE completed" },
        // Plain EXPUNGE (folder-wide) — NOT `UID EXPUNGE`.
        Step::Expect { verb: "EXPUNGE" },
        Step::Send(b"* 1 EXPUNGE\r\n".to_vec()),
        Step::Reply { text: "OK EXPUNGE completed" },
    ])
    .await;

    let conn = server.connection("user@example.com");
    let uid = Uid::from(NonZeroU32::new(5).unwrap());
    let outcome = conn
        .move_messages("INBOX", "Archive", &[uid], None)
        .await
        .expect("move should succeed via fallback");

    assert!(outcome.used_fallback, "non-atomic fallback must be flagged");
    assert!(
        outcome.folder_wide_expunge,
        "data-loss folder-wide EXPUNGE must be flagged (no MOVE, no UIDPLUS)",
    );

    // Wire check: a plain EXPUNGE was issued, never a scoped UID EXPUNGE.
    let dialog = server.recorded().join("\n").to_ascii_uppercase();
    assert!(dialog.contains("EXPUNGE"), "client must issue EXPUNGE");
    assert!(
        !dialog.contains("UID EXPUNGE"),
        "client must NOT scope the expunge to UIDs on the no-UIDPLUS path",
    );
}
```

- [ ] **Step 2: Run it, adjust the script to the real dialog.**

```bash
cargo nextest run -p rimap-imap --locked expunge_folder_wide_gap --no-capture
```

Expected initially: may FAIL on a `fake: expected command` assert if the
SELECT/COPY/STATUS/STORE/EXPUNGE order or untagged-response shapes differ from
real async-imap. Adjust to the real dialog (use `--no-capture` and `recorded()`),
re-run until PASS. Confirm `used_fallback` / `folder_wide_expunge` hold.

- [ ] **Step 3: Confirm the placeholder is gone.**

```bash
grep -c "#\[ignore" crates/rimap-imap/tests/expunge_folder_wide_gap.rs
```

Expected: `0`.

- [ ] **Step 4: Clippy + commit.**

```bash
cargo clippy -p rimap-imap --tests --all-features --locked -- -D warnings
git add crates/rimap-imap/tests/expunge_folder_wide_gap.rs
git commit -m "test(imap): verify folder-wide EXPUNGE data-loss path via fake"
```

---

### Task 4: Scenario 2 — LOGINDISABLED auth provenance

**Files:**
- Modify: `crates/rimap-imap/tests/adversarial_imap.rs`

- [ ] **Step 1: Widen the module `#![expect(...)]`.** Scenario 2 adds
  `.unwrap_err()` (`unwrap_used`) and `panic!` (`clippy::panic`), so change the
  top of `adversarial_imap.rs` from
  `#![expect(clippy::expect_used, reason = "tests")]` to:

```rust
#![expect(clippy::unwrap_used, clippy::expect_used, clippy::panic, reason = "tests")]
```

- [ ] **Step 2: Add imports** near the top of `adversarial_imap.rs`:

```rust
use std::sync::Arc;
use std::time::Duration;

use rimap_imap::error::{AuthFailure, ImapError};
use support::fake_imap::PanicResolver;
```

- [ ] **Step 3: Add the test** (append to `adversarial_imap.rs`):

```rust
/// Scenario 2: LOGINDISABLED in CAPABILITY yields CapabilityMissing { needed:
/// "LOGIN" } BEFORE credential resolution — a PanicResolver proves resolve()
/// is never consulted.
#[tokio::test]
async fn logindisabled_maps_to_capability_missing_before_resolve() {
    let server = FakeImapServer::start(vec![
        Step::Send(b"* OK fake ready\r\n".to_vec()),
        Step::Expect { verb: "CAPABILITY" },
        Step::Send(b"* CAPABILITY IMAP4rev1 LOGINDISABLED\r\n".to_vec()),
        Step::Reply { text: "OK CAPABILITY completed" },
        // Client must NOT send LOGIN; it errors out here.
    ])
    .await;

    let conn = server.connection_with(
        "user@example.com",
        Arc::new(PanicResolver),
        Duration::from_secs(1),
    );
    let err = conn.list_folders("*").await.unwrap_err();
    match err {
        ImapError::Auth {
            reason: AuthFailure::CapabilityMissing { needed },
        } => assert_eq!(needed, "LOGIN"),
        other => panic!("expected CapabilityMissing {{ needed: LOGIN }}, got {other:?}"),
    }
}
```

- [ ] **Step 4: Run + clippy + commit.**

```bash
cargo nextest run -p rimap-imap --locked logindisabled --no-capture
cargo clippy -p rimap-imap --tests --all-features --locked -- -D warnings
git add crates/rimap-imap/tests/adversarial_imap.rs
git commit -m "test(imap): verify LOGINDISABLED auth provenance via fake"
```

Expected: PASS; `PanicResolver` never fires (no panic), confirming the
pre-resolve path.

---

### Task 5: Scenario 3 — missing/zero-UID FETCH skip + aggregated warn

**Files:**
- Modify: `crates/rimap-imap/Cargo.toml` (`tracing`, `tracing-subscriber` dev-deps)
- Create: `crates/rimap-imap/tests/support/tracing_capture.rs`
- Modify: `crates/rimap-imap/tests/support/mod.rs` (`pub mod tracing_capture;`)
- Modify: `crates/rimap-imap/src/ops/fetch.rs` (skip counter + `warn!`)
- Modify: `crates/rimap-imap/tests/adversarial_imap.rs` (add a test)

**Interfaces produced:**
- `support::tracing_capture::WarnCapture` with `fn install() -> WarnCapture`
  (holds a `DefaultGuard`) and `fn records(&self) -> Vec<String>`.

- [ ] **Step 1: Add capture dev-deps.** In `crates/rimap-imap/Cargo.toml`
  `[dev-dependencies]` add:

```toml
tracing = { workspace = true }
tracing-subscriber = { workspace = true }
```

- [ ] **Step 2: Create the scoped tracing capture.** Mirrors the established
  pattern at `crates/rimap-content/src/parse/safe_parser.rs:145-187`, but uses
  the guard API (`set_default`) so it can span an `.await`, and installs a
  permissive global once so the thread-local WARN is not filtered out by the
  static max-level hint (the footgun that motivated this repo's tracing-test
  convention). `crates/rimap-imap/tests/support/tracing_capture.rs`:

```rust
//! Thread-local capture of emitted `tracing` events for async tests.
//!
//! Async-safe: uses `dispatcher::set_default` (a `DefaultGuard` held across the
//! awaited call), not the sync `with_default` closure. A permissive global
//! default is installed once so the `warn!` is not short-circuited by the
//! runtime max-level hint before the scoped dispatcher runs.
#![expect(clippy::unwrap_used, reason = "tests")]

use std::fmt::Write as _;
use std::sync::{Arc, Mutex, Once};

use tracing::Subscriber;
use tracing::dispatcher::DefaultGuard;
use tracing::field::{Field, Visit};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::registry::Registry;

static PERMISSIVE_GLOBAL: Once = Once::new();

fn ensure_permissive_global() {
    PERMISSIVE_GLOBAL.call_once(|| {
        // A no-op global whose max_level_hint is unbounded, so WARN events are
        // not filtered before the scoped dispatcher sees them. Ignore the error
        // if some other component already set a global default.
        let _ = tracing::subscriber::set_global_default(Registry::default());
    });
}

struct CaptureLayer {
    events: Arc<Mutex<Vec<String>>>,
}

struct FieldWriter<'a>(&'a mut String);
impl Visit for FieldWriter<'_> {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        write!(self.0, " {}={value:?}", field.name()).ok();
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        write!(self.0, " {}={value}", field.name()).ok();
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        write!(self.0, " {}={value}", field.name()).ok();
    }
}

impl<S: Subscriber> Layer<S> for CaptureLayer {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let mut record = format!("target={}", event.metadata().target());
        event.record(&mut FieldWriter(&mut record));
        self.events.lock().unwrap().push(record);
    }
}

/// A scoped capture. Hold it across the awaited call under test; read
/// `records()` afterward. Dropping it removes the thread-local dispatcher.
pub struct WarnCapture {
    _guard: DefaultGuard,
    events: Arc<Mutex<Vec<String>>>,
}

impl WarnCapture {
    /// Install a thread-local capturing dispatcher on the current thread.
    pub fn install() -> WarnCapture {
        ensure_permissive_global();
        let events: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let layer = CaptureLayer {
            events: Arc::clone(&events),
        };
        let dispatch = tracing::Dispatch::new(Registry::default().with(layer));
        let guard = tracing::dispatcher::set_default(&dispatch);
        WarnCapture {
            _guard: guard,
            events,
        }
    }

    /// Snapshot of captured `"target=... field=value ..."` records.
    pub fn records(&self) -> Vec<String> {
        self.events.lock().unwrap().clone()
    }
}
```

- [ ] **Step 3: Declare the module.** In
  `crates/rimap-imap/tests/support/mod.rs` add:

```rust
pub mod tracing_capture;
```

- [ ] **Step 4: Write the failing scenario test first.** Append to
  `crates/rimap-imap/tests/adversarial_imap.rs`. Add imports at the top:

```rust
use core::num::NonZeroU32;

use rimap_imap::types::{FetchSpec, Uid};
use support::tracing_capture::WarnCapture;
```

  Then the test:

```rust
/// Scenario 3: a UID FETCH whose items omit or zero the UID are skipped, and a
/// single aggregated `warn!` carrying `skipped_uids` fires. Pinned to a
/// current-thread runtime so the thread-local capture covers the warn.
#[tokio::test(flavor = "current_thread")]
async fn missing_and_zero_uid_fetch_items_are_skipped_with_one_warn() {
    let capture = WarnCapture::install();

    let server = FakeImapServer::start(vec![
        Step::Send(b"* OK fake ready\r\n".to_vec()),
        Step::Expect { verb: "CAPABILITY" },
        Step::Send(b"* CAPABILITY IMAP4rev1 UIDPLUS\r\n".to_vec()),
        Step::Reply { text: "OK CAPABILITY completed" },
        Step::Expect { verb: "LOGIN" },
        Step::Reply { text: "OK LOGIN completed" },
        Step::Expect { verb: "CAPABILITY" },
        Step::Send(b"* CAPABILITY IMAP4rev1 UIDPLUS\r\n".to_vec()),
        Step::Reply { text: "OK CAPABILITY completed" },
        // fetch: EXAMINE (read-only open — ops::fetch calls select(...,true)).
        Step::Expect { verb: "EXAMINE" },
        Step::Send(b"* 3 EXISTS\r\n* OK [UIDVALIDITY 1] .\r\n".to_vec()),
        Step::Reply { text: "OK [READ-ONLY] EXAMINE completed" },
        // UID FETCH: item with no UID, item with UID 0, valid item (UID 5).
        Step::Expect { verb: "UID FETCH" },
        Step::Send(b"* 1 FETCH (FLAGS (\\Seen))\r\n".to_vec()),
        Step::Send(b"* 2 FETCH (UID 0 FLAGS (\\Seen))\r\n".to_vec()),
        Step::Send(b"* 3 FETCH (UID 5 FLAGS (\\Seen))\r\n".to_vec()),
        Step::Reply { text: "OK FETCH completed" },
    ])
    .await;

    let conn = server.connection("user@example.com");
    let spec = FetchSpec {
        envelope: false,
        bodystructure: false,
        uid: true,
        flags: true,
        size: false,
    };
    let (messages, _uidv) = conn
        .fetch("INBOX", &[Uid::from(NonZeroU32::new(5).unwrap())], spec, None)
        .await
        .expect("fetch should succeed, skipping malformed items");

    // Only the well-formed UID 5 survives.
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].uid, Uid::from(NonZeroU32::new(5).unwrap()));

    // Exactly one aggregated skip warn fired (filter by the distinctive field).
    let skip_warns: Vec<String> = capture
        .records()
        .into_iter()
        .filter(|r| r.contains("skipped_uids="))
        .collect();
    assert_eq!(skip_warns.len(), 1, "one aggregated skip warn expected: {skip_warns:?}");
    // TDD contingency (see below): tighten to the observed count once known.
    assert!(
        skip_warns[0].contains("skipped_uids=2") || skip_warns[0].contains("skipped_uids=1"),
        "warn must carry the skipped count: {}",
        skip_warns[0],
    );
}
```

  **Contingency (per spec):** the `UID 0` skip is certain; whether async-imap
  0.11 surfaces the UID-less `* 1 FETCH (FLAGS …)` item as `msg.uid == None`
  (count 2) or drops it in parsing (count 1) is confirmed in Step 7. Tighten the
  final assertion to the observed exact count.

- [ ] **Step 5: Run it — expect FAIL (no warn yet).**

```bash
cargo nextest run -p rimap-imap --locked missing_and_zero_uid --no-capture
```

Expected: FAIL at `one aggregated skip warn expected` — the skip is currently
silent. This proves the test drives the skip path.

- [ ] **Step 6: Add the aggregated warn to `ops::fetch::fetch`.** In
  `crates/rimap-imap/src/ops/fetch.rs`, the loop at line 155 currently reads:

```rust
    let mut out = Vec::with_capacity(uids.len());
    while let Some(msg) = stream.next().await {
        let msg = msg.map_err(super::folders::map_err)?;
        let Some(uid_raw) = msg.uid else {
            continue;
        };
        let Some(uid) = Uid::new(uid_raw) else {
            continue;
        };
```

  Replace it with (add a counter and increment on each skip arm):

```rust
    let mut out = Vec::with_capacity(uids.len());
    let mut skipped_uids: u64 = 0;
    while let Some(msg) = stream.next().await {
        let msg = msg.map_err(super::folders::map_err)?;
        let Some(uid_raw) = msg.uid else {
            skipped_uids += 1;
            continue;
        };
        let Some(uid) = Uid::new(uid_raw) else {
            skipped_uids += 1;
            continue;
        };
```

  Then, **after** the `while` loop closes and **before** the function's final
  `Ok((out, uid_validity))`, insert:

```rust
    if skipped_uids > 0 {
        tracing::warn!(
            folder = %folder,
            skipped_uids,
            "FETCH response omitted or zeroed the UID on one or more items; \
             skipping them (possible malformed or hostile server)",
        );
    }
```

  (`folder: &str` is the `fetch` fn parameter — in scope here. `Uid::new` stays
  as-is; it is `pub(crate)` and this is in-crate `src/`.)

- [ ] **Step 7: Run again — expect PASS; pin the count.**

```bash
cargo nextest run -p rimap-imap --locked missing_and_zero_uid --no-capture
```

Expected: PASS. Read `--no-capture` to see the emitted `skipped_uids=` value and
tighten the Step-4 assertion to `assert!(skip_warns[0].contains("skipped_uids=2"))`
(or `=1`) per the observed behavior.

- [ ] **Step 8: Verify existing fetch tests still pass.**

```bash
cargo nextest run -p rimap-imap --locked fetch
```

Expected: PASS.

- [ ] **Step 9: Clippy + commit.**

```bash
cargo clippy -p rimap-imap --all-targets --all-features --locked -- -D warnings
git add crates/rimap-imap/src/ops/fetch.rs \
        crates/rimap-imap/tests/adversarial_imap.rs \
        crates/rimap-imap/tests/support/tracing_capture.rs \
        crates/rimap-imap/tests/support/mod.rs \
        crates/rimap-imap/Cargo.toml
git commit -m "feat(imap): warn on skipped missing/zero-UID FETCH items"
```

---

### Task 6: Scenario 4 — truncated response mid-literal, typed error no hang

**Files:**
- Modify: `crates/rimap-imap/tests/adversarial_imap.rs`

- [ ] **Step 1: Add the test.** Append to `crates/rimap-imap/tests/adversarial_imap.rs`
  (all needed imports — `NonZeroU32`, `Uid`, `FetchSpec`, `ImapError`, `Duration`
  — are already imported by Tasks 4–5):

```rust
/// Scenario 4: a FETCH BODY[] literal announcing more bytes than are sent,
/// followed by a mid-literal disconnect, must surface a typed error (not a
/// hang, not a bare Timeout). The accept-loop re-serves the script if the
/// ReadOnly path reconnects on ConnectionLost.
#[tokio::test]
async fn truncated_literal_yields_typed_error_not_timeout() {
    let server = FakeImapServer::start(vec![
        Step::Send(b"* OK fake ready\r\n".to_vec()),
        Step::Expect { verb: "CAPABILITY" },
        Step::Send(b"* CAPABILITY IMAP4rev1 UIDPLUS\r\n".to_vec()),
        Step::Reply { text: "OK CAPABILITY completed" },
        Step::Expect { verb: "LOGIN" },
        Step::Reply { text: "OK LOGIN completed" },
        Step::Expect { verb: "CAPABILITY" },
        Step::Send(b"* CAPABILITY IMAP4rev1 UIDPLUS\r\n".to_vec()),
        Step::Reply { text: "OK CAPABILITY completed" },
        Step::Expect { verb: "EXAMINE" },
        Step::Send(b"* 1 EXISTS\r\n* OK [UIDVALIDITY 1] .\r\n".to_vec()),
        Step::Reply { text: "OK [READ-ONLY] EXAMINE completed" },
        // UID FETCH: announce a 100-byte BODY[] literal, send 5 bytes, drop.
        Step::Expect { verb: "UID FETCH" },
        Step::Send(b"* 1 FETCH (UID 5 BODY[] {100}\r\nHELLO".to_vec()),
        Step::Disconnect,
    ])
    .await;

    // LOGIN succeeds here, so use the static-resolver constructor with a
    // generous 5s backstop so the near-instant loopback EOF wins the race.
    let conn = server.connection_timeout("user@example.com", Duration::from_secs(5));
    let spec = FetchSpec {
        envelope: false,
        bodystructure: false,
        uid: true,
        flags: false,
        size: false,
    };
    let result = conn
        .fetch("INBOX", &[Uid::from(NonZeroU32::new(5).unwrap())], spec, None)
        .await;

    let err = result.expect_err("truncated literal must fail, not return Ok");
    assert!(
        !matches!(err, ImapError::Timeout { .. }),
        "must be a truncation-class error, not a mere timeout; got {err:?}",
    );
}
```

- [ ] **Step 2: Run it — capture the real error variant.**

```bash
cargo nextest run -p rimap-imap --locked truncated_literal --no-capture
```

Expected: PASS (err is `Protocol` or `ConnectionLost`, not `Timeout`).
**Contingency (per spec):** if async-imap instead returns `Ok` (graceful stream
end), `expect_err` fails — switch the trigger: send the untagged FETCH fully,
then `Step::Disconnect` **before** a tagged `OK` (the command never completes),
so async-imap surfaces an error. Re-run until a real `Err` is observed. The
accept-loop already covers a ReadOnly reconnect if the error is `ConnectionLost`.

- [ ] **Step 3: Clippy + commit.**

```bash
cargo clippy -p rimap-imap --tests --all-features --locked -- -D warnings
git add crates/rimap-imap/tests/adversarial_imap.rs
git commit -m "test(imap): verify truncated-literal surfaces typed error"
```

---

### Task 7: CONTRIBUTING note (fake vs Dovecot)

**Files:**
- Modify: `AGENTS.md` (under *Testing expectations*)

- [ ] **Step 1: Add the note.** In `AGENTS.md`, in the *Testing expectations*
  section, add a bullet:

```markdown
- **Fake vs Dovecot.** Use the in-process scriptable fake
  (`crates/rimap-imap/tests/support/fake_imap.rs`) to test client behavior
  against a *misbehaving* server — missing capabilities (no MOVE/UIDPLUS,
  `LOGINDISABLED`), malformed or zero UIDs, truncated literals, mid-command
  disconnects. It terminates TLS with a pinned self-signed cert, is
  host-runnable (no container), and is PR-blocking. Use the Dovecot container
  harness (`tests/integration/`) for *conformant* end-to-end behavior; it is
  container-gated and silent-skips without a runtime.
```

- [ ] **Step 2: Run hooks / markdown lint.**

```bash
just hooks
```

Expected: clean (or fix any markdown-lint findings).

- [ ] **Step 3: Commit.**

```bash
git add AGENTS.md
git commit -m "docs: note when to use the IMAP fake vs Dovecot"
```

---

### Task 8: Full guardrail gate

**Files:** none (verification only)

- [ ] **Step 1: Run the full local CI equivalent.**

```bash
just ci
```

Expected: green — `fmt-check`, `lint` (clippy `-D warnings`, all targets),
`test` (full nextest), `deny`, and hooks all pass. `cargo deny check` must stay
clean (no shipped dependency was added; dev-deps were already in-tree).

- [ ] **Step 2: Confirm the four scenarios pass and the placeholder is gone.**

```bash
cargo nextest run -p rimap-imap --locked adversarial_imap expunge_folder_wide_gap
grep -c "#\[ignore" crates/rimap-imap/tests/expunge_folder_wide_gap.rs
```

Expected: all scenario tests pass; ignore count `0`.

- [ ] **Step 3: If `just ci` is green, the plan is complete.** Do not claim
  completion before this gate is green locally.

---

## Self-Review

**Spec coverage:**
- Harness under `tests/support/` → Tasks 1, 2 (+ `tracing_capture` in Task 5). ✔
- Four scripts green → Tasks 3 (s1), 4 (s2), 5 (s3), 6 (s4). ✔
- `expunge_folder_wide_gap.rs` un-`#[ignore]`d → Task 3 rewrite + Task 8 check. ✔
- CONTRIBUTING note → Task 7. ✔
- Aggregated `warn!` (spec's only shipped change) → Task 5. ✔
- `#![allow(dead_code)]` support module, no new shipped dep, accept-loop for the
  ReadOnly retry, `set_default` guard capture + permissive global, EXAMINE (not
  SELECT) for fetch scenarios, ASCII creds, generous scenario-4 timeout →
  embodied across Tasks 1–6. ✔

**Type consistency (verified against the repo):**
- **`Uid`** is constructed only via the public
  `rimap_imap::types::Uid::from(core::num::NonZeroU32::new(N).unwrap())` in every
  test file (the `pub(crate) Uid::new` is used ONLY in the in-crate `fetch.rs`
  edit). Matches `dovecot.rs:494`.
- `FakeImapServer`/`Step`/`connection`/`connection_timeout`/`connection_with`/
  `recorded`/`PanicResolver`/`SelfSigned { chain, key, pin }`/`WarnCapture`,
  `Connection::move_messages`/`fetch`/`list_folders`, `FetchSpec { envelope,
  bodystructure, uid, flags, size }`, `ImapError::{Auth, Timeout}`,
  `AuthFailure::CapabilityMissing { needed }`, `MoveOutcome::{used_fallback,
  folder_wide_expunge}` — all match the source signatures.

**Per-commit clippy hygiene:** each scenario file's `#![expect(...)]` lists
exactly the lints its body triggers, and tasks that introduce a new construct
(`.unwrap()`/`.expect()`/`panic!`) update the list in the same commit; every task
runs `cargo clippy ... -- -D warnings` before committing so no commit fails the
`unfulfilled_lint_expectations`/`-D warnings` gate.

**Calibration dependency (called out, not a placeholder):** the exact async-imap
0.11 dialog is confirmed empirically in Task 2 and the scenario scripts are
adjusted to it — the spec's "captured during TDD" contract. Concrete best-guess
scripts are provided for every scenario.
