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
- **Zero warnings.** CI runs all builds under `RUSTFLAGS="-D warnings"`.
  `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
  must be clean.
- **No `#[allow(...)]`** except the module-level `#![allow(dead_code)]` on the
  shared test-support module (mirrors `tests/integration/support/container.rs:7`).
  Use `#![expect(clippy::unwrap_used, reason = "tests")]` etc. inside test files.
- **No new shipped dependency.** `rcgen`/`tokio-rustls`/`rustls` are added only
  to `rimap-imap` **dev-dependencies**.
- **Absolute imports only** (no relative `..`). 100-char lines. Google-style
  docstrings on public items (`missing_docs = "warn"` is on for test targets too).
- **Guardrail suite:** `just ci` (runs `fmt-check`, `lint`, `test`, `deny`,
  hooks). Fast inner loop: `cargo nextest run -p rimap-imap --locked`.
- **TDD:** failing test first, watch it fail, minimal implementation, watch it
  pass, commit. One logical change per commit; conventional-commit subjects
  ≤72 chars; end each commit message with the trailer
  `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.

---

## File Structure

- `crates/rimap-imap/Cargo.toml` — add `rcgen` (+ confirm `tokio-rustls`,
  `rustls`) to `[dev-dependencies]`; add a self dev-dep only if a feature gate
  is needed (it is not — the harness lives in `tests/`, not `src/`).
- `crates/rimap-imap/tests/support/mod.rs` — `#![allow(dead_code)]`,
  `pub mod certs; pub mod fake_imap;`.
- `crates/rimap-imap/tests/support/certs.rs` — self-signed cert + pin.
- `crates/rimap-imap/tests/support/fake_imap.rs` — `Step`, `FakeImapServer`.
- `crates/rimap-imap/tests/adversarial_imap.rs` — smoke test + scenarios 2, 3, 4.
- `crates/rimap-imap/tests/expunge_folder_wide_gap.rs` — **rewritten** from the
  `#[ignore]` placeholder into scenario 1.
- `crates/rimap-imap/src/ops/fetch.rs` — aggregated skip `warn!` (scenario 3).
- `AGENTS.md` — CONTRIBUTING note (fake vs Dovecot).

**Cargo test discovery note:** every top-level `tests/*.rs` file is its own test
binary; the `tests/support/` subdirectory is **not** compiled as a binary, so it
is included per-scenario-binary via `mod support;`. Both scenario binaries
include it; the module-level `#![allow(dead_code)]` absorbs the per-binary
unused-helper warnings.

---

### Task 1: Dev-deps + support skeleton + self-signed cert

**Files:**
- Modify: `crates/rimap-imap/Cargo.toml` (`[dev-dependencies]`)
- Create: `crates/rimap-imap/tests/support/mod.rs`
- Create: `crates/rimap-imap/tests/support/certs.rs`

**Interfaces:**
- Produces: `support::certs::self_signed() -> SelfSigned` where
  `struct SelfSigned { chain: Vec<CertificateDer<'static>>, key: PrivateKeyDer<'static>, pin: TlsFingerprint }`.

- [ ] **Step 1: Add dev-dependencies.** In `crates/rimap-imap/Cargo.toml`, under
  `[dev-dependencies]`, add (`tokio-rustls` and `rustls` are already normal deps,
  but dev code needs them too — inheriting `workspace = true` is fine to repeat):

```toml
# In-process fake IMAP server (tests/support): terminates TLS with a
# self-signed rcgen cert the client pins by fingerprint. Test-only.
rcgen = { workspace = true }
tokio-rustls = { workspace = true }
rustls = { workspace = true }
```

- [ ] **Step 2: Create the support module root.**
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

- [ ] **Step 3: Write the failing cert test.** Create
  `crates/rimap-imap/tests/support/certs.rs` with the test only:

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
    fn pin_matches_leaf_der_fingerprint() {
        let a = self_signed();
        // The pin is exactly the fingerprint of the leaf we serve.
        assert_eq!(
            a.pin,
            rimap_core::TlsFingerprint::from_cert_der(a.chain[0].as_ref()),
        );
        // Two independent generations differ (fresh key each time).
        let b = self_signed();
        assert_ne!(a.pin, b.pin);
    }
}
```

  **Note:** a `tests/support/*.rs` file is not compiled as its own test binary,
  so the `#[cfg(test)] mod tests` here does not run standalone; it compiles and
  runs only when a scenario binary includes `mod support;`. That is acceptable —
  the real proof is Task 2's smoke test. If you prefer, fold this assertion into
  Task 2 instead. Keep it here for a focused first commit.

- [ ] **Step 4: Verify it compiles (harness not yet used).** Because no scenario
  binary includes `support` yet, add a temporary throwaway to confirm it builds,
  OR proceed to Task 2 which exercises it. Run:

```bash
cargo check -p rimap-imap --tests --locked
```

Expected: compiles. (`fake_imap` does not exist yet, so temporarily comment out
`pub mod fake_imap;` in `mod.rs` for this check, or land Steps together with
Task 2. Simplest: commit Task 1 with `pub mod fake_imap;` commented, uncomment in
Task 2.)

- [ ] **Step 5: Commit.**

```bash
git add crates/rimap-imap/Cargo.toml crates/rimap-imap/tests/support/mod.rs \
        crates/rimap-imap/tests/support/certs.rs
git commit -m "test(imap): add support skeleton and self-signed cert for fake"
```

---

### Task 2: The `FakeImapServer` harness + smoke test (CALIBRATION)

**This task is the calibration point.** The exact async-imap 0.11 command
sequence (does `Session::capabilities()` re-issue `CAPABILITY` post-login? are
`LOGIN` args quoted?) is implementation-defined. Task 2's smoke test drives a
real login through the fake and prints `recorded()`; **read that output and
adjust the scenario scripts in Tasks 3–6 to match the observed sequence.**

**Files:**
- Create: `crates/rimap-imap/tests/support/fake_imap.rs`
- Create: `crates/rimap-imap/tests/adversarial_imap.rs`
- Modify: `crates/rimap-imap/tests/support/mod.rs` (uncomment `pub mod fake_imap;`)

**Interfaces:**
- Consumes: `support::certs::self_signed`.
- Produces:
  - `enum Step { Expect { verb: &'static str }, Send(Vec<u8>), Reply { text: &'static str }, Delay(Duration), Disconnect }`
  - `struct FakeImapServer` with:
    - `async fn start(script: Vec<Step>) -> FakeImapServer`
    - `fn port(&self) -> u16`
    - `fn pin(&self) -> TlsFingerprint`
    - `fn connection(&self, username: &str) -> Connection`
    - `fn connection_timeout(&self, username: &str, command_timeout: Duration) -> Connection`
    - `fn connection_with(&self, username: &str, resolver: Arc<dyn CredentialResolver>, command_timeout: Duration) -> Connection`
    - `fn recorded(&self) -> Vec<String>`
  - `struct PanicResolver` (impl `CredentialResolver`, panics in `resolve`).

- [ ] **Step 1: Write the harness.** Create
  `crates/rimap-imap/tests/support/fake_imap.rs`:

```rust
//! In-process TLS-terminating scriptable IMAP fake. Replays an ordered
//! `Vec<Step>` per accepted connection (accept-loop) so a client's transparent
//! ReadOnly reconnect re-observes the same dialog. Drives the real `Connection`.
#![expect(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

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

/// Bounded number of connections the accept-loop serves before stopping — a
/// ReadOnly retry needs at most 2; the cap prevents a storming client.
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

    /// Fully-wired `Connection` pointed at this fake (~1s command timeout,
    /// static-password resolver, no-op audit sink).
    pub fn connection(&self, username: &str) -> Connection {
        self.connection_with(
            username,
            Arc::new(StaticResolver),
            Duration::from_secs(1),
        )
    }

    /// Static-resolver connection with a caller-chosen command timeout
    /// (scenario 4 uses a generous 5s backstop).
    pub fn connection_timeout(&self, username: &str, command_timeout: Duration) -> Connection {
        self.connection_with(username, Arc::new(StaticResolver), command_timeout)
    }

    /// Same, but inject an arbitrary resolver and command timeout.
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

- [ ] **Step 2: Uncomment `pub mod fake_imap;`** in
  `crates/rimap-imap/tests/support/mod.rs` (if you commented it in Task 1).

- [ ] **Step 3: Write the smoke test.** Create
  `crates/rimap-imap/tests/adversarial_imap.rs`:

```rust
//! Adversarial IMAP scenarios driven against the in-process fake
//! (`support::fake_imap`). Scenario 1 (folder-wide EXPUNGE) lives in
//! `expunge_folder_wide_gap.rs`; scenarios 2–4 live here.
//!
//! Fake, no container runtime — runs on every PR.
#![expect(clippy::unwrap_used, clippy::expect_used, clippy::panic, reason = "tests")]

mod support;

use support::fake_imap::{FakeImapServer, Step};

/// Smoke/calibration: a real login + LIST through the fake proves the TLS
/// handshake, pin, greeting, CAPABILITY drain, LOGIN, and post-login
/// CAPABILITY all work end-to-end. Print `recorded()` and use the observed
/// command order to write the scenario scripts.
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
        // LIST "" "*"
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

- [ ] **Step 4: Run the smoke test and read the dialog.**

```bash
cargo nextest run -p rimap-imap --locked adversarial_imap --no-capture
```

Expected: PASS. **Read the `recorded dialog:` output.** Confirm the exact command
order (pre-login CAPABILITY, LOGIN, post-login CAPABILITY?, LIST). If the test
fails on an `Expect` verb-mismatch panic (visible in the fake's assert message),
the observed order differs from the script above — adjust the script to match and
re-run until PASS. **The confirmed order is the template for Tasks 3–6.**

- [ ] **Step 5: Commit.**

```bash
git add crates/rimap-imap/tests/support/fake_imap.rs \
        crates/rimap-imap/tests/support/mod.rs \
        crates/rimap-imap/tests/adversarial_imap.rs
git commit -m "test(imap): add scriptable TLS fake and login smoke test"
```

---

### Task 3: Scenario 1 — folder-wide EXPUNGE data loss (un-ignore)

**Files:**
- Modify (rewrite): `crates/rimap-imap/tests/expunge_folder_wide_gap.rs`

**Interfaces:**
- Consumes: `support::fake_imap::{FakeImapServer, Step}`; `Connection::move_messages`.

- [ ] **Step 1: Replace the placeholder with the real test.** Overwrite
  `crates/rimap-imap/tests/expunge_folder_wide_gap.rs` entirely:

```rust
//! Scenario 1: a server advertising neither MOVE nor UIDPLUS forces the
//! COPY + STORE \Deleted + folder-wide EXPUNGE fallback (the data-loss path).
//! Drives the real `Connection::move_messages` against the in-process fake and
//! asserts both `used_fallback` and `folder_wide_expunge`, plus that a plain
//! `EXPUNGE` (not `UID EXPUNGE`) reached the wire.
//!
//! Fake, no container runtime — runs on every PR. Replaces the former
//! `#[ignore]`d placeholder that marked this gap.
#![expect(clippy::unwrap_used, clippy::expect_used, clippy::panic, reason = "tests")]

mod support;

use rimap_imap::types::Uid;
use support::fake_imap::{FakeImapServer, Step};

#[tokio::test]
async fn no_move_no_uidplus_uses_folder_wide_expunge() {
    // Post-login CAPABILITY advertises NEITHER MOVE NOR UIDPLUS, so the client
    // takes copy_delete_fallback -> run_expunge(FolderWide) -> plain EXPUNGE.
    // Adjust the CAPABILITY placement per Task 2's calibration.
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
    let outcome = conn
        .move_messages("INBOX", "Archive", &[Uid::new(5).unwrap()], None)
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

- [ ] **Step 2: Run it, expect the calibration-dependent first failure.**

```bash
cargo nextest run -p rimap-imap --locked expunge_folder_wide_gap --no-capture
```

Expected initially: may FAIL on a `fake: expected command` assert if the SELECT/
STATUS/COPY/STORE/EXPUNGE order or the untagged-response shape differs from real
async-imap. Adjust the untagged responses / step order to the real dialog (use
`--no-capture` output and `recorded()`), then re-run until PASS. Verify the
assertions on `used_fallback` / `folder_wide_expunge` hold.

- [ ] **Step 3: Confirm the placeholder is gone.**

```bash
grep -c "#\[ignore" crates/rimap-imap/tests/expunge_folder_wide_gap.rs
```

Expected: `0`.

- [ ] **Step 4: Commit.**

```bash
git add crates/rimap-imap/tests/expunge_folder_wide_gap.rs
git commit -m "test(imap): verify folder-wide EXPUNGE data-loss path via fake"
```

---

### Task 4: Scenario 2 — LOGINDISABLED auth provenance

**Files:**
- Modify: `crates/rimap-imap/tests/adversarial_imap.rs` (add a test)

**Interfaces:**
- Consumes: `support::fake_imap::{FakeImapServer, Step, PanicResolver}`;
  `ImapError`, `AuthFailure`.

- [ ] **Step 1: Add the test** to `crates/rimap-imap/tests/adversarial_imap.rs`
  (append; add imports at the top):

```rust
use std::sync::Arc;
use std::time::Duration;

use rimap_imap::error::{AuthFailure, ImapError};
use support::fake_imap::PanicResolver;
```

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

- [ ] **Step 2: Run it.**

```bash
cargo nextest run -p rimap-imap --locked logindisabled --no-capture
```

Expected: PASS. The `PanicResolver` never fires (no panic), confirming the
pre-resolve error path. If the fake asserts a verb mismatch, align the CAPABILITY
step count with Task 2's calibration.

- [ ] **Step 3: Commit.**

```bash
git add crates/rimap-imap/tests/adversarial_imap.rs
git commit -m "test(imap): verify LOGINDISABLED auth provenance via fake"
```

---

### Task 5: Scenario 3 — missing/zero-UID FETCH skip + aggregated warn

**Files:**
- Modify: `crates/rimap-imap/src/ops/fetch.rs` (add skip counter + `warn!`)
- Modify: `crates/rimap-imap/tests/adversarial_imap.rs` (add a test)

**Interfaces:**
- Consumes: `Connection::fetch`, `FetchSpec`, `Uid`; `tracing` capture.

- [ ] **Step 1: Write the failing scenario test first (asserts the warn).**
  Append to `crates/rimap-imap/tests/adversarial_imap.rs`. Add imports:

```rust
use rimap_imap::types::{FetchSpec, Uid};
use tracing::Level;
use tracing_subscriber::layer::SubscriberExt;
```

  (Add `tracing` and `tracing-subscriber` to `rimap-imap` dev-deps in this task —
  see Step 4. If a lighter capture already exists in the repo's test utilities,
  prefer it.) The test:

```rust
/// Scenario 3: a UID FETCH whose items omit or zero the UID are skipped, and a
/// single aggregated `warn!` carrying `skipped_uids` fires. Pinned to a
/// current-thread runtime so the thread-local dispatcher covers the warn.
#[tokio::test(flavor = "current_thread")]
async fn missing_and_zero_uid_fetch_items_are_skipped_with_one_warn() {
    use std::sync::{Arc, Mutex};
    use tracing::field::{Field, Visit};

    // Minimal capture layer: record (target, message-or-skipped_uids) for warns.
    #[derive(Clone, Default)]
    struct Captured {
        skip_warns: Arc<Mutex<Vec<u64>>>,
    }
    struct SkipVisitor(Option<u64>);
    impl Visit for SkipVisitor {
        fn record_u64(&mut self, field: &Field, value: u64) {
            if field.name() == "skipped_uids" {
                self.0 = Some(value);
            }
        }
        fn record_debug(&mut self, _f: &Field, _v: &dyn std::fmt::Debug) {}
    }
    struct CaptureLayer(Captured);
    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for CaptureLayer {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            if *event.metadata().level() == Level::WARN {
                let mut v = SkipVisitor(None);
                event.record(&mut v);
                if let Some(n) = v.0 {
                    self.0.skip_warns.lock().unwrap().push(n);
                }
            }
        }
    }

    let captured = Captured::default();
    let subscriber = tracing_subscriber::registry().with(CaptureLayer(captured.clone()));
    let dispatch = tracing::Dispatch::new(subscriber);
    let _guard = tracing::dispatcher::set_default(&dispatch);

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
        // fetch: EXAMINE (read-only open).
        Step::Expect { verb: "EXAMINE" },
        Step::Send(b"* 3 EXISTS\r\n* OK [UIDVALIDITY 1] .\r\n".to_vec()),
        Step::Reply { text: "OK [READ-ONLY] EXAMINE completed" },
        // UID FETCH: one item with no UID, one with UID 0, one valid (UID 5).
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
        .fetch(
            "INBOX",
            &[Uid::new(5).unwrap()],
            spec,
            None,
        )
        .await
        .expect("fetch should succeed, skipping malformed items");

    // Only the well-formed UID 5 survives.
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].uid, Uid::new(5).unwrap());

    // Exactly one aggregated skip warn fired; its count is the TDD-observed
    // total (see contingency below). Assert on the filtered skip warns only.
    let warns = captured.skip_warns.lock().unwrap().clone();
    assert_eq!(warns.len(), 1, "exactly one aggregated skip warn expected");
    assert!(warns[0] >= 1, "skipped_uids must count the malformed items");
    // If Task-5 calibration confirms async-imap surfaces the UID-less item as
    // msg.uid == None, tighten this to `assert_eq!(warns[0], 2);`.
}
```

  **Contingency (per spec):** confirm during this task how async-imap 0.11
  surfaces the UID-less `* 1 FETCH (FLAGS …)` item. If it yields `msg.uid ==
  None` (the `fetch.rs:158` arm), the count is 2; if async-imap drops it during
  parsing, the count is 1 (only the UID-0 item). Tighten the final assertion to
  the observed exact count.

- [ ] **Step 2: Run it — expect FAIL (no warn yet).**

```bash
cargo nextest run -p rimap-imap --locked missing_and_zero_uid --no-capture
```

Expected: FAIL at `exactly one aggregated skip warn expected` (the skip is
currently silent). This proves the test drives the skip path.

- [ ] **Step 3: Add the aggregated warn to `ops::fetch::fetch`.** In
  `crates/rimap-imap/src/ops/fetch.rs`, at line 155 replace:

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

  with:

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

  Then, immediately **after** the `while` loop and **before** the final
  `Ok((out, uid_validity))` return, add:

```rust
    if skipped_uids > 0 {
        tracing::warn!(
            folder = %folder,
            skipped_uids,
            "FETCH response omitted or zeroed the UID on {skipped_uids} item(s); \
             skipping them (possible malformed or hostile server)",
        );
    }
```

- [ ] **Step 4: Add dev-deps for capture (if not already present).** In
  `crates/rimap-imap/Cargo.toml` `[dev-dependencies]`, add:

```toml
tracing = { workspace = true }
tracing-subscriber = { workspace = true }
```

  (Confirm both are `[workspace.dependencies]`; `tracing` already is. If
  `tracing-subscriber` is not, use the workspace's existing test-capture
  utility instead of adding a dep — check `rimap-content` tests for the
  established pattern before adding.)

- [ ] **Step 5: Run again — expect PASS.**

```bash
cargo nextest run -p rimap-imap --locked missing_and_zero_uid --no-capture
```

Expected: PASS. Read `--no-capture` output to confirm the observed `skipped_uids`
count and tighten the assertion (Step 1 contingency).

- [ ] **Step 6: Verify no other fetch tests regressed.**

```bash
cargo nextest run -p rimap-imap --locked fetch
```

Expected: PASS.

- [ ] **Step 7: Commit.**

```bash
git add crates/rimap-imap/src/ops/fetch.rs crates/rimap-imap/tests/adversarial_imap.rs \
        crates/rimap-imap/Cargo.toml
git commit -m "feat(imap): warn on skipped missing/zero-UID FETCH items"
```

---

### Task 6: Scenario 4 — truncated response mid-literal, typed error no hang

**Files:**
- Modify: `crates/rimap-imap/tests/adversarial_imap.rs` (add a test)

**Interfaces:**
- Consumes: `Connection::fetch` (or `fetch_body`), `Step::Send`/`Disconnect`,
  `ImapError`, `connection_with` (5s timeout).

- [ ] **Step 1: Add the test.** Append to
  `crates/rimap-imap/tests/adversarial_imap.rs`:

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
    let conn = server.connection_timeout("user@example.com", std::time::Duration::from_secs(5));
    let spec = rimap_imap::types::FetchSpec {
        envelope: false,
        bodystructure: false,
        uid: true,
        flags: false,
        size: false,
    };
    let result = conn
        .fetch("INBOX", &[Uid::new(5).unwrap()], spec, None)
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
end) — the `expect_err` fails — switch the truncation trigger: replace the last
two steps with a truncated **tagged completion** (send the untagged FETCH fully,
then `Disconnect` before the tagged `OK`), so the command never completes and
async-imap surfaces an error. Re-run until a real `Err` is observed. Record
whether a reconnect occurred (a second connection in `recorded()`); the
accept-loop handles it.

- [ ] **Step 3: Commit.**

```bash
git add crates/rimap-imap/tests/adversarial_imap.rs crates/rimap-imap/tests/support/fake_imap.rs
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

- [ ] **Step 2: Run doc hooks / markdown lint if any.**

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

Expected: green — `fmt-check`, `lint` (clippy `-D warnings`), `test` (full
nextest), `deny`, and hooks all pass. `deny` must show no delta (no new
dependency was shipped; dev-deps are not audited differently, but confirm
`cargo deny check` stays clean).

- [ ] **Step 2: Confirm the four scenarios are green and the placeholder is gone.**

```bash
cargo nextest run -p rimap-imap --locked adversarial_imap expunge_folder_wide_gap
grep -rc "#\[ignore" crates/rimap-imap/tests/expunge_folder_wide_gap.rs
```

Expected: all scenario tests pass; ignore count `0`.

- [ ] **Step 3: If `just ci` is green, the plan is complete.** Do not claim
  completion before this gate is green locally.

---

## Self-Review

**Spec coverage:**
- Harness under `tests/support/` → Tasks 1, 2. ✔
- Four scripts green → Tasks 3 (s1), 4 (s2), 5 (s3), 6 (s4). ✔
- `expunge_folder_wide_gap.rs` un-`#[ignore]`d → Task 3 (rewrite) + Task 8 check. ✔
- CONTRIBUTING note → Task 7. ✔
- Aggregated `warn!` (spec's only shipped change) → Task 5. ✔
- `#![allow(dead_code)]` support module, no new shipped dep, accept-loop for
  ReadOnly retry, `set_default` guard capture, EXAMINE (not SELECT) for fetch
  scenarios, ASCII creds, generous scenario-4 timeout → embodied across Tasks
  1–6. ✔

**Calibration dependency (called out, not a placeholder):** the exact async-imap
0.11 dialog (post-login CAPABILITY presence, response shapes) is confirmed
empirically in Task 2 and the scenario scripts are adjusted to it — this is the
spec's "captured during TDD" contract, not an unfilled TODO. Concrete best-guess
scripts are provided for every scenario.

**Type consistency:** `FakeImapServer`, `Step` (`Expect`/`Send`/`Reply`/`Delay`/
`Disconnect`), `connection`/`connection_with`/`connection_timeout`, `recorded`,
`PanicResolver`, `SelfSigned { chain, key, pin }`, `Connection::move_messages`/
`fetch`, `FetchSpec { envelope, bodystructure, uid, flags, size }`, `Uid::new`,
`ImapError::{Auth, Timeout}`, `AuthFailure::CapabilityMissing { needed }` — all
match the source crate signatures verified against `dispatch.rs`, `error.rs`,
`types.rs`, and `credential.rs`.
