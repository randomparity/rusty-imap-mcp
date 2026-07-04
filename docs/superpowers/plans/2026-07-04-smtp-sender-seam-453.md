# Mockable `SmtpSender` Seam Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give `rimap-smtp` a one-method `SmtpSender` trait that `SmtpClient` implements, plus an in-memory fake, and wire `AccountState.smtp` to the trait object so tests can inject the fake without a live SMTP server.

**Architecture:** A `dyn`-safe async trait (`send_raw` returning a hand-rolled `Pin<Box<dyn Future + Send>>`) lives in `rimap-smtp`. `SmtpClient` delegates to its existing inherent `send_raw`. `AccountState.smtp` becomes `Option<Box<dyn SmtpSender>>`. The fake lives behind a `test-support` cargo feature (the same pattern `rimap-imap`/`rimap-config` use) and is a cloneable spy sharing an `Arc<Mutex<Vec<CapturedSend>>>` capture log.

**Tech Stack:** Rust 2024 (edition), MSRV 1.88, `lettre` 0.11.21, `tokio`, `thiserror`. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-07-04-issue-453-smtp-sender-seam-design.md`

## Global Constraints

- **No new runtime dependencies.** Hand-roll the boxed future; do not add `async-trait`.
- **Zero warnings.** `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` must be clean. `--all-features` compiles the `test-support` fake, so it is held to the full lint bar (no `unwrap`, `impl Default` for any argument-less `new`, docs on every public item — the crate has `#![deny(missing_docs)]`).
- **No `#[allow(...)]`.** Use `#[expect(..., reason = "...")]`.
- **No `unwrap()` in non-test code.** The fake is feature-gated *non-test* code; use poison-tolerant `MutexGuard` recovery, never `unwrap`.
- **Newtypes / no wildcard matches / absolute imports only.** No `matches!`; explicit destructuring.
- **TDD.** Failing test first, watch it fail, minimal implementation, re-run, commit.
- **Member crates inherit workspace deps** and pin path deps as `{ path = "...", version = "0.1.0" }` — never `workspace = true` for the intra-repo path deps (match the existing `rimap-smtp/Cargo.toml` style).
- Guardrails: `just check` (fast), `just lint`, `just test-fast`, `just test`, `just ci` (full, run before pushing).

---

### Task 1: `SmtpSender` trait + `SmtpClient` impl (compile spike)

This is the load-bearing spike from the spec: it proves lettre's async send
future is `Send`, which the entire boxed-future dispatch depends on. **Do not
start Task 2 until `cargo check -p rimap-smtp` is green here.**

**Files:**
- Create: `crates/rimap-smtp/src/sender.rs`
- Modify: `crates/rimap-smtp/src/lib.rs`
- Test: unit test inside `crates/rimap-smtp/src/sender.rs`

**Interfaces:**
- Consumes: `crate::client::{SmtpClient, SendEnvelope}`, `crate::error::SmtpError` (existing).
- Produces:
  - `pub type SendRawFuture<'a> = Pin<Box<dyn Future<Output = Result<String, SmtpError>> + Send + 'a>>;`
  - `pub trait SmtpSender: Send + Sync { fn send_raw<'a>(&'a self, envelope: &'a SendEnvelope, raw: &'a [u8]) -> SendRawFuture<'a>; }`
  - `impl SmtpSender for SmtpClient`

- [ ] **Step 1: Write the failing test (module wired, trait absent)**

So the failure is real (an *undeclared* module is silently uncompiled, not
failed), wire the module into `lib.rs` first, then write only the test that
references the not-yet-existing trait.

Modify `crates/rimap-smtp/src/lib.rs` — add the module declaration and re-exports:

```rust
//! SMTP client for rusty-imap-mcp.
//!
//! Thin wrapper around `lettre` providing connection management,
//! TLS via `rustls`, and error mapping. Does not construct messages —
//! message building is handled by the server layer.

#![deny(missing_docs)]

pub mod client;
pub mod error;
pub mod sender;

pub use crate::client::{SendEnvelope, SmtpClient};
pub use crate::error::SmtpError;
pub use crate::sender::{SendRawFuture, SmtpSender};
```

Create `crates/rimap-smtp/src/sender.rs` with **only** the test (no trait yet):

```rust
//! `SmtpSender` — the mockable seam over one-shot SMTP delivery.

#[cfg(test)]
mod tests {
    use crate::sender::SmtpSender;
    use crate::SmtpClient;

    fn assert_impls_sender<T: SmtpSender>() {}

    #[test]
    fn smtp_client_implements_sender() {
        // Compile-time proof that SmtpClient: SmtpSender (+ Send + Sync,
        // via the supertrait bounds). This is the spike's assertion:
        // it only compiles once lettre's send future is Send.
        assert_impls_sender::<SmtpClient>();
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p rimap-smtp --lib sender 2>&1 | tail -20`
Expected: compile FAIL — `cannot find trait SmtpSender` / unresolved `crate::sender::SmtpSender` and the `SendRawFuture` re-export in `lib.rs`. This is a genuine failure because the module is now part of the crate.

- [ ] **Step 3: Write the trait + `SmtpClient` impl**

Replace `crates/rimap-smtp/src/sender.rs` with the full module (test retained):

```rust
//! `SmtpSender` — the mockable seam over one-shot SMTP delivery.
//!
//! The trait mirrors the single call `send_email`/`forward` make on a
//! configured client (`send_raw`). It is a `dyn`-safe async trait: the
//! method returns a hand-rolled boxed future ([`SendRawFuture`]) rather
//! than using `async fn`-in-trait (not `dyn`-compatible) or the
//! `async-trait` crate (a dependency this crate does not carry).

use core::future::Future;
use core::pin::Pin;

use crate::client::{SendEnvelope, SmtpClient};
use crate::error::SmtpError;

/// Boxed, `Send` future returned by [`SmtpSender::send_raw`]. Borrows the
/// sender, envelope, and bytes for the duration of the send.
pub type SendRawFuture<'a> =
    Pin<Box<dyn Future<Output = Result<String, SmtpError>> + Send + 'a>>;

/// Seam over one-shot SMTP delivery. Implemented by the real
/// [`SmtpClient`] and by in-memory test fakes.
pub trait SmtpSender: Send + Sync {
    /// Send raw RFC 5322 bytes with an explicit envelope. Mirrors
    /// [`SmtpClient::send_raw`]; returns the SMTP status string on
    /// success.
    fn send_raw<'a>(
        &'a self,
        envelope: &'a SendEnvelope,
        raw: &'a [u8],
    ) -> SendRawFuture<'a>;
}

impl SmtpSender for SmtpClient {
    fn send_raw<'a>(
        &'a self,
        envelope: &'a SendEnvelope,
        raw: &'a [u8],
    ) -> SendRawFuture<'a> {
        // Inherent `SmtpClient::send_raw` is preferred by method
        // resolution over this trait method, so this delegates to the
        // real implementation without recursing. (If resolution ever
        // picked the trait method, the return-type mismatch would fail
        // to compile — it cannot silently recurse.)
        Box::pin(self.send_raw(envelope, raw))
    }
}

#[cfg(test)]
mod tests {
    use crate::sender::SmtpSender;
    use crate::SmtpClient;

    fn assert_impls_sender<T: SmtpSender>() {}

    #[test]
    fn smtp_client_implements_sender() {
        // Compile-time proof that SmtpClient: SmtpSender (+ Send + Sync,
        // via the supertrait bounds). This is the spike's assertion:
        // it only compiles once lettre's send future is Send.
        assert_impls_sender::<SmtpClient>();
    }
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cargo check -p rimap-smtp && cargo test -p rimap-smtp --lib sender 2>&1 | tail -20`
Expected: PASS — `smtp_client_implements_sender` compiles and passes. This confirms lettre's send future is `Send`.

**If `cargo check` fails on the `+ Send` bound** (lettre future is `!Send`): stop and apply the spec's fallback — drop `+ Send` from `SendRawFuture`, reassess whether `AccountState` can stay `Send` (it feeds `AccountRegistry`, shared across tasks). Do not proceed to Task 3 with a `!Send` `AccountState` without re-reviewing registry sharing. Report the finding before continuing.

- [ ] **Step 5: Run clippy and commit**

Run: `cargo clippy -p rimap-smtp --all-targets --all-features --locked -- -D warnings`
Expected: clean.

```bash
git add crates/rimap-smtp/src/sender.rs crates/rimap-smtp/src/lib.rs
git commit -m "feat(smtp): add dyn-safe SmtpSender seam over SmtpClient"
```

---

### Task 2: In-memory `FakeSmtpSender` behind `test-support`

**Files:**
- Create: `crates/rimap-smtp/src/testing.rs`
- Modify: `crates/rimap-smtp/Cargo.toml` (add `[features]` + self dev-dep)
- Modify: `crates/rimap-smtp/src/lib.rs` (feature-gated `pub mod testing;`)
- Test: unit tests inside `crates/rimap-smtp/src/testing.rs`

**Interfaces:**
- Consumes: `crate::sender::{SendRawFuture, SmtpSender}`, `crate::client::SendEnvelope`, `crate::error::SmtpError`.
- Produces:
  - `pub struct CapturedSend { pub envelope: SendEnvelope, pub raw: Vec<u8> }` (`Debug + Clone`)
  - `pub struct FakeSmtpSender` (`Debug + Clone`) — clones share one capture log
  - `FakeSmtpSender::new() -> Self`, `::rejecting(reason: impl Into<String>) -> Self`, `::calls(&self) -> Vec<CapturedSend>`, `::call_count(&self) -> usize`
  - `impl Default for FakeSmtpSender`, `impl SmtpSender for FakeSmtpSender`

- [ ] **Step 1: Add the `test-support` feature and self dev-dep**

Modify `crates/rimap-smtp/Cargo.toml`. After the `[lints]` block (before `[dependencies]`), add:

```toml
[features]
# Exposes the in-memory `rimap_smtp::testing::FakeSmtpSender` so this
# crate's own tests and downstream crates (rimap-server) can drive the
# SMTP seam without a live server. Off by default; never enabled in a
# release build.
test-support = []
```

And in `[dev-dependencies]`, add a self dev-dep that turns the feature on
for this crate's own tests (mirrors the `rimap-server` self dev-dep pattern):

```toml
[dev-dependencies]
tokio = { workspace = true, features = ["test-util", "macros"] }
rimap-smtp = { path = ".", version = "0.1.0", features = ["test-support"] }
```

- [ ] **Step 2: Declare the module (feature-gated) in `lib.rs`**

Modify `crates/rimap-smtp/src/lib.rs`, adding after `pub mod sender;`:

```rust
#[cfg(feature = "test-support")]
pub mod testing;
```

- [ ] **Step 3: Write the failing test + fake**

Create `crates/rimap-smtp/src/testing.rs`:

```rust
//! In-memory [`SmtpSender`] fake for driving the SMTP seam under test.
//!
//! Gated behind the `test-support` feature. [`FakeSmtpSender`] is a
//! cloneable spy: every clone shares one capture log, so a test can
//! inject one clone into an `AccountState` and keep another to inspect
//! what was submitted.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::client::SendEnvelope;
use crate::error::SmtpError;
use crate::sender::{SendRawFuture, SmtpSender};

/// One captured send: the envelope and raw RFC 5322 bytes submitted.
#[derive(Debug, Clone)]
pub struct CapturedSend {
    /// The envelope (`MAIL FROM` / `RCPT TO`) passed to `send_raw`.
    pub envelope: SendEnvelope,
    /// The raw RFC 5322 message bytes passed to `send_raw`.
    pub raw: Vec<u8>,
}

/// The outcome a [`FakeSmtpSender`] returns from every `send_raw` call.
#[derive(Debug, Clone)]
enum Outcome {
    /// Succeed, returning this SMTP status string.
    Ok(String),
    /// Fail with `SmtpError::Rejected { reason }`.
    Rejected(String),
}

/// In-memory SMTP sender that records each submission and returns a
/// preconfigured outcome. Clones share the capture log.
#[derive(Debug, Clone)]
pub struct FakeSmtpSender {
    calls: Arc<Mutex<Vec<CapturedSend>>>,
    outcome: Outcome,
}

impl FakeSmtpSender {
    /// A fake that succeeds, returning `"250 2.0.0 OK"`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            calls: Arc::new(Mutex::new(Vec::new())),
            outcome: Outcome::Ok("250 2.0.0 OK".to_string()),
        }
    }

    /// A fake that rejects every send with `SmtpError::Rejected`.
    #[must_use]
    pub fn rejecting(reason: impl Into<String>) -> Self {
        Self {
            calls: Arc::new(Mutex::new(Vec::new())),
            outcome: Outcome::Rejected(reason.into()),
        }
    }

    /// Snapshot of every captured send, in submission order.
    #[must_use]
    pub fn calls(&self) -> Vec<CapturedSend> {
        self.locked().clone()
    }

    /// Number of `send_raw` calls captured so far.
    #[must_use]
    pub fn call_count(&self) -> usize {
        self.locked().len()
    }

    fn locked(&self) -> MutexGuard<'_, Vec<CapturedSend>> {
        self.calls.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Default for FakeSmtpSender {
    fn default() -> Self {
        Self::new()
    }
}

impl SmtpSender for FakeSmtpSender {
    fn send_raw<'a>(
        &'a self,
        envelope: &'a SendEnvelope,
        raw: &'a [u8],
    ) -> SendRawFuture<'a> {
        // Record eagerly (owned copies — the borrows do not outlive the
        // call) and drop the guard before building the future, so no lock
        // is held across an await.
        self.locked().push(CapturedSend {
            envelope: envelope.clone(),
            raw: raw.to_vec(),
        });
        let outcome = self.outcome.clone();
        Box::pin(async move {
            match outcome {
                Outcome::Ok(response) => Ok(response),
                Outcome::Rejected(reason) => Err(SmtpError::Rejected { reason }),
            }
        })
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[tokio::test]
    async fn captures_bytes_and_envelope_and_returns_ok() {
        let fake = FakeSmtpSender::new();
        let env = SendEnvelope {
            from: "a@x.test".into(),
            to: vec!["b@y.test".into()],
        };
        let sender: &dyn SmtpSender = &fake;
        let response = sender
            .send_raw(&env, b"From: a\r\n\r\nhi")
            .await
            .unwrap();
        assert_eq!(response, "250 2.0.0 OK");

        let calls = fake.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].envelope.to, vec!["b@y.test".to_string()]);
        assert_eq!(calls[0].raw, b"From: a\r\n\r\nhi");
    }

    #[tokio::test]
    async fn rejecting_fake_errors_and_maps_to_smtp_protocol() {
        let fake = FakeSmtpSender::rejecting("550 blocked");
        let env = SendEnvelope {
            from: "a@x.test".into(),
            to: vec!["b@y.test".into()],
        };
        let err = fake.send_raw(&env, b"x").await.unwrap_err();
        let mapped: rimap_core::RimapError = err.into();
        assert_eq!(mapped.code(), rimap_core::ErrorCode::SmtpProtocol);
        assert_eq!(fake.call_count(), 1);
    }

    #[tokio::test]
    async fn clones_share_the_capture_log() {
        let fake = FakeSmtpSender::new();
        let spy = fake.clone();
        let env = SendEnvelope {
            from: "a@x.test".into(),
            to: vec!["b@y.test".into()],
        };
        fake.send_raw(&env, b"one").await.unwrap();
        // The clone observes the send the original recorded.
        assert_eq!(spy.call_count(), 1);
        assert_eq!(spy.calls()[0].raw, b"one");
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p rimap-smtp --lib testing 2>&1 | tail -25`
Expected: 3 tests PASS. (The self dev-dep enables `test-support`, so the module compiles under a plain `cargo test -p rimap-smtp`.)

- [ ] **Step 5: Run clippy with all features and commit**

Run: `cargo clippy -p rimap-smtp --all-targets --all-features --locked -- -D warnings`
Expected: clean (verifies `impl Default`, poison-tolerant lock, and docs satisfy the bar).

```bash
git add crates/rimap-smtp/Cargo.toml crates/rimap-smtp/src/lib.rs crates/rimap-smtp/src/testing.rs
git commit -m "feat(smtp): add in-memory FakeSmtpSender behind test-support"
```

---

### Task 3: Wire `AccountState.smtp` to the trait object

Pure type change: `Option<SmtpClient>` → `Option<Box<dyn SmtpSender>>`. Every
consumer already goes through `is_some()` / `as_ref()…send_raw()`, so only the
field declaration, the `registry.rs` import, and the boot constructor change.
The compile is the test.

**Files:**
- Modify: `crates/rimap-server/src/boot/registry.rs` (import + field type)
- Modify: `crates/rimap-server/src/main.rs` (`build_smtp_client` return type + box)

**Interfaces:**
- Consumes: `rimap_smtp::SmtpSender` (from Task 1).
- Produces: `AccountState.smtp: Option<Box<dyn rimap_smtp::SmtpSender>>` — consumed by `send_email`/`forward` handlers unchanged and by the Task 4 proof test.

- [ ] **Step 1: Change the import in `registry.rs`**

In `crates/rimap-server/src/boot/registry.rs`, replace the import at line 23:

```rust
use rimap_smtp::SmtpSender;
```

(was `use rimap_smtp::SmtpClient;` — nothing else in the file references `SmtpClient`.)

- [ ] **Step 2: Change the field type**

In the same file, change the `smtp` field on `AccountState` (was line 60):

```rust
    /// Optional SMTP sender (present when sending is configured). A
    /// trait object so tests can inject an in-memory fake in place of
    /// the real `SmtpClient`.
    pub smtp: Option<Box<dyn SmtpSender>>,
```

The `Debug` impl's `.field("smtp", &self.smtp.is_some())` needs no change.

- [ ] **Step 3: Box the client in `build_smtp_client`**

In `crates/rimap-server/src/main.rs`, change the return type of
`build_smtp_client` (was line 491):

```rust
) -> anyhow::Result<Option<Box<dyn rimap_smtp::SmtpSender>>> {
```

and its final `Ok` (was line 508):

```rust
    Ok(Some(Box::new(client)))
```

- [ ] **Step 4: Verify the workspace compiles and existing tests pass**

Run: `cargo check -p rimap-server && cargo test -p rimap-server --lib boot::registry 2>&1 | tail -20`
Expected: compiles; existing `registry` unit tests PASS (they use `smtp: None`, still valid for `Option<Box<dyn ...>>`).

- [ ] **Step 5: Run clippy and commit**

Run: `cargo clippy -p rimap-server --all-targets --all-features --locked -- -D warnings`
Expected: clean.

```bash
git add crates/rimap-server/src/boot/registry.rs crates/rimap-server/src/main.rs
git commit -m "refactor(server): hold SMTP sender as a trait object on AccountState"
```

---

### Task 4: Prove injection through a rimap-server `AccountState`

This is the acceptance test: build an `AccountState` carrying a
`FakeSmtpSender`, dispatch a send through its `smtp` field, and assert the
fake captured the bytes + envelope. A `rimap-smtp`-only test does **not**
satisfy the "wired through `rimap-server`" criterion — this test must go
through `AccountState`.

**Files:**
- Modify: `crates/rimap-server/Cargo.toml` (dev-dep enables `rimap-smtp/test-support`)
- Test: new `#[tokio::test]` in `crates/rimap-server/src/boot/registry.rs` `mod tests`

**Interfaces:**
- Consumes: `rimap_smtp::testing::FakeSmtpSender`, `rimap_smtp::{SendEnvelope, SmtpSender}`, `crate::test_support::make_test_account_state`, `AccountState.smtp` (Task 3).

- [ ] **Step 1: Enable the fake for rimap-server tests**

In `crates/rimap-server/Cargo.toml` `[dev-dependencies]`, add a `rimap-smtp`
entry that turns on `test-support` (mirrors the existing `rimap-imap` /
`rimap-config` dev-dep lines):

```toml
rimap-smtp = { path = "../rimap-smtp", version = "0.1.0", features = ["test-support"] }
```

- [ ] **Step 2: Write the failing proof test**

In `crates/rimap-server/src/boot/registry.rs`, inside the existing
`#[cfg(test)] mod tests` block (it already carries
`#[expect(clippy::unwrap_used, ...)]`), add:

```rust
    #[tokio::test]
    async fn account_state_dispatches_send_through_injected_fake() {
        // Acceptance for #453: an AccountState can hold a fake sender and
        // dispatch to it with no live SMTP server. The `spy` clone shares
        // the injected fake's capture log, so we can inspect what the
        // seam submitted after boxing it into the AccountState.
        use rimap_smtp::testing::FakeSmtpSender;
        use rimap_smtp::{SendEnvelope, SmtpSender};

        use crate::test_support::make_test_account_state;

        let fake = FakeSmtpSender::new();
        let spy = fake.clone();

        let mut state = make_test_account_state("sender-seam");
        state.smtp = Some(Box::new(fake));

        let envelope = SendEnvelope {
            from: "me@test.invalid".into(),
            to: vec!["you@test.invalid".into()],
        };
        let smtp = state.smtp.as_ref().unwrap();
        let response = smtp
            .send_raw(&envelope, b"From: me\r\n\r\nbody")
            .await
            .unwrap();

        assert_eq!(response, "250 2.0.0 OK");
        assert_eq!(spy.call_count(), 1);
        let calls = spy.calls();
        assert_eq!(calls[0].envelope.to, vec!["you@test.invalid".to_string()]);
        assert_eq!(calls[0].raw, b"From: me\r\n\r\nbody");
    }
```

- [ ] **Step 3: Run the test to verify it passes**

Run: `cargo test -p rimap-server --lib account_state_dispatches_send_through_injected_fake 2>&1 | tail -20`
Expected: PASS. (If `tokio::test` is unavailable, confirm `tokio` with the
`macros` + `rt` features is on the dependency graph; the server binary uses
tokio, so it is — surface a blocker if not.)

- [ ] **Step 4: Run clippy and commit**

Run: `cargo clippy -p rimap-server --all-targets --all-features --locked -- -D warnings`
Expected: clean.

```bash
git add crates/rimap-server/Cargo.toml crates/rimap-server/src/boot/registry.rs
git commit -m "test(server): prove FakeSmtpSender injects through AccountState (#453)"
```

---

## Final verification

- [ ] **Run the full local-CI equivalent**

Run: `just ci`
Expected: green — `fmt-check`, `lint`, `check`, `test`, `test-msrv`, `deny` all pass. This is the gate before pushing; `cargo deny` confirms no new dependency was introduced.

## Self-review notes (spec coverage)

- Trait extraction → Task 1. Fake capturing bytes + envelope → Task 2.
  Wired through `rimap-server` → Task 3 (type) + Task 4 (proof).
- Compile-spike-first (spec's load-bearing assumption) → Task 1 Step 4 gate.
- `impl Default` (clippy `new_without_default`) → Task 2 fake.
- Proof test exercises `AccountState`, not a bare trait → Task 4.
- No new deps (`cargo deny`) → Final verification.
- `Arc<Mutex>`-backed cloneable spy is a refinement of the spec's `Mutex<Vec>`:
  required so the proof test can inspect captures after the fake is boxed into
  `AccountState`.
