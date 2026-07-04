# Mockable `SmtpSender` seam + in-memory fake — design

Issue: #453 (epic #446, FABLE_RELEASE_AUDIT finding **H-5a**, High/enabler).
Verified on `main` @ `0169365f`.

## Problem

`rimap_smtp::SmtpClient` (`crates/rimap-smtp/src/client.rs`) is a concrete
struct with no trait boundary. The `send_email` and `forward` handlers reach
SMTP through exactly one call — `account.smtp.as_ref()…send_raw(&envelope,
&raw).await?` (`send_email.rs:107`, `forward.rs:112`) — where
`account.smtp: Option<SmtpClient>`. Because the field is a concrete type and
`SmtpClient::send_raw` opens a live TCP/TLS connection, those handlers cannot
be driven under test without a real SMTP server, and no SMTP fixture exists
anywhere in the repo. This blocks the `send_email`/`forward` functional-test
work (#454, audit H-4a/H-5b).

## Acceptance (from the issue)

A test can substitute a fake sender for `SmtpClient` without a live SMTP
server; the fake captures the submitted RFC 5322 bytes and the envelope. The
seam is wired through `rimap-server` so a test can inject the fake.

## Decision: one-method async trait, boxed-future dispatch, `test-support` fake

### Seam shape

Introduce `trait SmtpSender` in `rimap-smtp` with a single method mirroring the
only call the handlers make:

```rust
pub type SendRawFuture<'a> =
    Pin<Box<dyn Future<Output = Result<String, SmtpError>> + Send + 'a>>;

pub trait SmtpSender: Send + Sync {
    fn send_raw<'a>(&'a self, envelope: &'a SendEnvelope, raw: &'a [u8])
        -> SendRawFuture<'a>;
}
```

`SmtpClient` implements it by delegating to its existing inherent
`send_raw` (kept as the real implementation; the trait impl only wraps the
future in `Box::pin`). No behavior change to the live path.

**Load-bearing assumption — verify first.** The `+ Send` bound on
`SendRawFuture` requires that lettre's `AsyncTransport::send_raw` future is
itself `Send`. This is unproven until it compiles. The plan's **first task is
a compile spike**: define the trait + `impl SmtpSender for SmtpClient` and run
`cargo check -p rimap-smtp`; do not build anything else until the `Send`
future compiles. Fallback if lettre's future turns out `!Send`: the seam still
works with the `+ Send` bound dropped, but `AccountState` then loses `Send`
and the registry impact must be reassessed before proceeding. (lettre 0.11.21
with `tokio1-rustls-tls` is expected to yield a `Send` future, but the spike,
not this sentence, is the proof.)

`AccountState.smtp` changes from `Option<SmtpClient>` to
`Option<Box<dyn SmtpSender>>`. Every existing consumer already goes through
`Option::is_some()` or `as_ref()…send_raw()`, so no call site changes except
the boot constructor `build_smtp_client` (`main.rs`), which now boxes the
`SmtpClient` it builds. `SmtpSender: Send + Sync` keeps `AccountState`
`Send + Sync`, which the shared-across-tasks `AccountRegistry` requires.

### Why a hand-rolled boxed future, not `async fn` in trait or `async-trait`

- **`AccountState.smtp` must be a trait object** (`Box<dyn SmtpSender>`) so a
  single non-generic `AccountState` can hold either the real client or a fake.
  Making `AccountState` generic over the sender type would ripple through the
  registry and every tool handler — far more invasive than the seam warrants.
- Native `async fn` in traits (RPITIT) is stable on the MSRV (1.88) but is
  **not `dyn`-compatible**, so it cannot back a trait object. The standard
  `dyn`-safe form is a method returning `Pin<Box<dyn Future + Send>>`.
- `async-trait` expands to exactly that boxed-future form but adds a
  proc-macro dependency. AGENTS.md forbids new runtime deps without scope
  approval, and a single one-method trait does not justify one. Hand-rolling
  the `Pin<Box<…>>` keeps the dependency budget flat.

### Where the fake lives

The in-memory fake lives in `rimap-smtp` behind a `test-support` cargo
feature — the identical pattern `rimap-imap`, `rimap-content`, and
`rimap-config` already use to expose test-only constructors to cross-crate
tests. `rimap-server` enables `rimap-smtp/test-support` in its
`[dev-dependencies]` (mirroring its existing `rimap-imap`/`rimap-config`
dev-dep lines), so `send_email`/`forward` tests in #454 can inject the fake
regardless of whether they are unit or integration tests.

Cargo does not unify dev-dependency-only features into normal builds, and the
release workflow builds without `--all-features`, so the fake is **never**
compiled into a shipped binary. `just lint` (clippy `--all-features
--all-targets`) does compile it, so it is held to the full lint bar.

### Fake surface

```rust
// rimap_smtp::testing (feature = "test-support")
pub struct CapturedSend { pub envelope: SendEnvelope, pub raw: Vec<u8> }

pub struct FakeSmtpSender { /* Mutex<Vec<CapturedSend>> + configured outcome */ }

impl FakeSmtpSender {
    pub fn new() -> Self;                       // succeeds, returns "250 2.0.0 OK"
    pub fn rejecting(reason: impl Into<String>) -> Self; // errs SmtpError::Rejected
    pub fn calls(&self) -> Vec<CapturedSend>;   // snapshot of captured sends
    pub fn call_count(&self) -> usize;
}
impl Default for FakeSmtpSender { /* delegates to new() */ }
impl SmtpSender for FakeSmtpSender { /* records the call, returns the outcome */ }
```

`FakeSmtpSender::new()` takes no arguments, so a matching `impl Default` is
mandatory: the feature-gated fake is non-test-cfg code compiled by
`just lint` (`--all-features`), and clippy `pedantic`'s `new_without_default`
is a `-D warnings` failure without it. The fake records the call by cloning
the envelope and copying `raw` into an owned `CapturedSend` (it cannot store
the borrowed `&'a` arguments), locks the `Mutex` only to push, and drops the
guard before the future resolves — no lock is held across an await
(`await_holding_lock` is denied).

Only the two externally-constructible `SmtpError` shapes are offered as
outcomes: success (canned response string) and `Rejected { reason }`. The
lettre-wrapping variants (`Connection`/`Tls`/`Transport`) have crate-private
constructors and cannot be fabricated, so they are out of scope for the fake —
`send_email`/`forward` map all SMTP failures through `From<SmtpError>`, and
`Rejected → ErrorCode::SmtpProtocol` exercises that path. The `Mutex` is
locked with poison-tolerant recovery (no `unwrap`), satisfying the workspace
lint bar for non-test (feature-gated) code.

## Non-goals

- No connection pooling, retries, or any change to `SmtpClient`'s live
  behavior. The inherent `send_raw` is untouched; the trait delegates to it.
- No functional tests of `send_email`/`forward` themselves — that is #454,
  which consumes this seam. #453 ships a seam-level proof test that **must
  exercise the rimap-server wiring**, not just the bare trait: build an
  `AccountState` (via `test_support`) whose `smtp` field holds
  `Some(Box::new(FakeSmtpSender::new()))`, dispatch a send through that
  `AccountState`'s `smtp`, and assert the fake captured the RFC 5322 bytes +
  envelope and returned the configured outcome. A rimap-smtp-only test that
  calls the fake through a bare `&dyn SmtpSender` does **not** satisfy the
  acceptance criterion ("wired through `rimap-server` so a test can inject the
  fake"). A separate rimap-smtp unit test additionally covers the fake's own
  capture/outcome behavior in isolation.
- No `async-trait` dependency; no generic `AccountState`.

## Considered & rejected

- **Fake in `rimap-server` test code only (`#[cfg(test)] test_support.rs`).**
  Simpler, but `#[cfg(test)]` items are invisible to integration tests under
  `tests/`, and the fake is conceptually a test double *for the SMTP crate's
  own abstraction*. Housing it in `rimap-smtp/test-support` makes it the one
  canonical fake reachable from any downstream test, matching the three
  sibling crates.
- **`async-trait` crate.** Rejected: new proc-macro dependency for a
  one-method trait, against AGENTS.md’s dependency policy. Hand-rolled
  `Pin<Box<…>>` is equivalent and dependency-free.
- **Generic `AccountState<S: SmtpSender>`.** Rejected: monomorphization
  ripples through `AccountRegistry` and every handler signature for zero
  runtime benefit over a single boxed trait object on a cold path (one SMTP
  send per tool call).
- **`Arc<dyn SmtpSender>` instead of `Box`.** Rejected: `AccountState` owns its
  sender and is never cloned; `Box` is the cheaper exact-fit. Revisit only if
  a future feature needs to share one sender across accounts.
