//! `connect_inner` writes exactly one `auth` record per connect attempt, and
//! that record describes the attempt accurately (#623).
//!
//! The unit tests beside `connect_inner` cover the two *failure* shapes — a
//! connect cut mid-handshake, and one that reached its own verdict — because a
//! bare TCP listener is enough to produce both. Neither reaches a successful
//! LOGIN, so neither exercises the arm where the credential source is known:
//! `ConnectProgress::record_credential_source` is called between resolution and
//! the LOGIN round trip, and every other path leaves it unwritten. Deleting
//! that call leaves the unit tests green.
//!
//! This scenario closes that gap against the scriptable TLS fake: a real
//! greeting, a real CAPABILITY exchange, a real LOGIN, one `auth` Success
//! record naming the store the credential came from — and, the double-emit
//! half, exactly one.
//!
//! Fake, no container runtime — runs on every PR.
#![expect(clippy::expect_used, reason = "tests")]

use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rimap_core::ErrorCode;
use rimap_core::auth_event::{AuthEvent, AuthResult};
use rimap_core::auth_sink::{AuthEventSink, AuthSinkError};
use rimap_core::credential::CredentialSource;
use rimap_fake_imap::fake_imap::{FakeImapServer, StaticResolver, Step, login_preamble};

/// Records every emitted event so the test can count and inspect them.
#[derive(Debug, Default)]
struct RecordingSink {
    events: Mutex<Vec<AuthEvent>>,
}

impl RecordingSink {
    fn events(&self) -> Vec<AuthEvent> {
        self.events.lock().expect("recording sink mutex").clone()
    }
}

impl AuthEventSink for RecordingSink {
    /// Reports a poisoned lock as an [`AuthSinkError`] rather than unwrapping,
    /// because that is what the trait requires of every implementation and an
    /// in-tree example should model the contract it documents (#646).
    /// [`Self::events`] still unwraps: it is the *test's* accessor, not part of
    /// the sink's contract, and a poisoned lock there should fail the test.
    fn emit_auth(&self, event: AuthEvent) -> Result<(), AuthSinkError> {
        match self.events.lock() {
            Ok(mut events) => {
                events.push(event);
                Ok(())
            }
            Err(poisoned) => Err(AuthSinkError::new(
                ErrorCode::Internal,
                "recording sink lock poisoned",
                Box::new(std::io::Error::other(poisoned.to_string())),
            )),
        }
    }
}

/// Log in, then serve one `LIST`, so the connect completes through a real
/// command rather than stopping at the greeting.
fn list_script() -> Vec<Step> {
    let mut steps = login_preamble("IMAP4rev1 UIDPLUS");
    steps.push(Step::Expect { verb: "LIST" });
    steps.push(Step::Send(
        b"* LIST (\\HasNoChildren) \".\" \"INBOX\"\r\n".to_vec(),
    ));
    steps.push(Step::Reply {
        text: "OK LIST completed",
    });
    steps
}

#[tokio::test]
async fn a_successful_connect_emits_one_auth_record_naming_the_credential_source() {
    let server = FakeImapServer::start(list_script()).await;
    let sink = Arc::new(RecordingSink::default());
    let conn = server.connection_with(
        "user@example.com",
        Arc::new(StaticResolver),
        Arc::clone(&sink) as Arc<dyn AuthEventSink>,
        Duration::from_secs(1),
    );

    let folders = conn
        .list_folders("*")
        .await
        .expect("the scripted LIST must succeed");
    assert_eq!(folders.len(), 1, "the fake serves exactly one folder");

    let events = sink.events();
    assert_eq!(
        events.len(),
        1,
        "one connect must leave one auth record — the drop guard added for \
         #623 must not add a second on the normal path: {events:?}",
    );
    let event = &events[0];
    assert_eq!(event.result, AuthResult::Success);
    assert_eq!(event.error_code, None, "a successful login carries no code");
    assert_eq!(
        event.credential_source,
        Some(CredentialSource::Keyring),
        "the record must name the store the credential came from; the fake's \
         resolver reports Keyring",
    );
    assert!(
        event.tls_fingerprint_sha256.is_some(),
        "the handshake reached certificate verification, so the observed \
         fingerprint must be recorded",
    );
    assert_eq!(
        event.fingerprint_match,
        Some(true),
        "the connection pins the fake's own certificate",
    );
    assert_eq!(event.username, "user@example.com");
}

/// A completed connect's `auth` record must not depend on tokio's blocking
/// pool (#643).
///
/// The loss this pins is `rimap-server` shutting down with
/// `Runtime::shutdown_background` — which waits for nothing — while
/// `connect_inner`'s emit is still owed to the blocking pool. ADR-0014 has the
/// exact tokio mechanics; they are subtler than they look, and a test that
/// depended on them would pass against the bug whenever the lucky path was
/// taken.
///
/// So the assertion rests instead on the weaker, fully deterministic condition
/// that subsumes them: **the pool never runs another task at all.** One
/// unclaimed pool thread, occupied for the whole test, and the sink read while
/// it is still occupied. A `connect_inner` that defers its emit cannot have
/// recorded — its closure is provably still on the queue at that moment — and
/// one that writes inline is unaffected. Verified at 40/40 green against the
/// inline emit and 0/40 against the deferred one.
///
/// Two implicit dependencies worth naming, both load-bearing and invisible:
///
/// * `max_blocking_threads` counts threads *available to `spawn_blocking`*,
///   over and above the runtime's own workers — which are themselves pool
///   tasks. So `worker_threads(2)` + `max_blocking_threads(1)` leaves exactly
///   one thread for the occupier to take, which is what saturates the pool.
/// * With that thread taken, *any* `spawn_blocking` on the connect path would
///   hang this test rather than fail it informatively. The connect avoids one
///   only because the fake binds `127.0.0.1` and `TcpStream::connect`
///   short-circuits a literal address instead of resolving it on the pool. A
///   harness that moved to a hostname would surface here as a timeout, not as
///   an `emit_auth` regression.
#[test]
fn a_completed_connect_records_its_auth_event_without_the_blocking_pool() {
    /// Bounds the occupier thread's own wait, so a failed assertion cannot
    /// leave it parked for the rest of the test binary's life.
    const OCCUPIER_MAX_HOLD: Duration = Duration::from_secs(30);
    /// Generous upper bound on a local connect; the passing path needs
    /// milliseconds, and only the failing path spends the whole budget.
    const RECORD_DEADLINE: Duration = Duration::from_secs(5);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(1)
        .enable_all()
        .build()
        .expect("multi-thread test runtime");

    // Saturate the blocking pool before the connect starts, so any
    // `spawn_blocking` the connect issues is queued rather than run.
    let (occupied_tx, occupied_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    rt.spawn_blocking(move || {
        occupied_tx.send(()).ok();
        let _ = release_rx.recv_timeout(OCCUPIER_MAX_HOLD);
    });
    occupied_rx
        .recv_timeout(RECORD_DEADLINE)
        .expect("the pool's only thread must be occupied before the connect");

    let server = rt.block_on(FakeImapServer::start(list_script()));
    let sink = Arc::new(RecordingSink::default());
    let conn = server.connection_with(
        "user@example.com",
        Arc::new(StaticResolver),
        Arc::clone(&sink) as Arc<dyn AuthEventSink>,
        Duration::from_secs(1),
    );
    let call = rt.spawn(async move {
        // The `auth` record is written when the connect completes, before
        // LIST is issued, so the command's own outcome is irrelevant here.
        let _ = conn.list_folders("*").await;
    });

    let deadline = Instant::now() + RECORD_DEADLINE;
    while sink.events().is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }

    // Stop the call before reading, so a `ConnectionLost` retry — `list_folders`
    // is read-only, and `with_session` reconnects once for those — cannot add a
    // second connect's record between the poll and the assertion.
    call.abort();
    let events = sink.events();

    // Everything past here is teardown, deliberately *after* the read: while
    // the occupier still holds the pool's only thread, a deferred emit is
    // provably unrun, so `events` cannot have been rescued by the freed thread.
    release_tx.send(()).ok();
    rt.shutdown_background();

    assert_eq!(
        events.len(),
        1,
        "a connect that completed must leave its auth record even when the \
         blocking pool never runs another task: {events:?}",
    );
    assert_eq!(events[0].result, AuthResult::Success);
}
