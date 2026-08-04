//! Integration proof that a command cut mid-flight cannot hand its half-read
//! session to the peer already queued on the session lock (#620).
//!
//! #594 closed this hazard for one trigger — the per-tool-call ceiling, which
//! calls `Connection::poison` itself. A client cancellation reaches the same
//! desync by a different route: the MCP dispatch future is dropped by the
//! *runtime*, so no code of ours runs to call `poison`. The next command then
//! parses the cut command's unread server response as its own, and that desync
//! produces no error `is_transport_failure` recognizes, so the account never
//! self-heals.
//!
//! `dispatch::attempt` therefore holds the session lock inside a
//! `SessionGuard`, which poisons the connection when dropped undisarmed.
//! Ordering is the whole point: the lock guard is a *field*, and Rust runs a
//! value's own `Drop::drop` before dropping its fields, so the flag is always
//! set before the lock is released. `tokio::sync::Mutex` is FIFO-fair, so a
//! peer already queued sits ahead of anything that starts waiting later — a
//! flag set after the lock was released would arrive too late for exactly
//! that peer.
//!
//! Mechanism. The cut command's connection is scripted to read `EXAMINE` and
//! then `Stall`, which parks the client mid-command holding the session lock.
//! A peer `store_flags` is spawned and queues on that lock. The cut command's
//! task is then aborted. The peer's outcome is the read-out:
//!
//! * poisoned — the peer drops the cached session, reconnects, and the STORE
//!   succeeds against the fake's second script: two LOGINs.
//! * not poisoned — the peer inherits the cut command's session and writes
//!   `SELECT` into the stalled connection, which the fake closes at the end of
//!   its script. `store_flags` is [`Idempotency::Mutating`], so it does not
//!   auto-retry and the call surfaces the error: one LOGIN.
//!
//! The paired control runs the identical concurrency against an identical
//! script prefix and simply does not abort, so the peer reuses one connection.
//! Without it a two-LOGIN count would not distinguish the poison from a
//! reconnect the fake forced anyway — the trap `reconnect_recovery.rs` falls
//! into by design (its script is exhausted after one dialog, so the socket
//! closes and the second call reconnects either way).
//!
//! Fake, no container runtime — runs on every PR.
#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests"
)]

use core::num::NonZeroU32;
use std::time::Duration;

use rimap_fake_imap::fake_imap::{FakeImapServer, Step, login_preamble};
use rimap_imap::Connection;
use rimap_imap::error::ImapError;
use rimap_imap::types::{Flag, FlagAction, SearchQuery, StructuredQuery, Uid};

/// Generous command timeout so nothing in the loopback dialog races a
/// `Timeout` (mirrors `poison_reconnect` and `reconnect_recovery`).
const BACKSTOP: Duration = Duration::from_secs(5);

/// How long the fake holds the first connection open without replying.
///
/// Two properties, both satisfied with a wide margin at 500ms:
///
/// * It must outlast the test's setup — waiting for the `EXAMINE` to be
///   recorded, spawning the peer, and aborting — because a search that had
///   *already failed* on its own would leave nothing to poison and make the
///   assertions vacuous. The `is_cancelled` assertion below is what proves it
///   held; it is a correctness guard, not a tuning signal. Do not read the
///   500ms as the threshold: the setup takes single-digit milliseconds on a
///   warm loopback, so far smaller values also pass here. The headroom is for
///   a loaded CI runner, where the setup is what stretches.
/// * It must stay well under `connect_timeout` (5s, from the fake's
///   `ConnectionConfig`), because the accept-loop is sequential: a peer that
///   reconnects waits out the remainder of this stall for its TLS handshake.
const STALL: Duration = Duration::from_millis(500);

/// Count recorded client command lines whose (upper-cased) text contains
/// `needle`.
fn count(dialog: &[String], needle: &str) -> usize {
    dialog
        .iter()
        .filter(|line| line.to_ascii_uppercase().contains(needle))
        .count()
}

/// Build `Uid`s from a slice of raw values (all assumed non-zero).
fn uids(values: &[u32]) -> Vec<Uid> {
    values
        .iter()
        .map(|v| Uid::from(NonZeroU32::new(*v).unwrap()))
        .collect()
}

/// The peer command: a writable `SELECT` then `UID STORE`.
/// [`Idempotency::Mutating`], so a `ConnectionLost` from a stale session
/// surfaces to the caller instead of being papered over by the read-only
/// reconnect-and-retry path.
fn store_exchange() -> Vec<Step> {
    vec![
        Step::Expect { verb: "SELECT" },
        Step::Send(b"* 1 EXISTS\r\n* OK [UIDVALIDITY 1] .\r\n".to_vec()),
        Step::Reply {
            text: "OK [READ-WRITE] SELECT completed",
        },
        Step::Expect { verb: "UID STORE" },
        Step::Send(b"* 1 FETCH (UID 5 FLAGS (\\Seen))\r\n".to_vec()),
        Step::Reply {
            text: "OK STORE completed",
        },
    ]
}

/// The rest of the read-only search dialog, after the `EXAMINE` command line
/// has already been read.
fn search_completion() -> Vec<Step> {
    vec![
        Step::Send(b"* 3 EXISTS\r\n* OK [UIDVALIDITY 1] .\r\n".to_vec()),
        Step::Reply {
            text: "OK [READ-ONLY] EXAMINE completed",
        },
        Step::Expect { verb: "UID SEARCH" },
        Step::Send(b"* SEARCH 5 7 9\r\n".to_vec()),
        Step::Reply {
            text: "OK SEARCH completed",
        },
    ]
}

/// First connection, cut case: log in, read the `EXAMINE`, then park. Script
/// exhaustion after the stall closes the socket, which frees the sequential
/// accept-loop to serve the peer's reconnect.
fn stalled_script() -> Vec<Step> {
    let mut steps = login_preamble("IMAP4rev1 UIDPLUS");
    steps.push(Step::Expect { verb: "EXAMINE" });
    steps.push(Step::Stall(STALL));
    steps
}

/// First connection, control case: the identical prefix — same login, same
/// `EXAMINE`, same stall — but the dialog then completes and goes on to serve
/// the peer's STORE on the same connection.
fn stalled_then_completing_script() -> Vec<Step> {
    let mut steps = stalled_script();
    steps.extend(search_completion());
    steps.extend(store_exchange());
    steps
}

/// Second connection: what a peer that dropped its poisoned session sees.
fn reconnect_script() -> Vec<Step> {
    let mut steps = login_preamble("IMAP4rev1 UIDPLUS");
    steps.extend(store_exchange());
    steps
}

async fn search(conn: &Connection) -> Result<Vec<Uid>, ImapError> {
    let (found, _uidvalidity) = conn
        .search("INBOX", SearchQuery::Structured(StructuredQuery::default()))
        .await?;
    Ok(found)
}

async fn store(conn: &Connection) -> Result<Vec<Uid>, ImapError> {
    let (updated, _uidvalidity) = conn
        .store_flags("INBOX", &uids(&[5]), &[Flag::Seen], FlagAction::Add, None)
        .await?;
    Ok(updated)
}

/// Block until the fake has recorded a command line containing `needle`.
///
/// Panics rather than returning on timeout: every caller uses this to
/// establish a precondition, so a miss is a broken test, not a slow one.
async fn wait_for_recorded(server: &FakeImapServer, needle: &str) {
    for _ in 0..200 {
        if count(&server.recorded(), needle) > 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!(
        "fake never recorded a `{needle}` command line: {:?}",
        server.recorded()
    );
}

/// Let a freshly spawned task run until it parks. On the current-thread
/// runtime these tests use, yielding hands the scheduler to the spawned task,
/// which runs until its first pending await — for the peer that is the
/// session-lock acquisition, which is precisely where it has to be.
async fn yield_until_parked() {
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
}

/// The regression guard. A peer already queued on the session lock must not
/// receive the session a cut command left half-read.
#[tokio::test]
async fn peer_queued_on_the_lock_does_not_inherit_a_cut_commands_session() {
    let server = FakeImapServer::start_sequence(vec![stalled_script(), reconnect_script()]).await;
    let conn = server.connection_timeout("user@example.com", BACKSTOP);

    // The command that gets cut: parks awaiting the `EXAMINE` reply, holding
    // the session lock.
    let cut = tokio::spawn({
        let conn = conn.clone();
        async move { search(&conn).await }
    });
    wait_for_recorded(&server, "EXAMINE").await;

    // The peer: queues on the session lock behind the cut command.
    let peer = tokio::spawn({
        let conn = conn.clone();
        async move { store(&conn).await }
    });
    yield_until_parked().await;

    // The cancellation. `abort` makes the runtime drop the in-flight future,
    // which is the same thing an MCP client cancellation does to the dispatch
    // future — and, unlike the ceiling, runs none of our code on the way out.
    cut.abort();
    let joined = cut.await;
    assert!(
        joined.is_err_and(|e| e.is_cancelled()),
        "the search must have been cut while still in flight; a search that \
         completed on its own would leave nothing to poison and make the \
         assertions below vacuous",
    );

    let updated = peer.await.expect("the peer task must not panic").expect(
        "the peer must reconnect and complete; inheriting the cut \
             command's session makes this a ConnectionLost that store_flags \
             (Mutating) does not retry",
    );
    assert_eq!(updated, uids(&[5]), "the reconnected STORE result");

    let dialog = server.recorded();
    assert_eq!(
        count(&dialog, "LOGIN"),
        2,
        "exactly two LOGINs — the peer dropped the poisoned session and \
         reconnected rather than reusing it: {dialog:?}",
    );
}

/// Control. Identical script prefix and identical concurrency, minus the
/// abort: the peer inherits a *healthy* session and reuses the one connection.
/// This is what makes the two-LOGIN count above a read of the poison rather
/// than of a reconnect the fake would have forced anyway.
#[tokio::test]
async fn peer_queued_on_the_lock_reuses_an_uncut_commands_session() {
    let server =
        FakeImapServer::start_sequence(vec![stalled_then_completing_script(), reconnect_script()])
            .await;
    let conn = server.connection_timeout("user@example.com", BACKSTOP);

    let first = tokio::spawn({
        let conn = conn.clone();
        async move { search(&conn).await }
    });
    wait_for_recorded(&server, "EXAMINE").await;

    let peer = tokio::spawn({
        let conn = conn.clone();
        async move { store(&conn).await }
    });
    yield_until_parked().await;

    let found = first
        .await
        .expect("the first task must not panic")
        .expect("the uncut search completes normally");
    assert_eq!(found, uids(&[5, 7, 9]), "the search result");

    let updated = peer
        .await
        .expect("the peer task must not panic")
        .expect("the peer inherits a healthy session");
    assert_eq!(updated, uids(&[5]), "the STORE result");

    let dialog = server.recorded();
    assert_eq!(
        count(&dialog, "LOGIN"),
        1,
        "exactly one LOGIN — an uncut command hands the queued peer a healthy \
         session, so the second script is never reached: {dialog:?}",
    );
}
