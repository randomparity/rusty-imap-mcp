//! Integration proof that a command whose body ended MID-RESPONSE poisons the
//! session, even though it returned normally and nothing was cancelled (#620).
//!
//! `cancel_poison.rs` covers the cut route: the dispatch future is dropped and
//! `SessionGuard` is still armed. This is the same desync reached with no cut
//! at all. `with_timeout` elapsing around the body drops that future exactly as
//! a cancellation would, and `SizeLimit` aborts a fetch mid-stream; either way
//! `attempt` *returns*, and disarming on the way out would hand the half-read
//! session to whoever holds the lock next.
//!
//! ## Why the peer has to be queued
//!
//! `with_session` already calls `invalidate().await` for exactly these errors,
//! so any command arriving after `with_session` returns finds an empty slot and
//! reconnects whether or not the fix exists. A test built on that shape would
//! pass either way. The defect is only observable in the window `invalidate`
//! cannot cover: it must RE-ACQUIRE the session lock, and `tokio::sync::Mutex`
//! is FIFO-fair, so a peer that queued while the failing command held the lock
//! is served *first*. That peer is the read-out.
//!
//! ## Budget arithmetic
//!
//! The peer waits on the lock under the same `command_timeout` the failing
//! command is about to trip, so its wait has to fit inside that budget. It
//! does, by construction: the failing command trips at `t_body + TIMEOUT`, the
//! peer queues at `t_body + PEER_DELAY`, so the peer waits `TIMEOUT -
//! PEER_DELAY` and keeps `PEER_DELAY` of margin. `PEER_DELAY` is deliberately a
//! large fraction of `TIMEOUT` rather than the smallest value that works.
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

/// Command deadline for the timing-out case. Also bounds the peer's wait on
/// the session lock — see the budget arithmetic above.
const TIMEOUT: Duration = Duration::from_millis(600);

/// How long after the failing command's body starts the peer is spawned. The
/// margin the peer keeps against `TIMEOUT`.
const PEER_DELAY: Duration = Duration::from_millis(250);

/// Server-side stall. Must outlast `TIMEOUT` so the client trips its own
/// deadline rather than the fake ending the dialog first, and must stay under
/// `connect_timeout` (5s) because the sequential accept-loop cannot serve the
/// peer's reconnect until it ends.
const STALL: Duration = Duration::from_millis(900);

/// Generous deadline for the control, where nothing is supposed to time out.
const BACKSTOP: Duration = Duration::from_secs(5);

fn count(dialog: &[String], needle: &str) -> usize {
    dialog
        .iter()
        .filter(|line| line.to_ascii_uppercase().contains(needle))
        .count()
}

fn uids(values: &[u32]) -> Vec<Uid> {
    values
        .iter()
        .map(|v| Uid::from(NonZeroU32::new(*v).unwrap()))
        .collect()
}

fn search_exchange() -> Vec<Step> {
    vec![
        Step::Expect { verb: "EXAMINE" },
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

async fn search(conn: &Connection) -> Result<Vec<Uid>, ImapError> {
    let (found, _uidvalidity) = conn
        .search("INBOX", SearchQuery::Structured(StructuredQuery::default()))
        .await?;
    Ok(found)
}

/// `expected_uidvalidity` is threaded through so the control can force a
/// mismatch: `store_flags` checks it after the SELECT completes and before the
/// STORE is sent, which is a failure that leaves the session perfectly in sync.
async fn store(
    conn: &Connection,
    expected_uidvalidity: Option<u32>,
) -> Result<Vec<Uid>, ImapError> {
    let (updated, _uidvalidity) = conn
        .store_flags(
            "INBOX",
            &uids(&[5]),
            &[Flag::Seen],
            FlagAction::Add,
            expected_uidvalidity,
        )
        .await?;
    Ok(updated)
}

/// Block until the fake has recorded a command line containing `needle`.
/// Panics on miss: every caller uses it to establish a precondition.
async fn wait_for_recorded(server: &FakeImapServer, needle: &str) {
    for _ in 0..400 {
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

/// The regression guard. A body cut off by its own `command_timeout` must
/// leave the session poisoned, so the peer queued behind it reconnects
/// instead of reading the timed-out command's reply as its own.
#[tokio::test]
async fn peer_queued_behind_a_timed_out_body_does_not_inherit_its_session() {
    let mut stalled = login_preamble("IMAP4rev1 UIDPLUS");
    stalled.push(Step::Expect { verb: "EXAMINE" });
    stalled.push(Step::Stall(STALL));

    let mut reconnect = login_preamble("IMAP4rev1 UIDPLUS");
    reconnect.extend(store_exchange());

    let server = FakeImapServer::start_sequence(vec![stalled, reconnect]).await;
    let conn = server.connection_timeout("user@example.com", TIMEOUT);

    // Trips its own command deadline while holding the session lock.
    let failing = tokio::spawn({
        let conn = conn.clone();
        async move { search(&conn).await }
    });
    wait_for_recorded(&server, "EXAMINE").await;

    // Queue the peer with room to spare inside the same budget.
    tokio::time::sleep(PEER_DELAY).await;
    let peer = tokio::spawn({
        let conn = conn.clone();
        async move { store(&conn, None).await }
    });

    let err = failing
        .await
        .expect("the failing task must not panic")
        .expect_err("the stalled search must trip its command deadline");
    assert!(
        matches!(err, ImapError::Timeout { .. }),
        "the discriminator is a stage timeout, not some other failure: {err:?}",
    );

    let updated = peer.await.expect("the peer task must not panic").expect(
        "the peer must reconnect and complete; inheriting the timed-out \
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

/// Control. A body that fails WITHOUT ending mid-response must not poison:
/// `store_flags` rejects a UIDVALIDITY mismatch after the SELECT's tagged reply
/// and before the STORE is sent, so the session is perfectly in sync and the
/// queued peer reuses it.
///
/// This is what makes the guard above a read of `is_transport_failure` rather
/// than of "the command failed". Widening the gate to every `Err` — the obvious
/// wrong implementation — costs a reconnect on every ordinary rejection, and
/// fails here.
#[tokio::test]
async fn peer_queued_behind_an_in_sync_failure_reuses_the_session() {
    let mut script = login_preamble("IMAP4rev1 UIDPLUS");
    script.extend([
        Step::Expect { verb: "SELECT" },
        // Hold the lock long enough for the peer to queue behind it.
        Step::Stall(PEER_DELAY),
        Step::Send(b"* 1 EXISTS\r\n* OK [UIDVALIDITY 1] .\r\n".to_vec()),
        Step::Reply {
            text: "OK [READ-WRITE] SELECT completed",
        },
    ]);
    script.extend(search_exchange());

    let mut reconnect = login_preamble("IMAP4rev1 UIDPLUS");
    reconnect.extend(search_exchange());

    let server = FakeImapServer::start_sequence(vec![script, reconnect]).await;
    let conn = server.connection_timeout("user@example.com", BACKSTOP);

    // Fails on the UIDVALIDITY guard: the server says 1, this demands 999.
    let failing = tokio::spawn({
        let conn = conn.clone();
        async move { store(&conn, Some(999)).await }
    });
    wait_for_recorded(&server, "SELECT").await;

    let peer = tokio::spawn({
        let conn = conn.clone();
        async move { search(&conn).await }
    });

    let err = failing
        .await
        .expect("the failing task must not panic")
        .expect_err("a UIDVALIDITY mismatch must be rejected");
    assert!(
        matches!(err, ImapError::UidValidityChanged { .. }),
        "the control's failure must be the in-sync one: {err:?}",
    );

    let found = peer
        .await
        .expect("the peer task must not panic")
        .expect("the peer inherits an in-sync session");
    assert_eq!(found, uids(&[5, 7, 9]), "the reused search result");

    let dialog = server.recorded();
    assert_eq!(
        count(&dialog, "LOGIN"),
        1,
        "exactly one LOGIN — a failure that left the session in sync must not \
         cost a reconnect, so the second script is never reached: {dialog:?}",
    );
}
