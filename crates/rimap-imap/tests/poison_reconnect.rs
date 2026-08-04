//! Integration proof that [`Connection::poison`] actually reaches the cached
//! session — that is, that `dispatch::attempt` consumes the flag before
//! reusing a session (#594, ADR-0012).
//!
//! The unit test in `connection/mod.rs` calls `take_poisoned` directly, so it
//! cannot see whether `attempt` still calls it. Deleting that call site keeps
//! every other test green while the ceiling silently stops recovering: it
//! would still return `ERR_TIMEOUT`, but the NEXT command would parse the cut
//! command's unread server response as its own. That desync produces no error
//! `is_transport_failure` recognizes, so the account never self-heals.
//!
//! Mechanism: the script holds TWO complete search dialogs on ONE connection.
//! Without a poison the second `search` reuses the live cached session and the
//! fake records a single LOGIN. With a poison between the two calls the client
//! must drop that session and reconnect, and the fake — which re-serves the
//! whole script to each new connection — records a second LOGIN. The LOGIN
//! count is therefore a direct read of whether the flag was honoured.
//!
//! Fake, no container runtime — runs on every PR.
#![expect(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use core::num::NonZeroU32;
use std::time::Duration;

use rimap_fake_imap::fake_imap::{FakeImapServer, Step, login_preamble};
use rimap_imap::types::{SearchQuery, StructuredQuery, Uid};

/// Generous command timeout so nothing in the loopback dialog races a
/// `Timeout` (mirrors `reconnect_recovery`).
const BACKSTOP: Duration = Duration::from_secs(5);

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

/// One read-only search exchange: `EXAMINE` then `UID SEARCH` returning 5/7/9.
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

/// Login preamble followed by TWO search exchanges, so one connection can
/// serve both calls when the session is reused.
fn two_search_dialog() -> Vec<Step> {
    let mut steps = login_preamble("IMAP4rev1 UIDPLUS");
    steps.extend(search_exchange());
    steps.extend(search_exchange());
    steps
}

async fn search(conn: &rimap_imap::Connection) -> Vec<Uid> {
    let (found, _uidvalidity) = conn
        .search("INBOX", SearchQuery::Structured(StructuredQuery::default()))
        .await
        .expect("scripted search should succeed");
    found
}

/// Control: with no poison, two searches share one connection. This is what
/// makes the poisoned case below meaningful rather than a reconnect the fake
/// would have forced anyway.
#[tokio::test]
async fn two_searches_without_poison_reuse_one_connection() {
    let server = FakeImapServer::start(two_search_dialog()).await;
    let conn = server.connection_timeout("user@example.com", BACKSTOP);

    assert_eq!(search(&conn).await, uids(&[5, 7, 9]), "first search");
    assert_eq!(search(&conn).await, uids(&[5, 7, 9]), "second search");

    let dialog = server.recorded();
    assert_eq!(
        count(&dialog, "LOGIN"),
        1,
        "the script serves both searches on one connection, so an unpoisoned \
         session must be reused: {dialog:?}",
    );
}

/// A poisoned connection must drop its cached session: the next command
/// reconnects and logs in again rather than reusing a session that may hold an
/// unread server response.
///
/// This is the assertion that fails if `dispatch::attempt` stops consuming the
/// flag — the call site the ceiling's recovery depends on.
#[tokio::test]
async fn poisoned_session_is_dropped_before_the_next_command() {
    let server = FakeImapServer::start(two_search_dialog()).await;
    let conn = server.connection_timeout("user@example.com", BACKSTOP);

    assert_eq!(search(&conn).await, uids(&[5, 7, 9]), "first search");

    // What the ceiling does when it fires mid-command.
    conn.poison();

    assert_eq!(
        search(&conn).await,
        uids(&[5, 7, 9]),
        "the poisoned session must be replaced transparently, not surface an error",
    );

    let dialog = server.recorded();
    assert_eq!(
        count(&dialog, "LOGIN"),
        2,
        "exactly two LOGINs — proof the poison reached the cached session and \
         forced a reconnect instead of reusing it: {dialog:?}",
    );
}
