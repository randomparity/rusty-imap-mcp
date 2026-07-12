//! Integration proof that a read-only IMAP op transparently reconnects and
//! succeeds after an idle disconnect (issue #567).
//!
//! The recovery policy lives in
//! `crates/rimap-imap/src/connection/dispatch.rs`: `should_reconnect` fires for
//! an `Idempotency::ReadOnly` op that hit `ConnectionLost`, so the first call on
//! a stale cached session reconnects and retries once — the caller never sees the
//! error. A unit test (`dispatch.rs`) exercises the retry *predicate* against a
//! decoupled mirror loop, and `mutating_no_retry.rs` proves the *no-retry* branch
//! end-to-end; this test proves the *success* branch end-to-end over the
//! scriptable fake, driving the whole `with_session` reconnect path.
//!
//! Mechanism: the script is one full search dialog. The fake's accept-loop
//! re-serves the entire script to each new connection, and `serve()` closes the
//! socket at script exhaustion. So the first `search` succeeds and the fake then
//! drops the connection; the second `search` reuses the now-dead cached session,
//! surfaces `ConnectionLost` internally, reconnects against the re-served script,
//! and succeeds transparently. `recorded()` accumulates across connections, so a
//! two-LOGIN count is the proof a real reconnect happened rather than the first
//! connection surviving.
//!
//! Fake, no container runtime — runs on every PR.
#![expect(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use core::num::NonZeroU32;
use std::time::Duration;

use rimap_fake_imap::fake_imap::{FakeImapServer, Step, login_preamble};
use rimap_imap::types::{SearchQuery, StructuredQuery, Uid};

/// Generous command timeout so the near-instant loopback EOF surfaces as
/// `ConnectionLost` rather than racing a `Timeout` (mirrors `mutating_no_retry`
/// and `adversarial_imap` scenario 4).
const BACKSTOP: Duration = Duration::from_secs(5);

/// Count recorded client command lines whose (upper-cased) text contains
/// `needle`. Two LOGINs proves the second call reconnected rather than reusing
/// a surviving first connection.
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

/// One full read-only search dialog: read-only SELECT (EXAMINE) then
/// `UID SEARCH ALL` returning UIDs 5, 7, 9. Appended to the login preamble;
/// script exhaustion closes the connection.
fn search_dialog() -> Vec<Step> {
    let mut steps = login_preamble("IMAP4rev1 UIDPLUS");
    steps.extend([
        // search issues a read-only SELECT (EXAMINE) before UID SEARCH.
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
    ]);
    steps
}

/// A read-only `search` whose cached session died at script exhaustion must
/// transparently reconnect and succeed on the next call: the caller sees Ok with
/// the scripted UIDs (no error), and `recorded()` shows two LOGINs — the second
/// connection is the reconnect.
#[tokio::test]
async fn read_only_search_reconnects_and_recovers_after_idle_disconnect() {
    let server = FakeImapServer::start(search_dialog()).await;
    let conn = server.connection_timeout("user@example.com", BACKSTOP);

    // First call succeeds, then the fake exhausts its script and drops the
    // connection, leaving the client's cached session stale.
    let (first_uids, _uidv) = conn
        .search("INBOX", SearchQuery::Structured(StructuredQuery::default()))
        .await
        .expect("first search should succeed");
    assert_eq!(first_uids, uids(&[5, 7, 9]), "first search results");

    // Second call hits the dead cached session -> ConnectionLost internally ->
    // transparent reconnect against the re-served script -> success. No error
    // reaches the caller.
    let (second_uids, _uidv) = conn
        .search("INBOX", SearchQuery::Structured(StructuredQuery::default()))
        .await
        .expect("second search must recover transparently, not surface an error");
    assert_eq!(
        second_uids,
        uids(&[5, 7, 9]),
        "recovered search returns the same scripted results",
    );

    let dialog = server.recorded();
    assert_eq!(
        count(&dialog, "LOGIN"),
        2,
        "exactly two LOGINs — proof the second call reconnected: {dialog:?}",
    );
}
