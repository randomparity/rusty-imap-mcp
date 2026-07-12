//! Integration proof that mutating IMAP ops never auto-retry after a
//! mid-command disconnect (issue #565).
//!
//! The retry-safety guard lives in
//! `crates/rimap-imap/src/connection/dispatch.rs`: `should_reconnect` only
//! fires for `Idempotency::ReadOnly`, so a `ConnectionLost` mid-write must
//! surface as an error with the command sent exactly once — re-sending could
//! double-apply the mutation (a `STORE` that toggled a flag, an `APPEND` that
//! landed). A unit test (`dispatch.rs`) exercises the retry *predicate* against
//! a decoupled mirror loop; these tests drive a real session over the
//! scriptable fake so the whole `with_session` path is proven end-to-end.
//!
//! The fake's accept-loop re-serves its script to any subsequent connection, so
//! a spurious retry would appear in `recorded()` as a second LOGIN plus a second
//! mutating command. Asserting exactly one of each is the proof that no
//! reconnect happened.
//!
//! Fake, no container runtime — runs on every PR.
#![expect(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use core::num::NonZeroU32;
use std::time::Duration;

use rimap_fake_imap::fake_imap::{FakeImapServer, Step, login_preamble};
use rimap_imap::error::ImapError;
use rimap_imap::types::{Flag, FlagAction, Uid};

/// Generous command timeout so the near-instant loopback EOF surfaces as
/// `ConnectionLost` rather than racing a `Timeout` (mirrors the truncated-body
/// scenario in `adversarial_imap.rs`).
const BACKSTOP: Duration = Duration::from_secs(5);

/// Count recorded client command lines whose (upper-cased) text contains
/// `needle`. Used to prove a command — or the whole login preamble — ran
/// exactly once, never a second time via a spurious reconnect.
fn count(dialog: &[String], needle: &str) -> usize {
    dialog
        .iter()
        .filter(|line| line.to_ascii_uppercase().contains(needle))
        .count()
}

/// `STORE` (SELECT-then-`UID STORE`, `dispatch.rs`): a disconnect after the
/// server receives the `UID STORE` must surface `ConnectionLost` with the STORE
/// sent exactly once and no reconnect — a re-send could re-toggle the flag.
#[tokio::test]
async fn store_does_not_auto_retry_after_mid_command_disconnect() {
    let mut steps = login_preamble("IMAP4rev1 UIDPLUS");
    steps.extend([
        // store_flags issues a writable SELECT before the STORE.
        Step::Expect { verb: "SELECT" },
        Step::Send(b"* 1 EXISTS\r\n* OK [UIDVALIDITY 1] .\r\n".to_vec()),
        Step::Reply {
            text: "OK [READ-WRITE] SELECT completed",
        },
        // The mutating verb: receive it, then tear down mid-command.
        Step::Expect { verb: "UID STORE" },
        Step::Disconnect,
    ]);
    let server = FakeImapServer::start(steps).await;

    let conn = server.connection_timeout("user@example.com", BACKSTOP);
    let result = conn
        .store_flags(
            "INBOX",
            &[Uid::from(NonZeroU32::new(5).unwrap())],
            &[Flag::Seen],
            FlagAction::Add,
            None,
        )
        .await;

    let err = result.expect_err("mid-write STORE disconnect must fail, not return Ok");
    assert!(
        matches!(err, ImapError::ConnectionLost),
        "expected ConnectionLost, got {err:?}",
    );

    let dialog = server.recorded();
    assert_eq!(
        count(&dialog, "LOGIN"),
        1,
        "exactly one LOGIN — a retry would reconnect and re-login: {dialog:?}",
    );
    assert_eq!(
        count(&dialog, "UID STORE"),
        1,
        "STORE sent exactly once, never re-sent: {dialog:?}",
    );
}

/// `APPEND` (targets the mailbox directly, no SELECT — `dispatch.rs`): a
/// disconnect right after the server receives the `APPEND` command line (before
/// the literal continuation) must surface `ConnectionLost` with `APPEND` sent
/// exactly once and no reconnect — a re-send could append the message twice.
/// A second mutating verb pins the classification table, not just one branch.
#[tokio::test]
async fn append_does_not_auto_retry_after_mid_command_disconnect() {
    let mut steps = login_preamble("IMAP4rev1 UIDPLUS");
    steps.extend([
        // APPEND announces a literal; drop before sending the `+` continuation,
        // so the write is torn down mid-command.
        Step::Expect { verb: "APPEND" },
        Step::Disconnect,
    ]);
    let server = FakeImapServer::start(steps).await;

    let conn = server.connection_timeout("user@example.com", BACKSTOP);
    let message = b"From: a@example.com\r\nSubject: x\r\n\r\nhello\r\n";
    let result = conn.append_message("INBOX", message, &[], &[]).await;

    let err = result.expect_err("mid-write APPEND disconnect must fail, not return Ok");
    assert!(
        matches!(err, ImapError::ConnectionLost),
        "expected ConnectionLost, got {err:?}",
    );

    let dialog = server.recorded();
    assert_eq!(
        count(&dialog, "LOGIN"),
        1,
        "exactly one LOGIN — a retry would reconnect and re-login: {dialog:?}",
    );
    assert_eq!(
        count(&dialog, "APPEND"),
        1,
        "APPEND sent exactly once, never re-sent: {dialog:?}",
    );
}
