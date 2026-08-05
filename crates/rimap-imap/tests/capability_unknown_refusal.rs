//! A reconnect whose LOGIN succeeds but whose post-login `CAPABILITY` probe
//! says nothing must refuse the mutating command, not fall back to the
//! folder-wide `EXPUNGE` (#649).
//!
//! This is the cut that reaches the defect in production. `delete_message` and
//! `move_messages` are [`Idempotency::Mutating`], so `with_session` never
//! retries them; the reconnect they can see is the one `dispatch::attempt`
//! performs when it consumes the poison flag under the session lock — after a
//! per-tool-call ceiling fired, a client cancelled, or a peer command was cut.
//! That reconnect logs in again and re-probes CAPABILITY, and a server that is
//! restarting or shedding load can answer `BAD`. The connect still succeeds;
//! only the advertisement is missing.
//!
//! Until #649 that missing advertisement was recorded as `(has_move=false,
//! has_uidplus=false)`, indistinguishable from a server that affirmatively
//! advertises neither — and that pair is exactly what
//! `ops::expunge::fallback_uses_folder_wide_expunge` selects the RFC 3501
//! folder-wide `EXPUNGE` on, removing every `\Deleted` message in the mailbox
//! rather than the requested UIDs.
//!
//! ## What keeps these tests from passing for the wrong reason
//!
//! Two things, because the state under test used to be bit-identical to two
//! others:
//!
//! * **The warm-up advertises `MOVE UIDPLUS`.** So the discarded session's
//!   value is `Known { true, true }`, distinct both from the fresh-connection
//!   default and from the `Known { false, false }` an `IMAP4rev1`-only server
//!   produces. A command built from the stale value issues `UID MOVE`; one
//!   built from a mis-encoded `Unknown` issues the fallback; only the fix
//!   issues neither.
//! * **The destructive dialog is scripted and never reached.** The second
//!   connection's script carries the full COPY/STORE/EXPUNGE fallback. With the
//!   refusal removed the command *succeeds* against it, so the `expect_err`
//!   fails on the refusal itself rather than on whatever error a
//!   desynchronized fake happens to raise.
//!
//! Fake, no container runtime — runs on every PR.
#![expect(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
#![expect(clippy::panic, reason = "test diagnostics")]

use core::num::NonZeroU32;
use std::time::Duration;

use rimap_fake_imap::fake_imap::{FakeImapServer, Step, login_preamble};
use rimap_imap::ServerCapabilities;
use rimap_imap::error::ImapError;
use rimap_imap::types::Uid;

/// Generous command timeout so the loopback dialog cannot race a `Timeout`
/// (mirrors `capability_reconnect_freshness`).
const BACKSTOP: Duration = Duration::from_secs(5);

/// Login preamble advertising `caps`, followed by the boot-style `LIST` the
/// tests use to establish a session and populate the capability record.
fn warm_up(caps: &str) -> Vec<Step> {
    let mut steps = login_preamble(caps);
    steps.extend([
        Step::Expect { verb: "LIST" },
        Step::Send(b"* LIST (\\HasNoChildren) \"/\" \"INBOX\"\r\n".to_vec()),
        Step::Reply {
            text: "OK LIST completed",
        },
    ]);
    steps
}

/// Greeting → pre-login `CAPABILITY` (informative) → `LOGIN OK` → post-login
/// `CAPABILITY` answered `BAD` with no untagged listing.
///
/// The pre-login line advertises `MOVE UIDPLUS` deliberately: it is not a
/// source of truth for the session's capabilities, and a client that fell back
/// to it would issue `UID MOVE` here rather than refuse.
fn login_with_unreadable_probe() -> Vec<Step> {
    vec![
        Step::Send(b"* OK fake ready\r\n".to_vec()),
        Step::Expect { verb: "CAPABILITY" },
        Step::Send(b"* CAPABILITY IMAP4rev1 MOVE UIDPLUS\r\n".to_vec()),
        Step::Reply {
            text: "OK CAPABILITY completed",
        },
        Step::Expect { verb: "LOGIN" },
        Step::Reply {
            text: "OK LOGIN completed",
        },
        // async-imap's `parse_capabilities` returns `Ok` at the tagged
        // completion without inspecting its status, so this is a "successful"
        // probe over an empty capability set — the common shape of unknown,
        // and the one that is not an `Err`.
        Step::Expect { verb: "CAPABILITY" },
        Step::Reply {
            text: "BAD capability temporarily unavailable",
        },
        Step::Expect { verb: "SELECT" },
        Step::Send(b"* 3 EXISTS\r\n* OK [UIDVALIDITY 1] .\r\n".to_vec()),
        Step::Reply {
            text: "OK [READ-WRITE] SELECT completed",
        },
    ]
}

/// `move_messages`' fallback dialog: UID COPY → STATUS dest → UID STORE
/// `\Deleted` → folder-wide EXPUNGE.
///
/// Appended to the script so that removing the refusal makes the command
/// *succeed* rather than desync against a short script — a desync would raise
/// `ConnectionLost`, which `expect_err` would happily accept. Reaching any of
/// these steps is the defect.
fn move_fallback_dialog() -> Vec<Step> {
    vec![
        Step::Expect { verb: "UID COPY" },
        Step::Reply {
            text: "OK COPY completed",
        },
        Step::Expect { verb: "STATUS" },
        Step::Send(b"* STATUS \"Trash\" (UIDVALIDITY 7)\r\n".to_vec()),
        Step::Reply {
            text: "OK STATUS completed",
        },
        Step::Expect { verb: "UID STORE" },
        Step::Send(b"* 1 FETCH (UID 5 FLAGS (\\Deleted))\r\n".to_vec()),
        Step::Reply {
            text: "OK STORE completed",
        },
        Step::Expect { verb: "EXPUNGE" },
        Step::Send(b"* 1 EXPUNGE\r\n".to_vec()),
        Step::Reply {
            text: "OK EXPUNGE completed",
        },
    ]
}

/// `delete_message`' fallback dialog, which is a different order and one
/// command shorter than [`move_fallback_dialog`]: UID STORE `\Deleted` → UID
/// COPY → folder-wide EXPUNGE, with no destination STATUS probe.
///
/// Spelled out separately rather than shared, because a script that does not
/// match the operation makes the command fail on a desync — and a test whose
/// `expect_err` is satisfied by `ConnectionLost` proves nothing about the
/// refusal.
fn delete_fallback_dialog() -> Vec<Step> {
    vec![
        Step::Expect { verb: "UID STORE" },
        Step::Send(b"* 1 FETCH (UID 5 FLAGS (\\Deleted))\r\n".to_vec()),
        Step::Reply {
            text: "OK STORE completed",
        },
        Step::Expect { verb: "UID COPY" },
        Step::Reply {
            text: "OK COPY completed",
        },
        Step::Expect { verb: "EXPUNGE" },
        Step::Send(b"* 1 EXPUNGE\r\n".to_vec()),
        Step::Reply {
            text: "OK EXPUNGE completed",
        },
    ]
}

fn uid(value: u32) -> Uid {
    Uid::from(NonZeroU32::new(value).unwrap())
}

/// Assertions shared by both operations: nothing that mutates the mailbox may
/// reach the wire, and the recorded state must be `Unknown` rather than either
/// bool pair it used to be confused with.
async fn assert_refused_without_touching_the_mailbox(
    conn: &rimap_imap::Connection,
    dialog: &[String],
    err: &ImapError,
    expected_op: &str,
) {
    match err {
        ImapError::CapabilitiesUnknown { op } => assert_eq!(*op, expected_op),
        other => panic!("expected ImapError::CapabilitiesUnknown, got {other:?}"),
    }

    assert_eq!(
        conn.capabilities().await,
        ServerCapabilities::Unknown,
        "the serving session's probe established nothing, so nothing may be \
         recorded as its advertisement",
    );

    let text = dialog.join("\n").to_ascii_uppercase();
    assert!(
        !text.contains("EXPUNGE"),
        "no EXPUNGE of any form may follow an unreadable probe — the \
         folder-wide one removes every \\Deleted message in INBOX rather than \
         UID 5: {text}",
    );
    assert!(
        !text.contains("UID STORE"),
        "the refusal must land before the \\Deleted flag is set, or the \
         message is left for whatever expunges INBOX next: {text}",
    );
    assert!(
        !text.contains("UID COPY"),
        "a refused command must not have copied anything to the destination: \
         {text}",
    );
    assert!(
        !text.contains("UID MOVE"),
        "UID MOVE was never advertised by the serving session: {text}",
    );
}

/// `delete_message` over a reconnect whose probe told us nothing.
#[tokio::test]
async fn delete_after_an_unreadable_reconnect_probe_refuses_rather_than_expunging() {
    let mut second = login_with_unreadable_probe();
    second.extend(delete_fallback_dialog());

    let server =
        FakeImapServer::start_sequence(vec![warm_up("IMAP4rev1 MOVE UIDPLUS"), second]).await;
    let conn = server.connection_timeout("user@example.com", BACKSTOP);

    conn.list_folders("*").await.expect("warm-up list");
    assert_eq!(
        conn.capabilities().await,
        ServerCapabilities::Known {
            has_move: true,
            has_uidplus: true,
        },
        "the warm-up must leave a value distinct from both `Unknown` and the \
         `neither` that selects the folder-wide EXPUNGE, or the assertions \
         below cannot tell the three apart",
    );

    // What the per-tool-call ceiling does when it cuts a command mid-flight:
    // the next command reconnects from inside `dispatch::attempt`.
    conn.poison();

    let err = conn
        .delete_message("INBOX", uid(5), "Trash", None)
        .await
        .expect_err("a reconnect that established no capabilities must refuse");

    assert_refused_without_touching_the_mailbox(&conn, &server.recorded(), &err, "delete_message")
        .await;
}

/// `move_messages` over the same reconnect. A separate call site with its own
/// refusal, so it needs its own coverage — `delete_message` passing proves
/// nothing about it.
#[tokio::test]
async fn move_after_an_unreadable_reconnect_probe_refuses_rather_than_expunging() {
    let mut second = login_with_unreadable_probe();
    second.extend(move_fallback_dialog());

    let server =
        FakeImapServer::start_sequence(vec![warm_up("IMAP4rev1 MOVE UIDPLUS"), second]).await;
    let conn = server.connection_timeout("user@example.com", BACKSTOP);

    conn.list_folders("*").await.expect("warm-up list");
    conn.poison();

    let err = conn
        .move_messages("INBOX", "Trash", &[uid(5)], None)
        .await
        .expect_err("a reconnect that established no capabilities must refuse");

    assert_refused_without_touching_the_mailbox(&conn, &server.recorded(), &err, "move").await;
}

/// The refusal keys on `Unknown`, not on "no MOVE and no UIDPLUS".
///
/// A server that affirmatively advertises `IMAP4rev1` and nothing else still
/// gets the folder-wide fallback, because that is what it asked for. Without
/// this, "refuse when capabilities are unknown" and "refuse whenever the
/// fallback would run" are indistinguishable — and the second would break every
/// pre-UIDPLUS server rather than fix a fail-open.
#[tokio::test]
async fn an_affirmative_neither_still_takes_the_documented_fallback() {
    let mut steps = login_preamble("IMAP4rev1");
    steps.extend([
        Step::Expect { verb: "SELECT" },
        Step::Send(b"* 3 EXISTS\r\n* OK [UIDVALIDITY 1] .\r\n".to_vec()),
        Step::Reply {
            text: "OK [READ-WRITE] SELECT completed",
        },
    ]);
    steps.extend(move_fallback_dialog());

    let server = FakeImapServer::start(steps).await;
    let conn = server.connection_timeout("user@example.com", BACKSTOP);

    let outcome = conn
        .move_messages("INBOX", "Trash", &[uid(5)], None)
        .await
        .expect("an IMAP4rev1-only server is a known state, not an unknown one");

    assert_eq!(
        conn.capabilities().await,
        ServerCapabilities::Known {
            has_move: false,
            has_uidplus: false,
        },
        "an IMAP4rev1 listing without MOVE or UIDPLUS is an advertisement, and \
         must be recorded as one",
    );
    assert!(outcome.used_fallback);
    assert!(
        outcome.folder_wide_expunge,
        "the folder-wide path is still reachable — from a known `neither`, \
         which is the only state that may reach it",
    );

    let dialog = server.recorded().join("\n").to_ascii_uppercase();
    assert!(
        dialog.contains("EXPUNGE") && !dialog.contains("UID EXPUNGE"),
        "the fallback issues a folder-wide EXPUNGE, not UID EXPUNGE: {dialog}",
    );
}
