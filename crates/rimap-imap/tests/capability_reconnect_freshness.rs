//! A reconnect that happens *inside* a mutating dispatch must leave the
//! command acting on the capabilities of the session that actually serves it,
//! not the ones the discarded session reported (#634).
//!
//! `move_messages` and `delete_message` are [`Idempotency::Mutating`], so
//! `with_session` never retries them; the only reconnect they can see is the
//! one `dispatch::attempt` performs when it consumes the poison flag under the
//! session lock. That reconnect logs in again and re-reads CAPABILITY, so the
//! session slot carries a different advertisement *during* the dispatch —
//! after the point at which the command used to snapshot it.
//!
//! Mechanism: `start_sequence` serves a different capability advertisement to
//! each of the two connections. A warm-up `list_folders` establishes the first
//! session and its advertisement; `poison()` then
//! forces the mutating op to reconnect to the second, which advertises the
//! opposite set. Every step of the second connection's dialog is scripted for
//! the *fresh* capabilities, so a command built from the stale ones desynchs
//! against the fake and the operation fails.
//!
//! Both error directions are covered because they fail differently:
//!   * stale `false` → the folder-wide EXPUNGE fallback runs against a server
//!     that advertised MOVE, purging every `\Deleted` message in the folder
//!     rather than the requested UIDs (the data-loss direction);
//!   * stale `true` → `UID MOVE` is issued to a server that never advertised
//!     it.
//!
//! Fake, no container runtime — runs on every PR.
#![expect(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use core::num::NonZeroU32;
use std::time::Duration;

use rimap_fake_imap::fake_imap::{FakeImapServer, Step, login_preamble};
use rimap_imap::ServerCapabilities;
use rimap_imap::types::Uid;

/// Generous command timeout so the loopback dialog cannot race a `Timeout`
/// (mirrors `poison_reconnect`).
const BACKSTOP: Duration = Duration::from_secs(5);

/// Login preamble advertising `caps`, followed by the boot-style `LIST` the
/// tests use to establish a session and its capability advertisement.
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

/// Whether any recorded client command line contains `needle` (upper-cased).
fn issued(dialog: &[String], needle: &str) -> bool {
    dialog
        .iter()
        .any(|line| line.to_ascii_uppercase().contains(needle))
}

fn uid(value: u32) -> Uid {
    Uid::from(NonZeroU32::new(value).unwrap())
}

/// Stale `false` — the data-loss direction. The first session advertised
/// neither MOVE nor UIDPLUS; the reconnect lands on a server advertising both.
/// A move built from the discarded session's flags would take the COPY + STORE
/// + folder-wide EXPUNGE fallback against a server that supports the atomic
/// `UID MOVE`.
#[tokio::test]
async fn move_after_reconnect_uses_the_serving_sessions_capabilities() {
    let mut second = login_preamble("IMAP4rev1 MOVE UIDPLUS");
    second.extend([
        Step::Expect { verb: "SELECT" },
        Step::Send(b"* 3 EXISTS\r\n* OK [UIDVALIDITY 1] .\r\n".to_vec()),
        Step::Reply {
            text: "OK [READ-WRITE] SELECT completed",
        },
        Step::Expect { verb: "UID MOVE" },
        Step::Send(b"* OK [COPYUID 7 5 10] Moved\r\n* 1 EXPUNGE\r\n".to_vec()),
        Step::Reply {
            text: "OK MOVE completed",
        },
    ]);
    let server = FakeImapServer::start_sequence(vec![warm_up("IMAP4rev1"), second]).await;
    let conn = server.connection_timeout("user@example.com", BACKSTOP);

    conn.list_folders("*").await.expect("warm-up list");
    assert_eq!(
        conn.capabilities().await,
        ServerCapabilities::Known {
            has_move: false,
            has_uidplus: false,
        },
        "the first session's IMAP4rev1-only advertisement is an affirmative \
         `neither` — not `Unknown`, which is what an unreadable probe yields \
         (#649)",
    );

    // What the per-tool-call ceiling does when it cuts a command mid-flight:
    // the next command reconnects from inside `dispatch::attempt`.
    conn.poison();

    let outcome = conn
        .move_messages("INBOX", "Archive", &[uid(5)], None)
        .await
        .expect("the reconnected session advertises MOVE, so UID MOVE must be issued");

    assert!(
        !outcome.used_fallback,
        "the serving session advertised MOVE, so the non-atomic fallback must not run",
    );
    assert!(
        !outcome.folder_wide_expunge,
        "no folder-wide EXPUNGE may be issued against a MOVE/UIDPLUS server",
    );

    let dialog = server.recorded();
    assert!(
        issued(&dialog, "UID MOVE"),
        "the atomic UID MOVE must reach the wire: {dialog:?}",
    );
    assert!(
        !issued(&dialog, "EXPUNGE"),
        "a folder-wide EXPUNGE would purge every \\Deleted message in INBOX: {dialog:?}",
    );
}

/// Stale `true` — a command the new server never advertised. The first session
/// advertised MOVE and UIDPLUS; the reconnect lands on an IMAP4rev1-only
/// server, so the delete must fall back to COPY + folder-wide EXPUNGE rather
/// than issue `UID MOVE`.
#[tokio::test]
async fn delete_after_reconnect_does_not_issue_an_unadvertised_move() {
    let mut second = login_preamble("IMAP4rev1");
    second.extend([
        Step::Expect { verb: "SELECT" },
        Step::Send(b"* 3 EXISTS\r\n* OK [UIDVALIDITY 1] .\r\n".to_vec()),
        Step::Reply {
            text: "OK [READ-WRITE] SELECT completed",
        },
        // delete_message flags `\Deleted` before moving, whichever path runs.
        Step::Expect { verb: "UID STORE" },
        Step::Send(b"* 1 FETCH (UID 5 FLAGS (\\Deleted))\r\n".to_vec()),
        Step::Reply {
            text: "OK STORE completed",
        },
        Step::Expect { verb: "UID COPY" },
        Step::Reply {
            text: "OK COPY completed",
        },
        // Plain EXPUNGE (no UIDPLUS), NOT a scoped `UID EXPUNGE`.
        Step::Expect { verb: "EXPUNGE" },
        Step::Send(b"* 1 EXPUNGE\r\n".to_vec()),
        Step::Reply {
            text: "OK EXPUNGE completed",
        },
    ]);
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
        "the first session advertised MOVE and UIDPLUS, so both flags must be on",
    );

    conn.poison();

    let (result, _uidvalidity) = conn
        .delete_message("INBOX", uid(5), "Trash", None)
        .await
        .expect("the reconnected session lacks MOVE, so the fallback must run");

    assert!(
        result.used_fallback,
        "an IMAP4rev1-only serving session forces the non-atomic fallback",
    );
    assert!(
        result.folder_wide_expunge,
        "no MOVE and no UIDPLUS on the serving session means a folder-wide EXPUNGE",
    );

    let dialog = server.recorded();
    assert!(
        !issued(&dialog, "UID MOVE"),
        "UID MOVE must never be issued to a server that did not advertise it: {dialog:?}",
    );
}
