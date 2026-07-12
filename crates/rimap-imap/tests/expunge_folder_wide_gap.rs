//! Scenario 1: a server advertising neither MOVE nor UIDPLUS forces the
//! COPY + STORE \Deleted + folder-wide EXPUNGE fallback (the data-loss path).
//! Drives the real `Connection::move_messages` against the in-process fake and
//! asserts both `used_fallback` and `folder_wide_expunge`, plus that a plain
//! `EXPUNGE` (not `UID EXPUNGE`) reached the wire.
//!
//! The connection is WARMED with `list_folders` before the move. Otherwise the
//! move would be the connection's first op, and `Connection::move_messages`
//! snapshots `has_move_capability()` / `has_uidplus_capability()` *before* it
//! establishes the session (see `connection/dispatch.rs`). On a cold connection
//! those atomics still hold their construction-time `false`, so the fallback
//! would be taken regardless of what the server advertised — a vacuous
//! assertion. Warming first runs the post-login CAPABILITY probe (scripted in
//! `login_preamble`, advertising only `IMAP4rev1`), populating the atomics from
//! the server's actual reply so the move below genuinely depends on the absence
//! of MOVE/UIDPLUS.
//!
//! Fake, no container runtime — runs on every PR. Replaces the former
//! ignored placeholder that marked this gap.
#![expect(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use core::num::NonZeroU32;

use rimap_fake_imap::fake_imap::{FakeImapServer, Step, login_preamble};
use rimap_imap::types::Uid;

#[tokio::test]
async fn no_move_no_uidplus_uses_folder_wide_expunge() {
    // No UIDPLUS and no MOVE advertised → the copy/store/folder-wide-EXPUNGE
    // fallback runs.
    let mut steps = login_preamble("IMAP4rev1");
    steps.extend([
        // Warm-up: the boot-style LIST that establishes the session and runs
        // the post-login CAPABILITY probe (scripted in the preamble), so the
        // capability atomics are populated before the move snapshots them.
        Step::Expect { verb: "LIST" },
        Step::Send(b"* LIST (\\HasNoChildren) \"/\" \"INBOX\"\r\n".to_vec()),
        Step::Reply {
            text: "OK LIST completed",
        },
        // move_messages: SELECT source (read-write; select(...,false)).
        Step::Expect { verb: "SELECT" },
        Step::Send(b"* 3 EXISTS\r\n* OK [UIDVALIDITY 1] .\r\n".to_vec()),
        Step::Reply {
            text: "OK [READ-WRITE] SELECT completed",
        },
        // UID COPY 5 "Archive"
        Step::Expect { verb: "UID COPY" },
        Step::Reply {
            text: "OK COPY completed",
        },
        // STATUS "Archive" (UIDVALIDITY) — dest probe after COPY.
        Step::Expect { verb: "STATUS" },
        Step::Send(b"* STATUS \"Archive\" (UIDVALIDITY 7)\r\n".to_vec()),
        Step::Reply {
            text: "OK STATUS completed",
        },
        // UID STORE 5 +FLAGS (\Deleted)
        Step::Expect { verb: "UID STORE" },
        Step::Send(b"* 1 FETCH (FLAGS (\\Deleted))\r\n".to_vec()),
        Step::Reply {
            text: "OK STORE completed",
        },
        // Plain EXPUNGE (folder-wide) — NOT `UID EXPUNGE`.
        Step::Expect { verb: "EXPUNGE" },
        Step::Send(b"* 1 EXPUNGE\r\n".to_vec()),
        Step::Reply {
            text: "OK EXPUNGE completed",
        },
    ]);
    let server = FakeImapServer::start(steps).await;

    let conn = server.connection("user@example.com");

    // Warm the connection so the post-login probe runs and the capability
    // atomics reflect the server's advertisement (neither MOVE nor UIDPLUS)
    // before move_messages snapshots them.
    conn.list_folders("*").await.expect("warm-up list");
    assert!(
        !conn.has_move_capability(),
        "IMAP4rev1-only probe must leave MOVE off",
    );
    assert!(
        !conn.has_uidplus_capability(),
        "IMAP4rev1-only probe must leave UIDPLUS off",
    );

    let uid = Uid::from(NonZeroU32::new(5).unwrap());
    let outcome = conn
        .move_messages("INBOX", "Archive", &[uid], None)
        .await
        .expect("move should succeed via fallback");

    assert!(outcome.used_fallback, "non-atomic fallback must be flagged");
    assert!(
        outcome.folder_wide_expunge,
        "data-loss folder-wide EXPUNGE must be flagged (no MOVE, no UIDPLUS)",
    );

    // Wire check: a plain EXPUNGE was issued, never a scoped UID EXPUNGE.
    let dialog = server.recorded().join("\n").to_ascii_uppercase();
    assert!(dialog.contains("EXPUNGE"), "client must issue EXPUNGE");
    assert!(
        !dialog.contains("UID EXPUNGE"),
        "client must NOT scope the expunge to UIDs on the no-UIDPLUS path",
    );
}
