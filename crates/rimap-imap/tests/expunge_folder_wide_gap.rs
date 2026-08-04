//! Scenario 1: a server advertising neither MOVE nor UIDPLUS forces the
//! COPY + STORE \Deleted + folder-wide EXPUNGE fallback (the data-loss path).
//! Drives the real `Connection::move_messages` against the in-process fake and
//! asserts both `used_fallback` and `folder_wide_expunge`, plus that a plain
//! `EXPUNGE` (not `UID EXPUNGE`) reached the wire.
//!
//! The move runs as the connection's first op, on a cold connection. That is
//! not vacuous: `Connection::move_messages` reads
//! `has_move_capability()` / `has_uidplus_capability()` from inside the
//! `with_session` body (#634), which runs after the lazy connect has logged in
//! and run the post-login CAPABILITY probe (scripted in `login_preamble`,
//! advertising only `IMAP4rev1`). So the atomics the move reads are the ones
//! that probe populated, and the fallback below genuinely depends on the
//! absence of MOVE/UIDPLUS rather than on the construction-time `false`.
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

    let uid = Uid::from(NonZeroU32::new(5).unwrap());
    let outcome = conn
        .move_messages("INBOX", "Archive", &[uid], None)
        .await
        .expect("move should succeed via fallback");

    // The move's own lazy connect ran the post-login probe, so these now read
    // the server's actual advertisement rather than the construction-time
    // default — the fallback above was chosen from these values.
    assert!(
        !conn.has_move_capability(),
        "IMAP4rev1-only probe must leave MOVE off",
    );
    assert!(
        !conn.has_uidplus_capability(),
        "IMAP4rev1-only probe must leave UIDPLUS off",
    );

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
