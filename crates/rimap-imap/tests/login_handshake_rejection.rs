//! Login/handshake rejection paths over the scriptable in-process fake (#566).
//!
//! Three server-side refusals had never been exercised over a real socket
//! because the fake's `login_preamble` always answers `OK` — no test had ever
//! seen a server *refuse*. The only socket-level coverage was the Docker-gated
//! Dovecot suite, which silently skips on standard CI. These tests script the
//! refusals with `Step::Send`/`Expect`/`Reply` and drive the real `Connection`,
//! so they run on every PR with no container gate.
//!
//! Paths covered (all in `rimap-imap/src/connection/login.rs`):
//!   1. LOGIN tagged `NO` → `AuthFailure::LoginRejected`.
//!   2. Implicit-TLS greeting `BYE` → `AuthFailure::ServerRejected`.
//!   3. Post-login `CAPABILITY` probe answered `BAD` (empty capability set) →
//!      `(has_move, has_uidplus)` recorded as `(false, false)` → non-atomic
//!      COPY/STORE/EXPUNGE move fallback on a subsequently-issued move
//!      (observable in `recorded()`).
//!
//! Fake, no container runtime — runs on every PR.
#![expect(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
#![expect(clippy::panic, reason = "test diagnostics")]

use core::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use rimap_fake_imap::fake_imap::{FakeImapServer, PanicResolver, Step};
use rimap_imap::error::{AuthFailure, ImapError};
use rimap_imap::types::Uid;

#[tokio::test]
async fn login_no_surfaces_login_rejected() {
    // Greeting OK, pre-login CAPABILITY OK, then the server refuses LOGIN with a
    // tagged `NO [AUTHENTICATIONFAILED]`. Credential resolution succeeds (the
    // static resolver returns a password) — the refusal is the server's, so the
    // typed error must be `LoginRejected`, not a generic protocol error.
    let steps = vec![
        Step::Send(b"* OK fake ready\r\n".to_vec()),
        Step::Expect { verb: "CAPABILITY" },
        Step::Send(b"* CAPABILITY IMAP4rev1\r\n".to_vec()),
        Step::Reply {
            text: "OK CAPABILITY completed",
        },
        Step::Expect { verb: "LOGIN" },
        Step::Reply {
            text: "NO [AUTHENTICATIONFAILED] invalid credentials",
        },
    ];
    let server = FakeImapServer::start(steps).await;

    let conn = server.connection("user@example.com");
    let err = conn
        .list_folders("*")
        .await
        .expect_err("LOGIN NO must reject the connection");

    match err {
        ImapError::Auth {
            reason: AuthFailure::LoginRejected,
        } => {}
        other => panic!("expected AuthFailure::LoginRejected, got {other:?}"),
    }

    // The client got far enough to send LOGIN, and no folder command followed.
    let dialog = server.recorded().join("\n").to_ascii_uppercase();
    assert!(
        dialog.contains("LOGIN"),
        "client must issue LOGIN: {dialog}"
    );
    assert!(
        !dialog.contains("LIST"),
        "no LIST must follow a rejected LOGIN: {dialog}",
    );
}

#[tokio::test]
async fn bye_greeting_surfaces_server_rejected() {
    // Implicit-TLS path: the greeting is read by `imap_login`. A `BYE` greeting
    // means the server refused us before authentication, so resolution is never
    // reached — a `PanicResolver` bakes that invariant in.
    let steps = vec![
        Step::Send(b"* BYE server shutting down\r\n".to_vec()),
        Step::Disconnect,
    ];
    let server = FakeImapServer::start(steps).await;

    let conn = server.connection_with(
        "user@example.com",
        Arc::new(PanicResolver),
        Duration::from_secs(1),
    );
    let err = conn
        .list_folders("*")
        .await
        .expect_err("BYE greeting must reject the connection");

    match err {
        ImapError::Auth {
            reason: AuthFailure::ServerRejected,
        } => {}
        other => panic!("expected AuthFailure::ServerRejected, got {other:?}"),
    }

    // The refusal is in the greeting, before any client command is sent.
    assert!(
        server.recorded().is_empty(),
        "no IMAP command must be sent after a BYE greeting; recorded: {:?}",
        server.recorded(),
    );
}

#[tokio::test]
async fn post_login_capability_probe_failure_forces_move_fallback() {
    // The pre-login CAPABILITY advertises MOVE and UIDPLUS, but the *post-login*
    // probe (`session.capabilities()`) is answered `BAD` with no untagged
    // `* CAPABILITY` line, so it yields an empty capability set. `imap_login`
    // therefore records `(has_move=false, has_uidplus=false)`, and a later move
    // takes the non-atomic COPY + STORE \Deleted + folder-wide EXPUNGE fallback
    // — even though the server advertised MOVE/UIDPLUS pre-login.
    //
    // Why the connection is WARMED first (with `list_folders`) before the move:
    // `Connection::move_messages` snapshots `has_move_capability()` /
    // `has_uidplus_capability()` *before* it establishes the session (see
    // `connection/dispatch.rs`). On a cold connection those atomics still hold
    // their construction-time `false`, so a move issued as the very first
    // operation would take the fallback *regardless of the probe result* — a
    // vacuous assertion. Warming the connection first runs the post-login probe
    // and populates the atomics from the server's actual reply, so the move
    // below genuinely depends on the probe outcome: with a MOVE/UIDPLUS-
    // advertising probe the atomics would be `true` and the move would issue
    // `UID MOVE` instead, diverging from the scripted fallback dialog.
    //
    // (`expunge_folder_wide_gap.rs` issues its move as the first op and so does
    // not exercise the post-login probe result; this test does.)
    let steps = vec![
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
        // Post-login CAPABILITY probe: a tagged `BAD` with no untagged
        // `* CAPABILITY` line. async-imap's capability parser stops on the
        // tagged completion without inspecting its status, so the probe yields
        // an empty capability set — MOVE and UIDPLUS are both absent.
        Step::Expect { verb: "CAPABILITY" },
        Step::Reply {
            text: "BAD capability temporarily unavailable",
        },
        // Warm-up: the boot-style `LIST` that establishes the session and runs
        // the probe above, so the capability atomics are populated before the
        // move snapshots them.
        Step::Expect { verb: "LIST" },
        Step::Send(b"* LIST (\\HasNoChildren) \"/\" \"INBOX\"\r\n".to_vec()),
        Step::Reply {
            text: "OK LIST completed",
        },
        // move_messages fallback dialog: SELECT source (read-write) → UID COPY →
        // STATUS dest → UID STORE \Deleted → folder-wide EXPUNGE (NOT
        // `UID EXPUNGE`).
        Step::Expect { verb: "SELECT" },
        Step::Send(b"* 3 EXISTS\r\n* OK [UIDVALIDITY 1] .\r\n".to_vec()),
        Step::Reply {
            text: "OK [READ-WRITE] SELECT completed",
        },
        Step::Expect { verb: "UID COPY" },
        Step::Reply {
            text: "OK COPY completed",
        },
        Step::Expect { verb: "STATUS" },
        Step::Send(b"* STATUS \"Archive\" (UIDVALIDITY 7)\r\n".to_vec()),
        Step::Reply {
            text: "OK STATUS completed",
        },
        Step::Expect { verb: "UID STORE" },
        Step::Send(b"* 1 FETCH (FLAGS (\\Deleted))\r\n".to_vec()),
        Step::Reply {
            text: "OK STORE completed",
        },
        Step::Expect { verb: "EXPUNGE" },
        Step::Send(b"* 1 EXPUNGE\r\n".to_vec()),
        Step::Reply {
            text: "OK EXPUNGE completed",
        },
    ];
    let server = FakeImapServer::start(steps).await;

    let conn = server.connection("user@example.com");

    // Warm the connection so the post-login probe runs and the atomics reflect
    // its (empty) result.
    conn.list_folders("*").await.expect("warm-up list");

    // The probe yielded no capabilities despite the pre-login advertisement —
    // the post-login probe is the only source of truth for MOVE/UIDPLUS.
    assert!(
        !conn.has_move_capability(),
        "an empty post-login CAPABILITY probe must leave MOVE off",
    );
    assert!(
        !conn.has_uidplus_capability(),
        "an empty post-login CAPABILITY probe must leave UIDPLUS off",
    );

    let uid = Uid::from(NonZeroU32::new(5).unwrap());
    let outcome = conn
        .move_messages("INBOX", "Archive", &[uid], None)
        .await
        .expect("move should succeed via the fallback path");

    assert!(
        outcome.used_fallback,
        "an empty capability probe must force the non-atomic fallback",
    );
    assert!(
        outcome.folder_wide_expunge,
        "no UIDPLUS (empty probe) means a folder-wide EXPUNGE",
    );

    let dialog = server.recorded().join("\n").to_ascii_uppercase();
    assert!(
        !dialog.contains("UID MOVE"),
        "the fallback must not issue UID MOVE despite pre-login MOVE: {dialog}",
    );
    assert!(
        dialog.contains("EXPUNGE") && !dialog.contains("UID EXPUNGE"),
        "the fallback must issue a folder-wide EXPUNGE, not UID EXPUNGE: {dialog}",
    );
}
