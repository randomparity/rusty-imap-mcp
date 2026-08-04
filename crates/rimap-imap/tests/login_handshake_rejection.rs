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

use rimap_fake_imap::fake_imap::{FakeImapServer, NoopAudit, PanicResolver, Step};
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
        Arc::new(NoopAudit),
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
    // This test pins the behaviour as it stands; it does not endorse it. A
    // failed probe means the capabilities are UNKNOWN, and `imap_login` maps
    // unknown onto the same `(false, false)` that means "absent" — which is
    // exactly `fallback_uses_folder_wide_expunge`'s condition, so an
    // uninformative probe fails open into a destructive default rather than
    // refusing. Tracked as its own defect in #649; #634 fixed the adjacent
    // problem of reading flags that describe a *different* session, not this
    // one of reading flags that describe *no* session.
    //
    // The move is the connection's first op, and that is what makes the
    // assertion sharp: `Connection::move_messages` reads
    // `has_move_capability()` / `has_uidplus_capability()` from inside the
    // `with_session` body (#634), which runs after the lazy connect has logged
    // in and issued the probe. So the move depends on the probe outcome, not on
    // the atomics' construction-time `false` — had the probe answered with the
    // pre-login `MOVE UIDPLUS` line, the atomics would be `true` and the move
    // would issue `UID MOVE`, diverging from the scripted fallback dialog.
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

    let uid = Uid::from(NonZeroU32::new(5).unwrap());
    let outcome = conn
        .move_messages("INBOX", "Archive", &[uid], None)
        .await
        .expect("move should succeed via the fallback path");

    // The probe yielded no capabilities despite the pre-login advertisement —
    // the post-login probe is the only source of truth for MOVE/UIDPLUS, and
    // the move above read these same values from inside its dispatch.
    assert!(
        !conn.has_move_capability(),
        "an empty post-login CAPABILITY probe must leave MOVE off",
    );
    assert!(
        !conn.has_uidplus_capability(),
        "an empty post-login CAPABILITY probe must leave UIDPLUS off",
    );

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
