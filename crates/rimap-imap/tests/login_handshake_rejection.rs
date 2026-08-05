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
//!      `ServerCapabilities::Unknown` → a subsequently-issued move is refused
//!      with `ImapError::CapabilitiesUnknown` rather than falling back to a
//!      folder-wide EXPUNGE (observable in `recorded()`).
//!
//! Fake, no container runtime — runs on every PR.
#![expect(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
#![expect(clippy::panic, reason = "test diagnostics")]

use core::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use rimap_fake_imap::fake_imap::{FakeImapServer, NoopAudit, PanicResolver, Step};
use rimap_imap::ServerCapabilities;
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
async fn post_login_capability_probe_failure_refuses_the_move() {
    // The pre-login CAPABILITY advertises MOVE and UIDPLUS, but the *post-login*
    // probe (`session.capabilities()`) is answered `BAD` with no untagged
    // `* CAPABILITY` line. async-imap's parser stops at the tagged completion
    // without inspecting its status, so the probe returns `Ok` over an empty
    // capability set: a success that established nothing.
    //
    // That state is `ServerCapabilities::Unknown`, and a move must refuse it
    // (#649). Until then it was recorded as `(has_move=false,
    // has_uidplus=false)` — the same value an `IMAP4rev1`-only server produces
    // — and `(false, false)` is exactly the condition
    // `ops::expunge::fallback_uses_folder_wide_expunge` selects the RFC 3501
    // folder-wide EXPUNGE on. So an uninformative probe used to fail open into
    // the branch that removes every `\Deleted` message in INBOX rather than the
    // requested UID.
    //
    // The divergence between the two advertisements is what makes this bite:
    // the pre-login line offers `MOVE UIDPLUS`, so a client that trusted it
    // would issue `UID MOVE`. The probe is the only source of truth, and when
    // the probe says nothing there is no truth to act on.
    //
    // The whole fallback dialog is still scripted below and is deliberately
    // never reached. Leaving it in is what stops this test passing for the
    // wrong reason: with the refusal removed the move *succeeds* against these
    // steps, so `expect_err` fails loudly instead of catching whatever error a
    // desynchronized fake happened to produce.
    //
    // It does NOT pin where the flags are read; `capability_reconnect_freshness.rs`
    // does that (#634).
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
        // `* CAPABILITY` line, so the probe yields an empty capability set.
        Step::Expect { verb: "CAPABILITY" },
        Step::Reply {
            text: "BAD capability temporarily unavailable",
        },
        // `move_messages` SELECTs before it consults capabilities, so the
        // SELECT is expected. Everything after it is the fallback dialog that
        // must NOT run: UID COPY → STATUS dest → UID STORE \Deleted →
        // folder-wide EXPUNGE.
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
    let err = conn
        .move_messages("INBOX", "Archive", &[uid], None)
        .await
        .expect_err("an unreadable capability probe must refuse the move");

    match err {
        ImapError::CapabilitiesUnknown { op } => assert_eq!(op, "move"),
        other => panic!("expected ImapError::CapabilitiesUnknown, got {other:?}"),
    }

    // The empty probe is `Unknown`, distinct from the `Known { false, false }`
    // an `IMAP4rev1`-only server produces — the distinction the refusal rests
    // on, asserted directly so it cannot rot into the old bool pair.
    assert_eq!(
        conn.capabilities().await,
        ServerCapabilities::Unknown,
        "an empty post-login CAPABILITY probe establishes nothing about the \
         server and must not be recorded as an advertisement",
    );

    let dialog = server.recorded().join("\n").to_ascii_uppercase();
    assert!(
        !dialog.contains("EXPUNGE"),
        "no EXPUNGE of any form may be issued off an unreadable probe — the \
         folder-wide one purges every \\Deleted message in INBOX: {dialog}",
    );
    assert!(
        !dialog.contains("UID STORE"),
        "the refusal must land before the \\Deleted flag is set, or the \
         message is left for whatever expunges INBOX next: {dialog}",
    );
    assert!(
        !dialog.contains("UID COPY") && !dialog.contains("UID MOVE"),
        "nothing may be written to the destination folder either: {dialog}",
    );
}
