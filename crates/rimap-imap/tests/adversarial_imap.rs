//! Adversarial IMAP scenarios driven against the in-process fake
//! (`rimap_fake_imap::fake_imap`). Scenario 1 (folder-wide EXPUNGE) lives in
//! `expunge_folder_wide_gap.rs`; scenarios 2–4 live here.
//!
//! Fake, no container runtime — runs on every PR.
//!
//! The `#![expect(...)]` list below must match exactly the clippy lints this
//! file's body triggers; later scenarios extend it as they add `.unwrap()` /
//! `panic!` constructs.
#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests"
)]

mod support;

use core::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use rimap_fake_imap::fake_imap::{FakeImapServer, PanicResolver, Step, login_preamble};
use rimap_imap::error::{AuthFailure, ImapError};
use rimap_imap::types::{FetchSpec, Uid};
use support::tracing_capture::WarnCapture;

/// Smoke/calibration: a real login + LIST through the fake proves the TLS
/// handshake, pin, greeting, CAPABILITY drain, LOGIN, and post-login
/// CAPABILITY all work end-to-end. Prints `recorded()` so the exact client
/// command order can be read off and used to write the other scenarios.
#[tokio::test]
async fn login_and_list_succeed_through_fake() {
    let mut steps = login_preamble("IMAP4rev1 UIDPLUS");
    steps.extend([
        Step::Expect { verb: "LIST" },
        Step::Send(b"* LIST (\\HasNoChildren) \"/\" \"INBOX\"\r\n".to_vec()),
        Step::Reply {
            text: "OK LIST completed",
        },
    ]);
    let server = FakeImapServer::start(steps).await;

    let conn = server.connection("user@example.com");
    let folders = conn.list_folders("*").await.expect("list should succeed");
    assert!(folders.iter().any(|f| f.name == "INBOX"));

    // Calibration aid: dump the exact client command order. `print_stderr` is
    // denied workspace-wide (stdout is the MCP transport); stderr is fine in a
    // test, so suppress it at the call site.
    #[expect(clippy::print_stderr, reason = "calibration output for TDD")]
    {
        eprintln!("recorded dialog: {:#?}", server.recorded());
    }
}

/// Scenario 2: LOGINDISABLED in CAPABILITY yields `CapabilityMissing` with
/// `needed: "LOGIN"` BEFORE credential resolution — a `PanicResolver` proves
/// `resolve()` is never consulted.
#[tokio::test]
async fn logindisabled_maps_to_capability_missing_before_resolve() {
    let server = FakeImapServer::start(vec![
        Step::Send(b"* OK fake ready\r\n".to_vec()),
        Step::Expect { verb: "CAPABILITY" },
        Step::Send(b"* CAPABILITY IMAP4rev1 LOGINDISABLED\r\n".to_vec()),
        Step::Reply {
            text: "OK CAPABILITY completed",
        },
        // Client must NOT send LOGIN; it errors out here.
    ])
    .await;

    let conn = server.connection_with(
        "user@example.com",
        Arc::new(PanicResolver),
        Duration::from_secs(1),
    );
    let err = conn.list_folders("*").await.unwrap_err();
    match err {
        ImapError::Auth {
            reason: AuthFailure::CapabilityMissing { needed },
        } => assert_eq!(needed, "LOGIN"),
        other => panic!("expected CapabilityMissing {{ needed: LOGIN }}, got {other:?}"),
    }
}

/// Scenario 3: a UID FETCH whose items omit or zero the UID are skipped, and a
/// single aggregated `warn!` carrying `skipped_uids` fires. Pinned to a
/// current-thread runtime so the thread-local capture covers the warn.
#[tokio::test(flavor = "current_thread")]
async fn missing_and_zero_uid_fetch_items_are_skipped_with_one_warn() {
    let capture = WarnCapture::install();

    let mut steps = login_preamble("IMAP4rev1 UIDPLUS");
    steps.extend([
        // fetch: EXAMINE (read-only open — ops::fetch calls select(...,true)).
        Step::Expect { verb: "EXAMINE" },
        Step::Send(b"* 3 EXISTS\r\n* OK [UIDVALIDITY 1] .\r\n".to_vec()),
        Step::Reply {
            text: "OK [READ-ONLY] EXAMINE completed",
        },
        // UID FETCH: item with no UID, item with UID 0, valid item (UID 5).
        Step::Expect { verb: "UID FETCH" },
        Step::Send(b"* 1 FETCH (FLAGS (\\Seen))\r\n".to_vec()),
        Step::Send(b"* 2 FETCH (UID 0 FLAGS (\\Seen))\r\n".to_vec()),
        Step::Send(b"* 3 FETCH (UID 5 FLAGS (\\Seen))\r\n".to_vec()),
        Step::Reply {
            text: "OK FETCH completed",
        },
    ]);
    let server = FakeImapServer::start(steps).await;

    let conn = server.connection("user@example.com");
    let spec = FetchSpec {
        envelope: false,
        bodystructure: false,
        uid: true,
        flags: true,
        size: false,
    };
    let (messages, _uidv) = conn
        .fetch(
            "INBOX",
            &[Uid::from(NonZeroU32::new(5).unwrap())],
            spec,
            None,
        )
        .await
        .expect("fetch should succeed, skipping malformed items");

    // Only the well-formed UID 5 survives.
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].uid, Uid::from(NonZeroU32::new(5).unwrap()));

    // Exactly one aggregated skip warn fired (filter by the distinctive field).
    let skip_warns: Vec<String> = capture
        .records()
        .into_iter()
        .filter(|r| r.contains("skipped_uids="))
        .collect();
    assert_eq!(
        skip_warns.len(),
        1,
        "one aggregated skip warn expected: {skip_warns:?}"
    );
    assert!(
        skip_warns[0].contains("skipped_uids=2"),
        "expected skipped_uids=2, got: {}",
        skip_warns[0],
    );
}

/// Scenario 4: a FETCH `BODY[]` literal announcing more bytes than are sent,
/// followed by a mid-literal disconnect, must surface a typed error (not a
/// hang, not a bare `Timeout`). The accept-loop re-serves the script if the
/// read-only path reconnects on `ConnectionLost`.
#[tokio::test]
async fn truncated_literal_yields_typed_error_not_timeout() {
    let mut steps = login_preamble("IMAP4rev1 UIDPLUS");
    steps.extend([
        Step::Expect { verb: "EXAMINE" },
        Step::Send(b"* 1 EXISTS\r\n* OK [UIDVALIDITY 1] .\r\n".to_vec()),
        Step::Reply {
            text: "OK [READ-ONLY] EXAMINE completed",
        },
        // UID FETCH: announce a 100-byte BODY[] literal, send 5 bytes, drop.
        Step::Expect { verb: "UID FETCH" },
        Step::Send(b"* 1 FETCH (UID 5 BODY[] {100}\r\nHELLO".to_vec()),
        Step::Disconnect,
    ]);
    let server = FakeImapServer::start(steps).await;

    // LOGIN succeeds here, so use the static-resolver constructor with a
    // generous 5s backstop so the near-instant loopback EOF wins the race.
    let conn = server.connection_timeout("user@example.com", Duration::from_secs(5));
    let spec = FetchSpec {
        envelope: false,
        bodystructure: false,
        uid: true,
        flags: false,
        size: false,
    };
    let result = conn
        .fetch(
            "INBOX",
            &[Uid::from(NonZeroU32::new(5).unwrap())],
            spec,
            None,
        )
        .await;

    // The mid-literal EOF surfaces as the truncation-class `ConnectionLost`
    // (async-imap 0.11), the client's typed signal for a torn-down stream —
    // NOT a `Timeout` (which would mean the client hung waiting rather than
    // detecting the truncation). `fetch` is read-only, so this also exercises
    // the one reconnect-and-retry against the accept-loop fake, which re-serves
    // the same truncation. Pin the exact variant so a regression to a
    // different (non-`Timeout`) error still fails loudly.
    let err = result.expect_err("truncated literal must fail, not return Ok");
    assert!(
        matches!(err, ImapError::ConnectionLost),
        "expected truncation-class ConnectionLost, got {err:?}",
    );
}
