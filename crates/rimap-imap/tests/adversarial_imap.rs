//! Adversarial IMAP scenarios driven against the in-process fake
//! (`support::fake_imap`). Scenario 1 (folder-wide EXPUNGE) lives in
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

use std::sync::Arc;
use std::time::Duration;

use rimap_imap::error::{AuthFailure, ImapError};
use support::fake_imap::{FakeImapServer, PanicResolver, Step};

/// Smoke/calibration: a real login + LIST through the fake proves the TLS
/// handshake, pin, greeting, CAPABILITY drain, LOGIN, and post-login
/// CAPABILITY all work end-to-end. Prints `recorded()` so the exact client
/// command order can be read off and used to write the other scenarios.
#[tokio::test]
async fn login_and_list_succeed_through_fake() {
    let server = FakeImapServer::start(vec![
        Step::Send(b"* OK fake ready\r\n".to_vec()),
        Step::Expect { verb: "CAPABILITY" },
        Step::Send(b"* CAPABILITY IMAP4rev1 UIDPLUS\r\n".to_vec()),
        Step::Reply {
            text: "OK CAPABILITY completed",
        },
        Step::Expect { verb: "LOGIN" },
        Step::Reply {
            text: "OK LOGIN completed",
        },
        // Post-login CAPABILITY probe (login.rs calls session.capabilities()).
        Step::Expect { verb: "CAPABILITY" },
        Step::Send(b"* CAPABILITY IMAP4rev1 UIDPLUS\r\n".to_vec()),
        Step::Reply {
            text: "OK CAPABILITY completed",
        },
        Step::Expect { verb: "LIST" },
        Step::Send(b"* LIST (\\HasNoChildren) \"/\" \"INBOX\"\r\n".to_vec()),
        Step::Reply {
            text: "OK LIST completed",
        },
    ])
    .await;

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
