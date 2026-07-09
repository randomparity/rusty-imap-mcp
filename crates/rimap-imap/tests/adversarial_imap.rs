//! Adversarial IMAP scenarios driven against the in-process fake
//! (`support::fake_imap`). Scenario 1 (folder-wide EXPUNGE) lives in
//! `expunge_folder_wide_gap.rs`; scenarios 2–4 live here.
//!
//! Fake, no container runtime — runs on every PR.
//!
//! The `#![expect(...)]` list below must match exactly the clippy lints this
//! file's body triggers; later scenarios extend it as they add `.unwrap()` /
//! `panic!` constructs.
#![expect(clippy::expect_used, reason = "tests")]

mod support;

use support::fake_imap::{FakeImapServer, Step};

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
