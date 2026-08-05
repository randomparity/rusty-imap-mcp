//! A capability advertisement must not outlive the session it describes
//! (#652).
//!
//! The connect flow reads the post-login `CAPABILITY` reply and then, still
//! inside `connect_inner`, writes the connect's `auth` audit record. That write
//! can fail — a full disk, a read-only mount, an `audit.path` whose directory
//! was removed — and when it does on the *success* branch the whole connect is
//! reported as `ImapError::Audit`, so the freshly logged-in session is dropped
//! rather than cached. The slot stays empty.
//!
//! While the advertisement lived in an atomic *beside* the slot, the store had
//! already happened by then and nothing rolled it back: the connection went on
//! reporting `Known { .. }` for a session that never existed and that no
//! command could ever be served by. That is precisely the state #652 says must
//! be unrepresentable — an advertisement with no session behind it — and no
//! reset covered it, because `take_poisoned` only runs when something poisoned
//! the connection, and a failed connect does not.
//!
//! Carrying the pair *in* the slot removes the case rather than patching it:
//! there is no advertisement to leave behind, because the value was dropped
//! with the session it travelled with.
//!
//! Fake, no container runtime — runs on every PR.
#![expect(clippy::panic, reason = "test diagnostics")]

use std::sync::Arc;
use std::time::Duration;

use rimap_core::auth_event::AuthEvent;
use rimap_core::auth_sink::{AuthEventSink, AuthSinkError};
use rimap_fake_imap::fake_imap::{FakeImapServer, Step, login_preamble};
use rimap_imap::ServerCapabilities;
use rimap_imap::error::ImapError;

/// Generous command timeout so the loopback dialog cannot race a `Timeout`
/// (mirrors `capability_reconnect_freshness`).
const BACKSTOP: Duration = Duration::from_secs(5);

/// Rejects every `auth` record, the way the production `AuditWriter` does
/// under `fail_open = false` on a full disk. `connect_inner` propagates that
/// as `ImapError::Audit` from its success branch, which is the only way to
/// reach a connect that logged in and still returned `Err`.
#[derive(Debug)]
struct RejectingSink;

impl AuthEventSink for RejectingSink {
    fn emit_auth(&self, _event: AuthEvent) -> Result<(), AuthSinkError> {
        Err(AuthSinkError::new(
            rimap_core::ErrorCode::Internal,
            "sink rejects everything",
            Box::new(std::io::Error::other("disk full (test)")),
        ))
    }
}

/// A login that succeeds and advertises both extensions, followed by the
/// `LIST` the command would have issued had the connect been reported as a
/// success. The `LIST` steps are scripted but unreachable: the audit write
/// fails first, so a run that reaches them means the connect stopped failing
/// and the assertion below would be vacuous — the dialog check catches that.
fn login_then_list() -> Vec<Step> {
    let mut steps = login_preamble("IMAP4rev1 MOVE UIDPLUS");
    steps.extend([
        Step::Expect { verb: "LIST" },
        Step::Send(b"* LIST (\\HasNoChildren) \"/\" \"INBOX\"\r\n".to_vec()),
        Step::Reply {
            text: "OK LIST completed",
        },
    ]);
    steps
}

/// A connect that logged in, read `MOVE UIDPLUS`, and then failed on its own
/// audit write leaves no session in the slot — so it must leave no
/// advertisement either.
#[tokio::test]
async fn a_connect_that_failed_after_login_leaves_no_advertisement() {
    let server = FakeImapServer::start_sequence(vec![login_then_list()]).await;
    let conn = server.connection_with(
        "user@example.com",
        Arc::new(rimap_fake_imap::fake_imap::StaticResolver),
        Arc::new(RejectingSink),
        BACKSTOP,
    );

    let outcome = conn.list_folders("*").await;
    match outcome {
        Err(ImapError::Audit { op, .. }) => assert_eq!(op, "emit_auth"),
        other => panic!(
            "the rejecting sink must fail the connect on its success branch; \
             got {other:?}"
        ),
    }

    let dialog = server.recorded();
    assert!(
        !dialog.iter().any(|line| line.contains("LIST")),
        "the command must have been stopped by the audit failure, not served: \
         {dialog:?}",
    );

    assert_eq!(
        conn.capabilities().await,
        ServerCapabilities::Unknown,
        "the session this advertisement described was dropped by the failing \
         connect and never reached the slot; reporting `Known` for it is an \
         advertisement with no session behind it (#652)",
    );
}
