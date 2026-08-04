//! `connect_inner` writes exactly one `auth` record per connect attempt, and
//! that record describes the attempt accurately (#623).
//!
//! The unit tests beside `connect_inner` cover the two *failure* shapes — a
//! connect cut mid-handshake, and one that reached its own verdict — because a
//! bare TCP listener is enough to produce both. Neither reaches a successful
//! LOGIN, so neither exercises the arm where the credential source is known:
//! `ConnectProgress::record_credential_source` is called between resolution and
//! the LOGIN round trip, and every other path leaves it unwritten. Deleting
//! that call leaves the unit tests green.
//!
//! This scenario closes that gap against the scriptable TLS fake: a real
//! greeting, a real CAPABILITY exchange, a real LOGIN, one `auth` Success
//! record naming the store the credential came from — and, the double-emit
//! half, exactly one.
//!
//! Fake, no container runtime — runs on every PR.
#![expect(clippy::expect_used, reason = "tests")]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use rimap_core::auth_event::{AuthEvent, AuthResult};
use rimap_core::auth_sink::{AuthEventSink, AuthSinkError};
use rimap_core::credential::CredentialSource;
use rimap_fake_imap::fake_imap::{FakeImapServer, StaticResolver, Step, login_preamble};

/// Records every emitted event so the test can count and inspect them.
#[derive(Debug, Default)]
struct RecordingSink {
    events: Mutex<Vec<AuthEvent>>,
}

impl RecordingSink {
    fn events(&self) -> Vec<AuthEvent> {
        self.events.lock().expect("recording sink mutex").clone()
    }
}

impl AuthEventSink for RecordingSink {
    fn emit_auth(&self, event: AuthEvent) -> Result<(), AuthSinkError> {
        self.events
            .lock()
            .expect("recording sink mutex")
            .push(event);
        Ok(())
    }
}

/// Log in, then serve one `LIST`, so the connect completes through a real
/// command rather than stopping at the greeting.
fn list_script() -> Vec<Step> {
    let mut steps = login_preamble("IMAP4rev1 UIDPLUS");
    steps.push(Step::Expect { verb: "LIST" });
    steps.push(Step::Send(
        b"* LIST (\\HasNoChildren) \".\" \"INBOX\"\r\n".to_vec(),
    ));
    steps.push(Step::Reply {
        text: "OK LIST completed",
    });
    steps
}

#[tokio::test]
async fn a_successful_connect_emits_one_auth_record_naming_the_credential_source() {
    let server = FakeImapServer::start(list_script()).await;
    let sink = Arc::new(RecordingSink::default());
    let conn = server.connection_with(
        "user@example.com",
        Arc::new(StaticResolver),
        Arc::clone(&sink) as Arc<dyn AuthEventSink>,
        Duration::from_secs(1),
    );

    let folders = conn
        .list_folders("*")
        .await
        .expect("the scripted LIST must succeed");
    assert_eq!(folders.len(), 1, "the fake serves exactly one folder");

    let events = sink.events();
    assert_eq!(
        events.len(),
        1,
        "one connect must leave one auth record — the drop guard added for \
         #623 must not add a second on the normal path: {events:?}",
    );
    let event = &events[0];
    assert_eq!(event.result, AuthResult::Success);
    assert_eq!(event.error_code, None, "a successful login carries no code");
    assert_eq!(
        event.credential_source,
        Some(CredentialSource::Keyring),
        "the record must name the store the credential came from; the fake's \
         resolver reports Keyring",
    );
    assert!(
        event.tls_fingerprint_sha256.is_some(),
        "the handshake reached certificate verification, so the observed \
         fingerprint must be recorded",
    );
    assert_eq!(
        event.fingerprint_match,
        Some(true),
        "the connection pins the fake's own certificate",
    );
    assert_eq!(event.username, "user@example.com");
}
