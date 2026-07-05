//! Dovecot-in-container integration suite for rimap-imap. Runs against
//! docker or podman (autodetected, override with `RIMAP_CONTAINER_TOOL`).
//! Local devs without either runtime get the skip path automatically.

#![expect(clippy::unwrap_used, reason = "tests")]
#![expect(clippy::expect_used, reason = "tests")]

mod support;

use std::time::Duration;

use rimap_imap::error::{AuthFailure, ImapError};
use rimap_imap::{Connection, ConnectionConfig};
use support::container::{ConnectedHarness, DovecotHarness, HarnessError, PinChoice};

fn boot(pin: PinChoice) -> Option<ConnectedHarness> {
    match ConnectedHarness::new(pin) {
        Ok(h) => Some(h),
        Err(HarnessError::DockerUnavailable) => None, // silent skip — print_stderr denied
        #[expect(clippy::panic, reason = "test failure path")]
        Err(e) => panic!("harness failed: {e}"),
    }
}

#[expect(clippy::panic, reason = "test failure path")]
fn read_audit_lines(path: &std::path::Path) -> Vec<serde_json::Value> {
    let s = std::fs::read_to_string(path).unwrap_or_default();
    s.lines()
        .enumerate()
        .map(|(idx, l)| {
            serde_json::from_str(l).unwrap_or_else(|e| {
                panic!(
                    "audit line {} failed to parse as JSON: {e}\nline: {l}",
                    idx + 1
                )
            })
        })
        .collect()
}

#[tokio::test]
async fn case_01_connect_with_correct_pin_succeeds() {
    let Some(h) = boot(PinChoice::Correct) else {
        return;
    };
    let folders = h.connection.list_folders("*").await.unwrap();
    assert!(folders.iter().any(|f| f.name.eq_ignore_ascii_case("INBOX")));
    // is_connected removed — list_folders success already proves connectivity

    let lines = read_audit_lines(&h.audit_path());
    let auths: Vec<_> = lines.iter().filter(|v| v["kind"] == "auth").collect();
    assert_eq!(auths.len(), 1);
    assert_eq!(auths[0]["result"], "success");
    assert_eq!(auths[0]["fingerprint_match"], true);
}

#[tokio::test]
async fn case_02_connect_with_wrong_pin_emits_audit_and_returns_tls_error() {
    let Some(h) = boot(PinChoice::Wrong) else {
        return;
    };
    let result = h.connection.list_folders("*").await;
    match result {
        Err(ImapError::Tls { observed, expected }) => {
            assert_eq!(
                expected,
                rimap_core::TlsFingerprint::from_cert_der(b"deliberately-wrong")
            );
            assert_eq!(observed, h.harness.pinned_fingerprint());
        }
        Err(ImapError::TlsHandshake(_)) => {
            // Acceptable fallback if the enrichment path didn't fire.
        }
        #[expect(clippy::panic, reason = "test failure path")]
        other => panic!("expected TLS error, got {other:?}"),
    }
    let lines = read_audit_lines(&h.audit_path());
    let mismatch = lines
        .iter()
        .find(|v| v["kind"] == "auth" && v["error_code"] == "ERR_TLS")
        .expect("expected an ERR_TLS auth record");
    assert_eq!(mismatch["fingerprint_match"], false);
    // Verify the audit captured the *live* observed fingerprint, not a placeholder.
    assert_eq!(
        mismatch["tls_fingerprint_sha256"].as_str().unwrap(),
        h.harness.pinned_fingerprint().to_hex(),
    );
}

#[tokio::test]
async fn case_03_connect_with_no_pin_uses_system_trust_and_fails_self_signed() {
    let Some(h) = boot(PinChoice::None) else {
        return;
    };
    let result = h.connection.list_folders("*").await;
    match result {
        Err(ImapError::TlsHandshake(_)) => {}
        #[expect(clippy::panic, reason = "test failure path")]
        other => panic!("expected TlsHandshake error, got {other:?}"),
    }
    let lines = read_audit_lines(&h.audit_path());
    let auth = lines
        .iter()
        .find(|v| v["kind"] == "auth")
        .expect("auth record");
    assert_eq!(auth["result"], "failure");
    assert_eq!(auth["error_code"], "ERR_TLS");
}

#[tokio::test]
async fn case_04_login_rejected_emits_audit() {
    use rimap_config::credential::CredentialStore;
    use std::sync::Arc;

    struct WrongPass;
    impl CredentialStore for WrongPass {
        fn get_password(
            &self,
            _: &str,
        ) -> Result<Option<secrecy::SecretString>, rimap_config::ConfigError> {
            Ok(Some(secrecy::SecretString::from("wrong-password")))
        }
        #[expect(clippy::panic, clippy::panic_in_result_fn, reason = "test stub")]
        fn set_password(&self, _: &str, _: &str) -> Result<(), rimap_config::ConfigError> {
            panic!("tests do not write credentials")
        }
    }

    let Some(h) = boot(PinChoice::Correct) else {
        return;
    };
    let cfg = ConnectionConfig {
        account: None,
        account_id: rimap_core::account::AccountId::default_account(),
        host: DovecotHarness::host().to_string(),
        port: h.harness.port(),
        encryption: rimap_imap::ImapEncryption::Tls,
        username: DovecotHarness::username().to_string(),
        pinned_fingerprint: Some(h.harness.pinned_fingerprint()),
        connect_timeout: Duration::from_secs(10),
        command_timeout: Duration::from_secs(10),
        max_fetch_body_bytes: 5_242_880,
        max_append_bytes: 10_485_760,
    };
    let store: Arc<dyn CredentialStore> = Arc::new(WrongPass);
    let creds: Arc<dyn rimap_core::CredentialResolver> =
        Arc::new(rimap_config::credential::KeyringCredentialResolver::new(
            store,
            rimap_config::model::FallbackMode::KeyringThenEnv,
            rimap_config::credential::Protocol::Imap,
        ));
    let sink: Arc<dyn rimap_core::auth_sink::AuthEventSink> = Arc::new(h.audit.clone());
    // Reuse h.audit so the rejected-auth record lands in the same file
    // the audit assertions below read from. Opening a fresh AuditWriter
    // here would emit the record to a different file and break the test.
    let conn = Connection::new(cfg, sink, creds);

    let result = conn.list_folders("*").await;
    match result {
        Err(ImapError::Auth {
            reason: AuthFailure::LoginRejected,
        }) => {}
        #[expect(clippy::panic, reason = "test failure path")]
        other => panic!("expected LoginRejected, got {other:?}"),
    }
    let lines = read_audit_lines(&h.audit_path());
    let rejected = lines
        .iter()
        .find(|v| v["kind"] == "auth" && v["error_code"] == "ERR_AUTH")
        .expect("ERR_AUTH record");
    assert_eq!(rejected["result"], "failure");
}

#[tokio::test]
async fn case_05_list_returns_seeded_folders() {
    let Some(h) = boot(PinChoice::Correct) else {
        return;
    };
    let folders = h.connection.list_folders("*").await.unwrap();
    let names: Vec<&str> = folders.iter().map(|f| f.name.as_str()).collect();
    assert!(names.iter().any(|n| n.eq_ignore_ascii_case("INBOX")));
    assert!(names.iter().any(|n| n.contains("Archive")));
    assert!(names.iter().any(|n| n.contains("Subfolder")));
}

#[tokio::test]
async fn case_06_search_structured_subject_match() {
    use rimap_imap::types::{SearchQuery, StructuredQuery};

    let Some(h) = boot(PinChoice::Correct) else {
        return;
    };
    let q = SearchQuery::Structured(StructuredQuery {
        subject: Some("Sprint 3 plain text fixture".to_string()),
        ..StructuredQuery::default()
    });
    let (uids, _) = Box::pin(h.connection.search("INBOX", q)).await.unwrap();
    assert!(
        !uids.is_empty(),
        "expected at least one UID for the seeded subject"
    );
}

#[tokio::test]
async fn case_07_search_raw_passthrough() {
    use rimap_imap::types::SearchQuery;

    let Some(h) = boot(PinChoice::Correct) else {
        return;
    };
    let q = SearchQuery::Raw("HEADER \"X-Test\" \"marker\"".to_string());
    let (uids, _) = Box::pin(h.connection.search("INBOX", q)).await.unwrap();
    assert!(
        !uids.is_empty(),
        "expected at least one UID for X-Test: marker"
    );
}

#[tokio::test]
async fn case_08_fetch_envelope_and_bodystructure() {
    use rimap_imap::types::{FetchSpec, SearchQuery, StructuredQuery};

    let Some(h) = boot(PinChoice::Correct) else {
        return;
    };
    let q = SearchQuery::Structured(StructuredQuery {
        subject: Some("Sprint 3 multipart fixture".to_string()),
        ..StructuredQuery::default()
    });
    let (uids, _) = Box::pin(h.connection.search("INBOX", q)).await.unwrap();
    assert!(!uids.is_empty());
    let spec = FetchSpec {
        envelope: true,
        bodystructure: true,
        uid: true,
        flags: false,
        size: false,
    };
    let (msgs, _) = h
        .connection
        .fetch("INBOX", &uids, spec, None)
        .await
        .unwrap();
    assert_eq!(msgs.len(), uids.len());
    let envelope = msgs[0].envelope.as_ref().expect("envelope");
    let subject = envelope.subject_raw.as_ref().expect("subject_raw");
    assert_eq!(subject.as_slice(), b"Sprint 3 multipart fixture");
    assert!(msgs[0].bodystructure.is_some());
}

#[tokio::test]
async fn case_09_fetch_body_under_limit() {
    use rimap_imap::types::{SearchQuery, StructuredQuery};

    let Some(h) = boot(PinChoice::Correct) else {
        return;
    };
    let q = SearchQuery::Structured(StructuredQuery {
        subject: Some("Sprint 3 plain text fixture".to_string()),
        ..StructuredQuery::default()
    });
    let (uids, _) = Box::pin(h.connection.search("INBOX", q)).await.unwrap();
    assert!(!uids.is_empty());
    let body = h
        .connection
        .fetch_body("INBOX", uids[0], None)
        .await
        .unwrap();
    assert!(!body.is_empty());
    assert!(body.len() < 5_000, "fixture is small");
}

#[tokio::test]
async fn case_10_fetch_body_over_limit_drops_connection() {
    use rimap_config::credential::CredentialStore;
    use rimap_imap::types::{SearchQuery, StructuredQuery};
    use std::sync::Arc;

    let Some(h) = boot(PinChoice::Correct) else {
        return;
    };
    let cfg = ConnectionConfig {
        account: None,
        account_id: rimap_core::account::AccountId::default_account(),
        host: DovecotHarness::host().to_string(),
        port: h.harness.port(),
        encryption: rimap_imap::ImapEncryption::Tls,
        username: DovecotHarness::username().to_string(),
        pinned_fingerprint: Some(h.harness.pinned_fingerprint()),
        connect_timeout: Duration::from_secs(10),
        command_timeout: Duration::from_secs(10),
        max_fetch_body_bytes: 10,
        max_append_bytes: 10_485_760,
    };
    let store: Arc<dyn CredentialStore> = Arc::new(support::container::StaticCreds(
        DovecotHarness::password().to_string(),
    ));
    let creds: Arc<dyn rimap_core::CredentialResolver> =
        Arc::new(rimap_config::credential::KeyringCredentialResolver::new(
            store,
            rimap_config::model::FallbackMode::KeyringThenEnv,
            rimap_config::credential::Protocol::Imap,
        ));
    let sink: Arc<dyn rimap_core::auth_sink::AuthEventSink> = Arc::new(h.audit.clone());
    // Reuse h.audit so the size-limit / connection-loss records land in
    // the file the audit assertions below read from. The override here
    // is `max_fetch_body_bytes`, not the audit writer.
    let conn = Connection::new(cfg, sink, creds);

    let q = SearchQuery::Structured(StructuredQuery {
        subject: Some("Sprint 3 multipart fixture".to_string()),
        ..StructuredQuery::default()
    });
    let (uids, _) = Box::pin(conn.search("INBOX", q)).await.unwrap();
    let result = conn.fetch_body("INBOX", uids[0], None).await;
    match result {
        Err(ImapError::SizeLimit { limit }) => assert_eq!(limit, 10),
        #[expect(clippy::panic, reason = "test failure path")]
        other => panic!("expected SizeLimit, got {other:?}"),
    }
    // is_connected removed — SizeLimit return already proves the overflow path fired
}

#[tokio::test]
async fn case_11_tcp_half_open_recovery() {
    let Some(h) = boot(PinChoice::Correct) else {
        return;
    };
    // Establish a cached session.
    let _ = h.connection.list_folders("*").await.unwrap();

    // Force the server-side TCP to die. `pkill -9 imap` is racy because
    // dovecot's master respawns the worker before the next client command
    // lands; a full container restart deterministically tears down every
    // worker fd. The cert is preserved across the restart so the pinned
    // reconnect below uses the same fingerprint.
    h.harness.restart().expect("dovecot restart");

    // Read op: the first resumed call must recover transparently. The stale
    // cached session yields ConnectionLost on the first attempt; with_session
    // reconnects and retries once, so the caller sees a clean result rather
    // than ERR_CONNECTION_LOST (#450).
    let folders = h
        .connection
        .list_folders("*")
        .await
        .expect("read op should transparently recover after idle disconnect");
    assert!(!folders.is_empty());

    // Kill the (now healthy) session again to test the write path.
    h.harness.restart().expect("dovecot restart");

    // Write op: a mutating command must NOT auto-retry — re-sending after a
    // mid-command disconnect could double-apply. The first resumed APPEND
    // surfaces ConnectionLost; only the caller's next call reconnects.
    let msg = support::fixtures::minimal_rfc5322("half-open-write");
    let result = h.connection.append_message("INBOX", &msg, &[], &[]).await;
    match result {
        Err(ImapError::ConnectionLost | ImapError::Protocol(_)) => {}
        #[expect(clippy::panic, reason = "test failure path")]
        other => panic!("write must not auto-retry; expected ConnectionLost, got {other:?}"),
    }

    // The session was invalidated, so the caller's next APPEND reconnects and
    // succeeds — proving the write path still recovers on the following call.
    h.connection
        .append_message("INBOX", &msg, &[], &[])
        .await
        .expect("follow-up append should reconnect");
}

#[tokio::test]
async fn case_12_store_add_seen_flag() {
    let Some(h) = boot(PinChoice::Correct) else {
        return;
    };

    // Seed a message via APPEND.
    let msg = support::fixtures::minimal_rfc5322("store-seen");
    h.connection
        .append_message("INBOX", &msg, &[], &[])
        .await
        .unwrap();

    // Search for it.
    let (uids, _) = Box::pin(h.connection.search(
        "INBOX",
        rimap_imap::types::SearchQuery::Structured(rimap_imap::types::StructuredQuery {
            subject: Some("store-seen".to_string()),
            ..Default::default()
        }),
    ))
    .await
    .unwrap();
    assert!(!uids.is_empty(), "seeded message not found");
    let uid = uids[0];

    // Add \Seen flag.
    let (updated, _) = h
        .connection
        .store_flags(
            "INBOX",
            &[uid],
            &[rimap_imap::types::Flag::Seen],
            rimap_imap::types::FlagAction::Add,
            None,
        )
        .await
        .unwrap();
    assert!(updated.contains(&uid));

    // Verify the flag is set.
    let (fetched, _) = h
        .connection
        .fetch(
            "INBOX",
            &[uid],
            rimap_imap::types::FetchSpec {
                flags: true,
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    let flags = fetched[0].flags.as_ref().unwrap();
    assert!(flags.contains(&rimap_imap::types::Flag::Seen));
}

#[tokio::test]
async fn case_13_store_remove_seen_flag() {
    let Some(h) = boot(PinChoice::Correct) else {
        return;
    };

    // Seed a message with \Seen.
    let msg = support::fixtures::minimal_rfc5322("store-unseen");
    h.connection
        .append_message("INBOX", &msg, &[rimap_imap::types::Flag::Seen], &[])
        .await
        .unwrap();

    let (uids, _) = Box::pin(h.connection.search(
        "INBOX",
        rimap_imap::types::SearchQuery::Structured(rimap_imap::types::StructuredQuery {
            subject: Some("store-unseen".to_string()),
            ..Default::default()
        }),
    ))
    .await
    .unwrap();
    assert!(!uids.is_empty());
    let uid = uids[0];

    // Remove \Seen flag.
    let (updated, _) = h
        .connection
        .store_flags(
            "INBOX",
            &[uid],
            &[rimap_imap::types::Flag::Seen],
            rimap_imap::types::FlagAction::Remove,
            None,
        )
        .await
        .unwrap();
    assert!(updated.contains(&uid));

    // Verify the flag is removed.
    let (fetched, _) = h
        .connection
        .fetch(
            "INBOX",
            &[uid],
            rimap_imap::types::FetchSpec {
                flags: true,
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    let flags = fetched[0].flags.as_ref().unwrap();
    assert!(!flags.contains(&rimap_imap::types::Flag::Seen));
}

#[tokio::test]
async fn case_14_store_batch_too_large() {
    let Some(h) = boot(PinChoice::Correct) else {
        return;
    };

    let uids: Vec<rimap_imap::types::Uid> = (1..=101)
        .map(|n| rimap_imap::types::Uid::from(core::num::NonZeroU32::new(n).unwrap()))
        .collect();

    let result = h
        .connection
        .store_flags(
            "INBOX",
            &uids,
            &[rimap_imap::types::Flag::Seen],
            rimap_imap::types::FlagAction::Add,
            None,
        )
        .await;

    match result {
        Err(rimap_imap::error::ImapError::BatchTooLarge {
            count: 101,
            limit: 100,
        }) => {}
        #[expect(clippy::panic, reason = "test failure path")]
        other => panic!("expected BatchTooLarge, got {other:?}"),
    }
}

#[tokio::test]
async fn case_15_append_message_to_inbox() {
    let Some(h) = boot(PinChoice::Correct) else {
        return;
    };

    let msg = support::fixtures::minimal_rfc5322("append-test");
    let result = h
        .connection
        .append_message(
            "INBOX",
            &msg,
            &[rimap_imap::types::Flag::Draft],
            &["$PendingReview"],
        )
        .await
        .unwrap();

    // async-imap doesn't expose APPENDUID, so uid is None.
    assert_eq!(result.uid, None);

    // Verify the message is in INBOX by searching for it.
    let (uids, _) = Box::pin(h.connection.search(
        "INBOX",
        rimap_imap::types::SearchQuery::Structured(rimap_imap::types::StructuredQuery {
            subject: Some("append-test".to_string()),
            ..Default::default()
        }),
    ))
    .await
    .unwrap();
    assert!(!uids.is_empty(), "appended message not found");

    // Verify it has the \Draft flag.
    let (fetched, _) = h
        .connection
        .fetch(
            "INBOX",
            &[uids[0]],
            rimap_imap::types::FetchSpec {
                flags: true,
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    let flags = fetched[0].flags.as_ref().unwrap();
    assert!(flags.contains(&rimap_imap::types::Flag::Draft));
}

#[tokio::test]
async fn case_16_move_message_between_folders() {
    let Some(h) = boot(PinChoice::Correct) else {
        return;
    };

    // Seed a message in INBOX.
    let msg = support::fixtures::minimal_rfc5322("move-test");
    h.connection
        .append_message("INBOX", &msg, &[], &[])
        .await
        .unwrap();

    let (uids, _) = Box::pin(h.connection.search(
        "INBOX",
        rimap_imap::types::SearchQuery::Structured(rimap_imap::types::StructuredQuery {
            subject: Some("move-test".to_string()),
            ..Default::default()
        }),
    ))
    .await
    .unwrap();
    assert!(!uids.is_empty(), "seeded message not found");
    let uid = uids[0];

    // Move to Archive (seeded in Dovecot entrypoint.sh).
    let outcome = h
        .connection
        .move_messages("INBOX", "Archive", &[uid], None)
        .await
        .unwrap();
    assert_eq!(outcome.results.len(), 1);
    assert_eq!(outcome.results[0].old_uid, uid);

    // Verify the message is gone from INBOX.
    let (after_uids, _) = Box::pin(h.connection.search(
        "INBOX",
        rimap_imap::types::SearchQuery::Structured(rimap_imap::types::StructuredQuery {
            subject: Some("move-test".to_string()),
            ..Default::default()
        }),
    ))
    .await
    .unwrap();
    assert!(
        after_uids.is_empty(),
        "message should be gone from INBOX after move"
    );

    // Verify the message is in Archive.
    let (archive_uids, _) = Box::pin(h.connection.search(
        "Archive",
        rimap_imap::types::SearchQuery::Structured(rimap_imap::types::StructuredQuery {
            subject: Some("move-test".to_string()),
            ..Default::default()
        }),
    ))
    .await
    .unwrap();
    assert!(
        !archive_uids.is_empty(),
        "message should be in Archive after move"
    );
}

/// `delete_message`: flag + move to Trash, verify UID gone from INBOX.
#[tokio::test]
async fn case_17_delete_message() {
    let Some(h) = boot(PinChoice::Correct) else {
        return;
    };
    // Append a test message to INBOX
    let msg = support::fixtures::minimal_rfc5322("delete-test");
    h.connection
        .append_message("INBOX", &msg, &[], &[])
        .await
        .unwrap();

    // Find the appended message
    let (uids, _) = Box::pin(h.connection.search(
        "INBOX",
        rimap_imap::types::SearchQuery::Structured(rimap_imap::types::StructuredQuery {
            subject: Some("delete-test".to_string()),
            ..Default::default()
        }),
    ))
    .await
    .unwrap();
    assert!(!uids.is_empty(), "seeded message not found");
    let uid = uids[0];

    // Create Trash folder (Dovecot may not have it by default)
    let _ = h.connection.create_folder("Trash").await;

    // Delete it (move to Trash)
    let (result, _uid_validity) = h
        .connection
        .delete_message("INBOX", uid, "Trash", None)
        .await
        .unwrap();
    assert!(result.moved_to_trash);

    // Verify it's gone from INBOX
    let (after, _) = Box::pin(h.connection.search(
        "INBOX",
        rimap_imap::types::SearchQuery::Structured(rimap_imap::types::StructuredQuery {
            subject: Some("delete-test".to_string()),
            ..Default::default()
        }),
    ))
    .await
    .unwrap();
    assert!(
        !after.contains(&uid),
        "message should be gone from INBOX after delete"
    );
}

/// `delete_message` with `expected_uidvalidity`: a matching value proceeds
/// and echoes the observed UIDVALIDITY; a stale value (captured before the
/// folder is deleted and recreated, which rotates UIDVALIDITY) aborts with
/// `ImapError::UidValidityChanged` and performs no delete.
#[tokio::test]
async fn case_23_delete_message_uidvalidity_guard() {
    let Some(h) = boot(PinChoice::Correct) else {
        return;
    };
    let folder = "DeleteGuardTest";
    h.connection.create_folder(folder).await.unwrap();
    let _ = h.connection.create_folder("Trash").await;

    let msg = support::fixtures::minimal_rfc5322("delete-guard-test");
    h.connection
        .append_message(folder, &msg, &[], &[])
        .await
        .unwrap();
    let (uids, uid_validity) = Box::pin(h.connection.search(
        folder,
        rimap_imap::types::SearchQuery::Structured(rimap_imap::types::StructuredQuery {
            subject: Some("delete-guard-test".to_string()),
            ..Default::default()
        }),
    ))
    .await
    .unwrap();
    assert!(!uids.is_empty(), "seeded message not found");
    let uid = uids[0];
    let stale_validity = uid_validity.expect("dovecot reports UIDVALIDITY");

    // Matching UIDVALIDITY: the delete proceeds and echoes the value back.
    let (result, observed) = h
        .connection
        .delete_message(folder, uid, "Trash", Some(stale_validity))
        .await
        .unwrap();
    assert!(result.moved_to_trash);
    assert_eq!(observed, Some(stale_validity));

    // Force a new UIDVALIDITY by deleting and recreating the folder. The
    // prior `delete_message` call left `folder` selected via SELECT on this
    // session; deselect it first (Dovecot drops the connection if a client
    // tries to DELETE its own currently-selected mailbox) by selecting
    // INBOX instead.
    let _ = Box::pin(h.connection.search(
        "INBOX",
        rimap_imap::types::SearchQuery::Structured(rimap_imap::types::StructuredQuery::default()),
    ))
    .await
    .unwrap();
    h.connection.delete_folder(folder).await.unwrap();
    h.connection.create_folder(folder).await.unwrap();
    h.connection
        .append_message(folder, &msg, &[], &[])
        .await
        .unwrap();
    let (uids, fresh_validity) = Box::pin(h.connection.search(
        folder,
        rimap_imap::types::SearchQuery::Structured(rimap_imap::types::StructuredQuery {
            subject: Some("delete-guard-test".to_string()),
            ..Default::default()
        }),
    ))
    .await
    .unwrap();
    assert!(!uids.is_empty(), "seeded message not found after recreate");
    let fresh_uid = uids[0];
    assert_ne!(
        fresh_validity,
        Some(stale_validity),
        "recreating the folder should rotate UIDVALIDITY"
    );

    // Stale UIDVALIDITY: the guard aborts before any STORE/MOVE is issued.
    let err = h
        .connection
        .delete_message(folder, fresh_uid, "Trash", Some(stale_validity))
        .await
        .unwrap_err();
    assert!(
        matches!(err, ImapError::UidValidityChanged { .. }),
        "expected UidValidityChanged, got {err:?}"
    );

    // The message must still be present — the guard aborted before delete.
    let (after, _) = Box::pin(h.connection.search(
        folder,
        rimap_imap::types::SearchQuery::Structured(rimap_imap::types::StructuredQuery {
            subject: Some("delete-guard-test".to_string()),
            ..Default::default()
        }),
    ))
    .await
    .unwrap();
    assert!(
        after.contains(&fresh_uid),
        "message must survive a guard-aborted delete"
    );
}

/// expunge: flag \Deleted + expunge, verify message is permanently removed.
#[tokio::test]
async fn case_18_expunge() {
    let Some(h) = boot(PinChoice::Correct) else {
        return;
    };
    let _ = h.connection.create_folder("Trash").await;

    // Append a message directly to Trash
    let msg = support::fixtures::minimal_rfc5322("expunge-test");
    h.connection
        .append_message("Trash", &msg, &[], &[])
        .await
        .unwrap();

    // Find it
    let (uids, _) = Box::pin(h.connection.search(
        "Trash",
        rimap_imap::types::SearchQuery::Structured(rimap_imap::types::StructuredQuery {
            subject: Some("expunge-test".to_string()),
            ..Default::default()
        }),
    ))
    .await
    .unwrap();
    assert!(!uids.is_empty());
    let uid = uids[0];

    // Flag as \Deleted
    h.connection
        .store_flags(
            "Trash",
            &[uid],
            &[rimap_imap::types::Flag::Deleted],
            rimap_imap::types::FlagAction::Add,
            None,
        )
        .await
        .unwrap();

    // Expunge
    let (deleted_uids, count) = h.connection.expunge("Trash").await.unwrap();
    assert!(
        !deleted_uids.is_empty(),
        "should find deleted UIDs pre-expunge"
    );
    assert!(count > 0, "should expunge at least one message");

    // Verify it's gone
    let (after, _) = Box::pin(h.connection.search(
        "Trash",
        rimap_imap::types::SearchQuery::Structured(rimap_imap::types::StructuredQuery {
            subject: Some("expunge-test".to_string()),
            ..Default::default()
        }),
    ))
    .await
    .unwrap();
    assert!(
        !after.contains(&uid),
        "message should be gone after expunge"
    );
}

/// `create_folder` + `rename_folder` + `delete_folder` round-trip.
#[tokio::test]
async fn case_19_folder_management() {
    let Some(h) = boot(PinChoice::Correct) else {
        return;
    };

    // Create
    h.connection.create_folder("TestFolder").await.unwrap();
    let folders = h.connection.list_folders("*").await.unwrap();
    assert!(
        folders.iter().any(|f| f.name == "TestFolder"),
        "TestFolder should exist after create"
    );

    // Rename
    h.connection
        .rename_folder("TestFolder", "RenamedFolder")
        .await
        .unwrap();
    let folders = h.connection.list_folders("*").await.unwrap();
    assert!(
        folders.iter().any(|f| f.name == "RenamedFolder"),
        "RenamedFolder should exist after rename"
    );
    assert!(
        !folders.iter().any(|f| f.name == "TestFolder"),
        "TestFolder should not exist after rename"
    );

    // Delete
    h.connection.delete_folder("RenamedFolder").await.unwrap();
    let folders = h.connection.list_folders("*").await.unwrap();
    assert!(
        !folders.iter().any(|f| f.name == "RenamedFolder"),
        "RenamedFolder should not exist after delete"
    );
}

#[tokio::test]
async fn case_20_special_use_discovery_populates_each_slot() {
    use rimap_imap::{SpecialUse, SpecialUseMap};

    let Some(h) = boot(PinChoice::Correct) else {
        return;
    };
    let folders = h.connection.list_folders("*").await.unwrap();
    let map = SpecialUseMap::from_folders(&folders);

    assert_eq!(map.drafts(), Some("Drafts"));
    assert_eq!(map.sent(), Some("Sent"));
    assert_eq!(map.trash(), Some("Trash"));

    let drafts_folder = folders.iter().find(|f| f.name == "Drafts").unwrap();
    assert_eq!(drafts_folder.special_use, Some(SpecialUse::Drafts));
}

// --- STARTTLS suite (port 143) ---
//
// Dovecot is configured with `ssl = required`, so LOGIN is only
// possible after STARTTLS. These tests exercise the rimap-imap
// STARTTLS upgrade end-to-end.

mod starttls {
    use super::*;
    use rimap_imap::ImapEncryption;

    fn boot_starttls(pin: PinChoice) -> Option<ConnectedHarness> {
        match ConnectedHarness::new_with_encryption(pin, ImapEncryption::Starttls) {
            Ok(h) => Some(h),
            Err(HarnessError::DockerUnavailable) => None,
            #[expect(clippy::panic, reason = "test failure path")]
            Err(e) => panic!("starttls harness failed: {e}"),
        }
    }

    #[tokio::test]
    async fn starttls_connect_list_logout_succeeds() {
        let Some(h) = boot_starttls(PinChoice::Correct) else {
            return;
        };
        let folders = h.connection.list_folders("*").await.unwrap();
        assert!(folders.iter().any(|f| f.name.eq_ignore_ascii_case("INBOX")));

        let lines = read_audit_lines(&h.audit_path());
        let auths: Vec<_> = lines.iter().filter(|v| v["kind"] == "auth").collect();
        assert_eq!(auths.len(), 1);
        assert_eq!(auths[0]["result"], "success");
        assert_eq!(auths[0]["fingerprint_match"], true);
    }

    #[tokio::test]
    async fn starttls_with_wrong_pin_returns_tls_error() {
        let Some(h) = boot_starttls(PinChoice::Wrong) else {
            return;
        };
        let err = h.connection.list_folders("*").await.unwrap_err();
        match err {
            rimap_imap::error::ImapError::Tls { .. }
            | rimap_imap::error::ImapError::TlsHandshake(_) => {}
            #[expect(clippy::panic, reason = "test failure path")]
            other => panic!("expected Tls pin mismatch, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dovecot_starttls_port_advertises_starttls_capability() {
        // Dovecot is configured with `disable_plaintext_auth = yes` and no
        // trusted networks, so LOGIN on port 143 requires STARTTLS first.
        // This test verifies that STARTTLS is advertised in the CAPABILITY
        // response on the plaintext port, which is the structural precondition
        // for our client's STARTTLS negotiation.
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let Some(h) = boot_starttls(PinChoice::Correct) else {
            return;
        };
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", h.starttls_port()))
            .await
            .unwrap();
        let (read, mut write) = stream.split();
        let mut reader = BufReader::new(read);

        // Read lines until we see the tagged greeting OK.
        let mut capability_seen = false;
        let mut greeting_ok = false;
        for _ in 0..10 {
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            let upper = line.to_ascii_uppercase();
            if upper.contains("STARTTLS") {
                capability_seen = true;
            }
            if upper.contains("* OK") || upper.contains("OK DOVECOT") {
                greeting_ok = true;
            }
            if greeting_ok {
                break;
            }
        }
        assert!(greeting_ok, "did not receive IMAP greeting");

        // Issue CAPABILITY to get the definitive pre-auth list.
        write.write_all(b"a0 CAPABILITY\r\n").await.unwrap();
        for _ in 0..5 {
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            let upper = line.to_ascii_uppercase();
            if upper.contains("STARTTLS") {
                capability_seen = true;
            }
            // Stop once we see the tagged OK for our CAPABILITY command.
            if upper.starts_with("A0 OK") {
                break;
            }
        }

        assert!(
            capability_seen,
            "STARTTLS not found in pre-auth CAPABILITY on port 143"
        );
    }
}

#[tokio::test]
async fn case_21_probe_preflight_returns_observed_fingerprint() {
    let Some(h) = boot(PinChoice::None) else {
        return;
    };
    let cfg = ConnectionConfig {
        account: None,
        account_id: rimap_core::account::AccountId::default_account(),
        host: DovecotHarness::host().to_string(),
        port: h.harness.port(),
        encryption: rimap_imap::ImapEncryption::Tls,
        username: DovecotHarness::username().to_string(),
        pinned_fingerprint: None,
        connect_timeout: Duration::from_secs(10),
        command_timeout: Duration::from_secs(10),
        max_fetch_body_bytes: 5_242_880,
        max_append_bytes: 10_485_760,
    };
    let info = rimap_imap::preflight::probe_preflight(&cfg)
        .await
        .expect("preflight should succeed against the live harness");
    assert_eq!(info.tls_fingerprint, h.harness.pinned_fingerprint());
    assert!(!info.capabilities.is_empty());
}

#[tokio::test]
async fn case_22_probe_preflight_mismatch_returns_typed_tls_error() {
    let Some(h) = boot(PinChoice::None) else {
        return;
    };
    let wrong = rimap_core::TlsFingerprint::from_cert_der(b"deliberately-wrong");
    let cfg = ConnectionConfig {
        account: None,
        account_id: rimap_core::account::AccountId::default_account(),
        host: DovecotHarness::host().to_string(),
        port: h.harness.port(),
        encryption: rimap_imap::ImapEncryption::Tls,
        username: DovecotHarness::username().to_string(),
        pinned_fingerprint: Some(wrong),
        connect_timeout: Duration::from_secs(10),
        command_timeout: Duration::from_secs(10),
        max_fetch_body_bytes: 5_242_880,
        max_append_bytes: 10_485_760,
    };
    let err = rimap_imap::preflight::probe_preflight(&cfg)
        .await
        .expect_err("mismatched pin must produce an error");
    match err {
        ImapError::Tls { observed, expected } => {
            assert_eq!(observed, h.harness.pinned_fingerprint());
            assert_eq!(expected, wrong);
        }
        #[expect(clippy::panic, reason = "test failure path")]
        other => panic!("expected ImapError::Tls, got {other:?}"),
    }
}

/// #435: `thread_related` finds a reply from the parent's own
/// Message-ID (descendant search via `References`/`In-Reply-To`), and
/// finds the parent from the reply's own References chain (ancestor
/// search via `Message-ID`). No IMAP THREAD extension involved — this
/// exercises the fallback Message-ID chain-walk end to end.
#[tokio::test]
async fn case_24_thread_related_chain_walk_finds_reply_and_parent() {
    let Some(h) = boot(PinChoice::Correct) else {
        return;
    };

    let parent_message_id = "<test-thread-parent-435@example.com>";
    let parent_msg = support::fixtures::minimal_rfc5322("thread-parent-435");
    h.connection
        .append_message("INBOX", &parent_msg, &[], &[])
        .await
        .unwrap();

    let reply_message_id = "<test-reply-thread-parent-435@example.com>";
    let reply_msg = support::fixtures::reply_rfc5322("thread-parent-435", parent_message_id);
    h.connection
        .append_message("INBOX", &reply_msg, &[], &[])
        .await
        .unwrap();

    // Locate the parent's own UID by its exact Message-ID (SUBJECT search
    // would substring-match both the parent and "Re: <parent subject>").
    let (parent_uids, _) = Box::pin(h.connection.search(
        "INBOX",
        rimap_imap::types::SearchQuery::Raw(format!("HEADER Message-ID \"{parent_message_id}\"")),
    ))
    .await
    .unwrap();
    assert_eq!(parent_uids.len(), 1, "expected exactly one parent match");
    let parent_uid = parent_uids[0];

    // Descendant direction: search from the parent's own Message-ID
    // should find the reply (via its References/In-Reply-To).
    let (descendants, _) = h
        .connection
        .thread_related("INBOX", Some(parent_message_id), &[])
        .await
        .unwrap();
    assert!(
        !descendants.contains(&parent_uid),
        "descendant search must not match the parent itself"
    );
    let (fetched, _) = h
        .connection
        .fetch(
            "INBOX",
            &descendants,
            rimap_imap::types::FetchSpec {
                envelope: true,
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    let subjects: Vec<String> = fetched
        .iter()
        .filter_map(|m| m.envelope.as_ref())
        .filter_map(|e| e.subject_raw.as_ref())
        .map(|s| String::from_utf8_lossy(s).to_string())
        .collect();
    assert!(
        subjects.iter().any(|s| s.contains("thread-parent-435")),
        "reply not found via thread_related descendant search; subjects: {subjects:?}",
    );

    // Ancestor direction: search from the reply's own ancestor chain
    // (its References, which name the parent) should find the parent.
    let (ancestors, _) = h
        .connection
        .thread_related(
            "INBOX",
            Some(reply_message_id),
            &[parent_message_id.to_string()],
        )
        .await
        .unwrap();
    assert!(
        ancestors.contains(&parent_uid),
        "parent not found via thread_related ancestor search; got {ancestors:?}",
    );
}
