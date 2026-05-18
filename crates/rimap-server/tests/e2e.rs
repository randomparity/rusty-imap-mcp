//! Dovecot e2e smoke test: exercises the full MCP tool chain against
//! a real Dovecot IMAP server running in a container.
//!
//! Skips silently when no container runtime is available. Set
//! `RIMAP_REQUIRE_DOCKER=1` to fail loudly instead.
//!
//! # Scope and structure
//!
//! `e2e_full_session` is intentionally a single monolithic
//! scenario-level flow rather than a set of isolated per-tool tests.
//! Bringing up a Dovecot container, seeding mailboxes, and wiring the
//! full `ImapMcpServer` stack (audit log, circuit breakers, rate
//! limiters, posture, credential store) dominates wall time; each
//! split test would pay that cost again. The monolithic flow also
//! catches ordering bugs (e.g. a flag set in one step visible to the
//! next) that isolated tests by construction cannot see.
//!
//! The tradeoff is that individual input-shape and error-branch
//! coverage is NOT the job of this file. Those belong to unit tests
//! next to each handler — see e.g. `tools::admin::accounts::tests`
//! and `tools::fetch_by_uid::tests` for the input-validation and
//! empty-result branches that used to rely on this e2e for coverage.

#![expect(clippy::unwrap_used, reason = "tests")]
#![expect(clippy::expect_used, reason = "tests")]
#![expect(clippy::panic, reason = "test diagnostics")]

// Import dovecot directly (not via support/mod.rs) so this binary
// doesn't compile the wire driver it doesn't use.
#[path = "support/dovecot/mod.rs"]
mod dovecot;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use rimap_audit::{AuditOptions, AuditWriter, Seq};
use rimap_authz::DispatchGuard;
use rimap_authz::breaker::{BreakerConfig, CircuitBreaker, SystemClock};
use rimap_authz::matrix::EffectiveMatrix;
use rimap_authz::rate_limit::Governor;
use rimap_config::credential::CredentialStore;
use rimap_config::model::{ImapConfig, ImapEncryption, LimitsConfig, SecurityConfig};
use rimap_config::validate::ValidatedAccountConfig;
use rimap_core::account::AccountId;
use rimap_core::posture::Posture;
use rimap_imap::{Connection, ConnectionConfig};
use tempfile::TempDir;

use dovecot::{DovecotHarness, HarnessError};
use rimap_server::mcp::server::ImapMcpServer;

struct StaticCreds(String);

impl CredentialStore for StaticCreds {
    fn get_password(
        &self,
        _account: &str,
    ) -> Result<Option<secrecy::SecretString>, rimap_config::ConfigError> {
        Ok(Some(secrecy::SecretString::from(self.0.clone())))
    }

    #[expect(clippy::panic, clippy::panic_in_result_fn, reason = "test stub")]
    fn set_password(
        &self,
        _account: &str,
        _password: &str,
    ) -> Result<(), rimap_config::ConfigError> {
        panic!("tests do not write credentials")
    }
}

// ── Server builder ──────────────────────────────────────────────────

struct TestEnv {
    _harness: DovecotHarness,
    _audit_dir: TempDir,
    _download_dir: TempDir,
    server: ImapMcpServer,
}

fn build_test_env(harness: DovecotHarness) -> TestEnv {
    let audit_dir = TempDir::new().expect("audit tempdir");
    let download_dir = TempDir::new().expect("download tempdir");

    let audit = AuditWriter::open(&AuditOptions {
        path: audit_dir.path().join("audit.jsonl"),
        rotate_bytes: 0,
        rotate_keep: 0,
        retention_seconds: None,
        fail_open: false,
        initial_seq: Seq::FIRST,
    })
    .expect("audit open");

    let account_cfg = test_account_config(&harness);
    let imap = test_connection(&harness, &audit);
    let guard = test_guard(&account_cfg);
    let folder_guard = rimap_authz::FolderGuard::new(
        &account_cfg.security.protected_folders,
        &account_cfg.security.expunge_folders,
    );
    let id = account_cfg.id.clone();
    let state = rimap_server::boot::registry::AccountState {
        id: id.clone(),
        imap,
        smtp: None,
        guard,
        folder_guard,
        download_dir: std::sync::Arc::from(download_dir.path().to_path_buf().into_boxed_path()),
        special_use: rimap_imap::SpecialUseMap::default(),
    };
    let mut accounts = BTreeMap::new();
    accounts.insert(id, state);
    let registry = rimap_server::boot::registry::AccountRegistry::new(accounts);

    let (cancellation_sender, _cancellation_rx) = rimap_audit::cancellation_channel();
    let server = ImapMcpServer::new(registry, audit, cancellation_sender);

    TestEnv {
        _harness: harness,
        _audit_dir: audit_dir,
        _download_dir: download_dir,
        server,
    }
}

fn test_account_config(harness: &DovecotHarness) -> ValidatedAccountConfig {
    ValidatedAccountConfig {
        id: AccountId::default_account(),
        imap: ImapConfig {
            host: "127.0.0.1".into(),
            port: harness.port(),
            username: "rimap-test".into(),
            encryption: ImapEncryption::Tls,
            tls_fingerprint_sha256: None,
            connect_timeout_seconds: 10,
            command_timeout_seconds: 30,
        },
        smtp: None,
        security: SecurityConfig {
            posture: Posture::DraftSafe,
            ..SecurityConfig::default()
        },
        limits: LimitsConfig::default(),
        tool_overrides: BTreeMap::new(),
        tls_fingerprint: Some(*harness.fingerprint()),
        fallback_mode: rimap_config::model::FallbackMode::default(),
    }
}

fn test_connection(harness: &DovecotHarness, audit: &AuditWriter) -> Connection {
    let conn_cfg = ConnectionConfig {
        account: None,
        account_id: rimap_core::account::AccountId::default_account(),
        host: "127.0.0.1".into(),
        port: harness.port(),
        encryption: rimap_imap::ImapEncryption::Tls,
        username: "rimap-test".into(),
        pinned_fingerprint: Some(*harness.fingerprint()),
        connect_timeout: Duration::from_secs(10),
        command_timeout: Duration::from_secs(30),
        max_fetch_body_bytes: 5_242_880,
        max_append_bytes: 10_485_760,
    };
    let store: Arc<dyn CredentialStore> = Arc::new(StaticCreds("testpass".into()));
    let creds: Arc<dyn rimap_core::CredentialResolver> =
        Arc::new(rimap_config::credential::KeyringCredentialResolver::new(
            store,
            rimap_config::model::FallbackMode::KeyringThenEnv,
        ));
    let sink: Arc<dyn rimap_core::auth_sink::AuthEventSink> = Arc::new(audit.clone());
    Connection::new(conn_cfg, sink, creds)
}

fn test_guard(config: &ValidatedAccountConfig) -> DispatchGuard<SystemClock> {
    let matrix = EffectiveMatrix::build(config.security.posture, &config.tool_overrides);
    let breaker = CircuitBreaker::new(SystemClock::new(), BreakerConfig::default_spec());
    let governor = Governor::new(
        config.limits.commands_per_second,
        config.limits.drafts_per_minute,
        config.limits.sends_per_minute,
    )
    .expect("governor");
    DispatchGuard::new(matrix, breaker, governor)
}

// ── Tool dispatch helper ────────────────────────────────────────────

async fn call_tool(
    server: &ImapMcpServer,
    tool_name: &str,
    args: serde_json::Value,
) -> Result<serde_json::Value, rimap_core::RimapError> {
    let tool = std::str::FromStr::from_str(tool_name).map_err(
        |e: rimap_core::tool::ParseToolNameError| rimap_core::RimapError::Internal(e.to_string()),
    )?;
    server.execute_tool_for_test(None, tool, args).await
}

/// Extract a u32 from a JSON value (safe truncation check).
fn json_u32(val: &serde_json::Value) -> u32 {
    let n = val.as_u64().expect("expected u64");
    u32::try_from(n).expect("value exceeds u32")
}

// ── Seed message ────────────────────────────────────────────────────

fn test_message() -> Vec<u8> {
    concat!(
        "From: sender@example.com\r\n",
        "To: rimap-test@localhost\r\n",
        "Subject: e2e-test-smoke\r\n",
        "Date: Sat, 12 Apr 2026 10:00:00 +0000\r\n",
        "Message-ID: <e2e-smoke-001@example.com>\r\n",
        "MIME-Version: 1.0\r\n",
        "Content-Type: text/plain; charset=utf-8\r\n",
        "\r\n",
        "Hello from the e2e smoke test.\r\n",
    )
    .as_bytes()
    .to_vec()
}

// ── The test ────────────────────────────────────────────────────────

#[tokio::test]
async fn e2e_full_session() {
    let harness = match DovecotHarness::try_start() {
        Ok(h) => h,
        Err(HarnessError::DockerUnavailable) => return,
        Err(e) => panic!("Dovecot harness failed: {e}"),
    };

    harness.create_mailbox("Drafts");
    harness.create_mailbox("Trash");

    let env = build_test_env(harness);
    let server = &env.server;

    assert_list_folders(server).await;
    seed_message(server).await;
    let uid = assert_search(server).await;
    assert_fetch(server, uid).await;
    assert_mark_read(server, uid).await;
    assert_create_draft(server, uid).await;
    assert_create_draft_uses_special_use_when_available(server).await;
    assert_move_and_gone(server, uid).await;
}

async fn assert_list_folders(server: &ImapMcpServer) {
    let result = call_tool(server, "list_folders", serde_json::json!({}))
        .await
        .expect("list_folders failed");
    let folders = result["meta"]["folders"].as_array().expect("folders");
    let names: Vec<&str> = folders.iter().filter_map(|f| f["name"].as_str()).collect();
    assert!(names.contains(&"INBOX"), "INBOX not in {names:?}",);
}

async fn seed_message(server: &ImapMcpServer) {
    let account = server.registry.resolve(None).expect("resolve account");
    account
        .imap
        .append_message("INBOX", &test_message(), &[], &[])
        .await
        .expect("APPEND failed");
}

async fn assert_search(server: &ImapMcpServer) -> u32 {
    let result = call_tool(
        server,
        "search",
        serde_json::json!({
            "folder": "INBOX",
            "subject": "e2e-test-smoke"
        }),
    )
    .await
    .expect("search failed");

    let total = result["meta"]["total_matched"].as_u64().unwrap();
    assert!(total >= 1, "expected at least one match");

    let messages = result["untrusted"]["messages"]
        .as_array()
        .expect("messages array");
    let uid = json_u32(&messages[0]["uid"]);
    assert!(uid > 0);
    uid
}

async fn assert_fetch(server: &ImapMcpServer, uid: u32) {
    let result = call_tool(
        server,
        "fetch_message",
        serde_json::json!({"folder": "INBOX", "uid": uid}),
    )
    .await
    .expect("fetch_message failed");

    let body = result["untrusted"]["body_text"]
        .as_str()
        .expect("body_text");
    assert!(
        body.contains("Hello from the e2e smoke test"),
        "unexpected body: {body}",
    );
    assert_eq!(json_u32(&result["meta"]["uid"]), uid);
}

async fn assert_mark_read(server: &ImapMcpServer, uid: u32) {
    let result = call_tool(
        server,
        "mark_read",
        serde_json::json!({"folder": "INBOX", "uid": uid}),
    )
    .await
    .expect("mark_read failed");

    let updated = result["meta"]["uids_updated"]
        .as_array()
        .expect("uids_updated");
    assert!(
        updated.iter().any(|u| json_u32(u) == uid),
        "uid {uid} not in updated list",
    );
}

async fn assert_create_draft(server: &ImapMcpServer, reply_uid: u32) {
    let result = call_tool(
        server,
        "create_draft",
        serde_json::json!({
            "to": [{"address": "reply@example.com"}],
            "subject": "Re: e2e-test-smoke",
            "body_text": "Acknowledged.",
            "in_reply_to_uid": reply_uid,
            "in_reply_to_folder": "INBOX"
        }),
    )
    .await
    .expect("create_draft failed");

    assert_eq!(result["meta"]["folder"].as_str().unwrap(), "Drafts",);
    let keywords = result["meta"]["keywords"].as_array().expect("keywords");
    assert!(
        keywords
            .iter()
            .any(|k| k.as_str() == Some("$PendingReview")),
        "missing $PendingReview keyword",
    );
}

async fn assert_create_draft_uses_special_use_when_available(server: &ImapMcpServer) {
    let account = server.registry.resolve(None).expect("resolve account");
    let expected = account
        .special_use
        .drafts()
        .map_or_else(|| "Drafts".to_string(), str::to_string);

    let result = call_tool(
        server,
        "create_draft",
        serde_json::json!({
            "to": [{"address": "dest@example.com"}],
            "subject": "s",
            "body_text": "b",
        }),
    )
    .await
    .expect("create_draft failed");
    assert_eq!(result["meta"]["folder"].as_str().unwrap(), expected);
}

async fn assert_move_and_gone(server: &ImapMcpServer, uid: u32) {
    let result = call_tool(
        server,
        "move_message",
        serde_json::json!({
            "folder": "INBOX",
            "destination": "Trash",
            "uid": uid
        }),
    )
    .await
    .expect("move_message failed");

    let moves = result["meta"]["moves"].as_array().expect("moves");
    assert_eq!(moves.len(), 1);
    assert_eq!(json_u32(&moves[0]["old_uid"]), uid);

    // Verify message is gone from INBOX.
    let result = call_tool(
        server,
        "search",
        serde_json::json!({
            "folder": "INBOX",
            "subject": "e2e-test-smoke"
        }),
    )
    .await
    .expect("post-move search failed");
    assert_eq!(
        result["meta"]["total_matched"].as_u64().unwrap(),
        0,
        "message should be gone from INBOX after move",
    );
}
