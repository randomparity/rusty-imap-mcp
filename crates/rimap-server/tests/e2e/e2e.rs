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
#[path = "../support/dovecot/mod.rs"]
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
use rimap_config::model::{ImapConfig, ImapEncryption};
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
    harness: DovecotHarness,
    _audit_dir: TempDir,
    _download_dir: TempDir,
    server: ImapMcpServer,
}

fn build_test_env(harness: DovecotHarness) -> TestEnv {
    let audit_dir = TempDir::new().expect("audit tempdir");
    let download_dir = TempDir::new().expect("download tempdir");

    let audit = AuditWriter::open(&AuditOptions::new(
        audit_dir.path().join("audit.jsonl"),
        Seq::FIRST,
    ))
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
        tool_call_timeout: std::time::Duration::from_secs(u64::from(
            account_cfg.limits.tool_call_timeout_seconds,
        )),
    };
    let mut accounts = BTreeMap::new();
    accounts.insert(id, state);
    let registry = rimap_server::boot::registry::AccountRegistry::new(accounts);

    let (cancellation_sender, _cancellation_rx) = rimap_audit::cancellation_channel();
    let server = ImapMcpServer::new(registry, audit, cancellation_sender);

    TestEnv {
        harness,
        _audit_dir: audit_dir,
        _download_dir: download_dir,
        server,
    }
}

fn test_account_config(harness: &DovecotHarness) -> ValidatedAccountConfig {
    let mut cfg = ValidatedAccountConfig::new_for_tests(AccountId::default_account(), {
        let mut imap = ImapConfig::new("127.0.0.1".into(), harness.port(), "rimap-test".into());
        imap.encryption = ImapEncryption::Tls;
        imap
    });
    cfg.security.posture = Posture::DraftSafe;
    // Enable the default-deny `export_messages` tool — the equivalent of
    // `[security.tools] export_messages = true` in a real config.
    cfg.tool_overrides.insert(
        rimap_core::tool::ToolName::ExportMessages,
        rimap_config::model::Verdict::Allow,
    );
    cfg.account_written_tools
        .insert(rimap_core::tool::ToolName::ExportMessages);
    cfg.tls_fingerprint = Some(*harness.fingerprint());
    cfg
}

fn test_connection(harness: &DovecotHarness, audit: &AuditWriter) -> Connection {
    let mut conn_cfg = ConnectionConfig::new(
        rimap_core::account::AccountId::default_account(),
        "127.0.0.1".into(),
        harness.port(),
        rimap_imap::ImapEncryption::Tls,
        "rimap-test".into(),
        Duration::from_secs(10),
        Duration::from_secs(30),
        5_242_880,
        10_485_760,
    );
    conn_cfg.pinned_fingerprint = Some(*harness.fingerprint());
    let store: Arc<dyn CredentialStore> =
        Arc::new(StaticCreds("RIMAP-CANARY-DVC-9f83b1a7c0d6e4f2".into()));
    let creds: Arc<dyn rimap_core::CredentialResolver> =
        Arc::new(rimap_config::credential::KeyringCredentialResolver::new(
            store,
            rimap_config::model::FallbackMode::KeyringThenEnv,
            rimap_config::credential::Protocol::Imap,
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
    assert_export_happy_path(server, &env.harness).await;
    assert_export_partial_success(server, uid).await;
    assert_export_uidvalidity_change(server, &env.harness).await;
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
    let account = server.registry().resolve(None).expect("resolve account");
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

    // body_preview_bytes (#410): one search returns a sanitized body
    // preview inline, no per-message fetch_message round trip.
    let with_preview = call_tool(
        server,
        "search",
        serde_json::json!({
            "folder": "INBOX",
            "subject": "e2e-test-smoke",
            "body_preview_bytes": 1024
        }),
    )
    .await
    .expect("search with body_preview_bytes failed");
    let previewed = with_preview["untrusted"]["messages"]
        .as_array()
        .expect("messages array");
    let preview = previewed[0]["body_preview"]
        .as_str()
        .expect("body_preview present when body_preview_bytes set");
    assert!(
        preview.contains("Hello from the e2e smoke test"),
        "unexpected preview: {preview}",
    );
    // The fixture body is well under 1024 bytes, so it is not truncated.
    assert_eq!(
        previewed[0]["body_preview_truncated"],
        serde_json::json!(false)
    );

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

    // include_headers: a header outside the fixed parsed set (MIME-Version)
    // is returned under untrusted.headers; a requested-but-absent name is
    // omitted rather than erroring.
    let with_headers = call_tool(
        server,
        "fetch_message",
        serde_json::json!({
            "folder": "INBOX",
            "uid": uid,
            "include_headers": ["MIME-Version", "X-Absent-Header"]
        }),
    )
    .await
    .expect("fetch_message with include_headers failed");

    let headers = &with_headers["untrusted"]["headers"];
    assert_eq!(
        headers["MIME-Version"],
        serde_json::json!(["1.0"]),
        "expected MIME-Version header, got {headers}",
    );
    assert!(
        headers.get("X-Absent-Header").is_none(),
        "absent header must be omitted, got {headers}",
    );
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
    let account = server.registry().resolve(None).expect("resolve account");
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

// ── export_messages ─────────────────────────────────────────────────

/// A `git format-patch`-style email: exporting it to mbox must apply cleanly
/// with `git am`. Adds a single file `hello.txt` on top of an empty base repo.
fn patch_message() -> Vec<u8> {
    concat!(
        "From 1234567890abcdef1234567890abcdef12345678 Mon Sep 17 00:00:00 2001\r\n",
        "From: Patch Author <author@example.com>\r\n",
        "Date: Sat, 12 Apr 2026 11:00:00 +0000\r\n",
        "Subject: [PATCH] add hello.txt\r\n",
        "Message-ID: <e2e-patch-001@example.com>\r\n",
        "MIME-Version: 1.0\r\n",
        "Content-Type: text/plain; charset=utf-8\r\n",
        "Content-Transfer-Encoding: 8bit\r\n",
        "\r\n",
        "Adds a greeting file.\r\n",
        "---\r\n",
        " hello.txt | 1 +\r\n",
        " 1 file changed, 1 insertion(+)\r\n",
        " create mode 100644 hello.txt\r\n",
        "\r\n",
        "diff --git a/hello.txt b/hello.txt\r\n",
        "new file mode 100644\r\n",
        "index 0000000..ce01362\r\n",
        "--- /dev/null\r\n",
        "+++ b/hello.txt\r\n",
        "@@ -0,0 +1 @@\r\n",
        "+hello\r\n",
        "-- \r\n",
        "2.40.0\r\n",
    )
    .as_bytes()
    .to_vec()
}

/// Search a folder by subject and return `(first_uid, uid_validity)`.
async fn search_uid_and_validity(
    server: &ImapMcpServer,
    folder: &str,
    subject: &str,
) -> (u32, u32) {
    let result = call_tool(
        server,
        "search",
        serde_json::json!({"folder": folder, "subject": subject}),
    )
    .await
    .expect("search failed");
    let messages = result["untrusted"]["messages"]
        .as_array()
        .expect("messages array");
    let uid = json_u32(&messages[0]["uid"]);
    let uid_validity = json_u32(&result["meta"]["uid_validity"]);
    (uid, uid_validity)
}

/// Happy path: seed a `git format-patch`-style message in a dedicated folder,
/// export it, and assert the artifact exists, its SHA-256 matches the file
/// bytes, `message_count` is correct, and the file applies cleanly with
/// `git am` in a throwaway repo.
async fn assert_export_happy_path(server: &ImapMcpServer, harness: &DovecotHarness) {
    let folder = "PatchExport";
    harness.create_mailbox(folder);
    let account = server.registry().resolve(None).expect("resolve account");
    account
        .imap
        .append_message(folder, &patch_message(), &[], &[])
        .await
        .expect("APPEND patch message failed");

    let (uid, uid_validity) = search_uid_and_validity(server, folder, "add hello.txt").await;
    let result = call_tool(
        server,
        "export_messages",
        serde_json::json!({
            "folder": folder,
            "uids": [uid],
            "expected_uidvalidity": uid_validity,
            "filename": "patch",
        }),
    )
    .await
    .expect("export_messages failed");

    assert!(result["meta"]["complete"].as_bool().unwrap());
    assert_eq!(result["meta"]["message_count"].as_u64().unwrap(), 1);
    assert!(
        result["meta"]["partial_path"].is_null(),
        "complete export must not carry partial_path",
    );
    let path = result["meta"]["path"].as_str().expect("path");
    let bytes = std::fs::read(path).expect("artifact exists on disk");
    let expected_sha = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(&bytes))
    };
    assert_eq!(
        result["meta"]["sha256"].as_str().unwrap(),
        expected_sha,
        "manifest sha256 must match file bytes",
    );
    assert_git_am_applies(path);
}

/// Partial success: request the present UID plus a non-existent one with
/// `allow_partial=true`; assert a `.partial.mbox` is written, the present UID
/// succeeds, and the missing UID is reported `not_found`. Then assert
/// `allow_partial=false` errors and writes no `path`.
async fn assert_export_partial_success(server: &ImapMcpServer, present_uid: u32) {
    let (_uid, uid_validity) = search_uid_and_validity(server, "INBOX", "e2e-test-smoke").await;
    let missing_uid = present_uid + 100_000;

    let result = call_tool(
        server,
        "export_messages",
        serde_json::json!({
            "folder": "INBOX",
            "uids": [present_uid, missing_uid],
            "expected_uidvalidity": uid_validity,
            "allow_partial": true,
        }),
    )
    .await
    .expect("partial export should succeed");

    assert!(!result["meta"]["complete"].as_bool().unwrap());
    assert!(result["meta"]["path"].is_null(), "partial must omit path");
    let partial_path = result["meta"]["partial_path"]
        .as_str()
        .expect("partial_path present");
    assert!(partial_path.ends_with(".partial.mbox"));
    assert!(std::path::Path::new(partial_path).exists());
    assert_eq!(result["meta"]["message_count"].as_u64().unwrap(), 1);
    let failed = result["meta"]["failed"].as_array().expect("failed array");
    assert_eq!(failed.len(), 1);
    assert_eq!(json_u32(&failed[0]["uid"]), missing_uid);
    assert_eq!(failed[0]["reason"].as_str().unwrap(), "not_found");

    // allow_partial defaults to false: the same request must error and write
    // no artifact.
    let err = call_tool(
        server,
        "export_messages",
        serde_json::json!({
            "folder": "INBOX",
            "uids": [present_uid, missing_uid],
            "expected_uidvalidity": uid_validity,
        }),
    )
    .await;
    assert!(
        err.is_err(),
        "all-or-nothing export with a missing UID must error",
    );
}

/// UIDVALIDITY change: seed a dedicated folder, capture its UIDVALIDITY,
/// delete+recreate it (forcing a new UIDVALIDITY), then export with the STALE
/// value. The preflight must abort with a UIDVALIDITY error under both
/// `allow_partial` settings, writing no artifact.
async fn assert_export_uidvalidity_change(server: &ImapMcpServer, harness: &DovecotHarness) {
    let folder = "UidValidityExport";
    harness.create_mailbox(folder);
    let account = server.registry().resolve(None).expect("resolve account");
    account
        .imap
        .append_message(folder, &test_message(), &[], &[])
        .await
        .expect("APPEND failed");

    let (uid, stale_validity) = search_uid_and_validity(server, folder, "e2e-test-smoke").await;

    // Force a new UIDVALIDITY by deleting and recreating the mailbox.
    harness.delete_mailbox(folder);
    harness.create_mailbox(folder);

    // Snapshot the sandbox dir: a preflight UIDVALIDITY abort must not write a
    // new artifact. Earlier export steps wrote files here, so compare counts
    // rather than asserting empty.
    let dest = account.download_dir.as_ref();
    let before = dir_entry_count(dest);

    for allow_partial in [false, true] {
        let result = call_tool(
            server,
            "export_messages",
            serde_json::json!({
                "folder": folder,
                "uids": [uid],
                "expected_uidvalidity": stale_validity,
                "allow_partial": allow_partial,
            }),
        )
        .await;
        let err = result.expect_err("stale UIDVALIDITY must abort the export");
        // `execute_tool_for_test` flattens MCP errors to `Internal`, preserving
        // the original message as a string. Match on the typed message text.
        let msg = err.to_string();
        assert!(
            msg.contains("UIDVALIDITY changed"),
            "expected UIDVALIDITY error (allow_partial={allow_partial}), got {msg}",
        );
    }

    assert_eq!(
        dir_entry_count(dest),
        before,
        "preflight UIDVALIDITY abort must write no artifact to the sandbox",
    );
}

/// Count entries directly under `dir`.
fn dir_entry_count(dir: &std::path::Path) -> usize {
    std::fs::read_dir(dir).expect("read_dir").count()
}

/// Apply an exported mbox file with `git am` in a fresh throwaway repo. Panics
/// if `git am` rejects the file.
fn assert_git_am_applies(mbox_path: &str) {
    use std::process::Command;
    let repo = TempDir::new().expect("git repo tempdir");
    let run = |args: &[&str]| {
        let status = Command::new("git")
            .args(args)
            .current_dir(repo.path())
            .status()
            .expect("git invocation failed");
        assert!(status.success(), "git {args:?} failed");
    };
    run(&["init", "-q"]);
    run(&["config", "user.email", "e2e@example.com"]);
    run(&["config", "user.name", "e2e"]);
    run(&["commit", "-q", "--allow-empty", "-m", "base"]);
    let status = Command::new("git")
        .args(["am", mbox_path])
        .current_dir(repo.path())
        .status()
        .expect("git am invocation failed");
    assert!(status.success(), "git am {mbox_path} did not apply cleanly");
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
