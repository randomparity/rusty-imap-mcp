//! Destructive-posture wire-driven Dovecot e2e (#455). Companion to
//! `e2e_wire.rs`, covering the destructive IMAP path that the draft-safe
//! suite deliberately excludes: `delete_message` and `expunge`.
//!
//! Audit finding H-4b: before this suite, no test executed the
//! `delete_message` / `expunge` handlers end-to-end — only their
//! trash-name / serialization helpers were unit-tested. This drives the
//! full round-trip against a live Dovecot container:
//!
//!   1. `delete_message` flags `\Deleted` + UID MOVEs INBOX → Trash.
//!   2. `expunge` permanently removes the `\Deleted` message from Trash.
//!
//! and the two dispatch-level rejections on the expunge path:
//!
//!   - a protected folder (INBOX / Sent) is never in the expunge
//!     allowlist, so expunging it is refused with `ERR_EXPUNGE_DENIED`.
//!
//! Silent-skip when no container runtime is available;
//! `RIMAP_REQUIRE_DOCKER=1` flips to loud failure, matching `e2e_wire.rs`.

#![expect(clippy::expect_used, reason = "integration tests")]
#![expect(clippy::panic, reason = "test diagnostics")]

// Each integration-test binary imports only its needed support
// submodules directly to avoid cross-binary dead-code warnings.
#[path = "support/canary.rs"]
mod canary;
#[path = "support/dovecot/mod.rs"]
mod dovecot;
#[path = "support/wire/mod.rs"]
mod wire;

use std::sync::Arc;
use std::time::Duration;

use rimap_audit::{AuditOptions, AuditWriter, Seq};
use rimap_config::credential::{CredentialStore, KeyringCredentialResolver, PASSWORD_ENV_VAR};
use rimap_config::model::FallbackMode;
use rimap_imap::{Connection, ConnectionConfig, ImapEncryption};
use secrecy::SecretString;
use serde_json::{Value, json};
use tempfile::TempDir;

use dovecot::{DovecotHarness, HarnessError};
use wire::config::build_dovecot_destructive_config;
use wire::schema::validator_for_tool_response;
use wire::{Harness, assert_valid};

// Per-binary dead-code cross-talk: each integration-test binary compiles
// `support/` independently, but items other binaries use appear dead
// here. Workspace lint `clippy::allow_attributes` forbids `#[allow]`, so
// we reference cross-binary items in a never-called helper — the
// reference itself counts as "use" for dead-code analysis. Mirrors
// `e2e_wire.rs::force_use_for_dead_code_link`.
#[expect(
    dead_code,
    reason = "type-link to items used only by other integration-test binaries"
)]
fn force_use_for_dead_code_link() {
    let _: Duration = wire::harness::REQUEST_TIMEOUT;
    let _: Duration = wire::harness::SHUTDOWN_TIMEOUT;
    let _ = Harness::spawn;
    let _ = Harness::assert_no_response_within;
    let _ = wire::PINNED_PROTOCOL_VERSION;
    let _ = DovecotHarness::delete_mailbox;
}

/// Dovecot's seeded test password. Matches `e2e_wire.rs`.
const DOVECOT_PASSWORD: &str = canary::DOVECOT_CANARY_PASSWORD;

/// Subject of the message seeded into INBOX for the delete round-trip.
/// Distinct from `e2e_wire.rs`'s smoke subject so a search for it can
/// only ever match this suite's seed.
const SEED_SUBJECT: &str = "e2e-destructive-delete-smoke";

/// In-process credential store for the seed connection. Returns
/// `DOVECOT_PASSWORD` unconditionally.
struct StaticCreds;

impl CredentialStore for StaticCreds {
    fn get_password(
        &self,
        _account: &str,
    ) -> Result<Option<SecretString>, rimap_config::ConfigError> {
        Ok(Some(SecretString::from(DOVECOT_PASSWORD.to_string())))
    }

    #[expect(clippy::panic_in_result_fn, reason = "seed never writes")]
    fn set_password(
        &self,
        _account: &str,
        _password: &str,
    ) -> Result<(), rimap_config::ConfigError> {
        panic!("seed never writes credentials")
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wire_e2e_destructive_delete_then_expunge() {
    let dovecot = match DovecotHarness::try_start() {
        Ok(d) => d,
        Err(HarnessError::DockerUnavailable) => return,
        Err(e) => panic!("Dovecot harness failed: {e}"),
    };
    dovecot.create_mailbox("Trash");

    let tempdir = TempDir::new().expect("tempdir");
    let audit_path = tempdir.path().join("audit.jsonl");
    let allowed_base = tempdir.path().to_path_buf();
    let download_dir = tempdir.path().join("downloads");
    std::fs::create_dir_all(&download_dir).expect("mkdir download_dir");

    seed_plain_message(&dovecot).await;

    let config_path = tempdir.path().join("config.toml");
    let fingerprint_hex = dovecot.fingerprint().to_hex();
    let config = build_dovecot_destructive_config(
        &fingerprint_hex,
        dovecot.port(),
        &audit_path,
        &allowed_base,
        &download_dir,
    );
    std::fs::write(&config_path, config).expect("write config");

    let envs = [(PASSWORD_ENV_VAR, DOVECOT_PASSWORD)];
    let mut harness = Harness::spawn_with_config(&config_path, tempdir, &envs).await;

    let init = harness.initialize_handshake().await;
    assert_valid(&init["result"], "InitializeResult");
    harness.send_initialized().await;

    assert_destructive_tools_advertised(&mut harness).await;

    let _ = call_tool(
        &mut harness,
        "use_account",
        json!({ "account": "destructive" }),
    )
    .await;

    let inbox_uid = search_subject_uid(&mut harness, "INBOX")
        .await
        .expect("seeded message must be found in INBOX");

    let trash_uid = assert_delete_moves_to_trash(&mut harness, inbox_uid).await;
    assert_expunge_purges_trash(&mut harness, trash_uid).await;
    assert_expunge_denied_on_protected_folders(&mut harness).await;

    // Bind the returned tempdir guard so the audit file outlives the
    // harness; dropping it before the assertion below would delete the
    // file the test is about to read.
    let (status, tempdir_guard) = harness.shutdown_and_wait().await;
    assert!(status.success(), "binary exited non-zero: {status:?}");
    canary::assert_absent(DOVECOT_PASSWORD, &[tempdir_guard.path()], &[]);

    assert_destructive_audit_records(&audit_path);
}

/// The destructive namespace must advertise both `delete_message` and
/// `expunge` — the two tools this suite exists to exercise.
async fn assert_destructive_tools_advertised(harness: &mut Harness) {
    let tools_list = harness.request("tools/list", json!({})).await;
    assert_valid(&tools_list["result"], "ListToolsResult");
    let names: Vec<&str> = tools_list["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    for required in ["destructive.delete_message", "destructive.expunge"] {
        assert!(
            names.contains(&required),
            "destructive namespace must advertise {required}; got {names:?}",
        );
    }
}

/// Step 1 of the two-step semantics: `delete_message` flags `\Deleted`
/// and UID MOVEs the message INBOX → Trash. Assert the response meta and
/// that the message left INBOX and now lives in Trash (proving MOVE, not
/// COPY). Returns the message's new UID in Trash for step 2.
async fn assert_delete_moves_to_trash(harness: &mut Harness, inbox_uid: u32) -> u32 {
    let deleted = call_tool(
        harness,
        "destructive.delete_message",
        json!({ "folder": "INBOX", "uid": inbox_uid }),
    )
    .await;
    assert_eq!(deleted["meta"]["deleted"], json!(true), "meta: {deleted}");
    assert_eq!(
        deleted["meta"]["moved_to_trash"],
        json!(true),
        "delete_message must MOVE to Trash on a MOVE-capable server: {deleted}",
    );
    assert_eq!(
        deleted["meta"]["destination"].as_str(),
        Some("Trash"),
        "destination must resolve to Trash: {deleted}",
    );
    assert_eq!(
        deleted["meta"]["uid"].as_u64(),
        Some(u64::from(inbox_uid)),
        "meta.uid must echo the source UID: {deleted}",
    );

    // MOVE removes the message from the source folder.
    assert!(
        search_subject_uid(harness, "INBOX").await.is_none(),
        "message must no longer be in INBOX after delete_message MOVE",
    );
    // ...and the moved copy is now in Trash, carrying the `\Deleted` flag.
    search_subject_uid(harness, "Trash")
        .await
        .expect("moved message must be present in Trash after delete_message")
}

/// Step 2 of the two-step semantics: `expunge` permanently removes the
/// `\Deleted` message from Trash. `trash_uid` is the UID step 1 resolved
/// for the moved message. Assert the reported counts and that the message
/// is gone afterwards.
async fn assert_expunge_purges_trash(harness: &mut Harness, trash_uid: u32) {
    let expunged = call_tool(harness, "destructive.expunge", json!({ "folder": "Trash" })).await;
    assert_eq!(
        expunged["meta"]["folder"].as_str(),
        Some("Trash"),
        "expunge meta.folder must echo Trash: {expunged}",
    );
    assert_eq!(
        expunged["meta"]["expunged_count"].as_u64(),
        Some(1),
        "exactly the one moved message must be expunged: {expunged}",
    );
    let deleted_before: Vec<u64> = expunged["meta"]["deleted_uids_before_expunge"]
        .as_array()
        .expect("deleted_uids_before_expunge array")
        .iter()
        .filter_map(Value::as_u64)
        .collect();
    assert_eq!(
        deleted_before,
        vec![u64::from(trash_uid)],
        "the moved message must have carried \\Deleted before expunge \
         (proves delete_message STOREd the flag): {expunged}",
    );

    // The message is permanently gone from Trash.
    assert!(
        search_subject_uid(harness, "Trash").await.is_none(),
        "message must be gone from Trash after expunge",
    );
}

/// The two dispatch-level rejections on the expunge path. A protected
/// folder is never in the expunge allowlist, so `expunge` on INBOX or
/// Sent is refused with `ERR_EXPUNGE_DENIED` — a tool-execution error
/// (`isError: true`), not a JSON-RPC error envelope.
async fn assert_expunge_denied_on_protected_folders(harness: &mut Harness) {
    for folder in ["INBOX", "Sent"] {
        let resp = harness
            .request(
                "tools/call",
                json!({
                    "name": "destructive.expunge",
                    "arguments": { "folder": folder },
                }),
            )
            .await;
        assert!(
            resp["error"].is_null(),
            "expunge denial must not be a JSON-RPC error envelope; folder={folder}, got {resp}",
        );
        assert_valid(&resp["result"], "CallToolResult");
        assert_eq!(
            resp["result"]["isError"],
            json!(true),
            "expunge on protected folder {folder} must be denied: {resp}",
        );
        assert_eq!(
            resp["result"]["structuredContent"]["error_code"],
            json!("ERR_EXPUNGE_DENIED"),
            "expunge on {folder} must carry ERR_EXPUNGE_DENIED: {resp}",
        );
        assert!(
            resp["result"]["content"][0]["text"]
                .as_str()
                .is_some_and(|t| !t.is_empty()),
            "expunge denial must carry a non-empty message; folder={folder}, got {resp}",
        );
    }
}

/// Search `folder` for the seeded subject and return the highest matching
/// UID, or `None` when there is no match.
async fn search_subject_uid(harness: &mut Harness, folder: &str) -> Option<u32> {
    let body = call_tool(
        harness,
        "destructive.search",
        json!({ "folder": folder, "subject": SEED_SUBJECT }),
    )
    .await;
    body["untrusted"]["messages"]
        .as_array()
        .expect("search messages array")
        .iter()
        .filter_map(|m| m["uid"].as_u64())
        .max()
        .and_then(|u| u32::try_from(u).ok())
}

/// Invoke `tools/call` and validate the response against the envelope
/// schema, `CallToolResult`, and the per-tool response schema fixture.
async fn call_tool(harness: &mut Harness, name: &str, args: Value) -> Value {
    let resp = harness
        .request("tools/call", json!({ "name": name, "arguments": args }))
        .await;
    assert!(resp["error"].is_null(), "tool {name} failed: {resp}");
    assert_valid(&resp["result"], "CallToolResult");
    let body = &resp["result"]["structuredContent"];
    let bare = name.rsplit_once('.').map_or(name, |(_, b)| b);
    let validator = validator_for_tool_response(static_tool_name(bare));
    if !validator.is_valid(body) {
        let errors: Vec<String> = validator.iter_errors(body).map(|e| e.to_string()).collect();
        panic!(
            "tool {name} response failed schema:\n  {}\n\nresponse: {body}",
            errors.join("\n  ")
        );
    }
    body.clone()
}

/// Map a bare tool name to its `'static str` form for the validator
/// cache. Only the tools this suite exercises are listed; a new tool
/// added without a schema fixture mapping panics at runtime.
fn static_tool_name(bare: &str) -> &'static str {
    match bare {
        "use_account" => "use_account",
        "search" => "search",
        "delete_message" => "delete_message",
        "expunge" => "expunge",
        other => panic!("no schema fixture mapping for tool: {other}"),
    }
}

/// Assert the audit log paired every `delete_message` and `expunge`
/// handler execution, each attributed to the `destructive` account.
///
/// `delete_message` is dispatched once (the successful MOVE); `expunge`
/// is dispatched three times (one successful purge + the INBOX and Sent
/// protected-folder denials). Denied calls still pair a `tool_start`
/// with a `tool_end` — that they reach dispatch at all is the point.
fn assert_destructive_audit_records(audit_path: &std::path::Path) {
    let records = read_audit_records(audit_path);
    assert_paired_tool(&records, "delete_message", 1);
    assert_paired_tool(&records, "expunge", 3);
}

/// Assert exactly `expected` `tool_start` / `tool_end` pairs for `tool`,
/// each attributed to the `destructive` account and joined by `start_seq`.
fn assert_paired_tool(records: &[Value], tool: &str, expected: usize) {
    let starts: Vec<&Value> = records
        .iter()
        .filter(|r| r["kind"] == "tool_start" && r["tool"] == tool)
        .collect();
    let ends: Vec<&Value> = records
        .iter()
        .filter(|r| r["kind"] == "tool_end" && r["tool"] == tool)
        .collect();
    assert_eq!(
        starts.len(),
        expected,
        "expected {expected} {tool} tool_start: {records:#?}",
    );
    assert_eq!(
        ends.len(),
        expected,
        "expected {expected} {tool} tool_end: {records:#?}",
    );

    let start_seqs: std::collections::HashSet<&Value> = starts.iter().map(|s| &s["seq"]).collect();
    for rec in starts.iter().chain(ends.iter()) {
        assert_eq!(
            rec["account"].as_str(),
            Some("destructive"),
            "{tool} record must attribute to destructive: {rec:#?}",
        );
    }
    for end in &ends {
        assert!(
            start_seqs.contains(&end["start_seq"]),
            "{tool} tool_end.start_seq must match a tool_start.seq: {records:#?}",
        );
    }
}

/// Parse the audit JSONL into a vector of `Value`s. Tolerates a single
/// trailing empty line; any other parse failure panics with the line
/// number.
fn read_audit_records(path: &std::path::Path) -> Vec<Value> {
    let raw = std::fs::read_to_string(path).expect("read audit file");
    raw.lines()
        .enumerate()
        .filter(|(_, l)| !l.is_empty())
        .map(|(i, l)| {
            serde_json::from_str(l)
                .unwrap_or_else(|e| panic!("audit line {} parse error: {e}: {l}", i + 1))
        })
        .collect()
}

/// Build the raw bytes of a minimal `text/plain` RFC 5322 message and
/// APPEND it into INBOX via a direct IMAP connection. Mirrors
/// `e2e_wire.rs::seed_multipart_message` but seeds a single plain part —
/// the destructive path only needs one addressable message.
async fn seed_plain_message(dovecot: &DovecotHarness) {
    let audit_dir = TempDir::new().expect("seed-audit tempdir");
    let audit = AuditWriter::open(&AuditOptions {
        path: audit_dir.path().join("seed.jsonl"),
        rotate_bytes: 0,
        rotate_keep: 0,
        retention_seconds: None,
        fail_open: false,
        initial_seq: Seq::FIRST,
    })
    .expect("audit open");

    let cfg = ConnectionConfig {
        account: None,
        account_id: rimap_core::account::AccountId::default_account(),
        host: "127.0.0.1".into(),
        port: dovecot.port(),
        encryption: ImapEncryption::Tls,
        username: "rimap-test".into(),
        pinned_fingerprint: Some(*dovecot.fingerprint()),
        connect_timeout: Duration::from_secs(10),
        command_timeout: Duration::from_secs(30),
        max_fetch_body_bytes: 5_242_880,
        max_append_bytes: 10_485_760,
    };
    let store: Arc<dyn CredentialStore> = Arc::new(StaticCreds);
    let creds: Arc<dyn rimap_core::CredentialResolver> = Arc::new(KeyringCredentialResolver::new(
        store,
        FallbackMode::KeyringThenEnv,
        rimap_config::credential::Protocol::Imap,
    ));
    let sink: Arc<dyn rimap_core::auth_sink::AuthEventSink> = Arc::new(audit.clone());
    let conn = Connection::new(cfg, sink, creds);
    conn.append_message("INBOX", &plain_message(), &[], &[])
        .await
        .expect("APPEND plain seed");
}

/// The seed message: one `text/plain` part with the unique `SEED_SUBJECT`.
fn plain_message() -> Vec<u8> {
    format!(
        "From: sender@example.com\r\n\
         To: rimap-test@localhost\r\n\
         Subject: {SEED_SUBJECT}\r\n\
         Date: Sat, 04 Jul 2026 10:00:00 +0000\r\n\
         Message-ID: <e2e-destructive-001@example.com>\r\n\
         \r\n\
         Destructive-path e2e seed body.\r\n"
    )
    .into_bytes()
}
