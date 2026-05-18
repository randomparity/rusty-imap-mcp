//! Phase 3 wire-driven Dovecot e2e (#265). Drives `rusty-imap-mcp`
//! over its stdio JSON-RPC wire against the existing Dovecot
//! container fixture, exercising every draft-safe + read-only
//! posture tool category and validating each response against
//! Phase 1's vendored MCP spec schemas + per-tool response schemas
//! under `tests/fixtures/rimap-tool-schemas/`.
//!
//! Silent-skip when no container runtime is available;
//! `RIMAP_REQUIRE_DOCKER=1` flips to loud failure.

#![expect(clippy::expect_used, reason = "integration tests")]
#![expect(clippy::panic, reason = "test diagnostics")]

// Each integration-test binary imports only its needed support
// submodules directly to avoid cross-binary dead-code warnings.
#[path = "support/dovecot/mod.rs"]
mod dovecot;
#[path = "support/wire/mod.rs"]
mod wire;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use rimap_audit::{AuditOptions, AuditWriter, Seq};
use rimap_config::credential::{CredentialStore, KeyringCredentialResolver, PASSWORD_ENV_VAR};
use rimap_config::model::FallbackMode;
use rimap_imap::{Connection, ConnectionConfig, ImapEncryption};
use secrecy::SecretString;
use serde_json::{Value, json};
use tempfile::TempDir;

use dovecot::{DovecotHarness, HarnessError, fixtures};
// `Harness`, `PINNED_PROTOCOL_VERSION`, and `assert_valid` go through
// `wire::*` (the same re-exports `mcp_wire_conformance.rs` uses) so
// the re-exports in `support/wire/mod.rs` register as "used" in both
// binaries. `e2e_wire`-only items live one level deeper in the
// sub-modules to avoid creating re-exports that appear dead from the
// Phase 1 binary's perspective.
use wire::config::build_dovecot_config;
use wire::schema::validator_for_tool_response;
use wire::{Harness, PINNED_PROTOCOL_VERSION, assert_valid};

// Per-binary dead-code cross-talk: each integration-test file is its
// own compilation unit, but every binary that pulls in
// `support/wire/harness.rs` compiles every method on `Harness`. Items
// used only by `mcp_wire_conformance.rs` (`Harness::spawn`,
// `Harness::assert_no_response_within`) appear dead here. Workspace
// lint `clippy::allow_attributes = "deny"` forbids `#[allow]`, so we
// reference the cross-binary items in a never-called function — the
// reference itself counts as "use" for the dead-code analysis. The
// function name omits the leading `_` so the function itself is
// flagged dead and the `#[expect(dead_code)]` is fulfilled.
#[expect(
    dead_code,
    reason = "type-link to items used only by mcp_wire_conformance"
)]
fn force_use_for_dead_code_link() {
    let _: &str = PINNED_PROTOCOL_VERSION;
    let _: Duration = wire::harness::REQUEST_TIMEOUT;
    let _: Duration = wire::harness::SHUTDOWN_TIMEOUT;
    let _ = Harness::spawn;
    let _ = Harness::assert_no_response_within;
}

/// Dovecot's seeded test password. Matches the value injected via the
/// docker-compose fixture; see `e2e.rs` `StaticCreds` for the in-process
/// equivalent.
const DOVECOT_PASSWORD: &str = "testpass";

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
async fn wire_e2e_full_session_draft_safe() {
    let dovecot = match DovecotHarness::try_start() {
        Ok(d) => d,
        Err(HarnessError::DockerUnavailable) => return,
        Err(e) => panic!("Dovecot harness failed: {e}"),
    };
    dovecot.create_mailbox("Drafts");
    dovecot.create_mailbox("Trash");

    let tempdir = TempDir::new().expect("tempdir");
    let audit_path = tempdir.path().join("audit.jsonl");
    let allowed_base = tempdir.path().to_path_buf();
    let download_dir = tempdir.path().join("downloads");
    std::fs::create_dir_all(&download_dir).expect("mkdir download_dir");

    seed_multipart_message(&dovecot).await;

    let config_path = tempdir.path().join("config.toml");
    // build_dovecot_config has a decoupled signature: pass fingerprint+port
    // directly so the wire support module does not depend on DovecotHarness.
    let fingerprint_hex = dovecot.fingerprint().to_hex();
    let config = build_dovecot_config(
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
    let init_result = &init["result"];
    assert_valid(init_result, "InitializeResult");
    assert!(init_result["capabilities"]["tools"].is_object());
    harness.send_initialized().await;

    assert_tools_list(&mut harness).await;
    let uid = drive_account_scoped_tools(&mut harness).await;
    assert_move_message(&mut harness, uid).await;

    // Bind the returned tempdir guard so the audit file outlives the
    // harness; dropping it before the assertion below would delete the
    // file the test is about to read.
    let (status, _tempdir_guard) = harness.shutdown_and_wait().await;
    assert!(status.success(), "binary exited non-zero: {status:?}");

    assert_audit_records(&audit_path);
}

/// Drive the account-scoped tools and return the UID of the seeded message.
async fn drive_account_scoped_tools(harness: &mut Harness) -> u32 {
    // 1. use_account → draftsafe.
    let _ = call_tool(harness, "use_account", json!({ "account": "draftsafe" })).await;

    // 2. list_accounts (infrastructure).
    let accounts_body = call_tool(harness, "list_accounts", json!({})).await;
    assert_eq!(accounts_body["meta"]["count"].as_u64(), Some(2));

    // 3. list_folders.
    let folders_body = call_tool(harness, "draftsafe.list_folders", json!({})).await;
    let folder_names: Vec<&str> = folders_body["meta"]["folders"]
        .as_array()
        .expect("folders array")
        .iter()
        .filter_map(|f| f["name"].as_str())
        .collect();
    assert!(
        folder_names.contains(&"INBOX"),
        "INBOX missing: {folder_names:?}",
    );

    // 4. search → grab the seeded UID.
    let uid = assert_search(harness).await;

    // 5. fetch_message.
    assert_fetch_message(harness, uid).await;

    // 6 + 7. list_attachments + download_attachment.
    let part_id = assert_list_attachments(harness, uid).await;
    assert_download_attachment(harness, uid, &part_id).await;

    // 8. flag / unflag pair.
    let _ = call_tool(
        harness,
        "draftsafe.flag",
        json!({ "folder": "INBOX", "uid": uid }),
    )
    .await;
    let _ = call_tool(
        harness,
        "draftsafe.unflag",
        json!({ "folder": "INBOX", "uid": uid }),
    )
    .await;

    // 9. mark_read / mark_unread pair.
    let _ = call_tool(
        harness,
        "draftsafe.mark_read",
        json!({ "folder": "INBOX", "uid": uid }),
    )
    .await;
    let _ = call_tool(
        harness,
        "draftsafe.mark_unread",
        json!({ "folder": "INBOX", "uid": uid }),
    )
    .await;

    // 10. add_label / list_labels / remove_label.
    assert_label_round_trip(harness, uid).await;

    // 11. create_draft (with reply context + plain).
    let _ = call_tool(
        harness,
        "draftsafe.create_draft",
        json!({
            "to": [{"address": "reply@example.com"}],
            "subject": "Re: e2e-wire-test-smoke",
            "body_text": "Acknowledged.",
            "in_reply_to_uid": uid,
            "in_reply_to_folder": "INBOX",
        }),
    )
    .await;
    let _ = call_tool(
        harness,
        "draftsafe.create_draft",
        json!({
            "to": [{"address": "dest@example.com"}],
            "subject": "wire e2e plain draft",
            "body_text": "body",
        }),
    )
    .await;

    uid
}

async fn assert_tools_list(harness: &mut Harness) {
    let tools_list = harness.request("tools/list", json!({})).await;
    assert_valid(&tools_list["result"], "ListToolsResult");
    let tools: BTreeMap<String, Value> = tools_list["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .map(|t| (t["name"].as_str().expect("name").to_string(), t.clone()))
        .collect();

    for required in [
        "draftsafe.list_folders",
        "draftsafe.search",
        "draftsafe.fetch_message",
        "draftsafe.list_attachments",
        "draftsafe.download_attachment",
        "draftsafe.list_labels",
        "draftsafe.mark_read",
        "draftsafe.mark_unread",
        "draftsafe.flag",
        "draftsafe.unflag",
        "draftsafe.add_label",
        "draftsafe.remove_label",
        "draftsafe.move_message",
        "draftsafe.create_draft",
        "list_accounts",
        "use_account",
    ] {
        assert!(tools.contains_key(required), "missing tool: {required}");
    }

    for forbidden in [
        "readonly.move_message",
        "readonly.create_draft",
        "readonly.mark_read",
        "readonly.mark_unread",
        "readonly.flag",
        "readonly.unflag",
        "readonly.add_label",
        "readonly.remove_label",
    ] {
        assert!(
            !tools.contains_key(forbidden),
            "readonly namespace must not advertise {forbidden}",
        );
    }
}

async fn assert_search(harness: &mut Harness) -> u32 {
    let search_body = call_tool(
        harness,
        "draftsafe.search",
        json!({ "folder": "INBOX", "subject": "e2e-wire-test-smoke" }),
    )
    .await;
    let total = search_body["meta"]["total_matched"]
        .as_u64()
        .expect("total_matched");
    assert!(total >= 1, "expected at least one match, got {total}");
    let messages = search_body["untrusted"]["messages"]
        .as_array()
        .expect("messages array");
    assert!(
        !messages.is_empty(),
        "messages unexpectedly empty despite total_matched={total}",
    );
    let uid_u64 = messages[0]["uid"].as_u64().expect("uid is integer");
    let uid = u32::try_from(uid_u64).expect("uid fits u32");
    assert!(uid > 0);
    uid
}

async fn assert_fetch_message(harness: &mut Harness, uid: u32) {
    let fetch_body = call_tool(
        harness,
        "draftsafe.fetch_message",
        json!({ "folder": "INBOX", "uid": uid }),
    )
    .await;
    let body_text = fetch_body["untrusted"]["body_text"]
        .as_str()
        .expect("body_text");
    assert!(
        body_text.contains("Hello from the Phase 3 wire-driven e2e smoke test."),
        "unexpected body_text: {body_text}",
    );
}

async fn assert_list_attachments(harness: &mut Harness, uid: u32) -> String {
    let list_att = call_tool(
        harness,
        "draftsafe.list_attachments",
        json!({ "folder": "INBOX", "uid": uid }),
    )
    .await;
    let attachments = list_att["untrusted"]["attachments"]
        .as_array()
        .expect("attachments array");
    assert_eq!(
        attachments.len(),
        1,
        "expected 1 attachment, got {attachments:?}",
    );
    let part_id = attachments[0]["part_id"]
        .as_str()
        .expect("part_id")
        .to_string();
    let filename = attachments[0]["filename"].as_str().expect("filename");
    assert_eq!(filename, fixtures::ATTACHMENT_FILENAME);
    part_id
}

async fn assert_download_attachment(harness: &mut Harness, uid: u32, part_id: &str) {
    let dl = call_tool(
        harness,
        "draftsafe.download_attachment",
        json!({
            "folder": "INBOX",
            "uid": uid,
            "part_id": part_id,
        }),
    )
    .await;
    let dl_path = dl["meta"]["path"].as_str().expect("path");
    let dl_bytes = std::fs::read(dl_path).expect("read downloaded bytes");
    assert_eq!(
        dl_bytes.as_slice(),
        fixtures::ATTACHMENT_BYTES,
        "downloaded bytes must match seeded payload",
    );
}

async fn assert_label_round_trip(harness: &mut Harness, uid: u32) {
    let _ = call_tool(
        harness,
        "draftsafe.add_label",
        json!({ "folder": "INBOX", "uid": uid, "label": "WireE2E" }),
    )
    .await;
    let labels_body = call_tool(
        harness,
        "draftsafe.list_labels",
        json!({ "folder": "INBOX", "uid": uid }),
    )
    .await;
    let labels: Vec<&str> = labels_body["meta"]["labels"]
        .as_array()
        .expect("labels array")
        .iter()
        .filter_map(|l| l.as_str())
        .collect();
    assert!(
        labels.contains(&"WireE2E"),
        "labels missing WireE2E: {labels:?}",
    );
    let _ = call_tool(
        harness,
        "draftsafe.remove_label",
        json!({ "folder": "INBOX", "uid": uid, "label": "WireE2E" }),
    )
    .await;
}

async fn assert_move_message(harness: &mut Harness, uid: u32) {
    let move_body = call_tool(
        harness,
        "draftsafe.move_message",
        json!({ "folder": "INBOX", "destination": "Trash", "uid": uid }),
    )
    .await;
    let moves = move_body["meta"]["moves"].as_array().expect("moves array");
    assert_eq!(moves.len(), 1);
    assert_eq!(
        moves[0]["old_uid"].as_u64().expect("old_uid"),
        u64::from(uid),
    );
}

fn assert_audit_records(audit_path: &std::path::Path) {
    let records = read_audit_records(audit_path);

    // Pair every tool_start with a tool_end (matching start_seq).
    let mut start_seqs: BTreeMap<u64, &Value> = BTreeMap::new();
    let mut end_start_seqs: Vec<u64> = Vec::new();
    for rec in &records {
        match rec["kind"].as_str() {
            Some("tool_start") => {
                let seq = rec["seq"].as_u64().expect("tool_start seq");
                start_seqs.insert(seq, rec);
            }
            Some("tool_end") => {
                let start = rec["start_seq"].as_u64().expect("tool_end start_seq");
                end_start_seqs.push(start);
            }
            _ => {}
        }
    }
    assert_eq!(
        start_seqs.len(),
        end_start_seqs.len(),
        "tool_start / tool_end count mismatch: starts={} ends={}",
        start_seqs.len(),
        end_start_seqs.len(),
    );
    for start in &end_start_seqs {
        assert!(
            start_seqs.contains_key(start),
            "tool_end.start_seq={start} has no matching tool_start; \
             start_seqs={:?}",
            start_seqs.keys().collect::<Vec<_>>(),
        );
    }

    // Namespace attribution: account-scoped tools carry `draftsafe`;
    // infrastructure tools carry no `account` field.
    let infrastructure = ["use_account", "list_accounts"];
    for rec in &records {
        let kind = rec["kind"].as_str().unwrap_or("");
        if kind != "tool_start" && kind != "tool_end" {
            continue;
        }
        let tool = rec["tool"].as_str().expect("tool name");
        let account = rec.get("account").and_then(|a| a.as_str());
        if infrastructure.contains(&tool) {
            assert!(
                account.is_none(),
                "infrastructure tool {tool} must omit account, got {account:?}",
            );
        } else {
            assert_eq!(
                account,
                Some("draftsafe"),
                "account-scoped tool {tool} must attribute to draftsafe, \
                 got {account:?}",
            );
        }
    }
}

/// Invoke `tools/call` and validate the response against (a) the
/// envelope schema, (b) `CallToolResult`, and (c) the per-tool response
/// schema fixture under `tests/fixtures/rimap-tool-schemas/`.
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
/// cache. Listing every wire-exercised tool here keeps the binding free
/// of `Box::leak` and forces a runtime panic if a new tool is added
/// without a corresponding `tests/fixtures/rimap-tool-schemas/` entry.
fn static_tool_name(bare: &str) -> &'static str {
    match bare {
        "list_folders" => "list_folders",
        "search" => "search",
        "fetch_message" => "fetch_message",
        "list_attachments" => "list_attachments",
        "download_attachment" => "download_attachment",
        "mark_read" => "mark_read",
        "mark_unread" => "mark_unread",
        "flag" => "flag",
        "unflag" => "unflag",
        "add_label" => "add_label",
        "remove_label" => "remove_label",
        "list_labels" => "list_labels",
        "move_message" => "move_message",
        "create_draft" => "create_draft",
        "use_account" => "use_account",
        "list_accounts" => "list_accounts",
        other => panic!("no schema fixture mapping for tool: {other}"),
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

// Pin the posture-denial JSON-RPC error code. If `to_mcp_error` (in
// `crates/rimap-server/src/mcp/error.rs`) remaps `ErrorCode::PostureDenied`,
// update this constant and document why — silent drift in posture wire
// shape is exactly what this test surfaces.
// (-32001 = custom server-error code reserved for posture denials; see
//  the `POSTURE_DENIED` constant in `mcp/error.rs`.)
const POSTURE_DENIAL_CODE: i64 = -32001;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wire_e2e_readonly_posture_denial() {
    let dovecot = match DovecotHarness::try_start() {
        Ok(d) => d,
        Err(HarnessError::DockerUnavailable) => return,
        Err(e) => panic!("Dovecot harness failed: {e}"),
    };
    let tempdir = TempDir::new().expect("tempdir");
    let audit_path = tempdir.path().join("audit.jsonl");
    let allowed_base = tempdir.path().to_path_buf();
    let download_dir = tempdir.path().join("downloads");
    std::fs::create_dir_all(&download_dir).expect("mkdir download_dir");

    let config_path = tempdir.path().join("config.toml");
    let fingerprint_hex = dovecot.fingerprint().to_hex();
    let config = build_dovecot_config(
        &fingerprint_hex,
        dovecot.port(),
        &audit_path,
        &allowed_base,
        &download_dir,
    );
    std::fs::write(&config_path, config).expect("write config");

    let envs = [(PASSWORD_ENV_VAR, DOVECOT_PASSWORD)];
    let mut harness = Harness::spawn_with_config(&config_path, tempdir, &envs).await;
    let _ = harness.initialize_handshake().await;
    harness.send_initialized().await;

    assert_readonly_tools_list(&mut harness).await;
    assert_readonly_success_path(&mut harness).await;
    assert_readonly_denial(&mut harness).await;

    // Bind the returned tempdir guard so the audit file outlives the
    // harness; dropping it before the assertion below would delete the
    // file the test is about to read.
    let (status, _tempdir_guard) = harness.shutdown_and_wait().await;
    assert!(status.success(), "child must exit 0, got {status:?}");

    assert_readonly_audit_records(&audit_path);
}

/// Verify tools/list advertisement posture for the readonly namespace.
async fn assert_readonly_tools_list(harness: &mut Harness) {
    let tools_list = harness.request("tools/list", json!({})).await;
    assert_valid(&tools_list["result"], "ListToolsResult");
    let names: Vec<&str> = tools_list["result"]["tools"]
        .as_array()
        .expect("tools")
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    assert!(
        names.contains(&"draftsafe.move_message"),
        "draftsafe.move_message must be advertised; got {names:?}",
    );
    assert!(
        names.contains(&"readonly.list_folders"),
        "readonly.list_folders must be advertised; got {names:?}",
    );
    assert!(
        !names.contains(&"readonly.move_message"),
        "readonly.move_message must not be advertised; got {names:?}",
    );
}

/// Readonly success path: drive `list_folders` end-to-end.
async fn assert_readonly_success_path(harness: &mut Harness) {
    let readonly_folders = call_tool(harness, "readonly.list_folders", json!({})).await;
    let folder_names: Vec<&str> = readonly_folders["meta"]["folders"]
        .as_array()
        .expect("folders")
        .iter()
        .filter_map(|f| f["name"].as_str())
        .collect();
    assert!(
        folder_names.contains(&"INBOX"),
        "readonly.list_folders did not return INBOX: {folder_names:?}",
    );
}

/// Posture denial on the wire: `readonly.move_message` must return an error envelope.
async fn assert_readonly_denial(harness: &mut Harness) {
    // Use harness.request directly — call_tool asserts error.is_null() and
    // would panic here. We expect an error envelope, not a success result.
    let resp = harness
        .request(
            "tools/call",
            json!({
                "name": "readonly.move_message",
                "arguments": {"folder": "INBOX", "destination": "Trash", "uid": 1},
            }),
        )
        .await;
    assert!(
        resp["error"].is_object(),
        "expected error envelope, got {resp}",
    );
    assert_eq!(
        resp["error"]["code"].as_i64(),
        Some(POSTURE_DENIAL_CODE),
        "posture-denial wire code drifted; got {resp}",
    );
}

/// Verify audit records from the readonly posture denial test.
fn assert_readonly_audit_records(audit_path: &std::path::Path) {
    let records = read_audit_records(audit_path);

    // Success path: list_folders pair, account="readonly".
    let lf_starts: Vec<&Value> = records
        .iter()
        .filter(|r| r["kind"] == "tool_start" && r["tool"] == "list_folders")
        .collect();
    assert_eq!(
        lf_starts.len(),
        1,
        "expected exactly one list_folders tool_start"
    );
    assert_eq!(
        lf_starts[0]["account"].as_str(),
        Some("readonly"),
        "readonly.list_folders tool_start must record account=\"readonly\": {records:#?}",
    );
    let lf_ends: Vec<&Value> = records
        .iter()
        .filter(|r| r["kind"] == "tool_end" && r["tool"] == "list_folders")
        .collect();
    assert_eq!(
        lf_ends.len(),
        1,
        "expected exactly one list_folders tool_end"
    );
    assert_eq!(
        lf_ends[0]["account"].as_str(),
        Some("readonly"),
        "readonly.list_folders tool_end must record account=\"readonly\": {records:#?}",
    );
    assert_eq!(lf_ends[0]["start_seq"], lf_starts[0]["seq"]);

    // Denial path: move_message pair, account="readonly".
    let mm_starts: Vec<&Value> = records
        .iter()
        .filter(|r| r["kind"] == "tool_start" && r["tool"] == "move_message")
        .collect();
    assert_eq!(
        mm_starts.len(),
        1,
        "expected exactly one move_message tool_start"
    );
    assert_eq!(
        mm_starts[0]["account"].as_str(),
        Some("readonly"),
        "readonly.move_message tool_start must record account=\"readonly\" \
         (not collapsed to None): {records:#?}",
    );
    let mm_ends: Vec<&Value> = records
        .iter()
        .filter(|r| r["kind"] == "tool_end" && r["tool"] == "move_message")
        .collect();
    assert_eq!(
        mm_ends.len(),
        1,
        "expected exactly one move_message tool_end"
    );
    assert_eq!(
        mm_ends[0]["account"].as_str(),
        Some("readonly"),
        "readonly.move_message tool_end must record account=\"readonly\": {records:#?}",
    );
    assert_eq!(mm_ends[0]["start_seq"], mm_starts[0]["seq"]);
}

async fn seed_multipart_message(dovecot: &DovecotHarness) {
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
    ));
    let sink: Arc<dyn rimap_core::auth_sink::AuthEventSink> = Arc::new(audit.clone());
    let conn = Connection::new(cfg, sink, creds);
    conn.append_message("INBOX", &fixtures::multipart_with_attachment(), &[], &[])
        .await
        .expect("APPEND multipart seed");
}
