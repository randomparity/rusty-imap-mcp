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
#[path = "support/canary.rs"]
mod canary;
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
use wire::config::{build_dovecot_config, build_dovecot_full_config};
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
const DOVECOT_PASSWORD: &str = canary::DOVECOT_CANARY_PASSWORD;

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

    assert_initial_catalog_infra_only(&mut harness).await;
    let uid = drive_account_scoped_tools(&mut harness, &download_dir).await;
    assert_move_message(&mut harness, uid).await;

    // Bind the returned tempdir guard so the audit file outlives the
    // harness; dropping it before the assertion below would delete the
    // file the test is about to read.
    let (status, tempdir_guard) = harness.shutdown_and_wait().await;
    assert!(status.success(), "binary exited non-zero: {status:?}");
    canary::assert_absent(DOVECOT_PASSWORD, &[tempdir_guard.path()], &[]);

    assert_audit_records(&audit_path);
}

/// Drive the account-scoped tools and return the UID of the seeded message.
async fn drive_account_scoped_tools(harness: &mut Harness, download_dir: &std::path::Path) -> u32 {
    // 1. use_account → draftsafe. This reveals the draftsafe namespace in
    //    tools/list (reveal-on-select, #439).
    let _ = call_tool(harness, "use_account", json!({ "account": "draftsafe" })).await;
    assert_draftsafe_revealed(harness).await;

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

    // 12. create_draft with a sandbox-sourced attachment (#408): the file is
    //     read from the download sandbox, appended to the real Drafts folder,
    //     and the stored message is re-fetched to prove the attachment
    //     round-trips through the IMAP server.
    assert_create_draft_with_attachment(harness, download_dir).await;

    // 13. HTML body requires full posture; the draftsafe account must be
    //     denied at the wire (create_draft.include_html capability gate).
    assert_html_body_denied_at_draftsafe(harness).await;

    uid
}

/// Functional round-trip for a sandbox-sourced attachment (#408): place a file
/// in the download sandbox, create a draft referencing it, then re-fetch the
/// appended draft from Dovecot and assert the attachment is present.
async fn assert_create_draft_with_attachment(
    harness: &mut Harness,
    download_dir: &std::path::Path,
) {
    let payload = b"%PDF-1.4 e2e-wire attachment payload".to_vec();
    let att_path = download_dir.join("e2e-wire-report.pdf");
    std::fs::write(&att_path, &payload).expect("write sandbox attachment");

    let subject = "wire e2e attachment draft";
    let draft = call_tool(
        harness,
        "draftsafe.create_draft",
        json!({
            "to": [{"address": "dest@example.com"}],
            "subject": subject,
            "body_text": "see attached",
            "attachments": [{ "path": att_path.to_str().expect("utf8 path") }],
        }),
    )
    .await;

    // The response meta records the attachment provenance (basename + bytes).
    let meta_atts = draft["meta"]["attachments"]
        .as_array()
        .expect("meta.attachments array");
    assert_eq!(meta_atts.len(), 1, "expected one attachment: {draft}");
    assert_eq!(
        meta_atts[0]["filename"].as_str(),
        Some("e2e-wire-report.pdf"),
    );
    assert_eq!(
        meta_atts[0]["bytes"].as_u64(),
        Some(payload.len() as u64),
        "attachment byte count must match the sandbox file",
    );

    let folder = draft["meta"]["folder"].as_str().expect("draft folder");

    // APPENDUID is optional per server (Dovecot omits it here), so locate the
    // appended draft by subject rather than trusting `meta.uid`.
    let search = call_tool(
        harness,
        "draftsafe.search",
        json!({ "folder": folder, "subject": subject }),
    )
    .await;
    let uid = search["untrusted"]["messages"]
        .as_array()
        .expect("draft search messages")
        .iter()
        .filter_map(|m| m["uid"].as_u64())
        .max()
        .expect("appended draft must be found by subject");

    // Re-fetch the appended draft from the server and confirm the attachment
    // survived the build → APPEND → IMAP store round-trip.
    let listed = call_tool(
        harness,
        "draftsafe.list_attachments",
        json!({ "folder": folder, "uid": uid }),
    )
    .await;
    let attachments = listed["untrusted"]["attachments"]
        .as_array()
        .expect("attachments array");
    assert!(
        attachments
            .iter()
            .any(|a| a["filename"].as_str() == Some("e2e-wire-report.pdf")),
        "attachment not found on the appended draft: {listed}",
    );
}

/// The `create_draft.include_html` capability requires `full` posture, so a
/// `body_html` on the draft-safe account must be denied at the wire — proving
/// the `refine_tool_name` → posture-gate seam end-to-end (#408).
async fn assert_html_body_denied_at_draftsafe(harness: &mut Harness) {
    let resp = harness
        .request(
            "tools/call",
            json!({
                "name": "draftsafe.create_draft",
                "arguments": {
                    "to": [{"address": "dest@example.com"}],
                    "subject": "wire e2e html gate",
                    "body_text": "plain fallback",
                    "body_html": "<p>rich</p>",
                },
            }),
        )
        .await;

    // Posture denial is a tool-execution error: no JSON-RPC error envelope,
    // but the CallToolResult carries isError = true.
    assert!(
        resp["error"].is_null(),
        "posture denial must not be a JSON-RPC error: {resp}",
    );
    assert_eq!(
        resp["result"]["isError"].as_bool(),
        Some(true),
        "draftsafe create_draft with body_html must be denied: {resp}",
    );
}

/// Before any `use_account` selection, a multi-account server advertises
/// only the infrastructure tools (reveal-on-select, #439). Per-posture
/// exact advertised sets are covered by `e2e_wire_tool_advertisement.rs`;
/// the full reveal handshake by `e2e_wire_multi_account_advertisement.rs`.
async fn assert_initial_catalog_infra_only(harness: &mut Harness) {
    let tools_list = harness.request("tools/list", json!({})).await;
    assert_valid(&tools_list["result"], "ListToolsResult");
    let mut names: Vec<String> = tools_list["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .filter_map(|t| t["name"].as_str().map(str::to_string))
        .collect();
    names.sort();
    assert_eq!(
        names,
        vec!["list_accounts".to_string(), "use_account".to_string()],
        "multi-account initial tools/list must advertise infra tools only \
         before use_account (reveal-on-select, #439)",
    );
    assert!(
        tools_list["result"]["nextCursor"].is_null(),
        "infra-only catalog fits one page; unexpected nextCursor",
    );
}

/// After `use_account("draftsafe")`, the catalog reveals the selected
/// account's namespaced tools and no other account's.
async fn assert_draftsafe_revealed(harness: &mut Harness) {
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

    assert!(
        !tools.keys().any(|n| n.starts_with("readonly.")),
        "after selecting draftsafe, no readonly namespace tools may be \
         advertised (reveal-on-select shows only the active account): {:?}",
        tools.keys().collect::<Vec<_>>(),
    );
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

    // Exercise the new `cc` input field. The seeded message has no
    // Cc header (see fixtures.rs::multipart_with_attachment), so this
    // asserts that the wire path round-trips the new field and the
    // IMAP server honors the `CC` SEARCH key (returning zero matches).
    //
    // Coverage caveat: a regression that silently drops the `cc` arg
    // would also produce zero matches (the IMAP query would degrade
    // to ALL on an inbox with one message that doesn't match other
    // criteria). The wire-format direction itself is pinned by the
    // unit tests:
    //   - rimap-server build_query_threads_cc_into_structured_query
    //   - rimap-imap structured_to_key_emits_cc_and_bcc
    // Together those guarantee the field reaches the IMAP key; this
    // e2e check adds proof that Dovecot accepts the resulting
    // command.
    let cc_body = call_tool(
        harness,
        "draftsafe.search",
        json!({ "folder": "INBOX", "cc": "noone@example.com" }),
    )
    .await;
    assert_eq!(
        cc_body["meta"]["total_matched"].as_u64(),
        Some(0),
        "cc filter against unseeded address must yield zero hits: {cc_body}",
    );

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

    assert_initial_catalog_infra_only(&mut harness).await;
    assert_readonly_success_path(&mut harness).await;
    assert_readonly_resource_reports_posture(&mut harness).await;
    assert_static_doc_resources_readable(&mut harness).await;
    assert_readonly_denial(&mut harness).await;

    // Bind the returned tempdir guard so the audit file outlives the
    // harness; dropping it before the assertion below would delete the
    // file the test is about to read.
    let (status, tempdir_guard) = harness.shutdown_and_wait().await;
    assert!(status.success(), "child must exit 0, got {status:?}");
    canary::assert_absent(DOVECOT_PASSWORD, &[tempdir_guard.path()], &[]);

    assert_readonly_audit_records(&audit_path);
}

/// The `rimap://accounts/readonly` resource must report the account's
/// posture over the wire (#406): the instructions promise it, and it is
/// the agent's self-service answer to a posture denial.
async fn assert_readonly_resource_reports_posture(harness: &mut Harness) {
    let resp = harness
        .request(
            "resources/read",
            json!({ "uri": "rimap://accounts/readonly" }),
        )
        .await;
    assert!(
        resp["error"].is_null(),
        "resources/read must succeed, got {resp}",
    );
    let text = resp["result"]["contents"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("resource contents[0].text must be a string, got {resp}"));
    let body: Value = serde_json::from_str(text)
        .unwrap_or_else(|e| panic!("resource body must be JSON: {e}: {text}"));
    assert_eq!(
        body["posture"], "readonly",
        "resource must report the readonly account's posture; got {body}",
    );
    assert_eq!(
        body["name"], "readonly",
        "resource must echo the account name"
    );
}

/// The `rimap://docs/postures` and `rimap://docs/workflows` static
/// resources must both be listed and readable over the wire (#407): the
/// instructions promise both URIs, so a client that follows them must not
/// hit a dead end.
async fn assert_static_doc_resources_readable(harness: &mut Harness) {
    let list = harness.request("resources/list", json!({})).await;
    let uris: Vec<&str> = list["result"]["resources"]
        .as_array()
        .expect("resources array")
        .iter()
        .filter_map(|r| r["uri"].as_str())
        .collect();
    assert!(
        uris.contains(&"rimap://docs/postures"),
        "resources/list must include rimap://docs/postures, got {uris:?}",
    );
    assert!(
        uris.contains(&"rimap://docs/workflows"),
        "resources/list must include rimap://docs/workflows, got {uris:?}",
    );

    for uri in ["rimap://docs/postures", "rimap://docs/workflows"] {
        let resp = harness
            .request("resources/read", json!({ "uri": uri }))
            .await;
        assert!(
            resp["error"].is_null(),
            "resources/read {uri} must succeed, got {resp}",
        );
        let text = resp["result"]["contents"][0]["text"]
            .as_str()
            .unwrap_or_else(|| {
                panic!("resource {uri} contents[0].text must be a string, got {resp}")
            });
        assert!(!text.is_empty(), "resource {uri} content must be non-empty",);
        assert_eq!(
            resp["result"]["contents"][0]["mimeType"], "text/markdown",
            "resource {uri} must advertise text/markdown, got {resp}",
        );
    }
}

/// Verify tools/list advertisement posture for the readonly namespace.
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

/// Posture denial on the wire: a denied tool must return a tool result
/// with `isError: true` (not a JSON-RPC error envelope), carrying the
/// stable `ERR_POSTURE_DENIED` machine code in `structuredContent` and a
/// non-empty message in `content` (#402).
async fn assert_readonly_denial(harness: &mut Harness) {
    // Each case denies under the Readonly posture:
    //  - move_message is not advertised under Readonly.
    //  - refine_tool_name promotes Search -> SearchAdvanced when
    //    `advanced_query` or the `body` content-oracle is set; the
    //    posture matrix denies SearchAdvanced under Readonly. The
    //    TOOL_DEFS check must run on the parsed (parent) name so the
    //    refined name reaches DispatchGuard and is posture-denied rather
    //    than returning RESOURCE_NOT_FOUND (sub-capability dispatch-order
    //    regression net).
    let cases = [
        json!({
            "name": "readonly.move_message",
            "arguments": {"folder": "INBOX", "destination": "Trash", "uid": 1},
        }),
        json!({
            "name": "readonly.search",
            "arguments": {"folder": "INBOX", "advanced_query": "FROM x"},
        }),
        json!({
            "name": "readonly.search",
            "arguments": {"folder": "INBOX", "body": "hello"},
        }),
    ];

    for args in cases {
        let resp = harness.request("tools/call", args.clone()).await;
        assert!(
            resp["error"].is_null(),
            "posture denial must not be a JSON-RPC error envelope; args={args}, got {resp}",
        );
        assert_valid(&resp["result"], "CallToolResult");
        assert_eq!(
            resp["result"]["isError"],
            json!(true),
            "posture denial must be a tool result with isError=true; args={args}, got {resp}",
        );
        assert_eq!(
            resp["result"]["structuredContent"]["error_code"],
            json!("ERR_POSTURE_DENIED"),
            "posture denial must carry the ERR_POSTURE_DENIED code; args={args}, got {resp}",
        );
        assert!(
            resp["result"]["content"][0]["text"]
                .as_str()
                .is_some_and(|t| !t.is_empty()),
            "posture denial result must carry a non-empty message; args={args}, got {resp}",
        );
    }
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

    // Denial path: TWO search.advanced_query pairs, account="readonly".
    // One from advanced_query, one from body — both refine to
    // SearchAdvanced and serialize as "search.advanced_query" in the
    // audit log. Each pair shares start_seq via the dispatch envelope.
    assert_readonly_audit_search_pairs(&records);
}

/// Assert the two `search.advanced_query` audit pairs produced by the
/// readonly denial test (one from `advanced_query`, one from `body` — both
/// refine to `SearchAdvanced` and serialize as `"search.advanced_query"`).
fn assert_readonly_audit_search_pairs(records: &[Value]) {
    let s_starts: Vec<&Value> = records
        .iter()
        .filter(|r| r["kind"] == "tool_start" && r["tool"] == "search.advanced_query")
        .collect();
    assert_eq!(
        s_starts.len(),
        2,
        "expected exactly two search.advanced_query tool_start \
         (advanced_query + body): {records:#?}",
    );
    for s in &s_starts {
        assert_eq!(
            s["account"].as_str(),
            Some("readonly"),
            "readonly.search tool_start must record account=\"readonly\": {records:#?}",
        );
    }
    let s_ends: Vec<&Value> = records
        .iter()
        .filter(|r| r["kind"] == "tool_end" && r["tool"] == "search.advanced_query")
        .collect();
    assert_eq!(
        s_ends.len(),
        2,
        "expected exactly two search.advanced_query tool_end: {records:#?}",
    );
    for e in &s_ends {
        assert_eq!(
            e["account"].as_str(),
            Some("readonly"),
            "readonly.search tool_end must record account=\"readonly\": {records:#?}",
        );
    }
    // Each tool_end's start_seq must match a tool_start's seq.
    let start_seqs: std::collections::HashSet<&Value> =
        s_starts.iter().map(|s| &s["seq"]).collect();
    for e in &s_ends {
        let start_seq = &e["start_seq"];
        assert!(
            start_seqs.contains(start_seq),
            "tool_end start_seq {start_seq} should match a \
             tool_start seq from {start_seqs:?}",
        );
    }
}

async fn seed_multipart_message(dovecot: &DovecotHarness) {
    append_seed_to_inbox(dovecot, &fixtures::multipart_with_attachment()).await;
}

/// APPEND a raw MIME message into the seeded user's INBOX over a
/// short-lived pinned-TLS connection. Shared by the plain-multipart and
/// HTML-alternative seeds so both reference the same connection setup.
async fn append_seed_to_inbox(dovecot: &DovecotHarness, raw: &[u8]) {
    let audit_dir = TempDir::new().expect("seed-audit tempdir");
    let audit = AuditWriter::open(&AuditOptions::new(
        audit_dir.path().join("seed.jsonl"),
        Seq::FIRST,
    ))
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
    conn.append_message("INBOX", raw, &[], &[])
        .await
        .expect("APPEND seed message");
}

/// Full-posture ALLOW round-trips for the two gated sub-capabilities that
/// the draft-safe and readonly suites only ever exercise as denials (#460):
///  - `search.advanced_query` (`SearchAdvanced`), and
///  - `fetch_message.include_html` (`FetchMessageHtml`).
///
/// Both are denied under `draft-safe`/`readonly` (see
/// `wire_e2e_readonly_posture_denial`), so this uses a dedicated single-
/// account `full`-posture config. The seed is a `text/html` message whose
/// HTML body is what makes `include_html` return a non-empty `body_html`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wire_e2e_full_posture_sub_capabilities() {
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

    append_seed_to_inbox(&dovecot, &fixtures::html_body_message()).await;

    let config_path = tempdir.path().join("config.toml");
    let fingerprint_hex = dovecot.fingerprint().to_hex();
    let config = build_dovecot_full_config(
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

    let _ = call_tool(&mut harness, "use_account", json!({ "account": "full" })).await;

    let uid = assert_search_advanced_query_allow(&mut harness).await;
    assert_fetch_message_html_allow(&mut harness, uid).await;

    let (status, tempdir_guard) = harness.shutdown_and_wait().await;
    assert!(status.success(), "binary exited non-zero: {status:?}");
    canary::assert_absent(DOVECOT_PASSWORD, &[tempdir_guard.path()], &[]);
}

/// `search.advanced_query` ALLOW round-trip under `full` posture: a raw
/// IMAP boolean `OR` key (beyond what the structured search API can
/// express) reaches Dovecot and returns the seeded HTML message. Returns
/// its UID for the fetch round-trip.
async fn assert_search_advanced_query_allow(harness: &mut Harness) -> u32 {
    let advanced_query = format!(
        "OR SUBJECT \"{}\" SUBJECT \"totally-absent-subject\"",
        fixtures::HTML_SUBJECT,
    );
    let search_body = call_tool(
        harness,
        "full.search",
        json!({ "folder": "INBOX", "advanced_query": advanced_query }),
    )
    .await;
    let total = search_body["meta"]["total_matched"]
        .as_u64()
        .expect("total_matched");
    assert!(
        total >= 1,
        "advanced_query must match the seeded HTML message, got {total}: {search_body}",
    );
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

/// `fetch_message.include_html` ALLOW round-trip under `full` posture:
/// `include_html = true` returns a sanitized `body_html` carrying the
/// fixture's HTML marker, proving the HTML body round-trips through
/// IMAP FETCH and the content sanitizer.
async fn assert_fetch_message_html_allow(harness: &mut Harness, uid: u32) {
    let fetch_body = call_tool(
        harness,
        "full.fetch_message",
        json!({ "folder": "INBOX", "uid": uid, "include_html": true }),
    )
    .await;
    let body_html = fetch_body["untrusted"]["body_html"]
        .as_str()
        .unwrap_or_else(|| {
            panic!("body_html must be present with include_html=true: {fetch_body}")
        });
    assert!(
        body_html.contains(fixtures::HTML_MARKER),
        "body_html must contain the fixture marker {:?}: {body_html}",
        fixtures::HTML_MARKER,
    );
}
