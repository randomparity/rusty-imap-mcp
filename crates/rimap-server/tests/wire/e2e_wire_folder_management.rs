//! Folder-management wire-driven Dovecot e2e (#456). Companion to
//! `e2e_wire.rs` and `e2e_wire_destructive.rs`, covering the three
//! folder-mutation handlers that had no end-to-end test before this
//! suite: `create_folder`, `rename_folder`, and `delete_folder`.
//!
//! Audit finding H-4c: only the protected-folder rejection was
//! unit-tested (`folder_management.rs`); no test drove the handlers
//! against a live server. This suite exercises, over the production
//! stdio JSON-RPC wire against a Dovecot container:
//!
//!   1. The create -> rename -> delete round-trip, with a `list_folders`
//!      call after each mutation asserting the listing reflects it.
//!   2. The folder-guard denials on the destructive account:
//!      - `create_folder`/`rename_folder`/`delete_folder` on a protected
//!        folder (INBOX / Sent) -> `ERR_PROTECTED_FOLDER`.
//!      - `delete_folder` on a folder outside the expunge allowlist ->
//!        `ERR_EXPUNGE_DENIED` (the same allowlist that gates `expunge`
//!        gates folder deletion).
//!   3. The posture boundary on the `full` account: `create_folder` and
//!      `rename_folder` are advertised (full+), but `delete_folder`
//!      (destructive-only) is not, and calling it is refused with
//!      `ERR_POSTURE_DENIED`.
//!
//! Silent-skip when no container runtime is available;
//! `RIMAP_REQUIRE_DOCKER=1` flips to loud failure, matching `e2e_wire.rs`.

#![expect(clippy::expect_used, reason = "integration tests")]
#![expect(clippy::panic, reason = "test diagnostics")]

// Each integration-test binary imports only its needed support
// submodules directly to avoid cross-binary dead-code warnings.
#[path = "../support/canary.rs"]
mod canary;
#[path = "../support/dovecot/mod.rs"]
mod dovecot;
#[path = "../support/wire/mod.rs"]
mod wire;

use std::time::Duration;

use serde_json::{Value, json};
use tempfile::TempDir;

use dovecot::{DovecotHarness, HarnessError};
use rimap_config::credential::PASSWORD_ENV_VAR;
use wire::config::build_dovecot_folder_config;
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
    let _ = DovecotHarness::create_mailbox;
    let _ = DovecotHarness::delete_mailbox;
}

/// Dovecot's seeded test password. Matches `e2e_wire.rs`.
const DOVECOT_PASSWORD: &str = canary::DOVECOT_CANARY_PASSWORD;

/// Folder created in step 1 of the round-trip. Not protected and not
/// expunge-allowlisted, so it can be created but not directly deleted.
const SRC_FOLDER: &str = "e2e-folder-src";

/// Folder the round-trip renames into and then deletes. MUST match the
/// single entry in `expunge_folders` in `build_dovecot_folder_config`,
/// because `delete_folder` runs `check_expunge` after `check_protected`.
const DST_FOLDER: &str = "e2e-folder-dst";

/// A never-created, never-allowlisted folder used to prove `delete_folder`
/// honors the expunge allowlist. The folder guard rejects it before any
/// IMAP traffic, so it need not exist on the server.
const ORPHAN_FOLDER: &str = "e2e-folder-orphan";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wire_e2e_folder_create_rename_delete() {
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
    let config = build_dovecot_folder_config(
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

    assert_folder_tools_advertised(&mut harness).await;

    assert_create_rename_delete_round_trip(&mut harness).await;
    assert_protected_folder_guards(&mut harness).await;
    assert_delete_folder_honors_expunge_allowlist(&mut harness).await;
    assert_full_posture_denies_delete_folder(&mut harness).await;

    // Bind the returned tempdir guard so the audit file outlives the
    // harness; dropping it before the assertion below would delete the
    // file the test is about to read.
    let (status, tempdir_guard) = harness.shutdown_and_wait().await;
    assert!(status.success(), "binary exited non-zero: {status:?}");
    canary::assert_absent(DOVECOT_PASSWORD, &[tempdir_guard.path()], &[]);

    assert_folder_audit_records(&audit_path);
}

/// Before any `use_account` selection, a multi-account server advertises
/// only the infrastructure tools (reveal-on-select, #439) — the per-account
/// namespaced folder tools are revealed after selection. The per-posture
/// exact advertised sets (e.g. that a `full` account advertises
/// `create_folder`/`rename_folder` but not `delete_folder`, while a
/// `destructive` account advertises all three) are covered by
/// `e2e_wire_tool_advertisement.rs`; the reveal handshake by
/// `e2e_wire_multi_account_advertisement.rs`. Every namespaced folder tool
/// this test drives stays dispatchable by `<account>.<tool>` regardless of
/// the active selection, so no `use_account` is needed for the steps below.
async fn assert_folder_tools_advertised(harness: &mut Harness) {
    let names = collect_all_advertised_tools(harness).await;
    let mut names_sorted = names.clone();
    names_sorted.sort();
    assert_eq!(
        names_sorted,
        vec!["list_accounts".to_string(), "use_account".to_string()],
        "multi-account initial tools/list must advertise infra tools only \
         before use_account (reveal-on-select, #439); got {names:?}",
    );
}

/// Walk the `tools/list` cursor pagination to completion, returning every
/// advertised tool name across all pages. A well-behaved client follows
/// `nextCursor` until it is absent; each page validates against
/// `ListToolsResult`.
async fn collect_all_advertised_tools(harness: &mut Harness) -> Vec<String> {
    // Bound the walk so a server-side pagination regression — a repeating
    // or non-advancing `nextCursor` — fails loudly here instead of hanging
    // the suite until a CI timeout. The two-account catalog spans a handful
    // of 25-tool pages; 100 is a generous ceiling.
    const MAX_PAGES: usize = 100;
    let mut names = Vec::new();
    let mut seen_cursors: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut cursor: Option<String> = None;
    for _ in 0..MAX_PAGES {
        let params = match &cursor {
            Some(c) => json!({ "cursor": c }),
            None => json!({}),
        };
        let resp = harness.request("tools/list", params).await;
        assert_valid(&resp["result"], "ListToolsResult");
        for tool in resp["result"]["tools"].as_array().expect("tools array") {
            if let Some(name) = tool["name"].as_str() {
                names.push(name.to_string());
            }
        }
        match resp["result"]["nextCursor"].as_str() {
            Some(next) => {
                assert!(
                    seen_cursors.insert(next.to_string()),
                    "tools/list returned a repeating cursor {next:?}; pagination is not advancing",
                );
                cursor = Some(next.to_string());
            }
            None => return names,
        }
    }
    panic!("tools/list pagination did not terminate within {MAX_PAGES} pages");
}

/// The create -> rename -> delete round-trip, asserting the response meta
/// of each mutation and that `list_folders` reflects it.
async fn assert_create_rename_delete_round_trip(harness: &mut Harness) {
    assert!(
        !folder_listed(harness, SRC_FOLDER).await,
        "{SRC_FOLDER} must not exist before the round-trip",
    );

    let created = call_tool(
        harness,
        "destructive.create_folder",
        json!({ "folder": SRC_FOLDER }),
    )
    .await;
    assert_eq!(created["meta"]["created"], json!(true), "meta: {created}");
    assert_eq!(
        created["meta"]["folder"].as_str(),
        Some(SRC_FOLDER),
        "create meta.folder must echo the created folder: {created}",
    );
    assert!(
        folder_listed(harness, SRC_FOLDER).await,
        "list_folders must show {SRC_FOLDER} after create_folder",
    );

    let renamed = call_tool(
        harness,
        "destructive.rename_folder",
        json!({ "folder": SRC_FOLDER, "new_folder": DST_FOLDER }),
    )
    .await;
    assert_eq!(renamed["meta"]["renamed"], json!(true), "meta: {renamed}");
    assert_eq!(
        renamed["meta"]["old_folder"].as_str(),
        Some(SRC_FOLDER),
        "rename meta.old_folder must echo the source: {renamed}",
    );
    assert_eq!(
        renamed["meta"]["new_folder"].as_str(),
        Some(DST_FOLDER),
        "rename meta.new_folder must echo the destination: {renamed}",
    );
    assert!(
        folder_listed(harness, DST_FOLDER).await,
        "list_folders must show {DST_FOLDER} after rename_folder",
    );
    assert!(
        !folder_listed(harness, SRC_FOLDER).await,
        "rename must remove {SRC_FOLDER} from the listing",
    );

    let deleted = call_tool(
        harness,
        "destructive.delete_folder",
        json!({ "folder": DST_FOLDER }),
    )
    .await;
    assert_eq!(deleted["meta"]["deleted"], json!(true), "meta: {deleted}");
    assert_eq!(
        deleted["meta"]["folder"].as_str(),
        Some(DST_FOLDER),
        "delete meta.folder must echo the deleted folder: {deleted}",
    );
    assert_eq!(
        deleted["meta"]["message_count"].as_u64(),
        Some(0),
        "the freshly-created empty folder must report zero messages: {deleted}",
    );
    assert!(
        !folder_listed(harness, DST_FOLDER).await,
        "list_folders must not show {DST_FOLDER} after delete_folder",
    );
}

/// Each mutation refuses a protected folder before any IMAP traffic, with
/// `isError: true` and `ERR_PROTECTED_FOLDER` — a tool-execution error,
/// not a JSON-RPC error envelope. `rename_folder` guards both the source
/// and the destination name, so a protected destination is enough.
async fn assert_protected_folder_guards(harness: &mut Harness) {
    let cases = [
        json!({ "name": "destructive.create_folder", "arguments": { "folder": "INBOX" } }),
        json!({
            "name": "destructive.rename_folder",
            "arguments": { "folder": SRC_FOLDER, "new_folder": "Sent" },
        }),
        json!({ "name": "destructive.delete_folder", "arguments": { "folder": "INBOX" } }),
    ];
    for args in cases {
        assert_tool_error(harness, args, "ERR_PROTECTED_FOLDER").await;
    }
}

/// `delete_folder` runs the expunge allowlist guard: a folder that is
/// neither protected nor allowlisted is refused with `ERR_EXPUNGE_DENIED`.
/// The guard fires before IMAP, so the orphan folder need not exist.
async fn assert_delete_folder_honors_expunge_allowlist(harness: &mut Harness) {
    let args = json!({
        "name": "destructive.delete_folder",
        "arguments": { "folder": ORPHAN_FOLDER },
    });
    assert_tool_error(harness, args, "ERR_EXPUNGE_DENIED").await;
}

/// `delete_folder` requires the destructive posture. On the `full`
/// account it is refused at the dispatch gate with `ERR_POSTURE_DENIED`,
/// before the handler — and never reaches the folder guard.
async fn assert_full_posture_denies_delete_folder(harness: &mut Harness) {
    let args = json!({
        "name": "full.delete_folder",
        "arguments": { "folder": ORPHAN_FOLDER },
    });
    assert_tool_error(harness, args, "ERR_POSTURE_DENIED").await;
}

/// Call `list_folders` on the destructive account and report whether the
/// listing contains a folder whose sanitized name equals `name`.
async fn folder_listed(harness: &mut Harness, name: &str) -> bool {
    let body = call_tool(harness, "destructive.list_folders", json!({})).await;
    body["meta"]["folders"]
        .as_array()
        .expect("list_folders meta.folders array")
        .iter()
        .filter_map(|f| f["name"].as_str())
        .any(|n| n == name)
}

/// Assert a `tools/call` is refused as a tool-execution error (`isError:
/// true`, not a JSON-RPC error envelope) carrying `expected_code` in
/// `structuredContent.error_code` and a non-empty message in `content`.
async fn assert_tool_error(harness: &mut Harness, args: Value, expected_code: &str) {
    let resp = harness.request("tools/call", args.clone()).await;
    assert!(
        resp["error"].is_null(),
        "denial must not be a JSON-RPC error envelope; args={args}, got {resp}",
    );
    assert_valid(&resp["result"], "CallToolResult");
    assert_eq!(
        resp["result"]["isError"],
        json!(true),
        "call must be denied; args={args}, got {resp}",
    );
    assert_eq!(
        resp["result"]["structuredContent"]["error_code"],
        json!(expected_code),
        "denial must carry {expected_code}; args={args}, got {resp}",
    );
    assert!(
        resp["result"]["content"][0]["text"]
            .as_str()
            .is_some_and(|t| !t.is_empty()),
        "denial must carry a non-empty message; args={args}, got {resp}",
    );
}

/// Invoke `tools/call` on a successful path and validate the response
/// against the envelope schema, `CallToolResult`, and the per-tool
/// response schema fixture.
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
/// cache. Only the tools this suite exercises on a success path are
/// listed; a new tool added without a schema fixture mapping panics.
fn static_tool_name(bare: &str) -> &'static str {
    match bare {
        "list_folders" => "list_folders",
        "create_folder" => "create_folder",
        "rename_folder" => "rename_folder",
        "delete_folder" => "delete_folder",
        other => panic!("no schema fixture mapping for tool: {other}"),
    }
}

/// Assert the audit log paired every folder-mutation handler execution,
/// each attributed to the expected account.
///
/// Destructive account:
///
///   - `create_folder`: 2 (SRC success + INBOX denial).
///   - `rename_folder`: 2 (SRC->DST success + Sent-destination denial).
///   - `delete_folder`: 3 (DST success + INBOX denial + orphan
///     expunge-denied).
///   - `list_folders`: 5 (one before the round-trip; one after create;
///     two after rename — DST present, SRC gone; one after delete).
///
/// Full account:
///
///   - `delete_folder`: 1 (posture denial). A dispatch-gate denial still
///     pairs a `tool_start` with a `tool_end`.
fn assert_folder_audit_records(audit_path: &std::path::Path) {
    let records = read_audit_records(audit_path);
    // Each expected outcome is one paired call's recorded `(status,
    // error_code)`, matched order-independently against the `tool_end`
    // records — so this proves the on-disk attribution of success vs. the
    // specific denial code, not just the wire response.
    let ok = ("ok", None);
    assert_paired_tool(
        &records,
        "create_folder",
        "destructive",
        &[ok, ("error", Some("ERR_PROTECTED_FOLDER"))],
    );
    assert_paired_tool(
        &records,
        "rename_folder",
        "destructive",
        &[ok, ("error", Some("ERR_PROTECTED_FOLDER"))],
    );
    assert_paired_tool(
        &records,
        "delete_folder",
        "destructive",
        &[
            ok,
            ("error", Some("ERR_PROTECTED_FOLDER")),
            ("error", Some("ERR_EXPUNGE_DENIED")),
        ],
    );
    assert_paired_tool(
        &records,
        "list_folders",
        "destructive",
        &[ok, ok, ok, ok, ok],
    );
    assert_paired_tool(
        &records,
        "delete_folder",
        "full",
        &[("error", Some("ERR_POSTURE_DENIED"))],
    );
}

/// Assert the `tool_start` / `tool_end` records for `tool` on `account`
/// match `expected_outcomes` — one entry per paired call. Beyond the bare
/// counts this verifies:
///   - a one-to-one bijection between starts and ends (the multiset of
///     `tool_end.start_seq` equals the multiset of `tool_start.seq`), so a
///     duplicated or dropped `tool_end` cannot pass;
///   - each `tool_end`'s recorded `(status, error_code)` outcome;
///   - account attribution on both halves (via the filter).
///
/// Filtering by account is required because `delete_folder` is dispatched
/// on both the `destructive` and `full` accounts.
fn assert_paired_tool(
    records: &[Value],
    tool: &str,
    account: &str,
    expected_outcomes: &[(&str, Option<&str>)],
) {
    let matches = |r: &&Value, kind: &str| {
        r["kind"] == kind && r["tool"] == tool && r["account"].as_str() == Some(account)
    };
    let starts: Vec<&Value> = records
        .iter()
        .filter(|r| matches(r, "tool_start"))
        .collect();
    let ends: Vec<&Value> = records.iter().filter(|r| matches(r, "tool_end")).collect();
    let expected = expected_outcomes.len();
    assert_eq!(
        starts.len(),
        expected,
        "expected {expected} {tool} tool_start for {account}: {records:#?}",
    );
    assert_eq!(
        ends.len(),
        expected,
        "expected {expected} {tool} tool_end for {account}: {records:#?}",
    );

    // One-to-one pairing: each `tool_start.seq` is consumed by exactly one
    // `tool_end.start_seq`. Comparing the two as sorted multisets rejects a
    // duplicated end (which set membership alone would accept).
    let mut start_seqs: Vec<String> = starts.iter().map(|s| s["seq"].to_string()).collect();
    let mut end_refs: Vec<String> = ends.iter().map(|e| e["start_seq"].to_string()).collect();
    start_seqs.sort();
    end_refs.sort();
    assert_eq!(
        start_seqs, end_refs,
        "{tool}/{account} tool_end.start_seq set must equal the tool_start.seq set \
         one-to-one: {records:#?}",
    );

    // Recorded outcomes, compared order-independently.
    let mut actual: Vec<String> = ends.iter().map(|e| outcome_key(e)).collect();
    let mut want: Vec<String> = expected_outcomes
        .iter()
        .map(|(status, code)| encode_outcome(status, *code))
        .collect();
    actual.sort();
    want.sort();
    assert_eq!(
        actual, want,
        "{tool}/{account} tool_end outcomes must match expected: {records:#?}",
    );
}

/// Encode a `tool_end` record's recorded `(status, error_code)` as a
/// comparable key. A successful call carries `status = "ok"` and a null
/// `error_code`; a denial carries `status = "error"` and the stable code.
fn outcome_key(end: &Value) -> String {
    let status = end["status"].as_str().expect("tool_end.status");
    encode_outcome(status, end["error_code"].as_str())
}

/// Canonical string form of a `(status, error_code)` outcome, used to
/// compare recorded and expected outcomes as order-independent multisets.
fn encode_outcome(status: &str, code: Option<&str>) -> String {
    match code {
        Some(c) => format!("{status}:{c}"),
        None => format!("{status}:-"),
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
