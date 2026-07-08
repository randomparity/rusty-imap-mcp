//! Wire-level reveal-on-select assertion for multi-account deployments (#439).
//!
//! In a multi-account deployment the initial `tools/list` (before any
//! `use_account` selection) advertises only the infrastructure tools
//! (`use_account`, `list_accounts`); a chosen account's namespaced tools are
//! revealed only after `use_account` selects it. This suite boots a
//! two-account server over the production stdio JSON-RPC wire and asserts
//! that handshake end to end — the two-request client cycle the socket-free
//! unit seam (`build_tool_catalog_for`) cannot observe.
//!
//! Both accounts target the same shared Dovecot user, mirroring how
//! `e2e_wire_tool_advertisement.rs` targets one user across four
//! single-account servers. Tool advertisement derives purely from
//! posture/config and never inspects mailbox contents, but the server's
//! boot path issues one `LIST "" "*"` per account to discover special-use
//! folders, so a live IMAP server is required to boot at all.
//!
//! Container-gated: silently skips when no container runtime is available,
//! and `RIMAP_REQUIRE_DOCKER=1` flips to loud failure — matching
//! `e2e_wire.rs`. The `e2e_wire_*` binary name keeps this suite inside CI's
//! `binary(/e2e/)` docker-required guard.

#![expect(clippy::expect_used, reason = "integration tests")]
#![expect(clippy::panic, reason = "test diagnostics")]

use std::collections::BTreeSet;
use std::time::Duration;

// Each integration-test binary imports only its needed support submodules
// directly to avoid cross-binary dead-code warnings.
#[path = "support/dovecot/mod.rs"]
mod dovecot;
#[path = "support/wire/mod.rs"]
mod wire;

use serde_json::json;
use tempfile::TempDir;

use dovecot::{DovecotHarness, HarnessError};
use rimap_config::credential::PASSWORD_ENV_VAR;
use wire::{Harness, assert_valid};

// Per-binary dead-code cross-talk: each integration-test binary compiles
// `support/` independently, but items other binaries use appear dead here.
// Workspace lint `clippy::allow_attributes` forbids `#[allow]`, so we
// reference the cross-binary items in a never-called helper — the reference
// itself counts as "use" for dead-code analysis. Mirrors
// `e2e_wire_tool_advertisement.rs::force_use_for_dead_code_link`.
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

const DOVECOT_PASSWORD: &str = "testpass";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multi_account_reveals_tools_only_after_use_account() {
    let dovecot = match DovecotHarness::try_start() {
        Ok(d) => d,
        Err(HarnessError::DockerUnavailable) => return,
        Err(e) => panic!("Dovecot harness failed: {e}"),
    };
    let fingerprint_hex = dovecot.fingerprint().to_hex();
    let port = dovecot.port();

    let tempdir = TempDir::new().expect("tempdir");
    let audit_path = tempdir.path().join("audit.jsonl");
    let download_dir = tempdir.path().join("downloads");
    std::fs::create_dir_all(&download_dir).expect("mkdir download_dir");
    let config_path = tempdir.path().join("config.toml");
    let config = build_two_account_config(
        &fingerprint_hex,
        port,
        &audit_path,
        tempdir.path(),
        &download_dir,
    );
    std::fs::write(&config_path, config).expect("write config");

    let envs = [(PASSWORD_ENV_VAR, DOVECOT_PASSWORD)];
    let mut harness = Harness::spawn_with_config(&config_path, tempdir, &envs).await;

    let init = harness.initialize_handshake().await;
    assert_valid(&init["result"], "InitializeResult");
    harness.send_initialized().await;

    // Before any selection: infra tools ONLY, exactly.
    let infra_only = collect_all_advertised_tools(&mut harness).await;
    let expected_infra: BTreeSet<String> = ["use_account", "list_accounts"]
        .into_iter()
        .map(String::from)
        .collect();
    assert_eq!(
        infra_only, expected_infra,
        "multi-account initial tools/list must advertise infra tools only \
         (reveal-on-select); got {infra_only:?}",
    );

    // Select `work`.
    let resp = harness
        .request(
            "tools/call",
            json!({ "name": "use_account", "arguments": { "account": "work" } }),
        )
        .await;
    assert!(resp["error"].is_null(), "use_account failed: {resp}");
    assert_valid(&resp["result"], "CallToolResult");
    assert_ne!(
        resp["result"]["isError"].as_bool(),
        Some(true),
        "use_account returned isError: {resp}",
    );

    // After selection: `work.*` revealed, `personal.*` still hidden, infra
    // tools still present, and the set strictly grew.
    let after = collect_all_advertised_tools(&mut harness).await;
    assert!(
        after.len() > infra_only.len(),
        "advertised set must strictly grow after use_account; before={infra_only:?} after={after:?}",
    );
    assert!(
        after.is_superset(&expected_infra),
        "infra tools must remain advertised after use_account; got {after:?}",
    );
    assert!(
        after.iter().any(|n| n.starts_with("work.")),
        "selected account's namespaced tools must be revealed; got {after:?}",
    );
    assert!(
        !after.iter().any(|n| n.starts_with("personal.")),
        "non-selected account's tools must stay hidden; got {after:?}",
    );

    let (status, _tempdir_guard) = harness.shutdown_and_wait().await;
    assert!(status.success(), "binary exited non-zero: {status:?}");
}

/// Walk the `tools/list` cursor pagination to completion, returning every
/// advertised tool name across all pages as a set. Mirrors the collector in
/// `e2e_wire_tool_advertisement.rs`: follow `nextCursor` until absent,
/// validating each page and bounding the walk so a non-advancing cursor
/// fails loudly instead of hanging.
async fn collect_all_advertised_tools(harness: &mut Harness) -> BTreeSet<String> {
    const MAX_PAGES: usize = 100;
    let mut names = BTreeSet::new();
    let mut seen_cursors: BTreeSet<String> = BTreeSet::new();
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
                assert!(
                    names.insert(name.to_string()),
                    "tools/list advertised {name:?} more than once across pages",
                );
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

/// Build a two-account (`work`, `personal`) TOML at `draft-safe`, both
/// targeting the shared Dovecot user. Draft-safe advertises mailbox tools
/// without needing an `[smtp]` section (no `send_email`).
fn build_two_account_config(
    fingerprint_hex: &str,
    port: u16,
    audit_path: &std::path::Path,
    allowed_base: &std::path::Path,
    download_dir: &std::path::Path,
) -> String {
    format!(
        r#"
[audit]
path = "{audit_path}"
allowed_base_dir = "{allowed_base}"

[attachments]
download_dir = "{download_dir}"

[defaults.credentials]
fallback = "keyring-then-env"

[[accounts]]
name = "work"

[accounts.imap]
host = "127.0.0.1"
port = {port}
username = "rimap-test"
encryption = "tls"
tls_fingerprint_sha256 = "{fingerprint_hex}"

[accounts.security]
posture = "draft-safe"

[[accounts]]
name = "personal"

[accounts.imap]
host = "127.0.0.1"
port = {port}
username = "rimap-test"
encryption = "tls"
tls_fingerprint_sha256 = "{fingerprint_hex}"

[accounts.security]
posture = "draft-safe"
"#,
        audit_path = audit_path.display(),
        allowed_base = allowed_base.display(),
        download_dir = download_dir.display(),
    )
}
