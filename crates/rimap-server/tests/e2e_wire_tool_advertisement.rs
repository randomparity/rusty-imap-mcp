//! Wire-level advertised-tool-set assertion across all four postures (#459).
//!
//! Audit finding L-21: "denied tools are not advertised" and "allowed
//! tools are dispatchable" was wire-asserted only for `readonly`
//! (`e2e_wire.rs`) and `draft-safe` (`server_capabilities.rs`), and only
//! as *subset* checks (a required tool present, a forbidden tool absent).
//! No single test booted a server per posture and asserted its
//! `tools/list` output against the EXACT advertised set — so a posture
//! that leaked or dropped a tool outside the specific names those subset
//! checks probed would pass silently.
//!
//! This suite parametrizes one wire-driven assertion over every
//! [`Posture`] variant. For each posture it boots the production
//! `rusty-imap-mcp` binary against a single-account config at that posture,
//! walks `tools/list` cursor pagination to collect the complete
//! advertisement, and asserts the collected set equals the exact expected
//! set — infrastructure tools (`use_account`/`list_accounts`, always bare)
//! plus the posture's namespaced (`<account>.<tool>`) mailbox tools.
//!
//! Container-gated. Tool advertisement itself derives purely from
//! posture/config and never inspects mailbox contents, but the server's
//! boot path issues one `LIST "" "*"` per account to discover special-use
//! folders, so a live IMAP server is required to boot at all. Runs against
//! the shared Dovecot harness (one container, all four single-account
//! servers target the same user); silently skips when no container runtime
//! is available, and `RIMAP_REQUIRE_DOCKER=1` flips to loud failure —
//! matching `e2e_wire.rs`. The `e2e_wire_*` binary name keeps this suite
//! inside CI's `binary(/e2e/)` docker-required guard.

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
use rimap_core::posture::Posture;
use wire::{Harness, assert_valid};

// Per-binary dead-code cross-talk: each integration-test binary compiles
// `support/` independently, but items other binaries use appear dead here.
// Workspace lint `clippy::allow_attributes` forbids `#[allow]`, so we
// reference the cross-binary items in a never-called helper — the reference
// itself counts as "use" for dead-code analysis. Mirrors
// `e2e_wire_folder_management.rs::force_use_for_dead_code_link`.
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
const DOVECOT_PASSWORD: &str = "testpass";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_posture_advertises_its_exact_tool_set() {
    let dovecot = match DovecotHarness::try_start() {
        Ok(d) => d,
        Err(HarnessError::DockerUnavailable) => return,
        Err(e) => panic!("Dovecot harness failed: {e}"),
    };
    let fingerprint_hex = dovecot.fingerprint().to_hex();
    let port = dovecot.port();

    // One boot per posture: each asserts that posture's exact advertised
    // set independently, so a failure names the offending posture.
    for posture in Posture::all() {
        assert_posture_advertises_exact(posture, &fingerprint_hex, port).await;
    }
}

/// Boot a single-account server at `posture` against the shared Dovecot
/// harness, collect its complete `tools/list` advertisement across
/// pagination, and assert it equals the exact expected set.
async fn assert_posture_advertises_exact(posture: Posture, fingerprint_hex: &str, port: u16) {
    let tempdir = TempDir::new().expect("tempdir");
    let audit_path = tempdir.path().join("audit.jsonl");
    let download_dir = tempdir.path().join("downloads");
    std::fs::create_dir_all(&download_dir).expect("mkdir download_dir");
    let config_path = tempdir.path().join("config.toml");
    let config = build_posture_config(
        posture,
        fingerprint_hex,
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

    let advertised = collect_all_advertised_tools(&mut harness).await;
    let expected = expected_advertised(posture);
    assert_eq!(
        advertised,
        expected,
        "posture {posture} advertised set mismatch\n  missing: {:?}\n  unexpected: {:?}",
        expected.difference(&advertised).collect::<Vec<_>>(),
        advertised.difference(&expected).collect::<Vec<_>>(),
    );

    let (status, _tempdir_guard) = harness.shutdown_and_wait().await;
    assert!(
        status.success(),
        "binary exited non-zero for posture {posture}: {status:?}",
    );
}

/// The account name for a posture's single-account config. Deliberately
/// NOT the legacy `default` sentinel, so `is_legacy_single_account` is
/// false and tools advertise in the multi-account `<account>.<tool>` form
/// — the production namespacing contract asserted below.
fn account_name(posture: Posture) -> &'static str {
    match posture {
        Posture::Readonly => "readonly",
        Posture::DraftSafe => "draftsafe",
        Posture::Full => "full",
        Posture::Destructive => "destructive",
    }
}

/// The exact set of tool names `tools/list` must advertise at `posture`:
/// the always-present infrastructure tools (bare) plus the posture's
/// mailbox tools in namespaced `<account>.<tool>` form.
///
/// Built cumulatively to mirror the posture hierarchy — each posture is a
/// strict superset of the one below it — and to keep this hardcoded
/// contract auditable: adding a tool to a posture must show up here as a
/// reviewed diff, not slip through silently. Sub-capability tools
/// (`search.advanced_query`, `fetch_message.include_html`,
/// `create_draft.include_html`) are intentionally absent: they share an
/// MCP tool with their parent and are never advertised as standalone
/// entries. `export_messages` is default-deny at every posture and so
/// never appears without an explicit override.
fn expected_advertised(posture: Posture) -> BTreeSet<String> {
    let readonly = [
        "list_folders",
        "search",
        "fetch_message",
        "list_attachments",
        "download_attachment",
        "list_labels",
    ];
    let draft_safe_add = [
        "mark_read",
        "mark_unread",
        "flag",
        "unflag",
        "add_label",
        "remove_label",
        "move_message",
        "create_draft",
    ];
    let full_add = [
        "send_email",
        "forward",
        "delete_message",
        "create_folder",
        "rename_folder",
    ];
    let destructive_add = ["expunge", "delete_folder"];

    let mut bare: Vec<&str> = readonly.to_vec();
    if matches!(
        posture,
        Posture::DraftSafe | Posture::Full | Posture::Destructive
    ) {
        bare.extend_from_slice(&draft_safe_add);
    }
    if matches!(posture, Posture::Full | Posture::Destructive) {
        bare.extend_from_slice(&full_add);
    }
    if matches!(posture, Posture::Destructive) {
        bare.extend_from_slice(&destructive_add);
    }

    let account = account_name(posture);
    let mut expected: BTreeSet<String> = bare
        .iter()
        .map(|tool| format!("{account}.{tool}"))
        .collect();
    // Infrastructure tools are always advertised and never namespaced.
    expected.insert("use_account".to_string());
    expected.insert("list_accounts".to_string());
    expected
}

/// Walk the `tools/list` cursor pagination to completion, returning every
/// advertised tool name across all pages as a set. Mirrors the collector
/// in `e2e_wire_folder_management.rs`: follow `nextCursor` until absent,
/// validating each page against `ListToolsResult` and bounding the walk so
/// a non-advancing cursor fails loudly instead of hanging.
///
/// A single-account catalog fits in one page today, but paginating here
/// keeps the assertion honest if a future tool addition pushes a posture
/// over `TOOLS_PER_PAGE`.
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

/// Build a single-account TOML at `posture` targeting the shared Dovecot
/// user. `full`/`destructive` enable `send_email`, which the config
/// validator requires an `[smtp]` section for; that SMTP transport is
/// never contacted while answering `tools/list` (lettre connects lazily
/// per-send), so its endpoint is inert.
fn build_posture_config(
    posture: Posture,
    fingerprint_hex: &str,
    port: u16,
    audit_path: &std::path::Path,
    allowed_base: &std::path::Path,
    download_dir: &std::path::Path,
) -> String {
    let account = account_name(posture);
    let smtp_section = if matches!(posture, Posture::Full | Posture::Destructive) {
        format!(
            r#"
[accounts.smtp]
host = "127.0.0.1"
port = 587
encryption = "starttls"
username = "{account}@test.invalid"
"#
        )
    } else {
        String::new()
    };

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
name = "{account}"

[accounts.imap]
host = "127.0.0.1"
port = {port}
username = "rimap-test"
encryption = "tls"
tls_fingerprint_sha256 = "{fingerprint_hex}"

[accounts.security]
posture = "{posture}"
{smtp_section}"#,
        audit_path = audit_path.display(),
        allowed_base = allowed_base.display(),
        download_dir = download_dir.display(),
    )
}
