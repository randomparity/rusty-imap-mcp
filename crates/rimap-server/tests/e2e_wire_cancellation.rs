//! Wire-layer cancellation acceptance (issue #266, Phase 4 §4.4).
//!
//! Race-free assertions only. The audit-layer Drop contract from
//! #71/#99 (`tool_end {status: cancelled}` on Drop) is pinned by the
//! in-process tests at
//! `crates/rimap-server/src/mcp/audit_envelope.rs::tests` and by
//! `tests/dispatch_ticket.rs::drop_during_body_enqueues_cancellation_tool_end`.
//! This file only asserts that the server accepts
//! `notifications/cancelled` without crashing and remains responsive
//! afterwards.
//!
//! Silent-skip on `DockerUnavailable` mirrors the existing repo
//! contract from `e2e_wire.rs`; `RIMAP_REQUIRE_DOCKER=1` flips that to
//! loud failure inside `DovecotHarness::try_start`.

#![expect(clippy::expect_used, reason = "integration tests")]
#![expect(clippy::panic, reason = "test assertions render diagnostics")]

// Each integration-test binary imports only its needed support
// submodules directly to avoid cross-binary dead-code warnings.
#[path = "support/dovecot/mod.rs"]
mod dovecot;
#[path = "support/wire/mod.rs"]
mod wire;

use std::time::Duration;

use rimap_config::credential::PASSWORD_ENV_VAR;
use serde_json::json;
use tempfile::TempDir;

use dovecot::{DovecotHarness, HarnessError};
use wire::config::build_dovecot_config;
use wire::harness::Harness;

// Per-binary dead-code cross-talk: each integration-test binary
// compiles `support/` independently, but items that other binaries
// use appear dead here. Workspace lint `clippy::allow_attributes`
// forbids `#[allow]`, so we reference cross-binary items in a
// never-called helper — the reference itself counts as "use" for
// dead-code analysis. Mirrors `e2e_wire.rs::force_use_for_dead_code_link`.
#[expect(
    dead_code,
    reason = "type-link to items used only by other integration-test binaries"
)]
fn force_use_for_dead_code_link() {
    // Used by mcp_wire_negative, mcp_wire_conformance, mcp_wire_proptest.
    let _ = Harness::spawn;
    // Used by e2e_wire to seed Drafts / Trash mailboxes.
    let _ = DovecotHarness::create_mailbox;
}

/// Dovecot's seeded test password. Matches `e2e_wire.rs`.
const DOVECOT_PASSWORD: &str = "testpass";

/// Hold the spawned `Harness` together with the `DovecotHarness` that
/// owns the underlying container. Dropping the latter tears the
/// container down, so it MUST outlive the `Harness`.
struct CancellationSession {
    harness: Harness,
    /// Held to keep the container alive for the duration of the test.
    /// Dropping `_dovecot` after `harness` lets the child process
    /// finish its TLS teardown before the IMAP listener disappears.
    _dovecot: DovecotHarness,
}

/// Spawn the wire harness against a fresh Dovecot container, walk the
/// `initialize` / `notifications/initialized` / `use_account
/// "draftsafe"` handshake, and return the ready-to-drive session.
/// Returns `None` (silent skip) when the container runtime is absent,
/// matching the contract enforced at `e2e_wire.rs:95-98`.
async fn spawn_with_dovecot() -> Option<CancellationSession> {
    let dovecot = match DovecotHarness::try_start() {
        Ok(d) => d,
        Err(HarnessError::DockerUnavailable) => return None,
        Err(e) => panic!("Dovecot harness failed: {e}"),
    };

    let tempdir = TempDir::new().expect("tempdir");
    let audit_path = tempdir.path().join("audit.jsonl");
    let allowed_base = tempdir.path().to_path_buf();
    let download_dir = tempdir.path().join("downloads");
    std::fs::create_dir_all(&download_dir).expect("mkdir download_dir");

    let fingerprint_hex = dovecot.fingerprint().to_hex();
    let config = build_dovecot_config(
        &fingerprint_hex,
        dovecot.port(),
        &audit_path,
        &allowed_base,
        &download_dir,
    );
    let config_path = tempdir.path().join("config.toml");
    std::fs::write(&config_path, config).expect("write config");

    let envs = [(PASSWORD_ENV_VAR, DOVECOT_PASSWORD)];
    let mut harness = Harness::spawn_with_config(&config_path, tempdir, &envs).await;

    let _init = harness.initialize_handshake().await;
    harness.send_initialized().await;

    // Pin the session to the "draftsafe" account so subsequent tool
    // calls can use the bare `draftsafe.<tool>` namespaced names.
    let use_account = harness
        .request(
            "tools/call",
            json!({ "name": "use_account", "arguments": { "account": "draftsafe" } }),
        )
        .await;
    assert!(
        use_account["error"].is_null(),
        "use_account failed: {use_account}",
    );

    Some(CancellationSession {
        harness,
        _dovecot: dovecot,
    })
}

/// Send a `tools/call` for `draftsafe.search` then immediately a
/// `notifications/cancelled` for that request id. The server must
/// produce ONE response envelope for the cancelled id (race-dependent:
/// result OR error) and remain responsive to a follow-up `tools/list`.
/// No panic, no envelope corruption.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancel_during_inflight_tools_call_keeps_session_alive() {
    let Some(mut session) = spawn_with_dovecot().await else {
        return;
    };

    let search_id = session
        .harness
        .send_request_no_wait(
            "tools/call",
            json!({
                "name": "draftsafe.search",
                "arguments": { "folder": "INBOX", "criteria": "ALL" },
            }),
        )
        .await;

    session
        .harness
        .notify(
            "notifications/cancelled",
            json!({ "requestId": search_id, "reason": "test cancel" }),
        )
        .await;

    let response = session.harness.recv_until_id(search_id).await;
    assert_eq!(response["id"], json!(search_id));
    assert!(
        response.get("result").is_some() || response.get("error").is_some(),
        "expected a result or error envelope for cancelled id, got {response}",
    );

    let list = session.harness.request("tools/list", json!({})).await;
    assert!(
        list["result"].is_object(),
        "server must remain responsive after cancellation, got {list}",
    );
}

/// `notifications/cancelled` for an id that was never issued. The
/// server must accept it silently (no response envelope) and remain
/// responsive to a follow-up `tools/list`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancel_unknown_request_id_is_noop() {
    let Some(mut session) = spawn_with_dovecot().await else {
        return;
    };

    session
        .harness
        .notify(
            "notifications/cancelled",
            json!({ "requestId": 999_999, "reason": "test cancel unknown" }),
        )
        .await;

    session
        .harness
        .assert_no_response_within(Duration::from_millis(200))
        .await;

    let list = session.harness.request("tools/list", json!({})).await;
    assert!(
        list["result"].is_object(),
        "server must remain responsive after no-op cancellation, got {list}",
    );
}
