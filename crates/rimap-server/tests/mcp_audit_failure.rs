//! Audit fail-closed boundary tests (issue #266, Phase 4 §4.3).
//!
//! Arms the production `AuditWriter`'s `force_next_write_failure()`
//! hook via the `test-support`-gated env var
//! `RIMAP_TEST_FORCE_NEXT_AUDIT_WRITE_FAILURE=1`, then exercises
//! the wire. The next audit write — `tool_start` for the first
//! `tools/call` — takes the real lock/append/error-mapping path
//! and fails. The server must respond with an error envelope
//! rather than silently proceeding.
//!
//! The pair `list_accounts_succeeds_when_audit_healthy` (control)
//! and `list_accounts_fails_closed_when_audit_armed` (armed) is
//! the only way to prove the contract: if the env-var hook is
//! never read, the armed test passes when it shouldn't; if the
//! hook fires unconditionally, the control test fails. Both
//! tests passing together is the proof. Phase 4 Codex review
//! finding #1: a single test against a call that ALWAYS fails
//! (e.g. `use_account` on a missing account) is vacuous because
//! the assertion holds whether or not the hook fires.

#![expect(clippy::expect_used, reason = "integration tests")]

#[path = "support/mod.rs"]
mod support;

use serde_json::{Value, json};
use tempfile::TempDir;

use support::wire::harness::Harness;

/// Build a zero-account config TOML with `fail_open = false`.
fn write_zero_account_config(tempdir: &TempDir) -> std::path::PathBuf {
    let config_path = tempdir.path().join("config.toml");
    let audit_path = tempdir.path().join("audit.jsonl");
    let allowed_base = tempdir.path();
    let config = format!(
        r#"
accounts = []

[audit]
path = "{}"
allowed_base_dir = "{}"
fail_open = false
"#,
        audit_path.display(),
        allowed_base.display(),
    );
    std::fs::write(&config_path, &config).expect("write config");
    config_path
}

/// Drive `tools/call list_accounts` against the harness and return
/// the response envelope. Caller asserts on the outcome.
async fn call_list_accounts(harness: &mut Harness) -> Value {
    let _ = harness.initialize_handshake().await;
    harness.send_initialized().await;
    harness
        .request(
            "tools/call",
            json!({
                "name": "list_accounts",
                "arguments": {},
            }),
        )
        .await
}

/// Control case: with the audit-failure hook UNARMED, `tools/call
/// list_accounts` MUST succeed against `accounts = []`. The tool
/// is universally available (it does not require a configured
/// account) and returns an empty list in the zero-account config.
///
/// This case is the proof that the call we use in
/// `list_accounts_fails_closed_when_audit_armed` is healthy by
/// default — without it, that armed test could not distinguish
/// "audit failure caused the rejection" from "the call was
/// already going to fail."
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn list_accounts_succeeds_when_audit_healthy() {
    let tempdir = TempDir::new().expect("tempdir");
    let config_path = write_zero_account_config(&tempdir);

    // No env var: hook does NOT fire.
    let mut harness = Harness::spawn_with_config(&config_path, tempdir, &[]).await;
    let response = call_list_accounts(&mut harness).await;

    assert!(
        response.get("error").is_none(),
        "control: list_accounts must not produce a JSON-RPC error envelope when audit is healthy, got {response}",
    );
    let is_tool_error = response["result"]["isError"].as_bool().unwrap_or(false);
    assert!(
        !is_tool_error,
        "control: list_accounts must not return isError when audit is healthy, got {response}",
    );
}

/// Armed case: with the audit-failure hook ARMED via
/// `RIMAP_TEST_FORCE_NEXT_AUDIT_WRITE_FAILURE=1`, the same
/// `tools/call list_accounts` MUST fail. The next audit write —
/// `tool_start` for this call — takes the real `AuditWriter`
/// lock/append/error-mapping path and surfaces an error to the
/// dispatch envelope, which (with `fail_open = false`) must
/// propagate as a wire-level rejection.
///
/// Paired with `list_accounts_succeeds_when_audit_healthy` above.
/// Both tests must pass; if either fails, the audit-failure
/// boundary is regressed or the hook is broken.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn list_accounts_fails_closed_when_audit_armed() {
    let tempdir = TempDir::new().expect("tempdir");
    let config_path = write_zero_account_config(&tempdir);

    let mut harness = Harness::spawn_with_config(
        &config_path,
        tempdir,
        &[("RIMAP_TEST_FORCE_NEXT_AUDIT_WRITE_FAILURE", "1")],
    )
    .await;
    let response = call_list_accounts(&mut harness).await;

    let is_envelope_error = response.get("error").is_some();
    let is_tool_error = response["result"]["isError"].as_bool().unwrap_or(false);
    assert!(
        is_envelope_error || is_tool_error,
        "armed: list_accounts must fail closed when audit-write is armed to fail, got {response}",
    );
}

/// Initialize handshake must succeed (or fail cleanly) regardless
/// of audit-failure arming. `initialize` doesn't write an audit
/// record by itself, so this test pins that the env-var hook
/// doesn't accidentally break the handshake.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn audit_write_failure_does_not_block_initialize() {
    let tempdir = TempDir::new().expect("tempdir");
    let config_path = write_zero_account_config(&tempdir);

    let mut harness = Harness::spawn_with_config(
        &config_path,
        tempdir,
        &[("RIMAP_TEST_FORCE_NEXT_AUDIT_WRITE_FAILURE", "1")],
    )
    .await;
    let response = harness.initialize_handshake().await;
    assert!(
        response["result"].is_object(),
        "initialize must succeed even with audit failure armed, got {response}",
    );
}
