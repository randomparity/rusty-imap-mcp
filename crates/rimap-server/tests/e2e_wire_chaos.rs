//! Network-chaos wire-driven e2e (#522). Interposes Toxiproxy between the
//! `rusty-imap-mcp` binary and the Dovecot fixture to exercise degraded-but-alive
//! network conditions — delayed greeting, mid-FETCH stall, RST during STARTTLS,
//! byte-trickle — asserting the typed `ERR_*` wire code, the audit record, and
//! post-fault recovery with no wedged session/breaker.
//!
//! Nightly-only: gated behind `RIMAP_CHAOS=1` so the suite silent-skips on PR CI
//! (which sweeps `binary(/e2e/)` under `RIMAP_REQUIRE_DOCKER=1` but never sets
//! `RIMAP_CHAOS`). See
//! `docs/superpowers/specs/2026-07-09-issue-522-wire-chaos-design.md`.

#![expect(clippy::expect_used, reason = "integration tests")]

use std::path::Path;
use std::time::Duration;

use rimap_config::credential::PASSWORD_ENV_VAR;
use serde_json::{Value, json};
use tempfile::TempDir;

#[path = "support/chaos/mod.rs"]
mod chaos;
#[path = "support/wire/mod.rs"]
mod wire;

use chaos::{ChaosHarness, ChaosSkip, audit};
use wire::{Harness, assert_valid};

/// Dovecot's seeded test password (matches `e2e_wire.rs`).
const DOVECOT_PASSWORD: &str = "testpass";

/// A `max_fetch_body_bytes` comfortably above any fixture (25 MiB).
const ROOMY_FETCH: u64 = 26_214_400;
/// A `max_append_bytes` comfortably above the largest seed body (25 MiB).
const ROOMY_APPEND: u64 = 26_214_400;

// PERMANENT dead-code link. Each e2e binary compiles support/chaos
// independently, so every public accessor a given scenario does not call appears
// dead under -D warnings. Referencing them here counts as "use". Mirrors
// e2e_wire_fault_injection.rs::force_use_for_dead_code_link. Keep permanently.
#[expect(
    dead_code,
    reason = "cross-boundary dead-code link for support/chaos items"
)]
fn force_use_for_dead_code_link() {
    let _ = ChaosHarness::imaps_port;
    let _ = ChaosHarness::starttls_port;
    let _ = ChaosHarness::fingerprint;
    let _ = ChaosHarness::toxics;
    let _ = chaos::ToxiproxyControl::add_toxic;
    let _ = chaos::ToxiproxyControl::reset;
    let _: fn() -> _ = || ChaosSkip::Disabled;
    let _: fn() -> _ = || ChaosSkip::DockerUnavailable;
}

/// Emit a per-scenario run marker to stderr. The nightly workflow asserts each of
/// `scenario1`..`scenario4b` is present so a silently skipped scenario cannot pass
/// vacuously green.
#[expect(
    clippy::print_stderr,
    reason = "run marker for the nightly vacuous-green guard"
)]
fn mark_ran(scenario: &str) {
    eprintln!("RIMAP_CHAOS_RAN {scenario}");
}

/// Chaos account TOML params. A struct (not 10 positional args) — clippy's
/// `too_many_arguments` default threshold is 7 and the repo caps positional
/// params at 5.
struct ChaosConfigParams<'a> {
    fingerprint_hex: &'a str,
    port: u16,
    /// "tls" (imaps/993 proxy) or "starttls" (143 proxy).
    encryption: &'a str,
    connect_timeout_seconds: u32,
    command_timeout_seconds: u32,
    max_fetch_body_bytes: u64,
    max_append_bytes: u64,
    audit_path: &'a Path,
    allowed_base: &'a Path,
    download_dir: &'a Path,
}

fn build_chaos_config(p: &ChaosConfigParams<'_>) -> String {
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
name = "chaos"

[accounts.imap]
host = "127.0.0.1"
port = {port}
username = "rimap-test"
encryption = "{encryption}"
tls_fingerprint_sha256 = "{fingerprint_hex}"
connect_timeout_seconds = {connect_timeout_seconds}
command_timeout_seconds = {command_timeout_seconds}

[accounts.security]
posture = "draft-safe"

[accounts.limits]
max_fetch_body_bytes = {max_fetch_body_bytes}
max_append_bytes = {max_append_bytes}
"#,
        audit_path = p.audit_path.display(),
        allowed_base = p.allowed_base.display(),
        download_dir = p.download_dir.display(),
        port = p.port,
        encryption = p.encryption,
        fingerprint_hex = p.fingerprint_hex,
        connect_timeout_seconds = p.connect_timeout_seconds,
        command_timeout_seconds = p.command_timeout_seconds,
        max_fetch_body_bytes = p.max_fetch_body_bytes,
        max_append_bytes = p.max_append_bytes,
    )
}

/// Spawn the server against the given proxy `port` + `encryption` with
/// per-scenario timeout budgets, and complete the MCP handshake. The returned
/// `Harness` owns the tempdir; its `audit_path()` is `<tempdir>/audit.jsonl`.
async fn spawn_ready(
    chaos: &ChaosHarness,
    port: u16,
    encryption: &str,
    connect_timeout_seconds: u32,
    command_timeout_seconds: u32,
    max_fetch_body_bytes: u64,
    max_append_bytes: u64,
) -> Harness {
    let tempdir = TempDir::new().expect("tempdir");
    let audit_path = tempdir.path().join("audit.jsonl");
    let allowed_base = tempdir.path().to_path_buf();
    let download_dir = tempdir.path().join("downloads");
    std::fs::create_dir_all(&download_dir).expect("mkdir download_dir");

    let config_path = tempdir.path().join("config.toml");
    let fingerprint_hex = chaos.fingerprint().to_hex();
    let config = build_chaos_config(&ChaosConfigParams {
        fingerprint_hex: &fingerprint_hex,
        port,
        encryption,
        connect_timeout_seconds,
        command_timeout_seconds,
        max_fetch_body_bytes,
        max_append_bytes,
        audit_path: &audit_path,
        allowed_base: &allowed_base,
        download_dir: &download_dir,
    });
    std::fs::write(&config_path, config).expect("write config");

    let envs = [(PASSWORD_ENV_VAR, DOVECOT_PASSWORD)];
    let mut harness = Harness::spawn_with_config(&config_path, tempdir, &envs).await;
    let _ = harness.initialize_handshake().await;
    harness.send_initialized().await;
    harness
}

/// Assert a `tools/call` response is a tool-execution error whose
/// `structuredContent.error_code` equals `expected_code`. Mirrors
/// `e2e_wire_fault_injection.rs::assert_error_code`.
fn assert_error_code(resp: &Value, expected_code: &str) {
    assert!(
        resp["error"].is_null(),
        "tool-execution failure must not be a JSON-RPC error envelope; got {resp}",
    );
    assert_valid(&resp["result"], "CallToolResult");
    assert_eq!(
        resp["result"]["isError"],
        json!(true),
        "fault must surface as a tool result with isError=true; got {resp}",
    );
    assert_eq!(
        resp["result"]["structuredContent"]["error_code"],
        json!(expected_code),
        "fault must carry {expected_code} through dispatch; got {resp}",
    );
    assert!(
        resp["result"]["content"][0]["text"]
            .as_str()
            .is_some_and(|t| !t.is_empty()),
        "fault result must carry a non-empty message; got {resp}",
    );
}

/// Assert a `tools/call` response succeeded (recovery calls).
fn assert_ok(resp: &Value, context: &str) {
    assert!(
        resp["error"].is_null() && resp["result"]["isError"] == json!(false),
        "{context} must succeed; got {resp}",
    );
}

/// Scenario 1 — a greeting delayed past `connect_timeout` surfaces `ERR_TIMEOUT`
/// on a RECONNECT. The server requires a healthy connect at boot (special-use
/// folder discovery is fatal-on-failure), so the greeting stall is exercised on a
/// reconnect after a healthy boot, routed through the STARTTLS proxy (143) where
/// the plaintext greeting is read before TLS. The reconnect emits an `auth`
/// Failure with `error_code=Timeout` (per-step connect timeout returns an `Err`
/// that reaches `connect_inner`'s emit — established against the source), which a
/// command timeout on the live session does not, so it specifically evidences the
/// greeting-on-connect stall.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn chaos_delayed_greeting_times_out() {
    let Ok(chaos) = ChaosHarness::try_start() else {
        return;
    };
    mark_ran("scenario1");

    // The server REQUIRES a healthy IMAP connect at boot (special-use folder
    // discovery is fatal-on-failure), so a connect-phase greeting stall can only
    // be exercised on a RECONNECT. Boot healthy on the STARTTLS path with tight
    // budgets, then degrade the network: op #1's command stalls (command_timeout
    // → ERR_TIMEOUT, session invalidated); op #2 reconnects and its plaintext
    // greeting is blocked (connect_timeout → ERR_TIMEOUT + an `auth` Failure —
    // the delayed-greeting-on-connect fault). connect==command==1s so both trip
    // fast; the wire deadline (15s) comfortably exceeds them.
    let mut h = spawn_ready(
        &chaos,
        chaos.starttls_port(),
        "starttls",
        1,
        1,
        ROOMY_FETCH,
        ROOMY_APPEND,
    )
    .await;
    let audit_path = h.audit_path();

    chaos.toxics().add_toxic(
        "starttls",
        &json!({ "type": "timeout", "stream": "downstream", "attributes": { "timeout": 0 } }),
    );

    // Op #1: command on the established session stalls → ERR_TIMEOUT, invalidated.
    let r1 = h
        .request_within(
            "tools/call",
            json!({ "name": "chaos.list_folders", "arguments": {} }),
            Duration::from_secs(15),
        )
        .await;
    assert_error_code(&r1, "ERR_TIMEOUT");

    // Op #2: session invalidated → reconnect → greeting blocked → connect_timeout
    // → ERR_TIMEOUT, and the reconnect emits an `auth` Failure (the greeting stall).
    let r2 = h
        .request_within(
            "tools/call",
            json!({ "name": "chaos.list_folders", "arguments": {} }),
            Duration::from_secs(15),
        )
        .await;
    assert_error_code(&r2, "ERR_TIMEOUT");

    // Recovery: remove toxic → reconnect succeeds.
    chaos.toxics().reset();
    let ok = h
        .request_within(
            "tools/call",
            json!({ "name": "chaos.list_folders", "arguments": {} }),
            Duration::from_secs(15),
        )
        .await;
    assert_ok(&ok, "recovery list_folders after greeting stall");

    let (status, _tempdir) = h.shutdown_and_wait().await;
    assert!(status.success(), "binary exited non-zero: {status:?}");

    // Audit: a reconnect attempt emitted an `auth` Failure with ERR_TIMEOUT — the
    // connect-phase greeting stall. (A command timeout on the live session emits
    // no auth record, so this specifically evidences the greeting-on-connect stall.)
    let recs = audit::read_records(&audit_path);
    assert!(
        recs.iter().any(|r| r["kind"] == "auth"
            && r["result"] == "failure"
            && r["error_code"] == "ERR_TIMEOUT"),
        "expected an auth Failure with ERR_TIMEOUT from the reconnect; got {recs:?}",
    );
}
