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
#![expect(clippy::panic, reason = "test diagnostics")]

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use rimap_audit::{AuditOptions, AuditWriter, Seq};
use rimap_config::credential::{
    CredentialStore, KeyringCredentialResolver, PASSWORD_ENV_VAR, Protocol,
};
use rimap_config::model::FallbackMode;
use rimap_imap::{Connection, ConnectionConfig, ImapEncryption};
use secrecy::SecretString;
use serde_json::{Value, json};
use tempfile::TempDir;

#[path = "support/chaos/mod.rs"]
mod chaos;
// Only the fixtures are needed here (not the DovecotHarness) — include the
// self-contained fixtures module directly so the harness's items don't appear
// dead in this binary.
#[path = "support/dovecot/fixtures.rs"]
mod fixtures;
#[path = "support/wire/mod.rs"]
mod wire;

use chaos::{ChaosHarness, ChaosSkip, audit};
use wire::{Harness, assert_valid};

/// Dovecot's seeded test password (matches `e2e_wire.rs`).
const DOVECOT_PASSWORD: &str = "RIMAP-CANARY-DVC-9f83b1a7c0d6e4f2";

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
        max_append_bytes: ROOMY_APPEND,
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
/// `structuredContent.error_code` equals `expected_code` and that carries a
/// non-empty message. Mirrors `e2e_wire_fault_injection.rs::assert_error_code`.
fn assert_error_code(resp: &Value, expected_code: &str) {
    assert_error_code_in(resp, &[expected_code]);
    assert!(
        resp["result"]["content"][0]["text"]
            .as_str()
            .is_some_and(|t| !t.is_empty()),
        "fault result must carry a non-empty message; got {resp}",
    );
}

/// Like `assert_error_code`, but the wire code must be one of `expected` (for
/// faults whose typed code is a set — e.g. a TCP reset that lands in either the
/// plaintext-greeting or TLS-handshake phase). Same accessor as
/// `assert_error_code`, so scenario 3 cannot diverge onto a hand-rolled path.
fn assert_error_code_in(resp: &Value, expected: &[&str]) {
    assert!(
        resp["error"].is_null(),
        "tool-execution failure must not be a JSON-RPC error envelope; got {resp}",
    );
    assert_valid(&resp["result"], "CallToolResult");
    assert_eq!(resp["result"]["isError"], json!(true), "{resp}");
    let code = resp["result"]["structuredContent"]["error_code"]
        .as_str()
        .unwrap_or("");
    assert!(
        expected.contains(&code),
        "expected one of {expected:?}; got {code:?} in {resp}",
    );
}

/// Assert a `tools/call` response succeeded (recovery/warm-up calls).
fn assert_ok(resp: &Value, context: &str) {
    assert!(
        resp["error"].is_null() && resp["result"]["isError"] == json!(false),
        "{context} must succeed; got {resp}",
    );
}

/// In-process credential store for seed connections; returns `DOVECOT_PASSWORD`.
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

fn parse_encryption(encryption: &str) -> ImapEncryption {
    match encryption {
        "tls" => ImapEncryption::Tls,
        "starttls" => ImapEncryption::Starttls,
        other => panic!("unknown encryption {other:?}"),
    }
}

/// Append `raw` to INBOX through the given proxy `port` while no toxic is active.
/// The seed uses its OWN `ConnectionConfig` whose `max_append_bytes` (25 MiB) is
/// independent of the server's TOML cap, so an over-fetch-cap body still seeds.
async fn seed_body_through_proxy(chaos: &ChaosHarness, port: u16, encryption: &str, raw: &[u8]) {
    let audit_dir = TempDir::new().expect("seed-audit tempdir");
    let audit = AuditWriter::open(&AuditOptions {
        path: audit_dir.path().join("seed.jsonl"),
        rotate_bytes: 0,
        rotate_keep: 0,
        retention_seconds: None,
        fail_open: false,
        initial_seq: Seq::FIRST,
    })
    .expect("seed audit open");

    let cfg = ConnectionConfig {
        account: None,
        account_id: rimap_core::account::AccountId::default_account(),
        host: "127.0.0.1".into(),
        port,
        encryption: parse_encryption(encryption),
        username: "rimap-test".into(),
        pinned_fingerprint: Some(*chaos.fingerprint()),
        connect_timeout: Duration::from_secs(10),
        command_timeout: Duration::from_secs(30),
        max_fetch_body_bytes: ROOMY_FETCH,
        max_append_bytes: ROOMY_APPEND,
    };
    let store: Arc<dyn CredentialStore> = Arc::new(StaticCreds);
    let creds: Arc<dyn rimap_core::CredentialResolver> = Arc::new(KeyringCredentialResolver::new(
        store,
        FallbackMode::KeyringThenEnv,
        Protocol::Imap,
    ));
    let sink: Arc<dyn rimap_core::auth_sink::AuthEventSink> = Arc::new(audit.clone());
    let conn = Connection::new(cfg, sink, creds);
    conn.append_message("INBOX", raw, &[], &[])
        .await
        .expect("APPEND seed");
}

/// Seed the shared multipart-with-attachment fixture (subject
/// `e2e-wire-test-smoke`) through the proxy.
async fn seed_through_proxy(chaos: &ChaosHarness, port: u16, encryption: &str) {
    seed_body_through_proxy(
        chaos,
        port,
        encryption,
        &fixtures::multipart_with_attachment(),
    )
    .await;
}

/// Build a valid RFC 5322 message of ~`n` bytes (headers + repeated-filler
/// plaintext body). Subject is the smoke subject so `search_seed_uid` finds it.
fn message_of_size(n: usize) -> Vec<u8> {
    let header = "From: chaos@example.test\r\n\
                  To: rimap-test@example.test\r\n\
                  Subject: e2e-wire-test-smoke\r\n\
                  Date: Wed, 09 Jul 2026 00:00:00 +0000\r\n\
                  Message-ID: <chaos-size@example.test>\r\n\
                  MIME-Version: 1.0\r\n\
                  Content-Type: text/plain; charset=utf-8\r\n\r\n";
    let filler = b"chaos-filler-line-0123456789ABCDEF\r\n";
    let mut msg = Vec::with_capacity(n + header.len());
    msg.extend_from_slice(header.as_bytes());
    while msg.len() < n {
        msg.extend_from_slice(filler);
    }
    msg
}

/// Drive `chaos.search` for the seeded smoke subject; return its max UID.
async fn search_seed_uid(h: &mut Harness) -> u64 {
    let resp = h
        .request(
            "tools/call",
            json!({
                "name": "chaos.search",
                "arguments": { "folder": "INBOX", "subject": "e2e-wire-test-smoke" },
            }),
        )
        .await;
    assert!(resp["error"].is_null(), "search failed: {resp}");
    resp["result"]["structuredContent"]["untrusted"]["messages"]
        .as_array()
        .expect("messages array")
        .iter()
        .filter_map(|m| m["uid"].as_u64())
        .max()
        .expect("seeded message must be found by subject")
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
    let mut h = spawn_ready(&chaos, chaos.starttls_port(), "starttls", 1, 1, ROOMY_FETCH).await;
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

    // Audit: op #2's reconnect emitted exactly one `auth` Failure — the
    // connect-phase greeting stall. Scope strictly to op #2's Seq window (the
    // LAST ERR_TIMEOUT tool_end — op #1 precedes it) so a stray auth record
    // elsewhere cannot satisfy this vacuously. op #1 is a command timeout on the
    // established session (no reconnect, no `auth` record: `auth` is emitted only
    // by `connect_inner`), so the single auth Failure in op #2's window
    // specifically evidences the greeting-on-connect stall.
    let recs = audit::read_records(&audit_path);
    let (s0, s1) = audit::last_tool_call_matching_error(&recs, &["ERR_TIMEOUT"])
        .expect("op #2's failing tool_end with ERR_TIMEOUT");
    assert_eq!(
        audit::count_auth_failures_between(&recs, s0, s1),
        1,
        "op #2's reconnect must emit exactly one auth Failure (the greeting stall); got {recs:?}",
    );
}

/// Scenario 2 — a mid-FETCH latency spike times out the operation (`ERR_TIMEOUT`),
/// invalidates the session, and the next call recovers. The boot connect plus a
/// warm-up search establish a live session; a `timeout` toxic then stalls the
/// FETCH on that session (a command-stage stall, not a connect stall). A
/// preceding successful `tool_end` before the failing one proves a connect-time
/// timeout cannot masquerade as the mid-operation case.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn chaos_mid_fetch_stall_times_out_then_recovers() {
    let Ok(chaos) = ChaosHarness::try_start() else {
        return;
    };
    mark_ran("scenario2");
    seed_through_proxy(&chaos, chaos.imaps_port(), "tls").await;

    // imaps (993): connect_timeout generous (recovery reconnect not gated);
    // command_timeout low (1s) so the stalled FETCH trips fast.
    let mut h = spawn_ready(&chaos, chaos.imaps_port(), "tls", 10, 1, ROOMY_FETCH).await;
    let audit_path = h.audit_path();

    // Warm-up on the live session (success is load-bearing for the audit assertion).
    let uid = search_seed_uid(&mut h).await;

    // Degrade: stall all data → the in-flight FETCH exceeds command_timeout.
    chaos.toxics().add_toxic(
        "imaps",
        &json!({ "type": "timeout", "stream": "downstream", "attributes": { "timeout": 0 } }),
    );
    let resp = h
        .request_within(
            "tools/call",
            json!({ "name": "chaos.fetch_message", "arguments": { "folder": "INBOX", "uid": uid } }),
            Duration::from_secs(15),
        )
        .await;
    assert_error_code(&resp, "ERR_TIMEOUT");

    // Recovery: session invalidated → reconnect succeeds.
    chaos.toxics().reset();
    let ok = h
        .request_within(
            "tools/call",
            json!({ "name": "chaos.search", "arguments": { "folder": "INBOX", "subject": "e2e-wire-test-smoke" } }),
            Duration::from_secs(15),
        )
        .await;
    assert_ok(&ok, "recovery search after mid-FETCH stall");

    let (status, _tempdir) = h.shutdown_and_wait().await;
    assert!(status.success(), "binary exited non-zero: {status:?}");

    // Audit: a preceding successful tool_end (warm-up search) then the failing
    // FETCH tool_end (ERR_TIMEOUT).
    let recs = audit::read_records(&audit_path);
    let (s0, _s1) = audit::last_tool_call_matching_error(&recs, &["ERR_TIMEOUT"])
        .expect("a failing tool_end with ERR_TIMEOUT");
    assert!(
        recs.iter().any(|r| r["kind"] == "tool_end"
            && r["error_code"].is_null()
            && r["seq"].as_u64().is_some_and(|s| s < s0)),
        "a successful warm-up tool_end must precede the failing FETCH; got {recs:?}",
    );
}

/// Scenario 3 — a connection reset during STARTTLS surfaces a typed
/// TLS/connection error (`ERR_TLS` or `ERR_CONNECTION_LOST` — a TCP-layer RST is
/// not deterministic between the plaintext-greeting and TLS-handshake phases),
/// and the failing call's window carries exactly one `auth` Failure. The server
/// boots healthy on the STARTTLS path; a `reset_peer` toxic then RSTs traffic
/// through the proxy, so the session's next op fails and its reconnect's STARTTLS
/// handshake is reset.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn chaos_starttls_reset_typed_error_one_auth() {
    let Ok(chaos) = ChaosHarness::try_start() else {
        return;
    };
    mark_ran("scenario3");

    // STARTTLS path; generous budgets (a prompt RST needs no low budget, and a
    // generous connect budget keeps the recovery reconnect flake-free).
    let mut h = spawn_ready(
        &chaos,
        chaos.starttls_port(),
        "starttls",
        10,
        10,
        ROOMY_FETCH,
    )
    .await;
    let audit_path = h.audit_path();

    // reset_peer: RST at/near connection open on the starttls proxy.
    chaos.toxics().add_toxic(
        "starttls",
        &json!({ "type": "reset_peer", "stream": "downstream", "attributes": { "timeout": 0 } }),
    );
    let resp = h
        .request_within(
            "tools/call",
            json!({ "name": "chaos.list_folders", "arguments": {} }),
            Duration::from_secs(15),
        )
        .await;
    assert_error_code_in(&resp, &["ERR_TLS", "ERR_CONNECTION_LOST"]);

    // Recovery: remove toxic → fresh STARTTLS connect succeeds.
    chaos.toxics().reset();
    let ok = h
        .request_within(
            "tools/call",
            json!({ "name": "chaos.list_folders", "arguments": {} }),
            Duration::from_secs(15),
        )
        .await;
    assert_ok(&ok, "recovery over STARTTLS after reset");

    let (status, _tempdir) = h.shutdown_and_wait().await;
    assert!(status.success(), "binary exited non-zero: {status:?}");

    // Audit: exactly one `auth` Failure within the failing call's Seq window.
    // (Confirm in first runs: a pre-login RST still emits exactly one auth
    // record; if a future refactor moves auth emission post-login, re-derive.)
    let recs = audit::read_records(&audit_path);
    let (s0, s1) = audit::last_tool_call_matching_error(&recs, &["ERR_TLS", "ERR_CONNECTION_LOST"])
        .expect("a failing tool_end with ERR_TLS/ERR_CONNECTION_LOST");
    assert_eq!(
        audit::count_auth_failures_between(&recs, s0, s1),
        1,
        "exactly one auth Failure in the failing call window; got {recs:?}",
    );
}

/// Scenario 4a — an over-cap body under a slow byte-trickle is rejected PROMPTLY
/// with `ERR_ATTACHMENT_TOO_LARGE` by the `RFC822.SIZE` pre-check, before any body
/// bytes are read. Falsifiable against a buffering regression: if `fetch_body`
/// regressed to read the body before checking size, the bandwidth toxic would
/// stall it to `command_timeout` and surface `ERR_TIMEOUT` instead — the prompt
/// rejection is then evidence that no body was buffered.
///
/// Scope caveat: `ERR_ATTACHMENT_TOO_LARGE` and the `< 20s` bound both hold even
/// if the bandwidth toxic were inert (an unthrottled over-cap fetch also rejects
/// promptly), so 4a alone does not *prove* the trickle throttled. That the
/// bandwidth toxic on the imaps proxy genuinely throttles the body stream is
/// proven non-vacuously by **scenario 4b** (same toxic type, same proxy): without
/// the toxic 4b's 2 MiB fetch succeeds; with it, it times out. 4a's role is the
/// prompt size-rejection (no buffering) under that established throttle.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn chaos_trickle_over_cap_rejects_promptly() {
    let Ok(chaos) = ChaosHarness::try_start() else {
        return;
    };
    mark_ran("scenario4a");

    // Seed a body well OVER the fetch cap (10 MiB body, 1 MiB cap).
    seed_body_through_proxy(
        &chaos,
        chaos.imaps_port(),
        "tls",
        &message_of_size(10 * 1024 * 1024),
    )
    .await;

    // command_timeout generous so the size rejection is unambiguously "prompt".
    let mut h = spawn_ready(&chaos, chaos.imaps_port(), "tls", 10, 30, 1_048_576).await;
    let uid = search_seed_uid(&mut h).await;

    // Slow trickle: the tiny RFC822.SIZE preflight returns fast even at ~64 KB/s;
    // the size check then rejects before the body is read.
    chaos.toxics().add_toxic(
        "imaps",
        &json!({ "type": "bandwidth", "stream": "downstream", "attributes": { "rate": 64 } }),
    );
    let t0 = std::time::Instant::now();
    let resp = h
        .request_within(
            "tools/call",
            json!({ "name": "chaos.fetch_message", "arguments": { "folder": "INBOX", "uid": uid } }),
            Duration::from_secs(30),
        )
        .await;
    assert_error_code(&resp, "ERR_ATTACHMENT_TOO_LARGE");
    assert!(
        t0.elapsed() < Duration::from_secs(20),
        "rejection must be prompt (preflight, not a body-read stall); took {:?}",
        t0.elapsed(),
    );

    // Recovery: a small metadata call (re-fetching the over-cap body would still
    // be ERR_ATTACHMENT_TOO_LARGE); ERR_ATTACHMENT_TOO_LARGE is transport-neutral,
    // so the session stays live and this needs no reconnect.
    chaos.toxics().reset();
    let ok = h
        .request(
            "tools/call",
            json!({ "name": "chaos.list_folders", "arguments": {} }),
        )
        .await;
    assert_ok(&ok, "recovery metadata call after over-cap rejection");

    let (status, _tempdir) = h.shutdown_and_wait().await;
    assert!(status.success(), "binary exited non-zero: {status:?}");
}

/// Scenario 4b — an under-cap body trickled below the command budget surfaces
/// `ERR_TIMEOUT` (the time bound), the session is invalidated, and the next call
/// recovers. The cap is raised above the body so the size guard does not fire;
/// the `bandwidth` toxic makes the body unable to arrive within `command_timeout`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn chaos_trickle_under_cap_times_out_then_recovers() {
    let Ok(chaos) = ChaosHarness::try_start() else {
        return;
    };
    mark_ran("scenario4b");

    // ~2 MiB body, UNDER the raised fetch cap; at ~64 KB/s it needs ~32s ≫ 2s.
    seed_body_through_proxy(
        &chaos,
        chaos.imaps_port(),
        "tls",
        &message_of_size(2 * 1024 * 1024),
    )
    .await;

    // command_timeout low (2s) so the trickled body times out; connect generous.
    let mut h = spawn_ready(&chaos, chaos.imaps_port(), "tls", 10, 2, ROOMY_FETCH).await;
    let uid = search_seed_uid(&mut h).await;

    chaos.toxics().add_toxic(
        "imaps",
        &json!({ "type": "bandwidth", "stream": "downstream", "attributes": { "rate": 64 } }),
    );
    let resp = h
        .request_within(
            "tools/call",
            json!({ "name": "chaos.fetch_message", "arguments": { "folder": "INBOX", "uid": uid } }),
            Duration::from_secs(15),
        )
        .await;
    assert_error_code(&resp, "ERR_TIMEOUT");

    // Recovery reconnects AND fetches the 2 MiB body — request_within (the 2s
    // request() cap would trip before the reconnect+fetch completes).
    chaos.toxics().reset();
    let ok = h
        .request_within(
            "tools/call",
            json!({ "name": "chaos.fetch_message", "arguments": { "folder": "INBOX", "uid": uid } }),
            Duration::from_secs(15),
        )
        .await;
    assert_ok(&ok, "recovery fetch after byte-trickle timeout");

    let (status, _tempdir) = h.shutdown_and_wait().await;
    assert!(status.success(), "binary exited non-zero: {status:?}");
}
