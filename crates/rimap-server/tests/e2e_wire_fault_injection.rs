//! Fault-injection wire-driven Dovecot e2e (#458). Provokes three
//! transport / protocol fault conditions through the *real MCP
//! tool-dispatch boundary* and asserts the client-visible `ERR_*` code
//! that surfaces in `structuredContent.error_code`.
//!
//! Audit finding M-16: the `ERR_CONNECTION_LOST`,
//! `ERR_ATTACHMENT_TOO_LARGE`, and `ERR_UID_VALIDITY_CHANGED` codes had
//! string round-trip tests (`rimap-core::error`) and rimap-imap-layer
//! enum-variant tests (`case_10`/`case_11`/`case_23`), but nothing drove
//! them all the way out through `impl From<ImapError> for RimapError`
//! and the `is_tool_execution_error` classifier to the wire envelope an
//! agent actually reads. Each test here spawns `rusty-imap-mcp` over its
//! stdio JSON-RPC wire, provokes the fault, and asserts the resulting
//! `CallToolResult { isError: true }` carries the stable code:
//!
//!   1. Oversize fetch (`max_fetch_body_bytes` cap) via
//!      `download_attachment`  -> `ERR_ATTACHMENT_TOO_LARGE`.
//!   2. Stale `expected_uidvalidity` via `mark_read`
//!      -> `ERR_UID_VALIDITY_CHANGED`.
//!   3. Server stopped before first connect, then `list_folders`
//!      -> `ERR_CONNECTION_LOST`.
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

use dovecot::{DovecotHarness, HarnessError, fixtures};
use wire::{Harness, assert_valid};

// Per-binary dead-code cross-talk: each integration-test binary compiles
// `support/` independently, but items other binaries use appear dead
// here. Workspace lint `clippy::allow_attributes` forbids `#[allow]`, so
// we reference cross-binary items in a never-called helper — the
// reference itself counts as "use" for dead-code analysis. Mirrors
// `e2e_wire_destructive.rs::force_use_for_dead_code_link`.
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

/// A `max_fetch_body_bytes` cap smaller than the seeded multipart
/// message (headers + body + base64 attachment run to a few hundred
/// bytes), so the first `fetch_body` a retrieval tool issues overflows
/// deterministically. `> 0` satisfies the config limits validator.
const TINY_FETCH_CAP: u64 = 32;

/// A `max_fetch_body_bytes` value comfortably above any fixture, used by
/// the tests that must NOT trip the size cap. Matches the shipped default.
const ROOMY_FETCH_CAP: u64 = 26_214_400;

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

/// Single draft-safe account TOML for the fault-injection suite. Only
/// the draft-safe posture is needed; `max_fetch_body_bytes` is a
/// caller-supplied knob so one builder serves both the size-cap test
/// (tiny cap) and the tests that must not trip it (roomy cap).
fn build_fault_config(
    fingerprint_hex: &str,
    port: u16,
    audit_path: &std::path::Path,
    allowed_base: &std::path::Path,
    download_dir: &std::path::Path,
    max_fetch_body_bytes: u64,
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
name = "draftsafe"

[accounts.imap]
host = "127.0.0.1"
port = {port}
username = "rimap-test"
encryption = "tls"
tls_fingerprint_sha256 = "{fingerprint_hex}"

[accounts.security]
posture = "draft-safe"

[accounts.limits]
max_fetch_body_bytes = {max_fetch_body_bytes}
"#,
        audit_path = audit_path.display(),
        allowed_base = allowed_base.display(),
        download_dir = download_dir.display(),
    )
}

/// Spawn the server against `dovecot` with the given fetch-body cap and
/// complete the MCP `initialize` handshake. Returns the live harness;
/// the `TempDir` is owned by the harness and outlives it via
/// `shutdown_and_wait`.
async fn spawn_ready(dovecot: &DovecotHarness, max_fetch_body_bytes: u64) -> Harness {
    let tempdir = TempDir::new().expect("tempdir");
    let audit_path = tempdir.path().join("audit.jsonl");
    let allowed_base = tempdir.path().to_path_buf();
    let download_dir = tempdir.path().join("downloads");
    std::fs::create_dir_all(&download_dir).expect("mkdir download_dir");

    let config_path = tempdir.path().join("config.toml");
    let fingerprint_hex = dovecot.fingerprint().to_hex();
    let config = build_fault_config(
        &fingerprint_hex,
        dovecot.port(),
        &audit_path,
        &allowed_base,
        &download_dir,
        max_fetch_body_bytes,
    );
    std::fs::write(&config_path, config).expect("write config");

    let envs = [(PASSWORD_ENV_VAR, DOVECOT_PASSWORD)];
    let mut harness = Harness::spawn_with_config(&config_path, tempdir, &envs).await;
    let _ = harness.initialize_handshake().await;
    harness.send_initialized().await;
    harness
}

/// Drive `draftsafe.search` for the seeded smoke subject and return its
/// UID. Fails loudly if the seed is missing.
async fn search_seed_uid(harness: &mut Harness) -> u64 {
    let resp = harness
        .request(
            "tools/call",
            json!({
                "name": "draftsafe.search",
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

/// Assert a `tools/call` response is a tool-execution error whose
/// `structuredContent.error_code` equals `expected_code`. Mirrors the
/// posture-denial shape in `e2e_wire.rs::assert_readonly_denial`: no
/// JSON-RPC error envelope, `isError: true`, a stable machine code, and
/// a non-empty human message.
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

/// Oversize fetch through `download_attachment` surfaces
/// `ERR_ATTACHMENT_TOO_LARGE`. With `max_fetch_body_bytes` capped below
/// the seeded message, the tool's first `UID FETCH … BODY` overflows and
/// `ImapError::SizeLimit` flows through `From<ImapError> for RimapError`
/// to the dedicated `AttachmentTooLarge` variant. Provoked through the
/// wire, not asserted at the rimap-imap enum layer (the #458 gap).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wire_fault_attachment_too_large() {
    let dovecot = match DovecotHarness::try_start() {
        Ok(d) => d,
        Err(HarnessError::DockerUnavailable) => return,
        Err(e) => panic!("Dovecot harness failed: {e}"),
    };
    seed_multipart_message(&dovecot).await;

    let mut harness = spawn_ready(&dovecot, TINY_FETCH_CAP).await;
    let uid = search_seed_uid(&mut harness).await;

    // `fetch_body` overflows before any MIME part walking, so `part_id`
    // only needs to pass the non-empty check; it is never reached.
    let resp = harness
        .request(
            "tools/call",
            json!({
                "name": "draftsafe.download_attachment",
                "arguments": { "folder": "INBOX", "uid": uid, "part_id": "2" },
            }),
        )
        .await;

    assert_error_code(&resp, "ERR_ATTACHMENT_TOO_LARGE");
    // The typed `limit` (#303) must echo the configured cap through the
    // structured `data`, proving the value survives the conversion.
    assert_eq!(
        resp["result"]["structuredContent"]["limit"].as_u64(),
        Some(TINY_FETCH_CAP),
        "AttachmentTooLarge must surface the configured cap as limit; got {resp}",
    );

    let (status, tempdir_guard) = harness.shutdown_and_wait().await;
    assert!(status.success(), "binary exited non-zero: {status:?}");
    canary::assert_absent(DOVECOT_PASSWORD, &[tempdir_guard.path()], &[]);
}

/// A stale `expected_uidvalidity` on `mark_read` surfaces
/// `ERR_UID_VALIDITY_CHANGED`. The real UIDVALIDITY is read back from a
/// first (successful) `mark_read`, then a second call passes a value one
/// higher — guaranteed to mismatch — so the folder's UIDVALIDITY guard
/// aborts before any STORE and `ImapError::UidValidityChanged` flows to
/// the dedicated `RimapError` variant with typed `expected`/`actual`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wire_fault_uid_validity_changed() {
    let dovecot = match DovecotHarness::try_start() {
        Ok(d) => d,
        Err(HarnessError::DockerUnavailable) => return,
        Err(e) => panic!("Dovecot harness failed: {e}"),
    };
    seed_multipart_message(&dovecot).await;

    let mut harness = spawn_ready(&dovecot, ROOMY_FETCH_CAP).await;
    let uid = search_seed_uid(&mut harness).await;

    // Successful mark_read: reads back the folder's real UIDVALIDITY.
    let ok = harness
        .request(
            "tools/call",
            json!({
                "name": "draftsafe.mark_read",
                "arguments": { "folder": "INBOX", "uid": uid },
            }),
        )
        .await;
    assert!(ok["error"].is_null(), "baseline mark_read failed: {ok}");
    assert_eq!(
        ok["result"]["isError"],
        json!(false),
        "baseline mark_read must succeed: {ok}",
    );
    let real_validity = ok["result"]["structuredContent"]["meta"]["uid_validity"]
        .as_u64()
        .expect("Dovecot reports UIDVALIDITY on SELECT");
    let stale_validity = real_validity.wrapping_add(1);

    let resp = harness
        .request(
            "tools/call",
            json!({
                "name": "draftsafe.mark_read",
                "arguments": {
                    "folder": "INBOX",
                    "uid": uid,
                    "expected_uidvalidity": stale_validity,
                },
            }),
        )
        .await;

    assert_error_code(&resp, "ERR_UID_VALIDITY_CHANGED");
    // The typed recovery fields must survive the conversion: the guard
    // echoes what the client asked for and what the folder actually is.
    let data = &resp["result"]["structuredContent"];
    assert_eq!(
        data["expected"].as_u64(),
        Some(stale_validity),
        "guard must echo the stale expected UIDVALIDITY; got {resp}",
    );
    assert_eq!(
        data["actual"].as_u64(),
        Some(real_validity),
        "guard must echo the folder's real UIDVALIDITY; got {resp}",
    );

    let (status, tempdir_guard) = harness.shutdown_and_wait().await;
    assert!(status.success(), "binary exited non-zero: {status:?}");
    canary::assert_absent(DOVECOT_PASSWORD, &[tempdir_guard.path()], &[]);
}

/// A dead server surfaces `ERR_CONNECTION_LOST`. The container is stopped
/// before the server opens its first IMAP connection, so `list_folders`
/// triggers a fresh connect that is refused; `ImapError::Connect` maps to
/// `ErrorCode::ConnectionLost`. Stopping before first use (rather than
/// mid-session) makes the code deterministic: there is no half-open
/// socket to yield an intermittent `ERR_IMAP_PROTOCOL` first.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wire_fault_connection_lost() {
    let dovecot = match DovecotHarness::try_start() {
        Ok(d) => d,
        Err(HarnessError::DockerUnavailable) => return,
        Err(e) => panic!("Dovecot harness failed: {e}"),
    };

    // Spawn and handshake while the container is up (config validation +
    // the fingerprint read happen here); the server connects to IMAP
    // lazily on the first tool call, not during initialize.
    let mut harness = spawn_ready(&dovecot, ROOMY_FETCH_CAP).await;

    // Tear down the server so the next connect is refused.
    dovecot.stop();

    let resp = harness
        .request(
            "tools/call",
            json!({
                "name": "draftsafe.list_folders",
                "arguments": {},
            }),
        )
        .await;

    assert_error_code(&resp, "ERR_CONNECTION_LOST");

    let (status, tempdir_guard) = harness.shutdown_and_wait().await;
    assert!(status.success(), "binary exited non-zero: {status:?}");
    canary::assert_absent(DOVECOT_PASSWORD, &[tempdir_guard.path()], &[]);
}

/// Seed the INBOX with the shared multipart-with-attachment fixture via a
/// direct IMAP connection (independent of the server under test), so the
/// retrieval and flag tools have a real message to act on. Mirrors
/// `e2e_wire.rs::seed_multipart_message`.
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
        rimap_config::credential::Protocol::Imap,
    ));
    let sink: Arc<dyn rimap_core::auth_sink::AuthEventSink> = Arc::new(audit.clone());
    let conn = Connection::new(cfg, sink, creds);
    conn.append_message("INBOX", &fixtures::multipart_with_attachment(), &[], &[])
        .await
        .expect("APPEND multipart seed");
}
