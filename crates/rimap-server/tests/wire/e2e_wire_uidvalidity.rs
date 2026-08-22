//! Full-wire assertion of the two typed UIDVALIDITY-guard errors (#568),
//! driven against the in-process scriptable fake (`rimap_fake_imap`) so the
//! suite runs on **every PR** with no container runtime.
//!
//! The container-gated Dovecot case
//! (`e2e_wire_fault_injection::wire_fault_uid_validity_changed`) stays as the
//! conformant-server complement: a real server can only produce a *legitimate*
//! UIDVALIDITY bump. The fake scripts what Dovecot cannot — a **changed** value
//! between two SELECTs/EXAMINEs of one dialog, or a SELECT/EXAMINE that
//! **omits** the UIDVALIDITY response code entirely.
//!
//! ## The distinguisher
//!
//! Both guard failures collapse to the *same* wire error code string,
//! `ERR_UID_VALIDITY_CHANGED` (`rimap_imap::error::ImapError::code`). They are
//! told apart over the JSON-RPC wire only by the structured payload
//! (`rimap_server::mcp::error::structured_error_data`):
//!
//! - **Changed** (`ImapError::UidValidityChanged`) routes to the dedicated
//!   `RimapError::UidValidityChanged` variant, so `structuredContent` carries
//!   `folder` / `expected` / `actual`.
//! - **Omitted** (`ImapError::UidValidityUnavailable`) has no concrete
//!   mismatch to surface; it flows through the generic `Imap` arm, so
//!   `structuredContent` is just `{ "error_code": "ERR_UID_VALIDITY_CHANGED" }`
//!   — NO `expected`/`actual`/`folder`.
//!
//! Each omitted-case assertion therefore keys on the *absence* of those fields,
//! not on a distinct code string; otherwise it would silently alias the changed
//! case and prove nothing.
//!
//! ## Coverage
//!
//! - `mark_read` (mutating; guard is fail-open `check_uidvalidity` on the STORE
//!   path) — the changed case. A mutating tool cannot reach the omitted case:
//!   the store/delete guard only *warns* on an omitted value, so there is no
//!   `UidValidityUnavailable` to surface there.
//! - `export_messages` (read; guard is fail-closed `require_uidvalidity` on the
//!   body-fetch path) — both the changed case and the omitted case, so the
//!   changed-vs-omitted payload contrast is proven on one tool.

#![expect(clippy::expect_used, reason = "integration tests")]

#[path = "../support/wire/mod.rs"]
mod wire;

#[path = "../support/canary.rs"]
mod canary;

use rimap_fake_imap::fake_imap::{FakeImapServer, Step, login_preamble};
use serde_json::{Value, json};
use tempfile::TempDir;

use wire::{Harness, assert_valid};

/// Env var the keyring falls back to for the account password. The fake
/// accepts any password, so the value only needs to be present so credential
/// resolution succeeds.
const PASSWORD_ENV_VAR: &str = "RUSTY_IMAP_MCP_PASSWORD";

/// UIDVALIDITY the client pins its request to (as if discovered from a prior
/// `search`).
const PINNED_VALIDITY: u32 = 1;

/// UIDVALIDITY the fake reports on the changed-case dialog: different from
/// [`PINNED_VALIDITY`], so the guard's mismatch branch fires.
const CHANGED_VALIDITY: u32 = 99;

/// Prints the fake's recorded client-command dialog to stderr **iff** the test
/// is unwinding, so a miscalibrated script surfaces as a legible divergence
/// rather than a bare 2s harness timeout. Mirrors
/// `e2e_wire_fetch_skipped::DumpOnPanic`.
struct DumpOnPanic<'a>(&'a FakeImapServer);

impl Drop for DumpOnPanic<'_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            #[expect(clippy::print_stderr, reason = "test diagnostic on failure")]
            {
                eprintln!("fake recorded dialog:\n{:#?}", self.0.recorded());
            }
        }
    }
}

/// The `LIST "" *` the server issues at startup to build its reveal-on-select
/// tool catalog, answered with a single `INBOX` so the binary boots. Prepended
/// to every scenario after the login preamble.
fn list_boot() -> Vec<Step> {
    vec![
        Step::Expect { verb: "LIST" },
        Step::Send(b"* LIST (\\HasNoChildren) \"/\" \"INBOX\"\r\n".to_vec()),
        Step::Reply {
            text: "OK LIST completed",
        },
    ]
}

/// `mark_read` changed-UIDVALIDITY dialog. `mark_read` issues a read-write
/// `SELECT` (`store_flags` calls `select(_, false)`); the fake reports
/// [`CHANGED_VALIDITY`] where the client pinned [`PINNED_VALIDITY`], so
/// `check_uidvalidity` aborts with `UidValidityChanged` before any `STORE`.
fn mark_read_changed_script() -> Vec<Step> {
    let mut steps = login_preamble("IMAP4rev1");
    steps.extend(list_boot());
    steps.extend([
        Step::Expect { verb: "SELECT" },
        Step::Send(
            format!("* 1 EXISTS\r\n* OK [UIDVALIDITY {CHANGED_VALIDITY}] .\r\n").into_bytes(),
        ),
        Step::Reply {
            text: "OK [READ-WRITE] SELECT completed",
        },
    ]);
    steps
}

/// `export_messages` changed-UIDVALIDITY dialog. The export's size preflight
/// issues a read-only `EXAMINE` (`ops::fetch::fetch` calls `select(_, true)`);
/// the fake reports [`CHANGED_VALIDITY`], so `check_uidvalidity` aborts with
/// `UidValidityChanged` before the `UID FETCH`.
fn export_changed_script() -> Vec<Step> {
    let mut steps = login_preamble("IMAP4rev1");
    steps.extend(list_boot());
    steps.extend([
        Step::Expect { verb: "EXAMINE" },
        Step::Send(
            format!("* 1 EXISTS\r\n* OK [UIDVALIDITY {CHANGED_VALIDITY}] .\r\n").into_bytes(),
        ),
        Step::Reply {
            text: "OK [READ-ONLY] EXAMINE completed",
        },
    ]);
    steps
}

/// `export_messages` omitted-UIDVALIDITY dialog. The export refuses to run when
/// the *preflight* SELECT omits UIDVALIDITY (that surfaces as `InvalidInput`),
/// so the fake reports [`PINNED_VALIDITY`] on the first EXAMINE — clearing the
/// preflight — then omits the response code on the second (body-fetch) EXAMINE.
/// The body path's fail-closed `require_uidvalidity` then aborts with
/// `UidValidityUnavailable`. This present-then-omitted shape is exactly what a
/// conformant server never does and what the fake exists to script.
fn export_omitted_script() -> Vec<Step> {
    let mut steps = login_preamble("IMAP4rev1");
    steps.extend(list_boot());
    steps.extend([
        // Size preflight: EXAMINE reports UIDVALIDITY (matches the pin), then
        // UID FETCH returns a small in-bounds size so UID 1 is eligible for a
        // body fetch.
        Step::Expect { verb: "EXAMINE" },
        Step::Send(
            format!("* 1 EXISTS\r\n* OK [UIDVALIDITY {PINNED_VALIDITY}] .\r\n").into_bytes(),
        ),
        Step::Reply {
            text: "OK [READ-ONLY] EXAMINE completed",
        },
        Step::Expect { verb: "UID FETCH" },
        Step::Send(b"* 1 FETCH (UID 1 RFC822.SIZE 42)\r\n".to_vec()),
        Step::Reply {
            text: "OK FETCH completed",
        },
        // Body fetch: the second EXAMINE OMITS the UIDVALIDITY response code.
        // `require_uidvalidity` fail-closes on the absent value.
        Step::Expect { verb: "EXAMINE" },
        Step::Send(b"* 1 EXISTS\r\n".to_vec()),
        Step::Reply {
            text: "OK [READ-ONLY] EXAMINE completed",
        },
    ]);
    steps
}

/// Single-account, draft-safe config pointing the binary at the fake, with the
/// default-deny `export_messages` tool enabled via a `[security.tools]`
/// override. Draft-safe permits `mark_read`; the override permits
/// `export_messages`.
fn fake_config(port: u16, fingerprint_hex: &str, tempdir: &TempDir) -> String {
    let base = tempdir.path();
    format!(
        r#"
[audit]
path = "{audit}"
allowed_base_dir = "{base}"

[attachments]
download_dir = "{base}"

[defaults.credentials]
fallback = "keyring-then-env"

[[accounts]]
name = "guard"

[accounts.imap]
host = "127.0.0.1"
port = {port}
username = "rimap-test"
encryption = "tls"
tls_fingerprint_sha256 = "{fingerprint_hex}"

[accounts.security]
posture = "draft-safe"

[accounts.security.tools]
export_messages = "allow"
"#,
        audit = base.join("audit.jsonl").display(),
        base = base.display(),
    )
}

/// Spawn the binary against `server`, complete the MCP handshake, and select
/// the single account. Returns the live harness ready for a tool call.
async fn spawn_ready(server: &FakeImapServer, tempdir: TempDir, password: &str) -> Harness {
    let config_path = tempdir.path().join("config.toml");
    let config = fake_config(server.port(), &server.pin().to_hex(), &tempdir);
    std::fs::write(&config_path, config).expect("write config");

    let mut harness =
        Harness::spawn_with_config(&config_path, tempdir, &[(PASSWORD_ENV_VAR, password)]).await;

    harness.initialize_handshake().await;
    harness.send_initialized().await;

    let resp = harness
        .request(
            "tools/call",
            json!({ "name": "use_account", "arguments": { "account": "guard" } }),
        )
        .await;
    assert!(resp["error"].is_null(), "use_account failed: {resp}");

    harness
}

/// Assert `resp` is a tool-execution error (not a JSON-RPC error envelope)
/// carrying `ERR_UID_VALIDITY_CHANGED` and a non-empty human message. Returns
/// the `structuredContent` payload for per-variant field assertions.
fn assert_uidvalidity_error(resp: &Value) -> Value {
    assert!(
        resp["error"].is_null(),
        "guard failure must be a tool result, not a JSON-RPC error; got {resp}",
    );
    assert_valid(&resp["result"], "CallToolResult");
    assert_eq!(
        resp["result"]["isError"],
        json!(true),
        "guard failure must surface as isError=true; got {resp}",
    );
    let sc = &resp["result"]["structuredContent"];
    assert_eq!(
        sc["error_code"],
        json!("ERR_UID_VALIDITY_CHANGED"),
        "both guard failures share this code; got {resp}",
    );
    assert!(
        resp["result"]["content"][0]["text"]
            .as_str()
            .is_some_and(|t| !t.is_empty()),
        "guard failure must carry a non-empty message; got {resp}",
    );
    sc.clone()
}

/// Mutating tool, changed case: `mark_read` with a stale `expected_uidvalidity`
/// surfaces `UidValidityChanged` — the dedicated variant, so `structuredContent`
/// carries the typed `expected`/`actual` recovery fields.
#[tokio::test]
async fn mark_read_changed_uidvalidity_over_wire() {
    let server = FakeImapServer::start(mark_read_changed_script()).await;
    let _dump = DumpOnPanic(&server);
    let password = canary::fresh_canary();
    let tempdir = TempDir::new().expect("tempdir");
    let mut harness = spawn_ready(&server, tempdir, &password).await;

    let resp = harness
        .request(
            "tools/call",
            json!({
                "name": "guard.mark_read",
                "arguments": {
                    "folder": "INBOX",
                    "uid": 1,
                    "expected_uidvalidity": PINNED_VALIDITY,
                },
            }),
        )
        .await;

    let sc = assert_uidvalidity_error(&resp);
    assert_eq!(
        sc["expected"].as_u64(),
        Some(u64::from(PINNED_VALIDITY)),
        "changed case must echo the client's pinned value; got {resp}",
    );
    assert_eq!(
        sc["actual"].as_u64(),
        Some(u64::from(CHANGED_VALIDITY)),
        "changed case must echo the folder's observed value; got {resp}",
    );

    let recorded = server.recorded();
    let (_status, tempdir) = harness.shutdown_and_wait().await;
    canary::assert_login_frame_only(&password, &recorded);
    canary::assert_absent(&password, &[tempdir.path()], &[]);
}

/// Read tool, changed case: `export_messages` whose folder reports a different
/// UIDVALIDITY surfaces `UidValidityChanged` with the typed `expected`/`actual`
/// fields present — the payload that the omitted case below must NOT have.
#[tokio::test]
async fn export_changed_uidvalidity_over_wire() {
    let server = FakeImapServer::start(export_changed_script()).await;
    let _dump = DumpOnPanic(&server);
    let password = canary::fresh_canary();
    let tempdir = TempDir::new().expect("tempdir");
    let mut harness = spawn_ready(&server, tempdir, &password).await;

    let resp = harness
        .request(
            "tools/call",
            json!({
                "name": "guard.export_messages",
                "arguments": {
                    "folder": "INBOX",
                    "uids": [1],
                    "expected_uidvalidity": PINNED_VALIDITY,
                },
            }),
        )
        .await;

    let sc = assert_uidvalidity_error(&resp);
    assert_eq!(
        sc["expected"].as_u64(),
        Some(u64::from(PINNED_VALIDITY)),
        "changed case must echo the client's pinned value; got {resp}",
    );
    assert_eq!(
        sc["actual"].as_u64(),
        Some(u64::from(CHANGED_VALIDITY)),
        "changed case must echo the folder's observed value; got {resp}",
    );

    let recorded = server.recorded();
    let (_status, tempdir) = harness.shutdown_and_wait().await;
    canary::assert_login_frame_only(&password, &recorded);
    canary::assert_absent(&password, &[tempdir.path()], &[]);
}

/// Read tool, omitted case: `export_messages` whose body-fetch SELECT omits the
/// UIDVALIDITY response code surfaces `UidValidityUnavailable`. Same
/// `error_code`, but — the load-bearing distinguisher — NO `expected`/`actual`/
/// `folder` payload, because the generic `Imap` arm carries no structured data.
/// Keying on absence is what stops this case from silently aliasing the changed
/// case.
#[tokio::test]
async fn export_omitted_uidvalidity_over_wire() {
    let server = FakeImapServer::start(export_omitted_script()).await;
    let _dump = DumpOnPanic(&server);
    let password = canary::fresh_canary();
    let tempdir = TempDir::new().expect("tempdir");
    let mut harness = spawn_ready(&server, tempdir, &password).await;

    let resp = harness
        .request(
            "tools/call",
            json!({
                "name": "guard.export_messages",
                "arguments": {
                    "folder": "INBOX",
                    "uids": [1],
                    "expected_uidvalidity": PINNED_VALIDITY,
                },
            }),
        )
        .await;

    let sc = assert_uidvalidity_error(&resp);
    assert!(
        sc.get("expected").is_none_or(Value::is_null),
        "omitted case must NOT carry a typed `expected` (else it aliases the \
         changed case); got {resp}",
    );
    assert!(
        sc.get("actual").is_none_or(Value::is_null),
        "omitted case must NOT carry a typed `actual`; got {resp}",
    );
    assert!(
        sc.get("folder").is_none_or(Value::is_null),
        "omitted case must NOT carry a typed `folder`; got {resp}",
    );

    let recorded = server.recorded();
    let (_status, tempdir) = harness.shutdown_and_wait().await;
    canary::assert_login_frame_only(&password, &recorded);
    canary::assert_absent(&password, &[tempdir.path()], &[]);
}
