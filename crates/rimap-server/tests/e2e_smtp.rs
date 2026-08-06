//! Dovecot e2e for `send_email` and `forward` through the dispatch handler.
//!
//! `send_email` and `forward` are the highest-consequence tools — they emit
//! mail off-box — yet only their pure envelope/message-building helpers were
//! unit-tested before this file (#454). These tests drive both tools through
//! the real dispatch pipeline (`execute_tool_for_test` → posture guard →
//! audit envelope → handler) with a [`FakeSmtpSender`] injected on the
//! `AccountState` seam (#453), against a real Dovecot IMAP fixture.
//!
//! They assert the four things the audit finding called out:
//! 1. Both tools are driven end-to-end via the injected SMTP fake.
//! 2. The on-wire RFC 5322 bytes the fake captured carry the expected
//!    headers/recipients, exclude `Bcc` from the DATA (#432), and wrap the
//!    forwarded original as a base64 `message/rfc822` part.
//! 3. The best-effort copy lands in the Sent folder — verified by reading
//!    the folder back over IMAP, independent of the tool's self-reported
//!    `sent_copy`.
//! 4. A rejecting fake surfaces `ERR_SMTP_PROTOCOL`, and no Sent copy is
//!    written when the send itself fails.
//!
//! # Why in-process, not the stdio wire
//!
//! The wire harness (`e2e_wire.rs`) spawns the production binary, which
//! builds SMTP solely from config — there is no seam to inject a fake into a
//! subprocess. The `AccountState.smtp` trait object exists precisely so the
//! fake can be injected on the in-process path, which still exercises the
//! full dispatch pipeline. See the module doc on `e2e.rs` for the same
//! single-container, in-process rationale.
//!
//! Skips silently when no container runtime is available. Set
//! `RIMAP_REQUIRE_DOCKER=1` to fail loudly instead.

#![expect(clippy::expect_used, reason = "tests")]
#![expect(clippy::panic, reason = "test diagnostics")]

// Import dovecot directly (not via support/mod.rs) so this binary does not
// compile the wire driver it doesn't use.
#[path = "support/dovecot/mod.rs"]
mod dovecot;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use mail_parser::{MessageParser, PartType};
use rimap_audit::{AuditOptions, AuditWriter, Seq};
use rimap_authz::DispatchGuard;
use rimap_authz::breaker::{BreakerConfig, CircuitBreaker, SystemClock};
use rimap_authz::matrix::EffectiveMatrix;
use rimap_authz::rate_limit::Governor;
use rimap_config::credential::CredentialStore;
use rimap_config::model::{ImapConfig, ImapEncryption};
use rimap_config::validate::ValidatedAccountConfig;
use rimap_core::account::AccountId;
use rimap_core::posture::Posture;
use rimap_imap::{Connection, ConnectionConfig};
use rimap_smtp::testing::FakeSmtpSender;
use tempfile::TempDir;

use dovecot::{DovecotHarness, HarnessError};
use rimap_server::mcp::server::ImapMcpServer;

// ── Fixtures ────────────────────────────────────────────────────────

const ACCOUNT_USERNAME: &str = "rimap-test";

const FORWARD_OK_SUBJECT: &str = "e2e-smtp-forward-ok-source";
const FORWARD_OK_BODY: &str = "original body forwarded on the happy path";
const FORWARD_FAIL_SUBJECT: &str = "e2e-smtp-forward-fail-source";
const FORWARD_FAIL_BODY: &str = "original body forwarded on the failing path";

struct StaticCreds(String);

impl CredentialStore for StaticCreds {
    fn get_password(
        &self,
        _account: &str,
    ) -> Result<Option<secrecy::SecretString>, rimap_config::ConfigError> {
        Ok(Some(secrecy::SecretString::from(self.0.clone())))
    }

    #[expect(clippy::panic, clippy::panic_in_result_fn, reason = "test stub")]
    fn set_password(
        &self,
        _account: &str,
        _password: &str,
    ) -> Result<(), rimap_config::ConfigError> {
        panic!("tests do not write credentials")
    }
}

// ── Server builder ──────────────────────────────────────────────────

/// One in-process server plus the tempdirs its audit/download roots live in.
/// The tempdirs must outlive the server, so callers keep the whole struct.
struct ServerScope {
    _audit_dir: TempDir,
    _download_dir: TempDir,
    server: ImapMcpServer,
}

/// Build a `Full`-posture in-process server for `harness`, with `fake`
/// injected as the account's SMTP sender. Send/forward require `Full`
/// (`Readonly`/`DraftSafe` deny them), and rate limits are set generous so
/// this suite exercises delivery, not throttling.
fn build_server(harness: &DovecotHarness, fake: FakeSmtpSender) -> ServerScope {
    let audit_dir = TempDir::new().expect("audit tempdir");
    let download_dir = TempDir::new().expect("download tempdir");

    let audit = AuditWriter::open(&AuditOptions::new(
        audit_dir.path().join("audit.jsonl"),
        Seq::FIRST,
    ))
    .expect("audit open");

    let account_cfg = test_account_config(harness);
    let imap = test_connection(harness, &audit);
    let guard = test_guard(&account_cfg);
    let folder_guard = rimap_authz::FolderGuard::new(
        &account_cfg.security.protected_folders,
        &account_cfg.security.expunge_folders,
    );
    let id = account_cfg.id.clone();
    let state = rimap_server::boot::registry::AccountState {
        id: id.clone(),
        imap,
        smtp: Some(Box::new(fake)),
        guard,
        folder_guard,
        download_dir: Arc::from(download_dir.path().to_path_buf().into_boxed_path()),
        special_use: rimap_imap::SpecialUseMap::default(),
        tool_call_timeout: std::time::Duration::from_secs(u64::from(
            account_cfg.limits.tool_call_timeout_seconds,
        )),
    };
    let mut accounts = BTreeMap::new();
    accounts.insert(id, state);
    let registry = rimap_server::boot::registry::AccountRegistry::new(accounts);

    let (cancellation_sender, _cancellation_rx) = rimap_audit::cancellation_channel();
    let server = ImapMcpServer::new(registry, audit, cancellation_sender);

    ServerScope {
        _audit_dir: audit_dir,
        _download_dir: download_dir,
        server,
    }
}

fn test_account_config(harness: &DovecotHarness) -> ValidatedAccountConfig {
    let mut cfg = ValidatedAccountConfig::new_for_tests(AccountId::default_account(), {
        let mut imap = ImapConfig::new("127.0.0.1".into(), harness.port(), ACCOUNT_USERNAME.into());
        imap.encryption = ImapEncryption::Tls;
        imap
    });
    cfg.security.posture = Posture::Full;
    cfg.limits.commands_per_second = 1000;
    cfg.limits.drafts_per_minute = 1000;
    cfg.limits.sends_per_minute = 1000;
    cfg.tls_fingerprint = Some(*harness.fingerprint());
    cfg
}

fn test_connection(harness: &DovecotHarness, audit: &AuditWriter) -> Connection {
    let conn_cfg = ConnectionConfig {
        account: None,
        account_id: AccountId::default_account(),
        host: "127.0.0.1".into(),
        port: harness.port(),
        encryption: rimap_imap::ImapEncryption::Tls,
        username: ACCOUNT_USERNAME.into(),
        pinned_fingerprint: Some(*harness.fingerprint()),
        connect_timeout: Duration::from_secs(10),
        command_timeout: Duration::from_secs(30),
        max_fetch_body_bytes: 5_242_880,
        max_append_bytes: 10_485_760,
    };
    let store: Arc<dyn CredentialStore> =
        Arc::new(StaticCreds("RIMAP-CANARY-DVC-9f83b1a7c0d6e4f2".into()));
    let creds: Arc<dyn rimap_core::CredentialResolver> =
        Arc::new(rimap_config::credential::KeyringCredentialResolver::new(
            store,
            rimap_config::model::FallbackMode::KeyringThenEnv,
            rimap_config::credential::Protocol::Imap,
        ));
    let sink: Arc<dyn rimap_core::auth_sink::AuthEventSink> = Arc::new(audit.clone());
    Connection::new(conn_cfg, sink, creds)
}

fn test_guard(config: &ValidatedAccountConfig) -> DispatchGuard<SystemClock> {
    let matrix = EffectiveMatrix::build(config.security.posture, &config.tool_overrides);
    let breaker = CircuitBreaker::new(SystemClock::new(), BreakerConfig::default_spec());
    let governor = Governor::new(
        config.limits.commands_per_second,
        config.limits.drafts_per_minute,
        config.limits.sends_per_minute,
    )
    .expect("governor");
    DispatchGuard::new(matrix, breaker, governor)
}

// ── Dispatch + IMAP helpers ─────────────────────────────────────────

async fn call_tool(
    server: &ImapMcpServer,
    tool_name: &str,
    args: serde_json::Value,
) -> Result<serde_json::Value, rimap_core::RimapError> {
    let tool = std::str::FromStr::from_str(tool_name).map_err(
        |e: rimap_core::tool::ParseToolNameError| rimap_core::RimapError::Internal(e.to_string()),
    )?;
    server.execute_tool_for_test(None, tool, args).await
}

/// Run the `search` tool against `folder` for messages whose `Subject`
/// contains `subject`. The one response carries both the match count
/// (`meta.total_matched`) and the matched UIDs (`untrusted.messages`), so
/// the Sent-folder assertions read a copy back over IMAP rather than
/// trusting the tool's self-reported `sent_copy`.
async fn search_folder(server: &ImapMcpServer, folder: &str, subject: &str) -> serde_json::Value {
    call_tool(
        server,
        "search",
        serde_json::json!({ "folder": folder, "subject": subject }),
    )
    .await
    .expect("search failed")
}

/// Number of matches in a `search_folder` response.
fn match_count(search_result: &serde_json::Value) -> u64 {
    search_result["meta"]["total_matched"]
        .as_u64()
        .expect("total_matched")
}

/// Newest (highest) UID among a `search_folder` response's matches, or
/// `None` when nothing matched.
fn newest_uid(search_result: &serde_json::Value) -> Option<u32> {
    let uid = search_result["untrusted"]["messages"]
        .as_array()
        .expect("messages array")
        .iter()
        .filter_map(|m| m["uid"].as_u64())
        .max()?;
    Some(u32::try_from(uid).expect("uid fits u32"))
}

/// Fetch a message's raw bytes from `folder` by `uid` over IMAP.
async fn fetch_body(server: &ImapMcpServer, folder: &str, uid: u32) -> Vec<u8> {
    let uid = core::num::NonZeroU32::new(uid).expect("server UIDs are non-zero");
    let account = server.registry.resolve(None).expect("resolve account");
    account
        .imap
        .fetch_body(folder, rimap_imap::types::Uid::from(uid), None)
        .await
        .expect("fetch_body failed")
}

fn forward_source(subject: &str, body: &str) -> Vec<u8> {
    format!(
        "From: origin@example.com\r\n\
         To: {ACCOUNT_USERNAME}@localhost\r\n\
         Subject: {subject}\r\n\
         Date: Sat, 04 Jul 2026 10:00:00 +0000\r\n\
         Message-ID: <{subject}@example.com>\r\n\
         MIME-Version: 1.0\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         \r\n\
         {body}\r\n"
    )
    .into_bytes()
}

/// First recipient address in an optional `mail_parser` address header.
fn first_address<'a>(header: Option<&'a mail_parser::Address<'a>>) -> &'a str {
    header
        .expect("address header present")
        .first()
        .expect("at least one address")
        .address()
        .expect("address value")
}

/// APPEND a to-be-forwarded message to INBOX and return its server UID.
async fn seed_forward_source(server: &ImapMcpServer, subject: &str, body: &str) -> u32 {
    let account = server.registry.resolve(None).expect("resolve account");
    account
        .imap
        .append_message("INBOX", &forward_source(subject, body), &[], &[])
        .await
        .expect("APPEND to INBOX failed");
    newest_uid(&search_folder(server, "INBOX", subject).await).expect("seeded message has a UID")
}

// ── The test ────────────────────────────────────────────────────────

#[tokio::test]
async fn e2e_send_email_and_forward_through_dispatch() {
    let harness = match DovecotHarness::try_start() {
        Ok(h) => h,
        Err(HarnessError::DockerUnavailable) => return,
        Err(e) => panic!("Dovecot harness failed: {e}"),
    };
    harness.create_mailbox("Sent");

    // The happy-path server and its rejecting counterpart share one Dovecot
    // container but hold independent SMTP fakes and rate governors.
    let ok_fake = FakeSmtpSender::new();
    let ok = build_server(&harness, ok_fake.clone());

    let ok_uid = seed_forward_source(&ok.server, FORWARD_OK_SUBJECT, FORWARD_OK_BODY).await;
    let fail_uid = seed_forward_source(&ok.server, FORWARD_FAIL_SUBJECT, FORWARD_FAIL_BODY).await;

    assert_send_email_happy_path(&ok.server, &ok_fake).await;
    assert_forward_happy_path(&ok.server, &ok_fake, ok_uid).await;

    let bad_fake = FakeSmtpSender::rejecting("550 5.7.1 blocked by policy");
    let bad = build_server(&harness, bad_fake.clone());

    assert_send_email_smtp_failure(&bad.server, &bad_fake).await;
    assert_forward_smtp_failure(&bad.server, &bad_fake, fail_uid).await;
}

async fn assert_send_email_happy_path(server: &ImapMcpServer, spy: &FakeSmtpSender) {
    let subject = "e2e-smtp-send-happy";
    let before = spy.call_count();
    let result = call_tool(
        server,
        "send_email",
        serde_json::json!({
            "to": [{"address": "rcpt@example.com"}],
            "cc": [{"address": "cc@example.com"}],
            "bcc": [{"address": "blind@secret.example"}],
            "subject": subject,
            "body_text": "hello from the send_email e2e",
        }),
    )
    .await
    .expect("send_email failed");

    assert_eq!(result["meta"]["sent"], true);
    assert_eq!(result["meta"]["smtp_status"], "delivered");
    assert_eq!(result["meta"]["sent_copy"]["folder"], "Sent");
    assert_eq!(result["meta"]["sent_copy"]["failed"], false);

    // send_email produced exactly one new submission on the fake.
    let calls = spy.calls();
    assert_eq!(calls.len(), before + 1, "expected one captured send");
    let sent = calls.last().expect("a captured send");

    // Envelope: MAIL FROM is the account username; RCPT TO unions To+Cc+Bcc
    // (in that order) so blind recipients are still delivered.
    assert_eq!(sent.envelope.from, ACCOUNT_USERNAME);
    assert_eq!(
        sent.envelope.to,
        vec!["rcpt@example.com", "cc@example.com", "blind@secret.example"],
    );

    // On-wire RFC 5322 bytes: headers + recipients, and no Bcc in the DATA.
    let parsed = MessageParser::new()
        .parse(&sent.raw)
        .expect("parse sent bytes");
    assert_eq!(parsed.subject().expect("subject"), subject);
    assert_eq!(first_address(parsed.to()), "rcpt@example.com");
    assert_eq!(first_address(parsed.cc()), "cc@example.com");
    assert!(
        parsed.bcc().is_none(),
        "Bcc header leaked into the sent DATA"
    );
    let raw_text = String::from_utf8_lossy(&sent.raw);
    assert!(
        !raw_text.contains("blind@secret.example"),
        "blind recipient leaked into the sent DATA",
    );
    assert!(
        parsed
            .body_text(0)
            .expect("body")
            .contains("hello from the send_email e2e"),
    );

    // The best-effort Sent copy landed in IMAP — exactly one — and is the
    // same Bcc-free bytes that went on the wire (#432): a regression that
    // archived the pre-stripping bytes would leak the blind recipient into
    // Sent while still matching the subject search. One search serves the
    // count check and the byte-level read-back.
    let sent_search = search_folder(server, "Sent", subject).await;
    assert_eq!(
        match_count(&sent_search),
        1,
        "send_email did not APPEND a copy to Sent",
    );
    let uid = newest_uid(&sent_search).expect("a Sent copy UID");
    let sent_copy = fetch_body(server, "Sent", uid).await;
    let parsed_copy = MessageParser::new()
        .parse(&sent_copy)
        .expect("parse Sent copy");
    assert!(
        parsed_copy.bcc().is_none(),
        "Bcc header leaked into the Sent copy",
    );
    assert!(
        !String::from_utf8_lossy(&sent_copy).contains("blind@secret.example"),
        "blind recipient leaked into the Sent copy",
    );
    assert_eq!(
        parsed_copy.subject().expect("Sent copy subject"),
        subject,
        "Sent copy subject does not match the sent message",
    );
}

/// Assert `raw` is a well-formed forward: a base64 `message/rfc822` wrapper
/// addressed to `expected_to` with a `Fwd:`-prefixed subject, whose original
/// never leaks unencoded and whose wrapper decodes back to `original_body`.
///
/// The decode check is load-bearing: the three string checks alone would
/// still pass a regression that emitted an empty (dropped) base64 part, so
/// the parse confirms the original actually survived the round trip.
fn assert_forward_wrapper(raw: &[u8], expected_to: &str, original_body: &str) {
    let raw_text = String::from_utf8_lossy(raw);
    assert!(
        raw_text.contains("message/rfc822"),
        "forward missing message/rfc822 wrapper",
    );
    assert!(
        raw_text.to_ascii_lowercase().contains("base64"),
        "forward wrapper must be base64-encoded, not a raw/8bit part",
    );
    assert!(
        !raw_text.contains(original_body),
        "forwarded original leaked unencoded into the bytes",
    );

    let parsed = MessageParser::new()
        .parse(raw)
        .expect("parse forward bytes");
    let subject = parsed.subject().expect("forward subject");
    assert!(
        subject.starts_with("Fwd:"),
        "forward subject not prefixed: {subject}",
    );
    assert_eq!(first_address(parsed.to()), expected_to);

    assert!(
        message_body_contains(&parsed, original_body),
        "base64 message/rfc822 wrapper did not decode back to the original body",
    );
}

/// Whether any text part of `msg` — including inside a nested
/// `message/rfc822` part — contains `needle`. `mail_parser` exposes a
/// decoded `message/rfc822` as `PartType::Message` with its own parts, so a
/// forward's original is reachable only by recursing into it.
fn message_body_contains(msg: &mail_parser::Message<'_>, needle: &str) -> bool {
    msg.parts.iter().any(|p| match &p.body {
        PartType::Text(t) => t.contains(needle),
        PartType::Message(nested) => message_body_contains(nested, needle),
        PartType::Html(_)
        | PartType::Binary(_)
        | PartType::InlineBinary(_)
        | PartType::Multipart(_) => false,
    })
}

async fn assert_forward_happy_path(server: &ImapMcpServer, spy: &FakeSmtpSender, uid: u32) {
    let before = spy.call_count();
    let result = call_tool(
        server,
        "forward",
        serde_json::json!({
            "folder": "INBOX",
            "uid": uid,
            "to": [{"address": "fwd-rcpt@example.com"}],
            "comment": "please see the forwarded message below",
        }),
    )
    .await
    .expect("forward failed");

    assert_eq!(result["meta"]["sent"], true);
    assert_eq!(result["meta"]["source_uid"], uid);
    assert_eq!(result["meta"]["sent_copy"]["failed"], false);

    // forward produced exactly one new submission on the fake.
    let calls = spy.calls();
    assert_eq!(calls.len(), before + 1, "expected one captured send");
    let fwd = calls.last().expect("a captured send");
    assert_eq!(fwd.envelope.to, vec!["fwd-rcpt@example.com"]);

    // The on-wire forward wraps the original as a base64 message/rfc822 part
    // addressed to the forward recipient, decoding back to the original.
    assert_forward_wrapper(&fwd.raw, "fwd-rcpt@example.com", FORWARD_OK_BODY);

    // The Sent copy landed — and is the same wrapper, read back over IMAP.
    // Reapplying the full wrapper check (not just presence) guards against a
    // forward Sent-copy path that diverges from the sent bytes, mirroring the
    // send_email Bcc read-back.
    let sent_search = search_folder(server, "Sent", FORWARD_OK_SUBJECT).await;
    assert_eq!(
        match_count(&sent_search),
        1,
        "forward did not APPEND a copy to Sent",
    );
    let sent_copy = fetch_body(
        server,
        "Sent",
        newest_uid(&sent_search).expect("a Sent copy UID"),
    )
    .await;
    assert_forward_wrapper(&sent_copy, "fwd-rcpt@example.com", FORWARD_OK_BODY);
}

/// Shared tail for the two SMTP-failure scenarios: the tool must surface
/// `ERR_SMTP_PROTOCOL`, the rejected send must still have been captured by
/// the fake, and no Sent copy may exist (the failure short-circuits before
/// the APPEND). `before` is the fake's call count captured before the call.
async fn assert_smtp_rejected(
    server: &ImapMcpServer,
    spy: &FakeSmtpSender,
    before: usize,
    err: &rimap_core::RimapError,
    sent_subject: &str,
) {
    assert_eq!(err.code(), rimap_core::ErrorCode::SmtpProtocol);
    assert_eq!(
        spy.call_count(),
        before + 1,
        "the rejected send should still be captured",
    );
    assert_eq!(
        match_count(&search_folder(server, "Sent", sent_subject).await),
        0,
        "a failed send must not leave a Sent copy",
    );
}

async fn assert_send_email_smtp_failure(server: &ImapMcpServer, spy: &FakeSmtpSender) {
    let subject = "e2e-smtp-send-failure";
    let before = spy.call_count();
    let err = call_tool(
        server,
        "send_email",
        serde_json::json!({
            "to": [{"address": "rcpt@example.com"}],
            "subject": subject,
            "body_text": "this send is rejected at SMTP",
        }),
    )
    .await
    .expect_err("send_email must fail when SMTP rejects");

    assert_smtp_rejected(server, spy, before, &err, subject).await;
}

async fn assert_forward_smtp_failure(server: &ImapMcpServer, spy: &FakeSmtpSender, uid: u32) {
    let before = spy.call_count();
    let err = call_tool(
        server,
        "forward",
        serde_json::json!({
            "folder": "INBOX",
            "uid": uid,
            "to": [{"address": "fwd-rcpt@example.com"}],
        }),
    )
    .await
    .expect_err("forward must fail when SMTP rejects");

    assert_smtp_rejected(server, spy, before, &err, FORWARD_FAIL_SUBJECT).await;
}
