//! Real-socket SMTP e2e: `send_email` and `forward` through the dispatch
//! pipeline against a real Mailpit SMTP endpoint, with a real `SmtpClient`
//! injected on the `AccountState.smtp` seam (in place of `FakeSmtpSender`) and
//! a Dovecot fixture backing the IMAP Sent-copy read-back.
//!
//! Unlike `e2e_smtp.rs` (which injects an in-memory fake and asserts captured
//! bytes), this drives the production `SmtpClient` dialog over a socket and
//! fetches the delivered message from Mailpit's HTTP API, so the on-wire bytes
//! and multipart structure are asserted post-delivery.
//!
//! Container-gated: silent-skips when no runtime is available. Set
//! `RIMAP_REQUIRE_DOCKER=1` to fail loudly instead.

#![expect(clippy::expect_used, reason = "tests")]
#![expect(clippy::panic, reason = "test diagnostics")]

#[path = "support/dovecot/mod.rs"]
mod dovecot;
#[path = "support/mailpit/mod.rs"]
mod mailpit;

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use mail_parser::{MessageParser, PartType};
use rimap_audit::{AuditOptions, AuditWriter, Seq};
use rimap_authz::DispatchGuard;
use rimap_authz::breaker::{BreakerConfig, CircuitBreaker, SystemClock};
use rimap_authz::matrix::EffectiveMatrix;
use rimap_authz::rate_limit::Governor;
use rimap_config::credential::CredentialStore;
use rimap_config::model::{ImapConfig, ImapEncryption, SmtpConfig, SmtpEncryption};
use rimap_config::validate::ValidatedAccountConfig;
use rimap_core::account::AccountId;
use rimap_core::posture::Posture;
use rimap_imap::{Connection, ConnectionConfig};
use tempfile::TempDir;

use dovecot::{DovecotHarness, HarnessError};
use mailpit::MailpitHarness;
use rimap_server::mcp::server::ImapMcpServer;

// A valid-email IMAP username: the tool reuses it as the SMTP MAIL FROM, which
// the real client parses and rejects if it lacks a domain. Dovecot's
// `auth_username_format` normalizes it back to the stored `rimap-test` user.
const ACCOUNT_USERNAME: &str = "rimap-test@example.com";

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

/// One in-process server plus the tempdirs its audit/download roots live in.
struct ServerScope {
    _audit_dir: TempDir,
    download_dir: TempDir,
    server: ImapMcpServer,
}

impl ServerScope {
    fn download_dir(&self) -> &Path {
        self.download_dir.path()
    }
}

/// Build a `Full`-posture in-process server whose SMTP sender is a real
/// `SmtpClient` pointed at `mailpit`, with `dovecot` backing IMAP.
/// `special_use` sets the resolved Sent folder: `default()` → `"Sent"` (which
/// the fixture auto-creates), or a map pointing Sent at a nonexistent folder to
/// exercise the copy-to-Sent fail-open path.
fn build_server_real(
    dovecot: &DovecotHarness,
    mailpit: &MailpitHarness,
    special_use: rimap_imap::SpecialUseMap,
) -> ServerScope {
    let audit_dir = TempDir::new().expect("audit tempdir");
    let download_dir = TempDir::new().expect("download tempdir");

    let audit = AuditWriter::open(&AuditOptions::new(
        audit_dir.path().join("audit.jsonl"),
        Seq::FIRST,
    ))
    .expect("audit open");

    let account_cfg = test_account_config(dovecot);
    let imap = test_connection(dovecot, &audit);
    let guard = test_guard(&account_cfg);
    let folder_guard = rimap_authz::FolderGuard::new(
        &account_cfg.security.protected_folders,
        &account_cfg.security.expunge_folders,
    );

    let smtp_cfg = SmtpConfig::new(
        "127.0.0.1".into(),
        mailpit.smtp_port(),
        SmtpEncryption::None,
        ACCOUNT_USERNAME.into(),
    );
    let smtp = rimap_smtp::SmtpClient::new(&smtp_cfg, "RIMAP-CANARY-DVC-9f83b1a7c0d6e4f2")
        .expect("smtp client");

    let id = account_cfg.id.clone();
    let state = rimap_server::boot::registry::AccountState {
        id: id.clone(),
        imap,
        smtp: Some(Box::new(smtp)),
        guard,
        folder_guard,
        download_dir: Arc::from(download_dir.path().to_path_buf().into_boxed_path()),
        special_use,
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
        download_dir,
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

async fn search_folder(server: &ImapMcpServer, folder: &str, subject: &str) -> serde_json::Value {
    call_tool(
        server,
        "search",
        serde_json::json!({ "folder": folder, "subject": subject }),
    )
    .await
    .expect("search failed")
}

fn match_count(search_result: &serde_json::Value) -> u64 {
    search_result["meta"]["total_matched"]
        .as_u64()
        .expect("total_matched")
}

fn newest_uid(search_result: &serde_json::Value) -> Option<u32> {
    let uid = search_result["untrusted"]["messages"]
        .as_array()
        .expect("messages array")
        .iter()
        .filter_map(|m| m["uid"].as_u64())
        .max()?;
    Some(u32::try_from(uid).expect("uid fits u32"))
}

fn forward_source(subject: &str, body: &str) -> Vec<u8> {
    format!(
        "From: origin@example.com\r\n\
         To: {ACCOUNT_USERNAME}\r\n\
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

async fn seed_forward_source(server: &ImapMcpServer, subject: &str, body: &str) -> u32 {
    let account = server.registry().resolve(None).expect("resolve account");
    account
        .imap
        .append_message("INBOX", &forward_source(subject, body), &[], &[])
        .await
        .expect("APPEND to INBOX failed");
    newest_uid(&search_folder(server, "INBOX", subject).await).expect("seeded message has a UID")
}

fn first_address<'a>(header: Option<&'a mail_parser::Address<'a>>) -> &'a str {
    header
        .expect("address header present")
        .first()
        .expect("at least one address")
        .address()
        .expect("address value")
}

/// Whether any text part of `msg` — including inside a nested `message/rfc822`
/// part — contains `needle`.
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

/// Assert `raw` is a well-formed forward: a base64 `message/rfc822` wrapper
/// addressed to `expected_to` with a `Fwd:` subject whose original decodes back
/// to `original_body`.
fn assert_forward_wrapper(raw: &[u8], expected_to: &str, original_body: &str) {
    let raw_text = String::from_utf8_lossy(raw);
    assert!(
        raw_text.contains("message/rfc822"),
        "forward missing message/rfc822 wrapper",
    );
    assert!(
        raw_text.to_ascii_lowercase().contains("base64"),
        "forward wrapper must be base64-encoded",
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

// ── Tests ───────────────────────────────────────────────────────────

#[tokio::test]
async fn send_email_real_socket_delivers_multipart_and_copies() {
    let dovecot = match DovecotHarness::try_start() {
        Ok(h) => h,
        Err(HarnessError::DockerUnavailable) => return,
        Err(e) => panic!("dovecot: {e}"),
    };
    let mailpit = match MailpitHarness::try_start() {
        Ok(h) => h,
        Err(mailpit::HarnessError::DockerUnavailable) => return,
        Err(e) => panic!("mailpit: {e}"),
    };
    dovecot.create_mailbox("Sent");
    let scope = build_server_real(&dovecot, &mailpit, rimap_imap::SpecialUseMap::default());

    // Attachments are read from the account's download-sandbox root by absolute
    // path; stage a file there.
    let attachment_path = scope.download_dir().join("note.txt");
    std::fs::write(&attachment_path, b"hello attachment").expect("stage attachment");

    let subject = "e2e-smtp-real-multipart";
    let result = call_tool(
        &scope.server,
        "send_email",
        serde_json::json!({
            "to": [{"address": "rcpt@example.com"}],
            "bcc": [{"address": "blind@secret.example"}],
            "subject": subject,
            "body_text": "hello over a real socket",
            "attachments": [{
                "path": attachment_path.to_str().expect("utf-8 path"),
                "content_type": "text/plain"
            }],
        }),
    )
    .await
    .expect("send_email failed");

    assert_eq!(result["meta"]["sent"], true);

    // Delivered bytes fetched from Mailpit: assert the multipart structure
    // survived real delivery and the blind recipient is not disclosed in the
    // visible To/Cc headers. NOTE: this does NOT verify DATA-level Bcc-header
    // stripping (#432) — Mailpit synthesizes a `Bcc` header from envelope-only
    // recipients, so the delivered raw cannot distinguish a stripped-DATA
    // client from a leaking one. The byte-level #432 regression net is the
    // fake-based `e2e_smtp.rs`; here we verify non-disclosure in To/Cc only.
    let raw = mailpit
        .fetch_raw_by_subject(subject)
        .expect("delivered message not found in Mailpit");
    let parsed = MessageParser::new().parse(&raw).expect("parse delivered");
    assert_eq!(parsed.subject().expect("subject"), subject);
    assert!(
        parsed.attachment_count() >= 1,
        "attachment did not survive delivery",
    );

    // #432: the blind recipient is delivered via the SMTP envelope but must
    // never be disclosed in the visible To/Cc headers of the DATA. Mailpit
    // synthesizes a `Bcc` header from envelope-only recipients (a sink
    // convenience — its presence confirms `blind@` was delivered
    // envelope-only), so assert on the visible recipient headers rather than a
    // raw-substring check.
    let to_addrs: Vec<&str> = parsed
        .to()
        .into_iter()
        .flat_map(|a| a.iter())
        .filter_map(|addr| addr.address())
        .collect();
    assert_eq!(
        to_addrs,
        vec!["rcpt@example.com"],
        "blind recipient leaked into the visible To header",
    );
    let cc_has_blind = parsed
        .cc()
        .into_iter()
        .flat_map(|a| a.iter())
        .filter_map(|addr| addr.address())
        .any(|addr| addr == "blind@secret.example");
    assert!(!cc_has_blind, "blind recipient leaked into the Cc header");

    // Sent copy landed over IMAP (read-back, independent of self-report).
    let sent = search_folder(&scope.server, "Sent", subject).await;
    assert_eq!(match_count(&sent), 1, "send_email did not APPEND to Sent");
}

/// A `SpecialUseMap` whose resolved Sent folder is a valid-named but
/// nonexistent mailbox, so the copy-to-Sent APPEND fails against the live IMAP
/// server (the fixture auto-creates `Sent`, so an absent-`Sent` approach would
/// not fail). Exercises the fail-open path.
fn nonexistent_sent_map() -> rimap_imap::SpecialUseMap {
    let folder = rimap_imap::types::Folder {
        name: "NonexistentSentFolder".into(),
        attributes: Vec::new(),
        delimiter: Some('/'),
        special_use: Some(rimap_imap::SpecialUse::Sent),
    };
    rimap_imap::SpecialUseMap::from_folders(&[folder])
}

#[tokio::test]
async fn send_email_real_socket_sent_copy_fails_open() {
    // Own harnesses (do not share a container with the happy-path test).
    let dovecot = match DovecotHarness::try_start() {
        Ok(h) => h,
        Err(HarnessError::DockerUnavailable) => return,
        Err(e) => panic!("dovecot: {e}"),
    };
    let mailpit = match MailpitHarness::try_start() {
        Ok(h) => h,
        Err(mailpit::HarnessError::DockerUnavailable) => return,
        Err(e) => panic!("mailpit: {e}"),
    };
    let scope = build_server_real(&dovecot, &mailpit, nonexistent_sent_map());

    let result = call_tool(
        &scope.server,
        "send_email",
        serde_json::json!({
            "to": [{"address": "rcpt@example.com"}],
            "subject": "e2e-smtp-real-failopen",
            "body_text": "sent even though Sent copy fails",
        }),
    )
    .await
    .expect("send_email failed");

    // Delivery succeeded even though the Sent APPEND could not (folder absent).
    assert_eq!(result["meta"]["sent"], true);
    assert_eq!(result["meta"]["sent_copy"]["failed"], true);
}

#[tokio::test]
async fn forward_real_socket_delivers_wrapper() {
    // Own harnesses (per-test isolation).
    let dovecot = match DovecotHarness::try_start() {
        Ok(h) => h,
        Err(HarnessError::DockerUnavailable) => return,
        Err(e) => panic!("dovecot: {e}"),
    };
    let mailpit = match MailpitHarness::try_start() {
        Ok(h) => h,
        Err(mailpit::HarnessError::DockerUnavailable) => return,
        Err(e) => panic!("mailpit: {e}"),
    };
    dovecot.create_mailbox("Sent");
    let scope = build_server_real(&dovecot, &mailpit, rimap_imap::SpecialUseMap::default());

    let subject = "e2e-smtp-real-forward-src";
    let body = "original body forwarded over a real socket";
    let uid = seed_forward_source(&scope.server, subject, body).await;

    let result = call_tool(
        &scope.server,
        "forward",
        serde_json::json!({
            "folder": "INBOX",
            "uid": uid,
            "to": [{"address": "fwd-rcpt@example.com"}],
            "comment": "see the forwarded message below",
        }),
    )
    .await
    .expect("forward failed");
    assert_eq!(result["meta"]["sent"], true);

    // The delivered forward wraps the original as a base64 message/rfc822 part.
    let fwd_subject = format!("Fwd: {subject}");
    let raw = mailpit
        .fetch_raw_by_subject(&fwd_subject)
        .expect("delivered forward not found in Mailpit");
    assert_forward_wrapper(&raw, "fwd-rcpt@example.com", body);
}
