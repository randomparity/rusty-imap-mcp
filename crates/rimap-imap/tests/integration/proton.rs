//! Proton Bridge integration tests. Local only — never runs in CI.

#![expect(clippy::unwrap_used, reason = "tests")]
#![expect(clippy::expect_used, reason = "tests")]

mod support;

use std::sync::Arc;
use std::time::Duration;

use rimap_audit::{AuditOptions, AuditWriter, Seq};
use rimap_config::credential::CredentialStore;
use rimap_core::TlsFingerprint;
use rimap_imap::types::FetchSpec;
use rimap_imap::{Connection, ConnectionConfig};

struct EnvCreds(String);
impl CredentialStore for EnvCreds {
    fn get_password(
        &self,
        _: &str,
    ) -> Result<Option<secrecy::SecretString>, rimap_config::ConfigError> {
        Ok(Some(secrecy::SecretString::from(self.0.clone())))
    }
    #[expect(clippy::panic, clippy::panic_in_result_fn, reason = "test stub")]
    fn set_password(&self, _: &str, _: &str) -> Result<(), rimap_config::ConfigError> {
        panic!("tests do not write credentials")
    }
}

struct ProtonConfig {
    host: String,
    port: u16,
    user: String,
    pass: String,
    fingerprint: TlsFingerprint,
}

fn require_proton() -> Option<ProtonConfig> {
    if std::env::var("PROTON_BRIDGE_TEST").is_err() {
        return None; // silent skip — print_stderr denied
    }
    let host = std::env::var("PROTON_BRIDGE_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port: u16 = std::env::var("PROTON_BRIDGE_PORT")
        .unwrap_or_else(|_| "1143".to_string())
        .parse()
        .expect("PROTON_BRIDGE_PORT must be a u16");
    let user = std::env::var("PROTON_BRIDGE_USER").expect("PROTON_BRIDGE_USER required");
    let pass = std::env::var("PROTON_BRIDGE_PASS").expect("PROTON_BRIDGE_PASS required");
    let fingerprint_hex =
        std::env::var("PROTON_BRIDGE_FINGERPRINT").expect("PROTON_BRIDGE_FINGERPRINT required");
    let fingerprint = TlsFingerprint::from_hex(&fingerprint_hex).expect("valid hex fingerprint");
    Some(ProtonConfig {
        host,
        port,
        user,
        pass,
        fingerprint,
    })
}

fn build_connection(cfg: &ProtonConfig) -> Connection {
    let dir = tempfile::tempdir().unwrap();
    let audit = AuditWriter::open(&AuditOptions {
        path: dir.path().join("audit.jsonl"),
        rotate_bytes: 0,
        rotate_keep: 0,
        retention_seconds: None,
        fail_open: false,
        initial_seq: Seq::FIRST,
    })
    .unwrap();
    let conn_cfg = ConnectionConfig {
        account: None,
        account_id: rimap_core::account::AccountId::default_account(),
        host: cfg.host.clone(),
        port: cfg.port,
        encryption: rimap_imap::ImapEncryption::Starttls,
        username: cfg.user.clone(),
        pinned_fingerprint: Some(cfg.fingerprint),
        connect_timeout: Duration::from_secs(15),
        command_timeout: Duration::from_secs(60),
        max_fetch_body_bytes: 26_214_400,
        max_append_bytes: 10_485_760,
    };
    let store: Arc<dyn CredentialStore> = Arc::new(EnvCreds(cfg.pass.clone()));
    let creds: Arc<dyn rimap_core::CredentialResolver> =
        Arc::new(rimap_config::credential::KeyringCredentialResolver::new(
            store,
            rimap_config::model::FallbackMode::KeyringThenEnv,
            rimap_config::credential::Protocol::Imap,
        ));
    let sink: Arc<dyn rimap_core::auth_sink::AuthEventSink> = Arc::new(audit);
    Connection::new(conn_cfg, sink, creds)
}

#[tokio::test]
async fn proton_bridge_connect_and_list() {
    let Some(cfg) = require_proton() else {
        return;
    };
    let conn = build_connection(&cfg);
    let folders = conn.list_folders("*").await.unwrap();
    assert!(folders.iter().any(|f| f.name.eq_ignore_ascii_case("INBOX")));
}

#[tokio::test]
async fn proton_bridge_connect_and_fetch_one_envelope() {
    let Some(cfg) = require_proton() else {
        return;
    };
    let conn = build_connection(&cfg);
    let _ = conn.select("INBOX", true).await.unwrap();
    let (uids, _) =
        Box::pin(conn.search("INBOX", rimap_imap::types::SearchQuery::Raw("ALL".into())))
            .await
            .unwrap();
    assert!(!uids.is_empty(), "expected at least one message in INBOX");
    let spec = FetchSpec {
        envelope: true,
        bodystructure: false,
        uid: true,
        flags: true,
        size: true,
    };
    let (msgs, _) = conn.fetch("INBOX", &uids[..1], spec, None).await.unwrap();
    assert_eq!(msgs.len(), 1);
}
