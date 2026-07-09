//! In-process TLS-terminating scriptable IMAP fake. Replays an ordered
//! `Vec<Step>` per accepted connection (accept-loop) so a client's transparent
//! read-only reconnect re-observes the same dialog. Drives the real
//! `Connection`.
#![expect(clippy::unwrap_used, reason = "tests")]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use rimap_core::TlsFingerprint;
use rimap_core::account::AccountId;
use rimap_core::auth_event::AuthEvent;
use rimap_core::auth_sink::{AuthEventSink, AuthSinkError};
use rimap_core::credential::{CredentialResolver, CredentialResolverError, CredentialSource};
use rimap_imap::{Connection, ConnectionConfig, ImapEncryption};
use secrecy::SecretString;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

use crate::support::certs::{self, SelfSigned};

/// Bounded number of connections the accept-loop serves — a read-only retry
/// needs at most 2; the cap prevents a storming client.
const MAX_ACCEPTS: usize = 4;

/// Fixed password the static resolver returns.
const FAKE_PASSWORD: &str = "fake-password";

/// One scripted server step.
pub enum Step {
    /// Read one CRLF client command line; assert the verb (after the tag)
    /// case-insensitively starts with `verb`, and capture the tag for `Reply`.
    Expect {
        /// Command verb the next client line must start with.
        verb: &'static str,
    },
    /// Send these bytes verbatim (untagged data, literals, or malformed bytes).
    Send(Vec<u8>),
    /// Emit `<captured-tag> <text>\r\n` using the most recent `Expect`'s tag.
    Reply {
        /// Status + text after the echoed tag (e.g. `"OK LOGIN completed"`).
        text: &'static str,
    },
    /// Drop the connection immediately (prompt FIN, no `close_notify`).
    Disconnect,
}

/// The shared greeting → `CAPABILITY` → `LOGIN` → post-login `CAPABILITY`
/// preamble that every full-login scenario opens with. `caps` is the
/// capability atom list advertised both pre- and post-login (e.g.
/// `"IMAP4rev1 UIDPLUS"`, or `"IMAP4rev1"` for a no-`UIDPLUS`/no-`MOVE`
/// server). Append the scenario-specific steps to the returned vec.
#[must_use]
pub fn login_preamble(caps: &str) -> Vec<Step> {
    let cap_line = format!("* CAPABILITY {caps}\r\n").into_bytes();
    vec![
        Step::Send(b"* OK fake ready\r\n".to_vec()),
        Step::Expect { verb: "CAPABILITY" },
        Step::Send(cap_line.clone()),
        Step::Reply {
            text: "OK CAPABILITY completed",
        },
        Step::Expect { verb: "LOGIN" },
        Step::Reply {
            text: "OK LOGIN completed",
        },
        Step::Expect { verb: "CAPABILITY" },
        Step::Send(cap_line),
        Step::Reply {
            text: "OK CAPABILITY completed",
        },
    ]
}

/// A running fake. Drop aborts the accept-loop and closes the listener.
pub struct FakeImapServer {
    port: u16,
    pin: TlsFingerprint,
    recorded: Arc<Mutex<Vec<String>>>,
    task: JoinHandle<()>,
}

impl Drop for FakeImapServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl FakeImapServer {
    /// Bind `127.0.0.1:0`, spawn the accept-loop, and return once listening.
    pub async fn start(script: Vec<Step>) -> FakeImapServer {
        let SelfSigned { chain, key, pin } = certs::self_signed();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let recorded = Arc::new(Mutex::new(Vec::new()));
        let script = Arc::new(script);
        let rec_task = Arc::clone(&recorded);

        let task = tokio::spawn(async move {
            for _ in 0..MAX_ACCEPTS {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let Ok(tls) = acceptor.accept(stream).await else {
                    continue;
                };
                let _ = serve(tls, &script, &rec_task).await;
            }
        });

        FakeImapServer {
            port,
            pin,
            recorded,
            task,
        }
    }

    /// Loopback port the fake is listening on.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Leaf-cert fingerprint the client must pin to accept the fake.
    #[must_use]
    pub fn pin(&self) -> TlsFingerprint {
        self.pin
    }

    /// Snapshot of client command lines read so far (for ordering assertions).
    #[must_use]
    pub fn recorded(&self) -> Vec<String> {
        self.recorded.lock().unwrap().clone()
    }

    /// Fully-wired `Connection` (static-password resolver, ~1s timeout).
    #[must_use]
    pub fn connection(&self, username: &str) -> Connection {
        self.connection_timeout(username, Duration::from_secs(1))
    }

    /// Static-resolver connection with a caller-chosen command timeout
    /// (scenario 4 uses a generous 5s backstop).
    #[must_use]
    pub fn connection_timeout(&self, username: &str, command_timeout: Duration) -> Connection {
        self.connection_with(username, Arc::new(StaticResolver), command_timeout)
    }

    /// Inject an arbitrary resolver and command timeout (scenario 2 uses a
    /// `PanicResolver` to prove `resolve` is never consulted).
    #[must_use]
    pub fn connection_with(
        &self,
        username: &str,
        resolver: Arc<dyn CredentialResolver>,
        command_timeout: Duration,
    ) -> Connection {
        let cfg = ConnectionConfig {
            account: None,
            account_id: AccountId::default_account(),
            host: "127.0.0.1".to_string(),
            port: self.port,
            encryption: ImapEncryption::Tls,
            username: username.to_string(),
            pinned_fingerprint: Some(self.pin),
            connect_timeout: Duration::from_secs(5),
            command_timeout,
            max_fetch_body_bytes: 1024 * 1024,
            max_append_bytes: 1024 * 1024,
        };
        Connection::new(cfg, Arc::new(NoopAudit), resolver)
    }
}

async fn serve(
    tls: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    script: &[Step],
    recorded: &Arc<Mutex<Vec<String>>>,
) -> std::io::Result<()> {
    let (read, mut write) = tokio::io::split(tls);
    let mut reader = BufReader::new(read);
    let mut last_tag = String::new();
    for step in script {
        match step {
            Step::Expect { verb } => {
                let mut line = String::new();
                let n = reader.read_line(&mut line).await?;
                if n == 0 {
                    return Ok(()); // client closed
                }
                recorded.lock().unwrap().push(line.clone());
                let (tag, rest) = line.split_once(' ').unwrap_or((line.trim(), ""));
                last_tag = tag.to_string();
                assert!(
                    rest.trim_start().to_ascii_uppercase().starts_with(verb),
                    "fake: expected command `{verb}`, got `{}`",
                    line.trim(),
                );
            }
            Step::Send(bytes) => {
                write.write_all(bytes).await?;
                write.flush().await?;
            }
            Step::Reply { text } => {
                let line = format!("{last_tag} {text}\r\n");
                write.write_all(line.as_bytes()).await?;
                write.flush().await?;
            }
            Step::Disconnect => return Ok(()), // drop halves → FIN
        }
    }
    Ok(())
}

/// Resolver returning a fixed password. Used by `connection`.
#[derive(Debug)]
struct StaticResolver;

impl CredentialResolver for StaticResolver {
    fn resolve(
        &self,
        _account: &AccountId,
        _username: &str,
        _host: &str,
    ) -> Result<(SecretString, CredentialSource), CredentialResolverError> {
        Ok((
            SecretString::from(FAKE_PASSWORD.to_string()),
            CredentialSource::Keyring,
        ))
    }
}

/// Resolver that panics if consulted — proves the pre-resolve error paths
/// (e.g. `LOGINDISABLED`) never reach credential resolution.
#[derive(Debug)]
pub struct PanicResolver;

impl CredentialResolver for PanicResolver {
    #[expect(
        clippy::panic,
        clippy::panic_in_result_fn,
        reason = "deliberate: proves the resolver is never called"
    )]
    fn resolve(
        &self,
        _account: &AccountId,
        _username: &str,
        _host: &str,
    ) -> Result<(SecretString, CredentialSource), CredentialResolverError> {
        panic!("credential resolver must not be consulted on this path");
    }
}

/// No-op audit sink.
#[derive(Debug)]
struct NoopAudit;

impl AuthEventSink for NoopAudit {
    fn emit_auth(&self, _event: AuthEvent) -> Result<(), AuthSinkError> {
        Ok(())
    }
}
