//! In-process TLS-terminating scriptable IMAP fake. Serves an ordered
//! `Vec<Step>` per accepted connection (accept-loop). `start` replays one
//! shared script for every connection so a client's transparent read-only
//! reconnect re-observes the same dialog; `start_sequence` serves a *distinct*
//! script per connection for asymmetric reconnect scenarios (fail, fail,
//! succeed). Drives the real `Connection`.
#![expect(
    clippy::unwrap_used,
    clippy::missing_panics_doc,
    reason = "in-process test fake: unwrap/panic on bind, lock-poison, or scripting errors are test-infra failures"
)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use rimap_core::TlsFingerprint;
use rimap_core::account::AccountId;
use rimap_core::auth_event::AuthEvent;
use rimap_core::auth_sink::{AuthEventSink, AuthSinkError};
use rimap_core::credential::{CredentialResolver, CredentialResolverError, CredentialSource};
use rimap_imap::{Connection, ConnectionConfig, ImapEncryption};
use secrecy::SecretString;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

use crate::certs::{self, SelfSigned};

/// Bounded number of connections the accept-loop serves — a read-only retry
/// needs at most 2, and the longest scripted sequence (fail, fail, succeed)
/// needs 3; the cap prevents a storming client.
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
    /// Drain a client synchronizing-literal payload. The most recent `Expect`
    /// must have read a command line ending in a `{N}` literal declaration (e.g.
    /// an `APPEND ... {N}`); this reads and discards exactly `N` octets plus the
    /// trailing `CRLF` the client writes after the continuation. Consuming the
    /// literal keeps the byte stream aligned for any following command and lets
    /// the connection close with a clean `FIN` — a close with the literal still
    /// unread would `RST` and race with delivery of the tagged reply.
    ExpectLiteral,
    /// Emit `<captured-tag> <text>\r\n` using the most recent `Expect`'s tag.
    Reply {
        /// Status + text after the echoed tag (e.g. `"OK LOGIN completed"`).
        text: &'static str,
    },
    /// Hold the connection open for `duration` without reading or writing,
    /// then continue the script.
    ///
    /// Parks a client that is awaiting a tagged reply, which is the only way
    /// to script a command that is genuinely *in flight* — `Disconnect` ends
    /// it instead. Tests that cut a command mid-flight need that state.
    ///
    /// The duration is bounded rather than infinite because the accept-loop
    /// serves connections **sequentially**: a connection that never finishes
    /// its script would stop the fake from ever accepting the next one, so a
    /// client that reconnects during the stall would hang.
    Stall(Duration),
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
    /// The single `script` is replayed for every accepted connection — the
    /// len-1 case of [`FakeImapServer::start_sequence`].
    pub async fn start(script: Vec<Step>) -> FakeImapServer {
        Self::start_sequence(vec![script]).await
    }

    /// Bind `127.0.0.1:0` and spawn an accept-loop that serves a *distinct*
    /// script per connection: the i-th accepted connection is served
    /// `scripts[i]`, and every connection past the last script replays the
    /// final one (so `start_sequence(vec![script])` is exactly
    /// [`FakeImapServer::start`]). This expresses asymmetric reconnect
    /// scenarios — e.g. fail, fail, then succeed across three connections —
    /// that a single replayed script cannot.
    ///
    /// # Panics
    /// Panics if `scripts` is empty (there is no script to serve).
    pub async fn start_sequence(scripts: Vec<Vec<Step>>) -> FakeImapServer {
        assert!(
            !scripts.is_empty(),
            "start_sequence requires at least one script",
        );
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
        let scripts = Arc::new(scripts);
        let rec_task = Arc::clone(&recorded);

        let task = tokio::spawn(async move {
            let mut served = 0usize;
            for _ in 0..MAX_ACCEPTS {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let Ok(tls) = acceptor.accept(stream).await else {
                    continue;
                };
                let script = scripts
                    .get(served)
                    .unwrap_or_else(|| scripts.last().unwrap());
                served += 1;
                let _ = serve(tls, script, &rec_task).await;
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

    /// Like [`FakeImapServer::recorded`] but rewrites `LOGIN` frames so the
    /// password argument is replaced with `<REDACTED>`. Safe to pass to
    /// `DumpOnPanic` and similar diagnostic helpers when the resolver may carry
    /// a real credential. `assert_login_frame_only` in
    /// `crates/rimap-server/tests/support/canary.rs` intentionally uses
    /// [`FakeImapServer::recorded`] — not this accessor — because it asserts
    /// *on* the credential value inside the LOGIN frame.
    #[must_use]
    pub fn recorded_redacted(&self) -> Vec<String> {
        self.recorded
            .lock()
            .unwrap()
            .iter()
            .map(|frame| redact_login_frame(frame))
            .collect()
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
        self.connection_with(
            username,
            Arc::new(StaticResolver),
            Arc::new(NoopAudit),
            command_timeout,
        )
    }

    /// Inject an arbitrary resolver, auth sink, and command timeout.
    ///
    /// Scenario 2 passes a `PanicResolver` to prove `resolve` is never
    /// consulted. A scenario that asserts on the `auth` records the connect
    /// flow wrote passes a recording `sink` — [`NoopAudit`], which the other
    /// constructors use, makes them invisible.
    #[must_use]
    pub fn connection_with(
        &self,
        username: &str,
        resolver: Arc<dyn CredentialResolver>,
        sink: Arc<dyn AuthEventSink>,
        command_timeout: Duration,
    ) -> Connection {
        let cfg = self.connection_config(username, Some(self.pin), command_timeout);
        Connection::new(cfg, sink, resolver)
    }

    /// Build a `Connection` pinned to `wrong_pin` (which the caller
    /// guarantees differs from [`FakeImapServer::pin`]) to exercise the
    /// live TLS pin-mismatch rejection path. The rustls handshake fails
    /// before any IMAP command is issued, so credential resolution is never
    /// reached — a [`PanicResolver`] bakes that invariant in. A 1s command
    /// timeout is a backstop only; the connect fails at the handshake first.
    #[must_use]
    pub fn connection_wrong_pin(&self, username: &str, wrong_pin: TlsFingerprint) -> Connection {
        let cfg = self.connection_config(username, Some(wrong_pin), Duration::from_secs(1));
        Connection::new(cfg, Arc::new(NoopAudit), Arc::new(PanicResolver))
    }

    /// Assemble a `ConnectionConfig` targeting this fake's loopback port.
    /// `pinned_fingerprint` is the only field callers vary — the correct
    /// [`FakeImapServer::pin`] for the success paths, or a deliberately
    /// wrong fingerprint for the mismatch path.
    fn connection_config(
        &self,
        username: &str,
        pinned_fingerprint: Option<TlsFingerprint>,
        command_timeout: Duration,
    ) -> ConnectionConfig {
        ConnectionConfig {
            account: None,
            account_id: AccountId::default_account(),
            host: "127.0.0.1".to_string(),
            port: self.port,
            encryption: ImapEncryption::Tls,
            username: username.to_string(),
            pinned_fingerprint,
            connect_timeout: Duration::from_secs(5),
            command_timeout,
            max_fetch_body_bytes: 1024 * 1024,
            max_append_bytes: 1024 * 1024,
        }
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
    let mut pending_literal: Option<usize> = None;
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
                let tag_verb: String = line
                    .split_whitespace()
                    .take(2)
                    .collect::<Vec<_>>()
                    .join(" ");
                assert!(
                    rest.trim_start().to_ascii_uppercase().starts_with(verb),
                    "fake: expected command `{verb}`, got `{tag_verb}`",
                );
                pending_literal = parse_sync_literal(&line);
            }
            Step::ExpectLiteral => {
                let len = pending_literal.take();
                assert!(
                    len.is_some(),
                    "fake: ExpectLiteral requires the preceding Expect to have read a command line ending in a `{{N}}` synchronizing literal",
                );
                let mut payload = vec![0u8; len.unwrap()];
                reader.read_exact(&mut payload).await?;
                // Consume the CRLF that terminates the command after the literal.
                let mut trailing = String::new();
                reader.read_line(&mut trailing).await?;
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
            Step::Stall(duration) => tokio::time::sleep(*duration).await,
            Step::Disconnect => return Ok(()), // drop halves → FIN
        }
    }
    Ok(())
}

/// Parse a trailing IMAP synchronizing-literal declaration `{N}` from a command
/// line (e.g. `A5 APPEND "Drafts" {464}`), returning `N`. Returns `None` when
/// the line does not end in a literal marker or the literal is non-synchronizing
/// (`{N+}`) — which the client sends without waiting for a continuation and
/// which the scripts here never exercise.
fn parse_sync_literal(line: &str) -> Option<usize> {
    let inner = line.trim_end().strip_suffix('}')?;
    let open = inner.rfind('{')?;
    let digits = &inner[open + 1..];
    if digits.ends_with('+') {
        return None; // non-synchronizing literal — no continuation, no drain
    }
    digits.parse().ok()
}

/// Rewrite a single recorded client command frame to mask the LOGIN password.
/// A `LOGIN` frame has the form `<tag> LOGIN <user> <pass>\r\n`; this replaces
/// `<pass>` with `<REDACTED>` while leaving every other frame untouched.
fn redact_login_frame(frame: &str) -> String {
    // Fast path: skip the allocation when the frame is not a LOGIN command.
    let upper = frame.to_ascii_uppercase();
    let mut words = upper.split_whitespace();
    words.next(); // tag
    if words.next() != Some("LOGIN") {
        return frame.to_string();
    }
    // Reconstruct from the first three whitespace-separated tokens (tag, verb,
    // user) and replace whatever follows with <REDACTED> + the original line
    // ending.
    let ending = if frame.ends_with("\r\n") {
        "\r\n"
    } else if frame.ends_with('\n') {
        "\n"
    } else {
        ""
    };
    let mut parts = frame.split_whitespace();
    let tag = parts.next().unwrap_or("");
    let login = parts.next().unwrap_or("");
    let user = parts.next().unwrap_or("");
    format!("{tag} {login} {user} <REDACTED>{ending}")
}

/// Resolver returning the password [`FakeImapServer`]'s scripts expect. The
/// default for [`FakeImapServer::connection`] and
/// [`FakeImapServer::connection_timeout`]; public so a caller varying only the
/// auth sink can keep it.
#[derive(Debug)]
pub struct StaticResolver;

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

/// No-op audit sink, for scenarios that assert on the IMAP dialog rather than
/// on what the connect flow recorded. Public for the same reason
/// [`PanicResolver`] is: [`FakeImapServer::connection_with`] takes the sink,
/// so a caller that does not care still has to name one.
#[derive(Debug)]
pub struct NoopAudit;

impl AuthEventSink for NoopAudit {
    fn emit_auth(&self, _event: AuthEvent) -> Result<(), AuthSinkError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{FakeImapServer, Step, login_preamble, parse_sync_literal, redact_login_frame};

    #[test]
    fn parse_sync_literal_reads_trailing_brace_count() {
        assert_eq!(
            parse_sync_literal("A5 APPEND \"Drafts\" (\\Draft) {464}\r\n"),
            Some(464),
        );
        assert_eq!(parse_sync_literal("A1 NOOP\r\n"), None);
        assert_eq!(parse_sync_literal("A5 APPEND x {12+}\r\n"), None);
    }

    /// A synchronizing-literal `APPEND` drained by `ExpectLiteral` leaves the
    /// byte stream aligned, so a second command on the same pooled connection is
    /// read as a command — not as leftover literal bytes. Two back-to-back
    /// appends on one `Connection` prove it: without the drain, the first
    /// message body would be misread as the second `APPEND` line and the second
    /// call would fail. Guards the RST-on-close race #524's triage transcript
    /// hit in CI, where the undrained literal made the close a `RST` that beat
    /// the tagged `OK` to the client.
    #[tokio::test]
    async fn expect_literal_drains_append_payload_keeping_connection_aligned() {
        let mut script = login_preamble("IMAP4rev1 UIDPLUS");
        script.extend([
            Step::Expect { verb: "APPEND" },
            Step::Send(b"+ OK\r\n".to_vec()),
            Step::ExpectLiteral,
            Step::Reply {
                text: "OK [APPENDUID 1 1] APPEND completed",
            },
            Step::Expect { verb: "APPEND" },
            Step::Send(b"+ OK\r\n".to_vec()),
            Step::ExpectLiteral,
            Step::Reply {
                text: "OK [APPENDUID 1 2] APPEND completed",
            },
        ]);
        let server = FakeImapServer::start(script).await;
        let conn = server.connection("user@example.com");

        conn.append_message("Drafts", b"first message body\r\n", &[], &[])
            .await
            .unwrap();
        conn.append_message("Drafts", b"second, longer message body\r\n", &[], &[])
            .await
            .unwrap();

        let appends = server
            .recorded()
            .iter()
            .filter(|line| line.to_ascii_uppercase().contains("APPEND"))
            .count();
        assert_eq!(
            appends, 2,
            "both APPEND command lines must be read as commands, not literal bytes",
        );
    }

    /// A connection the server refuses at LOGIN with a tagged `NO`, so the
    /// client's first operation fails and it issues nothing further. Models a
    /// "failing" connection in a reconnect sequence.
    fn failing_login() -> Vec<Step> {
        vec![
            Step::Send(b"* OK fake ready\r\n".to_vec()),
            Step::Expect { verb: "CAPABILITY" },
            Step::Send(b"* CAPABILITY IMAP4rev1\r\n".to_vec()),
            Step::Reply {
                text: "OK CAPABILITY completed",
            },
            Step::Expect { verb: "LOGIN" },
            Step::Reply {
                text: "NO [AUTHENTICATIONFAILED] invalid credentials",
            },
        ]
    }

    /// A connection that logs in and answers `LIST` successfully. Models a
    /// "healthy" connection.
    fn healthy_list() -> Vec<Step> {
        let mut steps = login_preamble("IMAP4rev1");
        steps.extend([
            Step::Expect { verb: "LIST" },
            Step::Send(b"* LIST (\\HasNoChildren) \"/\" \"INBOX\"\r\n".to_vec()),
            Step::Reply {
                text: "OK LIST completed",
            },
        ]);
        steps
    }

    /// AC proof: a sequence-scripted fake serves fail, fail, succeed across
    /// three independent connections. Each fresh `Connection` opens exactly one
    /// socket (a refused LOGIN does not reconnect), so connection *i* is served
    /// `scripts[i]`. Non-vacuous by construction: were one script replayed for
    /// every connection, the third `list_folders` could not succeed while the
    /// first two fail — no single script satisfies both.
    #[tokio::test]
    async fn start_sequence_serves_distinct_script_per_connection() {
        let server =
            FakeImapServer::start_sequence(vec![failing_login(), failing_login(), healthy_list()])
                .await;

        for attempt in 0..2 {
            let conn = server.connection("user@example.com");
            assert!(
                conn.list_folders("*").await.is_err(),
                "connection {attempt} was scripted to refuse LOGIN, so its first operation must fail",
            );
        }

        let conn = server.connection("user@example.com");
        assert!(
            conn.list_folders("*").await.is_ok(),
            "the third connection is scripted healthy and must succeed — proof it was served a distinct script from the first two",
        );

        // The global ordered recording still attributes every connection's
        // commands: three connections means three LOGINs.
        let logins = server
            .recorded()
            .iter()
            .filter(|line| line.to_ascii_uppercase().contains("LOGIN"))
            .count();
        assert_eq!(
            logins, 3,
            "each of the three connections must issue its own LOGIN",
        );
    }

    /// Unit-level coverage for `redact_login_frame`: LOGIN frames lose the
    /// password field; all other frames are returned unchanged.
    #[test]
    fn redact_login_frame_masks_password_and_passes_through_other_frames() {
        // LOGIN frame: password replaced with <REDACTED>
        assert_eq!(
            redact_login_frame("A3 LOGIN user@example.com s3cr3t\r\n"),
            "A3 LOGIN user@example.com <REDACTED>\r\n",
        );
        // Case-insensitive LOGIN detection
        assert_eq!(
            redact_login_frame("A3 login user@example.com s3cr3t\r\n"),
            "A3 login user@example.com <REDACTED>\r\n",
        );
        // Non-LOGIN frames are passed through verbatim
        assert_eq!(redact_login_frame("A1 CAPABILITY\r\n"), "A1 CAPABILITY\r\n",);
        assert_eq!(
            redact_login_frame("A2 LIST \"\" \"*\"\r\n"),
            "A2 LIST \"\" \"*\"\r\n",
        );
        // Line ending variants
        assert_eq!(
            redact_login_frame("A3 LOGIN user pass\n"),
            "A3 LOGIN user <REDACTED>\n",
        );
        assert_eq!(
            redact_login_frame("A3 LOGIN user pass"),
            "A3 LOGIN user <REDACTED>",
        );
    }

    /// `recorded_redacted()` returns frames with LOGIN passwords masked while
    /// `recorded()` retains the plaintext credential — proving the two
    /// accessors are independent. Also guards that non-LOGIN frames are
    /// identical between the two views.
    #[tokio::test]
    async fn recorded_redacted_masks_login_password_recorded_retains_it() {
        let server = FakeImapServer::start(login_preamble("IMAP4rev1")).await;
        let conn = server.connection("user@example.com");
        // list_folders triggers the full login preamble and then returns an
        // error because the script has no LIST step — that is fine; we only
        // need the preamble frames to be recorded.
        let _ = conn.list_folders("*").await;

        let plain = server.recorded();
        let redacted = server.recorded_redacted();
        assert_eq!(
            plain.len(),
            redacted.len(),
            "redacted view must have the same frame count as the plain view",
        );

        let login_plain: Vec<_> = plain
            .iter()
            .filter(|f| f.to_ascii_uppercase().contains("LOGIN"))
            .collect();
        assert!(
            !login_plain.is_empty(),
            "at least one LOGIN frame must be recorded",
        );
        for frame in &login_plain {
            assert!(
                frame.contains("fake-password"),
                "recorded() must retain the plaintext password in LOGIN frames",
            );
        }

        let login_redacted: Vec<_> = redacted
            .iter()
            .filter(|f| f.to_ascii_uppercase().contains("LOGIN"))
            .collect();
        for frame in &login_redacted {
            assert!(
                !frame.contains("fake-password"),
                "recorded_redacted() must not contain the plaintext password",
            );
            assert!(
                frame.contains("<REDACTED>"),
                "recorded_redacted() LOGIN frame must contain <REDACTED>",
            );
        }

        // Non-LOGIN frames must be identical between the two views.
        let non_login_plain: Vec<_> = plain
            .iter()
            .filter(|f| !f.to_ascii_uppercase().contains("LOGIN"))
            .collect();
        let non_login_redacted: Vec<_> = redacted
            .iter()
            .filter(|f| !f.to_ascii_uppercase().contains("LOGIN"))
            .collect();
        assert_eq!(
            non_login_plain, non_login_redacted,
            "non-LOGIN frames must be identical between recorded() and recorded_redacted()",
        );
    }
}
