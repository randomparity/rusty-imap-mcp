//! TCP / TLS / STARTTLS handshake helpers for [`Connection`].
//!
//! Holds the methods and free functions that bring a raw [`TcpStream`]
//! up to a `TlsStream<TcpStream>` ready for IMAP login. The plaintext
//! STARTTLS negotiation lives here too, because its CVE-2011-0411
//! defense (drop the buffered `Client` via `into_inner()`) is part of
//! the same handshake path.

use async_imap::imap_proto::{Capability as ImapCapability, Response, Status};
use async_imap::types::UnsolicitedResponse;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::ServerName;

use crate::error::{ImapError, StarttlsFailure, StarttlsRefusal};
use crate::tls::TlsConfigBundle;

use super::{Connection, ImapEncryption, SessionEntry};

impl Connection {
    /// Run TCP connect, TLS establishment, and IMAP login against `bundle`,
    /// all under the account's `connect_timeout` as a single total budget.
    ///
    /// Facts the connect learns on the way — the observed TLS fingerprint, the
    /// credential source — are published to `bundle.last_observed` and
    /// `progress` respectively rather than returned, so a caller cut mid-connect
    /// can still read them. See [`super::ConnectProgress`].
    pub(super) async fn connect_with_bundle(
        &self,
        bundle: &TlsConfigBundle,
        progress: &super::ConnectProgress,
    ) -> Result<SessionEntry, ImapError> {
        let cfg = &self.inner.cfg;
        let total_deadline = cfg.connect_timeout;
        let started = std::time::Instant::now();

        // Name the step an elapsed per-step timeout belongs to. Factors the
        // repeated timeout arm without wrapping the (large) step futures in
        // another async layer.
        let timeout_err = |op: &'static str| move |_| ImapError::Timeout { op };

        // Step 1: TCP connect.
        let tcp = timeout(
            total_deadline,
            TcpStream::connect((cfg.host.as_str(), cfg.port)),
        )
        .await
        .map_err(timeout_err("tcp_connect"))?
        .map_err(ImapError::Connect)?;

        // Step 2: TLS establishment. Branches on encryption mode.
        // The `already_greeted` flag tracks whether the plaintext greeting was
        // already consumed during STARTTLS negotiation (true) or must be read
        // from the TLS stream (false).
        let remaining = total_deadline.saturating_sub(started.elapsed());
        let (tls_stream, already_greeted): (TlsStream<TcpStream>, bool) = match cfg.encryption {
            ImapEncryption::Tls => {
                let s = timeout(remaining, tls_handshake(tcp, bundle, &cfg.host))
                    .await
                    .map_err(timeout_err("tls_handshake"))??;
                (s, false)
            }
            ImapEncryption::Starttls => {
                let s = timeout(remaining, starttls_upgrade(tcp, bundle, &cfg.host))
                    .await
                    .map_err(timeout_err("starttls_upgrade"))??;
                (s, true)
            }
        };

        // Step 3: IMAP greeting + capability check + login. STARTTLS already
        // consumed the plaintext greeting during negotiation; `imap_login` must
        // skip the greeting read in that case.
        let remaining = total_deadline.saturating_sub(started.elapsed());
        timeout(
            remaining,
            self.imap_login(tls_stream, already_greeted, progress),
        )
        .await
        .map_err(timeout_err("imap_login"))?
    }
}

/// Walk the unsolicited-response channel and return `true` on the first
/// `Response::Capabilities` item that contains an `ImapCapability::Atom`
/// matching `atom` (case-insensitive). Returns `false` if the channel is
/// drained without a match.
///
/// The channel is non-blocking at this point: `run_command_and_check_ok`
/// has already returned (the tagged Done was received), so all intermediate
/// responses are already queued.
fn capability_advertised(rx: &async_channel::Receiver<UnsolicitedResponse>, atom: &str) -> bool {
    while let Ok(item) = rx.try_recv() {
        if let UnsolicitedResponse::Other(resp) = item
            && let Response::Capabilities(caps) = resp.parsed()
        {
            for cap in caps {
                if let ImapCapability::Atom(name) = cap
                    && name.eq_ignore_ascii_case(atom)
                {
                    return true;
                }
            }
        }
    }
    false
}

/// Drain the unsolicited-response channel and return `true` if any
/// `Response::Capabilities` item contains the `LOGINDISABLED` atom.
pub(super) fn drain_for_logindisabled(rx: &async_channel::Receiver<UnsolicitedResponse>) -> bool {
    capability_advertised(rx, "LOGINDISABLED")
}

/// Plaintext STARTTLS negotiation: greeting → CAPABILITY → STARTTLS.
/// On success, returns the raw `TcpStream`. The intermediate
/// `async_imap::Client` (and its buffer) is dropped by `into_inner()`,
/// which is the structural defense against CVE-2011-0411-class
/// buffered-plaintext injection.
async fn starttls_negotiate(tcp: TcpStream) -> Result<TcpStream, ImapError> {
    use async_imap::Client as ImapPlainClient;

    let mut client: ImapPlainClient<TcpStream> = ImapPlainClient::new(tcp);

    // Read greeting. Must be OK; BYE → UnexpectedBye.
    let greeting = client
        .read_response()
        .await
        .map_err(|e| ImapError::Connect(std::io::Error::other(format!("read greeting: {e}"))))?
        .ok_or(ImapError::Starttls {
            reason: StarttlsFailure::UnexpectedBye,
        })?;
    match greeting.parsed() {
        Response::Data {
            status: Status::Bye,
            ..
        } => {
            return Err(ImapError::Starttls {
                reason: StarttlsFailure::UnexpectedBye,
            });
        }
        Response::Data {
            status: Status::PreAuth,
            ..
        } => {
            return Err(ImapError::Starttls {
                reason: StarttlsFailure::UnexpectedPreauth,
            });
        }
        _ => {}
    }

    // CAPABILITY + drain for STARTTLS token.
    let (tx, rx) = async_channel::bounded::<UnsolicitedResponse>(32);
    client
        .run_command_and_check_ok("CAPABILITY", Some(tx))
        .await
        .map_err(ImapError::Protocol)?;
    if !drain_for_starttls(&rx) {
        return Err(ImapError::Starttls {
            reason: StarttlsFailure::CapabilityMissing,
        });
    }

    // Issue STARTTLS. Map NO/BAD to ServerRefused; other protocol errors pass through.
    match client.run_command_and_check_ok("STARTTLS", None).await {
        Ok(()) => {}
        Err(async_imap::error::Error::No(_)) => {
            return Err(ImapError::Starttls {
                reason: StarttlsFailure::ServerRefused {
                    tagged_status: StarttlsRefusal::No,
                },
            });
        }
        Err(async_imap::error::Error::Bad(_)) => {
            return Err(ImapError::Starttls {
                reason: StarttlsFailure::ServerRefused {
                    tagged_status: StarttlsRefusal::Bad,
                },
            });
        }
        Err(other) => return Err(ImapError::Protocol(other)),
    }

    // Drop Client (and its ImapStream buffer) by extracting the TcpStream.
    Ok(client.into_inner())
}

/// Drain the unsolicited-response channel and return `true` if any
/// `Response::Capabilities` item contains the `STARTTLS` atom.
fn drain_for_starttls(rx: &async_channel::Receiver<UnsolicitedResponse>) -> bool {
    capability_advertised(rx, "STARTTLS")
}

/// Perform the TLS handshake over an established TCP stream using the
/// provided `TlsConfigBundle`. Pin verification happens inside this call.
pub(crate) async fn tls_handshake(
    tcp: TcpStream,
    bundle: &TlsConfigBundle,
    host: &str,
) -> Result<TlsStream<TcpStream>, ImapError> {
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|_| ImapError::Connect(std::io::Error::other("invalid server name for TLS")))?;
    let connector = TlsConnector::from(bundle.config.clone());
    connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| map_tls_handshake_error(&e))
}

/// Full STARTTLS upgrade: plaintext negotiation + TLS handshake with the
/// same `TlsConfigBundle` the implicit-TLS path uses.
pub(crate) async fn starttls_upgrade(
    tcp: TcpStream,
    bundle: &TlsConfigBundle,
    host: &str,
) -> Result<TlsStream<TcpStream>, ImapError> {
    let tcp = starttls_negotiate(tcp).await?;
    tls_handshake(tcp, bundle, host).await
}

/// Map an `io::ImapError` from the TLS connect call to `ImapError::TlsHandshake`.
/// `connect_inner` will enrich this into `ImapError::Tls { observed, expected }`
/// when the `TlsConfigBundle`'s `last_observed` slot shows a mismatch.
fn map_tls_handshake_error(err: &std::io::Error) -> ImapError {
    ImapError::TlsHandshake(tokio_rustls::rustls::Error::General(err.to_string()))
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "tests")]
#[expect(clippy::panic, reason = "tests")]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use std::io::{Error as IoError, ErrorKind};
    use std::net::SocketAddr;
    use std::sync::Arc;

    use rimap_core::auth_event::AuthEvent;
    use rimap_core::auth_sink::{AuthEventSink, AuthSinkError};
    use rimap_core::credential::{CredentialResolver, CredentialResolverError, CredentialSource};
    use secrecy::SecretString;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::task::JoinHandle;

    use crate::error::{ImapError, StarttlsFailure, StarttlsRefusal};

    use super::super::{Connection, ConnectionConfig, ImapEncryption};

    /// A one-shot scripted IMAP server. Each step either writes bytes or
    /// reads one CRLF-terminated line and checks its prefix. Returns on
    /// script completion or client disconnect.
    pub(super) struct MockImap {
        addr: SocketAddr,
        join: JoinHandle<Result<Vec<String>, IoError>>,
    }

    /// One script step.
    pub(super) enum Step {
        /// Server sends these bytes verbatim (append to response).
        Send(&'static [u8]),
        /// Server reads one CRLF-terminated line; asserts the line
        /// (after the tag) starts with the given uppercase command.
        ExpectCommand(&'static str),
        /// Hold the connection open indefinitely (until the client closes it
        /// or the test drops the mock). Use this as the final step when you
        /// want the client to stall waiting for a reply that never arrives.
        Stall,
    }

    impl MockImap {
        /// Start a listener bound to 127.0.0.1:0 and spawn a task that
        /// accepts one connection and runs the script.
        pub(super) async fn start(script: Vec<Step>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr = listener.local_addr().expect("local_addr");
            let join = tokio::spawn(async move {
                let (stream, _) = listener.accept().await?;
                run_script(stream, script).await
            });
            Self { addr, join }
        }

        pub(super) fn addr(&self) -> SocketAddr {
            self.addr
        }

        /// Wait for the server task to finish; return the list of lines
        /// it read from the client (in the order it read them).
        pub(super) async fn finish(self) -> Result<Vec<String>, IoError> {
            self.join.await.map_err(IoError::other)?
        }
    }

    async fn run_script(stream: TcpStream, script: Vec<Step>) -> Result<Vec<String>, IoError> {
        let (read, mut write) = stream.into_split();
        let mut reader = BufReader::new(read);
        let mut recorded: Vec<String> = Vec::new();
        for step in script {
            match step {
                Step::Send(bytes) => {
                    write.write_all(bytes).await?;
                    write.flush().await?;
                }
                Step::ExpectCommand(cmd) => {
                    let mut line = String::new();
                    let n = reader.read_line(&mut line).await?;
                    if n == 0 {
                        return Err(IoError::new(ErrorKind::UnexpectedEof, "client closed"));
                    }
                    recorded.push(line.clone());
                    // Line is "<tag> <COMMAND> ...\r\n". Split off tag.
                    let rest = line.split_once(' ').map_or("", |(_, r)| r);
                    if !rest.trim_start().to_ascii_uppercase().starts_with(cmd) {
                        return Err(IoError::other(format!(
                            "expected command `{cmd}` but got `{}`",
                            line.trim()
                        )));
                    }
                }
                Step::Stall => {
                    // Hold the connection open until the peer closes it.
                    // Discard any bytes; we just need the socket to stay alive.
                    let mut discard = String::new();
                    let _ = reader.read_line(&mut discard).await;
                    // Stream is dropped here; return normally.
                    return Ok(recorded);
                }
            }
        }
        Ok(recorded)
    }

    #[derive(Debug)]
    pub(super) struct PanicResolver;

    impl CredentialResolver for PanicResolver {
        #[expect(
            clippy::panic_in_result_fn,
            reason = "deliberate: proves resolver is never called"
        )]
        fn resolve(
            &self,
            _account: &rimap_core::account::AccountId,
            _username: &str,
            _host: &str,
        ) -> Result<(SecretString, CredentialSource), CredentialResolverError> {
            panic!("credential resolver must not be invoked before TLS");
        }
    }

    #[derive(Debug)]
    pub(super) struct NoopAudit;

    impl AuthEventSink for NoopAudit {
        fn emit_auth(&self, _event: AuthEvent) -> Result<(), AuthSinkError> {
            Ok(())
        }
    }

    pub(super) fn connection_for(addr: std::net::SocketAddr, timeout_ms: u64) -> Connection {
        let cfg = ConnectionConfig {
            account: None,
            account_id: rimap_core::account::AccountId::default_account(),
            host: addr.ip().to_string(),
            port: addr.port(),
            encryption: ImapEncryption::Starttls,
            username: "unused".to_string(),
            pinned_fingerprint: None,
            connect_timeout: std::time::Duration::from_millis(timeout_ms),
            command_timeout: std::time::Duration::from_secs(1),
            max_fetch_body_bytes: 1024,
            max_append_bytes: 1024,
        };
        Connection::new(cfg, Arc::new(NoopAudit), Arc::new(PanicResolver))
    }

    /// Sink that keeps every emitted [`AuthEvent`] so a test can assert on
    /// the audit trail a connect attempt left behind.
    #[derive(Debug, Default)]
    pub(super) struct RecordingAudit {
        events: std::sync::Mutex<Vec<AuthEvent>>,
    }

    impl RecordingAudit {
        /// The error code of every recorded Failure, in order. The codes
        /// matter and not just the count: since #623 a connect cut by an
        /// enclosing deadline also leaves a Failure behind, so a test that
        /// counted alone could no longer tell the two apart.
        ///
        /// Unlike the sink's own `emit_auth`, this keeps its `.expect`: it is
        /// the test's accessor rather than an implementation of the no-panic
        /// contract, and a poisoned lock here means an earlier panic the test
        /// should fail on rather than read through.
        pub(super) fn failure_codes(&self) -> Vec<rimap_core::ErrorCode> {
            self.events
                .lock()
                .expect("recording sink mutex")
                .iter()
                .filter(|e| e.result == rimap_core::auth_event::AuthResult::Failure)
                .filter_map(|e| e.error_code)
                .collect()
        }
    }

    impl AuthEventSink for RecordingAudit {
        fn emit_auth(&self, event: AuthEvent) -> Result<(), AuthSinkError> {
            match self.events.lock() {
                Ok(mut events) => {
                    events.push(event);
                    Ok(())
                }
                Err(poisoned) => Err(AuthSinkError::new(
                    rimap_core::ErrorCode::Internal,
                    "recording sink lock poisoned",
                    Box::new(std::io::Error::other(poisoned.to_string())),
                )),
            }
        }
    }

    /// A [`RecordingAudit`] whose mutex is poisoned the only way a real one
    /// ever is: a panic raised while the lock was held.
    fn poisoned_recording_audit() -> RecordingAudit {
        let audit = RecordingAudit::default();

        let poisoning = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _held = audit.events.lock().expect("a fresh mutex is unpoisoned");
            // "lock", not "mutex": #681's sweep greps for the latter to find
            // sinks still panicking through their lock, and this fixture is
            // not one of them.
            panic!("poison the recording sink lock (test)");
        }));

        assert!(poisoning.is_err(), "the poisoning panic must be raised");
        assert!(
            audit.events.lock().is_err(),
            "the held guard must have dropped during that unwind, which is \
             what poisons the mutex; without it the tests below are vacuous",
        );
        audit
    }

    /// An event whose contents no assertion reads — the tests below are about
    /// what the sink does with the lock, not with the record.
    fn any_auth_event() -> AuthEvent {
        AuthEvent::new(
            rimap_core::auth_event::AuthResult::Failure,
            "127.0.0.1".to_string(),
            143,
            "unused".to_string(),
            None,
            None,
            Some(rimap_core::ErrorCode::Internal),
            None,
        )
    }

    /// A poisoned lock must be *reported*, because [`AuthEventSink`] forbids
    /// panicking and this sink is an implementation of it like any other.
    ///
    /// #646 wrapped the crate's one call into the trait in `catch_unwind`, so
    /// the `.expect` this replaces no longer failed a test loudly: the panic
    /// was caught, the record counted as lost, and the reader left with a
    /// count mismatch several frames from its cause (#681). Fixing the sink
    /// removes the mismatch rather than relying on the backstop to soften it.
    #[test]
    fn a_poisoned_recording_sink_reports_the_poison_rather_than_panicking() {
        let audit = poisoned_recording_audit();

        let err = audit
            .emit_auth(any_auth_event())
            .expect_err("a poisoned lock cannot record the event");

        assert_eq!(
            err.code(),
            rimap_core::ErrorCode::Internal,
            "a broken sink is an internal fault, not a transport one",
        );
    }

    /// The shape that actually aborts: the sink's write running in a `Drop`
    /// while an unwind is already in flight. Rust treats a panic escaping a
    /// destructor during cleanup as unrecoverable and calls `abort` — no
    /// second unwind, no test failure to read, just SIGABRT.
    ///
    /// The test above covers the ordinary call and fails ordinarily; this one
    /// is why the contract exists at all. `Connection::emit_auth` contains a
    /// sink panic at the crate's one call site (#646), so the write is dropped
    /// into an unwind directly here rather than driven through a connect —
    /// that containment is a backstop for a broken sink, not a licence for
    /// one, and a test routed through it would pass whatever this sink did.
    #[test]
    fn a_poisoned_recording_sink_written_during_an_unwind_does_not_abort() {
        struct EmitOnDrop<'a> {
            audit: &'a RecordingAudit,
            rejected: &'a std::cell::Cell<bool>,
        }

        impl Drop for EmitOnDrop<'_> {
            fn drop(&mut self) {
                let lost = self.audit.emit_auth(any_auth_event());
                self.rejected.set(lost.is_err());
            }
        }

        let audit = poisoned_recording_audit();
        let rejected = std::cell::Cell::new(false);

        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _emitter = EmitOnDrop {
                audit: &audit,
                rejected: &rejected,
            };
            panic!("an unwind passing through the connect");
        }));

        assert!(
            caught.is_err(),
            "the outer panic must unwind normally; reaching this line at all \
             means the sink's write did not abort the process",
        );
        assert!(
            rejected.get(),
            "the drop must have reached the sink and had its write rejected — \
             surviving the unwind proves nothing if nothing was emitted, and \
             the flag is set after the call so it also pins that `emit_auth` \
             returned rather than diverged",
        );
    }

    fn connection_with_budgets(
        addr: std::net::SocketAddr,
        connect_ms: u64,
        command_ms: u64,
        audit: Arc<RecordingAudit>,
    ) -> Connection {
        let cfg = ConnectionConfig {
            account: None,
            account_id: rimap_core::account::AccountId::default_account(),
            host: addr.ip().to_string(),
            port: addr.port(),
            encryption: ImapEncryption::Starttls,
            username: "unused".to_string(),
            pinned_fingerprint: None,
            connect_timeout: std::time::Duration::from_millis(connect_ms),
            command_timeout: std::time::Duration::from_millis(command_ms),
            max_fetch_body_bytes: 1024,
            max_append_bytes: 1024,
        };
        Connection::new(cfg, audit, Arc::new(PanicResolver))
    }

    /// A connect-phase stall must always leave an `auth` Failure behind, no
    /// matter how `command_timeout` compares to `connect_timeout`.
    ///
    /// `connect_inner` documents "exactly one `Auth` audit record on every
    /// termination path", but a *Failure* record with the connect's own
    /// verdict is written only if the connect deadline is the one that fires.
    /// When the enclosing command deadline is shorter (or merely starts
    /// earlier, as it always does), it cancels the connect future while it is
    /// still parked on the network. Before #623 that lost the record silently —
    /// no error, no emit — which is what dropped the nightly-chaos `auth`
    /// Failure that scenario 1 asserts on; since #623 `AuthEmitGuard` writes an
    /// `ERR_CANCELLED` record instead. Either way the budget split is what
    /// keeps the record here a real timeout, so the count below still reads the
    /// split rather than the guard.
    #[tokio::test]
    async fn connect_stall_emits_auth_failure_whatever_the_command_budget() {
        // (connect_ms, command_ms): the tight-command case that chaos
        // scenarios 2 and 5 use, and the equal case from scenario 1.
        for (connect_ms, command_ms) in [(600, 100), (400, 400)] {
            let mock = MockImap::start(vec![
                Step::Send(b"* OK ready\r\n"),
                Step::ExpectCommand("CAPABILITY"),
                Step::Stall,
            ])
            .await;

            let audit = Arc::new(RecordingAudit::default());
            let conn =
                connection_with_budgets(mock.addr(), connect_ms, command_ms, Arc::clone(&audit));
            let err = conn.list_folders("*").await.unwrap_err();
            assert!(
                matches!(err, ImapError::Timeout { .. }),
                "connect stall must surface a timeout for \
                 connect={connect_ms}ms/command={command_ms}ms, got {err:?}",
            );
            assert_eq!(
                audit.failure_codes(),
                vec![rimap_core::ErrorCode::Timeout],
                "connect stall must emit exactly one auth Failure, carrying the \
                 connect's own timeout rather than the ERR_CANCELLED a cut \
                 connect records, for \
                 connect={connect_ms}ms/command={command_ms}ms",
            );
            let _ = mock.finish().await;
        }
    }

    #[test]
    fn map_tls_handshake_error_wraps_io_error() {
        let io_err = std::io::Error::other("handshake boom");
        let mapped = super::map_tls_handshake_error(&io_err);
        match mapped {
            ImapError::TlsHandshake(e) => {
                assert!(e.to_string().contains("handshake boom"));
            }
            other => panic!("expected TlsHandshake variant, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn connect_with_starttls_capability_missing_does_not_resolve_credentials() {
        let mock = MockImap::start(vec![
            Step::Send(b"* OK ready\r\n"),
            Step::ExpectCommand("CAPABILITY"),
            Step::Send(b"* CAPABILITY IMAP4rev1\r\n"),
            Step::Send(b"A0001 OK CAPABILITY completed\r\n"),
        ])
        .await;

        let conn = connection_for(mock.addr(), 5000);
        let err = conn.list_folders("*").await.unwrap_err();
        match err {
            ImapError::Starttls {
                reason: StarttlsFailure::CapabilityMissing,
            } => {}
            other => panic!("expected CapabilityMissing, got {other:?}"),
        }
        let _ = mock.finish().await;
    }

    #[tokio::test]
    async fn connect_with_starttls_stall_times_out_with_starttls_upgrade_op() {
        // Mock greets, reads CAPABILITY, then stalls (never sends a reply).
        // The client waits for the CAPABILITY response. The 100ms
        // connect_timeout fires and must surface the distinctive op tag.
        let mock = MockImap::start(vec![
            Step::Send(b"* OK ready\r\n"),
            Step::ExpectCommand("CAPABILITY"),
            // Stall: hold the connection open; never send the CAPABILITY reply.
            Step::Stall,
        ])
        .await;

        let conn = connection_for(mock.addr(), 100);
        let err = conn.list_folders("*").await.unwrap_err();
        match err {
            ImapError::Timeout { op } => assert_eq!(op, "starttls_upgrade"),
            other => panic!("expected Timeout(starttls_upgrade), got {other:?}"),
        }
        let _ = mock.finish().await;
    }

    #[tokio::test]
    async fn negotiate_capability_missing() {
        let mock = MockImap::start(vec![
            Step::Send(b"* OK IMAP ready\r\n"),
            Step::ExpectCommand("CAPABILITY"),
            // Advertise LOGIN-related caps but NOT STARTTLS.
            Step::Send(b"* CAPABILITY IMAP4rev1 AUTH=PLAIN\r\n"),
            Step::Send(b"A0001 OK CAPABILITY completed\r\n"),
        ])
        .await;

        let tcp = tokio::net::TcpStream::connect(mock.addr()).await.unwrap();
        let err = super::starttls_negotiate(tcp).await.unwrap_err();
        match err {
            ImapError::Starttls {
                reason: StarttlsFailure::CapabilityMissing,
            } => {}
            other => panic!("expected CapabilityMissing, got {other:?}"),
        }

        // Server-side: no STARTTLS command was issued before the client
        // errored out. `recorded` must be exactly one line (CAPABILITY).
        let recorded = mock.finish().await.unwrap();
        assert_eq!(recorded.len(), 1);
        assert!(recorded[0].to_ascii_uppercase().contains("CAPABILITY"));
    }

    #[tokio::test]
    async fn negotiate_unexpected_bye() {
        let mock = MockImap::start(vec![Step::Send(b"* BYE go away\r\n")]).await;

        let tcp = tokio::net::TcpStream::connect(mock.addr()).await.unwrap();
        let err = super::starttls_negotiate(tcp).await.unwrap_err();
        match err {
            ImapError::Starttls {
                reason: StarttlsFailure::UnexpectedBye,
            } => {}
            other => panic!("expected UnexpectedBye, got {other:?}"),
        }
        let _ = mock.finish().await;
    }

    #[tokio::test]
    async fn negotiate_unexpected_preauth() {
        let mock =
            MockImap::start(vec![Step::Send(b"* PREAUTH pre-authenticated session\r\n")]).await;

        let tcp = tokio::net::TcpStream::connect(mock.addr()).await.unwrap();
        let err = super::starttls_negotiate(tcp).await.unwrap_err();
        match err {
            ImapError::Starttls {
                reason: StarttlsFailure::UnexpectedPreauth,
            } => {}
            other => panic!("expected UnexpectedPreauth, got {other:?}"),
        }
        let _ = mock.finish().await;
    }

    #[tokio::test]
    async fn negotiate_server_refused_no() {
        let mock = MockImap::start(vec![
            Step::Send(b"* OK IMAP ready\r\n"),
            Step::ExpectCommand("CAPABILITY"),
            Step::Send(b"* CAPABILITY IMAP4rev1 STARTTLS\r\n"),
            Step::Send(b"A0001 OK CAPABILITY completed\r\n"),
            Step::ExpectCommand("STARTTLS"),
            Step::Send(b"A0002 NO STARTTLS currently unavailable\r\n"),
        ])
        .await;

        let tcp = tokio::net::TcpStream::connect(mock.addr()).await.unwrap();
        let err = super::starttls_negotiate(tcp).await.unwrap_err();
        match err {
            ImapError::Starttls {
                reason: StarttlsFailure::ServerRefused { tagged_status },
            } => assert_eq!(tagged_status, StarttlsRefusal::No),
            other => panic!("expected ServerRefused NO, got {other:?}"),
        }
        let _ = mock.finish().await;
    }

    #[tokio::test]
    async fn negotiate_server_refused_bad() {
        let mock = MockImap::start(vec![
            Step::Send(b"* OK IMAP ready\r\n"),
            Step::ExpectCommand("CAPABILITY"),
            Step::Send(b"* CAPABILITY IMAP4rev1 STARTTLS\r\n"),
            Step::Send(b"A0001 OK CAPABILITY completed\r\n"),
            Step::ExpectCommand("STARTTLS"),
            Step::Send(b"A0002 BAD command unknown\r\n"),
        ])
        .await;

        let tcp = tokio::net::TcpStream::connect(mock.addr()).await.unwrap();
        let err = super::starttls_negotiate(tcp).await.unwrap_err();
        match err {
            ImapError::Starttls {
                reason: StarttlsFailure::ServerRefused { tagged_status },
            } => assert_eq!(tagged_status, StarttlsRefusal::Bad),
            other => panic!("expected ServerRefused BAD, got {other:?}"),
        }
        let _ = mock.finish().await;
    }

    #[tokio::test]
    async fn negotiate_happy_path() {
        let mock = MockImap::start(vec![
            Step::Send(b"* OK IMAP server ready\r\n"),
            Step::ExpectCommand("CAPABILITY"),
            Step::Send(b"* CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED\r\n"),
            Step::Send(b"A0001 OK CAPABILITY completed\r\n"),
            Step::ExpectCommand("STARTTLS"),
            Step::Send(b"A0002 OK Begin TLS negotiation\r\n"),
        ])
        .await;

        let tcp = tokio::net::TcpStream::connect(mock.addr()).await.unwrap();
        let result = super::starttls_negotiate(tcp).await;
        assert!(result.is_ok(), "expected Ok(_), got {result:?}");

        let recorded = mock.finish().await.unwrap();
        assert_eq!(recorded.len(), 2);
        assert!(recorded[0].to_ascii_uppercase().contains("CAPABILITY"));
        assert!(recorded[1].to_ascii_uppercase().contains("STARTTLS"));
    }

    #[tokio::test]
    async fn negotiate_returns_bare_tcpstream_and_drops_client_wrapper() {
        // Regression test for CVE-2011-0411 class: verifies that
        // `starttls_negotiate` returns a raw `TcpStream` (not a
        // `Client<TcpStream>`), which means the plaintext client's
        // internal `ImapStream` buffer was dropped by `into_inner()`.
        // A caller that re-wraps with `Client::new(tls_stream)` after
        // TLS gets a fresh buffer — no buffered plaintext can be
        // replayed against the post-TLS stream.
        //
        // We further simulate a MITM-style injection by having the mock
        // send trailing bytes in the SAME turn as the tagged OK for
        // STARTTLS. If the plaintext parser buffered them, they are
        // lost with `into_inner()`; if not, they remain on the kernel
        // socket but cannot enter any `ImapStream` buffer the caller
        // holds, because none is returned.
        let mock = MockImap::start(vec![
            Step::Send(b"* OK ready\r\n"),
            Step::ExpectCommand("CAPABILITY"),
            Step::Send(b"* CAPABILITY IMAP4rev1 STARTTLS\r\n"),
            Step::Send(b"A0001 OK CAPABILITY completed\r\n"),
            Step::ExpectCommand("STARTTLS"),
            // Tagged OK + trailing injected bytes in the SAME server turn.
            Step::Send(b"A0002 OK Begin TLS negotiation\r\n* INJECTED garbage\r\n"),
        ])
        .await;

        let tcp = tokio::net::TcpStream::connect(mock.addr()).await.unwrap();
        // Explicit type annotation: `returned` must be TcpStream, not
        // Client<TcpStream>. This is checked by the compiler; the
        // annotation documents the CVE-defense guarantee.
        let returned: tokio::net::TcpStream = super::starttls_negotiate(tcp).await.unwrap();
        let _ = returned;

        let _ = mock.finish().await;
    }

    #[tokio::test]
    async fn mock_server_round_trips_a_line() {
        // Smoke test: mock sends a greeting, reads one line, returns.
        let mock = MockImap::start(vec![
            Step::Send(b"* OK hi\r\n"),
            Step::ExpectCommand("NOOP"),
            Step::Send(b"a1 OK NOOP done\r\n"),
        ])
        .await;

        let stream = TcpStream::connect(mock.addr()).await.unwrap();
        let (read, mut write) = stream.into_split();
        let mut reader = BufReader::new(read);
        let mut greeting = String::new();
        reader.read_line(&mut greeting).await.unwrap();
        assert!(greeting.contains("OK hi"));
        write.write_all(b"a1 NOOP\r\n").await.unwrap();
        let mut resp = String::new();
        reader.read_line(&mut resp).await.unwrap();
        assert!(resp.contains("NOOP done"));

        drop((reader, write));
        let recorded = mock.finish().await.unwrap();
        assert_eq!(recorded.len(), 1);
        assert!(recorded[0].contains("NOOP"));
    }

    #[test]
    fn debug_format_includes_connection_fields() {
        // The manual `Debug` impl for `Connection` writes host, port,
        // and username via `debug_struct(...).finish_non_exhaustive()`.
        // The cargo-mutants `replace <impl Debug>::fmt -> std::fmt::Result
        // with Ok(Default::default())` mutation at connection.rs:127
        // returns Ok(()) without writing — the formatted output collapses
        // to the empty string. Asserting that distinctive field values
        // round-trip through the formatter kills the mutation.
        //
        // `Connection::new` is socket-free, so the IP / port values here
        // are pure config — no listener is bound.
        let cfg = ConnectionConfig {
            account: None,
            account_id: rimap_core::account::AccountId::default_account(),
            host: "imap.fixture.invalid".into(),
            port: 6143,
            encryption: ImapEncryption::Tls,
            username: "u@fixture.invalid".into(),
            pinned_fingerprint: None,
            connect_timeout: std::time::Duration::from_millis(1),
            command_timeout: std::time::Duration::from_millis(1),
            max_fetch_body_bytes: 1024,
            max_append_bytes: 1024,
        };
        let conn = Connection::new(cfg, Arc::new(NoopAudit), Arc::new(PanicResolver));
        let formatted = format!("{conn:?}");
        assert!(
            formatted.contains("Connection"),
            "Debug must include struct name; got {formatted:?}",
        );
        assert!(
            formatted.contains("imap.fixture.invalid"),
            "Debug must include host; got {formatted:?}",
        );
        assert!(
            formatted.contains("6143"),
            "Debug must include port; got {formatted:?}",
        );
        assert!(
            formatted.contains("u@fixture.invalid"),
            "Debug must include username; got {formatted:?}",
        );
    }
}
