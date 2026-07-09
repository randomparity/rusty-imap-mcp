//! Minimal scripted SMTP responder that drives the real `SmtpClient`.
//!
//! Each scenario serves exactly one connection on a background task and
//! replies with a fixed script, so a taxonomy test can assert the exact
//! `SmtpError` variant the client produces.
#![expect(clippy::unwrap_used, reason = "tests")]

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::support::certs;

/// Which scripted dialog the responder serves.
#[derive(Debug, Clone, Copy)]
pub enum Scenario {
    /// Advertise AUTH, reject it with 535 → `SmtpError::Auth`.
    AuthReject,
    /// Accept AUTH (235), reject RCPT with 550 → `SmtpError::Rejected`.
    RcptReject,
    /// Advertise + begin STARTTLS, present a self-signed cert → `SmtpError::Tls`.
    StarttlsBadCert,
}

/// A listening responder. `port` is the loopback port the client dials.
pub struct Responder {
    /// Host port the scripted responder is listening on.
    pub port: u16,
}

impl Responder {
    /// Bind `127.0.0.1:0`, spawn the one-connection server, and return once
    /// the listener is accepting.
    pub async fn spawn(scenario: Scenario) -> Responder {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                let _ = serve(stream, scenario).await;
            }
        });
        Responder { port }
    }
}

/// Read one CRLF-terminated line (or until EOF) byte-by-byte. Byte-at-a-time
/// keeps the raw `TcpStream` intact for the STARTTLS handoff (no buffered
/// over-read past the line boundary).
async fn read_line(stream: &mut TcpStream) -> std::io::Result<String> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            break;
        }
        buf.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

async fn serve(mut stream: TcpStream, scenario: Scenario) -> std::io::Result<()> {
    stream.write_all(b"220 rimap-test ESMTP\r\n").await?;
    read_line(&mut stream).await?; // EHLO ...
    match scenario {
        Scenario::AuthReject => {
            stream
                .write_all(b"250-rimap-test\r\n250 AUTH PLAIN\r\n")
                .await?;
            read_line(&mut stream).await?; // AUTH PLAIN <b64>
            stream
                .write_all(b"535 5.7.8 authentication failed\r\n")
                .await?;
            Ok(())
        }
        Scenario::RcptReject => {
            stream
                .write_all(b"250-rimap-test\r\n250 AUTH PLAIN\r\n")
                .await?;
            read_line(&mut stream).await?; // AUTH PLAIN <b64>
            stream.write_all(b"235 2.7.0 accepted\r\n").await?;
            read_line(&mut stream).await?; // MAIL FROM
            stream.write_all(b"250 2.1.0 ok\r\n").await?;
            read_line(&mut stream).await?; // RCPT TO
            stream.write_all(b"550 5.1.1 no such user\r\n").await?;
            Ok(())
        }
        Scenario::StarttlsBadCert => {
            stream
                .write_all(b"250-rimap-test\r\n250 STARTTLS\r\n")
                .await?;
            read_line(&mut stream).await?; // STARTTLS
            stream.write_all(b"220 2.0.0 ready\r\n").await?;
            let (certs, key) = certs::self_signed();
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let config = rustls::ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .unwrap();
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
            // The client rejects the self-signed cert; the handshake fails.
            let _ = acceptor.accept(stream).await;
            Ok(())
        }
    }
}
