//! Inbound bridge: real stdin → validator → rmcp duplex / rejection to
//! shared stdout. Owns the per-line read loop and the CRLF-strip.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWriteExt, BufReader, DuplexStream, Stdout};
use tokio::sync::Mutex;

use super::envelope::{parse_error, synthesize_error_line, validate};
use super::{BUF_SIZE, ValidationOutcome};
use crate::mcp::preinit::synthesize_pre_init_error_envelope;
use rmcp::model::{
    ClientJsonRpcMessage,
    ClientRequest::{InitializeRequest, PingRequest},
};
use serde_json::from_str;

/// Inbound bridge task. Reads from real stdin one line at a time
/// (preserving the trailing `\n`), validates each line, and forwards
/// or rejects.
///
/// # Cancellation
///
/// This function is intended to be `tokio::spawn`'d and managed by
/// `ValidatorSupervisor`. If `JoinHandle::abort()` lands between
/// `write_all` and `flush` on the rejection path, a partial line
/// may reach real stdout — breaking the stdout serialization
/// invariant. The supervisor's `shutdown_after_failure` (Task 2.3)
/// uses abort only on failure paths where stdout integrity is
/// already lost (e.g. `BrokenPipe`). Cooperative cancellation via
/// `tokio_util::sync::CancellationToken` could close this gap if
/// stronger guarantees become necessary; deferred per Task 2.3
/// design.
///
/// # Pre-init interception (ADR-0025)
///
/// While `initialized` is false, a JSON-RPC REQUEST (has forwardable
/// `id`) whose `method` is neither `"initialize"` nor `"ping"` is
/// intercepted: the -32002 envelope is synthesized and written to
/// stdout, the `pre_init_intercepted` flag is raised, and the rmcp
/// inbound duplex is closed (preventing rmcp from ever observing the
/// request), so rmcp 3.x's pre-init `_meta` validation never emits its
/// own -32602 envelope. The function then returns `Ok(())`; the binary's
/// `serve_mcp` reads the flag (raised strictly before the duplex drop,
/// so it is observable no matter which arm of the init race resolves)
/// and treats the run as a clean exit.
///
/// Returns `Ok(())` on stdin EOF and after a pre-init interception.
/// Returns `Err(io::Error)` if any write fails — including the
/// interception envelope write, so a broken pipe still records
/// `process_end.reason: Error`.
pub(crate) async fn validate_inbound<R>(
    stdin: R,
    mut to_rmcp: DuplexStream,
    stdout: Arc<Mutex<Stdout>>,
    initialized: Arc<AtomicBool>,
    pre_init_intercepted: Arc<AtomicBool>,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut reader = BufReader::new(stdin);
    let mut buf = Vec::with_capacity(BUF_SIZE);

    loop {
        buf.clear();
        let n = reader.read_until(b'\n', &mut buf).await?;
        if n == 0 {
            return Ok(()); // stdin EOF — clean shutdown.
        }

        // Strip trailing \n and optional \r for the validation view.
        // rmcp's codec also strips \r; matching its grammar.
        // cargo-mutants: known-equivalent group — for the next two
        // `match` blocks, both `delete match arm Some(&b'\n'/'\r')`
        // and `replace - with /` mutants are observably equivalent.
        // The trimmed view is fed to `serde_json::from_str` (and
        // `Deserializer::from_str` in the dup-check), both of which
        // tolerate trailing whitespace — so a line that retains its
        // \n or \r still parses identically. `len() / 1 == len()` so
        // the slice does not shrink, same effect as deleting the arm.
        // The `replace - with +` mutant at the \r-strip site IS a
        // real gap (slices past the buffer end and panics on \r\n
        // input) and is killed by `validate_inbound_strips_crlf_line_ending`.
        let trimmed: &[u8] = match buf.last() {
            Some(&b'\n') => &buf[..buf.len() - 1],
            _ => &buf,
        };

        let trimmed: &[u8] = match trimmed.last() {
            Some(&b'\r') => &trimmed[..trimmed.len() - 1],
            _ => trimmed,
        };

        // Non-UTF-8 bytes never reach rmcp. A lossy-decode-then-validate
        // path would let invalid bytes inside a syntactically valid JSON
        // string slip through (U+FFFD makes the string parseable), so
        // the strict check happens before any parsing. JSON-RPC §4.2 / §5.1.
        let Ok(line_for_validation) = std::str::from_utf8(trimmed) else {
            let line = synthesize_error_line(&parse_error());
            let mut stdout_lock = stdout.lock().await;
            stdout_lock.write_all(line.as_bytes()).await?;
            stdout_lock.flush().await?;
            continue;
        };

        // ADR-0025: Pre-init interception. While !initialized, intercept
        // non-ping/non-initialize requests to prevent rmcp from emitting
        // its own -32602 envelope. This restores the single-envelope contract.
        if !initialized.load(std::sync::atomic::Ordering::SeqCst) {
            // Attempt to parse the line as a JSON-RPC message to check
            // if it's a request with a method we need to intercept.
            // If parsing fails, we still let it fall through to the
            // normal validation path (which will emit -32700 or -32600).
            if let Ok(ClientJsonRpcMessage::Request(req)) =
                from_str::<ClientJsonRpcMessage>(line_for_validation)
            {
                // Check if this is a pre-init violation: not initialize, not ping.
                let is_initialize = matches!(req.request, InitializeRequest(_));
                let is_ping = matches!(req.request, PingRequest(_));

                if !is_initialize && !is_ping {
                    // Synthesize and write the -32002 envelope. A
                    // write failure propagates via `?` BEFORE the
                    // flag is raised, so a broken pipe keeps the
                    // real-error contract
                    // (`pre_initialize_envelope_write_failure_records_error`).
                    let full_msg = ClientJsonRpcMessage::Request(req);
                    if let Some(envelope) = synthesize_pre_init_error_envelope(&full_msg) {
                        let mut stdout_lock = stdout.lock().await;
                        // Same operator-facing context as the
                        // pre-ADR-0025 emit path in `main.rs`
                        // (`pre_initialize_envelope_write_failure_records_error`
                        // greps stderr for it).
                        stdout_lock
                            .write_all(envelope.as_bytes())
                            .await
                            .map_err(|e| {
                                std::io::Error::other(format!(
                                    "writing pre-init error envelope to stdout: {e}"
                                ))
                            })?;
                        stdout_lock.flush().await.map_err(|e| {
                            std::io::Error::other(format!(
                                "writing pre-init error envelope to stdout: {e}"
                            ))
                        })?;
                    }

                    // Raise the interception flag strictly before
                    // dropping the duplex. Dropping wakes rmcp (and
                    // possibly the init-race select on another
                    // worker thread) while this task is still
                    // mid-poll, so no signal that comes AFTER the
                    // drop — not even this task's own completion —
                    // can win that race deterministically. The flag,
                    // stored first and read by `serve_mcp` before it
                    // interprets whichever arm fired, is the only
                    // race-free ordering.
                    pre_init_intercepted.store(true, std::sync::atomic::Ordering::SeqCst);

                    // Close the rmcp inbound duplex: rmcp observes
                    // EOF-before-initialize without ever seeing this
                    // request, then the function exits cleanly.
                    drop(to_rmcp);
                    return Ok(());
                }

                // This is an initialize request. Set the flag.
                if is_initialize {
                    initialized.store(true, std::sync::atomic::Ordering::SeqCst);
                }
            }
        }

        match validate(line_for_validation) {
            ValidationOutcome::Forward => {
                // Valid envelope: forward to rmcp.
                to_rmcp.write_all(&buf).await?;
                to_rmcp.flush().await?;
            }
            ValidationOutcome::Skip => {
                // Empty or whitespace-only line — drop silently; the
                // match is the loop tail, so control continues anyway.
            }
            ValidationOutcome::Reject(env) => {
                // Rejection envelope: write to shared stdout.
                let line = synthesize_error_line(&env);
                let mut stdout_lock = stdout.lock().await;
                stdout_lock.write_all(line.as_bytes()).await?;
                stdout_lock.flush().await?;
                // Lock released; loop continues.
            }
        }
    }
}
