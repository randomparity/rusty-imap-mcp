//! Inbound bridge: real stdin → validator → rmcp duplex / rejection to
//! shared stdout. Owns the per-line read loop and the CRLF-strip.

use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWriteExt, BufReader, DuplexStream, Stdout};
use tokio::sync::Mutex;

use super::envelope::{parse_error, synthesize_error_line, validate};
use super::{BUF_SIZE, ValidationOutcome};

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
/// Returns `Ok(())` on stdin EOF. Returns `Err(io::Error)` if a write
/// to either the inbound duplex (forwarding) or shared stdout
/// (rejection) fails — `BrokenPipe` on stdout is the most common
/// failure mode and surfaces to `main.rs::run` via the supervisor so
/// `process_end.reason: Error` is recorded.
pub(crate) async fn validate_inbound<R>(
    stdin: R,
    mut to_rmcp: DuplexStream,
    stdout: Arc<Mutex<Stdout>>,
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
            _ => &buf[..],
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
            let mut sout = stdout.lock().await;
            sout.write_all(line.as_bytes()).await?;
            sout.flush().await?;
            continue;
        };

        match validate(line_for_validation) {
            ValidationOutcome::Skip => {}
            ValidationOutcome::Forward => {
                // Forward the buffer including its trailing \n so
                // rmcp's framed reader sees the complete envelope.
                if buf.last() != Some(&b'\n') {
                    buf.push(b'\n');
                }
                to_rmcp.write_all(&buf).await?;
                to_rmcp.flush().await?;
            }
            ValidationOutcome::Reject(env) => {
                let line = synthesize_error_line(&env);
                let mut sout = stdout.lock().await;
                sout.write_all(line.as_bytes()).await?;
                sout.flush().await?;
                // Lock released here; loop continues.
            }
        }
    }
}
