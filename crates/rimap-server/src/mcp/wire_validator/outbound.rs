//! Outbound bridge: rmcp duplex → shared stdout. Newline-framed
//! passthrough; no validation on this leg because rmcp's
//! `FramedWrite` already produces wire-valid frames.

use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream, Stdout};
use tokio::sync::Mutex;

use super::BUF_SIZE;

/// Outbound bridge task. Reads newline-framed frames from rmcp's
/// outbound duplex (rmcp's `FramedWrite` terminates each envelope
/// with `\n`) and writes each frame through the shared stdout mutex.
///
/// Returns `Ok(())` when rmcp drops its outbound duplex end (EOF).
/// Returns `Err(io::Error)` if writing to real stdout fails —
/// typically `BrokenPipe`, which surfaces to `main.rs::run` via the
/// supervisor so `process_end.reason: Error` is recorded.
///
/// # Cancellation
///
/// Same caveat as `validate_inbound`: an abort between `write_all`
/// and `flush` may leave a partial frame on stdout. The supervisor's
/// `shutdown_after_failure` (Task 2.3) uses abort only on failure
/// paths where stdout integrity is already suspect.
pub(crate) async fn passthrough_outbound(
    from_rmcp: DuplexStream,
    stdout: Arc<Mutex<Stdout>>,
) -> std::io::Result<()> {
    let mut reader = BufReader::new(from_rmcp);
    let mut buf = Vec::with_capacity(BUF_SIZE);

    loop {
        buf.clear();
        let n = reader.read_until(b'\n', &mut buf).await?;
        if n == 0 {
            return Ok(()); // rmcp dropped outbound — clean shutdown.
        }
        let mut sout = stdout.lock().await;
        sout.write_all(&buf).await?;
        sout.flush().await?;
        // Lock released; loop.
    }
}
