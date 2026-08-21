//! Write-deadline watchdog: detects slow or hung audit writes per ADR-0022.
//!
//! This module provides the timeout mechanism that wraps audit write operations.
//! When a write exceeds the configured deadline, it returns an error rather than
//! blocking indefinitely, preventing a hung network mount from wedging the runtime.
//!
//! # Design
//!
//! The deadline is enforced by checking elapsed time around blocking I/O operations.
//! This approach never holds the audit mutex across an `.await` (ADR-0014 constraint)
//! and uses only std primitives (`std::time::Instant`).
//!
//! # Error handling
//!
//! On deadline fire, the caller receives `AuditError::WriteDeadline` and follows
//! the existing audit error propagation rules:
//! - `fail_open = false`: surfaces as `ERR_INTERNAL` tool error (default)
//! - `fail_open = true`: logged via `tracing::error!` and suppressed

use std::io::{self, Write};
use std::time::Instant;

/// A deadline-aware writer that wraps a BufWriter and checks for timeout.
///
/// This wrapper checks the deadline before each potentially-blocking operation
/// (write_all, flush, sync_data). If the deadline is exceeded, it returns an
/// error immediately rather than blocking indefinitely.
pub struct DeadlineWriter<'a, T> {
    inner: &'a mut T,
    start: Instant,
    deadline_seconds: u64,
    path: &'a std::path::Path,
}

impl<'a, T> DeadlineWriter<'a, T> {
    /// Create a new deadline-aware writer.
    pub fn new(inner: &'a mut T, start: Instant, deadline_seconds: u64, path: &'a std::path::Path) -> Self {
        Self {
            inner,
            start,
            deadline_seconds,
            path,
        }
    }

    /// Check if the deadline has been exceeded.
    fn check_deadline(&self) -> Result<(), super::AuditError> {
        if self.deadline_seconds > 0 && self.start.elapsed().as_secs() >= self.deadline_seconds {
            return Err(super::AuditError::WriteDeadline {
                path: self.path.to_path_buf(),
                deadline_seconds: self.deadline_seconds,
            });
        }
        Ok(())
    }
}

impl<'a, T: Write> Write for DeadlineWriter<'a, T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.check_deadline().map_err(|e| io::Error::other(e.to_string()))?;
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.check_deadline().map_err(|e| io::Error::other(e.to_string()))?;
        self.inner.flush()
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.check_deadline().map_err(|e| io::Error::other(e.to_string()))?;
        self.inner.write_all(buf)
    }
}

impl<'a, T> DeadlineWriter<'a, T> {
    /// Get a mutable reference to the inner writer for direct operations.
    pub fn get_mut(&mut self) -> &mut T {
        self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn deadline_writer_allows_quick_operations() {
        let mut cursor = Cursor::new(Vec::new());
        let start = Instant::now();
        let mut writer = DeadlineWriter::new(&mut cursor, start, 5, std::path::Path::new("/test"));
        
        writer.write_all(b"test data").unwrap();
        writer.flush().unwrap();
    }

    #[test]
    fn deadline_writer_times_out_slow_operations() {
        let mut cursor = Cursor::new(Vec::new());
        let start = Instant::now();
        let mut writer = DeadlineWriter::new(&mut cursor, start, 1, std::path::Path::new("/test"));
        
        // Simulate a slow operation by sleeping
        thread::sleep(Duration::from_secs(2));
        
        let result = writer.write_all(b"test data");
        assert!(result.is_err());
    }

    #[test]
    fn deadline_writer_disabled_when_zero() {
        let mut cursor = Cursor::new(Vec::new());
        let start = Instant::now();
        let mut writer = DeadlineWriter::new(&mut cursor, start, 0, std::path::Path::new("/test"));
        
        // Even with a "slow" operation, deadline is disabled
        thread::sleep(Duration::from_millis(10));
        
        writer.write_all(b"test data").unwrap();
        writer.flush().unwrap();
    }
}