//! Audit crate error type. Open-time errors map to `ERR_CONFIG`; runtime
//! write/flush/fsync errors map to `ERR_INTERNAL`. See design spec §10.

use std::path::PathBuf;

use rimap_core::{ErrorCode, RimapError};
use thiserror::Error;

/// Errors produced by `rimap-audit`.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AuditError {
    /// The audit file could not be opened for read+write.
    #[error("failed to open audit file `{path}`: {source}")]
    Open {
        /// Attempted path.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The audit file's parent directory could not be created.
    #[error("failed to create parent directory for `{path}`: {source}")]
    ParentDir {
        /// Attempted path.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The audit file is already locked by another process.
    #[error(
        "audit file `{path}` is already locked by another rusty-imap-mcp process. \
         Each MCP client must use a distinct `[audit].path`; \
         see docs/audit-log.md#running-multiple-mcp-clients"
    )]
    Locked {
        /// Path that could not be locked.
        path: PathBuf,
    },
    /// A record could not be serialized to JSON.
    #[error("failed to serialize audit record: {0}")]
    Serialize(#[source] serde_json::Error),
    /// A record could not be deserialized from JSON when no file path /
    /// line number is available (e.g. `parse_line` called by an external
    /// consumer or a fuzz harness). `stream_records` rewraps these as
    /// [`AuditError::Read`] with the real path and line.
    #[error("failed to parse audit record: {0}")]
    Parse(#[source] serde_json::Error),
    /// A record could not be written to disk.
    #[error("failed to write audit record to `{path}`: {source}")]
    Write {
        /// The audit file path.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// `fsync` failed after a flush.
    #[error("failed to fsync audit file `{path}`: {source}")]
    Fsync {
        /// The audit file path.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// Rotation rename or fresh-file creation failed.
    #[error("failed to rotate audit file `{path}`: {reason}")]
    Rotate {
        /// The active file path that was being rotated.
        path: PathBuf,
        /// Specific reason.
        reason: String,
    },
    /// Reading the audit file for self-check or `audit merge` failed.
    #[error("failed to read audit file `{path}`{}: {source}", Self::fmt_line(*line))]
    Read {
        /// The audit file path.
        path: PathBuf,
        /// Line number (1-based) when the error originated from JSON parsing
        /// a specific line. `None` for whole-file I/O errors.
        line: Option<usize>,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
}

impl AuditError {
    fn fmt_line(line: Option<usize>) -> String {
        match line {
            Some(n) => format!(" (line {n})"),
            None => String::new(),
        }
    }
}

impl AuditError {
    /// The stable [`ErrorCode`] this error maps to at the top-level boundary.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Open { .. } | Self::ParentDir { .. } | Self::Locked { .. } => ErrorCode::Config,
            Self::Serialize(_)
            | Self::Parse(_)
            | Self::Write { .. }
            | Self::Fsync { .. }
            | Self::Rotate { .. }
            | Self::Read { .. } => ErrorCode::Internal,
        }
    }
}

impl From<AuditError> for RimapError {
    fn from(err: AuditError) -> Self {
        let code = err.code();
        let source: Box<dyn std::error::Error + Send + Sync + 'static> = Box::new(err);
        Self::Audit {
            code,
            message: source.to_string(),
            source,
        }
    }
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "tests")]
mod tests {
    use std::path::PathBuf;

    use rimap_core::ErrorCode;

    use crate::AuditError;

    #[test]
    fn open_time_errors_map_to_config() {
        let err = AuditError::Locked {
            path: PathBuf::from("/tmp/a.jsonl"),
        };
        assert_eq!(err.code(), ErrorCode::Config);

        let err = AuditError::Open {
            path: PathBuf::from("/tmp/a.jsonl"),
            source: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        };
        assert_eq!(err.code(), ErrorCode::Config);
    }

    #[test]
    fn runtime_errors_map_to_internal() {
        let err = AuditError::Write {
            path: PathBuf::from("/tmp/a.jsonl"),
            source: std::io::Error::from(std::io::ErrorKind::BrokenPipe),
        };
        assert_eq!(err.code(), ErrorCode::Internal);
    }

    #[test]
    fn parse_variant_maps_to_internal() {
        // Pin the `Parse` variant in the runtime/Internal bucket alongside
        // its peers (`Serialize`, `Read`, ...). A future mutation that moves
        // `Parse` into the Config arm would silently misclassify deserialize
        // failures from `parse_line`.
        let serde_err = serde_json::from_slice::<serde_json::Value>(b"{not json")
            .expect_err("malformed JSON must error");
        let err = AuditError::Parse(serde_err);
        assert_eq!(err.code(), ErrorCode::Internal);
    }

    #[test]
    fn locked_message_names_the_path() {
        let err = AuditError::Locked {
            path: PathBuf::from("/tmp/a.jsonl"),
        };
        let msg = err.to_string();
        assert!(msg.contains("/tmp/a.jsonl"), "got: {msg}");
        assert!(msg.contains("another rusty-imap-mcp process"), "got: {msg}");
        assert!(
            msg.contains("distinct `[audit].path`"),
            "message must name the resolution; got: {msg}"
        );
    }

    #[test]
    fn locked_message_includes_docs_anchor() {
        // The error string is the canonical entry-point users see when the
        // lock collides. It must point at the docs anchor so the cross-link
        // does not silently rot when docs/audit-log.md is edited.
        let err = AuditError::Locked {
            path: PathBuf::from("/tmp/a.jsonl"),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("docs/audit-log.md#running-multiple-mcp-clients"),
            "got: {msg}"
        );
    }

    #[test]
    fn read_error_with_line_number_renders_line_marker() {
        // Pin `fmt_line -> String::new()` and `fmt_line -> "xyzzy".into()`
        // mutations: a `Read` error carrying `line: Some(N)` must render
        // its Display with " (line N)". The empty-string stub would drop
        // the marker; the constant stub would emit `xyzzy` instead.
        let err = AuditError::Read {
            path: PathBuf::from("/tmp/a.jsonl"),
            line: Some(42),
            source: std::io::Error::from(std::io::ErrorKind::InvalidData),
        };
        let display = err.to_string();
        assert!(
            display.contains("(line 42)"),
            "Display must include the line marker; got: {display}",
        );
        assert!(
            !display.contains("xyzzy"),
            "Display must not echo the mutation stub; got: {display}",
        );
    }

    #[test]
    fn read_error_without_line_number_omits_line_marker() {
        // The `None` arm produces an empty string. Confirm the formatted
        // message has no `(line ...)` substring when `line: None`.
        let err = AuditError::Read {
            path: PathBuf::from("/tmp/a.jsonl"),
            line: None,
            source: std::io::Error::from(std::io::ErrorKind::InvalidData),
        };
        let display = err.to_string();
        assert!(
            !display.contains("(line "),
            "no line marker for `line: None`; got: {display}",
        );
    }

    #[test]
    fn rimap_error_conversion_preserves_code_and_source() {
        use std::error::Error as _;

        let err = AuditError::Locked {
            path: PathBuf::from("/tmp/a.jsonl"),
        };
        let rimap: rimap_core::RimapError = err.into();

        // Open-time errors still carry ERR_CONFIG.
        assert_eq!(rimap.code(), ErrorCode::Config);

        // Display form must include the code AND the original path so
        // operators see what went wrong.
        let display = rimap.to_string();
        assert!(display.contains("ERR_CONFIG"), "got: {display}");
        assert!(display.contains("/tmp/a.jsonl"), "got: {display}");

        // Source chain preserved.
        let source = rimap.source().expect("source chain must be preserved");
        assert!(
            source.to_string().contains("/tmp/a.jsonl"),
            "source should be the AuditError with path, got: {source}",
        );

        // Runtime error still maps to ERR_INTERNAL.
        let err = AuditError::Write {
            path: PathBuf::from("/tmp/a.jsonl"),
            source: std::io::Error::from(std::io::ErrorKind::BrokenPipe),
        };
        let rimap: rimap_core::RimapError = err.into();
        assert_eq!(rimap.code(), ErrorCode::Internal);
    }
}
