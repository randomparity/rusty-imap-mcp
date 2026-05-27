//! Async wrapper for the synchronous `rimap_content::parse_message`.

use std::sync::LazyLock;

use rimap_content::{Content, ContentError, parse_message};
use rimap_core::RimapError;
use tokio::sync::Semaphore;

/// Classify a [`ContentError`] into the appropriate [`RimapError`].
///
/// `LimitExceeded` maps to `AttachmentTooLarge` because every hard limit
/// in the content pipeline (message bytes, MIME depth/parts, header
/// count, HTML body size) is a size cap the caller tripped. `Malformed`
/// maps to `InvalidInput` — the bytes are syntactically broken.
#[expect(
    clippy::match_same_arms,
    reason = "`ContentError` is #[non_exhaustive]; keeping `Malformed` and the \
              future-variant fallback listed separately documents that every \
              known variant has been classified explicitly"
)]
fn classify_content_error(err: &ContentError) -> RimapError {
    // cargo-mutants: known-equivalent — `delete match arm ContentError::Malformed`.
    // The Malformed arm and the `_` fallback produce identical
    // output (`RimapError::invalid_input(err.to_string())`), as the
    // `#[expect(clippy::match_same_arms)]` above documents. Deleting
    // the explicit arm routes through the fallback with no observable
    // behavior change. The `LimitExceeded` arm-delete IS a real gap
    // and is killed by `limit_exceeded_classifies_as_attachment_too_large`.
    match err {
        // The typed `kind`/`limit` from `ContentError::LimitExceeded` are
        // carried into the dedicated `RimapError::AttachmentTooLarge` variant
        // so they surface as structured MCP `data` (#303), rather than being
        // absorbed into a message string.
        ContentError::LimitExceeded { kind, limit } => RimapError::AttachmentTooLarge {
            kind: (*kind).to_string(),
            limit: *limit as u64,
        },
        ContentError::Malformed { .. } => RimapError::invalid_input(err.to_string()),
        // `ContentError` is `#[non_exhaustive]`: future variants fall through
        // to `InvalidInput` until this classifier is revisited.
        _ => RimapError::invalid_input(err.to_string()),
    }
}

/// Limits concurrent `spawn_blocking` parse invocations to avoid
/// saturating the blocking threadpool (default 512 threads).
static PARSE_SEMAPHORE: LazyLock<Semaphore> = LazyLock::new(|| Semaphore::new(8));

/// Run `parse_message` on the blocking threadpool to avoid starving
/// the tokio runtime. `parse_message` is CPU-bound (~2 ms per message).
///
/// Classifies failures by source:
/// - `ContentError::Malformed` surfaces as `RimapError::Authz { code:
///   InvalidInput, ... }` — the caller-supplied bytes are syntactically
///   broken.
/// - `ContentError::LimitExceeded` surfaces as `RimapError::Authz { code:
///   AttachmentTooLarge, ... }` — a hard content-pipeline cap (message
///   bytes, MIME depth/parts, header count, HTML size) was exceeded.
/// - Panics from the blocking task or a closed acquisition semaphore
///   surface as `RimapError::Internal` — those are infrastructure
///   failures, not content defects, and should trip the circuit breaker
///   rather than the user-error path.
///
/// # Errors
///
/// As described above — never returns `ContentError` directly so the
/// classification cannot drift at call sites.
pub async fn parse_message_async(raw: Vec<u8>) -> Result<Content, RimapError> {
    run_on_blocking_pool(move || parse_message(&raw)).await
}

/// Run `rimap_content::walk_attachment_parts` on the blocking
/// threadpool. Shares `PARSE_SEMAPHORE` with [`parse_message_async`]
/// so heavy attachment extractions cannot saturate the runtime.
///
/// # Errors
///
/// - `RimapError::Authz { code: InvalidInput, ... }` for
///   `ContentError::Malformed` (malformed RFC 5322).
/// - `RimapError::Authz { code: AttachmentTooLarge, ... }` for
///   `ContentError::LimitExceeded` (hard content-pipeline cap hit).
/// - `RimapError::Internal` for panics or a closed semaphore.
pub async fn walk_attachment_parts_async(
    raw: Vec<u8>,
) -> Result<Vec<rimap_content::RawPart>, RimapError> {
    run_on_blocking_pool(move || rimap_content::walk_attachment_parts(&raw)).await
}

/// Classifies `ContentError` via [`classify_content_error`] and panics
/// via [`spawn_blocking_panic_error`]. Acquires `PARSE_SEMAPHORE`.
async fn run_on_blocking_pool<F, T>(work: F) -> Result<T, RimapError>
where
    F: FnOnce() -> Result<T, ContentError> + Send + 'static,
    T: Send + 'static,
{
    let _permit = PARSE_SEMAPHORE
        .acquire()
        .await
        .map_err(|e| RimapError::InternalSourced {
            message: "parse semaphore closed".into(),
            source: Box::new(e),
        })?;
    match tokio::task::spawn_blocking(work).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(e)) => Err(classify_content_error(&e)),
        Err(join_err) => Err(crate::mcp::spawn_blocking_panic_error(join_err)),
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, clippy::panic, reason = "tests")]
mod tests {
    use super::*;
    use rimap_core::ErrorCode;

    #[tokio::test]
    async fn parse_message_async_matches_sync() {
        let raw = b"From: test@example.com\r\n\
                     Subject: async test\r\n\
                     \r\n\
                     Body.\r\n"
            .to_vec();

        let sync_result = parse_message(&raw).unwrap();
        let async_result = parse_message_async(raw).await.unwrap();

        assert_eq!(sync_result.meta.subject, async_result.meta.subject);
        assert_eq!(
            sync_result.untrusted.body_text,
            async_result.untrusted.body_text
        );
    }

    #[test]
    fn limit_exceeded_classifies_as_attachment_too_large() {
        // `LimitExceeded` must map to `ErrorCode::AttachmentTooLarge`,
        // not the generic `InvalidInput` fallback. The cargo-mutants
        // `delete match arm ContentError::LimitExceeded` mutation
        // would re-route here through the `_` arm and silently
        // downgrade size-cap rejections to syntax-error responses —
        // a real wire-contract change. The `Malformed` arm-delete is
        // observably equivalent to the `_` fallback (both produce
        // `invalid_input(...)`); see the inline note on the match.
        let err = ContentError::LimitExceeded {
            kind: "mime_depth",
            limit: 8,
        };
        match classify_content_error(&err) {
            RimapError::AttachmentTooLarge { kind, limit } => {
                assert_eq!(kind, "mime_depth");
                assert_eq!(limit, 8);
            }
            other => panic!("expected AttachmentTooLarge, got {other:?}"),
        }

        // Sanity: Malformed → InvalidInput (same as `_` fallback).
        let malformed = ContentError::Malformed {
            reason: "unterminated boundary".into(),
        };
        let mapped_malformed = classify_content_error(&malformed);
        assert_eq!(mapped_malformed.code(), ErrorCode::InvalidInput);
    }
}
