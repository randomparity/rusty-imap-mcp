//! Cross-cutting helpers shared by `retrieval` and `mailbox` handlers.

use rimap_imap::types::{FetchSpec, FetchedMessage, Uid};

use crate::boot::registry::AccountState;

/// Fetch exactly one message by UID, mapping an empty result to
/// `Authz { code: NotFound }`.
///
/// Several handlers (`list_attachments`, `list_labels`, ...) share this
/// preamble: request a single UID with a caller-chosen `FetchSpec`, then
/// treat an empty response as "UID not present in folder". Each caller
/// keeps its own `FetchSpec` so only the dedup-worthy code is centralized.
///
/// If `expected_uidvalidity` is `Some(v)`, the value is verified against the
/// folder's UIDVALIDITY before the FETCH. A mismatch propagates
/// `RimapError::UidValidityChanged`. Pass `None` to skip.
///
/// # Errors
///
/// - `RimapError::UidValidityChanged` if expected UIDVALIDITY does not match
///   the server's observed value.
/// - `RimapError::Authz { code: NotFound }` if the server returned no
///   message for `uid` in `folder`.
/// - Propagates `RimapError::Imap { ... }` from the underlying
///   `SELECT` / `UID FETCH`.
pub(crate) async fn fetch_single_by_uid(
    account: &AccountState,
    folder: &str,
    uid: Uid,
    spec: FetchSpec,
    expected_uidvalidity: Option<u32>,
) -> Result<(FetchedMessage, Option<u32>), rimap_core::RimapError> {
    let (messages, uid_validity) = account
        .imap
        .fetch(folder, &[uid], spec, expected_uidvalidity)
        .await?;
    let msg = first_or_not_found(messages, folder, uid)?;
    Ok((msg, uid_validity))
}

/// Take the first message from `messages`, or return a `NotFound`
/// `RimapError` describing the missing `(folder, uid)` pair. Extracted
/// so the empty-result → error transformation can be unit-tested
/// without a live IMAP connection.
fn first_or_not_found(
    messages: Vec<FetchedMessage>,
    folder: &str,
    uid: Uid,
) -> Result<FetchedMessage, rimap_core::RimapError> {
    messages
        .into_iter()
        .next()
        .ok_or_else(|| rimap_core::RimapError::Authz {
            code: rimap_core::error::ErrorCode::NotFound,
            message: format!("message UID {} not found in folder '{}'", uid.get(), folder),
        })
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests use unwrap_err for assertions")]
#[expect(clippy::expect_used, reason = "tests")]
#[expect(clippy::panic, reason = "tests assert variant shapes via panic")]
mod tests {
    use super::*;
    use rimap_core::RimapError;
    use rimap_core::error::ErrorCode;

    fn uid(n: u32) -> Uid {
        Uid::from(core::num::NonZeroU32::new(n).expect("non-zero literal"))
    }

    fn sample_message(u: Uid) -> FetchedMessage {
        FetchedMessage::new(u)
    }

    #[test]
    fn empty_fetch_result_maps_to_not_found_authz() {
        let err = first_or_not_found(Vec::new(), "INBOX", uid(42)).unwrap_err();
        match err {
            RimapError::Authz { code, message } => {
                assert_eq!(code, ErrorCode::NotFound);
                assert!(message.contains("42"), "message missing UID: {message}");
                assert!(
                    message.contains("INBOX"),
                    "message missing folder: {message}"
                );
            }
            other => panic!("expected Authz{{NotFound}}, got {other:?}"),
        }
    }

    #[test]
    fn non_empty_fetch_returns_first_message() {
        let first = sample_message(uid(7));
        let got = first_or_not_found(vec![first.clone(), sample_message(uid(8))], "INBOX", uid(7))
            .expect("non-empty input yields Ok");
        assert_eq!(got, first);
    }
}
