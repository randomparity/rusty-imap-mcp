//! UID MOVE with COPY+DELETE fallback for servers without the MOVE
//! extension (RFC 6851).

use crate::connection::{ImapSession, ServerCapabilities};
use crate::error::ImapError;
use crate::ops::store;
use crate::types::{Flag, FlagAction, MoveResult, Uid};

/// Maximum UIDs per MOVE command.
const MAX_BATCH: usize = 100;

/// Outcome of a `move_messages` call.
#[derive(Debug)]
#[must_use = "check used_fallback for security warnings"]
#[non_exhaustive]
pub struct MoveOutcome {
    /// Per-UID results.
    pub results: Vec<MoveResult>,
    /// `true` when the non-atomic COPY+DELETE+EXPUNGE fallback was used
    /// instead of the atomic UID MOVE command. Callers should surface a
    /// security warning when this is `true`.
    pub used_fallback: bool,
    /// `true` only when the fallback ran AND the server lacked UIDPLUS, so
    /// the EXPUNGE was folder-wide (RFC 3501) — removing every `\Deleted`
    /// message in the source folder, not just the moved UIDs. This is the
    /// distinct data-loss condition (the server advertised *neither* MOVE nor
    /// UIDPLUS); callers should surface `ServerFolderWideExpungeDataLoss`.
    /// A session whose capabilities are unknown never produces this outcome —
    /// the move is refused instead (#649).
    pub folder_wide_expunge: bool,
    /// Source-folder UIDVALIDITY observed at the guard STATUS probe, or
    /// `None` if no guard was requested or the server omitted it.
    pub source_uid_validity: Option<u32>,
    /// Destination-folder UIDVALIDITY observed after the COPY fallback
    /// succeeds, or `None` (either not the fallback path, or the server
    /// omitted UIDVALIDITY from the STATUS response).
    pub destination_uid_validity: Option<u32>,
}

/// Move `uids` from the currently selected folder to `dest_folder`.
///
/// When the serving session advertised MOVE, UID MOVE is used directly. A BAD
/// response in this case is propagated as an error (the server lied about its
/// capabilities).
///
/// When it advertised no MOVE, the COPY+DELETE fallback is used immediately
/// without attempting UID MOVE.
///
/// When `capabilities` is [`ServerCapabilities::Unknown`] the move is refused
/// rather than served, because the fallback it would otherwise pick can issue
/// a folder-wide EXPUNGE — see the refusal below and #649.
///
/// If `expected_source_uidvalidity` is `Some(v)`, a STATUS probe is
/// issued against `src_folder` before the move. A mismatch returns
/// `ImapError::UidValidityChanged`; if the server omits UIDVALIDITY
/// from the STATUS response the guard is skipped with a warning.
///
/// # Errors
///
/// Returns `ImapError::BatchTooLarge` if `uids.len() > MAX_BATCH`.
/// Returns `ImapError::CapabilitiesUnknown` if `capabilities` is
/// [`ServerCapabilities::Unknown`].
/// Returns `ImapError::UidValidityChanged` on a UIDVALIDITY mismatch.
/// Propagates connection-lost or protocol errors from async-imap.
pub(crate) async fn move_messages(
    session: &mut ImapSession,
    src_folder: &str,
    dest_folder: &str,
    uids: &[Uid],
    expected_source_uidvalidity: Option<u32>,
    capabilities: ServerCapabilities,
) -> Result<MoveOutcome, ImapError> {
    crate::ops::folders::validate_server_folder_name(dest_folder)?;
    if uids.len() > MAX_BATCH {
        return Err(ImapError::BatchTooLarge {
            count: uids.len(),
            limit: MAX_BATCH,
        });
    }
    if uids.is_empty() {
        return Ok(MoveOutcome {
            results: Vec::new(),
            used_fallback: false,
            folder_wide_expunge: false,
            source_uid_validity: None,
            destination_uid_validity: None,
        });
    }

    // Both branches below turn on the advertisement, and the one they pick
    // when it says "no MOVE, no UIDPLUS" purges every `\Deleted` message in
    // `src_folder`. A session that never produced a readable advertisement
    // gets a refusal, not that branch by default (#649). Ahead of the STATUS
    // probe and every mutation, so a refused move leaves the mailbox as it
    // found it.
    let (has_move, has_uidplus) = capabilities.require_known("move")?;

    // UIDVALIDITY guard: STATUS does not require SELECT and does not
    // perturb the session's currently selected mailbox.
    let source_uid_validity = if let Some(expected) = expected_source_uidvalidity {
        let items = crate::types::StatusItems {
            messages: false,
            recent: false,
            uid_next: false,
            uid_validity: true,
            unseen: false,
        };
        let status = crate::ops::folders::status(session, src_folder, items).await?;
        match status.uid_validity {
            Some(actual) if actual != expected => {
                return Err(ImapError::UidValidityChanged {
                    folder: src_folder.to_string(),
                    expected,
                    actual,
                });
            }
            Some(actual) => Some(actual),
            None => {
                tracing::warn!(
                    folder = %src_folder,
                    "STATUS omitted UIDVALIDITY; skipping UIDVALIDITY guard",
                );
                None
            }
        }
    } else {
        None
    };

    if !has_move {
        let (results, destination_uid_validity) =
            copy_delete_fallback(session, src_folder, dest_folder, uids, has_uidplus).await?;
        return Ok(MoveOutcome {
            results,
            used_fallback: true,
            folder_wide_expunge: crate::ops::expunge::fallback_uses_folder_wide_expunge(
                false,
                has_uidplus,
            ),
            source_uid_validity,
            destination_uid_validity,
        });
    }

    let uid_set = store::uid_set_string(uids);
    let move_result = session.uid_mv(&uid_set, dest_folder).await;

    match move_result {
        Ok(()) => Ok(MoveOutcome {
            results: build_results(uids),
            used_fallback: false,
            folder_wide_expunge: false,
            source_uid_validity,
            destination_uid_validity: None,
        }),
        Err(e) => Err(super::folders::map_err(e)),
    }
}

/// Fallback: COPY + STORE \Deleted + EXPUNGE. Not atomic.
///
/// EXPUNGE selection (scoped UID EXPUNGE vs folder-wide) is delegated to
/// [`crate::ops::expunge::run_expunge`]. Servers that support MOVE never
/// reach this path.
///
/// Returns `(results, destination_uid_validity)`. The destination UIDVALIDITY
/// is probed via STATUS after the COPY succeeds so the caller can surface it.
async fn copy_delete_fallback(
    session: &mut ImapSession,
    src_folder: &str,
    dest_folder: &str,
    uids: &[Uid],
    has_uidplus: bool,
) -> Result<(Vec<MoveResult>, Option<u32>), ImapError> {
    crate::ops::folders::validate_server_folder_name(dest_folder)?;
    let uid_set = store::uid_set_string(uids);

    // Step 1: COPY to destination.
    session
        .uid_copy(&uid_set, dest_folder)
        .await
        .map_err(super::folders::map_err)?;

    // Step 2: Probe the destination UIDVALIDITY so the caller can echo it.
    // STATUS does not change the selected mailbox.
    let dest_status = crate::ops::folders::status(
        session,
        dest_folder,
        crate::types::StatusItems {
            messages: false,
            recent: false,
            uid_next: false,
            uid_validity: true,
            unseen: false,
        },
    )
    .await?;
    let destination_uid_validity = dest_status.uid_validity;

    // Step 3: STORE +FLAGS \Deleted on the originals.
    store::store(session, uids, &[Flag::Deleted], FlagAction::Add).await?;

    // Step 4: Remove the flagged messages from the source folder.
    let strategy = crate::ops::expunge::expunge_strategy(has_uidplus);
    crate::ops::expunge::run_expunge(session, &uid_set, strategy, src_folder).await?;

    Ok((build_results(uids), destination_uid_validity))
}

/// Build `MoveResult` entries with `new_uid: None` (async-imap does
/// not expose UIDPLUS data). `used_fallback_reason` is always set
/// because `new_uid` is always `None` in this version of the library.
fn build_results(uids: &[Uid]) -> Vec<MoveResult> {
    let mut results = Vec::with_capacity(uids.len());
    for &uid in uids {
        results.push(MoveResult {
            old_uid: uid,
            new_uid: None,
            used_fallback_reason: Some("async_imap_copyuid_unavailable".to_string()),
        });
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::tests::uid;

    #[test]
    fn build_results_is_empty_for_empty_input() {
        assert!(build_results(&[]).is_empty());
    }

    #[test]
    fn build_results_preserves_order_and_leaves_new_uid_unknown() {
        // UIDPLUS is not parsed out of async-imap's MOVE response today,
        // so every entry records the old UID and a None for new_uid.
        // Documenting this at the unit layer prevents a future COPYUID
        // refactor from breaking the client contract silently.
        // used_fallback_reason is always set while new_uid is always None.
        let uids = [uid(7), uid(3), uid(11)];
        let results = build_results(&uids);
        assert_eq!(results.len(), 3);
        for (i, r) in results.iter().enumerate() {
            assert_eq!(r.old_uid, uids[i]);
            assert!(r.new_uid.is_none());
            assert_eq!(
                r.used_fallback_reason.as_deref(),
                Some("async_imap_copyuid_unavailable"),
            );
        }
    }

    #[test]
    fn build_results_preserves_duplicates() {
        // MOVE is called with pre-deduped UIDs, but the helper itself does
        // no filtering — that responsibility sits with the caller.
        let uids = [uid(5), uid(5)];
        let results = build_results(&uids);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].old_uid, uids[0]);
        assert_eq!(results[1].old_uid, uids[1]);
    }

    #[test]
    fn server_folder_validator_rejects_nul_dest_folder() {
        // Pins that validate_server_folder_name — which move_messages and
        // copy_delete_fallback both call at entry — rejects control bytes.
        use crate::ops::folders::validate_server_folder_name;
        assert!(validate_server_folder_name("target\0folder").is_err());
        assert!(validate_server_folder_name("target\x1ffolder").is_err());
        assert!(validate_server_folder_name("normal/path").is_ok());
    }
}
