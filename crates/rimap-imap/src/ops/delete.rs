//! `delete_message`: STORE +FLAGS (\Deleted) + UID MOVE to Trash.

use crate::connection::ImapSession;
use crate::error::ImapError;
use crate::ops::store;
use crate::types::{Flag, FlagAction, Uid};

/// Delete a message: flag it as `\Deleted` and move it to Trash.
///
/// If the message is already in the Trash folder (case-insensitive match),
/// only the `\Deleted` flag is applied — no move is attempted.
///
/// Caller must SELECT the `source_folder` before calling this function.
///
/// # Errors
///
/// Returns `ImapError::InvalidInput` if `source_folder` or `trash_folder`
/// fails `validate_folder_name`.
/// Propagates connection-lost or protocol errors from async-imap.
pub(crate) async fn delete_message(
    session: &mut ImapSession,
    uid: Uid,
    source_folder: &str,
    trash_folder: &str,
    has_move: bool,
    has_uidplus: bool,
) -> Result<DeleteResult, ImapError> {
    super::folder_management::validate_folder_name(source_folder)?;
    super::folder_management::validate_folder_name(trash_folder)?;

    // Step 1: STORE +FLAGS (\Deleted)
    store::store(session, &[uid], &[Flag::Deleted], FlagAction::Add).await?;

    // Step 2: If already in Trash, skip the move
    let in_trash = source_folder.eq_ignore_ascii_case(trash_folder);
    if in_trash {
        return Ok(DeleteResult {
            uid,
            moved_to_trash: false,
            used_fallback: false,
            folder_wide_expunge: false,
        });
    }

    // Step 3: Move to Trash
    let uid_set = store::uid_set_string(&[uid]);
    if has_move {
        session
            .uid_mv(&uid_set, trash_folder)
            .await
            .map_err(super::folders::map_err)?;
    } else {
        // Fallback: COPY + scoped-or-folder-wide EXPUNGE.
        session
            .uid_copy(&uid_set, trash_folder)
            .await
            .map_err(super::folders::map_err)?;
        // The \Deleted flag was already set in step 1.
        let strategy = super::expunge::expunge_strategy(has_uidplus);
        super::expunge::run_expunge(session, &uid_set, strategy, source_folder).await?;
    }

    Ok(DeleteResult {
        uid,
        moved_to_trash: true,
        used_fallback: !has_move,
        folder_wide_expunge: super::expunge::fallback_uses_folder_wide_expunge(
            has_move,
            has_uidplus,
        ),
    })
}

/// Result of a `delete_message` operation.
#[derive(Debug)]
#[must_use = "check used_fallback for security warnings"]
#[non_exhaustive]
pub struct DeleteResult {
    /// The UID of the deleted message (in its original folder).
    pub uid: Uid,
    /// `true` if the message was moved to Trash; `false` if it was
    /// already in Trash and only flagged.
    pub moved_to_trash: bool,
    /// `true` when the non-atomic COPY+EXPUNGE fallback was used instead
    /// of server-side `UID MOVE`. When the server also lacks UIDPLUS this
    /// fallback issues a folder-wide EXPUNGE (data-loss risk); callers
    /// should surface a security warning. Mirrors `MoveOutcome::used_fallback`.
    pub used_fallback: bool,
    /// `true` only when the fallback ran AND the server lacked UIDPLUS, so
    /// the EXPUNGE was folder-wide (RFC 3501) — removing every `\Deleted`
    /// message in the source folder, not just the targeted UID. This is the
    /// distinct data-loss condition (`!has_move && !has_uidplus`); callers
    /// should surface `ServerFolderWideExpungeDataLoss`.
    pub folder_wide_expunge: bool,
}
