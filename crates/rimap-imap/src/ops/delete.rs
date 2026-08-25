//! `delete_message`: STORE +FLAGS (\Deleted) + UID MOVE to Trash.

use crate::connection::SessionEntry;
use crate::error::ImapError;
use crate::ops::store;
use crate::types::{Flag, FlagAction, Uid};

/// Outcome of a `delete_message` dispatch: the operation result plus the
/// observed UIDVALIDITY of the folder it ran against.
#[non_exhaustive]
#[derive(Debug)]
#[must_use = "check used_fallback for security warnings"]
pub struct DeleteOutcome {
    /// What the delete did.
    pub result: DeleteResult,
    /// UIDVALIDITY observed for the source folder, if reported.
    pub uidvalidity: Option<u32>,
}

/// Delete a message: flag it as `\Deleted` and move it to Trash.
///
/// Takes the whole [`SessionEntry`] rather than a session and an advertisement,
/// so the pair this branches on is the one that will serve the delete and a
/// caller has nowhere to pass a separately-read advertisement (#704).
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
/// Returns `ImapError::CapabilitiesUnknown` when the entry's advertisement is
/// [`crate::connection::ServerCapabilities::Unknown`] and a Trash move is
/// required — see the refusal below.
/// Propagates connection-lost or protocol errors from async-imap.
pub(crate) async fn delete_message(
    entry: &mut SessionEntry,
    uid: Uid,
    source_folder: &str,
    trash_folder: &str,
) -> Result<DeleteResult, ImapError> {
    super::folder_management::validate_folder_name(source_folder)?;
    super::folder_management::validate_folder_name(trash_folder)?;

    // Step 1: If already in Trash, flag and stop. Decided before capabilities
    // are consulted because this path issues neither UID MOVE nor EXPUNGE, so
    // an uninformative probe cannot endanger it — refusing here would cost
    // availability and buy nothing.
    if source_folder.eq_ignore_ascii_case(trash_folder) {
        store::store(entry.session(), &[uid], &[Flag::Deleted], FlagAction::Add).await?;
        return Ok(DeleteResult {
            uid,
            moved_to_trash: false,
            used_fallback: false,
            folder_wide_expunge: false,
        });
    }

    // Step 2: Everything below can reach the folder-wide EXPUNGE, so an
    // advertisement is required rather than assumed (#649). This runs *before*
    // the `\Deleted` STORE: refusing after it would leave the message flagged
    // for deletion by whatever expunges the folder next, which is the outcome
    // being refused, merely deferred.
    let (has_move, has_uidplus) = entry.capabilities().require_known("delete_message")?;

    // Borrowed after the read above, not before: this `&mut` lives to the end
    // of the function, so taking it first would make the `entry.capabilities()`
    // read a borrow error. The order the refusal needs is the only one that
    // compiles.
    let session = entry.session();

    // Step 3: STORE +FLAGS (\Deleted)
    store::store(session, &[uid], &[Flag::Deleted], FlagAction::Add).await?;

    // Step 4: Move to Trash
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
    /// distinct data-loss condition (the server advertised *neither* MOVE nor
    /// UIDPLUS); callers should surface `ServerFolderWideExpungeDataLoss`.
    /// A session whose capabilities are unknown never produces this result —
    /// the delete is refused instead (#649).
    pub folder_wide_expunge: bool,
}
