//! EXPUNGE: permanently remove messages flagged as `\Deleted`.
//!
//! Also provides the EXPUNGE strategy selection shared by delete and move
//! fallbacks. After flagging messages `\Deleted`, the server's UIDPLUS
//! capability decides whether we can scope the expunge to specific UIDs
//! (RFC 4315 `UID EXPUNGE`, safe) or must issue a folder-wide RFC 3501
//! `EXPUNGE` that removes ALL `\Deleted` messages in the selected mailbox.

use futures_util::StreamExt;

use crate::connection::ImapSession;
use crate::error::ImapError;
use crate::types::Uid;

/// Which EXPUNGE form to issue after flagging messages `\Deleted`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExpungeStrategy {
    /// `UID EXPUNGE` (RFC 4315): removes only the named UIDs. Safe.
    Scoped,
    /// Plain `EXPUNGE` (RFC 3501): removes ALL `\Deleted` messages in the
    /// selected folder. Data-loss risk when other messages are flagged
    /// `\Deleted` by concurrent clients.
    ///
    /// This branch runs only against a server advertising neither MOVE nor
    /// UIDPLUS. The integration suite is **not exercised** against such a
    /// server — Dovecot (the only integration target) always advertises
    /// UIDPLUS, so CI reaches [`ExpungeStrategy::Scoped`] exclusively.
    /// Closing this gap requires an in-process TLS mock that advertises
    /// neither capability; see `tests/expunge_folder_wide_gap.rs`.
    FolderWide,
}

/// Choose the EXPUNGE strategy from the server's UIDPLUS capability.
pub(crate) fn expunge_strategy(has_uidplus: bool) -> ExpungeStrategy {
    if has_uidplus {
        ExpungeStrategy::Scoped
    } else {
        ExpungeStrategy::FolderWide
    }
}

/// `true` when the COPY+EXPUNGE fallback path ran AND it had to issue a
/// folder-wide EXPUNGE (server lacks both MOVE and UIDPLUS) — the data-loss
/// condition. Distinct from `used_fallback` (`!has_move`), which is also
/// true on the safe scoped-UID-EXPUNGE path.
///
/// Both arguments come from destructuring a
/// [`crate::connection::ServerCapabilities::Known`], via
/// [`crate::connection::ServerCapabilities::require_known`] — the only way to
/// obtain them. So `(false, false)` here means the server *said* it has
/// neither, never "the probe told us nothing": that state is
/// [`crate::connection::ServerCapabilities::Unknown`] and its callers refuse
/// before reaching this predicate (#649).
pub(crate) fn fallback_uses_folder_wide_expunge(has_move: bool, has_uidplus: bool) -> bool {
    !has_move && !has_uidplus
}

/// Execute the chosen EXPUNGE against the currently selected mailbox,
/// draining the response stream. Emits a `warn!` on the folder-wide
/// (data-loss) path so operators can see when the unsafe fallback ran.
///
/// The folder-wide branch (and its `warn!` / `used_fallback=true` /
/// `folder_wide_expunge=true` surface) is not exercised by the Dovecot
/// integration suite, which always advertises UIDPLUS. See
/// [`ExpungeStrategy::FolderWide`] and `tests/expunge_folder_wide_gap.rs`.
pub(crate) async fn run_expunge(
    session: &mut ImapSession,
    uid_set: &str,
    strategy: ExpungeStrategy,
    selected_folder: &str,
) -> Result<(), ImapError> {
    match strategy {
        ExpungeStrategy::Scoped => {
            let stream = session
                .uid_expunge(uid_set)
                .await
                .map_err(super::folders::map_err)?;
            futures_util::pin_mut!(stream);
            while let Some(item) = stream.next().await {
                let _uid = item.map_err(super::folders::map_err)?;
            }
        }
        ExpungeStrategy::FolderWide => {
            tracing::warn!(
                folder = %selected_folder,
                "issuing folder-wide EXPUNGE because the server lacks UIDPLUS; \
                 every message flagged \\Deleted in this folder is removed, not \
                 only the targeted UIDs",
            );
            let stream = session.expunge().await.map_err(super::folders::map_err)?;
            futures_util::pin_mut!(stream);
            while let Some(item) = stream.next().await {
                let _seq = item.map_err(super::folders::map_err)?;
            }
        }
    }
    Ok(())
}

/// Count of `\Deleted`-flagged messages before expunge, for audit logging.
///
/// Issues `UID SEARCH DELETED` on the folder opened in `EXAMINE` mode.
///
/// # Errors
///
/// Returns `ImapError::InvalidInput` if `folder` fails `validate_folder_name`.
/// Propagates connection-lost or protocol errors.
pub(crate) async fn count_deleted(
    session: &mut ImapSession,
    folder: &str,
) -> Result<Vec<Uid>, ImapError> {
    super::folder_management::validate_folder_name(folder)?;
    super::folders::select(session, folder, true).await?;
    let uids = session
        .uid_search("DELETED")
        .await
        .map_err(super::folders::map_err)?;
    Ok(uids.into_iter().filter_map(Uid::new).collect())
}

/// Expunge all `\Deleted` messages from `folder`.
///
/// Caller must SELECT the folder in read-write mode before calling.
///
/// Returns the number of messages expunged (sequence numbers from the
/// server's EXPUNGE responses).
///
/// # Errors
///
/// Propagates connection-lost or protocol errors.
pub(crate) async fn expunge(session: &mut ImapSession) -> Result<u32, ImapError> {
    let stream = session.expunge().await.map_err(super::folders::map_err)?;
    futures_util::pin_mut!(stream);
    let mut count = 0u32;
    while let Some(item) = stream.next().await {
        let _seq = item.map_err(super::folders::map_err)?;
        count = count.saturating_add(1);
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::{ExpungeStrategy, expunge_strategy, fallback_uses_folder_wide_expunge};

    #[test]
    fn uidplus_present_selects_scoped() {
        assert_eq!(expunge_strategy(true), ExpungeStrategy::Scoped);
    }

    #[test]
    fn uidplus_absent_selects_folder_wide() {
        assert_eq!(expunge_strategy(false), ExpungeStrategy::FolderWide);
    }

    #[test]
    fn folder_wide_expunge_only_when_no_move_and_no_uidplus() {
        // The data-loss condition is exactly (!has_move && !has_uidplus).
        assert!(fallback_uses_folder_wide_expunge(false, false));
    }

    #[test]
    fn unknown_capabilities_cannot_reach_the_data_loss_predicate() {
        use crate::connection::ServerCapabilities;

        // The predicate above takes bools, and `(false, false)` selects the
        // destructive branch. This pins the one gate that decides whether
        // those bools can exist at all: `Unknown` yields no pair, so no
        // caller can hand `(false, false)` to it on the strength of a probe
        // that established nothing (#649).
        assert!(ServerCapabilities::Unknown.require_known("test").is_err());

        let affirmative_neither = ServerCapabilities::Known {
            has_move: false,
            has_uidplus: false,
        }
        .require_known("test")
        .ok();
        assert_eq!(
            affirmative_neither,
            Some((false, false)),
            "an affirmative `neither` is a known state and must still yield \
             its pair",
        );
        assert!(
            fallback_uses_folder_wide_expunge(false, false),
            "a server that advertised neither extension still takes the \
             folder-wide path — the fix narrows what can reach it, it does \
             not remove the path",
        );
    }

    #[test]
    fn move_capable_never_uses_folder_wide_expunge() {
        // With MOVE the fallback path never runs, regardless of UIDPLUS.
        assert!(!fallback_uses_folder_wide_expunge(true, false));
        assert!(!fallback_uses_folder_wide_expunge(true, true));
    }

    #[test]
    fn uidplus_fallback_is_scoped_not_folder_wide() {
        // No MOVE but UIDPLUS present: the fallback runs but scopes the
        // EXPUNGE to the targeted UIDs — safe, not the data-loss path.
        assert!(!fallback_uses_folder_wide_expunge(false, true));
    }
}
