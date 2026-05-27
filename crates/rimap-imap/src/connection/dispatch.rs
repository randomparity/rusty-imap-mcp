//! Command-dispatch surface for [`Connection`].
//!
//! Holds `with_session` (the timeout / connection-lost wrapper) and
//! every per-command method that calls into `crate::ops::*`. Each
//! `pub async fn` here is a one-liner that delegates to an op module
//! under the timeout guard.

use std::sync::atomic::Ordering;

use crate::error::ImapError;

use super::{Connection, ImapSession};

impl Connection {
    /// Run an IMAP operation with a command timeout and automatic session
    /// invalidation on connection-level failures.
    ///
    /// The closure receives a mutable reference to the live `Session`.
    /// If it returns `ImapError::ConnectionLost` or `ImapError::Timeout`, the
    /// cached session is dropped so the next call lazy-reconnects.
    pub(super) async fn with_session<T, F>(
        &self,
        op_name: &'static str,
        body: F,
    ) -> Result<T, ImapError>
    where
        F: for<'s> AsyncFnOnce(&'s mut ImapSession) -> Result<T, ImapError>,
    {
        let dur = self.inner.cfg.command_timeout;
        let result = crate::time::with_timeout(op_name, dur, async {
            let mut guard = self.session().await?;
            let session =
                guard
                    .as_mut()
                    .ok_or(ImapError::Protocol(async_imap::error::Error::Bad(
                        "session invariant violated: guard is None after session()".to_string(),
                    )))?;
            body(session).await
        })
        .await;
        if let Err(ImapError::ConnectionLost | ImapError::Timeout { .. }) = &result {
            self.invalidate().await;
        }
        result
    }

    /// `LIST` against `pattern` (e.g. `"*"`, `"INBOX/*"`).
    ///
    /// Drops the cached session on `ConnectionLost` so the next call
    /// lazy-reconnects without auto-retrying the failed command.
    ///
    /// # Errors
    ///
    /// Propagates any `ImapError` produced by `time::with_timeout` or the
    /// underlying `ops::folders::list` call.
    pub async fn list_folders(
        &self,
        pattern: &str,
    ) -> Result<Vec<crate::types::Folder>, ImapError> {
        self.with_session("list", async |session| {
            crate::ops::folders::list(session, pattern).await
        })
        .await
    }

    /// List folders and fetch their STATUS in a single operation,
    /// using RFC 5819 LIST-STATUS when the server advertises the
    /// capability. Currently always falls back to LIST-then-STATUS-
    /// per-folder (async-imap does not yet expose the extended LIST).
    ///
    /// Returns `(Folder, Option<FolderStatus>)` pairs. Non-selectable
    /// folders return `None` for the status.
    ///
    /// # Errors
    /// Propagates `ImapError` from the underlying commands.
    pub async fn list_folders_with_status(
        &self,
        pattern: &str,
    ) -> Result<Vec<(crate::types::Folder, Option<crate::types::FolderStatus>)>, ImapError> {
        let has_list_status = self.inner.has_list_status.load(Ordering::Relaxed);
        self.with_session("list_folders_with_status", async move |session| {
            crate::ops::folders::list_with_status(session, pattern, has_list_status).await
        })
        .await
    }

    /// `STATUS` for `folder` selecting the requested items.
    ///
    /// # Errors
    /// Propagates any `ImapError` produced by `time::with_timeout` or the
    /// underlying `ops::folders::status` call.
    pub async fn status(
        &self,
        folder: &str,
        items: crate::types::StatusItems,
    ) -> Result<crate::types::FolderStatus, ImapError> {
        self.with_session("status", async |session| {
            crate::ops::folders::status(session, folder, items).await
        })
        .await
    }

    /// `SELECT` (or `EXAMINE` if `read_only`) the named folder.
    ///
    /// # Errors
    /// Propagates any `ImapError` produced by `time::with_timeout` or the
    /// underlying `ops::folders::select` call.
    pub async fn select(
        &self,
        folder: &str,
        read_only: bool,
    ) -> Result<crate::types::SelectedFolder, ImapError> {
        self.with_session("select", async |session| {
            crate::ops::folders::select(session, folder, read_only).await
        })
        .await
    }

    /// `SEARCH` against `folder`. Returns matching UIDs paired with the
    /// UIDVALIDITY observed by the same read-only SELECT (`None` if the
    /// server omitted it). Thread the value into `export_messages`'
    /// `expected_uidvalidity`.
    ///
    /// # Errors
    /// Propagates timeout, connection-lost, or protocol errors from the
    /// underlying `ops::search::search` call.
    pub async fn search(
        &self,
        folder: &str,
        query: crate::types::SearchQuery,
    ) -> Result<(Vec<crate::types::Uid>, Option<u32>), ImapError> {
        self.with_session("search", async |session| {
            crate::ops::search::search(session, folder, query).await
        })
        .await
    }

    /// `FETCH` for the given UIDs with the requested items. Does NOT include
    /// `BODY[]` — see `fetch_body` (Task 13) for full message retrieval.
    ///
    /// If `expected_uidvalidity` is `Some(v)`, the value is compared against
    /// the UIDVALIDITY returned by the internal EXAMINE (read-only SELECT). A
    /// mismatch returns `ImapError::UidValidityChanged` before the FETCH is
    /// sent. Pass `None` to skip the guard.
    ///
    /// # Errors
    /// Returns `ImapError::UidValidityChanged` on a UIDVALIDITY mismatch.
    /// Propagates timeout, connection-lost, or protocol errors from the
    /// underlying `ops::fetch::fetch` call.
    pub async fn fetch(
        &self,
        folder: &str,
        uids: &[crate::types::Uid],
        spec: crate::types::FetchSpec,
        expected_uidvalidity: Option<u32>,
    ) -> Result<(Vec<crate::types::FetchedMessage>, Option<u32>), ImapError> {
        self.with_session("fetch", async |session| {
            crate::ops::fetch::fetch(session, folder, uids, spec, expected_uidvalidity).await
        })
        .await
    }

    /// Fetch the full `BODY[]` of `uid` from `folder`. Returns raw bytes
    /// (no MIME parsing — Sprint 4's `rimap-content` owns that). Drops
    /// the connection on size-limit overflow, connection loss, or timeout,
    /// so the half-consumed response state never leaks to the next op.
    ///
    /// # Pre-flight size check
    ///
    /// Before issuing `FETCH BODY.PEEK[]`, this method issues
    /// `UID FETCH <uid> (RFC822.SIZE)` and rejects with
    /// `ImapError::SizeLimit` if the server-reported size exceeds
    /// `max_fetch_body_bytes`. This prevents async-imap from buffering
    /// the full body into memory for oversize messages, at the cost of
    /// one extra IMAP round-trip.
    ///
    /// The post-parse `project_size` check inside `ops::fetch::fetch_body`
    /// remains as defense-in-depth because servers can lie about
    /// `RFC822.SIZE`.
    ///
    /// # UIDVALIDITY guard
    ///
    /// When `expected_uidvalidity` is `Some(v)`, BOTH internal read-only
    /// SELECTs (the `RFC822.SIZE` preflight and the `BODY.PEEK[]` fetch)
    /// verify the folder's current UIDVALIDITY against `v`, fail-closed: a
    /// mismatch returns `ImapError::UidValidityChanged` and an omitted
    /// server value returns `ImapError::UidValidityUnavailable`. Pass
    /// `None` to skip the guard.
    ///
    /// # Errors
    /// Propagates `ImapError::SizeLimit` if the body exceeds the configured
    /// `max_fetch_body_bytes`, `ImapError::UidValidityChanged` /
    /// `ImapError::UidValidityUnavailable` on a failed guard, plus the usual
    /// timeout / protocol / connection-lost errors.
    pub async fn fetch_body(
        &self,
        folder: &str,
        uid: crate::types::Uid,
        expected_uidvalidity: Option<u32>,
    ) -> Result<Vec<u8>, ImapError> {
        let dur = self.inner.cfg.command_timeout;
        let limit = self.inner.cfg.max_fetch_body_bytes;
        let result = crate::time::with_timeout("fetch_body", dur, async {
            let mut guard = self.session().await?;
            let session =
                guard
                    .as_mut()
                    .ok_or(ImapError::Protocol(async_imap::error::Error::Bad(
                        "session invariant violated: guard is None after session()".to_string(),
                    )))?;
            let server_size =
                crate::ops::fetch::preflight_fetch_size(session, folder, uid, expected_uidvalidity)
                    .await?;
            crate::ops::fetch::preflight_size_check(server_size, limit)?;
            crate::ops::fetch::fetch_body(session, folder, uid, limit, expected_uidvalidity).await
        })
        .await;
        // Drop the cached session on ConnectionLost, SizeLimit, OR Timeout.
        // SizeLimit and Timeout both abort mid-stream, so the IMAP response
        // state is half-consumed and the session cannot be reused.
        // UidValidityUnavailable is fail-closed but the session is healthy
        // (only mailbox identity is unverifiable), so it stays non-invalidating.
        // The match here lists every ImapError variant explicitly because
        // workspace lints ban `_ =>` wildcards.
        let should_invalidate = match &result {
            Err(
                ImapError::ConnectionLost | ImapError::SizeLimit { .. } | ImapError::Timeout { .. },
            ) => true,
            Err(
                ImapError::Tls { .. }
                | ImapError::TlsHandshake(_)
                | ImapError::Starttls { .. }
                | ImapError::Connect(_)
                | ImapError::Auth { .. }
                | ImapError::Protocol(_)
                | ImapError::InvalidInput { .. }
                | ImapError::BatchTooLarge { .. }
                | ImapError::UidValidityChanged { .. }
                | ImapError::UidValidityUnavailable { .. }
                | ImapError::Audit { .. },
            )
            | Ok(_) => false,
        };
        if should_invalidate {
            self.invalidate().await;
        }
        result
    }

    /// `UID STORE` — add or remove flags on messages.
    ///
    /// Batch limit: 100 UIDs. Returns the UIDs the server confirmed.
    ///
    /// If `expected_uidvalidity` is `Some(v)`, the value is compared against
    /// the UIDVALIDITY returned by the internal SELECT. A mismatch returns
    /// `ImapError::UidValidityChanged` before the STORE is sent. Pass `None`
    /// to skip the guard.
    ///
    /// # Errors
    /// Returns `ImapError::BatchTooLarge` if more than 100 UIDs are passed.
    /// Returns `ImapError::UidValidityChanged` on a UIDVALIDITY mismatch.
    /// Returns `ImapError::InvalidInput` if any flag fails `flags_string`
    /// (keyword contains non-atom characters).
    /// Propagates timeout, connection-lost, or protocol errors.
    pub async fn store_flags(
        &self,
        folder: &str,
        uids: &[crate::types::Uid],
        flags: &[crate::types::Flag],
        action: crate::types::FlagAction,
        expected_uidvalidity: Option<u32>,
    ) -> Result<(Vec<crate::types::Uid>, Option<u32>), ImapError> {
        self.with_session("store", async |session| {
            let selected = crate::ops::folders::select(session, folder, false).await?;
            let uid_validity = selected.uid_validity;
            crate::ops::fetch::check_uidvalidity(folder, expected_uidvalidity, uid_validity)?;
            let updated = crate::ops::store::store(session, uids, flags, action).await?;
            Ok((updated, uid_validity))
        })
        .await
    }

    /// Move messages from `source_folder` to `dest_folder`.
    ///
    /// Uses IMAP MOVE extension (RFC 6851) when the server advertised
    /// it; falls back to COPY + STORE \Deleted + EXPUNGE otherwise.
    /// The fallback is not atomic — callers should inspect
    /// `MoveOutcome::used_fallback` and surface a warning.
    ///
    /// If `expected_source_uidvalidity` is `Some(v)`, a STATUS probe is
    /// issued against `source_folder` before the move. A mismatch
    /// returns `ImapError::UidValidityChanged`. Pass `None` to skip the
    /// guard (Task 4 will thread the observed value from SELECT through
    /// tool input).
    ///
    /// Batch limit: 100 UIDs.
    ///
    /// # Errors
    /// Returns `ImapError::BatchTooLarge` if more than 100 UIDs are passed.
    /// Returns `ImapError::UidValidityChanged` on a UIDVALIDITY mismatch.
    /// Propagates timeout, connection-lost, or protocol errors.
    pub async fn move_messages(
        &self,
        source_folder: &str,
        dest_folder: &str,
        uids: &[crate::types::Uid],
        expected_source_uidvalidity: Option<u32>,
    ) -> Result<crate::ops::move_message::MoveOutcome, ImapError> {
        let has_move = self.has_move_capability();
        let has_uidplus = self.has_uidplus_capability();
        self.with_session("move", async |session| {
            crate::ops::folders::select(session, source_folder, false).await?;
            crate::ops::move_message::move_messages(
                session,
                source_folder,
                dest_folder,
                uids,
                expected_source_uidvalidity,
                has_move,
                has_uidplus,
            )
            .await
        })
        .await
    }

    /// `APPEND` a raw RFC 5322 message to `folder` with the given
    /// flags and keywords.
    ///
    /// Does NOT select the folder first -- APPEND targets a named
    /// mailbox directly per RFC 3501 section 6.3.11.
    ///
    /// # Errors
    ///
    /// - `ImapError::SizeLimit` if `message.len()` exceeds the configured
    ///   `max_append_bytes`.
    /// - `ImapError::InvalidInput` if any keyword or `Flag::Keyword` value
    ///   contains non-atom characters.
    /// - Propagates timeout, connection-lost, or protocol errors from
    ///   async-imap.
    pub async fn append_message(
        &self,
        folder: &str,
        message: &[u8],
        flags: &[crate::types::Flag],
        keywords: &[&str],
    ) -> Result<crate::types::AppendResult, ImapError> {
        let limit = self.inner.cfg.max_append_bytes;
        self.with_session("append", async |session| {
            crate::ops::append::append(session, folder, message, flags, keywords, limit).await
        })
        .await
    }

    /// Delete a message by flagging it as `\Deleted` and moving it to Trash.
    ///
    /// If the message is already in the Trash folder, only the flag is applied.
    ///
    /// # Errors
    ///
    /// Returns `ImapError::InvalidInput` if `folder` or `trash_folder` fails
    /// `validate_folder_name`.
    /// Returns `ImapError::ConnectionLost` or `ImapError::Timeout` on transport failure,
    /// or a protocol error if the server rejects the command.
    pub async fn delete_message(
        &self,
        folder: &str,
        uid: crate::types::Uid,
        trash_folder: &str,
    ) -> Result<crate::ops::delete::DeleteResult, ImapError> {
        let has_move = self.has_move_capability();
        let has_uidplus = self.has_uidplus_capability();
        self.with_session("delete_message", async |session| {
            crate::ops::folders::select(session, folder, false).await?;
            crate::ops::delete::delete_message(
                session,
                uid,
                folder,
                trash_folder,
                has_move,
                has_uidplus,
            )
            .await
        })
        .await
    }

    /// Expunge all `\Deleted` messages from `folder`.
    ///
    /// Returns `(deleted_uids, expunged_count)` — the UIDs found by
    /// `UID SEARCH DELETED` before the expunge, and the count from the
    /// EXPUNGE response.
    ///
    /// # Errors
    ///
    /// Returns `ImapError::InvalidInput` if `folder` fails `validate_folder_name`.
    /// Returns `ImapError::ConnectionLost` or `ImapError::Timeout` on transport failure,
    /// or a protocol error if the server rejects the command.
    pub async fn expunge(&self, folder: &str) -> Result<(Vec<crate::types::Uid>, u32), ImapError> {
        self.with_session("expunge", async |session| {
            let deleted_uids = crate::ops::expunge::count_deleted(session, folder).await?;
            crate::ops::folders::select(session, folder, false).await?;
            let count = crate::ops::expunge::expunge(session).await?;
            Ok((deleted_uids, count))
        })
        .await
    }

    /// Create a new IMAP folder.
    ///
    /// # Errors
    ///
    /// Returns `ImapError::InvalidInput` for invalid names, `ImapError::ConnectionLost`
    /// or `ImapError::Timeout` on transport failure, or a protocol error if the
    /// server rejects the command.
    pub async fn create_folder(&self, name: &str) -> Result<(), ImapError> {
        self.with_session("create_folder", async |session| {
            crate::ops::folder_management::create_folder(session, name).await
        })
        .await
    }

    /// Rename an IMAP folder.
    ///
    /// # Errors
    ///
    /// Returns `ImapError::InvalidInput` if either `old_name` or `new_name`
    /// fails `validate_folder_name` (empty, too long, or containing forbidden
    /// characters). Returns `ImapError::ConnectionLost` or
    /// `ImapError::Timeout` on transport failure, or a protocol error if the
    /// server rejects the command.
    pub async fn rename_folder(&self, old_name: &str, new_name: &str) -> Result<(), ImapError> {
        self.with_session("rename_folder", async |session| {
            crate::ops::folder_management::rename_folder(session, old_name, new_name).await
        })
        .await
    }

    /// Delete an IMAP folder and all its contents.
    ///
    /// # Errors
    ///
    /// Returns `ImapError::InvalidInput` if `name` fails
    /// `validate_folder_name`. Returns `ImapError::ConnectionLost` or
    /// `ImapError::Timeout` on transport failure, or a protocol error if
    /// the server rejects the command.
    pub async fn delete_folder(&self, name: &str) -> Result<(), ImapError> {
        self.with_session("delete_folder", async |session| {
            crate::ops::folder_management::delete_folder(session, name).await
        })
        .await
    }
}
