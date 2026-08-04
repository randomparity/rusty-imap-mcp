//! Command-dispatch surface for [`Connection`].
//!
//! Holds `with_session` (the timeout / connection-lost wrapper) and
//! every per-command method that calls into `crate::ops::*`. Each
//! `pub async fn` here is a one-liner that delegates to an op module
//! under the timeout guard.

use crate::error::ImapError;

use super::{Connection, ImapSession};

/// Whether an operation may be transparently reconnected-and-retried after an
/// idle disconnect.
///
/// Retrying re-sends the command against a freshly reconnected session. That
/// is safe only when the command has no server-visible side effect, because a
/// mid-command disconnect can leave the server having *already applied* the
/// first send (an `APPEND` that landed, a `MOVE`/`EXPUNGE` that committed, a
/// `STORE` that toggled a flag). Re-sending such a command would double-apply
/// it, so mutating ops must never auto-retry.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Idempotency {
    /// Read-only op with no server-visible side effect (`LIST`, `STATUS`,
    /// `SELECT`/`EXAMINE`, `SEARCH`, `FETCH`, `BODY.PEEK`). Safe to retry once.
    ReadOnly,
    /// Mutating op (`STORE`, `MOVE`, `APPEND`, `EXPUNGE`, folder
    /// create/rename/delete). Never auto-retried — a re-send could
    /// double-apply.
    Mutating,
}

/// Transport-level failures that mean the cached session is dead and must be
/// dropped before the next command reuses it.
///
/// `SizeLimit` aborts a fetch mid-stream, leaving the IMAP response
/// half-consumed, so the session must be dropped. (`append` is the only other
/// `SizeLimit` producer; it checks size before sending, so invalidating a
/// healthy session there is a harmless reconnect.)
fn is_transport_failure<T>(result: &Result<T, ImapError>) -> bool {
    matches!(
        result,
        Err(ImapError::ConnectionLost | ImapError::SizeLimit { .. } | ImapError::Timeout { .. })
    )
}

/// Whether `result` warrants one transparent reconnect-and-retry.
///
/// Fires only for an idempotent op that lost its connection — the stale-idle
/// case. A `Timeout` is excluded (the command may still be running
/// server-side) and so is `SizeLimit` (a deterministic rejection, not a
/// transient disconnect).
fn should_reconnect<T>(idempotency: Idempotency, result: &Result<T, ImapError>) -> bool {
    idempotency == Idempotency::ReadOnly && matches!(result, Err(ImapError::ConnectionLost))
}

impl Connection {
    /// Run an IMAP operation under a command timeout, transparently recovering
    /// from an idle disconnect.
    ///
    /// The closure receives a mutable reference to the live `Session`. On a
    /// transport-level failure (`ConnectionLost`, `SizeLimit`, or `Timeout`)
    /// the cached session is dropped so the next call lazy-reconnects. That
    /// discard happens in [`Self::attempt`], where [`super::SessionGuard`]
    /// still holds the session lock, and nothing here re-acquires the lock to
    /// repeat it. A command that has released the lock no longer knows whose
    /// session is in the slot: `tokio::sync::Mutex` is FIFO-fair, so the peer
    /// queued behind it is served first, and that peer consumes the poison and
    /// reconnects — leaving its own healthy session there to be discarded
    /// (#629). The retry below is the one exception, and it is safe precisely
    /// because it goes back through `attempt` and reads the flag under the
    /// lock rather than clearing the slot from outside.
    ///
    /// When `idempotency` is [`Idempotency::ReadOnly`] and the failure is
    /// [`ImapError::ConnectionLost`] — the signature of a session the server
    /// closed during an idle gap — the operation is reconnected and retried
    /// **once**, so the first resumed tool call recovers instead of surfacing
    /// `ERR_CONNECTION_LOST`. [`Idempotency::Mutating`] ops are never retried;
    /// a re-sent write could double-apply. The loop is bounded to two attempts
    /// so a persistently broken server cannot storm.
    ///
    /// `make_body` is a *factory*: it is called once per attempt to produce a
    /// fresh single-use body closure. A factory (rather than one reusable
    /// `AsyncFn` body) is required because passing this crate's real per-op
    /// closures through a multi-call `AsyncFn` generic trips a spurious
    /// higher-ranked lifetime error (E0477) at the caller's monomorphization
    /// site; a `Fn() -> AsyncFnOnce` factory keeps the looser, working
    /// `AsyncFnOnce` bound on the body.
    ///
    /// The control flow here mirrors the test-only `with_reconnect` helper; the
    /// two share the [`should_reconnect`] predicate that carries all the
    /// retry-policy logic.
    pub(super) async fn with_session<T, Mk, B>(
        &self,
        op_name: &'static str,
        idempotency: Idempotency,
        make_body: Mk,
    ) -> Result<T, ImapError>
    where
        Mk: Fn() -> B,
        B: for<'s> AsyncFnOnce(&'s mut ImapSession) -> Result<T, ImapError>,
    {
        let first = self.attempt(op_name, make_body()).await;
        if !should_reconnect(idempotency, &first) {
            return first;
        }
        self.attempt(op_name, make_body()).await
    }

    /// A single timeout-guarded run of `body` against the live session.
    ///
    /// The two stages carry **separate** budgets, and deliberately so:
    ///
    /// * Acquiring the session lock and running `body` are bounded by
    ///   `command_timeout` — a peer op mid-command must not stall this one
    ///   indefinitely, and a stalled command must still trip.
    /// * The lazy-connect in between is bounded only by its own
    ///   `connect_timeout`, inside `connect_with_bundle`.
    ///
    /// Wrapping the connect in `command_timeout` as well (as this did before)
    /// loses audit records: the command deadline starts strictly earlier — the
    /// lock acquisition and `build_tls_config` run before `connect_with_bundle`
    /// takes its own start instant — so it can elapse first and drop the
    /// connect future while it is still parked on the network. `connect_inner`
    /// then never reaches its `emit_auth` call and the `auth` record it
    /// documents on every termination path is silently lost. With the budgets
    /// split, the connect deadline always fires first on a stalled connect and
    /// the record is always written, whatever the two values are configured to.
    async fn attempt<T, B>(&self, op_name: &'static str, body: B) -> Result<T, ImapError>
    where
        B: for<'s> AsyncFnOnce(&'s mut ImapSession) -> Result<T, ImapError>,
    {
        let dur = self.inner.cfg.command_timeout;

        // `SessionGuard` owns the lock for the rest of this function. Anything
        // that cuts the command from here — a client cancellation, a runtime
        // shutdown, the per-tool-call ceiling — drops it, and its `Drop`
        // poisons the connection *before* releasing the lock, so the flag is
        // ordered ahead of any peer already queued on it. See `SessionGuard`.
        let mut guard = super::SessionGuard::new(
            self,
            crate::time::with_timeout(op_name, dur, async { Ok(self.inner.session.lock().await) })
                .await?,
        );

        // Something may have cut a command mid-flight and poisoned the
        // session. Consume the flag here, under the lock, so this command
        // reconnects instead of parsing the previous command's unread
        // response as its own.
        if self.take_poisoned(&mut guard) {
            tracing::debug!(
                op = op_name,
                "dropping poisoned IMAP session before command"
            );
        }

        let session = match &mut *guard {
            Some(session) => session,
            slot => slot.insert(self.connect_inner().await?),
        };
        let outcome = crate::time::with_timeout(op_name, dur, body(session)).await;

        // A body that RETURNED can still have ended mid-response, and that
        // reaches the same desync a cancellation does with nothing cancelled:
        // `with_timeout` elapsing drops the body future exactly as a cut would,
        // and `SizeLimit` aborts a fetch mid-stream (see `is_transport_failure`).
        //
        // Leaving the guard armed for those hands the flag to the next holder
        // of the lock, which is the only placement that works. Disarming and
        // clearing the slot after this function returns would not: that has to
        // RE-ACQUIRE the lock, so a FIFO peer queued behind this command takes
        // the desynced session first — and then it is that peer's *replacement*
        // session sitting in the slot when the lock finally comes back (#629).
        if !is_transport_failure(&outcome) {
            guard.disarm();
        }
        outcome
    }

    /// `LIST` against `pattern` (e.g. `"*"`, `"INBOX/*"`).
    ///
    /// A read-only op: on `ConnectionLost` it reconnects and retries once
    /// (see [`Self::with_session`]) so a stale idle session recovers
    /// transparently.
    ///
    /// # Errors
    ///
    /// Propagates any `ImapError` produced by `time::with_timeout` or the
    /// underlying `ops::folders::list` call.
    pub async fn list_folders(
        &self,
        pattern: &str,
    ) -> Result<Vec<crate::types::Folder>, ImapError> {
        self.with_session("list", Idempotency::ReadOnly, || {
            async |session| crate::ops::folders::list(session, pattern).await
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
        self.with_session("list_folders_with_status", Idempotency::ReadOnly, || {
            async move |session| crate::ops::folders::list_with_status(session, pattern).await
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
        self.with_session("status", Idempotency::ReadOnly, || {
            async |session| crate::ops::folders::status(session, folder, items).await
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
        self.with_session("select", Idempotency::ReadOnly, || {
            async |session| crate::ops::folders::select(session, folder, read_only).await
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
        self.with_session("search", Idempotency::ReadOnly, || {
            async |session| crate::ops::search::search(session, folder, query.clone()).await
        })
        .await
    }

    /// `SEARCH` for messages related to `own_message_id` by RFC 5322
    /// threading (`References`/`In-Reply-To`/`Message-ID`), within
    /// `folder`. See `ops::search::thread_related` for the query this
    /// builds and its injection-safety rationale.
    ///
    /// # Errors
    /// Propagates timeout, connection-lost, or protocol errors from the
    /// underlying `ops::search::thread_related` call.
    pub async fn thread_related(
        &self,
        folder: &str,
        own_message_id: Option<&str>,
        ancestor_ids: &[String],
    ) -> Result<(Vec<crate::types::Uid>, Option<u32>), ImapError> {
        self.with_session("thread_related", Idempotency::ReadOnly, || {
            async |session| {
                crate::ops::search::thread_related(session, folder, own_message_id, ancestor_ids)
                    .await
            }
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
        self.with_session("fetch", Idempotency::ReadOnly, || {
            async |session| {
                crate::ops::fetch::fetch(session, folder, uids, spec, expected_uidvalidity).await
            }
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
        self.fetch_body_with_limit(
            folder,
            uid,
            expected_uidvalidity,
            self.inner.cfg.max_fetch_body_bytes,
        )
        .await
    }

    /// Like [`Self::fetch_body`], but with a caller-supplied byte `limit`
    /// instead of the configured `max_fetch_body_bytes`.
    ///
    /// `export_messages` passes `min(max_fetch_body_bytes, remaining_budget)`
    /// so a single in-flight body cannot exceed the export's remaining
    /// aggregate budget, pinning peak heap to ≈ the budget (#318). The `limit`
    /// drives both the `RFC822.SIZE` preflight and the post-parse
    /// `project_size` read check, so an oversize body is rejected with
    /// `ImapError::SizeLimit` — before reading when the server reports an
    /// honest size, or mid-stream when it under-reports.
    ///
    /// # Errors
    ///
    /// Same as [`Self::fetch_body`], with `SizeLimit` keyed to `limit`.
    pub async fn fetch_body_with_limit(
        &self,
        folder: &str,
        uid: crate::types::Uid,
        expected_uidvalidity: Option<u32>,
        limit: u64,
    ) -> Result<Vec<u8>, ImapError> {
        self.with_session("fetch_body", Idempotency::ReadOnly, || {
            async |session| {
                let server_size = crate::ops::fetch::preflight_fetch_size(
                    session,
                    folder,
                    uid,
                    expected_uidvalidity,
                )
                .await?;
                crate::ops::fetch::preflight_size_check(server_size, limit)?;
                crate::ops::fetch::fetch_body(session, folder, uid, limit, expected_uidvalidity)
                    .await
            }
        })
        .await
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
        self.with_session("store", Idempotency::Mutating, || {
            async |session| {
                let selected = crate::ops::folders::select(session, folder, false).await?;
                let uid_validity = selected.uid_validity;
                crate::ops::fetch::check_uidvalidity(folder, expected_uidvalidity, uid_validity)?;
                let updated = crate::ops::store::store(session, uids, flags, action).await?;
                Ok((updated, uid_validity))
            }
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
        self.with_session("move", Idempotency::Mutating, || {
            async |session| {
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
            }
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
        self.with_session("append", Idempotency::Mutating, || {
            async |session| {
                crate::ops::append::append(session, folder, message, flags, keywords, limit).await
            }
        })
        .await
    }

    /// Delete a message by flagging it as `\Deleted` and moving it to Trash.
    ///
    /// If the message is already in the Trash folder, only the flag is applied.
    ///
    /// If `expected_uidvalidity` is `Some(v)`, the folder's UIDVALIDITY
    /// (observed at the SELECT this call performs) is verified against `v`
    /// before the delete proceeds; a mismatch returns
    /// `ImapError::UidValidityChanged`. Pass `None` to skip the guard.
    ///
    /// # Errors
    ///
    /// Returns `ImapError::InvalidInput` if `folder` or `trash_folder` fails
    /// `validate_folder_name`.
    /// Returns `ImapError::UidValidityChanged` if `expected_uidvalidity` is
    /// set and does not match the folder's observed UIDVALIDITY.
    /// Returns `ImapError::ConnectionLost` or `ImapError::Timeout` on transport failure,
    /// or a protocol error if the server rejects the command.
    pub async fn delete_message(
        &self,
        folder: &str,
        uid: crate::types::Uid,
        trash_folder: &str,
        expected_uidvalidity: Option<u32>,
    ) -> Result<(crate::ops::delete::DeleteResult, Option<u32>), ImapError> {
        let has_move = self.has_move_capability();
        let has_uidplus = self.has_uidplus_capability();
        self.with_session("delete_message", Idempotency::Mutating, || {
            async |session| {
                let selected = crate::ops::folders::select(session, folder, false).await?;
                let uid_validity = selected.uid_validity;
                crate::ops::fetch::check_uidvalidity(folder, expected_uidvalidity, uid_validity)?;
                let result = crate::ops::delete::delete_message(
                    session,
                    uid,
                    folder,
                    trash_folder,
                    has_move,
                    has_uidplus,
                )
                .await?;
                Ok((result, uid_validity))
            }
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
        self.with_session("expunge", Idempotency::Mutating, || {
            async |session| {
                let deleted_uids = crate::ops::expunge::count_deleted(session, folder).await?;
                crate::ops::folders::select(session, folder, false).await?;
                let count = crate::ops::expunge::expunge(session).await?;
                Ok((deleted_uids, count))
            }
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
        self.with_session("create_folder", Idempotency::Mutating, || {
            async |session| crate::ops::folder_management::create_folder(session, name).await
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
        self.with_session("rename_folder", Idempotency::Mutating, || {
            async |session| {
                crate::ops::folder_management::rename_folder(session, old_name, new_name).await
            }
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
        self.with_session("delete_folder", Idempotency::Mutating, || {
            async |session| crate::ops::folder_management::delete_folder(session, name).await
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::{Idempotency, is_transport_failure, should_reconnect};
    use crate::error::ImapError;

    /// Mirror of [`Connection::with_session`]'s retry loop, decoupled from a
    /// live session so the loop behavior can be exercised with a scripted
    /// `attempt` closure. It shares the exact [`should_reconnect`] predicate
    /// the real loop uses, so the retry *policy* is verified against the same
    /// code the production path runs; only the attempt itself is a stand-in.
    /// (The production loop cannot itself be generic over the closure — doing
    /// so trips an `AsyncFn` lifetime error at the real call sites.)
    ///
    /// What these tests can decide is how many attempts each
    /// (idempotency, error) pair earns and which result is returned.
    /// *Discarding* the dead session is no longer part of this loop — it
    /// happens inside `attempt`, under the session lock, and is pinned
    /// end-to-end by `tests/transport_failure_poison.rs` and
    /// `tests/reconnect_recovery.rs`.
    async fn with_reconnect<T, A>(idempotency: Idempotency, attempt: A) -> Result<T, ImapError>
    where
        A: AsyncFn() -> Result<T, ImapError>,
    {
        let first = attempt().await;
        if !should_reconnect(idempotency, &first) {
            return first;
        }
        attempt().await
    }

    fn protocol_err() -> ImapError {
        ImapError::Protocol(async_imap::error::Error::Bad("x".to_string()))
    }

    #[test]
    fn should_reconnect_only_for_read_op_connection_lost() {
        let cases: &[(Idempotency, Result<u8, ImapError>, bool)] = &[
            (Idempotency::ReadOnly, Err(ImapError::ConnectionLost), true),
            (Idempotency::Mutating, Err(ImapError::ConnectionLost), false),
            (
                Idempotency::ReadOnly,
                Err(ImapError::Timeout { op: "fetch" }),
                false,
            ),
            (
                Idempotency::ReadOnly,
                Err(ImapError::SizeLimit { limit: 1 }),
                false,
            ),
            (Idempotency::ReadOnly, Err(protocol_err()), false),
            (Idempotency::ReadOnly, Ok(1), false),
        ];
        for (idempotency, result, expected) in cases {
            assert_eq!(
                should_reconnect(*idempotency, result),
                *expected,
                "for {idempotency:?} / {result:?}",
            );
        }
    }

    #[test]
    fn is_transport_failure_covers_dead_session_errors_only() {
        assert!(is_transport_failure::<u8>(&Err(ImapError::ConnectionLost)));
        assert!(is_transport_failure::<u8>(&Err(ImapError::SizeLimit {
            limit: 1
        })));
        assert!(is_transport_failure::<u8>(&Err(ImapError::Timeout {
            op: "x"
        })));
        assert!(!is_transport_failure::<u8>(&Ok(1)));
        assert!(!is_transport_failure::<u8>(&Err(protocol_err())));
    }

    /// Drive `with_reconnect` with a scripted `attempt` (indexed by call
    /// count) and count the attempts. Returns `(result, attempts)`.
    async fn run(
        idempotency: Idempotency,
        script: impl Fn(usize) -> Result<u8, ImapError>,
    ) -> (Result<u8, ImapError>, usize) {
        let attempts = Cell::new(0usize);
        let out = with_reconnect(idempotency, async || {
            let n = attempts.get();
            attempts.set(n + 1);
            script(n)
        })
        .await;
        (out, attempts.get())
    }

    #[tokio::test]
    async fn read_op_recovers_transparently_after_idle_disconnect() {
        // First resumed call hits a stale session (ConnectionLost); the retry
        // against a fresh session succeeds — the caller never sees the error.
        let (out, attempts) = run(Idempotency::ReadOnly, |n| {
            if n == 0 {
                Err(ImapError::ConnectionLost)
            } else {
                Ok(7)
            }
        })
        .await;
        assert!(matches!(out, Ok(7)), "retry should recover, got {out:?}");
        assert_eq!(attempts, 2, "one retry after the lost connection");
    }

    #[tokio::test]
    async fn mutating_op_does_not_auto_retry() {
        // A write that loses its connection must surface the error, not
        // re-send (which could double-apply). Only one attempt is made.
        let (out, attempts) = run(Idempotency::Mutating, |n| {
            if n == 0 {
                Err(ImapError::ConnectionLost)
            } else {
                Ok(7) // must never be reached
            }
        })
        .await;
        assert!(
            matches!(out, Err(ImapError::ConnectionLost)),
            "write must propagate ConnectionLost, got {out:?}",
        );
        assert_eq!(attempts, 1, "write must not retry");
    }

    #[tokio::test]
    async fn read_op_retry_is_bounded_to_two_attempts() {
        // A persistently dead server must not storm: at most one retry.
        let (out, attempts) = run(Idempotency::ReadOnly, |_| Err(ImapError::ConnectionLost)).await;
        assert!(
            matches!(out, Err(ImapError::ConnectionLost)),
            "second failure propagates, got {out:?}",
        );
        assert_eq!(attempts, 2, "bounded to exactly two attempts");
    }

    #[tokio::test]
    async fn read_op_timeout_is_not_retried() {
        // A timeout may mean the command is still running server-side; do not
        // resend even for a read.
        let (out, attempts) = run(Idempotency::ReadOnly, |_| {
            Err(ImapError::Timeout { op: "fetch" })
        })
        .await;
        assert!(matches!(out, Err(ImapError::Timeout { .. })), "got {out:?}");
        assert_eq!(attempts, 1, "timeout is not retried");
    }

    #[tokio::test]
    async fn healthy_read_op_runs_once() {
        let (out, attempts) = run(Idempotency::ReadOnly, |_| Ok(7)).await;
        assert!(matches!(out, Ok(7)));
        assert_eq!(attempts, 1, "no retry on success");
    }
}
