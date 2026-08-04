//! Tool dispatch routing.
//!
//! [`ImapMcpServer::dispatch_tool`] routes a resolved `(account, tool,
//! args)` triple to the matching handler in `crate::tools`. Each arm
//! serializes its typed response to `serde_json::Value` so the audit
//! envelope can work with a single future type.
//!
//! Also hosts [`PostureContext`] — the audit-envelope posture header
//! tag — and [`rimap_error_to_breaker_reason`], the mapping from
//! [`rimap_core::RimapError`] codes to [`rimap_authz::breaker::FailureReason`]
//! used to drive the per-account circuit breaker.

use std::marker::PhantomData;

use rmcp::model::{CallToolResult, ErrorData};

use crate::boot::registry::AccountState;
use crate::mcp::server::ImapMcpServer;
use crate::mcp::tool_catalog::{parse_args, ser};
use rimap_core::tool::ToolName;

/// Proof that the audit envelope is open and the pre-dispatch checks
/// (posture, breaker, rate limit) have already run. Construction is
/// module-private; the only way to obtain one is via the `body`
/// closure of [`ImapMcpServer::run_with_audit_envelope`] (or the
/// sibling [`ImapMcpServer::dispatch_infrastructure`]). Because
/// [`ImapMcpServer::dispatch_tool`] consumes the ticket by value,
/// forgetting to wrap a dispatch in the envelope becomes a compile
/// error rather than a silent audit-log gap (#110).
///
/// Deliberately neither `Clone` nor `Copy`: a ticket is single-use,
/// scoped to one envelope. Kept `Send` so the dispatch future can
/// cross `await` boundaries inside the tokio-based MCP handler.
///
/// Note on marker choice: the original design sketched
/// `PhantomData<*const ()>` to kill `Send`/`Sync` auto-traits as a
/// further reuse barrier. `rmcp::ServerHandler::call_tool` returns a
/// `MaybeSendFuture`-bound future, and non-`Send` types held across
/// `.await` boundaries inside that future fail to compile. Since the
/// ticket is a ZST with no interior state, the weaker `PhantomData<()>`
/// is as safe as `*const ()` would be — the `Send`/`Sync` auto-traits
/// have nothing to leak — and the single-use guarantee still holds via
/// absence of `Clone`/`Copy` and module-private construction.
#[must_use]
pub(crate) struct DispatchTicket(PhantomData<()>);

impl DispatchTicket {
    /// Mint a new ticket. Callable only from within this module, so
    /// every ticket is necessarily produced by the audit-envelope
    /// machinery that opens a `tool_start` record.
    pub(super) fn new() -> Self {
        Self(PhantomData)
    }
}

/// Posture context recorded in audit envelope headers.
///
/// Per-account dispatches use the account's effective posture; the
/// infrastructure tools (`list_accounts`, `use_account`) bypass posture
/// gating by design and record the dedicated `Infrastructure` variant so
/// log readers can distinguish them from per-account dispatches.
#[derive(Debug, Clone, Copy)]
pub(super) enum PostureContext {
    Account(rimap_core::Posture),
    Infrastructure,
}

impl PostureContext {
    /// The per-account [`rimap_core::Posture`] this context represents, or
    /// `None` for the infrastructure dispatch path. The audit writer maps
    /// `None` to the `"infrastructure"` sentinel it records on disk.
    pub(super) fn posture(self) -> Option<rimap_core::Posture> {
        match self {
            Self::Account(p) => Some(p),
            Self::Infrastructure => None,
        }
    }
}

/// Map a [`rimap_core::RimapError`] to the breaker's [`FailureReason`], or
/// `None` when the error represents a user/agent/policy failure (which
/// the breaker must ignore per its contract).
pub(super) fn rimap_error_to_breaker_reason(
    err: &rimap_core::RimapError,
) -> Option<rimap_authz::breaker::FailureReason> {
    use rimap_authz::breaker::FailureReason;
    use rimap_core::ErrorCode;
    // SMTP send failures are breaker-neutral. The per-account breaker guards the
    // long-lived IMAP connection; `send_email`/`forward` open a fresh SMTP
    // connection per call and share no state with it, so a wrong SMTP password
    // (`ERR_AUTH`) or a rejected recipient (`ERR_SMTP_PROTOCOL`) must not open
    // the breaker and deny unrelated read-only IMAP tools. Before #517 these
    // surfaced as `ERR_INTERNAL` (neutral); this preserves that while keeping
    // the now-correct SMTP error codes.
    if let rimap_core::RimapError::Smtp { .. } = err {
        return None;
    }
    match err.code() {
        ErrorCode::ConnectionLost => Some(FailureReason::ConnectionLost),
        ErrorCode::Auth => Some(FailureReason::Auth),
        ErrorCode::Timeout => Some(FailureReason::Timeout),
        ErrorCode::ImapProtocol | ErrorCode::SmtpProtocol => Some(FailureReason::Protocol),
        ErrorCode::Tls => Some(FailureReason::Tls),
        ErrorCode::InvalidInput
        | ErrorCode::PostureDenied
        | ErrorCode::RateLimited
        | ErrorCode::CircuitOpen
        | ErrorCode::NotFound
        | ErrorCode::AttachmentTooLarge
        | ErrorCode::ProtectedFolder
        | ErrorCode::ExpungeDenied
        | ErrorCode::Config
        | ErrorCode::Internal
        | ErrorCode::NoAccount
        | ErrorCode::UnknownAccount
        | ErrorCode::Cancelled
        | ErrorCode::UidValidityChanged => None,
    }
}

/// Run one account-scoped tool dispatch under the per-tool-call ceiling
/// (#594, ADR-0012).
///
/// `[imap]`'s budgets bound the session-lock wait, the lazy connect and
/// the command *separately*, and `with_session` may run the whole
/// sequence twice, so no `[imap]` field predicts how long one tool call
/// can take. `ceiling` is that single bound.
///
/// Two placement properties this relies on, both load-bearing:
///
/// * It wraps the dispatch **inside** the audit envelope's body future,
///   not around the envelope. `AuditEnvelopeGuard` synthesizes an
///   `ERR_CANCELLED` `tool_end` when the envelope future is dropped, so
///   timing out the envelope would record an operator-configured ceiling
///   as a client cancellation. Cutting the body instead leaves the
///   envelope's frame alive, and the `Err` returned here reaches
///   `emit_tool_end` as an ordinary `ERR_TIMEOUT` outcome.
/// * It wraps only the dispatch, so the caller's breaker accounting still
///   runs on the way out and a ceiling that keeps firing opens the
///   per-account circuit breaker.
///
/// `on_timeout` runs only when the ceiling fires. Dropping the dispatch
/// future mid-command leaves the cached IMAP session holding an unread
/// server response, which the next command would misparse as its own, so
/// the caller uses it to mark the connection unusable. An inner
/// `ERR_TIMEOUT` is returned verbatim and does *not* run it — that path
/// stayed inside its stage budget and `with_session` invalidated already.
///
/// **`on_timeout` runs while `dispatch` is still alive**, which is why
/// `dispatch` is pinned to a local rather than moved into `timeout`. The
/// awaited `Timeout` drops the dispatch future — and with it the session
/// lock guard held inside `Connection::attempt` — as soon as the `.await`
/// completes, so a callback that ran after that would set its flag *after*
/// the lock had already woken the next FIFO waiter, and that waiter would
/// take the poisoned session. Holding the dispatch across the callback is
/// what orders the flag ahead of every queued waiter.
///
/// That ordering imposes a contract on `on_timeout`: it must be
/// non-blocking and must not touch the session lock, which the cut
/// dispatch still holds. `Connection::poison` is a plain atomic store for
/// exactly this reason; an `invalidate().await` here would deadlock.
pub(super) async fn with_tool_call_ceiling<T, F>(
    ceiling: std::time::Duration,
    dispatch: F,
    on_timeout: impl FnOnce(),
) -> Result<T, rimap_core::RimapError>
where
    F: std::future::Future<Output = Result<T, rimap_core::RimapError>>,
{
    let mut dispatch = std::pin::pin!(dispatch);
    match tokio::time::timeout(ceiling, dispatch.as_mut()).await {
        Ok(result) => result,
        Err(_elapsed) => {
            on_timeout();
            Err(rimap_core::RimapError::Imap {
                code: rimap_core::ErrorCode::Timeout,
                message: format!(
                    "tool call exceeded the {}s ceiling \
                     (limits.tool_call_timeout_seconds)",
                    ceiling.as_secs(),
                ),
                source: None,
            })
        }
    }
}

impl ImapMcpServer {
    /// Dispatch to the tool handler for `tool`. Each arm serializes its
    /// typed response to `serde_json::Value` before returning, so the
    /// audit envelope works with a single future type.
    ///
    /// The [`DispatchTicket`] is consumed by value — its construction is
    /// module-private and only `run_with_audit_envelope` /
    /// `dispatch_infrastructure` mint one, so any caller must first open
    /// the audit envelope. This closes the bypass where a direct
    /// `dispatch_tool` call would skip posture gating, breaker updates,
    /// rate limits, and the `tool_start`/`tool_end` envelope (#110).
    pub(crate) async fn dispatch_tool(
        &self,
        _ticket: DispatchTicket,
        account: &AccountState,
        tool: ToolName,
        args: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<serde_json::Value, rimap_core::RimapError> {
        use crate::tools::admin::list_folders;
        use crate::tools::compose::{create_draft, forward, send_email};
        use crate::tools::mailbox::{
            delete_message, expunge, flags, folder_management, labels, move_message,
        };
        use crate::tools::retrieval::{
            download_attachment, export_messages, fetch_message, list_attachments, search,
        };
        let resp = match tool {
            ToolName::ListFolders => ser(Box::pin(list_folders::handle(account)).await?)?,
            ToolName::MarkRead => {
                ser(Box::pin(flags::handle_mark_read(account, parse_args(args)?)).await?)?
            }
            ToolName::MarkUnread => {
                ser(Box::pin(flags::handle_mark_unread(account, parse_args(args)?)).await?)?
            }
            ToolName::Flag => ser(Box::pin(flags::handle_flag(account, parse_args(args)?)).await?)?,
            ToolName::Unflag => {
                ser(Box::pin(flags::handle_unflag(account, parse_args(args)?)).await?)?
            }
            ToolName::MoveMessage => {
                ser(Box::pin(move_message::handle(account, parse_args(args)?)).await?)?
            }
            ToolName::Search | ToolName::SearchAdvanced => {
                ser(Box::pin(search::handle(account, parse_args(args)?)).await?)?
            }
            ToolName::FetchMessage | ToolName::FetchMessageHtml => {
                ser(Box::pin(fetch_message::handle(account, parse_args(args)?)).await?)?
            }
            ToolName::ListAttachments => {
                ser(Box::pin(list_attachments::handle(account, parse_args(args)?)).await?)?
            }
            ToolName::DownloadAttachment => {
                ser(Box::pin(download_attachment::handle(account, parse_args(args)?)).await?)?
            }
            ToolName::ExportMessages => {
                ser(Box::pin(export_messages::handle(account, parse_args(args)?)).await?)?
            }
            ToolName::CreateDraft | ToolName::CreateDraftHtml => {
                ser(Box::pin(create_draft::handle(account, parse_args(args)?)).await?)?
            }
            ToolName::SendEmail => {
                ser(Box::pin(send_email::handle(account, parse_args(args)?)).await?)?
            }
            ToolName::Forward => ser(Box::pin(forward::handle(account, parse_args(args)?)).await?)?,
            ToolName::DeleteMessage => {
                ser(Box::pin(delete_message::handle(account, parse_args(args)?)).await?)?
            }
            ToolName::Expunge => ser(Box::pin(expunge::handle(account, parse_args(args)?)).await?)?,
            ToolName::CreateFolder => ser(Box::pin(folder_management::handle_create_folder(
                account,
                parse_args(args)?,
            ))
            .await?)?,
            ToolName::RenameFolder => ser(Box::pin(folder_management::handle_rename_folder(
                account,
                parse_args(args)?,
            ))
            .await?)?,
            ToolName::DeleteFolder => ser(Box::pin(folder_management::handle_delete_folder(
                account,
                parse_args(args)?,
            ))
            .await?)?,
            ToolName::AddLabel => {
                ser(Box::pin(labels::handle_add_label(account, parse_args(args)?)).await?)?
            }
            ToolName::RemoveLabel => {
                ser(Box::pin(labels::handle_remove_label(account, parse_args(args)?)).await?)?
            }
            ToolName::ListLabels => {
                ser(Box::pin(labels::handle_list_labels(account, parse_args(args)?)).await?)?
            }
            ToolName::UseAccount | ToolName::ListAccounts => {
                return Err(rimap_core::RimapError::Internal(
                    "infrastructure tools must not reach dispatch_tool".into(),
                ));
            }
        };
        Ok(resp)
    }

    /// Handle infrastructure tools that bypass account resolution.
    ///
    /// Infrastructure tools are not scoped to an account, so their audit
    /// records record `account: None` regardless of deployment mode.
    pub(super) async fn dispatch_infrastructure(
        &self,
        tool: ToolName,
        args: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<CallToolResult, ErrorData> {
        // Infrastructure tools have no per-account posture; record an
        // explicit sentinel so log readers can distinguish these from
        // per-account dispatches.
        self.run_with_audit_envelope(
            tool,
            None,
            PostureContext::Infrastructure,
            args,
            |_ticket| async move {
                // Infrastructure tools bypass posture + breaker, but still
                // enforce a process-wide rate limit.
                self.registry.check_infrastructure_rate()?;
                match tool {
                    ToolName::UseAccount => {
                        let input =
                            parse_args::<crate::tools::admin::accounts::UseAccountInput>(args)?;
                        ser(crate::tools::admin::accounts::handle_use_account(
                            &self.registry,
                            input,
                        )
                        .await?)
                    }
                    ToolName::ListAccounts => ser(
                        crate::tools::admin::accounts::handle_list_accounts(&self.registry).await?,
                    ),
                    ToolName::ListFolders
                    | ToolName::Search
                    | ToolName::SearchAdvanced
                    | ToolName::FetchMessage
                    | ToolName::FetchMessageHtml
                    | ToolName::ListAttachments
                    | ToolName::DownloadAttachment
                    | ToolName::ExportMessages
                    | ToolName::MarkRead
                    | ToolName::MarkUnread
                    | ToolName::Flag
                    | ToolName::Unflag
                    | ToolName::AddLabel
                    | ToolName::RemoveLabel
                    | ToolName::ListLabels
                    | ToolName::MoveMessage
                    | ToolName::CreateDraft
                    | ToolName::CreateDraftHtml
                    | ToolName::SendEmail
                    | ToolName::Forward
                    | ToolName::DeleteMessage
                    | ToolName::Expunge
                    | ToolName::CreateFolder
                    | ToolName::RenameFolder
                    | ToolName::DeleteFolder => Err(rimap_core::RimapError::Internal(format!(
                        "not an infrastructure tool: {}",
                        tool.as_str(),
                    ))),
                }
            },
        )
        .await
    }
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "tests")]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use rimap_core::tool::ToolName;

    use super::{rimap_error_to_breaker_reason, with_tool_call_ceiling};

    /// The ceiling drops the in-flight dispatch and reports `ERR_TIMEOUT`
    /// (not `ERR_CANCELLED`), naming the budget it enforced, and runs the
    /// caller's cleanup exactly once (#594).
    #[tokio::test]
    async fn ceiling_elapsing_reports_timeout_and_runs_cleanup() {
        let cleaned = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&cleaned);
        let err = with_tool_call_ceiling(
            Duration::from_millis(50),
            std::future::pending::<Result<(), rimap_core::RimapError>>(),
            || flag.store(true, Ordering::SeqCst),
        )
        .await
        .expect_err("a pending dispatch must be cut off by the ceiling");

        assert_eq!(err.code(), rimap_core::ErrorCode::Timeout);
        assert!(
            err.to_string().contains("tool_call_timeout_seconds"),
            "the message must name the knob an operator would raise: {err}",
        );
        assert!(
            cleaned.load(Ordering::SeqCst),
            "a fired ceiling must run the session-invalidation cleanup",
        );
    }

    /// `on_timeout` must run while the cut dispatch still holds whatever
    /// locks it took — that ordering is the whole reason
    /// `Connection::poison` beats a peer already queued on the session
    /// lock. If the dispatch future were dropped first, the lock would
    /// wake the next FIFO waiter *before* the flag was set and that
    /// waiter would take the poisoned session.
    ///
    /// Asserted directly rather than through the scheduler: a `try_lock`
    /// inside the callback must FAIL, because the dispatch still owns the
    /// guard. Moving `dispatch` into `timeout` (dropping it at the
    /// `.await`) makes this `try_lock` succeed and the test fail, with no
    /// dependence on tokio's wake heuristics.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cleanup_runs_before_the_cut_dispatch_releases_its_locks() {
        let lock = Arc::new(tokio::sync::Mutex::new(()));
        let probe = Arc::clone(&lock);
        let held_during_cleanup = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&held_during_cleanup);

        let body = {
            let lock = Arc::clone(&lock);
            async move {
                let _guard = lock.lock().await;
                std::future::pending::<Result<(), rimap_core::RimapError>>().await
            }
        };

        let err = with_tool_call_ceiling(Duration::from_millis(50), body, || {
            // The cut dispatch must still be holding the guard here.
            flag.store(probe.try_lock().is_err(), Ordering::SeqCst);
        })
        .await
        .expect_err("the ceiling must cut a dispatch parked while holding the lock");
        assert_eq!(err.code(), rimap_core::ErrorCode::Timeout);

        assert!(
            held_during_cleanup.load(Ordering::SeqCst),
            "cleanup ran after the dispatch released its lock: a queued peer \
             would already have been woken and taken the poisoned session",
        );
        assert!(
            lock.try_lock().is_ok(),
            "the lock must be released once with_tool_call_ceiling returns",
        );
    }

    /// A dispatch that finishes inside the ceiling passes its value
    /// through untouched and leaves the cleanup unrun.
    #[tokio::test]
    async fn dispatch_within_ceiling_passes_through() {
        let cleaned = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&cleaned);
        let value = with_tool_call_ceiling(
            Duration::from_secs(30),
            async { Ok::<_, rimap_core::RimapError>(7) },
            || flag.store(true, Ordering::SeqCst),
        )
        .await
        .expect("dispatch completed inside the ceiling");

        assert_eq!(value, 7);
        assert!(
            !cleaned.load(Ordering::SeqCst),
            "cleanup must not run when the ceiling did not fire",
        );
    }

    /// An inner failure — including a per-stage `ERR_TIMEOUT` that
    /// `with_session` already handled and invalidated for — is returned
    /// verbatim, and does NOT trigger the ceiling's cleanup.
    #[tokio::test]
    async fn inner_error_passes_through_without_cleanup() {
        let cleaned = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&cleaned);
        let err = with_tool_call_ceiling(
            Duration::from_secs(30),
            async {
                Err::<(), _>(rimap_core::RimapError::Imap {
                    code: rimap_core::ErrorCode::Timeout,
                    message: "list timed out".into(),
                    source: None,
                })
            },
            || flag.store(true, Ordering::SeqCst),
        )
        .await
        .expect_err("inner error");

        assert_eq!(err.to_string(), "ERR_TIMEOUT: list timed out");
        assert!(
            !cleaned.load(Ordering::SeqCst),
            "a stage timeout is not a ceiling timeout; with_session already invalidated",
        );
    }

    #[test]
    fn breaker_reason_maps_every_error_code() {
        use rimap_authz::breaker::FailureReason;
        use rimap_core::{ErrorCode, RimapError};

        // The expected classification is a `match` with NO wildcard arm, so a
        // newly added `ErrorCode` fails THIS test build until its breaker
        // classification is declared here — mirroring the no-wildcard intent
        // of the production mapping fn. Service failures trip the breaker;
        // user / policy / internal errors do not.
        fn expected_reason(code: ErrorCode) -> Option<FailureReason> {
            match code {
                ErrorCode::ConnectionLost => Some(FailureReason::ConnectionLost),
                ErrorCode::Auth => Some(FailureReason::Auth),
                ErrorCode::Timeout => Some(FailureReason::Timeout),
                ErrorCode::ImapProtocol | ErrorCode::SmtpProtocol => Some(FailureReason::Protocol),
                ErrorCode::Tls => Some(FailureReason::Tls),
                ErrorCode::InvalidInput
                | ErrorCode::PostureDenied
                | ErrorCode::RateLimited
                | ErrorCode::CircuitOpen
                | ErrorCode::NotFound
                | ErrorCode::AttachmentTooLarge
                | ErrorCode::ProtectedFolder
                | ErrorCode::ExpungeDenied
                | ErrorCode::Config
                | ErrorCode::Internal
                | ErrorCode::NoAccount
                | ErrorCode::UnknownAccount
                | ErrorCode::Cancelled
                | ErrorCode::UidValidityChanged => None,
            }
        }

        // The explicit variant list is also enforced by the no-wildcard match
        // above (a forgotten entry leaves `expected_reason` non-exhaustive),
        // and the length assert below catches a list entry dropped here.
        const ALL: &[ErrorCode] = &[
            ErrorCode::ConnectionLost,
            ErrorCode::Auth,
            ErrorCode::Timeout,
            ErrorCode::ImapProtocol,
            ErrorCode::SmtpProtocol,
            ErrorCode::Tls,
            ErrorCode::InvalidInput,
            ErrorCode::PostureDenied,
            ErrorCode::RateLimited,
            ErrorCode::CircuitOpen,
            ErrorCode::NotFound,
            ErrorCode::AttachmentTooLarge,
            ErrorCode::ProtectedFolder,
            ErrorCode::ExpungeDenied,
            ErrorCode::Config,
            ErrorCode::Internal,
            ErrorCode::NoAccount,
            ErrorCode::UnknownAccount,
            ErrorCode::Cancelled,
            ErrorCode::UidValidityChanged,
        ];

        for &code in ALL {
            let err = RimapError::Imap {
                code,
                message: "x".into(),
                source: None,
            };
            assert_eq!(
                rimap_error_to_breaker_reason(&err),
                expected_reason(code),
                "mapping mismatch for {code:?}",
            );
        }
        assert_eq!(
            ALL.len(),
            20,
            "list must enumerate all variants (6 service + 14 user)"
        );
    }

    #[test]
    fn smtp_errors_are_breaker_neutral() {
        use rimap_core::{ErrorCode, RimapError};

        // SMTP send failures must never trip the per-account (IMAP) breaker,
        // even for codes that trip it from an IMAP error — a wrong SMTP
        // password or a rejected recipient must not deny read-only IMAP tools.
        for code in [
            ErrorCode::Auth,
            ErrorCode::SmtpProtocol,
            ErrorCode::Tls,
            ErrorCode::Timeout,
            ErrorCode::ConnectionLost,
        ] {
            let err = RimapError::Smtp {
                code,
                message: "x".into(),
                source: None,
            };
            assert_eq!(
                rimap_error_to_breaker_reason(&err),
                None,
                "SMTP {code:?} must be breaker-neutral",
            );
        }
    }

    #[test]
    fn posture_context_round_trips_account_and_infrastructure() {
        // `PostureContext::posture` must:
        //   - return `Some(posture)` for the per-account variant
        //     (the audit writer formats this onto the per-call record).
        //   - return `None` for the infrastructure variant (the audit
        //     writer renders `None` as the dedicated
        //     "infrastructure" sentinel on disk).
        //
        // The two cargo-mutants survivors at line 73 (`replace ... ->
        // Option<Posture> with None` and `... with Some(Default::default())`)
        // would collapse one or both branches to the same wrong value.
        use super::PostureContext;
        use rimap_core::Posture;

        assert_eq!(
            PostureContext::Account(Posture::DraftSafe).posture(),
            Some(Posture::DraftSafe),
        );
        assert_eq!(
            PostureContext::Account(Posture::Readonly).posture(),
            Some(Posture::Readonly),
        );
        assert_eq!(PostureContext::Infrastructure.posture(), None);
    }

    #[tokio::test]
    async fn infrastructure_tool_emits_tool_start_and_tool_end() {
        use std::collections::BTreeMap;

        use rimap_audit::{AuditOptions, AuditWriter, Seq};
        use tempfile::TempDir;

        use crate::boot::registry::AccountRegistry;
        use crate::mcp::server::ImapMcpServer;

        let tmp = TempDir::new().expect("tempdir");
        let audit_path = tmp.path().join("audit.jsonl");
        let audit = AuditWriter::open(&AuditOptions {
            path: audit_path.clone(),
            rotate_bytes: 0,
            rotate_keep: 0,
            retention_seconds: None,
            fail_open: false,
            initial_seq: Seq::FIRST,
        })
        .expect("audit open");

        let registry = AccountRegistry::new(BTreeMap::new());
        let (cancellation_sender, _cancellation_rx) = rimap_audit::cancellation_channel();
        let server = ImapMcpServer::new(registry, audit, cancellation_sender);

        // list_accounts needs no args and no IMAP connection.
        let args = serde_json::Map::new();
        let _ = server
            .dispatch_infrastructure(ToolName::ListAccounts, &args)
            .await
            .expect("list_accounts dispatch");

        drop(server);

        let contents = std::fs::read_to_string(&audit_path).expect("read audit log");
        let records: Vec<serde_json::Value> = contents
            .lines()
            .map(|line| serde_json::from_str(line).expect("parse record"))
            .collect();

        let start = records
            .iter()
            .find(|r| r["kind"] == "tool_start" && r["tool"] == "list_accounts")
            .expect("tool_start record");
        let end = records
            .iter()
            .find(|r| r["kind"] == "tool_end" && r["tool"] == "list_accounts")
            .expect("tool_end record");

        assert_eq!(start["seq"], end["start_seq"]);
        assert_eq!(end["status"], "ok");
        assert!(start["account"].is_null());
        assert!(end["account"].is_null());
    }
}
