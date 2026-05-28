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
        use crate::tools::compose::{create_draft, send_email};
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
            ToolName::CreateDraft => {
                ser(Box::pin(create_draft::handle(account, parse_args(args)?)).await?)?
            }
            ToolName::SendEmail => {
                ser(Box::pin(send_email::handle(account, parse_args(args)?)).await?)?
            }
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
                    | ToolName::SendEmail
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
    use rimap_core::tool::ToolName;

    use super::rimap_error_to_breaker_reason;

    #[test]
    fn breaker_reason_maps_every_error_code() {
        use rimap_authz::breaker::FailureReason;
        use rimap_core::{ErrorCode, RimapError};

        // Pins the SEMANTICS for all 20 current ErrorCode variants (service
        // failures trip, user/policy/internal errors do not). Exhaustiveness
        // is enforced upstream: the mapping fn's own `match` is
        // compile-exhaustive, so a new ErrorCode breaks THAT build and forces
        // a classification decision before this table matters.
        let cases: &[(ErrorCode, Option<FailureReason>)] = &[
            (
                ErrorCode::ConnectionLost,
                Some(FailureReason::ConnectionLost),
            ),
            (ErrorCode::Auth, Some(FailureReason::Auth)),
            (ErrorCode::Timeout, Some(FailureReason::Timeout)),
            (ErrorCode::ImapProtocol, Some(FailureReason::Protocol)),
            (ErrorCode::SmtpProtocol, Some(FailureReason::Protocol)),
            (ErrorCode::Tls, Some(FailureReason::Tls)),
            (ErrorCode::InvalidInput, None),
            (ErrorCode::PostureDenied, None),
            (ErrorCode::RateLimited, None),
            (ErrorCode::CircuitOpen, None),
            (ErrorCode::NotFound, None),
            (ErrorCode::AttachmentTooLarge, None),
            (ErrorCode::ProtectedFolder, None),
            (ErrorCode::ExpungeDenied, None),
            (ErrorCode::Config, None),
            (ErrorCode::Internal, None),
            (ErrorCode::NoAccount, None),
            (ErrorCode::UnknownAccount, None),
            (ErrorCode::Cancelled, None),
            (ErrorCode::UidValidityChanged, None),
        ];

        for (code, expected) in cases {
            let err = RimapError::Imap {
                code: *code,
                message: "x".into(),
                source: None,
            };
            assert_eq!(
                rimap_error_to_breaker_reason(&err),
                *expected,
                "mapping mismatch for {code:?}",
            );
        }
        assert_eq!(
            cases.len(),
            20,
            "table must list all variants (6 service + 14 user)"
        );
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
