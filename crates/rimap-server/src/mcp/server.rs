//! MCP server struct and `ServerHandler` implementation.
//!
//! `ImapMcpServer` owns an `AccountRegistry` (per-account IMAP/SMTP
//! connections, guards, and the attachment download sandbox) and an
//! audit writer. The `ServerHandler` trait wires `list_tools`
//! (posture-filtered union across accounts) and `call_tool` (account
//! resolution + dispatch pipeline).

use std::str::FromStr;
use std::sync::Arc;

use rimap_audit::AuditWriter;
use rimap_audit::CancelledToolEndSender;
use rimap_audit::redact::RedactionSalt;
use rimap_core::account::AccountId;
use rimap_core::tool::ToolName;
use rmcp::RoleServer;
use rmcp::handler::server::ServerHandler;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, ErrorCode as McpCode, ErrorData, Implementation,
    InitializeRequestParams, InitializeResult, ListResourcesResult, ListToolsResult,
    PaginatedRequestParams, ProtocolVersion, RawResource, ReadResourceRequestParams,
    ReadResourceResult, Resource, ResourceContents, ServerCapabilities, ServerInfo, Tool,
};
use rmcp::service::RequestContext;

use crate::boot::registry::{AccountRegistry, AccountState};
use crate::mcp::dispatch::{PostureContext, rimap_error_to_breaker_reason};
use crate::mcp::tool_catalog::TOOL_DEFS;
use crate::mcp::tool_name::{
    is_bare_simple_tool_name, is_legacy_single_account, refine_tool_name, split_tool_name,
};

/// Core MCP server. Owns every resource the handler methods need.
pub struct ImapMcpServer {
    /// Account registry holding per-account state.
    #[doc(hidden)]
    pub registry: AccountRegistry,
    /// Append-only audit writer.
    pub(crate) audit: AuditWriter,
    /// Channel used by `AuditEnvelopeGuard::drop` to emit synthetic
    /// cancellation `tool_end` records when the MCP dispatch future is
    /// dropped mid-call (#71, #99).
    pub(crate) cancellation_sender: CancelledToolEndSender,
    /// Per-process salt used when applying `Redactor` to tool arguments.
    /// Wrapped in `Arc` so `spawn_blocking` closures can cheaply capture it.
    pub(crate) redaction_salt: Arc<RedactionSalt>,
}

impl ImapMcpServer {
    /// Construct a new server. Builds the per-process redaction salt;
    /// per-tool schemas are dispatched on demand via
    /// [`rimap_audit::redact::ToolRedactionSchema::redaction_schema`].
    #[must_use]
    pub fn new(
        registry: AccountRegistry,
        audit: AuditWriter,
        cancellation_sender: CancelledToolEndSender,
    ) -> Self {
        Self {
            registry,
            audit,
            cancellation_sender,
            redaction_salt: Arc::new(RedactionSalt::new_random()),
        }
    }

    /// Run an account-scoped tool through the full dispatch pipeline:
    /// posture header + breaker / rate-limit guard + audit envelope +
    /// handler. Returns the MCP-shaped `CallToolResult`.
    ///
    /// Single source of truth for the account-scoped dispatch
    /// composition. Used by the real [`ServerHandler::call_tool`] trait
    /// method and by `execute_tool_for_test`, so the two paths cannot
    /// drift.
    pub(crate) async fn dispatch_account_scoped(
        &self,
        account: &AccountState,
        tool: ToolName,
        args: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<CallToolResult, ErrorData> {
        // Legacy single-account `"default"` records `None`; multi-account
        // records the account name.
        let audit_account: Option<String> =
            if account.id.as_str() == rimap_core::account::DEFAULT_ACCOUNT_NAME {
                None
            } else {
                Some(account.id.as_str().to_string())
            };
        let posture = PostureContext::Account(account.guard.matrix().posture());

        self.run_with_audit_envelope(tool, audit_account, posture, args, |ticket| async move {
            account.guard.pre_dispatch(tool)?;
            let result = Box::pin(self.dispatch_tool(ticket, account, tool, args)).await;
            match &result {
                Ok(_) => account.guard.on_success(),
                Err(e) => {
                    if let Some(reason) = rimap_error_to_breaker_reason(e) {
                        account.guard.on_failure(reason);
                    }
                }
            }
            result
        })
        .await
    }
}

/// In-crate unit-test constructor. Compiled only under `cfg(test)` so it
/// never ships in the released binary. Builds an `ImapMcpServer` with an
/// empty `AccountRegistry` and the caller-supplied audit writer +
/// cancellation sender — the minimum surface needed to drive
/// [`ImapMcpServer::run_with_audit_envelope`] (which reads only `audit`,
/// `redaction_salt`, and `cancellation_sender`) without the heavyweight
/// boot machinery that real `ImapMcpServer::new` requires.
#[cfg(test)]
impl ImapMcpServer {
    /// Minimal test constructor — only fields touched by
    /// `run_with_audit_envelope` (and its inner callees `redact_tool_args`,
    /// `emit_tool_start`, `emit_tool_end`) get caller-supplied values.
    /// The `AccountRegistry` is empty; tool dispatch through this server
    /// will fail at account resolution, which is fine because the
    /// wrapper-level test injects its own body closure and never reaches
    /// dispatch.
    pub(crate) fn new_for_tests(
        audit: AuditWriter,
        cancellation_sender: CancelledToolEndSender,
    ) -> Self {
        Self {
            registry: AccountRegistry::new(std::collections::BTreeMap::new()),
            audit,
            cancellation_sender,
            redaction_salt: Arc::new(RedactionSalt::new_random()),
        }
    }
}

/// Integration-test entry point. Exposed under `#[cfg(any(test, feature =
/// "test-support"))]` so tests exercise the exact same pipeline (account
/// resolve → `pre_dispatch` → audit envelope → `dispatch_tool`) as real
/// MCP clients, instead of re-implementing the composition and drifting
/// from the production path. Production builds without the feature
/// cannot see this method, and `dispatch_tool` itself is `pub(crate)`.
#[cfg(any(test, feature = "test-support"))]
impl ImapMcpServer {
    /// Execute `tool` through the full dispatch pipeline. Mirrors
    /// [`ServerHandler::call_tool`] but takes a pre-parsed `ToolName`
    /// and a raw JSON args value; returns the handler's JSON body
    /// (the `structured_content` of the MCP `CallToolResult`).
    ///
    /// # Errors
    ///
    /// Any pipeline failure — unknown account, posture denial, rate
    /// limit, breaker open, handler error — is returned as a
    /// [`rimap_core::RimapError`] (the MCP `ErrorData` shape is
    /// bridged back).
    pub async fn execute_tool_for_test(
        &self,
        account_name: Option<&str>,
        tool: ToolName,
        args: serde_json::Value,
    ) -> Result<serde_json::Value, rimap_core::RimapError> {
        if account_name.is_some() && tool.is_infrastructure() {
            return Err(rimap_core::RimapError::invalid_input(
                "execute_tool_for_test: account_name must be None for infrastructure tools",
            ));
        }

        let args_map = match args {
            serde_json::Value::Object(m) => m,
            serde_json::Value::Null => serde_json::Map::new(),
            other => {
                return Err(rimap_core::RimapError::invalid_input(format!(
                    "execute_tool_for_test expects a JSON object or null, got {other}"
                )));
            }
        };

        let call_tool_result = if tool.is_infrastructure() {
            Box::pin(self.dispatch_infrastructure(tool, &args_map))
                .await
                .map_err(|e| error_data_to_rimap_error(&e))?
        } else {
            let account = self.registry.resolve(account_name)?;
            Box::pin(self.dispatch_account_scoped(account, tool, &args_map))
                .await
                .map_err(|e| error_data_to_rimap_error(&e))?
        };

        Ok(extract_json_from_call_tool_result(call_tool_result))
    }

    /// Drive `run_with_audit_envelope` with a caller-supplied async
    /// factory. The factory receives no ticket (infrastructure posture,
    /// no account) and returns a future that can suspend at will.
    ///
    /// Used in integration tests that need a body that actually yields
    /// at an `.await` point — e.g. to verify the `AuditEnvelopeGuard`
    /// fires when the dispatch future is aborted mid-body. Real tool
    /// handlers complete synchronously so the abort never lands mid-body;
    /// this method lets the test inject a never-resolving body instead.
    pub async fn run_envelope_with_body_for_test<Fut>(
        &self,
        tool: ToolName,
        body_fut: Fut,
    ) -> Result<CallToolResult, ErrorData>
    where
        Fut: std::future::Future<Output = Result<serde_json::Value, rimap_core::RimapError>>,
    {
        debug_assert!(
            tool.is_infrastructure(),
            "run_envelope_with_body_for_test only supports infrastructure tools; \
             use execute_tool_for_test for account-scoped tools"
        );
        let args = serde_json::Map::new();
        self.run_with_audit_envelope(
            tool,
            None,
            crate::mcp::dispatch::PostureContext::Infrastructure,
            &args,
            |_ticket| body_fut,
        )
        .await
    }
}

/// Extract the structured JSON body from a [`CallToolResult`]. Prefers
/// the `structured_content` field (populated by `CallToolResult::structured`),
/// falling back to parsing the first text content item. Returns
/// `serde_json::Value::Null` when neither is available.
#[cfg(any(test, feature = "test-support"))]
fn extract_json_from_call_tool_result(result: CallToolResult) -> serde_json::Value {
    if let Some(value) = result.structured_content {
        return value;
    }
    result
        .content
        .into_iter()
        .next()
        .and_then(|content| content.as_text().map(|t| t.text.clone()))
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or(serde_json::Value::Null)
}

/// Bridge an MCP `ErrorData` back to a `RimapError` for the test
/// helper's uniform `Result<_, RimapError>` surface. The original
/// message is preserved; the JSON-RPC / MCP code is surfaced as a
/// prefix so test assertions can still match on it.
#[cfg(any(test, feature = "test-support"))]
fn error_data_to_rimap_error(err: &ErrorData) -> rimap_core::RimapError {
    rimap_core::RimapError::Internal(format!("mcp error {}: {}", err.code.0, err.message))
}

impl ServerHandler for ImapMcpServer {
    fn get_info(&self) -> ServerInfo {
        // Spec-strict MCP clients refuse to call `tools/list` unless the
        // server's `initialize` response advertises a `tools` capability.
        // `ServerCapabilities::default()` is all-`None`, so without this
        // declaration the wire payload is `"capabilities": {}` and such
        // clients report "no tools found." `tool_list_changed` matches the
        // existing `notifications/tools/list_changed` emission after
        // `use_account` (see `call_tool` below). `resources` advertises the
        // `list_resources`/`read_resource` surface implemented in this file.
        let capabilities = ServerCapabilities::builder()
            .enable_tools()
            .enable_tool_list_changed()
            .enable_resources()
            .build();
        ServerInfo::new(capabilities).with_server_info(Implementation::new(
            "rusty-imap-mcp",
            rimap_core::version::version(),
        ))
    }

    async fn initialize(
        &self,
        request: InitializeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<InitializeResult, ErrorData> {
        // LATEST-only acceptance per spec §"Why LATEST-only" (#276):
        // rmcp 1.5 emits LATEST wire shapes regardless of negotiated
        // version, so accepting older known versions would echo the
        // peer's version string while serving 2025-11-25 capabilities.
        // The exact-equality check is the only honest option.
        if request.protocol_version != ProtocolVersion::LATEST {
            return Err(unsupported_protocol_version_error(
                &request.protocol_version,
            ));
        }
        // Preserve the default-impl behavior for the happy path so the
        // peer's ClientInfo is captured for subsequent dispatch.
        if context.peer.peer_info().is_none() {
            context.peer.set_peer_info(request);
        }
        Ok(self.get_info())
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let mut tools: Vec<Tool> = Vec::new();

        // Infrastructure tools — always advertised, never namespaced.
        for name in [ToolName::UseAccount, ToolName::ListAccounts] {
            if let Some(def) = TOOL_DEFS.get(&name) {
                tools.push(def.clone());
            }
        }

        let accounts = self.registry.accounts();
        let use_bare_names = is_legacy_single_account(accounts);

        for (id, state) in accounts {
            for &tn in &state.guard.matrix().advertised() {
                let Some(base_def) = TOOL_DEFS.get(&tn) else {
                    continue;
                };
                let tool_name = if use_bare_names {
                    base_def.name.clone()
                } else {
                    format!("{}.{}", id.as_str(), base_def.name).into()
                };
                let description = if use_bare_names {
                    base_def.description.clone()
                } else {
                    Some(
                        format!(
                            "[account: {}, posture: {}] {}",
                            id.as_str(),
                            state.guard.matrix().posture().as_str(),
                            base_def.description.as_deref().unwrap_or(""),
                        )
                        .into(),
                    )
                };
                let mut def = base_def.clone();
                def.name = tool_name;
                def.description = description;
                tools.push(def);
            }
        }

        Ok(ListToolsResult::with_all_items(tools))
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        let resources: Vec<Resource> = self
            .registry
            .accounts()
            .values()
            .map(|state| {
                let name = state.id.as_str();
                let desc = format!(
                    "IMAP account: {} on {}",
                    state.imap.username(),
                    state.imap.host(),
                );
                Resource {
                    raw: RawResource::new(format!("rimap://accounts/{name}"), name)
                        .with_description(desc)
                        .with_mime_type("application/json"),
                    annotations: None,
                }
            })
            .collect();
        Ok(ListResourcesResult::with_all_items(resources))
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResult, ErrorData> {
        let uri = &request.uri;
        let account_name = uri.strip_prefix("rimap://accounts/").ok_or_else(|| {
            ErrorData::new(
                McpCode::INVALID_PARAMS,
                format!("unsupported resource URI: {uri}"),
                None,
            )
        })?;

        // Validate the account name before using it in a lookup or
        // echoing it back in any error. Do not reflect the raw input.
        AccountId::new(account_name).map_err(|_| {
            ErrorData::new(
                McpCode::RESOURCE_NOT_FOUND,
                "invalid account name in resource URI".to_string(),
                None,
            )
        })?;

        let state = self
            .registry
            .resolve(Some(account_name))
            .map_err(|e| crate::mcp::error::to_mcp_error(&e))?;

        let available_tools: Vec<String> = state
            .guard
            .matrix()
            .advertised()
            .iter()
            .filter_map(|tn| TOOL_DEFS.get(tn).map(|d| d.name.to_string()))
            .collect();

        let metadata = serde_json::json!({
            "name": account_name,
            "imap_host": state.imap.host(),
            "smtp_configured": state.smtp.is_some(),
            "available_tools": available_tools,
        });

        let text = serde_json::to_string_pretty(&metadata)
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;

        let contents =
            ResourceContents::text(text, uri.as_str()).with_mime_type("application/json");

        Ok(ReadResourceResult::new(vec![contents]))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let (namespaced_account, bare_name) = split_tool_name(&request.name);

        let tool_name = ToolName::from_str(bare_name)
            .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
        // Refine the tool name based on argument shape BEFORE DispatchGuard::pre_dispatch
        // so the posture check covers sub-capabilities (FetchMessageHtml vs
        // FetchMessage, SearchAdvanced vs Search) at a single seam rather
        // than being re-checked inside every handler.
        let tool_name = refine_tool_name(tool_name, request.arguments.as_ref());

        // Reject tools that have no definition (not yet implemented).
        // This prevents unimplemented v2 tools from consuming rate
        // limiter tokens and producing misleading INTERNAL_ERROR.
        if TOOL_DEFS.get(&tool_name).is_none() {
            return Err(ErrorData::new(
                McpCode::RESOURCE_NOT_FOUND,
                format!("tool `{}` is not available", request.name),
                None,
            ));
        }

        // Multi-account contract: bare simple tool names are only valid
        // in legacy single-account mode. In multi-account mode, clients
        // must use the advertised <account>.<tool> form. Sub-capability
        // dotted tools (e.g. search.advanced_query) and infrastructure
        // tools (use_account, list_accounts) remain valid bare forms
        // regardless. (#73)
        let accounts = self.registry.accounts();
        if !is_legacy_single_account(accounts) && is_bare_simple_tool_name(&request.name) {
            return Err(ErrorData::invalid_params(
                format!(
                    "tool name must be namespaced in multi-account mode: \
                     <account>.{}",
                    &request.name,
                ),
                None,
            ));
        }

        let mut args = request.arguments.unwrap_or_default();

        // Infrastructure tools bypass account resolution and guards and
        // must never be namespaced.
        if tool_name.is_infrastructure() {
            if namespaced_account.is_some() {
                return Err(ErrorData::invalid_params(
                    "infrastructure tools cannot be namespaced".to_string(),
                    None,
                ));
            }
            let result = Box::pin(self.dispatch_infrastructure(tool_name, &args)).await;
            // After a successful use_account, notify subscribed clients that
            // the effective tool list has changed (the session default account
            // flipped). Best-effort: transport failures do not fail the call
            // because use_account itself succeeded. (#80)
            if result.is_ok()
                && tool_name == ToolName::UseAccount
                && let Err(e) = context.peer.notify_tool_list_changed().await
            {
                tracing::warn!(
                    error = %e,
                    "failed to emit notifications/tools/list_changed after use_account",
                );
            }
            return result;
        }

        // Account resolution order: URI namespace > args["account"] >
        // session default > auto-select.
        let explicit_account = namespaced_account.map(String::from).or_else(|| {
            args.remove("account")
                .and_then(|v| v.as_str().map(String::from))
        });

        let account = self
            .registry
            .resolve(explicit_account.as_deref())
            .map_err(|e| crate::mcp::error::to_mcp_error(&e))?;

        self.dispatch_account_scoped(account, tool_name, &args)
            .await
    }
}

/// Build the `ErrorData` payload returned by `ImapMcpServer::initialize`
/// when the peer's `protocolVersion` is not exactly
/// `ProtocolVersion::LATEST`. The envelope's `data` field carries
/// `supported_versions` as a single-element array so clients have a
/// machine-readable retry hint, and the message echoes the offending
/// version in single quotes for log readability. (#276)
fn unsupported_protocol_version_error(peer_version: &ProtocolVersion) -> ErrorData {
    let supported = [ProtocolVersion::LATEST.as_str()];
    let message = format!(
        "Unsupported protocol version: '{}'. Server supports: {}.",
        peer_version.as_str(),
        supported.join(", "),
    );
    let data = serde_json::json!({ "supported_versions": supported });
    ErrorData::invalid_params(message, Some(data))
}

#[cfg(test)]
mod protocol_version_tests {
    #![expect(clippy::expect_used, reason = "tests")]

    use rmcp::model::{ErrorCode as McpCode, ProtocolVersion};
    use serde_json::json;

    use super::unsupported_protocol_version_error;

    /// Build a `ProtocolVersion` carrying an arbitrary version string.
    /// The rmcp deserializer accepts any string and produces a
    /// `ProtocolVersion(Cow::Owned(s))` for unknown values, so this is
    /// the cleanest way to construct one for tests.
    fn version_from_str(s: &str) -> ProtocolVersion {
        serde_json::from_value(json!(s)).expect("deserialize ProtocolVersion")
    }

    #[test]
    fn shape_matches_spec() {
        let v = version_from_str("1999-01-01");
        let err = unsupported_protocol_version_error(&v);

        assert_eq!(err.code, McpCode::INVALID_PARAMS);
        assert!(
            err.message.contains("1999-01-01"),
            "message must echo the peer version, got {:?}",
            err.message,
        );
        assert!(
            err.message.contains("2025-11-25"),
            "message must include the supported version, got {:?}",
            err.message,
        );

        let data = err.data.as_ref().expect("data field present");
        assert_eq!(
            data["supported_versions"],
            json!(["2025-11-25"]),
            "supported_versions must be a single-element array of LATEST, got {data}",
        );
    }

    #[test]
    fn uses_runtime_latest() {
        // Pins the contract that `supported_versions[0]` is built from
        // `ProtocolVersion::LATEST.as_str()` at runtime, not a hard-
        // coded literal. If a future rmcp bump shifts LATEST, this
        // test stays green; the literal-pinning `shape_matches_spec`
        // test will then surface the change visibly.
        let v = version_from_str("anything-goes");
        let err = unsupported_protocol_version_error(&v);
        let data = err.data.as_ref().expect("data field present");
        let arr = data["supported_versions"]
            .as_array()
            .expect("supported_versions is an array");
        assert_eq!(arr.len(), 1, "single-element array");
        assert_eq!(
            arr[0].as_str().expect("string"),
            ProtocolVersion::LATEST.as_str(),
        );
    }

    #[test]
    fn empty_peer_version_still_produces_envelope() {
        let v = version_from_str("");
        let err = unsupported_protocol_version_error(&v);
        assert_eq!(err.code, McpCode::INVALID_PARAMS);
        // Single-quoted empty string in the message: "...'%s'..."
        assert!(
            err.message.contains("''"),
            "empty peer version should appear as '' in message, got {:?}",
            err.message,
        );
    }

    #[test]
    fn data_field_is_present() {
        // Guards against accidentally constructing the error without
        // the data payload (would break machine-readable retry).
        let v = version_from_str("1999-01-01");
        let err = unsupported_protocol_version_error(&v);
        assert!(err.data.is_some(), "data field must be present");
    }
}
