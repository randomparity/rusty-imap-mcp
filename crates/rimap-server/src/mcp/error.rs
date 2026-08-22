//! Map `RimapError` to rmcp `ErrorData` for MCP tool error responses.
//!
//! Custom error codes in the JSON-RPC "server error" range
//! (-32000 to -32099):
//! - -32001: posture denied
//! - -32002: server not initialized (pre-initialize request)
//! - -32003: rate limited
//! - -32004: circuit breaker open
//! - -32005: attachment too large

use rimap_core::{ErrorCode, RimapError};
use rmcp::model::{CallToolResult, ContentBlock, ErrorCode as McpCode, ErrorData};

/// Posture denied (tool not allowed by current posture).
pub const POSTURE_DENIED: McpCode = McpCode(-32001);

/// Rate limiter rejected the call.
pub const RATE_LIMITED: McpCode = McpCode(-32003);

/// Circuit breaker is open.
pub const CIRCUIT_OPEN: McpCode = McpCode(-32004);

/// Attachment exceeded size cap.
pub const ATTACHMENT_TOO_LARGE: McpCode = McpCode(-32005);

/// Server has not yet received the MCP `initialize` request. The first
/// message a client sends MUST be `initialize` (or `ping`). Any other
/// pre-initialize request is rejected with this code and a clean
/// session shutdown.
pub const NOT_INITIALIZED: McpCode = McpCode(-32002);

/// Classify a `RimapError` as a tool-execution failure (returned to the
/// client as `CallToolResult { isError: true }`) versus a protocol /
/// routing / infrastructure failure (returned as a JSON-RPC `ErrorData`).
///
/// A tool-execution error means the request was validly routed and the
/// tool ran but failed in a way the agent should read and can act on
/// (missing UID, stale UIDVALIDITY, rate limit, posture / folder
/// denial, IMAP/SMTP/TLS/timeout). Per the MCP spec these belong inside
/// the result. Protocol / routing errors (`InvalidInput` params shape,
/// account selection, server config / bug, cancellation) stay JSON-RPC
/// errors: the framework could not run the tool as requested, or the
/// failure is not agent-recoverable.
///
/// The `match` has no wildcard arm, so a newly added [`ErrorCode`] fails
/// to compile until its channel is declared here. See issue #402.
#[must_use]
pub fn is_tool_execution_error(err: &RimapError) -> bool {
    match err.code() {
        ErrorCode::NotFound
        | ErrorCode::UidValidityChanged
        | ErrorCode::RateLimited
        | ErrorCode::CircuitOpen
        | ErrorCode::AttachmentTooLarge
        | ErrorCode::ImapProtocol
        | ErrorCode::SmtpProtocol
        | ErrorCode::Tls
        | ErrorCode::Auth
        | ErrorCode::ConnectionLost
        | ErrorCode::Timeout
        | ErrorCode::PostureDenied
        | ErrorCode::ProtectedFolder
        | ErrorCode::ExpungeDenied => true,
        ErrorCode::InvalidInput
        | ErrorCode::NoAccount
        | ErrorCode::UnknownAccount
        | ErrorCode::Config
        | ErrorCode::Internal
        | ErrorCode::Cancelled => false,
    }
}

/// The human-readable wire message for `err`, applying the folder-denial
/// opacity: `ProtectedFolder` / `ExpungeDenied` never reveal the folder
/// name or the `protected_folders` / `expunge_folders` field names.
/// Shared by [`to_mcp_error`] and [`to_error_call_result`] so both
/// channels present the same (opaque where applicable) message.
fn wire_message(err: &RimapError) -> String {
    match err.code() {
        ErrorCode::ProtectedFolder | ErrorCode::ExpungeDenied => {
            "operation denied for this folder".to_string()
        }
        _ => err.to_string(),
    }
}

/// The structured `data` payload for the variants that carry typed
/// recovery fields (#303), or `None` for variants with none. Shared by
/// both wire channels so the `error_code` + typed fields are identical
/// whether the failure surfaces as `ErrorData.data` or
/// `CallToolResult.structuredContent`.
fn structured_error_data(err: &RimapError) -> Option<serde_json::Value> {
    match err {
        RimapError::NoAccount { available } => Some(serde_json::json!({
            "error_code": ErrorCode::NoAccount.as_str(),
            "available": available,
            "hint": "call use_account or pass account argument",
        })),
        RimapError::UnknownAccount { name, available } => Some(serde_json::json!({
            "error_code": ErrorCode::UnknownAccount.as_str(),
            "name": name,
            "available": available,
        })),
        RimapError::UidValidityChanged {
            folder,
            expected,
            actual,
            ..
        } => Some(serde_json::json!({
            "error_code": ErrorCode::UidValidityChanged.as_str(),
            "folder": folder,
            "expected": expected,
            "actual": actual,
        })),
        RimapError::RateLimited { retry_after_ms } => Some(serde_json::json!({
            "error_code": ErrorCode::RateLimited.as_str(),
            "retry_after_ms": retry_after_ms,
        })),
        RimapError::CircuitOpen { retry_after_ms } => Some(serde_json::json!({
            "error_code": ErrorCode::CircuitOpen.as_str(),
            "retry_after_ms": retry_after_ms,
        })),
        RimapError::AttachmentTooLarge { kind, limit } => Some(serde_json::json!({
            "error_code": ErrorCode::AttachmentTooLarge.as_str(),
            "kind": kind,
            "limit": limit,
        })),
        _ => None,
    }
}

/// Build a tool-execution error `CallToolResult` (`isError: true`) for
/// `err`: the human-readable `wire_message` as `content` text and the
/// machine-readable `error_code` (+ typed `structured_error_data`) as
/// `structured_content`. Codes with no typed data still carry
/// `{ "error_code": "ERR_…" }` so the agent always has the stable code.
///
/// Used by `run_with_audit_envelope` for errors classified as
/// [`is_tool_execution_error`]. See issue #402.
#[must_use]
pub fn to_error_call_result(err: &RimapError) -> CallToolResult {
    let message = wire_message(err);
    let data = structured_error_data(err)
        .unwrap_or_else(|| serde_json::json!({ "error_code": err.code().as_str() }));
    // `CallToolResult` is `#[non_exhaustive]`; build via the `error`
    // constructor (sets `is_error = Some(true)`) then set the public
    // `structured_content` field.
    let mut result = CallToolResult::error(vec![ContentBlock::text(message)]);
    result.structured_content = Some(data);
    result
}

/// Convert a `RimapError` into an rmcp `ErrorData`.
///
/// Maps each `ErrorCode` variant to the closest JSON-RPC / MCP
/// error code. Application-specific codes use the JSON-RPC
/// "server error" range (-32000 to -32099). Used for protocol /
/// routing failures; tool-execution failures use
/// [`to_error_call_result`] instead (see [`is_tool_execution_error`]).
#[must_use]
pub fn to_mcp_error(err: &RimapError) -> ErrorData {
    let message = wire_message(err);
    let data = structured_error_data(err);
    match err.code() {
        ErrorCode::InvalidInput
        | ErrorCode::NoAccount
        | ErrorCode::UnknownAccount
        | ErrorCode::UidValidityChanged => ErrorData::invalid_params(message, data),

        ErrorCode::NotFound => ErrorData::new(McpCode::RESOURCE_NOT_FOUND, message, data),
        ErrorCode::PostureDenied | ErrorCode::ProtectedFolder | ErrorCode::ExpungeDenied => {
            ErrorData::new(POSTURE_DENIED, message, data)
        }
        ErrorCode::RateLimited => ErrorData::new(RATE_LIMITED, message, data),
        ErrorCode::CircuitOpen => ErrorData::new(CIRCUIT_OPEN, message, data),
        ErrorCode::AttachmentTooLarge => ErrorData::new(ATTACHMENT_TOO_LARGE, message, data),
        ErrorCode::ImapProtocol
        | ErrorCode::SmtpProtocol
        | ErrorCode::Tls
        | ErrorCode::Auth
        | ErrorCode::ConnectionLost
        | ErrorCode::Timeout
        | ErrorCode::Config
        | ErrorCode::Internal
        | ErrorCode::Cancelled => ErrorData::internal_error(message, data),
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "tests")]

    use rimap_core::{ErrorCode, RimapError};
    use rmcp::model::ErrorCode as McpCode;

    use super::to_mcp_error;

    fn authz_error(code: ErrorCode, msg: &str) -> RimapError {
        RimapError::Authz {
            code,
            message: msg.to_owned(),
        }
    }

    #[test]
    fn invalid_input_maps_to_invalid_params() {
        let err = authz_error(ErrorCode::InvalidInput, "bad uid");
        let mcp = to_mcp_error(&err);
        assert_eq!(mcp.code, McpCode::INVALID_PARAMS);
    }

    #[test]
    fn not_found_maps_to_resource_not_found() {
        let err = RimapError::Imap {
            code: ErrorCode::NotFound,
            message: "no such UID".to_owned(),
            source: None,
        };
        let mcp = to_mcp_error(&err);
        assert_eq!(mcp.code, McpCode::RESOURCE_NOT_FOUND);
    }

    #[test]
    fn posture_denied_maps_to_custom_code() {
        let err = authz_error(ErrorCode::PostureDenied, "tool denied");
        let mcp = to_mcp_error(&err);
        assert_eq!(mcp.code, super::POSTURE_DENIED);
    }

    #[test]
    fn internal_errors_map_to_internal_error() {
        let err = RimapError::Internal("bug".to_owned());
        let mcp = to_mcp_error(&err);
        assert_eq!(mcp.code, McpCode::INTERNAL_ERROR);
    }

    #[test]
    fn message_is_preserved() {
        let err = authz_error(ErrorCode::RateLimited, "slow down");
        let mcp = to_mcp_error(&err);
        assert!(mcp.message.contains("slow down"));
    }

    #[test]
    fn not_initialized_code_value() {
        assert_eq!(super::NOT_INITIALIZED, McpCode(-32002));
    }

    #[test]
    fn custom_codes_lie_in_jsonrpc_server_error_range() {
        // JSON-RPC §5.1 reserves -32000 to -32099 for application-defined
        // server errors. The MCP wire contract requires these constants
        // to be negative; the `delete -` cargo-mutants mutations on the
        // numeric literals would flip them to positive values that no
        // client would recognize as server errors. Asserting each
        // constant's exact value pins the negative-range invariant and
        // kills the three `delete -` survivors at lines 18/21/24.
        assert_eq!(super::POSTURE_DENIED, McpCode(-32001));
        assert_eq!(super::NOT_INITIALIZED, McpCode(-32002));
        assert_eq!(super::RATE_LIMITED, McpCode(-32003));
        assert_eq!(super::CIRCUIT_OPEN, McpCode(-32004));
        assert_eq!(super::ATTACHMENT_TOO_LARGE, McpCode(-32005));
    }

    #[test]
    fn protected_folder_uses_opaque_message() {
        let err = authz_error(
            ErrorCode::ProtectedFolder,
            "folder `INBOX` is protected and cannot be deleted",
        );
        let mcp = to_mcp_error(&err);
        assert_eq!(mcp.code, super::POSTURE_DENIED);
        assert!(!mcp.message.contains("INBOX"));
        assert!(!mcp.message.contains("protected_folders"));
        assert_eq!(mcp.message, "operation denied for this folder");
    }

    #[test]
    fn expunge_denied_uses_opaque_message() {
        let err = authz_error(
            ErrorCode::ExpungeDenied,
            "expunge denied for folder `Sent`; add it to expunge_folders",
        );
        let mcp = to_mcp_error(&err);
        assert_eq!(mcp.code, super::POSTURE_DENIED);
        assert!(!mcp.message.contains("Sent"));
        assert!(!mcp.message.contains("expunge_folders"));
        assert_eq!(mcp.message, "operation denied for this folder");
    }

    #[test]
    fn no_account_carries_structured_data() {
        let err = RimapError::NoAccount {
            available: vec!["work".into(), "personal".into()],
        };
        let mcp = to_mcp_error(&err);
        let data = mcp.data.as_ref().expect("data populated");
        let data_value = serde_json::to_value(data).expect("data serializes");
        assert_eq!(data_value["error_code"], "ERR_NO_ACCOUNT");
        assert_eq!(
            data_value["available"],
            serde_json::json!(["work", "personal"]),
        );
        assert!(
            data_value["hint"]
                .as_str()
                .is_some_and(|h| h.contains("use_account")),
            "hint must mention use_account; got {data_value}",
        );
    }

    #[test]
    fn unknown_account_carries_structured_data() {
        let err = RimapError::UnknownAccount {
            name: "missing".into(),
            available: vec!["work".into()],
        };
        let mcp = to_mcp_error(&err);
        let data = mcp.data.as_ref().expect("data populated");
        let data_value = serde_json::to_value(data).expect("data serializes");
        assert_eq!(data_value["error_code"], "ERR_UNKNOWN_ACCOUNT");
        assert_eq!(data_value["name"], "missing");
        assert_eq!(data_value["available"], serde_json::json!(["work"]));
    }

    #[test]
    fn rate_limited_carries_structured_data() {
        let err = RimapError::RateLimited {
            retry_after_ms: 250,
        };
        let mcp = to_mcp_error(&err);
        assert_eq!(mcp.code, super::RATE_LIMITED);
        let data = mcp.data.as_ref().expect("data populated");
        let v = serde_json::to_value(data).expect("data serializes");
        assert_eq!(v["error_code"], "ERR_RATE_LIMITED");
        assert_eq!(v["retry_after_ms"], 250);
    }

    #[test]
    fn circuit_open_carries_structured_data() {
        let err = RimapError::CircuitOpen { retry_after_ms: 0 };
        let mcp = to_mcp_error(&err);
        assert_eq!(mcp.code, super::CIRCUIT_OPEN);
        let data = mcp.data.as_ref().expect("data populated");
        let v = serde_json::to_value(data).expect("data serializes");
        assert_eq!(v["error_code"], "ERR_CIRCUIT_OPEN");
        // 0 is the half-open probe value and must round-trip, not be omitted.
        assert_eq!(v["retry_after_ms"], 0);
    }

    #[test]
    fn attachment_too_large_carries_structured_data() {
        let err = RimapError::AttachmentTooLarge {
            kind: "message_bytes".to_string(),
            limit: 26_214_400,
        };
        let mcp = to_mcp_error(&err);
        assert_eq!(mcp.code, super::ATTACHMENT_TOO_LARGE);
        let data = mcp.data.as_ref().expect("data populated");
        let v = serde_json::to_value(data).expect("data serializes");
        assert_eq!(v["error_code"], "ERR_ATTACHMENT_TOO_LARGE");
        assert_eq!(v["kind"], "message_bytes");
        assert_eq!(v["limit"], 26_214_400);
    }

    #[test]
    fn uid_validity_changed_carries_structured_data() {
        let err = RimapError::UidValidityChanged {
            folder: "INBOX".into(),
            expected: 100,
            actual: 101,
            source: Box::new(std::io::Error::other("test source")),
        };
        let mcp = to_mcp_error(&err);
        let data = mcp.data.as_ref().expect("data populated");
        let data_value = serde_json::to_value(data).expect("data serializes");
        assert_eq!(data_value["error_code"], "ERR_UID_VALIDITY_CHANGED");
        assert_eq!(data_value["folder"], "INBOX");
        assert_eq!(data_value["expected"], 100);
        assert_eq!(data_value["actual"], 101);
    }

    /// Extract the first text content item from a `CallToolResult`.
    fn result_text(result: &rmcp::model::CallToolResult) -> String {
        result
            .content
            .first()
            .and_then(|c| c.as_text().map(|t| t.text.clone()))
            .expect("result must carry text content")
    }

    #[test]
    fn classification_covers_every_error_code_with_no_wildcard() {
        // The expected classification is a `match` with NO wildcard arm,
        // so a newly added `ErrorCode` fails THIS test build until its
        // channel (isError vs protocol) is declared here — mirroring the
        // no-wildcard intent of the production `is_tool_execution_error`.
        fn expected(code: ErrorCode) -> bool {
            match code {
                ErrorCode::NotFound
                | ErrorCode::UidValidityChanged
                | ErrorCode::RateLimited
                | ErrorCode::CircuitOpen
                | ErrorCode::AttachmentTooLarge
                | ErrorCode::ImapProtocol
                | ErrorCode::SmtpProtocol
                | ErrorCode::Tls
                | ErrorCode::Auth
                | ErrorCode::ConnectionLost
                | ErrorCode::Timeout
                | ErrorCode::PostureDenied
                | ErrorCode::ProtectedFolder
                | ErrorCode::ExpungeDenied => true,
                ErrorCode::InvalidInput
                | ErrorCode::NoAccount
                | ErrorCode::UnknownAccount
                | ErrorCode::Config
                | ErrorCode::Internal
                | ErrorCode::Cancelled => false,
            }
        }

        const ALL: &[ErrorCode] = &[
            ErrorCode::InvalidInput,
            ErrorCode::PostureDenied,
            ErrorCode::RateLimited,
            ErrorCode::CircuitOpen,
            ErrorCode::NotFound,
            ErrorCode::ImapProtocol,
            ErrorCode::SmtpProtocol,
            ErrorCode::Tls,
            ErrorCode::Auth,
            ErrorCode::ConnectionLost,
            ErrorCode::Timeout,
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
                super::is_tool_execution_error(&err),
                expected(code),
                "classification mismatch for {code:?}",
            );
        }
        assert_eq!(ALL.len(), 20, "list must enumerate all ErrorCode variants");
    }

    #[test]
    fn not_found_becomes_iserror_result_with_code() {
        let err = RimapError::Imap {
            code: ErrorCode::NotFound,
            message: "no such UID 5 in INBOX".into(),
            source: None,
        };
        assert!(super::is_tool_execution_error(&err));
        let result = super::to_error_call_result(&err);
        assert_eq!(result.is_error, Some(true));
        assert!(
            result_text(&result).contains("no such UID 5 in INBOX"),
            "message text must reach the agent",
        );
        let sc = result
            .structured_content
            .as_ref()
            .expect("structured content populated");
        assert_eq!(sc["error_code"], "ERR_NOT_FOUND");
    }

    #[test]
    fn protected_folder_iserror_result_is_opaque() {
        // Folder-policy denials must not leak the folder name or config
        // field names in the result text; the machine code still travels.
        let err = authz_error(
            ErrorCode::ProtectedFolder,
            "folder `INBOX` is protected; remove it from protected_folders",
        );
        assert!(super::is_tool_execution_error(&err));
        let result = super::to_error_call_result(&err);
        let text = result_text(&result);
        assert_eq!(text, "operation denied for this folder");
        assert!(!text.contains("INBOX"));
        assert!(!text.contains("protected_folders"));
        let sc = result
            .structured_content
            .as_ref()
            .expect("structured content populated");
        assert_eq!(sc["error_code"], "ERR_PROTECTED_FOLDER");
    }

    #[test]
    fn rate_limited_iserror_result_carries_retry_hint() {
        let err = RimapError::RateLimited {
            retry_after_ms: 250,
        };
        let result = super::to_error_call_result(&err);
        assert_eq!(result.is_error, Some(true));
        let sc = result
            .structured_content
            .as_ref()
            .expect("structured content populated");
        assert_eq!(sc["error_code"], "ERR_RATE_LIMITED");
        assert_eq!(sc["retry_after_ms"], 250);
    }

    #[test]
    fn uid_validity_changed_iserror_result_carries_expected_actual() {
        let err = RimapError::UidValidityChanged {
            folder: "INBOX".into(),
            expected: 5,
            actual: 6,
            source: Box::new(std::io::Error::other("test source")),
        };
        let result = super::to_error_call_result(&err);
        assert_eq!(result.is_error, Some(true));
        assert!(result_text(&result).contains("UIDVALIDITY changed"));
        let sc = result
            .structured_content
            .as_ref()
            .expect("structured content populated");
        assert_eq!(sc["error_code"], "ERR_UID_VALIDITY_CHANGED");
        assert_eq!(sc["expected"], 5);
        assert_eq!(sc["actual"], 6);
    }
}
