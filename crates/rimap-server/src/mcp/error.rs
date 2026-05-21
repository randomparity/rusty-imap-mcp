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
use rmcp::model::{ErrorCode as McpCode, ErrorData};

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

/// Convert a `RimapError` into an rmcp `ErrorData`.
///
/// Maps each `ErrorCode` variant to the closest JSON-RPC / MCP
/// error code. Application-specific codes use the JSON-RPC
/// "server error" range (-32000 to -32099).
#[must_use]
pub fn to_mcp_error(err: &RimapError) -> ErrorData {
    let message = err.to_string();

    // Variants with structured data: build `data` from typed fields
    // and short-circuit so the generic `code()`-based mapping below
    // doesn't lose the data argument.
    match err {
        RimapError::NoAccount { available } => {
            let data = serde_json::json!({
                "error_code": ErrorCode::NoAccount.as_str(),
                "available": available,
                "hint": "call use_account or pass account argument",
            });
            return ErrorData::invalid_params(message, Some(data));
        }
        RimapError::UnknownAccount { name, available } => {
            let data = serde_json::json!({
                "error_code": ErrorCode::UnknownAccount.as_str(),
                "name": name,
                "available": available,
            });
            return ErrorData::invalid_params(message, Some(data));
        }
        RimapError::UidValidityChanged {
            folder,
            expected,
            actual,
            ..
        } => {
            let data = serde_json::json!({
                "error_code": ErrorCode::UidValidityChanged.as_str(),
                "folder": folder,
                "expected": expected,
                "actual": actual,
            });
            return ErrorData::invalid_params(message, Some(data));
        }
        _ => {}
    }

    // Existing code-based dispatch for non-structured variants. The
    // `NoAccount` / `UnknownAccount` / `UidValidityChanged` arms below
    // are defensive: the dedicated `RimapError` variants are short-
    // circuited above with structured data, so these only fire if a
    // future `RimapError::Authz { code: ErrorCode::NoAccount, .. }`
    // (or similar) is ever constructed by accident — they produce a
    // correct but data-less response rather than a wrong code.
    match err.code() {
        ErrorCode::InvalidInput
        | ErrorCode::NoAccount
        | ErrorCode::UnknownAccount
        | ErrorCode::UidValidityChanged => ErrorData::invalid_params(message, None),

        ErrorCode::NotFound => ErrorData::new(McpCode::RESOURCE_NOT_FOUND, message, None),
        ErrorCode::PostureDenied => ErrorData::new(POSTURE_DENIED, message, None),
        ErrorCode::ProtectedFolder | ErrorCode::ExpungeDenied => ErrorData::new(
            POSTURE_DENIED,
            "operation denied for this folder".to_string(),
            None,
        ),
        ErrorCode::RateLimited => ErrorData::new(RATE_LIMITED, message, None),
        ErrorCode::CircuitOpen => ErrorData::new(CIRCUIT_OPEN, message, None),
        ErrorCode::AttachmentTooLarge => ErrorData::new(ATTACHMENT_TOO_LARGE, message, None),
        ErrorCode::ImapProtocol
        | ErrorCode::SmtpProtocol
        | ErrorCode::Tls
        | ErrorCode::Auth
        | ErrorCode::ConnectionLost
        | ErrorCode::Timeout
        | ErrorCode::Config
        | ErrorCode::Internal
        | ErrorCode::Cancelled => ErrorData::internal_error(message, None),
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
}
