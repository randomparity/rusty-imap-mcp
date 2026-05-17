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
}
