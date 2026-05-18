//! Pre-initialize request handler.
//!
//! Synthesizes the JSON-RPC error envelope that the MCP server sends
//! when a client violates the lifecycle by issuing any non-`initialize`,
//! non-`ping` request as its first message (#275). The helper is pure:
//! it does no I/O and holds no state. The transport write happens in
//! `main.rs::run`.
//!
//! Notifications and Responses pre-initialize return `None`: per
//! JSON-RPC §4.1 notifications never receive a response, and a
//! standalone Response is malformed (no matching server request).

use rmcp::model::ClientJsonRpcMessage;
use serde_json::json;

use crate::mcp::error::NOT_INITIALIZED;

/// Build the newline-terminated JSON-RPC error line to emit for an
/// offending pre-initialize message. Returns `Some` only for the
/// `Request` variant.
#[must_use]
pub fn synthesize_pre_init_error_envelope(msg: &ClientJsonRpcMessage) -> Option<String> {
    match msg {
        ClientJsonRpcMessage::Request(req) => {
            let id = req.id.clone().into_json_value();
            let envelope = json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": NOT_INITIALIZED.0,
                    "message": "Server not initialized: send `initialize` \
                                before any other request",
                },
            });
            Some(format!("{envelope}\n"))
        }
        ClientJsonRpcMessage::Notification(_)
        | ClientJsonRpcMessage::Response(_)
        | ClientJsonRpcMessage::Error(_) => None,
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "tests")]
    #![expect(clippy::unwrap_used, reason = "tests")]

    use std::sync::Arc;

    use rmcp::model::{
        ClientJsonRpcMessage, ClientNotification, ClientRequest, ClientResult, ErrorData,
        JsonRpcError, JsonRpcNotification, JsonRpcRequest, JsonRpcResponse, JsonRpcVersion2_0,
        ListToolsRequest, NumberOrString, PaginatedRequestParams, ProgressNotification,
        ProgressNotificationParam, ProgressToken,
    };
    use serde_json::{Value, json};

    use super::synthesize_pre_init_error_envelope;

    /// Build a Request variant carrying a `tools/list` request with the
    /// supplied id.
    fn request_msg(id: NumberOrString) -> ClientJsonRpcMessage {
        let list_tools = ListToolsRequest::with_param(PaginatedRequestParams::default());
        ClientJsonRpcMessage::Request(JsonRpcRequest {
            jsonrpc: JsonRpcVersion2_0,
            id,
            request: ClientRequest::ListToolsRequest(list_tools),
        })
    }

    #[test]
    fn request_with_numeric_id_produces_minus_32002_envelope() {
        let msg = request_msg(NumberOrString::Number(42));
        let line = synthesize_pre_init_error_envelope(&msg).expect("Some line");
        assert!(line.ends_with('\n'), "must be newline-terminated");
        let parsed: Value = serde_json::from_str(line.trim_end()).expect("envelope is valid JSON");
        assert_eq!(parsed["jsonrpc"], json!("2.0"));
        assert_eq!(parsed["id"], json!(42));
        assert_eq!(parsed["error"]["code"], json!(-32002));
        assert!(
            parsed["error"]["message"]
                .as_str()
                .unwrap()
                .contains("Server not initialized")
        );
    }

    #[test]
    fn request_with_string_id_preserves_string_id() {
        let msg = request_msg(NumberOrString::String(Arc::from("abc-123")));
        let line = synthesize_pre_init_error_envelope(&msg).expect("Some line");
        let parsed: Value = serde_json::from_str(line.trim_end()).unwrap();
        assert_eq!(parsed["id"], json!("abc-123"));
        assert_eq!(parsed["error"]["code"], json!(-32002));
    }

    #[test]
    fn line_is_single_line_with_one_trailing_newline() {
        let msg = request_msg(NumberOrString::Number(1));
        let line = synthesize_pre_init_error_envelope(&msg).expect("Some line");
        assert_eq!(line.matches('\n').count(), 1, "exactly one newline");
        assert!(line.ends_with('\n'), "newline is trailing");
        assert!(!line.trim_end().contains('\n'), "no embedded newlines");
    }

    #[test]
    fn notification_returns_none() {
        let progress = ProgressNotification::new(ProgressNotificationParam::new(
            ProgressToken(NumberOrString::Number(1)),
            0.0,
        ));
        let msg = ClientJsonRpcMessage::Notification(JsonRpcNotification {
            jsonrpc: JsonRpcVersion2_0,
            notification: ClientNotification::ProgressNotification(progress),
        });
        assert!(synthesize_pre_init_error_envelope(&msg).is_none());
    }

    #[test]
    fn response_returns_none() {
        let msg = ClientJsonRpcMessage::Response(JsonRpcResponse {
            jsonrpc: JsonRpcVersion2_0,
            id: NumberOrString::Number(1),
            result: ClientResult::empty(()),
        });
        assert!(synthesize_pre_init_error_envelope(&msg).is_none());
    }

    #[test]
    fn error_variant_returns_none() {
        let msg = ClientJsonRpcMessage::Error(JsonRpcError {
            jsonrpc: JsonRpcVersion2_0,
            id: NumberOrString::Number(1),
            error: ErrorData::internal_error("synthetic".to_string(), None),
        });
        assert!(synthesize_pre_init_error_envelope(&msg).is_none());
    }
}
