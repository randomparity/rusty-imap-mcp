//! Response envelope types for MCP tool responses.
//!
//! Every tool returns a JSON object with three top-level fields:
//! `meta` (trusted server metadata), `untrusted` (sanitized email
//! content), and `security_warnings` (structured observations).

use serde::Serialize;

/// Top-level tool response envelope.
///
/// `M` is the trusted metadata shape (must `Serialize`). `U` is the
/// untrusted payload shape (must `Serialize`). Handlers that have no
/// untrusted body should return `ToolResponse<M, ()>` with
/// `untrusted: None`.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct ToolResponse<M: Serialize = serde_json::Value, U: Serialize = serde_json::Value> {
    /// Server-controlled metadata. Trusted.
    pub meta: M,
    /// Sanitized content derived from email data. Untrusted.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(default)]
    pub untrusted: Option<U>,
    /// Structured security observations. Trusted metadata.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[schemars(default)]
    pub security_warnings: Vec<rimap_content::SecurityWarning>,
}

impl<M: Serialize, U: Serialize> ToolResponse<M, U> {
    /// Build a response carrying only trusted metadata.
    ///
    /// Equivalent to the struct literal with `untrusted: None` and an
    /// empty `security_warnings` vec.
    pub fn meta_only(meta: M) -> Self {
        Self {
            meta,
            untrusted: None,
            security_warnings: Vec::new(),
        }
    }

    /// Attach an untrusted payload.
    #[must_use]
    pub fn with_untrusted(mut self, untrusted: U) -> Self {
        self.untrusted = Some(untrusted);
        self
    }

    /// Replace the security warnings vector.
    #[must_use]
    pub fn with_warnings(mut self, warnings: Vec<rimap_content::SecurityWarning>) -> Self {
        self.security_warnings = warnings;
        self
    }

    /// Append a single security warning.
    #[must_use]
    pub fn with_warning(mut self, warning: rimap_content::SecurityWarning) -> Self {
        self.security_warnings.push(warning);
        self
    }
}

/// Build the schemars-derived JSON Schema for a `ToolResponse<M, U>`
/// (or any other schemars-typed wire response). Strips the root
/// `title` so dumped/published schemas don't leak Rust type names.
///
/// This is the SINGLE SOURCE OF TRUTH for the per-tool output
/// envelope. Both runtime publication (`tool_catalog::tool_def_parts`)
/// and the test-support fixture dump (`cli::dump_tool_schemas::tool_envelope`)
/// MUST call this so the dumped fixtures and the published `outputSchema`
/// are byte-identical.
#[must_use]
pub fn envelope_schema<T: schemars::JsonSchema>() -> serde_json::Map<String, serde_json::Value> {
    let schema = schemars::schema_for!(T);
    match serde_json::to_value(schema) {
        Ok(serde_json::Value::Object(mut map)) => {
            map.remove("title");
            map
        }
        _ => serde_json::Map::new(),
    }
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "tests")]
mod schema_tests {
    use super::ToolResponse;

    #[test]
    fn untrusted_is_optional_in_json_schema() {
        // Regression net for the verification-gate concern in the
        // catalog-richness spec (Delta 4): if `untrusted` is in
        // `required`, a future code path returning `meta_only()` for a
        // tool whose outputSchema declared `untrusted` required would
        // fail wire validation.
        let schema = schemars::schema_for!(
            ToolResponse<serde_json::Value, serde_json::Value>
        );
        let value = serde_json::to_value(&schema).expect("schema serializes");
        let required = value
            .get("required")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let required_names: Vec<&str> = required.iter().filter_map(|v| v.as_str()).collect();
        assert!(
            !required_names.contains(&"untrusted"),
            "untrusted must not be in required; got {required_names:?}",
        );
    }

    #[test]
    fn security_warnings_is_optional_in_json_schema() {
        // Mirror of `untrusted_is_optional_in_json_schema`: the field carries
        // `skip_serializing_if = "Vec::is_empty"` so it's absent from the wire
        // when no warnings are present. Without `#[schemars(default)]`, schemars
        // would put it in `required` and the wire validator would reject every
        // tool response that omits it.
        let schema = schemars::schema_for!(
            ToolResponse<serde_json::Value, serde_json::Value>
        );
        let value = serde_json::to_value(&schema).expect("schema serializes");
        let required = value
            .get("required")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let required_names: Vec<&str> = required.iter().filter_map(|v| v.as_str()).collect();
        assert!(
            !required_names.contains(&"security_warnings"),
            "security_warnings must not be in required; got {required_names:?}",
        );
    }
}
