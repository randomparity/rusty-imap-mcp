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
    pub untrusted: Option<U>,
    /// Structured security observations. Trusted metadata.
    #[serde(skip_serializing_if = "Vec::is_empty")]
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
