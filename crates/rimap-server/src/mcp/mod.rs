//! MCP runtime: server handler, response/error types, content parsing.

pub(crate) mod audit_envelope;
pub mod content;
pub(crate) mod dispatch;
pub mod error;
pub mod preinit;
pub mod response;
pub(crate) mod result_provenance;
pub mod server;
// `tool_catalog` is in-crate only: production callers route through
// `dispatch` and `server`. `TOOL_DEFS` is re-exported below under
// `test-support` so the binary's `dump-tool-catalog` subcommand (#264)
// can reach it without widening the module's surface for production.
pub(crate) mod tool_catalog;

/// Re-export of the static tool catalog for the binary's test-support
/// `dump-tool-catalog` subcommand (#264). Gated to keep `TOOL_DEFS` out
/// of the production library surface, mirroring `execute_tool_for_test`
/// in [`server`].
#[cfg(any(test, feature = "test-support"))]
pub use tool_catalog::TOOL_DEFS;
pub(crate) mod tool_name;
pub mod wire_validator;

// Feature-gated: see `crates/rimap-server/Cargo.toml` `fuzzing` and
// `crates/rimap-server/src/mcp/fuzz_oracle.rs` for the contract.
// Production builds (default features) do not see this module.
#[cfg(feature = "fuzzing")]
pub mod fuzz_oracle;

/// Render a `tokio::task::JoinError` from `spawn_blocking` as
/// `RimapError::InternalSourced`. Shared by every `mcp/*` async wrapper so
/// panics in the blocking threadpool always surface with the same code
/// and message prefix — infrastructure failure, not user input. The
/// original `JoinError` is preserved via the `#[source]` chain so
/// tracing subscribers can walk to the underlying panic payload.
pub(crate) fn spawn_blocking_panic_error(err: tokio::task::JoinError) -> rimap_core::RimapError {
    rimap_core::RimapError::InternalSourced {
        message: "spawn_blocking panicked".to_string(),
        source: Box::new(err),
    }
}
