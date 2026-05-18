//! Wire driver and MCP spec schema validators shared by Phase 1
//! (`mcp_wire_conformance.rs`) and Phase 3 (`e2e_wire.rs`).
//!
//! Only items imported by `mcp_wire_conformance.rs` are re-exported
//! here. `e2e_wire.rs` imports directly from the sub-modules
//! (`wire::config::build_dovecot_config`, `wire::schema::assert_envelope_valid`,
//! etc.) to avoid `unused_imports` warnings on re-exports that one
//! binary uses and the other does not — `clippy::allow_attributes`
//! is denied workspace-wide, and `#[expect(unused_imports)]` cannot
//! satisfy both per-binary lint states at once.

pub mod config;
pub mod harness;
pub mod schema;

pub use harness::{Harness, PINNED_PROTOCOL_VERSION};
pub use schema::assert_valid;

/// Suppress per-binary unused-import warnings on re-exports consumed by some
/// but not all integration-test binaries. `mcp_wire_conformance.rs` imports
/// `Harness`, `PINNED_PROTOCOL_VERSION`, and `assert_valid` via these re-exports;
/// `mcp_wire_negative.rs` imports from sub-modules directly and does not consume
/// these re-exports. Referencing the items here marks them as used in every
/// binary compilation.
///
/// Mirrors the pattern in `schema.rs` and `harness.rs`.
#[expect(
    dead_code,
    reason = "type-link to suppress per-binary unused-import warnings"
)]
fn force_use_of_re_exports() {
    let _ = std::mem::size_of::<Harness>();
    let _ = PINNED_PROTOCOL_VERSION;
    let _ = assert_valid as fn(_, _);
}
