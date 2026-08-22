//! Shared support for `rimap-server` integration tests. Re-exports
//! the wire driver (Phase 1 + Phase 3) and the Dovecot harness
//! (Phase 3 + the legacy `e2e_full_session`).
//!
//! Each integration-test file pulls in the sub-module(s) it needs via
//! `#[path = "../support/<sub>/mod.rs"] mod <sub>;` rather than including
//! this file wholesale, so that each test binary compiles only the code
//! it actually uses and avoids spurious dead-code warnings.

pub mod wire;
// `pub mod dovecot;` will be added when e2e_wire.rs (Task 10/11) needs
// both the wire driver and the Dovecot harness in the same binary.
