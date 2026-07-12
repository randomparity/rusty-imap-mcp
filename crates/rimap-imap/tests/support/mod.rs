//! Test support: scoped tracing capture for skip-warn assertions.
//!
//! The scriptable IMAP fake moved to the shared `rimap-fake-imap` crate
//! (ADR-0008); only `tracing_capture` remains a per-binary include here.
//!
//! Included per-scenario-binary via `mod support;`. The module-level
//! `#![allow(dead_code)]` (the one place the repo permits a bare `#[allow]`,
//! mirroring `tests/integration/support/container.rs:7`) absorbs the
//! per-binary unused-helper warnings under CI's `-D warnings`.
#![allow(dead_code)]

pub mod tracing_capture;
