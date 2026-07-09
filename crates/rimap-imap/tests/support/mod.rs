//! Test support: in-process scriptable adversarial IMAP fake.
//!
//! Included per-scenario-binary via `mod support;`. The module-level
//! `#![allow(dead_code)]` (the one place the repo permits a bare `#[allow]`,
//! mirroring `tests/integration/support/container.rs:7`) absorbs the
//! per-binary unused-helper warnings under CI's `-D warnings`.
#![allow(dead_code)]

pub mod certs;
pub mod fake_imap;
pub mod tracing_capture;
