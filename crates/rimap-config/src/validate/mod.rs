//! Config validation. Runs as a separate pass after `loader::load_from_path`.
//!
//! Checks (per design spec §4 "Config validation at startup"):
//!   - Posture is a known value (enforced by enum parsing — trivially true).
//!   - Every override tool name is a known v1 tool.
//!   - TLS fingerprint parses as 32 hex bytes.
//!   - Audit directory exists and is writable (parent dir of `audit.path`).
//!   - Attachment download dir, if non-empty, is writable.
//!   - All numeric limits are positive and cap/default invariants hold.
//!   - `[imap]`/`[smtp]` timeouts are positive (a zero budget makes every
//!     connect or command time out instantly — see #593).
//!
//! Submodules group helpers by concern (all private):
//!   - `compose`  — multi-account composition pipeline and per-account
//!     orchestration (the `ValidatedAccountConfig` / `ValidatedMultiConfig`
//!     types and the public `validate_multi` / `validate_legacy_as_multi`
//!     entry points)
//!   - `identity` — username and TLS fingerprint
//!   - `limits`   — numeric-limits zero/cap checks and `[imap]`/`[smtp]`
//!     timeout zero checks
//!   - `paths`    — audit and download-dir filesystem probes
//!   - `rules`    — folder safety, SMTP requirement and encryption,
//!     per-tool override resolution

mod compose;
mod identity;
mod limits;
mod paths;
mod rules;

pub use compose::{
    ValidatedAccountConfig, ValidatedMultiConfig, validate_legacy_as_multi, validate_multi,
};

#[cfg(feature = "test-support")]
pub use compose::validate_multi_allowing_empty;
