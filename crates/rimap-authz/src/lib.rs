//! Posture-based authorization, rate limiting, and circuit breaker for rusty-imap-mcp.

#![deny(missing_docs)]

pub mod breaker;
pub mod error;
pub mod folder_guard;
pub mod folder_name;
pub mod guard;
pub mod matrix;
pub mod rate_limit;

pub use crate::breaker::{
    BreakerConfig, CircuitBreaker, Clock, FailureReason, ManualClock, State, SystemClock,
};
pub use crate::error::AuthzError;
pub use crate::folder_guard::{FolderGuard, normalize_folder_name};
pub use crate::guard::DispatchGuard;
pub use crate::matrix::EffectiveMatrix;
pub use crate::rate_limit::Governor;
