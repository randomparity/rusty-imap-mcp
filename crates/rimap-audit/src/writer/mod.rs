//! Exclusively-locked, append-only JSONL writer. See design spec §10 "File
//! handling & locking".
//!
//! ## Invariants
//! - One `AuditWriter` holds `LOCK_EX` on its active file for its entire
//!   lifetime. The lock is released implicitly on drop (OS cleanup — no
//!   explicit `unlock()` call required).
//! - `try_lock` is non-blocking; a second writer against the same
//!   path fails immediately with [`AuditError::Locked`].
//! - Per-record writes go through a buffered writer, flushed after each
//!   record. `fsync` is only issued on `process_*` / `auth` records
//!   (Task 16 wires that).

mod core;
pub(crate) mod emit;
pub(crate) mod log;
pub(crate) mod provenance;
pub(crate) mod rotation;
pub(crate) mod self_check;

pub use core::{AuditOptions, AuditWriter};
pub(crate) use core::{Inner, set_file_mode_0600};
pub use log::{ProcessStartInputs, ToolEndInputs, ToolStartInputs};
