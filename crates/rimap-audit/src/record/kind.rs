//! Canonical on-disk `kind` discriminators for [`Payload`](super::Payload)
//! records.
//!
//! One home for the strings so the writer's self-check, the reader's
//! known-kind table, and any future producer cannot drift apart. Adding a
//! [`Payload`](super::Payload) variant requires an arm in [`of`] (the
//! exhaustive match enforces it) and a constant in [`KNOWN`].

use super::Payload;

pub(crate) const PROCESS_START: &str = "process_start";
pub(crate) const PROCESS_END: &str = "process_end";
pub(crate) const AUTH: &str = "auth";
pub(crate) const TOOL_START: &str = "tool_start";
pub(crate) const TOOL_END: &str = "tool_end";
pub(crate) const CONFIG: &str = "config";
pub(crate) const FOLDER_POLICY: &str = "folder_policy";

/// Every `kind` discriminator this build recognizes, and the order
/// `kind_of`'s match arms name them.
pub(crate) const KNOWN: [&str; 7] = [
    PROCESS_START,
    PROCESS_END,
    AUTH,
    TOOL_START,
    TOOL_END,
    CONFIG,
    FOLDER_POLICY,
];

/// The canonical discriminator for `payload`'s record shape.
pub(crate) fn of(payload: &Payload) -> &'static str {
    match payload {
        Payload::ProcessStart(_) => PROCESS_START,
        Payload::ProcessEnd(_) => PROCESS_END,
        Payload::Auth(_) => AUTH,
        Payload::ToolStart(_) => TOOL_START,
        Payload::ToolEnd(_) => TOOL_END,
        Payload::Config(_) => CONFIG,
        Payload::FolderPolicy(_) => FOLDER_POLICY,
    }
}
