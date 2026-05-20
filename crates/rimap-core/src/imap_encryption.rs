//! IMAP transport encryption mode. The single source of truth shared by
//! `rimap-config` (parses it from TOML) and `rimap-imap` (consumes it
//! when opening a connection). Lives in `rimap-core` so neither crate
//! needs to mirror the variant set, and so adding a new transport mode
//! is a single-place edit instead of three.

use serde::{Deserialize, Serialize};

/// IMAP transport encryption mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ImapEncryption {
    /// Implicit TLS (IMAPS), typical port 993.
    #[default]
    Tls,
    /// STARTTLS upgrade on the IMAP port, typical port 143 or 1143.
    Starttls,
}
