//! Shared core types for rusty-imap-mcp: errors, postures, tool names.

#![deny(missing_docs)]

pub mod account;
pub mod auth_event;
pub mod auth_sink;
pub mod credential;
pub use credential::{CredentialResolver, CredentialResolverError, CredentialSource};
pub mod error;
pub mod folder_name;
pub mod imap_encryption;
pub mod lenient_int;
pub mod posture;
pub mod posture_matrix;
pub mod tls;
pub mod tool;
pub mod uid_selector;
pub mod version;
pub mod warning;

pub use crate::auth_event::{AuthEvent, AuthResult};
pub use crate::auth_sink::{AuthEventSink, AuthSinkError};
pub use crate::error::{ErrorCode, RimapError};
pub use crate::folder_name::{FolderName, FolderNameError, is_rejected_display_codepoint};
pub use crate::imap_encryption::ImapEncryption;
pub use crate::posture::{Posture, UnknownPosture};
pub use crate::posture_matrix::base_allows;
pub use crate::tls::{FingerprintParseError, TlsFingerprint};
pub use crate::tool::{ParseToolNameError, ToolName};
pub use crate::uid_selector::UidSelector;
pub use crate::warning::{WarningCode, WarningSeverity};
