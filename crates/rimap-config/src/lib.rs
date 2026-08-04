//! Configuration loading, validation, and credential resolution for rusty-imap-mcp.

#![deny(missing_docs)]

pub mod credential;
pub mod error;
pub mod loader;
pub mod login;
pub mod model;
pub mod validate;

#[cfg(any(feature = "test-support", test))]
pub mod test_support;

pub use crate::credential::{
    CredentialStore, IMAP_PASSWORD_ENV_VAR, KEYCHAIN_SERVICE, KeyringCredentialResolver,
    KeyringStore, PASSWORD_ENV_VAR, Protocol, ResolutionPolicy, SMTP_PASSWORD_ENV_VAR, account_key,
    resolve_credential,
};
pub use crate::error::ConfigError;
#[cfg(feature = "test-support")]
pub use crate::loader::load_and_validate_allowing_empty;
pub use crate::loader::{CONFIG_ENV_VAR, load_and_validate, load_from_path, resolve_config_path};
pub use crate::login::{run_login, tty_prompt};
pub use crate::model::{
    AccountCredentialsOverrides, AccountLimitsOverrides, AccountLookalikeOverrides,
    AccountSecurityOverrides, AttachmentsConfig, AuditConfig, Config, CredentialsConfig,
    DefaultsConfig, FallbackMode, ImapConfig, LimitsConfig, LookalikeConfig, MultiAccountConfig,
    RawAccountConfig, SecurityConfig, SmtpConfig, SmtpEncryption, Verdict,
};
#[cfg(feature = "test-support")]
pub use crate::validate::validate_multi_allowing_empty;
pub use crate::validate::{
    ValidatedAccountConfig, ValidatedMultiConfig, validate_legacy_as_multi, validate_multi,
};
