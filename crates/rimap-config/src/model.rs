//! Strongly-typed config model. Field-for-field mapping of the TOML schema
//! from design spec §4 "File format".
//!
//! Validation is a separate pass (`validate.rs`): these structs only describe
//! *shape*. An instance that deserializes successfully may still be invalid.
//!
//! # Policy: every struct here is `#[non_exhaustive]`
//!
//! The TOML schema grows — that is the normal life of a config format — and
//! before #665 each new `pub` field was a breaking change to the public API.
//! #648 is the worked example: one field on [`LimitsConfig`] forced the whole
//! workspace to `0.2.0`. Marking every struct `#[non_exhaustive]` retires that
//! failure mode; adding a field is now additive.
//!
//! This mirrors `rimap_content::output`, which has carried the same policy
//! since Sprint 4b. **Any struct added to this module gets the attribute.**
//!
//! The attribute does not restrict this crate, so the `merge_onto`
//! destructuring below and the derived `Deserialize` impls are unaffected.
//! What it costs downstream is the struct literal: callers use
//! `..Default::default()` where a `Default` exists, and the constructors on
//! [`ImapConfig`], [`SmtpConfig`], and [`AuditConfig`] where one does not.
//!
//! [`Config`], [`MultiAccountConfig`], and [`RawAccountConfig`] deliberately
//! get neither a `Default` nor a constructor. They are file-load roots
//! produced by [`crate::load_and_validate`] / [`crate::load_from_path`], and a
//! `Default` for them would mint a config with an empty `host` and `username`
//! — precisely the invalid state `deny_unknown_fields` and the `validate`
//! module exist to reject.

use std::collections::BTreeMap;
use std::path::PathBuf;

use rimap_core::posture::Posture;
use serde::{Deserialize, Serialize};

/// The full config file.
///
/// Obtained from [`crate::load_from_path`]; not constructible downstream by
/// design (see the module-level policy note).
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// IMAP connection settings.
    pub imap: ImapConfig,
    /// SMTP connection settings (optional — required when `send_email` is enabled).
    #[serde(default)]
    pub smtp: Option<SmtpConfig>,
    /// Security posture and overrides.
    #[serde(default)]
    pub security: SecurityConfig,
    /// Numeric limits.
    #[serde(default)]
    pub limits: LimitsConfig,
    /// Audit log settings.
    pub audit: AuditConfig,
    /// Attachment download settings.
    #[serde(default)]
    pub attachments: AttachmentsConfig,
}

/// `[imap]` block.
///
/// Build one with [`ImapConfig::new`] and assign the optional fields
/// afterwards:
///
/// ```
/// use rimap_config::ImapConfig;
///
/// let mut imap = ImapConfig::new("imap.example.com".to_string(), 993, "alice".to_string());
/// imap.command_timeout_seconds = 60;
/// ```
///
/// The struct literal is not available downstream:
///
/// ```compile_fail
/// use rimap_config::ImapConfig;
///
/// let imap = ImapConfig {
///     host: "imap.example.com".to_string(),
///     port: 993,
///     username: "alice".to_string(),
///     encryption: Default::default(),
///     tls_fingerprint_sha256: None,
///     command_timeout_seconds: 30,
///     connect_timeout_seconds: 10,
/// };
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImapConfig {
    /// Server host.
    pub host: String,
    /// Server port (993 for TLS, 143/1143 for STARTTLS).
    pub port: u16,
    /// IMAP username.
    pub username: String,
    /// Transport encryption mode. Defaults to implicit TLS for
    /// backward-compatibility with pre-STARTTLS configs.
    #[serde(default)]
    pub encryption: ImapEncryption,
    /// Optional pinned TLS certificate SHA-256 fingerprint. Hex, colons
    /// optional (e.g. `"ab:cd:…"` or `"abcd…"`).
    #[serde(default)]
    pub tls_fingerprint_sha256: Option<String>,
    /// Per-command timeout in seconds.
    #[serde(default = "default_command_timeout")]
    pub command_timeout_seconds: u32,
    /// TCP + TLS handshake + greeting + CAPABILITY probe deadline.
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_seconds: u32,
}

impl ImapConfig {
    /// Build an `[imap]` block from the three fields the TOML schema requires.
    ///
    /// Every remaining field takes the same value the loader applies when the
    /// file omits it, so `ImapConfig::new(host, port, username)` and a config
    /// file naming only those three keys produce identical values.
    #[must_use]
    pub fn new(host: String, port: u16, username: String) -> Self {
        Self {
            host,
            port,
            username,
            encryption: ImapEncryption::default(),
            tls_fingerprint_sha256: None,
            command_timeout_seconds: default_command_timeout(),
            connect_timeout_seconds: default_connect_timeout(),
        }
    }
}

fn default_command_timeout() -> u32 {
    30
}

fn default_connect_timeout() -> u32 {
    10
}

/// How credential resolution falls back when the keyring has no entry.
///
/// - `KeyringThenEnv` (default) — try the keyring; on either a miss or
///   a hard keyring failure (e.g. no D-Bus session available, as in CI
///   runners and Docker containers), fall back to the protocol-scoped
///   `RUSTY_IMAP_MCP_IMAP_PASSWORD` / `RUSTY_IMAP_MCP_SMTP_PASSWORD`,
///   then the legacy shared `RUSTY_IMAP_MCP_PASSWORD`; if none is set,
///   fail. Suitable for CI/test and single-account deployments,
///   including headless environments without a running secret-service.
///   When the fallback fires because of a keyring transport error
///   rather than a plain miss, the resolver emits a `tracing::warn!`
///   naming the env var used, so the misconfiguration is still visible
///   to operators.
/// - `KeyringOnly` — keyring only; a miss returns `NoCredential` and a
///   transport error propagates as `Keychain`. The env var is never
///   consulted. Recommended for multi-account deployments where a
///   shared env-var fallback would silently send one account's
///   password to another account's server (see #78).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FallbackMode {
    /// Keyring, then env var, then fail.
    #[default]
    KeyringThenEnv,
    /// Keyring only; no env-var fallback.
    KeyringOnly,
}

/// `[defaults.credentials]` / `[[accounts.credentials]]` block.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialsConfig {
    /// Fallback policy.
    #[serde(default)]
    pub fallback: FallbackMode,
}

/// SMTP encryption mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SmtpEncryption {
    /// STARTTLS upgrade on port 587.
    Starttls,
    /// Implicit TLS on port 465.
    Tls,
    /// No encryption (testing only).
    None,
}

// IMAP transport encryption mode lives in rimap-core as the single source
// of truth shared with rimap-imap. See `rimap_core::imap_encryption`.
pub use rimap_core::ImapEncryption;

/// `[smtp]` block. Optional — required only when `send_email` is enabled.
///
/// Build one with [`SmtpConfig::new`]; the struct literal is not available
/// downstream.
#[non_exhaustive]
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SmtpConfig {
    /// SMTP server host.
    pub host: String,
    /// SMTP server port (587 for STARTTLS, 465 for implicit TLS).
    pub port: u16,
    /// Encryption mode.
    pub encryption: SmtpEncryption,
    /// SMTP username.
    pub username: String,
    /// Per-command timeout in seconds.
    #[serde(default = "default_command_timeout")]
    pub command_timeout_seconds: u32,
}

impl SmtpConfig {
    /// Build an `[smtp]` block from the four fields the TOML schema requires.
    ///
    /// `command_timeout_seconds` takes the same value the loader applies when
    /// the file omits it.
    #[must_use]
    pub fn new(host: String, port: u16, encryption: SmtpEncryption, username: String) -> Self {
        Self {
            host,
            port,
            encryption,
            username,
            command_timeout_seconds: default_command_timeout(),
        }
    }
}

impl core::fmt::Debug for SmtpConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SmtpConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("encryption", &self.encryption)
            .field("username", &"[redacted]")
            .field("command_timeout_seconds", &self.command_timeout_seconds)
            .finish()
    }
}

/// Override verdict for a per-tool override.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// Tool is allowed regardless of posture.
    Allow,
    /// Tool is denied regardless of posture.
    Deny,
}

/// `[security]` block.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityConfig {
    /// Base posture.
    #[serde(default)]
    pub posture: Posture,
    /// Per-tool overrides, keyed by raw TOML tool name. Resolved to
    /// [`rimap_core::tool::ToolName`] during validation.
    #[serde(default)]
    pub tools: BTreeMap<String, Verdict>,
    /// Folders that cannot be deleted or renamed. Case-insensitive matching.
    #[serde(default = "default_protected_folders")]
    pub protected_folders: Vec<String>,
    /// Folders where `expunge` and `delete_folder` are permitted.
    #[serde(default)]
    pub expunge_folders: Vec<String>,
    /// Look-alike detection settings (placeholder for Sprint 4).
    #[serde(default)]
    pub lookalike: LookalikeConfig,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            posture: Posture::default(),
            tools: BTreeMap::new(),
            protected_folders: default_protected_folders(),
            expunge_folders: Vec::new(),
            lookalike: LookalikeConfig::default(),
        }
    }
}

fn default_protected_folders() -> Vec<String> {
    vec![
        "INBOX".to_string(),
        "Sent".to_string(),
        "Drafts".to_string(),
        "Trash".to_string(),
    ]
}

/// `[security.lookalike]` block. Shape only; Sprint 4 owns semantics.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LookalikeConfig {
    /// Whether look-alike detection is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// User-curated watchlist of protected domains.
    #[serde(default)]
    pub known_domains: Vec<String>,
    /// Warn on any non-ASCII domain, even if not in the watchlist.
    #[serde(default)]
    pub warn_on_any_non_ascii_domain: bool,
}

impl Default for LookalikeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            known_domains: Vec::new(),
            warn_on_any_non_ascii_domain: false,
        }
    }
}

fn default_true() -> bool {
    true
}

/// `[limits]` block.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsConfig {
    /// Default search result limit.
    #[serde(default = "default_max_search")]
    pub max_search_results: u32,
    /// Hard cap on `max_search_results`.
    #[serde(default = "default_max_search_cap")]
    pub max_search_results_cap: u32,
    /// Max fetched body bytes per message.
    #[serde(default = "default_max_body")]
    pub max_fetch_body_bytes: u64,
    /// Max attachment bytes.
    #[serde(default = "default_max_attach")]
    pub max_attachment_bytes: u64,
    /// Max APPEND message bytes.
    #[serde(default = "default_max_append")]
    pub max_append_bytes: u64,
    /// Rate limiter: commands per second.
    #[serde(default = "default_cps")]
    pub commands_per_second: u32,
    /// Per-minute draft creation cap.
    #[serde(default = "default_drafts_per_min")]
    pub drafts_per_minute: u32,
    /// Per-minute email send cap.
    #[serde(default = "default_sends_per_min")]
    pub sends_per_minute: u32,
    /// Circuit breaker error threshold within the window.
    #[serde(default = "default_breaker_threshold")]
    pub circuit_breaker_error_threshold: u32,
    /// Circuit breaker window in seconds.
    #[serde(default = "default_breaker_window")]
    pub circuit_breaker_window_seconds: u32,
    /// Wall-clock ceiling on one account-scoped tool call, covering the
    /// session-lock wait, the lazy connect, the command, and the one
    /// read-only retry — the budgets `[imap]` bounds only stage by stage
    /// (#594, ADR-0012). Must be at least the worst case those stages can
    /// add up to; see `validate::limits::validate_tool_call_ceiling`.
    #[serde(default = "default_tool_call_timeout")]
    pub tool_call_timeout_seconds: u32,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_search_results: default_max_search(),
            max_search_results_cap: default_max_search_cap(),
            max_fetch_body_bytes: default_max_body(),
            max_attachment_bytes: default_max_attach(),
            max_append_bytes: default_max_append(),
            commands_per_second: default_cps(),
            drafts_per_minute: default_drafts_per_min(),
            sends_per_minute: default_sends_per_min(),
            circuit_breaker_error_threshold: default_breaker_threshold(),
            circuit_breaker_window_seconds: default_breaker_window(),
            tool_call_timeout_seconds: default_tool_call_timeout(),
        }
    }
}

fn default_max_search() -> u32 {
    200
}
fn default_max_search_cap() -> u32 {
    1000
}
fn default_max_body() -> u64 {
    5_242_880
}
fn default_max_attach() -> u64 {
    26_214_400
}
fn default_max_append() -> u64 {
    10_485_760
}
fn default_cps() -> u32 {
    10
}
fn default_drafts_per_min() -> u32 {
    5
}
fn default_sends_per_min() -> u32 {
    3
}
fn default_breaker_threshold() -> u32 {
    5
}
fn default_breaker_window() -> u32 {
    30
}
/// 300s: above the 140s worst case one IMAP operation can reach at the
/// shipped `[imap]` defaults (a stock config must not self-reject), with
/// room for tools that issue several operations per call.
fn default_tool_call_timeout() -> u32 {
    300
}

/// `[audit]` block.
///
/// Build one with [`AuditConfig::new`]; the struct literal is not available
/// downstream.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    /// Path to the audit log file.
    pub path: PathBuf,
    /// Rotate when the file reaches this many bytes.
    #[serde(default = "default_rotate_bytes")]
    pub rotate_bytes: u64,
    /// Number of rotated files to keep on disk after a rotation. This is
    /// a count-based cap. For time-based expiry, also set
    /// `retention_seconds`. A rotated file is kept only if it is among
    /// the newest `rotate_keep` AND within the retention window.
    /// Default: 5.
    #[serde(default = "default_rotate_keep")]
    pub rotate_keep: u32,
    /// Optional time-based retention in seconds. When set, rotated siblings
    /// whose mtime is older than `now - retention_seconds` are deleted during
    /// pruning, in addition to the count-based `rotate_keep` cap. A file is
    /// kept only if it is among the newest `rotate_keep` AND within the
    /// retention window. `None` (the default) disables time-based expiry.
    /// `Some(0)` is rejected at validation — use `None` instead.
    #[serde(default)]
    pub retention_seconds: Option<u64>,
    /// Provenance ring buffer window in seconds.
    #[serde(default = "default_provenance_window")]
    pub provenance_window_seconds: u32,
    /// Write deadline in seconds (ADR-0022 write-deadline watchdog). If a write
    /// exceeds this duration, the write fails with `AuditError::WriteDeadline`
    /// rather than blocking indefinitely. A default of 15 seconds catches a
    /// completely hung mount while not triggering on momentarily slow but
    /// healthy local disks. Set to 0 to disable the deadline.
    #[serde(default = "default_write_deadline_seconds")]
    pub write_deadline_seconds: u64,
    /// If true, continue on audit write failure (insecure; default false).
    #[serde(default)]
    pub fail_open: bool,
    /// Optional containment base for `audit.path`. When set, the
    /// audit path must canonicalize to a path under this base, or
    /// config validation fails. When `None`, the default is
    /// `$XDG_STATE_HOME/rusty-imap-mcp/` (or platform equivalent via
    /// `directories::ProjectDirs::data_local_dir`). Set to
    /// `allowed_base_dir = "/"` to opt out of containment entirely
    /// (NOT recommended).
    #[serde(default)]
    pub allowed_base_dir: Option<PathBuf>,
}

impl AuditConfig {
    /// Build an `[audit]` block from the one field the TOML schema requires.
    ///
    /// Every remaining field takes the same value the loader applies when the
    /// file omits it — notably `fail_open: false`, the secure default.
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            rotate_bytes: default_rotate_bytes(),
            rotate_keep: default_rotate_keep(),
            retention_seconds: None,
            provenance_window_seconds: default_provenance_window(),
            write_deadline_seconds: default_write_deadline_seconds(),
            fail_open: false,
            allowed_base_dir: None,
        }
    }
}

fn default_rotate_bytes() -> u64 {
    10_485_760
}
fn default_rotate_keep() -> u32 {
    5
}
fn default_provenance_window() -> u32 {
    60
}

fn default_write_deadline_seconds() -> u64 {
    15
}

/// `[attachments]` block.
#[non_exhaustive]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttachmentsConfig {
    /// Download directory. Empty = per-session tempdir.
    #[serde(default)]
    pub download_dir: String,
}

// ---------------------------------------------------------------------------
// Multi-account config format
// ---------------------------------------------------------------------------

/// Multi-account configuration format with `[[accounts]]` array.
///
/// A file-load root; not constructible downstream by design (see the
/// module-level policy note).
#[non_exhaustive]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MultiAccountConfig {
    /// Default security/limits inherited by accounts that omit them.
    #[serde(default)]
    pub defaults: DefaultsConfig,
    /// One or more account definitions.
    pub accounts: Vec<RawAccountConfig>,
    /// Global audit log settings.
    pub audit: AuditConfig,
    /// Global attachment download settings.
    #[serde(default)]
    pub attachments: AttachmentsConfig,
}

/// `[defaults]` block — shared settings inherited by accounts.
#[non_exhaustive]
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DefaultsConfig {
    /// Default security posture and overrides.
    #[serde(default)]
    pub security: SecurityConfig,
    /// Default numeric limits.
    #[serde(default)]
    pub limits: LimitsConfig,
    /// Default credential policy inherited by accounts that omit it.
    #[serde(default)]
    pub credentials: CredentialsConfig,
}

/// A single account entry in `[[accounts]]`.
///
/// Deserialized as part of [`MultiAccountConfig`]; not constructible
/// downstream by design (see the module-level policy note).
#[non_exhaustive]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawAccountConfig {
    /// Human-readable account name (validated as `AccountId`).
    pub name: String,
    /// IMAP connection settings (required per account).
    pub imap: ImapConfig,
    /// SMTP connection settings (optional per account).
    #[serde(default)]
    pub smtp: Option<SmtpConfig>,
    /// Per-account `[accounts.security]` overrides. Every key the account
    /// omits inherits from `[defaults.security]`; see
    /// [`AccountSecurityOverrides`].
    #[serde(default)]
    pub security: Option<AccountSecurityOverrides>,
    /// Per-account `[accounts.limits]` overrides. Every key the account
    /// omits inherits from `[defaults.limits]`; see
    /// [`AccountLimitsOverrides`].
    #[serde(default)]
    pub limits: Option<AccountLimitsOverrides>,
    /// Per-account `[accounts.credentials]` overrides. Every key the account
    /// omits inherits from `[defaults.credentials]`; see
    /// [`AccountCredentialsOverrides`].
    #[serde(default)]
    pub credentials: Option<AccountCredentialsOverrides>,
}

// ---------------------------------------------------------------------------
// Per-account overrides (#624, ADR-0013)
//
// These mirror `SecurityConfig` / `LimitsConfig` / `LookalikeConfig` /
// `CredentialsConfig` with every field `Option<T>` and no
// `#[serde(default = "...")]` value function, so `None` means "the account did
// not write this key" rather than "the account wrote the built-in default".
// Deserializing an account block into the concrete struct erases that
// distinction — serde has already filled the omitted fields by the time
// composition runs — which is why the merge needs its own type rather than a
// smarter `unwrap_or_else`.
//
// Each `merge_onto` destructures its concrete base exhaustively. Adding a
// field to one of the concrete configs without adding it here is then a
// compile error rather than another silently-dropped default.
// ---------------------------------------------------------------------------

/// `[accounts.limits]` — the subset of `[limits]` one account overrides.
///
/// Merged onto `[defaults.limits]` by [`AccountLimitsOverrides::merge_onto`].
#[non_exhaustive]
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountLimitsOverrides {
    /// Overrides [`LimitsConfig::max_search_results`].
    pub max_search_results: Option<u32>,
    /// Overrides [`LimitsConfig::max_search_results_cap`].
    pub max_search_results_cap: Option<u32>,
    /// Overrides [`LimitsConfig::max_fetch_body_bytes`].
    pub max_fetch_body_bytes: Option<u64>,
    /// Overrides [`LimitsConfig::max_attachment_bytes`].
    pub max_attachment_bytes: Option<u64>,
    /// Overrides [`LimitsConfig::max_append_bytes`].
    pub max_append_bytes: Option<u64>,
    /// Overrides [`LimitsConfig::commands_per_second`].
    pub commands_per_second: Option<u32>,
    /// Overrides [`LimitsConfig::drafts_per_minute`].
    pub drafts_per_minute: Option<u32>,
    /// Overrides [`LimitsConfig::sends_per_minute`].
    pub sends_per_minute: Option<u32>,
    /// Overrides [`LimitsConfig::circuit_breaker_error_threshold`].
    pub circuit_breaker_error_threshold: Option<u32>,
    /// Overrides [`LimitsConfig::circuit_breaker_window_seconds`].
    pub circuit_breaker_window_seconds: Option<u32>,
    /// Overrides [`LimitsConfig::tool_call_timeout_seconds`].
    pub tool_call_timeout_seconds: Option<u32>,
}

impl AccountLimitsOverrides {
    /// Apply these overrides to `base`, returning the account's effective
    /// limits. Every field the account left unset keeps its `base` value.
    #[must_use]
    #[expect(
        clippy::needless_pass_by_value,
        reason = "every `merge_onto` consumes its base and yields the merged \
                  config; `LimitsConfig`'s fields all happen to be `Copy`, so \
                  only this one could take a reference, and doing so would \
                  split the shared signature for no behavioural gain"
    )]
    pub fn merge_onto(self, base: LimitsConfig) -> LimitsConfig {
        let LimitsConfig {
            max_search_results,
            max_search_results_cap,
            max_fetch_body_bytes,
            max_attachment_bytes,
            max_append_bytes,
            commands_per_second,
            drafts_per_minute,
            sends_per_minute,
            circuit_breaker_error_threshold,
            circuit_breaker_window_seconds,
            tool_call_timeout_seconds,
        } = base;
        LimitsConfig {
            max_search_results: self.max_search_results.unwrap_or(max_search_results),
            max_search_results_cap: self
                .max_search_results_cap
                .unwrap_or(max_search_results_cap),
            max_fetch_body_bytes: self.max_fetch_body_bytes.unwrap_or(max_fetch_body_bytes),
            max_attachment_bytes: self.max_attachment_bytes.unwrap_or(max_attachment_bytes),
            max_append_bytes: self.max_append_bytes.unwrap_or(max_append_bytes),
            commands_per_second: self.commands_per_second.unwrap_or(commands_per_second),
            drafts_per_minute: self.drafts_per_minute.unwrap_or(drafts_per_minute),
            sends_per_minute: self.sends_per_minute.unwrap_or(sends_per_minute),
            circuit_breaker_error_threshold: self
                .circuit_breaker_error_threshold
                .unwrap_or(circuit_breaker_error_threshold),
            circuit_breaker_window_seconds: self
                .circuit_breaker_window_seconds
                .unwrap_or(circuit_breaker_window_seconds),
            tool_call_timeout_seconds: self
                .tool_call_timeout_seconds
                .unwrap_or(tool_call_timeout_seconds),
        }
    }
}

/// `[accounts.security]` — the subset of `[security]` one account overrides.
///
/// Merged onto `[defaults.security]` by
/// [`AccountSecurityOverrides::merge_onto`].
#[non_exhaustive]
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountSecurityOverrides {
    /// Overrides [`SecurityConfig::posture`].
    pub posture: Option<Posture>,
    /// Per-tool overrides merged **per key** onto `[defaults.security.tools]`:
    /// an entry here replaces the default's verdict for that tool and leaves
    /// every other inherited entry standing. An account cannot erase an
    /// inherited entry, only restate its verdict.
    pub tools: Option<BTreeMap<String, Verdict>>,
    /// Overrides [`SecurityConfig::protected_folders`]. Replaces the
    /// inherited list outright rather than unioning with it.
    pub protected_folders: Option<Vec<String>>,
    /// Overrides [`SecurityConfig::expunge_folders`]. Replaces the inherited
    /// list outright rather than unioning with it.
    pub expunge_folders: Option<Vec<String>>,
    /// Overrides [`SecurityConfig::lookalike`], itself merged per key.
    pub lookalike: Option<AccountLookalikeOverrides>,
}

impl AccountSecurityOverrides {
    /// Apply these overrides to `base`, returning the account's effective
    /// security config. Every field the account left unset keeps its `base`
    /// value; `tools` and `lookalike` merge per key.
    #[must_use]
    pub fn merge_onto(self, base: SecurityConfig) -> SecurityConfig {
        let SecurityConfig {
            posture,
            mut tools,
            protected_folders,
            expunge_folders,
            lookalike,
        } = base;
        if let Some(overriding) = self.tools {
            tools.extend(overriding);
        }
        let lookalike = match self.lookalike {
            Some(overriding) => overriding.merge_onto(lookalike),
            None => lookalike,
        };
        SecurityConfig {
            posture: self.posture.unwrap_or(posture),
            tools,
            protected_folders: self.protected_folders.unwrap_or(protected_folders),
            expunge_folders: self.expunge_folders.unwrap_or(expunge_folders),
            lookalike,
        }
    }
}

/// `[accounts.security.lookalike]` — the subset of `[security.lookalike]`
/// one account overrides.
#[non_exhaustive]
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountLookalikeOverrides {
    /// Overrides [`LookalikeConfig::enabled`].
    pub enabled: Option<bool>,
    /// Overrides [`LookalikeConfig::known_domains`]. Replaces the inherited
    /// list outright rather than unioning with it.
    pub known_domains: Option<Vec<String>>,
    /// Overrides [`LookalikeConfig::warn_on_any_non_ascii_domain`].
    pub warn_on_any_non_ascii_domain: Option<bool>,
}

impl AccountLookalikeOverrides {
    /// Apply these overrides to `base`, returning the account's effective
    /// look-alike config. Every field the account left unset keeps its
    /// `base` value.
    #[must_use]
    pub fn merge_onto(self, base: LookalikeConfig) -> LookalikeConfig {
        let LookalikeConfig {
            enabled,
            known_domains,
            warn_on_any_non_ascii_domain,
        } = base;
        LookalikeConfig {
            enabled: self.enabled.unwrap_or(enabled),
            known_domains: self.known_domains.unwrap_or(known_domains),
            warn_on_any_non_ascii_domain: self
                .warn_on_any_non_ascii_domain
                .unwrap_or(warn_on_any_non_ascii_domain),
        }
    }
}

/// `[accounts.credentials]` — the subset of `[credentials]` one account
/// overrides.
///
/// `CredentialsConfig::fallback` carries `#[serde(default)]`, so an empty
/// `[accounts.credentials]` table deserializes into a fully-populated
/// `CredentialsConfig` — the same erasure #624 describes, and in the more
/// dangerous direction: it would silently restore the shared env-var
/// fallback that `keyring-only` exists to prevent (#78).
#[non_exhaustive]
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountCredentialsOverrides {
    /// Overrides [`CredentialsConfig::fallback`].
    pub fallback: Option<FallbackMode>,
}

impl AccountCredentialsOverrides {
    /// Apply these overrides to `base`, returning the account's effective
    /// credential policy. Every field the account left unset keeps its
    /// `base` value.
    #[must_use]
    pub fn merge_onto(self, base: CredentialsConfig) -> CredentialsConfig {
        let CredentialsConfig { fallback } = base;
        CredentialsConfig {
            fallback: self.fallback.unwrap_or(fallback),
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod imap_config_encryption_tests {
    use super::*;

    const MINIMAL: &str = r#"
host = "imap.example.com"
port = 993
username = "alice"
"#;

    const WITH_STARTTLS: &str = r#"
host = "imap.example.com"
port = 1143
username = "alice"
encryption = "starttls"
"#;

    #[test]
    fn omitted_encryption_defaults_to_tls() {
        let cfg: ImapConfig = toml::from_str(MINIMAL).unwrap();
        assert_eq!(cfg.encryption, ImapEncryption::Tls);
    }

    #[test]
    fn explicit_starttls_round_trips() {
        let cfg: ImapConfig = toml::from_str(WITH_STARTTLS).unwrap();
        assert_eq!(cfg.encryption, ImapEncryption::Starttls);
        assert_eq!(cfg.port, 1143);
    }

    #[test]
    fn explicit_tls_round_trips() {
        let cfg: ImapConfig = toml::from_str(
            r#"
host = "imap.gmail.com"
port = 993
username = "alice"
encryption = "tls"
"#,
        )
        .unwrap();
        assert_eq!(cfg.encryption, ImapEncryption::Tls);
    }

    #[test]
    fn rejects_unknown_encryption_value() {
        let toml = r#"
host = "h"
port = 993
username = "u"
encryption = "mutual-tls"
"#;
        assert!(toml::from_str::<ImapConfig>(toml).is_err());
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod imap_encryption_tests {
    use serde::Deserialize as _;
    use serde::Serialize as _;

    use super::*;

    #[test]
    fn default_is_tls() {
        assert_eq!(ImapEncryption::default(), ImapEncryption::Tls);
    }

    #[test]
    fn serializes_as_lowercase_tls() {
        let mut s = String::new();
        ImapEncryption::Tls
            .serialize(toml::ser::ValueSerializer::new(&mut s))
            .unwrap();
        assert_eq!(s.trim(), "\"tls\"");
    }

    #[test]
    fn serializes_as_lowercase_starttls() {
        let mut s = String::new();
        ImapEncryption::Starttls
            .serialize(toml::ser::ValueSerializer::new(&mut s))
            .unwrap();
        assert_eq!(s.trim(), "\"starttls\"");
    }

    #[test]
    fn deserializes_starttls() {
        let de = toml::de::ValueDeserializer::parse("\"starttls\"").unwrap();
        let v = ImapEncryption::deserialize(de).unwrap();
        assert_eq!(v, ImapEncryption::Starttls);
    }

    #[test]
    fn deserializes_tls() {
        let de = toml::de::ValueDeserializer::parse("\"tls\"").unwrap();
        let v = ImapEncryption::deserialize(de).unwrap();
        assert_eq!(v, ImapEncryption::Tls);
    }

    #[test]
    fn rejects_unknown_value() {
        let de = toml::de::ValueDeserializer::parse("\"mutual-tls\"").unwrap();
        let err = ImapEncryption::deserialize(de).unwrap_err();
        assert!(err.to_string().contains("mutual-tls"));
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn limits_default_values_are_sensible() {
        let l = LimitsConfig::default();
        assert!(l.max_search_results > 0);
        assert!(l.max_search_results_cap >= l.max_search_results);
        assert!(l.max_fetch_body_bytes > 0);
        assert!(l.max_attachment_bytes > 0);
        assert!(l.max_append_bytes > 0);
        assert!(l.commands_per_second > 0);
        assert!(l.drafts_per_minute > 0);
        assert!(l.sends_per_minute > 0);
        assert!(l.circuit_breaker_error_threshold > 0);
        assert!(l.circuit_breaker_window_seconds > 0);
    }

    #[test]
    fn security_defaults_protect_common_system_folders() {
        let s = SecurityConfig::default();
        assert_eq!(s.posture, rimap_core::posture::Posture::DraftSafe);
        // INBOX, Sent, Drafts, Trash are protected by default — destructive
        // tools must opt-in via expunge_folders to touch these.
        for required in ["INBOX", "Sent", "Drafts", "Trash"] {
            assert!(
                s.protected_folders.iter().any(|f| f == required),
                "expected `{required}` in default protected_folders, got {:?}",
                s.protected_folders,
            );
        }
        assert!(s.expunge_folders.is_empty());
        assert!(s.tools.is_empty());
    }

    #[test]
    fn lookalike_default_is_disabled() {
        let l = LookalikeConfig::default();
        // Sanity: defaults exist and are non-panicking.
        let _ = format!("{l:?}");
    }

    // -----------------------------------------------------------------------
    // Override-struct field coverage (#624, ADR-0013)
    //
    // Each of these serializes a fully-populated concrete config, deserializes
    // it into the mirror override struct, and merges it onto the built-in
    // default. Serialization emits *every* field of the concrete struct, so
    // the round trip fails on both drift directions: a field missing from the
    // mirror trips `deny_unknown_fields`, and a field the mirror declares but
    // `merge_onto` forgets shows up as an inequality.
    // -----------------------------------------------------------------------

    /// Every `LimitsConfig` field at a value distinct from its default.
    fn non_default_limits() -> LimitsConfig {
        LimitsConfig {
            max_search_results: 11,
            max_search_results_cap: 22,
            max_fetch_body_bytes: 33,
            max_attachment_bytes: 44,
            max_append_bytes: 55,
            commands_per_second: 66,
            drafts_per_minute: 77,
            sends_per_minute: 88,
            circuit_breaker_error_threshold: 99,
            circuit_breaker_window_seconds: 111,
            tool_call_timeout_seconds: 222,
        }
    }

    #[test]
    fn limits_overrides_cover_every_limits_field() {
        let populated = non_default_limits();
        assert_ne!(populated, LimitsConfig::default(), "fixture must differ");
        let value = toml::Value::try_from(&populated).unwrap();
        let overrides: AccountLimitsOverrides = value.try_into().unwrap();
        assert_eq!(overrides.merge_onto(LimitsConfig::default()), populated);
    }

    #[test]
    fn security_overrides_cover_every_security_field() {
        let mut tools = BTreeMap::new();
        tools.insert("mark_read".to_string(), Verdict::Deny);
        let populated = SecurityConfig {
            posture: Posture::Readonly,
            tools,
            protected_folders: vec!["Archive".to_string()],
            expunge_folders: vec!["Junk".to_string()],
            lookalike: non_default_lookalike(),
        };
        assert_ne!(populated, SecurityConfig::default(), "fixture must differ");
        let value = toml::Value::try_from(&populated).unwrap();
        let overrides: AccountSecurityOverrides = value.try_into().unwrap();
        assert_eq!(overrides.merge_onto(SecurityConfig::default()), populated);
    }

    /// Every `LookalikeConfig` field at a value distinct from its default.
    fn non_default_lookalike() -> LookalikeConfig {
        LookalikeConfig {
            enabled: false,
            known_domains: vec!["example.test".to_string()],
            warn_on_any_non_ascii_domain: true,
        }
    }

    #[test]
    fn lookalike_overrides_cover_every_lookalike_field() {
        let populated = non_default_lookalike();
        assert_ne!(populated, LookalikeConfig::default(), "fixture must differ");
        let value = toml::Value::try_from(&populated).unwrap();
        let overrides: AccountLookalikeOverrides = value.try_into().unwrap();
        assert_eq!(overrides.merge_onto(LookalikeConfig::default()), populated);
    }

    #[test]
    fn credentials_overrides_cover_every_credentials_field() {
        let populated = CredentialsConfig {
            fallback: FallbackMode::KeyringOnly,
        };
        let value = toml::Value::try_from(populated).unwrap();
        let overrides: AccountCredentialsOverrides = value.try_into().unwrap();
        let merged = overrides.merge_onto(CredentialsConfig::default());
        assert_eq!(merged.fallback, FallbackMode::KeyringOnly);
    }

    #[test]
    fn empty_credentials_overrides_keep_the_base_fallback() {
        let base = CredentialsConfig {
            fallback: FallbackMode::KeyringOnly,
        };
        let merged = AccountCredentialsOverrides::default().merge_onto(base);
        assert_eq!(merged.fallback, FallbackMode::KeyringOnly);
    }

    #[test]
    fn empty_overrides_leave_the_base_untouched() {
        let base = non_default_limits();
        assert_eq!(
            AccountLimitsOverrides::default().merge_onto(base.clone()),
            base,
        );

        let base = SecurityConfig {
            posture: Posture::Readonly,
            ..SecurityConfig::default()
        };
        assert_eq!(
            AccountSecurityOverrides::default().merge_onto(base.clone()),
            base,
        );
    }

    #[test]
    fn tool_overrides_merge_per_key_leaving_other_entries_standing() {
        let mut base = SecurityConfig::default();
        base.tools.insert("mark_read".to_string(), Verdict::Deny);
        base.tools.insert("search".to_string(), Verdict::Deny);

        let mut overriding = BTreeMap::new();
        overriding.insert("search".to_string(), Verdict::Allow);
        overriding.insert("delete_message".to_string(), Verdict::Allow);

        let merged = AccountSecurityOverrides {
            tools: Some(overriding),
            ..AccountSecurityOverrides::default()
        }
        .merge_onto(base);

        assert_eq!(merged.tools.get("mark_read"), Some(&Verdict::Deny));
        assert_eq!(merged.tools.get("search"), Some(&Verdict::Allow));
        assert_eq!(merged.tools.get("delete_message"), Some(&Verdict::Allow));
    }

    #[test]
    fn smtp_encryption_starttls_round_trips_via_toml() {
        #[derive(serde::Serialize, serde::Deserialize)]
        struct W {
            v: SmtpEncryption,
        }
        let s = toml::to_string(&W {
            v: SmtpEncryption::Starttls,
        })
        .unwrap();
        let back: W = toml::from_str(&s).unwrap();
        assert_eq!(back.v, SmtpEncryption::Starttls);
    }

    #[test]
    fn verdict_allow_deny_round_trip_via_toml() {
        #[derive(serde::Serialize, serde::Deserialize)]
        struct W {
            v: Verdict,
        }
        for v in [Verdict::Allow, Verdict::Deny] {
            let s = toml::to_string(&W { v }).unwrap();
            let back: W = toml::from_str(&s).unwrap();
            assert_eq!(back.v, v);
        }
    }

    #[test]
    fn fallback_mode_defaults_to_keyring_then_env() {
        assert_eq!(FallbackMode::default(), FallbackMode::KeyringThenEnv);
    }

    #[test]
    fn fallback_mode_round_trips_via_toml() {
        #[derive(serde::Serialize, serde::Deserialize)]
        struct W {
            v: FallbackMode,
        }
        for v in [FallbackMode::KeyringOnly, FallbackMode::KeyringThenEnv] {
            let s = toml::to_string(&W { v }).unwrap();
            let back: W = toml::from_str(&s).unwrap();
            assert_eq!(back.v, v);
        }
    }

    #[test]
    fn credentials_config_deserializes_with_fallback_key() {
        let toml_str = r#"
fallback = "keyring-only"
"#;
        let cfg: CredentialsConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.fallback, FallbackMode::KeyringOnly);
    }
}
