//! Configuration error type. Every variant is surfaced as `ERR_CONFIG` at the
//! top level per design spec §9.

use std::path::PathBuf;

use rimap_core::account::InvalidAccountName;
use rimap_core::posture::UnknownPosture;
use rimap_core::tool::ParseToolNameError;
use thiserror::Error;

/// Error produced by config loading, parsing, validation, or credential resolution.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// The config file could not be read from disk.
    #[error("failed to read config file `{path}`: {source}")]
    Read {
        /// Attempted path.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The config file was not valid TOML.
    #[error("failed to parse config file `{path}`: {source}")]
    Parse {
        /// Attempted path.
        path: PathBuf,
        /// Underlying `toml` parse error.
        #[source]
        source: toml::de::Error,
    },
    /// The posture name in the config was not recognized.
    #[error(transparent)]
    Posture(#[from] UnknownPosture),
    /// A per-tool override referenced an unknown tool name.
    #[error("invalid tool override: {0}")]
    ToolOverride(#[from] ParseToolNameError),
    /// TLS fingerprint did not parse as 32 hex bytes.
    #[error("invalid tls_fingerprint_sha256: {reason}")]
    TlsFingerprint {
        /// Specific parse failure reason.
        reason: String,
    },
    /// A required directory is missing or not writable.
    #[error("path `{path}` is not writable: {reason}")]
    PathNotWritable {
        /// The offending path.
        path: PathBuf,
        /// Explanation.
        reason: String,
    },
    /// `audit.path` resolved to a location outside the configured
    /// `allowed_base_dir`.
    ///
    /// ## Path disclosure exemption (LOCAL-ERR-05)
    ///
    /// The `Display` for this variant embeds both canonicalized paths.
    /// The LOCAL-ERR-05 rule normally forbids filesystem paths in error
    /// messages because they leak layout into operator-visible logs.
    /// This variant is exempted because:
    ///
    ///   - It fires only at config validation time, during startup,
    ///     against a path the OPERATOR themselves wrote in their config
    ///     file. The audience is never an attacker — it is the same
    ///     operator who supplied the misconfigured path.
    ///   - The canonicalized paths are the actionable information the
    ///     operator needs to diagnose the problem (e.g. "I wrote
    ///     `~/audit.jsonl` but my allowed base is `~/Library/...`").
    ///
    /// Both paths are filesystem layout, which is sensitive if this
    /// variant ever starts firing from runtime (non-startup) code paths
    /// or from attacker-controlled config. If that changes, revisit
    /// this exemption.
    #[error("audit path `{path}` is not contained in allowed base `{base}`")]
    AuditPathOutsideBase {
        /// The canonicalized audit path.
        path: PathBuf,
        /// The canonicalized base directory.
        base: PathBuf,
    },
    /// A numeric limit was zero or out of range.
    #[error("invalid value for `{field}`: {reason}")]
    InvalidLimit {
        /// TOML field name in dotted form, e.g. `limits.commands_per_second`.
        field: &'static str,
        /// Explanation.
        reason: String,
    },
    /// No credential could be found in keychain or environment.
    ///
    /// Display never includes the username. `host` is the IMAP/SMTP host
    /// (public DNS in practice). `account_tag` is `hash_account_tag(username,
    /// host)` — operators can correlate logs without seeing the username.
    #[error("no credential for host `{host}` (account_tag {account_tag}): {reason}")]
    NoCredential {
        /// IMAP/SMTP host (public DNS, safe to log).
        host: String,
        /// Short hash of `username@host` for log correlation.
        account_tag: String,
        /// What we tried and what the user should do next.
        reason: String,
    },
    /// Keychain access error (not "not found" — that becomes `NoCredential`).
    ///
    /// Display never includes the username. See `NoCredential` for the rules
    /// on `host` and `account_tag`. The underlying source error is accessible
    /// via the error chain (e.g. `#[source]` / traversal by `anyhow` or similar),
    /// never interpolated into the Display string.
    #[error("keychain error for host `{host}` (account_tag {account_tag})")]
    Keychain {
        /// IMAP/SMTP host (public DNS, safe to log).
        host: String,
        /// Short hash of `username@host` for log correlation.
        account_tag: String,
        /// Underlying keyring error. Not included in Display to prevent
        /// leaking username-bearing content from the keyring crate.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// `send_email` is enabled by the base posture but no `[smtp]` section
    /// is configured.
    #[error(
        "send_email is enabled by the '{posture}' posture but no [smtp] \
         section is configured; add [smtp] or deny send_email via \
         [security.tools] send_email = \"deny\""
    )]
    SmtpRequired {
        /// The base posture that enabled `send_email`.
        posture: rimap_core::Posture,
    },
    /// `send_email` is enabled by an explicit `[security.tools]` override on
    /// a posture that does not itself enable it, but no `[smtp]` section is
    /// configured (see #327).
    #[error(
        "send_email is enabled by a [security.tools] send_email = \"allow\" \
         override (the '{posture}' posture does not enable it) but no [smtp] \
         section is configured; add [smtp] or remove the send_email override"
    )]
    SmtpRequiredByOverride {
        /// The base posture, which does not itself enable `send_email`.
        posture: rimap_core::Posture,
    },
    /// A folder appears in both `protected_folders` and `expunge_folders`.
    #[error(
        "folder `{folder}` is in both protected_folders and expunge_folders; \
         a folder cannot be both protected and expungeable"
    )]
    ConflictingFolders {
        /// The conflicting folder name.
        folder: String,
    },
    /// SMTP encryption set to "none" for a non-localhost host.
    #[error(
        "smtp encryption is 'none' for host `{host}`; \
         plaintext SMTP exposes credentials on the network"
    )]
    SmtpPlaintextDenied {
        /// The configured SMTP host.
        host: String,
    },
    /// Two accounts share the same name.
    #[error("duplicate account name `{name}`")]
    DuplicateAccountName {
        /// The duplicated name.
        name: String,
    },
    /// Config file contains both legacy `[imap]` and multi-account
    /// `[[accounts]]` sections.
    #[error(
        "config contains both [imap] and [[accounts]]; \
         use one format or the other, not both"
    )]
    MixedConfigFormat,
    /// Account name failed validation.
    #[error(transparent)]
    InvalidAccountName(#[from] InvalidAccountName),
    /// Multi-account config has an empty `[[accounts]]` array.
    ///
    /// Codex adversarial review (PR #270, 2026-05-12) flagged that
    /// silently accepting empty-accounts configs in production makes
    /// broken deployments look identical to healthy zero-data servers.
    /// The check stays in production; tests opt in via
    /// [`crate::validate::validate_multi_allowing_empty`] behind the
    /// `test-support` feature.
    #[error("no accounts defined in [[accounts]] array")]
    NoAccounts,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_credential_display_omits_username() {
        let err = ConfigError::NoCredential {
            host: "mail.example.com".to_string(),
            account_tag: "deadbeefcafef00d".to_string(),
            reason: "nothing in keyring".to_string(),
        };
        let display = format!("{err}");
        let full = format!("{err:#}");
        assert!(
            !display.contains("alice"),
            "display leaked username: {display}"
        );
        assert!(
            !full.contains("alice"),
            "full chain leaked username: {full}"
        );
        assert!(display.contains("mail.example.com"));
        assert!(display.contains("deadbeefcafef00d"));
    }

    #[test]
    fn keychain_display_omits_username() {
        let err = ConfigError::Keychain {
            host: "mail.example.com".to_string(),
            account_tag: "deadbeefcafef00d".to_string(),
            source: "underlying kernel error for alice@something".into(),
        };
        let display = format!("{err}");
        assert!(
            !display.contains("alice"),
            "display leaked username: {display}"
        );
        assert!(display.contains("mail.example.com"));
        assert!(display.contains("deadbeefcafef00d"));
    }
}
