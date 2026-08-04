//! Numeric-limits and timeout validation. New positive-integer fields get
//! a row in the zero-check table for their config block rather than
//! another `if` block.

use crate::error::ConfigError;
use crate::model::{ImapConfig, LimitsConfig, SmtpConfig};

/// Accessor reading one positive-integer field off a config block `T`.
type ZeroAccessor<T> = fn(&T) -> u64;

/// Reject the first field in `checks` whose accessor reads zero.
fn reject_zero<T>(
    block: &T,
    checks: &[(&'static str, ZeroAccessor<T>)],
) -> Result<(), ConfigError> {
    for (field, accessor) in checks {
        if accessor(block) == 0 {
            return Err(ConfigError::InvalidLimit {
                field,
                reason: "must be > 0".to_string(),
            });
        }
    }
    Ok(())
}

/// Reject zero-second timeouts on `[imap]` and, when present, `[smtp]`.
///
/// A zero budget is not "unlimited": it makes every `timeout()` around a
/// connect or command elapse immediately, so the account is permanently
/// unusable and fails as a network error rather than a config error
/// (#593).
pub(super) fn validate_timeouts(
    imap: &ImapConfig,
    smtp: Option<&SmtpConfig>,
) -> Result<(), ConfigError> {
    /// Zero-check table for `[imap]` timeouts.
    const IMAP_CHECKS: &[(&str, ZeroAccessor<ImapConfig>)] = &[
        ("imap.command_timeout_seconds", |i| {
            u64::from(i.command_timeout_seconds)
        }),
        ("imap.connect_timeout_seconds", |i| {
            u64::from(i.connect_timeout_seconds)
        }),
    ];
    /// Zero-check table for `[smtp]` timeouts.
    const SMTP_CHECKS: &[(&str, ZeroAccessor<SmtpConfig>)] =
        &[("smtp.command_timeout_seconds", |s| {
            u64::from(s.command_timeout_seconds)
        })];

    reject_zero(imap, IMAP_CHECKS)?;
    if let Some(smtp) = smtp {
        reject_zero(smtp, SMTP_CHECKS)?;
    }
    Ok(())
}

pub(super) fn validate_limits(limits: &LimitsConfig) -> Result<(), ConfigError> {
    /// Table of `(field_name, accessor)` for zero-value checks. New limits
    /// that must be `> 0` get added here rather than as another `if` block.
    const ZERO_CHECKS: &[(&str, ZeroAccessor<LimitsConfig>)] = &[
        ("limits.commands_per_second", |l| {
            u64::from(l.commands_per_second)
        }),
        ("limits.drafts_per_minute", |l| {
            u64::from(l.drafts_per_minute)
        }),
        ("limits.sends_per_minute", |l| u64::from(l.sends_per_minute)),
        ("limits.circuit_breaker_error_threshold", |l| {
            u64::from(l.circuit_breaker_error_threshold)
        }),
        ("limits.circuit_breaker_window_seconds", |l| {
            u64::from(l.circuit_breaker_window_seconds)
        }),
        ("limits.max_search_results", |l| {
            u64::from(l.max_search_results)
        }),
        ("limits.max_fetch_body_bytes", |l| l.max_fetch_body_bytes),
        ("limits.max_attachment_bytes", |l| l.max_attachment_bytes),
        ("limits.max_append_bytes", |l| l.max_append_bytes),
    ];
    reject_zero(limits, ZERO_CHECKS)?;
    if limits.max_search_results > limits.max_search_results_cap {
        return Err(ConfigError::InvalidLimit {
            field: "limits.max_search_results",
            reason: format!(
                "default {} exceeds cap {}",
                limits.max_search_results, limits.max_search_results_cap
            ),
        });
    }
    Ok(())
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
#[expect(clippy::panic, reason = "test failure paths")]
mod tests {
    use super::*;

    #[test]
    fn defaults_pass() {
        let limits = LimitsConfig::default();
        assert!(validate_limits(&limits).is_ok());
    }

    #[test]
    fn zero_commands_per_second_rejected() {
        let limits = LimitsConfig {
            commands_per_second: 0,
            ..LimitsConfig::default()
        };
        let err = validate_limits(&limits).unwrap_err();
        assert!(
            matches!(&err, ConfigError::InvalidLimit { field, .. } if *field == "limits.commands_per_second")
        );
    }

    #[test]
    fn zero_max_append_bytes_rejected() {
        let limits = LimitsConfig {
            max_append_bytes: 0,
            ..LimitsConfig::default()
        };
        let err = validate_limits(&limits).unwrap_err();
        assert!(
            matches!(&err, ConfigError::InvalidLimit { field, .. } if *field == "limits.max_append_bytes")
        );
    }

    #[test]
    fn max_search_results_above_cap_rejected() {
        let base = LimitsConfig::default();
        let limits = LimitsConfig {
            max_search_results: base.max_search_results_cap + 1,
            ..base
        };
        let err = validate_limits(&limits).unwrap_err();
        let ConfigError::InvalidLimit { field, reason } = &err else {
            panic!("expected InvalidLimit, got {err:?}");
        };
        assert_eq!(*field, "limits.max_search_results");
        assert!(reason.contains("exceeds cap"));
    }

    #[test]
    fn max_search_results_at_cap_accepted() {
        let base = LimitsConfig::default();
        let limits = LimitsConfig {
            max_search_results: base.max_search_results_cap,
            ..base
        };
        assert!(validate_limits(&limits).is_ok());
    }

    /// `[imap]` block carrying the serde-supplied timeout defaults.
    fn imap_config() -> ImapConfig {
        toml::from_str(
            r#"
host = "imap.example.test"
port = 993
username = "alice@example.test"
"#,
        )
        .unwrap()
    }

    /// `[smtp]` block carrying the serde-supplied timeout default.
    fn smtp_config() -> SmtpConfig {
        toml::from_str(
            r#"
host = "smtp.example.test"
port = 587
encryption = "starttls"
username = "alice@example.test"
"#,
        )
        .unwrap()
    }

    #[test]
    fn shipped_timeout_defaults_pass() {
        let imap = imap_config();
        assert_eq!(imap.command_timeout_seconds, 30);
        assert_eq!(imap.connect_timeout_seconds, 10);
        let smtp = smtp_config();
        assert_eq!(smtp.command_timeout_seconds, 30);
        assert!(validate_timeouts(&imap, Some(&smtp)).is_ok());
    }

    #[test]
    fn absent_smtp_block_passes() {
        assert!(validate_timeouts(&imap_config(), None).is_ok());
    }

    #[test]
    fn zero_imap_connect_timeout_rejected() {
        let imap = ImapConfig {
            connect_timeout_seconds: 0,
            ..imap_config()
        };
        let err = validate_timeouts(&imap, None).unwrap_err();
        assert!(
            matches!(&err, ConfigError::InvalidLimit { field, .. } if *field == "imap.connect_timeout_seconds"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn zero_imap_command_timeout_rejected() {
        let imap = ImapConfig {
            command_timeout_seconds: 0,
            ..imap_config()
        };
        let err = validate_timeouts(&imap, None).unwrap_err();
        assert!(
            matches!(&err, ConfigError::InvalidLimit { field, .. } if *field == "imap.command_timeout_seconds"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn zero_smtp_command_timeout_rejected() {
        let smtp = SmtpConfig {
            command_timeout_seconds: 0,
            ..smtp_config()
        };
        let err = validate_timeouts(&imap_config(), Some(&smtp)).unwrap_err();
        assert!(
            matches!(&err, ConfigError::InvalidLimit { field, .. } if *field == "smtp.command_timeout_seconds"),
            "unexpected error: {err:?}"
        );
    }
}
