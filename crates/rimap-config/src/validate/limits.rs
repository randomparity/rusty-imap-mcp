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

/// Longest one IMAP operation can run while every `[imap]` deadline is
/// still honouring it, as `rimap_imap::connection::dispatch` spends the
/// budgets: each `attempt` waits up to `command_timeout` for the session
/// lock, then up to `connect_timeout` on the lazy connect (which runs
/// outside the command deadline by design — #592), then up to
/// `command_timeout` on the command body; `with_session` runs a second
/// `attempt` when a read-only op fails with `ConnectionLost`.
///
/// This covers the *deadline-bounded* stages only. A few awaits on the
/// same path carry no deadline of their own — `with_session`'s
/// `invalidate()` parks on the session lock, and `connect_inner`'s
/// `emit_auth` runs an audit write outside the connect deadline — so a
/// ceiling set exactly at this value still has no slack for them. It is
/// a floor for the validation below, not a promise about wall clock.
///
/// Computed in `u64` so `u32::MAX` budgets cannot wrap into a value that
/// passes the comparison in [`validate_tool_call_ceiling`].
fn imap_operation_bounded_seconds(imap: &ImapConfig) -> u64 {
    const ATTEMPTS: u64 = 2;
    const COMMAND_STAGES_PER_ATTEMPT: u64 = 2;
    COMMAND_STAGES_PER_ATTEMPT
        .saturating_mul(u64::from(imap.command_timeout_seconds))
        .saturating_add(u64::from(imap.connect_timeout_seconds))
        .saturating_mul(ATTEMPTS)
}

/// Reject a per-tool-call ceiling that cannot cover the longest tool call
/// every per-stage deadline still considers healthy (#594, ADR-0012).
///
/// The `[smtp]` term is what keeps `send_email` safe. It sends over SMTP
/// and *then* appends the message to the Sent folder — a full IMAP
/// operation — so a ceiling that fits the append but not the send ahead
/// of it could cut the call after delivery already happened, reporting
/// `ERR_TIMEOUT` for a message that went out. Requiring the ceiling to
/// cover `smtp.command_timeout_seconds + imap_operation_bounded_seconds`
/// keeps that out of reach for a send whose pre-send work is negligible.
/// It is not an absolute guarantee: `send_email` builds the message —
/// reading up to `MAX_ATTACHMENTS` files from disk — before `send_raw`,
/// and that read carries no deadline of its own, so it is not in this
/// minimum.
///
/// Failing here is a startup error rather than an intermittent runtime
/// one. All three blocks resolve per account, so this is checked per
/// account.
pub(super) fn validate_tool_call_ceiling(
    imap: &ImapConfig,
    smtp: Option<&SmtpConfig>,
    limits: &LimitsConfig,
) -> Result<(), ConfigError> {
    let imap_seconds = imap_operation_bounded_seconds(imap);
    let smtp_seconds = smtp.map_or(0, |s| u64::from(s.command_timeout_seconds));
    let minimum = imap_seconds.saturating_add(smtp_seconds);
    if u64::from(limits.tool_call_timeout_seconds) >= minimum {
        return Ok(());
    }
    let smtp_term = match smtp {
        Some(s) => format!(
            " + smtp.command_timeout_seconds {}s for the send that precedes \
             the Sent-folder append",
            s.command_timeout_seconds,
        ),
        None => String::new(),
    };
    Err(ConfigError::InvalidLimit {
        field: "limits.tool_call_timeout_seconds",
        reason: format!(
            "{}s is below the {minimum}s a tool call can take with every \
             per-stage deadline still honouring it (2 attempts x (2 x \
             imap.command_timeout_seconds {}s + imap.connect_timeout_seconds \
             {}s){smtp_term}); raise the ceiling or lower the per-stage timeouts",
            limits.tool_call_timeout_seconds,
            imap.command_timeout_seconds,
            imap.connect_timeout_seconds,
        ),
    })
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
        ("limits.tool_call_timeout_seconds", |l| {
            u64::from(l.tool_call_timeout_seconds)
        }),
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
    fn shipped_ceiling_default_covers_shipped_timeout_defaults() {
        // The stock config must not self-reject: 300 >= 2 x (2 x 30 + 10).
        let imap = imap_config();
        let limits = LimitsConfig::default();
        assert_eq!(limits.tool_call_timeout_seconds, 300);
        assert!(validate_tool_call_ceiling(&imap, None, &limits).is_ok());
    }

    #[test]
    fn ceiling_exactly_at_worst_case_accepted() {
        let imap = imap_config();
        let limits = LimitsConfig {
            tool_call_timeout_seconds: 140,
            ..LimitsConfig::default()
        };
        assert!(validate_tool_call_ceiling(&imap, None, &limits).is_ok());
    }

    #[test]
    fn ceiling_below_worst_case_rejected_naming_the_arithmetic() {
        let imap = imap_config();
        let limits = LimitsConfig {
            tool_call_timeout_seconds: 139,
            ..LimitsConfig::default()
        };
        let err = validate_tool_call_ceiling(&imap, None, &limits).unwrap_err();
        let ConfigError::InvalidLimit { field, reason } = &err else {
            panic!("expected InvalidLimit, got {err:?}");
        };
        assert_eq!(*field, "limits.tool_call_timeout_seconds");
        assert!(
            reason.contains("140"),
            "reason must state the minimum: {reason}"
        );
        assert!(
            reason.contains("command_timeout_seconds")
                && reason.contains("connect_timeout_seconds"),
            "reason must name both IMAP budgets: {reason}",
        );
    }

    #[test]
    fn raised_command_timeout_requires_a_raised_ceiling() {
        // 2 x (2 x 120 + 10) = 500 > the 300s default, so the stock ceiling
        // no longer covers a single operation and the config is rejected.
        let imap = ImapConfig {
            command_timeout_seconds: 120,
            ..imap_config()
        };
        let limits = LimitsConfig::default();
        let err = validate_tool_call_ceiling(&imap, None, &limits).unwrap_err();
        assert!(
            matches!(&err, ConfigError::InvalidLimit { field, .. } if *field == "limits.tool_call_timeout_seconds"),
            "unexpected error: {err:?}",
        );
    }

    #[test]
    fn smtp_send_budget_is_added_to_the_minimum() {
        // `send_email` sends over SMTP and then appends to Sent, so the
        // ceiling has to cover both or a fired ceiling could report
        // ERR_TIMEOUT for a message that was already delivered. 140 alone
        // passes without an [smtp] block and must not with one.
        let imap = imap_config();
        let smtp = smtp_config();
        let limits = LimitsConfig {
            tool_call_timeout_seconds: 140,
            ..LimitsConfig::default()
        };
        assert!(validate_tool_call_ceiling(&imap, None, &limits).is_ok());

        let err = validate_tool_call_ceiling(&imap, Some(&smtp), &limits).unwrap_err();
        let ConfigError::InvalidLimit { field, reason } = &err else {
            panic!("expected InvalidLimit, got {err:?}");
        };
        assert_eq!(*field, "limits.tool_call_timeout_seconds");
        assert!(reason.contains("170"), "140 + smtp 30 = 170: {reason}");
        assert!(
            reason.contains("smtp.command_timeout_seconds"),
            "the reason must name the SMTP term it added: {reason}",
        );

        let ok = LimitsConfig {
            tool_call_timeout_seconds: 170,
            ..LimitsConfig::default()
        };
        assert!(validate_tool_call_ceiling(&imap, Some(&smtp), &ok).is_ok());
    }

    #[test]
    fn imap_only_reason_omits_the_smtp_term() {
        let imap = imap_config();
        let limits = LimitsConfig {
            tool_call_timeout_seconds: 139,
            ..LimitsConfig::default()
        };
        let err = validate_tool_call_ceiling(&imap, None, &limits).unwrap_err();
        let ConfigError::InvalidLimit { reason, .. } = &err else {
            panic!("expected InvalidLimit, got {err:?}");
        };
        assert!(
            !reason.contains("smtp."),
            "an account without [smtp] must not be told about an SMTP term: {reason}",
        );
    }

    #[test]
    fn worst_case_math_does_not_overflow_on_max_budgets() {
        // u32::MAX on both budgets must not wrap into a passing comparison.
        let imap = ImapConfig {
            command_timeout_seconds: u32::MAX,
            connect_timeout_seconds: u32::MAX,
            ..imap_config()
        };
        let limits = LimitsConfig {
            tool_call_timeout_seconds: u32::MAX,
            ..LimitsConfig::default()
        };
        assert!(validate_tool_call_ceiling(&imap, None, &limits).is_err());
    }

    #[test]
    fn zero_tool_call_timeout_rejected() {
        let limits = LimitsConfig {
            tool_call_timeout_seconds: 0,
            ..LimitsConfig::default()
        };
        let err = validate_limits(&limits).unwrap_err();
        assert!(
            matches!(&err, ConfigError::InvalidLimit { field, .. } if *field == "limits.tool_call_timeout_seconds"),
            "unexpected error: {err:?}",
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
