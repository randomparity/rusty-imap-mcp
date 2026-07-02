//! Domain rules: folder-list safety, SMTP requirement and encryption,
//! per-tool override resolution.

use std::collections::BTreeMap;
use std::str::FromStr;

use rimap_core::tool::ToolName;

use crate::error::ConfigError;
use crate::model::{SecurityConfig, SmtpConfig, SmtpEncryption, Verdict};

pub(super) fn validate_folder_safety(security: &SecurityConfig) -> Result<(), ConfigError> {
    let mut protected: Vec<String> = security
        .protected_folders
        .iter()
        .map(|f| utf7_imap::decode_utf7_imap(f.clone()).to_lowercase())
        .collect();
    protected.push("inbox".to_string());

    for folder in &security.expunge_folders {
        let norm = utf7_imap::decode_utf7_imap(folder.clone()).to_lowercase();
        if protected.contains(&norm) {
            return Err(ConfigError::ConflictingFolders {
                folder: folder.clone(),
            });
        }
    }
    Ok(())
}

pub(super) fn validate_smtp_required(
    security: &SecurityConfig,
    tool_overrides: &BTreeMap<ToolName, Verdict>,
    smtp: Option<&SmtpConfig>,
) -> Result<(), ConfigError> {
    let posture = security.posture;
    let send_email_base = rimap_core::base_allows(posture, ToolName::SendEmail);
    let override_verdict = tool_overrides.get(&ToolName::SendEmail);
    let send_email_effective = match override_verdict {
        Some(Verdict::Allow) => true,
        Some(Verdict::Deny) => false,
        None => send_email_base,
    };
    if send_email_effective && smtp.is_none() {
        // Attribute the requirement to its real cause: an explicit `allow`
        // override enables send_email only where the posture itself does not.
        let enabled_by_override = !send_email_base && override_verdict == Some(&Verdict::Allow);
        return Err(if enabled_by_override {
            ConfigError::SmtpRequiredByOverride { posture }
        } else {
            ConfigError::SmtpRequired { posture }
        });
    }
    Ok(())
}

pub(super) fn validate_smtp_encryption(smtp: Option<&SmtpConfig>) -> Result<(), ConfigError> {
    let Some(smtp) = smtp else {
        return Ok(());
    };
    if smtp.encryption == SmtpEncryption::None {
        let host = &smtp.host;
        let is_localhost = host == "localhost" || host == "127.0.0.1" || host == "::1";
        if !is_localhost {
            return Err(ConfigError::SmtpPlaintextDenied { host: host.clone() });
        }
    }
    Ok(())
}

pub(super) fn resolve_tool_overrides(
    security: &SecurityConfig,
) -> Result<BTreeMap<ToolName, Verdict>, ConfigError> {
    let mut out = BTreeMap::new();
    for (name, verdict) in &security.tools {
        let tool = ToolName::from_str(name)?;
        out.insert(tool, *verdict);
    }
    Ok(out)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;
    use crate::model::SmtpEncryption;
    use rimap_core::Posture;

    fn security_with(protected: &[&str], expunge: &[&str]) -> SecurityConfig {
        SecurityConfig {
            protected_folders: protected.iter().map(|x| (*x).to_string()).collect(),
            expunge_folders: expunge.iter().map(|x| (*x).to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn folder_safety_inbox_always_protected() {
        let s = security_with(&[], &["INBOX"]);
        let err = validate_folder_safety(&s).unwrap_err();
        assert!(matches!(err, ConfigError::ConflictingFolders { .. }));
    }

    #[test]
    fn folder_safety_matches_case_insensitively() {
        let s = security_with(&["Sent"], &["sent"]);
        let err = validate_folder_safety(&s).unwrap_err();
        assert!(matches!(err, ConfigError::ConflictingFolders { folder } if folder == "sent"));
    }

    #[test]
    fn folder_safety_no_conflict_passes() {
        let s = security_with(&["Sent", "Drafts"], &["Trash"]);
        assert!(validate_folder_safety(&s).is_ok());
    }

    fn security_with_posture(posture: Posture) -> SecurityConfig {
        SecurityConfig {
            posture,
            ..Default::default()
        }
    }

    #[test]
    fn smtp_required_when_send_email_allowed_by_posture() {
        let s = security_with_posture(Posture::Full);
        let overrides = BTreeMap::new();
        let err = validate_smtp_required(&s, &overrides, None).unwrap_err();
        assert!(matches!(err, ConfigError::SmtpRequired { .. }));
    }

    #[test]
    fn smtp_required_passes_when_smtp_present() {
        let s = security_with_posture(Posture::Full);
        let overrides = BTreeMap::new();
        let smtp = SmtpConfig {
            host: "smtp.example.com".to_string(),
            port: 587,
            encryption: SmtpEncryption::Starttls,
            username: "u".to_string(),
            command_timeout_seconds: 30,
        };
        assert!(validate_smtp_required(&s, &overrides, Some(&smtp)).is_ok());
    }

    #[test]
    fn smtp_required_satisfied_when_override_denies_send_email() {
        let s = security_with_posture(Posture::Full);
        let mut overrides = BTreeMap::new();
        overrides.insert(ToolName::SendEmail, Verdict::Deny);
        assert!(validate_smtp_required(&s, &overrides, None).is_ok());
    }

    #[test]
    fn smtp_required_by_posture_blames_the_posture() {
        // A posture that base-allows send_email (full/destructive) is the
        // genuine cause; the message must attribute it to the posture.
        let s = security_with_posture(Posture::Full);
        let overrides = BTreeMap::new();
        let err = validate_smtp_required(&s, &overrides, None).unwrap_err();
        assert!(matches!(err, ConfigError::SmtpRequired { .. }));
        let msg = err.to_string();
        assert!(
            msg.contains("full"),
            "message should name the posture: {msg}"
        );
    }

    #[test]
    fn smtp_required_by_override_blames_the_override_not_the_posture() {
        // Regression (#327): readonly/draft-safe never base-allow send_email,
        // so an explicit `send_email = "allow"` override is the real cause.
        // The diagnostic must say so instead of blaming the posture.
        for posture in [Posture::Readonly, Posture::DraftSafe] {
            let s = security_with_posture(posture);
            let mut overrides = BTreeMap::new();
            overrides.insert(ToolName::SendEmail, Verdict::Allow);
            let err = validate_smtp_required(&s, &overrides, None).unwrap_err();
            assert!(
                matches!(err, ConfigError::SmtpRequiredByOverride { posture: p } if p == posture),
                "expected SmtpRequiredByOverride for {posture}, got {err:?}",
            );
            let msg = err.to_string();
            assert!(
                msg.contains("override"),
                "message should name the override: {msg}"
            );
            assert!(
                msg.contains(posture.as_str()),
                "message should name the posture that does not enable it: {msg}",
            );
        }
    }

    #[test]
    fn redundant_allow_override_on_enabling_posture_stays_posture_blamed() {
        // A `send_email = "allow"` override on a posture that already
        // base-allows it is redundant; the posture is still the cause.
        let s = security_with_posture(Posture::Full);
        let mut overrides = BTreeMap::new();
        overrides.insert(ToolName::SendEmail, Verdict::Allow);
        let err = validate_smtp_required(&s, &overrides, None).unwrap_err();
        assert!(
            matches!(err, ConfigError::SmtpRequired { .. }),
            "redundant override should stay posture-blamed, got {err:?}",
        );
    }

    #[test]
    fn smtp_plaintext_denied_for_non_localhost() {
        let smtp = SmtpConfig {
            host: "remote.example.com".to_string(),
            port: 25,
            encryption: SmtpEncryption::None,
            username: "u".to_string(),
            command_timeout_seconds: 30,
        };
        let err = validate_smtp_encryption(Some(&smtp)).unwrap_err();
        assert!(matches!(err, ConfigError::SmtpPlaintextDenied { .. }));
    }

    #[test]
    fn smtp_plaintext_allowed_for_localhost() {
        for host in ["localhost", "127.0.0.1", "::1"] {
            let smtp = SmtpConfig {
                host: host.to_string(),
                port: 25,
                encryption: SmtpEncryption::None,
                username: "u".to_string(),
                command_timeout_seconds: 30,
            };
            assert!(
                validate_smtp_encryption(Some(&smtp)).is_ok(),
                "plaintext to {host} must be allowed"
            );
        }
    }

    #[test]
    fn smtp_encryption_none_smtp_passes() {
        assert!(validate_smtp_encryption(None).is_ok());
    }

    #[test]
    fn resolve_tool_overrides_rejects_unknown_tool() {
        let mut tools = std::collections::BTreeMap::new();
        tools.insert("not_a_real_tool".to_string(), Verdict::Allow);
        let s = SecurityConfig {
            tools,
            ..Default::default()
        };
        assert!(resolve_tool_overrides(&s).is_err());
    }

    #[test]
    fn resolve_tool_overrides_maps_valid_tools() {
        let mut tools = std::collections::BTreeMap::new();
        tools.insert("send_email".to_string(), Verdict::Deny);
        tools.insert("search".to_string(), Verdict::Allow);
        let s = SecurityConfig {
            tools,
            ..Default::default()
        };
        let out = resolve_tool_overrides(&s).unwrap();
        assert_eq!(out.get(&ToolName::SendEmail).copied(), Some(Verdict::Deny));
        assert_eq!(out.get(&ToolName::Search).copied(), Some(Verdict::Allow));
    }
}
