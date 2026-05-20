//! Identity-shaped checks: username sanity and TLS fingerprint parsing.

use rimap_core::tls::TlsFingerprint;

use crate::error::ConfigError;

pub(super) fn validate_imap_username(username: &str) -> Result<(), ConfigError> {
    validate_username_field(username, "imap.username")
}

pub(super) fn validate_smtp_username(username: &str) -> Result<(), ConfigError> {
    validate_username_field(username, "smtp.username")
}

fn validate_username_field(username: &str, field: &'static str) -> Result<(), ConfigError> {
    if username.is_empty() {
        return Err(ConfigError::InvalidLimit {
            field,
            reason: "username must not be empty".to_string(),
        });
    }
    if username
        .chars()
        .any(|c| c == '\r' || c == '\n' || c == '\0')
    {
        return Err(ConfigError::InvalidLimit {
            field,
            reason: "username must not contain CR, LF, or NUL".to_string(),
        });
    }
    Ok(())
}

pub(super) fn parse_fingerprint(
    maybe_fp: Option<&str>,
) -> Result<Option<TlsFingerprint>, ConfigError> {
    let Some(raw) = maybe_fp else {
        return Ok(None);
    };
    let fp = TlsFingerprint::from_hex(raw).map_err(|e| ConfigError::TlsFingerprint {
        reason: e.to_string(),
    })?;
    Ok(Some(fp))
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn imap_username_rejects_empty() {
        let err = validate_imap_username("").unwrap_err();
        assert!(matches!(err, ConfigError::InvalidLimit { field, .. } if field == "imap.username"));
    }

    #[test]
    fn smtp_username_rejects_empty() {
        let err = validate_smtp_username("").unwrap_err();
        assert!(matches!(err, ConfigError::InvalidLimit { field, .. } if field == "smtp.username"));
    }

    #[test]
    fn imap_username_rejects_crlf_and_nul() {
        for bad in [
            "alice\r@example.com",
            "alice\n@example.com",
            "alice\0@example.com",
        ] {
            let err = validate_imap_username(bad).unwrap_err();
            assert!(
                matches!(&err, ConfigError::InvalidLimit { field, reason } if *field == "imap.username" && reason.contains("CR")),
                "expected CR/LF/NUL rejection for {bad:?}, got: {err:?}",
            );
        }
    }

    #[test]
    fn smtp_username_rejects_crlf_and_nul() {
        for bad in [
            "bob\r@example.com",
            "bob\n@example.com",
            "bob\0@example.com",
        ] {
            let err = validate_smtp_username(bad).unwrap_err();
            assert!(
                matches!(&err, ConfigError::InvalidLimit { field, reason } if *field == "smtp.username" && reason.contains("CR")),
                "expected CR/LF/NUL rejection for {bad:?}, got: {err:?}",
            );
        }
    }

    #[test]
    fn imap_username_accepts_well_formed() {
        assert!(validate_imap_username("alice@example.com").is_ok());
        assert!(validate_imap_username("user.name+tag@host").is_ok());
    }

    #[test]
    fn smtp_username_accepts_well_formed() {
        assert!(validate_smtp_username("bob@example.com").is_ok());
    }

    #[test]
    fn parse_fingerprint_none_passthrough() {
        assert!(parse_fingerprint(None).unwrap().is_none());
    }

    #[test]
    fn parse_fingerprint_accepts_valid_hex() {
        let hex = "a".repeat(64);
        assert!(parse_fingerprint(Some(&hex)).unwrap().is_some());
    }

    #[test]
    fn parse_fingerprint_rejects_short_hex() {
        let err = parse_fingerprint(Some("ab")).unwrap_err();
        assert!(matches!(err, ConfigError::TlsFingerprint { .. }));
    }

    #[test]
    fn parse_fingerprint_rejects_non_hex() {
        let err = parse_fingerprint(Some(&"z".repeat(64))).unwrap_err();
        assert!(matches!(err, ConfigError::TlsFingerprint { .. }));
    }
}
