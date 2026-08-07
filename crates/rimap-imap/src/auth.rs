//! Builders that translate connect-flow outcomes into
//! [`rimap_core::AuthEvent`] records. Pure functions — no I/O, no
//! audit emission. The caller (`connection.rs`) hands the result to
//! [`rimap_core::auth_sink::AuthEventSink::emit_auth`].

use rimap_core::TlsFingerprint;
use rimap_core::auth_event::{AuthEvent, AuthResult};

/// Inputs every `Auth` record needs.
pub(crate) struct AuthContext<'a> {
    /// Account name this auth attempt belongs to. `None` for legacy
    /// single-account deployments; `Some(name)` in multi-account configs.
    pub account: Option<&'a str>,
    /// IMAP server host.
    pub host: &'a str,
    /// IMAP server port.
    pub port: u16,
    /// IMAP login identity (never a password).
    pub username: &'a str,
    /// Configured pinned fingerprint, if any.
    pub pinned: Option<TlsFingerprint>,
    /// Fingerprint the server actually presented, if handshake reached cert verification.
    pub observed: Option<TlsFingerprint>,
    /// Source of the resolved credential. `None` before `resolve_credential`
    /// runs (e.g. a TLS failure) or when resolution itself failed.
    pub credential_source: Option<rimap_core::CredentialSource>,
}

impl AuthContext<'_> {
    fn fingerprint_match(&self) -> Option<bool> {
        match (self.pinned, self.observed) {
            (Some(p), Some(o)) => Some(p == o),
            (Some(_) | None, None) | (None, Some(_)) => None,
        }
    }

    fn observed_hex(&self) -> Option<String> {
        self.observed.map(|f| f.to_hex())
    }

    /// The parts of an [`AuthEvent`] that do not depend on the outcome.
    ///
    /// `AuthEvent` is `#[non_exhaustive]` (#716), so a struct literal is not
    /// available from this crate — functional update included (E0639). The
    /// constructor takes every field a reader of the trail draws a conclusion
    /// from; `account` is the operator label it leaves to assignment.
    ///
    /// The two `Host` / `Username` wraps below are the whole process's only
    /// `String` → newtype boundary for these two values (#748), and the one
    /// place left where a transposition is expressible. Everything downstream
    /// of here is type-checked; everything upstream reaches `AuthContext`
    /// through a named struct literal, where a transposition is not
    /// expressible either. `context_fields_land_on_the_event_fields_they_name`
    /// below pins these two lines.
    fn event(&self, result: AuthResult, error_code: Option<rimap_core::ErrorCode>) -> AuthEvent {
        let mut event = AuthEvent::new(
            result,
            rimap_core::Host(self.host.to_string()),
            self.port,
            rimap_core::Username(self.username.to_string()),
            self.observed_hex(),
            self.fingerprint_match(),
            error_code,
            self.credential_source,
        );
        event.account = self.account.map(str::to_string);
        event
    }
}

/// Build a successful [`AuthEvent`] record.
pub(crate) fn auth_success(ctx: &AuthContext<'_>) -> AuthEvent {
    ctx.event(AuthResult::Success, None)
}

/// Build a failure [`AuthEvent`] record carrying the stable error code.
pub(crate) fn auth_failure(ctx: &AuthContext<'_>, error_code: rimap_core::ErrorCode) -> AuthEvent {
    ctx.event(AuthResult::Failure, Some(error_code))
}

#[cfg(test)]
mod tests {
    use super::{AuthContext, auth_failure, auth_success};
    use rimap_core::TlsFingerprint;
    use rimap_core::auth_event::AuthResult;

    fn fp(seed: &[u8]) -> TlsFingerprint {
        TlsFingerprint::from_cert_der(seed)
    }

    /// Every `AuthContext` field has to land on the `AuthEvent` field of the
    /// same name. Since #716 the mapping runs through `AuthEvent::new`'s
    /// positional parameters; since #748 those are `Host` and `Username`, so
    /// a transposed *argument* no longer compiles. What is still expressible
    /// is a transposed `Host(self.username…)` **wrap**, one line up — so each
    /// value here names its own field, and this test is what reads those two
    /// wraps. `account` is checked separately because it is the one field the
    /// constructor does not take and the builder assigns afterwards.
    ///
    /// Both builders are exercised: they share `AuthContext::event`, so a
    /// mapping defect would reach every `auth` record the process writes, and
    /// only the `result`/`error_code` pair differs between them.
    #[test]
    fn context_fields_land_on_the_event_fields_they_name() {
        let ctx = AuthContext {
            account: Some("ACCOUNT-goes-here"),
            host: "HOST-goes-here",
            port: 1993,
            username: "USERNAME-goes-here",
            pinned: None,
            observed: None,
            credential_source: Some(rimap_core::CredentialSource::EnvVar),
        };

        for rec in [
            auth_success(&ctx),
            auth_failure(&ctx, rimap_core::ErrorCode::Auth),
        ] {
            assert_eq!(rec.account.as_deref(), Some("ACCOUNT-goes-here"));
            assert_eq!(rec.host.0, "HOST-goes-here");
            assert_eq!(rec.username.0, "USERNAME-goes-here");
            assert_eq!(rec.port, 1993);
            assert_eq!(
                rec.credential_source,
                Some(rimap_core::CredentialSource::EnvVar),
                "the resolved credential source must reach the record",
            );
        }

        assert_eq!(auth_success(&ctx).result, AuthResult::Success);
        assert_eq!(auth_success(&ctx).error_code, None);
        assert_eq!(
            auth_failure(&ctx, rimap_core::ErrorCode::Auth).result,
            AuthResult::Failure,
        );
        assert_eq!(
            auth_failure(&ctx, rimap_core::ErrorCode::Auth).error_code,
            Some(rimap_core::ErrorCode::Auth),
        );
    }

    #[test]
    fn success_with_matching_fingerprint() {
        let pin = fp(b"good");
        let ctx = AuthContext {
            account: None,
            host: "h",
            port: 993,
            username: "u",
            pinned: Some(pin),
            observed: Some(pin),
            credential_source: None,
        };
        let rec = auth_success(&ctx);
        assert_eq!(rec.result, AuthResult::Success);
        assert_eq!(rec.fingerprint_match, Some(true));
        assert_eq!(rec.tls_fingerprint_sha256, Some(pin.to_hex()));
        assert!(rec.error_code.is_none());
    }

    #[test]
    fn failure_with_mismatched_fingerprint() {
        let pin = fp(b"good");
        let observed = fp(b"bad");
        let ctx = AuthContext {
            account: None,
            host: "h",
            port: 993,
            username: "u",
            pinned: Some(pin),
            observed: Some(observed),
            credential_source: None,
        };
        let rec = auth_failure(&ctx, rimap_core::ErrorCode::Tls);
        assert_eq!(rec.result, AuthResult::Failure);
        assert_eq!(rec.fingerprint_match, Some(false));
        assert_eq!(rec.error_code, Some(rimap_core::ErrorCode::Tls));
    }

    #[test]
    fn unpinned_observed_yields_none_match() {
        let observed = fp(b"x");
        let ctx = AuthContext {
            account: None,
            host: "h",
            port: 993,
            username: "u",
            pinned: None,
            observed: Some(observed),
            credential_source: None,
        };
        let rec = auth_success(&ctx);
        assert_eq!(rec.fingerprint_match, None);
        assert!(rec.tls_fingerprint_sha256.is_some());
    }

    #[test]
    fn pinned_with_no_observation_yields_no_fingerprint() {
        // The handshake aborted before the verifier ran (e.g., TCP RST
        // mid-TLS), so we have a pin but never captured a fingerprint.
        // The audit record must carry no fingerprint hex and no match
        // verdict — recording stale data here would mislead operators.
        let pin = fp(b"good");
        let ctx = AuthContext {
            account: None,
            host: "h",
            port: 993,
            username: "u",
            pinned: Some(pin),
            observed: None,
            credential_source: None,
        };
        let rec = auth_failure(&ctx, rimap_core::ErrorCode::ConnectionLost);
        assert_eq!(rec.result, AuthResult::Failure);
        assert_eq!(rec.tls_fingerprint_sha256, None);
        assert_eq!(rec.fingerprint_match, None);
        assert_eq!(rec.error_code, Some(rimap_core::ErrorCode::ConnectionLost));
    }
}
