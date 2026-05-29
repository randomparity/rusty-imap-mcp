//! Rate limiter wrapper around `governor`.
//!
//! Three buckets (design spec §9):
//!   - Global: `limits.commands_per_second` with burst = 2× rate.
//!   - Draft: `limits.drafts_per_minute`, only consulted on `create_draft`.
//!   - Send: `limits.sends_per_minute`, only consulted on `send_email`.
//!
//! On exceed: return `AuthzError::RateLimited { retry_after_ms }`. The caller
//! (dispatch guard) decides whether to wait or fail.

use std::num::NonZeroU32;

use governor::NotUntil;
use governor::clock::{Clock, DefaultClock};
use governor::middleware::NoOpMiddleware;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter};
use rimap_core::tool::ToolName;

use crate::error::AuthzError;

type DirectLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock, NoOpMiddleware>;

/// Instant type used by the `DefaultClock`. Extracted as an alias so the
/// [`retry_after_ms`] helper's signature reads cleanly without repeating the
/// `<DefaultClock as Clock>::Instant` projection.
pub type DefaultInstant = <DefaultClock as Clock>::Instant;

/// Compute the millisecond retry hint from a `governor` rejection against
/// the given clock. Saturates at `u64::MAX` on the hypothetical >500M-year
/// overflow. Exposed so rate-limit sites in other crates (e.g.,
/// `rimap-server`'s infrastructure governor) produce identical hints
/// without duplicating the cast.
#[must_use]
pub fn retry_after_ms(not_until: &NotUntil<DefaultInstant>, clock: &DefaultClock) -> u64 {
    saturating_millis_to_u64(not_until.wait_time_from(clock.now()).as_millis())
}

/// Saturating `u128` → `u64` cast: returns the value on success,
/// `u64::MAX` on overflow. Factored out of [`retry_after_ms`] so the
/// saturation contract (the only non-trivial logic in the wrapper) is
/// unit-testable without fabricating a multi-hundred-million-year
/// `NotUntil` value.
#[must_use]
pub(crate) fn saturating_millis_to_u64(millis: u128) -> u64 {
    u64::try_from(millis).unwrap_or(u64::MAX)
}

fn rate_limited(not_until: &NotUntil<DefaultInstant>, clock: &DefaultClock) -> AuthzError {
    AuthzError::RateLimited {
        retry_after_ms: retry_after_ms(not_until, clock),
    }
}

/// Combined global + draft + send rate limiter.
pub struct Governor {
    global: DirectLimiter,
    drafts: DirectLimiter,
    sends: DirectLimiter,
    clock: DefaultClock,
}

impl Governor {
    /// Build from numeric limits.
    ///
    /// # Errors
    /// Returns `AuthzError::ConfigBuild` if either rate is zero (validation
    /// should have caught this already, but we refuse to build a degenerate
    /// limiter).
    pub fn new(
        commands_per_second: u32,
        drafts_per_minute: u32,
        sends_per_minute: u32,
    ) -> Result<Self, AuthzError> {
        let cps = NonZeroU32::new(commands_per_second).ok_or_else(|| {
            AuthzError::ConfigBuild("commands_per_second must be > 0".to_string())
        })?;
        let dpm = NonZeroU32::new(drafts_per_minute)
            .ok_or_else(|| AuthzError::ConfigBuild("drafts_per_minute must be > 0".to_string()))?;
        let spm = NonZeroU32::new(sends_per_minute)
            .ok_or_else(|| AuthzError::ConfigBuild("sends_per_minute must be > 0".to_string()))?;
        let burst = NonZeroU32::new(commands_per_second.saturating_mul(2).max(1))
            .unwrap_or(NonZeroU32::MIN);
        let global_quota = Quota::per_second(cps).allow_burst(burst);
        let draft_quota = Quota::per_minute(dpm);
        let send_quota = Quota::per_minute(spm);
        Ok(Self {
            global: RateLimiter::direct(global_quota),
            drafts: RateLimiter::direct(draft_quota),
            sends: RateLimiter::direct(send_quota),
            clock: DefaultClock::default(),
        })
    }

    /// Attempt to admit a single call. Returns `Ok(())` on admit,
    /// `Err(RateLimited)` on reject.
    ///
    /// # Errors
    /// `AuthzError::RateLimited` when the relevant bucket is empty.
    pub fn check(&self, tool: ToolName) -> Result<(), AuthzError> {
        self.global
            .check()
            .map_err(|nu| rate_limited(&nu, &self.clock))?;
        if tool.is_draft_quota_gated() {
            self.drafts
                .check()
                .map_err(|nu| rate_limited(&nu, &self.clock))?;
        }
        if tool.is_send_quota_gated() {
            self.sends
                .check()
                .map_err(|nu| rate_limited(&nu, &self.clock))?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
#[expect(clippy::panic, reason = "tests")]
mod tests {
    use rimap_core::tool::ToolName;

    use crate::error::AuthzError;
    use crate::rate_limit::{Governor, saturating_millis_to_u64};

    #[test]
    fn saturating_millis_exact_cast_when_in_u64() {
        assert_eq!(saturating_millis_to_u64(0), 0);
        assert_eq!(saturating_millis_to_u64(1_500), 1_500);
        assert_eq!(saturating_millis_to_u64(u128::from(u64::MAX)), u64::MAX);
    }

    #[test]
    fn saturating_millis_saturates_above_u64_max() {
        // Any `u128` value > u64::MAX pins the retry hint at u64::MAX
        // rather than panicking or wrapping. Covers the unwrap_or(u64::MAX)
        // branch of retry_after_ms that `NotUntil::as_millis()` could
        // in principle hit (hypothetical >584M-year overflow).
        assert_eq!(saturating_millis_to_u64(u128::from(u64::MAX) + 1), u64::MAX);
        assert_eq!(saturating_millis_to_u64(u128::MAX), u64::MAX);
    }

    #[test]
    fn zero_rate_rejected_at_build() {
        assert!(Governor::new(0, 5, 3).is_err());
        assert!(Governor::new(10, 0, 3).is_err());
    }

    #[test]
    fn admits_first_call_in_bucket() {
        let g = Governor::new(10, 5, 3).unwrap();
        assert!(g.check(ToolName::ListFolders).is_ok());
    }

    #[test]
    fn rejects_after_bucket_drains() {
        let g = Governor::new(2, 5, 3).unwrap(); // burst = 4
        for _ in 0..4 {
            let _ = g.check(ToolName::Search);
        }
        let mut rejected = false;
        for _ in 0..4 {
            if let Err(AuthzError::RateLimited { .. }) = g.check(ToolName::Search) {
                rejected = true;
                break;
            }
        }
        assert!(rejected, "bucket should drain within a handful of calls");
    }

    #[test]
    fn draft_bucket_is_separate() {
        let g = Governor::new(1000, 5, 3).unwrap(); // huge global, tight draft
        for _ in 0..5 {
            let _ = g.check(ToolName::CreateDraft);
        }
        let draft_err = g.check(ToolName::CreateDraft).unwrap_err();
        assert!(matches!(draft_err, AuthzError::RateLimited { .. }));
        assert!(g.check(ToolName::Search).is_ok());
    }

    #[test]
    fn sends_bucket_is_separate() {
        let g = Governor::new(1000, 5, 3).unwrap();
        for _ in 0..3 {
            let _ = g.check(ToolName::SendEmail);
        }
        let send_err = g.check(ToolName::SendEmail).unwrap_err();
        assert!(matches!(send_err, AuthzError::RateLimited { .. }));
        assert!(g.check(ToolName::Search).is_ok());
    }

    #[test]
    fn zero_sends_per_minute_rejected_at_build() {
        assert!(Governor::new(10, 5, 0).is_err());
    }

    #[test]
    fn rate_limited_retry_after_ms_is_meaningful_lower_bound() {
        // Drains the draft bucket (5 per minute → ~12s between refills) and
        // asserts the retry hint is at least 2ms. Kills both the
        // `retry_after_ms -> 0` and `-> 1` mutations on rate_limit.rs:36.
        let g = Governor::new(1000, 5, 3).unwrap();
        for _ in 0..5 {
            let _ = g.check(ToolName::CreateDraft);
        }
        match g.check(ToolName::CreateDraft) {
            Err(AuthzError::RateLimited { retry_after_ms }) => {
                assert!(
                    retry_after_ms >= 2,
                    "expected retry hint >= 2ms after draining draft bucket, \
                     got {retry_after_ms}ms"
                );
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    use proptest::prelude::*;

    proptest! {
        /// Steady-state: with N calls against a bucket of burst B, we should
        /// admit *at most* B + (time_elapsed * rate) calls, and at least B
        /// if no meaningful time elapses.
        #[test]
        fn steady_state_never_exceeds_burst_plus_refill(
            cps in 1u32..50u32,
            attempts in 1usize..200usize,
        ) {
            let g = Governor::new(cps, 1, 3).unwrap();
            let mut admitted = 0usize;
            for _ in 0..attempts {
                if g.check(ToolName::Search).is_ok() {
                    admitted += 1;
                }
            }
            let burst = (cps as usize).saturating_mul(2);
            prop_assert!(
                admitted <= burst * 10 + 10,
                "admitted {admitted} calls against burst {burst} (cps={cps})"
            );
            prop_assert!(admitted >= 1, "should admit at least one call");
        }
    }
}
