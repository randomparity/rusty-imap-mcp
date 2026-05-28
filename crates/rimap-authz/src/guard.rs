//! Composed dispatch guard: posture + circuit breaker + rate limiter.
//!
//! Call order (design spec §9):
//!   1. Posture authorization (effective matrix).
//!   2. Circuit breaker pre-call check.
//!   3. Rate limiter admission.
//!
//! If any stage short-circuits, subsequent stages are skipped. The breaker is
//! notified of success/failure via `on_success` / `on_failure` after dispatch.

use rimap_core::tool::ToolName;

use crate::breaker::{CircuitBreaker, Clock, FailureReason};
use crate::error::AuthzError;
use crate::matrix::EffectiveMatrix;
use crate::rate_limit::Governor;

/// Composed authorization gate. Not async — none of the stages await.
pub struct DispatchGuard<C: Clock> {
    matrix: EffectiveMatrix,
    breaker: CircuitBreaker<C>,
    governor: Governor,
}

impl<C: Clock> DispatchGuard<C> {
    /// Construct from pre-built pieces.
    #[must_use]
    pub fn new(matrix: EffectiveMatrix, breaker: CircuitBreaker<C>, governor: Governor) -> Self {
        Self {
            matrix,
            breaker,
            governor,
        }
    }

    /// Run the full pre-dispatch chain.
    ///
    /// # Errors
    /// Returns the first stage error encountered.
    pub fn pre_dispatch(&self, tool: ToolName) -> Result<(), AuthzError> {
        self.matrix.check(tool)?;
        self.breaker.pre_call()?;
        self.governor.check(tool)?;
        Ok(())
    }

    /// Signal a successful tool dispatch to the breaker.
    pub fn on_success(&self) {
        self.breaker.on_success();
    }

    /// Signal a failed tool dispatch to the breaker.
    pub fn on_failure(&self, reason: FailureReason) {
        self.breaker.on_failure(reason);
    }

    /// Access the effective matrix (for `list_tools` advertisement and
    /// `--dry-run` printing).
    #[must_use]
    pub fn matrix(&self) -> &EffectiveMatrix {
        &self.matrix
    }

    /// Access the underlying breaker (used in tests for manual-clock
    /// advancement; production callers should use `on_success` / `on_failure`).
    #[must_use]
    pub fn breaker(&self) -> &CircuitBreaker<C> {
        &self.breaker
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use std::collections::BTreeMap;
    use std::time::Duration;

    use rimap_core::posture::Posture;
    use rimap_core::tool::ToolName;

    use crate::breaker::{BreakerConfig, CircuitBreaker, FailureReason, ManualClock};
    use crate::error::AuthzError;
    use crate::guard::DispatchGuard;
    use crate::matrix::EffectiveMatrix;
    use crate::rate_limit::Governor;

    fn guard(posture: Posture) -> DispatchGuard<ManualClock> {
        let matrix = EffectiveMatrix::build(posture, &BTreeMap::new());
        let breaker = CircuitBreaker::new(
            ManualClock::new(),
            BreakerConfig {
                error_threshold: 2,
                window: Duration::from_secs(10),
                starting_cooldown: Duration::from_secs(5),
                max_cooldown: Duration::from_secs(60),
                auth_starting_cooldown: Duration::from_secs(30),
                auth_max_cooldown: Duration::from_secs(600),
            },
        );
        let governor = Governor::new(100, 5, 3).unwrap();
        DispatchGuard::new(matrix, breaker, governor)
    }

    #[test]
    fn readonly_denies_create_draft_at_posture_stage() {
        let g = guard(Posture::Readonly);
        let err = g.pre_dispatch(ToolName::CreateDraft).unwrap_err();
        assert!(matches!(
            err,
            AuthzError::PostureDenied(ToolName::CreateDraft)
        ));
    }

    #[test]
    fn draft_safe_allows_mark_read() {
        let g = guard(Posture::DraftSafe);
        g.pre_dispatch(ToolName::MarkRead).unwrap();
    }

    #[test]
    fn posture_denied_does_not_consume_rate_limiter() {
        let g = guard(Posture::Readonly);
        for _ in 0..500 {
            let _ = g.pre_dispatch(ToolName::CreateDraft);
        }
        g.pre_dispatch(ToolName::ListFolders).unwrap();
    }

    #[test]
    fn matrix_accessor_returns_effective_matrix() {
        let g = guard(Posture::Full);
        assert_eq!(g.matrix().posture(), Posture::Full);
    }

    #[test]
    fn timeout_threshold_trips_breaker_then_probe_success_closes_it() {
        let g = guard(Posture::DraftSafe);

        // A tool that DraftSafe permits, so admission is gated only by the breaker.
        g.pre_dispatch(ToolName::ListFolders).unwrap();

        // One non-auth service failure is below threshold (2): still Closed.
        g.on_failure(FailureReason::Timeout);
        g.pre_dispatch(ToolName::ListFolders).unwrap(); // one failure is below the threshold; breaker stays Closed

        // Second non-auth failure reaches threshold → Open.
        g.on_failure(FailureReason::Timeout);
        assert!(
            matches!(
                g.pre_dispatch(ToolName::ListFolders),
                Err(AuthzError::CircuitOpen { .. })
            ),
            "two service failures must trip the breaker Open",
        );

        // After cooldown, a probe + success closes it again.
        g.breaker().clock.advance(Duration::from_secs(5));
        g.pre_dispatch(ToolName::ListFolders).unwrap(); // HalfOpen probe
        g.on_success();
        g.pre_dispatch(ToolName::ListFolders).unwrap(); // on_success after a half-open probe must close the breaker
    }

    #[test]
    fn single_auth_failure_trips_breaker_immediately() {
        let g = guard(Posture::DraftSafe);
        g.pre_dispatch(ToolName::ListFolders).unwrap();
        g.on_failure(FailureReason::Auth);
        assert!(
            matches!(
                g.pre_dispatch(ToolName::ListFolders),
                Err(AuthzError::CircuitOpen { .. })
            ),
            "a single Auth failure must trip the breaker Open immediately",
        );
    }
}
