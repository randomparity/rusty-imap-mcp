//! Circuit breaker state machine.
//!
//! States (design spec §9):
//!   - **Closed** — count errors in a sliding window; if ≥ threshold, trip
//!     to Open.
//!   - **Open** — reject all calls for a cooldown duration. After cooldown,
//!     transition to `HalfOpen` on next call.
//!   - **`HalfOpen`** — admit exactly one probe. Success → Closed (reset).
//!     Failure → Open with doubled cooldown (capped at 5 minutes, or 10
//!     minutes for auth-failure reasons).
//!
//! Auth failures trip immediately: a single `FailureReason::Auth` in Closed
//! state moves directly to Open with a 60-second cooldown (starting backoff).
//!
//! Time is abstracted via [`Clock`] so tests are fully deterministic without
//! `tokio::time::pause`.

use std::collections::VecDeque;
use std::time::Duration;

use parking_lot::Mutex;

use crate::error::AuthzError;

/// Reasons a call may fail from the breaker's point of view.
///
/// Per spec, `NotFound`, `InvalidInput`, `PostureDenied`, `RateLimited`,
/// `AttachmentTooLarge`, and `BodyTruncated` are NOT reported here — they're
/// user/agent/policy errors, not service health signals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureReason {
    /// TCP/TLS session dropped mid-call.
    ConnectionLost,
    /// Authentication rejected.
    Auth,
    /// Tokio timeout elapsed.
    Timeout,
    /// IMAP server returned a malformed response.
    Protocol,
    /// TLS handshake or pinning rejection.
    Tls,
}

/// Abstract monotonic clock. Production uses [`SystemClock`]; tests use
/// [`ManualClock`].
pub trait Clock: Send + Sync + 'static {
    /// Current monotonic time as a [`Duration`] since an arbitrary epoch.
    fn now(&self) -> Duration;
}

/// `std::time::Instant`-backed clock.
pub struct SystemClock {
    epoch: std::time::Instant,
}

impl SystemClock {
    /// Construct at the current instant.
    #[must_use]
    pub fn new() -> Self {
        Self {
            epoch: std::time::Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn now(&self) -> Duration {
        std::time::Instant::now().saturating_duration_since(self.epoch)
    }
}

/// Hand-advanced clock for tests.
#[derive(Debug, Default)]
pub struct ManualClock {
    inner: Mutex<Duration>,
}

impl ManualClock {
    /// Construct at time zero.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Advance the clock by `by`.
    pub fn advance(&self, by: Duration) {
        let mut guard = self.inner.lock();
        *guard += by;
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Duration {
        *self.inner.lock()
    }
}

/// Public state enum — used only for tests / introspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Normal operation.
    Closed,
    /// Fast-failing; cooldown in effect.
    Open,
    /// Next call is a probe.
    HalfOpen,
}

#[derive(Debug)]
struct Inner {
    state: State,
    failures: VecDeque<Duration>,
    open_until: Duration,
    current_cooldown: Duration,
    last_trip_was_auth: bool,
}

/// Circuit breaker configuration (subset of `LimitsConfig` relevant here).
///
/// ```compile_fail,E0639
/// let _ = rimap_authz::BreakerConfig {
///     error_threshold: 1,
///     ..rimap_authz::BreakerConfig::default_spec()
/// };
/// ```
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct BreakerConfig {
    /// Threshold of failures within the window that trips the breaker.
    pub error_threshold: u32,
    /// Sliding window length.
    pub window: Duration,
    /// Starting cooldown for non-auth trips.
    pub starting_cooldown: Duration,
    /// Max cooldown for non-auth trips.
    pub max_cooldown: Duration,
    /// Starting cooldown for auth-failure trips.
    pub auth_starting_cooldown: Duration,
    /// Max cooldown for auth-failure trips.
    pub auth_max_cooldown: Duration,
}

impl BreakerConfig {
    /// Defaults derived from design spec §9.
    #[must_use]
    pub fn default_spec() -> Self {
        Self {
            error_threshold: 5,
            window: Duration::from_secs(30),
            starting_cooldown: Duration::from_secs(15),
            max_cooldown: Duration::from_secs(300),
            auth_starting_cooldown: Duration::from_secs(60),
            auth_max_cooldown: Duration::from_secs(600),
        }
    }
}

/// The breaker itself. Cheap to clone-via-Arc; internal state is mutex-protected.
pub struct CircuitBreaker<C: Clock> {
    /// Clock used for window pruning and cooldown checks. Public so tests
    /// using [`ManualClock`] can advance it; production uses [`SystemClock`]
    /// which has no public mutation API, so exposing it is safe.
    pub clock: C,
    cfg: BreakerConfig,
    inner: Mutex<Inner>,
}

impl<C: Clock> CircuitBreaker<C> {
    /// Construct a new breaker in the Closed state.
    pub fn new(clock: C, cfg: BreakerConfig) -> Self {
        Self {
            clock,
            cfg,
            inner: Mutex::new(Inner {
                state: State::Closed,
                failures: VecDeque::new(),
                open_until: Duration::ZERO,
                current_cooldown: cfg.starting_cooldown,
                last_trip_was_auth: false,
            }),
        }
    }

    /// Current state (for tests and tracing).
    #[must_use]
    pub fn state(&self) -> State {
        self.inner.lock().state
    }

    /// Called *before* a tool dispatch.
    ///
    /// # Errors
    /// `AuthzError::CircuitOpen` when the breaker is Open and has not yet
    /// reached its cooldown deadline.
    pub fn pre_call(&self) -> Result<(), AuthzError> {
        let mut g = self.inner.lock();
        let now = self.clock.now();
        match g.state {
            State::Closed => Ok(()),
            State::Open => {
                if now >= g.open_until {
                    g.state = State::HalfOpen;
                    Ok(())
                } else {
                    let remaining = g.open_until.saturating_sub(now);
                    Err(AuthzError::CircuitOpen {
                        retry_after_ms: u64::try_from(remaining.as_millis()).unwrap_or(u64::MAX),
                    })
                }
            }
            State::HalfOpen => {
                let remaining = g.open_until.saturating_sub(now);
                Err(AuthzError::CircuitOpen {
                    retry_after_ms: u64::try_from(remaining.as_millis()).unwrap_or(u64::MAX),
                })
            }
        }
    }

    /// Called *after* a successful tool dispatch.
    pub fn on_success(&self) {
        let mut g = self.inner.lock();
        match g.state {
            State::Closed => {
                let now = self.clock.now();
                Self::prune_expired(&mut g.failures, now, self.cfg.window);
            }
            State::Open | State::HalfOpen => {
                g.state = State::Closed;
                g.failures.clear();
                g.current_cooldown = self.cfg.starting_cooldown;
                g.last_trip_was_auth = false;
                g.open_until = Duration::ZERO;
            }
        }
    }

    /// Called *after* a failed tool dispatch, with the failure class.
    pub fn on_failure(&self, reason: FailureReason) {
        let now = self.clock.now();
        let mut g = self.inner.lock();
        match g.state {
            State::Open => {
                // Shouldn't happen — pre_call would have rejected — but ignore.
            }
            State::HalfOpen => {
                self.trip_open(&mut g, now, reason, /* doubling */ true);
            }
            State::Closed => {
                if reason == FailureReason::Auth {
                    self.trip_open(&mut g, now, reason, false);
                    return;
                }
                Self::prune_expired(&mut g.failures, now, self.cfg.window);
                g.failures.push_back(now);
                if g.failures.len() >= self.cfg.error_threshold as usize {
                    self.trip_open(&mut g, now, reason, false);
                }
            }
        }
    }

    fn trip_open(&self, g: &mut Inner, now: Duration, reason: FailureReason, doubling: bool) {
        let is_auth = reason == FailureReason::Auth;
        let (start, cap) = if is_auth {
            (self.cfg.auth_starting_cooldown, self.cfg.auth_max_cooldown)
        } else {
            (self.cfg.starting_cooldown, self.cfg.max_cooldown)
        };
        let next = if doubling {
            (g.current_cooldown.saturating_mul(2)).min(cap)
        } else {
            start
        };
        g.current_cooldown = next;
        g.open_until = now + next;
        g.state = State::Open;
        g.failures.clear();
        g.last_trip_was_auth = is_auth;
    }

    fn prune_expired(failures: &mut VecDeque<Duration>, now: Duration, window: Duration) {
        let cutoff = now.saturating_sub(window);
        while failures.front().copied().is_some_and(|t| t < cutoff) {
            failures.pop_front();
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
#[expect(clippy::panic, reason = "tests")]
mod tests {
    use std::time::Duration;

    use crate::breaker::{BreakerConfig, CircuitBreaker, FailureReason, ManualClock, State};
    use crate::error::AuthzError;

    fn test_cfg() -> BreakerConfig {
        BreakerConfig {
            error_threshold: 3,
            window: Duration::from_secs(10),
            starting_cooldown: Duration::from_secs(5),
            max_cooldown: Duration::from_secs(60),
            auth_starting_cooldown: Duration::from_secs(30),
            auth_max_cooldown: Duration::from_secs(600),
        }
    }

    #[test]
    fn starts_closed() {
        let b = CircuitBreaker::new(ManualClock::new(), test_cfg());
        assert_eq!(b.state(), State::Closed);
        assert!(b.pre_call().is_ok());
    }

    #[test]
    fn trips_after_threshold_failures_in_window() {
        let clock = ManualClock::new();
        let b = CircuitBreaker::new(clock, test_cfg());
        for _ in 0..2 {
            b.on_failure(FailureReason::Timeout);
        }
        assert_eq!(b.state(), State::Closed);
        b.on_failure(FailureReason::Timeout);
        assert_eq!(b.state(), State::Open);
        let err = b.pre_call().unwrap_err();
        assert!(matches!(err, AuthzError::CircuitOpen { .. }));
    }

    #[test]
    fn failures_outside_window_do_not_count() {
        let b = CircuitBreaker::new(ManualClock::new(), test_cfg());
        b.on_failure(FailureReason::Timeout);
        b.on_failure(FailureReason::Timeout);
        b.clock.advance(Duration::from_secs(11));
        b.on_failure(FailureReason::Timeout);
        assert_eq!(
            b.state(),
            State::Closed,
            "old failures should have pruned out of the window"
        );
    }

    #[test]
    fn auth_failure_trips_immediately() {
        let b = CircuitBreaker::new(ManualClock::new(), test_cfg());
        b.on_failure(FailureReason::Auth);
        assert_eq!(b.state(), State::Open);
    }

    #[test]
    fn open_transitions_to_half_open_after_cooldown() {
        let b = CircuitBreaker::new(ManualClock::new(), test_cfg());
        for _ in 0..3 {
            b.on_failure(FailureReason::Timeout);
        }
        assert_eq!(b.state(), State::Open);
        assert!(b.pre_call().is_err());
        b.clock.advance(Duration::from_secs(5));
        assert!(b.pre_call().is_ok());
        assert_eq!(b.state(), State::HalfOpen);
    }

    #[test]
    fn half_open_success_closes_breaker_and_resets_cooldown() {
        let b = CircuitBreaker::new(ManualClock::new(), test_cfg());
        for _ in 0..3 {
            b.on_failure(FailureReason::Timeout);
        }
        b.clock.advance(Duration::from_secs(5));
        assert!(b.pre_call().is_ok()); // HalfOpen probe admitted
        b.on_success();
        assert_eq!(b.state(), State::Closed);
        assert!(b.pre_call().is_ok());
    }

    #[test]
    fn half_open_failure_reopens_with_doubled_cooldown() {
        let b = CircuitBreaker::new(ManualClock::new(), test_cfg());
        for _ in 0..3 {
            b.on_failure(FailureReason::Timeout);
        }
        b.clock.advance(Duration::from_secs(5));
        assert!(b.pre_call().is_ok()); // HalfOpen
        b.on_failure(FailureReason::Timeout);
        assert_eq!(b.state(), State::Open);
        b.clock.advance(Duration::from_secs(6));
        assert!(b.pre_call().is_err());
        b.clock.advance(Duration::from_secs(5));
        assert!(b.pre_call().is_ok());
        assert_eq!(b.state(), State::HalfOpen);
    }

    #[test]
    fn cooldown_caps_at_max() {
        let mut cfg = test_cfg();
        cfg.starting_cooldown = Duration::from_secs(40);
        cfg.max_cooldown = Duration::from_secs(60);
        let b = CircuitBreaker::new(ManualClock::new(), cfg);
        for _ in 0..3 {
            b.on_failure(FailureReason::Timeout);
        }
        for _ in 0..5 {
            b.clock.advance(Duration::from_secs(120));
            assert!(b.pre_call().is_ok()); // HalfOpen
            b.on_failure(FailureReason::Timeout);
        }
        if let Err(AuthzError::CircuitOpen { retry_after_ms }) = b.pre_call() {
            assert!(retry_after_ms <= 60_000);
        } else {
            panic!("expected CircuitOpen");
        }
    }

    #[test]
    fn half_open_reject_reports_retry_after_ms_zero() {
        // Documents the convention that CircuitOpen { retry_after_ms: 0 }
        // means "half-open probe in flight" — not "retry immediately".
        let b = CircuitBreaker::new(ManualClock::new(), test_cfg());
        for _ in 0..3 {
            b.on_failure(FailureReason::Timeout);
        }
        b.clock.advance(Duration::from_secs(5));
        assert!(b.pre_call().is_ok()); // probe admitted → HalfOpen
        assert_eq!(b.state(), State::HalfOpen);
        match b.pre_call() {
            Err(AuthzError::CircuitOpen { retry_after_ms }) => {
                assert_eq!(
                    retry_after_ms, 0,
                    "half-open rejection must signal retry_after_ms=0 \
                     so callers can distinguish it from a timed cooldown"
                );
            }
            other => panic!("expected CircuitOpen in HalfOpen state, got {other:?}"),
        }
    }

    #[test]
    fn half_open_rejects_concurrent_calls_until_probe_resolves() {
        let b = CircuitBreaker::new(ManualClock::new(), test_cfg());
        for _ in 0..3 {
            b.on_failure(FailureReason::Timeout);
        }
        b.clock.advance(Duration::from_secs(5));
        assert!(b.pre_call().is_ok()); // probe admitted
        assert_eq!(b.state(), State::HalfOpen);
        assert!(matches!(b.pre_call(), Err(AuthzError::CircuitOpen { .. })));
    }

    #[test]
    fn success_in_closed_state_prunes_old_failures() {
        let b = CircuitBreaker::new(ManualClock::new(), test_cfg());
        b.on_failure(FailureReason::Timeout);
        b.clock.advance(Duration::from_secs(11));
        b.on_success();
        b.on_failure(FailureReason::Timeout);
        b.on_failure(FailureReason::Timeout);
        assert_eq!(b.state(), State::Closed);
    }

    #[test]
    fn every_failure_reason_can_trip_the_breaker_in_closed() {
        for reason in [
            FailureReason::ConnectionLost,
            FailureReason::Auth,
            FailureReason::Timeout,
            FailureReason::Protocol,
            FailureReason::Tls,
        ] {
            let b = CircuitBreaker::new(ManualClock::new(), test_cfg());
            let needed = if reason == FailureReason::Auth { 1 } else { 3 };
            for _ in 0..needed {
                b.on_failure(reason);
            }
            assert_eq!(b.state(), State::Open, "reason {reason:?} should trip");
        }
    }

    #[test]
    fn default_spec_breaker_config_has_expected_values() {
        let cfg = BreakerConfig::default_spec();
        assert_eq!(cfg.error_threshold, 5);
        assert_eq!(cfg.window, Duration::from_secs(30));
    }

    #[test]
    fn system_clock_now_is_monotonic_nondecreasing() {
        use crate::breaker::{Clock, SystemClock};
        let c = SystemClock::default();
        let a = c.now();
        let b = c.now();
        assert!(b >= a);
    }

    #[test]
    fn system_clock_now_advances_with_wall_time() {
        // Stronger than the non-decreasing assertion above: this also kills
        // the `now -> Duration::default()` mutation, which would pin both
        // reads to Duration::ZERO and fail the strict-greater check.
        use crate::breaker::{Clock, SystemClock};
        let c = SystemClock::default();
        let a = c.now();
        std::thread::sleep(Duration::from_millis(2));
        let b = c.now();
        assert!(b > a, "SystemClock::now must advance across a real sleep");
    }

    #[test]
    fn on_failure_in_open_is_a_noop() {
        let b = CircuitBreaker::new(ManualClock::new(), test_cfg());
        b.on_failure(FailureReason::Auth); // trip
        assert_eq!(b.state(), State::Open);
        // Now in Open: on_failure should not change state.
        b.on_failure(FailureReason::Timeout);
        assert_eq!(b.state(), State::Open);
    }

    #[test]
    fn prune_with_empty_failures_does_nothing() {
        let b = CircuitBreaker::new(ManualClock::new(), test_cfg());
        // on_success in Closed state with empty failures hits the
        // prune_expired empty-queue early-return path.
        b.on_success();
        assert_eq!(b.state(), State::Closed);
    }
}
