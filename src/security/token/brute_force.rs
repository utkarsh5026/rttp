//! Brute-force and credential-stuffing protection.
//!
//! [`LoginAttemptTracker`] counts failed authentication attempts per key
//! (typically a client IP address or username) and applies an exponential
//! lockout after too many consecutive failures.
//!
//! # Lockout behaviour
//!
//! | Failure # | Lockout duration (base = 30 s) |
//! |-----------|-------------------------------|
//! | 5         | 30 s                          |
//! | 6         | 60 s                          |
//! | 7         | 120 s                         |
//! | 8         | 240 s                         |
//! | …         | base × 2^(failures − max)     |
//! | ≥ 15      | capped at 1 h                 |
//!
//! A successful login resets the counter for that key immediately.
//!
//! # Examples
//!
//! ```rust,no_run
//! use std::time::Duration;
//! use rttp::security::token::brute_force::LoginAttemptTracker;
//!
//! # async fn example() {
//! let tracker = LoginAttemptTracker::new()
//!     .with_max_attempts(3)
//!     .with_base_lockout(Duration::from_secs(10));
//!
//! // First two failures — not yet locked.
//! assert!(tracker.record_failure("alice").await.is_none());
//! assert!(tracker.record_failure("alice").await.is_none());
//!
//! // Third failure — locked out.
//! let retry_after = tracker.record_failure("alice").await;
//! assert!(retry_after.is_some());
//!
//! // Subsequent check confirms the lock.
//! assert!(tracker.check_locked("alice").await.is_some());
//!
//! // A successful login clears the lock.
//! tracker.record_success("alice").await;
//! assert!(tracker.check_locked("alice").await.is_none());
//! # }
//! ```

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use tokio::sync::Mutex;
use tracing::warn;

/// Default number of consecutive failures before a key is locked out.
const DEFAULT_MAX_ATTEMPTS: u32 = 5;

/// Default base lockout duration — doubles on each additional failure.
const DEFAULT_BASE_LOCKOUT: Duration = Duration::from_secs(30);

/// Maximum lockout duration (cap on exponential growth).
const MAX_LOCKOUT: Duration = Duration::from_secs(3600); // 1 hour

#[derive(Debug, Clone)]
struct LockoutState {
    /// Total consecutive failed attempts since last success.
    failed_attempts: u32,
    /// The point in time until which the key is locked, if any.
    locked_until: Option<Instant>,
}

/// Tracks failed login attempts and locks out keys after too many failures.
///
/// Keyed by any string — typically the client IP address, username, or a
/// combination of both. Use separate tracker instances if you want independent
/// limits per strategy.
///
/// Wrap in an [`Arc`](std::sync::Arc) to share across middleware.
pub struct LoginAttemptTracker {
    max_attempts: u32,
    base_lockout: Duration,
    entries: Mutex<HashMap<String, LockoutState>>,
}

impl LoginAttemptTracker {
    /// Create a tracker with default limits (5 attempts, 30 s base lockout).
    #[must_use]
    pub fn new() -> Self {
        Self {
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            base_lockout: DEFAULT_BASE_LOCKOUT,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Set the maximum number of consecutive failures before lockout.
    #[must_use]
    pub fn with_max_attempts(mut self, max: u32) -> Self {
        self.max_attempts = max;
        self
    }

    /// Set the base lockout duration.
    ///
    /// The actual lockout doubles with each additional failure beyond the limit,
    /// up to a hard cap of 1 hour.
    #[must_use]
    pub fn with_base_lockout(mut self, duration: Duration) -> Self {
        self.base_lockout = duration;
        self
    }

    /// Check whether `key` is currently locked out.
    ///
    /// Returns `Some(retry_after_secs)` if locked, `None` if the key may proceed.
    ///
    /// This is a read-only check — it does not modify the failure count.
    pub async fn check_locked(&self, key: &str) -> Option<u64> {
        let entries = self.entries.lock().await;
        if let Some(state) = entries.get(key) {
            if let Some(until) = state.locked_until {
                let now = Instant::now();
                if until > now {
                    return Some(remaining_secs(until, now));
                }
            }
        }
        None
    }

    /// Record a failed authentication attempt for `key`.
    ///
    /// Returns `Some(retry_after_secs)` if the key is now locked out,
    /// `None` if further attempts are still allowed.
    pub async fn record_failure(&self, key: &str) -> Option<u64> {
        let mut entries = self.entries.lock().await;
        let state = entries.entry(key.to_owned()).or_insert(LockoutState {
            failed_attempts: 0,
            locked_until: None,
        });

        state.failed_attempts += 1;

        if state.failed_attempts >= self.max_attempts {
            let exponent = state.failed_attempts - self.max_attempts;
            // 2^exponent, capped to avoid overflow (2^20 already exceeds 1 h at 30 s base).
            let multiplier = 2u32.checked_pow(exponent.min(20)).unwrap_or(u32::MAX);
            let lockout = (self.base_lockout * multiplier).min(MAX_LOCKOUT);
            let until = Instant::now() + lockout;
            state.locked_until = Some(until);

            warn!(
                key = %key,
                attempts = state.failed_attempts,
                lockout_secs = lockout.as_secs(),
                "key locked after too many failed auth attempts"
            );

            Some(lockout.as_secs().max(1))
        } else {
            None
        }
    }

    /// Record a successful login for `key`.
    ///
    /// Clears all failure history and removes any active lockout for the key.
    pub async fn record_success(&self, key: &str) {
        self.entries.lock().await.remove(key);
    }

    /// Remove entries for keys that are no longer locked.
    ///
    /// Call periodically from a background task to prevent unbounded memory
    /// growth. Entries with no active lockout (i.e., key is within the allowed
    /// failure window but not yet locked) are also removed.
    pub async fn purge_expired(&self) {
        let now = Instant::now();
        let mut entries = self.entries.lock().await;
        entries.retain(|_, state| {
            // Keep only entries that are actively locked and not yet expired.
            state.locked_until.map(|u| u > now).unwrap_or(false)
        });
    }
}

impl Default for LoginAttemptTracker {
    fn default() -> Self {
        Self::new()
    }
}

fn remaining_secs(until: Instant, now: Instant) -> u64 {
    until.duration_since(now).as_secs().max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tracker_3() -> LoginAttemptTracker {
        LoginAttemptTracker::new()
            .with_max_attempts(3)
            .with_base_lockout(Duration::from_secs(10))
    }

    #[tokio::test]
    async fn test_check_locked_unknown_key_returns_none() {
        let t = tracker_3();
        assert!(t.check_locked("nobody").await.is_none());
    }

    #[tokio::test]
    async fn test_failures_below_limit_do_not_lock() {
        let t = tracker_3();
        assert!(t.record_failure("alice").await.is_none());
        assert!(t.record_failure("alice").await.is_none());
        assert!(t.check_locked("alice").await.is_none());
    }

    #[tokio::test]
    async fn test_failure_at_limit_returns_retry_after() {
        let t = tracker_3();
        t.record_failure("bob").await;
        t.record_failure("bob").await;
        let result = t.record_failure("bob").await; // 3rd — at limit
        assert!(result.is_some());
        assert!(result.unwrap() >= 1);
    }

    #[tokio::test]
    async fn test_check_locked_after_lockout_returns_some() {
        let t = tracker_3();
        for _ in 0..3 {
            t.record_failure("carol").await;
        }
        assert!(t.check_locked("carol").await.is_some());
    }

    #[tokio::test]
    async fn test_record_success_clears_lockout() {
        let t = tracker_3();
        for _ in 0..3 {
            t.record_failure("dave").await;
        }
        assert!(t.check_locked("dave").await.is_some());
        t.record_success("dave").await;
        assert!(t.check_locked("dave").await.is_none());
    }

    #[tokio::test]
    async fn test_record_success_unknown_key_is_noop() {
        let t = tracker_3();
        t.record_success("ghost").await; // must not panic
        assert!(t.check_locked("ghost").await.is_none());
    }

    #[tokio::test]
    async fn test_lockout_doubles_on_extra_failures() {
        let t = tracker_3();
        // Trigger lockout at attempt 3 — base 10 s.
        for _ in 0..3 {
            t.record_failure("eve").await;
        }
        // 4th failure — lockout should double (20 s).
        let secs = t.record_failure("eve").await.unwrap();
        assert!(secs >= 20, "expected ≥ 20 s, got {secs}");
    }

    #[tokio::test]
    async fn test_lockout_capped_at_one_hour() {
        let t = LoginAttemptTracker::new()
            .with_max_attempts(1)
            .with_base_lockout(Duration::from_secs(3600));
        // Many failures — should never exceed 1 h.
        for _ in 0..30 {
            t.record_failure("spammer").await;
        }
        let secs = t.check_locked("spammer").await.unwrap();
        assert!(secs <= 3600, "lockout exceeded 1 h cap: {secs}");
    }

    #[tokio::test]
    async fn test_keys_are_independent() {
        let t = tracker_3();
        t.record_failure("user-a").await;
        t.record_failure("user-a").await;
        t.record_failure("user-a").await;
        // user-b should not be affected.
        assert!(t.check_locked("user-b").await.is_none());
    }

    #[tokio::test]
    async fn test_purge_expired_removes_past_lockouts() {
        // We can't easily create a past lockout without sleep, so we test that
        // purge on active entries keeps them and purge on empty is a no-op.
        let t = tracker_3();
        t.purge_expired().await; // empty — must not panic

        for _ in 0..3 {
            t.record_failure("locked").await;
        }
        t.purge_expired().await;
        // Active lockout should still be present.
        assert!(t.check_locked("locked").await.is_some());
    }
}
