//! Sliding-window rate limiting algorithm.
//!
//! Unlike the token bucket, the sliding window enforces a strict request count
//! over a rolling time window. This eliminates the burst that a fixed-window
//! counter allows at the window boundary.
//!
//! # How it works
//!
//! Each key maintains a `VecDeque<Instant>` of request timestamps. On every
//! check, timestamps older than the window are evicted; the remaining count is
//! compared against `max_requests`.
//!
//! # Examples
//!
//! ```rust
//! use std::time::Duration;
//! use rttp::security::rate_limit::sliding_window::SlidingWindowCounter;
//!
//! let counter = SlidingWindowCounter::new(3, Duration::from_secs(60));
//!
//! // Three requests within the window are allowed.
//! let (ok, remaining, _) = counter.check_and_record("client-1");
//! assert!(ok);
//! assert_eq!(remaining, 2);
//!
//! counter.check_and_record("client-1");
//! counter.check_and_record("client-1");
//!
//! // Fourth request is rejected.
//! let (ok, _, reset) = counter.check_and_record("client-1");
//! assert!(!ok);
//! assert!(reset > 0);
//! ```

use std::{
    collections::{HashMap, VecDeque},
    sync::Mutex,
    time::{Duration, Instant},
};

use super::store::RateLimitStore;

/// A synchronous, in-process sliding-window request counter.
///
/// Each key gets an independent ring buffer of request timestamps. Entries are
/// evicted lazily on each call to [`check_and_record`](Self::check_and_record).
///
/// Wrap in an [`Arc`](std::sync::Arc) to share across threads.
pub struct SlidingWindowCounter {
    entries: Mutex<HashMap<String, VecDeque<Instant>>>,
    window: Duration,
    max_requests: usize,
}

impl SlidingWindowCounter {
    /// Create a new counter that allows `max_requests` per `window`.
    #[must_use]
    pub fn new(max_requests: usize, window: Duration) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            window,
            max_requests,
        }
    }

    /// Record a request for `key` and check whether it is within the limit.
    ///
    /// Returns `(allowed, remaining, reset_after_secs)`:
    ///
    /// - `allowed` — `true` if the request may proceed.
    /// - `remaining` — how many more requests are allowed in the current window.
    ///   Always `0` when `allowed` is `false`.
    /// - `reset_after_secs` — seconds until the window resets enough to admit
    ///   another request. When `allowed` is `true` this is the full window size.
    pub fn check_and_record(&self, key: &str) -> (bool, usize, u64) {
        let now = Instant::now();
        let cutoff = now - self.window;

        let mut entries = self.entries.lock().expect("sliding window lock poisoned");
        let deque = entries.entry(key.to_owned()).or_default();

        // Evict timestamps that have fallen outside the window.
        while deque.front().map(|&t| t <= cutoff).unwrap_or(false) {
            deque.pop_front();
        }

        let count = deque.len();

        if count < self.max_requests {
            deque.push_back(now);
            let remaining = self.max_requests - count - 1;
            (true, remaining, self.window.as_secs())
        } else {
            // Time until the oldest request falls outside the window.
            let oldest = *deque.front().unwrap_or(&now);
            let reset = (oldest + self.window)
                .checked_duration_since(now)
                .unwrap_or(Duration::ZERO)
                .as_secs()
                .max(1);
            (false, 0, reset)
        }
    }
}

impl RateLimitStore for SlidingWindowCounter {
    fn try_consume(&self, key: &str) -> bool {
        let (allowed, _, _) = self.check_and_record(key);
        allowed
    }
}

impl SlidingWindowCounter {
    /// Remove all tracking data for keys whose window has fully elapsed.
    ///
    /// Call periodically to bound memory usage.
    pub fn purge_idle(&self) {
        let now = Instant::now();
        let cutoff = now - self.window;
        let mut entries = self.entries.lock().expect("sliding window lock poisoned");
        entries.retain(|_, deque| {
            while deque.front().map(|&t| t <= cutoff).unwrap_or(false) {
                deque.pop_front();
            }
            !deque.is_empty()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn counter(max: usize) -> SlidingWindowCounter {
        SlidingWindowCounter::new(max, Duration::from_secs(60))
    }

    #[test]
    fn test_first_request_is_allowed() {
        let c = counter(5);
        let (ok, _, _) = c.check_and_record("a");
        assert!(ok);
    }

    #[test]
    fn test_remaining_decrements_on_each_request() {
        let c = counter(3);
        let (_, r1, _) = c.check_and_record("a");
        let (_, r2, _) = c.check_and_record("a");
        let (_, r3, _) = c.check_and_record("a");
        assert_eq!(r1, 2);
        assert_eq!(r2, 1);
        assert_eq!(r3, 0);
    }

    #[test]
    fn test_request_beyond_limit_is_rejected() {
        let c = counter(2);
        c.check_and_record("b");
        c.check_and_record("b");
        let (ok, remaining, reset) = c.check_and_record("b");
        assert!(!ok);
        assert_eq!(remaining, 0);
        assert!(reset >= 1);
    }

    #[test]
    fn test_different_keys_are_independent() {
        let c = counter(1);
        let (ok_a, _, _) = c.check_and_record("key-a");
        let (ok_b, _, _) = c.check_and_record("key-b");
        assert!(ok_a);
        assert!(ok_b);
    }

    #[test]
    fn test_purge_idle_removes_empty_entries() {
        let c = SlidingWindowCounter::new(5, Duration::from_nanos(1));
        c.check_and_record("stale");
        std::thread::sleep(Duration::from_millis(1));
        c.purge_idle();
        // After purge the key is gone; a new request starts fresh.
        let (ok, remaining, _) = c.check_and_record("stale");
        assert!(ok);
        assert_eq!(remaining, 4);
    }

    #[test]
    fn test_rate_limit_store_impl_delegates_to_check_and_record() {
        use super::super::store::RateLimitStore;

        let c = SlidingWindowCounter::new(2, Duration::from_secs(60));
        assert!(c.try_consume("k"));
        assert!(c.try_consume("k"));
        assert!(!c.try_consume("k")); // 3rd — rejected
    }
}
