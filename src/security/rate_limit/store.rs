//! Pluggable rate-limit state backends.
//!
//! [`RateLimitStore`] is a synchronous trait that abstracts where per-key
//! token-bucket state lives. rttp ships [`InMemoryStore`] — a `Mutex<HashMap>`
//! backend suitable for single-process deployments and testing.
//!
//! # Examples
//!
//! ```rust
//! use rttp::security::rate_limit::{RateLimitConfig, RateLimitStore, store::InMemoryStore};
//!
//! let cfg = RateLimitConfig::per_minute(60);
//! let store = InMemoryStore::from_config(&cfg);
//!
//! // First request is always allowed.
//! assert!(store.try_consume("127.0.0.1"));
//! ```

use std::collections::HashMap;
use std::sync::Mutex;

use super::bucket::{RateLimitConfig, TokenBucket};

/// A synchronous, key-scoped token-bucket store.
///
/// Each key (e.g. client IP, API key) gets its own `TokenBucket`. Implement
/// this trait to back the rate limiter with Redis, DynamoDB, or any other store.
///
/// The trait is intentionally **synchronous** so it can be called inside
/// [`Middleware::handle`](crate::middleware::Middleware::handle) without
/// requiring an inner `async` block or a mutex guard across an `.await`.
pub trait RateLimitStore: Send + Sync + 'static {
    /// Try to consume one token for `key`.
    ///
    /// Returns `true` if the request is allowed, `false` if the bucket for
    /// this key is empty (i.e. the request should be throttled).
    fn try_consume(&self, key: &str) -> bool;
}

/// In-process, in-memory [`RateLimitStore`] backed by a `Mutex<HashMap>`.
///
/// Each key gets its own `TokenBucket` initialised on first access.
/// Buckets are never evicted — for long-running servers with many ephemeral
/// IPs, wire up a background task that calls [`InMemoryStore::evict_stale`].
///
/// # Thread safety
///
/// Internally protected by a `std::sync::Mutex`. The critical section is small
/// (just the bucket update), so contention is negligible in practice.
pub struct InMemoryStore {
    buckets: Mutex<HashMap<String, TokenBucket>>,
    capacity: f64,
    refill_rate: f64,
}

impl InMemoryStore {
    /// Create a store where every key gets a bucket with `capacity` tokens
    /// that refills at `refill_rate` tokens per second.
    #[must_use]
    pub fn new(capacity: f64, refill_rate: f64) -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            capacity,
            refill_rate,
        }
    }

    /// Create a store from a [`RateLimitConfig`].
    #[must_use]
    pub fn from_config(config: &RateLimitConfig) -> Self {
        Self::new(config.capacity, config.refill_rate)
    }

    /// Remove buckets that have been fully refilled and are therefore
    /// indistinguishable from a brand-new bucket.
    ///
    /// Call periodically from a background task to bound memory usage when
    /// the set of keys is large and constantly changing.
    pub fn evict_stale(&self) {
        let mut buckets = self.buckets.lock().expect("rate limit store lock poisoned");
        buckets.retain(|_, b| !b.is_full());
    }
}

impl RateLimitStore for InMemoryStore {
    fn try_consume(&self, key: &str) -> bool {
        let mut buckets = self.buckets.lock().expect("rate limit store lock poisoned");
        let capacity = self.capacity;
        let refill_rate = self.refill_rate;
        buckets
            .entry(key.to_owned())
            .or_insert_with(|| TokenBucket::new(capacity, refill_rate))
            .try_consume()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store_per_second(n: u32) -> InMemoryStore {
        InMemoryStore::from_config(&RateLimitConfig::per_second(n))
    }

    #[test]
    fn test_first_request_is_allowed() {
        let s = store_per_second(5);
        assert!(s.try_consume("a"));
    }

    #[test]
    fn test_requests_up_to_capacity_are_allowed() {
        let s = store_per_second(3);
        assert!(s.try_consume("x"));
        assert!(s.try_consume("x"));
        assert!(s.try_consume("x"));
    }

    #[test]
    fn test_request_beyond_capacity_is_rejected() {
        let s = store_per_second(2);
        s.try_consume("y");
        s.try_consume("y");
        assert!(!s.try_consume("y")); // 3rd — bucket empty
    }

    #[test]
    fn test_different_keys_have_independent_buckets() {
        let s = store_per_second(1);
        assert!(s.try_consume("key-a"));
        assert!(!s.try_consume("key-a")); // key-a exhausted
        assert!(s.try_consume("key-b")); // key-b untouched
    }

    #[test]
    fn test_evict_stale_does_not_remove_non_full_buckets() {
        let s = store_per_second(5);
        s.try_consume("ip-1"); // partially drained
        s.evict_stale();
        // After eviction, next consume should still work (bucket was kept).
        assert!(s.try_consume("ip-1"));
    }
}
