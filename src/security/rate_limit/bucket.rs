//! Token bucket — the core algorithm for burst-tolerant rate limiting.
//!
//! The bucket starts full and drains by one token per request. It refills
//! continuously at a fixed rate up to its capacity. Bursts are absorbed by
//! the pre-filled tokens; sustained traffic above the refill rate is throttled.

use std::time::{Duration, Instant};

/// Configuration for a token-bucket rate limiter.
pub struct RateLimitConfig {
    /// Maximum number of tokens (requests) in the bucket.
    pub capacity: f64,
    /// Token refill rate (tokens per second).
    pub refill_rate: f64,
    /// Nominal time window — used to derive the refill rate.
    pub window: Duration,
}

impl RateLimitConfig {
    /// Build a config allowing `max_requests` per `window_secs` second window.
    pub fn new(max_requests: u32, window_secs: u64) -> Self {
        let capacity = max_requests as f64;
        let refill_rate = capacity / window_secs as f64;

        Self {
            capacity,
            refill_rate,
            window: Duration::from_secs(window_secs),
        }
    }

    /// Allow `max_requests` per second.
    pub fn per_second(max_requests: u32) -> Self {
        Self::new(max_requests, 1)
    }

    /// Allow `max_requests` per minute.
    pub fn per_minute(max_requests: u32) -> Self {
        Self::new(max_requests, 60)
    }

    /// Allow `max_requests` per hour.
    pub fn per_hour(max_requests: u32) -> Self {
        Self::new(max_requests, 3600)
    }
}

/// Token bucket for rate limiting a single key (e.g., one client IP).
#[derive(Debug, Clone)]
pub(crate) struct TokenBucket {
    /// Current number of available tokens.
    tokens: f64,
    /// Last time tokens were refilled.
    last_update: Instant,
    /// Maximum token capacity.
    capacity: f64,
    /// Refill rate in tokens per second.
    refill_rate: f64,
}

impl TokenBucket {
    /// Create a new, full token bucket.
    pub(crate) fn new(capacity: f64, refill_rate: f64) -> Self {
        Self {
            tokens: capacity,
            last_update: Instant::now(),
            capacity,
            refill_rate,
        }
    }

    /// Returns `true` if the bucket is at full capacity (no tokens have been consumed
    /// recently enough to matter). Used by [`super::store::InMemoryStore::evict_stale`].
    pub(super) fn is_full(&mut self) -> bool {
        // Refill first so that a bucket that was drained long ago reads as full.
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.capacity);
        self.last_update = now;
        self.tokens >= self.capacity
    }

    /// Attempt to consume one token.
    ///
    /// Refills based on elapsed time, then deducts one token.
    /// Returns `true` if the request is allowed, `false` if the bucket is empty.
    pub(crate) fn try_consume(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.capacity);
        self.last_update = now;

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}
