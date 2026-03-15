//! JWT token revocation via a pluggable blocklist.
//!
//! # Overview
//!
//! JWTs are stateless — once issued they stay valid until their `exp` claim
//! passes, with no built-in revocation mechanism.  A blocklist solves this by
//! recording the `jti` (JWT ID) of every token that should be treated as
//! invalid before its natural expiry.
//!
//! # Design
//!
//! [`TokenBlocklist`] is an async trait.  Implement it against whatever storage
//! backend you need (Redis, Postgres, Memcached, …).  rttp ships one built-in
//! implementation — [`InMemoryBlocklist`] — which is backed by a
//! `tokio::sync::RwLock<HashMap>` and suitable for single-process deployments
//! or testing.
//!
//! # Using the blocklist with `JwtMiddleware`
//!
//! Wrap your implementation in an `Arc` and pass it to the middleware:
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use rttp::security::token::blocklist::{InMemoryBlocklist, TokenBlocklist};
//!
//! let blocklist: Arc<dyn TokenBlocklist> = Arc::new(InMemoryBlocklist::new());
//! // pass `blocklist` to JwtMiddleware (once that integration is wired up)
//! ```
//!
//! # Rolling your own backend
//!
//! ```rust,no_run
//! use std::time::Instant;
//! use rttp::security::token::blocklist::{BlocklistError, TokenBlocklist};
//!
//! struct RedisBlocklist { /* ... */ }
//!
//! #[async_trait::async_trait]
//! impl TokenBlocklist for RedisBlocklist {
//!     async fn revoke(&self, jti: &str, exp: Instant) -> Result<(), BlocklistError> {
//!         // SET jti "" EX <ttl> in Redis
//!         todo!()
//!     }
//!
//!     async fn is_blocked(&self, jti: &str) -> Result<bool, BlocklistError> {
//!         // EXISTS jti
//!         todo!()
//!     }
//!
//!     async fn prune(&self) -> Result<usize, BlocklistError> {
//!         // Redis TTL handles expiry automatically; nothing to do
//!         Ok(0)
//!     }
//! }
//! ```

use std::{collections::HashMap, time::Instant};

use thiserror::Error;
use tokio::sync::RwLock;

/// Errors returned by [`TokenBlocklist`] operations.
#[derive(Debug, Error)]
pub enum BlocklistError {
    /// The underlying storage backend returned an error.
    #[error("blocklist backend error: {0}")]
    Backend(String),
}

/// A pluggable store for revoked JWT IDs (`jti` claims).
///
/// Implement this trait against any storage backend — in-process memory,
/// Redis, Postgres, etc.  Wrap the implementation in [`std::sync::Arc`] and
/// pass it to `JwtMiddleware` to enable per-token revocation.
///
/// # Contract
///
/// - [`TokenBlocklist::revoke`] records a `jti` as revoked until `exp`.
/// - [`TokenBlocklist::is_blocked`] must return `true` for any `jti` that has
///   been revoked and whose `exp` has not yet passed.
/// - [`TokenBlocklist::prune`] removes entries whose `exp` has passed.  This
///   is a no-op for backends (like Redis) that expire entries automatically.
///
/// All methods take `&self` so the implementation can use interior mutability
/// (e.g. `RwLock`, a connection pool, or an HTTP client).
#[async_trait::async_trait]
pub trait TokenBlocklist: Send + Sync {
    /// Mark a token as revoked.
    ///
    /// # Arguments
    ///
    /// - `jti` — the unique JWT ID from the token's `jti` claim.
    /// - `exp` — the point in time at which the token would naturally expire.
    ///   The blocklist may use this to evict the entry automatically.
    async fn revoke(&self, jti: &str, exp: Instant) -> Result<(), BlocklistError>;

    /// Returns `true` if `jti` has been revoked and not yet expired.
    async fn is_blocked(&self, jti: &str) -> Result<bool, BlocklistError>;

    /// Remove entries whose expiry has passed.
    ///
    /// Returns the number of entries removed.  Backends with native TTL support
    /// (Redis, Memcached) can return `Ok(0)` without doing any work.
    async fn prune(&self) -> Result<usize, BlocklistError>;
}

/// A single-process, in-memory [`TokenBlocklist`] backed by a `HashMap`.
///
/// Suitable for development, testing, and single-instance deployments.
/// Entries are evicted lazily on [`InMemoryBlocklist::is_blocked`] and eagerly
/// via [`InMemoryBlocklist::prune`].
///
/// # Thread safety
///
/// Internally protected by a `tokio::sync::RwLock`.  Safe to share across
/// tasks via `Arc<InMemoryBlocklist>`.
///
/// # Limitations
///
/// - Revocations are lost on process restart.
/// - Not suitable for multi-instance deployments — use a shared backend
///   (Redis, Postgres) in that case.
///
/// # Examples
///
/// ```rust
/// use std::{sync::Arc, time::{Duration, Instant}};
/// use rttp::security::token::blocklist::{InMemoryBlocklist, TokenBlocklist};
///
/// # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
/// let bl = Arc::new(InMemoryBlocklist::new());
/// let exp = Instant::now() + Duration::from_secs(3600);
///
/// bl.revoke("jti-abc", exp).await.unwrap();
/// assert!(bl.is_blocked("jti-abc").await.unwrap());
/// assert!(!bl.is_blocked("jti-xyz").await.unwrap());
/// # });
/// ```
pub struct InMemoryBlocklist {
    /// Map of `jti` → expiry `Instant`.
    entries: RwLock<HashMap<String, Instant>>,
}

impl InMemoryBlocklist {
    /// Create an empty blocklist.
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryBlocklist {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl TokenBlocklist for InMemoryBlocklist {
    async fn revoke(&self, jti: &str, exp: Instant) -> Result<(), BlocklistError> {
        self.entries.write().await.insert(jti.to_owned(), exp);
        Ok(())
    }

    async fn is_blocked(&self, jti: &str) -> Result<bool, BlocklistError> {
        let guard = self.entries.read().await;
        match guard.get(jti) {
            None => Ok(false),
            Some(&exp) => Ok(Instant::now() < exp),
        }
    }

    async fn prune(&self) -> Result<usize, BlocklistError> {
        let now = Instant::now();
        let mut guard = self.entries.write().await;
        let before = guard.len();
        guard.retain(|_, exp| now < *exp);
        Ok(before - guard.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn bl() -> InMemoryBlocklist {
        InMemoryBlocklist::new()
    }

    #[tokio::test]
    async fn unknown_jti_is_not_blocked() {
        assert!(!bl().is_blocked("unknown").await.unwrap());
    }

    #[tokio::test]
    async fn revoked_jti_is_blocked() {
        let bl = bl();
        let exp = Instant::now() + Duration::from_secs(3600);
        bl.revoke("jti-1", exp).await.unwrap();
        assert!(bl.is_blocked("jti-1").await.unwrap());
    }

    #[tokio::test]
    async fn expired_entry_is_not_blocked() {
        let bl = bl();
        // exp in the past
        let exp = Instant::now() - Duration::from_secs(1);
        bl.revoke("jti-old", exp).await.unwrap();
        assert!(!bl.is_blocked("jti-old").await.unwrap());
    }

    #[tokio::test]
    async fn prune_removes_expired_entries() {
        let bl = bl();
        let future = Instant::now() + Duration::from_secs(3600);
        let past = Instant::now() - Duration::from_secs(1);

        bl.revoke("live", future).await.unwrap();
        bl.revoke("dead", past).await.unwrap();

        let removed = bl.prune().await.unwrap();
        assert_eq!(removed, 1);
        assert!(bl.is_blocked("live").await.unwrap());
    }

    #[tokio::test]
    async fn prune_on_empty_blocklist_returns_zero() {
        assert_eq!(bl().prune().await.unwrap(), 0);
    }
}
