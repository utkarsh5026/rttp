//! API key authentication — validation of static pre-shared keys.
//!
//! Provides a pluggable [`ApiKeyStore`] trait for key-storage backends, an
//! in-memory [`InMemoryApiKeyStore`] backed by a `HashMap`, and per-key metadata
//! via [`ApiKeyIdentity`].
//!
//! # Quick Start
//!
//! ```rust
//! use rttp::security::auth::api_key::{ApiKeyIdentity, ApiKeyStore, InMemoryApiKeyStore};
//!
//! let store = InMemoryApiKeyStore::new()
//!     .add_key("secret-key-abc", ApiKeyIdentity::new("service-a").scope("read"))
//!     .add_key("another-key-xyz", ApiKeyIdentity::new("service-b"));
//!
//! let identity = store.lookup("secret-key-abc");
//! assert!(identity.is_some());
//! assert_eq!(identity.unwrap().name, "service-a");
//! ```

use std::collections::HashMap;

/// Identity metadata attached to a validated API key.
///
/// Returned by [`ApiKeyStore::lookup`] on a successful match and injected into
/// [`Context::extensions`](crate::context::Context) by
/// [`ApiKeyMiddleware`](crate::security::middleware::api_key::ApiKeyMiddleware)
/// so that downstream handlers can read the caller's identity:
///
/// ```rust,no_run
/// use rttp::security::auth::api_key::ApiKeyIdentity;
/// // inside a handler:
/// // let id = ctx.extensions().get::<ApiKeyIdentity>();
/// ```
#[derive(Debug, Clone)]
pub struct ApiKeyIdentity {
    /// Human-readable name for this key (e.g. `"service-a"`, `"admin-cli"`).
    pub name: String,

    /// Access scopes granted to this key (e.g. `["read", "write"]`).
    pub scopes: Vec<String>,

    /// Optional Unix-timestamp expiry. `None` means the key never expires.
    pub expires_at: Option<u64>,
}

impl ApiKeyIdentity {
    /// Create a new identity with the given `name` and no scopes or expiry.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::security::auth::api_key::ApiKeyIdentity;
    ///
    /// let id = ApiKeyIdentity::new("service-a");
    /// assert_eq!(id.name, "service-a");
    /// assert!(id.scopes.is_empty());
    /// assert!(id.expires_at.is_none());
    /// ```
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            scopes: Vec::new(),
            expires_at: None,
        }
    }

    /// Add an access scope to this identity.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::security::auth::api_key::ApiKeyIdentity;
    ///
    /// let id = ApiKeyIdentity::new("svc").scope("read").scope("write");
    /// assert_eq!(id.scopes, ["read", "write"]);
    /// ```
    #[must_use]
    pub fn scope(mut self, scope: impl Into<String>) -> Self {
        self.scopes.push(scope.into());
        self
    }

    /// Set the expiry as a Unix timestamp (seconds since the epoch).
    ///
    /// Requests made after the expiry timestamp are rejected even if the raw key
    /// is correct.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::security::auth::api_key::ApiKeyIdentity;
    ///
    /// let id = ApiKeyIdentity::new("svc").expires_at(9_999_999_999);
    /// assert_eq!(id.expires_at, Some(9_999_999_999));
    /// ```
    #[must_use]
    pub fn expires_at(mut self, ts: u64) -> Self {
        self.expires_at = Some(ts);
        self
    }

    /// Returns `true` if this key has not yet expired relative to `now`.
    ///
    /// A key with no expiry (`expires_at == None`) is always considered valid.
    pub fn is_valid_at(&self, now: u64) -> bool {
        self.expires_at.is_none_or(|exp| now < exp)
    }
}

// ── Trait ─────────────────────────────────────────────────────────────────────

/// Pluggable API key storage backend.
///
/// Implement this trait to provide custom key-lookup logic (e.g. database
/// queries, cache lookups, or external secret manager calls).
///
/// The method is called on **every authenticated request** so implementations
/// should be cheap — e.g. query a hot in-process cache rather than a remote DB
/// on the hot path.
///
/// `Send + Sync` is required because the store is shared across Tokio tasks.
pub trait ApiKeyStore: Send + Sync {
    /// Look up an API key and return its associated [`ApiKeyIdentity`] if valid.
    ///
    /// Implementations must perform a **constant-time** key comparison to
    /// prevent timing-based key enumeration attacks.
    ///
    /// Returns `Some(identity)` when the key is recognized and not expired,
    /// or `None` when the key is unknown or expired.
    fn lookup(&self, key: &str) -> Option<ApiKeyIdentity>;
}

/// In-memory [`ApiKeyStore`] backed by a `HashMap`.
///
/// Suitable for single-instance deployments and testing. Keys are compared
/// using a constant-time equality check to resist timing attacks.
///
/// # Examples
///
/// ```rust
/// use rttp::security::auth::api_key::{ApiKeyIdentity, ApiKeyStore, InMemoryApiKeyStore};
///
/// let store = InMemoryApiKeyStore::new()
///     .add_key("key-abc", ApiKeyIdentity::new("client-a"))
///     .add_key("key-xyz", ApiKeyIdentity::new("client-b").scope("admin"));
///
/// assert!(store.lookup("key-abc").is_some());
/// assert!(store.lookup("unknown").is_none());
/// ```
pub struct InMemoryApiKeyStore {
    keys: HashMap<String, ApiKeyIdentity>,
}

impl InMemoryApiKeyStore {
    /// Create an empty store with no registered keys.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::security::auth::api_key::InMemoryApiKeyStore;
    ///
    /// let store = InMemoryApiKeyStore::new();
    /// ```
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    /// Register an API key with the associated identity.
    ///
    /// If `key` was already registered the entry is overwritten with `identity`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::security::auth::api_key::{ApiKeyIdentity, InMemoryApiKeyStore};
    ///
    /// let store = InMemoryApiKeyStore::new()
    ///     .add_key("my-key", ApiKeyIdentity::new("my-service"));
    /// ```
    #[must_use]
    pub fn add_key(mut self, key: impl Into<String>, identity: ApiKeyIdentity) -> Self {
        self.keys.insert(key.into(), identity);
        self
    }
}

impl Default for InMemoryApiKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Constant-time byte-slice equality.
///
/// Returns `true` iff `a` and `b` have the same length and identical contents.
/// The byte comparison never short-circuits on a mismatch, preventing
/// timing-based attacks that infer key prefixes from response latency.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

impl ApiKeyStore for InMemoryApiKeyStore {
    /// Scan all registered keys with a constant-time comparison and return
    /// the matching [`ApiKeyIdentity`] if the key is recognized and not expired.
    ///
    /// Iterating all entries (rather than using a direct `HashMap` index) ensures
    /// that the lookup time does not vary with whether a key prefix matches, which
    /// would otherwise enable an oracle-style timing attack.
    fn lookup(&self, key: &str) -> Option<ApiKeyIdentity> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let key_bytes = key.as_bytes();
        let mut found: Option<&ApiKeyIdentity> = None;

        for (stored_key, identity) in &self.keys {
            if constant_time_eq(key_bytes, stored_key.as_bytes()) {
                found = Some(identity);
            }
        }

        found.filter(|id| id.is_valid_at(now)).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── ApiKeyIdentity ────────────────────────────────────────────────────────

    #[test]
    fn identity_new_sets_name_and_empty_fields() {
        let id = ApiKeyIdentity::new("svc");
        assert_eq!(id.name, "svc");
        assert!(id.scopes.is_empty());
        assert!(id.expires_at.is_none());
    }

    #[test]
    fn identity_scope_appends_scopes_in_order() {
        let id = ApiKeyIdentity::new("svc").scope("read").scope("write");
        assert_eq!(id.scopes, ["read", "write"]);
    }

    #[test]
    fn identity_expires_at_sets_expiry() {
        let id = ApiKeyIdentity::new("svc").expires_at(12345);
        assert_eq!(id.expires_at, Some(12345));
    }

    #[test]
    fn is_valid_at_no_expiry_is_always_true() {
        let id = ApiKeyIdentity::new("svc");
        assert!(id.is_valid_at(0));
        assert!(id.is_valid_at(u64::MAX));
    }

    #[test]
    fn is_valid_at_before_expiry_is_true() {
        let id = ApiKeyIdentity::new("svc").expires_at(1000);
        assert!(id.is_valid_at(999));
    }

    #[test]
    fn is_valid_at_at_expiry_timestamp_is_false() {
        let id = ApiKeyIdentity::new("svc").expires_at(1000);
        assert!(!id.is_valid_at(1000));
    }

    #[test]
    fn is_valid_at_after_expiry_is_false() {
        let id = ApiKeyIdentity::new("svc").expires_at(1000);
        assert!(!id.is_valid_at(1001));
    }

    // ── constant_time_eq ──────────────────────────────────────────────────────

    #[test]
    fn constant_time_eq_identical_slices_returns_true() {
        assert!(constant_time_eq(b"hello", b"hello"));
    }

    #[test]
    fn constant_time_eq_different_content_returns_false() {
        assert!(!constant_time_eq(b"hello", b"world"));
    }

    #[test]
    fn constant_time_eq_different_lengths_returns_false() {
        assert!(!constant_time_eq(b"hi", b"hello"));
    }

    #[test]
    fn constant_time_eq_empty_slices_returns_true() {
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn constant_time_eq_one_byte_off_returns_false() {
        assert!(!constant_time_eq(b"abc", b"abd"));
    }

    // ── InMemoryApiKeyStore ───────────────────────────────────────────────────

    fn make_store() -> InMemoryApiKeyStore {
        InMemoryApiKeyStore::new()
            .add_key("valid-key", ApiKeyIdentity::new("service-a").scope("read"))
            .add_key("admin-key", ApiKeyIdentity::new("admin").scope("write"))
    }

    #[test]
    fn lookup_known_key_returns_identity() {
        let id = make_store().lookup("valid-key");
        assert!(id.is_some());
        assert_eq!(id.unwrap().name, "service-a");
    }

    #[test]
    fn lookup_second_key_returns_correct_identity() {
        let id = make_store().lookup("admin-key");
        assert!(id.is_some());
        assert_eq!(id.unwrap().name, "admin");
    }

    #[test]
    fn lookup_unknown_key_returns_none() {
        assert!(make_store().lookup("bad-key").is_none());
    }

    #[test]
    fn lookup_empty_string_returns_none() {
        assert!(make_store().lookup("").is_none());
    }

    #[test]
    fn lookup_key_prefix_returns_none() {
        // "valid" is a prefix of "valid-key" but must not match.
        assert!(make_store().lookup("valid").is_none());
    }

    #[test]
    fn lookup_key_returns_correct_scopes() {
        let id = make_store().lookup("admin-key").unwrap();
        assert_eq!(id.scopes, ["write"]);
    }

    #[test]
    fn add_key_overwrites_existing_entry() {
        let store = InMemoryApiKeyStore::new()
            .add_key("k", ApiKeyIdentity::new("first"))
            .add_key("k", ApiKeyIdentity::new("second"));
        assert_eq!(store.lookup("k").unwrap().name, "second");
    }

    #[test]
    fn lookup_expired_key_returns_none() {
        // expires_at = 1 is long in the past.
        let store =
            InMemoryApiKeyStore::new().add_key("old", ApiKeyIdentity::new("svc").expires_at(1));
        assert!(store.lookup("old").is_none());
    }

    #[test]
    fn lookup_far_future_expiry_returns_identity() {
        let store = InMemoryApiKeyStore::new()
            .add_key("fresh", ApiKeyIdentity::new("svc").expires_at(u64::MAX));
        assert!(store.lookup("fresh").is_some());
    }

    #[test]
    fn empty_store_always_returns_none() {
        assert!(InMemoryApiKeyStore::new().lookup("any-key").is_none());
    }
}
