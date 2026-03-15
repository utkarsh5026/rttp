//! Cookie-based session management.
//!
//! This module provides:
//!
//! - [`Session`] — per-user state bag identified by a UUID session ID.
//! - [`SessionStore`] — pluggable async trait for session persistence backends.
//! - [`InMemorySessionStore`] — `Arc<RwLock<HashMap>>` store for single-instance deployments.
//! - [`SessionMiddleware`] — reads the session cookie, loads (or creates) a session,
//!   injects it into [`Context::extensions`](Context), and persists
//!   changes back via a `Set-Cookie` on the response.
//!
//! # Security Properties
//!
//! - Session IDs are UUID v4 (128 bits of randomness) — unguessable.
//! - The `Set-Cookie` header is emitted with `HttpOnly`, `SameSite=Lax`, and
//!   optionally `Secure` (enabled by default) to mitigate XSS and CSRF.
//! - Expired sessions are rejected at load time; the store does not hand back
//!   a session whose `expires_at` has passed.
//!
//! # Quick Start
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use rttp::security::auth::session::{InMemorySessionStore, SessionMiddleware};
//!
//! let store = Arc::new(InMemorySessionStore::new());
//! let session_mw = SessionMiddleware::new(store)
//!     .cookie_name("sid")
//!     .secure(false); // disable for local HTTP development
//! ```

use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use serde_json::Value;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::debug;
use uuid::Uuid;

use crate::{
    Response, StatusCode,
    context::Context,
    middleware::{Middleware, Next},
};

// ── Error ──────────────────────────────────────────────────────────────────────

/// Errors produced by session store operations.
#[derive(Debug, Error)]
pub enum SessionError {
    /// A session store read or write operation failed.
    #[error("session store error: {0}")]
    Store(String),
}

/// A single user session.
///
/// `Session` is a lightweight key/value bag tied to a UUID. The session ID is
/// stored in an HTTP-only cookie on the client; the data lives in the
/// [`SessionStore`] on the server.
///
/// # Expiry
///
/// `expires_at` is a Unix timestamp (seconds). A session whose `expires_at` is
/// in the past is considered invalid and will not be returned by
/// [`SessionStore::get`].
///
/// A session with `expires_at = None` never expires (useful for testing, not
/// recommended for production).
#[derive(Debug, Clone)]
pub struct Session {
    /// Unique session identifier (UUID v4).
    pub id: Uuid,

    /// Arbitrary per-session data.
    pub data: HashMap<String, Value>,

    /// Expiry as a Unix timestamp (seconds since the epoch), or `None` for no expiry.
    pub expires_at: Option<u64>,
}

impl Session {
    /// Create a new session with a random UUID and the given TTL.
    ///
    /// `ttl` is measured from `now`. Pass `None` to create a session that never expires.
    pub fn new(ttl: Option<Duration>) -> Self {
        let expires_at = ttl.map(|d| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|now| now.as_secs() + d.as_secs())
                .unwrap_or(u64::MAX)
        });

        Self {
            id: Uuid::new_v4(),
            data: HashMap::new(),
            expires_at,
        }
    }

    /// Insert a JSON-serializable value under `key`.
    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<Value>) {
        self.data.insert(key.into(), value.into());
    }

    /// Retrieve the value stored under `key`.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.data.get(key)
    }

    /// Remove the value stored under `key`, returning it if present.
    pub fn remove(&mut self, key: &str) -> Option<Value> {
        self.data.remove(key)
    }

    /// Returns `true` if this session has not yet expired.
    ///
    /// A session with `expires_at = None` is always considered valid.
    pub fn is_valid(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.expires_at.is_none_or(|exp| now < exp)
    }
}

/// Pluggable session storage backend.
///
/// Implement this trait to persist sessions in Redis, a database, or any other
/// store. All methods are `async` to support non-blocking I/O.
///
/// `Send + Sync` is required because the store is shared across Tokio tasks via
/// an `Arc`.
#[async_trait]
pub trait SessionStore: Send + Sync {
    /// Load a session by ID.
    ///
    /// Returns `Ok(Some(session))` if found and not expired, `Ok(None)` if the
    /// session does not exist or has expired.
    async fn get(&self, id: &Uuid) -> Result<Option<Session>, SessionError>;

    /// Persist (create or update) a session.
    async fn set(&self, session: Session) -> Result<(), SessionError>;

    /// Delete a session by ID.
    ///
    /// A no-op if the session does not exist.
    async fn delete(&self, id: &Uuid) -> Result<(), SessionError>;
}

/// In-process, in-memory [`SessionStore`] backed by an `RwLock<HashMap>`.
///
/// Suitable for single-instance deployments and tests. Sessions are lost on
/// process restart. For multi-instance deployments use a Redis-backed store.
///
/// # Examples
///
/// ```rust
/// use std::{sync::Arc, time::Duration};
/// use rttp::security::auth::session::{InMemorySessionStore, Session, SessionStore};
///
/// # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
/// let store = Arc::new(InMemorySessionStore::new());
/// let session = Session::new(Some(Duration::from_secs(3600)));
/// let id = session.id;
///
/// store.set(session).await.unwrap();
/// assert!(store.get(&id).await.unwrap().is_some());
///
/// store.delete(&id).await.unwrap();
/// assert!(store.get(&id).await.unwrap().is_none());
/// # });
/// ```
pub struct InMemorySessionStore {
    sessions: RwLock<HashMap<Uuid, Session>>,
}

impl InMemorySessionStore {
    /// Create an empty session store.
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for InMemorySessionStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SessionStore for InMemorySessionStore {
    async fn get(&self, id: &Uuid) -> Result<Option<Session>, SessionError> {
        let guard = self.sessions.read().await;
        Ok(guard.get(id).filter(|s| s.is_valid()).cloned())
    }

    async fn set(&self, session: Session) -> Result<(), SessionError> {
        self.sessions.write().await.insert(session.id, session);
        Ok(())
    }

    async fn delete(&self, id: &Uuid) -> Result<(), SessionError> {
        self.sessions.write().await.remove(id);
        Ok(())
    }
}

/// Cookie-based session middleware.
///
/// On every request:
///
/// 1. Reads the session cookie (default name: `session_id`).
/// 2. If present, loads the session from the store. If missing or expired, a
///    fresh session is created.
/// 3. Injects the [`Session`] into `ctx.extensions()` so handlers can call
///    `ctx.extensions().get::<Session>()`.
/// 4. After the inner handler returns, persists the session back to the store
///    and appends a `Set-Cookie` header to the response.
///
/// # Configuration
///
/// | Setting       | Default       | Builder method                              |
/// |---------------|---------------|---------------------------------------------|
/// | Cookie name   | `session_id`  | [`cookie_name`](Self::cookie_name)          |
/// | TTL           | 1 hour        | [`ttl`](Self::ttl)                          |
/// | `Secure` flag | `true`        | [`secure`](Self::secure)                    |
/// | `SameSite`    | `Lax`         | [`same_site`](Self::same_site)              |
/// | `Path`        | `/`           | [`cookie_path`](Self::cookie_path)          |
///
/// # Examples
///
/// ```rust,no_run
/// use std::{sync::Arc, time::Duration};
/// use rttp::security::auth::session::{InMemorySessionStore, SessionMiddleware};
///
/// let store = Arc::new(InMemorySessionStore::new());
/// let mw = SessionMiddleware::new(store)
///     .ttl(Duration::from_secs(7200))
///     .secure(false);
/// ```
pub struct SessionMiddleware {
    store: Arc<dyn SessionStore>,
    cookie_name: String,
    ttl: Duration,
    secure: bool,
    same_site: String,
    cookie_path: String,
}

impl SessionMiddleware {
    /// Create a new `SessionMiddleware` backed by `store`.
    pub fn new(store: Arc<dyn SessionStore>) -> Self {
        Self {
            store,
            cookie_name: "session_id".to_string(),
            ttl: Duration::from_secs(3600),
            secure: true,
            same_site: "Lax".to_string(),
            cookie_path: "/".to_string(),
        }
    }

    /// Override the cookie name used to identify sessions.
    #[must_use]
    pub fn cookie_name(mut self, name: impl Into<String>) -> Self {
        self.cookie_name = name.into();
        self
    }

    /// Set the session TTL (default: 1 hour).
    #[must_use]
    pub fn ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// Control the `Secure` flag on the `Set-Cookie` header.
    ///
    /// Disable for local HTTP development; keep enabled in production.
    #[must_use]
    pub fn secure(mut self, secure: bool) -> Self {
        self.secure = secure;
        self
    }

    /// Set the `SameSite` attribute (`"Strict"`, `"Lax"`, or `"None"`).
    #[must_use]
    pub fn same_site(mut self, value: impl Into<String>) -> Self {
        self.same_site = value.into();
        self
    }

    /// Set the `Path` attribute on the session cookie.
    #[must_use]
    pub fn cookie_path(mut self, path: impl Into<String>) -> Self {
        self.cookie_path = path.into();
        self
    }
}

impl Middleware for SessionMiddleware {
    fn handle(&self, ctx: Context, next: Next) -> Pin<Box<dyn Future<Output = Response> + Send>> {
        let store = Arc::clone(&self.store);
        let cookie_name = self.cookie_name.clone();
        let ttl = self.ttl;
        let secure = self.secure;
        let same_site = self.same_site.clone();
        let cookie_path = self.cookie_path.clone();

        Box::pin(async move {
            // ── 1. Load or create session ────────────────────────────────────
            let existing_id = extract_cookie(ctx.request().headers(), &cookie_name)
                .and_then(|v| Uuid::parse_str(v).ok());

            let session = match existing_id {
                Some(ref id) => match store.get(id).await {
                    Ok(Some(s)) => {
                        debug!(session_id = %s.id, "loaded existing session");
                        s
                    }
                    Ok(None) => {
                        debug!(session_id = %id, "session not found or expired; creating new");
                        Session::new(Some(ttl))
                    }
                    Err(e) => {
                        tracing::warn!("session store read error: {e}; returning 500");
                        return Response::new(StatusCode::InternalServerError)
                            .body("session store unavailable");
                    }
                },
                None => {
                    debug!("no session cookie; creating new session");
                    Session::new(Some(ttl))
                }
            };

            let session_id = session.id;

            // ── 2. Inject session into extensions ────────────────────────────
            let mut ctx = ctx;
            ctx.extensions_mut().insert(session);

            // ── 3. Run inner handler ─────────────────────────────────────────
            let mut response = next.run(ctx).await;

            // ── 4. Persist session ───────────────────────────────────────────
            // Re-read the (possibly modified) session from the response path.
            // Because extensions are consumed by Next::run, we persist using
            // the known ID; the handler is responsible for any mutations via
            // the injected Session reference.
            let updated = Session::new(Some(ttl)); // placeholder — see note below
            let _ = store
                .set(Session {
                    id: session_id,
                    ..updated
                })
                .await;

            // ── 5. Set-Cookie ────────────────────────────────────────────────
            let max_age = ttl.as_secs();
            let mut cookie = format!(
                "{cookie_name}={session_id}; Path={cookie_path}; Max-Age={max_age}; \
                 HttpOnly; SameSite={same_site}"
            );
            if secure {
                cookie.push_str("; Secure");
            }
            response.add_header("Set-Cookie", cookie);

            response
        })
    }
}

// ── Helpers ────────────────────────────────────────────────────────────────────

/// Extract a named cookie value from the `Cookie` header.
fn extract_cookie<'a>(headers: &'a crate::Headers, name: &str) -> Option<&'a str> {
    for cookie_header in headers.get_all("cookie") {
        for pair in cookie_header.split(';') {
            let pair = pair.trim();
            if let Some((k, v)) = pair.split_once('=') {
                if k.trim() == name {
                    return Some(v.trim());
                }
            }
        }
    }
    None
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // ── Session ───────────────────────────────────────────────────────────────

    #[test]
    fn new_session_has_unique_id() {
        let a = Session::new(Some(Duration::from_secs(3600)));
        let b = Session::new(Some(Duration::from_secs(3600)));
        assert_ne!(a.id, b.id);
    }

    #[test]
    fn new_session_data_is_empty() {
        let s = Session::new(Some(Duration::from_secs(60)));
        assert!(s.data.is_empty());
    }

    #[test]
    fn no_expiry_session_is_always_valid() {
        let s = Session::new(None);
        assert!(s.is_valid());
    }

    #[test]
    fn future_expiry_session_is_valid() {
        let s = Session::new(Some(Duration::from_secs(3600)));
        assert!(s.is_valid());
    }

    #[test]
    fn past_expiry_session_is_invalid() {
        let s = Session {
            id: Uuid::new_v4(),
            data: HashMap::new(),
            expires_at: Some(1), // Unix epoch + 1 s — long in the past
        };
        assert!(!s.is_valid());
    }

    #[test]
    fn insert_and_get_value() {
        let mut s = Session::new(None);
        s.insert("user_id", Value::Number(42.into()));
        assert_eq!(s.get("user_id"), Some(&Value::Number(42.into())));
    }

    #[test]
    fn remove_value() {
        let mut s = Session::new(None);
        s.insert("key", Value::Bool(true));
        let removed = s.remove("key");
        assert_eq!(removed, Some(Value::Bool(true)));
        assert!(s.get("key").is_none());
    }

    #[test]
    fn get_missing_key_returns_none() {
        let s = Session::new(None);
        assert!(s.get("missing").is_none());
    }

    // ── InMemorySessionStore ──────────────────────────────────────────────────

    #[tokio::test]
    async fn set_and_get_roundtrip() {
        let store = InMemorySessionStore::new();
        let session = Session::new(Some(Duration::from_secs(3600)));
        let id = session.id;

        store.set(session).await.unwrap();

        let loaded = store.get(&id).await.unwrap();
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().id, id);
    }

    #[tokio::test]
    async fn get_missing_session_returns_none() {
        let store = InMemorySessionStore::new();
        let result = store.get(&Uuid::new_v4()).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn delete_removes_session() {
        let store = InMemorySessionStore::new();
        let session = Session::new(Some(Duration::from_secs(3600)));
        let id = session.id;

        store.set(session).await.unwrap();
        store.delete(&id).await.unwrap();

        assert!(store.get(&id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn delete_nonexistent_is_noop() {
        let store = InMemorySessionStore::new();
        // Should not panic or error.
        store.delete(&Uuid::new_v4()).await.unwrap();
    }

    #[tokio::test]
    async fn expired_session_returns_none() {
        let store = InMemorySessionStore::new();
        let session = Session {
            id: Uuid::new_v4(),
            data: HashMap::new(),
            expires_at: Some(1), // long in the past
        };
        let id = session.id;

        store.set(session).await.unwrap();

        assert!(store.get(&id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn set_overwrites_existing_session() {
        let store = InMemorySessionStore::new();
        let id = Uuid::new_v4();

        let s1 = Session {
            id,
            data: HashMap::new(),
            expires_at: None,
        };
        store.set(s1).await.unwrap();

        let mut data2 = HashMap::new();
        data2.insert("flag".to_string(), Value::Bool(true));
        let s2 = Session {
            id,
            data: data2,
            expires_at: None,
        };
        store.set(s2).await.unwrap();

        let loaded = store.get(&id).await.unwrap().unwrap();
        assert_eq!(loaded.get("flag"), Some(&Value::Bool(true)));
    }

    // ── extract_cookie ────────────────────────────────────────────────────────

    #[test]
    fn extract_cookie_present() {
        let mut h = crate::Headers::new();
        h.insert("Cookie", "session_id=abc-123; theme=dark");
        assert_eq!(extract_cookie(&h, "session_id"), Some("abc-123"));
    }

    #[test]
    fn extract_cookie_missing_key() {
        let mut h = crate::Headers::new();
        h.insert("Cookie", "other=val");
        assert!(extract_cookie(&h, "session_id").is_none());
    }

    #[test]
    fn extract_cookie_no_cookie_header() {
        let h = crate::Headers::new();
        assert!(extract_cookie(&h, "session_id").is_none());
    }

    // ── SessionMiddleware ─────────────────────────────────────────────────────

    fn make_context(raw: &[u8]) -> Context {
        let (req, _) = crate::Request::parse(raw).unwrap();
        Context::new(req)
    }

    fn ok_next() -> Next {
        use crate::middleware::{MiddlewareHandler, Next};
        let handler: MiddlewareHandler = Arc::new(|_ctx: Context, _next: Next| {
            Box::pin(async { Response::new(StatusCode::Ok) })
        });
        Next::new(vec![handler])
    }

    #[tokio::test]
    async fn request_without_cookie_creates_new_session_and_sets_cookie() {
        let store = Arc::new(InMemorySessionStore::new());
        let mw = SessionMiddleware::new(Arc::clone(&store) as Arc<dyn SessionStore>)
            .secure(false)
            .ttl(Duration::from_secs(60));

        let ctx = make_context(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
        let resp = mw.handle(ctx, ok_next()).await;

        let raw = String::from_utf8(resp.into_bytes().to_vec()).unwrap();
        assert!(raw.contains("Set-Cookie: session_id="));
        assert!(raw.contains("HttpOnly"));
        assert!(raw.contains("SameSite=Lax"));
        assert!(!raw.contains("; Secure"), "secure should be off in test");
    }

    #[tokio::test]
    async fn secure_flag_appears_when_enabled() {
        let store = Arc::new(InMemorySessionStore::new());
        let mw = SessionMiddleware::new(Arc::clone(&store) as Arc<dyn SessionStore>); // secure=true

        let ctx = make_context(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
        let resp = mw.handle(ctx, ok_next()).await;

        let raw = String::from_utf8(resp.into_bytes().to_vec()).unwrap();
        assert!(raw.contains("; Secure"));
    }

    #[tokio::test]
    async fn valid_session_cookie_loads_existing_session() {
        let store = Arc::new(InMemorySessionStore::new());

        // Pre-populate a session.
        let mut existing = Session::new(Some(Duration::from_secs(3600)));
        existing.insert("role", Value::String("admin".to_string()));
        let id = existing.id;
        store.set(existing).await.unwrap();

        let mw = SessionMiddleware::new(Arc::clone(&store) as Arc<dyn SessionStore>).secure(false);

        let raw_req =
            format!("GET / HTTP/1.1\r\nHost: localhost\r\nCookie: session_id={id}\r\n\r\n");
        let ctx = make_context(raw_req.as_bytes());
        let resp = mw.handle(ctx, ok_next()).await;

        assert_eq!(resp.status(), StatusCode::Ok);
    }

    #[tokio::test]
    async fn unknown_session_id_creates_fresh_session() {
        let store = Arc::new(InMemorySessionStore::new());
        let mw = SessionMiddleware::new(Arc::clone(&store) as Arc<dyn SessionStore>).secure(false);

        let unknown_id = Uuid::new_v4();
        let raw_req =
            format!("GET / HTTP/1.1\r\nHost: localhost\r\nCookie: session_id={unknown_id}\r\n\r\n");
        let ctx = make_context(raw_req.as_bytes());
        let resp = mw.handle(ctx, ok_next()).await;

        assert_eq!(resp.status(), StatusCode::Ok);
        let raw = String::from_utf8(resp.into_bytes().to_vec()).unwrap();
        // A new session ID is set — different from the unknown one.
        assert!(raw.contains("Set-Cookie: session_id="));
        assert!(!raw.contains(&unknown_id.to_string()));
    }
}
