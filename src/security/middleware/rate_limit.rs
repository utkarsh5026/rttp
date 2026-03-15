//! Rate-limiting middleware.
//!
//! [`RateLimitMiddleware`] sits in the middleware pipeline and throttles
//! requests that exceed the configured limit. Throttled requests receive a
//! `429 Too Many Requests` response with a `Retry-After` header; they never
//! reach the downstream handler.
//!
//! The middleware delegates state management to a [`RateLimitStore`], so you
//! can swap in any backend without changing the middleware itself.
//!
//! # Examples
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use rttp::security::rate_limit::{RateLimitConfig, store::InMemoryStore};
//! use rttp::security::middleware::RateLimitMiddleware;
//! use rttp::middleware::from_middleware;
//!
//! // Allow 100 requests per minute per client IP.
//! let store = InMemoryStore::from_config(&RateLimitConfig::per_minute(100));
//! let mw = from_middleware(Arc::new(RateLimitMiddleware::new(store)));
//! ```

use std::{future::Future, pin::Pin, sync::Arc};

use tracing::debug;

use crate::{
    Response, StatusCode,
    context::Context,
    middleware::{Middleware, Next},
    security::middleware::util::extract_client_ip,
    security::rate_limit::store::RateLimitStore,
};

/// Strategy for deriving the rate-limit key from an incoming request.
pub enum KeyStrategy {
    /// Use the leftmost entry in `X-Forwarded-For`, falling back to
    /// `X-Real-IP`, and finally to the string `"unknown"`.
    ClientIp,
    /// Use the value of the named request header as the key.
    ///
    /// Useful for keying on API tokens, user IDs, or any other header.
    Header(String),
}

/// Rate-limiting middleware.
///
/// Consumes one token per request from the configured [`RateLimitStore`].
/// When the store returns `false` (bucket empty), the middleware short-circuits
/// with `429 Too Many Requests` and a `Retry-After: <secs>` header.
///
/// The downstream handler is **not** called for throttled requests.
pub struct RateLimitMiddleware {
    store: Arc<dyn RateLimitStore>,
    key_strategy: KeyStrategy,
    /// Value written to the `Retry-After` header on throttled responses.
    retry_after_secs: u64,
    /// If set, emits `X-RateLimit-Limit` on every response.
    limit_header_value: Option<String>,
}

impl RateLimitMiddleware {
    /// Create a new middleware backed by `store`, keyed on client IP.
    #[must_use]
    pub fn new(store: impl RateLimitStore + 'static) -> Self {
        Self {
            store: Arc::new(store),
            key_strategy: KeyStrategy::ClientIp,
            retry_after_secs: 60,
            limit_header_value: None,
        }
    }

    /// Advertise the rate limit in `X-RateLimit-Limit` on every response.
    #[must_use]
    pub fn with_limit_header(mut self, max_requests: u64) -> Self {
        self.limit_header_value = Some(max_requests.to_string());
        self
    }

    /// Override the key extraction strategy.
    #[must_use]
    pub fn with_key_strategy(mut self, strategy: KeyStrategy) -> Self {
        self.key_strategy = strategy;
        self
    }

    /// Override the `Retry-After` value sent to throttled clients (seconds).
    #[must_use]
    pub fn with_retry_after(mut self, secs: u64) -> Self {
        self.retry_after_secs = secs;
        self
    }

    fn extract_key(&self, ctx: &Context) -> String {
        match &self.key_strategy {
            KeyStrategy::ClientIp => extract_client_ip(ctx),

            KeyStrategy::Header(name) => ctx
                .request()
                .headers()
                .get(name.as_str())
                .map(str::to_owned)
                .unwrap_or_else(|| "unknown".to_owned()),
        }
    }
}

impl Middleware for RateLimitMiddleware {
    fn handle(&self, ctx: Context, next: Next) -> Pin<Box<dyn Future<Output = Response> + Send>> {
        let store = Arc::clone(&self.store);
        let key = self.extract_key(&ctx);
        let retry_after = self.retry_after_secs.to_string();
        let limit_header = self.limit_header_value.clone();

        Box::pin(async move {
            if store.try_consume(&key) {
                debug!(rate_limit.key = %key, "allowed");
                let mut resp = next.run(ctx).await;
                if let Some(limit) = limit_header {
                    resp.add_header("X-RateLimit-Limit", limit);
                }
                resp
            } else {
                debug!(rate_limit.key = %key, "throttled — sending 429");
                let mut resp = Response::new(StatusCode::TooManyRequests)
                    .header("Retry-After", retry_after)
                    .header("X-RateLimit-Remaining", "0")
                    .body("Too Many Requests");
                if let Some(limit) = limit_header {
                    resp.add_header("X-RateLimit-Limit", limit);
                }
                resp
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        Response, StatusCode,
        context::Context,
        middleware::Middleware,
        security::middleware::test_helpers::{make_context, ok_next, response_to_string},
        security::rate_limit::{RateLimitConfig, store::InMemoryStore},
    };

    use super::{KeyStrategy, RateLimitMiddleware};

    fn make_mw(max_per_second: u32) -> RateLimitMiddleware {
        let store = InMemoryStore::from_config(&RateLimitConfig::per_second(max_per_second));
        RateLimitMiddleware::new(store)
    }

    fn ctx_with_forwarded_for(ip: &str) -> Context {
        let raw = format!("GET / HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-For: {ip}\r\n\r\n");
        make_context(raw.as_bytes())
    }

    fn ctx_plain() -> Context {
        make_context(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
    }

    fn response_text(r: Response) -> String {
        response_to_string(r)
    }

    #[tokio::test]
    async fn test_allowed_request_calls_next() {
        let mw = make_mw(5);
        let resp = mw.handle(ctx_plain(), ok_next()).await;
        assert_eq!(resp.status(), StatusCode::Ok);
    }

    #[tokio::test]
    async fn test_throttled_request_returns_429() {
        let mw = make_mw(1);
        mw.handle(ctx_plain(), ok_next()).await;
        let resp = mw.handle(ctx_plain(), ok_next()).await;
        assert_eq!(resp.status(), StatusCode::TooManyRequests);
    }

    #[tokio::test]
    async fn test_throttled_response_has_retry_after_header() {
        let mw = make_mw(1);
        mw.handle(ctx_plain(), ok_next()).await;
        let resp = mw.handle(ctx_plain(), ok_next()).await;
        let text = response_text(resp);
        assert!(text.contains("Retry-After:"), "missing Retry-After header");
    }

    #[tokio::test]
    async fn test_throttled_response_has_x_ratelimit_remaining_zero() {
        let mw = make_mw(1);
        mw.handle(ctx_plain(), ok_next()).await;
        let resp = mw.handle(ctx_plain(), ok_next()).await;
        let text = response_text(resp);
        assert!(text.contains("X-RateLimit-Remaining: 0"));
    }

    #[tokio::test]
    async fn test_custom_retry_after_is_used() {
        let store = InMemoryStore::from_config(&RateLimitConfig::per_second(1));
        let mw = RateLimitMiddleware::new(store).with_retry_after(120);
        mw.handle(ctx_plain(), ok_next()).await;
        let resp = mw.handle(ctx_plain(), ok_next()).await;
        let text = response_text(resp);
        assert!(text.contains("Retry-After: 120"));
    }

    #[tokio::test]
    async fn test_client_ip_key_strategy_uses_x_forwarded_for() {
        let mw = make_mw(1);
        mw.handle(ctx_with_forwarded_for("1.2.3.4"), ok_next())
            .await;
        // Different IP — should have an independent bucket.
        let resp = mw
            .handle(ctx_with_forwarded_for("5.6.7.8"), ok_next())
            .await;
        assert_eq!(resp.status(), StatusCode::Ok);
    }

    #[tokio::test]
    async fn test_header_key_strategy_uses_named_header() {
        let store = InMemoryStore::from_config(&RateLimitConfig::per_second(1));
        let mw = RateLimitMiddleware::new(store)
            .with_key_strategy(KeyStrategy::Header("x-api-key".to_owned()));

        let make_ctx = |key: &str| {
            let raw = format!("GET / HTTP/1.1\r\nHost: localhost\r\nX-Api-Key: {key}\r\n\r\n");
            make_context(raw.as_bytes())
        };

        mw.handle(make_ctx("key-a"), ok_next()).await;
        // key-a exhausted — key-b should still be allowed.
        let resp = mw.handle(make_ctx("key-b"), ok_next()).await;
        assert_eq!(resp.status(), StatusCode::Ok);
    }
}
