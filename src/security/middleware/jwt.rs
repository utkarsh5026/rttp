//! JWT bearer-token authentication middleware.
//!
//! Extracts `Authorization: Bearer <token>`, verifies the JWT, and injects
//! the decoded [`Claims`] into the request context for downstream handlers.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use tracing::warn;

use crate::{
    context::Context,
    middleware::{Middleware, Next},
    security::auth::{Claims, JwtAuth},
    security::middleware::util::extract_client_ip,
    security::token::{blocklist::TokenBlocklist, brute_force::LoginAttemptTracker},
    Response,
};

/// JWT Bearer-token authentication middleware.
///
/// Extracts the `Authorization: Bearer <token>` header from each incoming
/// request, verifies the JWT using the configured [`JwtAuth`], and — on
/// success — injects the decoded [`Claims`] into [`Context::extensions`] so
/// downstream handlers can retrieve them with
/// `ctx.extensions().get::<Claims>()`.
///
/// Optionally checks a [`TokenBlocklist`] to reject revoked tokens, and a
/// [`LoginAttemptTracker`] to enforce brute-force lockouts.
///
/// On failure the middleware **short-circuits** the pipeline and returns
/// `401 Unauthorized` with a `WWW-Authenticate: Bearer` header. The downstream
/// handler is **not** called.
///
/// # Examples
///
/// ```rust,no_run
/// use std::sync::Arc;
/// use rttp::security::auth::{Claims, JwtAuth};
/// use rttp::security::middleware::JwtMiddleware;
/// use rttp::middleware::from_middleware;
///
/// let auth = JwtAuth::hs256(b"my-secret");
/// let jwt_mw = from_middleware(Arc::new(JwtMiddleware::new(auth)));
/// ```
pub struct JwtMiddleware {
    auth: Arc<JwtAuth>,
    blocklist: Option<Arc<dyn TokenBlocklist>>,
    brute_force: Option<Arc<LoginAttemptTracker>>,
}

impl JwtMiddleware {
    /// Create a new `JwtMiddleware` from a [`JwtAuth`] instance.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::security::auth::JwtAuth;
    /// use rttp::security::middleware::JwtMiddleware;
    ///
    /// let mw = JwtMiddleware::new(JwtAuth::hs256(b"secret"));
    /// ```
    pub fn new(auth: JwtAuth) -> Self {
        Self {
            auth: Arc::new(auth),
            blocklist: None,
            brute_force: None,
        }
    }

    /// Enable token revocation checking via a [`TokenBlocklist`].
    ///
    /// When set, the middleware rejects tokens whose `jti` claim appears in the
    /// blocklist, even if the JWT signature and expiry are valid.
    #[must_use]
    pub fn with_blocklist(mut self, blocklist: Arc<dyn TokenBlocklist>) -> Self {
        self.blocklist = Some(blocklist);
        self
    }

    /// Enable brute-force protection via a [`LoginAttemptTracker`].
    ///
    /// When set, the middleware checks whether the client IP is locked out
    /// before verifying the token, and records failures/successes to the
    /// tracker. The client IP is resolved from `X-Forwarded-For`, `X-Real-IP`,
    /// or falls back to `"unknown"`.
    #[must_use]
    pub fn with_brute_force(mut self, tracker: Arc<LoginAttemptTracker>) -> Self {
        self.brute_force = Some(tracker);
        self
    }
}

impl Middleware for JwtMiddleware {
    /// Authenticate the request via the `Authorization: Bearer <token>` header.
    ///
    /// # Behavior
    ///
    /// 1. If brute-force protection is enabled, checks whether the client IP
    ///    is currently locked out.
    /// 2. Reads the `authorization` request header.
    /// 3. If missing, returns `401 Unauthorized` immediately.
    /// 4. Calls [`JwtAuth::verify_bearer`] on the header value.
    /// 5. If the token is invalid or expired, records a failure and returns
    ///    `401 Unauthorized`.
    /// 6. If a blocklist is configured and the token's `jti` is revoked,
    ///    returns `401 Unauthorized`.
    /// 7. On success, records a success, injects the decoded [`Claims`] into
    ///    `ctx.extensions`, and delegates to the next middleware.
    fn handle(&self, ctx: Context, next: Next) -> Pin<Box<dyn Future<Output = Response> + Send>> {
        let auth = Arc::clone(&self.auth);
        let blocklist = self.blocklist.clone();
        let brute_force = self.brute_force.clone();

        Box::pin(async move {
            let client_ip = extract_client_ip(&ctx);

            // Check brute-force lockout before doing any work.
            if let Some(ref tracker) = brute_force {
                if let Some(retry_after) = tracker.check_locked(&client_ip).await {
                    warn!(client_ip = %client_ip, retry_after, "JWT auth blocked — client locked out");
                    return Response::new(crate::StatusCode::TooManyRequests)
                        .header("Retry-After", retry_after.to_string())
                        .body("Too many failed authentication attempts");
                }
            }

            let authorization = ctx
                .request()
                .headers()
                .get("authorization")
                .map(str::to_owned);

            let Some(auth_header) = authorization else {
                if let Some(ref tracker) = brute_force {
                    tracker.record_failure(&client_ip).await;
                }
                return Response::new(crate::StatusCode::Unauthorized)
                    .header("WWW-Authenticate", "Bearer")
                    .body("Missing Authorization header");
            };

            match auth.verify_bearer::<Claims>(&auth_header) {
                Ok(claims) => {
                    // Check blocklist if configured and the token has a jti.
                    if let Some(ref bl) = blocklist {
                        if let Some(ref jti) = claims.jti {
                            match bl.is_blocked(jti).await {
                                Ok(true) => {
                                    warn!(jti = %jti, "JWT rejected — token revoked");
                                    return Response::new(crate::StatusCode::Unauthorized)
                                        .header(
                                            "WWW-Authenticate",
                                            r#"Bearer error="invalid_token""#,
                                        )
                                        .body("Token has been revoked");
                                }
                                Err(e) => {
                                    warn!(error = %e, "blocklist check failed — rejecting token");
                                    return Response::new(crate::StatusCode::Unauthorized)
                                        .header(
                                            "WWW-Authenticate",
                                            r#"Bearer error="invalid_token""#,
                                        )
                                        .body("Invalid or expired token");
                                }
                                Ok(false) => {} // not blocked — continue
                            }
                        }
                    }

                    if let Some(ref tracker) = brute_force {
                        tracker.record_success(&client_ip).await;
                    }

                    let mut ctx = ctx;
                    ctx.extensions_mut().insert(claims);
                    next.run(ctx).await
                }
                Err(_) => {
                    if let Some(ref tracker) = brute_force {
                        tracker.record_failure(&client_ip).await;
                    }
                    Response::new(crate::StatusCode::Unauthorized)
                        .header("WWW-Authenticate", r#"Bearer error="invalid_token""#)
                        .body("Invalid or expired token")
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::{
        context::Context, middleware::{Middleware, MiddlewareHandler, Next},
        security::auth::{Claims, JwtAuth},
        security::middleware::test_helpers::{make_context, ok_next, response_to_string},
        Response,
        StatusCode,
    };

    use super::JwtMiddleware;

    fn make_auth() -> JwtAuth {
        JwtAuth::hs256(b"test-secret-for-jwt-middleware")
    }

    fn make_middleware() -> JwtMiddleware {
        JwtMiddleware::new(make_auth())
    }

    fn context_without_auth() -> Context {
        make_context(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
    }

    fn context_with_auth_header(value: &str) -> Context {
        let raw = format!("GET / HTTP/1.1\r\nHost: localhost\r\nAuthorization: {value}\r\n\r\n");
        make_context(raw.as_bytes())
    }

    fn valid_token() -> String {
        let auth = make_auth();
        let claims = Claims::new("test-user", 3600);
        auth.sign(&claims).unwrap()
    }

    fn valid_bearer_header() -> String {
        format!("Bearer {}", valid_token())
    }

    fn claims_echo_next() -> Next {
        let handler: MiddlewareHandler = Arc::new(|ctx: Context, _next: Next| {
            Box::pin(async move {
                let sub = ctx
                    .extensions()
                    .get::<Claims>()
                    .map(|c| c.sub.clone())
                    .unwrap_or_else(|| "no-claims".to_string());
                Response::new(StatusCode::Ok).body(sub)
            })
        });
        Next::new(vec![handler])
    }

    #[tokio::test]
    async fn test_handle_missing_auth_header_returns_401() {
        let mw = make_middleware();
        let ctx = context_without_auth();
        let resp = mw.handle(ctx, Next::new(vec![])).await;
        assert_eq!(resp.status(), StatusCode::Unauthorized);
    }

    #[tokio::test]
    async fn test_handle_missing_auth_header_sets_www_authenticate_bearer() {
        let mw = make_middleware();
        let ctx = context_without_auth();
        let resp = mw.handle(ctx, Next::new(vec![])).await;
        let text = response_to_string(resp);
        assert!(text.contains("WWW-Authenticate: Bearer\r\n"));
    }

    #[tokio::test]
    async fn test_handle_missing_auth_header_body_explains_reason() {
        let mw = make_middleware();
        let ctx = context_without_auth();
        let resp = mw.handle(ctx, Next::new(vec![])).await;
        let text = response_to_string(resp);
        assert!(text.ends_with("Missing Authorization header"));
    }

    #[tokio::test]
    async fn test_handle_missing_auth_header_does_not_call_next() {
        let mw = make_middleware();
        let ctx = context_without_auth();
        // ok_next() returns 200; if next were called we'd see 200, not 401.
        let resp = mw.handle(ctx, ok_next()).await;
        assert_eq!(resp.status(), StatusCode::Unauthorized);
    }

    #[tokio::test]
    async fn test_handle_raw_token_without_bearer_prefix_returns_401() {
        let mw = make_middleware();
        let ctx = context_with_auth_header(&valid_token()); // no "Bearer " prefix
        let resp = mw.handle(ctx, Next::new(vec![])).await;
        assert_eq!(resp.status(), StatusCode::Unauthorized);
    }

    #[tokio::test]
    async fn test_handle_lowercase_bearer_prefix_returns_401() {
        let header = format!("bearer {}", valid_token()); // wrong case
        let mw = make_middleware();
        let ctx = context_with_auth_header(&header);
        let resp = mw.handle(ctx, Next::new(vec![])).await;
        assert_eq!(resp.status(), StatusCode::Unauthorized);
    }

    #[tokio::test]
    async fn test_handle_basic_scheme_returns_401() {
        let mw = make_middleware();
        let ctx = context_with_auth_header("Basic dXNlcjpwYXNz");
        let resp = mw.handle(ctx, Next::new(vec![])).await;
        assert_eq!(resp.status(), StatusCode::Unauthorized);
    }

    #[tokio::test]
    async fn test_handle_garbage_token_returns_401() {
        let mw = make_middleware();
        let ctx = context_with_auth_header("Bearer not.a.real.token");
        let resp = mw.handle(ctx, Next::new(vec![])).await;
        assert_eq!(resp.status(), StatusCode::Unauthorized);
    }

    #[tokio::test]
    async fn test_handle_invalid_token_sets_www_authenticate_error_header() {
        let mw = make_middleware();
        let ctx = context_with_auth_header("Bearer not.a.real.token");
        let resp = mw.handle(ctx, Next::new(vec![])).await;
        let text = response_to_string(resp);
        assert!(text.contains(r#"WWW-Authenticate: Bearer error="invalid_token""#));
    }

    #[tokio::test]
    async fn test_handle_invalid_token_body_explains_reason() {
        let mw = make_middleware();
        let ctx = context_with_auth_header("Bearer not.a.real.token");
        let resp = mw.handle(ctx, Next::new(vec![])).await;
        let text = response_to_string(resp);
        assert!(text.ends_with("Invalid or expired token"));
    }

    #[tokio::test]
    async fn test_handle_wrong_secret_returns_401() {
        let signer = JwtAuth::hs256(b"secret-a");
        let token = signer.sign(&Claims::new("user", 3600)).unwrap();
        let mw = JwtMiddleware::new(JwtAuth::hs256(b"secret-b")); // different key
        let ctx = context_with_auth_header(&format!("Bearer {token}"));
        let resp = mw.handle(ctx, Next::new(vec![])).await;
        assert_eq!(resp.status(), StatusCode::Unauthorized);
    }

    #[tokio::test]
    async fn test_handle_expired_token_returns_401() {
        let auth = make_auth();
        let expired = Claims {
            sub: "user".to_string(),
            exp: 1,
            iat: None,
            iss: None,
            jti: None,
        };
        let token = auth.sign(&expired).unwrap();
        let mw = make_middleware();
        let ctx = context_with_auth_header(&format!("Bearer {token}"));
        let resp = mw.handle(ctx, Next::new(vec![])).await;
        assert_eq!(resp.status(), StatusCode::Unauthorized);
    }

    #[tokio::test]
    async fn test_handle_bearer_prefix_with_empty_token_returns_401() {
        let mw = make_middleware();
        let ctx = context_with_auth_header("Bearer ");
        let resp = mw.handle(ctx, Next::new(vec![])).await;
        assert_eq!(resp.status(), StatusCode::Unauthorized);
    }

    #[tokio::test]
    async fn test_handle_valid_token_calls_next_and_returns_200() {
        let mw = make_middleware();
        let ctx = context_with_auth_header(&valid_bearer_header());
        let resp = mw.handle(ctx, ok_next()).await;
        assert_eq!(resp.status(), StatusCode::Ok);
    }

    #[tokio::test]
    async fn test_handle_valid_token_passes_next_body_through() {
        let mw = make_middleware();
        let ctx = context_with_auth_header(&valid_bearer_header());
        let resp = mw.handle(ctx, ok_next()).await;
        let text = response_to_string(resp);
        assert!(text.ends_with("downstream"));
    }

    #[tokio::test]
    async fn test_handle_valid_token_injects_claims_into_extensions() {
        let auth = make_auth();
        let token = auth.sign(&Claims::new("alice", 3600)).unwrap();
        let mw = make_middleware();
        let ctx = context_with_auth_header(&format!("Bearer {token}"));
        let resp = mw.handle(ctx, claims_echo_next()).await;
        let text = response_to_string(resp);
        assert!(text.ends_with("alice"));
    }

    #[tokio::test]
    async fn test_handle_valid_token_injected_claims_sub_matches_original() {
        let auth = make_auth();
        let token = auth.sign(&Claims::new("user-99", 3600)).unwrap();
        let mw = make_middleware();
        let ctx = context_with_auth_header(&format!("Bearer {token}"));
        let resp = mw.handle(ctx, claims_echo_next()).await;
        let text = response_to_string(resp);
        assert!(text.ends_with("user-99"));
    }

    // ── Blocklist integration ─────────────────────────────────────────────

    mod blocklist_tests {
        use super::*;
        use std::time::{Duration, Instant};

        use crate::security::token::blocklist::{InMemoryBlocklist, TokenBlocklist};

        fn token_with_jti(jti: &str) -> String {
            let auth = make_auth();
            let claims = Claims::new("user", 3600).with_jti(jti.to_owned());
            auth.sign(&claims).unwrap()
        }

        #[tokio::test]
        async fn revoked_jti_returns_401() {
            let bl = Arc::new(InMemoryBlocklist::new());
            let exp = Instant::now() + Duration::from_secs(3600);
            bl.revoke("revoked-jti", exp).await.unwrap();

            let mw = JwtMiddleware::new(make_auth()).with_blocklist(bl);
            let token = token_with_jti("revoked-jti");
            let ctx = context_with_auth_header(&format!("Bearer {token}"));
            let resp = mw.handle(ctx, ok_next()).await;
            assert_eq!(resp.status(), StatusCode::Unauthorized);
        }

        #[tokio::test]
        async fn revoked_jti_body_says_revoked() {
            let bl = Arc::new(InMemoryBlocklist::new());
            let exp = Instant::now() + Duration::from_secs(3600);
            bl.revoke("jti-x", exp).await.unwrap();

            let mw = JwtMiddleware::new(make_auth()).with_blocklist(bl);
            let token = token_with_jti("jti-x");
            let ctx = context_with_auth_header(&format!("Bearer {token}"));
            let resp = mw.handle(ctx, ok_next()).await;
            let text = response_to_string(resp);
            assert!(text.ends_with("Token has been revoked"));
        }

        #[tokio::test]
        async fn non_revoked_jti_passes_through() {
            let bl = Arc::new(InMemoryBlocklist::new());
            let mw = JwtMiddleware::new(make_auth()).with_blocklist(bl);
            let token = token_with_jti("good-jti");
            let ctx = context_with_auth_header(&format!("Bearer {token}"));
            let resp = mw.handle(ctx, ok_next()).await;
            assert_eq!(resp.status(), StatusCode::Ok);
        }

        #[tokio::test]
        async fn token_without_jti_passes_through_with_blocklist() {
            let bl = Arc::new(InMemoryBlocklist::new());
            let mw = JwtMiddleware::new(make_auth()).with_blocklist(bl);
            // valid_bearer_header() creates a token without jti
            let ctx = context_with_auth_header(&valid_bearer_header());
            let resp = mw.handle(ctx, ok_next()).await;
            assert_eq!(resp.status(), StatusCode::Ok);
        }
    }

    mod brute_force_tests {
        use super::*;
        use std::time::Duration;

        use crate::security::token::brute_force::LoginAttemptTracker;

        fn tracker() -> Arc<LoginAttemptTracker> {
            Arc::new(
                LoginAttemptTracker::new()
                    .with_max_attempts(2)
                    .with_base_lockout(Duration::from_secs(60)),
            )
        }

        #[tokio::test]
        async fn lockout_after_repeated_failures_returns_429() {
            let t = tracker(); // 2 attempts max
            let mw = JwtMiddleware::new(make_auth()).with_brute_force(Arc::clone(&t));

            // Two failed attempts to trigger lockout
            for _ in 0..2 {
                let ctx = context_with_auth_header("Bearer bad.token.here");
                mw.handle(ctx, ok_next()).await;
            }

            // Third attempt should be 429 (locked out)
            let ctx = context_with_auth_header(&valid_bearer_header());
            let resp = mw.handle(ctx, ok_next()).await;
            assert_eq!(resp.status(), StatusCode::TooManyRequests);
        }

        #[tokio::test]
        async fn lockout_response_includes_retry_after() {
            let t = tracker();
            let mw = JwtMiddleware::new(make_auth()).with_brute_force(Arc::clone(&t));

            for _ in 0..2 {
                let ctx = context_with_auth_header("Bearer bad");
                mw.handle(ctx, ok_next()).await;
            }

            let ctx = context_with_auth_header(&valid_bearer_header());
            let resp = mw.handle(ctx, ok_next()).await;
            let text = response_to_string(resp);
            assert!(text.contains("Retry-After:"));
        }

        #[tokio::test]
        async fn successful_auth_resets_failure_count() {
            let t = tracker(); // 2 attempts max
            let mw = JwtMiddleware::new(make_auth()).with_brute_force(Arc::clone(&t));

            // One failure
            let ctx = context_with_auth_header("Bearer bad");
            mw.handle(ctx, ok_next()).await;

            // One success — should reset
            let ctx = context_with_auth_header(&valid_bearer_header());
            let resp = mw.handle(ctx, ok_next()).await;
            assert_eq!(resp.status(), StatusCode::Ok);

            // Another failure — should not be locked (counter was reset)
            let ctx = context_with_auth_header("Bearer bad");
            let resp = mw.handle(ctx, ok_next()).await;
            assert_eq!(resp.status(), StatusCode::Unauthorized); // not 429
        }
    }
}
