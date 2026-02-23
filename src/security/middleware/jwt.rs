//! JWT bearer-token authentication middleware.
//!
//! Extracts `Authorization: Bearer <token>`, verifies the JWT, and injects
//! the decoded [`Claims`] into the request context for downstream handlers.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::{
    Response,
    context::Context,
    middleware::{Middleware, Next},
    security::auth::{Claims, JwtAuth},
};

/// JWT Bearer-token authentication middleware.
///
/// Extracts the `Authorization: Bearer <token>` header from each incoming
/// request, verifies the JWT using the configured [`JwtAuth`], and — on
/// success — injects the decoded [`Claims`] into [`Context::extensions`] so
/// downstream handlers can retrieve them with
/// `ctx.extensions().get::<Claims>()`.
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
        }
    }
}

impl Middleware for JwtMiddleware {
    /// Authenticate the request via the `Authorization: Bearer <token>` header.
    ///
    /// # Behavior
    ///
    /// 1. Reads the `authorization` request header.
    /// 2. If missing, returns `401 Unauthorized` immediately.
    /// 3. Calls [`JwtAuth::verify_bearer`] on the header value.
    /// 4. If the token is invalid or expired, returns `401 Unauthorized`.
    /// 5. On success, injects the decoded [`Claims`] into `ctx.extensions` and
    ///    delegates to the next middleware.
    fn handle(&self, ctx: Context, next: Next) -> Pin<Box<dyn Future<Output = Response> + Send>> {
        let auth = Arc::clone(&self.auth);

        Box::pin(async move {
            let authorization = ctx
                .request()
                .headers()
                .get("authorization")
                .map(str::to_owned);

            let Some(auth_header) = authorization else {
                return Response::new(crate::StatusCode::Unauthorized)
                    .header("WWW-Authenticate", "Bearer")
                    .body("Missing Authorization header");
            };

            match auth.verify_bearer::<Claims>(&auth_header) {
                Ok(claims) => {
                    let mut ctx = ctx;
                    ctx.extensions_mut().insert(claims);
                    next.run(ctx).await
                }
                Err(_) => Response::new(crate::StatusCode::Unauthorized)
                    .header("WWW-Authenticate", r#"Bearer error="invalid_token""#)
                    .body("Invalid or expired token"),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::{
        Response, StatusCode,
        context::Context,
        http::request::Request,
        middleware::{Middleware, MiddlewareHandler, Next},
        security::auth::{Claims, JwtAuth},
    };

    use super::JwtMiddleware;

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn make_auth() -> JwtAuth {
        JwtAuth::hs256(b"test-secret-for-jwt-middleware")
    }

    fn make_middleware() -> JwtMiddleware {
        JwtMiddleware::new(make_auth())
    }

    fn parse_context(raw: &[u8]) -> Context {
        let (req, _) = Request::parse(raw).unwrap();
        Context::new(req)
    }

    fn context_without_auth() -> Context {
        parse_context(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
    }

    fn context_with_auth_header(value: &str) -> Context {
        let raw =
            format!("GET / HTTP/1.1\r\nHost: localhost\r\nAuthorization: {value}\r\n\r\n");
        parse_context(raw.as_bytes())
    }

    fn valid_token() -> String {
        let auth = make_auth();
        let claims = Claims::new("test-user", 3600);
        auth.sign(&claims).unwrap()
    }

    fn valid_bearer_header() -> String {
        format!("Bearer {}", valid_token())
    }

    /// Returns a `Next` whose sole handler responds with `200 OK` and body `"downstream"`.
    fn ok_next() -> Next {
        let handler: MiddlewareHandler = Arc::new(|_ctx, _next| {
            Box::pin(async move { Response::new(StatusCode::Ok).body("downstream") })
        });
        Next::new(vec![handler])
    }

    /// Returns a `Next` that reads `Claims` from extensions and echoes the `sub` as the body.
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

    fn response_to_string(r: Response) -> String {
        String::from_utf8(r.into_bytes().to_vec()).unwrap()
    }

    // ── Constructor ───────────────────────────────────────────────────────────

    #[test]
    fn test_new_wraps_jwt_auth_without_panic() {
        let _mw = JwtMiddleware::new(JwtAuth::hs256(b"any-secret"));
    }

    // ── Missing Authorization header ──────────────────────────────────────────

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

    // ── Malformed / wrong-scheme Authorization header ─────────────────────────

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

    // ── Invalid JWT ───────────────────────────────────────────────────────────

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
        // exp = 1 → January 1 1970 00:00:01 UTC, long expired.
        let expired = Claims { sub: "user".to_string(), exp: 1, iat: None, iss: None };
        let token = auth.sign(&expired).unwrap();
        let mw = make_middleware();
        let ctx = context_with_auth_header(&format!("Bearer {token}"));
        let resp = mw.handle(ctx, Next::new(vec![])).await;
        assert_eq!(resp.status(), StatusCode::Unauthorized);
    }

    #[tokio::test]
    async fn test_handle_bearer_prefix_with_empty_token_returns_401() {
        // "Bearer " with nothing after the space — strip_prefix succeeds but
        // the resulting empty string is not a valid JWT.
        let mw = make_middleware();
        let ctx = context_with_auth_header("Bearer ");
        let resp = mw.handle(ctx, Next::new(vec![])).await;
        assert_eq!(resp.status(), StatusCode::Unauthorized);
    }

    // ── Valid token — happy path ───────────────────────────────────────────────

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
}
