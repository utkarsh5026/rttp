//! Security middleware — authentication, authorization, CORS, and rate limiting.
//!
//! This module provides middleware implementations for common HTTP security concerns.
//! Currently implemented:
//!
//! - [`CorsMiddleware`] — Cross-Origin Resource Sharing header injection and
//!   preflight (`OPTIONS`) short-circuiting.
//! - [`JwtMiddleware`] — Bearer-token JWT authentication; short-circuits with
//!   `401 Unauthorized` and injects verified [`Claims`] into the request context.
//!
//! ## Planned Features
//!
//! - API key validation
//! - Per-route rate limiting (token bucket / sliding window)
//! - CSRF protection
//! - Secure header injection (HSTS, CSP, X-Frame-Options)

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::{
    Response,
    context::Context,
    middleware::{Middleware, Next},
    security::auth::{Claims, JwtAuth},
};

/// CORS middleware — validates the `Origin` header, handles preflight requests,
/// and injects `Access-Control-*` headers on actual responses.
///
/// Constructed via [`CorsMiddleware::new`] and further configured through the
/// builder methods [`allow_origin`](Self::allow_origin),
/// [`allow_method`](Self::allow_method), and [`allow_header`](Self::allow_header).
///
/// # Behavior
///
/// - If no `Origin` header is present the request passes through unmodified.
/// - If the origin is not in the allow-list the request passes through unmodified.
/// - `OPTIONS` preflight requests are short-circuited with `204 No Content` and the
///   appropriate `Access-Control-*` headers; the downstream handler is **not** called.
/// - For all other requests the handler runs normally and the CORS headers are appended
///   to the response.
/// - When the wildcard origin `"*"` is used, a `Vary: Origin` header is **not** added;
///   for specific origins it is added to ensure correct cache behavior.
///
/// # Examples
///
/// ```rust,no_run
/// use rttp::security::CorsMiddleware;
///
/// let cors = CorsMiddleware::new()
///     .allow_origin("https://example.com")
///     .allow_method("PATCH")
///     .allow_header("X-Custom-Header");
/// ```
pub struct CorsMiddleware {
    allowed_origins: Vec<String>,
    allowed_methods: Vec<String>,
    allowed_headers: Vec<String>,
    allow_credentials: bool,
    expose_headers: Vec<String>,
}

impl Default for CorsMiddleware {
    fn default() -> Self {
        Self::new()
    }
}

impl CorsMiddleware {
    /// Creates a new `CorsMiddleware` with permissive defaults:
    /// all origins (`*`), common methods, and common headers.
    ///
    /// The defaults are:
    ///
    /// | Setting          | Default value                          |
    /// |------------------|----------------------------------------|
    /// | Allowed origins  | `*` (all origins)                      |
    /// | Allowed methods  | `GET`, `POST`, `PUT`, `DELETE`         |
    /// | Allowed headers  | `Content-Type`, `Authorization`        |
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::security::CorsMiddleware;
    ///
    /// let cors = CorsMiddleware::new();
    /// ```
    pub fn new() -> Self {
        Self {
            allowed_origins: vec!["*".to_string()],
            allowed_methods: vec![
                "GET".to_string(),
                "POST".to_string(),
                "PUT".to_string(),
                "DELETE".to_string(),
            ],
            allowed_headers: vec!["Content-Type".to_string(), "Authorization".to_string()],
            allow_credentials: false,
            expose_headers: Vec::new(),
        }
    }

    /// Adds an allowed origin.
    ///
    /// Pass `"*"` to permit all origins. When the allow-list contains `"*"`,
    /// every `Origin` value is accepted and the response carries
    /// `Access-Control-Allow-Origin: *`.
    ///
    /// When a **specific** origin is added the default wildcard `"*"` is removed
    /// so that origin restrictions are not silently masked. Subsequent calls with
    /// additional specific origins extend the allow-list without re-introducing the
    /// wildcard.
    ///
    /// # Arguments
    ///
    /// - `origin` — a URL origin string (e.g. `"https://example.com"`) or `"*"`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::security::CorsMiddleware;
    ///
    /// let cors = CorsMiddleware::new()
    ///     .allow_origin("https://app.example.com")
    ///     .allow_origin("https://staging.example.com");
    /// ```
    #[must_use]
    pub fn allow_origin(mut self, origin: impl Into<String>) -> Self {
        let origin = origin.into();
        if origin != "*" {
            // Transition from the default wildcard to an explicit allow-list so that
            // restrictions are not silently masked by the pre-seeded "*".
            self.allowed_origins.retain(|o| o != "*");
        }
        self.allowed_origins.push(origin);
        self
    }

    /// Adds an allowed HTTP method.
    ///
    /// The method string is sent verbatim in the
    /// `Access-Control-Allow-Methods` response header. Use standard uppercase
    /// method names such as `"PATCH"` or `"OPTIONS"`.
    ///
    /// # Arguments
    ///
    /// - `method` — an HTTP method name (e.g. `"PATCH"`).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::security::CorsMiddleware;
    ///
    /// let cors = CorsMiddleware::new().allow_method("PATCH");
    /// ```
    #[must_use]
    pub fn allow_method(mut self, method: impl Into<String>) -> Self {
        self.allowed_methods.push(method.into());
        self
    }

    /// Controls whether credentials (cookies, HTTP authentication) are included.
    ///
    /// When set to `true`, the `Access-Control-Allow-Credentials: true` header
    /// is added to both preflight and actual responses. Per the CORS spec, when
    /// credentials are allowed and the allow-list contains `"*"`, the actual request
    /// origin is reflected instead of `"*"` (browsers reject credentialed requests
    /// paired with `Access-Control-Allow-Origin: *`).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::security::CorsMiddleware;
    ///
    /// let cors = CorsMiddleware::new().allow_credentials(true);
    /// ```
    #[must_use]
    pub fn allow_credentials(mut self, allow: bool) -> Self {
        self.allow_credentials = allow;
        self
    }

    /// Adds a header name to the `Access-Control-Expose-Headers` list.
    ///
    /// Exposed headers are accessible to browser JavaScript via
    /// `XMLHttpRequest.getResponseHeader()` or the Fetch API. By default no
    /// headers beyond the CORS-safelisted ones are exposed.
    ///
    /// # Arguments
    ///
    /// - `header` — an HTTP header name (e.g. `"X-Request-ID"`).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::security::CorsMiddleware;
    ///
    /// let cors = CorsMiddleware::new().expose_header("X-Request-ID");
    /// ```
    #[must_use]
    pub fn expose_header(mut self, header: impl Into<String>) -> Self {
        self.expose_headers.push(header.into());
        self
    }

    /// Adds an allowed request header.
    ///
    /// The header name is sent verbatim in the
    /// `Access-Control-Allow-Headers` response header.
    ///
    /// # Arguments
    ///
    /// - `header` — an HTTP header name (e.g. `"X-Request-ID"`).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::security::CorsMiddleware;
    ///
    /// let cors = CorsMiddleware::new().allow_header("X-Request-ID");
    /// ```
    #[must_use]
    pub fn allow_header(mut self, header: impl Into<String>) -> Self {
        self.allowed_headers.push(header.into());
        self
    }
}

impl Middleware for CorsMiddleware {
    /// Process a request through the CORS policy and return the appropriate response.
    ///
    /// Inspects the `Origin` request header and applies one of three strategies:
    ///
    /// 1. **No origin / rejected origin** — passes the request to the next handler
    ///    unchanged.
    /// 2. **Preflight (`OPTIONS`)** — short-circuits with `204 No Content` and the
    ///    `Access-Control-Allow-Origin`, `Access-Control-Allow-Methods`,
    ///    `Access-Control-Allow-Headers`, and `Access-Control-Max-Age` headers set.
    ///    The downstream handler is **not** called.
    /// 3. **Actual request** — calls the next handler and appends
    ///    `Access-Control-Allow-Origin`, `Access-Control-Allow-Methods`, and
    ///    `Access-Control-Allow-Headers` to its response. A `Vary: Origin` header is
    ///    added when a specific (non-wildcard) origin is echoed back.
    ///
    /// # Arguments
    ///
    /// - `ctx` — the per-request [`Context`] carrying the HTTP method, headers, path,
    ///   and extensions.
    /// - `next` — the remainder of the middleware chain; invoke [`Next::run`] to
    ///   forward the request to the next layer.
    ///
    /// # Returns
    ///
    /// A [`Response`] with CORS headers applied, or the unmodified downstream
    /// response when the origin check does not pass.
    fn handle(&self, ctx: Context, next: Next) -> Pin<Box<dyn Future<Output = Response> + Send>> {
        let allowed_origins = self.allowed_origins.clone();
        let allowed_methods = self.allowed_methods.clone();
        let allowed_headers = self.allowed_headers.clone();
        let allow_credentials = self.allow_credentials;
        let exposed_headers = self.expose_headers.clone();

        Box::pin(async move {
            let req_headers = ctx.request().headers();
            let request_origin = req_headers.get("origin").map(str::to_owned);
            let is_preflight = ctx.request().method() == &crate::Method::Options
                && req_headers.contains("access-control-request-method");
            let Some(origin) = request_origin else {
                return next.run(ctx).await;
            };

            let allow_origin = if allowed_origins.iter().any(|o| o == "*") {
                if allow_credentials {
                    origin.clone()
                } else {
                    "*".to_owned()
                }
            } else if allowed_origins.contains(&origin) {
                origin.clone()
            } else if is_preflight {
                return Response::new(crate::StatusCode::Forbidden);
            } else {
                return next.run(ctx).await;
            };

            let is_wildcard = allow_origin == "*";

            if is_preflight {
                let mut resp = Response::new(crate::StatusCode::NoContent)
                    .header("Access-Control-Allow-Origin", &allow_origin)
                    .header("Access-Control-Max-Age", "86400"); // 24 hours is a modern standard

                if !allowed_methods.is_empty() {
                    resp.add_header("Access-Control-Allow-Methods", allowed_methods.join(", "));
                }
                if !allowed_headers.is_empty() {
                    resp.add_header("Access-Control-Allow-Headers", allowed_headers.join(", "));
                }

                if allow_credentials {
                    resp.add_header("Access-Control-Allow-Credentials", "true");
                }

                if !is_wildcard {
                    resp.add_header("Vary", "Origin");
                }

                return resp;
            }

            let mut resp = next.run(ctx).await;
            resp.add_header("Access-Control-Allow-Origin", &allow_origin);

            if allow_credentials {
                resp.add_header("Access-Control-Allow-Credentials", "true");
            }

            if !exposed_headers.is_empty() {
                resp.add_header("Access-Control-Expose-Headers", exposed_headers.join(", "));
            }

            if !is_wildcard {
                resp.add_header("Vary", "Origin");
            }

            resp
        })
    }
}

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
    ///
    /// # Arguments
    ///
    /// - `ctx` — the per-request context.
    /// - `next` — remainder of the middleware chain.
    ///
    /// # Returns
    ///
    /// Either a `401` response (unauthenticated) or the response produced by
    /// the downstream handler.
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

    use super::*;
    use crate::{
        Response, StatusCode,
        context::Context,
        middleware::{MiddlewareHandler, Next},
    };

    /// Builds a `Context` by parsing a raw HTTP/1.1 request byte slice.
    fn make_context(raw: &[u8]) -> Context {
        let (req, _) = crate::Request::parse(raw).unwrap();
        Context::new(req)
    }

    /// Returns a `Next` whose only handler always responds with `200 OK`.
    fn ok_next() -> Next {
        let handler: MiddlewareHandler = Arc::new(|_ctx: Context, _next: Next| {
            Box::pin(async { Response::new(StatusCode::Ok) })
        });
        Next::new(vec![handler])
    }

    /// Serializes a `Response` to its HTTP/1.1 wire representation.
    fn wire(response: Response) -> String {
        String::from_utf8(response.into_bytes().to_vec()).unwrap()
    }

    #[tokio::test]
    async fn no_origin_passes_through_unchanged() {
        let cors = CorsMiddleware::new();
        let ctx = make_context(b"GET /api HTTP/1.1\r\nHost: localhost\r\n\r\n");

        let resp = cors.handle(ctx, ok_next()).await;

        let w = wire(resp);
        assert!(w.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(!w.contains("Access-Control-Allow-Origin"));
    }

    #[tokio::test]
    async fn wildcard_accepts_any_origin_and_returns_star() {
        let cors = CorsMiddleware::new();
        let ctx = make_context(
            b"GET /api HTTP/1.1\r\nHost: localhost\r\nOrigin: https://random.io\r\n\r\n",
        );

        let resp = cors.handle(ctx, ok_next()).await;
        let w = wire(resp);

        assert!(w.contains("Access-Control-Allow-Origin: *\r\n"));
        assert!(!w.contains("Vary: Origin"));
    }

    #[tokio::test]
    async fn specific_origin_match_reflects_origin_and_adds_vary() {
        let cors = CorsMiddleware::new().allow_origin("https://example.com");
        let ctx = make_context(
            b"GET /api HTTP/1.1\r\nHost: localhost\r\nOrigin: https://example.com\r\n\r\n",
        );

        let resp = cors.handle(ctx, ok_next()).await;
        let w = wire(resp);

        assert!(w.contains("Access-Control-Allow-Origin: https://example.com\r\n"));
        assert!(w.contains("Vary: Origin\r\n"));
    }

    #[tokio::test]
    async fn specific_origin_mismatch_no_cors_headers() {
        let cors = CorsMiddleware::new().allow_origin("https://trusted.com");
        let ctx = make_context(
            b"GET /api HTTP/1.1\r\nHost: localhost\r\nOrigin: https://attacker.com\r\n\r\n",
        );

        let resp = cors.handle(ctx, ok_next()).await;
        let status = resp.status();
        let w = wire(resp);

        assert_eq!(status, StatusCode::Ok);
        assert!(!w.contains("Access-Control-Allow-Origin"));
    }

    #[tokio::test]
    async fn allow_origin_builder_restricts_wildcard_default() {
        let cors = CorsMiddleware::new().allow_origin("https://trusted.com");
        let ctx = make_context(
            b"GET /api HTTP/1.1\r\nHost: localhost\r\nOrigin: https://other.com\r\n\r\n",
        );

        let resp = cors.handle(ctx, ok_next()).await;
        assert!(!wire(resp).contains("Access-Control-Allow-Origin"));
    }

    #[tokio::test]
    async fn multiple_allowed_origins_each_accepted() {
        let cors = CorsMiddleware::new()
            .allow_origin("https://app.example.com")
            .allow_origin("https://staging.example.com");

        for origin in &["https://app.example.com", "https://staging.example.com"] {
            let raw = format!("GET /api HTTP/1.1\r\nHost: localhost\r\nOrigin: {origin}\r\n\r\n");
            let ctx = make_context(raw.as_bytes());
            let resp = cors.handle(ctx, ok_next()).await;
            assert!(
                wire(resp).contains(&format!("Access-Control-Allow-Origin: {origin}\r\n")),
                "expected CORS header for origin {origin}"
            );
        }
    }

    #[tokio::test]
    async fn preflight_wildcard_returns_204_with_cors_headers() {
        let cors = CorsMiddleware::new();
        let ctx = make_context(
            b"OPTIONS /api HTTP/1.1\r\nHost: localhost\r\nOrigin: https://example.com\r\n\
              Access-Control-Request-Method: POST\r\n\r\n",
        );

        let resp = cors.handle(ctx, ok_next()).await;
        let status = resp.status();
        let w = wire(resp);

        assert_eq!(status, StatusCode::NoContent);
        assert!(w.contains("Access-Control-Allow-Origin: *\r\n"));
        assert!(w.contains("Access-Control-Max-Age: 86400\r\n"));
        assert!(w.contains("Access-Control-Allow-Methods:"));
        assert!(w.contains("Access-Control-Allow-Headers:"));
        // Wildcard must NOT add Vary: Origin on preflight either
        assert!(!w.contains("Vary: Origin"));
    }

    #[tokio::test]
    async fn preflight_specific_origin_returns_204_with_vary() {
        let cors = CorsMiddleware::new().allow_origin("https://example.com");
        let ctx = make_context(
            b"OPTIONS /api HTTP/1.1\r\nHost: localhost\r\nOrigin: https://example.com\r\n\
              Access-Control-Request-Method: DELETE\r\n\r\n",
        );

        let resp = cors.handle(ctx, ok_next()).await;
        let status = resp.status();
        let w = wire(resp);

        assert_eq!(status, StatusCode::NoContent);
        assert!(w.contains("Access-Control-Allow-Origin: https://example.com\r\n"));
        assert!(w.contains("Vary: Origin\r\n"));
    }

    #[tokio::test]
    async fn preflight_rejected_origin_returns_403() {
        let cors = CorsMiddleware::new().allow_origin("https://trusted.com");
        let ctx = make_context(
            b"OPTIONS /api HTTP/1.1\r\nHost: localhost\r\nOrigin: https://attacker.com\r\n\
              Access-Control-Request-Method: POST\r\n\r\n",
        );

        let resp = cors.handle(ctx, ok_next()).await;
        assert_eq!(resp.status(), StatusCode::Forbidden);
    }

    /// An `OPTIONS` request without `Access-Control-Request-Method` is NOT a
    /// preflight — it must be treated as an ordinary request.
    #[tokio::test]
    async fn options_without_acr_method_is_not_preflight() {
        let cors = CorsMiddleware::new();
        let ctx = make_context(
            b"OPTIONS /api HTTP/1.1\r\nHost: localhost\r\nOrigin: https://example.com\r\n\r\n",
        );

        let resp = cors.handle(ctx, ok_next()).await;
        let status = resp.status();
        let w = wire(resp);

        // next.run() is called → 200 from stub handler
        assert_eq!(status, StatusCode::Ok);
        // But CORS header IS still present (it's a cross-origin actual request)
        assert!(w.contains("Access-Control-Allow-Origin: *\r\n"));
    }

    // ── Credentials ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn credentials_with_wildcard_reflects_origin_not_star() {
        // Per the CORS spec, credentials + wildcard must echo the real origin.
        let cors = CorsMiddleware::new().allow_credentials(true);
        let ctx = make_context(
            b"GET /api HTTP/1.1\r\nHost: localhost\r\nOrigin: https://example.com\r\n\r\n",
        );

        let resp = cors.handle(ctx, ok_next()).await;
        let w = wire(resp);

        assert!(w.contains("Access-Control-Allow-Origin: https://example.com\r\n"));
        assert!(!w.contains("Access-Control-Allow-Origin: *"));
        assert!(w.contains("Access-Control-Allow-Credentials: true\r\n"));
    }

    #[tokio::test]
    async fn credentials_with_specific_origin_adds_header() {
        let cors = CorsMiddleware::new()
            .allow_origin("https://example.com")
            .allow_credentials(true);
        let ctx = make_context(
            b"GET /api HTTP/1.1\r\nHost: localhost\r\nOrigin: https://example.com\r\n\r\n",
        );

        let resp = cors.handle(ctx, ok_next()).await;
        let w = wire(resp);

        assert!(w.contains("Access-Control-Allow-Origin: https://example.com\r\n"));
        assert!(w.contains("Access-Control-Allow-Credentials: true\r\n"));
    }

    #[tokio::test]
    async fn credentials_on_preflight_adds_header() {
        let cors = CorsMiddleware::new().allow_credentials(true);
        let ctx = make_context(
            b"OPTIONS /api HTTP/1.1\r\nHost: localhost\r\nOrigin: https://example.com\r\n\
              Access-Control-Request-Method: POST\r\n\r\n",
        );

        let resp = cors.handle(ctx, ok_next()).await;
        let status = resp.status();
        let w = wire(resp);

        assert_eq!(status, StatusCode::NoContent);
        assert!(w.contains("Access-Control-Allow-Credentials: true\r\n"));
    }

    // ── Expose-Headers ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn expose_header_appears_on_actual_response() {
        let cors = CorsMiddleware::new().expose_header("X-Request-ID");
        let ctx = make_context(
            b"GET /api HTTP/1.1\r\nHost: localhost\r\nOrigin: https://example.com\r\n\r\n",
        );

        let resp = cors.handle(ctx, ok_next()).await;
        assert!(wire(resp).contains("Access-Control-Expose-Headers: X-Request-ID\r\n"));
    }

    #[tokio::test]
    async fn multiple_expose_headers_are_joined() {
        let cors = CorsMiddleware::new()
            .expose_header("X-Request-ID")
            .expose_header("X-Trace-ID");
        let ctx = make_context(
            b"GET /api HTTP/1.1\r\nHost: localhost\r\nOrigin: https://example.com\r\n\r\n",
        );

        let resp = cors.handle(ctx, ok_next()).await;
        assert!(wire(resp).contains("Access-Control-Expose-Headers: X-Request-ID, X-Trace-ID\r\n"));
    }

    // ── Allow-Methods / Allow-Headers on preflight ────────────────────────────

    #[tokio::test]
    async fn preflight_contains_custom_method() {
        let cors = CorsMiddleware::new().allow_method("PATCH");
        let ctx = make_context(
            b"OPTIONS /api HTTP/1.1\r\nHost: localhost\r\nOrigin: https://example.com\r\n\
              Access-Control-Request-Method: PATCH\r\n\r\n",
        );

        let resp = cors.handle(ctx, ok_next()).await;
        let w = wire(resp);

        assert!(w.contains("PATCH"), "expected PATCH in Allow-Methods: {w}");
    }

    #[tokio::test]
    async fn preflight_contains_custom_header() {
        let cors = CorsMiddleware::new().allow_header("X-Custom-Token");
        let ctx = make_context(
            b"OPTIONS /api HTTP/1.1\r\nHost: localhost\r\nOrigin: https://example.com\r\n\
              Access-Control-Request-Method: POST\r\n\r\n",
        );

        let resp = cors.handle(ctx, ok_next()).await;
        let w = wire(resp);

        assert!(
            w.contains("X-Custom-Token"),
            "expected X-Custom-Token in Allow-Headers: {w}"
        );
    }
}
