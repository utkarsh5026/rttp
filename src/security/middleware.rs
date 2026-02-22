//! Security middleware — authentication, authorization, CORS, and rate limiting.
//!
//! This module provides middleware implementations for common HTTP security concerns.
//! Currently implemented:
//!
//! - [`CorsMiddleware`] — Cross-Origin Resource Sharing header injection and
//!   preflight (`OPTIONS`) short-circuiting.
//!
//! ## Planned Features
//!
//! - JWT authentication middleware
//! - API key validation
//! - Per-route rate limiting (token bucket / sliding window)
//! - CSRF protection
//! - Secure header injection (HSTS, CSP, X-Frame-Options)

use std::pin::Pin;

use crate::{
    Response,
    context::Context,
    middleware::{Middleware, Next},
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
        }
    }

    /// Adds an allowed origin.
    ///
    /// Pass `"*"` to permit all origins. When the allow-list contains `"*"`,
    /// every `Origin` value is accepted and the response carries
    /// `Access-Control-Allow-Origin: *`.
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
        self.allowed_origins.push(origin.into());
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

        Box::pin(async move {
            let request_origin = ctx.request().headers().get("origin").map(str::to_owned);
            let is_preflight = ctx.request().method() == &crate::Method::Options;
            let Some(origin) = request_origin else {
                return next.run(ctx).await;
            };

            let allow_origin = if allowed_origins.iter().any(|o| o == "*") {
                "*".to_owned()
            } else if allowed_origins.contains(&origin) {
                origin.clone()
            } else {
                return next.run(ctx).await;
            };

            let methods_str = allowed_methods.join(", ");
            let headers_str = allowed_headers.join(", ");
            let is_wildcard = allow_origin == "*";

            if is_preflight {
                let mut resp = Response::new(crate::StatusCode::NoContent)
                    .header("Access-Control-Allow-Origin", &allow_origin)
                    .header("Access-Control-Allow-Methods", &methods_str)
                    .header("Access-Control-Allow-Headers", &headers_str)
                    .header("Access-Control-Max-Age", "3600");
                if !is_wildcard {
                    resp.add_header("Vary", "Origin");
                }
                return resp;
            }

            let mut resp = next.run(ctx).await;
            resp.add_header("Access-Control-Allow-Origin", &allow_origin);
            resp.add_header("Access-Control-Allow-Methods", &methods_str);
            resp.add_header("Access-Control-Allow-Headers", &headers_str);
            if !is_wildcard {
                resp.add_header("Vary", "Origin");
            }
            resp
        })
    }
}
