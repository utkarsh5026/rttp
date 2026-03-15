//! CSRF (Cross-Site Request Forgery) protection middleware.
//!
//! Implements the **double-submit cookie** pattern for stateless CSRF protection:
//!
//! 1. On safe methods (`GET`, `HEAD`, `OPTIONS`) a random CSRF token is generated
//!    and set as a `Set-Cookie` header on the response.
//! 2. On state-changing methods (`POST`, `PUT`, `PATCH`, `DELETE`) the middleware
//!    compares the token from the cookie against a token submitted via the
//!    `X-CSRF-Token` header (or a configurable header name).
//! 3. If the tokens don't match or either is missing, the request is rejected
//!    with `403 Forbidden`.
//!
//! # Examples
//!
//! ```rust,no_run
//! use rttp::security::middleware::csrf::CsrfMiddleware;
//!
//! let csrf = CsrfMiddleware::new()
//!     .cookie_name("csrf_token")
//!     .header_name("X-CSRF-Token")
//!     .token_length(32);
//! ```

use std::future::Future;
use std::pin::Pin;

use crate::{
    Method, Response, StatusCode,
    context::Context,
    middleware::{Middleware, Next},
    security::middleware::util::constant_time_eq,
};

/// CSRF protection middleware using the double-submit cookie pattern.
///
/// Safe methods (`GET`, `HEAD`, `OPTIONS`) pass through and receive a
/// `Set-Cookie` with a fresh CSRF token. State-changing methods must present
/// a matching token in both the cookie and a request header.
///
/// # Configuration
///
/// | Setting        | Default          | Builder method                                |
/// |----------------|------------------|-----------------------------------------------|
/// | Cookie name    | `_csrf`          | [`cookie_name`](Self::cookie_name)            |
/// | Header name    | `X-CSRF-Token`   | [`header_name`](Self::header_name)            |
/// | Token length   | 32 bytes         | [`token_length`](Self::token_length)          |
/// | Cookie path    | `/`              | [`cookie_path`](Self::cookie_path)            |
/// | `SameSite`     | `Strict`         | [`same_site`](Self::same_site)                |
/// | `Secure` flag  | `true`           | [`secure`](Self::secure)                      |
/// | `HttpOnly`     | `false`          | (intentional — JS must read the cookie)       |
///
/// # Examples
///
/// ```rust,no_run
/// use rttp::security::middleware::csrf::CsrfMiddleware;
///
/// let csrf = CsrfMiddleware::new();
/// ```
pub struct CsrfMiddleware {
    cookie_name: String,
    header_name: String,
    token_length: usize,
    cookie_path: String,
    same_site: String,
    secure: bool,
}

impl Default for CsrfMiddleware {
    fn default() -> Self {
        Self::new()
    }
}

impl CsrfMiddleware {
    /// Creates a new `CsrfMiddleware` with secure defaults.
    ///
    /// See the [struct-level docs](Self) for the default configuration table.
    pub fn new() -> Self {
        Self {
            cookie_name: "_csrf".to_string(),
            header_name: "X-CSRF-Token".to_string(),
            token_length: 32,
            cookie_path: "/".to_string(),
            same_site: "Strict".to_string(),
            secure: true,
        }
    }

    /// Sets the cookie name used to store the CSRF token.
    #[must_use]
    pub fn cookie_name(mut self, name: impl Into<String>) -> Self {
        self.cookie_name = name.into();
        self
    }

    /// Sets the request header name from which the submitted CSRF token is read.
    #[must_use]
    pub fn header_name(mut self, name: impl Into<String>) -> Self {
        self.header_name = name.into();
        self
    }

    /// Sets the length (in bytes) of the generated CSRF token.
    ///
    /// The token is hex-encoded, so the cookie value will be `2 * length` characters.
    #[must_use]
    pub fn token_length(mut self, len: usize) -> Self {
        self.token_length = len;
        self
    }

    /// Sets the `Path` attribute on the CSRF cookie.
    #[must_use]
    pub fn cookie_path(mut self, path: impl Into<String>) -> Self {
        self.cookie_path = path.into();
        self
    }

    /// Sets the `SameSite` attribute on the CSRF cookie.
    ///
    /// Accepted values: `"Strict"`, `"Lax"`, `"None"`.
    #[must_use]
    pub fn same_site(mut self, value: impl Into<String>) -> Self {
        self.same_site = value.into();
        self
    }

    /// Controls the `Secure` flag on the CSRF cookie.
    ///
    /// When `true` (default), the cookie is only sent over HTTPS.
    #[must_use]
    pub fn secure(mut self, secure: bool) -> Self {
        self.secure = secure;
        self
    }
}

/// Returns `true` for methods that do not mutate server state.
fn is_safe_method(method: &Method) -> bool {
    matches!(method, Method::Get | Method::Head | Method::Options)
}

/// Generate a hex-encoded random token of the given byte length.
fn generate_token(len: usize) -> String {
    use std::fmt::Write;
    let mut buf = vec![0u8; len];
    getrandom::fill(&mut buf).expect("getrandom failed");
    let mut hex = String::with_capacity(len * 2);
    for byte in &buf {
        write!(hex, "{byte:02x}").expect("hex write failed");
    }
    hex
}

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

impl Middleware for CsrfMiddleware {
    /// Process a request through the CSRF protection policy.
    ///
    /// - **Safe methods** (`GET`, `HEAD`, `OPTIONS`): the request is forwarded to the
    ///   next handler and a `Set-Cookie` with a fresh CSRF token is appended to the
    ///   response.
    /// - **State-changing methods**: the middleware extracts the token from the cookie
    ///   and the configured request header. If both are present and match (constant-time
    ///   comparison), the request proceeds; otherwise `403 Forbidden` is returned.
    fn handle(&self, ctx: Context, next: Next) -> Pin<Box<dyn Future<Output = Response> + Send>> {
        let cookie_name = self.cookie_name.clone();
        let header_name = self.header_name.clone();
        let token_length = self.token_length;
        let cookie_path = self.cookie_path.clone();
        let same_site = self.same_site.clone();
        let secure = self.secure;

        Box::pin(async move {
            let method = ctx.request().method().clone();

            if is_safe_method(&method) {
                let mut resp = next.run(ctx).await;

                let token = generate_token(token_length);
                let mut cookie =
                    format!("{cookie_name}={token}; Path={cookie_path}; SameSite={same_site}");
                if secure {
                    cookie.push_str("; Secure");
                }
                resp.add_header("Set-Cookie", cookie);

                return resp;
            }

            // State-changing method — validate the double-submit token.
            let cookie_token =
                extract_cookie(ctx.request().headers(), &cookie_name).map(str::to_owned);
            let header_token = ctx.request().headers().get(&header_name).map(str::to_owned);

            let (Some(ct), Some(ht)) = (cookie_token, header_token) else {
                return Response::new(StatusCode::Forbidden).body("CSRF token missing");
            };

            // Constant-time comparison to prevent timing attacks.
            if !constant_time_eq(ct.as_bytes(), ht.as_bytes()) {
                return Response::new(StatusCode::Forbidden).body("CSRF token mismatch");
            }

            next.run(ctx).await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Response, StatusCode,
        security::middleware::test_helpers::{make_context, ok_next, response_to_string},
    };

    fn wire(response: Response) -> String {
        response_to_string(response)
    }

    #[tokio::test]
    async fn get_request_passes_through_and_sets_cookie() {
        let csrf = CsrfMiddleware::new().secure(false);
        let ctx = make_context(b"GET /page HTTP/1.1\r\nHost: localhost\r\n\r\n");

        let resp = csrf.handle(ctx, ok_next()).await;
        let w = wire(resp);

        assert!(w.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(w.contains("Set-Cookie: _csrf="));
        assert!(w.contains("Path=/"));
        assert!(w.contains("SameSite=Strict"));
    }

    #[tokio::test]
    async fn head_request_passes_through_and_sets_cookie() {
        let csrf = CsrfMiddleware::new().secure(false);
        let ctx = make_context(b"HEAD /page HTTP/1.1\r\nHost: localhost\r\n\r\n");

        let resp = csrf.handle(ctx, ok_next()).await;
        let w = wire(resp);

        assert!(w.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(w.contains("Set-Cookie: _csrf="));
    }

    #[tokio::test]
    async fn options_request_passes_through_and_sets_cookie() {
        let csrf = CsrfMiddleware::new().secure(false);
        let ctx = make_context(b"OPTIONS /page HTTP/1.1\r\nHost: localhost\r\n\r\n");

        let resp = csrf.handle(ctx, ok_next()).await;
        let w = wire(resp);

        assert!(w.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(w.contains("Set-Cookie: _csrf="));
    }

    #[tokio::test]
    async fn secure_flag_appears_when_enabled() {
        let csrf = CsrfMiddleware::new(); // secure=true by default
        let ctx = make_context(b"GET /page HTTP/1.1\r\nHost: localhost\r\n\r\n");

        let resp = csrf.handle(ctx, ok_next()).await;
        let w = wire(resp);

        assert!(w.contains("; Secure"));
    }

    #[tokio::test]
    async fn secure_flag_absent_when_disabled() {
        let csrf = CsrfMiddleware::new().secure(false);
        let ctx = make_context(b"GET /page HTTP/1.1\r\nHost: localhost\r\n\r\n");

        let resp = csrf.handle(ctx, ok_next()).await;
        let w = wire(resp);

        assert!(!w.contains("; Secure"));
    }

    #[tokio::test]
    async fn post_without_token_returns_403() {
        let csrf = CsrfMiddleware::new();
        let ctx = make_context(b"POST /submit HTTP/1.1\r\nHost: localhost\r\n\r\n");

        let resp = csrf.handle(ctx, ok_next()).await;

        assert_eq!(resp.status(), StatusCode::Forbidden);
        assert!(wire(resp).contains("CSRF token missing"));
    }

    #[tokio::test]
    async fn post_with_cookie_but_no_header_returns_403() {
        let csrf = CsrfMiddleware::new();
        let ctx = make_context(
            b"POST /submit HTTP/1.1\r\nHost: localhost\r\nCookie: _csrf=abc123\r\n\r\n",
        );

        let resp = csrf.handle(ctx, ok_next()).await;

        assert_eq!(resp.status(), StatusCode::Forbidden);
        assert!(wire(resp).contains("CSRF token missing"));
    }

    #[tokio::test]
    async fn post_with_header_but_no_cookie_returns_403() {
        let csrf = CsrfMiddleware::new();
        let ctx = make_context(
            b"POST /submit HTTP/1.1\r\nHost: localhost\r\nX-CSRF-Token: abc123\r\n\r\n",
        );

        let resp = csrf.handle(ctx, ok_next()).await;

        assert_eq!(resp.status(), StatusCode::Forbidden);
        assert!(wire(resp).contains("CSRF token missing"));
    }

    #[tokio::test]
    async fn post_with_mismatched_tokens_returns_403() {
        let csrf = CsrfMiddleware::new();
        let ctx = make_context(
            b"POST /submit HTTP/1.1\r\nHost: localhost\r\n\
              Cookie: _csrf=token_a\r\n\
              X-CSRF-Token: token_b\r\n\r\n",
        );

        let resp = csrf.handle(ctx, ok_next()).await;

        assert_eq!(resp.status(), StatusCode::Forbidden);
        assert!(wire(resp).contains("CSRF token mismatch"));
    }

    #[tokio::test]
    async fn post_with_matching_tokens_passes_through() {
        let csrf = CsrfMiddleware::new();
        let ctx = make_context(
            b"POST /submit HTTP/1.1\r\nHost: localhost\r\n\
              Cookie: _csrf=valid_token\r\n\
              X-CSRF-Token: valid_token\r\n\r\n",
        );

        let resp = csrf.handle(ctx, ok_next()).await;

        assert_eq!(resp.status(), StatusCode::Ok);
    }

    #[tokio::test]
    async fn put_with_matching_tokens_passes_through() {
        let csrf = CsrfMiddleware::new();
        let ctx = make_context(
            b"PUT /resource HTTP/1.1\r\nHost: localhost\r\n\
              Cookie: _csrf=tok\r\n\
              X-CSRF-Token: tok\r\n\r\n",
        );

        let resp = csrf.handle(ctx, ok_next()).await;

        assert_eq!(resp.status(), StatusCode::Ok);
    }

    #[tokio::test]
    async fn delete_without_token_returns_403() {
        let csrf = CsrfMiddleware::new();
        let ctx = make_context(b"DELETE /resource HTTP/1.1\r\nHost: localhost\r\n\r\n");

        let resp = csrf.handle(ctx, ok_next()).await;

        assert_eq!(resp.status(), StatusCode::Forbidden);
    }

    #[tokio::test]
    async fn patch_with_matching_tokens_passes_through() {
        let csrf = CsrfMiddleware::new();
        let ctx = make_context(
            b"PATCH /resource HTTP/1.1\r\nHost: localhost\r\n\
              Cookie: _csrf=abc\r\n\
              X-CSRF-Token: abc\r\n\r\n",
        );

        let resp = csrf.handle(ctx, ok_next()).await;

        assert_eq!(resp.status(), StatusCode::Ok);
    }

    #[tokio::test]
    async fn custom_cookie_and_header_names() {
        let csrf = CsrfMiddleware::new()
            .cookie_name("my_csrf")
            .header_name("X-My-Token");

        // Valid with custom names
        let ctx = make_context(
            b"POST /submit HTTP/1.1\r\nHost: localhost\r\n\
              Cookie: my_csrf=tok\r\n\
              X-My-Token: tok\r\n\r\n",
        );
        let resp = csrf.handle(ctx, ok_next()).await;
        assert_eq!(resp.status(), StatusCode::Ok);

        // Fails with default names
        let ctx = make_context(
            b"POST /submit HTTP/1.1\r\nHost: localhost\r\n\
              Cookie: _csrf=tok\r\n\
              X-CSRF-Token: tok\r\n\r\n",
        );
        let resp = csrf.handle(ctx, ok_next()).await;
        assert_eq!(resp.status(), StatusCode::Forbidden);
    }

    #[tokio::test]
    async fn custom_same_site_appears_in_cookie() {
        let csrf = CsrfMiddleware::new().same_site("Lax").secure(false);
        let ctx = make_context(b"GET /page HTTP/1.1\r\nHost: localhost\r\n\r\n");

        let resp = csrf.handle(ctx, ok_next()).await;
        let w = wire(resp);

        assert!(w.contains("SameSite=Lax"));
    }

    #[tokio::test]
    async fn custom_cookie_path_appears_in_cookie() {
        let csrf = CsrfMiddleware::new().cookie_path("/api").secure(false);
        let ctx = make_context(b"GET /api/data HTTP/1.1\r\nHost: localhost\r\n\r\n");

        let resp = csrf.handle(ctx, ok_next()).await;
        let w = wire(resp);

        assert!(w.contains("Path=/api"));
    }

    #[test]
    fn generated_token_has_correct_hex_length() {
        let token = generate_token(32);
        assert_eq!(token.len(), 64); // 32 bytes × 2 hex chars
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn generated_tokens_are_unique() {
        let a = generate_token(32);
        let b = generate_token(32);
        assert_ne!(a, b);
    }

    #[test]
    fn constant_time_eq_same() {
        assert!(constant_time_eq(b"hello", b"hello"));
    }

    #[test]
    fn constant_time_eq_different() {
        assert!(!constant_time_eq(b"hello", b"world"));
    }

    #[test]
    fn constant_time_eq_different_lengths() {
        assert!(!constant_time_eq(b"short", b"longer"));
    }

    #[test]
    fn constant_time_eq_empty() {
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn extract_cookie_single_value() {
        let mut headers = crate::Headers::new();
        headers.insert("Cookie", "_csrf=abc123");
        assert_eq!(extract_cookie(&headers, "_csrf"), Some("abc123"));
    }

    #[test]
    fn extract_cookie_multiple_cookies() {
        let mut headers = crate::Headers::new();
        headers.insert("Cookie", "session=xyz; _csrf=tok456; theme=dark");
        assert_eq!(extract_cookie(&headers, "_csrf"), Some("tok456"));
    }

    #[test]
    fn extract_cookie_missing() {
        let mut headers = crate::Headers::new();
        headers.insert("Cookie", "session=xyz");
        assert_eq!(extract_cookie(&headers, "_csrf"), None);
    }

    #[test]
    fn extract_cookie_no_cookie_header() {
        let headers = crate::Headers::new();
        assert_eq!(extract_cookie(&headers, "_csrf"), None);
    }
}
