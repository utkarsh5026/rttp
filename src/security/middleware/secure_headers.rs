//! Secure HTTP response headers middleware.
//!
//! Injects the following defensive headers on every response:
//!
//! | Header                      | Default value                                    |
//! |-----------------------------|--------------------------------------------------|
//! | `Strict-Transport-Security` | `max-age=31536000`                               |
//! | `X-Content-Type-Options`    | `nosniff`                                        |
//! | `X-Frame-Options`           | `DENY`                                           |
//! | `Content-Security-Policy`   | `default-src 'self'`                             |
//! | `Referrer-Policy`           | `no-referrer`                                    |
//! | `Permissions-Policy`        | `geolocation=(), microphone=(), camera=()`       |
//!
//! All headers can be overridden via builder methods. Where the spec defines a
//! fixed set of valid values, typed helpers ([`FrameOptions`], [`ReferrerPolicy`],
//! [`HstsConfig`]) are provided so the compiler can reject invalid input.
//! Raw strings are still accepted for forward-compatibility.
//!
//! # Examples
//!
//! ```rust,no_run
//! use rttp::security::middleware::secure_headers::{
//!     FrameOptions, HstsConfig, ReferrerPolicy, SecureHeadersMiddleware,
//! };
//!
//! let mw = SecureHeadersMiddleware::new()
//!     .hsts(HstsConfig::new(63_072_000).include_subdomains().preload())
//!     .frame_options(FrameOptions::SameOrigin)
//!     .referrer_policy(ReferrerPolicy::StrictOriginWhenCrossOrigin)
//!     .csp("default-src 'self'; script-src 'self' https://cdn.example.com");
//! ```

use std::{future::Future, pin::Pin};

use crate::{
    Response,
    context::Context,
    middleware::{Middleware, Next},
};

/// Valid values for the `X-Frame-Options` response header.
///
/// Pass one of these variants to [`SecureHeadersMiddleware::frame_options`] for
/// compile-time safety, or pass a raw `&str` / `String` for custom values.
///
/// # Examples
///
/// ```rust
/// use rttp::security::middleware::secure_headers::{FrameOptions, SecureHeadersMiddleware};
///
/// let mw = SecureHeadersMiddleware::new().frame_options(FrameOptions::SameOrigin);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameOptions {
    /// `DENY` — the page cannot be displayed in a frame at all.
    Deny,
    /// `SAMEORIGIN` — the page can only be displayed in a frame on the same origin.
    SameOrigin,
}

impl From<FrameOptions> for String {
    fn from(f: FrameOptions) -> Self {
        match f {
            FrameOptions::Deny => "DENY".to_string(),
            FrameOptions::SameOrigin => "SAMEORIGIN".to_string(),
        }
    }
}

/// Valid values for the `Referrer-Policy` response header.
///
/// Pass one of these variants to [`SecureHeadersMiddleware::referrer_policy`] for
/// compile-time safety, or pass a raw `&str` / `String` for custom values.
///
/// # Examples
///
/// ```rust
/// use rttp::security::middleware::secure_headers::{ReferrerPolicy, SecureHeadersMiddleware};
///
/// let mw = SecureHeadersMiddleware::new()
///     .referrer_policy(ReferrerPolicy::StrictOriginWhenCrossOrigin);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReferrerPolicy {
    NoReferrer,
    NoReferrerWhenDowngrade,
    Origin,
    OriginWhenCrossOrigin,
    SameOrigin,
    StrictOrigin,
    StrictOriginWhenCrossOrigin,
    UnsafeUrl,
}

impl From<ReferrerPolicy> for String {
    fn from(r: ReferrerPolicy) -> Self {
        match r {
            ReferrerPolicy::NoReferrer => "no-referrer",
            ReferrerPolicy::NoReferrerWhenDowngrade => "no-referrer-when-downgrade",
            ReferrerPolicy::Origin => "origin",
            ReferrerPolicy::OriginWhenCrossOrigin => "origin-when-cross-origin",
            ReferrerPolicy::SameOrigin => "same-origin",
            ReferrerPolicy::StrictOrigin => "strict-origin",
            ReferrerPolicy::StrictOriginWhenCrossOrigin => "strict-origin-when-cross-origin",
            ReferrerPolicy::UnsafeUrl => "unsafe-url",
        }
        .to_string()
    }
}

/// Builder for the `Strict-Transport-Security` header value.
///
/// Constructs the HSTS header string from structured fields so you never have
/// to hand-write `"max-age=31536000; includeSubDomains"` yourself.
///
/// # Examples
///
/// ```rust
/// use rttp::security::middleware::secure_headers::{HstsConfig, SecureHeadersMiddleware};
///
/// let mw = SecureHeadersMiddleware::new()
///     .hsts(HstsConfig::new(63_072_000).include_subdomains().preload());
/// ```
#[derive(Debug, Clone)]
pub struct HstsConfig {
    max_age: u64,
    include_subdomains: bool,
    preload: bool,
}

impl HstsConfig {
    /// Creates a new `HstsConfig` with the given `max-age` in seconds.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::security::middleware::secure_headers::HstsConfig;
    ///
    /// let hsts = HstsConfig::new(31_536_000); // 1 year
    /// ```
    pub fn new(max_age: u64) -> Self {
        Self {
            max_age,
            include_subdomains: false,
            preload: false,
        }
    }

    /// Appends `; includeSubDomains` to the header value.
    #[must_use]
    pub fn include_subdomains(mut self) -> Self {
        self.include_subdomains = true;
        self
    }

    /// Appends `; preload` to the header value.
    ///
    /// Only add this if your domain is submitted to the HSTS preload list.
    #[must_use]
    pub fn preload(mut self) -> Self {
        self.preload = true;
        self
    }
}

impl From<HstsConfig> for String {
    fn from(h: HstsConfig) -> Self {
        let mut value = format!("max-age={}", h.max_age);
        if h.include_subdomains {
            value.push_str("; includeSubDomains");
        }
        if h.preload {
            value.push_str("; preload");
        }
        value
    }
}

/// Middleware that injects security-hardening HTTP headers on every response.
///
/// Constructed via [`SecureHeadersMiddleware::new`] and configured through the
/// builder methods [`hsts`](Self::hsts), [`csp`](Self::csp),
/// [`frame_options`](Self::frame_options), [`referrer_policy`](Self::referrer_policy),
/// and [`permissions_policy`](Self::permissions_policy).
///
/// Each builder method accepts either a typed helper ([`HstsConfig`],
/// [`FrameOptions`], [`ReferrerPolicy`]) or a raw `&str` / `String`.
pub struct SecureHeadersMiddleware {
    hsts: String,
    csp: String,
    frame_options: String,
    referrer_policy: String,
    permissions_policy: String,
}

impl Default for SecureHeadersMiddleware {
    fn default() -> Self {
        Self::new()
    }
}

impl SecureHeadersMiddleware {
    /// Creates a new `SecureHeadersMiddleware` with sensible, conservative defaults.
    ///
    /// | Header                      | Default                                    |
    /// |-----------------------------|--------------------------------------------|
    /// | `Strict-Transport-Security` | `max-age=31536000`                         |
    /// | `X-Content-Type-Options`    | `nosniff` (always fixed)                   |
    /// | `X-Frame-Options`           | `DENY`                                     |
    /// | `Content-Security-Policy`   | `default-src 'self'`                       |
    /// | `Referrer-Policy`           | `no-referrer`                              |
    /// | `Permissions-Policy`        | `geolocation=(), microphone=(), camera=()` |
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::security::middleware::secure_headers::SecureHeadersMiddleware;
    ///
    /// let mw = SecureHeadersMiddleware::new();
    /// ```
    pub fn new() -> Self {
        Self {
            hsts: "max-age=31536000".to_string(),
            csp: "default-src 'self'".to_string(),
            frame_options: "DENY".to_string(),
            referrer_policy: "no-referrer".to_string(),
            permissions_policy: "geolocation=(), microphone=(), camera=()".to_string(),
        }
    }

    /// Overrides the `Strict-Transport-Security` header value.
    ///
    /// Accepts a [`HstsConfig`] for structured, type-safe construction or a
    /// raw `&str` / `String` for custom values.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::security::middleware::secure_headers::{HstsConfig, SecureHeadersMiddleware};
    ///
    /// // typed
    /// let mw = SecureHeadersMiddleware::new()
    ///     .hsts(HstsConfig::new(63_072_000).include_subdomains());
    ///
    /// // raw string
    /// let mw = SecureHeadersMiddleware::new()
    ///     .hsts("max-age=63072000; includeSubDomains");
    /// ```
    #[must_use]
    pub fn hsts(mut self, value: impl Into<String>) -> Self {
        self.hsts = value.into();
        self
    }

    /// Overrides the `Content-Security-Policy` header value.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::security::middleware::secure_headers::SecureHeadersMiddleware;
    ///
    /// let mw = SecureHeadersMiddleware::new()
    ///     .csp("default-src 'self'; script-src 'self' https://cdn.example.com");
    /// ```
    #[must_use]
    pub fn csp(mut self, value: impl Into<String>) -> Self {
        self.csp = value.into();
        self
    }

    /// Overrides the `X-Frame-Options` header value.
    ///
    /// Accepts a [`FrameOptions`] variant for compile-time safety or a raw
    /// `&str` / `String` for custom values.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::security::middleware::secure_headers::{FrameOptions, SecureHeadersMiddleware};
    ///
    /// // typed
    /// let mw = SecureHeadersMiddleware::new().frame_options(FrameOptions::SameOrigin);
    ///
    /// // raw string
    /// let mw = SecureHeadersMiddleware::new().frame_options("SAMEORIGIN");
    /// ```
    #[must_use]
    pub fn frame_options(mut self, value: impl Into<String>) -> Self {
        self.frame_options = value.into();
        self
    }

    /// Overrides the `Referrer-Policy` header value.
    ///
    /// Accepts a [`ReferrerPolicy`] variant for compile-time safety or a raw
    /// `&str` / `String` for custom values.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::security::middleware::secure_headers::{ReferrerPolicy, SecureHeadersMiddleware};
    ///
    /// // typed
    /// let mw = SecureHeadersMiddleware::new()
    ///     .referrer_policy(ReferrerPolicy::StrictOriginWhenCrossOrigin);
    ///
    /// // raw string
    /// let mw = SecureHeadersMiddleware::new()
    ///     .referrer_policy("strict-origin-when-cross-origin");
    /// ```
    #[must_use]
    pub fn referrer_policy(mut self, value: impl Into<String>) -> Self {
        self.referrer_policy = value.into();
        self
    }

    /// Overrides the `Permissions-Policy` header value.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::security::middleware::secure_headers::SecureHeadersMiddleware;
    ///
    /// let mw = SecureHeadersMiddleware::new()
    ///     .permissions_policy("geolocation=(), fullscreen=(self)");
    /// ```
    #[must_use]
    pub fn permissions_policy(mut self, value: impl Into<String>) -> Self {
        self.permissions_policy = value.into();
        self
    }
}

impl Middleware for SecureHeadersMiddleware {
    /// Calls the downstream handler and appends the security headers to its response.
    fn handle(&self, ctx: Context, next: Next) -> Pin<Box<dyn Future<Output = Response> + Send>> {
        let hsts = self.hsts.clone();
        let csp = self.csp.clone();
        let frame_options = self.frame_options.clone();
        let referrer_policy = self.referrer_policy.clone();
        let permissions_policy = self.permissions_policy.clone();

        Box::pin(async move {
            let mut resp = next.run(ctx).await;

            resp.add_header("Strict-Transport-Security", hsts);
            resp.add_header("X-Content-Type-Options", "nosniff");
            resp.add_header("X-Frame-Options", frame_options);
            resp.add_header("Content-Security-Policy", csp);
            resp.add_header("Referrer-Policy", referrer_policy);
            resp.add_header("Permissions-Policy", permissions_policy);

            resp
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

    fn make_context() -> Context {
        let (req, _) = crate::Request::parse(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
        Context::new(req)
    }

    fn ok_next() -> Next {
        let handler: MiddlewareHandler = Arc::new(|_ctx: Context, _next: Next| {
            Box::pin(async { Response::new(StatusCode::Ok) })
        });
        Next::new(vec![handler])
    }

    fn wire(r: Response) -> String {
        String::from_utf8(r.into_bytes().to_vec()).unwrap()
    }

    #[tokio::test]
    async fn default_hsts_header_present() {
        let resp = SecureHeadersMiddleware::new()
            .handle(make_context(), ok_next())
            .await;
        assert!(wire(resp).contains("Strict-Transport-Security: max-age=31536000\r\n"));
    }

    #[tokio::test]
    async fn x_content_type_options_always_nosniff() {
        let resp = SecureHeadersMiddleware::new()
            .handle(make_context(), ok_next())
            .await;
        assert!(wire(resp).contains("X-Content-Type-Options: nosniff\r\n"));
    }

    #[tokio::test]
    async fn default_x_frame_options_deny() {
        let resp = SecureHeadersMiddleware::new()
            .handle(make_context(), ok_next())
            .await;
        assert!(wire(resp).contains("X-Frame-Options: DENY\r\n"));
    }

    #[tokio::test]
    async fn default_csp_header_present() {
        let resp = SecureHeadersMiddleware::new()
            .handle(make_context(), ok_next())
            .await;
        assert!(wire(resp).contains("Content-Security-Policy: default-src 'self'\r\n"));
    }

    #[tokio::test]
    async fn default_referrer_policy_no_referrer() {
        let resp = SecureHeadersMiddleware::new()
            .handle(make_context(), ok_next())
            .await;
        assert!(wire(resp).contains("Referrer-Policy: no-referrer\r\n"));
    }

    #[tokio::test]
    async fn default_permissions_policy_present() {
        let resp = SecureHeadersMiddleware::new()
            .handle(make_context(), ok_next())
            .await;
        assert!(
            wire(resp).contains("Permissions-Policy: geolocation=(), microphone=(), camera=()\r\n")
        );
    }

    #[test]
    fn frame_options_deny_converts_to_string() {
        assert_eq!(String::from(FrameOptions::Deny), "DENY");
    }

    #[test]
    fn frame_options_sameorigin_converts_to_string() {
        assert_eq!(String::from(FrameOptions::SameOrigin), "SAMEORIGIN");
    }

    #[tokio::test]
    async fn frame_options_enum_deny_used_in_middleware() {
        let resp = SecureHeadersMiddleware::new()
            .frame_options(FrameOptions::Deny)
            .handle(make_context(), ok_next())
            .await;
        assert!(wire(resp).contains("X-Frame-Options: DENY\r\n"));
    }

    #[tokio::test]
    async fn frame_options_enum_sameorigin_used_in_middleware() {
        let resp = SecureHeadersMiddleware::new()
            .frame_options(FrameOptions::SameOrigin)
            .handle(make_context(), ok_next())
            .await;
        assert!(wire(resp).contains("X-Frame-Options: SAMEORIGIN\r\n"));
    }

    #[test]
    fn referrer_policy_variants_convert_correctly() {
        let cases = [
            (ReferrerPolicy::NoReferrer, "no-referrer"),
            (
                ReferrerPolicy::NoReferrerWhenDowngrade,
                "no-referrer-when-downgrade",
            ),
            (ReferrerPolicy::Origin, "origin"),
            (
                ReferrerPolicy::OriginWhenCrossOrigin,
                "origin-when-cross-origin",
            ),
            (ReferrerPolicy::SameOrigin, "same-origin"),
            (ReferrerPolicy::StrictOrigin, "strict-origin"),
            (
                ReferrerPolicy::StrictOriginWhenCrossOrigin,
                "strict-origin-when-cross-origin",
            ),
            (ReferrerPolicy::UnsafeUrl, "unsafe-url"),
        ];
        for (variant, expected) in cases {
            assert_eq!(String::from(variant), expected);
        }
    }

    #[tokio::test]
    async fn referrer_policy_enum_used_in_middleware() {
        let resp = SecureHeadersMiddleware::new()
            .referrer_policy(ReferrerPolicy::StrictOriginWhenCrossOrigin)
            .handle(make_context(), ok_next())
            .await;
        assert!(wire(resp).contains("Referrer-Policy: strict-origin-when-cross-origin\r\n"));
    }

    #[test]
    fn hsts_config_max_age_only() {
        assert_eq!(
            String::from(HstsConfig::new(31_536_000)),
            "max-age=31536000"
        );
    }

    #[test]
    fn hsts_config_with_include_subdomains() {
        assert_eq!(
            String::from(HstsConfig::new(31_536_000).include_subdomains()),
            "max-age=31536000; includeSubDomains"
        );
    }

    #[test]
    fn hsts_config_with_preload() {
        assert_eq!(
            String::from(HstsConfig::new(31_536_000).preload()),
            "max-age=31536000; preload"
        );
    }

    #[test]
    fn hsts_config_full() {
        assert_eq!(
            String::from(HstsConfig::new(63_072_000).include_subdomains().preload()),
            "max-age=63072000; includeSubDomains; preload"
        );
    }

    #[tokio::test]
    async fn hsts_config_used_in_middleware() {
        let resp = SecureHeadersMiddleware::new()
            .hsts(HstsConfig::new(63_072_000).include_subdomains())
            .handle(make_context(), ok_next())
            .await;
        assert!(
            wire(resp)
                .contains("Strict-Transport-Security: max-age=63072000; includeSubDomains\r\n")
        );
    }

    #[tokio::test]
    async fn raw_string_hsts_accepted() {
        let resp = SecureHeadersMiddleware::new()
            .hsts("max-age=63072000; includeSubDomains")
            .handle(make_context(), ok_next())
            .await;
        assert!(
            wire(resp)
                .contains("Strict-Transport-Security: max-age=63072000; includeSubDomains\r\n")
        );
    }

    #[tokio::test]
    async fn raw_string_frame_options_accepted() {
        let resp = SecureHeadersMiddleware::new()
            .frame_options("SAMEORIGIN")
            .handle(make_context(), ok_next())
            .await;
        assert!(wire(resp).contains("X-Frame-Options: SAMEORIGIN\r\n"));
    }

    #[tokio::test]
    async fn downstream_response_status_preserved() {
        let handler: MiddlewareHandler = Arc::new(|_ctx: Context, _next: Next| {
            Box::pin(async { Response::new(StatusCode::Created) })
        });
        let next = Next::new(vec![handler]);

        let resp = SecureHeadersMiddleware::new()
            .handle(make_context(), next)
            .await;
        assert_eq!(resp.status(), StatusCode::Created);
    }
}
