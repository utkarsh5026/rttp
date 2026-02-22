//! Request routing — map URL patterns and HTTP methods to handler functions.
//!
//! This module provides [`Router`], which dispatches incoming HTTP requests to handler
//! functions based on the request method and URL path. Three pattern styles are supported:
//!
//! | Pattern              | Example match              | Captured params              |
//! |----------------------|----------------------------|------------------------------|
//! | `/users`             | `/users`                   | *(none)*                     |
//! | `/users/:id`         | `/users/42`                | `id → "42"`                  |
//! | `/files/*`           | `/files/docs/readme.txt`   | `wildcard → "/docs/readme.txt"` |
//!
//! Trailing slashes are normalized on both patterns and incoming paths, so `/users/` and
//! `/users` are treated as equivalent.
//!
//! Routes are matched in registration order; the first route whose method and pattern both
//! match the incoming request wins.

use std::pin::Pin;
use std::sync::Arc;

use crate::context::{Context, PathParams};
use crate::{Method, Request, Response, StatusCode};

/// Type-erased, heap-allocated async handler that processes a [`Context`] and returns a
/// [`Response`].
///
/// Handlers are stored behind `Arc<dyn Fn(…)>` so they can be cloned and shared across
/// threads without copying the underlying closure. In practice you never construct this
/// type directly — use [`Router::get`], [`Router::post`], and the other method-specific
/// helpers instead.
pub type Handler =
    Arc<dyn Fn(Context) -> Pin<Box<dyn Future<Output = Response> + Send>> + Send + Sync + 'static>;

/// Conversion trait for async handler functions.
///
/// Any `Fn(Context) -> impl Future<Output = Response> + Send` that is also
/// `Send + Sync + 'static` implements this trait automatically via the blanket impl
/// below. Router methods accept `impl IntoHandler` so the two-type-parameter where-bound
/// does not need to be repeated at every call site.
pub trait IntoHandler: Send + Sync + 'static {
    /// Call the handler with the given context, boxing the returned future.
    fn call(&self, ctx: Context) -> Pin<Box<dyn Future<Output = Response> + Send>>;
}

impl<T, F> IntoHandler for T
where
    T: Fn(Context) -> F + Send + Sync + 'static,
    F: Future<Output = Response> + Send + 'static,
{
    fn call(&self, ctx: Context) -> Pin<Box<dyn Future<Output = Response> + Send>> {
        Box::pin((self)(ctx))
    }
}

// A single path segment, either a literal string or a named capture (`:name`).
#[derive(Debug, Clone)]
enum Segment {
    Static(String),
    Parameter(String),
}

// Compiled representation of a route pattern string.
#[derive(Debug, Clone)]
enum Pattern {
    // Matches one exact path string, e.g. `/users`.
    Exact(String),
    // Matches a fixed number of segments where some may be named captures, e.g. `/users/:id`.
    Parameterized { segments: Vec<Segment> },
    // Matches any path that starts with the given prefix, e.g. `/files/*`.
    Wildcard(String),
}

impl Pattern {
    /// Parse a route pattern string into a `Pattern`.
    ///
    /// The pattern is classified as follows (checked in order):
    ///
    /// 1. Ends with `/*` → [`Pattern::Wildcard`] — matches any path sharing the prefix.
    /// 2. Contains `:` → [`Pattern::Parameterized`] — one or more named captures.
    /// 3. Otherwise → [`Pattern::Exact`] — literal path match.
    ///
    /// A trailing slash (other than on the root `/`) is stripped before classification so
    /// that `/users/` and `/users` compile to identical patterns.
    ///
    /// # Arguments
    ///
    /// - `pattern` — The raw pattern string, e.g. `"/users/:id"` or `"/files/*"`.
    ///
    /// # Returns
    ///
    /// The compiled [`Pattern`] variant corresponding to `pattern`.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use rttp::router::Pattern; // illustrative — Pattern is crate-private
    /// let p = Pattern::parse("/users/:id");
    /// // p is Pattern::Parameterized with segments ["users", ":id"]
    /// ```
    pub fn parse(pattern: &str) -> Self {
        let pattern = if pattern != "/" && pattern.ends_with('/') {
            &pattern[..pattern.len() - 1]
        } else {
            pattern
        };

        if let Some(prefix) = pattern.strip_suffix("/*") {
            return Pattern::Wildcard(prefix.to_string());
        }

        if pattern.contains(':') {
            let segments = pattern
                .split('/')
                .filter(|s| !s.is_empty())
                .map(|s| {
                    if let Some(p) = s.strip_prefix(':') {
                        Segment::Parameter(p.to_string())
                    } else {
                        Segment::Static(s.to_string())
                    }
                })
                .collect();

            return Pattern::Parameterized { segments };
        }

        Pattern::Exact(pattern.to_string())
    }

    // Try to match `path` against this pattern, returning extracted [`PathParams`] on success.
    fn matches(&self, path: &str) -> Option<PathParams> {
        let path = if path != "/" && path.ends_with('/') {
            &path[..path.len() - 1]
        } else {
            path
        };

        match self {
            Pattern::Exact(p) => {
                if p == path {
                    Some(PathParams::new())
                } else {
                    None
                }
            }
            Pattern::Parameterized { segments } => {
                let mut params = PathParams::new();
                let path_segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

                if segments.len() != path_segments.len() {
                    return None;
                }

                for (seg, path_seg) in segments.iter().zip(path_segments) {
                    match seg {
                        Segment::Static(s) => {
                            if s != path_seg {
                                return None;
                            }
                        }
                        Segment::Parameter(name) => {
                            params.insert(name.clone(), path_seg.to_string());
                        }
                    }
                }

                Some(params)
            }
            Pattern::Wildcard(prefix) => {
                if let Some(suffix) = path.strip_prefix(prefix) {
                    let mut params = PathParams::new();
                    params.insert("wildcard".to_string(), suffix.to_string());
                    Some(params)
                } else {
                    None
                }
            }
        }
    }
}

// A single registered route binding a method + pattern to a handler.
struct Route {
    method: Method,
    pattern: Pattern,
    handler: Handler,
}

impl Route {
    fn new(method: Method, pattern: &str, handler: Handler) -> Self {
        Self {
            method,
            pattern: Pattern::parse(pattern),
            handler,
        }
    }

    // Returns `Some(params)` when both the HTTP method and path pattern match, `None` otherwise.
    fn matches(&self, method: &Method, path: &str) -> Option<PathParams> {
        if &self.method == method {
            self.pattern.matches(path)
        } else {
            None
        }
    }
}

/// HTTP request router that dispatches requests to registered handler functions.
///
/// Routes are evaluated in registration order; the first route whose HTTP method and path
/// pattern both match the incoming request is used. When no route matches, a
/// `404 Not Found` response is returned automatically.
///
/// # Examples
///
/// ```rust,no_run
/// use rttp::{Router, Response, StatusCode};
///
/// let mut router = Router::new();
///
/// router.get("/ping", |_ctx| async { Response::new(StatusCode::Ok) });
///
/// router.get("/users/:id", |ctx| async move {
///     let id = ctx.params().get("id").unwrap_or("unknown").to_owned();
///     Response::new(StatusCode::Ok).body(id)
/// });
/// ```
pub struct Router {
    routes: Vec<Route>,
}

impl Default for Router {
    fn default() -> Self {
        Self::new()
    }
}

impl Router {
    /// Create a new, empty `Router` with no registered routes.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::Router;
    ///
    /// let router = Router::new();
    /// assert!(router.is_empty());
    /// ```
    pub fn new() -> Self {
        Self { routes: Vec::new() }
    }

    /// Register a handler for `GET` requests matching `path`.
    ///
    /// # Arguments
    ///
    /// - `path` — URL pattern string (e.g. `"/users"`, `"/users/:id"`, or `"/files/*"`).
    /// - `handler` — Async function that receives a [`Context`] and returns a [`Response`].
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use rttp::{Router, Response, StatusCode};
    ///
    /// let mut router = Router::new();
    /// router.get("/hello", |_ctx| async { Response::new(StatusCode::Ok) });
    /// ```
    pub fn get(&mut self, path: &str, handler: impl IntoHandler) {
        self.add_route(Method::Get, path, handler);
    }

    /// Register a handler for `POST` requests matching `path`.
    ///
    /// # Arguments
    ///
    /// - `path` — URL pattern string (e.g. `"/users"`, `"/users/:id"`, or `"/files/*"`).
    /// - `handler` — Async function that receives a [`Context`] and returns a [`Response`].
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use rttp::{Router, Response, StatusCode};
    ///
    /// let mut router = Router::new();
    /// router.post("/users", |_ctx| async { Response::new(StatusCode::Created) });
    /// ```
    pub fn post(&mut self, path: &str, handler: impl IntoHandler) {
        self.add_route(Method::Post, path, handler);
    }

    /// Register a handler for `PUT` requests matching `path`.
    ///
    /// # Arguments
    ///
    /// - `path` — URL pattern string (e.g. `"/users/:id"`).
    /// - `handler` — Async function that receives a [`Context`] and returns a [`Response`].
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use rttp::{Router, Response, StatusCode};
    ///
    /// let mut router = Router::new();
    /// router.put("/users/:id", |_ctx| async { Response::new(StatusCode::Ok) });
    /// ```
    pub fn put(&mut self, path: &str, handler: impl IntoHandler) {
        self.add_route(Method::Put, path, handler);
    }

    /// Register a handler for `DELETE` requests matching `path`.
    ///
    /// # Arguments
    ///
    /// - `path` — URL pattern string (e.g. `"/users/:id"`).
    /// - `handler` — Async function that receives a [`Context`] and returns a [`Response`].
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use rttp::{Router, Response, StatusCode};
    ///
    /// let mut router = Router::new();
    /// router.delete("/users/:id", |_ctx| async { Response::new(StatusCode::Ok) });
    /// ```
    pub fn delete(&mut self, path: &str, handler: impl IntoHandler) {
        self.add_route(Method::Delete, path, handler);
    }

    /// Register a handler for `OPTIONS` requests matching `path`.
    ///
    /// # Arguments
    ///
    /// - `path` — URL pattern string.
    /// - `handler` — Async function that receives a [`Context`] and returns a [`Response`].
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use rttp::{Router, Response, StatusCode};
    ///
    /// let mut router = Router::new();
    /// router.options("/users", |_ctx| async { Response::new(StatusCode::Ok) });
    /// ```
    pub fn options(&mut self, path: &str, handler: impl IntoHandler) {
        self.add_route(Method::Options, path, handler);
    }

    /// Register a handler for `PATCH` requests matching `path`.
    ///
    /// # Arguments
    ///
    /// - `path` — URL pattern string (e.g. `"/users/:id"`).
    /// - `handler` — Async function that receives a [`Context`] and returns a [`Response`].
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use rttp::{Router, Response, StatusCode};
    ///
    /// let mut router = Router::new();
    /// router.patch("/users/:id", |_ctx| async { Response::new(StatusCode::Ok) });
    /// ```
    pub fn patch(&mut self, path: &str, handler: impl IntoHandler) {
        self.add_route(Method::Patch, path, handler);
    }

    // Erase the concrete handler type and store it as a `Handler` trait object.
    fn add_route(&mut self, method: Method, path: &str, handler: impl IntoHandler) {
        let handler: Handler = Arc::new(move |ctx| handler.call(ctx));
        self.routes.push(Route::new(method, path, handler));
    }

    /// Return the number of routes registered in this router.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use rttp::{Router, Response, StatusCode};
    ///
    /// let mut router = Router::new();
    /// assert_eq!(router.len(), 0);
    /// router.get("/a", |_ctx| async { Response::new(StatusCode::Ok) });
    /// assert_eq!(router.len(), 1);
    /// ```
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// Return `true` if no routes have been registered.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::Router;
    ///
    /// assert!(Router::new().is_empty());
    /// ```
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// Dispatch `request` to the first matching route and return its response.
    ///
    /// Routes are tested in registration order. The first route whose HTTP method and path
    /// pattern both match wins. If no route matches, a `404 Not Found` response is returned.
    ///
    /// # Arguments
    ///
    /// - `request` — The incoming HTTP request to dispatch.
    ///
    /// # Returns
    ///
    /// The [`Response`] produced by the matching handler, or a `404 Not Found` response
    /// when no route matches.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use rttp::{Router, Response, StatusCode};
    ///
    /// # async fn example(request: rttp::Request) {
    /// let mut router = Router::new();
    /// router.get("/ping", |_ctx| async { Response::new(StatusCode::Ok) });
    ///
    /// let response = router.route(request).await;
    /// assert_eq!(response.status(), StatusCode::Ok);
    /// # }
    /// ```
    pub async fn route(&self, request: Request) -> Response {
        let path = request.path();

        for route in &self.routes {
            if let Some(params) = route.matches(request.method(), path) {
                let ctx = Context::with_params(request, params);
                return (route.handler)(ctx).await;
            }
        }

        Response::new(StatusCode::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::request::Request;

    fn make_request(method: &str, path: &str) -> Request {
        let raw = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\n\r\n");
        let (req, _) = Request::parse(raw.as_bytes()).unwrap();
        req
    }

    // ── Pattern::parse ────────────────────────────────────────────────────────

    #[test]
    fn pattern_parse_root() {
        assert!(matches!(Pattern::parse("/"), Pattern::Exact(s) if s == "/"));
    }

    #[test]
    fn pattern_parse_exact() {
        assert!(matches!(Pattern::parse("/users"), Pattern::Exact(s) if s == "/users"));
    }

    #[test]
    fn pattern_parse_exact_nested() {
        assert!(matches!(
            Pattern::parse("/users/profile"),
            Pattern::Exact(s) if s == "/users/profile"
        ));
    }

    #[test]
    fn pattern_parse_trailing_slash_stripped() {
        // "/users/" should be normalized to "/users"
        assert!(matches!(Pattern::parse("/users/"), Pattern::Exact(s) if s == "/users"));
    }

    #[test]
    fn pattern_parse_parameterized_single() {
        let pat = Pattern::parse("/users/:id");
        match pat {
            Pattern::Parameterized { segments } => {
                assert_eq!(segments.len(), 2);
                assert!(matches!(&segments[0], Segment::Static(s) if s == "users"));
                assert!(matches!(&segments[1], Segment::Parameter(s) if s == "id"));
            }
            other => panic!("expected Parameterized, got {other:?}"),
        }
    }

    #[test]
    fn pattern_parse_parameterized_multi() {
        let pat = Pattern::parse("/users/:id/posts/:post_id");
        match pat {
            Pattern::Parameterized { segments } => {
                assert_eq!(segments.len(), 4);
                assert!(matches!(&segments[1], Segment::Parameter(s) if s == "id"));
                assert!(matches!(&segments[3], Segment::Parameter(s) if s == "post_id"));
            }
            other => panic!("expected Parameterized, got {other:?}"),
        }
    }

    #[test]
    fn pattern_parse_wildcard() {
        assert!(matches!(
            Pattern::parse("/files/*"),
            Pattern::Wildcard(s) if s == "/files"
        ));
    }

    // ── Pattern::matches ──────────────────────────────────────────────────────

    #[test]
    fn pattern_exact_match_hit() {
        let pat = Pattern::parse("/users");
        assert!(pat.matches("/users").is_some());
    }

    #[test]
    fn pattern_exact_match_miss() {
        let pat = Pattern::parse("/users");
        assert!(pat.matches("/posts").is_none());
    }

    #[test]
    fn pattern_exact_match_trailing_slash_normalized() {
        let pat = Pattern::parse("/users");
        assert!(pat.matches("/users/").is_some());
    }

    #[test]
    fn pattern_exact_match_root() {
        let pat = Pattern::parse("/");
        assert!(pat.matches("/").is_some());
        assert!(pat.matches("/other").is_none());
    }

    #[test]
    fn pattern_param_extracts_value() {
        let pat = Pattern::parse("/users/:id");
        let params = pat.matches("/users/42").unwrap();
        assert_eq!(params.get("id"), Some("42"));
    }

    #[test]
    fn pattern_param_multi_extracts_values() {
        let pat = Pattern::parse("/users/:id/posts/:post_id");
        let params = pat.matches("/users/7/posts/99").unwrap();
        assert_eq!(params.get("id"), Some("7"));
        assert_eq!(params.get("post_id"), Some("99"));
    }

    #[test]
    fn pattern_param_wrong_segment_count() {
        let pat = Pattern::parse("/users/:id");
        assert!(pat.matches("/users").is_none());
        assert!(pat.matches("/users/42/extra").is_none());
    }

    #[test]
    fn pattern_param_wrong_static_segment() {
        let pat = Pattern::parse("/users/:id");
        // "posts" != "users"
        assert!(pat.matches("/posts/42").is_none());
    }

    #[test]
    fn pattern_wildcard_match_hit() {
        let pat = Pattern::parse("/files/*");
        let params = pat.matches("/files/docs/readme.txt").unwrap();
        assert_eq!(params.get("wildcard"), Some("/docs/readme.txt"));
    }

    #[test]
    fn pattern_wildcard_match_miss() {
        let pat = Pattern::parse("/files/*");
        assert!(pat.matches("/other/readme.txt").is_none());
    }

    // ── Router ────────────────────────────────────────────────────────────────

    #[test]
    fn router_starts_empty() {
        let router = Router::new();
        assert!(router.is_empty());
        assert_eq!(router.len(), 0);
    }

    #[test]
    fn router_default_is_empty() {
        let router = Router::default();
        assert!(router.is_empty());
    }

    #[test]
    fn router_len_increments_on_add() {
        let mut router = Router::new();
        router.get("/a", |_ctx| async { Response::new(StatusCode::Ok) });
        router.post("/b", |_ctx| async { Response::new(StatusCode::Ok) });
        assert_eq!(router.len(), 2);
        assert!(!router.is_empty());
    }

    #[tokio::test]
    async fn router_empty_returns_404() {
        let router = Router::new();
        let res = router.route(make_request("GET", "/")).await;
        assert_eq!(res.status(), StatusCode::NotFound);
    }

    #[tokio::test]
    async fn router_get_matches() {
        let mut router = Router::new();
        router.get("/hello", |_ctx| async { Response::new(StatusCode::Ok) });
        let res = router.route(make_request("GET", "/hello")).await;
        assert_eq!(res.status(), StatusCode::Ok);
    }

    #[tokio::test]
    async fn router_get_does_not_match_post() {
        let mut router = Router::new();
        router.get("/hello", |_ctx| async { Response::new(StatusCode::Ok) });
        let res = router.route(make_request("POST", "/hello")).await;
        assert_eq!(res.status(), StatusCode::NotFound);
    }

    #[tokio::test]
    async fn router_post_matches() {
        let mut router = Router::new();
        router.post("/submit", |_ctx| async {
            Response::new(StatusCode::Created)
        });
        let res = router.route(make_request("POST", "/submit")).await;
        assert_eq!(res.status(), StatusCode::Created);
    }

    #[tokio::test]
    async fn router_unregistered_path_returns_404() {
        let mut router = Router::new();
        router.get("/hello", |_ctx| async { Response::new(StatusCode::Ok) });
        let res = router.route(make_request("GET", "/world")).await;
        assert_eq!(res.status(), StatusCode::NotFound);
    }

    #[tokio::test]
    async fn router_first_matching_route_wins() {
        let mut router = Router::new();
        router.get("/path", |_ctx| async { Response::new(StatusCode::Ok) });
        router.get("/path", |_ctx| async {
            Response::new(StatusCode::Accepted)
        });

        let res = router.route(make_request("GET", "/path")).await;
        assert_eq!(res.status(), StatusCode::Ok);
    }

    #[tokio::test]
    async fn router_parameterized_route_receives_params() {
        let mut router = Router::new();
        router.get("/users/:id", |ctx: Context| async move {
            let id = ctx.params().get("id").unwrap_or("").to_owned();
            Response::new(StatusCode::Ok).body(id)
        });
        let res = router.route(make_request("GET", "/users/42")).await;
        assert_eq!(res.status(), StatusCode::Ok);
    }

    #[tokio::test]
    async fn router_wildcard_route_matches() {
        let mut router = Router::new();
        router.get("/files/*", |_ctx| async { Response::new(StatusCode::Ok) });
        let res = router
            .route(make_request("GET", "/files/docs/readme.txt"))
            .await;
        assert_eq!(res.status(), StatusCode::Ok);
    }

    #[tokio::test]
    async fn router_method_variants_registered() {
        let mut router = Router::new();
        router.put("/r", |_ctx| async { Response::new(StatusCode::Ok) });
        router.delete("/r", |_ctx| async { Response::new(StatusCode::Ok) });
        router.patch("/r", |_ctx| async { Response::new(StatusCode::Ok) });
        router.options("/r", |_ctx| async { Response::new(StatusCode::Ok) });
        assert_eq!(router.len(), 4);
        assert_eq!(
            router.route(make_request("PUT", "/r")).await.status(),
            StatusCode::Ok
        );
        assert_eq!(
            router.route(make_request("DELETE", "/r")).await.status(),
            StatusCode::Ok
        );
        assert_eq!(
            router.route(make_request("PATCH", "/r")).await.status(),
            StatusCode::Ok
        );
        assert_eq!(
            router.route(make_request("OPTIONS", "/r")).await.status(),
            StatusCode::Ok
        );
    }
}
