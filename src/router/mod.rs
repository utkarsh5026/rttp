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

pub mod handler;
pub mod pattern;

pub use handler::{IntoHandler, IntoRouteConfig};

use crate::context::{Context, PathParams};
use crate::extract::HandlerFn;
use crate::{Method, Request, Response, StatusCode};

use pattern::Pattern;

// A single registered route binding a method + pattern to a handler.
struct Route {
    method: Method,
    pattern: Pattern,
    pattern_str: String,
    handler: HandlerFn,
}

impl Route {
    fn new(method: Method, pattern: &str, handler: HandlerFn) -> Self {
        Self {
            method,
            pattern: Pattern::parse(pattern),
            pattern_str: pattern.to_string(),
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
/// router.get("/users/:id", |ctx: rttp::context::Context| async move {
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
    pub fn get(&mut self, path: &str, handler: impl IntoRouteConfig) {
        self.routes
            .push(Route::new(Method::Get, path, handler.into_route_fn()));
    }

    /// Register a handler for `POST` requests matching `path`.
    ///
    /// # Arguments
    ///
    /// - `path` — URL pattern string (e.g. `"/users"`, `"/users/:id"`, or `"/files/*"`).
    /// - `handler` — Handler or `(middleware, …, handler)` tuple.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use rttp::{Router, Response, StatusCode};
    ///
    /// let mut router = Router::new();
    /// router.post("/users", |_ctx| async { Response::new(StatusCode::Created) });
    /// ```
    pub fn post(&mut self, path: &str, handler: impl IntoRouteConfig) {
        self.routes
            .push(Route::new(Method::Post, path, handler.into_route_fn()));
    }

    /// Register a handler for `PUT` requests matching `path`.
    ///
    /// # Arguments
    ///
    /// - `path` — URL pattern string (e.g. `"/users/:id"`).
    /// - `handler` — Handler or `(middleware, …, handler)` tuple.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use rttp::{Router, Response, StatusCode};
    ///
    /// let mut router = Router::new();
    /// router.put("/users/:id", |_ctx| async { Response::new(StatusCode::Ok) });
    /// ```
    pub fn put(&mut self, path: &str, handler: impl IntoRouteConfig) {
        self.routes
            .push(Route::new(Method::Put, path, handler.into_route_fn()));
    }

    /// Register a handler for `DELETE` requests matching `path`.
    ///
    /// # Arguments
    ///
    /// - `path` — URL pattern string (e.g. `"/users/:id"`).
    /// - `handler` — Handler or `(middleware, …, handler)` tuple.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use rttp::{Router, Response, StatusCode};
    ///
    /// let mut router = Router::new();
    /// router.delete("/users/:id", |_ctx| async { Response::new(StatusCode::Ok) });
    /// ```
    pub fn delete(&mut self, path: &str, handler: impl IntoRouteConfig) {
        self.routes
            .push(Route::new(Method::Delete, path, handler.into_route_fn()));
    }

    /// Register a handler for `OPTIONS` requests matching `path`.
    ///
    /// # Arguments
    ///
    /// - `path` — URL pattern string.
    /// - `handler` — Handler or `(middleware, …, handler)` tuple.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use rttp::{Router, Response, StatusCode};
    ///
    /// let mut router = Router::new();
    /// router.options("/users", |_ctx| async { Response::new(StatusCode::Ok) });
    /// ```
    pub fn options(&mut self, path: &str, handler: impl IntoRouteConfig) {
        self.routes
            .push(Route::new(Method::Options, path, handler.into_route_fn()));
    }

    /// Register a handler for `PATCH` requests matching `path`.
    ///
    /// # Arguments
    ///
    /// - `path` — URL pattern string (e.g. `"/users/:id"`).
    /// - `handler` — Handler or `(middleware, …, handler)` tuple.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use rttp::{Router, Response, StatusCode};
    ///
    /// let mut router = Router::new();
    /// router.patch("/users/:id", |_ctx| async { Response::new(StatusCode::Ok) });
    /// ```
    pub fn patch(&mut self, path: &str, handler: impl IntoRouteConfig) {
        self.routes
            .push(Route::new(Method::Patch, path, handler.into_route_fn()));
    }

    /// Register a handler for `HEAD` requests matching `path`.
    ///
    /// `HEAD` is identical to `GET` but the server must not send a response body.
    /// Ensure your handler returns a [`Response`] with no body set.
    ///
    /// # Arguments
    ///
    /// - `path` — URL pattern string (e.g. `"/users/:id"`).
    /// - `handler` — Handler or `(middleware, …, handler)` tuple.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use rttp::{Router, Response, StatusCode};
    ///
    /// let mut router = Router::new();
    /// router.head("/users/:id", |_ctx| async { Response::new(StatusCode::Ok) });
    /// ```
    pub fn head(&mut self, path: &str, handler: impl IntoRouteConfig) {
        self.routes
            .push(Route::new(Method::Head, path, handler.into_route_fn()));
    }

    /// Register a handler for `TRACE` requests matching `path`.
    ///
    /// # Arguments
    ///
    /// - `path` — URL pattern string.
    /// - `handler` — Handler or `(middleware, …, handler)` tuple.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use rttp::{Router, Response, StatusCode};
    ///
    /// let mut router = Router::new();
    /// router.trace("/echo", |_ctx| async { Response::new(StatusCode::Ok) });
    /// ```
    pub fn trace(&mut self, path: &str, handler: impl IntoRouteConfig) {
        self.routes
            .push(Route::new(Method::Trace, path, handler.into_route_fn()));
    }

    /// Register a handler for `CONNECT` requests matching `path`.
    ///
    /// # Arguments
    ///
    /// - `path` — URL pattern string.
    /// - `handler` — Handler or `(middleware, …, handler)` tuple.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use rttp::{Router, Response, StatusCode};
    ///
    /// let mut router = Router::new();
    /// router.connect("/tunnel", |_ctx| async { Response::new(StatusCode::Ok) });
    /// ```
    pub fn connect(&mut self, path: &str, handler: impl IntoRouteConfig) {
        self.routes
            .push(Route::new(Method::Connect, path, handler.into_route_fn()));
    }

    /// Register a route with a pre-built [`HandlerFn`].
    ///
    /// This is used internally by [`App`](crate::app::App) to register
    /// extractor-based handlers that have already been converted.
    pub(crate) fn add_raw_route(&mut self, method: Method, path: &str, handler: HandlerFn) {
        self.routes.push(Route::new(method, path, handler));
    }

    /// Merge all routes from `other` into this router.
    ///
    /// Routes from `other` are appended after this router's existing routes,
    /// so existing routes retain priority on conflict. Paths are taken as-is —
    /// no prefix transformation is applied.
    ///
    /// This is the primary mechanism for splitting route definitions across
    /// modules and composing them at startup.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use rttp::{Router, Response, StatusCode};
    ///
    /// fn user_routes() -> Router {
    ///     let mut r = Router::new();
    ///     r.get("/users", |_ctx| async { Response::new(StatusCode::Ok) });
    ///     r
    /// }
    ///
    /// let mut router = Router::new();
    /// router.get("/health", |_ctx| async { Response::new(StatusCode::Ok) });
    /// router.merge(user_routes());
    /// // router now has: GET /health, GET /users
    /// ```
    pub fn merge(&mut self, other: Router) {
        self.routes.extend(other.routes);
    }

    /// Mount all routes from `other` under `prefix`, prepending it to every pattern.
    ///
    /// Unlike [`merge`](Self::merge), `nest` rewrites each child route's path by prepending
    /// `prefix`, so a child route registered as `"/users"` becomes `"/api/users"` when nested
    /// under `"/api"`. A trailing slash on `prefix` is stripped before concatenation.
    ///
    /// Routes from `other` are appended after this router's existing routes, so existing
    /// routes retain priority on conflict.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use rttp::{Router, Response, StatusCode};
    ///
    /// fn user_routes() -> Router {
    ///     let mut r = Router::new();
    ///     r.get("/users", |_ctx| async { Response::new(StatusCode::Ok) });
    ///     r.get("/users/:id", |_ctx| async { Response::new(StatusCode::Ok) });
    ///     r
    /// }
    ///
    /// let mut router = Router::new();
    /// router.nest("/api/v1", user_routes());
    /// // router now has: GET /api/v1/users, GET /api/v1/users/:id
    /// ```
    pub fn nest(&mut self, prefix: &str, other: Router) {
        let prefix = prefix.trim_end_matches('/');
        for route in other.routes {
            let new_pattern = format!("{}{}", prefix, route.pattern_str);
            self.routes.push(Route::new(route.method, &new_pattern, route.handler));
        }
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

    /// Dispatch a pre-built [`Context`] to the first matching route.
    ///
    /// Unlike [`route`](Self::route), this method receives an existing `Context`
    /// (with extensions already populated by middleware) and merges in the
    /// extracted path parameters before calling the handler.
    ///
    /// Returns `404 Not Found` when no route matches.
    pub async fn dispatch(&self, mut ctx: Context) -> Response {
        let path = ctx.request().path().to_owned();
        let method = ctx.request().method().clone();

        for route in &self.routes {
            if let Some(params) = route.matches(&method, &path) {
                *ctx.params_mut() = params;
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

    #[tokio::test]
    async fn router_nest_prepends_prefix() {
        let mut sub = Router::new();
        sub.get("/users", |_ctx| async { Response::new(StatusCode::Ok) });
        sub.get("/users/:id", |_ctx| async { Response::new(StatusCode::Ok) });

        let mut router = Router::new();
        router.nest("/api/v1", sub);

        assert_eq!(router.len(), 2);
        assert_eq!(
            router.route(make_request("GET", "/api/v1/users")).await.status(),
            StatusCode::Ok
        );
        assert_eq!(
            router.route(make_request("GET", "/api/v1/users/42")).await.status(),
            StatusCode::Ok
        );
        assert_eq!(
            router.route(make_request("GET", "/users")).await.status(),
            StatusCode::NotFound
        );
    }

    #[tokio::test]
    async fn router_nest_trailing_slash_on_prefix_normalized() {
        let mut sub = Router::new();
        sub.get("/ping", |_ctx| async { Response::new(StatusCode::Ok) });

        let mut router = Router::new();
        router.nest("/api/", sub);

        assert_eq!(
            router.route(make_request("GET", "/api/ping")).await.status(),
            StatusCode::Ok
        );
    }

    #[tokio::test]
    async fn router_nest_existing_routes_retain_priority() {
        let mut sub = Router::new();
        sub.get("/path", |_ctx| async { Response::new(StatusCode::Accepted) });

        let mut router = Router::new();
        router.get("/v1/path", |_ctx| async { Response::new(StatusCode::Ok) });
        router.nest("/v1", sub);

        assert_eq!(
            router.route(make_request("GET", "/v1/path")).await.status(),
            StatusCode::Ok
        );
    }

    #[tokio::test]
    async fn router_nest_deep_nesting() {
        let mut inner = Router::new();
        inner.get("/items", |_ctx| async { Response::new(StatusCode::Ok) });

        let mut mid = Router::new();
        mid.nest("/v1", inner);

        let mut root = Router::new();
        root.nest("/api", mid);

        assert_eq!(
            root.route(make_request("GET", "/api/v1/items")).await.status(),
            StatusCode::Ok
        );
    }

    #[tokio::test]
    async fn router_head_trace_connect_registered() {
        let mut router = Router::new();
        router.head("/r", |_ctx| async { Response::new(StatusCode::Ok) });
        router.trace("/r", |_ctx| async { Response::new(StatusCode::Ok) });
        router.connect("/r", |_ctx| async { Response::new(StatusCode::Ok) });
        assert_eq!(
            router.route(make_request("HEAD", "/r")).await.status(),
            StatusCode::Ok
        );
        assert_eq!(
            router.route(make_request("TRACE", "/r")).await.status(),
            StatusCode::Ok
        );
        assert_eq!(
            router.route(make_request("CONNECT", "/r")).await.status(),
            StatusCode::Ok
        );
    }
}
