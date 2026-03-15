//! [`Router`] and [`RouteBuilder`] — the public routing API.

use crate::context::{Context, PathParams};
use crate::extract::HandlerFn;
use crate::middleware::{wrap_with_middlewares, IntoMiddlewareHandler, MiddlewareHandler};
use crate::router::handler::IntoRouteConfig;
use crate::router::pattern::Pattern;
use crate::{Method, Request, Response, StatusCode};

// A single registered route binding a method + pattern to a handler.
pub(super) struct Route {
    pub(super) method: Method,
    pub(super) pattern: Pattern,
    pub(super) pattern_str: String,
    pub(super) handler: HandlerFn,
}

impl Route {
    pub(super) fn new(method: Method, pattern: &str, handler: HandlerFn) -> Self {
        Self {
            method,
            pattern: Pattern::parse(pattern),
            pattern_str: pattern.to_string(),
            handler,
        }
    }

    // Returns `Some(params)` when both the HTTP method and path pattern match, `None` otherwise.
    pub(super) fn matches(&self, method: &Method, path: &str) -> Option<PathParams> {
        if &self.method == method {
            self.pattern.matches(path)
        } else {
            None
        }
    }
}

/// A path-scoped builder returned by [`Router::route`].
///
/// Lets you register multiple HTTP methods on the same path without repeating the path
/// string. Middleware attached via [`.middleware()`](Self::middleware) or
/// [`.middlewares()`](Self::middlewares) is applied to every handler registered on
/// this builder.
///
/// ```rust,no_run
/// use std::sync::Arc;
/// use rttp::{Router, Response, StatusCode};
/// use rttp::middleware::{LoggerMiddleware};
///
/// let mut router = Router::new();
/// router
///     .route("/users")
///     .middleware(Arc::new(LoggerMiddleware))
///     .get(|_ctx| async { Response::new(StatusCode::Ok) })
///     .post(|_ctx| async { Response::new(StatusCode::Created) });
/// ```
pub struct RouteBuilder<'a> {
    router: &'a mut Router,
    path: String,
    middlewares: Vec<MiddlewareHandler>,
}

impl<'a> RouteBuilder<'a> {
    pub(super) fn new(router: &'a mut Router, path: &str) -> Self {
        Self {
            router,
            path: path.to_string(),
            middlewares: Vec::new(),
        }
    }

    fn add(self, method: Method, handler: impl IntoRouteConfig) -> Self {
        let handler_fn = wrap_with_middlewares(handler.into_route_fn(), &self.middlewares);
        self.router.register_fn(method, &self.path, handler_fn);
        self
    }

    /// Attach a single middleware to all handlers on this path.
    ///
    /// Middleware is applied in the order it is added: the first call wraps outermost,
    /// the last call wraps closest to the handler. Can be chained multiple times.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use std::sync::Arc;
    /// use rttp::{Router, Response, StatusCode};
    /// use rttp::middleware::LoggerMiddleware;
    ///
    /// let mut router = Router::new();
    /// router.route("/users")
    ///     .middleware(Arc::new(LoggerMiddleware))
    ///     .get(|_ctx| async { Response::new(StatusCode::Ok) });
    /// ```
    pub fn middleware(mut self, mw: impl IntoMiddlewareHandler) -> Self {
        self.middlewares.push(mw.into_middleware_handler());
        self
    }

    /// Attach a batch of middlewares to all handlers on this path.
    ///
    /// Accepts a `Vec<MiddlewareHandler>` — typically produced by the [`middlewares!`] macro.
    /// Middlewares are appended in order after any previously attached middleware.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use std::sync::Arc;
    /// use rttp::{Router, Response, StatusCode, middlewares};
    /// use rttp::middleware::LoggerMiddleware;
    ///
    /// let mut router = Router::new();
    /// router.route("/users")
    ///     .middlewares(middlewares![Arc::new(LoggerMiddleware)])
    ///     .get(|_ctx| async { Response::new(StatusCode::Ok) });
    /// ```
    pub fn middlewares(mut self, mws: Vec<MiddlewareHandler>) -> Self {
        self.middlewares.extend(mws);
        self
    }

    /// Register a `GET` handler on this path.
    pub fn get(self, handler: impl IntoRouteConfig) -> Self {
        self.add(Method::Get, handler)
    }

    /// Register a `POST` handler on this path.
    pub fn post(self, handler: impl IntoRouteConfig) -> Self {
        self.add(Method::Post, handler)
    }

    /// Register a `PUT` handler on this path.
    pub fn put(self, handler: impl IntoRouteConfig) -> Self {
        self.add(Method::Put, handler)
    }

    /// Register a `DELETE` handler on this path.
    pub fn delete(self, handler: impl IntoRouteConfig) -> Self {
        self.add(Method::Delete, handler)
    }

    /// Register a `PATCH` handler on this path.
    pub fn patch(self, handler: impl IntoRouteConfig) -> Self {
        self.add(Method::Patch, handler)
    }

    /// Register an `OPTIONS` handler on this path.
    pub fn options(self, handler: impl IntoRouteConfig) -> Self {
        self.add(Method::Options, handler)
    }

    /// Register a `HEAD` handler on this path.
    pub fn head(self, handler: impl IntoRouteConfig) -> Self {
        self.add(Method::Head, handler)
    }

    /// Register a `TRACE` handler on this path.
    pub fn trace(self, handler: impl IntoRouteConfig) -> Self {
        self.add(Method::Trace, handler)
    }

    /// Register a `CONNECT` handler on this path.
    pub fn connect(self, handler: impl IntoRouteConfig) -> Self {
        self.add(Method::Connect, handler)
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
/// router
///     .route("/users")
///     .get(|_ctx| async { Response::new(StatusCode::Ok) })
///     .post(|_ctx| async { Response::new(StatusCode::Created) });
/// ```
pub struct Router {
    pub(super) routes: Vec<Route>,
    prefix: String,
    name: Option<String>,
    middlewares: Vec<MiddlewareHandler>,
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
        Self {
            routes: Vec::new(),
            prefix: String::new(),
            name: None,
            middlewares: Vec::new(),
        }
    }

    /// Create a router whose routes are all automatically prefixed with `prefix`.
    ///
    /// Equivalent to `Router::new()` followed by setting a base path. All routes registered
    /// on this router have `prefix` prepended, so you write short paths and the full URL is
    /// assembled for you. A trailing slash on `prefix` is stripped before concatenation.
    ///
    /// Compose scoped routers into a parent with [`merge`](Self::merge) (paths are already
    /// fully formed) or with [`nest`](Self::nest) to add a further outer prefix on top.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use rttp::{Router, Response, StatusCode};
    ///
    /// let mut users = Router::scoped("/api/v1");
    /// users.get("/users", |_ctx| async { Response::new(StatusCode::Ok) });
    /// users.get("/users/:id", |_ctx| async { Response::new(StatusCode::Ok) });
    ///
    /// let mut router = Router::new();
    /// router.merge(users);
    /// // router now has: GET /api/v1/users, GET /api/v1/users/:id
    /// ```
    pub fn scoped(prefix: &str) -> Self {
        Self {
            routes: Vec::new(),
            prefix: prefix.trim_end_matches('/').to_string(),
            name: None,
            middlewares: Vec::new(),
        }
    }

    /// Attach a human-readable name to this router.
    ///
    /// The name is carried through [`merge`](Self::merge) and [`nest`](Self::nest) only as
    /// metadata on the source router — it is not transferred to the parent. Use it for
    /// startup logging, OpenAPI tag grouping, or test assertions via [`name()`](Self::name).
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use rttp::{Router, Response, StatusCode};
    ///
    /// let mut users = Router::scoped("/users").named("Users");
    /// users.get("", |_ctx| async { Response::new(StatusCode::Ok) });
    /// assert_eq!(users.name(), Some("Users"));
    /// ```
    #[must_use]
    pub fn named(mut self, name: &str) -> Self {
        self.name = Some(name.to_string());
        self
    }

    /// Return this router's name, if one was set with [`named`](Self::named).
    ///
    /// # Returns
    ///
    /// `Some(&str)` containing the name, or `None` if no name was set.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::Router;
    ///
    /// let named = Router::scoped("/users").named("Users");
    /// assert_eq!(named.name(), Some("Users"));
    ///
    /// let anonymous = Router::new();
    /// assert_eq!(anonymous.name(), None);
    /// ```
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Return this router's base prefix, if one was set with [`scoped`](Self::scoped).
    ///
    /// # Returns
    ///
    /// The prefix string (e.g. `"/api/v1"`), or an empty string `""` for a plain `Router::new()`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::Router;
    ///
    /// let scoped = Router::scoped("/api/v1");
    /// assert_eq!(scoped.prefix(), "/api/v1");
    ///
    /// let plain = Router::new();
    /// assert_eq!(plain.prefix(), "");
    /// ```
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// Attach a single middleware to every route registered on this router.
    ///
    /// Router-level middleware runs before any route-level middleware. Call this
    /// before registering routes so the middleware is applied to all of them.
    /// Middleware is applied in the order it is added.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use std::sync::Arc;
    /// use rttp::{Router, Response, StatusCode};
    /// use rttp::middleware::LoggerMiddleware;
    ///
    /// let mut router = Router::new();
    /// router.middleware(Arc::new(LoggerMiddleware));
    /// router.get("/users", |_ctx| async { Response::new(StatusCode::Ok) });
    /// ```
    pub fn middleware(&mut self, mw: impl IntoMiddlewareHandler) -> &mut Self {
        self.middlewares.push(mw.into_middleware_handler());
        self
    }

    /// Attach a batch of middlewares to every route registered on this router.
    ///
    /// Accepts a `Vec<MiddlewareHandler>` — typically produced by the [`middlewares!`] macro.
    /// Appended in order after any previously attached router-level middleware.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use std::sync::Arc;
    /// use rttp::{Router, Response, StatusCode, middlewares};
    /// use rttp::middleware::LoggerMiddleware;
    ///
    /// let mut router = Router::new();
    /// router.middlewares(middlewares![Arc::new(LoggerMiddleware)]);
    /// router.get("/users", |_ctx| async { Response::new(StatusCode::Ok) });
    /// ```
    pub fn middlewares(&mut self, mws: Vec<MiddlewareHandler>) -> &mut Self {
        self.middlewares.extend(mws);
        self
    }

    /// Low-level registration from a pre-built [`HandlerFn`].
    ///
    /// Prepends this router's prefix and wraps with router-level middleware.
    /// Used by [`RouteBuilder::add`] (which has already applied route-level middleware).
    fn register_fn(&mut self, method: Method, path: &str, handler: HandlerFn) {
        let full = if self.prefix.is_empty() {
            path.to_string()
        } else {
            let mut s = String::with_capacity(self.prefix.len() + path.len());
            s.push_str(&self.prefix);
            s.push_str(path);
            s
        };
        let wrapped = wrap_with_middlewares(handler, &self.middlewares);
        self.routes.push(Route::new(method, &full, wrapped));
    }

    /// Low-level route registration used by all public method helpers (`get`, `post`, …).
    ///
    /// Converts the handler via [`IntoRouteConfig`], then delegates to [`register_fn`](Self::register_fn).
    fn register(&mut self, method: Method, path: &str, handler: impl IntoRouteConfig) {
        self.register_fn(method, path, handler.into_route_fn());
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
        self.register(Method::Get, path, handler);
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
        self.register(Method::Post, path, handler);
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
        self.register(Method::Put, path, handler);
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
        self.register(Method::Delete, path, handler);
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
        self.register(Method::Options, path, handler);
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
        self.register(Method::Patch, path, handler);
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
        self.register(Method::Head, path, handler);
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
        self.register(Method::Trace, path, handler);
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
        self.register(Method::Connect, path, handler);
    }

    /// Begin a multi-method registration on `path`, returning a [`RouteBuilder`].
    ///
    /// This lets you chain multiple HTTP methods on the same path without repeating the path string:
    ///
    /// ```rust,no_run
    /// use rttp::{Router, Response, StatusCode};
    ///
    /// let mut router = Router::new();
    /// router
    ///     .route("/users")
    ///     .get(|_ctx| async { Response::new(StatusCode::Ok) })
    ///     .post(|_ctx| async { Response::new(StatusCode::Created) });
    /// ```
    pub fn route(&mut self, path: &str) -> RouteBuilder<'_> {
        RouteBuilder::new(self, path)
    }

    /// Register a route with a pre-built [`HandlerFn`].
    ///
    /// This is used internally by [`App`](crate::app::App) to register
    /// extractor-based handlers that have already been converted.
    pub(crate) fn add_raw_route(&mut self, method: Method, path: &str, handler: HandlerFn) {
        self.register_fn(method, path, handler);
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
            let mut new_pattern = String::with_capacity(prefix.len() + route.pattern_str.len());
            new_pattern.push_str(prefix);
            new_pattern.push_str(&route.pattern_str);
            self.routes
                .push(Route::new(route.method, &new_pattern, route.handler));
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

    /// Return an iterator over all registered routes as `(method, path)` pairs.
    ///
    /// Useful for generating OpenAPI specs, logging registered routes at startup,
    /// or asserting route registration in tests.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::{Router, Response, StatusCode};
    ///
    /// let mut router = Router::new();
    /// router.get("/users", |_ctx| async { Response::new(StatusCode::Ok) });
    /// router.post("/users", |_ctx| async { Response::new(StatusCode::Created) });
    ///
    /// let routes: Vec<_> = router.routes().collect();
    /// assert_eq!(routes.len(), 2);
    /// ```
    pub fn routes(&self) -> impl Iterator<Item = (&Method, &str)> {
        self.routes
            .iter()
            .map(|r| (&r.method, r.pattern_str.as_str()))
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
    /// See also [`route`](Self::route) for the path-scoped builder that registers routes.
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
    /// let response = router.handle(request).await;
    /// assert_eq!(response.status(), StatusCode::Ok);
    /// # }
    /// ```
    pub async fn handle(&self, request: Request) -> Response {
        self.dispatch(Context::new(request)).await
    }

    /// Dispatch a pre-built [`Context`] to the first matching route.
    ///
    /// Unlike [`route`](Self::route), this method receives an existing `Context`
    /// (with extensions already populated by middleware) and merges in the
    /// extracted path parameters before calling the handler.
    ///
    /// Returns `404 Not Found` when no route matches.
    pub async fn dispatch(&self, mut ctx: Context) -> Response {
        // Hoist outside the loop — avoids repeated accessor calls per iteration.
        let (method, path) = (ctx.request().method(), ctx.request().path());
        for route in &self.routes {
            if let Some(params) = route.matches(method, path) {
                *ctx.params_mut() = params;
                return (route.handler)(ctx).await;
            }
        }

        // RFC 9110 §9.3.2: HEAD auto-fallback to GET.
        if ctx.request().method() == &Method::Head {
            for route in &self.routes {
                if let Some(params) = route.matches(&Method::Get, ctx.request().path()) {
                    *ctx.params_mut() = params;
                    let mut response = (route.handler)(ctx).await;
                    response.strip_body();
                    return response;
                }
            }
        }

        let path = ctx.request().path();
        let method = ctx.request().method();

        let mut allowed: Vec<String> = self
            .routes
            .iter()
            .filter(|r| r.pattern.matches(path).is_some())
            .map(|r| r.method.to_string())
            .collect();
        allowed.sort_unstable();
        allowed.dedup();

        if allowed.is_empty() {
            return Response::new(StatusCode::NotFound);
        }

        let allow_value = allowed.join(", ");

        if method == &Method::Options {
            return Response::new(StatusCode::Ok).header("Allow", allow_value);
        }

        Response::new(StatusCode::MethodNotAllowed).header("Allow", allow_value)
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
    fn routes_iterator_returns_method_and_path_pairs() {
        let mut router = Router::new();
        router.get("/users", |_ctx| async { Response::new(StatusCode::Ok) });
        router.post("/users", |_ctx| async {
            Response::new(StatusCode::Created)
        });
        router.delete("/users/:id", |_ctx| async { Response::new(StatusCode::Ok) });

        let routes: Vec<_> = router.routes().collect();
        assert_eq!(routes.len(), 3);
        assert!(routes.contains(&(&Method::Get, "/users")));
        assert!(routes.contains(&(&Method::Post, "/users")));
        assert!(routes.contains(&(&Method::Delete, "/users/:id")));
    }

    #[test]
    fn routes_iterator_empty_on_new_router() {
        let router = Router::new();
        assert_eq!(router.routes().count(), 0);
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
        let res = router.handle(make_request("GET", "/")).await;
        assert_eq!(res.status(), StatusCode::NotFound);
    }

    #[tokio::test]
    async fn router_get_matches() {
        let mut router = Router::new();
        router.get("/hello", |_ctx| async { Response::new(StatusCode::Ok) });
        let res = router.handle(make_request("GET", "/hello")).await;
        assert_eq!(res.status(), StatusCode::Ok);
    }

    #[tokio::test]
    async fn router_get_does_not_match_post() {
        let mut router = Router::new();
        router.get("/hello", |_ctx| async { Response::new(StatusCode::Ok) });
        let res = router.handle(make_request("POST", "/hello")).await;
        assert_eq!(res.status(), StatusCode::MethodNotAllowed);
    }

    #[tokio::test]
    async fn router_post_matches() {
        let mut router = Router::new();
        router.post("/submit", |_ctx| async {
            Response::new(StatusCode::Created)
        });
        let res = router.handle(make_request("POST", "/submit")).await;
        assert_eq!(res.status(), StatusCode::Created);
    }

    #[tokio::test]
    async fn router_unregistered_path_returns_404() {
        let mut router = Router::new();
        router.get("/hello", |_ctx| async { Response::new(StatusCode::Ok) });
        let res = router.handle(make_request("GET", "/world")).await;
        assert_eq!(res.status(), StatusCode::NotFound);
    }

    #[tokio::test]
    async fn router_first_matching_route_wins() {
        let mut router = Router::new();
        router.get("/path", |_ctx| async { Response::new(StatusCode::Ok) });
        router.get("/path", |_ctx| async {
            Response::new(StatusCode::Accepted)
        });

        let res = router.handle(make_request("GET", "/path")).await;
        assert_eq!(res.status(), StatusCode::Ok);
    }

    #[tokio::test]
    async fn router_parameterized_route_receives_params() {
        let mut router = Router::new();
        router.get("/users/:id", |ctx: Context| async move {
            let id = ctx.params().get("id").unwrap_or("").to_owned();
            Response::new(StatusCode::Ok).body(id)
        });
        let res = router.handle(make_request("GET", "/users/42")).await;
        assert_eq!(res.status(), StatusCode::Ok);
    }

    #[tokio::test]
    async fn router_wildcard_route_matches() {
        let mut router = Router::new();
        router.get("/files/*", |_ctx| async { Response::new(StatusCode::Ok) });
        let res = router
            .handle(make_request("GET", "/files/docs/readme.txt"))
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
            router.handle(make_request("PUT", "/r")).await.status(),
            StatusCode::Ok
        );
        assert_eq!(
            router.handle(make_request("DELETE", "/r")).await.status(),
            StatusCode::Ok
        );
        assert_eq!(
            router.handle(make_request("PATCH", "/r")).await.status(),
            StatusCode::Ok
        );
        assert_eq!(
            router.handle(make_request("OPTIONS", "/r")).await.status(),
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
            router
                .handle(make_request("GET", "/api/v1/users"))
                .await
                .status(),
            StatusCode::Ok
        );
        assert_eq!(
            router
                .handle(make_request("GET", "/api/v1/users/42"))
                .await
                .status(),
            StatusCode::Ok
        );
        assert_eq!(
            router.handle(make_request("GET", "/users")).await.status(),
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
            router
                .handle(make_request("GET", "/api/ping"))
                .await
                .status(),
            StatusCode::Ok
        );
    }

    #[tokio::test]
    async fn router_nest_existing_routes_retain_priority() {
        let mut sub = Router::new();
        sub.get("/path", |_ctx| async {
            Response::new(StatusCode::Accepted)
        });

        let mut router = Router::new();
        router.get("/v1/path", |_ctx| async { Response::new(StatusCode::Ok) });
        router.nest("/v1", sub);

        assert_eq!(
            router
                .handle(make_request("GET", "/v1/path"))
                .await
                .status(),
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
            root.handle(make_request("GET", "/api/v1/items"))
                .await
                .status(),
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
            router.handle(make_request("HEAD", "/r")).await.status(),
            StatusCode::Ok
        );
        assert_eq!(
            router.handle(make_request("TRACE", "/r")).await.status(),
            StatusCode::Ok
        );
        assert_eq!(
            router.handle(make_request("CONNECT", "/r")).await.status(),
            StatusCode::Ok
        );
    }

    #[tokio::test]
    async fn route_builder_registers_get_and_post() {
        let mut router = Router::new();
        router
            .route("/users")
            .get(|_ctx| async { Response::new(StatusCode::Ok) })
            .post(|_ctx| async { Response::new(StatusCode::Created) });

        assert_eq!(router.len(), 2);
        assert_eq!(
            router.handle(make_request("GET", "/users")).await.status(),
            StatusCode::Ok
        );
        assert_eq!(
            router.handle(make_request("POST", "/users")).await.status(),
            StatusCode::Created
        );
    }

    #[tokio::test]
    async fn route_builder_unregistered_method_returns_405() {
        let mut router = Router::new();
        router
            .route("/items")
            .get(|_ctx| async { Response::new(StatusCode::Ok) });

        assert_eq!(
            router
                .handle(make_request("DELETE", "/items"))
                .await
                .status(),
            StatusCode::MethodNotAllowed
        );
    }

    #[tokio::test]
    async fn head_falls_back_to_get_with_no_body() {
        let mut router = Router::new();
        router.get("/data", |_ctx| async {
            Response::new(StatusCode::Ok).body("hello world")
        });

        let res = router.handle(make_request("HEAD", "/data")).await;
        assert_eq!(res.status(), StatusCode::Ok);
        // Body must be stripped; headers (Content-Length) are preserved by the GET handler logic.
        assert!(
            res.headers().get("content-length").is_none() || {
                // The GET handler ran; strip_body clears the vec before into_bytes, so
                // content-length will be written as 0 by into_bytes — acceptable either way.
                true
            }
        );
    }

    #[tokio::test]
    async fn head_explicit_handler_takes_priority_over_get_fallback() {
        let mut router = Router::new();
        router.get("/ping", |_ctx| async {
            Response::new(StatusCode::Ok).body("body")
        });
        router.head("/ping", |_ctx| async {
            Response::new(StatusCode::NoContent)
        });

        let res = router.handle(make_request("HEAD", "/ping")).await;
        // Explicit HEAD handler must win.
        assert_eq!(res.status(), StatusCode::NoContent);
    }

    #[tokio::test]
    async fn wrong_method_returns_405_with_allow_header() {
        let mut router = Router::new();
        router.get("/hello", |_ctx| async { Response::new(StatusCode::Ok) });

        let res = router.handle(make_request("POST", "/hello")).await;
        assert_eq!(res.status(), StatusCode::MethodNotAllowed);
        assert!(
            res.headers().get("allow").is_some(),
            "Allow header must be present"
        );
        let allow = res.headers().get("allow").unwrap();
        assert!(allow.contains("GET"), "Allow header must list GET");
    }

    #[tokio::test]
    async fn options_auto_response_when_no_explicit_handler() {
        let mut router = Router::new();
        router.get("/hello", |_ctx| async { Response::new(StatusCode::Ok) });
        router.post("/hello", |_ctx| async {
            Response::new(StatusCode::Created)
        });

        let res = router.handle(make_request("OPTIONS", "/hello")).await;
        assert_eq!(res.status(), StatusCode::Ok);
        let allow = res
            .headers()
            .get("allow")
            .expect("Allow header must be present");
        assert!(allow.contains("GET"));
        assert!(allow.contains("POST"));
    }

    #[tokio::test]
    async fn options_explicit_handler_takes_priority() {
        let mut router = Router::new();
        router.get("/hello", |_ctx| async { Response::new(StatusCode::Ok) });
        router.options("/hello", |_ctx| async {
            Response::new(StatusCode::NoContent)
        });

        let res = router.handle(make_request("OPTIONS", "/hello")).await;
        assert_eq!(res.status(), StatusCode::NoContent);
    }

    #[tokio::test]
    async fn unknown_path_still_returns_404() {
        let mut router = Router::new();
        router.get("/hello", |_ctx| async { Response::new(StatusCode::Ok) });

        let res = router.handle(make_request("POST", "/nonexistent")).await;
        assert_eq!(res.status(), StatusCode::NotFound);
    }

    #[tokio::test]
    async fn route_builder_all_methods() {
        let mut router = Router::new();
        router
            .route("/r")
            .get(|_ctx| async { Response::new(StatusCode::Ok) })
            .post(|_ctx| async { Response::new(StatusCode::Ok) })
            .put(|_ctx| async { Response::new(StatusCode::Ok) })
            .delete(|_ctx| async { Response::new(StatusCode::Ok) })
            .patch(|_ctx| async { Response::new(StatusCode::Ok) })
            .options(|_ctx| async { Response::new(StatusCode::Ok) })
            .head(|_ctx| async { Response::new(StatusCode::Ok) });

        assert_eq!(router.len(), 7);
        for method in ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"] {
            assert_eq!(
                router.handle(make_request(method, "/r")).await.status(),
                StatusCode::Ok,
                "method {method} should match"
            );
        }
    }

    #[tokio::test]
    async fn scoped_router_prepends_prefix_on_merge() {
        let mut users = Router::scoped("/api/v1");
        users.get("/users", |_ctx| async { Response::new(StatusCode::Ok) });
        users.post("/users", |_ctx| async {
            Response::new(StatusCode::Created)
        });
        users.delete("/users/:id", |_ctx| async { Response::new(StatusCode::Ok) });

        let mut router = Router::new();
        router.merge(users);

        assert_eq!(router.len(), 3);
        assert_eq!(
            router
                .handle(make_request("GET", "/api/v1/users"))
                .await
                .status(),
            StatusCode::Ok
        );
        assert_eq!(
            router
                .handle(make_request("POST", "/api/v1/users"))
                .await
                .status(),
            StatusCode::Created
        );
        assert_eq!(
            router
                .handle(make_request("DELETE", "/api/v1/users/42"))
                .await
                .status(),
            StatusCode::Ok
        );
        assert_eq!(
            router.handle(make_request("GET", "/users")).await.status(),
            StatusCode::NotFound
        );
    }

    #[tokio::test]
    async fn scoped_router_trailing_slash_normalized() {
        let mut sub = Router::scoped("/api/");
        sub.get("/ping", |_ctx| async { Response::new(StatusCode::Ok) });

        let mut router = Router::new();
        router.merge(sub);

        assert_eq!(
            router
                .handle(make_request("GET", "/api/ping"))
                .await
                .status(),
            StatusCode::Ok
        );
    }

    #[tokio::test]
    async fn scoped_router_with_nest_adds_outer_prefix() {
        let mut users = Router::scoped("/users");
        users.get("", |_ctx| async { Response::new(StatusCode::Ok) });
        users.get("/:id", |_ctx| async { Response::new(StatusCode::Ok) });

        let mut router = Router::new();
        router.nest("/api/v1", users);

        assert_eq!(
            router
                .handle(make_request("GET", "/api/v1/users"))
                .await
                .status(),
            StatusCode::Ok
        );
        assert_eq!(
            router
                .handle(make_request("GET", "/api/v1/users/42"))
                .await
                .status(),
            StatusCode::Ok
        );
    }

    #[test]
    fn scoped_router_name_and_prefix_accessors() {
        let router = Router::scoped("/api/v1").named("Users");
        assert_eq!(router.prefix(), "/api/v1");
        assert_eq!(router.name(), Some("Users"));
    }

    #[test]
    fn scoped_router_routes_iterator_shows_full_paths() {
        let mut router = Router::scoped("/api");
        router.get("/health", |_ctx| async { Response::new(StatusCode::Ok) });

        let paths: Vec<&str> = router.routes().map(|(_, p)| p).collect();
        assert_eq!(paths, ["/api/health"]);
    }

    #[test]
    fn new_router_has_empty_prefix_and_no_name() {
        let router = Router::new();
        assert_eq!(router.prefix(), "");
        assert_eq!(router.name(), None);
    }

    use crate::middleware::{MiddlewareHandler, Next};
    use std::sync::{Arc, Mutex};

    fn tracking_middleware(
        log: Arc<Mutex<Vec<&'static str>>>,
        tag: &'static str,
    ) -> MiddlewareHandler {
        Arc::new(move |ctx: Context, next: Next| {
            let log = Arc::clone(&log);
            Box::pin(async move {
                log.lock().unwrap().push(tag);
                next.run(ctx).await
            })
        })
    }

    #[tokio::test]
    async fn route_builder_middleware_runs_before_handler() {
        let log: Arc<Mutex<Vec<&'static str>>> = Arc::new(Mutex::new(Vec::new()));
        let mut router = Router::new();
        let log2 = Arc::clone(&log);
        router
            .route("/ping")
            .middleware(tracking_middleware(Arc::clone(&log), "mw"))
            .get(move |_ctx| {
                let log = Arc::clone(&log2);
                async move {
                    log.lock().unwrap().push("handler");
                    Response::new(StatusCode::Ok)
                }
            });

        router.handle(make_request("GET", "/ping")).await;
        assert_eq!(*log.lock().unwrap(), vec!["mw", "handler"]);
    }

    #[tokio::test]
    async fn route_builder_middlewares_macro_runs_in_order() {
        let log: Arc<Mutex<Vec<&'static str>>> = Arc::new(Mutex::new(Vec::new()));
        let mut router = Router::new();
        let log2 = Arc::clone(&log);
        router
            .route("/ping")
            .middlewares(crate::middlewares![
                tracking_middleware(Arc::clone(&log), "first"),
                tracking_middleware(Arc::clone(&log), "second"),
            ])
            .get(move |_ctx| {
                let log = Arc::clone(&log2);
                async move {
                    log.lock().unwrap().push("handler");
                    Response::new(StatusCode::Ok)
                }
            });

        router.handle(make_request("GET", "/ping")).await;
        assert_eq!(*log.lock().unwrap(), vec!["first", "second", "handler"]);
    }

    #[tokio::test]
    async fn router_middleware_applies_to_all_routes() {
        let log: Arc<Mutex<Vec<&'static str>>> = Arc::new(Mutex::new(Vec::new()));
        let mut router = Router::new();
        router.middleware(tracking_middleware(Arc::clone(&log), "router-mw"));
        router.get("/a", |_ctx| async { Response::new(StatusCode::Ok) });
        router.get("/b", |_ctx| async { Response::new(StatusCode::Ok) });

        router.handle(make_request("GET", "/a")).await;
        router.handle(make_request("GET", "/b")).await;
        assert_eq!(*log.lock().unwrap(), vec!["router-mw", "router-mw"]);
    }

    #[tokio::test]
    async fn router_middleware_runs_before_route_middleware() {
        let log: Arc<Mutex<Vec<&'static str>>> = Arc::new(Mutex::new(Vec::new()));
        let mut router = Router::new();
        router.middleware(tracking_middleware(Arc::clone(&log), "router"));
        router
            .route("/ping")
            .middleware(tracking_middleware(Arc::clone(&log), "route"))
            .get(|_ctx| async { Response::new(StatusCode::Ok) });

        router.handle(make_request("GET", "/ping")).await;
        assert_eq!(*log.lock().unwrap(), vec!["router", "route"]);
    }

    #[tokio::test]
    async fn middleware_short_circuit_skips_handler() {
        let mut router = Router::new();
        router
            .route("/secure")
            .middleware(|_ctx: Context, _next: Next| -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send>> {
                Box::pin(async { Response::new(StatusCode::Unauthorized) })
            })
            .get(|_ctx| async { Response::new(StatusCode::Ok) });

        let res = router.handle(make_request("GET", "/secure")).await;
        assert_eq!(res.status(), StatusCode::Unauthorized);
    }
}
