//! Application builder — unified API for routes, middleware, and shared state.
//!
//! [`App`] ties together routing, middleware, and state injection into a single
//! builder that can be passed directly to [`Server::run`](crate::server::Server::run).
//!
//! # Examples
//!
//! ```rust,no_run
//! use rttp::app::App;
//! use rttp::extract::{Path, Json, State};
//! use rttp::middleware::LoggerMiddleware;
//! use rttp::{Response, StatusCode};
//! use std::sync::Arc;
//!
//! #[derive(Clone)]
//! struct AppState { db_url: String }
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let state = Arc::new(AppState { db_url: "postgres://...".into() });
//!
//!     let app = App::new()
//!         .state(state)
//!         .middleware(LoggerMiddleware)
//!         .get("/", || async { "Hello, World!" })
//!         .get("/users/:id", |Path(id): Path<i64>| async move {
//!             format!("User #{id}")
//!         })
//!         .group("/api", |group| {
//!             group
//!                 .get("/health", || async { "ok" })
//!                 .get("/version", || async { "1.0.0" })
//!         });
//!
//!     let server = rttp::server::Server::bind("127.0.0.1:8080").await?;
//!     server.run(app.into_service()).await?;
//!     Ok(())
//! }
//! ```

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::context::{Context, Extensions};
use crate::extract::{Handler, HandlerFn};
use crate::middleware::{
    Middleware, MiddlewareHandler, Next, from_middleware, wrap_with_middlewares,
};
use crate::router::Router;
use crate::{Method, Request, Response};

/// A closure that installs shared state into a request's [`Extensions`].
type StateInstaller = Arc<dyn Fn(&mut Extensions) + Send + Sync>;

/// Application builder — the primary API for configuring an rttp server.
///
/// Combines routing, middleware, and shared state into a single fluent builder.
/// Call [`into_service`](Self::into_service) to produce a handler compatible
/// with [`Server::run`](crate::server::Server::run).
pub struct App {
    router: Router,
    middlewares: Vec<MiddlewareHandler>,
    state_installers: Vec<StateInstaller>,
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    /// Create a new, empty application.
    pub fn new() -> Self {
        Self {
            router: Router::new(),
            middlewares: Vec::new(),
            state_installers: Vec::new(),
        }
    }

    /// Register shared state that will be cloned into every request's extensions.
    ///
    /// The value must be `Clone + Send + Sync + 'static`. For expensive types,
    /// wrap in [`Arc`] for cheap cloning.
    ///
    /// Retrieve the state in handlers via the [`State<T>`](crate::extract::State)
    /// extractor.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use rttp::app::App;
    /// use std::sync::Arc;
    ///
    /// #[derive(Clone)]
    /// struct Config { port: u16 }
    ///
    /// let app = App::new().state(Arc::new(Config { port: 8080 }));
    /// ```
    #[must_use]
    pub fn state<T: Clone + Send + Sync + 'static>(mut self, value: T) -> Self {
        self.state_installers
            .push(Arc::new(move |ext: &mut Extensions| {
                ext.insert(value.clone());
            }));
        self
    }

    /// Add a middleware to the application pipeline.
    ///
    /// Middleware is executed in registration order (first registered = outermost).
    /// All middleware runs before route dispatch.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use rttp::app::App;
    /// use rttp::middleware::LoggerMiddleware;
    ///
    /// let app = App::new().middleware(LoggerMiddleware);
    /// ```
    #[must_use]
    pub fn middleware<M: Middleware + 'static>(mut self, mw: M) -> Self {
        self.middlewares.push(from_middleware(Arc::new(mw)));
        self
    }

    /// Register a `GET` route with extractor-based handler.
    #[must_use]
    pub fn get<H, T>(mut self, path: &str, handler: H) -> Self
    where
        H: Handler<T>,
        T: 'static,
    {
        self.router
            .add_raw_route(Method::Get, path, handler.into_handler_fn());
        self
    }

    /// Register a `POST` route with extractor-based handler.
    #[must_use]
    pub fn post<H, T>(mut self, path: &str, handler: H) -> Self
    where
        H: Handler<T>,
        T: 'static,
    {
        self.router
            .add_raw_route(Method::Post, path, handler.into_handler_fn());
        self
    }

    /// Register a `PUT` route with extractor-based handler.
    #[must_use]
    pub fn put<H, T>(mut self, path: &str, handler: H) -> Self
    where
        H: Handler<T>,
        T: 'static,
    {
        self.router
            .add_raw_route(Method::Put, path, handler.into_handler_fn());
        self
    }

    /// Register a `DELETE` route with extractor-based handler.
    #[must_use]
    pub fn delete<H, T>(mut self, path: &str, handler: H) -> Self
    where
        H: Handler<T>,
        T: 'static,
    {
        self.router
            .add_raw_route(Method::Delete, path, handler.into_handler_fn());
        self
    }

    /// Register a `PATCH` route with extractor-based handler.
    #[must_use]
    pub fn patch<H, T>(mut self, path: &str, handler: H) -> Self
    where
        H: Handler<T>,
        T: 'static,
    {
        self.router
            .add_raw_route(Method::Patch, path, handler.into_handler_fn());
        self
    }

    /// Register an `OPTIONS` route with extractor-based handler.
    #[must_use]
    pub fn options<H, T>(mut self, path: &str, handler: H) -> Self
    where
        H: Handler<T>,
        T: 'static,
    {
        self.router
            .add_raw_route(Method::Options, path, handler.into_handler_fn());
        self
    }

    /// Register a route for any HTTP method with extractor-based handler.
    #[must_use]
    pub fn route<H, T>(mut self, method: Method, path: &str, handler: H) -> Self
    where
        H: Handler<T>,
        T: 'static,
    {
        self.router
            .add_raw_route(method, path, handler.into_handler_fn());
        self
    }

    /// Add a group of routes under a shared path prefix.
    ///
    /// Routes registered inside the closure are prefixed with the given path.
    /// Groups can be nested and can carry their own middleware that runs only
    /// for routes within that group.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use rttp::app::App;
    /// use rttp::StatusCode;
    ///
    /// let app = App::new()
    ///     .group("/api/v1", |g| {
    ///         g.get("/users", || async { "users list" })
    ///          .get("/posts", || async { "posts list" })
    ///     });
    /// // Registers: GET /api/v1/users, GET /api/v1/posts
    /// ```
    #[must_use]
    pub fn group(self, prefix: &str, f: impl FnOnce(RouteGroup) -> RouteGroup) -> Self {
        let group = f(RouteGroup::new(prefix));
        group.merge_into(self)
    }

    /// Merge a standalone [`Router`] into this application.
    ///
    /// All routes registered on `router` are appended to the application's
    /// routing table in registration order. This is the primary way to split
    /// route definitions across modules — each module builds and returns its
    /// own [`Router`], and the top-level `App` merges them together.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use rttp::app::App;
    /// use rttp::Router;
    ///
    /// fn user_routes() -> Router {
    ///     let mut r = Router::new();
    ///     r.get("/users", |_ctx| async { "users" });
    ///     r
    /// }
    ///
    /// let app = App::new()
    ///     .get("/health", || async { "ok" })
    ///     .merge(user_routes());
    /// ```
    #[must_use]
    pub fn merge(mut self, router: Router) -> Self {
        self.router.merge(router);
        self
    }

    /// Convert this application into a request handler compatible with
    /// [`Server::run`](crate::server::Server::run).
    ///
    /// The returned closure handles:
    /// 1. Injecting shared state into each request's extensions.
    /// 2. Running the middleware pipeline.
    /// 3. Dispatching to the matched route handler.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use rttp::app::App;
    /// use rttp::server::Server;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let app = App::new().get("/", || async { "hello" });
    /// let server = Server::bind("127.0.0.1:8080").await?;
    /// server.run(app.into_service()).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn into_service(
        self,
    ) -> impl Fn(Request) -> Pin<Box<dyn Future<Output = Response> + Send>> + Send + Sync + 'static
    {
        let router = Arc::new(self.router);
        let middlewares = Arc::new(self.middlewares);
        let state_installers = Arc::new(self.state_installers);

        move |req: Request| {
            let router = Arc::clone(&router);
            let middlewares = Arc::clone(&middlewares);
            let state_installers = Arc::clone(&state_installers);

            Box::pin(async move {
                let mut ctx = Context::new(req);

                for installer in state_installers.iter() {
                    installer(ctx.extensions_mut());
                }

                let router_handler: MiddlewareHandler =
                    Arc::new(move |ctx: Context, _next: Next| {
                        let router = Arc::clone(&router);
                        Box::pin(async move { router.dispatch(ctx).await })
                            as Pin<Box<dyn Future<Output = Response> + Send>>
                    });

                let mut chain: Vec<MiddlewareHandler> = middlewares.as_ref().clone();
                chain.push(router_handler);

                let next = Next::new(chain);
                next.run(ctx).await
            }) as Pin<Box<dyn Future<Output = Response> + Send>>
        }
    }
}

/// A route group — collects routes under a shared path prefix.
///
/// Created by [`App::group`]. Routes are registered with the same API as
/// [`App`], but each path is automatically prefixed. Groups can carry their
/// own middleware stack (applied only to routes in the group) and can be
/// nested arbitrarily deep.
///
/// # Examples
///
/// ```rust,no_run
/// use rttp::app::App;
/// use rttp::middleware::LoggerMiddleware;
///
/// let app = App::new()
///     .group("/api", |g| {
///         g.middleware(LoggerMiddleware)          // only for /api/* routes
///          .get("/health", || async { "ok" })
///          .group("/v1", |inner| {                // nested: /api/v1/*
///              inner.get("/users", || async { "users" })
///          })
///     });
/// ```
pub struct RouteGroup {
    prefix: String,
    routes: Vec<(Method, String, HandlerFn)>,
    middlewares: Vec<MiddlewareHandler>,
}

impl RouteGroup {
    fn new(prefix: &str) -> Self {
        let prefix = prefix.trim_end_matches('/').to_string();
        Self {
            prefix,
            routes: Vec::new(),
            middlewares: Vec::new(),
        }
    }

    /// Add middleware that runs only for routes within this group.
    ///
    /// Middleware is applied in registration order (first registered = outermost).
    /// Group middleware wraps around any nested sub-group middleware.
    #[must_use]
    pub fn middleware<M: Middleware + 'static>(mut self, mw: M) -> Self {
        self.middlewares.push(from_middleware(Arc::new(mw)));
        self
    }

    /// Nest a sub-group under an additional path prefix.
    ///
    /// The sub-group's routes are resolved relative to this group's prefix.
    /// The outer group's middleware wraps the inner group's middleware.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use rttp::app::App;
    ///
    /// let app = App::new()
    ///     .group("/api", |g| {
    ///         g.group("/v1", |inner| inner.get("/ping", || async { "pong" }))
    ///     });
    /// // Registers: GET /api/v1/ping
    /// ```
    #[must_use]
    pub fn group(mut self, sub_prefix: &str, f: impl FnOnce(RouteGroup) -> RouteGroup) -> Self {
        let child_prefix = format!("{}{}", self.prefix, sub_prefix.trim_end_matches('/'));
        let inner = f(RouteGroup::new(&child_prefix));

        let combined: Vec<MiddlewareHandler> = self
            .middlewares
            .iter()
            .cloned()
            .chain(inner.middlewares)
            .collect();

        for (method, path, handler) in inner.routes {
            let handler = wrap_with_middlewares(handler, &combined);
            self.routes.push((method, path, handler));
        }
        self
    }

    /// Register a `GET` route within this group.
    #[must_use]
    pub fn get<H, T>(mut self, path: &str, handler: H) -> Self
    where
        H: Handler<T>,
        T: 'static,
    {
        let full = format!("{}{}", self.prefix, path);
        self.routes
            .push((Method::Get, full, handler.into_handler_fn()));
        self
    }

    /// Register a `POST` route within this group.
    #[must_use]
    pub fn post<H, T>(mut self, path: &str, handler: H) -> Self
    where
        H: Handler<T>,
        T: 'static,
    {
        let full = format!("{}{}", self.prefix, path);
        self.routes
            .push((Method::Post, full, handler.into_handler_fn()));
        self
    }

    /// Register a `PUT` route within this group.
    #[must_use]
    pub fn put<H, T>(mut self, path: &str, handler: H) -> Self
    where
        H: Handler<T>,
        T: 'static,
    {
        let full = format!("{}{}", self.prefix, path);
        self.routes
            .push((Method::Put, full, handler.into_handler_fn()));
        self
    }

    /// Register a `DELETE` route within this group.
    #[must_use]
    pub fn delete<H, T>(mut self, path: &str, handler: H) -> Self
    where
        H: Handler<T>,
        T: 'static,
    {
        let full = format!("{}{}", self.prefix, path);
        self.routes
            .push((Method::Delete, full, handler.into_handler_fn()));
        self
    }

    /// Register a `PATCH` route within this group.
    #[must_use]
    pub fn patch<H, T>(mut self, path: &str, handler: H) -> Self
    where
        H: Handler<T>,
        T: 'static,
    {
        let full = format!("{}{}", self.prefix, path);
        self.routes
            .push((Method::Patch, full, handler.into_handler_fn()));
        self
    }

    fn merge_into(self, mut app: App) -> App {
        // Routes already carry their full path (prefix was applied at registration).
        for (method, path, handler) in self.routes {
            let handler = wrap_with_middlewares(handler, &self.middlewares);
            app.router.add_raw_route(method, &path, handler);
        }
        app
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StatusCode;
    use crate::extract::{Json, Path};
    use crate::http::request::Request;

    fn make_request(method: &str, path: &str) -> Request {
        let raw = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\n\r\n");
        let (req, _) = Request::parse(raw.as_bytes()).unwrap();
        req
    }

    fn make_request_with_body(method: &str, path: &str, body: &str) -> Request {
        let raw = format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let (req, _) = Request::parse(raw.as_bytes()).unwrap();
        req
    }

    #[tokio::test]
    async fn app_simple_get() {
        let app = App::new().get("/", || async { "hello" });
        let service = app.into_service();
        let resp = service(make_request("GET", "/")).await;
        assert_eq!(resp.status(), StatusCode::Ok);
    }

    #[tokio::test]
    async fn app_with_path_extractor() {
        let app = App::new().get("/users/:id", |Path(id): Path<i64>| async move {
            format!("User #{id}")
        });
        let service = app.into_service();
        let resp = service(make_request("GET", "/users/42")).await;
        assert_eq!(resp.status(), StatusCode::Ok);
    }

    #[tokio::test]
    async fn app_with_json_extractor() {
        #[derive(serde::Deserialize)]
        struct Body {
            name: String,
        }
        let app = App::new().post("/users", |Json(body): Json<Body>| async move {
            (StatusCode::Created, format!("Created {}", body.name))
        });
        let service = app.into_service();
        let resp = service(make_request_with_body(
            "POST",
            "/users",
            r#"{"name":"Alice"}"#,
        ))
        .await;
        assert_eq!(resp.status(), StatusCode::Created);
    }

    #[tokio::test]
    async fn app_with_state() {
        use crate::extract::State;

        #[derive(Clone)]
        struct Config {
            name: String,
        }

        let app = App::new()
            .state(Arc::new(Config {
                name: "test".into(),
            }))
            .get("/", |State(cfg): State<Arc<Config>>| async move {
                format!("App: {}", cfg.name)
            });
        let service = app.into_service();
        let resp = service(make_request("GET", "/")).await;
        assert_eq!(resp.status(), StatusCode::Ok);
    }

    #[tokio::test]
    async fn app_404_on_unmatched() {
        let app = App::new().get("/exists", || async { "ok" });
        let service = app.into_service();
        let resp = service(make_request("GET", "/not-here")).await;
        assert_eq!(resp.status(), StatusCode::NotFound);
    }

    #[tokio::test]
    async fn app_group_prefixes_routes() {
        let app = App::new().group("/api", |g| {
            g.get("/health", || async { "ok" })
                .get("/version", || async { "1.0" })
        });
        let service = app.into_service();

        let resp = service(make_request("GET", "/api/health")).await;
        assert_eq!(resp.status(), StatusCode::Ok);

        let resp = service(make_request("GET", "/api/version")).await;
        assert_eq!(resp.status(), StatusCode::Ok);

        // Without prefix should 404
        let resp = service(make_request("GET", "/health")).await;
        assert_eq!(resp.status(), StatusCode::NotFound);
    }

    #[tokio::test]
    async fn app_with_context_handler() {
        let app = App::new().get("/", |ctx: Context| async move {
            format!("Path: {}", ctx.request().path())
        });
        let service = app.into_service();
        let resp = service(make_request("GET", "/")).await;
        assert_eq!(resp.status(), StatusCode::Ok);
    }

    #[tokio::test]
    async fn app_middleware_runs() {
        use crate::middleware::Middleware;
        use std::pin::Pin;

        struct AddHeader;

        impl Middleware for AddHeader {
            fn handle(
                &self,
                ctx: Context,
                next: Next,
            ) -> Pin<Box<dyn Future<Output = Response> + Send>> {
                Box::pin(async move {
                    let mut resp = next.run(ctx).await;
                    resp.add_header("X-Test", "present");
                    resp
                })
            }
        }

        let app = App::new()
            .middleware(AddHeader)
            .get("/", || async { "hello" });
        let service = app.into_service();
        let resp = service(make_request("GET", "/")).await;
        assert_eq!(resp.status(), StatusCode::Ok);
        assert_eq!(resp.headers().get("x-test"), Some("present"));
    }

    #[tokio::test]
    async fn app_merge_router() {
        use crate::Router;

        let mut extra = Router::new();
        extra.get("/extra", |_ctx| async { Response::new(StatusCode::Ok) });

        let app = App::new().get("/base", || async { "base" }).merge(extra);
        let service = app.into_service();

        assert_eq!(
            service(make_request("GET", "/base")).await.status(),
            StatusCode::Ok
        );
        assert_eq!(
            service(make_request("GET", "/extra")).await.status(),
            StatusCode::Ok
        );
        // Routes not in either router still 404.
        assert_eq!(
            service(make_request("GET", "/nope")).await.status(),
            StatusCode::NotFound
        );
    }

    #[tokio::test]
    async fn group_per_group_middleware() {
        use crate::middleware::Middleware;
        use std::pin::Pin;

        struct TagHeader;

        impl Middleware for TagHeader {
            fn handle(
                &self,
                ctx: Context,
                next: Next,
            ) -> Pin<Box<dyn Future<Output = Response> + Send>> {
                Box::pin(async move {
                    let mut resp = next.run(ctx).await;
                    resp.add_header("X-Group", "api");
                    resp
                })
            }
        }

        let app = App::new()
            .group("/api", |g| {
                g.middleware(TagHeader).get("/ping", || async { "pong" })
            })
            .get("/health", || async { "ok" });
        let service = app.into_service();

        let resp = service(make_request("GET", "/api/ping")).await;
        assert_eq!(resp.status(), StatusCode::Ok);
        assert_eq!(resp.headers().get("x-group"), Some("api"));

        let resp = service(make_request("GET", "/health")).await;
        assert_eq!(resp.status(), StatusCode::Ok);
        assert_eq!(resp.headers().get("x-group"), None);
    }

    #[tokio::test]
    async fn nested_group_resolves_full_path() {
        let app = App::new().group("/api", |g| {
            g.group("/v1", |inner| inner.get("/users", || async { "users" }))
        });
        let service = app.into_service();

        assert_eq!(
            service(make_request("GET", "/api/v1/users")).await.status(),
            StatusCode::Ok
        );
        // Partial paths must 404.
        assert_eq!(
            service(make_request("GET", "/api/users")).await.status(),
            StatusCode::NotFound
        );
        assert_eq!(
            service(make_request("GET", "/v1/users")).await.status(),
            StatusCode::NotFound
        );
    }

    #[tokio::test]
    async fn app_multiple_methods() {
        let app = App::new()
            .get("/r", || async { "get" })
            .post("/r", || async { "post" })
            .put("/r", || async { "put" })
            .delete("/r", || async { "delete" })
            .patch("/r", || async { "patch" });
        let service = app.into_service();

        assert_eq!(
            service(make_request("GET", "/r")).await.status(),
            StatusCode::Ok
        );
        assert_eq!(
            service(make_request("POST", "/r")).await.status(),
            StatusCode::Ok
        );
        assert_eq!(
            service(make_request("PUT", "/r")).await.status(),
            StatusCode::Ok
        );
        assert_eq!(
            service(make_request("DELETE", "/r")).await.status(),
            StatusCode::Ok
        );
        assert_eq!(
            service(make_request("PATCH", "/r")).await.status(),
            StatusCode::Ok
        );
    }
}
