//! Handler conversion traits for the router.
//!
//! [`IntoHandler`] abstracts over any async function that takes a [`Context`] and returns
//! something that implements [`IntoResponse`]. [`IntoRouteConfig`] extends this to also
//! accept tuples of `(Middleware..., Handler)` for per-route middleware.

use std::pin::Pin;
use std::sync::Arc;

use crate::Response;
use crate::context::Context;
use crate::extract::HandlerFn;
use crate::http::response::IntoResponse;
use crate::middleware::{Middleware, MiddlewareHandler, from_middleware, wrap_with_middlewares};

/// Conversion trait for async handler functions.
///
/// Any `Fn(Context) -> impl Future<Output = impl IntoResponse> + Send` that is also
/// `Send + Sync + 'static` implements this trait automatically via the blanket impl
/// below. Router methods accept `impl IntoHandler` so the two-type-parameter where-bound
/// does not need to be repeated at every call site.
pub trait IntoHandler: Send + Sync + 'static {
    /// Call the handler with the given context, boxing the returned future.
    fn call(&self, ctx: Context) -> Pin<Box<dyn Future<Output = Response> + Send>>;
}

impl<T, F, Res> IntoHandler for T
where
    T: Fn(Context) -> F + Send + Sync + 'static,
    F: Future<Output = Res> + Send + 'static,
    Res: IntoResponse,
{
    fn call(&self, ctx: Context) -> Pin<Box<dyn Future<Output = Response> + Send>> {
        let fut = self(ctx);
        Box::pin(async move { fut.await.into_response() })
    }
}

/// Converts a handler (optionally bundled with per-route middleware) into a
/// type-erased [`HandlerFn`].
///
/// Implemented for:
/// - Any bare [`IntoHandler`] — `handler`
/// - Tuples `(M, H)`, `(M1, M2, H)`, … `(M1..M5, H)` where leading elements
///   are [`Middleware`] and the final element is an [`IntoHandler`].
///
/// # Examples
///
/// ```rust,no_run
/// use rttp::{Router, Response, StatusCode};
/// use rttp::middleware::LoggerMiddleware;
///
/// let mut router = Router::new();
///
/// // bare handler — no per-route middleware
/// router.get("/health", |_ctx| async { Response::new(StatusCode::Ok) });
///
/// // one middleware + handler
/// router.get("/users", (LoggerMiddleware, |_ctx| async { Response::new(StatusCode::Ok) }));
/// ```
pub trait IntoRouteConfig: Send + Sync + 'static {
    /// Build the final type-erased handler, wrapping with any bundled middleware.
    fn into_route_fn(self) -> HandlerFn;
}

// Bare handler — delegates to the existing IntoHandler blanket impl.
impl<T: IntoHandler> IntoRouteConfig for T {
    fn into_route_fn(self) -> HandlerFn {
        Arc::new(move |ctx| self.call(ctx))
    }
}

// Macro: (M1, H), (M1, M2, H), … up to five middleware layers.
macro_rules! impl_into_route_config {
    ($($M:ident),+) => {
        #[allow(non_snake_case)]
        impl<$($M,)+ H> IntoRouteConfig for ($($M,)+ H)
        where
            $($M: Middleware + 'static,)+
            H: IntoHandler,
        {
            fn into_route_fn(self) -> HandlerFn {
                let ($($M,)+ h) = self;
                let base: HandlerFn = Arc::new(move |ctx| h.call(ctx));
                let middlewares: Vec<MiddlewareHandler> =
                    vec![$(from_middleware(Arc::new($M)),)+];
                wrap_with_middlewares(base, &middlewares)
            }
        }
    };
}

impl_into_route_config!(M1);
impl_into_route_config!(M1, M2);
impl_into_route_config!(M1, M2, M3);
impl_into_route_config!(M1, M2, M3, M4);
impl_into_route_config!(M1, M2, M3, M4, M5);
impl_into_route_config!(M1, M2, M3, M4, M5, M6);
impl_into_route_config!(M1, M2, M3, M4, M5, M6, M7);
impl_into_route_config!(M1, M2, M3, M4, M5, M6, M7, M8);
impl_into_route_config!(M1, M2, M3, M4, M5, M6, M7, M8, M9);
impl_into_route_config!(M1, M2, M3, M4, M5, M6, M7, M8, M9, M10);
impl_into_route_config!(M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11);
impl_into_route_config!(M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12);

/// Implement [`IntoRouteConfig`] for `(Vec<Arc<dyn Middleware>>, H)`.
///
/// Use this when the number of middleware layers is not known at compile time,
/// or when you want to build the middleware list dynamically:
///
/// ```rust,no_run
/// use std::sync::Arc;
/// use rttp::{Router, Response, StatusCode};
/// use rttp::middleware::{Middleware, LoggerMiddleware};
///
/// let mut router = Router::new();
/// let mws: Vec<Arc<dyn Middleware>> = vec![Arc::new(LoggerMiddleware)];
/// router.get("/users", (mws, |_ctx| async { Response::new(StatusCode::Ok) }));
/// ```
impl<H: IntoHandler> IntoRouteConfig for (Vec<Arc<dyn Middleware>>, H) {
    fn into_route_fn(self) -> HandlerFn {
        let (middlewares, h) = self;
        let base: HandlerFn = Arc::new(move |ctx| h.call(ctx));
        let handlers: Vec<MiddlewareHandler> = middlewares
            .into_iter()
            .map(|m| -> MiddlewareHandler { Arc::new(move |ctx, next| m.handle(ctx, next)) })
            .collect();
        wrap_with_middlewares(base, &handlers)
    }
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::context::Context;
    use crate::http::request::Request;
    use crate::middleware::{Middleware, Next};
    use crate::{Response, StatusCode};

    fn make_ctx() -> Context {
        let raw = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let (req, _) = Request::parse(raw).unwrap();
        Context::new(req)
    }

    struct PassThrough;

    impl Middleware for PassThrough {
        fn handle(
            &self,
            ctx: Context,
            next: Next,
        ) -> Pin<Box<dyn Future<Output = Response> + Send>> {
            Box::pin(async move { next.run(ctx).await })
        }
    }

    struct ShortCircuit;

    impl Middleware for ShortCircuit {
        fn handle(
            &self,
            _ctx: Context,
            _next: Next,
        ) -> Pin<Box<dyn Future<Output = Response> + Send>> {
            Box::pin(async move { Response::new(StatusCode::Unauthorized) })
        }
    }

    struct Marker {
        label: &'static str,
        log: Arc<Mutex<Vec<&'static str>>>,
    }

    impl Middleware for Marker {
        fn handle(
            &self,
            ctx: Context,
            next: Next,
        ) -> Pin<Box<dyn Future<Output = Response> + Send>> {
            let label = self.label;
            let log = Arc::clone(&self.log);
            Box::pin(async move {
                log.lock().unwrap().push(label);
                next.run(ctx).await
            })
        }
    }

    #[tokio::test]
    async fn test_into_handler_returns_response() {
        let handler = |_ctx: Context| async { Response::new(StatusCode::Ok) };
        let resp = IntoHandler::call(&handler, make_ctx()).await;
        assert_eq!(resp.status(), StatusCode::Ok);
    }

    #[tokio::test]
    async fn test_into_handler_str_into_response() {
        let handler = |_ctx: Context| async { "hello" };
        let resp = IntoHandler::call(&handler, make_ctx()).await;
        assert_eq!(resp.status(), StatusCode::Ok);
    }

    #[tokio::test]
    async fn test_into_handler_tuple_status_into_response() {
        let handler = |_ctx: Context| async { (StatusCode::Created, "created") };
        let resp = IntoHandler::call(&handler, make_ctx()).await;
        assert_eq!(resp.status(), StatusCode::Created);
    }

    #[tokio::test]
    async fn test_bare_handler_into_route_fn_calls_handler() {
        let handler_fn = (|_ctx: Context| async { Response::new(StatusCode::Ok) }).into_route_fn();
        let resp = handler_fn(make_ctx()).await;
        assert_eq!(resp.status(), StatusCode::Ok);
    }

    #[tokio::test]
    async fn test_bare_handler_into_route_fn_preserves_status() {
        let handler_fn =
            (|_ctx: Context| async { Response::new(StatusCode::NotFound) }).into_route_fn();
        let resp = handler_fn(make_ctx()).await;
        assert_eq!(resp.status(), StatusCode::NotFound);
    }

    #[tokio::test]
    async fn test_one_passthrough_middleware_calls_handler() {
        let handler_fn = (PassThrough, |_ctx: Context| async {
            Response::new(StatusCode::Ok)
        })
            .into_route_fn();
        let resp = handler_fn(make_ctx()).await;
        assert_eq!(resp.status(), StatusCode::Ok);
    }

    #[tokio::test]
    async fn test_one_short_circuit_middleware_skips_handler() {
        let handler_fn = (ShortCircuit, |_ctx: Context| async {
            Response::new(StatusCode::Ok)
        })
            .into_route_fn();
        let resp = handler_fn(make_ctx()).await;
        assert_eq!(resp.status(), StatusCode::Unauthorized);
    }

    #[tokio::test]
    async fn test_two_middleware_execute_in_order() {
        let log: Arc<Mutex<Vec<&'static str>>> = Arc::new(Mutex::new(Vec::new()));
        let m1 = Marker {
            label: "m1",
            log: Arc::clone(&log),
        };
        let m2 = Marker {
            label: "m2",
            log: Arc::clone(&log),
        };
        let handler_fn = (m1, m2, |_ctx: Context| async {
            Response::new(StatusCode::Ok)
        })
            .into_route_fn();
        handler_fn(make_ctx()).await;
        assert_eq!(*log.lock().unwrap(), vec!["m1", "m2"]);
    }

    #[tokio::test]
    async fn test_three_middleware_execute_in_order() {
        let log: Arc<Mutex<Vec<&'static str>>> = Arc::new(Mutex::new(Vec::new()));
        let m1 = Marker {
            label: "first",
            log: Arc::clone(&log),
        };
        let m2 = Marker {
            label: "second",
            log: Arc::clone(&log),
        };
        let m3 = Marker {
            label: "third",
            log: Arc::clone(&log),
        };
        let handler_fn = (m1, m2, m3, |_ctx: Context| async {
            Response::new(StatusCode::Ok)
        })
            .into_route_fn();
        handler_fn(make_ctx()).await;
        assert_eq!(*log.lock().unwrap(), vec!["first", "second", "third"]);
    }

    #[tokio::test]
    async fn test_tuple_short_circuit_stops_subsequent_middleware() {
        let log: Arc<Mutex<Vec<&'static str>>> = Arc::new(Mutex::new(Vec::new()));
        let m1 = Marker {
            label: "before",
            log: Arc::clone(&log),
        };
        let handler_fn = (m1, ShortCircuit, |_ctx: Context| async {
            Response::new(StatusCode::Ok)
        })
            .into_route_fn();
        let resp = handler_fn(make_ctx()).await;
        assert_eq!(resp.status(), StatusCode::Unauthorized);
        assert_eq!(*log.lock().unwrap(), vec!["before"]);
    }

    #[tokio::test]
    async fn test_vec_empty_middleware_calls_handler() {
        let mws: Vec<Arc<dyn Middleware>> = vec![];
        let handler_fn =
            (mws, |_ctx: Context| async { Response::new(StatusCode::Ok) }).into_route_fn();
        let resp = handler_fn(make_ctx()).await;
        assert_eq!(resp.status(), StatusCode::Ok);
    }

    #[tokio::test]
    async fn test_vec_one_passthrough_middleware_calls_handler() {
        let mws: Vec<Arc<dyn Middleware>> = vec![Arc::new(PassThrough)];
        let handler_fn =
            (mws, |_ctx: Context| async { Response::new(StatusCode::Ok) }).into_route_fn();
        let resp = handler_fn(make_ctx()).await;
        assert_eq!(resp.status(), StatusCode::Ok);
    }

    #[tokio::test]
    async fn test_vec_short_circuit_skips_handler() {
        let mws: Vec<Arc<dyn Middleware>> = vec![Arc::new(ShortCircuit)];
        let handler_fn =
            (mws, |_ctx: Context| async { Response::new(StatusCode::Ok) }).into_route_fn();
        let resp = handler_fn(make_ctx()).await;
        assert_eq!(resp.status(), StatusCode::Unauthorized);
    }

    #[tokio::test]
    async fn test_vec_middleware_executes_in_order() {
        let log: Arc<Mutex<Vec<&'static str>>> = Arc::new(Mutex::new(Vec::new()));
        let mws: Vec<Arc<dyn Middleware>> = vec![
            Arc::new(Marker {
                label: "a",
                log: Arc::clone(&log),
            }),
            Arc::new(Marker {
                label: "b",
                log: Arc::clone(&log),
            }),
            Arc::new(Marker {
                label: "c",
                log: Arc::clone(&log),
            }),
        ];
        let handler_fn =
            (mws, |_ctx: Context| async { Response::new(StatusCode::Ok) }).into_route_fn();
        handler_fn(make_ctx()).await;
        assert_eq!(*log.lock().unwrap(), vec!["a", "b", "c"]);
    }

    #[tokio::test]
    async fn test_vec_many_middleware_all_execute() {
        let log: Arc<Mutex<Vec<&'static str>>> = Arc::new(Mutex::new(Vec::new()));
        let labels: &[&'static str] = &["1", "2", "3", "4", "5", "6", "7", "8"];
        let mws: Vec<Arc<dyn Middleware>> = labels
            .iter()
            .map(|&label| -> Arc<dyn Middleware> {
                Arc::new(Marker {
                    label,
                    log: Arc::clone(&log),
                })
            })
            .collect();
        let handler_fn =
            (mws, |_ctx: Context| async { Response::new(StatusCode::Ok) }).into_route_fn();
        handler_fn(make_ctx()).await;
        assert_eq!(*log.lock().unwrap(), labels.to_vec());
    }

    #[tokio::test]
    async fn test_vec_short_circuit_stops_subsequent_middleware() {
        let log: Arc<Mutex<Vec<&'static str>>> = Arc::new(Mutex::new(Vec::new()));
        let mws: Vec<Arc<dyn Middleware>> = vec![
            Arc::new(Marker {
                label: "before",
                log: Arc::clone(&log),
            }),
            Arc::new(ShortCircuit),
            Arc::new(Marker {
                label: "after",
                log: Arc::clone(&log),
            }),
        ];
        let handler_fn =
            (mws, |_ctx: Context| async { Response::new(StatusCode::Ok) }).into_route_fn();
        let resp = handler_fn(make_ctx()).await;
        assert_eq!(resp.status(), StatusCode::Unauthorized);
        assert_eq!(*log.lock().unwrap(), vec!["before"]);
    }

    #[tokio::test]
    async fn test_vec_preserves_handler_response_status() {
        let mws: Vec<Arc<dyn Middleware>> = vec![Arc::new(PassThrough), Arc::new(PassThrough)];
        let handler_fn = (mws, |_ctx: Context| async {
            Response::new(StatusCode::Created)
        })
            .into_route_fn();
        let resp = handler_fn(make_ctx()).await;
        assert_eq!(resp.status(), StatusCode::Created);
    }
}
