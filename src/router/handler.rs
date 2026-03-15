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
            .map(|m| -> MiddlewareHandler {
                Arc::new(move |ctx, next| m.handle(ctx, next))
            })
            .collect();
        wrap_with_middlewares(base, &handlers)
    }
}
