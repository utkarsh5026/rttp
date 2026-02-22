//! Middleware pipeline — composable before/after request handler logic.
//!
//! This module defines the core types for building an ordered middleware stack.
//! Each middleware wraps the next layer, enabling request inspection, short-circuit
//! responses, and response decoration without coupling handlers to infrastructure
//! concerns.
//!
//! ## Core types
//!
//! - [`Middleware`] — trait implemented by all middleware.
//! - [`Next`] — cursor into the remaining middleware chain; call [`Next::run`] to
//!   advance to the next layer.
//! - [`MiddlewareHandler`] — type-erased, cheaply-cloneable middleware function.
//! - [`from_middleware`] — converts a [`Middleware`] trait object into a
//!   [`MiddlewareHandler`].
//! - [`LoggerMiddleware`] — built-in request/response logger.
//!
//! ## Planned Features
//!
//! - Ordered middleware stack execution
//! - Request transformation (header injection, body modification)
//! - Response transformation (compression, caching headers)
//! - Short-circuit responses (auth checks, rate limiting)
//! - Async-first middleware trait

use std::{future::Future, pin::Pin, sync::Arc};
use tokio::time::Instant;

use crate::{Response, context::Context};

/// A cursor into the remaining middleware chain for a single request.
///
/// `Next` is passed to each middleware's [`Middleware::handle`] implementation.
/// Calling [`Next::run`] advances the cursor by one position and invokes the next
/// middleware (or returns a fallback `500` response when the chain is exhausted
/// without any middleware generating a response).
///
/// `Next` is consumed on each call to [`run`](Self::run), so it cannot be called
/// more than once per middleware invocation.
///
/// # Examples
///
/// ```rust,no_run
/// use std::pin::Pin;
/// use rttp::{Response, context::Context, middleware::{Middleware, Next}};
///
/// struct PassThrough;
///
/// impl Middleware for PassThrough {
///     fn handle(
///         &self,
///         ctx: Context,
///         next: Next,
///     ) -> Pin<Box<dyn std::future::Future<Output = Response> + Send>> {
///         Box::pin(async move { next.run(ctx).await })
///     }
/// }
/// ```
pub struct Next {
    middlewares: Vec<MiddlewareHandler>,
    // Tracks which middleware to invoke on the next `run` call.
    index: usize,
}

/// A type-erased, reference-counted middleware function.
///
/// Every entry in the middleware stack is stored as a `MiddlewareHandler`.
/// The [`Arc`] wrapper makes handlers cheap to clone so that [`Next`] can
/// advance through the chain without copying closures.
///
/// Construct one with [`from_middleware`] or by wrapping a closure directly:
///
/// ```rust,no_run
/// use std::{pin::Pin, sync::Arc};
/// use rttp::{Response, context::Context, middleware::{MiddlewareHandler, Next}};
///
/// let handler: MiddlewareHandler = Arc::new(|ctx: Context, next: Next| {
///     Box::pin(async move { next.run(ctx).await })
/// });
/// ```
pub type MiddlewareHandler = Arc<
    dyn Fn(Context, Next) -> Pin<Box<dyn Future<Output = Response> + Send>> + Send + Sync + 'static,
>;

/// Converts a [`Middleware`] implementation into a [`MiddlewareHandler`].
///
/// # Arguments
///
/// - `middleware` — a reference-counted [`Middleware`] to wrap.
///
/// # Examples
///
/// ```rust,no_run
/// use std::sync::Arc;
/// use rttp::middleware::{LoggerMiddleware, from_middleware};
///
/// let handler = from_middleware(Arc::new(LoggerMiddleware));
/// ```
pub fn from_middleware<M>(middleware: Arc<M>) -> MiddlewareHandler
where
    M: Middleware + 'static,
{
    Arc::new(move |ctx: Context, next: Next| middleware.handle(ctx, next))
}

impl Next {
    /// Creates a new `Next` positioned at the start of the given middleware stack.
    ///
    /// # Arguments
    ///
    /// - `middlewares` — the ordered list of handlers that make up the pipeline.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use rttp::middleware::Next;
    ///
    /// let next = Next::new(vec![]);
    /// ```
    pub fn new(middlewares: Vec<MiddlewareHandler>) -> Self {
        Self {
            middlewares,
            index: 0,
        }
    }

    /// Invokes the next middleware in the chain and returns its response.
    ///
    /// Advances the internal cursor by one, clones the handler at the current
    /// position, and awaits it. If no handler remains (i.e. the chain is
    /// exhausted without producing a response), a `500 Internal Server Error`
    /// response is returned as a safe fallback.
    ///
    /// # Arguments
    ///
    /// - `ctx` — the per-request [`Context`] to pass to the next middleware.
    ///
    /// # Returns
    ///
    /// The [`Response`] produced by the next middleware or handler in the chain.
    pub async fn run(mut self, ctx: Context) -> Response {
        if self.index < self.middlewares.len() {
            let handler = self.middlewares[self.index].clone();
            self.index += 1;
            handler(ctx, self).await
        } else {
            Response::new(crate::StatusCode::InternalServerError)
                .body("No response generated by middleware pipeline")
        }
    }
}

/// The core trait for all rttp middleware.
///
/// Implementors receive a [`Context`] and a [`Next`] cursor. They may:
///
/// - **Pass through** — call `next.run(ctx).await` without modification.
/// - **Short-circuit** — return a [`Response`] directly without calling `next`.
/// - **Decorate** — call `next.run(ctx).await`, inspect the response, and return
///   a modified copy.
///
/// # Contract
///
/// - Implementations **must** be `Send + Sync` because middleware is shared across
///   Tokio tasks.
/// - `handle` **must** return a pinned, `Send` future so it can be awaited across
///   `.await` points in multi-threaded runtimes.
/// - Implementations **should not** hold `&mut` references to shared state across
///   an `.await` point.
pub trait Middleware: Send + Sync {
    /// Handle the request and optionally delegate to the next middleware.
    ///
    /// # Arguments
    ///
    /// - `ctx` — the per-request [`Context`] carrying the HTTP method, headers,
    ///   path, path parameters, and extensions.
    /// - `next` — cursor into the remainder of the middleware chain; call
    ///   [`Next::run`] to forward the request.
    ///
    /// # Returns
    ///
    /// A [`Response`] — either produced by this middleware directly (short-circuit)
    /// or forwarded from a downstream handler.
    fn handle(&self, ctx: Context, next: Next) -> Pin<Box<dyn Future<Output = Response> + Send>>;
}

/// Built-in middleware that logs each request's method, path, status, and duration.
///
/// Emits a single `tracing::info!` line after the downstream handler completes,
/// in the format:
///
/// ```text
/// METHOD /path - STATUS (duration)
/// ```
///
/// `LoggerMiddleware` does not short-circuit; it always delegates to the next
/// middleware and decorates the response timing after the fact.
///
/// # Examples
///
/// ```rust,no_run
/// use std::sync::Arc;
/// use rttp::middleware::{LoggerMiddleware, from_middleware};
///
/// let handler = from_middleware(Arc::new(LoggerMiddleware));
/// ```
pub struct LoggerMiddleware;

impl Middleware for LoggerMiddleware {
    /// Log the request method, path, response status, and elapsed time.
    ///
    /// Captures the start time before delegating to the next middleware, then
    /// emits a `tracing::info!` record once the response is available.
    ///
    /// # Arguments
    ///
    /// - `ctx` — the per-request [`Context`]; method and path are extracted
    ///   before `next` consumes it.
    /// - `next` — the remainder of the middleware chain.
    ///
    /// # Returns
    ///
    /// The unmodified [`Response`] returned by the downstream handler.
    fn handle(&self, ctx: Context, next: Next) -> Pin<Box<dyn Future<Output = Response> + Send>> {
        Box::pin(async move {
            let start = Instant::now();
            let method = ctx.request().method().as_str().to_string();
            let path = ctx.request().path().to_string();

            let response = next.run(ctx).await;

            let duration = start.elapsed();
            let status = response.status().as_u16();

            tracing::info!("{} {} - {} ({:?})", method, path, status, duration);

            response
        })
    }
}
