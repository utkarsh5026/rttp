//! Request ID / correlation ID middleware.
//!
//! Assigns every incoming request a UUID v4 correlation ID and echoes it back
//! on the response as `X-Request-ID`. The ID is also recorded on the active
//! [`tracing`] span so all log lines emitted during the request are
//! automatically tagged.
//!
//! # Behaviour
//!
//! | Incoming `X-Request-ID`      | `trust_incoming` | ID used                 |
//! |------------------------------|------------------|-------------------------|
//! | Absent                       | any              | freshly generated UUID  |
//! | Present and valid UUID       | `true`           | client-supplied value   |
//! | Present and valid UUID       | `false`          | freshly generated UUID  |
//! | Present but **not** a UUID   | any              | freshly generated UUID  |
//!
//! Rejecting non-UUID values prevents header-injection attacks where a
//! malicious client supplies a value that could pollute log aggregators.
//!
//! # Examples
//!
//! ```rust,no_run
//! use rttp::security::middleware::request_id::RequestIdMiddleware;
//!
//! // Trust a UUID supplied by an upstream gateway (default).
//! let mw = RequestIdMiddleware::new();
//!
//! // Always generate a fresh ID, ignoring the client header.
//! let mw = RequestIdMiddleware::new().distrust_incoming();
//! ```

use std::{future::Future, pin::Pin};

use tracing::Instrument as _;
use uuid::Uuid;

use crate::{
    Response,
    context::Context,
    middleware::{Middleware, Next},
};

// ── Middleware ────────────────────────────────────────────────────────────────

/// Middleware that assigns a UUID v4 correlation ID to every request.
///
/// See the [module-level docs](self) for the full behavior table.
pub struct RequestIdMiddleware {
    trust_incoming: bool,
}

impl Default for RequestIdMiddleware {
    fn default() -> Self {
        Self::new()
    }
}

impl RequestIdMiddleware {
    /// Creates a new `RequestIdMiddleware` that **trusts** a valid UUID supplied
    /// by the client in `X-Request-ID`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::security::middleware::request_id::RequestIdMiddleware;
    ///
    /// let mw = RequestIdMiddleware::new();
    /// ```
    pub fn new() -> Self {
        Self {
            trust_incoming: true,
        }
    }

    /// Configures the middleware to **ignore** the incoming `X-Request-ID` header
    /// and always generate a fresh UUID.
    ///
    /// Useful at the public edge of your service where you do not want external
    /// callers to influence internal trace IDs.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::security::middleware::request_id::RequestIdMiddleware;
    ///
    /// let mw = RequestIdMiddleware::new().distrust_incoming();
    /// ```
    #[must_use]
    pub fn distrust_incoming(mut self) -> Self {
        self.trust_incoming = false;
        self
    }
}

impl Middleware for RequestIdMiddleware {
    /// Resolves the correlation ID, instruments the downstream span, and appends
    /// `X-Request-ID` to the response.
    fn handle(&self, ctx: Context, next: Next) -> Pin<Box<dyn Future<Output = Response> + Send>> {
        let trust_incoming = self.trust_incoming;

        let create_uuid = || Uuid::new_v4().to_string();

        Box::pin(async move {
            let request_id = if trust_incoming {
                ctx.request()
                    .headers()
                    .get("x-request-id")
                    .filter(|v| Uuid::parse_str(v).is_ok())
                    .map(str::to_owned)
                    .unwrap_or_else(create_uuid)
            } else {
                create_uuid()
            };

            let span = tracing::info_span!("request", request_id = %request_id);

            let mut resp = next.run(ctx).instrument(span).await;
            resp.add_header("X-Request-ID", &request_id);
            resp
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    fn is_valid_uuid(s: &str) -> bool {
        Uuid::parse_str(s).is_ok()
    }
    use crate::{
        Response, StatusCode,
        context::Context,
        http::request::Request,
        middleware::{Middleware, MiddlewareHandler, Next},
    };

    fn parse_context(raw: &[u8]) -> Context {
        let (req, _) = Request::parse(raw).unwrap();
        Context::new(req)
    }

    fn plain_context() -> Context {
        parse_context(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
    }

    fn context_with_request_id(id: &str) -> Context {
        let raw = format!("GET / HTTP/1.1\r\nHost: localhost\r\nX-Request-ID: {id}\r\n\r\n");
        parse_context(raw.as_bytes())
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

    fn extract_response_request_id(raw: &str) -> Option<&str> {
        raw.lines().find_map(|line| {
            line.strip_prefix("X-Request-ID: ")
                .map(|v| v.trim_end_matches('\r'))
        })
    }

    #[tokio::test]
    async fn response_always_has_x_request_id_header() {
        let resp = RequestIdMiddleware::new()
            .handle(plain_context(), ok_next())
            .await;
        assert!(wire(resp).contains("X-Request-ID:"));
    }

    #[tokio::test]
    async fn valid_incoming_id_echoed_on_response() {
        let incoming = "550e8400-e29b-41d4-a716-446655440000";
        let ctx = context_with_request_id(incoming);
        let resp = RequestIdMiddleware::new().handle(ctx, ok_next()).await;
        let raw = wire(resp);
        let id = extract_response_request_id(&raw).unwrap();
        assert_eq!(id, incoming);
    }

    #[tokio::test]
    async fn invalid_incoming_id_replaced_with_fresh_uuid() {
        let ctx = context_with_request_id("not-a-uuid");
        let resp = RequestIdMiddleware::new().handle(ctx, ok_next()).await;
        let raw = wire(resp);
        let id = extract_response_request_id(&raw).unwrap();
        assert_ne!(id, "not-a-uuid");
        assert!(is_valid_uuid(id));
    }

    #[tokio::test]
    async fn distrust_incoming_ignores_valid_client_uuid() {
        let incoming = "550e8400-e29b-41d4-a716-446655440000";
        let ctx = context_with_request_id(incoming);
        let resp = RequestIdMiddleware::new()
            .distrust_incoming()
            .handle(ctx, ok_next())
            .await;
        let raw = wire(resp);
        let id = extract_response_request_id(&raw).unwrap();
        assert_ne!(id, incoming);
        assert!(is_valid_uuid(id));
    }

    #[tokio::test]
    async fn downstream_status_is_preserved() {
        let handler: MiddlewareHandler = Arc::new(|_ctx: Context, _next: Next| {
            Box::pin(async { Response::new(StatusCode::Created) })
        });
        let resp = RequestIdMiddleware::new()
            .handle(plain_context(), Next::new(vec![handler]))
            .await;
        assert_eq!(resp.status(), StatusCode::Created);
    }
}
