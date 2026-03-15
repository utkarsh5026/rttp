//! Security audit logging middleware.
//!
//! Emits structured [`tracing`] events for security-relevant actions:
//! authentication successes and failures, rate-limit hits, blocked IPs,
//! and CSRF rejections.
//!
//! Place this middleware early in the pipeline (before auth middleware) so it
//! can observe the final response status and log accordingly.
//!
//! # Examples
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use rttp::security::middleware::AuditMiddleware;
//! use rttp::middleware::from_middleware;
//!
//! let mw = from_middleware(Arc::new(AuditMiddleware::new()));
//! ```

use std::{future::Future, pin::Pin, time::Instant};

use tracing::{info, warn};

use crate::{
    Response, StatusCode,
    context::Context,
    middleware::{Middleware, Next},
    security::middleware::util::extract_client_ip,
};

/// Security audit logging middleware.
///
/// Logs a structured event for every request, including method, path, status,
/// latency, and client IP. Emits at `WARN` level for security-relevant status
/// codes (401, 403, 429) and at `INFO` level otherwise.
pub struct AuditMiddleware {
    /// If true, log all requests. If false, only log security events.
    log_all: bool,
}

impl Default for AuditMiddleware {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditMiddleware {
    /// Create a new audit middleware that logs only security-relevant events
    /// (401, 403, 429).
    #[must_use]
    pub fn new() -> Self {
        Self { log_all: false }
    }

    /// Log all requests, not just security events.
    #[must_use]
    pub fn log_all(mut self) -> Self {
        self.log_all = true;
        self
    }
}

impl Middleware for AuditMiddleware {
    fn handle(&self, ctx: Context, next: Next) -> Pin<Box<dyn Future<Output = Response> + Send>> {
        let log_all = self.log_all;
        let method = ctx.request().method().to_string();
        let path = ctx.request().path().to_owned();
        let client_ip = extract_client_ip(&ctx);

        Box::pin(async move {
            let start = Instant::now();
            let resp = next.run(ctx).await;
            let elapsed_ms = start.elapsed().as_millis();
            let status = resp.status();

            match status {
                StatusCode::Unauthorized => {
                    warn!(
                        event = "auth_failure",
                        %method,
                        %path,
                        %client_ip,
                        status = 401u16,
                        elapsed_ms = elapsed_ms as u64,
                        "authentication failed"
                    );
                }
                StatusCode::Forbidden => {
                    warn!(
                        event = "access_denied",
                        %method,
                        %path,
                        %client_ip,
                        status = 403u16,
                        elapsed_ms = elapsed_ms as u64,
                        "access denied"
                    );
                }
                StatusCode::TooManyRequests => {
                    warn!(
                        event = "rate_limited",
                        %method,
                        %path,
                        %client_ip,
                        status = 429u16,
                        elapsed_ms = elapsed_ms as u64,
                        "rate limited"
                    );
                }
                _ if log_all => {
                    info!(
                        event = "request",
                        %method,
                        %path,
                        %client_ip,
                        status = u16::from(status),
                        elapsed_ms = elapsed_ms as u64,
                        "request completed"
                    );
                }
                _ => {}
            }

            resp
        })
    }
}
