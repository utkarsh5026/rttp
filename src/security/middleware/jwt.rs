//! JWT bearer-token authentication middleware.
//!
//! Extracts `Authorization: Bearer <token>`, verifies the JWT, and injects
//! the decoded [`Claims`] into the request context for downstream handlers.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::{
    Response,
    context::Context,
    middleware::{Middleware, Next},
    security::auth::{Claims, JwtAuth},
};

/// JWT Bearer-token authentication middleware.
///
/// Extracts the `Authorization: Bearer <token>` header from each incoming
/// request, verifies the JWT using the configured [`JwtAuth`], and — on
/// success — injects the decoded [`Claims`] into [`Context::extensions`] so
/// downstream handlers can retrieve them with
/// `ctx.extensions().get::<Claims>()`.
///
/// On failure the middleware **short-circuits** the pipeline and returns
/// `401 Unauthorized` with a `WWW-Authenticate: Bearer` header. The downstream
/// handler is **not** called.
///
/// # Examples
///
/// ```rust,no_run
/// use std::sync::Arc;
/// use rttp::security::auth::{Claims, JwtAuth};
/// use rttp::security::middleware::JwtMiddleware;
/// use rttp::middleware::from_middleware;
///
/// let auth = JwtAuth::hs256(b"my-secret");
/// let jwt_mw = from_middleware(Arc::new(JwtMiddleware::new(auth)));
/// ```
pub struct JwtMiddleware {
    auth: Arc<JwtAuth>,
}

impl JwtMiddleware {
    /// Create a new `JwtMiddleware` from a [`JwtAuth`] instance.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::security::auth::JwtAuth;
    /// use rttp::security::middleware::JwtMiddleware;
    ///
    /// let mw = JwtMiddleware::new(JwtAuth::hs256(b"secret"));
    /// ```
    pub fn new(auth: JwtAuth) -> Self {
        Self {
            auth: Arc::new(auth),
        }
    }
}

impl Middleware for JwtMiddleware {
    /// Authenticate the request via the `Authorization: Bearer <token>` header.
    ///
    /// # Behavior
    ///
    /// 1. Reads the `authorization` request header.
    /// 2. If missing, returns `401 Unauthorized` immediately.
    /// 3. Calls [`JwtAuth::verify_bearer`] on the header value.
    /// 4. If the token is invalid or expired, returns `401 Unauthorized`.
    /// 5. On success, injects the decoded [`Claims`] into `ctx.extensions` and
    ///    delegates to the next middleware.
    fn handle(&self, ctx: Context, next: Next) -> Pin<Box<dyn Future<Output = Response> + Send>> {
        let auth = Arc::clone(&self.auth);

        Box::pin(async move {
            let authorization = ctx
                .request()
                .headers()
                .get("authorization")
                .map(str::to_owned);

            let Some(auth_header) = authorization else {
                return Response::new(crate::StatusCode::Unauthorized)
                    .header("WWW-Authenticate", "Bearer")
                    .body("Missing Authorization header");
            };

            match auth.verify_bearer::<Claims>(&auth_header) {
                Ok(claims) => {
                    let mut ctx = ctx;
                    ctx.extensions_mut().insert(claims);
                    next.run(ctx).await
                }
                Err(_) => Response::new(crate::StatusCode::Unauthorized)
                    .header("WWW-Authenticate", r#"Bearer error="invalid_token""#)
                    .body("Invalid or expired token"),
            }
        })
    }
}
