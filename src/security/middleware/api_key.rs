//! API key authentication middleware.
//!
//! Extracts the API key from either the `X-Api-Key` header or the
//! `Authorization: ApiKey <key>` header, validates it against a pluggable
//! [`ApiKeyStore`], and injects the resolved [`ApiKeyIdentity`] into the
//! request context on success.
//!
//! # Behavior
//!
//! | Outcome                       | Status             |
//! |-------------------------------|--------------------|
//! | No key header present         | `401 Unauthorized` |
//! | Key not in the store / expired | `403 Forbidden`   |
//! | Valid key                     | delegate to `next` |
//!
//! Header lookup priority:
//!
//! 1. `X-Api-Key` — raw key value.
//! 2. `Authorization: ApiKey <key>` — key is stripped of the scheme prefix.
//!
//! # Examples
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use rttp::security::auth::api_key::{ApiKeyIdentity, InMemoryApiKeyStore};
//! use rttp::security::middleware::api_key::ApiKeyMiddleware;
//! use rttp::middleware::from_middleware;
//!
//! let store = InMemoryApiKeyStore::new()
//!     .add_key("sk-prod-abc", ApiKeyIdentity::new("service-a").scope("read"));
//!
//! let mw = from_middleware(Arc::new(ApiKeyMiddleware::new(store)));
//! ```

use std::{future::Future, pin::Pin, sync::Arc};

use crate::{
    Response, StatusCode,
    context::Context,
    middleware::{Middleware, Next},
    security::auth::api_key::ApiKeyStore,
};

/// API key authentication middleware.
///
/// See the [module documentation](self) for header priority, response codes,
/// and usage examples.
pub struct ApiKeyMiddleware<S: ApiKeyStore> {
    store: Arc<S>,
}

impl<S: ApiKeyStore + 'static> ApiKeyMiddleware<S> {
    /// Wrap an [`ApiKeyStore`] in the middleware.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::security::auth::api_key::{ApiKeyIdentity, InMemoryApiKeyStore};
    /// use rttp::security::middleware::api_key::ApiKeyMiddleware;
    ///
    /// let store = InMemoryApiKeyStore::new()
    ///     .add_key("my-key", ApiKeyIdentity::new("client"));
    /// let _mw = ApiKeyMiddleware::new(store);
    /// ```
    pub fn new(store: S) -> Self {
        Self {
            store: Arc::new(store),
        }
    }
}

impl<S: ApiKeyStore + 'static> Middleware for ApiKeyMiddleware<S> {
    /// Authenticate the request via an API key header.
    ///
    /// # Behavior
    ///
    /// 1. Reads `X-Api-Key`; if absent, tries `Authorization: ApiKey <key>`.
    /// 2. If neither header is present, returns `401 Unauthorized` with a
    ///    `WWW-Authenticate: ApiKey` challenge header.
    /// 3. Passes the extracted key to [`ApiKeyStore::lookup`].
    /// 4. If the key is unknown or expired, returns `403 Forbidden`.
    /// 5. On success, injects the [`ApiKeyIdentity`] into `ctx.extensions` and
    ///    delegates to the next middleware.
    fn handle(&self, ctx: Context, next: Next) -> Pin<Box<dyn Future<Output = Response> + Send>> {
        let store = Arc::clone(&self.store);

        Box::pin(async move {
            let headers = ctx.request().headers();

            let key = if let Some(k) = headers.get("x-api-key") {
                Some(k.to_owned())
            } else if let Some(auth) = headers.get("authorization") {
                auth.strip_prefix("ApiKey ").map(str::to_owned)
            } else {
                None
            };

            let Some(key) = key else {
                return Response::new(StatusCode::Unauthorized)
                    .header("WWW-Authenticate", "ApiKey")
                    .body("Missing API key");
            };

            match store.lookup(&key) {
                Some(identity) => {
                    let mut ctx = ctx;
                    ctx.extensions_mut().insert(identity);
                    next.run(ctx).await
                }
                None => Response::new(StatusCode::Forbidden).body("Invalid or expired API key"),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::{
        Response, StatusCode,
        context::Context,
        http::request::Request,
        middleware::{Middleware, MiddlewareHandler, Next},
        security::auth::api_key::{ApiKeyIdentity, InMemoryApiKeyStore},
    };

    use super::ApiKeyMiddleware;

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn make_store() -> InMemoryApiKeyStore {
        InMemoryApiKeyStore::new()
            .add_key("valid-key", ApiKeyIdentity::new("service-a").scope("read"))
            .add_key("admin-key", ApiKeyIdentity::new("admin").scope("write"))
    }

    fn make_middleware() -> ApiKeyMiddleware<InMemoryApiKeyStore> {
        ApiKeyMiddleware::new(make_store())
    }

    fn parse_context(raw: &[u8]) -> Context {
        let (req, _) = Request::parse(raw).unwrap();
        Context::new(req)
    }

    fn context_without_key() -> Context {
        parse_context(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
    }

    fn context_with_x_api_key(key: &str) -> Context {
        let raw = format!("GET / HTTP/1.1\r\nHost: localhost\r\nX-Api-Key: {key}\r\n\r\n");
        parse_context(raw.as_bytes())
    }

    fn context_with_authorization(value: &str) -> Context {
        let raw = format!("GET / HTTP/1.1\r\nHost: localhost\r\nAuthorization: {value}\r\n\r\n");
        parse_context(raw.as_bytes())
    }

    /// A `Next` that always responds `200 OK` with body `"downstream"`.
    fn ok_next() -> Next {
        let handler: MiddlewareHandler = Arc::new(|_ctx: Context, _next: Next| {
            Box::pin(async move { Response::new(StatusCode::Ok).body("downstream") })
        });
        Next::new(vec![handler])
    }

    /// A `Next` that reads the injected [`ApiKeyIdentity`] and echoes `name`.
    fn identity_echo_next() -> Next {
        let handler: MiddlewareHandler = Arc::new(|ctx: Context, _next: Next| {
            Box::pin(async move {
                let name = ctx
                    .extensions()
                    .get::<ApiKeyIdentity>()
                    .map(|id| id.name.clone())
                    .unwrap_or_else(|| "no-identity".to_string());
                Response::new(StatusCode::Ok).body(name)
            })
        });
        Next::new(vec![handler])
    }

    fn wire(r: Response) -> String {
        String::from_utf8(r.into_bytes().to_vec()).unwrap()
    }

    // ── Constructor ───────────────────────────────────────────────────────────

    #[test]
    fn new_does_not_panic() {
        let _mw = ApiKeyMiddleware::new(make_store());
    }

    // ── Missing key header ────────────────────────────────────────────────────

    #[tokio::test]
    async fn missing_key_returns_401() {
        let resp = make_middleware()
            .handle(context_without_key(), Next::new(vec![]))
            .await;
        assert_eq!(resp.status(), StatusCode::Unauthorized);
    }

    #[tokio::test]
    async fn missing_key_sets_www_authenticate_apikey_header() {
        let resp = make_middleware()
            .handle(context_without_key(), Next::new(vec![]))
            .await;
        assert!(wire(resp).contains("WWW-Authenticate: ApiKey\r\n"));
    }

    #[tokio::test]
    async fn missing_key_body_explains_reason() {
        let resp = make_middleware()
            .handle(context_without_key(), Next::new(vec![]))
            .await;
        assert!(wire(resp).ends_with("Missing API key"));
    }

    #[tokio::test]
    async fn missing_key_does_not_call_next() {
        // ok_next() returns 200; if next were called we'd see 200, not 401.
        let resp = make_middleware()
            .handle(context_without_key(), ok_next())
            .await;
        assert_eq!(resp.status(), StatusCode::Unauthorized);
    }

    // ── Unknown / invalid key ─────────────────────────────────────────────────

    #[tokio::test]
    async fn unknown_key_via_x_api_key_returns_403() {
        let resp = make_middleware()
            .handle(context_with_x_api_key("bad-key"), Next::new(vec![]))
            .await;
        assert_eq!(resp.status(), StatusCode::Forbidden);
    }

    #[tokio::test]
    async fn unknown_key_via_authorization_returns_403() {
        let ctx = context_with_authorization("ApiKey bad-key");
        let resp = make_middleware().handle(ctx, Next::new(vec![])).await;
        assert_eq!(resp.status(), StatusCode::Forbidden);
    }

    #[tokio::test]
    async fn invalid_key_body_explains_reason() {
        let resp = make_middleware()
            .handle(context_with_x_api_key("bad-key"), Next::new(vec![]))
            .await;
        assert!(wire(resp).ends_with("Invalid or expired API key"));
    }

    #[tokio::test]
    async fn empty_key_string_returns_403() {
        let resp = make_middleware()
            .handle(context_with_x_api_key(""), Next::new(vec![]))
            .await;
        assert_eq!(resp.status(), StatusCode::Forbidden);
    }

    // ── Wrong Authorization scheme ────────────────────────────────────────────

    #[tokio::test]
    async fn bearer_scheme_without_x_api_key_header_returns_401() {
        // "Bearer" is not the "ApiKey" scheme and no X-Api-Key header is present.
        let ctx = context_with_authorization("Bearer some-jwt-token");
        let resp = make_middleware().handle(ctx, Next::new(vec![])).await;
        assert_eq!(resp.status(), StatusCode::Unauthorized);
    }

    #[tokio::test]
    async fn lowercase_apikey_scheme_returns_401() {
        // Scheme prefix matching is case-sensitive.
        let ctx = context_with_authorization("apikey valid-key");
        let resp = make_middleware().handle(ctx, Next::new(vec![])).await;
        assert_eq!(resp.status(), StatusCode::Unauthorized);
    }

    // ── Valid key via X-Api-Key ───────────────────────────────────────────────

    #[tokio::test]
    async fn valid_key_via_x_api_key_calls_next_returns_200() {
        let resp = make_middleware()
            .handle(context_with_x_api_key("valid-key"), ok_next())
            .await;
        assert_eq!(resp.status(), StatusCode::Ok);
    }

    #[tokio::test]
    async fn valid_key_via_x_api_key_passes_downstream_body_through() {
        let resp = make_middleware()
            .handle(context_with_x_api_key("valid-key"), ok_next())
            .await;
        assert!(wire(resp).ends_with("downstream"));
    }

    #[tokio::test]
    async fn valid_key_via_x_api_key_injects_identity_name() {
        let resp = make_middleware()
            .handle(context_with_x_api_key("valid-key"), identity_echo_next())
            .await;
        assert!(wire(resp).ends_with("service-a"));
    }

    #[tokio::test]
    async fn valid_key_via_x_api_key_injected_name_matches_registered_identity() {
        let resp = make_middleware()
            .handle(context_with_x_api_key("admin-key"), identity_echo_next())
            .await;
        assert!(wire(resp).ends_with("admin"));
    }

    // ── Valid key via Authorization: ApiKey ───────────────────────────────────

    #[tokio::test]
    async fn valid_key_via_authorization_calls_next_returns_200() {
        let ctx = context_with_authorization("ApiKey admin-key");
        let resp = make_middleware().handle(ctx, ok_next()).await;
        assert_eq!(resp.status(), StatusCode::Ok);
    }

    #[tokio::test]
    async fn valid_key_via_authorization_injects_identity_name() {
        let ctx = context_with_authorization("ApiKey admin-key");
        let resp = make_middleware().handle(ctx, identity_echo_next()).await;
        assert!(wire(resp).ends_with("admin"));
    }

    // ── X-Api-Key priority over Authorization ─────────────────────────────────

    #[tokio::test]
    async fn x_api_key_takes_priority_over_authorization_header() {
        // X-Api-Key = valid-key (service-a), Authorization = admin-key (admin).
        // X-Api-Key wins; downstream should see "service-a".
        let raw = b"GET / HTTP/1.1\r\nHost: localhost\r\n\
                    X-Api-Key: valid-key\r\n\
                    Authorization: ApiKey admin-key\r\n\r\n";
        let ctx = parse_context(raw);
        let resp = make_middleware().handle(ctx, identity_echo_next()).await;
        assert!(wire(resp).ends_with("service-a"));
    }
}
