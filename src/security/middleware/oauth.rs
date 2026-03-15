//! OAuth / OIDC bearer-token authentication middleware.
//!
//! Extracts `Authorization: Bearer <token>`, validates the token against the
//! provider's JWKS via [`OAuthValidator`], and injects the decoded
//! [`crate::security::auth::oauth::OAuthClaims`] into the request context for downstream handlers.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::{
    Response,
    context::Context,
    middleware::{Middleware, Next},
    security::auth::oauth::OAuthValidator,
};

/// OAuth / OIDC bearer-token authentication middleware.
///
/// Extracts the `Authorization: Bearer <token>` header from each incoming
/// request, validates the JWT against the provider's JWKS using the configured
/// [`OAuthValidator`], and — on success — injects the decoded [`crate::security::auth::oauth::OAuthClaims`]
/// into [`Context::extensions`] so downstream handlers can retrieve them with
/// `ctx.extensions().get::<OAuthClaims>()`.
///
/// On failure the middleware **short-circuits** the pipeline and returns
/// `401 Unauthorized` with a `WWW-Authenticate: Bearer` header.
///
/// # Examples
///
/// ```rust,no_run
/// use std::sync::Arc;
/// use rttp::security::auth::oauth::{OAuthConfig, OAuthValidator};
/// use rttp::security::middleware::OAuthMiddleware;
/// use rttp::middleware::from_middleware;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let validator = OAuthValidator::new(
///     OAuthConfig::new("https://accounts.google.com", "my-client-id"),
/// ).await?;
///
/// let oauth_mw = from_middleware(Arc::new(OAuthMiddleware::new(validator)));
/// # Ok(())
/// # }
/// ```
pub struct OAuthMiddleware {
    validator: Arc<OAuthValidator>,
}

impl OAuthMiddleware {
    /// Create a new `OAuthMiddleware` from an [`OAuthValidator`].
    pub fn new(validator: OAuthValidator) -> Self {
        Self {
            validator: Arc::new(validator),
        }
    }
}

impl Middleware for OAuthMiddleware {
    /// Authenticate the request via the `Authorization: Bearer <token>` header.
    ///
    /// 1. Reads the `authorization` request header.
    /// 2. If missing, returns `401 Unauthorized` immediately.
    /// 3. Strips the `Bearer ` prefix and validates the token.
    /// 4. If the token is invalid or expired, returns `401 Unauthorized`.
    /// 5. On success, injects [`crate::security::auth::oauth::OAuthClaims`] into `ctx.extensions` and
    ///    delegates to the next middleware.
    fn handle(&self, ctx: Context, next: Next) -> Pin<Box<dyn Future<Output = Response> + Send>> {
        let validator = Arc::clone(&self.validator);

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

            let Some(token) = auth_header.strip_prefix("Bearer ") else {
                return Response::new(crate::StatusCode::Unauthorized)
                    .header("WWW-Authenticate", r#"Bearer error="invalid_request""#)
                    .body("Malformed Authorization header — expected `Bearer <token>`");
            };

            match validator.validate(token).await {
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Instant;

    use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header};
    use tokio::sync::RwLock;

    use crate::{
        Response, StatusCode,
        context::Context,
        http::request::Request,
        middleware::{Middleware, MiddlewareHandler, Next},
        security::auth::oauth::{OAuthClaims, OAuthConfig, OAuthValidator},
    };

    use super::OAuthMiddleware;

    /// Build a validator with a manually injected RSA key (no HTTP).
    fn make_test_validator() -> (OAuthValidator, EncodingKey) {
        let rsa_private = include_str!("../../test_fixtures/rsa_private.pem");
        let rsa_public = include_str!("../../test_fixtures/rsa_public.pem");

        let encoding_key = EncodingKey::from_rsa_pem(rsa_private.as_bytes()).unwrap();
        let decoding_key = DecodingKey::from_rsa_pem(rsa_public.as_bytes()).unwrap();

        let config = OAuthConfig::new("https://test-issuer.example.com", "test-audience");

        let mut keys = HashMap::new();
        keys.insert("test-key-1".to_string(), decoding_key);
        let mut algorithms = HashMap::new();
        algorithms.insert("test-key-1".to_string(), Algorithm::RS256);

        let validator = OAuthValidator {
            config: Arc::new(config),
            cache: Arc::new(RwLock::new(Some(crate::security::auth::oauth::JwksCache {
                keys,
                algorithms,
                fetched_at: Instant::now(),
            }))),
            jwks_uri: Arc::new("https://unused.example.com/jwks".to_string()),
            http: reqwest::Client::new(),
        };

        (validator, encoding_key)
    }

    fn sign_test_token(encoding_key: &EncodingKey) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("test-key-1".to_string());

        let claims = OAuthClaims {
            sub: "oauth-user".to_string(),
            exp: 9_999_999_999,
            iat: Some(1_000_000_000),
            iss: Some("https://test-issuer.example.com".to_string()),
            aud: Some(serde_json::Value::String("test-audience".to_string())),
            email: Some("oauth@example.com".to_string()),
            email_verified: Some(true),
            name: None,
            picture: None,
            azp: None,
            extra: HashMap::new(),
        };

        jsonwebtoken::encode(&header, &claims, encoding_key).unwrap()
    }

    fn parse_context(raw: &[u8]) -> Context {
        let (req, _) = Request::parse(raw).unwrap();
        Context::new(req)
    }

    fn context_without_auth() -> Context {
        parse_context(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
    }

    fn context_with_auth_header(value: &str) -> Context {
        let raw = format!("GET / HTTP/1.1\r\nHost: localhost\r\nAuthorization: {value}\r\n\r\n");
        parse_context(raw.as_bytes())
    }

    fn ok_next() -> Next {
        let handler: MiddlewareHandler = Arc::new(|_ctx, _next| {
            Box::pin(async move { Response::new(StatusCode::Ok).body("downstream") })
        });
        Next::new(vec![handler])
    }

    fn claims_echo_next() -> Next {
        let handler: MiddlewareHandler = Arc::new(|ctx: Context, _next: Next| {
            Box::pin(async move {
                let sub = ctx
                    .extensions()
                    .get::<OAuthClaims>()
                    .map(|c| c.sub.clone())
                    .unwrap_or_else(|| "no-claims".to_string());
                Response::new(StatusCode::Ok).body(sub)
            })
        });
        Next::new(vec![handler])
    }

    fn response_to_string(r: Response) -> String {
        String::from_utf8(r.into_bytes().to_vec()).unwrap()
    }

    #[tokio::test]
    async fn missing_auth_header_returns_401() {
        let (validator, _) = make_test_validator();
        let mw = OAuthMiddleware::new(validator);
        let resp = mw.handle(context_without_auth(), Next::new(vec![])).await;
        assert_eq!(resp.status(), StatusCode::Unauthorized);
    }

    #[tokio::test]
    async fn missing_auth_header_sets_www_authenticate() {
        let (validator, _) = make_test_validator();
        let mw = OAuthMiddleware::new(validator);
        let resp = mw.handle(context_without_auth(), Next::new(vec![])).await;
        let text = response_to_string(resp);
        assert!(text.contains("WWW-Authenticate: Bearer\r\n"));
    }

    #[tokio::test]
    async fn missing_bearer_prefix_returns_401() {
        let (validator, key) = make_test_validator();
        let mw = OAuthMiddleware::new(validator);
        let token = sign_test_token(&key);
        let resp = mw
            .handle(context_with_auth_header(&token), Next::new(vec![]))
            .await;
        assert_eq!(resp.status(), StatusCode::Unauthorized);
    }

    #[tokio::test]
    async fn garbage_token_returns_401() {
        let (validator, _) = make_test_validator();
        let mw = OAuthMiddleware::new(validator);
        let resp = mw
            .handle(
                context_with_auth_header("Bearer not.a.real.token"),
                Next::new(vec![]),
            )
            .await;
        assert_eq!(resp.status(), StatusCode::Unauthorized);
    }

    #[tokio::test]
    async fn valid_token_calls_next_and_returns_200() {
        let (validator, key) = make_test_validator();
        let mw = OAuthMiddleware::new(validator);
        let token = format!("Bearer {}", sign_test_token(&key));
        let resp = mw.handle(context_with_auth_header(&token), ok_next()).await;
        assert_eq!(resp.status(), StatusCode::Ok);
    }

    #[tokio::test]
    async fn valid_token_injects_claims_into_extensions() {
        let (validator, key) = make_test_validator();
        let mw = OAuthMiddleware::new(validator);
        let token = format!("Bearer {}", sign_test_token(&key));
        let resp = mw
            .handle(context_with_auth_header(&token), claims_echo_next())
            .await;
        let text = response_to_string(resp);
        assert!(text.ends_with("oauth-user"));
    }
}
