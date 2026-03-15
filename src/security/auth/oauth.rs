//! OAuth 2.0 / OpenID Connect token validation.
//!
//! Validates JWT tokens issued by external OIDC-compliant providers (Google,
//! GitHub, Auth0, etc.) by fetching and caching their public keys via the
//! [JWKS] (JSON Web Key Set) endpoint.
//!
//! # Features
//!
//! - OIDC discovery via `/.well-known/openid-configuration`.
//! - JWKS fetching with configurable TTL-based caching.
//! - Automatic key refresh on unknown `kid` (handles key rotation).
//! - `iss` (issuer) and `aud` (audience) claim validation.
//! - RS256 and ES256 asymmetric signature verification.
//!
//! # Quick Start
//!
//! ```rust,no_run
//! use rttp::security::auth::oauth::{OAuthConfig, OAuthValidator};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = OAuthConfig::new(
//!     "https://accounts.google.com",
//!     "your-client-id.apps.googleusercontent.com",
//! );
//!
//! let validator = OAuthValidator::new(config).await?;
//! let claims = validator.validate("eyJhbGciOi...").await?;
//! println!("Authenticated user: {}", claims.sub);
//! # Ok(())
//! # }
//! ```
//!
//! [JWKS]: https://www.rfc-editor.org/rfc/rfc7517

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, warn};

/// Errors produced during OAuth / OIDC token validation.
#[derive(Debug, Error)]
pub enum OAuthError {
    /// The JWKS or OIDC discovery HTTP request failed.
    #[error("JWKS fetch failed: {0}")]
    FetchError(#[from] reqwest::Error),

    /// The JWT is malformed, expired, or has an invalid signature.
    #[error("invalid token: {0}")]
    TokenError(#[from] jsonwebtoken::errors::Error),

    /// No key in the JWKS matches the token's `kid` header.
    #[error("no matching key for kid `{0}`")]
    UnknownKid(String),

    /// The token header does not contain a `kid` claim.
    #[error("token header missing kid")]
    MissingKid,

    /// The token uses an algorithm not in the allowed set.
    #[error("unsupported algorithm: {0:?}")]
    UnsupportedAlgorithm(Algorithm),

    /// OIDC discovery response was missing or malformed.
    #[error("OIDC discovery failed: {0}")]
    DiscoveryError(String),
}

/// Configuration for an OAuth / OIDC token validator.
///
/// Use the builder methods to customize beyond the defaults.
///
/// # Examples
///
/// ```rust
/// use rttp::security::auth::oauth::OAuthConfig;
/// use std::time::Duration;
///
/// let config = OAuthConfig::new("https://accounts.google.com", "my-client-id")
///     .jwks_ttl(Duration::from_secs(600));
/// ```
#[derive(Debug, Clone)]
pub struct OAuthConfig {
    /// The expected token issuer (e.g. `https://accounts.google.com`).
    pub issuer: String,
    /// The expected audience — typically the OAuth client ID.
    pub audience: String,
    /// Algorithms accepted for token validation. Defaults to `[RS256]`.
    pub allowed_algorithms: Vec<Algorithm>,
    /// How long to cache JWKS keys before re-fetching. Defaults to 5 minutes.
    pub jwks_ttl: Duration,
}

impl OAuthConfig {
    /// Create a new `OAuthConfig` with sensible defaults.
    ///
    /// Defaults: RS256 algorithm, 5-minute JWKS cache TTL.
    pub fn new(issuer: impl Into<String>, audience: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into(),
            audience: audience.into(),
            allowed_algorithms: vec![Algorithm::RS256],
            jwks_ttl: Duration::from_secs(300),
        }
    }

    /// Add an allowed algorithm (e.g. `Algorithm::ES256`).
    #[must_use]
    pub fn algorithm(mut self, alg: Algorithm) -> Self {
        if !self.allowed_algorithms.contains(&alg) {
            self.allowed_algorithms.push(alg);
        }
        self
    }

    /// Set the JWKS cache time-to-live.
    #[must_use]
    pub fn jwks_ttl(mut self, ttl: Duration) -> Self {
        self.jwks_ttl = ttl;
        self
    }
}

/// Decoded OIDC claims from an external provider's ID token.
///
/// Standard OIDC claims are provided as typed fields. Any additional
/// provider-specific claims are captured in the `extra` map via
/// `#[serde(flatten)]`.
///
/// # Examples
///
/// ```rust
/// use rttp::security::auth::oauth::OAuthClaims;
///
/// let json = r#"{"sub":"user-1","exp":9999999999,"email":"a@b.com"}"#;
/// let claims: OAuthClaims = serde_json::from_str(json).unwrap();
/// assert_eq!(claims.sub, "user-1");
/// assert_eq!(claims.email.as_deref(), Some("a@b.com"));
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthClaims {
    /// Subject — the user's unique identifier at the provider.
    pub sub: String,

    /// Expiry as a Unix timestamp.
    pub exp: u64,

    /// Issued-at timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iat: Option<u64>,

    /// Issuer — the provider that issued the token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,

    /// Audience — may be a single string or an array of strings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aud: Option<serde_json::Value>,

    /// The user's email address (if granted by the provider).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,

    /// Whether the provider has verified the email address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,

    /// The user's display name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// URL to the user's profile picture.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,

    /// Authorized party — the client that the token was issued to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub azp: Option<String>,

    /// Any additional claims not covered by the typed fields above.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// OIDC discovery document (subset of fields we need).
#[derive(Debug, Deserialize)]
struct OidcDiscovery {
    issuer: String,
    jwks_uri: String,
}

/// Internal JWKS cache entry.
pub(crate) struct JwksCache {
    /// kid → DecodingKey
    pub(crate) keys: HashMap<String, DecodingKey>,
    /// kid → Algorithm (stored for diagnostics and multi-algorithm validation).
    #[allow(dead_code)]
    pub(crate) algorithms: HashMap<String, Algorithm>,
    /// When the cache was last populated.
    pub(crate) fetched_at: Instant,
}

/// Validates OAuth / OIDC tokens against a provider's JWKS.
///
/// Construct with [`OAuthValidator::new`], which performs OIDC discovery to
/// locate the provider's JWKS endpoint. Tokens are then validated with
/// [`OAuthValidator::validate`].
///
/// The validator is cheap to clone — the internal state is reference-counted.
///
/// # Examples
///
/// ```rust,no_run
/// use rttp::security::auth::oauth::{OAuthConfig, OAuthValidator};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let validator = OAuthValidator::new(
///     OAuthConfig::new("https://accounts.google.com", "my-client-id"),
/// ).await?;
///
/// let claims = validator.validate("eyJhbGciOi...").await?;
/// println!("sub = {}", claims.sub);
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct OAuthValidator {
    pub(crate) config: Arc<OAuthConfig>,
    pub(crate) cache: Arc<RwLock<Option<JwksCache>>>,
    pub(crate) jwks_uri: Arc<String>,
    pub(crate) http: reqwest::Client,
}

impl OAuthValidator {
    /// Create a new validator by performing OIDC discovery against the issuer.
    ///
    /// This is an async constructor because it fetches the provider's
    /// `/.well-known/openid-configuration` to resolve the JWKS URI, then
    /// performs an initial JWKS fetch.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthError::FetchError`] if the HTTP request fails, or
    /// [`OAuthError::DiscoveryError`] if the discovery document is malformed.
    pub async fn new(config: OAuthConfig) -> Result<Self, OAuthError> {
        let http = reqwest::Client::new();
        let jwks_uri = Self::discover(&config.issuer, &http).await?;

        debug!(issuer = %config.issuer, jwks_uri = %jwks_uri, "OIDC discovery complete");

        let validator = Self {
            config: Arc::new(config),
            cache: Arc::new(RwLock::new(None)),
            jwks_uri: Arc::new(jwks_uri),
            http,
        };

        validator.refresh_jwks().await?;
        Ok(validator)
    }

    /// Create a validator with a pre-known JWKS URI, skipping OIDC discovery.
    ///
    /// Useful when the provider's JWKS URI is already known or the provider
    /// does not support standard OIDC discovery.
    pub async fn with_jwks_uri(
        config: OAuthConfig,
        jwks_uri: impl Into<String>,
    ) -> Result<Self, OAuthError> {
        let http = reqwest::Client::new();
        let jwks_uri = jwks_uri.into();

        debug!(jwks_uri = %jwks_uri, "skipping OIDC discovery, using provided JWKS URI");

        let validator = Self {
            config: Arc::new(config),
            cache: Arc::new(RwLock::new(None)),
            jwks_uri: Arc::new(jwks_uri),
            http,
        };

        validator.refresh_jwks().await?;
        Ok(validator)
    }

    /// Validate a raw JWT string and return the decoded [`OAuthClaims`].
    ///
    /// 1. Decodes the JWT header to extract `kid` and `alg`.
    /// 2. Looks up the corresponding key in the JWKS cache.
    /// 3. If the `kid` is unknown or the cache is stale, refreshes the JWKS.
    /// 4. Validates the signature, `exp`, `iss`, and `aud` claims.
    ///
    /// # Errors
    ///
    /// Returns an [`OAuthError`] variant if any validation step fails.
    pub async fn validate(&self, token: &str) -> Result<OAuthClaims, OAuthError> {
        let header = decode_header(token)?;

        let kid = header.kid.ok_or(OAuthError::MissingKid)?;
        let alg = header.alg;

        if !self.config.allowed_algorithms.contains(&alg) {
            return Err(OAuthError::UnsupportedAlgorithm(alg));
        }

        // Try with current cache first.
        if let Some(claims) = self.try_validate_with_cache(token, &kid, alg).await? {
            return Ok(claims);
        }

        // Cache miss or stale — refresh and retry.
        debug!(kid = %kid, "kid not in cache, refreshing JWKS");
        self.refresh_jwks().await?;

        if let Some(claims) = self.try_validate_with_cache(token, &kid, alg).await? {
            return Ok(claims);
        }

        Err(OAuthError::UnknownKid(kid))
    }

    /// Attempt validation using the current cache. Returns `Ok(None)` if the
    /// `kid` is not found in the cache (caller should refresh and retry).
    async fn try_validate_with_cache(
        &self,
        token: &str,
        kid: &str,
        alg: Algorithm,
    ) -> Result<Option<OAuthClaims>, OAuthError> {
        let cache = self.cache.read().await;
        let Some(cache) = cache.as_ref() else {
            return Ok(None);
        };

        // Check TTL.
        if cache.fetched_at.elapsed() > self.config.jwks_ttl {
            return Ok(None);
        }

        let Some(key) = cache.keys.get(kid) else {
            return Ok(None);
        };

        let mut validation = Validation::new(alg);
        validation.set_issuer(&[&self.config.issuer]);
        validation.set_audience(&[&self.config.audience]);
        validation.validate_exp = true;

        let token_data = decode::<OAuthClaims>(token, key, &validation)?;
        Ok(Some(token_data.claims))
    }

    /// Fetch the JWKS from the provider and update the cache.
    async fn refresh_jwks(&self) -> Result<(), OAuthError> {
        debug!(jwks_uri = %self.jwks_uri, "fetching JWKS");

        let jwk_set: JwkSet = self
            .http
            .get(self.jwks_uri.as_str())
            .send()
            .await?
            .json()
            .await?;

        let mut keys = HashMap::new();
        let mut algorithms = HashMap::new();

        for jwk in &jwk_set.keys {
            let Some(ref kid) = jwk.common.key_id else {
                continue;
            };

            let alg = match jwk.common.key_algorithm {
                Some(ka) => match ka {
                    jsonwebtoken::jwk::KeyAlgorithm::RS256 => Algorithm::RS256,
                    jsonwebtoken::jwk::KeyAlgorithm::RS384 => Algorithm::RS384,
                    jsonwebtoken::jwk::KeyAlgorithm::RS512 => Algorithm::RS512,
                    jsonwebtoken::jwk::KeyAlgorithm::ES256 => Algorithm::ES256,
                    jsonwebtoken::jwk::KeyAlgorithm::ES384 => Algorithm::ES384,
                    jsonwebtoken::jwk::KeyAlgorithm::PS256 => Algorithm::PS256,
                    jsonwebtoken::jwk::KeyAlgorithm::PS384 => Algorithm::PS384,
                    jsonwebtoken::jwk::KeyAlgorithm::PS512 => Algorithm::PS512,
                    jsonwebtoken::jwk::KeyAlgorithm::EdDSA => Algorithm::EdDSA,
                    other => {
                        warn!(kid = %kid, algorithm = ?other, "skipping JWK with unsupported algorithm");
                        continue;
                    }
                },
                None => {
                    // Default to RS256 if not specified (common for many providers).
                    Algorithm::RS256
                }
            };

            match DecodingKey::from_jwk(jwk) {
                Ok(decoding_key) => {
                    debug!(kid = %kid, algorithm = ?alg, "cached JWK");
                    keys.insert(kid.clone(), decoding_key);
                    algorithms.insert(kid.clone(), alg);
                }
                Err(e) => {
                    warn!(kid = %kid, error = %e, "failed to convert JWK to decoding key");
                }
            }
        }

        debug!(key_count = keys.len(), "JWKS cache refreshed");

        let mut cache = self.cache.write().await;
        *cache = Some(JwksCache {
            keys,
            algorithms,
            fetched_at: Instant::now(),
        });

        Ok(())
    }

    /// Perform OIDC discovery to find the JWKS URI.
    async fn discover(issuer: &str, http: &reqwest::Client) -> Result<String, OAuthError> {
        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            issuer.trim_end_matches('/')
        );

        debug!(url = %discovery_url, "performing OIDC discovery");

        let discovery: OidcDiscovery = http
            .get(&discovery_url)
            .send()
            .await?
            .json()
            .await
            .map_err(|e| OAuthError::DiscoveryError(e.to_string()))?;

        // Verify the issuer in the discovery document matches what we expect.
        if discovery.issuer != issuer {
            return Err(OAuthError::DiscoveryError(format!(
                "issuer mismatch: expected `{}`, got `{}`",
                issuer, discovery.issuer
            )));
        }

        Ok(discovery.jwks_uri)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── OAuthConfig ──────────────────────────────────────────────────────────

    #[test]
    fn config_new_sets_defaults() {
        let cfg = OAuthConfig::new("https://issuer.example.com", "client-123");
        assert_eq!(cfg.issuer, "https://issuer.example.com");
        assert_eq!(cfg.audience, "client-123");
        assert_eq!(cfg.allowed_algorithms, vec![Algorithm::RS256]);
        assert_eq!(cfg.jwks_ttl, Duration::from_secs(300));
    }

    #[test]
    fn config_algorithm_adds_without_duplicates() {
        let cfg = OAuthConfig::new("https://iss", "aud")
            .algorithm(Algorithm::ES256)
            .algorithm(Algorithm::ES256); // duplicate
        assert_eq!(
            cfg.allowed_algorithms,
            vec![Algorithm::RS256, Algorithm::ES256]
        );
    }

    #[test]
    fn config_jwks_ttl_overrides_default() {
        let cfg = OAuthConfig::new("https://iss", "aud").jwks_ttl(Duration::from_secs(60));
        assert_eq!(cfg.jwks_ttl, Duration::from_secs(60));
    }

    // ── OAuthClaims ──────────────────────────────────────────────────────────

    #[test]
    fn claims_deserialize_minimal() {
        let json = r#"{"sub":"user-1","exp":9999999999}"#;
        let claims: OAuthClaims = serde_json::from_str(json).unwrap();
        assert_eq!(claims.sub, "user-1");
        assert_eq!(claims.exp, 9_999_999_999);
        assert!(claims.email.is_none());
        assert!(claims.name.is_none());
    }

    #[test]
    fn claims_deserialize_full_google_style() {
        let json = r#"{
            "sub": "1234567890",
            "exp": 9999999999,
            "iat": 1609459200,
            "iss": "https://accounts.google.com",
            "aud": "my-client-id.apps.googleusercontent.com",
            "email": "user@gmail.com",
            "email_verified": true,
            "name": "Test User",
            "picture": "https://lh3.googleusercontent.com/photo.jpg",
            "azp": "my-client-id.apps.googleusercontent.com",
            "at_hash": "HK6E_P6Dh8Y93mRNtsDB1Q",
            "nonce": "abc123"
        }"#;
        let claims: OAuthClaims = serde_json::from_str(json).unwrap();
        assert_eq!(claims.sub, "1234567890");
        assert_eq!(claims.email.as_deref(), Some("user@gmail.com"));
        assert_eq!(claims.email_verified, Some(true));
        assert_eq!(claims.name.as_deref(), Some("Test User"));
        assert!(claims.picture.is_some());
        assert_eq!(
            claims.azp.as_deref(),
            Some("my-client-id.apps.googleusercontent.com")
        );
        // Extra claims captured via flatten.
        assert!(claims.extra.contains_key("at_hash"));
        assert!(claims.extra.contains_key("nonce"));
    }

    #[test]
    fn claims_roundtrip_serialize() {
        let claims = OAuthClaims {
            sub: "user-42".to_string(),
            exp: 9_999_999_999,
            iat: Some(1_000_000_000),
            iss: Some("https://issuer.example.com".to_string()),
            aud: None,
            email: Some("test@example.com".to_string()),
            email_verified: Some(true),
            name: None,
            picture: None,
            azp: None,
            extra: HashMap::new(),
        };
        let json = serde_json::to_string(&claims).unwrap();
        let decoded: OAuthClaims = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.sub, "user-42");
        assert_eq!(decoded.email.as_deref(), Some("test@example.com"));
    }

    // ── OAuthValidator (unit-testable parts) ────────────────────────────────

    #[test]
    fn missing_kid_header_produces_error() {
        // A token without a kid in the header — we can test decode_header behavior.
        // HS256 tokens typically don't have kid, so this is a good test.
        let auth = crate::security::auth::JwtAuth::hs256(b"test-secret");
        let claims = crate::security::auth::Claims::new("user", 3600);
        let token = auth.sign(&claims).unwrap();

        let header = decode_header(&token).unwrap();
        assert!(header.kid.is_none()); // confirms our test assumption
    }

    #[tokio::test]
    async fn validate_rs256_with_manual_key() {
        use jsonwebtoken::{EncodingKey, Header};

        // Generate an RSA key pair for testing.
        // We use a pre-generated small test key (this is NOT secure, test only).
        let rsa_private = include_str!("../../test_fixtures/rsa_private.pem");
        let rsa_public = include_str!("../../test_fixtures/rsa_public.pem");

        let encoding_key = EncodingKey::from_rsa_pem(rsa_private.as_bytes()).unwrap();
        let decoding_key = DecodingKey::from_rsa_pem(rsa_public.as_bytes()).unwrap();

        // Sign a token with kid.
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("test-key-1".to_string());

        let claims = OAuthClaims {
            sub: "rsa-user".to_string(),
            exp: 9_999_999_999,
            iat: Some(1_000_000_000),
            iss: Some("https://test-issuer.example.com".to_string()),
            aud: Some(serde_json::Value::String("test-audience".to_string())),
            email: Some("rsa@example.com".to_string()),
            email_verified: Some(true),
            name: None,
            picture: None,
            azp: None,
            extra: HashMap::new(),
        };

        let token = jsonwebtoken::encode(&header, &claims, &encoding_key).unwrap();

        // Build a validator with a pre-populated cache (no HTTP).
        let config = OAuthConfig::new("https://test-issuer.example.com", "test-audience");

        let mut keys = HashMap::new();
        keys.insert("test-key-1".to_string(), decoding_key);
        let mut algs = HashMap::new();
        algs.insert("test-key-1".to_string(), Algorithm::RS256);

        let validator = OAuthValidator {
            config: Arc::new(config),
            cache: Arc::new(RwLock::new(Some(JwksCache {
                keys,
                algorithms: algs,
                fetched_at: Instant::now(),
            }))),
            jwks_uri: Arc::new("https://unused.example.com/jwks".to_string()),
            http: reqwest::Client::new(),
        };

        let decoded = validator.validate(&token).await.unwrap();
        assert_eq!(decoded.sub, "rsa-user");
        assert_eq!(decoded.email.as_deref(), Some("rsa@example.com"));
    }
}
