//! JWT authentication — signing and verification using HMAC-SHA algorithms.
//!
//! This module provides:
//!
//! - [`Claims`] — a standard JWT claims struct with `sub`, `exp`, `iat`, and `iss`.
//! - [`JwtAuth`] — creates, signs, and verifies JWTs.
//! - [`JwtError`] — errors produced during signing or verification.
//!
//! # Quick Start
//!
//! ```rust
//! use rttp::security::auth::{Claims, JwtAuth};
//!
//! let auth = JwtAuth::hs256(b"super-secret");
//!
//! let claims = Claims::new("user-42", 3600);
//! let token = auth.sign(&claims).unwrap();
//!
//! let decoded: Claims = auth.verify(&token).unwrap();
//! assert_eq!(decoded.sub, "user-42");
//! ```

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors produced by JWT signing or verification.
#[derive(Debug, Error)]
pub enum JwtError {
    #[error("invalid token: {0}")]
    Invalid(#[from] jsonwebtoken::errors::Error),

    #[error("missing Authorization header")]
    MissingToken,

    #[error("malformed Authorization header — expected `Bearer <token>`")]
    MalformedHeader,
}

/// Standard JWT claims.
///
/// Contains the registered claims defined by [RFC 7519]:
/// `sub` (subject) and `exp` (expiry) are required by the default validation
/// performed in [`JwtAuth::verify`]. `iat` (issued-at), `iss` (issuer), and
/// `jti` (JWT ID) are optional and omitted from the token if `None`.
///
/// The `jti` claim is a unique token identifier used by
/// [`crate::security::token::blocklist::TokenBlocklist`] for revocation.
/// Populate it with [`Claims::with_jti`] or [`Claims::with_random_jti`].
///
/// For application-specific data, embed `Claims` inside your own struct that
/// also derives `Serialize` / `Deserialize`, then pass it to [`JwtAuth::sign`]
/// and [`JwtAuth::verify`].
///
/// [RFC 7519]: https://www.rfc-editor.org/rfc/rfc7519
///
/// # Examples
///
/// ```rust
/// use rttp::security::auth::Claims;
///
/// let claims = Claims::new("user-42", 3600).issuer("my-service").with_random_jti();
/// assert_eq!(claims.sub, "user-42");
/// assert_eq!(claims.iss.as_deref(), Some("my-service"));
/// assert!(claims.jti.is_some());
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject — typically the authenticated user's ID.
    pub sub: String,

    /// Expiry as a Unix timestamp (seconds since the epoch).
    pub exp: u64,

    /// Issued-at as a Unix timestamp; omitted from the token when `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<u64>,

    /// Issuer — the service that issued the token; omitted when `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,

    /// JWT ID — a unique identifier for this token, used for revocation.
    ///
    /// Set via [`Claims::with_jti`] or [`Claims::with_random_jti`].
    /// Required for blocklist-based revocation to work.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
}

impl Claims {
    /// Create claims with a `sub` subject and a lifetime of `expires_in_secs` seconds
    /// from the current wall-clock time.
    ///
    /// `iat` is set to the current time; `iss` is `None` unless set via
    /// [`Claims::issuer`].
    ///
    /// # Arguments
    ///
    /// - `sub` — the subject identifier (e.g. a user ID).
    /// - `expires_in_secs` — lifetime of the token in seconds from now.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::security::auth::Claims;
    ///
    /// let claims = Claims::new("user-1", 900); // 15 minutes
    /// ```
    pub fn new(sub: impl Into<String>, expires_in_secs: u64) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock is before Unix epoch")
            .as_secs();

        Self {
            sub: sub.into(),
            exp: now + expires_in_secs,
            iat: Some(now),
            iss: None,
            jti: None,
        }
    }

    /// Set the `iss` (issuer) field.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::security::auth::Claims;
    ///
    /// let claims = Claims::new("user-1", 3600).issuer("auth-service");
    /// assert_eq!(claims.iss.as_deref(), Some("auth-service"));
    /// ```
    #[must_use]
    pub fn issuer(mut self, iss: impl Into<String>) -> Self {
        self.iss = Some(iss.into());
        self
    }

    /// Set a specific `jti` (JWT ID) for this token.
    ///
    /// The `jti` is used by [`crate::security::token::blocklist::TokenBlocklist`]
    /// to identify and revoke individual tokens. It must be unique per token.
    ///
    /// Prefer [`Claims::with_random_jti`] unless you need a deterministic ID.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::security::auth::Claims;
    ///
    /// let claims = Claims::new("user-1", 3600).with_jti("my-unique-id");
    /// assert_eq!(claims.jti.as_deref(), Some("my-unique-id"));
    /// ```
    #[must_use]
    pub fn with_jti(mut self, jti: impl Into<String>) -> Self {
        self.jti = Some(jti.into());
        self
    }

    /// Generate and set a random UUID v4 as the `jti` claim.
    ///
    /// This is the recommended way to populate `jti` — each call produces a
    /// globally unique identifier, ensuring no two tokens share the same ID.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::security::auth::Claims;
    ///
    /// let claims = Claims::new("user-1", 3600).with_random_jti();
    /// assert!(claims.jti.is_some());
    /// ```
    #[must_use]
    pub fn with_random_jti(mut self) -> Self {
        self.jti = Some(uuid::Uuid::new_v4().to_string());
        self
    }
}

/// JWT authentication handler — signs and verifies JWTs using a symmetric HMAC key.
///
/// Construct with [`JwtAuth::hs256`] or [`JwtAuth::hs512`], then use
/// [`JwtAuth::sign`] to create tokens and [`JwtAuth::verify`] /
/// [`JwtAuth::verify_bearer`] to validate them.
///
/// `JwtAuth` is cheap to clone — the internal keys are reference-counted.
///
/// # Examples
///
/// ```rust
/// use rttp::security::auth::{Claims, JwtAuth};
///
/// let auth = JwtAuth::hs256(b"my-secret");
///
/// let claims = Claims::new("user-99", 3600);
/// let token = auth.sign(&claims).unwrap();
///
/// let verified: Claims = auth.verify(&token).unwrap();
/// assert_eq!(verified.sub, "user-99");
/// ```
#[derive(Clone)]
pub struct JwtAuth {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    algorithm: Algorithm,
    validation: Validation,
}

impl JwtAuth {
    /// Create a `JwtAuth` using **HMAC-SHA256** with the given secret.
    ///
    /// HS256 is widely supported and appropriate for most applications where
    /// the signing and verifying party are the same service.
    ///
    /// # Arguments
    ///
    /// - `secret` — any byte sequence; prefer at least 32 random bytes.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::security::auth::JwtAuth;
    ///
    /// let auth = JwtAuth::hs256(b"change-me-in-production");
    /// ```
    pub fn hs256(secret: impl AsRef<[u8]>) -> Self {
        let secret = secret.as_ref();
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;
        Self {
            encoding_key: EncodingKey::from_secret(secret),
            decoding_key: DecodingKey::from_secret(secret),
            algorithm: Algorithm::HS256,
            validation,
        }
    }

    /// Create a `JwtAuth` using **HMAC-SHA512** with the given secret.
    ///
    /// HS512 produces a larger signature and provides a higher security margin
    /// than HS256.
    ///
    /// # Arguments
    ///
    /// - `secret` — any byte sequence; prefer at least 64 random bytes.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::security::auth::JwtAuth;
    ///
    /// let auth = JwtAuth::hs512(b"a-very-long-secret-for-hs512");
    /// ```
    pub fn hs512(secret: impl AsRef<[u8]>) -> Self {
        let secret = secret.as_ref();
        let mut validation = Validation::new(Algorithm::HS512);
        validation.validate_exp = true;
        Self {
            encoding_key: EncodingKey::from_secret(secret),
            decoding_key: DecodingKey::from_secret(secret),
            algorithm: Algorithm::HS512,
            validation,
        }
    }

    /// Sign a claims value and return the compact JWT string.
    ///
    /// `C` can be any `Serialize` type — use [`Claims`] for the standard fields
    /// or your own struct that embeds additional application-specific data.
    ///
    /// # Errors
    ///
    /// Returns [`JwtError::Invalid`] if serialization or signing fails.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::security::auth::{Claims, JwtAuth};
    ///
    /// let auth = JwtAuth::hs256(b"secret");
    /// let token = auth.sign(&Claims::new("alice", 600)).unwrap();
    /// assert!(!token.is_empty());
    /// ```
    pub fn sign<C: Serialize>(&self, claims: &C) -> Result<String, JwtError> {
        encode(&Header::new(self.algorithm), claims, &self.encoding_key).map_err(JwtError::Invalid)
    }

    /// Verify and decode a raw JWT string.
    ///
    /// Validates the signature, the `exp` claim (token must not have expired),
    /// and the algorithm. Returns the decoded claims on success.
    ///
    /// # Errors
    ///
    /// Returns [`JwtError::Invalid`] if the token is malformed, the signature
    /// does not match, or the token has expired.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::security::auth::{Claims, JwtAuth};
    ///
    /// let auth = JwtAuth::hs256(b"secret");
    /// let token = auth.sign(&Claims::new("bob", 600)).unwrap();
    /// let decoded: Claims = auth.verify(&token).unwrap();
    /// assert_eq!(decoded.sub, "bob");
    /// ```
    pub fn verify<C: for<'de> Deserialize<'de>>(&self, token: &str) -> Result<C, JwtError> {
        decode::<C>(token, &self.decoding_key, &self.validation)
            .map(|data| data.claims)
            .map_err(JwtError::Invalid)
    }

    /// Extract and verify the bearer token from an `Authorization` header value.
    ///
    /// The header value must be of the form `Bearer <token>` (case-sensitive
    /// prefix), as sent by browsers and API clients following [RFC 6750].
    ///
    /// [RFC 6750]: https://www.rfc-editor.org/rfc/rfc6750
    ///
    /// # Errors
    ///
    /// - [`JwtError::MalformedHeader`] — the value does not start with `Bearer `.
    /// - [`JwtError::Invalid`] — the extracted token is invalid or expired.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::security::auth::{Claims, JwtAuth};
    ///
    /// let auth = JwtAuth::hs256(b"secret");
    /// let token = auth.sign(&Claims::new("charlie", 600)).unwrap();
    /// let header = format!("Bearer {token}");
    ///
    /// let decoded: Claims = auth.verify_bearer(&header).unwrap();
    /// assert_eq!(decoded.sub, "charlie");
    /// ```
    pub fn verify_bearer<C: for<'de> Deserialize<'de>>(
        &self,
        authorization: &str,
    ) -> Result<C, JwtError> {
        let token = authorization
            .strip_prefix("Bearer ")
            .ok_or(JwtError::MalformedHeader)?;
        self.verify(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hs256() -> JwtAuth {
        JwtAuth::hs256(b"test-secret-for-unit-tests")
    }

    // ── Claims ────────────────────────────────────────────────────────────────

    #[test]
    fn claims_new_sets_sub_and_future_exp() {
        let c = Claims::new("u1", 3600);
        assert_eq!(c.sub, "u1");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(c.exp > now);
        assert!(c.exp <= now + 3601);
    }

    #[test]
    fn claims_issuer_sets_iss() {
        let c = Claims::new("u1", 60).issuer("svc");
        assert_eq!(c.iss.as_deref(), Some("svc"));
    }

    #[test]
    fn claims_default_iss_is_none() {
        let c = Claims::new("u1", 60);
        assert!(c.iss.is_none());
    }

    // ── Sign / Verify ─────────────────────────────────────────────────────────

    #[test]
    fn sign_and_verify_roundtrip() {
        let auth = hs256();
        let claims = Claims::new("alice", 3600);
        let token = auth.sign(&claims).unwrap();
        let decoded: Claims = auth.verify(&token).unwrap();
        assert_eq!(decoded.sub, "alice");
    }

    #[test]
    fn wrong_secret_fails_verification() {
        let signer = JwtAuth::hs256(b"secret-a");
        let verifier = JwtAuth::hs256(b"secret-b");

        let token = signer.sign(&Claims::new("alice", 3600)).unwrap();
        assert!(verifier.verify::<Claims>(&token).is_err());
    }

    #[test]
    fn wrong_algorithm_fails_verification() {
        let signer = JwtAuth::hs256(b"shared");
        let verifier = JwtAuth::hs512(b"shared");

        let token = signer.sign(&Claims::new("alice", 3600)).unwrap();
        assert!(verifier.verify::<Claims>(&token).is_err());
    }

    #[test]
    fn garbage_token_returns_error() {
        let auth = hs256();
        assert!(auth.verify::<Claims>("not.a.jwt").is_err());
    }

    // ── verify_bearer ─────────────────────────────────────────────────────────

    #[test]
    fn verify_bearer_strips_prefix_and_verifies() {
        let auth = hs256();
        let token = auth.sign(&Claims::new("bob", 3600)).unwrap();
        let header = format!("Bearer {token}");
        let decoded: Claims = auth.verify_bearer(&header).unwrap();
        assert_eq!(decoded.sub, "bob");
    }

    #[test]
    fn verify_bearer_missing_prefix_returns_malformed_header() {
        let auth = hs256();
        let token = auth.sign(&Claims::new("bob", 3600)).unwrap();
        let err = auth.verify_bearer::<Claims>(&token).unwrap_err();
        assert!(matches!(err, JwtError::MalformedHeader));
    }

    #[test]
    fn verify_bearer_wrong_prefix_case_returns_malformed_header() {
        let auth = hs256();
        let token = auth.sign(&Claims::new("bob", 3600)).unwrap();
        let header = format!("bearer {token}");
        assert!(matches!(
            auth.verify_bearer::<Claims>(&header).unwrap_err(),
            JwtError::MalformedHeader
        ));
    }
}
