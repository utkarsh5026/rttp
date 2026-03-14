//! Authentication — identity verification primitives.
//!
//! | Module       | Status  | Notes                                    |
//! |--------------|---------|------------------------------------------|
//! | [`jwt`]      | Active  | HS256 / HS512 HMAC sign and verify       |
//! | [`api_key`]  | Active  | Static pre-shared API key validation     |
//! | [`password`] | Active  | Argon2id password hashing and verify     |
//! | [`session`]  | Active  | Cookie-backed session store and middleware |
//! | [`oauth`]    | Planned | OIDC / JWKS asymmetric token validation  |

pub mod api_key;
pub mod jwt;
pub mod password;
pub mod session;
#[cfg(feature = "oauth")]
pub mod oauth;

pub use api_key::{ApiKeyIdentity, ApiKeyStore, InMemoryApiKeyStore};
pub use jwt::{Claims, JwtAuth, JwtError};
pub use password::{PasswordError, hash_password, verify_password};
pub use session::{InMemorySessionStore, Session, SessionError, SessionMiddleware, SessionStore};

#[cfg(feature = "oauth")]
pub use oauth::{OAuthClaims, OAuthConfig, OAuthError, OAuthValidator};
