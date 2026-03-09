//! Authentication — identity verification primitives.
//!
//! | Module      | Status  | Notes                                    |
//! |-------------|---------|------------------------------------------|
//! | [`jwt`]     | Active  | HS256 / HS512 HMAC sign and verify       |
//! | [`api_key`] | Planned | Static pre-shared API key validation     |
//! | [`oauth`]   | Planned | OIDC / JWKS asymmetric token validation  |

pub mod api_key;
pub mod jwt;
pub mod oauth;

pub use api_key::{ApiKeyIdentity, ApiKeyStore, InMemoryApiKeyStore};
pub use jwt::{Claims, JwtAuth, JwtError};
