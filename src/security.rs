//! Security — public API re-exports.
//!
//! | Module         | Status  | Notes                                          |
//! |----------------|---------|------------------------------------------------|
//! | [`auth`]       | Active  | JWT, API key, and OAuth authentication         |
//! | [`middleware`] | Active  | CORS, JWT, CSRF, and other HTTP middleware      |
//! | [`rate_limit`] | Active  | Token bucket and sliding-window rate limiting  |
//! | [`token`]      | Active  | Token revocation and brute-force protection    |

pub mod auth;
pub mod middleware;
pub mod rate_limit;
pub mod token;

pub use auth::{Claims, JwtAuth, JwtError};
pub use middleware::{
    AuditMiddleware, CorsHeader, CorsMiddleware, CorsOrigin, CspBuilder, HmacVerifyMiddleware,
    JwtMiddleware,
};

#[cfg(feature = "oauth")]
pub use auth::{OAuthClaims, OAuthConfig, OAuthError, OAuthValidator};
#[cfg(feature = "oauth")]
pub use middleware::OAuthMiddleware;
