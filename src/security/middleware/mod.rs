//! Security middleware — per-request authentication, authorization, and hardening.
//!
//! | Module             | Status | Notes                                    |
//! |--------------------|--------|------------------------------------------|
//! | [`cors`]           | Active | CORS header injection and preflight      |
//! | [`jwt`]            | Active | Bearer-token JWT authentication          |
//! | [`api_key`]        | Active | API key header authentication            |
//! | [`csrf`]           | Active | Cross-site request forgery protection    |
//! | [`secure_headers`] | Active | HSTS, CSP, X-Frame-Options, etc.         |
//! | [`ip_filter`]      | Active | IP allowlist / blocklist                 |
//! | [`request_id`]     | Active | Request correlation ID injection         |
//! | [`rate_limit`]     | Active | Token-bucket request throttling          |
//! | [`audit`]          | Active | Security event audit logging             |
//! | [`hmac_verify`]    | Active | HMAC request body signature verification |
//! | [`csp_builder`]    | Active | Typed Content Security Policy builder    |

pub(super) mod util;
#[cfg(test)]
pub(crate) mod test_helpers;

pub mod api_key;
pub mod audit;
pub mod cors;
pub mod csp_builder;
pub mod csrf;
pub mod hmac_verify;
pub mod ip_filter;
pub mod jwt;
#[cfg(feature = "oauth")]
pub mod oauth;
pub mod rate_limit;
pub mod request_id;
pub mod secure_headers;

pub use api_key::ApiKeyMiddleware;
pub use audit::AuditMiddleware;
pub use cors::{CorsHeader, CorsMiddleware, CorsOrigin};
pub use csp_builder::CspBuilder;
pub use csrf::CsrfMiddleware;
pub use hmac_verify::HmacVerifyMiddleware;
pub use ip_filter::IpFilterMiddleware;
pub use jwt::JwtMiddleware;
#[cfg(feature = "oauth")]
pub use oauth::OAuthMiddleware;
pub use rate_limit::RateLimitMiddleware;
pub use request_id::RequestIdMiddleware;
pub use secure_headers::SecureHeadersMiddleware;
