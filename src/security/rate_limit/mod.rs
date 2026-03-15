//! Rate limiting — request throttling and abuse prevention.
//!
//! | Module             | Status | Notes                                    |
//! |--------------------|--------|------------------------------------------|
//! | [`bucket`]         | Active | Token bucket algorithm and configuration |
//! | [`sliding_window`] | Active | Sliding-window counter algorithm         |
//! | [`store`]          | Active | Pluggable rate-limit state backends      |
//!
//! Wire up rate limiting in your middleware stack with
//! [`crate::security::middleware::RateLimitMiddleware`].

pub mod bucket;
pub mod sliding_window;
pub mod store;

pub use bucket::RateLimitConfig;
pub use store::RateLimitStore;
