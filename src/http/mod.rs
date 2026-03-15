//! HTTP/1.1 protocol types and parsing.
//!
//! This module provides the core HTTP primitives:
//! [`Method`], [`StatusCode`], [`Headers`], [`Request`], [`Response`],
//! [`Cookie`], and [`CookieJar`].

pub mod cookie;
pub mod headers;
pub mod method;
pub mod query;
pub mod request;
pub mod response;
pub mod status;

pub use cookie::{Cookie, CookieJar};
pub use headers::Headers;
pub use method::Method;
pub use query::QueryParams;
pub use request::Request;
pub use response::Response;
pub use status::StatusCode;
