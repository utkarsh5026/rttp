//! HTTP/1.1 protocol types and parsing.
//!
//! This module provides the core HTTP primitives:
//! [`Method`], [`StatusCode`], [`Headers`], [`Request`], and [`Response`].

use std::fmt;

pub mod headers;
pub mod request;
pub mod response;

pub use headers::Headers;
pub use request::Request;
pub use response::Response;

/// An HTTP response status code.
///
/// # Examples
///
/// ```
/// use rttp::http::StatusCode;
///
/// let status = StatusCode::Ok;
/// assert_eq!(status.as_u16(), 200);
/// assert_eq!(status.canonical_reason(), "OK");
/// assert!(status.is_success());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum StatusCode {
    // 1xx Informational
    Continue = 100,
    SwitchingProtocols = 101,

    // 2xx Success
    Ok = 200,
    Created = 201,
    Accepted = 202,
    NoContent = 204,
    PartialContent = 206,

    // 3xx Redirection
    MovedPermanently = 301,
    Found = 302,
    SeeOther = 303,
    NotModified = 304,
    TemporaryRedirect = 307,
    PermanentRedirect = 308,

    // 4xx Client Error
    BadRequest = 400,
    Unauthorized = 401,
    Forbidden = 403,
    NotFound = 404,
    MethodNotAllowed = 405,
    Conflict = 409,
    Gone = 410,
    LengthRequired = 411,
    PayloadTooLarge = 413,
    UriTooLong = 414,
    UnsupportedMediaType = 415,
    UnprocessableEntity = 422,
    TooManyRequests = 429,

    // 5xx Server Error
    InternalServerError = 500,
    NotImplemented = 501,
    BadGateway = 502,
    ServiceUnavailable = 503,
    GatewayTimeout = 504,
    HttpVersionNotSupported = 505,
}

impl StatusCode {
    /// Returns the numeric status code as a `u16`.
    pub fn as_u16(self) -> u16 {
        self as u16
    }

    /// Returns the canonical reason phrase for this status code.
    pub fn canonical_reason(self) -> &'static str {
        match self {
            Self::Continue => "Continue",
            Self::SwitchingProtocols => "Switching Protocols",
            Self::Ok => "OK",
            Self::Created => "Created",
            Self::Accepted => "Accepted",
            Self::NoContent => "No Content",
            Self::PartialContent => "Partial Content",
            Self::MovedPermanently => "Moved Permanently",
            Self::Found => "Found",
            Self::SeeOther => "See Other",
            Self::NotModified => "Not Modified",
            Self::TemporaryRedirect => "Temporary Redirect",
            Self::PermanentRedirect => "Permanent Redirect",
            Self::BadRequest => "Bad Request",
            Self::Unauthorized => "Unauthorized",
            Self::Forbidden => "Forbidden",
            Self::NotFound => "Not Found",
            Self::MethodNotAllowed => "Method Not Allowed",
            Self::Conflict => "Conflict",
            Self::Gone => "Gone",
            Self::LengthRequired => "Length Required",
            Self::PayloadTooLarge => "Payload Too Large",
            Self::UriTooLong => "URI Too Long",
            Self::UnsupportedMediaType => "Unsupported Media Type",
            Self::UnprocessableEntity => "Unprocessable Entity",
            Self::TooManyRequests => "Too Many Requests",
            Self::InternalServerError => "Internal Server Error",
            Self::NotImplemented => "Not Implemented",
            Self::BadGateway => "Bad Gateway",
            Self::ServiceUnavailable => "Service Unavailable",
            Self::GatewayTimeout => "Gateway Timeout",
            Self::HttpVersionNotSupported => "HTTP Version Not Supported",
        }
    }
}

impl fmt::Display for StatusCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.as_u16(), self.canonical_reason())
    }
}

impl From<StatusCode> for u16 {
    fn from(code: StatusCode) -> u16 {
        code.as_u16()
    }
}

/// An HTTP request method.
///
/// Standard methods are represented as unit variants for zero-cost comparison.
/// Non-standard methods are captured in the `Custom` variant.
///
/// # Examples
///
/// ```
/// use rttp::http::Method;
///
/// let method: Method = "GET".parse().unwrap();
/// assert_eq!(method, Method::Get);
/// assert_eq!(method.as_str(), "GET");
/// assert!(method.is_safe());
/// assert!(method.is_idempotent());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Method {
    /// GET — retrieve a representation of the target resource.
    Get,
    /// POST — perform resource-specific processing on the request payload.
    Post,
    /// PUT — replace the target resource's current representation.
    Put,
    /// DELETE — remove the association between the target resource and its functionality.
    Delete,
    /// HEAD — identical to GET but without a response body.
    Head,
    /// OPTIONS — describe the communication options for the target resource.
    Options,
    /// PATCH — apply partial modifications to a resource.
    Patch,
    /// CONNECT — establish a tunnel to the server identified by the target resource.
    Connect,
    /// TRACE — perform a message loop-back test along the path to the target resource.
    Trace,
    /// A non-standard extension method.
    Custom(String),
}

impl Method {
    /// Returns the method as a string slice.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
            Self::Head => "HEAD",
            Self::Options => "OPTIONS",
            Self::Patch => "PATCH",
            Self::Connect => "CONNECT",
            Self::Trace => "TRACE",
            Self::Custom(s) => s.as_str(),
        }
    }

    /// Returns `true` if this method is considered "safe" (no side effects per RFC 9110 §9.2.1).
    ///
    /// Safe methods: GET, HEAD, OPTIONS, TRACE.
    pub fn is_safe(&self) -> bool {
        matches!(self, Self::Get | Self::Head | Self::Options | Self::Trace)
    }

    /// Returns `true` if this method is idempotent (RFC 9110 §9.2.2).
    ///
    /// Idempotent methods: GET, HEAD, PUT, DELETE, OPTIONS, TRACE.
    pub fn is_idempotent(&self) -> bool {
        matches!(
            self,
            Self::Get | Self::Head | Self::Put | Self::Delete | Self::Options | Self::Trace
        )
    }
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Method {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "GET" => Self::Get,
            "POST" => Self::Post,
            "PUT" => Self::Put,
            "DELETE" => Self::Delete,
            "HEAD" => Self::Head,
            "OPTIONS" => Self::Options,
            "PATCH" => Self::Patch,
            "CONNECT" => Self::Connect,
            "TRACE" => Self::Trace,
            other => Self::Custom(other.to_owned()),
        })
    }
}

impl AsRef<str> for Method {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
