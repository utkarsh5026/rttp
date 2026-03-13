//! HTTP response status codes.
//!
//! This module defines the [`StatusCode`] enum, which represents standard HTTP/1.1
//! status codes as defined in RFC 9110. Each variant maps directly to its numeric
//! value and provides access to the canonical reason phrase.

use std::fmt;

/// An HTTP response status code.
///
/// Covers the most commonly used status codes across the 1xx–5xx ranges.
/// Each variant is `repr(u16)` so it can be cast to its numeric value directly.
///
/// # Examples
///
/// ```
/// use rttp::http::StatusCode;
///
/// let status = StatusCode::Ok;
/// assert_eq!(status.as_u16(), 200);
/// assert_eq!(status.canonical_reason(), "OK");
/// assert_eq!(format!("{status}"), "200 OK");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum StatusCode {
    /// The server has received the request headers and the client should proceed.
    Continue = 100,
    /// The server is switching to the protocol specified in the `Upgrade` header.
    SwitchingProtocols = 101,

    /// The request succeeded.
    Ok = 200,
    /// The request succeeded and a new resource was created.
    Created = 201,
    /// The request has been accepted for processing, but processing has not completed.
    Accepted = 202,
    /// The request succeeded but the response carries no body.
    NoContent = 204,
    /// The server is delivering only part of the resource due to a range request.
    PartialContent = 206,

    // 3xx Redirection
    /// The resource has been permanently moved to a new URL.
    MovedPermanently = 301,
    /// The resource has been temporarily moved to a different URL.
    Found = 302,
    /// The response to the request can be found at another URI using `GET`.
    SeeOther = 303,
    /// The resource has not been modified since the version specified in the request headers.
    NotModified = 304,
    /// The resource resides temporarily at a different URI; repeat with the same method.
    TemporaryRedirect = 307,
    /// The resource has been permanently moved; future requests should use the new URI.
    PermanentRedirect = 308,

    /// The server cannot process the request due to a client error (e.g., malformed syntax).
    BadRequest = 400,
    /// Authentication is required and has failed or has not been provided.
    Unauthorized = 401,
    /// The client does not have permission to access the requested resource.
    Forbidden = 403,
    /// The requested resource could not be found.
    NotFound = 404,
    /// The HTTP method used is not allowed for the requested resource.
    MethodNotAllowed = 405,
    /// The request conflicts with the current state of the target resource.
    Conflict = 409,
    /// The requested resource is no longer available and will not be available again.
    Gone = 410,
    /// The `Content-Length` header field is required but was not defined.
    LengthRequired = 411,
    /// The request body is larger than the server is willing or able to process.
    PayloadTooLarge = 413,
    /// The URI provided was too long for the server to process.
    UriTooLong = 414,
    /// The media format of the request data is not supported by the server.
    UnsupportedMediaType = 415,
    /// The request was well-formed but could not be followed due to semantic errors.
    UnprocessableEntity = 422,
    /// The server timed out waiting for the request.
    RequestTimeout = 408,
    /// The client has sent too many requests in a given amount of time.
    TooManyRequests = 429,

    /// The server encountered an unexpected condition that prevented it from fulfilling the request.
    InternalServerError = 500,
    /// The server does not support the functionality required to fulfill the request.
    NotImplemented = 501,
    /// The server received an invalid response from an upstream server.
    BadGateway = 502,
    /// The server is temporarily unavailable, usually due to maintenance or overload.
    ServiceUnavailable = 503,
    /// The upstream server failed to send a response in time.
    GatewayTimeout = 504,
    /// The server does not support the HTTP protocol version used in the request.
    HttpVersionNotSupported = 505,
}

impl StatusCode {
    /// Returns the numeric status code as a `u16`.
    ///
    /// # Examples
    ///
    /// ```
    /// use rttp::http::StatusCode;
    ///
    /// assert_eq!(StatusCode::Ok.as_u16(), 200);
    /// assert_eq!(StatusCode::NotFound.as_u16(), 404);
    /// assert_eq!(StatusCode::InternalServerError.as_u16(), 500);
    /// ```
    pub fn as_u16(self) -> u16 {
        self as u16
    }

    /// Returns the canonical reason phrase for this status code.
    ///
    /// Reason phrases follow RFC 9110 §15.
    ///
    /// # Examples
    ///
    /// ```
    /// use rttp::http::StatusCode;
    ///
    /// assert_eq!(StatusCode::Ok.canonical_reason(), "OK");
    /// assert_eq!(StatusCode::NotFound.canonical_reason(), "Not Found");
    /// assert_eq!(StatusCode::ServiceUnavailable.canonical_reason(), "Service Unavailable");
    /// ```
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
            Self::RequestTimeout => "Request Timeout",
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
