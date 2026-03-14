//! HTTP/1.1 request parsing using the [`httparse`] crate.
//!
//! This module exposes [`Request`], a fully parsed representation of an incoming HTTP/1.1
//! request, along with [`RequestError`] for parse failures. Parsing is zero-copy where
//! possible: headers are validated in-place by `httparse` and the body is captured as a
//! [`bytes::Bytes`] slice of the original buffer.

use std::collections::HashMap;

use bytes::Bytes;
use thiserror::Error;

use super::{Headers, Method};

/// Errors that can occur while parsing an HTTP/1.1 request.
#[derive(Debug, Error)]
pub enum RequestError {
    /// The buffer ends before the header terminator (`\r\n\r\n`); more data is needed.
    #[error("request is incomplete — more data needed")]
    Incomplete,

    /// The data is structurally malformed and cannot be parsed by `httparse`.
    #[error("HTTP parse error: {0}")]
    Parse(#[from] httparse::Error),

    /// A required HTTP field (method, path, or version) was absent from the request.
    #[error("missing required field: {field}")]
    MissingField { field: &'static str },

    /// The declared `Content-Length` exceeds the configured body size limit.
    #[error("request body exceeds maximum allowed size of {max_bytes} bytes")]
    BodyTooLarge { max_bytes: usize },
}

/// A fully parsed HTTP/1.1 request.
///
/// Created by [`Request::parse`] from a raw byte buffer. The body is stored
/// as a [`Bytes`] buffer.
///
/// # Examples
///
/// ```
/// use rttp::http::request::Request;
///
/// let raw = b"GET /hello?name=world HTTP/1.1\r\nHost: localhost\r\n\r\n";
/// let (request, _offset) = Request::parse(raw).unwrap();
///
/// assert_eq!(request.method().as_str(), "GET");
/// assert_eq!(request.path(), "/hello");
/// assert_eq!(request.query_param("name"), Some("world"));
/// assert_eq!(request.headers().get("host"), Some("localhost"));
/// ```
#[derive(Debug)]
pub struct Request {
    method: Method,
    path: String,
    /// HTTP minor version: 0 for HTTP/1.0, 1 for HTTP/1.1.
    version: u8,
    headers: Headers,
    query: Option<String>,
    body: Bytes,
    params: HashMap<String, String>,
}

impl Request {
    /// Maximum number of headers we support per request.
    const MAX_HEADERS: usize = 64;

    /// Parse a raw HTTP/1.1 request from a byte slice.
    ///
    /// Returns the parsed `Request` and the byte offset at which the body begins
    /// in `buf` (i.e. immediately after the `\r\n\r\n` header terminator).
    ///
    /// # Errors
    ///
    /// - [`RequestError::Incomplete`] — more data is needed to complete the request headers.
    /// - [`RequestError::Parse`] — the data is malformed and cannot be parsed.
    /// - [`RequestError::MissingField`] — a required field (method, path, version) is absent.
    pub fn parse(buf: &[u8]) -> Result<(Self, usize), RequestError> {
        let mut headers = [httparse::EMPTY_HEADER; Self::MAX_HEADERS];
        let mut raw_req = httparse::Request::new(&mut headers);

        let body_offset = match raw_req.parse(buf)? {
            httparse::Status::Complete(offset) => offset,
            httparse::Status::Partial => return Err(RequestError::Incomplete),
        };

        let method: Method = raw_req
            .method
            .ok_or(RequestError::MissingField { field: "method" })?
            .parse()
            .unwrap();

        let raw_path = raw_req
            .path
            .ok_or(RequestError::MissingField { field: "path" })?;

        let (path, query) = match raw_path.find('?') {
            Some(pos) => (
                raw_path[..pos].to_owned(),
                Some(raw_path[pos + 1..].to_owned()),
            ),
            None => (raw_path.to_owned(), None),
        };

        let version = raw_req
            .version
            .ok_or(RequestError::MissingField { field: "version" })?;

        let mut header_map = Headers::with_capacity(raw_req.headers.len());
        for header in raw_req.headers.iter() {
            if let Ok(value) = std::str::from_utf8(header.value) {
                header_map.insert(header.name, value);
            }
        }

        let params = query.as_deref().map(parse_query_string).unwrap_or_default();

        let content_length = header_map
            .get("content-length")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(0);
        let body_end = body_offset + content_length;
        let body = Bytes::copy_from_slice(&buf[body_offset..body_end.min(buf.len())]);

        Ok((
            Self {
                method,
                path,
                version,
                headers: header_map,
                query,
                body,
                params,
            },
            body_offset,
        ))
    }

    /// Returns the HTTP method.
    pub fn method(&self) -> &Method {
        &self.method
    }

    /// Returns the request path (without the query string).
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the HTTP minor version number (0 = HTTP/1.0, 1 = HTTP/1.1).
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Returns the request headers.
    pub fn headers(&self) -> &Headers {
        &self.headers
    }

    /// Returns a mutable reference to the request headers.
    pub fn headers_mut(&mut self) -> &mut Headers {
        &mut self.headers
    }

    /// Replaces the request path.
    ///
    /// # Arguments
    ///
    /// - `path` — the new path string; typically set by router middleware after stripping a prefix.
    pub fn set_path(&mut self, path: impl Into<String>) {
        self.path = path.into();
    }

    /// Returns the raw query string (without the leading `?`), if any.
    pub fn query_string(&self) -> Option<&str> {
        self.query.as_deref()
    }

    /// Returns a parsed query parameter value by key.
    ///
    /// # Arguments
    ///
    /// - `key` — the query parameter name (case-sensitive, `+`-decoded).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::http::request::Request;
    ///
    /// let raw = b"GET /search?q=rust+lang HTTP/1.1\r\nHost: localhost\r\n\r\n";
    /// let (req, _) = Request::parse(raw).unwrap();
    /// assert_eq!(req.query_param("q"), Some("rust lang"));
    /// assert_eq!(req.query_param("missing"), None);
    /// ```
    pub fn query_param(&self, key: &str) -> Option<&str> {
        self.params.get(key).map(String::as_str)
    }

    /// Returns an iterator over all parsed query parameters as `(key, value)` pairs.
    ///
    /// The iteration order is unspecified (backed by a `HashMap`).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::http::request::Request;
    ///
    /// let raw = b"GET /?a=1&b=2 HTTP/1.1\r\nHost: localhost\r\n\r\n";
    /// let (req, _) = Request::parse(raw).unwrap();
    /// let mut pairs: Vec<_> = req.query_params().collect();
    /// pairs.sort();
    /// assert_eq!(pairs, vec![("a", "1"), ("b", "2")]);
    /// ```
    pub fn query_params(&self) -> impl Iterator<Item = (&str, &str)> {
        self.params.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Returns the request body bytes.
    pub fn body(&self) -> &Bytes {
        &self.body
    }

    /// Returns `true` if the connection should be kept alive after this request.
    ///
    /// HTTP/1.1 defaults to keep-alive. HTTP/1.0 defaults to close unless
    /// `Connection: keep-alive` is explicitly set.
    pub fn is_keep_alive(&self) -> bool {
        match self.headers.get("connection") {
            Some(conn) => conn.eq_ignore_ascii_case("keep-alive"),
            None => self.version == 1, // HTTP/1.1 default: keep-alive
        }
    }

    /// Returns the value of the `Content-Length` header parsed as a `usize`, if present.
    pub fn content_length(&self) -> Option<usize> {
        self.headers.get("content-length")?.parse().ok()
    }
}

/// Parses a URL query string (`key=value&key2=value2`) into a `HashMap`.
///
/// Keys and values have `+` decoded as a space. Full percent-decoding is
/// intentionally omitted here; it will be added with the `percent-encoding`
/// crate when the `context` module is implemented.
fn parse_query_string(query: &str) -> HashMap<String, String> {
    query
        .split('&')
        .filter_map(|pair| {
            let mut parts = pair.splitn(2, '=');
            let key = parts.next()?.replace('+', " ");
            let value = parts.next().unwrap_or("").replace('+', " ");
            Some((key, value))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_get() {
        let raw = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let (req, offset) = Request::parse(raw).unwrap();
        assert_eq!(req.method().as_str(), "GET");
        assert_eq!(req.path(), "/");
        assert_eq!(req.version(), 1);
        assert_eq!(req.headers().get("host"), Some("localhost"));
        assert_eq!(offset, raw.len()); // no body
    }

    #[test]
    fn parse_query_string() {
        let raw = b"GET /search?q=rust&page=2 HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let (req, _) = Request::parse(raw).unwrap();
        assert_eq!(req.path(), "/search");
        assert_eq!(req.query_string(), Some("q=rust&page=2"));
        assert_eq!(req.query_param("q"), Some("rust"));
        assert_eq!(req.query_param("page"), Some("2"));
    }

    #[test]
    fn incomplete_request() {
        let raw = b"GET / HTTP/1.1\r\nHost:";
        assert!(matches!(Request::parse(raw), Err(RequestError::Incomplete)));
    }

    #[test]
    fn keep_alive_http11_default() {
        let raw = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let (req, _) = Request::parse(raw).unwrap();
        assert!(req.is_keep_alive());
    }

    #[test]
    fn connection_close() {
        let raw = b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        let (req, _) = Request::parse(raw).unwrap();
        assert!(!req.is_keep_alive());
    }

    #[test]
    fn content_length() {
        let raw = b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nhello";
        let (req, body_offset) = Request::parse(raw).unwrap();
        assert_eq!(req.content_length(), Some(5));
        assert_eq!(&raw[body_offset..], b"hello");
    }
}
