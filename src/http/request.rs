//! HTTP/1.1 request parsing using the [`httparse`] crate.
//!
//! This module exposes [`Request`], a fully parsed representation of an incoming HTTP/1.1
//! request, along with [`RequestError`] for parse failures. Parsing is zero-copy where
//! possible: headers are validated in-place by `httparse` and the body is captured as a
//! [`bytes::Bytes`] slice of the original buffer.

use bytes::Bytes;
use serde::de::DeserializeOwned;
use thiserror::Error;

use super::cookie::CookieJar;
use super::query::QueryParams;
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

    /// The `Content-Type` header is missing on a request that requires it.
    #[error("missing Content-Type header")]
    MissingContentType,

    /// The `Content-Type` header does not match the expected media type.
    #[error("invalid content type: expected {expected}, got {actual}")]
    InvalidContentType { expected: String, actual: String },

    /// The request body could not be deserialized as JSON.
    #[error("JSON parse error: {0}")]
    InvalidJson(#[from] serde_json::Error),

    /// The request body could not be deserialized as URL-encoded form data.
    #[error("form parse error: {0}")]
    InvalidForm(#[from] serde_urlencoded::de::Error),
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
    raw_query: Option<String>,
    body: Bytes,
    query: QueryParams,
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

        let (path, raw_query) = match raw_path.find('?') {
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

        let query = raw_query
            .as_deref()
            .map(QueryParams::parse)
            .unwrap_or_else(QueryParams::empty);

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
                raw_query,
                body,
                query,
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
        self.raw_query.as_deref()
    }

    /// Returns the parsed query parameters.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::http::request::Request;
    ///
    /// let raw = b"GET /search?tag=rust&tag=async HTTP/1.1\r\nHost: localhost\r\n\r\n";
    /// let (req, _) = Request::parse(raw).unwrap();
    /// assert_eq!(req.query().get("tag"), Some("rust"));
    /// assert_eq!(req.query().get_all("tag"), &["rust", "async"]);
    /// ```
    pub fn query(&self) -> &QueryParams {
        &self.query
    }

    /// Returns a parsed query parameter value by key (first value if multi-valued).
    ///
    /// Convenience method that delegates to [`QueryParams::get`].
    ///
    /// # Arguments
    ///
    /// - `key` — the query parameter name (case-sensitive, percent-decoded).
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
        self.query.get(key)
    }

    /// Returns an iterator over all parsed query parameters as `(key, value)` pairs.
    ///
    /// For multi-valued keys, each value is yielded as a separate pair.
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
        self.query.iter()
    }

    /// Returns the request body bytes.
    pub fn body(&self) -> &Bytes {
        &self.body
    }

    /// Deserializes the request body as JSON.
    ///
    /// Checks that `Content-Type` is `application/json` before parsing. This method
    /// borrows the body and can be called multiple times (re-parses each time).
    ///
    /// # Errors
    ///
    /// - [`RequestError::MissingContentType`] — no `Content-Type` header present.
    /// - [`RequestError::InvalidContentType`] — `Content-Type` is not `application/json`.
    /// - [`RequestError::InvalidJson`] — the body is not valid JSON or does not match `T`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::http::request::Request;
    /// use serde::Deserialize;
    ///
    /// #[derive(Deserialize)]
    /// struct Payload { name: String }
    ///
    /// let raw = b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 16\r\n\r\n{\"name\":\"world\"}";
    /// let (req, _) = Request::parse(raw).unwrap();
    /// let payload: Payload = req.json().unwrap();
    /// assert_eq!(payload.name, "world");
    /// ```
    pub fn json<T: DeserializeOwned>(&self) -> Result<T, RequestError> {
        self.expect_content_type("application/json")?;
        Ok(serde_json::from_slice(&self.body)?)
    }

    /// Deserializes the request body as URL-encoded form data.
    ///
    /// Checks that `Content-Type` is `application/x-www-form-urlencoded` before parsing.
    /// This method borrows the body and can be called multiple times.
    ///
    /// # Errors
    ///
    /// - [`RequestError::MissingContentType`] — no `Content-Type` header present.
    /// - [`RequestError::InvalidContentType`] — wrong `Content-Type`.
    /// - [`RequestError::InvalidForm`] — the body is not valid form data or does not match `T`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::http::request::Request;
    /// use serde::Deserialize;
    ///
    /// #[derive(Deserialize)]
    /// struct Login { user: String, pass: String }
    ///
    /// let raw = b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 19\r\n\r\nuser=admin&pass=123";
    /// let (req, _) = Request::parse(raw).unwrap();
    /// let login: Login = req.form().unwrap();
    /// assert_eq!(login.user, "admin");
    /// assert_eq!(login.pass, "123");
    /// ```
    pub fn form<T: DeserializeOwned>(&self) -> Result<T, RequestError> {
        self.expect_content_type("application/x-www-form-urlencoded")?;
        Ok(serde_urlencoded::from_bytes(&self.body)?)
    }

    /// Parses the `Cookie` request header into a [`CookieJar`].
    ///
    /// Returns an empty jar if no `Cookie` header is present.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::http::request::Request;
    ///
    /// let raw = b"GET / HTTP/1.1\r\nHost: localhost\r\nCookie: session=abc; theme=dark\r\n\r\n";
    /// let (req, _) = Request::parse(raw).unwrap();
    /// let cookies = req.cookies();
    /// assert_eq!(cookies.get("session"), Some("abc"));
    /// assert_eq!(cookies.get("theme"), Some("dark"));
    /// ```
    pub fn cookies(&self) -> CookieJar {
        match self.headers.get("cookie") {
            Some(header) => CookieJar::parse(header),
            None => CookieJar::default(),
        }
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

    /// Validates that the `Content-Type` header matches the expected media type.
    ///
    /// Comparison ignores parameters (e.g. `; charset=utf-8`) and is case-insensitive.
    fn expect_content_type(&self, expected: &str) -> Result<(), RequestError> {
        let actual = self
            .headers
            .get("content-type")
            .ok_or(RequestError::MissingContentType)?;

        let media_type = actual.split(';').next().unwrap_or(actual).trim();

        if !media_type.eq_ignore_ascii_case(expected) {
            return Err(RequestError::InvalidContentType {
                expected: expected.to_owned(),
                actual: media_type.to_owned(),
            });
        }

        Ok(())
    }
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
    fn parse_query_string_simple() {
        let raw = b"GET /search?q=rust&page=2 HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let (req, _) = Request::parse(raw).unwrap();
        assert_eq!(req.path(), "/search");
        assert_eq!(req.query_string(), Some("q=rust&page=2"));
        assert_eq!(req.query_param("q"), Some("rust"));
        assert_eq!(req.query_param("page"), Some("2"));
    }

    #[test]
    fn parse_query_multi_value() {
        let raw = b"GET /items?tag=a&tag=b&tag=c HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let (req, _) = Request::parse(raw).unwrap();
        assert_eq!(req.query_param("tag"), Some("a"));
        assert_eq!(req.query().get_all("tag"), &["a", "b", "c"]);
    }

    #[test]
    fn parse_query_percent_encoded() {
        let raw = b"GET /search?q=hello%20world HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let (req, _) = Request::parse(raw).unwrap();
        assert_eq!(req.query_param("q"), Some("hello world"));
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

    #[test]
    fn json_body_parsing() {
        #[derive(serde::Deserialize, Debug, PartialEq)]
        struct Msg {
            text: String,
        }

        let raw = b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 16\r\n\r\n{\"text\":\"hello\"}";
        let (req, _) = Request::parse(raw).unwrap();
        let msg: Msg = req.json().unwrap();
        assert_eq!(
            msg,
            Msg {
                text: "hello".into()
            }
        );
    }

    #[test]
    fn json_wrong_content_type() {
        let raw = b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\n{}";
        let (req, _) = Request::parse(raw).unwrap();
        let err = req.json::<serde_json::Value>().unwrap_err();
        assert!(matches!(err, RequestError::InvalidContentType { .. }));
    }

    #[test]
    fn json_missing_content_type() {
        let raw = b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\n\r\n{}";
        let (req, _) = Request::parse(raw).unwrap();
        let err = req.json::<serde_json::Value>().unwrap_err();
        assert!(matches!(err, RequestError::MissingContentType));
    }

    #[test]
    fn json_content_type_with_charset() {
        let raw = b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: 2\r\n\r\n{}";
        let (req, _) = Request::parse(raw).unwrap();
        let val: serde_json::Value = req.json().unwrap();
        assert_eq!(val, serde_json::json!({}));
    }

    #[test]
    fn form_body_parsing() {
        #[derive(serde::Deserialize, Debug, PartialEq)]
        struct Login {
            user: String,
            pass: String,
        }

        let raw = b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 19\r\n\r\nuser=admin&pass=123";
        let (req, _) = Request::parse(raw).unwrap();
        let login: Login = req.form().unwrap();
        assert_eq!(
            login,
            Login {
                user: "admin".into(),
                pass: "123".into(),
            }
        );
    }

    #[test]
    fn form_wrong_content_type() {
        let raw = b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 5\r\n\r\na=1&b";
        let (req, _) = Request::parse(raw).unwrap();
        let err = req
            .form::<std::collections::HashMap<String, String>>()
            .unwrap_err();
        assert!(matches!(err, RequestError::InvalidContentType { .. }));
    }

    #[test]
    fn cookies_parsing() {
        let raw = b"GET / HTTP/1.1\r\nHost: localhost\r\nCookie: session=abc; theme=dark\r\n\r\n";
        let (req, _) = Request::parse(raw).unwrap();
        let cookies = req.cookies();
        assert_eq!(cookies.get("session"), Some("abc"));
        assert_eq!(cookies.get("theme"), Some("dark"));
    }

    #[test]
    fn cookies_empty_when_no_header() {
        let raw = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let (req, _) = Request::parse(raw).unwrap();
        let cookies = req.cookies();
        assert!(cookies.is_empty());
    }

    #[test]
    fn no_query_returns_empty_params() {
        let raw = b"GET /path HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let (req, _) = Request::parse(raw).unwrap();
        assert!(req.query().is_empty());
        assert_eq!(req.query_string(), None);
    }
}
