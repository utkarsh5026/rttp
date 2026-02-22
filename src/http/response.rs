//! HTTP/1.1 response builder.
//!
//! Provides a fluent builder API for constructing HTTP responses and
//! serializing them to a byte buffer for transmission over TCP.

use bytes::{BufMut, BytesMut};

use super::{Headers, StatusCode};

/// An HTTP/1.1 response, ready to be serialized and sent.
///
/// # Examples
///
/// ```
/// use rttp::http::{Response, StatusCode};
///
/// let response = Response::new(StatusCode::Ok)
///     .header("Content-Type", "application/json")
///     .body(r#"{"status":"ok"}"#);
///
/// let bytes = response.into_bytes();
/// let text = std::str::from_utf8(&bytes).unwrap();
/// assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
/// assert!(text.contains("Content-Length: 15\r\n"));
/// ```
#[derive(Debug)]
pub struct Response {
    status: StatusCode,
    headers: Headers,
    body: Vec<u8>,
    keep_alive: bool,
}

impl Response {
    /// Creates a new response with the given status and an empty body.
    pub fn new(status: StatusCode) -> Self {
        Self {
            status,
            headers: Headers::new(),
            body: Vec::new(),
            keep_alive: true,
        }
    }

    /// Appends a response header. Multiple calls with the same name are additive.
    #[must_use]
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(name, value);
        self
    }

    /// Appends a header in-place. Intended for middleware pipelines that receive
    /// a `Response` from downstream and need to decorate it without consuming it.
    pub fn add_header(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.headers.insert(name, value);
    }

    /// Sets the response body from a string.
    ///
    /// The `Content-Length` header is written automatically by [`into_bytes`](Self::into_bytes).
    #[must_use]
    pub fn body(mut self, body: impl Into<String>) -> Self {
        self.body = body.into().into_bytes();
        self
    }

    /// Sets the response body from raw bytes.
    #[must_use]
    pub fn body_bytes(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    /// Controls whether the `Connection: keep-alive` or `Connection: close` header is written.
    #[must_use]
    pub fn keep_alive(mut self, keep_alive: bool) -> Self {
        self.keep_alive = keep_alive;
        self
    }

    /// Returns the status code of this response.
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// Serializes the response into a `BytesMut` buffer using HTTP/1.1 wire format.
    ///
    /// Automatically adds:
    /// - `Content-Type: text/plain; charset=utf-8` if the body is non-empty and no
    ///   `Content-Type` header was set.
    /// - `Content-Length: <n>` (always written).
    /// - `Connection: keep-alive` or `Connection: close`.
    pub fn into_bytes(mut self) -> BytesMut {
        let content_length = self.body.len();

        if !self.body.is_empty() && !self.headers.contains("content-type") {
            self.headers
                .insert("Content-Type", "text/plain; charset=utf-8");
        }

        let connection = if self.keep_alive {
            "keep-alive"
        } else {
            "close"
        };
        self.headers.insert("Connection", connection);

        let estimated_size = 128 + self.headers.len() * 64 + content_length;
        let mut buf = BytesMut::with_capacity(estimated_size);

        // Status line
        buf.put(
            format!(
                "HTTP/1.1 {} {}\r\n",
                self.status.as_u16(),
                self.status.canonical_reason()
            )
            .as_bytes(),
        );

        // Headers
        for (name, value) in self.headers.iter() {
            buf.put(format!("{name}: {value}\r\n").as_bytes());
        }

        // Content-Length is always the last header before the blank line
        buf.put(format!("Content-Length: {content_length}\r\n").as_bytes());

        // Header/body separator
        buf.put(&b"\r\n"[..]);

        // Body
        if !self.body.is_empty() {
            buf.put(self.body.as_slice());
        }

        buf
    }
}

impl Default for Response {
    fn default() -> Self {
        Self::new(StatusCode::Ok)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_string(bytes: BytesMut) -> String {
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[test]
    fn simple_ok_response() {
        let r = Response::new(StatusCode::Ok).body("Hello");
        let s = to_string(r.into_bytes());
        assert!(s.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(s.contains("Content-Length: 5\r\n"));
        assert!(s.ends_with("\r\n\r\nHello"));
    }

    #[test]
    fn custom_header() {
        let r = Response::new(StatusCode::Ok)
            .header("X-Request-Id", "abc-123")
            .body("ok");
        let s = to_string(r.into_bytes());
        assert!(s.contains("X-Request-Id: abc-123\r\n"));
    }

    #[test]
    fn no_body_no_content_type() {
        let r = Response::new(StatusCode::NoContent);
        let s = to_string(r.into_bytes());
        assert!(!s.contains("Content-Type"));
        assert!(s.contains("Content-Length: 0\r\n"));
    }

    #[test]
    fn connection_close() {
        let r = Response::new(StatusCode::Ok).keep_alive(false);
        let s = to_string(r.into_bytes());
        assert!(s.contains("Connection: close\r\n"));
    }

    #[test]
    fn not_found() {
        let r = Response::new(StatusCode::NotFound).body("Not Found");
        let s = to_string(r.into_bytes());
        assert!(s.starts_with("HTTP/1.1 404 Not Found\r\n"));
    }
}
