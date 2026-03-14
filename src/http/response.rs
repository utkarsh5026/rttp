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
    ///
    /// Multiple calls with the same header name are additive (the header is not
    /// overwritten). Use this over [`header`](Self::header) when ownership of
    /// the response cannot be transferred.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::http::{Response, StatusCode};
    ///
    /// let mut response = Response::new(StatusCode::Ok).body("hello");
    /// response.add_header("X-Trace-Id", "abc-123");
    /// ```
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
    ///
    /// Use this instead of [`body`](Self::body) when the payload is already in binary form
    /// (e.g. a PNG image or a pre-encoded MessagePack buffer).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::http::{Response, StatusCode};
    ///
    /// let png_bytes: Vec<u8> = vec![0x89, 0x50, 0x4E, 0x47]; // PNG magic bytes
    /// let response = Response::new(StatusCode::Ok)
    ///     .header("Content-Type", "image/png")
    ///     .body_bytes(png_bytes);
    /// ```
    #[must_use]
    pub fn body_bytes(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    /// Controls whether the `Connection: keep-alive` or `Connection: close` header is written.
    ///
    /// Defaults to `true`. Set to `false` to signal the client that the TCP connection
    /// should be closed after this response is sent.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::http::{Response, StatusCode};
    ///
    /// let response = Response::new(StatusCode::Ok)
    ///     .body("goodbye")
    ///     .keep_alive(false);
    /// ```
    #[must_use]
    pub fn keep_alive(mut self, keep_alive: bool) -> Self {
        self.keep_alive = keep_alive;
        self
    }

    /// Returns the status code of this response.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::http::{Response, StatusCode};
    ///
    /// let response = Response::new(StatusCode::Created);
    /// assert_eq!(response.status(), StatusCode::Created);
    /// ```
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
        self.headers.set("Connection", connection);

        self.headers
            .set("Content-Length", content_length.to_string());

        let estimated_size = 128 + self.headers.len() * 64 + content_length;
        let mut buf = BytesMut::with_capacity(estimated_size);
        buf.put(
            format!(
                "HTTP/1.1 {} {}\r\n",
                self.status.as_u16(),
                self.status.canonical_reason()
            )
            .as_bytes(),
        );
        
        for (name, value) in self.headers.iter() {
            buf.put(format!("{name}: {value}\r\n").as_bytes());
        }

        buf.put(&b"\r\n"[..]);
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


/// Trait for types that can be converted into an HTTP [`Response`].
///
/// This enables handlers to return ergonomic types like `&str`, `String`,
/// `Json<T>`, or `(StatusCode, T)` instead of manually constructing a
/// `Response` every time.
///
/// # Examples
///
/// ```rust,no_run
/// use rttp::{Response, StatusCode};
/// use rttp::http::response::IntoResponse;
///
/// // All of these are valid handler return types:
/// async fn text() -> &'static str { "hello" }
/// async fn string() -> String { "hello".to_string() }
/// async fn with_status() -> (StatusCode, &'static str) { (StatusCode::NotFound, "not found") }
/// async fn response() -> Response { Response::new(StatusCode::Ok) }
/// ```
pub trait IntoResponse {
    /// Convert this value into an HTTP [`Response`].
    ///
    /// Implementors must produce a fully-formed [`Response`] that is ready to be
    /// serialized. The status code, headers, and body should all reflect the
    /// intended HTTP semantics of the type being converted.
    fn into_response(self) -> Response;
}

impl IntoResponse for Response {
    fn into_response(self) -> Response {
        self
    }
}

impl IntoResponse for &'static str {
    fn into_response(self) -> Response {
        Response::new(StatusCode::Ok).body(self)
    }
}

impl IntoResponse for String {
    fn into_response(self) -> Response {
        Response::new(StatusCode::Ok).body(self)
    }
}

impl IntoResponse for () {
    fn into_response(self) -> Response {
        Response::new(StatusCode::Ok)
    }
}

impl<T: IntoResponse> IntoResponse for (StatusCode, T) {
    fn into_response(self) -> Response {
        let mut resp = self.1.into_response();
        resp.set_status(self.0);
        resp
    }
}

impl<T: IntoResponse, E: IntoResponse> IntoResponse for Result<T, E> {
    fn into_response(self) -> Response {
        match self {
            Ok(v) => v.into_response(),
            Err(e) => e.into_response(),
        }
    }
}


impl Response {
    /// Sets the status code on an existing response.
    ///
    /// Mutates the response in place. Prefer constructing the response with the correct
    /// status via [`Response::new`] when possible; use this method when the status
    /// must be overridden after construction (e.g. inside the [`IntoResponse`] blanket impl
    /// for `(StatusCode, T)`).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::http::{Response, StatusCode};
    ///
    /// let mut response = Response::new(StatusCode::Ok).body("created");
    /// response.set_status(StatusCode::Created);
    /// assert_eq!(response.status(), StatusCode::Created);
    /// ```
    pub fn set_status(&mut self, status: StatusCode) {
        self.status = status;
    }

    /// Creates a JSON response from a serializable value.
    ///
    /// Sets `Content-Type: application/json` automatically.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::http::{Response, StatusCode};
    ///
    /// let response = Response::json(&serde_json::json!({"ok": true}));
    /// ```
    pub fn json<T: serde::Serialize>(value: &T) -> Self {
        match serde_json::to_string(value) {
            Ok(json) => Response::new(StatusCode::Ok)
                .header("Content-Type", "application/json")
                .body(json),
            Err(_) => {
                Response::new(StatusCode::InternalServerError).body("Failed to serialize JSON")
            }
        }
    }

    /// Creates a redirect response (302 Found) to the given URL.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::http::Response;
    ///
    /// let response = Response::redirect("/login");
    /// ```
    #[must_use]
    pub fn redirect(url: impl Into<String>) -> Self {
        Response::new(StatusCode::Found).header("Location", url.into())
    }

    /// Creates a permanent redirect response (301 Moved Permanently).
    ///
    /// Use this when a resource has moved to a new URL and the old URL should
    /// never be used again. Browsers will cache this redirect indefinitely.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::http::Response;
    ///
    /// let response = Response::permanent_redirect("/new-home");
    /// ```
    #[must_use]
    pub fn permanent_redirect(url: impl Into<String>) -> Self {
        Response::new(StatusCode::MovedPermanently).header("Location", url.into())
    }

    /// Creates an HTML response with `Content-Type: text/html; charset=utf-8`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::http::Response;
    ///
    /// let response = Response::html("<h1>Hello</h1>");
    /// ```
    #[must_use]
    pub fn html(body: impl Into<String>) -> Self {
        Response::new(StatusCode::Ok)
            .header("Content-Type", "text/html; charset=utf-8")
            .body(body)
    }

    /// Creates a plain text response with `Content-Type: text/plain; charset=utf-8`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::http::Response;
    ///
    /// let response = Response::text("Hello, world!");
    /// ```
    #[must_use]
    pub fn text(body: impl Into<String>) -> Self {
        Response::new(StatusCode::Ok)
            .header("Content-Type", "text/plain; charset=utf-8")
            .body(body)
    }

    /// Creates an empty response with the given status code.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::http::{Response, StatusCode};
    ///
    /// let response = Response::empty(StatusCode::NoContent);
    /// ```
    #[must_use]
    pub fn empty(status: StatusCode) -> Self {
        Response::new(status)
    }

    /// Returns a shared reference to the response headers.
    ///
    /// Useful for inspecting headers set by upstream middleware or handlers
    /// without consuming the response.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::http::{Response, StatusCode};
    ///
    /// let response = Response::new(StatusCode::Ok).header("X-Foo", "bar");
    /// assert!(response.headers().contains("x-foo"));
    /// ```
    pub fn headers(&self) -> &Headers {
        &self.headers
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
