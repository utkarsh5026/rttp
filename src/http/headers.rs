//! HTTP header map with case-insensitive name lookup.
//!
//! This module provides [`Headers`], an ordered, case-insensitive multi-value map
//! that models the header fields of an HTTP/1.1 message as defined in
//! [RFC 9110 §5](https://www.rfc-editor.org/rfc/rfc9110#section-5).
//! Insertion order is preserved, and multiple values for the same name are
//! supported (e.g. `Set-Cookie`).

use std::fmt;

use super::cookie::{Cookie, CookieJar};

/// A case-insensitive, multi-value HTTP header map.
///
/// Preserves insertion order and allows multiple values per header name,
/// matching the semantics of HTTP/1.1 header fields (RFC 9110 §5.3).
///
/// Header name comparisons are always case-insensitive (ASCII). The original
/// casing supplied by the caller is retained in the stored entries.
///
/// # Examples
///
/// ```rust
/// use rttp::http::Headers;
///
/// let mut headers = Headers::new();
/// headers.insert("Content-Type", "text/html; charset=utf-8");
/// headers.insert("X-Custom", "first");
/// headers.insert("X-Custom", "second");
///
/// assert_eq!(headers.get("content-type"), Some("text/html; charset=utf-8"));
/// let all: Vec<_> = headers.get_all("x-custom").collect();
/// assert_eq!(all, vec!["first", "second"]);
/// ```
#[derive(Debug, Clone, Default)]
pub struct Headers {
    inner: Vec<(String, String)>,
}

impl Headers {
    /// Creates an empty header map.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::http::Headers;
    ///
    /// let headers = Headers::new();
    /// assert!(headers.is_empty());
    /// ```
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a header map with pre-allocated capacity for `capacity` entries.
    ///
    /// This avoids reallocations when the approximate number of headers is known
    /// in advance.
    ///
    /// # Arguments
    ///
    /// - `capacity` — the number of header entries to pre-allocate space for.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::http::Headers;
    ///
    /// let mut headers = Headers::with_capacity(8);
    /// headers.insert("Accept", "application/json");
    /// ```
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: Vec::with_capacity(capacity),
        }
    }

    /// Sets a header, replacing all existing values for the given name.
    ///
    /// Any previously stored entries whose name matches `name`
    /// (case-insensitively) are removed before the new value is appended.
    /// Use [`append`](Self::append) to add multiple values for the same name
    /// (e.g. `Set-Cookie`).
    ///
    /// # Arguments
    ///
    /// - `name`  — the header field name (case-insensitive).
    /// - `value` — the header field value to store.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::http::Headers;
    ///
    /// let mut headers = Headers::new();
    /// headers.set("Content-Type", "text/plain");
    /// headers.set("Content-Type", "text/html");
    ///
    /// // Only the last value is retained.
    /// assert_eq!(headers.get("content-type"), Some("text/html"));
    /// assert_eq!(headers.len(), 1);
    /// ```
    pub fn set(&mut self, name: impl Into<String>, value: impl Into<String>) {
        let name = name.into();
        self.inner.retain(|(k, _)| !k.eq_ignore_ascii_case(&name));
        self.inner.push((name, value.into()));
    }

    /// Appends a header entry without removing existing values for the same name.
    ///
    /// Multiple values for the same header name are preserved in insertion order.
    /// This is the correct behaviour for headers such as `Set-Cookie` that may
    /// appear more than once per message.
    ///
    /// # Arguments
    ///
    /// - `name`  — the header field name.
    /// - `value` — the header field value to append.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::http::Headers;
    ///
    /// let mut headers = Headers::new();
    /// headers.append("Set-Cookie", "session=abc");
    /// headers.append("Set-Cookie", "theme=dark");
    ///
    /// let cookies: Vec<_> = headers.get_all("set-cookie").collect();
    /// assert_eq!(cookies, vec!["session=abc", "theme=dark"]);
    /// ```
    pub fn append(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.inner.push((name.into(), value.into()));
    }

    /// Alias for [`append`](Self::append) — adds a header entry without replacing existing values.
    ///
    /// # Arguments
    ///
    /// - `name`  — the header field name.
    /// - `value` — the header field value to add.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::http::Headers;
    ///
    /// let mut headers = Headers::new();
    /// headers.insert("X-Request-Id", "abc123");
    /// assert_eq!(headers.get("x-request-id"), Some("abc123"));
    /// ```
    pub fn insert(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.append(name, value);
    }

    /// Returns the first value for the given header name (case-insensitive).
    ///
    /// When multiple values are stored for the same name, only the first one
    /// (in insertion order) is returned. Use [`get_all`](Self::get_all) to
    /// iterate over every value.
    ///
    /// # Arguments
    ///
    /// - `name` — the header field name to look up (case-insensitive).
    ///
    /// # Returns
    ///
    /// `Some(&str)` with the first matching value, or `None` if no entry exists
    /// for `name`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::http::Headers;
    ///
    /// let mut headers = Headers::new();
    /// headers.insert("Authorization", "Bearer token123");
    ///
    /// assert_eq!(headers.get("authorization"), Some("Bearer token123"));
    /// assert_eq!(headers.get("X-Missing"), None);
    /// ```
    pub fn get(&self, name: &str) -> Option<&str> {
        self.inner
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Returns an iterator over all values for the given header name (case-insensitive).
    ///
    /// Values are yielded in insertion order. If no entries match `name`, the
    /// iterator is empty.
    ///
    /// # Arguments
    ///
    /// - `name` — the header field name to look up (case-insensitive).
    ///
    /// # Returns
    ///
    /// An iterator yielding `&str` values for each matching entry.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::http::Headers;
    ///
    /// let mut headers = Headers::new();
    /// headers.insert("Set-Cookie", "a=1");
    /// headers.insert("Set-Cookie", "b=2");
    ///
    /// let cookies: Vec<_> = headers.get_all("set-cookie").collect();
    /// assert_eq!(cookies, vec!["a=1", "b=2"]);
    /// ```
    pub fn get_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.inner
            .iter()
            .filter(move |(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Removes all entries with the given header name (case-insensitive).
    ///
    /// # Arguments
    ///
    /// - `name` — the header field name to remove (case-insensitive).
    ///
    /// # Returns
    ///
    /// `true` if at least one entry was removed, `false` if no matching entry
    /// was found.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::http::Headers;
    ///
    /// let mut headers = Headers::new();
    /// headers.insert("X-Foo", "bar");
    /// headers.insert("X-Foo", "baz");
    ///
    /// assert!(headers.remove("x-foo"));   // two entries removed
    /// assert!(headers.is_empty());
    /// assert!(!headers.remove("x-foo"));  // nothing left to remove
    /// ```
    pub fn remove(&mut self, name: &str) -> bool {
        let before = self.inner.len();
        self.inner.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
        self.inner.len() < before
    }

    /// Returns `true` if the map contains at least one entry with the given name.
    ///
    /// # Arguments
    ///
    /// - `name` — the header field name to check (case-insensitive).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::http::Headers;
    ///
    /// let mut headers = Headers::new();
    /// headers.insert("Authorization", "Bearer token");
    ///
    /// assert!(headers.contains("authorization"));
    /// assert!(!headers.contains("x-missing"));
    /// ```
    pub fn contains(&self, name: &str) -> bool {
        self.inner.iter().any(|(k, _)| k.eq_ignore_ascii_case(name))
    }

    /// Returns the total number of header entries (not the number of unique names).
    ///
    /// If the same header name appears multiple times, each occurrence is
    /// counted separately.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::http::Headers;
    ///
    /// let mut headers = Headers::new();
    /// headers.insert("Set-Cookie", "a=1");
    /// headers.insert("Set-Cookie", "b=2");
    ///
    /// assert_eq!(headers.len(), 2); // two entries, one unique name
    /// ```
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns `true` if there are no header entries.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::http::Headers;
    ///
    /// let mut headers = Headers::new();
    /// assert!(headers.is_empty());
    ///
    /// headers.insert("X-Foo", "bar");
    /// assert!(!headers.is_empty());
    /// ```
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Parse the `Cookie` request header into a [`CookieJar`].
    ///
    /// If no `Cookie` header is present the returned jar is empty.
    /// If multiple `Cookie` headers are present (unusual but valid), all of
    /// them are concatenated before parsing.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::http::Headers;
    ///
    /// let mut headers = Headers::new();
    /// headers.insert("Cookie", "session=abc; theme=dark");
    ///
    /// let jar = headers.cookies();
    /// assert_eq!(jar.get("session"), Some("abc"));
    /// assert_eq!(jar.get("theme"), Some("dark"));
    /// ```
    pub fn cookies(&self) -> CookieJar {
        let combined = self
            .get_all("cookie")
            .collect::<Vec<_>>()
            .join("; ");
        CookieJar::parse(&combined)
    }

    /// Append a `Set-Cookie` response header from a [`Cookie`] value.
    ///
    /// Equivalent to calling `headers.append("Set-Cookie", cookie.to_string())`,
    /// but avoids the manual serialization step.
    ///
    /// # Arguments
    ///
    /// - `cookie` — a configured [`Cookie`] to serialize and append.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::http::Headers;
    /// use rttp::http::cookie::Cookie;
    ///
    /// let mut headers = Headers::new();
    /// headers.set_cookie(Cookie::new("session", "abc").http_only(true));
    /// headers.set_cookie(Cookie::new("theme", "dark"));
    ///
    /// assert_eq!(headers.len(), 2);
    /// ```
    pub fn set_cookie(&mut self, cookie: Cookie) {
        self.append("Set-Cookie", cookie.to_string());
    }

    /// Returns an iterator over all `(name, value)` pairs in insertion order.
    ///
    /// Both the name and value are returned as `&str` slices borrowing from
    /// `self`. The original casing of each name is preserved.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::http::Headers;
    ///
    /// let mut headers = Headers::new();
    /// headers.insert("Content-Type", "text/plain");
    /// headers.insert("X-Powered-By", "rttp");
    ///
    /// let pairs: Vec<_> = headers.iter().collect();
    /// assert_eq!(pairs[0], ("Content-Type", "text/plain"));
    /// assert_eq!(pairs[1], ("X-Powered-By", "rttp"));
    /// ```
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.inner.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }
}

impl fmt::Display for Headers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (name, value) in &self.inner {
            write!(f, "{name}: {value}\r\n")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn case_insensitive_get() {
        let mut h = Headers::new();
        h.insert("Content-Type", "text/plain");
        assert_eq!(h.get("content-type"), Some("text/plain"));
        assert_eq!(h.get("CONTENT-TYPE"), Some("text/plain"));
        assert_eq!(h.get("Content-Type"), Some("text/plain"));
    }

    #[test]
    fn multi_value() {
        let mut h = Headers::new();
        h.insert("Set-Cookie", "a=1");
        h.insert("Set-Cookie", "b=2");
        let vals: Vec<_> = h.get_all("set-cookie").collect();
        assert_eq!(vals, vec!["a=1", "b=2"]);
    }

    #[test]
    fn remove() {
        let mut h = Headers::new();
        h.insert("X-Foo", "bar");
        h.insert("X-Foo", "baz");
        assert!(h.remove("x-foo"));
        assert!(h.is_empty());
        assert!(!h.remove("x-foo")); // already gone
    }

    #[test]
    fn contains() {
        let mut h = Headers::new();
        h.insert("Authorization", "Bearer token");
        assert!(h.contains("authorization"));
        assert!(!h.contains("x-missing"));
    }
}
