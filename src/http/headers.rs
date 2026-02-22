//! HTTP header map with case-insensitive name lookup.
//!
//! HTTP headers are order-preserving and case-insensitive per [RFC 9110 §5].

use std::fmt;

/// A case-insensitive, multi-value HTTP header map.
///
/// Preserves insertion order and allows multiple values per header name,
/// matching the semantics of HTTP/1.1 header fields (RFC 9110 §5.3).
///
/// # Examples
///
/// ```
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
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a header map with pre-allocated capacity for `capacity` entries.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: Vec::with_capacity(capacity),
        }
    }

    /// Appends a header entry. Multiple values for the same name are preserved.
    pub fn insert(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.inner.push((name.into(), value.into()));
    }

    /// Returns the first value for the given header name (case-insensitive), or `None`.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.inner
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Returns an iterator over all values for the given header name (case-insensitive).
    pub fn get_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.inner
            .iter()
            .filter(move |(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Removes all entries with the given header name (case-insensitive).
    ///
    /// Returns `true` if any entries were removed.
    pub fn remove(&mut self, name: &str) -> bool {
        let before = self.inner.len();
        self.inner.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
        self.inner.len() < before
    }

    /// Returns `true` if the map contains at least one entry with the given name.
    pub fn contains(&self, name: &str) -> bool {
        self.inner.iter().any(|(k, _)| k.eq_ignore_ascii_case(name))
    }

    /// Returns the total number of header entries (not unique names).
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns `true` if there are no header entries.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Returns an iterator over all `(name, value)` pairs in insertion order.
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
