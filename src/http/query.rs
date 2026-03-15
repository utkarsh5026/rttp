//! URL query-string parsing with percent-decoding and multi-value support.
//!
//! Provides [`QueryParams`], a new type over `HashMap<String, Vec<String>>` that
//! handles `+`-as-space, full percent-decoding, and duplicate keys.

use std::collections::HashMap;

use percent_encoding::percent_decode_str;

/// Parsed URL query parameters with multi-value support.
///
/// Wraps a `HashMap<String, Vec<String>>` and provides ergonomic accessors for
/// the common single-value case as well as the multi-value case (`?tag=a&tag=b`).
///
/// Keys and values are fully percent-decoded (`%20` → space, `%3D` → `=`, etc.)
/// and `+` is decoded as a space.
///
/// # Examples
///
/// ```rust
/// use rttp::http::query::QueryParams;
///
/// let params = QueryParams::parse("q=hello+world&tag=rust&tag=async");
/// assert_eq!(params.get("q"), Some("hello world"));
/// assert_eq!(params.get_all("tag"), &["rust", "async"]);
/// assert!(params.contains("q"));
/// assert!(!params.contains("missing"));
/// ```
#[derive(Debug, Clone, Default)]
pub struct QueryParams(HashMap<String, Vec<String>>);

impl QueryParams {
    /// Parse a raw query string into [`QueryParams`].
    ///
    /// The input should NOT include the leading `?`. Pairs are separated by `&`.
    /// Each pair is split on the first `=`. Keys without `=` get an empty-string value.
    ///
    /// Both keys and values are decoded: `+` becomes a space, and percent-encoded
    /// sequences (`%XX`) are decoded to their byte value.
    ///
    /// # Arguments
    ///
    /// - `query` — the raw query string (e.g. `"key=value&other=123"`).
    #[must_use]
    pub fn parse(query: &str) -> Self {
        let mut map: HashMap<String, Vec<String>> = HashMap::new();

        for pair in query.split('&') {
            if pair.is_empty() {
                continue;
            }

            let (raw_key, raw_value) = match pair.split_once('=') {
                Some((k, v)) => (k, v),
                None => (pair, ""),
            };

            let key = decode(raw_key);
            let value = decode(raw_value);

            map.entry(key).or_default().push(value);
        }

        Self(map)
    }

    /// Returns an empty `QueryParams` with no entries.
    #[must_use]
    pub fn empty() -> Self {
        Self(HashMap::new())
    }

    /// Returns the first value for the given key, or `None` if the key is absent.
    ///
    /// # Arguments
    ///
    /// - `key` — the query parameter name (case-sensitive, already decoded).
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key)?.first().map(String::as_str)
    }

    /// Returns all values for the given key.
    ///
    /// Returns an empty slice if the key is absent.
    ///
    /// # Arguments
    ///
    /// - `key` — the query parameter name.
    pub fn get_all(&self, key: &str) -> &[String] {
        self.0.get(key).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Returns `true` if the given key is present.
    pub fn contains(&self, key: &str) -> bool {
        self.0.contains_key(key)
    }

    /// Returns `true` if there are no query parameters.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the number of unique keys.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns an iterator over all `(key, value)` pairs, flattened.
    ///
    /// For a key with multiple values, each value is yielded as a separate pair.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0
            .iter()
            .flat_map(|(k, vs)| vs.iter().map(move |v| (k.as_str(), v.as_str())))
    }
}

/// Decode a URL-encoded string: `+` → space, then percent-decode.
fn decode(input: &str) -> String {
    let plus_decoded = input.replace('+', " ");
    percent_decode_str(&plus_decoded)
        .decode_utf8_lossy()
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_params() {
        let params = QueryParams::parse("a=1&b=2");
        assert_eq!(params.get("a"), Some("1"));
        assert_eq!(params.get("b"), Some("2"));
        assert_eq!(params.len(), 2);
    }

    #[test]
    fn parse_multi_value() {
        let params = QueryParams::parse("tag=rust&tag=async&tag=web");
        assert_eq!(params.get("tag"), Some("rust"));
        assert_eq!(params.get_all("tag"), &["rust", "async", "web"]);
    }

    #[test]
    fn parse_plus_as_space() {
        let params = QueryParams::parse("q=hello+world");
        assert_eq!(params.get("q"), Some("hello world"));
    }

    #[test]
    fn parse_percent_encoding() {
        let params = QueryParams::parse("name=hello%20world&sym=%3D%26");
        assert_eq!(params.get("name"), Some("hello world"));
        assert_eq!(params.get("sym"), Some("=&"));
    }

    #[test]
    fn parse_key_without_equals() {
        let params = QueryParams::parse("flag&key=val");
        assert_eq!(params.get("flag"), Some(""));
        assert_eq!(params.get("key"), Some("val"));
    }

    #[test]
    fn parse_empty_value() {
        let params = QueryParams::parse("key=");
        assert_eq!(params.get("key"), Some(""));
    }

    #[test]
    fn parse_empty_string() {
        let params = QueryParams::parse("");
        assert!(params.is_empty());
    }

    #[test]
    fn get_missing_key() {
        let params = QueryParams::parse("a=1");
        assert_eq!(params.get("b"), None);
        assert_eq!(params.get_all("b"), &[] as &[String]);
    }

    #[test]
    fn contains_key() {
        let params = QueryParams::parse("x=1");
        assert!(params.contains("x"));
        assert!(!params.contains("y"));
    }

    #[test]
    fn iter_flattens() {
        let params = QueryParams::parse("a=1&b=2&a=3");
        let mut pairs: Vec<_> = params.iter().collect();
        pairs.sort();
        assert_eq!(pairs, vec![("a", "1"), ("a", "3"), ("b", "2")]);
    }

    #[test]
    fn percent_encoded_key() {
        let params = QueryParams::parse("hello%20world=yes");
        assert_eq!(params.get("hello world"), Some("yes"));
    }

    #[test]
    fn empty_returns_empty() {
        let params = QueryParams::empty();
        assert!(params.is_empty());
        assert_eq!(params.len(), 0);
    }
}
