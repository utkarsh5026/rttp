//! HTTP cookie types for reading request cookies and building response cookies.
//!
//! Provides [`Cookie`], a builder for `Set-Cookie` response header values, and
//! [`CookieJar`], which parses the `Cookie` request header into individual name/value
//! pairs. Both types follow RFC 6265.

use std::fmt;

/// A single HTTP cookie with its optional attributes.
///
/// Use the builder methods to set attributes, then convert to a `Set-Cookie`
/// header value via [`Cookie::to_string`] or [`Cookie::into_header_value`].
///
/// # Examples
///
/// ```rust
/// use rttp::http::cookie::Cookie;
///
/// let value = Cookie::new("session", "abc123")
///     .http_only(true)
///     .secure(true)
///     .same_site("Strict")
///     .path("/")
///     .into_header_value();
///
/// assert!(value.starts_with("session=abc123;"));
/// assert!(value.contains("HttpOnly"));
/// assert!(value.contains("Secure"));
/// ```
#[derive(Debug, Clone)]
pub struct Cookie {
    name: String,
    value: String,
    path: Option<String>,
    domain: Option<String>,
    max_age: Option<i64>,
    secure: bool,
    http_only: bool,
    same_site: Option<String>,
}

impl Cookie {
    /// Create a new cookie with the given name and value.
    ///
    /// All attributes default to unset. Use the builder methods to configure them.
    ///
    /// # Arguments
    ///
    /// - `name`  — the cookie name (must not contain `=`, `;`, or whitespace).
    /// - `value` — the cookie value.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::http::cookie::Cookie;
    ///
    /// let c = Cookie::new("theme", "dark");
    /// assert_eq!(c.name(), "theme");
    /// assert_eq!(c.value(), "dark");
    /// ```
    #[must_use]
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            path: None,
            domain: None,
            max_age: None,
            secure: false,
            http_only: false,
            same_site: None,
        }
    }

    /// Create a cookie that instructs the browser to delete an existing cookie.
    ///
    /// Sets `Max-Age=0` so the browser expires it immediately.
    ///
    /// # Arguments
    ///
    /// - `name` — the name of the cookie to delete.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::http::cookie::Cookie;
    ///
    /// let c = Cookie::removal("session");
    /// assert!(c.into_header_value().contains("Max-Age=0"));
    /// ```
    #[must_use]
    pub fn removal(name: impl Into<String>) -> Self {
        Self::new(name, "").max_age(0)
    }

    /// Returns the cookie name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the cookie value.
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Set the `Path` attribute.
    #[must_use]
    pub fn path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    /// Set the `Domain` attribute.
    #[must_use]
    pub fn domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = Some(domain.into());
        self
    }

    /// Set the `Max-Age` attribute (in seconds).
    ///
    /// A value of `0` instructs the browser to delete the cookie immediately.
    /// Negative values are treated by browsers the same as `0`.
    #[must_use]
    pub fn max_age(mut self, seconds: i64) -> Self {
        self.max_age = Some(seconds);
        self
    }

    /// Set whether the `Secure` flag is included.
    ///
    /// When `true`, the browser only sends the cookie over HTTPS.
    #[must_use]
    pub fn secure(mut self, secure: bool) -> Self {
        self.secure = secure;
        self
    }

    /// Set whether the `HttpOnly` flag is included.
    ///
    /// When `true`, JavaScript cannot access the cookie via `document.cookie`.
    #[must_use]
    pub fn http_only(mut self, http_only: bool) -> Self {
        self.http_only = http_only;
        self
    }

    /// Set the `SameSite` attribute.
    ///
    /// Accepted values: `"Strict"`, `"Lax"`, `"None"`.
    /// When using `"None"`, [`secure`](Self::secure) should also be set to `true`.
    #[must_use]
    pub fn same_site(mut self, value: impl Into<String>) -> Self {
        self.same_site = Some(value.into());
        self
    }

    /// Serialize the cookie into a `Set-Cookie` header value string.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::http::cookie::Cookie;
    ///
    /// let value = Cookie::new("id", "42").path("/").secure(true).into_header_value();
    /// assert_eq!(value, "id=42; Path=/; Secure");
    /// ```
    #[must_use]
    pub fn into_header_value(self) -> String {
        self.to_string()
    }
}

impl fmt::Display for Cookie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}={}", self.name, self.value)?;
        if let Some(path) = &self.path {
            write!(f, "; Path={path}")?;
        }
        if let Some(domain) = &self.domain {
            write!(f, "; Domain={domain}")?;
        }
        if let Some(max_age) = self.max_age {
            write!(f, "; Max-Age={max_age}")?;
        }
        if let Some(same_site) = &self.same_site {
            write!(f, "; SameSite={same_site}")?;
        }
        if self.secure {
            write!(f, "; Secure")?;
        }
        if self.http_only {
            write!(f, "; HttpOnly")?;
        }
        Ok(())
    }
}

/// Parsed cookies from the `Cookie` request header.
///
/// `CookieJar` parses the `Cookie` header value (e.g. `"a=1; b=2"`) into
/// individual name/value pairs. Use [`CookieJar::get`] to look up a cookie
/// by name (case-sensitive, per RFC 6265).
///
/// # Examples
///
/// ```rust
/// use rttp::http::cookie::CookieJar;
///
/// let jar = CookieJar::parse("session=abc; theme=dark; _csrf=tok");
///
/// assert_eq!(jar.get("session"), Some("abc"));
/// assert_eq!(jar.get("theme"), Some("dark"));
/// assert_eq!(jar.get("missing"), None);
/// ```
#[derive(Debug, Clone, Default)]
pub struct CookieJar {
    cookies: Vec<(String, String)>,
}

impl CookieJar {
    /// Parse a `Cookie` header value into a `CookieJar`.
    ///
    /// Pairs are separated by `; ` (semicolon + space). Each pair is split on
    /// the first `=`. Pairs that do not contain `=` are silently ignored.
    ///
    /// # Arguments
    ///
    /// - `header` — the raw value of the `Cookie` header (not the full header line).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::http::cookie::CookieJar;
    ///
    /// let jar = CookieJar::parse("a=1; b=2");
    /// assert_eq!(jar.get("a"), Some("1"));
    /// assert_eq!(jar.get("b"), Some("2"));
    /// ```
    #[must_use]
    pub fn parse(header: &str) -> Self {
        let cookies = header
            .split(';')
            .filter_map(|pair| {
                let pair = pair.trim();
                let (name, value) = pair.split_once('=')?;
                Some((name.trim().to_owned(), value.trim().to_owned()))
            })
            .collect();
        Self { cookies }
    }

    /// Returns the value of the first cookie with the given name, or `None`.
    ///
    /// Cookie names are matched case-sensitively (RFC 6265 §4).
    ///
    /// # Arguments
    ///
    /// - `name` — the cookie name to look up.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::http::cookie::CookieJar;
    ///
    /// let jar = CookieJar::parse("Token=abc");
    /// assert_eq!(jar.get("Token"), Some("abc"));
    /// assert_eq!(jar.get("token"), None); // case-sensitive
    /// ```
    pub fn get(&self, name: &str) -> Option<&str> {
        self.cookies
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// Returns `true` if a cookie with the given name is present.
    pub fn contains(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    /// Returns an iterator over all `(name, value)` pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.cookies.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Returns the number of cookies in the jar.
    pub fn len(&self) -> usize {
        self.cookies.len()
    }

    /// Returns `true` if the jar contains no cookies.
    pub fn is_empty(&self) -> bool {
        self.cookies.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_basic_serialization() {
        let s = Cookie::new("id", "42").to_string();
        assert_eq!(s, "id=42");
    }

    #[test]
    fn cookie_with_all_attributes() {
        let s = Cookie::new("session", "abc")
            .path("/")
            .domain("example.com")
            .max_age(3600)
            .same_site("Strict")
            .secure(true)
            .http_only(true)
            .to_string();
        assert_eq!(
            s,
            "session=abc; Path=/; Domain=example.com; Max-Age=3600; SameSite=Strict; Secure; HttpOnly"
        );
    }

    #[test]
    fn cookie_removal_sets_max_age_zero() {
        let s = Cookie::removal("session").to_string();
        assert!(s.contains("Max-Age=0"));
    }

    #[test]
    fn jar_parses_single_cookie() {
        let jar = CookieJar::parse("a=1");
        assert_eq!(jar.get("a"), Some("1"));
    }

    #[test]
    fn jar_parses_multiple_cookies() {
        let jar = CookieJar::parse("a=1; b=2; c=3");
        assert_eq!(jar.get("a"), Some("1"));
        assert_eq!(jar.get("b"), Some("2"));
        assert_eq!(jar.get("c"), Some("3"));
    }

    #[test]
    fn jar_get_missing_returns_none() {
        let jar = CookieJar::parse("a=1");
        assert_eq!(jar.get("b"), None);
    }

    #[test]
    fn jar_is_case_sensitive() {
        let jar = CookieJar::parse("Token=abc");
        assert_eq!(jar.get("Token"), Some("abc"));
        assert_eq!(jar.get("token"), None);
    }

    #[test]
    fn jar_handles_values_with_equals_sign() {
        // Base64-encoded values may contain '='.
        let jar = CookieJar::parse("data=abc=def");
        assert_eq!(jar.get("data"), Some("abc=def"));
    }

    #[test]
    fn jar_empty_header() {
        let jar = CookieJar::parse("");
        assert!(jar.is_empty());
    }

    #[test]
    fn jar_len_and_iter() {
        let jar = CookieJar::parse("x=1; y=2");
        assert_eq!(jar.len(), 2);
        let pairs: Vec<_> = jar.iter().collect();
        assert_eq!(pairs, vec![("x", "1"), ("y", "2")]);
    }
}
