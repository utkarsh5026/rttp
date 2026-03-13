//! HTTP request methods.
//!
//! This module defines the [`Method`] enum, which represents standard HTTP/1.1
//! request methods as defined in RFC 9110 §9. All standard methods are zero-cost
//! unit variants; non-standard extension methods are captured in [`Method::Custom`].

use std::fmt;

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
    ///
    /// # Examples
    ///
    /// ```
    /// use rttp::http::Method;
    ///
    /// assert_eq!(Method::Get.as_str(), "GET");
    /// assert_eq!(Method::Post.as_str(), "POST");
    /// assert_eq!(Method::Custom("QUERY".to_owned()).as_str(), "QUERY");
    /// ```
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
    ///
    /// # Examples
    ///
    /// ```
    /// use rttp::http::Method;
    ///
    /// assert!(Method::Get.is_safe());
    /// assert!(Method::Head.is_safe());
    /// assert!(!Method::Post.is_safe());
    /// assert!(!Method::Put.is_safe());
    /// ```
    pub fn is_safe(&self) -> bool {
        matches!(self, Self::Get | Self::Head | Self::Options | Self::Trace)
    }

    /// Returns `true` if this method is idempotent (RFC 9110 §9.2.2).
    ///
    /// Idempotent methods: GET, HEAD, PUT, DELETE, OPTIONS, TRACE.
    ///
    /// # Examples
    ///
    /// ```
    /// use rttp::http::Method;
    ///
    /// assert!(Method::Get.is_idempotent());
    /// assert!(Method::Put.is_idempotent());
    /// assert!(Method::Delete.is_idempotent());
    /// assert!(!Method::Post.is_idempotent());
    /// assert!(!Method::Patch.is_idempotent());
    /// ```
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

impl From<Method> for String {
    fn from(m: Method) -> String {
        m.as_str().to_owned()
    }
}

impl From<&Method> for String {
    fn from(m: &Method) -> String {
        m.as_str().to_owned()
    }
}
