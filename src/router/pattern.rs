//! URL pattern parsing and matching.
//!
//! A [`Pattern`] is compiled once at route registration time from a pattern string and
//! reused for every incoming request. Three variants are supported:
//!
//! | Pattern        | Example match            | Captured params              |
//! |----------------|--------------------------|------------------------------|
//! | `/users`       | `/users`                 | *(none)*                     |
//! | `/users/:id`   | `/users/42`              | `id → "42"`                  |
//! | `/files/*`     | `/files/docs/readme.txt` | `wildcard → "/docs/readme.txt"` |

use crate::context::PathParams;

/// A single path segment, either a literal string or a named capture (`:name`).
#[derive(Debug, Clone)]
pub(super) enum Segment {
    /// A literal path segment that must match exactly, e.g. `users` in `/users/:id`.
    Static(String),
    /// A named capture that accepts any value, e.g. `id` from `:id`.
    Parameter(String),
}

/// Compiled representation of a route pattern string.
#[derive(Debug, Clone)]
pub(super) enum Pattern {
    /// Matches one exact path string, e.g. `/users`.
    Exact(String),
    /// Matches a fixed number of segments where some may be named captures, e.g. `/users/:id`.
    Parameterized { segments: Vec<Segment> },
    /// Matches any path that starts with the given prefix, e.g. `/files/*`.
    Wildcard(String),
}

/// Strip a trailing slash from `path`, unless `path` is the root `"/"`.
///
/// This ensures that `/users/` and `/users` are treated as the same path.
#[inline]
fn normalize(path: &str) -> &str {
    if path != "/" && path.ends_with('/') {
        &path[..path.len() - 1]
    } else {
        path
    }
}

impl Pattern {
    /// Parse a route pattern string into a `Pattern`.
    ///
    /// The pattern is classified as follows (checked in order):
    ///
    /// 1. Ends with `/*` → [`Pattern::Wildcard`] — matches any path sharing the prefix.
    /// 2. Contains `:` → [`Pattern::Parameterized`] — one or more named captures.
    /// 3. Otherwise, → [`Pattern::Exact`] — literal path match.
    ///
    /// A trailing slash (other than on the root `/`) is stripped before classification so
    /// that `/users/` and `/users` compile to identical patterns.
    ///
    /// # Arguments
    ///
    /// - `pattern` — the route pattern string, e.g. `"/users/:id"`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rttp::router::pattern::Pattern; // illustrative — adjust path as needed
    ///
    /// let exact = Pattern::parse("/users");
    /// let param = Pattern::parse("/users/:id");
    /// let wild  = Pattern::parse("/files/*");
    /// ```
    pub fn parse(pattern: &str) -> Self {
        let pattern = normalize(pattern);

        if let Some(prefix) = pattern.strip_suffix("/*") {
            return Pattern::Wildcard(prefix.to_string());
        }

        if pattern.contains(':') {
            let segments = pattern
                .split('/')
                .filter(|s| !s.is_empty())
                .map(|s| {
                    if let Some(p) = s.strip_prefix(':') {
                        Segment::Parameter(p.to_string())
                    } else {
                        Segment::Static(s.to_string())
                    }
                })
                .collect();

            return Pattern::Parameterized { segments };
        }

        Pattern::Exact(pattern.to_string())
    }

    /// Try to match `path` against this pattern, returning extracted [`PathParams`] on success.
    ///
    /// A trailing slash on `path` (other than the root `/`) is stripped before matching so
    /// that `/users/` and `/users` are treated identically.
    ///
    /// For [`Pattern::Wildcard`], the portion of the path after the prefix is stored under
    /// the key `"wildcard"` in the returned params.
    ///
    /// # Arguments
    ///
    /// - `path` — the request path to match against, e.g. `"/users/42"`.
    ///
    /// # Returns
    ///
    /// `Some(PathParams)` with any extracted named captures if the path matches, or `None`
    /// if it does not.
    ///
    /// # Examples
    ///
    /// ```rust
    /// let pat = Pattern::parse("/users/:id");
    /// let params = pat.matches("/users/42").unwrap();
    /// assert_eq!(params.get("id"), Some("42"));
    ///
    /// assert!(pat.matches("/posts/42").is_none());
    /// ```
    pub fn matches(&self, path: &str) -> Option<PathParams> {
        let path = normalize(path);

        match self {
            Pattern::Exact(p) => {
                if p == path {
                    Some(PathParams::new())
                } else {
                    None
                }
            }
            Pattern::Parameterized { segments } => {
                let mut params = PathParams::new();
                let mut path_iter = path.split('/').filter(|s| !s.is_empty());
                let mut matched = 0;

                for seg in segments.iter() {
                    let Some(path_seg) = path_iter.next() else {
                        return None;
                    };
                    match seg {
                        Segment::Static(s) => {
                            if s != path_seg {
                                return None;
                            }
                        }
                        Segment::Parameter(name) => {
                            params.insert(name.clone(), path_seg.to_string());
                        }
                    }
                    matched += 1;
                }

                if matched != segments.len() || path_iter.next().is_some() {
                    return None;
                }

                Some(params)
            }
            Pattern::Wildcard(prefix) => {
                if let Some(suffix) = path.strip_prefix(prefix) {
                    let mut params = PathParams::new();
                    params.insert("wildcard".to_string(), suffix.to_string());
                    Some(params)
                } else {
                    None
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pattern_parse_root() {
        assert!(matches!(Pattern::parse("/"), Pattern::Exact(s) if s == "/"));
    }

    #[test]
    fn pattern_parse_exact() {
        assert!(matches!(Pattern::parse("/users"), Pattern::Exact(s) if s == "/users"));
    }

    #[test]
    fn pattern_parse_exact_nested() {
        assert!(matches!(
            Pattern::parse("/users/profile"),
            Pattern::Exact(s) if s == "/users/profile"
        ));
    }

    #[test]
    fn pattern_parse_trailing_slash_stripped() {
        assert!(matches!(Pattern::parse("/users/"), Pattern::Exact(s) if s == "/users"));
    }

    #[test]
    fn pattern_parse_parameterized_single() {
        let pat = Pattern::parse("/users/:id");
        match pat {
            Pattern::Parameterized { segments } => {
                assert_eq!(segments.len(), 2);
                assert!(matches!(&segments[0], Segment::Static(s) if s == "users"));
                assert!(matches!(&segments[1], Segment::Parameter(s) if s == "id"));
            }
            other => panic!("expected Parameterized, got {other:?}"),
        }
    }

    #[test]
    fn pattern_parse_parameterized_multi() {
        let pat = Pattern::parse("/users/:id/posts/:post_id");
        match pat {
            Pattern::Parameterized { segments } => {
                assert_eq!(segments.len(), 4);
                assert!(matches!(&segments[1], Segment::Parameter(s) if s == "id"));
                assert!(matches!(&segments[3], Segment::Parameter(s) if s == "post_id"));
            }
            other => panic!("expected Parameterized, got {other:?}"),
        }
    }

    #[test]
    fn pattern_parse_wildcard() {
        assert!(matches!(
            Pattern::parse("/files/*"),
            Pattern::Wildcard(s) if s == "/files"
        ));
    }

    #[test]
    fn pattern_exact_match_hit() {
        let pat = Pattern::parse("/users");
        assert!(pat.matches("/users").is_some());
    }

    #[test]
    fn pattern_exact_match_miss() {
        let pat = Pattern::parse("/users");
        assert!(pat.matches("/posts").is_none());
    }

    #[test]
    fn pattern_exact_match_trailing_slash_normalized() {
        let pat = Pattern::parse("/users");
        assert!(pat.matches("/users/").is_some());
    }

    #[test]
    fn pattern_exact_match_root() {
        let pat = Pattern::parse("/");
        assert!(pat.matches("/").is_some());
        assert!(pat.matches("/other").is_none());
    }

    #[test]
    fn pattern_param_extracts_value() {
        let pat = Pattern::parse("/users/:id");
        let params = pat.matches("/users/42").unwrap();
        assert_eq!(params.get("id"), Some("42"));
    }

    #[test]
    fn pattern_param_multi_extracts_values() {
        let pat = Pattern::parse("/users/:id/posts/:post_id");
        let params = pat.matches("/users/7/posts/99").unwrap();
        assert_eq!(params.get("id"), Some("7"));
        assert_eq!(params.get("post_id"), Some("99"));
    }

    #[test]
    fn pattern_param_wrong_segment_count() {
        let pat = Pattern::parse("/users/:id");
        assert!(pat.matches("/users").is_none());
        assert!(pat.matches("/users/42/extra").is_none());
    }

    #[test]
    fn pattern_param_wrong_static_segment() {
        let pat = Pattern::parse("/users/:id");
        assert!(pat.matches("/posts/42").is_none());
    }

    #[test]
    fn pattern_wildcard_match_hit() {
        let pat = Pattern::parse("/files/*");
        let params = pat.matches("/files/docs/readme.txt").unwrap();
        assert_eq!(params.get("wildcard"), Some("/docs/readme.txt"));
    }

    #[test]
    fn pattern_wildcard_match_miss() {
        let pat = Pattern::parse("/files/*");
        assert!(pat.matches("/other/readme.txt").is_none());
    }
}
