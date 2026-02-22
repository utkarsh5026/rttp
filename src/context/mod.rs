//! Per-request context — type-safe state injection and request extensions.
//!
//! - [`Extensions`]: type-erased map for injecting arbitrary per-request state
//! - [`PathParams`]: named path segments extracted by the router (e.g. `/users/:id`)
//! - [`Context`]: wraps a [`Request`] together with the above, passed to handlers

use std::{
    any::{Any, TypeId},
    collections::HashMap,
};

use crate::Request;

/// Type-erased request extensions map — used to inject per-request state
/// into handlers without requiring handlers to know about each other's types.
#[derive(Default)]
pub struct Extensions {
    map: HashMap<TypeId, Box<dyn Any + Send + Sync>>,
}

impl Extensions {
    /// Create a new empty extensions map.
    #[must_use]
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    /// Insert a value, returning the previous value of the same type if one existed.
    pub fn insert<T>(&mut self, value: T) -> Option<T>
    where
        T: Send + Sync + 'static,
    {
        self.map
            .insert(TypeId::of::<T>(), Box::new(value))
            .and_then(|old| old.downcast::<T>().ok())
            .map(|old| *old)
    }

    /// Returns `true` if a value of type `T` is present.
    pub fn contains<T>(&self) -> bool
    where
        T: Send + Sync + 'static,
    {
        self.map.contains_key(&TypeId::of::<T>())
    }

    /// Get a shared reference to a value of type `T`.
    pub fn get<T>(&self) -> Option<&T>
    where
        T: Send + Sync + 'static,
    {
        self.map
            .get(&TypeId::of::<T>())
            .and_then(|value| value.downcast_ref::<T>())
    }

    /// Get a mutable reference to a value of type `T`.
    pub fn get_mut<T>(&mut self) -> Option<&mut T>
    where
        T: Send + Sync + 'static,
    {
        self.map
            .get_mut(&TypeId::of::<T>())
            .and_then(|value| value.downcast_mut::<T>())
    }

    /// Remove a value of type `T`, returning it if present.
    pub fn remove<T>(&mut self) -> Option<T>
    where
        T: Send + Sync + 'static,
    {
        self.map
            .remove(&TypeId::of::<T>())
            .and_then(|value| value.downcast::<T>().ok())
            .map(|value| *value)
    }
}

/// Path parameters extracted from the matched route (e.g. `/users/:id → id = "42"`).
///
/// Distinct from query parameters, which are accessed via [`Request::query_param`].
#[derive(Default, Debug, Clone)]
pub struct PathParams {
    map: HashMap<String, String>,
}

impl PathParams {
    /// Create a new empty path parameters map.
    #[must_use]
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    /// Insert a path parameter.
    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.map.insert(key.into(), value.into());
    }

    /// Get a path parameter value by name.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.map.get(key).map(String::as_str)
    }

    /// Get a mutable reference to a path parameter value.
    pub fn get_mut(&mut self, key: &str) -> Option<&mut String> {
        self.map.get_mut(key)
    }

    /// Remove a path parameter, returning its value if present.
    pub fn remove(&mut self, key: &str) -> Option<String> {
        self.map.remove(key)
    }
}

/// Per-request context — bundles the [`Request`] with [`PathParams`] and [`Extensions`].
///
/// Constructed by the server/router and passed to each handler.
pub struct Context {
    request: Request,
    params: PathParams,
    extensions: Extensions,
}

impl Context {
    /// Create a new context from a request with empty params and extensions.
    #[must_use]
    pub fn new(request: Request) -> Self {
        Self {
            request,
            params: PathParams::new(),
            extensions: Extensions::new(),
        }
    }

    /// Create a context with pre-populated path parameters (used by the router after matching).
    #[must_use]
    pub fn with_params(request: Request, params: PathParams) -> Self {
        Self {
            request,
            params,
            extensions: Extensions::new(),
        }
    }

    /// Returns a shared reference to the underlying request.
    pub fn request(&self) -> &Request {
        &self.request
    }

    /// Returns a shared reference to the path parameters.
    pub fn params(&self) -> &PathParams {
        &self.params
    }

    /// Returns a mutable reference to the path parameters.
    pub fn params_mut(&mut self) -> &mut PathParams {
        &mut self.params
    }

    /// Returns a shared reference to the extensions map.
    pub fn extensions(&self) -> &Extensions {
        &self.extensions
    }

    /// Returns a mutable reference to the extensions map.
    pub fn extensions_mut(&mut self) -> &mut Extensions {
        &mut self.extensions
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::request::Request;

    fn get_request() -> Request {
        let raw = b"GET /users/42 HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let (req, _) = Request::parse(raw).unwrap();
        req
    }

    // ── Extensions ────────────────────────────────────────────────────────────

    #[test]
    fn extensions_insert_and_get() {
        let mut ext = Extensions::new();
        ext.insert(42u32);
        assert_eq!(ext.get::<u32>(), Some(&42));
    }

    #[test]
    fn extensions_get_missing_returns_none() {
        let ext = Extensions::new();
        assert_eq!(ext.get::<u32>(), None);
    }

    #[test]
    fn extensions_insert_returns_previous_value() {
        let mut ext = Extensions::new();
        assert_eq!(ext.insert(1u32), None);
        assert_eq!(ext.insert(2u32), Some(1u32));
        assert_eq!(ext.get::<u32>(), Some(&2));
    }

    #[test]
    fn extensions_contains() {
        let mut ext = Extensions::new();
        assert!(!ext.contains::<u32>());
        ext.insert(1u32);
        assert!(ext.contains::<u32>());
    }

    #[test]
    fn extensions_get_mut() {
        let mut ext = Extensions::new();
        ext.insert(10u32);
        *ext.get_mut::<u32>().unwrap() = 99;
        assert_eq!(ext.get::<u32>(), Some(&99));
    }

    #[test]
    fn extensions_remove() {
        let mut ext = Extensions::new();
        ext.insert(7u32);
        assert_eq!(ext.remove::<u32>(), Some(7u32));
        assert_eq!(ext.get::<u32>(), None);
    }

    #[test]
    fn extensions_remove_missing_returns_none() {
        let mut ext = Extensions::new();
        assert_eq!(ext.remove::<u32>(), None);
    }

    #[test]
    fn extensions_different_types_are_independent() {
        let mut ext = Extensions::new();
        ext.insert(1u32);
        ext.insert("hello");
        assert_eq!(ext.get::<u32>(), Some(&1));
        assert_eq!(ext.get::<&str>(), Some(&"hello"));
        ext.remove::<u32>();
        assert_eq!(ext.get::<u32>(), None);
        assert_eq!(ext.get::<&str>(), Some(&"hello"));
    }

    // ── PathParams ────────────────────────────────────────────────────────────

    #[test]
    fn path_params_insert_and_get() {
        let mut p = PathParams::new();
        p.insert("id", "42");
        assert_eq!(p.get("id"), Some("42"));
    }

    #[test]
    fn path_params_get_missing_returns_none() {
        let p = PathParams::new();
        assert_eq!(p.get("id"), None);
    }

    #[test]
    fn path_params_get_mut_allows_replacement() {
        let mut p = PathParams::new();
        p.insert("id", "1");
        *p.get_mut("id").unwrap() = "99".to_owned();
        assert_eq!(p.get("id"), Some("99"));
    }

    #[test]
    fn path_params_remove() {
        let mut p = PathParams::new();
        p.insert("id", "42");
        assert_eq!(p.remove("id"), Some("42".to_owned()));
        assert_eq!(p.get("id"), None);
    }

    #[test]
    fn path_params_remove_missing_returns_none() {
        let mut p = PathParams::new();
        assert_eq!(p.remove("id"), None);
    }

    // ── Context ───────────────────────────────────────────────────────────────

    #[test]
    fn context_new_exposes_request() {
        let req = get_request();
        let ctx = Context::new(req);
        assert_eq!(ctx.request().path(), "/users/42");
    }

    #[test]
    fn context_with_params_pre_populates() {
        let mut params = PathParams::new();
        params.insert("id", "42");
        let ctx = Context::with_params(get_request(), params);
        assert_eq!(ctx.params().get("id"), Some("42"));
    }

    #[test]
    fn context_params_mut_allows_insertion() {
        let mut ctx = Context::new(get_request());
        ctx.params_mut().insert("slug", "hello-world");
        assert_eq!(ctx.params().get("slug"), Some("hello-world"));
    }

    #[test]
    fn context_extensions_mut_allows_insertion() {
        let mut ctx = Context::new(get_request());
        ctx.extensions_mut().insert(42u32);
        assert_eq!(ctx.extensions().get::<u32>(), Some(&42));
    }

    #[test]
    fn context_extensions_initially_empty() {
        let ctx = Context::new(get_request());
        assert!(!ctx.extensions().contains::<u32>());
    }
}
