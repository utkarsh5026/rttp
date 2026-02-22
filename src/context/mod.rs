//! Per-request context — type-safe state injection and request extensions.
//!
//! ## Planned Features
//!
//! - Type-erased extension map for handler state
//! - Path parameter extraction (from router matches)
//! - Authenticated user principal injection
//! - Request-scoped dependency injection
//!
//!


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
    /// Create a new empty extensions map
    pub fn new() -> Self {
        return Self {
            map: HashMap::new(),
        };
    }

    /// Insert a value into the extensions map
    pub fn insert<T>(&mut self, value: T)
    where
        T: Send + Sync + 'static,
    {
        self.map.insert(TypeId::of::<T>(), Box::new(value));
    }

    /// Get a value from the extensions map
    pub fn get<T>(&self) -> Option<&T>
    where
        T: Send + Sync + 'static,
    {
        self.map
            .get(&TypeId::of::<T>())
            .and_then(|value| value.downcast_ref::<T>())
    }

    /// Get a mutable reference to a value from the extensions map
    pub fn get_mut<T>(&mut self) -> Option<&mut T>
    where
        T: Send + Sync + 'static,
    {
        self.map
            .get_mut(&TypeId::of::<T>())
            .and_then(|value| value.downcast_mut::<T>())
    }

    /// Remove a value from the extensions map
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

/// Path parameters extracted from the matched route
#[derive(Default, Debug, Clone)]
pub struct Parameters {
    map: HashMap<String, String>,
}

impl Parameters {
    /// Create a new empty parameters map
    pub fn new() -> Self {
        return Self {
            map: HashMap::new(),
        };
    }

    /// Insert a value into the parameters map
    pub fn insert(&mut self, key: String, value: String) {
        self.map.insert(key, value);
    }

    /// Get a value from the parameters map
    pub fn get(&self, key: &str) -> Option<&str> {
        self.map.get(key).map(|value| value.as_str())
    }

    /// Get a mutable reference to a value from the parameters map
    pub fn get_mut(&mut self, key: &str) -> Option<&mut str> {
        self.map.get_mut(key).map(|value| value.as_mut())
    }

    /// Remove a value from the parameters map
    pub fn remove(&mut self, key: &str) -> Option<String> {
        self.map.remove(key)
    }
}

/// Per-request context — type-safe state injection and request extensions.
pub struct Context {
    request: Request,
    params: Parameters,
    extensions: Extensions,
}

impl Context {
    /// Create a new context from a request
    pub fn new(request: Request) -> Self {
        return Self {
            request,
            params: Parameters::new(),
            extensions: Extensions::new(),
        };
    }

    pub fn request(&self) -> &Request {
        &self.request
    }

    pub fn params(&self) -> &Parameters {
        &self.params
    }

    pub fn extensions(&self) -> &Extensions {
        &self.extensions
    }

    pub fn json<T>(&self) -> Result<T, serde_json::Error>
    where
        T: serde::de::DeserializeOwned,
    {
        let body = self.request.body();
        serde_json::from_slice(body)
    }
}
