//! Request routing — map URL patterns and HTTP methods to handler functions.
//!
//! This module provides [`Router`], which dispatches incoming HTTP requests to handler
//! functions based on the request method and URL path. Three pattern styles are supported:
//!
//! | Pattern              | Example match              | Captured params              |
//! |----------------------|----------------------------|------------------------------|
//! | `/users`             | `/users`                   | *(none)*                     |
//! | `/users/:id`         | `/users/42`                | `id → "42"`                  |
//! | `/files/*`           | `/files/docs/readme.txt`   | `wildcard → "/docs/readme.txt"` |
//!
//! Trailing slashes are normalized on both patterns and incoming paths, so `/users/` and
//! `/users` are treated as equivalent.
//!
//! Routes are matched in registration order; the first route whose method and pattern both
//! match the incoming request wins.

mod core;
/// Handler conversion traits for wrapping async functions and middleware pipelines.
pub mod handler;
/// URL pattern parsing and matching for route registration.
pub mod pattern;

pub use core::{RouteBuilder, Router};
pub use handler::{IntoHandler, IntoRouteConfig};
