//! # rttp
//!
//! A from-scratch async HTTP/1.1 server framework written in Rust.
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use rttp::server::Server;
//! use rttp::http::{Request, Response, StatusCode};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let server = Server::bind("127.0.0.1:8080").await?;
//!     println!("Listening on http://127.0.0.1:8080");
//!     server.run(|_req: Request| async {
//!         Response::new(StatusCode::Ok).body("Hello, World!")
//!     }).await?;
//!     Ok(())
//! }
//! ```

// ── Active modules with real implementations ──────────────────────────────────
pub mod http;
pub mod server;

// ── Planned modules — stubs for future implementation ────────────────────────
pub mod background;
pub mod cache;
pub mod context;
pub mod database;
pub mod llm;
pub mod middleware;
pub mod realtime;
pub mod router;
pub mod security;

// ── Convenience re-exports ────────────────────────────────────────────────────
pub use http::{Headers, Method, Request, Response, StatusCode};
pub use server::{Server, ServerError};
