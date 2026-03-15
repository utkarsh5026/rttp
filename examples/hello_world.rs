//! Minimal hello-world server.
//!
//! Demonstrates the simplest possible rttp application:
//! a single route that returns a plain-text response.
//!
//! Run with:
//!   cargo run --example hello_world
//!
//! Then visit: http://localhost:8080

use rttp::app::App;
use rttp::server::Server;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();

    let app = App::new()
        .get("/", || async { "Hello, World!" })
        .get("/ping", || async { "pong" });

    let server = Server::bind("127.0.0.1:8080").await?;
    tracing::info!("Listening on http://127.0.0.1:8080");
    server.run(app.into_service()).await?;
    Ok(())
}
