//! Async TCP server using Tokio.
//!
//! Accepts TCP connections and dispatches HTTP/1.1 requests to a handler function.
//! Supports HTTP/1.1 persistent connections (keep-alive) out of the box.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::BytesMut;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

use crate::http::{
    StatusCode,
    request::{Request, RequestError},
    response::Response,
};

/// Errors produced by the server.
#[derive(Debug, Error)]
pub enum ServerError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("failed to bind to {addr}: {source}")]
    Bind {
        addr: String,
        #[source]
        source: std::io::Error,
    },
}

/// Maximum size of a complete HTTP request we will buffer before rejecting it (8 MiB).
const MAX_REQUEST_SIZE: usize = 8 * 1024 * 1024;

/// Initial read buffer capacity per connection.
const INITIAL_BUF_SIZE: usize = 4096;

/// The rttp HTTP server.
///
/// Binds to a TCP address and dispatches incoming HTTP/1.1 requests to a
/// handler function.
///
/// # Examples
///
/// ```rust,no_run
/// use rttp::server::Server;
/// use rttp::http::{Request, Response, StatusCode};
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let server = Server::bind("127.0.0.1:8080").await?;
///     server.run(|_req| async {
///         Response::new(StatusCode::Ok).body("Hello!")
///     }).await?;
///     Ok(())
/// }
/// ```
pub struct Server {
    listener: TcpListener,
    local_addr: SocketAddr,
}

impl Server {
    /// Binds the server to the given TCP address.
    ///
    /// # Errors
    ///
    /// Returns [`ServerError::Bind`] if the address cannot be bound
    /// (e.g. port already in use, insufficient permissions).
    pub async fn bind(addr: impl AsRef<str>) -> Result<Self, ServerError> {
        let addr = addr.as_ref();
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| ServerError::Bind {
                addr: addr.to_owned(),
                source: e,
            })?;
        let local_addr = listener.local_addr()?;
        Ok(Self {
            listener,
            local_addr,
        })
    }

    /// Returns the local address the server is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Starts accepting connections and dispatching requests to `handler`.
    ///
    /// The handler receives a [`Request`] and must return a [`Future`] that
    /// resolves to a [`Response`]. The handler is wrapped in an [`Arc`] and
    /// shared across all spawned Tokio tasks, so it must be `Send + Sync + 'static`.
    ///
    /// This method runs until the process is terminated or an unrecoverable
    /// listener error occurs.
    ///
    /// # Errors
    ///
    /// Returns [`ServerError::Io`] if the TCP listener itself fails.
    pub async fn run<H, F>(self, handler: H) -> Result<(), ServerError>
    where
        H: Fn(Request) -> F + Send + Sync + 'static,
        F: Future<Output = Response> + Send + 'static,
    {
        let handler = Arc::new(handler);
        info!(address = %self.local_addr, "rttp listening");

        loop {
            let (stream, peer_addr) = match self.listener.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    error!(error = %e, "failed to accept connection");
                    continue;
                }
            };

            debug!(peer = %peer_addr, "connection accepted");
            let handler = Arc::clone(&handler);

            tokio::spawn(async move {
                if let Err(e) = handle_connection(stream, peer_addr, handler).await {
                    warn!(peer = %peer_addr, error = %e, "connection closed with error");
                }
            });
        }
    }
}

/// Handles a single TCP connection over its lifetime.
///
/// HTTP/1.1 connections are persistent by default: we loop, reading one
/// request per iteration, until the peer closes the connection or signals
/// `Connection: close`.
async fn handle_connection<H, F>(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    handler: Arc<H>,
) -> Result<(), std::io::Error>
where
    H: Fn(Request) -> F + Send + Sync + 'static,
    F: Future<Output = Response> + Send + 'static,
{
    let mut buf = BytesMut::with_capacity(INITIAL_BUF_SIZE);

    loop {
        let bytes_read = stream.read_buf(&mut buf).await?;

        if bytes_read == 0 {
            debug!(peer = %peer_addr, "connection closed by peer");
            break;
        }

        // Guard against excessively large requests.
        if buf.len() > MAX_REQUEST_SIZE {
            warn!(peer = %peer_addr, "request too large — sending 413");
            let response = Response::new(StatusCode::PayloadTooLarge)
                .body("Request entity too large")
                .keep_alive(false);
            stream.write_all(&response.into_bytes()).await?;
            break;
        }

        // Attempt to parse the buffered data as an HTTP request.
        let (request, body_offset) = match Request::parse(&buf) {
            Ok(pair) => pair,
            Err(RequestError::Incomplete) => {
                // Headers not yet fully received — read more data.
                continue;
            }
            Err(e) => {
                warn!(peer = %peer_addr, error = %e, "bad request — sending 400");
                let response = Response::new(StatusCode::BadRequest)
                    .body(format!("Bad Request: {e}"))
                    .keep_alive(false);
                stream.write_all(&response.into_bytes()).await?;
                break;
            }
        };

        // Wait for the full body to arrive if Content-Length is set.
        let content_length = request.content_length().unwrap_or(0);
        let total_needed = body_offset + content_length;
        if buf.len() < total_needed {
            continue;
        }

        let keep_alive = request.is_keep_alive();

        debug!(
            peer = %peer_addr,
            method = %request.method(),
            path = %request.path(),
            "dispatching request"
        );

        let response = handler(request).await;
        stream.write_all(&response.into_bytes()).await?;
        stream.flush().await?;

        // Drop the consumed request bytes from the buffer.
        let _ = buf.split_to(total_needed);

        if !keep_alive {
            debug!(peer = %peer_addr, "Connection: close — shutting down");
            break;
        }
    }

    Ok(())
}
