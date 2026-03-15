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
use tokio::sync::Semaphore;
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

/// Idle timeout for keep-alive connections (30 seconds between requests).
const KEEP_ALIVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Timeout for reading a complete request body once the first byte has arrived.
const REQUEST_BODY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Default maximum number of concurrent TCP connections.
const DEFAULT_MAX_CONNECTIONS: usize = 1024;

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
    max_connections: usize,
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
            max_connections: DEFAULT_MAX_CONNECTIONS,
        })
    }

    /// Returns the local address the server is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Set the maximum number of concurrent TCP connections.
    ///
    /// When the limit is reached, new connections are queued in the OS backlog
    /// until a slot becomes free. Defaults to `1024`.
    #[must_use]
    pub fn with_max_connections(mut self, max: usize) -> Self {
        self.max_connections = max;
        self
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
        let semaphore = Arc::new(Semaphore::new(self.max_connections));
        info!(address = %self.local_addr, max_connections = self.max_connections, "rttp listening");

        loop {
            // Acquire a connection slot before accepting. This blocks the accept
            // loop when the limit is reached, providing natural backpressure.
            let permit = Arc::clone(&semaphore)
                .acquire_owned()
                .await
                .expect("semaphore closed");

            let (stream, peer_addr) = match self.listener.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    error!(error = %e, "failed to accept connection");
                    drop(permit);
                    continue;
                }
            };

            debug!(peer = %peer_addr, "connection accepted");
            let handler = Arc::clone(&handler);

            tokio::spawn(async move {
                if let Err(e) = handle_connection(stream, peer_addr, handler).await {
                    warn!(peer = %peer_addr, error = %e, "connection closed with error");
                }
                drop(permit); // release slot when connection ends
            });
        }
    }

    /// Starts the server with a graceful shutdown signal.
    ///
    /// Behaves identically to [`run`](Self::run), but stops accepting new
    /// connections when the `shutdown` future resolves. In-flight connections
    /// are given `drain_timeout` to complete before the server returns.
    ///
    /// # Arguments
    ///
    /// - `handler` — request handler (same as [`run`](Self::run)).
    /// - `shutdown` — a future that resolves when the server should begin
    ///   shutting down (e.g. a Ctrl-C signal).
    /// - `drain_timeout` — maximum time to wait for in-flight requests after
    ///   the shutdown signal is received.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use rttp::server::Server;
    /// use rttp::http::{Response, StatusCode};
    /// use std::time::Duration;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let server = Server::bind("127.0.0.1:8080").await?;
    /// server.run_until(
    ///     |_req| async { Response::new(StatusCode::Ok) },
    ///     async { tokio::signal::ctrl_c().await.ok(); },
    ///     Duration::from_secs(30),
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn run_until<H, F, S>(
        self,
        handler: H,
        shutdown: S,
        drain_timeout: std::time::Duration,
    ) -> Result<(), ServerError>
    where
        H: Fn(Request) -> F + Send + Sync + 'static,
        F: Future<Output = Response> + Send + 'static,
        S: Future<Output = ()> + Send + 'static,
    {
        let handler = Arc::new(handler);
        let semaphore = Arc::new(Semaphore::new(self.max_connections));
        info!(
            address = %self.local_addr,
            max_connections = self.max_connections,
            "rttp listening (graceful shutdown enabled)"
        );

        let tracker = Arc::new(tokio::sync::Notify::new());
        let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        tokio::pin!(shutdown);

        loop {
            tokio::select! {
                biased;
                _ = &mut shutdown => {
                    info!("shutdown signal received — draining connections");
                    break;
                }
                result = self.listener.accept() => {
                    let (stream, peer_addr) = match result {
                        Ok(pair) => pair,
                        Err(e) => {
                            error!(error = %e, "failed to accept connection");
                            continue;
                        }
                    };

                    debug!(peer = %peer_addr, "connection accepted");
                    let handler = Arc::clone(&handler);
                    let active = Arc::clone(&active);
                    let tracker = Arc::clone(&tracker);
                    let semaphore = Arc::clone(&semaphore);

                    // Acquire a connection slot (non-blocking — skip if full).
                    let permit = match semaphore.try_acquire_owned() {
                        Ok(p) => p,
                        Err(_) => {
                            warn!(peer = %peer_addr, "connection limit reached — dropping connection");
                            continue;
                        }
                    };

                    active.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, peer_addr, handler).await {
                            warn!(peer = %peer_addr, error = %e, "connection closed with error");
                        }
                        drop(permit);
                        if active.fetch_sub(1, std::sync::atomic::Ordering::SeqCst) == 1 {
                            tracker.notify_one();
                        }
                    });
                }
            }
        }

        // Wait for in-flight connections to drain.
        if active.load(std::sync::atomic::Ordering::SeqCst) > 0 {
            info!("waiting up to {drain_timeout:?} for in-flight connections");
            let _ = tokio::time::timeout(drain_timeout, tracker.notified()).await;
        }

        info!("server shut down");
        Ok(())
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
    // Cached parse state: once headers are complete, store (body_offset, content_length)
    // so we don't re-run httparse on subsequent read chunks.
    let mut cached_parse: Option<(usize, usize)> = None;

    loop {
        // Apply a timeout on idle keep-alive reads (first read of a new request).
        // Once the buffer is non-empty we are mid-request and apply a tighter
        // body-read timeout to guard against slow-client / Slowloris attacks.
        let bytes_read = if buf.is_empty() {
            match tokio::time::timeout(KEEP_ALIVE_TIMEOUT, stream.read_buf(&mut buf)).await {
                Ok(result) => result?,
                Err(_) => {
                    debug!(peer = %peer_addr, "keep-alive timeout — closing");
                    break;
                }
            }
        } else {
            match tokio::time::timeout(REQUEST_BODY_TIMEOUT, stream.read_buf(&mut buf)).await {
                Ok(result) => result?,
                Err(_) => {
                    warn!(peer = %peer_addr, "request body timeout — sending 408");
                    let response = Response::new(StatusCode::RequestTimeout)
                        .body("Request Timeout")
                        .keep_alive(false);
                    let _ = stream.write_all(&response.into_bytes()).await;
                    break;
                }
            }
        };

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

        // Parse headers only if we haven't cached the result yet.
        let (body_offset, content_length) = if let Some(cached) = cached_parse {
            cached
        } else {
            match Request::parse(&buf) {
                Ok((request, body_offset)) => {
                    let cl = request.content_length().unwrap_or(0);

                    // Reject oversized Content-Length before buffering the body.
                    if cl > MAX_REQUEST_SIZE {
                        warn!(
                            peer = %peer_addr,
                            content_length = cl,
                            "Content-Length exceeds limit — sending 413"
                        );
                        let response = Response::new(StatusCode::PayloadTooLarge)
                            .body("Request entity too large")
                            .keep_alive(false);
                        stream.write_all(&response.into_bytes()).await?;
                        break;
                    }

                    cached_parse = Some((body_offset, cl));
                    (body_offset, cl)
                }
                Err(RequestError::Incomplete) => continue,
                Err(e) => {
                    warn!(peer = %peer_addr, error = %e, "bad request — sending 400");
                    let response = Response::new(StatusCode::BadRequest)
                        .body(format!("Bad Request: {e}"))
                        .keep_alive(false);
                    stream.write_all(&response.into_bytes()).await?;
                    break;
                }
            }
        };

        // Wait for the full body to arrive.
        let total_needed = body_offset + content_length;
        if buf.len() < total_needed {
            continue;
        }

        // Consume the request bytes from the buffer BEFORE calling the handler,
        // so that a handler panic doesn't leave stale bytes.
        let request_buf = buf.split_to(total_needed).freeze();
        cached_parse = None;

        let (request, _) = match Request::parse(&request_buf) {
            Ok(pair) => pair,
            Err(e) => {
                warn!(peer = %peer_addr, error = %e, "re-parse failed — sending 400");
                let response = Response::new(StatusCode::BadRequest)
                    .body(format!("Bad Request: {e}"))
                    .keep_alive(false);
                stream.write_all(&response.into_bytes()).await?;
                break;
            }
        };

        let keep_alive = request.is_keep_alive();

        debug!(
            peer = %peer_addr,
            method = %request.method(),
            path = %request.path(),
            "dispatching request"
        );

        // Spawn the handler as a separate task so that a handler panic is
        // caught by Tokio's task infrastructure rather than propagating up
        // and abruptly closing the connection without a proper response.
        let handler = Arc::clone(&handler);
        let response = match tokio::spawn(async move { handler(request).await }).await {
            Ok(resp) => resp,
            Err(_panic) => {
                error!(peer = %peer_addr, "handler panicked — sending 500");
                Response::new(StatusCode::InternalServerError)
                    .body("Internal Server Error")
                    .keep_alive(false)
            }
        };

        stream.write_all(&response.into_bytes()).await?;
        stream.flush().await?;

        if !keep_alive {
            debug!(peer = %peer_addr, "Connection: close — shutting down");
            break;
        }

        // Shrink the buffer back to the initial capacity after a large request
        // to avoid retaining a multi-megabyte allocation for the rest of the
        // keep-alive connection's life.
        if buf.capacity() > INITIAL_BUF_SIZE * 4 {
            buf = BytesMut::with_capacity(INITIAL_BUF_SIZE);
        }
    }

    Ok(())
}
