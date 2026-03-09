//! IP allowlist / blocklist middleware.
//!
//! Resolves the client IP from (in priority order):
//! 1. `X-Forwarded-For` — rightmost untrusted entry, controlled by
//!    [`trusted_proxy_depth`](IpFilterMiddleware::trusted_proxy_depth).
//! 2. `X-Real-IP` header.
//! 3. A [`std::net::SocketAddr`] stored in `ctx.extensions()` by the server.
//!
//! Both exact IPs and CIDR blocks (`192.168.1.0/24`, `::1/128`) are supported
//! for IPv4 and IPv6 addresses.
//!
//! # Examples
//!
//! ```rust,no_run
//! use rttp::security::IpFilterMiddleware;
//!
//! // Allowlist — only these ranges may proceed.
//! let filter = IpFilterMiddleware::allowlist()
//!     .add_cidr("10.0.0.0/8")
//!     .add_cidr("127.0.0.1/32");
//!
//! // Blocklist — these IPs are rejected; everyone else passes.
//! let filter = IpFilterMiddleware::blocklist()
//!     .add_cidr("192.0.2.0/24")
//!     .not_found_on_block();
//! ```

use std::{
    future::Future,
    net::{IpAddr, SocketAddr},
    pin::Pin,
};

use crate::{
    Response, StatusCode,
    context::Context,
    middleware::{Middleware, Next},
};

/// A parsed CIDR network range (IPv4 or IPv6).
#[derive(Debug, Clone)]
struct Cidr {
    addr: IpAddr,
    prefix_len: u8,
}

impl Cidr {
    /// Parse a CIDR string such as `"192.168.1.0/24"` or `"::1/128"`.
    ///
    /// A bare IP with no `/prefix` is treated as a /32 (IPv4) or /128 (IPv6).
    fn parse(s: &str) -> Result<Self, String> {
        let (addr_str, prefix_len) = if let Some((a, p)) = s.split_once('/') {
            let prefix: u8 = p
                .parse()
                .map_err(|_| format!("invalid prefix length in '{s}'"))?;
            (a, prefix)
        } else {
            let addr: IpAddr = s.parse().map_err(|_| format!("invalid IP address '{s}'"))?;
            let max = if addr.is_ipv4() { 32 } else { 128 };
            return Ok(Self {
                addr,
                prefix_len: max,
            });
        };

        let addr: IpAddr = addr_str
            .parse()
            .map_err(|_| format!("invalid IP address '{addr_str}'"))?;

        let max_prefix = if addr.is_ipv4() { 32u8 } else { 128u8 };
        if prefix_len > max_prefix {
            return Err(format!(
                "prefix length {prefix_len} exceeds maximum {max_prefix} for '{s}'"
            ));
        }

        Ok(Self { addr, prefix_len })
    }

    /// Returns `true` if `ip` falls within this CIDR block.
    fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(client)) => {
                let net_bits = u32::from(net);
                let client_bits = u32::from(client);
                let mask = if self.prefix_len == 0 {
                    0u32
                } else {
                    !0u32 << (32 - self.prefix_len)
                };
                (net_bits & mask) == (client_bits & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(client)) => {
                let net_bits = u128::from(net);
                let client_bits = u128::from(client);
                let mask = if self.prefix_len == 0 {
                    0u128
                } else {
                    !0u128 << (128 - self.prefix_len)
                };
                (net_bits & mask) == (client_bits & mask)
            }

            _ => false,
        }
    }
}

// ── Filter mode ───────────────────────────────────────────────────────────────

/// Controls whether the CIDR list is used as an allowlist or a blocklist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterMode {
    /// Only requests whose source IP matches one of the listed CIDRs are allowed.
    /// All others receive the configured block response.
    Allowlist,
    /// Requests whose source IP matches one of the listed CIDRs are blocked.
    /// All others pass through.
    Blocklist,
}

/// IP allowlist / blocklist middleware.
///
/// See the [module documentation](self) for details and usage examples.
pub struct IpFilterMiddleware {
    mode: FilterMode,
    cidrs: Vec<Cidr>,
    block_status: StatusCode,
    /// Number of rightmost `X-Forwarded-For` entries that belong to trusted
    /// proxies. E.g. `1` means the last entry is your own proxy and the one
    /// before it is the real client IP.
    trusted_proxy_depth: usize,
}

impl IpFilterMiddleware {
    fn new(mode: FilterMode) -> Self {
        Self {
            mode,
            cidrs: Vec::new(),
            block_status: StatusCode::Forbidden,
            trusted_proxy_depth: 0,
        }
    }

    /// Create an allowlist filter — only matching IPs are permitted.
    #[must_use]
    pub fn allowlist() -> Self {
        Self::new(FilterMode::Allowlist)
    }

    /// Create a blocklist filter — matching IPs are rejected.
    #[must_use]
    pub fn blocklist() -> Self {
        Self::new(FilterMode::Blocklist)
    }

    /// Add an IP or CIDR range to the filter list.
    ///
    /// Accepts dotted-decimal IPv4 (`"1.2.3.4"`), IPv6 (`"::1"`), or CIDR
    /// notation (`"10.0.0.0/8"`, `"2001:db8::/32"`).
    ///
    /// # Panics
    ///
    /// Panics if the string cannot be parsed as a valid IP/CIDR expression.
    #[must_use]
    pub fn add_cidr(mut self, cidr: &str) -> Self {
        match Cidr::parse(cidr) {
            Ok(c) => self.cidrs.push(c),
            Err(e) => panic!("IpFilterMiddleware::add_cidr: {e}"),
        }
        self
    }

    /// Use `404 Not Found` as the block response instead of `403 Forbidden`.
    ///
    /// Returning 404 avoids leaking the existence of rate-limited or
    /// restricted resources to probing attackers (security through obscurity).
    #[must_use]
    pub fn not_found_on_block(mut self) -> Self {
        self.block_status = StatusCode::NotFound;
        self
    }

    /// Set the number of rightmost `X-Forwarded-For` hops to skip as trusted
    /// proxy entries when resolving the client IP.
    ///
    /// With `depth = 1`, the second-to-last entry in `X-Forwarded-For` is used
    /// as the client IP (the last entry is assumed to be your own edge proxy).
    #[must_use]
    pub fn trusted_proxy_depth(mut self, depth: usize) -> Self {
        self.trusted_proxy_depth = depth;
        self
    }

    /// Resolve the effective client IP from the request context.
    ///
    /// Priority:
    /// 1. `X-Forwarded-For` — skip `trusted_proxy_depth` entries from the right.
    /// 2. `X-Real-IP` header.
    /// 3. `SocketAddr` stored in `ctx.extensions()`.
    fn resolve_ip(&self, ctx: &Context) -> Option<IpAddr> {
        let headers = ctx.request().headers();

        if let Some(xff) = headers.get("x-forwarded-for") {
            let parts: Vec<&str> = xff.split(',').map(str::trim).collect();
            let skip = self.trusted_proxy_depth.min(parts.len().saturating_sub(1));
            let index = parts.len().saturating_sub(1 + skip);
            if let Some(raw) = parts.get(index) {
                if let Ok(ip) = raw.parse::<IpAddr>() {
                    return Some(ip);
                }
            }
        }

        if let Some(raw) = headers.get("x-real-ip") {
            if let Ok(ip) = raw.trim().parse::<IpAddr>() {
                return Some(ip);
            }
        }

        ctx.extensions().get::<SocketAddr>().map(SocketAddr::ip)
    }

    /// Returns `true` if `ip` matches any entry in the CIDR list.
    fn matches(&self, ip: IpAddr) -> bool {
        self.cidrs.iter().any(|c| c.contains(ip))
    }
}

impl Middleware for IpFilterMiddleware {
    /// Enforce the IP filter policy before passing to the next handler.
    ///
    /// - **Allowlist**: if the resolved IP matches a listed CIDR, the request
    ///   proceeds; otherwise the block response is returned immediately.
    /// - **Blocklist**: if the resolved IP matches a listed CIDR, the block
    ///   response is returned immediately; otherwise the request proceeds.
    ///
    /// If no client IP can be resolved (no headers and no `SocketAddr` in
    /// extensions), the request is **blocked** on an allowlist and **allowed**
    /// through on a blocklist (fail-closed vs fail-open).
    fn handle(&self, ctx: Context, next: Next) -> Pin<Box<dyn Future<Output = Response> + Send>> {
        let block_status = self.block_status;
        let ip = self.resolve_ip(&ctx);
        let matched = ip.map(|ip| self.matches(ip));

        let allow = match self.mode {
            FilterMode::Allowlist => matched.unwrap_or(false),
            FilterMode::Blocklist => !matched.unwrap_or(false),
        };

        Box::pin(async move {
            if allow {
                next.run(ctx).await
            } else {
                Response::new(block_status)
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Response, StatusCode,
        context::Context,
        middleware::{MiddlewareHandler, Next},
    };
    use std::sync::Arc;

    fn make_context(raw: &[u8]) -> Context {
        let (req, _) = crate::Request::parse(raw).unwrap();
        Context::new(req)
    }

    fn make_context_with_peer(raw: &[u8], peer: SocketAddr) -> Context {
        let (req, _) = crate::Request::parse(raw).unwrap();
        let mut ctx = Context::new(req);
        ctx.extensions_mut().insert(peer);
        ctx
    }

    fn ok_next() -> Next {
        let handler: MiddlewareHandler = Arc::new(|_ctx: Context, _next: Next| {
            Box::pin(async { Response::new(StatusCode::Ok) })
        });
        Next::new(vec![handler])
    }

    // ── Cidr::parse ───────────────────────────────────────────────────────────

    #[test]
    fn cidr_parse_ipv4_with_prefix() {
        let c = Cidr::parse("192.168.1.0/24").unwrap();
        assert!(c.contains("192.168.1.1".parse().unwrap()));
        assert!(c.contains("192.168.1.255".parse().unwrap()));
        assert!(!c.contains("192.168.2.0".parse().unwrap()));
    }

    #[test]
    fn cidr_parse_bare_ipv4_is_slash32() {
        let c = Cidr::parse("10.0.0.5").unwrap();
        assert!(c.contains("10.0.0.5".parse().unwrap()));
        assert!(!c.contains("10.0.0.6".parse().unwrap()));
    }

    #[test]
    fn cidr_parse_ipv6_loopback() {
        let c = Cidr::parse("::1/128").unwrap();
        assert!(c.contains("::1".parse().unwrap()));
        assert!(!c.contains("::2".parse().unwrap()));
    }

    #[test]
    fn cidr_parse_ipv6_prefix() {
        let c = Cidr::parse("2001:db8::/32").unwrap();
        assert!(c.contains("2001:db8::1".parse().unwrap()));
        assert!(!c.contains("2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn cidr_parse_invalid_returns_err() {
        assert!(Cidr::parse("not-an-ip").is_err());
        assert!(Cidr::parse("192.168.0.0/33").is_err());
    }

    // ── Allowlist ─────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn allowlist_permits_matching_ip_via_xff() {
        let filter = IpFilterMiddleware::allowlist().add_cidr("10.0.0.0/8");
        let ctx =
            make_context(b"GET / HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-For: 10.1.2.3\r\n\r\n");
        let resp = filter.handle(ctx, ok_next()).await;
        assert_eq!(resp.status(), StatusCode::Ok);
    }

    #[tokio::test]
    async fn allowlist_blocks_non_matching_ip_via_xff() {
        let filter = IpFilterMiddleware::allowlist().add_cidr("10.0.0.0/8");
        let ctx =
            make_context(b"GET / HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-For: 1.2.3.4\r\n\r\n");
        let resp = filter.handle(ctx, ok_next()).await;
        assert_eq!(resp.status(), StatusCode::Forbidden);
    }

    #[tokio::test]
    async fn allowlist_blocks_no_ip_fail_closed() {
        let filter = IpFilterMiddleware::allowlist().add_cidr("10.0.0.0/8");
        let ctx = make_context(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
        let resp = filter.handle(ctx, ok_next()).await;
        assert_eq!(resp.status(), StatusCode::Forbidden);
    }

    // ── Blocklist ─────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn blocklist_blocks_matching_ip() {
        let filter = IpFilterMiddleware::blocklist().add_cidr("192.0.2.0/24");
        let ctx = make_context(
            b"GET / HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-For: 192.0.2.100\r\n\r\n",
        );
        let resp = filter.handle(ctx, ok_next()).await;
        assert_eq!(resp.status(), StatusCode::Forbidden);
    }

    #[tokio::test]
    async fn blocklist_permits_non_matching_ip() {
        let filter = IpFilterMiddleware::blocklist().add_cidr("192.0.2.0/24");
        let ctx = make_context(
            b"GET / HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-For: 203.0.113.5\r\n\r\n",
        );
        let resp = filter.handle(ctx, ok_next()).await;
        assert_eq!(resp.status(), StatusCode::Ok);
    }

    #[tokio::test]
    async fn blocklist_allows_no_ip_fail_open() {
        let filter = IpFilterMiddleware::blocklist().add_cidr("192.0.2.0/24");
        let ctx = make_context(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
        let resp = filter.handle(ctx, ok_next()).await;
        assert_eq!(resp.status(), StatusCode::Ok);
    }

    // ── Block status ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn not_found_on_block_returns_404() {
        let filter = IpFilterMiddleware::allowlist()
            .add_cidr("10.0.0.0/8")
            .not_found_on_block();
        let ctx =
            make_context(b"GET / HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-For: 1.2.3.4\r\n\r\n");
        let resp = filter.handle(ctx, ok_next()).await;
        assert_eq!(resp.status(), StatusCode::NotFound);
    }

    // ── IP resolution priority ────────────────────────────────────────────────

    #[tokio::test]
    async fn xff_takes_priority_over_x_real_ip() {
        // XFF says 10.x (allowed), X-Real-IP says 1.x (not allowed).
        // If XFF wins, the request should pass.
        let filter = IpFilterMiddleware::allowlist().add_cidr("10.0.0.0/8");
        let ctx = make_context(
            b"GET / HTTP/1.1\r\nHost: localhost\r\n\
              X-Forwarded-For: 10.0.0.1\r\nX-Real-IP: 1.2.3.4\r\n\r\n",
        );
        let resp = filter.handle(ctx, ok_next()).await;
        assert_eq!(resp.status(), StatusCode::Ok);
    }

    #[tokio::test]
    async fn x_real_ip_used_when_no_xff() {
        let filter = IpFilterMiddleware::allowlist().add_cidr("10.0.0.0/8");
        let ctx = make_context(b"GET / HTTP/1.1\r\nHost: localhost\r\nX-Real-IP: 10.0.0.5\r\n\r\n");
        let resp = filter.handle(ctx, ok_next()).await;
        assert_eq!(resp.status(), StatusCode::Ok);
    }

    #[tokio::test]
    async fn socket_addr_used_as_fallback() {
        let filter = IpFilterMiddleware::allowlist().add_cidr("10.0.0.0/8");
        let peer: SocketAddr = "10.0.0.9:4321".parse().unwrap();
        let ctx = make_context_with_peer(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n", peer);
        let resp = filter.handle(ctx, ok_next()).await;
        assert_eq!(resp.status(), StatusCode::Ok);
    }

    // ── Trusted proxy depth ───────────────────────────────────────────────────

    #[tokio::test]
    async fn trusted_proxy_depth_skips_rightmost_entries() {
        // XFF: "1.2.3.4, 10.0.0.1" — last entry is our trusted proxy.
        // With depth=1 the effective client IP is 1.2.3.4 (not allowed).
        let filter = IpFilterMiddleware::allowlist()
            .add_cidr("10.0.0.0/8")
            .trusted_proxy_depth(1);
        let ctx = make_context(
            b"GET / HTTP/1.1\r\nHost: localhost\r\n\
              X-Forwarded-For: 1.2.3.4, 10.0.0.1\r\n\r\n",
        );
        let resp = filter.handle(ctx, ok_next()).await;
        assert_eq!(resp.status(), StatusCode::Forbidden);
    }

    #[tokio::test]
    async fn trusted_proxy_depth_zero_uses_rightmost_entry() {
        // depth=0 — rightmost entry is the client IP.
        let filter = IpFilterMiddleware::allowlist()
            .add_cidr("10.0.0.0/8")
            .trusted_proxy_depth(0);
        let ctx = make_context(
            b"GET / HTTP/1.1\r\nHost: localhost\r\n\
              X-Forwarded-For: 1.2.3.4, 10.0.0.1\r\n\r\n",
        );
        let resp = filter.handle(ctx, ok_next()).await;
        assert_eq!(resp.status(), StatusCode::Ok);
    }

    // ── Multiple CIDRs ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn multiple_cidrs_any_match_is_sufficient() {
        let filter = IpFilterMiddleware::allowlist()
            .add_cidr("10.0.0.0/8")
            .add_cidr("172.16.0.0/12");
        for ip in &["10.5.5.5", "172.20.0.1"] {
            let raw = format!("GET / HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-For: {ip}\r\n\r\n");
            let ctx = make_context(raw.as_bytes());
            let resp = filter.handle(ctx, ok_next()).await;
            assert_eq!(resp.status(), StatusCode::Ok, "expected Ok for {ip}");
        }
    }
}
