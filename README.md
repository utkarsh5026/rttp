# rttp

**A from-scratch, async HTTP/1.1 server framework written in Rust.**

*No hyper. No axum. No magic — just Rust, Tokio, and curiosity.*

[![Build Status](https://img.shields.io/github/actions/workflow/status/utkarshpriyadarshi/rttp/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/utkarshpriyadarshi/rttp/actions)
[![Version](https://img.shields.io/badge/version-0.1.0-blue?style=flat-square)](Cargo.toml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)
[![Rust Edition](https://img.shields.io/badge/rust-2024%20%7C%20MSRV%201.85-orange?style=flat-square)](https://www.rust-lang.org/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen?style=flat-square)](CONTRIBUTING.md)

![rttp Banner](https://via.placeholder.com/800x200/1a1a2e/ffffff?text=rttp+%E2%80%94+Async+HTTP%2F1.1+in+Pure+Rust)

---

## Table of Contents

- [About The Project](#about-the-project)
- [Key Features](#key-features)
- [Getting Started](#getting-started)
- [Usage](#usage)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

---

## About The Project

**rttp** is an async HTTP/1.1 server framework built entirely from scratch in Rust — no `hyper`, no `axum`, no existing HTTP framework underneath. It is an intentional, ground-up exploration of how modern web frameworks operate at the protocol level, designed to be both educational and production-quality.

The project answers the question: *"What does it actually take to build a capable web framework from raw TCP bytes?"*

It handles everything from parsing raw HTTP/1.1 request buffers to routing, middleware pipelines, security primitives, and graceful shutdown — all built on a minimal dependency footprint.

### Tech Stack

| Crate | Purpose |
| --- | --- |
| [tokio](https://tokio.rs) | Async runtime — TCP listener, connection tasks, timers |
| [httparse](https://crates.io/crates/httparse) | Zero-copy HTTP/1.1 push parser |
| [bytes](https://crates.io/crates/bytes) | Efficient byte buffer management (`BytesMut`) |
| [thiserror](https://crates.io/crates/thiserror) | Ergonomic error enum derivation |
| [tracing](https://crates.io/crates/tracing) | Structured, async-aware logging |
| [serde / serde_json](https://serde.rs) | Serialization for JSON body handling |
| [jsonwebtoken](https://crates.io/crates/jsonwebtoken) | JWT signing and verification (HS256/HS512) |
| [uuid](https://crates.io/crates/uuid) | Request correlation ID generation |

---

## Key Features

- 🔍 **HTTP/1.1 Parsing** — zero-copy request parsing via `httparse`, with query-string decoding and keep-alive detection
- ⚡ **Async TCP Server** — Tokio-powered connection handling with HTTP/1.1 keep-alive, 30-second idle timeout, 8 MiB request size guard, and graceful shutdown with in-flight draining
- 🏗️ **Fluent Response Builder** — helper methods for `.json()`, `.html()`, `.text()`, `.redirect()`, `.empty()` with automatic `Content-Length` injection
- 📋 **Header Map** — case-insensitive, order-preserving, multi-value header map (RFC 9110 §5 compliant)
- 🗺️ **URL Router** — pattern-matching router supporting exact (`/users`), parameterized (`/users/:id`), and wildcard (`/files/*`) routes with first-match-wins semantics
- 🔐 **JWT Middleware** — Bearer token extraction, claims validation, and context injection with `401` on failure
- 🔑 **API Key Middleware** — `X-Api-Key` / `Authorization: ApiKey` support with constant-time comparison (timing-attack resistant) and `403` on invalid/expired keys
- 🌐 **CORS Middleware** — configurable origin/method/header restrictions, preflight (`OPTIONS`) short-circuit, and `Vary: Origin` for cache correctness
- 🚧 **IP Filter Middleware** — CIDR allowlist/blocklist for IPv4 and IPv6 with `X-Forwarded-For` proxy depth support
- 🛡️ **CSRF Protection** — token generation and header extraction infrastructure
- 🪣 **Token Bucket Rate Limiting** — per-second/minute/hour configs with a clean `RateLimitConfig` API
- 🪪 **Request ID Middleware** — automatic correlation ID injection per request
- 📡 **`IntoResponse` Trait** — ergonomic handler return types

---

## Getting Started

### Prerequisites

Rust 1.85+ is required for the 2024 edition:

```bash
rustup update stable
rustc --version  # should be >= 1.85
```

### Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/utkarshpriyadarshi/rttp.git
   cd rttp
   ```

2. Build the project:

   ```bash
   ~/.cargo/bin/cargo build
   ```

3. Run the hello-world example:

   ```bash
   make run
   # or directly:
   ~/.cargo/bin/cargo run --example hello_world
   ```

   The server will be available at `http://localhost:8080`.

### Common Commands

```bash
make run    # Run the hello_world example
make test   # Run all tests
make lint   # Clippy with -D warnings
make fmt    # Auto-format code
make ci     # Full CI pipeline (fmt + check + lint + test + audit)
make doc    # Generate and open documentation
```

---

## Usage

A minimal server with routing:

```rust
use rttp::{App, Router, Request, Response, StatusCode};

#[tokio::main]
async fn main() {
    let mut router = Router::new();

    router.get("/", |_req: Request| async {
        Response::text("Hello, world!")
    });

    router.get("/users/:id", |req: Request| async move {
        let id = req.params().get("id").cloned().unwrap_or_default();
        Response::json(serde_json::json!({ "user_id": id }))
    });

    router.post("/echo", |req: Request| async move {
        Response::builder()
            .status(StatusCode::OK)
            .body(req.body().to_vec())
            .build()
    });

    App::new()
        .router(router)
        .bind("0.0.0.0:8080")
        .run()
        .await
        .expect("server failed");
}
```

For complete working examples, see the [`examples/`](examples/) directory. Full API documentation can be generated locally with `make doc`.

---

## Roadmap

### Core Framework

- [x] HTTP/1.1 request parsing (zero-copy via `httparse`)
- [x] Async TCP server with keep-alive and graceful shutdown
- [x] Fluent response builder with `IntoResponse` trait
- [x] URL router (exact, `:param`, wildcard patterns)
- [ ] Middleware pipeline (before/after handler hooks)
- [ ] Chunked transfer encoding
- [ ] Cookie parsing and `Set-Cookie` builder

### Security

- [x] JWT authentication middleware (HS256/HS512)
- [x] API Key middleware (constant-time comparison)
- [x] CORS middleware (preflight, `Vary: Origin`)
- [x] IP filter middleware (CIDR allowlist/blocklist)
- [x] Request ID middleware
- [ ] Secure headers (HSTS, CSP, `X-Frame-Options`)
- [ ] Complete CSRF protection (expiry enforcement, single-use tokens)
- [ ] Rate limiting middleware (token bucket → 429 + `Retry-After`)
- [ ] Session management (cookie-based, `SameSite`/`HttpOnly`/`Secure`)
- [ ] Password hashing (Argon2id)
- [ ] OAuth 2.0 / OIDC (authorization code flow, JWKS validation)
- [ ] JWT blocklist (`jti` revocation)
- [ ] RS256/ES256 JWT signing

### Extended Platform

- [ ] TLS / HTTPS support
- [ ] WebSocket upgrade and connection handling
- [ ] Server-Sent Events (SSE)
- [ ] Database connection pooling (PostgreSQL, SQLite)
- [ ] In-memory LRU cache + Redis backend
- [ ] Background task queue and cron scheduling
- [ ] LLM / Claude API integration layer
- [ ] Metrics, distributed tracing, and health-check endpoints
- [ ] HTTP/2 support

See [`ROADMAP.md`](ROADMAP.md) for the full prioritized implementation plan.

---

## Contributing

Contributions are welcome! This project follows a standard GitHub flow:

1. **Fork** the repository
2. **Create** a feature branch

   ```bash
   git checkout -b feat/my-feature
   ```

3. **Commit** your changes (follow [Conventional Commits](https://www.conventionalcommits.org/))

   ```bash
   git commit -m "feat(router): add 405 Method Not Allowed response"
   ```

4. **Push** to your branch

   ```bash
   git push origin feat/my-feature
   ```

5. **Open a Pull Request** against `main`

Please make sure your code:

- Passes `make ci` (fmt check + clippy + tests + audit)
- Has doc comments on all public items
- Does not use `.unwrap()` in library code — use `?` with proper error propagation
- Includes unit tests in a `#[cfg(test)]` block at the bottom of the module

---

## License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for full details.

---

## Contact

**Utkarsh Priyadarshi**

- 🐛 Issues & Bugs — [GitHub Issues](https://github.com/utkarshpriyadarshi/rttp/issues)
- 💬 Discussions — [GitHub Discussions](https://github.com/utkarshpriyadarshi/rttp/discussions)
- 🐦 X (Twitter) — [@utkarsh\_priyadarshi](https://x.com/utkarshpriyadarshi)
- 💼 LinkedIn — [linkedin.com/in/utkarsh-priyadarshi](https://linkedin.com/in/utkarsh-priyadarshi)

---

Built with ❤️ and a healthy amount of TCP byte-wrangling.
