# rttp

A from-scratch HTTP/1.1 server framework written in Rust — built purely to learn Rust.

No hyper. No axum. No magic. Just Rust, Tokio, and curiosity.

## Why

This project exists for one reason: to understand how things work by building them.

Parsing HTTP requests, managing async connections, routing, middleware — all of it written by hand, the hard way. The goal is not a production framework. The goal is deep understanding.

## What's Inside

- **HTTP/1.1 parsing** — zero-copy request parsing via `httparse`
- **Async TCP server** — connection handling with keep-alive support via Tokio
- **Response builder** — serializes responses to bytes
- **Middleware pipeline** — composable before/after handler logic
- **Router** — URL pattern matching *(in progress)*

## Getting Started

```bash
make run    # run the hello_world example at http://localhost:8080
make test   # run all tests
make doc    # generate and open documentation
```

## Stack

- **Runtime:** [Tokio](https://tokio.rs)
- **HTTP parsing:** [httparse](https://github.com/seanmonstar/httparse)
- **Logging:** [tracing](https://github.com/tokio-rs/tracing)
- **Errors:** [thiserror](https://github.com/dtolnay/thiserror)

## License

MIT
