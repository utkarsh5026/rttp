# Router

Maps incoming HTTP requests to the right handler function based on the method (GET, POST, …) and the URL path.

## What's inside

- **`Router`** — the main struct you register routes on and hand to the server.
- **`RouteBuilder`** — returned by `router.route("/path")` when you want to register multiple methods on the same path at once.
- **`Pattern`** — compiled form of a route string; three styles are supported (see below).
- **`PathParams`** — a map of named values captured from the URL (e.g. `id → "42"`).

## How to use it

Register routes, then pass the router to the server:

```rust
use rttp::{Router, Response, StatusCode};

let mut router = Router::new();

// Exact path
router.get("/health", |_ctx| async {
    Response::new(StatusCode::Ok)
});

// Named URL parameter — read it back with ctx.params().get("id")
router.get("/users/:id", |ctx: rttp::context::Context| async move {
    let id = ctx.params().get("id").unwrap_or("unknown").to_owned();
    Response::new(StatusCode::Ok).body(id)
});

// Wildcard — captures everything after /files/ under the key "wildcard"
router.get("/files/*", |ctx: rttp::context::Context| async move {
    let path = ctx.params().get("wildcard").unwrap_or("").to_owned();
    Response::new(StatusCode::Ok).body(path)
});
```

If you want to attach middleware to a specific route, pass a tuple of `(Middleware, Handler)`:

```rust
use rttp::middleware::LoggerMiddleware;

router.get("/users", (LoggerMiddleware, |_ctx| async {
    Response::new(StatusCode::Ok)
}));
```

Middleware runs left to right. Any middleware can stop the chain early by returning a response without calling `next`.

## How it works

When a request comes in, the router walks its registered routes in order and checks both the HTTP method and the URL pattern. The first route that matches wins — unmatched requests automatically get a `404`. Patterns are compiled once at registration time, so matching is just an iterator walk with no parsing overhead per request.
