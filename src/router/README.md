# Router

The `router` module dispatches incoming HTTP requests to async handler functions based on the
request method and URL path.

## URL Pattern Syntax

Three pattern styles are supported:

| Pattern         | Example match              | Captured params                  |
|-----------------|----------------------------|----------------------------------|
| `/users`        | `/users`                   | *(none)*                         |
| `/users/:id`    | `/users/42`                | `id → "42"`                      |
| `/files/*`      | `/files/docs/readme.txt`   | `wildcard → "/docs/readme.txt"`  |

Trailing slashes are normalized — `/users/` and `/users` are treated as the same path.

Routes are matched in **registration order**; the first route whose method and pattern both
match wins. Unmatched requests get a `404 Not Found` response automatically.

## Basic Usage

```rust
use rttp::{Router, Response, StatusCode};

let mut router = Router::new();

// Static path
router.get("/health", |_ctx| async {
    Response::new(StatusCode::Ok)
});

// Named URL parameter — access via ctx.params()
router.get("/users/:id", |ctx: rttp::context::Context| async move {
    let id = ctx.params().get("id").unwrap_or("unknown").to_owned();
    Response::new(StatusCode::Ok).body(id)
});

// Wildcard — captures everything after the prefix under the key "wildcard"
router.get("/files/*", |ctx: rttp::context::Context| async move {
    let path = ctx.params().get("wildcard").unwrap_or("").to_owned();
    Response::new(StatusCode::Ok).body(path)
});
```

## HTTP Methods

All standard HTTP methods are supported:

```rust
router.get("/resource",     handler);
router.post("/resource",    handler);
router.put("/resource/:id", handler);
router.delete("/resource/:id", handler);
router.patch("/resource/:id",  handler);
router.options("/resource", handler);
```

## Per-Route Middleware

Attach middleware to a specific route by passing a tuple of `(Middleware..., Handler)`.
Up to 12 middleware layers can be composed this way via tuple syntax.

```rust
use rttp::middleware::LoggerMiddleware;

// One middleware
router.get("/users", (LoggerMiddleware, |_ctx| async {
    Response::new(StatusCode::Ok)
}));

// Multiple middleware — executed left to right
router.post("/users", (AuthMiddleware, LoggerMiddleware, |_ctx| async {
    Response::new(StatusCode::Created)
}));
```

A middleware can short-circuit the chain by returning a response without calling `next`:

```rust
// AuthMiddleware returns 401 without reaching the handler if auth fails
router.get("/admin", (AuthMiddleware, |_ctx| async {
    Response::new(StatusCode::Ok)
}));
```

### Dynamic Middleware Lists

When the number of middleware layers is not known at compile time, use a
`(Vec<Arc<dyn Middleware>>, Handler)` tuple:

```rust
use std::sync::Arc;
use rttp::middleware::Middleware;

let middlewares: Vec<Arc<dyn Middleware>> = build_middleware_stack();
router.get("/dynamic", (middlewares, |_ctx| async {
    Response::new(StatusCode::Ok)
}));
```

## Composing Routers

Split route definitions across modules and merge them at startup with `Router::merge`.
Existing routes retain priority over merged ones on conflict.

```rust
fn user_routes() -> Router {
    let mut r = Router::new();
    r.get("/users",     list_users_handler);
    r.post("/users",    create_user_handler);
    r.get("/users/:id", get_user_handler);
    r
}

fn post_routes() -> Router {
    let mut r = Router::new();
    r.get("/posts",     list_posts_handler);
    r.post("/posts",    create_post_handler);
    r
}

let mut router = Router::new();
router.get("/health", |_ctx| async { Response::new(StatusCode::Ok) });
router.merge(user_routes());
router.merge(post_routes());
```

## Dispatching Requests

`Router` is normally wired into the server automatically. For testing or manual use:

```rust
// From a raw Request
let response = router.route(request).await;

// From an existing Context (e.g. after global middleware runs)
let response = router.dispatch(ctx).await;
```

## Handler Return Types

Handlers can return anything that implements `IntoResponse`:

```rust
// Response directly
router.get("/a", |_ctx| async { Response::new(StatusCode::Ok) });

// &str / String — becomes 200 OK with text body
router.get("/b", |_ctx| async { "hello" });

// (StatusCode, body) tuple
router.get("/c", |_ctx| async { (StatusCode::Created, "created") });
```
