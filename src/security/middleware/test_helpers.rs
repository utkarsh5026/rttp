//! Shared test helpers for security middleware tests.

use std::sync::Arc;

use crate::{
    Response, StatusCode,
    context::Context,
    http::request::Request,
    middleware::{MiddlewareHandler, Next},
};

/// Build a [`Context`] from a raw HTTP/1.1 request byte slice.
pub fn make_context(raw: &[u8]) -> Context {
    let (req, _) = Request::parse(raw).unwrap();
    Context::new(req)
}

/// A [`Next`] that always responds `200 OK` with body `"downstream"`.
pub fn ok_next() -> Next {
    let handler: MiddlewareHandler = Arc::new(|_ctx: Context, _next: Next| {
        Box::pin(async { Response::new(StatusCode::Ok).body("downstream") })
    });
    Next::new(vec![handler])
}

/// Serialize a [`Response`] to a `String` for assertion.
pub fn response_to_string(r: Response) -> String {
    String::from_utf8(r.into_bytes().to_vec()).unwrap()
}
