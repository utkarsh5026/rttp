//! Request data extractors — pull typed data from [`Context`] automatically.
//!
//! Extractors implement [`FromContext`] and are used as handler function parameters.
//! The framework calls [`FromContext::from_context`] for each parameter before invoking
//! the handler, returning an appropriate error response if extraction fails.
//!
//! ## Available extractors
//!
//! | Extractor         | Extracts from         | Example                                   |
//! |-------------------|-----------------------|-------------------------------------------|
//! | [`Path<T>`]       | URL path parameters   | `Path(id): Path<i64>`                     |
//! | [`Query<T>`]      | Query string          | `Query(params): Query<SearchParams>`      |
//! | [`Json<T>`]       | JSON request body     | `Json(body): Json<CreateUser>`            |
//! | [`Extension<T>`]  | Context extensions    | `Extension(db): Extension<Arc<Database>>` |
//! | [`State<T>`]      | Shared app state      | `State(cfg): State<Arc<AppConfig>>`       |
//!
//! ## Handler trait
//!
//! The [`Handler`] trait converts functions with extractor parameters into
//! type-erased handler functions. It is implemented automatically for `async fn`s
//! with up to 12 extractor arguments via a macro.
//!
//! # Examples
//!
//! ```rust,no_run
//! use rttp::extract::{Path, Json, State};
//! use rttp::{Response, StatusCode};
//! use serde::{Deserialize, Serialize};
//! use std::sync::Arc;
//!
//! #[derive(Deserialize)]
//! struct CreateUser { name: String }
//!
//! #[derive(Clone)]
//! struct AppConfig { admin_email: String }
//!
//! async fn create_user(
//!     State(cfg): State<Arc<AppConfig>>,
//!     Json(body): Json<CreateUser>,
//! ) -> (StatusCode, String) {
//!     (StatusCode::Created, format!("Created user: {}", body.name))
//! }
//! ```

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::context::Context;
use crate::http::response::IntoResponse;
use crate::{Response, StatusCode};

/// Type-erased, reference-counted async handler function.
///
/// This is the internal representation used by the router and app to store
/// handlers. You never construct this directly — use [`Handler::into_handler_fn`]
/// or register handlers via [`Router`](crate::router::Router) /
/// [`App`](crate::app::App) methods.
pub type HandlerFn =
    Arc<dyn Fn(Context) -> Pin<Box<dyn Future<Output = Response> + Send>> + Send + Sync + 'static>;

/// Trait for types that can be extracted from a request [`Context`].
///
/// Implement this trait to create custom extractors. The framework calls
/// `from_context` for each handler parameter before invoking the handler.
///
/// # Example
///
/// ```rust,no_run
/// use rttp::context::Context;
/// use rttp::extract::{FromContext, Rejection};
///
/// struct UserId(i64);
///
/// impl FromContext for UserId {
///     type Rejection = Rejection;
///     fn from_context(ctx: &mut Context) -> Result<Self, Self::Rejection> {
///         ctx.params()
///             .get("user_id")
///             .and_then(|v| v.parse::<i64>().ok())
///             .map(UserId)
///             .ok_or(Rejection::MissingPathParam("user_id".into()))
///     }
/// }
/// ```
pub trait FromContext: Sized + Send + 'static {
    /// The error type returned when extraction fails.
    type Rejection: IntoResponse + Send;

    /// Extract this type from the request context.
    fn from_context(ctx: &mut Context) -> Result<Self, Self::Rejection>;
}

/// Error type returned when an extractor fails to produce a value.
///
/// Each variant maps to an appropriate HTTP error status code:
/// - Path/Query/JSON errors → `400 Bad Request`
/// - Missing extension/state → `500 Internal Server Error`
#[derive(Debug)]
pub enum Rejection {
    /// A required path parameter was not found in the route.
    MissingPathParam(String),
    /// A path parameter could not be parsed to the expected type.
    InvalidPathParam {
        /// The parameter name.
        name: String,
        /// The expected type name.
        expected: &'static str,
    },
    /// The query string could not be deserialized into the expected type.
    InvalidQuery(String),
    /// The JSON request body could not be deserialized.
    InvalidJson(String),
    /// A required extension or state value was not found in the context.
    MissingExtension(&'static str),
}

impl fmt::Display for Rejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingPathParam(name) => write!(f, "missing path parameter: {name}"),
            Self::InvalidPathParam { name, expected } => {
                write!(f, "path parameter '{name}' is not a valid {expected}")
            }
            Self::InvalidQuery(msg) => write!(f, "invalid query string: {msg}"),
            Self::InvalidJson(msg) => write!(f, "invalid JSON body: {msg}"),
            Self::MissingExtension(name) => write!(f, "missing extension: {name}"),
        }
    }
}

impl IntoResponse for Rejection {
    fn into_response(self) -> Response {
        let status = match &self {
            Self::MissingExtension(_) => StatusCode::InternalServerError,
            _ => StatusCode::BadRequest,
        };
        Response::new(status)
            .header("Content-Type", "application/json")
            .body(format!(r#"{{"error":"{}"}}"#, self))
    }
}

// ── Handler trait ────────────────────────────────────────────────────────────

/// Trait for async handler functions that support automatic extraction.
///
/// This trait is implemented automatically for `async fn`s with up to 12
/// extractor parameters. The marker type `T` encodes the function's parameter
/// list and prevents impl conflicts.
///
/// You never need to implement this trait manually — just write an `async fn`
/// with extractor parameters and pass it to [`App::get`](crate::app::App::get),
/// etc.
pub trait Handler<T>: Send + Sync + 'static {
    /// Convert this handler into a type-erased [`HandlerFn`].
    fn into_handler_fn(self) -> HandlerFn;
}

// Special case: `Fn(Context) -> impl Future<Output = impl IntoResponse>`
//
// This provides backward compatibility with the existing handler style and
// gives full access to the request context without going through extractors.
impl<F, Fut, Res> Handler<Context> for F
where
    F: Fn(Context) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Res> + Send + 'static,
    Res: IntoResponse,
{
    fn into_handler_fn(self) -> HandlerFn {
        let f = Arc::new(self);
        Arc::new(move |ctx: Context| {
            let f = Arc::clone(&f);
            Box::pin(async move { f(ctx).await.into_response() })
                as Pin<Box<dyn Future<Output = Response> + Send>>
        })
    }
}

macro_rules! impl_handler {
    () => {
        impl<F, Fut, Res> Handler<()> for F
        where
            F: Fn() -> Fut + Send + Sync + 'static,
            Fut: Future<Output = Res> + Send + 'static,
            Res: IntoResponse,
        {
            fn into_handler_fn(self) -> HandlerFn {
                let f = Arc::new(self);
                Arc::new(move |_ctx: Context| {
                    let f = Arc::clone(&f);
                    Box::pin(async move { f().await.into_response() })
                        as Pin<Box<dyn Future<Output = Response> + Send>>
                })
            }
        }
    };
    ($($T:ident),+) => {
        #[allow(non_snake_case)]
        impl<F, Fut, Res, $($T,)+> Handler<($($T,)+)> for F
        where
            F: Fn($($T,)+) -> Fut + Send + Sync + 'static,
            Fut: Future<Output = Res> + Send + 'static,
            Res: IntoResponse,
            $($T: FromContext,)+
        {
            fn into_handler_fn(self) -> HandlerFn {
                let f = Arc::new(self);
                Arc::new(move |mut ctx: Context| {
                    let f = Arc::clone(&f);
                    Box::pin(async move {
                        $(
                            let $T = match $T::from_context(&mut ctx) {
                                Ok(v) => v,
                                Err(e) => return e.into_response(),
                            };
                        )+
                        f($($T,)+).await.into_response()
                    }) as Pin<Box<dyn Future<Output = Response> + Send>>
                })
            }
        }
    };
}

impl_handler!();
impl_handler!(T1);
impl_handler!(T1, T2);
impl_handler!(T1, T2, T3);
impl_handler!(T1, T2, T3, T4);
impl_handler!(T1, T2, T3, T4, T5);
impl_handler!(T1, T2, T3, T4, T5, T6);
impl_handler!(T1, T2, T3, T4, T5, T6, T7);
impl_handler!(T1, T2, T3, T4, T5, T6, T7, T8);
impl_handler!(T1, T2, T3, T4, T5, T6, T7, T8, T9);
impl_handler!(T1, T2, T3, T4, T5, T6, T7, T8, T9, T10);
impl_handler!(T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11);
impl_handler!(T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12);

// ── Path extractor ──────────────────────────────────────────────────────────

/// Extracts a single path parameter, parsed into `T`.
///
/// Works with routes that have exactly one named parameter (e.g. `/users/:id`).
/// The value is parsed using [`FromStr`](std::str::FromStr).
///
/// # Examples
///
/// ```rust,no_run
/// use rttp::extract::Path;
/// use rttp::StatusCode;
///
/// // Route: GET /users/:id
/// async fn get_user(Path(id): Path<i64>) -> String {
///     format!("User #{id}")
/// }
/// ```
#[derive(Debug)]
pub struct Path<T>(pub T);

impl<T> FromContext for Path<T>
where
    T: std::str::FromStr + Send + 'static,
    T::Err: fmt::Display,
{
    type Rejection = Rejection;

    fn from_context(ctx: &mut Context) -> Result<Self, Self::Rejection> {
        let (name, value) = ctx
            .params()
            .iter()
            .next()
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .ok_or_else(|| Rejection::MissingPathParam("path parameter".into()))?;

        let parsed = value
            .parse::<T>()
            .map_err(|_| Rejection::InvalidPathParam {
                name,
                expected: std::any::type_name::<T>(),
            })?;

        Ok(Path(parsed))
    }
}

// ── Query extractor ─────────────────────────────────────────────────────────

/// Extracts and deserializes the URL query string into `T`.
///
/// Uses `serde_urlencoded` for deserialization, so `T` must implement
/// [`serde::Deserialize`].
///
/// # Examples
///
/// ```rust,no_run
/// use rttp::extract::Query;
/// use serde::Deserialize;
///
/// #[derive(Deserialize)]
/// struct Pagination { page: Option<u32>, per_page: Option<u32> }
///
/// // Route: GET /users?page=2&per_page=10
/// async fn list_users(Query(params): Query<Pagination>) -> String {
///     format!("Page {}", params.page.unwrap_or(1))
/// }
/// ```
#[derive(Debug)]
pub struct Query<T>(pub T);

impl<T: DeserializeOwned + Send + 'static> FromContext for Query<T> {
    type Rejection = Rejection;

    fn from_context(ctx: &mut Context) -> Result<Self, Self::Rejection> {
        let query = ctx.request().query_string().unwrap_or("");
        let value: T = serde_urlencoded::from_str(query)
            .map_err(|e| Rejection::InvalidQuery(e.to_string()))?;
        Ok(Query(value))
    }
}

// ── Json extractor / response ───────────────────────────────────────────────

/// Extracts a JSON request body, or serializes a value as a JSON response.
///
/// As an **extractor**, `Json<T>` reads the request body and deserializes it
/// from JSON. The `Content-Type` header is not enforced — any body that parses
/// as valid JSON is accepted.
///
/// As a **response**, `Json<T>` serializes `T` into JSON and sets
/// `Content-Type: application/json`.
///
/// # Examples
///
/// ```rust,no_run
/// use rttp::extract::Json;
/// use serde::{Deserialize, Serialize};
///
/// #[derive(Deserialize)]
/// struct CreateUser { name: String }
///
/// #[derive(Serialize)]
/// struct User { id: i64, name: String }
///
/// async fn create_user(Json(body): Json<CreateUser>) -> Json<User> {
///     Json(User { id: 1, name: body.name })
/// }
/// ```
#[derive(Debug)]
pub struct Json<T>(pub T);

impl<T: DeserializeOwned + Send + 'static> FromContext for Json<T> {
    type Rejection = Rejection;

    fn from_context(ctx: &mut Context) -> Result<Self, Self::Rejection> {
        let body = ctx.request().body();
        let value: T =
            serde_json::from_slice(body).map_err(|e| Rejection::InvalidJson(e.to_string()))?;
        Ok(Json(value))
    }
}

impl<T: Serialize> IntoResponse for Json<T> {
    fn into_response(self) -> Response {
        match serde_json::to_string(&self.0) {
            Ok(json) => Response::new(StatusCode::Ok)
                .header("Content-Type", "application/json")
                .body(json),
            Err(_) => {
                Response::new(StatusCode::InternalServerError).body("Failed to serialize JSON")
            }
        }
    }
}

// ── Extension extractor ─────────────────────────────────────────────────────

/// Extracts a value of type `T` from the request's [`Extensions`](crate::context::Extensions).
///
/// Extensions are typically inserted by middleware (e.g. JWT claims, database
/// connections, request IDs).
///
/// Returns `500 Internal Server Error` if the extension is missing, since a
/// missing extension usually indicates a middleware configuration error.
///
/// # Examples
///
/// ```rust,no_run
/// use rttp::extract::Extension;
/// use std::sync::Arc;
///
/// struct DatabasePool; // inserted by middleware
///
/// async fn handler(Extension(db): Extension<Arc<DatabasePool>>) -> &'static str {
///     "ok"
/// }
/// ```
#[derive(Debug)]
pub struct Extension<T>(pub T);

impl<T: Clone + Send + Sync + 'static> FromContext for Extension<T> {
    type Rejection = Rejection;

    fn from_context(ctx: &mut Context) -> Result<Self, Self::Rejection> {
        ctx.extensions()
            .get::<T>()
            .cloned()
            .map(Extension)
            .ok_or(Rejection::MissingExtension(std::any::type_name::<T>()))
    }
}

// ── State extractor ─────────────────────────────────────────────────────────

/// Extracts shared application state of type `T`.
///
/// State is registered once via [`App::state`](crate::app::App::state) and
/// cloned into every request's extensions. Use `Arc<T>` for state that is
/// expensive to clone.
///
/// # Examples
///
/// ```rust,no_run
/// use rttp::extract::State;
/// use std::sync::Arc;
///
/// #[derive(Clone)]
/// struct AppConfig { db_url: String }
///
/// async fn handler(State(cfg): State<Arc<AppConfig>>) -> String {
///     format!("DB: {}", cfg.db_url)
/// }
/// ```
#[derive(Debug)]
pub struct State<T>(pub T);

impl<T: Clone + Send + Sync + 'static> FromContext for State<T> {
    type Rejection = Rejection;

    fn from_context(ctx: &mut Context) -> Result<Self, Self::Rejection> {
        ctx.extensions()
            .get::<T>()
            .cloned()
            .map(State)
            .ok_or(Rejection::MissingExtension(std::any::type_name::<T>()))
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::request::Request;

    fn make_ctx(method: &str, path: &str, body: &str) -> Context {
        let raw = if body.is_empty() {
            format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\n\r\n")
        } else {
            format!(
                "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
        };
        let (req, _) = Request::parse(raw.as_bytes()).unwrap();
        Context::new(req)
    }

    fn make_ctx_with_params(path: &str, params: &[(&str, &str)]) -> Context {
        let raw = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n");
        let (req, _) = Request::parse(raw.as_bytes()).unwrap();
        let mut pp = crate::context::PathParams::new();
        for (k, v) in params {
            pp.insert(*k, *v);
        }
        Context::with_params(req, pp)
    }

    // ── Path ─────────────────────────────────────────────────────────────

    #[test]
    fn path_extracts_string() {
        let mut ctx = make_ctx_with_params("/users/42", &[("id", "42")]);
        let Path(id) = Path::<String>::from_context(&mut ctx).unwrap();
        assert_eq!(id, "42");
    }

    #[test]
    fn path_extracts_i64() {
        let mut ctx = make_ctx_with_params("/users/42", &[("id", "42")]);
        let Path(id) = Path::<i64>::from_context(&mut ctx).unwrap();
        assert_eq!(id, 42);
    }

    #[test]
    fn path_invalid_parse_returns_rejection() {
        let mut ctx = make_ctx_with_params("/users/abc", &[("id", "abc")]);
        let err = Path::<i64>::from_context(&mut ctx).unwrap_err();
        assert!(matches!(err, Rejection::InvalidPathParam { .. }));
    }

    #[test]
    fn path_missing_returns_rejection() {
        let mut ctx = make_ctx("GET", "/users", "");
        let err = Path::<String>::from_context(&mut ctx).unwrap_err();
        assert!(matches!(err, Rejection::MissingPathParam(_)));
    }

    // ── Query ────────────────────────────────────────────────────────────

    #[test]
    fn query_deserializes() {
        #[derive(serde::Deserialize, Debug)]
        struct Params {
            q: String,
            page: u32,
        }
        let mut ctx = make_ctx("GET", "/search?q=rust&page=2", "");
        let Query(params) = Query::<Params>::from_context(&mut ctx).unwrap();
        assert_eq!(params.q, "rust");
        assert_eq!(params.page, 2);
    }

    #[test]
    fn query_missing_field_returns_rejection() {
        #[derive(Debug, serde::Deserialize)]
        struct Params {
            #[allow(dead_code)]
            required: String,
        }
        let mut ctx = make_ctx("GET", "/search", "");
        let err = Query::<Params>::from_context(&mut ctx).unwrap_err();
        assert!(matches!(err, Rejection::InvalidQuery(_)));
    }

    // ── Json ─────────────────────────────────────────────────────────────

    #[test]
    fn json_deserializes_body() {
        #[derive(serde::Deserialize)]
        struct Body {
            name: String,
        }
        let mut ctx = make_ctx("POST", "/users", r#"{"name":"Alice"}"#);
        let Json(body) = Json::<Body>::from_context(&mut ctx).unwrap();
        assert_eq!(body.name, "Alice");
    }

    #[test]
    fn json_invalid_body_returns_rejection() {
        #[derive(Debug, serde::Deserialize)]
        struct Body {
            #[allow(dead_code)]
            name: String,
        }
        let mut ctx = make_ctx("POST", "/users", "not json");
        let err = Json::<Body>::from_context(&mut ctx).unwrap_err();
        assert!(matches!(err, Rejection::InvalidJson(_)));
    }

    #[test]
    fn json_into_response() {
        #[derive(serde::Serialize)]
        struct User {
            id: i64,
        }
        let resp = Json(User { id: 42 }).into_response();
        assert_eq!(resp.status(), StatusCode::Ok);
        assert_eq!(resp.headers().get("content-type"), Some("application/json"));
    }

    // ── Extension ────────────────────────────────────────────────────────

    #[test]
    fn extension_extracts_value() {
        let mut ctx = make_ctx("GET", "/", "");
        ctx.extensions_mut().insert(42u32);
        let Extension(val) = Extension::<u32>::from_context(&mut ctx).unwrap();
        assert_eq!(val, 42);
    }

    #[test]
    fn extension_missing_returns_rejection() {
        let mut ctx = make_ctx("GET", "/", "");
        let err = Extension::<u32>::from_context(&mut ctx).unwrap_err();
        assert!(matches!(err, Rejection::MissingExtension(_)));
    }

    // ── State ────────────────────────────────────────────────────────────

    #[test]
    fn state_extracts_value() {
        let mut ctx = make_ctx("GET", "/", "");
        ctx.extensions_mut().insert(Arc::new("config".to_string()));
        let State(val) = State::<Arc<String>>::from_context(&mut ctx).unwrap();
        assert_eq!(*val, "config");
    }

    // ── IntoResponse impls ───────────────────────────────────────────────

    #[test]
    fn str_into_response() {
        let resp = "hello".into_response();
        assert_eq!(resp.status(), StatusCode::Ok);
    }

    #[test]
    fn string_into_response() {
        let resp = String::from("hello").into_response();
        assert_eq!(resp.status(), StatusCode::Ok);
    }

    #[test]
    fn status_tuple_into_response() {
        let resp = (StatusCode::NotFound, "not found").into_response();
        assert_eq!(resp.status(), StatusCode::NotFound);
    }

    #[test]
    fn result_ok_into_response() {
        let resp: Result<&str, &str> = Ok("ok");
        let resp = resp.into_response();
        assert_eq!(resp.status(), StatusCode::Ok);
    }

    #[test]
    fn result_err_into_response() {
        let resp: Result<&str, (StatusCode, &str)> = Err((StatusCode::Forbidden, "denied"));
        let resp = resp.into_response();
        assert_eq!(resp.status(), StatusCode::Forbidden);
    }

    #[test]
    fn rejection_into_response_bad_request() {
        let rej = Rejection::MissingPathParam("id".into());
        let resp = rej.into_response();
        assert_eq!(resp.status(), StatusCode::BadRequest);
    }

    #[test]
    fn rejection_into_response_internal_error() {
        let rej = Rejection::MissingExtension("Database");
        let resp = rej.into_response();
        assert_eq!(resp.status(), StatusCode::InternalServerError);
    }

    // ── Handler trait ────────────────────────────────────────────────────

    #[tokio::test]
    async fn handler_no_args() {
        let handler: HandlerFn = (|| async { "hello" }).into_handler_fn();
        let ctx = make_ctx("GET", "/", "");
        let resp = handler(ctx).await;
        assert_eq!(resp.status(), StatusCode::Ok);
    }

    #[tokio::test]
    async fn handler_with_context() {
        let handler: HandlerFn = (|_ctx: Context| async { "hello" }).into_handler_fn();
        let ctx = make_ctx("GET", "/", "");
        let resp = handler(ctx).await;
        assert_eq!(resp.status(), StatusCode::Ok);
    }

    #[tokio::test]
    async fn handler_with_path_extractor() {
        let handler: HandlerFn =
            (|Path(id): Path<i64>| async move { format!("User {id}") }).into_handler_fn();
        let ctx = make_ctx_with_params("/users/42", &[("id", "42")]);
        let resp = handler(ctx).await;
        assert_eq!(resp.status(), StatusCode::Ok);
    }

    #[tokio::test]
    async fn handler_with_json_extractor() {
        #[derive(serde::Deserialize)]
        struct Body {
            name: String,
        }
        let handler: HandlerFn =
            (|Json(body): Json<Body>| async move { format!("Hello, {}", body.name) })
                .into_handler_fn();
        let ctx = make_ctx("POST", "/", r#"{"name":"Alice"}"#);
        let resp = handler(ctx).await;
        assert_eq!(resp.status(), StatusCode::Ok);
    }

    #[tokio::test]
    async fn handler_extraction_failure_returns_error() {
        let handler: HandlerFn = (|Path(_id): Path<i64>| async { "ok" }).into_handler_fn();
        // No path params → extraction fails
        let ctx = make_ctx("GET", "/", "");
        let resp = handler(ctx).await;
        assert_eq!(resp.status(), StatusCode::BadRequest);
    }
}
