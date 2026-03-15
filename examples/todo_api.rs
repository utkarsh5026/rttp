//! Todo CRUD API — full-featured rttp demo.
//!
//! Demonstrates:
//! - Shared state with `Arc<Mutex<...>>`
//! - Route groups with a common prefix
//! - Logger middleware
//! - Path parameters (`/todos/:id`)
//! - Query parameters (`?done=true`)
//! - JSON request body parsing
//! - JSON responses
//! - Multiple HTTP methods (GET, POST, PUT, DELETE)
//!
//! Run with:
//!   cargo run --example todo_api
//!
//! Example requests:
//!   curl http://localhost:8080/api/todos
//!   curl -X POST http://localhost:8080/api/todos \
//!        -H 'Content-Type: application/json' \
//!        -d '{"title":"Buy milk"}'
//!   curl http://localhost:8080/api/todos/1
//!   curl -X PUT http://localhost:8080/api/todos/1 \
//!        -H 'Content-Type: application/json' \
//!        -d '{"title":"Buy oat milk","done":true}'
//!   curl -X DELETE http://localhost:8080/api/todos/1
//!   curl 'http://localhost:8080/api/todos?done=false'

use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use rttp::app::App;
use rttp::extract::{Json, Path, Query, State};
use rttp::middleware::LoggerMiddleware;
use rttp::server::Server;
use rttp::{Response, StatusCode};

// ── Domain types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
struct Todo {
    id: u64,
    title: String,
    done: bool,
}

#[derive(Debug, Deserialize)]
struct CreateTodo {
    title: String,
}

#[derive(Debug, Deserialize)]
struct UpdateTodo {
    title: Option<String>,
    done: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct TodoFilter {
    done: Option<bool>,
}

// ── Shared state ──────────────────────────────────────────────────────────────

#[derive(Default)]
struct Store {
    todos: Vec<Todo>,
    next_id: u64,
}

impl Store {
    fn insert(&mut self, title: String) -> &Todo {
        self.next_id += 1;
        self.todos.push(Todo {
            id: self.next_id,
            title,
            done: false,
        });
        self.todos.last().unwrap()
    }

    fn get(&self, id: u64) -> Option<&Todo> {
        self.todos.iter().find(|t| t.id == id)
    }

    fn update(&mut self, id: u64, title: Option<String>, done: Option<bool>) -> Option<&Todo> {
        let todo = self.todos.iter_mut().find(|t| t.id == id)?;
        if let Some(t) = title {
            todo.title = t;
        }
        if let Some(d) = done {
            todo.done = d;
        }
        Some(todo)
    }

    fn delete(&mut self, id: u64) -> bool {
        let before = self.todos.len();
        self.todos.retain(|t| t.id != id);
        self.todos.len() < before
    }

    fn list(&self, filter: Option<bool>) -> Vec<&Todo> {
        self.todos
            .iter()
            .filter(|t| filter.is_none_or(|done| t.done == done))
            .collect()
    }
}

type SharedStore = Arc<Mutex<Store>>;

async fn list_todos(
    State(store): State<SharedStore>,
    Query(filter): Query<TodoFilter>,
) -> Response {
    let store = store.lock().unwrap();
    let todos = store.list(filter.done);
    Response::json(&todos)
}

async fn create_todo(State(store): State<SharedStore>, Json(body): Json<CreateTodo>) -> Response {
    let mut store = store.lock().unwrap();
    let todo = store.insert(body.title).clone();
    let mut resp = Response::json(&todo);
    resp.set_status(StatusCode::Created);
    resp
}

async fn get_todo(State(store): State<SharedStore>, Path(id): Path<u64>) -> Response {
    let store = store.lock().unwrap();
    match store.get(id) {
        Some(todo) => Response::json(todo),
        None => Response::new(StatusCode::NotFound).body("todo not found"),
    }
}

async fn update_todo(
    State(store): State<SharedStore>,
    Path(id): Path<u64>,
    Json(body): Json<UpdateTodo>,
) -> Response {
    let mut store = store.lock().unwrap();
    match store.update(id, body.title, body.done) {
        Some(todo) => Response::json(&todo.clone()),
        None => Response::new(StatusCode::NotFound).body("todo not found"),
    }
}

async fn delete_todo(State(store): State<SharedStore>, Path(id): Path<u64>) -> Response {
    let mut store = store.lock().unwrap();
    if store.delete(id) {
        Response::new(StatusCode::NoContent)
    } else {
        Response::new(StatusCode::NotFound).body("todo not found")
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter("info,rttp=debug")
        .init();

    let store: SharedStore = Arc::new(Mutex::new(Store::default()));

    let app = App::new()
        .state(store)
        .middleware(LoggerMiddleware)
        .get("/health", || async { "ok" })
        .group("/api", |g| {
            g.get("/todos", list_todos)
                .post("/todos", create_todo)
                .get("/todos/:id", get_todo)
                .put("/todos/:id", update_todo)
                .delete("/todos/:id", delete_todo)
        });

    let server = Server::bind("127.0.0.1:8080").await?;
    tracing::info!("Todo API listening on http://127.0.0.1:8080");
    tracing::info!("Try: curl http://127.0.0.1:8080/api/todos");
    server.run(app.into_service()).await?;
    Ok(())
}
