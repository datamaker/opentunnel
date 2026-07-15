//! Admin HTTP API and static panel, served on the admin port.
//!
//! Port of `admin/adminServer.ts` (axum instead of Express), including the
//! unauthenticated `/health` endpoint added in PR #1.

use crate::config::AdminConfig;
use crate::db::DbPool;
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{delete, get, post, put},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tower_http::services::ServeDir;
use uuid::Uuid;

const SESSION_TTL_MS: i64 = 24 * 60 * 60 * 1000;

#[derive(Clone)]
struct AdminState {
    db: DbPool,
    admin_password: String,
    tokens: Arc<Mutex<HashMap<String, i64>>>,
}

type ApiError = (StatusCode, Json<Value>);
type ApiResult = Result<Json<Value>, ApiError>;

fn err(status: StatusCode, message: &str) -> ApiError {
    (status, Json(json!({ "error": message })))
}

fn db_error() -> ApiError {
    err(StatusCode::INTERNAL_SERVER_ERROR, "Database error")
}

/// Start the admin server; runs until the process exits.
pub async fn serve(cfg: AdminConfig, db: DbPool) -> anyhow::Result<()> {
    let state = AdminState {
        db,
        admin_password: cfg.password,
        tokens: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/api/login", post(login))
        .route("/api/logout", post(logout))
        .route("/api/users", get(list_users).post(create_user))
        .route("/api/users/:id", put(update_user).delete(delete_user))
        .route("/api/sessions", get(list_sessions))
        .route("/api/sessions/:id", delete(delete_session))
        .route("/api/stats", get(stats))
        .route("/api/logs", get(logs))
        .fallback_service(ServeDir::new("public").append_index_html_on_directories(true))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], cfg.port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("Admin panel running at http://localhost:{}", cfg.port);
    axum::serve(listener, app).await?;
    Ok(())
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// Validate a bearer/query token against the in-memory session store.
fn check_auth(state: &AdminState, headers: &HeaderMap, token_q: Option<&str>) -> Result<(), ApiError> {
    let header_token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let token = header_token.or(token_q);

    let Some(token) = token else {
        return Err(err(StatusCode::UNAUTHORIZED, "Unauthorized"));
    };

    let mut tokens = state.tokens.lock().unwrap();
    match tokens.get(token) {
        Some(&expires) if now_ms() <= expires => Ok(()),
        Some(_) => {
            tokens.remove(token);
            Err(err(StatusCode::UNAUTHORIZED, "Session expired"))
        }
        None => Err(err(StatusCode::UNAUTHORIZED, "Unauthorized")),
    }
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

async fn health(State(state): State<AdminState>) -> impl IntoResponse {
    match state.db.get().await {
        Ok(client) => match client.query_one("SELECT 1", &[]).await {
            Ok(_) => (StatusCode::OK, Json(json!({ "status": "ok" }))),
            Err(_) => (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "status": "error", "db": "query_failed" })),
            ),
        },
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "status": "error", "db": "unavailable" })),
        ),
    }
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct LoginBody {
    password: String,
}

async fn login(State(state): State<AdminState>, Json(body): Json<LoginBody>) -> ApiResult {
    if body.password != state.admin_password {
        return Err(err(StatusCode::UNAUTHORIZED, "Invalid password"));
    }
    let token = Uuid::new_v4().simple().to_string();
    state
        .tokens
        .lock()
        .unwrap()
        .insert(token.clone(), now_ms() + SESSION_TTL_MS);
    Ok(Json(json!({ "token": token })))
}

async fn logout(State(state): State<AdminState>, headers: HeaderMap) -> ApiResult {
    if let Some(token) = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    {
        state.tokens.lock().unwrap().remove(token);
    }
    Ok(Json(json!({ "success": true })))
}

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct TokenQuery {
    token: Option<String>,
}

fn ts(row: &tokio_postgres::Row, col: &str) -> Value {
    match row.try_get::<_, chrono::DateTime<chrono::Utc>>(col) {
        Ok(dt) => json!(dt.to_rfc3339()),
        Err(_) => Value::Null,
    }
}

async fn list_users(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Query(q): Query<TokenQuery>,
) -> ApiResult {
    check_auth(&state, &headers, q.token.as_deref())?;
    let client = state.db.get().await.map_err(|_| db_error())?;
    let rows = client
        .query(
            "SELECT id, username, is_active, max_connections, created_at, updated_at \
             FROM users ORDER BY created_at DESC",
            &[],
        )
        .await
        .map_err(|_| db_error())?;

    let users: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({
                "id": r.get::<_, Uuid>("id").to_string(),
                "username": r.get::<_, String>("username"),
                "is_active": r.get::<_, bool>("is_active"),
                "max_connections": r.get::<_, i32>("max_connections"),
                "created_at": ts(r, "created_at"),
                "updated_at": ts(r, "updated_at"),
            })
        })
        .collect();
    Ok(Json(json!(users)))
}

#[derive(Deserialize)]
struct CreateUserBody {
    username: Option<String>,
    password: Option<String>,
    #[serde(rename = "maxConnections")]
    max_connections: Option<i32>,
}

async fn create_user(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Query(q): Query<TokenQuery>,
    Json(body): Json<CreateUserBody>,
) -> ApiResult {
    check_auth(&state, &headers, q.token.as_deref())?;

    let (Some(username), Some(password)) = (body.username, body.password) else {
        return Err(err(StatusCode::BAD_REQUEST, "Username and password required"));
    };
    let max_conn = body.max_connections.unwrap_or(3);
    let hash = bcrypt::hash(&password, 10).map_err(|_| db_error())?;

    let client = state.db.get().await.map_err(|_| db_error())?;
    let row = client
        .query_one(
            "INSERT INTO users (username, password_hash, is_active, max_connections) \
             VALUES ($1, $2, true, $3) \
             RETURNING id, username, is_active, max_connections, created_at",
            &[&username, &hash, &max_conn],
        )
        .await
        .map_err(|e| {
            if e.code().map(|c| c.code()) == Some("23505") {
                err(StatusCode::CONFLICT, "Username already exists")
            } else {
                db_error()
            }
        })?;

    tracing::info!("User created: {username}");
    Ok(Json(json!({
        "id": row.get::<_, Uuid>("id").to_string(),
        "username": row.get::<_, String>("username"),
        "is_active": row.get::<_, bool>("is_active"),
        "max_connections": row.get::<_, i32>("max_connections"),
        "created_at": ts(&row, "created_at"),
    })))
}

#[derive(Deserialize)]
struct UpdateUserBody {
    username: Option<String>,
    password: Option<String>,
    #[serde(rename = "isActive")]
    is_active: Option<bool>,
    #[serde(rename = "maxConnections")]
    max_connections: Option<i32>,
}

async fn update_user(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Query(q): Query<TokenQuery>,
    Json(body): Json<UpdateUserBody>,
) -> ApiResult {
    check_auth(&state, &headers, q.token.as_deref())?;

    let mut set_clauses: Vec<String> = vec!["updated_at = NOW()".to_string()];
    let mut params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> = Vec::new();

    if let Some(username) = body.username {
        params.push(Box::new(username));
        set_clauses.push(format!("username = ${}", params.len()));
    }
    if let Some(password) = body.password {
        let hash = bcrypt::hash(&password, 10).map_err(|_| db_error())?;
        params.push(Box::new(hash));
        set_clauses.push(format!("password_hash = ${}", params.len()));
    }
    if let Some(is_active) = body.is_active {
        params.push(Box::new(is_active));
        set_clauses.push(format!("is_active = ${}", params.len()));
    }
    if let Some(max_conn) = body.max_connections {
        params.push(Box::new(max_conn));
        set_clauses.push(format!("max_connections = ${}", params.len()));
    }

    params.push(Box::new(id));
    let query = format!(
        "UPDATE users SET {} WHERE id = ${} \
         RETURNING id, username, is_active, max_connections, updated_at",
        set_clauses.join(", "),
        params.len()
    );

    let refs: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> =
        params.iter().map(|p| p.as_ref() as &(dyn tokio_postgres::types::ToSql + Sync)).collect();

    let client = state.db.get().await.map_err(|_| db_error())?;
    let row = client
        .query_opt(query.as_str(), &refs)
        .await
        .map_err(|_| db_error())?;

    let Some(row) = row else {
        return Err(err(StatusCode::NOT_FOUND, "User not found"));
    };

    tracing::info!("User updated: {id}");
    Ok(Json(json!({
        "id": row.get::<_, Uuid>("id").to_string(),
        "username": row.get::<_, String>("username"),
        "is_active": row.get::<_, bool>("is_active"),
        "max_connections": row.get::<_, i32>("max_connections"),
        "updated_at": ts(&row, "updated_at"),
    })))
}

async fn delete_user(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Query(q): Query<TokenQuery>,
) -> ApiResult {
    check_auth(&state, &headers, q.token.as_deref())?;
    let client = state.db.get().await.map_err(|_| db_error())?;
    let row = client
        .query_opt(
            "DELETE FROM users WHERE id = $1 RETURNING username",
            &[&id],
        )
        .await
        .map_err(|_| db_error())?;

    let Some(row) = row else {
        return Err(err(StatusCode::NOT_FOUND, "User not found"));
    };
    tracing::info!("User deleted: {}", row.get::<_, String>("username"));
    Ok(Json(json!({ "success": true })))
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

async fn list_sessions(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Query(q): Query<TokenQuery>,
) -> ApiResult {
    check_auth(&state, &headers, q.token.as_deref())?;
    let client = state.db.get().await.map_err(|_| db_error())?;
    // The VPN core hard-deletes session rows on disconnect, so every row here is
    // an active session (the schema has no `disconnected_at` column).
    let rows = client
        .query(
            "SELECT s.id, s.assigned_ip, s.client_platform, s.connected_at, u.username \
             FROM sessions s JOIN users u ON s.user_id = u.id \
             ORDER BY s.connected_at DESC",
            &[],
        )
        .await
        .map_err(|_| db_error())?;

    let sessions: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({
                "id": r.get::<_, Uuid>("id").to_string(),
                "assigned_ip": r.get::<_, String>("assigned_ip"),
                "client_platform": r.get::<_, String>("client_platform"),
                "connected_at": ts(r, "connected_at"),
                "username": r.get::<_, String>("username"),
            })
        })
        .collect();
    Ok(Json(json!(sessions)))
}

async fn delete_session(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Query(q): Query<TokenQuery>,
) -> ApiResult {
    check_auth(&state, &headers, q.token.as_deref())?;
    let client = state.db.get().await.map_err(|_| db_error())?;
    // Hard delete, consistent with how the VPN core ends sessions.
    client
        .execute("DELETE FROM sessions WHERE id = $1", &[&id])
        .await
        .map_err(|_| db_error())?;
    tracing::info!("Session terminated: {id}");
    Ok(Json(json!({ "success": true })))
}

// ---------------------------------------------------------------------------
// Stats & logs
// ---------------------------------------------------------------------------

async fn stats(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Query(q): Query<TokenQuery>,
) -> ApiResult {
    check_auth(&state, &headers, q.token.as_deref())?;
    let client = state.db.get().await.map_err(|_| db_error())?;

    let users = client
        .query_one(
            "SELECT COUNT(*) as total, COUNT(*) FILTER (WHERE is_active) as active FROM users",
            &[],
        )
        .await
        .map_err(|_| db_error())?;
    let sessions = client
        .query_one("SELECT COUNT(*) as active FROM sessions", &[])
        .await
        .map_err(|_| db_error())?;
    let logs = client
        .query(
            "SELECT event_type, COUNT(*) as count FROM connection_logs \
             WHERE created_at > NOW() - INTERVAL '24 hours' GROUP BY event_type",
            &[],
        )
        .await
        .map_err(|_| db_error())?;

    let mut last24h = serde_json::Map::new();
    for r in &logs {
        last24h.insert(
            r.get::<_, String>("event_type"),
            json!(r.get::<_, i64>("count")),
        );
    }

    Ok(Json(json!({
        "users": {
            "total": users.get::<_, i64>("total"),
            "active": users.get::<_, i64>("active"),
        },
        "activeSessions": sessions.get::<_, i64>("active"),
        "last24h": last24h,
    })))
}

#[derive(Deserialize)]
struct LogsQuery {
    token: Option<String>,
    limit: Option<i64>,
}

async fn logs(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Query(q): Query<LogsQuery>,
) -> ApiResult {
    check_auth(&state, &headers, q.token.as_deref())?;
    let limit = q.limit.unwrap_or(100);
    let client = state.db.get().await.map_err(|_| db_error())?;
    let rows = client
        .query(
            "SELECT l.id, l.event_type, l.client_ip, l.created_at, u.username \
             FROM connection_logs l LEFT JOIN users u ON l.user_id = u.id \
             ORDER BY l.created_at DESC LIMIT $1",
            &[&limit],
        )
        .await
        .map_err(|_| db_error())?;

    let out: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({
                "id": r.get::<_, i32>("id"),
                "event_type": r.get::<_, String>("event_type"),
                "client_ip": r.try_get::<_, Option<String>>("client_ip").unwrap_or(None),
                "created_at": ts(r, "created_at"),
                "username": r.try_get::<_, Option<String>>("username").unwrap_or(None),
            })
        })
        .collect();
    Ok(Json(json!(out)))
}
