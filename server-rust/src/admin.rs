//! Admin HTTP API and static panel, served on the admin port.
//!
//! Port of `admin/adminServer.ts` (axum instead of Express), including the
//! unauthenticated `/health` endpoint added in PR #1.

use crate::auth::email_allowed;
use crate::config::AdminConfig;
use crate::db::DbPool;
use crate::split::SplitPolicy;
use crate::sso::SsoVerifier;
use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{delete, get, post, put},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use tower_http::services::ServeDir;
use uuid::Uuid;

const SESSION_TTL_MS: i64 = 24 * 60 * 60 * 1000;

/// The compiled-in fallback admin password. Password login is refused in
/// production while this is in effect — set `ADMIN_PASSWORD`.
const DEFAULT_ADMIN_PASSWORD: &str = "admin123";

/// Brute-force guard for the login endpoints: after this many consecutive
/// failures from one IP, logins from it are locked out for `LOCKOUT_MS`.
const MAX_LOGIN_FAILURES: u32 = 5;
const LOCKOUT_MS: i64 = 60_000;
const MIN_USER_PASSWORD_LEN: usize = 8;

#[derive(Default)]
struct LoginAttempts {
    failures: u32,
    locked_until: i64,
}

#[derive(Clone)]
struct AdminState {
    db: DbPool,
    admin_password: String,
    /// False when the compiled-in default password is in effect in production.
    password_login: bool,
    /// OIDC verifier for admin-panel SSO logins (aud = OIDC_ADMIN_CLIENT_ID).
    sso: Option<Arc<SsoVerifier>>,
    /// Client id exposed to the panel for Google Identity Services.
    sso_client_id: String,
    /// Allowlist for admin SSO logins. Empty = admin SSO disabled.
    sso_emails: Vec<String>,
    tokens: Arc<Mutex<HashMap<String, i64>>>,
    attempts: Arc<Mutex<HashMap<IpAddr, LoginAttempts>>>,
    split: Arc<SplitPolicy>,
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
pub async fn serve(
    cfg: AdminConfig,
    db: DbPool,
    split: Arc<SplitPolicy>,
    sso: Option<Arc<SsoVerifier>>,
    sso_client_id: String,
    production: bool,
) -> anyhow::Result<()> {
    // Refuse the compiled-in default password in production: a panel that
    // manages VPN accounts must not be reachable with known credentials.
    let default_password = cfg.password == DEFAULT_ADMIN_PASSWORD || cfg.password.is_empty();
    let password_login = !(production && default_password);
    if !password_login {
        tracing::warn!(
            "Admin password login DISABLED: ADMIN_PASSWORD is unset/default in production. \
             Set a strong ADMIN_PASSWORD (or configure ADMIN_SSO_EMAILS for SSO login)."
        );
    } else if default_password {
        tracing::warn!("Admin panel is using the default password — set ADMIN_PASSWORD");
    }

    let admin_sso = match (&sso, cfg.sso_emails.is_empty()) {
        (Some(_), false) => sso.clone(),
        (Some(_), true) => {
            tracing::info!("Admin SSO login disabled (ADMIN_SSO_EMAILS not set)");
            None
        }
        (None, _) => None,
    };

    let state = AdminState {
        db,
        admin_password: cfg.password,
        password_login,
        sso: admin_sso,
        sso_client_id,
        sso_emails: cfg.sso_emails,
        tokens: Arc::new(Mutex::new(HashMap::new())),
        attempts: Arc::new(Mutex::new(HashMap::new())),
        split,
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/api/auth/config", get(auth_config))
        .route("/api/login", post(login))
        .route("/api/login/sso", post(login_sso))
        .route("/api/logout", post(logout))
        .route("/api/users", get(list_users).post(create_user))
        .route("/api/users/:id", put(update_user).delete(delete_user))
        .route("/api/sessions", get(list_sessions))
        .route("/api/sessions/:id", delete(delete_session))
        .route("/api/stats", get(stats))
        .route("/api/logs", get(logs))
        .route("/api/split", get(get_split).post(set_split))
        .fallback_service(ServeDir::new("public").append_index_html_on_directories(true))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], cfg.port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("Admin panel running at http://localhost:{}", cfg.port);
    // ConnectInfo gives the login rate limiter the peer address.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

/// Constant-time string equality, so the admin password check does not leak
/// prefix length through response timing.
fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let mut diff = a.len() ^ b.len();
    for i in 0..a.len().min(b.len()) {
        diff |= (a[i] ^ b[i]) as usize;
    }
    diff == 0
}

/// Returns an error while the IP is locked out from logging in.
fn check_lockout(state: &AdminState, ip: IpAddr) -> Result<(), ApiError> {
    let attempts = state.attempts.lock().unwrap();
    if let Some(a) = attempts.get(&ip) {
        if now_ms() < a.locked_until {
            return Err(err(
                StatusCode::TOO_MANY_REQUESTS,
                "Too many failed logins — try again later",
            ));
        }
    }
    Ok(())
}

fn record_login_failure(state: &AdminState, ip: IpAddr) {
    let mut attempts = state.attempts.lock().unwrap();
    let a = attempts.entry(ip).or_default();
    a.failures += 1;
    if a.failures >= MAX_LOGIN_FAILURES {
        a.failures = 0;
        a.locked_until = now_ms() + LOCKOUT_MS;
        tracing::warn!("Admin login locked out for {ip} after repeated failures");
    }
}

fn record_login_success(state: &AdminState, ip: IpAddr) {
    state.attempts.lock().unwrap().remove(&ip);
}

fn issue_token(state: &AdminState) -> String {
    let token = format!(
        "{}{}",
        Uuid::new_v4().simple(),
        Uuid::new_v4().simple()
    );
    state
        .tokens
        .lock()
        .unwrap()
        .insert(token.clone(), now_ms() + SESSION_TTL_MS);
    token
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

#[cfg(test)]
mod tests {
    use super::ct_eq;

    #[test]
    fn ct_eq_matches_equal_strings() {
        assert!(ct_eq("secret-password", "secret-password"));
        assert!(ct_eq("", ""));
    }

    #[test]
    fn ct_eq_rejects_differences() {
        assert!(!ct_eq("secret-password", "secret-passworD"));
        assert!(!ct_eq("short", "short-but-longer"));
        assert!(!ct_eq("a", ""));
    }
}

/// Validate the bearer token against the in-memory session store. Tokens are
/// accepted from the Authorization header only — query-string tokens leak
/// into access logs, browser history and referrers.
fn check_auth(state: &AdminState, headers: &HeaderMap) -> Result<(), ApiError> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

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

/// Login methods available to the panel, plus the GIS client id. Unauthenticated
/// by design: the login screen needs it before any token exists.
async fn auth_config(State(state): State<AdminState>) -> ApiResult {
    Ok(Json(json!({
        "passwordLogin": state.password_login,
        "sso": state.sso.is_some(),
        "clientId": if state.sso.is_some() { json!(state.sso_client_id) } else { Value::Null },
    })))
}

async fn login(
    State(state): State<AdminState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(body): Json<LoginBody>,
) -> ApiResult {
    check_lockout(&state, peer.ip())?;
    if !state.password_login {
        return Err(err(StatusCode::FORBIDDEN, "Password login is disabled"));
    }
    if !ct_eq(&body.password, &state.admin_password) {
        record_login_failure(&state, peer.ip());
        return Err(err(StatusCode::UNAUTHORIZED, "Invalid password"));
    }
    record_login_success(&state, peer.ip());
    Ok(Json(json!({ "token": issue_token(&state) })))
}

#[derive(Deserialize)]
struct SsoLoginBody {
    #[serde(rename = "idToken")]
    id_token: String,
}

/// Admin-panel SSO login: verify a Google id_token (aud =
/// `OIDC_ADMIN_CLIENT_ID`) and check the email against `ADMIN_SSO_EMAILS`.
async fn login_sso(
    State(state): State<AdminState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(body): Json<SsoLoginBody>,
) -> ApiResult {
    check_lockout(&state, peer.ip())?;
    let Some(verifier) = state.sso.as_ref() else {
        return Err(err(StatusCode::FORBIDDEN, "SSO login is not enabled"));
    };

    let identity = match verifier.verify_id_token(&body.id_token).await {
        Ok(identity) => identity,
        Err(message) => {
            record_login_failure(&state, peer.ip());
            return Err(err(StatusCode::UNAUTHORIZED, &message));
        }
    };

    if !email_allowed(&identity.email, &state.sso_emails) {
        record_login_failure(&state, peer.ip());
        tracing::warn!(
            "Admin SSO login rejected for {} (not in ADMIN_SSO_EMAILS)",
            identity.email
        );
        return Err(err(StatusCode::FORBIDDEN, "This account is not an admin"));
    }

    record_login_success(&state, peer.ip());
    tracing::info!("Admin SSO login: {}", identity.email);
    Ok(Json(json!({ "token": issue_token(&state), "email": identity.email })))
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

fn ts(row: &tokio_postgres::Row, col: &str) -> Value {
    match row.try_get::<_, chrono::DateTime<chrono::Utc>>(col) {
        Ok(dt) => json!(dt.to_rfc3339()),
        Err(_) => Value::Null,
    }
}

async fn list_users(
    State(state): State<AdminState>,
    headers: HeaderMap,
) -> ApiResult {
    check_auth(&state, &headers)?;
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
    Json(body): Json<CreateUserBody>,
) -> ApiResult {
    check_auth(&state, &headers)?;

    let (Some(username), Some(password)) = (body.username, body.password) else {
        return Err(err(StatusCode::BAD_REQUEST, "Username and password required"));
    };
    if password.len() < MIN_USER_PASSWORD_LEN {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "Password must be at least 8 characters",
        ));
    }
    let max_conn = body.max_connections.unwrap_or(3);
    let hash = bcrypt::hash(&password, bcrypt::DEFAULT_COST).map_err(|_| db_error())?;

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
    Json(body): Json<UpdateUserBody>,
) -> ApiResult {
    check_auth(&state, &headers)?;

    let mut set_clauses: Vec<String> = vec!["updated_at = NOW()".to_string()];
    let mut params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> = Vec::new();

    if let Some(username) = body.username {
        params.push(Box::new(username));
        set_clauses.push(format!("username = ${}", params.len()));
    }
    if let Some(password) = body.password {
        if password.len() < MIN_USER_PASSWORD_LEN {
            return Err(err(
                StatusCode::BAD_REQUEST,
                "Password must be at least 8 characters",
            ));
        }
        let hash = bcrypt::hash(&password, bcrypt::DEFAULT_COST).map_err(|_| db_error())?;
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
) -> ApiResult {
    check_auth(&state, &headers)?;
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
) -> ApiResult {
    check_auth(&state, &headers)?;
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
) -> ApiResult {
    check_auth(&state, &headers)?;
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
) -> ApiResult {
    check_auth(&state, &headers)?;
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
    limit: Option<i64>,
}

async fn logs(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Query(q): Query<LogsQuery>,
) -> ApiResult {
    check_auth(&state, &headers)?;
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

// ---------------------------------------------------------------------------
// Split-tunnel policy
// ---------------------------------------------------------------------------

fn split_json(snap: &crate::split::SplitSnapshot) -> Value {
    serde_json::to_value(snap).unwrap_or_else(|_| json!({}))
}

/// View the effective split-tunnel policy (static routes + resolved domain IPs).
async fn get_split(
    State(state): State<AdminState>,
    headers: HeaderMap,
) -> ApiResult {
    check_auth(&state, &headers)?;
    Ok(Json(split_json(&state.split.snapshot())))
}

#[derive(Deserialize)]
struct SplitBody {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    routes: Vec<String>,
    #[serde(default)]
    domains: Vec<String>,
}

/// Replace the split-tunnel policy at runtime, re-resolve domains, and return
/// the new effective policy. Takes effect for subsequently-connecting clients.
async fn set_split(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(body): Json<SplitBody>,
) -> ApiResult {
    check_auth(&state, &headers)?;
    state
        .split
        .update(body.enabled, body.routes, body.domains)
        .await;
    tracing::info!("Split-tunnel policy updated via admin API");
    Ok(Json(split_json(&state.split.snapshot())))
}
