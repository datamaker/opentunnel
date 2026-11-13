//! Admin HTTP API and static panel, served on the admin port.
//!
//! Port of `admin/adminServer.ts` (axum instead of Express), including the
//! unauthenticated `/health` endpoint added in PR #1.

use crate::auth::email_allowed;
use crate::config::AdminConfig;
use crate::db::DbPool;
use crate::settings::{self, Apply, Store};
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

/// A panel session. `actor` is what the audit log records — an email for an
/// SSO or forward-auth login, or a marker for the shared password.
#[derive(Clone, Debug)]
struct Session {
    actor: String,
    expires: i64,
}

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
    /// Parsed `ADMIN_TRUSTED_PROXIES`. Empty = forward-auth login disabled.
    trusted_proxies: Vec<IpNet>,
    /// Live panel sessions: token -> who it belongs to and when it lapses.
    tokens: Arc<Mutex<HashMap<String, Session>>>,
    attempts: Arc<Mutex<HashMap<IpAddr, LoginAttempts>>>,
    split: Arc<SplitPolicy>,
    settings: Arc<Store>,
    /// The live copies of settings the panel can change, so an edit takes
    /// effect without a restart.
    auth: Arc<crate::auth::AuthService>,
    /// Live tunnels, so "disconnect" closes the connection and not just its
    /// database row.
    sessions: Arc<crate::session::SessionManager>,
    /// Allowlist for admin logins. Empty = SSO/forward-auth disabled.
    /// Behind a lock: the panel can edit it, and the change must apply to
    /// the very next login rather than at the next restart.
    sso_emails: Arc<std::sync::RwLock<Vec<String>>>,
}

impl AdminState {
    fn sso_emails(&self) -> Vec<String> {
        self.sso_emails.read().unwrap().clone()
    }

    /// Forward-auth needs a proxy to trust *and* an allowlist to check against.
    fn forward_auth_enabled(&self) -> bool {
        !self.trusted_proxies.is_empty() && !self.sso_emails().is_empty()
    }
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
#[allow(clippy::too_many_arguments)]
pub async fn serve(
    cfg: AdminConfig,
    db: DbPool,
    split: Arc<SplitPolicy>,
    sso: Option<Arc<SsoVerifier>>,
    sso_client_id: String,
    production: bool,
    settings: Arc<Store>,
    auth: Arc<crate::auth::AuthService>,
    sessions: Arc<crate::session::SessionManager>,
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

    // Forward-auth login needs both a proxy we trust and an allowlist to check
    // the proxy's claim against; either alone is not enough to admit anyone.
    let mut trusted_proxies = Vec::new();
    for entry in &cfg.trusted_proxies {
        match IpNet::parse(entry) {
            Some(net) => trusted_proxies.push(net),
            None => tracing::warn!("ADMIN_TRUSTED_PROXIES: ignoring unparseable entry {entry:?}"),
        }
    }
    if !trusted_proxies.is_empty() && cfg.sso_emails.is_empty() {
        tracing::warn!(
            "ADMIN_TRUSTED_PROXIES is set but ADMIN_SSO_EMAILS is empty — \
             forward-auth login stays disabled (nobody would be allowed in)."
        );
    } else if !trusted_proxies.is_empty() {
        tracing::info!(
            "Admin forward-auth login enabled for {} trusted proxy range(s)",
            trusted_proxies.len()
        );
    }

    let state = AdminState {
        db,
        admin_password: cfg.password,
        password_login,
        sso: admin_sso,
        sso_client_id,
        sso_emails: Arc::new(std::sync::RwLock::new(cfg.sso_emails)),
        trusted_proxies,
        settings,
        auth,
        sessions,
        tokens: Arc::new(Mutex::new(HashMap::new())),
        attempts: Arc::new(Mutex::new(HashMap::new())),
        split,
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/api/auth/config", get(auth_config))
        .route("/api/login", post(login))
        .route("/api/login/sso", post(login_sso))
        .route("/api/login/forward-auth", post(login_forward_auth))
        .route("/api/settings", get(get_settings).put(put_settings))
        .route("/api/audit", get(get_audit))
        .route("/api/logout", post(logout))
        .route("/api/users", get(list_users).post(create_user))
        .route("/api/users/:id", put(update_user).delete(delete_user))
        .route("/api/users/:id/revoke", post(revoke_user))
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

/// An IPv4/IPv6 CIDR, for the trusted-proxy check.
#[derive(Clone, Copy, Debug)]
pub struct IpNet {
    addr: IpAddr,
    prefix: u8,
}

impl IpNet {
    /// Parse `10.0.0.0/8`, or a bare address (treated as a single host).
    pub fn parse(entry: &str) -> Option<IpNet> {
        let entry = entry.trim();
        let (addr, prefix) = match entry.split_once('/') {
            Some((a, p)) => (a, Some(p.parse::<u8>().ok()?)),
            None => (entry, None),
        };
        let addr: IpAddr = addr.parse().ok()?;
        let full = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = prefix.unwrap_or(full);
        if prefix > full {
            return None;
        }
        Some(IpNet { addr, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        fn masked(bytes: &[u8], prefix: u8) -> Vec<u8> {
            let mut out = bytes.to_vec();
            for (i, b) in out.iter_mut().enumerate() {
                let bit = (i as u32) * 8;
                let keep = (prefix as u32).saturating_sub(bit).min(8);
                *b &= if keep == 0 { 0 } else { !0u8 << (8 - keep) };
            }
            out
        }
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                masked(&net.octets(), self.prefix) == masked(&ip.octets(), self.prefix)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                masked(&net.octets(), self.prefix) == masked(&ip.octets(), self.prefix)
            }
            // Never match across families: a v4 proxy entry must not admit a
            // v6 peer (or its v4-mapped form).
            _ => false,
        }
    }
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

fn issue_token(state: &AdminState, actor: &str) -> String {
    let token = format!(
        "{}{}",
        Uuid::new_v4().simple(),
        Uuid::new_v4().simple()
    );
    state.tokens.lock().unwrap().insert(
        token.clone(),
        Session {
            actor: actor.to_string(),
            expires: now_ms() + SESSION_TTL_MS,
        },
    );
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

    use super::IpNet;
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn cidr_matches_only_inside_the_prefix() {
        let net = IpNet::parse("172.20.0.0/16").unwrap();
        assert!(net.contains(ip("172.20.0.1")));
        assert!(net.contains(ip("172.20.255.254")));
        assert!(!net.contains(ip("172.21.0.1")));
        // The VPN subnet must never be admitted by a docker-network entry.
        assert!(!net.contains(ip("10.8.0.4")));
    }

    #[test]
    fn bare_address_is_a_single_host() {
        let net = IpNet::parse("11.0.1.21").unwrap();
        assert!(net.contains(ip("11.0.1.21")));
        assert!(!net.contains(ip("11.0.1.22")));
    }

    #[test]
    fn prefix_zero_and_boundaries() {
        assert!(IpNet::parse("0.0.0.0/0").unwrap().contains(ip("8.8.8.8")));
        let net = IpNet::parse("192.168.1.128/25").unwrap();
        assert!(net.contains(ip("192.168.1.200")));
        assert!(!net.contains(ip("192.168.1.127")));
    }

    #[test]
    fn families_never_cross() {
        // A v4 trusted-proxy entry must not admit a v6 peer, including the
        // v4-mapped form of an address that would otherwise match.
        let v4 = IpNet::parse("172.20.0.0/16").unwrap();
        assert!(!v4.contains(ip("::ffff:172.20.0.1")));
        let v6 = IpNet::parse("fd00::/8").unwrap();
        assert!(v6.contains(ip("fd00::1")));
        assert!(!v6.contains(ip("172.20.0.1")));
    }

    #[test]
    fn rejects_malformed_entries() {
        assert!(IpNet::parse("not-an-ip").is_none());
        assert!(IpNet::parse("10.0.0.0/33").is_none());
        assert!(IpNet::parse("").is_none());
    }
}

/// Validate the bearer token against the in-memory session store. Tokens are
/// accepted from the Authorization header only — query-string tokens leak
/// into access logs, browser history and referrers.
/// Validate the bearer token and return who it belongs to.
fn check_auth(state: &AdminState, headers: &HeaderMap) -> Result<String, ApiError> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    let Some(token) = token else {
        return Err(err(StatusCode::UNAUTHORIZED, "Unauthorized"));
    };

    let mut tokens = state.tokens.lock().unwrap();
    match tokens.get(token) {
        Some(session) if now_ms() <= session.expires => Ok(session.actor.clone()),
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
        "forwardAuth": state.forward_auth_enabled(),
    })))
}

/// Log in on the strength of the reverse proxy's authentication header.
///
/// The panel sits behind gatehouse forward-auth, which has already established
/// who the user is; re-authenticating them here would just be a second password
/// prompt. The header is only believed when the peer is a configured trusted
/// proxy — reaching the admin port directly (it also listens on the VPN
/// network) must not let a client assert its own identity.
async fn login_forward_auth(
    State(state): State<AdminState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> ApiResult {
    if !state.forward_auth_enabled() {
        return Err(err(StatusCode::FORBIDDEN, "Forward-auth login is not enabled"));
    }
    if !state.trusted_proxies.iter().any(|net| net.contains(peer.ip())) {
        tracing::warn!("Forward-auth login attempt from untrusted peer {}", peer.ip());
        return Err(err(StatusCode::FORBIDDEN, "Not a trusted proxy"));
    }

    let email = headers
        .get("x-auth-email")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|e| !e.is_empty());
    let Some(email) = email else {
        return Err(err(StatusCode::UNAUTHORIZED, "No authenticated identity"));
    };

    if !email_allowed(email, &state.sso_emails()) {
        tracing::warn!("Forward-auth login rejected for {email} (not in ADMIN_SSO_EMAILS)");
        return Err(err(StatusCode::FORBIDDEN, "This account is not an admin"));
    }

    tracing::info!("Admin forward-auth login: {email}");
    Ok(Json(json!({ "token": issue_token(&state, email), "email": email })))
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
    // The shared password names no person; the audit log says so plainly.
    Ok(Json(json!({ "token": issue_token(&state, "password-login") })))
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

    if !email_allowed(&identity.email, &state.sso_emails()) {
        record_login_failure(&state, peer.ip());
        tracing::warn!(
            "Admin SSO login rejected for {} (not in ADMIN_SSO_EMAILS)",
            identity.email
        );
        return Err(err(StatusCode::FORBIDDEN, "This account is not an admin"));
    }

    record_login_success(&state, peer.ip());
    tracing::info!("Admin SSO login: {}", identity.email);
    Ok(Json(json!({ "token": issue_token(&state, &identity.email), "email": identity.email })))
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
            "SELECT id, username, is_active, max_connections, created_at, updated_at, \
                    tokens_valid_after \
             FROM users ORDER BY created_at DESC",
            &[],
        )
        .await
        .map_err(|_| db_error())?;

    // Counted from the live tunnels, not from the `sessions` table: this is
    // what "is this person connected right now" actually means.
    let live = state.sessions.live_counts();
    let users: Vec<Value> = rows
        .iter()
        .map(|r| {
            let id = r.get::<_, Uuid>("id");
            json!({
                "id": id.to_string(),
                "username": r.get::<_, String>("username"),
                "is_active": r.get::<_, bool>("is_active"),
                "max_connections": r.get::<_, i32>("max_connections"),
                "created_at": ts(r, "created_at"),
                "updated_at": ts(r, "updated_at"),
                "tokens_valid_after": ts(r, "tokens_valid_after"),
                "live_connections": live.get(&id).copied().unwrap_or(0),
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
    let hash = crate::auth::hash_password(password.clone())
            .await
            .ok_or_else(db_error)?;

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
    let actor = check_auth(&state, &headers)?;
    let deactivating = body.is_active == Some(false);

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
        let hash = crate::auth::hash_password(password.clone())
            .await
            .ok_or_else(db_error)?;
        params.push(Box::new(hash));
        set_clauses.push(format!("password_hash = ${}", params.len()));
    }
    if let Some(is_active) = body.is_active {
        params.push(Box::new(is_active));
        set_clauses.push(format!("is_active = ${}", params.len()));
    }
    if deactivating {
        // Deactivation is a revocation: void the tokens in the same statement,
        // so re-activating the account later does not bring old tokens back.
        params.push(Box::new(revocation_instant()));
        set_clauses.push(format!("tokens_valid_after = ${}", params.len()));
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

    // The row is already inactive, so nothing closed here can reconnect.
    let mut closed = 0;
    if deactivating {
        let username: String = row.get("username");
        closed = close_user_sessions(&state, id, None, "account deactivated by an admin").await;
        state
            .settings
            .audit(
                &actor,
                "user.deactivate",
                &format!("{username}: 비활성화, 토큰 무효화, 연결 {closed}개 종료"),
            )
            .await;
    }

    Ok(Json(json!({
        "id": row.get::<_, Uuid>("id").to_string(),
        "username": row.get::<_, String>("username"),
        "is_active": row.get::<_, bool>("is_active"),
        "max_connections": row.get::<_, i32>("max_connections"),
        "updated_at": ts(&row, "updated_at"),
        "closedConnections": closed,
    })))
}

async fn delete_user(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult {
    let actor = check_auth(&state, &headers)?;
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
    let username: String = row.get("username");
    tracing::info!("User deleted: {username}");

    // The user's `sessions` rows went with the user (ON DELETE CASCADE), and
    // their tokens no longer resolve to anyone; what is left is the tunnels
    // that are open right now.
    let closed = state.sessions.kill_user(id, "user deleted by an admin").len();
    state
        .settings
        .audit(&actor, "user.delete", &format!("{username}: 삭제, 연결 {closed}개 종료"))
        .await;
    Ok(Json(json!({ "success": true, "closedConnections": closed })))
}

/// "모든 기기에서 로그아웃": void every session token of the user and close
/// their live tunnels. The account stays active — an SSO user gets back in by
/// signing in again.
async fn revoke_user(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult {
    let actor = check_auth(&state, &headers)?;
    let client = state.db.get().await.map_err(|_| db_error())?;
    let row = client
        .query_opt("SELECT username FROM users WHERE id = $1", &[&id])
        .await
        .map_err(|_| db_error())?;
    let Some(row) = row else {
        return Err(err(StatusCode::NOT_FOUND, "User not found"));
    };
    let username: String = row.get("username");
    drop(client);

    let closed = revoke_and_close(&state, id, None, "logged out everywhere by an admin").await?;
    state
        .settings
        .audit(
            &actor,
            "user.revoke",
            &format!("{username}: 모든 기기에서 로그아웃 (토큰 무효화, 연결 {closed}개 종료)"),
        )
        .await;
    Ok(Json(json!({ "success": true, "closedConnections": closed })))
}

/// The instant written to `users.tokens_valid_after`. Millisecond precision,
/// to match the `iat_ms` claim it is compared against.
fn revocation_instant() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp_millis(now_ms()).unwrap_or_else(chrono::Utc::now)
}

/// Void a user's tokens, then close their tunnels. In that order: a client
/// whose tunnel is closed reconnects within seconds, and must find its token
/// already dead. If the tokens cannot be voided nothing is closed.
async fn revoke_and_close(
    state: &AdminState,
    user_id: Uuid,
    extra_row: Option<Uuid>,
    reason: &str,
) -> Result<usize, ApiError> {
    let Some(killed) = state.auth.revoke_user(user_id, reason).await else {
        return Err(db_error());
    };
    Ok(finish_closing(state, killed, extra_row).await)
}

/// Close a user's live tunnels (the caller has already made sure they cannot
/// come back) and return how many were closed.
async fn close_user_sessions(
    state: &AdminState,
    user_id: Uuid,
    extra_row: Option<Uuid>,
    reason: &str,
) -> usize {
    let killed = state.sessions.kill_user(user_id, reason);
    finish_closing(state, killed, extra_row).await
}

/// Wait for the closed connections to finish their own cleanup (release the
/// tunnel IP, write the disconnect log, delete the `sessions` row), so that
/// the panel's next refresh already shows them gone. Rows that are still there
/// after the wait — or that had no live tunnel behind them to begin with — are
/// removed here.
async fn finish_closing(
    state: &AdminState,
    killed: Vec<Arc<crate::session::manager::SessionInfo>>,
    extra_row: Option<Uuid>,
) -> usize {
    let closed = killed.len();
    let rows: Vec<Uuid> = killed
        .iter()
        .filter_map(|info| info.db_id)
        .chain(extra_row)
        .collect();
    if rows.is_empty() {
        return closed;
    }
    let Ok(client) = state.db.get().await else {
        return closed;
    };
    if closed > 0 {
        for _ in 0..30 {
            let remaining = client
                .query_one("SELECT COUNT(*) FROM sessions WHERE id = ANY($1)", &[&rows])
                .await
                .map(|row| row.get::<_, i64>(0))
                .unwrap_or(0);
            if remaining == 0 {
                return closed;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }
    let _ = client
        .execute("DELETE FROM sessions WHERE id = ANY($1)", &[&rows])
        .await;
    closed
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
            let id = r.get::<_, Uuid>("id");
            json!({
                // False for a row whose tunnel is gone (it is cleaned up by
                // the stale-session sweep, or by disconnecting it here).
                "live": state.sessions.find_by_db_id(id).is_some(),
                "id": id.to_string(),
                "assigned_ip": r.get::<_, String>("assigned_ip"),
                "client_platform": r.get::<_, String>("client_platform"),
                "connected_at": ts(r, "connected_at"),
                "username": r.get::<_, String>("username"),
            })
        })
        .collect();
    Ok(Json(json!(sessions)))
}

/// "연결 끊기". Closing the socket alone would achieve nothing — every client
/// reconnects on its own with its session token — so this is a revocation of
/// the session's user: their tokens are voided and all of their tunnels are
/// closed, which sends an SSO user back to the sign-in screen. (A password
/// user can log straight back in; deactivate the account to keep one out.)
async fn delete_session(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult {
    let actor = check_auth(&state, &headers)?;
    let client = state.db.get().await.map_err(|_| db_error())?;
    let row = client
        .query_opt(
            "SELECT s.user_id, s.assigned_ip, u.username \
             FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.id = $1",
            &[&id],
        )
        .await
        .map_err(|_| db_error())?;
    drop(client);

    // The row normally exists; fall back to the live tunnel if it does not.
    let (user_id, label) = match (&row, state.sessions.find_by_db_id(id)) {
        (Some(row), _) => (
            row.get::<_, Uuid>("user_id"),
            format!(
                "{} ({})",
                row.get::<_, String>("username"),
                row.get::<_, String>("assigned_ip")
            ),
        ),
        (None, Some(info)) => (info.user_id, info.username.clone()),
        (None, None) => return Err(err(StatusCode::NOT_FOUND, "Session not found")),
    };

    let closed = revoke_and_close(&state, user_id, Some(id), "disconnected by an admin").await?;
    tracing::info!("Session terminated: {id} ({closed} live connection(s) closed)");
    state
        .settings
        .audit(
            &actor,
            "session.disconnect",
            &format!("{label}: 연결 끊기 (토큰 무효화, 연결 {closed}개 종료)"),
        )
        .await;
    Ok(Json(json!({ "success": true, "closedConnections": closed })))
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
    let actor = check_auth(&state, &headers)?;

    // Same rules as the settings form, checked for all three values before
    // anything is written: this endpoint used to store whatever it was sent,
    // and a bad entry could leave the policy half-saved.
    let clean = |entries: &[String]| -> Result<Vec<String>, ApiError> {
        let entries: Vec<String> = entries
            .iter()
            .map(|e| e.trim().to_string())
            .filter(|e| !e.is_empty())
            .collect();
        if entries.iter().any(|e| e.contains(',')) {
            return Err(err(StatusCode::BAD_REQUEST, "항목 안에 쉼표를 넣을 수 없습니다"));
        }
        Ok(entries)
    };
    let body = SplitBody {
        enabled: body.enabled,
        routes: clean(&body.routes)?,
        domains: clean(&body.domains)?,
    };
    for (key, value) in [
        ("SPLIT_TUNNEL", body.enabled.to_string()),
        ("SPLIT_INCLUDE_ROUTES", body.routes.join(",")),
        ("SPLIT_INCLUDE_DOMAINS", body.domains.join(",")),
    ] {
        settings::validate(key, &value).map_err(|e| err(StatusCode::BAD_REQUEST, &e))?;
    }

    // Persist before applying. The policy used to live only in memory, so a
    // container restart silently reverted whatever was set here back to the
    // environment — losing work with no error to notice.
    for (key, value) in [
        ("SPLIT_TUNNEL", body.enabled.to_string()),
        ("SPLIT_INCLUDE_ROUTES", body.routes.join(",")),
        ("SPLIT_INCLUDE_DOMAINS", body.domains.join(",")),
    ] {
        if let Err(e) = state.settings.set(key, &value, &actor).await {
            tracing::error!("split: failed to persist {key}: {e}");
            return Err(err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "정책을 저장하지 못했습니다 — 적용하지 않았습니다",
            ));
        }
    }

    state
        .split
        .update(body.enabled, body.routes, body.domains)
        .await;
    tracing::info!("Split-tunnel policy updated via admin API by {actor}");
    Ok(Json(split_json(&state.split.snapshot())))
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

/// The editable settings with their current values, so the panel can render a
/// form without knowing the schema. `source` tells the operator whether a value
/// is still the deployment default or something they changed.
async fn get_settings(State(state): State<AdminState>, headers: HeaderMap) -> ApiResult {
    check_auth(&state, &headers)?;
    let stored = state.settings.load().await;
    let live = state.split.snapshot();

    let items: Vec<Value> = settings::EDITABLE
        .iter()
        .map(|def| {
            // Split-tunnel values are read back from the live policy: it is the
            // thing actually in force, and it may have been changed in this
            // process since the row was written.
            let effective = match def.key {
                "SPLIT_TUNNEL" => Some(live.enabled.to_string()),
                "SPLIT_INCLUDE_ROUTES" => Some(live.static_routes.join(",")),
                "SPLIT_INCLUDE_DOMAINS" => Some(live.domains.join(",")),
                "ADMIN_SSO_EMAILS" => Some(state.sso_emails().join(",")),
                _ => stored.get(def.key).cloned(),
            };
            json!({
                "key": def.key,
                "kind": def.kind,
                "apply": def.apply,
                "group": def.group,
                "label": def.label,
                "help": def.help,
                "value": effective.unwrap_or_default(),
                "source": if stored.contains_key(def.key) { "db" } else { "env" },
            })
        })
        .collect();

    Ok(Json(json!({ "settings": items })))
}

#[derive(Deserialize)]
struct SettingsBody {
    /// Only the keys being changed; anything omitted is left alone.
    values: HashMap<String, String>,
}

async fn put_settings(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(body): Json<SettingsBody>,
) -> ApiResult {
    let actor = check_auth(&state, &headers)?;

    // Validate everything before writing anything, so a typo in one field
    // cannot leave the rest half-applied.
    for (key, value) in &body.values {
        settings::validate(key, value).map_err(|e| err(StatusCode::BAD_REQUEST, &e))?;
    }

    for (key, value) in &body.values {
        state
            .settings
            .set(key, value, &actor)
            .await
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;
    }

    // Push the live-applied ones into the running state. The rest take effect
    // at the next restart, which `apply` tells the panel to say out loud.
    let touches_split = body.values.keys().any(|k| k.starts_with("SPLIT_"));
    if touches_split {
        let merged = state.settings.load().await;
        let get = |key: &str, fallback: Vec<String>| -> Vec<String> {
            merged
                .get(key)
                .map(|raw| {
                    raw.split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or(fallback)
        };
        let current = state.split.snapshot();
        let enabled = merged
            .get("SPLIT_TUNNEL")
            .map(|v| v == "true")
            .unwrap_or(current.enabled);
        state
            .split
            .update(
                enabled,
                get("SPLIT_INCLUDE_ROUTES", current.static_routes),
                get("SPLIT_INCLUDE_DOMAINS", current.domains),
            )
            .await;
    }

    if let Some(raw) = body.values.get("SSO_ALLOWED_DOMAINS") {
        state.auth.set_sso_allowed(csv(raw));
    }
    if let Some(raw) = body.values.get("ADMIN_SSO_EMAILS") {
        *state.sso_emails.write().unwrap() = csv(raw);
    }

    let pending: Vec<&str> = body
        .values
        .keys()
        .filter_map(|k| settings::definition(k))
        .filter(|d| d.apply == Apply::Restart)
        .map(|d| d.key)
        .collect();

    Ok(Json(json!({ "ok": true, "restartRequired": pending })))
}

fn csv(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

async fn get_audit(State(state): State<AdminState>, headers: HeaderMap) -> ApiResult {
    check_auth(&state, &headers)?;
    let client = state.db.get().await.map_err(|_| db_error())?;
    let rows = client
        .query(
            "SELECT actor, action, detail, created_at
             FROM admin_audit ORDER BY created_at DESC LIMIT 200",
            &[],
        )
        .await
        .map_err(|_| db_error())?;

    let entries: Vec<Value> = rows
        .iter()
        .map(|row| {
            json!({
                "actor": row.get::<_, String>(0),
                "action": row.get::<_, String>(1),
                "detail": row.get::<_, Option<String>>(2),
                "createdAt": ts(row, "created_at"),
            })
        })
        .collect();
    Ok(Json(json!({ "entries": entries })))
}
