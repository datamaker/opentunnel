//! User authentication and session persistence.
//!
//! Port of `auth/authService.ts`. Uses bcrypt for password verification and
//! JWT for the opaque session token handed back to the client.
//!
//! ## Session tokens and revocation
//!
//! A session token is the reconnect credential: presenting one
//! (`authType: "session"`) yields a tunnel and a fresh token. So that this
//! chain ends, and can be cut:
//!
//! - every token carries `auth_time`, the moment of the real login it descends
//!   from (the SSO login, or the password login). Renewal is refused once
//!   `auth_time` is older than the absolute lifetime
//!   (`SSO_SESSION_MAX_LIFETIME_DAYS`, default `SSO_SESSION_TTL_DAYS`), and a
//!   renewed token never expires later than that;
//! - `users.tokens_valid_after` voids every token issued before it. It is set
//!   when an admin disconnects, deactivates or logs a user out;
//! - renewal re-checks `users.is_active`, the SSO allowlist and (for SSO users)
//!   gatehouse's account status, exactly like a fresh login.
//!
//! Tokens minted before these claims existed have neither `auth_time` nor
//! `iat`. They are read as issued at `exp - TTL` and logged in at that same
//! moment, so they keep working until they would have expired anyway.

use crate::db::DbPool;
use crate::gatehouse::{BoxFuture, GatehouseStatus, Verdict};
use crate::limits::{AuthFailLogLimiter, LogDecision};
use crate::protocol::ClientPlatform;
use crate::session::manager::SessionInfo;
use crate::session::SessionManager;
use chrono::{DateTime, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use uuid::Uuid;

/// Sentinel password hash for SSO-provisioned users. It is not a valid bcrypt
/// hash, so it can never match a password (bcrypt::verify errors out).
const SSO_PASSWORD_HASH: &str = "!sso";

/// Lifetime of a session token minted for a password login.
const PASSWORD_TOKEN_TTL_SECS: i64 = 24 * 60 * 60;

/// The one answer a failed password login gets, whatever the reason. Telling
/// "no such user" from "wrong password" from "account disabled" would let
/// anyone on the internet enumerate accounts.
const INVALID_CREDENTIALS: &str = "Invalid credentials";
const INVALID_SESSION_TOKEN: &str = "Invalid or expired session token";

/// A row of `users`, as far as authentication cares.
#[derive(Debug, Clone)]
pub struct UserRecord {
    pub id: Uuid,
    pub username: String,
    pub email: Option<String>,
    pub password_hash: String,
    pub is_active: bool,
    pub max_connections: i32,
    /// Tokens issued before this instant are void (`None` = never revoked).
    pub tokens_valid_after: Option<DateTime<Utc>>,
}

impl UserRecord {
    /// The address SSO knows this user by. Legacy accounts keep the email in
    /// `username` with an empty `email` column.
    fn sso_email(&self) -> &str {
        match self.email.as_deref().map(str::trim) {
            Some(email) if !email.is_empty() => email,
            _ => &self.username,
        }
    }
}

/// The store could not answer (database down, query failed).
#[derive(Debug, Clone, Copy)]
pub struct StoreError;

/// User lookups behind a trait, so the authentication rules can be tested
/// without a database.
pub trait UserStore: Send + Sync {
    fn by_username<'a>(&'a self, username: &'a str)
        -> BoxFuture<'a, Result<Option<UserRecord>, StoreError>>;
    fn by_id(&self, id: Uuid) -> BoxFuture<'_, Result<Option<UserRecord>, StoreError>>;
    /// Match on `email` or, for legacy accounts, `username` (case-insensitive;
    /// `email` is already lowercased).
    fn by_email<'a>(&'a self, email: &'a str)
        -> BoxFuture<'a, Result<Option<UserRecord>, StoreError>>;
    /// JIT-provision an SSO user: username = email, sentinel password hash.
    fn create_sso_user<'a>(&'a self, email: &'a str) -> BoxFuture<'a, Result<UserRecord, StoreError>>;
    /// Rows in `sessions` for this user (the concurrent-connection count).
    fn session_count(&self, user_id: Uuid) -> BoxFuture<'_, Result<i64, StoreError>>;
    /// Set `tokens_valid_after`. Returns whether the user exists.
    fn revoke_tokens(&self, user_id: Uuid, at: DateTime<Utc>)
        -> BoxFuture<'_, Result<bool, StoreError>>;
}

const USER_COLUMNS: &str =
    "id, username, email, password_hash, is_active, max_connections, tokens_valid_after";

pub struct PgUserStore {
    db: DbPool,
}

impl PgUserStore {
    pub fn new(db: DbPool) -> Self {
        PgUserStore { db }
    }

    fn record(row: &tokio_postgres::Row) -> UserRecord {
        UserRecord {
            id: row.get("id"),
            username: row.get("username"),
            email: row.get("email"),
            password_hash: row.get("password_hash"),
            // Both columns are nullable in the schema; a NULL must not panic
            // the connection task, and must not read as "active".
            is_active: row.get::<_, Option<bool>>("is_active").unwrap_or(false),
            max_connections: row.get::<_, Option<i32>>("max_connections").unwrap_or(3),
            tokens_valid_after: row.get("tokens_valid_after"),
        }
    }

    async fn one(
        &self,
        query: &str,
        params: &[&(dyn tokio_postgres::types::ToSql + Sync)],
    ) -> Result<Option<UserRecord>, StoreError> {
        let client = self.db.get().await.map_err(|_| StoreError)?;
        let row = client.query_opt(query, params).await.map_err(|e| {
            tracing::error!("user lookup failed: {e}");
            StoreError
        })?;
        Ok(row.as_ref().map(Self::record))
    }
}

impl UserStore for PgUserStore {
    fn by_username<'a>(
        &'a self,
        username: &'a str,
    ) -> BoxFuture<'a, Result<Option<UserRecord>, StoreError>> {
        Box::pin(async move {
            let query = format!("SELECT {USER_COLUMNS} FROM users WHERE username = $1");
            self.one(&query, &[&username]).await
        })
    }

    fn by_id(&self, id: Uuid) -> BoxFuture<'_, Result<Option<UserRecord>, StoreError>> {
        Box::pin(async move {
            let query = format!("SELECT {USER_COLUMNS} FROM users WHERE id = $1");
            self.one(&query, &[&id]).await
        })
    }

    fn by_email<'a>(
        &'a self,
        email: &'a str,
    ) -> BoxFuture<'a, Result<Option<UserRecord>, StoreError>> {
        Box::pin(async move {
            let query = format!(
                "SELECT {USER_COLUMNS} FROM users \
                 WHERE LOWER(email) = $1 OR LOWER(username) = $1 \
                 ORDER BY (LOWER(email) = $1) DESC, created_at LIMIT 1"
            );
            self.one(&query, &[&email]).await
        })
    }

    fn create_sso_user<'a>(&'a self, email: &'a str) -> BoxFuture<'a, Result<UserRecord, StoreError>> {
        Box::pin(async move {
            let client = self.db.get().await.map_err(|_| StoreError)?;
            let query = format!(
                "INSERT INTO users (username, email, password_hash, is_active) \
                 VALUES ($1, $1, $2, true) RETURNING {USER_COLUMNS}"
            );
            let row = client
                .query_one(&query, &[&email, &SSO_PASSWORD_HASH])
                .await
                .map_err(|e| {
                    tracing::error!("SSO: failed to JIT-create user {email}: {e}");
                    StoreError
                })?;
            Ok(Self::record(&row))
        })
    }

    fn session_count(&self, user_id: Uuid) -> BoxFuture<'_, Result<i64, StoreError>> {
        Box::pin(async move {
            let client = self.db.get().await.map_err(|_| StoreError)?;
            let row = client
                .query_one(
                    "SELECT COUNT(*) as count FROM sessions WHERE user_id = $1",
                    &[&user_id],
                )
                .await
                .map_err(|_| StoreError)?;
            Ok(row.get("count"))
        })
    }

    fn revoke_tokens(
        &self,
        user_id: Uuid,
        at: DateTime<Utc>,
    ) -> BoxFuture<'_, Result<bool, StoreError>> {
        Box::pin(async move {
            let client = self.db.get().await.map_err(|_| StoreError)?;
            let updated = client
                .execute(
                    "UPDATE users SET tokens_valid_after = $2 WHERE id = $1",
                    &[&user_id, &at],
                )
                .await
                .map_err(|e| {
                    tracing::error!("failed to revoke tokens of {user_id}: {e}");
                    StoreError
                })?;
            Ok(updated > 0)
        })
    }
}

/// Add what this version needs to a database created by an older one.
/// `schema.sql` only runs on a fresh database, so an existing deployment gets
/// the column here, at startup.
///
/// Safe to run against a live production database: adding a nullable column
/// with no default is a catalog-only change (no table rewrite, no backfill),
/// `IF NOT EXISTS` makes it idempotent, and the short `lock_timeout` means
/// that if something is holding `users` the server fails to start with a clear
/// error instead of queueing an exclusive lock in front of everyone else. The
/// previous server version never selects `*`, so it keeps working against the
/// new column if the deploy is rolled back.
pub async fn ensure_schema(db: &DbPool) -> anyhow::Result<()> {
    let client = db.get().await?;
    let result = client
        .batch_execute(
            "BEGIN;
             SET LOCAL lock_timeout = '5s';
             ALTER TABLE users
                 ADD COLUMN IF NOT EXISTS tokens_valid_after TIMESTAMP WITH TIME ZONE;
             COMMIT;",
        )
        .await;
    if let Err(e) = result {
        // Do not hand a connection stuck in an aborted transaction back to
        // the pool.
        let _ = client.batch_execute("ROLLBACK").await;
        return Err(e.into());
    }
    Ok(())
}

pub struct AuthService {
    db: DbPool,
    users: Arc<dyn UserStore>,
    /// Live tunnels, so that revoking a user also closes what is open.
    sessions: Arc<SessionManager>,
    gatehouse: Arc<GatehouseStatus>,
    jwt_secret: String,
    /// Lifetime of session tokens minted for SSO logins, in days.
    sso_session_ttl_days: i64,
    /// How long after the real login a token may keep being renewed, in days.
    max_lifetime_days: i64,
    /// Emails/domains allowed to authenticate via SSO. Empty = allow all.
    /// Behind a lock because the panel can change it while clients connect.
    sso_allowed: std::sync::RwLock<Vec<String>>,
    /// Whether `authType: "password"` (and tokens descending from it) work.
    password_auth: bool,
    /// Caps how many `auth_fail` rows one source can add to `connection_logs`.
    auth_fail_log: AuthFailLogLimiter,
    /// Password checks run against the dummy hash (no such user, or a stored
    /// hash that is not bcrypt), so those cost the same as a real check.
    dummy_verifications: AtomicU64,
}

/// What [`AuthService::new`] needs besides its collaborators.
#[derive(Debug, Clone)]
pub struct AuthSettings {
    pub jwt_secret: String,
    pub sso_session_ttl_days: i64,
    pub max_lifetime_days: i64,
    pub sso_allowed: Vec<String>,
    pub password_auth: bool,
    pub auth_fail_log_per_min: u32,
}

/// bcrypt is deliberately slow (tens of milliseconds of pure CPU), so it must
/// not run on the async workers, and it must not be allowed to occupy every
/// core either: this host also runs the SSO and the internal tools. At most
/// this many bcrypt operations run at once; the rest queue.
fn bcrypt_permits() -> &'static tokio::sync::Semaphore {
    static PERMITS: std::sync::OnceLock<tokio::sync::Semaphore> = std::sync::OnceLock::new();
    PERMITS.get_or_init(|| {
        let cores = std::thread::available_parallelism().map_or(2, |n| n.get());
        tokio::sync::Semaphore::new((cores / 2).max(1))
    })
}

/// Cost of the dummy hash: the same as real password hashes, so that checking
/// against it takes as long. (Tests use the cheapest cost to stay fast.)
#[cfg(not(test))]
const DUMMY_HASH_COST: u32 = bcrypt::DEFAULT_COST;
#[cfg(test)]
const DUMMY_HASH_COST: u32 = 4;

/// A real bcrypt hash that no login is ever compared against for a decision —
/// only to spend the time a genuine comparison would.
fn dummy_hash() -> &'static str {
    static HASH: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    HASH.get_or_init(|| {
        bcrypt::hash(Uuid::new_v4().to_string(), DUMMY_HASH_COST)
            .expect("bcrypt can hash a fixed-length string")
    })
}

/// Verify a password against a bcrypt hash on the blocking thread pool.
///
/// `hash` is `None` when there is no such user. In that case, and when the
/// stored hash is not a bcrypt hash at all (the SSO sentinel), the password is
/// checked against a dummy hash instead and the answer is `false` — so "no such
/// user" and "SSO-only user" are not distinguishable from "wrong password" by
/// how fast the server answers. The second value reports that this happened.
pub async fn verify_password(password: String, hash: Option<String>) -> (bool, bool) {
    let Ok(_permit) = bcrypt_permits().acquire().await else {
        return (false, false);
    };
    tokio::task::spawn_blocking(move || {
        if let Some(hash) = hash {
            if let Ok(matches) = bcrypt::verify(&password, &hash) {
                return (matches, false);
            }
        }
        let _ = bcrypt::verify(&password, dummy_hash());
        (false, true)
    })
    .await
    .unwrap_or((false, false))
}

/// Hash a password with bcrypt on the blocking thread pool.
pub async fn hash_password(password: String) -> Option<String> {
    let _permit = bcrypt_permits().acquire().await.ok()?;
    tokio::task::spawn_blocking(move || bcrypt::hash(password, bcrypt::DEFAULT_COST).ok())
        .await
        .ok()
        .flatten()
}

/// Check an email against an allowlist of emails and domains. Entries may be a
/// full email (`user@example.com`), a domain (`example.com`) or an
/// at-prefixed domain (`@example.com`). An empty list allows everything.
pub fn email_allowed(email: &str, allowed: &[String]) -> bool {
    if allowed.is_empty() {
        return true;
    }
    let email = email.trim().to_lowercase();
    if !email.contains('@') {
        return false; // not a plausible email — never allowlist-match it
    }
    let domain = email.rsplit('@').next().unwrap_or("");
    allowed.iter().any(|entry| {
        let entry = entry.trim().trim_start_matches('@').to_lowercase();
        if entry.is_empty() {
            false
        } else if entry.contains('@') {
            email == entry
        } else {
            domain == entry
        }
    })
}

#[derive(Debug)]
pub struct AuthOk {
    pub user_id: Uuid,
    pub username: String,
    pub session_token: String,
    /// True when the session descends from an SSO login.
    pub sso: bool,
    /// The SSO email (SSO sessions only).
    pub email: Option<String>,
    /// When this authentication began (unix milliseconds). The new token
    /// carries the same instant, and it is what `tokens_valid_after` is
    /// compared against — taken *before* the account was looked up, so a
    /// revocation that lands while a login is in flight still voids it.
    pub issued_at_ms: i64,
    /// When the user last really logged in (unix seconds).
    pub auth_time: i64,
}

/// Either an authenticated user or a client-facing error message.
pub type AuthResult = Result<AuthOk, String>;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    user_id: String,
    username: String,
    platform: String,
    exp: usize,
    /// True when the token was minted via SSO login (longer TTL).
    #[serde(default)]
    sso: bool,
    /// When this token was minted (unix seconds). Absent on tokens from
    /// before revocation support.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    iat: Option<i64>,
    /// `iat` with millisecond resolution, for comparing against
    /// `users.tokens_valid_after`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    iat_ms: Option<i64>,
    /// When the user really logged in (unix seconds); copied unchanged into
    /// every renewed token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    auth_time: Option<i64>,
    /// The SSO email the login was for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    email: Option<String>,
}

/// The two instants a session token stands for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TokenTimes {
    issued_at_ms: i64,
    auth_time: i64,
}

fn now_ms() -> i64 {
    Utc::now().timestamp_millis()
}

impl AuthService {
    pub fn new(
        db: DbPool,
        users: Arc<dyn UserStore>,
        sessions: Arc<SessionManager>,
        gatehouse: Arc<GatehouseStatus>,
        settings: AuthSettings,
    ) -> Self {
        // Pay for the dummy hash now rather than during the first failed login.
        std::thread::spawn(|| {
            dummy_hash();
        });
        AuthService {
            db,
            users,
            sessions,
            gatehouse,
            jwt_secret: settings.jwt_secret,
            sso_session_ttl_days: settings.sso_session_ttl_days,
            max_lifetime_days: settings.max_lifetime_days.max(1),
            sso_allowed: std::sync::RwLock::new(settings.sso_allowed),
            password_auth: settings.password_auth,
            auth_fail_log: AuthFailLogLimiter::new(settings.auth_fail_log_per_min),
            dummy_verifications: AtomicU64::new(0),
        }
    }

    /// Replace the SSO allowlist at runtime (panel edit). Applies to the next
    /// authentication attempt, including session-token renewals; tunnels that
    /// are already up stay up until they reconnect.
    pub fn set_sso_allowed(&self, allowed: Vec<String>) {
        *self.sso_allowed.write().unwrap() = allowed;
    }

    fn max_lifetime_secs(&self) -> i64 {
        self.max_lifetime_days.saturating_mul(24 * 60 * 60)
    }

    fn token_ttl_secs(&self, sso: bool) -> i64 {
        if sso {
            self.sso_session_ttl_days.saturating_mul(24 * 60 * 60)
        } else {
            PASSWORD_TOKEN_TTL_SECS
        }
    }

    /// Verify credentials, enforce the account/connection limits and, on
    /// success, mint a JWT session token.
    pub async fn authenticate(
        &self,
        username: &str,
        password: &str,
        platform: ClientPlatform,
        client_ip: IpAddr,
    ) -> AuthResult {
        if !self.password_auth {
            self.log_event(
                None,
                "auth_fail",
                platform,
                client_ip,
                Some("Password auth attempted but VPN_PASSWORD_AUTH is off"),
            )
            .await;
            return Err("Password login is disabled on this server — sign in with SSO".to_string());
        }
        let issued_at_ms = now_ms();

        let user = self
            .users
            .by_username(username)
            .await
            .map_err(|_| "Internal server error".to_string())?;

        // The password is always checked — against the dummy hash when there
        // is no user — and every failure below gets the same answer.
        let hash = user.as_ref().map(|u| u.password_hash.clone());
        let (password_valid, dummy) = verify_password(password.to_string(), hash).await;
        if dummy {
            self.dummy_verifications.fetch_add(1, Ordering::Relaxed);
        }

        let Some(user) = user else {
            self.log_event(None, "auth_fail", platform, client_ip, Some("User not found"))
                .await;
            return Err(INVALID_CREDENTIALS.to_string());
        };
        if !password_valid {
            self.log_event(Some(user.id), "auth_fail", platform, client_ip, Some("Wrong password"))
                .await;
            return Err(INVALID_CREDENTIALS.to_string());
        }
        if !user.is_active {
            self.log_event(Some(user.id), "auth_fail", platform, client_ip, Some("Account disabled"))
                .await;
            return Err(INVALID_CREDENTIALS.to_string());
        }

        self.check_connection_limit(&user, platform, client_ip).await?;

        let auth_time = issued_at_ms / 1000;
        let session_token = self.sign_token(&user, platform, false, None, issued_at_ms, auth_time)?;

        tracing::info!("User {username} authenticated successfully from {client_ip}");

        Ok(AuthOk {
            user_id: user.id,
            username: user.username,
            session_token,
            sso: false,
            email: None,
            issued_at_ms,
            auth_time,
        })
    }

    /// Authenticate an SSO login whose id_token has already been verified
    /// (see [`crate::sso::SsoVerifier`]). Looks the user up by email and
    /// JIT-provisions one on first login. `login_time` is when the IdP issued
    /// the id_token (unix seconds).
    pub async fn authenticate_sso(
        &self,
        email: &str,
        name: Option<&str>,
        login_time: i64,
        platform: ClientPlatform,
        client_ip: IpAddr,
    ) -> AuthResult {
        let issued_at_ms = now_ms();
        let auth_time = login_time.min(issued_at_ms / 1000);

        // Gate JIT provisioning (and login) on the allowlist: without this,
        // any account the IdP verifies gets a VPN account auto-created.
        if !self.sso_email_allowed(email) {
            self.log_event(
                None,
                "auth_fail",
                platform,
                client_ip,
                Some(&format!("SSO email not in allowlist: {email}")),
            )
            .await;
            return Err("This account is not allowed on this VPN".to_string());
        }

        let existing = self
            .users
            .by_email(email)
            .await
            .map_err(|_| "Internal server error".to_string())?;

        // gatehouse decides before anything is provisioned: an account it has
        // deactivated (or never heard of) gets no VPN user created.
        self.check_gatehouse(
            email,
            auth_time,
            existing.as_ref().map(|u| u.id),
            platform,
            client_ip,
        )
        .await?;

        let user = match existing {
            Some(user) => user,
            None => {
                let created = self
                    .users
                    .create_sso_user(email)
                    .await
                    .map_err(|_| "Internal server error".to_string())?;
                tracing::info!(
                    "SSO: JIT-created user {email}{}",
                    name.map(|n| format!(" ({n})")).unwrap_or_default()
                );
                created
            }
        };

        if !user.is_active {
            self.log_event(
                Some(user.id),
                "auth_fail",
                platform,
                client_ip,
                Some("Account disabled (sso)"),
            )
            .await;
            return Err("Account is disabled".to_string());
        }

        self.check_connection_limit(&user, platform, client_ip).await?;

        let session_token =
            self.sign_token(&user, platform, true, Some(email), issued_at_ms, auth_time)?;

        tracing::info!("User {email} authenticated via SSO from {client_ip}");

        Ok(AuthOk {
            user_id: user.id,
            username: user.username,
            session_token,
            sso: true,
            email: Some(email.to_string()),
            issued_at_ms,
            auth_time,
        })
    }

    /// Authenticate a reconnect with a previously-issued session JWT
    /// (`authType: "session"`). Validates the HS256 signature and expiry,
    /// re-checks everything a fresh login would (and that the token has not
    /// been revoked or outlived its absolute lifetime), then mints a fresh
    /// token that keeps the original login time.
    pub async fn authenticate_session_token(
        &self,
        token: &str,
        platform: ClientPlatform,
        client_ip: IpAddr,
    ) -> AuthResult {
        let issued_at_ms = now_ms();

        let validation = Validation::new(Algorithm::HS256);
        let data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.jwt_secret.as_bytes()),
            &validation,
        );
        let claims = match data {
            Ok(data) => data.claims,
            Err(e) => {
                self.log_event(
                    None,
                    "auth_fail",
                    platform,
                    client_ip,
                    Some(&format!("Invalid session token: {e}")),
                )
                .await;
                return Err(INVALID_SESSION_TOKEN.to_string());
            }
        };

        let Ok(user_id) = Uuid::parse_str(&claims.user_id) else {
            self.log_event(
                None,
                "auth_fail",
                platform,
                client_ip,
                Some("Session token has malformed user_id"),
            )
            .await;
            return Err(INVALID_SESSION_TOKEN.to_string());
        };

        let times = self.token_times(&claims);
        let reject = |details: &'static str| (details, INVALID_SESSION_TOKEN.to_string());

        // Checks that need nothing but the token itself.
        let token_problem = if !claims.sso && !self.password_auth {
            // A token from a password login is a password credential.
            Some(reject("Password-login session token while VPN_PASSWORD_AUTH is off"))
        } else if issued_at_ms / 1000 > times.auth_time.saturating_add(self.max_lifetime_secs()) {
            Some(reject("Session token is past its absolute lifetime — a new login is required"))
        } else {
            None
        };
        if let Some((details, message)) = token_problem {
            self.log_event(Some(user_id), "auth_fail", platform, client_ip, Some(details))
                .await;
            return Err(message);
        }

        let user = self
            .users
            .by_id(user_id)
            .await
            .map_err(|_| "Internal server error".to_string())?;

        let Some(user) = user else {
            self.log_event(
                None,
                "auth_fail",
                platform,
                client_ip,
                Some("Session token user not found"),
            )
            .await;
            return Err(INVALID_SESSION_TOKEN.to_string());
        };

        if !user.is_active {
            self.log_event(
                Some(user_id),
                "auth_fail",
                platform,
                client_ip,
                Some("Account disabled (session token)"),
            )
            .await;
            return Err("Account is disabled".to_string());
        }

        if revoked(&user, times.issued_at_ms) {
            self.log_event(
                Some(user_id),
                "auth_fail",
                platform,
                client_ip,
                Some("Session token was revoked (issued before tokens_valid_after)"),
            )
            .await;
            return Err(INVALID_SESSION_TOKEN.to_string());
        }

        let mut email = None;
        if claims.sso {
            // Same gates as a fresh SSO login: the allowlist as it is *now*,
            // and gatehouse's view of the account.
            let address = claims
                .email
                .clone()
                .unwrap_or_else(|| user.sso_email().to_string())
                .to_lowercase();
            if !self.sso_email_allowed(&address) {
                self.log_event(
                    Some(user_id),
                    "auth_fail",
                    platform,
                    client_ip,
                    Some(&format!("SSO email no longer in allowlist: {address} (session token)")),
                )
                .await;
                return Err("This account is not allowed on this VPN".to_string());
            }
            self.check_gatehouse(&address, times.auth_time, Some(user_id), platform, client_ip)
                .await?;
            email = Some(address);
        }

        self.check_connection_limit(&user, platform, client_ip).await?;

        // Preserve the SSO marker and the original login time across
        // reconnects: only a real login starts a new lifetime.
        let session_token = self.sign_token(
            &user,
            platform,
            claims.sso,
            email.as_deref(),
            issued_at_ms,
            times.auth_time,
        )?;

        tracing::info!(
            "User {} re-authenticated via session token from {client_ip}",
            user.username
        );

        Ok(AuthOk {
            user_id,
            username: user.username,
            session_token,
            sso: claims.sso,
            email,
            issued_at_ms,
            auth_time: times.auth_time,
        })
    }

    /// When a token was issued and when its user really logged in. Tokens
    /// from before these claims existed carry neither: such a token was minted
    /// one TTL before it expires, and that is also the best available answer
    /// for the login time — which makes it renewable until its own `exp`, so
    /// nobody is logged out by the upgrade.
    fn token_times(&self, claims: &Claims) -> TokenTimes {
        let issued_at_ms = claims
            .iat_ms
            .or(claims.iat.map(|iat| iat.saturating_mul(1000)))
            .unwrap_or_else(|| {
                (claims.exp as i64)
                    .saturating_sub(self.token_ttl_secs(claims.sso))
                    .saturating_mul(1000)
            });
        TokenTimes {
            issued_at_ms,
            auth_time: claims.auth_time.unwrap_or(issued_at_ms / 1000),
        }
    }

    fn sso_email_allowed(&self, email: &str) -> bool {
        email_allowed(email, &self.sso_allowed.read().unwrap())
    }

    /// Ask gatehouse whether an SSO session of `email` that logged in at
    /// `auth_time` may exist. A refusal is logged and, when the account is
    /// deactivated there, also revokes the user here.
    async fn check_gatehouse(
        &self,
        email: &str,
        auth_time: i64,
        user_id: Option<Uuid>,
        platform: ClientPlatform,
        client_ip: IpAddr,
    ) -> Result<(), String> {
        let (details, message) = match self.gatehouse.check(email, auth_time).await {
            Verdict::Allow => return Ok(()),
            Verdict::Inactive => {
                if let Some(user_id) = user_id {
                    self.revoke_user(user_id, "account deactivated in gatehouse").await;
                }
                ("Account inactive or unknown in gatehouse", "Account is disabled")
            }
            Verdict::Revoked => (
                "Login predates gatehouse revoked_before",
                "Your session was ended — sign in again",
            ),
        };
        self.log_event(user_id, "auth_fail", platform, client_ip, Some(details))
            .await;
        Err(message.to_string())
    }

    /// Void every session token of a user and close their live tunnels.
    /// Returns the sessions that were closed, or `None` if there is no such
    /// user (or the database could not be written — nothing is closed then,
    /// since the client would simply reconnect with its still-valid token).
    pub async fn revoke_user(&self, user_id: Uuid, reason: &str) -> Option<Vec<Arc<SessionInfo>>> {
        // Millisecond precision on both sides of the comparison.
        let at = DateTime::<Utc>::from_timestamp_millis(now_ms()).unwrap_or_else(Utc::now);
        match self.users.revoke_tokens(user_id, at).await {
            Ok(true) => Some(self.sessions.kill_user(user_id, reason)),
            Ok(false) | Err(StoreError) => None,
        }
    }

    /// Re-check every live tunnel and close the ones that should no longer
    /// exist. Runs periodically: a tunnel that never reconnects would
    /// otherwise never meet any of the checks made at authentication.
    ///
    /// Closed when: the user is gone or deactivated; the session predates
    /// `tokens_valid_after` (this also catches a login that was in flight
    /// while the user was being revoked); the login is older than the absolute
    /// lifetime; or, for SSO users, gatehouse says the account is inactive or
    /// the login predates its `revoked_before`. If the database cannot be
    /// read the session is left alone. Returns how many were closed.
    pub async fn revalidate_sessions(&self) -> usize {
        let now = Utc::now().timestamp();
        let mut users: HashMap<Uuid, Result<Option<UserRecord>, StoreError>> = HashMap::new();
        let mut closed = 0;

        for (id, info) in self.sessions.snapshot() {
            if !users.contains_key(&info.user_id) {
                users.insert(info.user_id, self.users.by_id(info.user_id).await);
            }
            let local = match &users[&info.user_id] {
                Err(StoreError) => None,
                Ok(None) => Some("user was deleted"),
                Ok(Some(user)) if !user.is_active => Some("account was deactivated"),
                Ok(Some(user)) if revoked(user, info.issued_at_ms) => Some("session was revoked"),
                Ok(Some(_)) if now > info.auth_time.saturating_add(self.max_lifetime_secs()) => {
                    Some("login is older than the session lifetime")
                }
                Ok(Some(_)) => None,
            };

            let reason = match (local, info.sso, info.email.as_deref()) {
                (Some(reason), _, _) => Some(reason),
                (None, true, Some(email)) => match self.gatehouse.check(email, info.auth_time).await {
                    Verdict::Allow => None,
                    Verdict::Inactive => {
                        // Also voids the tokens, so the client cannot simply
                        // reconnect while the cached answer is being refreshed.
                        self.revoke_user(info.user_id, "account deactivated in gatehouse").await;
                        Some("account deactivated in gatehouse")
                    }
                    Verdict::Revoked => Some("session ended in gatehouse"),
                },
                (None, _, _) => None,
            };

            if let Some(reason) = reason {
                // `false` when something else closed it in the meantime.
                let was_live = self.sessions.kill(id, reason);
                if was_live || reason == "account deactivated in gatehouse" {
                    closed += 1;
                    tracing::info!(
                        "Session {id} of {} closed by revalidation: {reason}",
                        info.username
                    );
                }
            }
        }
        closed
    }

    #[cfg(test)]
    pub fn dummy_verifications(&self) -> u64 {
        self.dummy_verifications.load(Ordering::Relaxed)
    }

    /// Mint a session token with chosen instants, as an earlier login or
    /// renewal would have.
    #[cfg(test)]
    pub fn token_for_test(
        &self,
        user: &UserRecord,
        sso: bool,
        issued_at_ms: i64,
        auth_time: i64,
    ) -> String {
        let email = sso.then(|| user.sso_email().to_string());
        self.sign_token(
            user,
            ClientPlatform::Macos,
            sso,
            email.as_deref(),
            issued_at_ms,
            auth_time,
        )
        .unwrap()
    }

    /// Record an `auth_fail` connection-log entry for failures that happen
    /// before a user is identified (e.g. SSO id_token verification).
    pub async fn log_auth_failure(
        &self,
        platform: ClientPlatform,
        client_ip: IpAddr,
        details: &str,
    ) {
        self.log_event(None, "auth_fail", platform, client_ip, Some(details))
            .await;
    }

    /// Enforce the per-user concurrent connection limit.
    async fn check_connection_limit(
        &self,
        user: &UserRecord,
        platform: ClientPlatform,
        client_ip: IpAddr,
    ) -> Result<(), String> {
        let current_sessions = self
            .users
            .session_count(user.id)
            .await
            .map_err(|_| "Internal server error".to_string())?;

        if current_sessions >= user.max_connections as i64 {
            self.log_event(
                Some(user.id),
                "auth_fail",
                platform,
                client_ip,
                Some("Max connections reached"),
            )
            .await;
            return Err("Maximum connections reached".to_string());
        }
        Ok(())
    }

    fn sign_token(
        &self,
        user: &UserRecord,
        platform: ClientPlatform,
        sso: bool,
        email: Option<&str>,
        issued_at_ms: i64,
        auth_time: i64,
    ) -> Result<String, String> {
        // Password logins keep the original 24h expiry (`expiresIn: '24h'`);
        // SSO logins get a longer-lived token (SSO_SESSION_TTL_DAYS). Either
        // way the token never outlives the absolute lifetime of its login.
        let issued_at = issued_at_ms / 1000;
        let exp = issued_at
            .saturating_add(self.token_ttl_secs(sso))
            .min(auth_time.saturating_add(self.max_lifetime_secs()));
        let claims = Claims {
            user_id: user.id.to_string(),
            username: user.username.clone(),
            platform: platform.as_str().to_string(),
            exp: exp.max(0) as usize,
            sso,
            iat: Some(issued_at),
            iat_ms: Some(issued_at_ms),
            auth_time: Some(auth_time),
            email: email.map(str::to_string),
        };
        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.jwt_secret.as_bytes()),
        )
        .map_err(|_| "Internal server error".to_string())
    }

    /// Insert a row into `sessions` and log the connect event. Returns the new
    /// session id.
    pub async fn create_session(
        &self,
        user_id: Uuid,
        assigned_ip: &str,
        platform: ClientPlatform,
        client_ip: IpAddr,
        client_version: &str,
    ) -> anyhow::Result<Uuid> {
        let session_id = Uuid::new_v4();
        let client = self.db.get().await?;
        client
            .execute(
                "INSERT INTO sessions \
                 (id, user_id, assigned_ip, client_ip, client_platform, client_version) \
                 VALUES ($1, $2, $3, $4, $5, $6)",
                &[
                    &session_id,
                    &user_id,
                    &assigned_ip,
                    &client_ip.to_string(),
                    &platform.as_str(),
                    &client_version,
                ],
            )
            .await?;

        self.log_event(Some(user_id), "connect", platform, client_ip, None)
            .await;
        Ok(session_id)
    }

    pub async fn update_session_activity(&self, session_id: Uuid) {
        if let Ok(client) = self.db.get().await {
            let _ = client
                .execute(
                    "UPDATE sessions SET last_activity = CURRENT_TIMESTAMP WHERE id = $1",
                    &[&session_id],
                )
                .await;
        }
    }

    pub async fn update_session_stats(&self, session_id: Uuid, bytes_sent: i64, bytes_received: i64) {
        if let Ok(client) = self.db.get().await {
            let _ = client
                .execute(
                    "UPDATE sessions SET bytes_sent = bytes_sent + $2, \
                     bytes_received = bytes_received + $3, last_activity = CURRENT_TIMESTAMP \
                     WHERE id = $1",
                    &[&session_id, &bytes_sent, &bytes_received],
                )
                .await;
        }
    }

    pub async fn end_session(&self, session_id: Uuid) {
        let Ok(client) = self.db.get().await else {
            return;
        };

        if let Ok(Some(row)) = client
            .query_opt(
                "SELECT user_id, client_platform, client_ip FROM sessions WHERE id = $1",
                &[&session_id],
            )
            .await
        {
            let user_id: Uuid = row.get("user_id");
            let platform: String = row.get("client_platform");
            let client_ip: Option<String> = row.get("client_ip");
            self.log_event_raw(Some(user_id), "disconnect", &platform, client_ip.as_deref(), None)
                .await;
        }

        let _ = client
            .execute("DELETE FROM sessions WHERE id = $1", &[&session_id])
            .await;
    }

    /// Delete sessions with no activity in the last `max_idle_minutes`.
    pub async fn cleanup_stale_sessions(&self, max_idle_minutes: i64) -> i64 {
        let Ok(client) = self.db.get().await else {
            return 0;
        };
        let query = format!(
            "DELETE FROM sessions \
             WHERE last_activity < CURRENT_TIMESTAMP - INTERVAL '{max_idle_minutes} minutes'"
        );
        client.execute(query.as_str(), &[]).await.unwrap_or(0) as i64
    }

    /// Delete `connection_logs` rows older than `retention_days`. Returns the
    /// number of rows removed.
    pub async fn cleanup_old_connection_logs(&self, retention_days: u32) -> u64 {
        let Ok(client) = self.db.get().await else {
            return 0;
        };
        let query = format!(
            "DELETE FROM connection_logs \
             WHERE created_at < CURRENT_TIMESTAMP - INTERVAL '{retention_days} days'"
        );
        match client.execute(query.as_str(), &[]).await {
            Ok(deleted) => deleted,
            Err(e) => {
                tracing::warn!("connection_logs retention cleanup failed: {e}");
                0
            }
        }
    }

    async fn log_event(
        &self,
        user_id: Option<Uuid>,
        event_type: &str,
        platform: ClientPlatform,
        client_ip: IpAddr,
        details: Option<&str>,
    ) {
        // Failed logins are attacker-triggered, so the rows one source can add
        // are capped per minute. Skipped failures are counted and reported on
        // the first row of that source's next window.
        let mut annotated = None;
        if event_type == "auth_fail" {
            match self.auth_fail_log.check(client_ip) {
                LogDecision::Skip => return,
                LogDecision::Write { suppressed: 0 } => {}
                LogDecision::Write { suppressed } => {
                    annotated = Some(format!(
                        "{} (+{suppressed} earlier failures from this address not logged)",
                        details.unwrap_or("auth_fail")
                    ));
                }
            }
        }
        self.log_event_raw(
            user_id,
            event_type,
            platform.as_str(),
            Some(&client_ip.to_string()),
            annotated.as_deref().or(details),
        )
        .await;
    }

    async fn log_event_raw(
        &self,
        user_id: Option<Uuid>,
        event_type: &str,
        platform: &str,
        client_ip: Option<&str>,
        details: Option<&str>,
    ) {
        if let Ok(client) = self.db.get().await {
            let _ = client
                .execute(
                    "INSERT INTO connection_logs \
                     (user_id, event_type, client_platform, client_ip, details) \
                     VALUES ($1, $2, $3, $4, $5)",
                    &[&user_id, &event_type, &platform, &client_ip, &details],
                )
                .await;
        }
    }
}

/// Was a credential issued at `issued_at_ms` voided by the user's
/// `tokens_valid_after`? One issued in the very millisecond of the revocation
/// counts as issued before it: the order within a millisecond is unknowable,
/// and erring this way costs at most one extra sign-in.
fn revoked(user: &UserRecord, issued_at_ms: i64) -> bool {
    user.tokens_valid_after
        .is_some_and(|valid_after| issued_at_ms <= valid_after.timestamp_millis())
}

#[cfg(test)]
mod tests {
    use super::email_allowed;

    fn list(entries: &[&str]) -> Vec<String> {
        entries.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn empty_allowlist_allows_everything() {
        assert!(email_allowed("anyone@anywhere.com", &[]));
    }

    #[test]
    fn domain_entry_matches_domain_only() {
        let allowed = list(&["datasee.co.kr"]);
        assert!(email_allowed("kim@datasee.co.kr", &allowed));
        assert!(email_allowed("KIM@DATASEE.CO.KR", &allowed));
        assert!(!email_allowed("kim@gmail.com", &allowed));
        // Domain must match exactly, not as a suffix.
        assert!(!email_allowed("kim@evil-datasee.co.kr", &allowed));
    }

    #[test]
    fn at_prefixed_domain_entry_matches() {
        let allowed = list(&["@datasee.co.kr"]);
        assert!(email_allowed("lee@datasee.co.kr", &allowed));
        assert!(!email_allowed("lee@other.com", &allowed));
    }

    #[test]
    fn full_email_entry_matches_exactly() {
        let allowed = list(&["contractor@gmail.com", "datasee.co.kr"]);
        assert!(email_allowed("contractor@gmail.com", &allowed));
        assert!(!email_allowed("other@gmail.com", &allowed));
        assert!(email_allowed("kim@datasee.co.kr", &allowed));
    }

    #[test]
    fn tricky_emails_do_not_bypass() {
        let allowed = list(&["datasee.co.kr"]);
        // rsplit('@') takes the text after the LAST @, so a crafted local part
        // cannot smuggle an allowed domain.
        assert!(!email_allowed("kim@datasee.co.kr@evil.com", &allowed));
        assert!(!email_allowed("datasee.co.kr", &allowed)); // no @ at all
    }
}

#[cfg(test)]
pub mod testing {
    //! An in-memory [`UserStore`] and an [`AuthService`] built on it, so the
    //! authentication rules run in tests without PostgreSQL.

    use super::*;
    use std::sync::Mutex;

    pub const SECRET: &str = "test-secret";

    #[derive(Default)]
    pub struct MemUserStore {
        pub users: Mutex<Vec<UserRecord>>,
    }

    impl MemUserStore {
        pub fn add(&self, username: &str, password: Option<&str>) -> UserRecord {
            let user = UserRecord {
                id: Uuid::new_v4(),
                username: username.to_string(),
                email: password.is_none().then(|| username.to_string()),
                password_hash: match password {
                    Some(password) => bcrypt::hash(password, 4).unwrap(),
                    None => SSO_PASSWORD_HASH.to_string(),
                },
                is_active: true,
                max_connections: 3,
                tokens_valid_after: None,
            };
            self.users.lock().unwrap().push(user.clone());
            user
        }

        pub fn update(&self, id: Uuid, change: impl FnOnce(&mut UserRecord)) {
            let mut users = self.users.lock().unwrap();
            change(users.iter_mut().find(|u| u.id == id).expect("no such user"));
        }

        pub fn get(&self, id: Uuid) -> Option<UserRecord> {
            self.users.lock().unwrap().iter().find(|u| u.id == id).cloned()
        }

        pub fn remove(&self, id: Uuid) {
            self.users.lock().unwrap().retain(|u| u.id != id);
        }
    }

    impl UserStore for MemUserStore {
        fn by_username<'a>(
            &'a self,
            username: &'a str,
        ) -> BoxFuture<'a, Result<Option<UserRecord>, StoreError>> {
            let found = self
                .users
                .lock()
                .unwrap()
                .iter()
                .find(|u| u.username == username)
                .cloned();
            Box::pin(async move { Ok(found) })
        }

        fn by_id(&self, id: Uuid) -> BoxFuture<'_, Result<Option<UserRecord>, StoreError>> {
            let found = self.get(id);
            Box::pin(async move { Ok(found) })
        }

        fn by_email<'a>(
            &'a self,
            email: &'a str,
        ) -> BoxFuture<'a, Result<Option<UserRecord>, StoreError>> {
            let found = self
                .users
                .lock()
                .unwrap()
                .iter()
                .find(|u| u.sso_email().to_lowercase() == email)
                .cloned();
            Box::pin(async move { Ok(found) })
        }

        fn create_sso_user<'a>(
            &'a self,
            email: &'a str,
        ) -> BoxFuture<'a, Result<UserRecord, StoreError>> {
            let user = self.add(email, None);
            Box::pin(async move { Ok(user) })
        }

        fn session_count(&self, _user_id: Uuid) -> BoxFuture<'_, Result<i64, StoreError>> {
            Box::pin(async { Ok(0) })
        }

        fn revoke_tokens(
            &self,
            user_id: Uuid,
            at: DateTime<Utc>,
        ) -> BoxFuture<'_, Result<bool, StoreError>> {
            let mut users = self.users.lock().unwrap();
            let found = users.iter_mut().find(|u| u.id == user_id).map(|user| {
                user.tokens_valid_after = Some(at);
            });
            Box::pin(async move { Ok(found.is_some()) })
        }
    }

    /// A pool that is never connected: deadpool only dials on `get()`, and
    /// the dial is refused at once. Session rows and connection logs are
    /// therefore silently skipped, as they are when the database is down.
    pub fn dead_pool() -> DbPool {
        let mut pg = deadpool_postgres::Config::new();
        pg.host = Some("127.0.0.1".into());
        pg.port = Some(1);
        pg.dbname = Some("unused".into());
        pg.user = Some("unused".into());
        pg.create_pool(Some(deadpool_postgres::Runtime::Tokio1), tokio_postgres::NoTls)
            .unwrap()
    }

    pub fn settings() -> AuthSettings {
        AuthSettings {
            jwt_secret: SECRET.into(),
            sso_session_ttl_days: 30,
            max_lifetime_days: 30,
            sso_allowed: Vec::new(),
            password_auth: true,
            auth_fail_log_per_min: 10,
        }
    }

    pub fn service(
        users: Arc<MemUserStore>,
        sessions: Arc<SessionManager>,
        gatehouse: Arc<GatehouseStatus>,
        settings: AuthSettings,
    ) -> AuthService {
        AuthService::new(dead_pool(), users, sessions, gatehouse, settings)
    }
}

#[cfg(test)]
mod revocation_tests {
    use super::testing::*;
    use super::*;
    use crate::gatehouse::testing::{FakeFetcher, ACTIVE, INACTIVE};
    use crate::gatehouse::AccountStatus;
    use crate::session::manager::{KillSwitch, SessionHandle};

    const DAY: i64 = 24 * 60 * 60;
    const EMAIL: &str = "kim@datasee.co.kr";

    fn ip() -> IpAddr {
        "203.0.113.9".parse().unwrap()
    }

    struct Fixture {
        users: Arc<MemUserStore>,
        sessions: Arc<SessionManager>,
        fetcher: Arc<FakeFetcher>,
        gatehouse: Arc<GatehouseStatus>,
        auth: AuthService,
    }

    /// `with_gatehouse = false` leaves status lookups disabled, as when the
    /// env vars are unset.
    fn fixture_with(with_gatehouse: bool, settings: AuthSettings) -> Fixture {
        let users = Arc::new(MemUserStore::default());
        let sessions = Arc::new(SessionManager::new());
        let fetcher = FakeFetcher::new();
        let gatehouse = Arc::new(if with_gatehouse {
            GatehouseStatus::with_fetcher(fetcher.clone())
        } else {
            GatehouseStatus::disabled()
        });
        let auth = service(users.clone(), sessions.clone(), gatehouse.clone(), settings);
        Fixture {
            users,
            sessions,
            fetcher,
            gatehouse,
            auth,
        }
    }

    fn fixture() -> Fixture {
        fixture_with(false, settings())
    }

    fn now() -> i64 {
        Utc::now().timestamp()
    }

    fn claims_of(token: &str) -> Claims {
        decode::<Claims>(
            token,
            &DecodingKey::from_secret(SECRET.as_bytes()),
            &Validation::new(Algorithm::HS256),
        )
        .unwrap()
        .claims
    }

    /// A token exactly as the currently deployed server mints them: no `iat`,
    /// no `auth_time`, no `email`.
    fn legacy_token(user: &UserRecord, sso: bool, exp: i64) -> String {
        encode(
            &Header::default(),
            &serde_json::json!({
                "user_id": user.id.to_string(),
                "username": user.username,
                "platform": "macos",
                "exp": exp,
                "sso": sso,
            }),
            &EncodingKey::from_secret(SECRET.as_bytes()),
        )
        .unwrap()
    }

    async fn renew(f: &Fixture, token: &str) -> AuthResult {
        f.auth
            .authenticate_session_token(token, ClientPlatform::Macos, ip())
            .await
    }

    /// Put a live tunnel for `user` into the session manager.
    fn open_tunnel(f: &Fixture, user: &UserRecord, sso: bool, issued_at_ms: i64, auth_time: i64) -> (Uuid, Arc<KillSwitch>) {
        let id = Uuid::new_v4();
        let kill = Arc::new(KillSwitch::default());
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let n = f.sessions.active_count() as u8;
        f.sessions.register(SessionHandle {
            id,
            assigned_ip: std::net::Ipv4Addr::new(10, 8, 0, 2 + n),
            tx,
            bytes_sent: Default::default(),
            bytes_received: Default::default(),
            info: Arc::new(SessionInfo {
                user_id: user.id,
                username: user.username.clone(),
                db_id: None,
                sso,
                email: sso.then(|| user.sso_email().to_string()),
                issued_at_ms,
                auth_time,
            }),
            kill: kill.clone(),
        });
        (id, kill)
    }

    async fn was_killed(kill: &KillSwitch) -> Option<String> {
        tokio::time::timeout(std::time::Duration::from_millis(50), kill.triggered())
            .await
            .ok()
    }

    // ---- 2. the session-token chain ------------------------------------

    #[tokio::test]
    async fn renewal_keeps_the_original_login_time() {
        let f = fixture();
        let user = f.users.add(EMAIL, None);
        let login = now() - 10 * DAY;
        let token = f.auth.token_for_test(&user, true, (login + DAY) * 1000, login);

        let ok = renew(&f, &token).await.unwrap();
        assert_eq!(ok.auth_time, login);
        assert!(ok.sso);

        let fresh = claims_of(&ok.session_token);
        assert_eq!(fresh.auth_time, Some(login));
        assert!(fresh.iat.unwrap() >= now() - 5);
        assert_eq!(fresh.email.as_deref(), Some(EMAIL));
        // 30-day TTL, but capped at login + 30 days: 20 days are left.
        assert_eq!(fresh.exp as i64, login + 30 * DAY);

        // Renewing the renewed token does not move the login time either.
        let again = renew(&f, &ok.session_token).await.unwrap();
        assert_eq!(claims_of(&again.session_token).auth_time, Some(login));
    }

    #[tokio::test]
    async fn renewal_is_refused_past_the_absolute_lifetime() {
        // The token itself is still unexpired (a longer TTL than lifetime, as
        // after the operator shortens SSO_SESSION_MAX_LIFETIME_DAYS): only the
        // absolute lifetime stands between it and another renewal.
        let mut settings = settings();
        settings.max_lifetime_days = 7;
        let f = fixture_with(false, settings);
        let user = f.users.add(EMAIL, None);

        let recent = now() - 6 * DAY;
        let token = legacy_like(&f, &user, recent);
        assert!(renew(&f, &token).await.is_ok());

        let too_old = now() - 7 * DAY - 60;
        let token = legacy_like(&f, &user, too_old);
        assert_eq!(renew(&f, &token).await.unwrap_err(), INVALID_SESSION_TOKEN);
    }

    /// An unexpired token (exp well in the future) whose login was at
    /// `auth_time`, written out claim by claim.
    fn legacy_like(_f: &Fixture, user: &UserRecord, auth_time: i64) -> String {
        encode(
            &Header::default(),
            &Claims {
                user_id: user.id.to_string(),
                username: user.username.clone(),
                platform: "macos".into(),
                exp: (now() + 20 * DAY) as usize,
                sso: true,
                iat: Some(now() - 60),
                iat_ms: Some((now() - 60) * 1000),
                auth_time: Some(auth_time),
                email: Some(EMAIL.into()),
            },
            &EncodingKey::from_secret(SECRET.as_bytes()),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn a_token_cannot_be_renewed_forever() {
        // Follow the chain: every renewal succeeds while the login is recent,
        // and every token it yields expires at login + lifetime at the latest.
        let f = fixture();
        let user = f.users.add(EMAIL, None);
        let login = now() - 29 * DAY;
        let mut token = f.auth.token_for_test(&user, true, login * 1000, login);
        for _ in 0..5 {
            let ok = renew(&f, &token).await.unwrap();
            assert_eq!(claims_of(&ok.session_token).exp as i64, login + 30 * DAY);
            token = ok.session_token;
        }
    }

    #[tokio::test]
    async fn tokens_issued_before_tokens_valid_after_are_refused() {
        let f = fixture();
        let user = f.users.add(EMAIL, None);
        let login = now() - DAY;
        let before = f.auth.token_for_test(&user, true, (now() - 3600) * 1000, login);

        assert!(renew(&f, &before).await.is_ok());

        // "모든 기기에서 로그아웃" half an hour ago.
        let revoked_at = Utc::now() - chrono::Duration::minutes(30);
        f.users.update(user.id, |u| u.tokens_valid_after = Some(revoked_at));
        assert_eq!(renew(&f, &before).await.unwrap_err(), INVALID_SESSION_TOKEN);

        // A token from a login after the revocation works.
        let after = f.auth.token_for_test(&user, true, (now() - 60) * 1000, now() - 60);
        assert!(renew(&f, &after).await.is_ok());
    }

    #[tokio::test]
    async fn revoke_user_voids_tokens_and_closes_every_tunnel_of_that_user_only() {
        let f = fixture();
        let user = f.users.add(EMAIL, None);
        let other = f.users.add("lee@datasee.co.kr", None);
        let issued = now_ms() - 5_000;
        let token = f.auth.token_for_test(&user, true, issued, issued / 1000);
        let other_token = f.auth.token_for_test(&other, true, issued, issued / 1000);
        let (_, laptop) = open_tunnel(&f, &user, true, issued, issued / 1000);
        let (_, phone) = open_tunnel(&f, &user, true, issued, issued / 1000);
        let (_, bystander) = open_tunnel(&f, &other, true, issued, issued / 1000);

        let closed = f.auth.revoke_user(user.id, "test").await.unwrap();
        assert_eq!(closed.len(), 2);
        assert_eq!(was_killed(&laptop).await.as_deref(), Some("test"));
        assert!(was_killed(&phone).await.is_some());
        assert!(was_killed(&bystander).await.is_none());
        assert_eq!(f.sessions.active_count(), 1);

        assert_eq!(renew(&f, &token).await.unwrap_err(), INVALID_SESSION_TOKEN);
        assert!(renew(&f, &other_token).await.is_ok());

        // Unknown user: nothing to revoke.
        assert!(f.auth.revoke_user(Uuid::new_v4(), "test").await.is_none());
    }

    #[tokio::test]
    async fn tokens_from_the_deployed_server_keep_working_until_their_own_expiry() {
        let f = fixture();
        let user = f.users.add(EMAIL, None);

        // Minted 12 days ago by the old server: exp = then + 30 days, and
        // nothing else to go on.
        let minted = now() - 12 * DAY;
        let token = legacy_token(&user, true, minted + 30 * DAY);
        let ok = renew(&f, &token).await.expect("legacy token must still be accepted");
        assert!(ok.sso);
        // Missing auth_time is read as the token's own issue time...
        assert_eq!(ok.auth_time, minted);
        let fresh = claims_of(&ok.session_token);
        assert_eq!(fresh.auth_time, Some(minted));
        // ...so the chain now ends where that token would have expired.
        assert_eq!(fresh.exp as i64, minted + 30 * DAY);

        // Even one minted 29 days ago is still let in (it has a day left).
        let old = legacy_token(&user, true, now() + DAY);
        assert!(renew(&f, &old).await.is_ok());

        // A legacy password-login token (24h) likewise.
        let pw_user = f.users.add("legacy-pw", Some("correct horse"));
        let pw = legacy_token(&pw_user, false, now() + 3600);
        let ok = renew(&f, &pw).await.unwrap();
        assert!(!ok.sso);
        assert_eq!(ok.auth_time, now() + 3600 - DAY);
    }

    #[tokio::test]
    async fn legacy_tokens_are_revocable_too() {
        let f = fixture();
        let user = f.users.add(EMAIL, None);
        let token = legacy_token(&user, true, now() - 12 * DAY + 30 * DAY);
        f.users.update(user.id, |u| u.tokens_valid_after = Some(Utc::now()));
        assert_eq!(renew(&f, &token).await.unwrap_err(), INVALID_SESSION_TOKEN);
    }

    #[tokio::test]
    async fn renewal_rechecks_the_account_and_the_allowlist() {
        let f = fixture();
        let user = f.users.add(EMAIL, None);
        let token = f.auth.token_for_test(&user, true, now_ms() - 1000, now() - 1);
        assert!(renew(&f, &token).await.is_ok());

        // The allowlist as it is now, not as it was at login.
        f.auth.set_sso_allowed(vec!["other.example".into()]);
        assert_eq!(
            renew(&f, &token).await.unwrap_err(),
            "This account is not allowed on this VPN"
        );
        f.auth.set_sso_allowed(vec!["datasee.co.kr".into()]);
        assert!(renew(&f, &token).await.is_ok());

        // Legacy tokens carry no email; the user's row supplies it.
        let legacy = legacy_token(&user, true, now() + 10 * DAY);
        assert!(renew(&f, &legacy).await.is_ok());
        f.auth.set_sso_allowed(vec!["other.example".into()]);
        assert!(renew(&f, &legacy).await.is_err());
        f.auth.set_sso_allowed(Vec::new());

        f.users.update(user.id, |u| u.is_active = false);
        assert_eq!(renew(&f, &token).await.unwrap_err(), "Account is disabled");

        f.users.remove(user.id);
        assert_eq!(renew(&f, &token).await.unwrap_err(), INVALID_SESSION_TOKEN);
    }

    // ---- 3. gatehouse ---------------------------------------------------

    #[tokio::test]
    async fn gatehouse_inactive_refuses_login_and_renewal_and_revokes_locally() {
        let f = fixture_with(true, settings());
        let user = f.users.add(EMAIL, None);
        let token = f.auth.token_for_test(&user, true, now_ms() - 1000, now() - 1);
        let (_, tunnel) = open_tunnel(&f, &user, true, now_ms() - 1000, now() - 1);

        f.fetcher.set(EMAIL, Ok(ACTIVE));
        assert!(renew(&f, &token).await.is_ok());

        // Deactivated in gatehouse (and the 60s cache has run out).
        f.fetcher.set(EMAIL, Ok(INACTIVE));
        f.gatehouse.expire_cache();
        assert_eq!(renew(&f, &token).await.unwrap_err(), "Account is disabled");
        // The local tokens are voided and the open tunnel is closed.
        assert!(f.users.get(user.id).unwrap().tokens_valid_after.is_some());
        assert!(was_killed(&tunnel).await.is_some());

        // A fresh SSO login is refused as well.
        let login = f
            .auth
            .authenticate_sso(EMAIL, None, now(), ClientPlatform::Macos, ip())
            .await;
        assert_eq!(login.unwrap_err(), "Account is disabled");
    }

    #[tokio::test]
    async fn gatehouse_unknown_account_is_not_provisioned() {
        let f = fixture_with(true, settings());
        f.fetcher.set("stranger@datasee.co.kr", Ok(INACTIVE));
        let login = f
            .auth
            .authenticate_sso("stranger@datasee.co.kr", None, now(), ClientPlatform::Macos, ip())
            .await;
        assert!(login.is_err());
        assert!(f.users.users.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn gatehouse_revoked_before_refuses_older_logins_only() {
        let f = fixture_with(true, settings());
        let user = f.users.add(EMAIL, None);
        let ended = now() - 600;
        f.fetcher.set(
            EMAIL,
            Ok(AccountStatus {
                active: true,
                revoked_before_ms: Some(ended * 1000),
            }),
        );

        // Logged in an hour ago, renewed a minute ago: the *login* is what
        // counts, so the recent renewal does not save it.
        let stale = f.auth.token_for_test(&user, true, (now() - 60) * 1000, now() - 3600);
        assert_eq!(
            renew(&f, &stale).await.unwrap_err(),
            "Your session was ended — sign in again"
        );
        // The account itself is fine: no local revocation.
        assert!(f.users.get(user.id).unwrap().tokens_valid_after.is_none());

        // Signed in again after the sessions were ended.
        let fresh = f.auth.token_for_test(&user, true, (now() - 60) * 1000, now() - 60);
        assert!(renew(&f, &fresh).await.is_ok());

        // An id_token issued before the revocation cannot start a session.
        let old_login = f
            .auth
            .authenticate_sso(EMAIL, None, ended - 30, ClientPlatform::Macos, ip())
            .await;
        assert!(old_login.is_err());
        let new_login = f
            .auth
            .authenticate_sso(EMAIL, None, now(), ClientPlatform::Macos, ip())
            .await
            .unwrap();
        assert_eq!(new_login.email.as_deref(), Some(EMAIL));
    }

    #[tokio::test]
    async fn gatehouse_unreachable_uses_the_last_result() {
        let f = fixture_with(true, settings());
        let user = f.users.add(EMAIL, None);
        let token = f.auth.token_for_test(&user, true, now_ms() - 1000, now() - 1);

        // Never answered: fail open.
        f.fetcher.set(EMAIL, Err("connection failed".into()));
        assert!(renew(&f, &token).await.is_ok());

        // Answered "active", then went away: still allowed.
        f.fetcher.set(EMAIL, Ok(ACTIVE));
        f.gatehouse.expire_cache();
        assert!(renew(&f, &token).await.is_ok());
        f.fetcher.set(EMAIL, Err("HTTP 503".into()));
        assert!(renew(&f, &token).await.is_ok());

        // Answered "inactive", then went away: still refused.
        let other = f.users.add("lee@datasee.co.kr", None);
        let other_token = f.auth.token_for_test(&other, true, now_ms() - 1000, now() - 1);
        f.fetcher.set("lee@datasee.co.kr", Ok(INACTIVE));
        f.gatehouse.expire_cache();
        assert!(renew(&f, &other_token).await.is_err());
        f.fetcher.set("lee@datasee.co.kr", Err("timed out".into()));
        assert!(renew(&f, &other_token).await.is_err());
    }

    #[tokio::test]
    async fn gatehouse_is_not_consulted_for_password_users() {
        let f = fixture_with(true, settings());
        f.users.add("svc-account", Some("correct horse"));
        let ok = f
            .auth
            .authenticate("svc-account", "correct horse", ClientPlatform::Macos, ip())
            .await
            .unwrap();
        assert!(renew(&f, &ok.session_token).await.is_ok());
        assert_eq!(f.fetcher.calls(), 0);
    }

    #[tokio::test]
    async fn revalidation_closes_tunnels_gatehouse_no_longer_allows() {
        let f = fixture_with(true, settings());
        let gone = f.users.add(EMAIL, None);
        let ended = f.users.add("lee@datasee.co.kr", None);
        let fine = f.users.add("park@datasee.co.kr", None);
        let login = now() - 3600;

        f.fetcher.set(EMAIL, Ok(INACTIVE));
        f.fetcher.set(
            "lee@datasee.co.kr",
            Ok(AccountStatus {
                active: true,
                revoked_before_ms: Some((now() - 60) * 1000),
            }),
        );
        f.fetcher.set("park@datasee.co.kr", Ok(ACTIVE));

        let (_, gone_tunnel) = open_tunnel(&f, &gone, true, login * 1000, login);
        let (_, ended_tunnel) = open_tunnel(&f, &ended, true, login * 1000, login);
        let (_, fine_tunnel) = open_tunnel(&f, &fine, true, login * 1000, login);

        assert_eq!(f.auth.revalidate_sessions().await, 2);
        assert_eq!(
            was_killed(&gone_tunnel).await.as_deref(),
            Some("account deactivated in gatehouse")
        );
        assert_eq!(
            was_killed(&ended_tunnel).await.as_deref(),
            Some("session ended in gatehouse")
        );
        assert!(was_killed(&fine_tunnel).await.is_none());
        assert_eq!(f.sessions.active_count(), 1);
        assert!(f.users.get(gone.id).unwrap().tokens_valid_after.is_some());
    }

    #[tokio::test]
    async fn revalidation_with_gatehouse_unreachable_goes_by_the_last_result() {
        let f = fixture_with(true, settings());
        let user = f.users.add(EMAIL, None);
        let login = now() - 3600;
        let (_, tunnel) = open_tunnel(&f, &user, true, login * 1000, login);

        // No answer and no earlier answer: the tunnel is left alone.
        f.fetcher.set(EMAIL, Err("timed out".into()));
        assert_eq!(f.auth.revalidate_sessions().await, 0);
        assert!(was_killed(&tunnel).await.is_none());

        // gatehouse answers "inactive" once and is unreachable again by this
        // server's next pass: what it last said still closes the tunnel. (The
        // expired-cache-plus-failure path itself is covered, with a clock, in
        // the gatehouse module's tests.)
        f.fetcher.set(EMAIL, Ok(INACTIVE));
        f.gatehouse.expire_cache();
        assert_eq!(f.gatehouse.check(EMAIL, login).await, Verdict::Inactive);
        f.fetcher.set(EMAIL, Err("timed out".into()));
        assert_eq!(f.auth.revalidate_sessions().await, 1);
        assert!(was_killed(&tunnel).await.is_some());
    }

    #[tokio::test]
    async fn revalidation_closes_tunnels_on_local_account_changes() {
        let f = fixture();
        let disabled = f.users.add("a@datasee.co.kr", None);
        let deleted = f.users.add("b@datasee.co.kr", None);
        let revoked = f.users.add("c@datasee.co.kr", None);
        let fine = f.users.add("pw-user", Some("correct horse"));
        let t = now() - 3600;

        let (_, k1) = open_tunnel(&f, &disabled, true, t * 1000, t);
        let (_, k2) = open_tunnel(&f, &deleted, true, t * 1000, t);
        let (_, k3) = open_tunnel(&f, &revoked, true, t * 1000, t);
        let (_, k5) = open_tunnel(&f, &fine, false, t * 1000, t);

        assert_eq!(f.auth.revalidate_sessions().await, 0);

        f.users.update(disabled.id, |u| u.is_active = false);
        f.users.remove(deleted.id);
        // Revoked *after* this tunnel's login began — the case of a login that
        // was in flight while the admin pressed the button.
        f.users.update(revoked.id, |u| u.tokens_valid_after = Some(Utc::now()));

        assert_eq!(f.auth.revalidate_sessions().await, 3);
        assert_eq!(was_killed(&k1).await.as_deref(), Some("account was deactivated"));
        assert_eq!(was_killed(&k2).await.as_deref(), Some("user was deleted"));
        assert_eq!(was_killed(&k3).await.as_deref(), Some("session was revoked"));
        assert!(was_killed(&k5).await.is_none());
    }

    #[tokio::test]
    async fn revalidation_closes_tunnels_older_than_the_absolute_lifetime() {
        let f = fixture();
        let user = f.users.add(EMAIL, None);
        let (_, old) = open_tunnel(&f, &user, true, now_ms(), now() - 30 * DAY - 60);
        let (_, recent) = open_tunnel(&f, &user, true, now_ms(), now() - 29 * DAY);
        assert_eq!(f.auth.revalidate_sessions().await, 1);
        assert!(was_killed(&old).await.is_some());
        assert!(was_killed(&recent).await.is_none());
    }

    // ---- 6. password authentication ------------------------------------

    #[tokio::test]
    async fn failed_password_logins_are_indistinguishable() {
        let f = fixture();
        f.users.add("alice", Some("correct horse"));
        let disabled = f.users.add("bob", Some("battery staple"));
        f.users.update(disabled.id, |u| u.is_active = false);
        f.users.add(EMAIL, None); // SSO-only: no usable password hash

        let attempt = |username: &'static str, password: &'static str| {
            let auth = &f.auth;
            async move {
                auth.authenticate(username, password, ClientPlatform::Macos, ip())
                    .await
                    .map(|ok| ok.username)
            }
        };

        assert_eq!(attempt("alice", "correct horse").await.unwrap(), "alice");

        let wrong_password = attempt("alice", "nope").await.unwrap_err();
        let no_such_user = attempt("mallory", "nope").await.unwrap_err();
        let disabled_right_password = attempt("bob", "battery staple").await.unwrap_err();
        let disabled_wrong_password = attempt("bob", "nope").await.unwrap_err();
        let sso_only = attempt(EMAIL, "!sso").await.unwrap_err();
        for message in [
            &no_such_user,
            &disabled_right_password,
            &disabled_wrong_password,
            &sso_only,
        ] {
            assert_eq!(message, &wrong_password);
        }
        assert_eq!(wrong_password, "Invalid credentials");
    }

    #[tokio::test]
    async fn unknown_users_still_cost_a_bcrypt_verification() {
        let f = fixture();
        f.users.add("alice", Some("correct horse"));
        f.users.add(EMAIL, None);

        // A real user with a real hash: verified against that hash.
        let _ = f.auth.authenticate("alice", "nope", ClientPlatform::Macos, ip()).await;
        assert_eq!(f.auth.dummy_verifications(), 0);

        // No such user, and a user whose stored hash is not bcrypt: both are
        // verified against the dummy hash instead of returning early.
        let _ = f.auth.authenticate("mallory", "nope", ClientPlatform::Macos, ip()).await;
        assert_eq!(f.auth.dummy_verifications(), 1);
        let _ = f.auth.authenticate(EMAIL, "nope", ClientPlatform::Macos, ip()).await;
        assert_eq!(f.auth.dummy_verifications(), 2);

        // The dummy hash is a genuine bcrypt hash, so that verification does
        // the full work rather than failing fast on a parse error.
        assert_eq!(bcrypt::verify("nope", dummy_hash()).ok(), Some(false));
        assert_eq!(verify_password("x".into(), None).await, (false, true));
        assert_eq!(verify_password("x".into(), Some("!sso".into())).await, (false, true));
    }

    #[tokio::test]
    async fn password_auth_can_be_switched_off() {
        let mut settings = settings();
        settings.password_auth = false;
        let f = fixture_with(false, settings);
        let user = f.users.add("alice", Some("correct horse"));

        let refused = f
            .auth
            .authenticate("alice", "correct horse", ClientPlatform::Macos, ip())
            .await
            .unwrap_err();
        assert!(refused.contains("disabled"), "{refused}");
        // Same answer whether or not the account exists, and no bcrypt at all.
        let unknown = f
            .auth
            .authenticate("mallory", "x", ClientPlatform::Macos, ip())
            .await
            .unwrap_err();
        assert_eq!(unknown, refused);
        assert_eq!(f.auth.dummy_verifications(), 0);

        // A session token that came from a password login is refused too...
        let pw_token = f.auth.token_for_test(&user, false, now_ms() - 1000, now() - 1);
        assert_eq!(renew(&f, &pw_token).await.unwrap_err(), INVALID_SESSION_TOKEN);
        // ...while SSO sessions are unaffected.
        let sso_user = f.users.add(EMAIL, None);
        let sso_token = f.auth.token_for_test(&sso_user, true, now_ms() - 1000, now() - 1);
        assert!(renew(&f, &sso_token).await.is_ok());
    }

    #[tokio::test]
    async fn password_login_token_carries_the_new_claims() {
        let f = fixture();
        f.users.add("alice", Some("correct horse"));
        let ok = f
            .auth
            .authenticate("alice", "correct horse", ClientPlatform::Macos, ip())
            .await
            .unwrap();
        let claims = claims_of(&ok.session_token);
        assert!(!claims.sso);
        assert_eq!(claims.auth_time, Some(ok.auth_time));
        assert_eq!(claims.iat_ms, Some(ok.issued_at_ms));
        assert_eq!(claims.exp as i64, ok.issued_at_ms / 1000 + DAY);
        assert!(claims.email.is_none());
    }
}
