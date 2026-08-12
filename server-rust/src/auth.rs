//! User authentication and session persistence.
//!
//! Port of `auth/authService.ts`. Uses bcrypt for password verification and
//! JWT for the opaque session token handed back to the client.

use crate::db::DbPool;
use crate::protocol::ClientPlatform;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use uuid::Uuid;

/// Sentinel password hash for SSO-provisioned users. It is not a valid bcrypt
/// hash, so it can never match a password (bcrypt::verify errors out).
const SSO_PASSWORD_HASH: &str = "!sso";

pub struct AuthService {
    db: DbPool,
    jwt_secret: String,
    /// Lifetime of session tokens minted for SSO logins, in days.
    sso_session_ttl_days: i64,
    /// Emails/domains allowed to authenticate via SSO. Empty = allow all.
    /// Behind a lock because the panel can change it while clients connect.
    sso_allowed: std::sync::RwLock<Vec<String>>,
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
}

impl AuthService {
    pub fn new(
        db: DbPool,
        jwt_secret: String,
        sso_session_ttl_days: i64,
        sso_allowed: Vec<String>,
    ) -> Self {
        AuthService {
            db,
            jwt_secret,
            sso_session_ttl_days,
            sso_allowed: std::sync::RwLock::new(sso_allowed),
        }
    }

    /// Replace the SSO allowlist at runtime (panel edit). Applies to the next
    /// authentication attempt; sessions already issued are unaffected.
    pub fn set_sso_allowed(&self, allowed: Vec<String>) {
        *self.sso_allowed.write().unwrap() = allowed;
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
        let client = self
            .db
            .get()
            .await
            .map_err(|_| "Internal server error".to_string())?;

        let row = client
            .query_opt(
                "SELECT id, username, password_hash, is_active, max_connections \
                 FROM users WHERE username = $1",
                &[&username],
            )
            .await
            .map_err(|_| "Internal server error".to_string())?;

        let Some(row) = row else {
            self.log_event(None, "auth_fail", platform, client_ip, Some("User not found"))
                .await;
            return Err("Invalid credentials".to_string());
        };

        let user_id: Uuid = row.get("id");
        let password_hash: String = row.get("password_hash");
        let is_active: bool = row.get("is_active");
        let max_connections: i32 = row.get("max_connections");

        if !is_active {
            self.log_event(Some(user_id), "auth_fail", platform, client_ip, Some("Account disabled"))
                .await;
            return Err("Account is disabled".to_string());
        }

        let password_valid = bcrypt::verify(password, &password_hash).unwrap_or(false);
        if !password_valid {
            self.log_event(Some(user_id), "auth_fail", platform, client_ip, Some("Wrong password"))
                .await;
            return Err("Invalid credentials".to_string());
        }

        self.check_connection_limit(&client, user_id, max_connections, platform, client_ip)
            .await?;

        let username_db: String = row.get("username");
        let session_token = self.sign_token(user_id, &username_db, platform, false)?;

        tracing::info!("User {username} authenticated successfully from {client_ip}");

        Ok(AuthOk {
            user_id,
            username: username_db,
            session_token,
        })
    }

    /// Authenticate an SSO login whose id_token has already been verified
    /// (see [`crate::sso::SsoVerifier`]). Looks the user up by email and
    /// JIT-provisions one on first login.
    pub async fn authenticate_sso(
        &self,
        email: &str,
        name: Option<&str>,
        platform: ClientPlatform,
        client_ip: IpAddr,
    ) -> AuthResult {
        // Gate JIT provisioning (and login) on the allowlist: without this,
        // any account the IdP verifies gets a VPN account auto-created.
        let allowed = self.sso_allowed.read().unwrap().clone();
        if !email_allowed(email, &allowed) {
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

        let client = self
            .db
            .get()
            .await
            .map_err(|_| "Internal server error".to_string())?;

        // Legacy accounts store the email in `username` with an empty `email`
        // column, so match either.
        let row = client
            .query_opt(
                "SELECT id, username, is_active, max_connections \
                 FROM users WHERE LOWER(email) = $1 OR LOWER(username) = $1",
                &[&email],
            )
            .await
            .map_err(|_| "Internal server error".to_string())?;

        let row = match row {
            Some(row) => row,
            None => {
                // JIT provisioning: username = email, sentinel password hash,
                // default max_connections from the schema.
                let inserted = client
                    .query_one(
                        "INSERT INTO users (username, email, password_hash, is_active) \
                         VALUES ($1, $1, $2, true) \
                         RETURNING id, username, is_active, max_connections",
                        &[&email, &SSO_PASSWORD_HASH],
                    )
                    .await
                    .map_err(|e| {
                        tracing::error!("SSO: failed to JIT-create user {email}: {e}");
                        "Internal server error".to_string()
                    })?;
                tracing::info!(
                    "SSO: JIT-created user {email}{}",
                    name.map(|n| format!(" ({n})")).unwrap_or_default()
                );
                inserted
            }
        };

        let user_id: Uuid = row.get("id");
        let is_active: bool = row.get("is_active");
        let max_connections: i32 = row.get("max_connections");

        if !is_active {
            self.log_event(
                Some(user_id),
                "auth_fail",
                platform,
                client_ip,
                Some("Account disabled (sso)"),
            )
            .await;
            return Err("Account is disabled".to_string());
        }

        self.check_connection_limit(&client, user_id, max_connections, platform, client_ip)
            .await?;

        let username_db: String = row.get("username");
        let session_token = self.sign_token(user_id, &username_db, platform, true)?;

        tracing::info!("User {email} authenticated via SSO from {client_ip}");

        Ok(AuthOk {
            user_id,
            username: username_db,
            session_token,
        })
    }

    /// Authenticate a reconnect with a previously-issued session JWT
    /// (`authType: "session"`). Validates the HS256 signature and expiry,
    /// re-checks the account, then mints a fresh token.
    pub async fn authenticate_session_token(
        &self,
        token: &str,
        platform: ClientPlatform,
        client_ip: IpAddr,
    ) -> AuthResult {
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
                return Err("Invalid or expired session token".to_string());
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
            return Err("Invalid or expired session token".to_string());
        };

        let client = self
            .db
            .get()
            .await
            .map_err(|_| "Internal server error".to_string())?;

        let row = client
            .query_opt(
                "SELECT id, username, is_active, max_connections \
                 FROM users WHERE id = $1",
                &[&user_id],
            )
            .await
            .map_err(|_| "Internal server error".to_string())?;

        let Some(row) = row else {
            self.log_event(
                None,
                "auth_fail",
                platform,
                client_ip,
                Some("Session token user not found"),
            )
            .await;
            return Err("Invalid or expired session token".to_string());
        };

        let is_active: bool = row.get("is_active");
        let max_connections: i32 = row.get("max_connections");

        if !is_active {
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

        self.check_connection_limit(&client, user_id, max_connections, platform, client_ip)
            .await?;

        let username_db: String = row.get("username");
        // Preserve the SSO marker (and its longer TTL) across reconnects.
        let session_token = self.sign_token(user_id, &username_db, platform, claims.sso)?;

        tracing::info!("User {username_db} re-authenticated via session token from {client_ip}");

        Ok(AuthOk {
            user_id,
            username: username_db,
            session_token,
        })
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
        client: &deadpool_postgres::Object,
        user_id: Uuid,
        max_connections: i32,
        platform: ClientPlatform,
        client_ip: IpAddr,
    ) -> Result<(), String> {
        let count_row = client
            .query_one(
                "SELECT COUNT(*) as count FROM sessions WHERE user_id = $1",
                &[&user_id],
            )
            .await
            .map_err(|_| "Internal server error".to_string())?;
        let current_sessions: i64 = count_row.get("count");

        if current_sessions >= max_connections as i64 {
            self.log_event(
                Some(user_id),
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
        user_id: Uuid,
        username: &str,
        platform: ClientPlatform,
        sso: bool,
    ) -> Result<String, String> {
        // Password logins keep the original 24h expiry (`expiresIn: '24h'`);
        // SSO logins get a longer-lived token (SSO_SESSION_TTL_DAYS).
        let ttl = if sso {
            chrono::Duration::days(self.sso_session_ttl_days)
        } else {
            chrono::Duration::hours(24)
        };
        let exp = (chrono::Utc::now() + ttl).timestamp() as usize;
        let claims = Claims {
            user_id: user_id.to_string(),
            username: username.to_string(),
            platform: platform.as_str().to_string(),
            exp,
            sso,
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

    async fn log_event(
        &self,
        user_id: Option<Uuid>,
        event_type: &str,
        platform: ClientPlatform,
        client_ip: IpAddr,
        details: Option<&str>,
    ) {
        self.log_event_raw(
            user_id,
            event_type,
            platform.as_str(),
            Some(&client_ip.to_string()),
            details,
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
