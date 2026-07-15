//! User authentication and session persistence.
//!
//! Port of `auth/authService.ts`. Uses bcrypt for password verification and
//! JWT for the opaque session token handed back to the client.

use crate::db::DbPool;
use crate::protocol::ClientPlatform;
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use uuid::Uuid;

pub struct AuthService {
    db: DbPool,
    jwt_secret: String,
}

#[derive(Debug)]
pub struct AuthOk {
    pub user_id: Uuid,
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
}

impl AuthService {
    pub fn new(db: DbPool, jwt_secret: String) -> Self {
        AuthService { db, jwt_secret }
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

        // Concurrent connection limit.
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

        let username_db: String = row.get("username");
        let session_token = self.sign_token(user_id, &username_db, platform)?;

        tracing::info!("User {username} authenticated successfully from {client_ip}");

        Ok(AuthOk {
            user_id,
            session_token,
        })
    }

    fn sign_token(
        &self,
        user_id: Uuid,
        username: &str,
        platform: ClientPlatform,
    ) -> Result<String, String> {
        // 24h expiry, matching the original `expiresIn: '24h'`.
        let exp = (chrono::Utc::now() + chrono::Duration::hours(24)).timestamp() as usize;
        let claims = Claims {
            user_id: user_id.to_string(),
            username: username.to_string(),
            platform: platform.as_str().to_string(),
            exp,
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
